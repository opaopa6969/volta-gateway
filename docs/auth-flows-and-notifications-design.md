# Auth Flows & Notification 設計メモ（tramli 統合）

Status: Phase 1 (skeleton). Owner: auth-server。
対象: `volta-gateway/auth-core` + `auth-server`（Rust / axum / sqlx / tramli 3.8）。

## 0. 前提（調査結果サマリ）

- 認証は現状 **passwordless 前提**（OIDC / magic link / passkey / SAML）。password 保存は無い。
  → 本設計の password 系は **`AUTH_PASSWORD_ENABLED`（既定 false）で gate する新規能力**として扱う。
- **tramli 3.8 が flow フレームワークとして稼働中**（`auth-core/src/flow/` に oidc/passkey/mfa/invite）。
  新フローは同パターンで追加し、`auth-server/src/handlers/viz.rs` の flow_tables と
  `flow_descriptors()` に登録、起動時 `validate()` で結線検証。
- flow の **context は非永続**（in-memory）。DB には `auth_flows`(state/version/ttl/`summary` JSONB)
  + `auth_flow_transitions`(監査) のメタのみ。**属性（再送回数・期限・送信先など）は
  フロー専用トークンテーブルに置く**（state には入れない=要件§3）。
- **メール送信は未実装**（`magic_link.rs` は dev スタブ）。本設計で `notification` 抽象を新設。
- **outbox は webhook 専用**（`outbox_events`/`outbox_worker.rs`）。通知は別 outbox
  （`notification_jobs`/`notification_logs`）に分離。
- このRust auth-server は**現在 live ではない**（本番は Java volta-auth-proxy）。安全に開発可能。

## 1. Notification 抽象（`auth-core/src/notification/`）

要件の型を Rust conventions に翻案:

| 要件 | Rust |
|---|---|
| NotificationChannel | `enum NotificationChannel { Email, Sms, Line, Log, Dummy }` |
| NotificationProvider | `enum NotificationProvider { Smtp, Ses, Mailpit, DummyEmail, Sns, Twilio, DummySms, LineMessagingApi, DummyLine, Log }` |
| NotificationMessage | `struct { channel, to, template, correlation_id }` |
| NotificationTemplate | `struct { id, vars, subject, body }` |
| NotificationSender | `#[async_trait] trait { channel(), provider(), send() -> Result<Receipt, NotificationError> }` |
| NotificationService | チャネル→sender ルーティング + enabled 検証 |

原則:
- **設定で無効なチャネル指定は明確にエラー**（`NotificationError::ChannelNotEnabled`）。
- **local/test は外部送信しない**（DUMMY=メモリ捕捉 / LOG=tracing のみ）。
- provider 実装は差し替え可能（trait object）。
- **状態遷移と送信を密結合しない**: flow は「送るべき」を outbox に積むだけ。実送信は worker（Phase 2+）。

## 2. 副作用（要件§4）

1. DB tx 内で flow state を遷移し、同 tx で `notification_jobs` に行を作る。
2. commit 後に worker が `notification_jobs` を拾い `NotificationService.send()`。
3. 結果を `notification_logs` に記録。失敗は retryable なら backoff 再試行（既存 webhook outbox と同型）。
4. idempotency: job に `correlation_id`（flow_id+step）を持たせ二重送信を防ぐ。

## 3. 設定（env、conventions 準拠）

```
NOTIFICATION_DEFAULT_CHANNEL=EMAIL
NOTIFICATION_ENABLED_CHANNELS=EMAIL          # CSV
NOTIFICATION_EMAIL_PROVIDER=SES|SMTP|MAILPIT|DUMMY
NOTIFICATION_EMAIL_FROM=no-reply@example.com
NOTIFICATION_SMTP_HOST / _PORT / _USER / _PASS / _STARTTLS
NOTIFICATION_SMS_PROVIDER=DUMMY   NOTIFICATION_SMS_ENABLED=false
NOTIFICATION_LINE_PROVIDER=DUMMY  NOTIFICATION_LINE_ENABLED=false
AUTH_EMAIL_VERIFICATION=enabled|disabled
AUTH_MFA_REGISTRATION=required|optional|disabled
AUTH_MFA_LOGIN=required|user|disabled
AUTH_MFA_METHODS=TOTP[,EMAIL_OTP,SMS_OTP,LINE_OTP]
AUTH_PASSWORD_ENABLED=false
```
`NotificationConfig` / `AuthPolicyConfig` を `AppState` に追加。

## 4. Flow 一覧（新規5・tramli）

既存 `auth_flows.flow_type` を流用し以下を追加:

- `registration` — START→EMAIL_SUBMITTED→(EMAIL_VERIFICATION_PENDING→EMAIL_VERIFIED)→PASSWORD_SET(opt)→MFA_SETUP_OPTIONAL(opt)→COMPLETED / EXPIRED / CANCELLED
- `email_verification` — TOKEN_ISSUED→SEND_REQUESTED→SENT→VERIFIED / EXPIRED / FAILED / CANCELLED
- `password_reset` — REQUESTED→TOKEN_ISSUED→SEND_REQUESTED→SENT→TOKEN_VERIFIED→PASSWORD_CHANGED→COMPLETED / EXPIRED / FAILED / CANCELLED
- `mfa_setup` — NOT_CONFIGURED→SETUP_STARTED→SECRET_ISSUED→CONFIRMATION_PENDING→ENABLED→RECOVERY_CODES_ISSUED / DISABLED / CANCELLED
- `login_challenge` — PASSWORD_ACCEPTED→MFA_REQUIRED→CHALLENGE_SENT→CHALLENGE_VERIFIED→LOGIN_GRANTED / LOGIN_DENIED / EXPIRED / LOCKED

設定分岐:
- `AUTH_EMAIL_VERIFICATION=disabled` → registration は EMAIL_VERIFICATION_PENDING を経由しない。
- `AUTH_MFA_REGISTRATION=required` → COMPLETED 前に mfa_setup を要求。
- `AUTH_MFA_LOGIN=disabled` → login_challenge は MFA_REQUIRED を経由せず LOGIN_GRANTED。
- `AUTH_MFA_METHODS=[TOTP]` → Email/SMS/LINE OTP challenge を生成しない（TOTP は外部送信なし）。

## 5. DB（追加、token は平文禁止）

- `email_verification_tokens`（token_hash, expires_at, used_at, resend_count, attempt_count, …）
- `password_reset_tokens`（同上）
- `user_credentials`（`AUTH_PASSWORD_ENABLED` 時のみ・**argon2** ハッシュ、users とは分離）
- `login_challenges`（kind, code_hash/external, expires_at, attempt_count, …）
- `notification_jobs` / `notification_logs`（通知 outbox）
- MFA は既存 `user_mfa` / `mfa_recovery_codes` を再利用

## 6. セキュリティ原則

- token は十分長いランダム + **ハッシュ保存**、期限・一度きり・再送 rate limit。
- password reset は **account enumeration 回避**（存在有無で応答を変えない）。
- TOTP secret は `KeyCipher`(AES-256-GCM) で暗号化、recovery code は SHA256 ハッシュ（既存踏襲）。
- 失敗回数は state ではなく属性（token/challenge 行の列）。

## 7. 未決事項

1. **password 能力 → 入れない（DECIDED, passwordless 継続）。** 本システムは意図的に
   passwordless（OIDC / magic link / passkey / SAML）。password は最も弱い要素を戻すため不採用。
   - 登録は「メール確認で有効化」（`setPassword` なし）。`runtime::start_registration/verify_email`
     で実装（MFA optional → 既定 skip で Completed）。
   - PasswordResetFlow は定義のみ残置（実装・配線せず）。`AUTH_PASSWORD_ENABLED` は false 固定。
   - アカウント回復が要れば magic link 再認証（既存）で代替。Phase 3 は実質スキップ。
2. EmailVerification は専用テーブル新設（magic_links は流用しない）で確定。
3. SES/SMTP/Twilio/LINE の secret 注入方式（env か secret store）は Phase 6 で確定。
4. live 反映は Java→Rust 移行が前提（別件）。

## Phase 進行（実装順）— 完了状況

- **P1 ✅** notification 抽象 + DUMMY/LOG + 5 flow 定義（unit 8 + flow 37）
- **P2 ✅** registration/email_verification ランタイム + notification_jobs + email_verification_tokens
  + viz 登録 + HTTP API(/auth/register/*) + notification worker（実DB統合テスト多数）
- **P3 ⛔** password_reset → 非採用（passwordless 確定 §7-1）。flow は定義のみ残置。
- **P4 △** mfa_setup: flow 定義 + viz 済。TOTP/recovery は既存エンドポイントが機能提供
  （重複回避のため flow-ランタイム再ラップは見送り。詳細は auth-runtime-and-notifications.md）。
- **P5 ✅** login_challenge OTP（Email/SMS/LINE）を通知経由で実装（login_challenges + 実DB統合テスト）。
  TOTP は既存 user_mfa 検証を使用。
- **P6 ✅** SMTP/Mailpit/Dummy/Log email provider（lettre）。SES は未実装→Log fallback。
  SMS/LINE は interface + dummy 先行。docs 整備（本メモ + auth-runtime-and-notifications.md）。

運用・API・設定の詳細は [`auth-runtime-and-notifications.md`](./auth-runtime-and-notifications.md)。
