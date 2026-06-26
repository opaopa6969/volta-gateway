# Auth Runtime & Notifications — 運用・API・設定リファレンス

tramli フロー + Notification 抽象による会員登録・メール確認・MFA・ログインチャレンジの
実装ガイド。設計の根拠は [`auth-flows-and-notifications-design.md`](./auth-flows-and-notifications-design.md)、
フロー図は [`passkey-flows.md`](./passkey-flows.md) と `/viz/flows`（アニメ表示）参照。

## 実装状況サマリ

| 領域 | 状態 |
|---|---|
| Notification 抽象（Channel/Provider/Sender/Service） | ✅ 実装・unit テスト |
| 通知 outbox（notification_jobs/logs）+ worker | ✅ 実装・実DB統合テスト |
| Email provider: SMTP / Mailpit / Dummy / Log | ✅ 実装（SES は未実装→Log fallback）|
| SMS provider: Twilio / Dummy / Log（SNS→Log）| ✅ 実装（実送信は creds 設定時）|
| LINE provider: Messaging API / Dummy / Log | ✅ 実装（実送信は token 設定時）|
| login OTP チャレンジ（Email/SMS/LINE）| ✅ 実装・実DB統合テスト |
| MFA setup ランタイム（TOTP flow 化、recovery codes）| ✅ 実装・実DB統合テスト |
| tramli 5フロー定義（registration/email_verification/password_reset/mfa_setup/login_challenge） | ✅ 定義 + validate + `/viz/flows` 登録 |
| 会員登録ランタイム（passwordless）+ HTTP API | ✅ 実装・実DB統合テスト |
| email_verification_tokens（ハッシュ/期限/一度きり/再送制限） | ✅ 実装・実DB統合テスト |
| login challenge OTP（Email/SMS/LINE、通知経由） | ✅ 実装・実DB統合テスト |
| **password reset** | ⛔ 非採用（passwordless 確定。flow は定義のみ残置）|
| **MFA setup** | ✅ flow-ランタイム実装（`runtime::start_mfa_setup`/`confirm_mfa_setup`、既存 TOTP/recovery 再利用、確認後のみ有効化）。既存 HTTP エンドポイント（`/api/v1/users/{id}/mfa/totp/*`）とも併存 |

すべて Rust 側（volta-gateway/auth-core, auth-server）。**本番(Java volta-auth-proxy)には無影響**。

## 設定（環境変数）

### 通知
| 変数 | 既定 | 説明 |
|---|---|---|
| `NOTIFICATION_DEFAULT_CHANNEL` | `DUMMY` | 既定チャネル（EMAIL/SMS/LINE/LOG/DUMMY）|
| `NOTIFICATION_ENABLED_CHANNELS` | `DUMMY,LOG,EMAIL` | 有効チャネル CSV（未知値は起動時エラー）|
| `NOTIFICATION_EMAIL_PROVIDER` | `LOG` | `SMTP`/`MAILPIT`/`DUMMY`/`SES`(未実装→LOG)/その他→LOG |
| `NOTIFICATION_EMAIL_FROM` | `no-reply@localhost` | 送信元 |
| `NOTIFICATION_SMTP_HOST` / `_PORT` | — / `587`(SMTP) `1025`(MAILPIT) | SMTP リレー |
| `NOTIFICATION_SMTP_USER` / `_PASS` | — | SMTP 認証（任意）|
| `NOTIFICATION_SMTP_STARTTLS` | `true` | `false` で平文（MAILPIT は常に平文）|
| `NOTIFICATION_POLL_SECS` | `5` | worker のポーリング間隔 |

### 認証ポリシー
| 変数 | 既定 | 説明 |
|---|---|---|
| `AUTH_EMAIL_VERIFICATION` | `enabled` | `disabled` で登録時のメール確認を省略 |
| `AUTH_EXPOSE_DEV_TOKEN` | （未設定）| `true` で register/start 応答に devToken を含める（**本番禁止**）|

ローカル例（外部送信なし）:
```
NOTIFICATION_DEFAULT_CHANNEL=DUMMY
NOTIFICATION_ENABLED_CHANNELS=DUMMY,LOG,EMAIL
NOTIFICATION_EMAIL_PROVIDER=LOG
```
Mailpit 例:
```
NOTIFICATION_DEFAULT_CHANNEL=EMAIL
NOTIFICATION_EMAIL_PROVIDER=MAILPIT
NOTIFICATION_SMTP_HOST=localhost
NOTIFICATION_SMTP_PORT=1025
```
本番(SMTP)例:
```
NOTIFICATION_DEFAULT_CHANNEL=EMAIL
NOTIFICATION_EMAIL_PROVIDER=SMTP
NOTIFICATION_EMAIL_FROM=no-reply@example.com
NOTIFICATION_SMTP_HOST=smtp.example.com
NOTIFICATION_SMTP_PORT=587
NOTIFICATION_SMTP_USER=...   NOTIFICATION_SMTP_PASS=...
```

## HTTP API（registration, passwordless）

すべて 5回/分/IP のレート制限。

### `POST /auth/register/start`
req: `{ "email": "user@example.com" }`
res: `{ "flowId": "...", "state": "EMAIL_VERIFICATION_PENDING", "nextActions": ["VERIFY_EMAIL","RESEND_VERIFICATION"] }`
（`AUTH_EXPOSE_DEV_TOKEN=true` 時のみ `devToken` を含む。`AUTH_EMAIL_VERIFICATION=disabled` 時は `state=EmailVerified`）

### `POST /auth/register/verify-email`
req: `{ "token": "<生トークン>" }`
res: `{ "flowId": "...", "state": "Completed", "nextActions": [] }`
失敗（不正/期限切れ/使用済）は enumeration 回避のため一律 `400 INVALID_TOKEN`。

### `POST /auth/register/resend-verification`
req: `{ "email": "..." }`
res: 常に `{ "ok": true, "message": "..." }`（存在有無を漏らさない。内部で 60s throttle）。

## ログイン OTP チャレンジ（Email/SMS/LINE）

ライブラリ API（HTTP 配線はログイン本体への統合時に追加）:
- `runtime::issue_login_otp(store, user_id, kind, destination, channel)` — 6桁コード生成→hash 保存→通知 enqueue。
- `runtime::verify_login_otp(store, user_id, raw_code)` → `ChallengeVerifyOutcome`（Verified/WrongCode{remaining}/Expired/TooManyAttempts/NotFound）。
TOTP は本パス不使用（既存 `user_mfa` で検証）。

## セキュリティ要点
- token/OTP は**平文保存しない**（SHA-256 ハッシュ）。期限・一度きり・試行上限・再送制限を属性で保持。
- account enumeration 回避（verify/resend は一律応答）。
- 副作用分離: フローは通知 job を積むだけ。worker が後で配信（backoff 付き retry 最大5）。idempotency は correlation_id。
- TOTP secret は既存どおり（本実装では非変更）。

## DB マイグレーション（追加分）
- `024_create_notification_jobs.sql`（notification_jobs / notification_logs）
- `025_create_email_verification_tokens.sql`
- `026_create_login_challenges.sql`
既存の `006/007 auth_flows`・`009 user_mfa`・`010 mfa_recovery_codes` 等を再利用。

## テスト
```
# unit（postgres 不要）
cargo test -p volta-auth-core
cargo test -p volta-auth-server

# 統合（testcontainers の実 Postgres、要 Docker）
cargo test -p volta-auth-core --features postgres -- --ignored
```
統合テスト: notification_job / email_verification_token / registration_runtime /
login_challenge（各テストは pgcrypto 拡張を有効化し必要 migration を適用）。
local/test は DUMMY/LOG で完結し、外部サービスへの送信は一切しない。

## 今後（未実装の follow-up）
- **Java→Rust 本番移行**: 完全ランブック + データ移行SQL を [`java-to-rust-migration-runbook.md`](./java-to-rust-migration-runbook.md) に整備済。実行は §2.1 のオペレーター判断6点 + maintenance window が前提（cutover は本書手順 D/E）。
- SMS の AWS SNS provider（現状 Twilio 実装・SNS→Log）。Email SES provider（aws-sdk、現状 SMTP 実装・SES→Log）。
- login OTP / MFA challenge の HTTP 統合をログイン本体（OIDC/passkey 後段）へ接続。
- テンプレートエンジン（現状は最小レンダラ）。
