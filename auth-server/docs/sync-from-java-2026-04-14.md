# auth-server: Java volta-auth-proxy 同期 Spec

> Date: 2026-04-14
> 基準点: `volta-gateway@e4a2daf` (2026-04-10) — auth-server を「Java 100% 互換」として作った時点
> 同期先: `volta-auth-proxy@afb6eab` (2026-04-13) — Java 側の最新コミット
> 対象: `auth-server/` crate のみ (gateway / auth-core は対象外)
> **Status**: ほぼ完了。P0/P1/P2 の主要項目を実装済み。KeyCipher/PKCE (#4/#15/#16) は Rust 側に PKCE 自体が未実装のため deferred (下記 *Implementation Status* 参照)。

## Implementation Status (実装結果)

| Phase | 項目 | Status | 実装場所 |
|---|---|---|---|
| P0 #1 | webhook SSRF | ✅ done | `security::validate_webhook_url` + `handlers/webhook.rs` |
| P0 #2 | OIDC nonce null check | ✅ N/A | Rust はまだ ID token 検証層が未実装 |
| P0 #3 | OIDC state atomic delete | ✅ N/A | Rust は HMAC-signed state (stateless) |
| P0 #4 | PKCE verifier 暗号化 | ⏸ **deferred** | Rust 側 PKCE 自体が未実装 — 機能追加扱い (O3) |
| P0 #5 | passkey credential_id UNIQUE | ✅ verified | `migrations/015_create_user_passkeys.sql:4` で `UNIQUE` |
| P0 #6 | passkey origin 検証 | ✅ verified | `webauthn-rs` が clientDataJSON origin を検証 |
| P0 #7 | /auth/* rate limit | ✅ done | `rate_limit::RateLimiter` + `app.rs` |
| P0 #8 | SAML devMode localhost | ✅ done | `handlers/saml.rs::saml_callback` |
| P0 #9 | admin OAuth scope | ✅ done | `helpers::require_admin` + admin/signing_key/extra/scim handlers |
| P0 #10 | invite rate limit | ✅ done | `rate_limit` `rl_invite` (20/min) |
| P0 #11 | clearSessionCookie flags | ✅ done | `helpers::clear_session_cookie` |
| P0 #12 | MFA state tenant switch | ✅ done | `handlers/auth.rs::switch_tenant` — `mfa_verified_at: None` |
| P0 #13 | wildcard domain matching | ✅ N/A | auth-server 側に redirect sanitize なし (gateway 側で対応済) |
| P0 #14 | Unicode NFC | ✅ done | `security::normalize_email` + `handlers/oidc.rs` + `saml.rs` |
| P0 #15 | KeyCipher PBKDF2 | ⏸ **deferred** | #4 と同時に実装 (O3) |
| P0 #16 | KeyCipher plain fallback | ⏸ **deferred** | #4 と同時 (O3) |
| P0 #17 | passkey counter atomic | ✅ done | `PasskeyStore::update_counter` 戻り値を `Result<bool>` に変更 |
| P0 #18 | GDPR hard delete 拡張 | ✅ done | `OutboxStore::delete_by_user` + `AuditStore::delete_flow_transitions_by_user` |
| P0 #19 | XXE 対策 | ✅ done | `security::reject_xml_doctype` in SAML parser |
| P0 #20 | rate limiter off-by-one | ✅ done (N/A) | 新規実装なので `count < limit` で正しい |
| P0 #21 | 定数時間比較 | ✅ done | `security::constant_time_eq` + M2M secret compare |
| P1.1 | AUTH-010 verify ロジック | ✅ done | `handlers/auth.rs::verify` 順序整理 + `handlers/mfa.rs::mfa_challenge` 追加 |
| P1.2 | SSE auth event stream | ✅ done | `auth_events::AuthEventBus` + `handlers/viz::auth_stream` |
| P1.3 | local network bypass | ✅ done | `local_bypass::LocalNetworkBypass` + `verify` 統合 |
| P2.1 | admin pagination | ✅ done | `pagination::{PageRequest,PageResponse}` + 5 endpoint (users/sessions/audit/members/invitations) + `migrations/021_pagination_indexes.sql` |
| P2.2 | tramli-viz integration | ✅ partial | `/viz/flows` (static) + `/api/v1/admin/flows/{id}/transitions` 実装。Mermaid 生成は tramli 依存で deferred |

Total: 18/21 ✅ done, 3 deferred (KeyCipher/PKCE)

### Tests
`cargo test -p volta-auth-server --bins`: 44 passed, 0 failed (security 16件、rate_limit 4件、local_bypass 7件、pagination 8件、auth_events 2件、saml 5件、他)

### Unchanged points (要注意)
- SAML 署名検証は "simplified" のまま (xmlsec なし) — production では `samael` crate 等の導入が必要 (別 task)
- 多くの admin ページの data endpoint で Bearer M2M scope チェック未実装 (セッション cookie 経由のみ — P3 以降)
- `force_secure_cookie: false` のままだと cookie Secure フラグが付かない — 本番デプロイ時は env `FORCE_SECURE_COOKIE=true` 必須

## 参照 Spec (Java 側)

| Spec ファイル | 関連項目 |
|---|---|
| `volta-auth-proxy/docs/AUTH-STATE-MACHINE-SPEC.md` | AUTH-010 統一 handler の設計原理、Flow SM/Session SM の 2 層構造 |
| `volta-auth-proxy/docs/HANDOFF-PAGINATION.md` | admin API ページネーション設計 (#23) |
| `volta-auth-proxy/docs/TENANT-SPEC.md` | AUTH-014 マルチテナント仕様 |
| `volta-auth-proxy/docs/decisions/002-reject-trusted-network-bypass.md` | local bypass の ADR (※下記 *Discrepancy* 参照) |

## 反映対象 Java コミット (2026-04-10 00:21 以降)

| 日付 | Commit | 種別 | タイトル |
|---|---|---|---|
| 04-11 | `99a2769` | feat | AUTH-010 統一 AuthFlowHandler |
| 04-11 | `f31a2f2` | feat | admin API pagination + search + sort (#23) |
| 04-11 | `abca91e` | sec | 全 20 セキュリティ修正 (#1-#21) |
| 04-11 | `6315cc0` | feat | tramli-viz リアルタイム可視化 (#22) |
| 04-12 | `9b4fe2c` | feat | SAAS-016 auth event SSE stream |
| 04-12 | `5f23f88` | feat | local network bypass for ForwardAuth |
| 04-13 | `4006ee7` | fix | local bypass: セッション無時のみ (MFA loop fix) |

除外: `6203de9` (gateway 側 config schema), `afb6eab` (nginx 設定), README/textbook docs, version bump, dep upgrade。

---

## P0 — セキュリティ修正 (Java `abca91e`, issue #1-#21)

Rust auth-server に同等の脆弱性がある可能性が高い。20 件中 **6 件は Java 側で「既に修正済」と確認** され、残り **14 件が新規修正**。Rust 側ではすべて新規確認が必要。

凡例: ✅=Rust 確認・修正不要 / ⚠️=要調査・修正 / 🔴=確実に該当

| # | Issue | Java 修正 | Rust auth-server 該当箇所 | 対応 |
|---|---|---|---|---|
| 1 | webhook SSRF | `ApiRouter`: HTTPS only + private IP block | `handlers/webhook.rs` create/patch | 🔴 URL バリデーション追加 |
| 2 | OIDC nonce null check | (Java は元から OK) | `auth-core` の OIDC callback | ⚠️ 確認のみ |
| 3 | OIDC state replay (atomic delete) | (Java は元から OK) | `handlers/oidc.rs` callback + `auth-core/store.rs` consume_oidc_flow | ⚠️ `SELECT FOR UPDATE` + `DELETE` 同 tx 確認 |
| 4 | PKCE verifier 平文保存 | `KeyCipher` で暗号化 | `handlers/oidc.rs` の OIDC start / `auth-core` の store | 🔴 KeyCipher 同等を導入 |
| 5 | passkey credential ID 非ユニーク | (Java は UNIQUE 制約あり) | `auth-core` の passkey table | ⚠️ schema 確認 |
| 6 | passkey origin = config | (Java は WebAuthn4j が clientDataJSON 検証) | `handlers/passkey_flow.rs` finish | ⚠️ webauthn-rs の origin 検証確認 |
| 7 | /auth/* rate limit 除外 | per-endpoint limits 追加 | auth-server 全体 (現状 rate limit middleware なし?) | 🔴 tower middleware で実装 |
| 8 | SAML 署名検証が devMode で skip | localhost-only ガード | `handlers/saml.rs` saml_callback / `src/saml.rs` | 🔴 dev_mode + localhost 二重ガード |
| 9 | admin API が OAuth scope 未強制 | `ADMIN/OWNER` scope 必須 | `handlers/admin.rs`, `handlers/manage.rs`, `handlers/scim.rs` 全部 | 🔴 scope 検証 middleware |
| 10 | invite に rate limit なし | 20/min per IP | `handlers/manage.rs::accept_invite` | 🔴 |
| 11 | clearSessionCookie 不完全 | Secure/SameSite/HttpOnly 付与 | `handlers/auth.rs::logout_*` | 🔴 |
| 12 | tenant switch 時 MFA state 引継ぎ | (Java は新 flow 毎回) | `handlers/auth.rs::switch_tenant` / MFA flow 起動箇所 | ⚠️ 確認 |
| 13 | wildcard ドメイン照合 (`evil-unlaxer.org`) | (Java は suffix pattern) | sanitize_redirect / allowed_redirect | ⚠️ Rust 側のロジック確認 |
| 14 | email Unicode 比較 (homoglyph) | NFC 正規化 | `handlers/manage.rs::accept_invite`, signup 系 | 🔴 `unicode-normalization` crate 導入 |
| 15 | KeyCipher: raw SHA-256 → KDF | PBKDF2 100K iterations | KeyCipher 相当 (まず存在確認) | 🔴 |
| 16 | KeyCipher decrypt: 平文 fallback | warn ログ | 同上 | 🔴 |
| 17 | passkey sign counter 非アトミック | `UPDATE WHERE sign_count < ?` | `auth-core` の passkey update | 🔴 |
| 18 | GDPR hard delete 不完全 | outbox_events + auth_flow_transitions も削除 | `handlers/admin.rs::hard_delete_user` | 🔴 |
| 19 | XXE: load-external-dtd | `FEATURE_SECURE_PROCESSING` 等 | `src/saml.rs` の XML パーサ | 🔴 quick-xml 設定確認 |
| 20 | rate limiter off-by-one | `count <= limit` → `count < limit` | rate limit 実装側 | 🔴 |
| 21 | 定数時間比較が早期 exit | `MessageDigest.isEqual()` | OidcStateCodec 相当, HMAC 比較箇所 | 🔴 `subtle::ConstantTimeEq` |

**実装方針**: 各項目を 1 commit ずつに分け、Java 側コミット (`abca91e`) のサブ粒度に対応させる。

---

## P1.1 — AUTH-010 統一 AuthFlowHandler (Java `99a2769`)

### Java 側の変更
6 endpoint を `AuthFlowHandler` 1 クラスに集約:
- `GET /auth/verify` — ForwardAuth (procedural session check)
- `GET /login` — login page + OIDC redirect (`?start=1`)
- `GET /callback` — IdP callback (HTML or JSON)
- `POST /auth/callback/complete` — IdP callback (JSON from JS)
- `GET /mfa/challenge` — MFA TOTP challenge page (新規)
- `POST /auth/mfa/verify` — MFA code verification

設計原則 (`AUTH-STATE-MACHINE-SPEC.md` §3-§7 参照):
- **既存** の `OidcFlowDef` + `MfaFlowDef` を使用 (新 AuthFlowDefinition は不採用 — flow ID mismatch のため)
- `OidcFlowRouter` + `MfaFlowRouter` + 旧 `/auth/verify` inline handler を置き換え
- Passkey + Invite flow router は独立を維持

### Rust 側の現状
- `handlers/auth.rs::verify` — `/auth/verify` 既存
- `handlers/oidc.rs::login`, `callback`, `callback_complete` — 既存
- `handlers/mfa.rs::mfa_verify_login` — 既存
- `GET /mfa/challenge` — **未実装** (route なし)
- `auth-core` の Flow SM (`OidcFlowDef`, `MfaFlowDef`) は既存 (3458a95)

### 必要な作業
1. `handlers/mfa.rs` に `mfa_challenge` (GET /mfa/challenge) 追加 — TOTP 入力画面 (HTML)
2. `app.rs` に `.route("/mfa/challenge", get(handlers::mfa::mfa_challenge))` 追加
3. `handlers/auth.rs::verify` のロジックを以下の順序に整理 (Java AuthFlowHandler.verify と同じ):
   1. local bypass チェック (P1.3 と統合)
   2. session 取得
   3. MFA pending → 302 to `/mfa/challenge`
   4. tenant suspended → 401
   5. OK → 200 + `X-Volta-*` headers
4. ファイル統合は **しない** — Rust では handler module 単位の分離が自然。Java の "1 class に集約" 原則は採用せず、Java AuthFlowHandler の **動作**だけを写す。

### Open question
Java AUTH-010 の主目的は「ForwardAuth redirect loop の修正」と「重複ロジックの統合」。Rust 側で同じ loop が再現するか要検証 (issue tracker に類似報告がないか確認)。

---

## P1.2 — SAAS-016 auth event SSE stream (Java `9b4fe2c`)

### Java 側
- `AuditService`: `LOGIN_SUCCESS` / `LOGOUT` / `SESSION_EXPIRED` を Redis channel `volta:auth:events` に publish
- `VizRouter`: `GET /viz/auth/stream` — SSE endpoint, Redis subscriber thread (virtual) → fan-out to SSE clients
- `Main`: `authEventJedis` (publish 用) を `AuditService` に注入

### Rust 側現状
- 該当 endpoint 無し (`/viz/*` route なし)
- `AuditService` 相当: `auth-core` 内 (詳細未確認)
- Redis client: 既に依存に入っているか要確認 (`redis` crate)

### 必要な作業
1. `auth-core` の audit に「event publish」hook を追加 (Redis pub/sub)
2. `handlers/viz.rs` (新規) を作成 — `axum::response::sse::Sse` を使う
3. `app.rs` に `.route("/viz/auth/stream", get(handlers::viz::auth_stream))` 追加
4. Redis 設定を `state.rs` に追加 (env: `REDIS_URL`)
5. graceful shutdown 対応

### 実装ヒント
- axum の SSE: `Sse::new(stream).keep_alive(KeepAlive::default())`
- Redis pub/sub: `redis::aio::PubSub` + `tokio::sync::broadcast` で fan-out

---

## P1.3 — Local network bypass + MFA loop fix (Java `5f23f88` + `4006ee7`)

### ⚠️ Discrepancy with ADR
`docs/decisions/002-reject-trusted-network-bypass.md` (2026-04-02) は trusted-network bypass を **Reject**。
しかし `5f23f88` (2026-04-12) でこの ADR を覆して bypass を実装している。Java 側 ADR 自体は更新されていない。

→ **判断**: 最新コードを正と見なし、Rust 側にも実装する。ただし spec 末尾の Open Decisions に記録し、後で ADR 更新を勧める。

### Java 側仕様
- **設定**: `LOCAL_BYPASS_CIDRS` env (空 = 無効)
- **デフォルト CIDR**: `192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,100.64.0.0/10,127.0.0.1/32` (RFC1918 + Tailscale CGNAT + loopback)
- **挙動** (`4006ee7` 後の最終形):
  1. session 取得を試みる
  2. session **あり** → 通常認証 (MFA check, user header 付与)
  3. session **なし** + local IP → `200 + X-Volta-Auth-Source: local-bypass` (anonymous)
  4. session **なし** + external IP → 302 to `/login`

### Rust 側現状
- 該当ロジック無し
- `gateway` 側に類似 (`gateway/src/auth.rs::sanitize_redirect`) があるが auth-server とは別

### 必要な作業
1. `auth-server/src/local_bypass.rs` (新規) — Java `LocalNetworkBypass.java` を Rust port
   - `ipnet` または `cidr` crate で CIDR 判定
   - `from_env()` constructor
2. `state.rs` の `AppState` に `local_bypass: Arc<LocalNetworkBypass>` を追加
3. `handlers/auth.rs::verify` で session check 後に bypass 判定を挿入 (上記 P1.1 の verify ロジックと統合)
4. テスト: `tests/local_bypass_test.rs` — 8 case (Java と同じ)
5. `X-Forwarded-For` の解釈は **trusted-proxy 設定** が前提 — gateway が信頼可能であることを assumption として記録

### IPv6
Java 実装は IPv6 を **non-match** 扱い。Rust 版も同様にする (IPv4 only)。

---

## P2.1 — Admin API pagination + search + sort (Java `f31a2f2`, issue #23)

### Java 側
**5 endpoint** に統一 pagination 適用:
- `GET /api/v1/admin/users` — `?page=&size=&sort=&q=` (email/name 検索)
- `GET /api/v1/admin/sessions` — `?page=&size=&user_id=` (新規 endpoint)
- `GET /api/v1/admin/audit` — `?page=&size=&from=&to=&event=`
- `GET /api/v1/tenants/{id}/members` — `?page=&size=`
- `GET /api/v1/tenants/{id}/invitations` — `?page=&size=&status=`

レスポンス形式:
```json
{ "items": [...], "total": N, "page": N, "size": N, "pages": N }
```

実装 (HANDOFF-PAGINATION.md 参照):
- `Pagination.java`: `PageRequest` + `PageResponse` records
- SQL: `SELECT *, COUNT(*) OVER() AS total_count ... LIMIT ? OFFSET ?`
- `sort` パラメータは whitelist サニタイズ
- DB index は `V22__pagination_indexes.sql` で追加済

### Rust 側現状
- 全 admin handler が full list 返却 (pagination 無し)
- `extra.rs:25` に "Simplified — real impl would list all sessions with pagination" コメントあり
- `auth-core` のクエリは pagination 未対応

### 必要な作業
1. `auth-server/src/pagination.rs` (新規) — `PageRequest { page, size, sort, q }` + `PageResponse<T>`
   ```rust
   #[derive(Deserialize)]
   pub struct PageRequest {
       #[serde(default = "default_page")] pub page: u32,
       #[serde(default = "default_size")] pub size: u32,
       pub sort: Option<String>,
       pub q: Option<String>,
   }
   #[derive(Serialize)]
   pub struct PageResponse<T> { items: Vec<T>, total: u64, page: u32, size: u32, pages: u32 }
   ```
2. `auth-core` 側 SqlStore に pagination メソッドを追加 (5 種):
   - `find_users_paginated`, `find_sessions_paginated`, `find_audit_paginated`, `find_members_paginated`, `find_invitations_paginated`
3. handlers 5 件を `Query<PageRequest>` 受け取りに改修
4. DB migration: `auth-server/migrations/` (もしくは `auth-core/migrations/`) に Java V22 相当を追加
5. sort whitelist:
   - users: `email`, `created_at`, `last_login_at`
   - sessions: `created_at`, `expires_at`
   - audit: `timestamp`
   - members: `joined_at`, `role`
   - invitations: `created_at`, `expires_at`

### Java V22 の bug fix (`5f23f88` 同梱)
audit_logs の column 名は `timestamp` であって `created_at` ではない:
```sql
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event ON audit_logs(event_type, timestamp DESC);
```
Rust 側でも同じ命名を踏襲する (`auth-core` schema 確認要)。

---

## P2.2 — tramli-viz integration (Java `6315cc0`, issue #22)

### Java 側
リアルタイム auth flow visualization (tramli-viz) 統合。具体内容は別調査が必要 (commit メッセージのみで spec doc 無し)。

### 判断
- P0/P1 完了後に着手
- Rust 側は `tramli` crate (auth-core が依存) に同等機能があるか要調査
- `9b4fe2c` (P1.2 SSE) と統合される可能性大 — 一緒に実装したほうが効率的

### 必要な作業 (暫定)
1. Java `VizRouter` の全コード読解 (`/viz/*` 全 endpoint 抽出)
2. tramli-viz が Rust port されているか確認
3. されていない場合は P2.2 を deferred 扱いとする

---

## 実装順序 (推奨)

1. **準備** (Day 0)
   - `auth-server/src/handlers/auth.rs::verify` の現コード読解 (P1 すべての起点)
   - `auth-core` の SqlStore メソッド一覧確認 (P0-#3, P0-#17, P2.1 の前提)
   - rate limit middleware の有無確認 (P0-#7, P0-#10, P0-#20)

2. **P0 セキュリティ** (Day 1-3)
   - 14 件を 1 issue/commit ずつ修正
   - 6 件 (Java で既存 OK) は Rust で確認のみ
   - tests を毎回追加

3. **P1.3 local bypass** (Day 3) — P1.1 の前に入れる (verify ロジックの土台)

4. **P1.1 AUTH-010** (Day 4-5) — verify 改修 + `/mfa/challenge` 新規

5. **P1.2 SSE** (Day 6) — Redis 依存追加から

6. **P2.1 pagination** (Day 7-8) — DB migration + handler 改修

7. **P2.2 tramli-viz** (Day 9+) — 別調査結果次第

---

## Open Decisions / 課題

| # | 内容 |
|---|---|
| O1 | `decisions/002-reject-trusted-network-bypass.md` を更新するか? Java 側 PR を別途立てるべき |
| O2 | Rust 側に rate limit middleware が無い場合の選定: `tower-governor` vs 自前実装 |
| O3 | KeyCipher (P0 #4, #15, #16) の Rust 実装 — `aes-gcm` + `pbkdf2` + `argon2` どれにするか |
| O4 | tramli-viz の Rust port 状況 (P2.2) |
| O5 | DB migration の置き場所 — `auth-core/migrations/` or `auth-server/migrations/` |
| O6 | Java AUTH-010 の "1 class 集約" 原則を採用しない理由を README に記載するか |

## 参考 — Java 側で除外する変更

| Commit | 除外理由 |
|---|---|
| `6203de9` volta-config schema v3 | gateway 側 config 領域 (auth-server 対象外) |
| `afb6eab` nginx fix | Rust では auth-server が直接 listen するため不要 |
| `4e870c9` README | README 更新は別 task |
| `cafb39c` auth textbook | docs only |
| `12124d6` 0.3.0-SNAPSHOT bump | バージョン管理は別途 |
| `7c54950` tramli 3.7.1 upgrade | dep 管理は別途 |
| `ba222dd`, `39d3b7e` docs | 該当作業時に参照のみ |
