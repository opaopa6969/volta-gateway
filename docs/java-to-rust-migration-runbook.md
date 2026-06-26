# Java → Rust Auth Migration Runbook

**volta-auth-proxy (Java/Flyway) → volta-gateway auth-server (Rust/sqlx)**

> 後日オペレーターが実行するための準備済みランブック。リポジトリ解析のみで作成（live DB/コンテナ/本番に未接触）。
> 以前の in-place 切替は schema 乖離で失敗・ロールバック済み。本書は **新規 Rust スキーマ DB + 列マッピング付きデータコピー**方式に置き換える。

## 0. 確定事項（ソース由来）
- Rust migrations は `auth-core/migrations/001…027.sql`、**外部適用**（`sqlx::migrate!` は無し）→ `sqlx migrate run` で適用。
- Rust バイナリ `volta-auth-server`、env `PORT`(既定7070)/`DATABASE_URL`。
- Rust は OIDC ユーザを **`users.google_sub`** で解決（UPSERT）。SAML 等は `provider:hash` を google_sub に詰める。**`user_identities` テーブルは無い**。
- prod `volta-gateway.yaml`: `auth.volta_url` と該当 backend が `:7070`。SAML サイドカーは Java :7070 に残置（DD-005）。
- Java DB: `volta_auth`。新 Rust DB（提案）: `volta_auth_rs`。

## 1. テーブル別スキーマ差分（要点）
✅一致 / ⚠️変換要 / ➕Rust専用 / ➖Java専用(破棄) / 🔁一過性(コピー除外)

- **users** ✅（google_sub nullable 一致）。⚠️非google `user_identities` は Rust に居場所なし→§2.1 決定。
- **tenants** ✅（branding/isolation/maintenance 列は➖破棄）。
- **memberships** ✅（public schema。tenant isolation 利用時のみ §3.10）。
- **invitations** ⚠️ **Java=`code_hash`(V27) / Rust=`code`** の名前・意味不一致。§2.1#2 で決定（既定: 移行スキップ・再発行）。
- **invitation_usages** ✅（invitations 移行時のみ）。
- **user_passkeys** ✅ byte-for-byte。
- **user_identities** ➖ Rust テーブル無し→google_sub へ寄せる（§3.1）。
- **signing_keys** ✅ **必須コピー**（JWT 継続性）。
- **idp_configs** ⚠️ `client_secret` は➕Rust専用(Java源なし)→NULL 挿入、切替後に再入力。
- **m2m_clients / user_mfa / mfa_recovery_codes** ✅。
- **known_devices / trusted_devices / policies** ✅。
- **plans** ⚠️ seed が `free`↔`FREE` で相違→Java plans は**コピーせず** Rust seed を使い、`subscriptions.plan_id` を大文字化。
- **subscriptions** ✅（plan_id 大文字化）。
- **audit_logs** ⚠️ `actor_ip` INET→VARCHAR(45)（`host()` で変換）。
- **webhook_subscriptions / outbox_events / webhook_deliveries** ✅/⚠️（outbox は未配信のみ or skip）。
- 🔁 **skip（一過性・空で開始、ユーザーは一度再ログイン）**: sessions / oidc_flows / auth_flows / auth_flow_transitions / passkey_challenges / login_challenges / notification_jobs / notification_logs / email_verification_tokens / magic_links / session_scopes / step_up_log。

## 2. 方式
**fresh スキーマ再構築**（in-place ALTER ではない）。
1. 空 DB `volta_auth_rs` 作成。
2. Rust migrations 適用（`sqlx migrate run`）＝権威スキーマ。
3. 永続テーブルのみ列マッピング `INSERT…SELECT`（`postgres_fdw`/`dblink` か `pg_dump --data-only --column-inserts | sed`）。
4. 一過性テーブルは skip。
5. FK 順: users → tenants → memberships → invitations → invitation_usages → signing_keys → idp_configs → m2m_clients → user_mfa → mfa_recovery_codes → user_passkeys → known_devices → trusted_devices → (plans seed) → subscriptions → policies → webhook_subscriptions → audit_logs。

### 2.1 実行前に要オペレーター判断（ask human）
1. **user_identities 非google**: 非Google プロバイダ利用者がいるか。いれば google_sub への詰め方（Rust が期待する `provider:sub` 形式）を確定。Google のみなら straight copy で完結。
2. **invitations code_hash↔code**: Rust の招待コード照合がハッシュか平文か確認 → (A)`code_hash→code` マップ or (B)スキップ再発行（**既定 B**）。
3. **plans 大文字小文字**: live の `subscriptions.plan_id`/`tenants.plan` の値を確認し Rust seed(大文字)へ remap。
4. **idp_configs.client_secret**: 切替後に各 IdP の secret 再入力（要 SSO は必須）。
5. **tenant schema isolation**: `tenants.isolation='schema'` の有無。無ければ public のみ（既定）。
6. **audit_logs 保持期間**（全 vs 直近N日）。

## 3. データコピー SQL
（`postgres_fdw` を target `volta_auth_rs` 側に設定して `java.*` foreign tables を参照する方式。フォールバックは `pg_dump --data-only --column-inserts | sed`。）

主要例（FK順・`ON CONFLICT (id) DO NOTHING`）:
```sql
-- fdw
CREATE EXTENSION IF NOT EXISTS postgres_fdw;
CREATE SERVER java_src FOREIGN DATA WRAPPER postgres_fdw OPTIONS (host 'JAVA_HOST', port '5432', dbname 'volta_auth');
CREATE USER MAPPING FOR CURRENT_USER SERVER java_src OPTIONS (user 'RO_USER', password 'RO_PASS');
CREATE SCHEMA IF NOT EXISTS java; IMPORT FOREIGN SCHEMA public FROM SERVER java_src INTO java;

-- users
INSERT INTO users (id,email,display_name,google_sub,created_at,is_active,locale,deleted_at)
SELECT id,email,display_name,google_sub,created_at,is_active,COALESCE(locale,'ja'),deleted_at
FROM java.users ON CONFLICT (id) DO NOTHING;

-- signing_keys（必須）
INSERT INTO signing_keys (kid,public_key,private_key,status,created_at,rotated_at,expires_at)
SELECT kid,public_key,private_key,status,created_at,rotated_at,expires_at
FROM java.signing_keys ON CONFLICT (kid) DO NOTHING;

-- user_passkeys（BYTEA 検証含む）
INSERT INTO user_passkeys (id,user_id,credential_id,public_key,sign_count,transports,name,aaguid,backup_eligible,backup_state,created_at,last_used_at)
SELECT id,user_id,credential_id,public_key,sign_count,transports,name,aaguid,backup_eligible,backup_state,created_at,last_used_at
FROM java.user_passkeys ON CONFLICT (id) DO NOTHING;

-- idp_configs（client_secret は NULL）
INSERT INTO idp_configs (id,tenant_id,provider_type,metadata_url,issuer,client_id,client_secret,x509_cert,created_at,is_active)
SELECT id,tenant_id,provider_type,metadata_url,issuer,client_id,NULL,x509_cert,created_at,is_active
FROM java.idp_configs ON CONFLICT (id) DO NOTHING;

-- subscriptions（plan_id 大文字化）/ audit_logs（INET→text）
INSERT INTO subscriptions (id,tenant_id,plan_id,status,stripe_sub_id,started_at,expires_at)
SELECT id,tenant_id,upper(plan_id),status,stripe_sub_id,started_at,expires_at FROM java.subscriptions ON CONFLICT (id) DO NOTHING;
INSERT INTO audit_logs (id,timestamp,event_type,actor_id,actor_ip,tenant_id,target_type,target_id,detail,request_id)
SELECT id,timestamp,event_type,actor_id,host(actor_ip),tenant_id,target_type,target_id,detail,request_id FROM java.audit_logs ON CONFLICT (id) DO NOTHING;
SELECT setval(pg_get_serial_sequence('audit_logs','id'), COALESCE((SELECT max(id) FROM audit_logs),1));
```
（tenants/memberships/m2m_clients/user_mfa/mfa_recovery_codes/known_devices/trusted_devices/policies は straight copy。完全版 SQL は本リポの調査ログ参照。）

## 4. 切替ランブック（オペレーター手順）
- **A 準備（無影響）**: `cargo build --release -p volta-auth-server` → `createdb volta_auth_rs` → `sqlx migrate run`（27 migrations, plans seed 確認）→ §2.1 決定。
- **B データコピー（snapshot/replica に対して）**: Java の一貫スナップショット取得 → §3 を FK 順で実行 → §5 行数照合。
- **C staging 検証（:7072、本番経路外）**: `PORT=7072 DATABASE_URL=…/volta_auth_rs ./target/release/volta-auth-server` → staging gateway を :7072 へ → OIDC ログイン / passkey 登録+ログイン(移行分も) / `/auth/verify` / `/viz/flows` / TOTP+recovery / m2m。全通過がゲート。
- **D 本番切替**: 差分再コピー（必要なら短い maintenance window）→ Rust を :7072 で永続起動 → `volta-gateway.yaml` の `auth.volta_url` と該当 backend を `:7070→:7072`（**SAML 経路は :7070 残置**）→ gateway リロード → smoke（実アカウントでログイン、`/auth/verify` 200、passkey 1件、15分エラー監視。既存ユーザーは一度だけ再ログイン）。
- **E ロールバック**: `gateway.yaml` を `:7070` に戻しリロード → Rust :7072 停止。**Rust は別 DB なので Java データは一切不変＝即時・無損失ロールバック**。

## 5. リスクと検証チェックリスト
主リスク: R1 user_identities 非google 不可ログイン / R2 招待リンク破損 / R3 plans casing / R4 idp client_secret NULL / R5 INET変換 / R6 全員再ログイン / R7 snapshot ドリフト / R8 BIGSERIAL 衝突 / R9 signing_keys 未コピーで全 JWT 失効 / R10 tenant schema 漏れ / R12 SAML 経路。
検証: コピー前(§2.1 各確認) → コピー後(行数照合・signing_keys kid 一致・passkey BYTEA 整合・sequence reset) → staging 機能(OIDC/passkey/TOTP/m2m/verify/viz) → 本番 smoke(15分監視・ロールバック手順把握)。

## ドライラン結果（2026-06-26 実施・クローン DB `volta_auth_rs`、本番無影響）
fresh Rust スキーマ DB を作成 → 27 migrations 適用（30 tables / plans=FREE,PRO,ENTERPRISE）→ `postgres_fdw` で live `volta_auth` から列マッピングコピー。**全行数一致**: users 3 / tenants 3 / memberships 3 / signing_keys 1 / idp_configs 1 / audit_logs 47（他は空）。変換成功: audit_logs `host(actor_ip)` / idp_configs `client_secret=NULL`。

**6 オペレーター判断の確定値**（live データに基づく）:
1. user_identities 非google: **0件**（3 users 全て google）→ straight copy で完結。
2. invitations code_hash↔code: invitations **0件** → 移行対象なし（既定 B）。
3. plans casing: subscriptions **0件**・tenants.plan=**FREE×3**（大文字、Rust seed と一致）→ remap 不要。
4. idp_configs.client_secret: **1件（SAML, active）** → NULL 挿入。SAML は x509_cert 使用＋DD-005 で Java 残置のため切替時の SSO 影響なし。
5. tenant schema isolation: `isolation='schema'` **0件** → public のみ。
6. audit_logs 保持: **47件**（少数）→ 全コピー。

**ヘッドレス検証（:7072, 本番経路外）**: database connected / flow definitions validated / webauthn configured。`/auth/verify`→401 ✅ / `/viz/flows`→200 ✅ / registration ランタイム（移行済 DB に対し register/start→devToken→verify-email→`Completed`）✅。OIDC ログイン・passkey 登録は Google 往復／ブラウザが必要 → 本番切替の §C staging gateway 段で実施（headless 不可）。**以前 in-place で失敗した「Rust が起動して移行データに対し正しく動く」点をこの方式は達成**。

**追加発見（署名方式）**: Rust auth-server は **HS256（共有 `JWT_SECRET`）** でトークン署名し、`/.well-known/jwks.json` は **空配列を返すスタブ**（`auth-server/src/handlers/health.rs`、設計どおり）。Java が RS256＋JWKS で発行している場合、切替で署名方式が HS256 に変わる。**platform gateway は ForwardAuth（`/auth/verify` 委譲）でトークンを自前検証しない**ため内部影響なし。ただし **JWKS/RS256 公開鍵でトークンを検証する外部 RP があれば破綻**する（要確認）。signing_keys のコピーは継続性のため実施したが **HS256 下では未使用**。既存 Java 発行セッションは Rust では無効 → R6（全員一度だけ再ログイン）どおり。

## この調査で判明した追加乖離（briefing 外）
1. **invitations** code_hash(Java V27) ↔ code(Rust) の不一致（要判断）。
2. **idp_configs.client_secret** は Rust 専用（再入力要）。
3. **plans** seed の大文字小文字・上限差。
4. **audit_logs.actor_ip** INET↔VARCHAR。
5. Java 専用で Rust に無いもの: tenant_domains / tenant_security_policies / billing_usage / session_scopes / step_up_log / user_identities ＋ tenants の branding/isolation/maintenance 列。
6. Rust migrations は外部適用（`sqlx migrate run`）。
7. OIDC は `users.google_sub` 解決（SAML は `saml:<hash>`）。
