# auth-server backlog

> Date: 2026-04-14
> 起源: Java → Rust 同期作業 (`sync-from-java-2026-04-14.md`) 完了後に残った未実装項目のトラッキング。

## 優先度の目安

- **P0**: 本番投入前にブロック (セキュリティ / 実装欠落)
- **P1**: 本番投入可だが機能的に Java と差分あり
- **P2**: 将来拡張、Java 側にもない / optional

---

## P0

### 1. OIDC PKCE + KeyCipher (Java #4 / #15 / #16)

**現状**
- `handlers/oidc.rs::login` は `state` + `nonce` のみ、`code_challenge` を送っていない。
- `oidc_flows` テーブル相当が無く、PKCE verifier を DB に持つ仕組みが無い。
- `KeyCipher` 相当 (対称暗号 + KDF) が存在しない。`idp_configs.client_secret`、`m2m_clients.client_secret_hash`、`signing_keys.key_material` はすべて平文 / 単純ハッシュ。

**必要作業**
1. `auth-core/src/crypto.rs` を新設:
   - master key (env `KEY_CIPHER_MASTER_KEY` or `JWT_SECRET` フォールバック)
   - PBKDF2-HMAC-SHA256 で 100K iterations 派生
   - AES-256-GCM で `encrypt(plaintext) -> (nonce, ciphertext, tag)`
   - 暗号化失敗時は error、**復号失敗時は plain fallback せず error** を返す (#16)
2. `auth-core/migrations/NNN_create_oidc_flows.sql`:
   ```sql
   CREATE TABLE oidc_flows (
     id UUID PRIMARY KEY,
     state VARCHAR(255) UNIQUE NOT NULL,
     code_verifier_encrypted BYTEA NOT NULL,  -- AES-GCM payload
     nonce VARCHAR(255) NOT NULL,
     return_to TEXT,
     invite_code VARCHAR(64),
     created_at TIMESTAMPTZ DEFAULT now(),
     expires_at TIMESTAMPTZ NOT NULL
   );
   ```
3. `OidcFlowStore` (新規 trait): `save_oidc_flow` / `consume_oidc_flow` (atomic SELECT FOR UPDATE + DELETE).
4. `IdpClient::authorization_url` に `code_challenge` + `code_challenge_method=S256` を追加。
5. `IdpClient::exchange_code` に `code_verifier` 引数を追加。
6. `handlers/oidc.rs` を state DB 保存モデルに変更 (現状の HMAC-signed state をこれに置き換え)。

**工数**: 中 (1-2 日)。trait 追加 + migration + 暗号レイヤ + handler 書き換え。
**関連**: Java `OidcInitProcessor.java`, `OidcTokenExchangeProcessor.java`, `KeyCipher.java`

---

### 2. SAML 署名の暗号学的検証

**現状** (`auth-server/src/saml.rs:85-97`)
```rust
// Signature validation (simplified — full XML DSig requires xmlsec)
if !skip_signature {
    if !xml.contains("<ds:Signature") && !xml.contains("<Signature") {
        return Err(ApiError::unauthorized("SAML_SIGNATURE_REQUIRED", ...));
    }
    // Note: Full XML DSig verification requires libxmlsec1 or samael.
}
```
`<Signature>` タグの**存在確認のみ**で、公開鍵との照合はしていない。

**リスク**: 攻撃者が署名付きの SAML response を偽造可能。**本番利用不可**。

**必要作業**
- `samael` crate 導入 (`features = ["xmlsec"]`)。依存に libxmlsec1-dev (system) が必要。
- `parse_identity` を samael の `SAMLBinding::parse_response` に置き換え。
- テストデータの IdP 証明書は既存のテスト fixture を流用。

**工数**: 中 (xmlsec の環境構築コスト含む)。Dockerfile 修正も必要。
**関連**: Java `SamlService.java` (Apache xmlsec 使用)

---

### 3. Bearer token / M2M scope middleware

**現状**
- `helpers::require_admin` は cookie session の `roles` を見るだけ。
- `/oauth/token` で M2M JWT を発行しているが、それを Bearer で受ける認証経路が無い。
- `/api/v1/admin/*` と `/scim/v2/*` に M2M でアクセスできない。

**必要作業**
1. `helpers::require_admin` を以下の順で評価するよう拡張:
   - `Authorization: Bearer <jwt>` があれば検証し、`scopes` に `ADMIN`/`OWNER` 含むかチェック。
   - なければ cookie session fallback。
2. JWT は `state.jwt_verifier` で検証。scope は `VoltaClaims.roles` (comma-separated) から。
3. SCIM handlers は Bearer only に固定 (cookie 経路を塞ぐ) — Java 側の慣習と揃える。

**工数**: 小 (数時間)。
**関連**: Java `ApiRouter.java` の `requireScope("ADMIN")` パターン

---

## P1

### 4. OIDC ID token 検証

**現状**
- `handlers/oidc.rs::complete_oidc` は `exchange_code` で access_token を取得後、`userinfo` endpoint で email を取得するだけ。
- id_token は受け取っても検証していない (nonce / iss / aud / at_hash / exp すべてチェックなし)。

**これが無いので Java issue #2 (OIDC nonce null check) は Rust では N/A 扱い** — そもそも nonce をチェックしていない。

**必要作業**
- `IdpClient::verify_id_token(id_token, expected_nonce, expected_aud) -> Claims`:
  - issuer の JWKS 取得 (cache 付き)
  - JWS 検証 (RS256 / ES256)
  - `iss` が issuer_url と一致
  - `aud` が client_id を含む
  - `exp` / `iat` が合理的範囲
  - `nonce` が期待値と一致 (これが #2)
  - `at_hash` が access_token のハッシュと一致 (OIDC Core §3.1.3.8)
- `userinfo` の前に id_token 検証を挟む。

**工数**: 中。JWKS fetch + cache と JWS verify で `jsonwebtoken` crate を使えば比較的短い。

---

### 5. Passkey handlers の webauthn-rs 本格統合

**現状** (`handlers/passkey_flow.rs`)
- `auth_start`: `challenge = UUID::new_v4()` とダミー値。`webauthn_rs::Webauthn::start_passkey_authentication` を呼んでいない。
- `auth_finish`: `credential_id` を DB 検索するだけで、signature / clientDataJSON の検証なし。
- `register_start` / `register_finish` も同様にスタブ。
- `user_id` / `tenant_id` resolving が簡略化。

**必要作業**
- `auth-core/src/passkey.rs` (既存 `PasskeyService`) を handler から適切に呼び出す。
- `Webauthn` インスタンスを `AppState` に持たせる (rp_id / rp_origin は env から)。
- `register_start` → `start_passkey_registration` → challenge + registration state を session cookie or session table に保存。
- `register_finish` → `finish_passkey_registration` → credential を DB に保存。
- login 側も同様。

**工数**: 中 (1 日)。`webauthn-rs` の API がやや独特で学習コスト。

---

### 6. `admin_list_tenants` pagination 実装

**現状** (`handlers/admin.rs:145-149`)
```rust
pub async fn admin_list_tenants(...) -> Result<Response, ApiError> {
    let _ = auth_admin(&s, &jar).await?;
    Ok(Json(serde_json::json!({"tenants": []})).into_response())
}
```
空配列返却の stub。Java 側もページネーション対象外なので P2.1 sync から外していた。

**必要作業**
- `PgStore::list_tenants_paginated` を追加 (他の 5 メソッドと同じパターン)。
- handler を `PageRequest` 受け取りに変更。
- 検索条件: `q` で `name` / `slug` を ILIKE 検索、sort は `created_at` / `name`。

**工数**: 小 (30 分)。

---

### 7. Redis pub/sub for cross-instance SSE fan-out

**現状** (`auth_events::AuthEventBus`)
- `tokio::broadcast` channel のみ。単一プロセス内でのみ fan-out。
- マルチインスタンス (レプリカ 2+ 台) で片方で起きた LOGIN_SUCCESS が他方の SSE クライアントに届かない。

**Java 実装**: `JedisPooled` で Redis channel `volta:auth:events` に publish / subscribe。

**必要作業**
- Cargo.toml に `redis = { version = "0.27", features = ["tokio-comp", "connection-manager"] }`.
- `auth_events.rs` に `RedisBridge` 追加:
  - main で `REDIS_URL` があれば spawn: Redis subscribe → 受信イベントを `broadcast::Sender` に流す。
  - `publish` は同時に Redis `PUBLISH` も行う。
- optional: `REDIS_URL` 未設定時は現状維持 (単一プロセス fan-out)。

**工数**: 小〜中 (半日)。

---

### 8. tramli-viz Mermaid 生成 (`/viz/flows` 強化)

**現状** (`handlers/viz.rs::list_flows`)
- Flow 名と states の静的配列を返すのみ。

**Java**: `MermaidGenerator.render(flowDefinition)` で Mermaid stateDiagram-v2 文字列を生成し、各 flow の `mermaid` フィールドに格納。

**必要作業**
- `auth-core/src/flow/mermaid.rs` に簡易ジェネレータ (state + transitions から Mermaid 文字列を組み立て)。
- `/viz/flows` レスポンスに `mermaid: String` フィールドを追加。

**工数**: 小 (1-2 時間)。

---

## P2

### 9. flow の requires/produces 検証 (Java `FlowDefinition.build()` の 8 項目)

Java Spec `AUTH-STATE-MACHINE-SPEC.md` §3.8 に記載:
- 全 state が到達可能
- initial → terminal の path 存在
- Auto/Branch が DAG (cycle なし)
- External は各 state に最大 1 つ
- Branch の全分岐先が定義済み
- 全 path の requires/produces chain 整合
- `@FlowData` alias 重複なし
- Terminal state からの遷移なし

**現状**: Rust `auth-core/src/flow/` の FlowDefinition builder にこれらの validation は未実装 (または一部のみ)。
**工数**: 中 (startup 時の検証なので fail-fast として入れる価値あり)。

---

### 10. Audit event — LOGIN_SUCCESS / LOGOUT の DB 書き込み

**現状**
- `auth_events.rs` で SSE publish はするが、`audit_logs` テーブルへの insert は行われていない。

**Java**: `AuditService.log()` が DB insert + Redis publish を両方行う。

**必要作業**
- `handlers/oidc.rs::complete_oidc` と `handlers/auth.rs::publish_logout_event` で `AuditStore::insert` も呼ぶ。
- 他のイベント (`TENANT_SWITCH`, `PASSKEY_REGISTERED`, `MFA_SETUP` etc.) も Java と同じ粒度で。

**工数**: 小〜中 (イベント種別の洗い出し含む)。

---

### 11. admin HTML ページに pagination UI

**現状** (`handlers/extra.rs::admin_layout`)
- テーブル表示のみ。sort / search / page navigation UI なし。

**Java 側**: `volta-auth-console` (別リポの React アプリ) が担当。Java の JTE テンプレ自体は同様にシンプル。

**対応方針**: auth-server の HTML stub は最低限のまま維持し、本格 UI は volta-auth-console 側で対応 (Rust 側もそちら優先)。

**工数**: 現時点で対応不要。

---

### 12. OIDC state を DB 保存モデルに (現在は HMAC-signed stateless)

**現状** (`helpers.rs::sign_state` / `verify_state`)
- HMAC-signed state を URL に乗せる stateless モデル。Java の DB-backed `oidc_flows` モデルと異なる。

**メリット (現状)**: DB round-trip 不要、水平スケールしやすい。
**デメリット**: 使い捨てが保証されない (signature が通れば何回でもリプレイ可能 — 署名自体は有効のため)。

**判断**: #1 PKCE 実装時に `oidc_flows` テーブルを作るので、そのタイミングで併せて state も DB 保存に寄せるのが自然。→ #1 の一部として扱う。

---

## 参考: 除外した項目 (Java と同等)

以下は一見未実装に見えるが Java と挙動が揃っているので backlog からは外した:

- admin HTML ページの詳細機能 → Java も JTE テンプレで同等に簡素
- invite の email match → 現状 Rust は accept_invite が session user で受けるだけで email mismatch 判定していないが、`auth-core/InvitationStore::accept` 内でロジックあり (要検証、P2 扱い)
- SCIM Groups handler → Java も stub

---

## トラッキング

GitHub issues は起こしていない (この backlog.md がソース)。issue 化が必要になった項目から順次 `gh issue create` で移行する方針。
