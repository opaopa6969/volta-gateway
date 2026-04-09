# auth-core Phase 2 — Processor DB 配線

> Status: Draft → Implementing
> Date: 2026-04-09
> Depends on: Phase 1 (SqlStore DAO traits) ✅

## 概要

tramli SM Processor のプレースホルダーを実装に置き換え、
IdP・Store・TOTP・JWT を実際に呼ぶ service layer を追加する。

## 課題

tramli の `StateProcessor::process()` は **sync** (`fn process(&self, ctx: &mut FlowContext)`)。
IdpClient / Store は **async**。Processor 内で直接 `.await` できない。

## 解決: Service Layer パターン

```
HTTP Handler → AuthService (async) → IdP / Store → FlowContext に結果投入 → SM 駆動
```

Processor 自体はデータの **検証・変換** のみ行う。
async I/O は Service レイヤーが先に実行し、結果を context に入れてから SM を進める。

## 追加コンポーネント

### 1. JwtIssuer (jwt.rs に追加)

```rust
pub struct JwtIssuer {
    encoding_key: EncodingKey,
    ttl_secs: u64,
}

impl JwtIssuer {
    pub fn new_hs256(secret: &[u8], ttl_secs: u64) -> Self;
    pub fn issue(&self, claims: &VoltaClaims) -> Result<String, JwtError>;
}
```

### 2. AuthService (service.rs)

```rust
pub struct AuthService {
    pub idp: IdpClient,
    pub user_store: Arc<dyn UserStore>,
    pub tenant_store: Arc<dyn TenantStore>,
    pub membership_store: Arc<dyn MembershipStore>,
    pub invitation_store: Arc<dyn InvitationStore>,
    pub session_store: Arc<dyn SessionStore>,
    pub jwt_issuer: JwtIssuer,
    pub jwt_verifier: JwtVerifier,
}
```

#### メソッド

| メソッド | 処理 | 使う外部リソース |
|----------|------|------------------|
| `oidc_start(init)` | auth URL 生成 | IdpClient.authorization_url() |
| `oidc_callback(code, state)` | code → token → userinfo → upsert user → session | IdpClient, UserStore, TenantStore, SessionStore, JwtIssuer |
| `mfa_verify(session_id, code, secret)` | TOTP 検証 → session MFA flag | totp::verify_totp(), SessionStore |
| `token_refresh(refresh_token, session_id)` | session 検証 → JWT 再発行 | SessionStore, JwtIssuer |
| `invite_accept(code, user_id)` | invitation 消費 → membership 作成 | InvitationStore (accept は tx 内で membership も作る) |

### 3. Processor 更新

| Processor | 変更内容 |
|-----------|----------|
| OidcInitProcessor | 変更なし (validation only) |
| TokenExchangeProcessor | OidcTokenData の検証強化 (access_token 空チェック) |
| UserResolveProcessor | OidcUserData の検証 (email 必須チェック) |
| RiskCheckProcessor | 変更なし (将来 FraudAlert 連携) |
| MfaCodeGuard | 変更なし (valid フラグチェック) |
| PasskeyVerifyProcessor | 変更なし (webauthn-rs は Phase 3) |
| TokenValidator | TokenValidation の検証 (session 存在チェック) |
| TokenIssuer | NewTokens の検証 (jwt 空チェック) |

**ポイント**: Processor は sync のまま。async I/O は AuthService が行い、
結果を SM context に投入してから transition を実行。

## フロー例: OIDC callback

```
1. HTTP handler receives callback (code, state)
2. AuthService.oidc_callback(code, state):
   a. idp.exchange_code(code)          → TokenResponse
   b. idp.userinfo(access_token)       → IdpUserInfo
   c. user_store.upsert(user)          → UserRecord
   d. tenant_store.find_by_user(uid)   → Vec<TenantRecord>
   e. Build OidcCallbackData, OidcTokenData, OidcUserData
   f. engine.resume_and_execute(flow_id, data)  ← SM 駆動 (sync processors run)
   g. If Complete: session_store.create() + jwt_issuer.issue()
   h. Return session JWT
```

## ファイル構成

```
auth-core/src/
  jwt.rs         ← JwtIssuer 追加
  service.rs     ← NEW: AuthService (async orchestrator)
  lib.rs         ← pub mod service 追加
  flow/oidc.rs   ← Processor 検証強化
  token.rs       ← Processor 検証強化
```

## テスト

- JwtIssuer: issue → verify roundtrip
- AuthService: mock stores + mock IdP でユニットテスト
- 既存 SM テスト: 変更なし (Processor は検証のみなので)
