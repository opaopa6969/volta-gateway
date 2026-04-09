# auth-core — WebAuthn/Passkey (webauthn-rs)

> Status: Implementing
> Date: 2026-04-09

## 概要

PasskeyVerifyProcessor のプレースホルダーを webauthn-rs による実検証に置き換える。

## 設計

- `webauthn-rs = "0.5"` (stable) を optional dep (`webauthn` feature)
- `PasskeyService` — challenge 生成 + assertion 検証をラップ
- `AuthService` に `passkey_authenticate_start()` / `passkey_authenticate_finish()` 追加

## コンポーネント

### PasskeyService (passkey.rs)

```rust
#[cfg(feature = "webauthn")]
pub struct PasskeyService {
    webauthn: Webauthn,
}

impl PasskeyService {
    pub fn new(rp_id: &str, rp_origin: &Url) -> Self;
    pub fn start_authentication(&self, credentials: &[Passkey]) -> Result<(..challenge.., ..state..)>;
    pub fn finish_authentication(&self, response: &PublicKeyCredential, state: &PasskeyAuthentication) -> Result<AuthenticationResult>;
}
```

### DB — user_passkeys テーブル (migration 008)

Java の V16 に合わせる。PasskeyStore trait で CRUD。

## 方針

webauthn-rs は 0.5.0 (latest non-dev stable)。
大きな依存なので `webauthn` feature gate で分離。
