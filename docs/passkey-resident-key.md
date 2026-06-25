# Passkey: resident key を required にする（Windows Hello PIN を usernameless ログインで使う）

**Status:** Implemented (auth-core `start_registration`)
**Date:** 2026-06-25
**Scope:** `auth-core/src/passkey.rs`、関連: volta-platform ADR-007 (passkey-webauthn)

## 症状

`https://auth.unlaxer.org/login` の「パスキーでログイン」を押すと、OS のパスキー選択ダイアログに

- iPhone / Android（スマホ＝ハイブリッド / QR）
- セキュリティキー（物理キー）

しか出ず、「**この PC（Windows Hello / PIN）**」が選べない。Windows の PIN でログインしたいのに候補に現れない。

## 調査

### ログイン側（認証）は仕様どおり
`navigator.credentials.get()` は「そのサイト用のパスキーを実際に保持している認証器」しか “この PC” として提示しない。ハイブリッド/セキュリティキーは常に出る外部手段。よって「この PC」が出ない＝**この端末に auth.unlaxer.org の discoverable な passkey が登録されていない**。ログイン画面からは新規作成できない（get は既存の利用のみ）。

「パスキーでログイン」はユーザー名なしの **discoverable（usernameless）** フロー（`start_discoverable_authentication`、`allowCredentials=[]`）。この方式で候補に出るには、登録時に作る資格情報が **discoverable（resident key）** である必要がある。

### 登録側に原因
auth-core は webauthn-rs の高レベル API `Webauthn::start_passkey_registration` を使用。これは内部で固定的に下記を設定する（webauthn-rs 0.6.0-dev）:

```rust
.attestation(AttestationConveyancePreference::None)
.authenticator_attachment(None)          // platform も roaming も許可（ここは問題なし）
.require_resident_key(false)             // ← 問題
.user_verification_policy(UserVerificationPolicy::Required)
```

そして `webauthn-rs-core` の challenge 生成で `require_resident_key` は次のようにマップされる（`core.rs`）:

```rust
let resident_key = if require_resident_key {
    Some(ResidentKeyRequirement::Required)
} else {
    Some(ResidentKeyRequirement::Discouraged)   // ← false のとき discouraged
};
```

つまりクライアントへ送られる `authenticatorSelection.residentKey = "discouraged"`。この指示だと Windows Hello は **非 discoverable** な資格情報を作るため、登録自体は成功しても usernameless ログインの一覧に出てこない。

**注意:** `authenticatorAttachment` は `None`（platform 許可）、対応アルゴリズムも `secure_algs()` = ES256/ES384/RS256 で新旧 Windows Hello 両対応。つまり attachment やアルゴリズムは原因ではなく、**resident key が discouraged だったこと**が唯一の原因。

## 決定

`start_registration` で `start_passkey_registration` の戻り値 `CreationChallengeResponse` を後処理し、`authenticatorSelection` を **`residentKey: required`** に上書きする。

```rust
if let Some(sel) = ccr.public_key.authenticator_selection.as_mut() {
    sel.resident_key = Some(ResidentKeyRequirement::Required);
    sel.require_resident_key = true;
}
```

### なぜコア直叩きでなく後処理か
高レベル API には「attestation なし＋resident key required」の passkey 登録関数が無い（`start_attested_resident_key_registration` は attestation 必須で戻り型も別）。`WebauthnCore` 直叩きは `Passkey` / `finish_passkey_registration` の型が全面的に変わり大改修になる。`CreationChallengeResponse` の各フィールドは `pub` で可変なため、戻り値を上書きするのが最小・低リスク。finish 側の server-state は resident な資格情報を拒否しないので影響なし。

### 依存追加
`ResidentKeyRequirement` は webauthn-rs の prelude に再エクスポートされていないため、`webauthn-rs-core`（webauthn-rs と同一 version 0.6.0-dev、既に推移的に存在）を `webauthn` feature 配下の optional 依存として明示追加した。新規の外部コードではない。

## 検証

- `cargo check -p volta-auth-core --features webauthn` / `-p volta-auth-server` 成功
- `cargo test -p volta-auth-core --features webauthn --lib passkey` 3件 pass

## 移行メモ（運用）

- この修正は**今後の登録**に適用される。既存の非 discoverable 資格情報は遡って discoverable にはならない。
- 「この PC（PIN）」でログインしたいユーザーは、ログイン後にパスキー管理画面から **Windows Hello で再登録**する必要がある（OS ダイアログで「このデバイス」を選ぶ）。
- 以後 `/login` の「パスキーでログイン」に「この PC」が現れ、PIN で認証できる。

## 関連

- volta-platform `docs/adr/007-passkey-webauthn.md`
- 実装: `auth-core/src/passkey.rs` `start_registration`
- ログインフロー: `auth-server/src/handlers/passkey_flow.rs`（`auth_start` / discoverable `*/discover/start`）
