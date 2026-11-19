# volta-platform 以外で使う（独立デプロイ）

volta-gateway（gateway + auth-server）を、unlaxer.org / volta-platform とは別の環境で
自前の docker compose として動かす手順。ローカル開発（`http://localhost`）と、
Cloudflare Tunnel などの背後に置く公開デモ（`https://app.example.com`）の両方を想定する。

> **unlaxer.org の本番の挙動は変わらない。** ここで増えた設定はすべて「未設定なら従来どおり」の
> 既定値を持つ（[本番での値](#本番unlaxerorgでの値と挙動)）。本番は今までどおり systemd +
> インストール済みバイナリで動かす（[deploy/README.md](../deploy/README.md)）。この文書のイメージは使わない。

## 構成

```
browser ──> gateway :8080 ──(ForwardAuth /auth/verify)──> auth-server :7070 ──> postgres
               │                                              ▲
               ├── /login /callback /auth/ /mfa/ ... ─────────┘ (auth_bypass_paths)
               └── それ以外 ──> あなたのアプリ（X-Volta-* ヘッダ付き）
```

1 つのオリジン（例 `http://localhost:18080`）に gateway を置き、認証系のパスだけ
`auth_bypass_paths` で auth-server に流す。auth-server を別ホスト（`auth.example.com`）に
置く構成も可能で、その場合は `COOKIE_DOMAIN=.example.com` にしてアプリと cookie を共有する。

## すぐ試す（compose 例）

[`deploy/compose/`](../deploy/compose/) に postgres + auth-server + gateway + ダミーのバックエンド
（`traefik/whoami`、受け取ったヘッダをそのまま返す）の最小構成がある。

```bash
docker compose -f deploy/compose/docker-compose.yml up -d --build
./deploy/compose/smoke-test.sh            # 開発用マジックリンクでログイン → ヘッダ到達を確認
docker compose -f deploy/compose/docker-compose.yml down -v
```

- ホスト側のポートは既定 `127.0.0.1:18080`。`VOLTA_PORT` / `VOLTA_BIND` で変える。
  変えたら `VOLTA_PUBLIC_URL`（ブラウザから見えるオリジン）も合わせる。
  値は `deploy/compose/.env`（git 管理外）に書ける。雛形は `deploy/compose/env.example`。
- 初回起動で `AUTH_AUTO_MIGRATE=true` によりスキーマが作られる。
- `AUTH_EXPOSE_DEV_TOKEN=true` は `/auth/magic-link/send` の応答にログインリンクを入れる
  **開発専用**の設定。メールを送らずにログインできる。公開する環境では必ず外す。

smoke-test.sh がやっていること（手で叩く場合も同じ）:

```bash
curl -i http://localhost:18080/whoami                 # 未ログイン → /login?return_to=... へ
curl -s -X POST -H 'content-type: application/json' \
  -d '{"email":"dev@example.com"}' http://localhost:18080/auth/magic-link/send   # → {"link": ...}
curl -c jar -o /dev/null "<link>"                     # session cookie を受け取る
curl -b jar http://localhost:18080/whoami             # X-Volta-User-Id / X-Volta-Email / ... が並ぶ
```

## イメージのビルド

リポジトリ直下の 2 つの Dockerfile（multi-stage: `rust:1-bookworm` でビルド →
`debian:bookworm-slim` で実行、uid 10001 の非 root）。

```bash
docker build -f Dockerfile.auth-server -t volta-auth-server .
docker build -f Dockerfile.gateway     -t volta-gateway .
```

- Rust のバージョンは `--build-arg RUST_VERSION=1.xx` で固定できる（既定は `1` = 最新の stable）。
- auth-server は環境変数だけで設定する（下表）。`PORT` 既定 7070。
- gateway は `/etc/volta-gateway/volta-gateway.yaml` を読む（別パスは引数で渡す）。
  非 root なので `server.port` は 1024 以上（例 8080）にして、ホスト側で 80/443 に割り当てる。
  ヘルスチェックは `volta-gateway --health-check <server.port>`。
  API 経由の設定変更は `VOLTA_CONFIG_OVERLAY=/var/lib/volta-gateway/volta-gateway.overlay.json` に書かれる。

## 公開環境（例: Cloudflare Tunnel の背後）

`https://app.example.com` で公開し、Tunnel が gateway の 8080 に繋がる場合:

| 設定 | 値 |
|---|---|
| `BASE_URL`（auth-server） | `https://app.example.com` |
| `COOKIE_DOMAIN` | 空（単一ホスト）。auth を別サブドメインに分けるなら `.example.com` |
| `ALLOWED_RETURN_TO_DOMAINS` | 通常は不要（`BASE_URL` のホストは常に許可）。他ホストへ戻すなら列挙 |
| `FORCE_SECURE_COOKIE` | `true`（TLS は Tunnel で終端されるので明示する） |
| `AUTH_EXPOSE_DEV_TOKEN` | **設定しない** |
| `JWT_SECRET` / DB パスワード | 必ず固有の値に |
| gateway `auth.auth_public_url` | `https://app.example.com` |
| gateway `routing[].host` | `app.example.com` |

IdP でログインさせる場合は下の「汎用 OIDC」を設定し、IdP 側の redirect URI に
`${BASE_URL}/callback` を登録する。

## 環境変数（今回増えたもの・意味が広がったもの）

### auth-server

| 変数 | 既定（未設定時） | 説明 |
|---|---|---|
| `ALLOWED_RETURN_TO_DOMAINS` | `COOKIE_DOMAIN` から導出。それも空なら `BASE_URL` のホストのみ | ログイン/ログアウト後に戻してよいホスト。カンマ区切り。`example.com` はそのホストのみ、`.example.com` / `*.example.com` はそのドメインとサブドメイン。`BASE_URL` のホストは常に許可。相対パス（`/app`）は常に許可。スキームは https、`BASE_URL` が http のときだけ http も可 |
| `SYSTEM_ADMIN_EMAILS` | 未設定（＝誰もいない） | テナントを横断する管理 API（`/api/v1/admin/tenants`・`/api/v1/admin/users` の一覧・`/api/v1/admin/sessions`・`/api/v1/admin/keys`・`/api/v1/users/{id}/data`・`/api/v1/users/{id}/export`・`/api/v1/admin/outbox/flush`・`/api/v1/oauth/clients`・`/scim/v2/*`・`/viz/auth/stream` 等）を使えるシステム管理者のメールアドレス。カンマ区切り、大小無視。cookie ログインのみ（Bearer 不可）。テナントの ADMIN / OWNER であることは条件にならない。未設定なら横断 API は全員 403（テナント単位の管理は従来どおり） |
| `AUTH_AUTO_MIGRATE` | `false` | `true` で起動時に `auth-core/migrations` を適用（sqlx、`_sqlx_migrations` 表で管理）。**既に手で作ったスキーマ（`users` はあるが `_sqlx_migrations` が無い DB）では起動を拒否する** |
| `IDP_ISSUER_URL` | 未設定 | 汎用 OIDC の issuer。設定すると起動時に `/.well-known/openid-configuration` を読んで各エンドポイントを埋め、`id_token` を検証する |
| `IDP_AUTH_URL` / `IDP_TOKEN_URL` / `IDP_USERINFO_URL` / `IDP_JWKS_URL` | 未設定 | エンドポイントの明示指定（discovery より優先） |
| `IDP_SCOPES` | provider の既定（`openid email profile` 等） | 空白またはカンマ区切り |
| `IDP_DISPLAY_NAME` | provider から（google → Google、github → GitHub、不明 → SSO） | ログイン画面のボタン「〇〇 でログイン」 |

既存の変数で、効く範囲が広がったもの:

| 変数 | 変化 |
|---|---|
| `COOKIE_DOMAIN` | 一時アクセス cookie（`__volta_temporary_access`）の `Domain` にも使う（以前は `.unlaxer.org` 固定）。空ならホスト限定 cookie |
| `BASE_URL` / `FORCE_SECURE_COOKIE` | 一時アクセス cookie の `Secure` は「`FORCE_SECURE_COOKIE=true` または `BASE_URL` が `http://` でない」とき付く（以前は常に付与）。一時アクセスの `return_to` は `BASE_URL` が http のときだけ http を受け付ける |
| `IDP_PROVIDER` | 組み込み（google / github / microsoft / linkedin / apple）以外の名前（例 `oidc`）も、`IDP_ISSUER_URL` と組み合わせて使える |
| `WEBAUTHN_RP_ID` | 変更なし（passkey の本体は従来からこれを使う）。未使用の placeholder flow に残っていた `rp_id: "unlaxer.org"` 決め打ちは、呼び出し側から渡す形に変えた |

旧 Java 実装の `ALLOWED_REDIRECT_DOMAINS` は Rust 版では読まない（意図的に別名にした。
本番 env にこの行が残っていても挙動は変わらない）。

### gateway（YAML）

| キー | 既定 | 説明 |
|---|---|---|
| `config_sources[].base_domain`（`type: services-json`） | `unlaxer.org` | 旧形式（配列）の services.json で `host` を省いたサービスのホスト名 `<name>.<base_domain>` |

### 汎用 OIDC の例（Keycloak）

```bash
IDP_PROVIDER=oidc
IDP_ISSUER_URL=https://keycloak.example.com/realms/myrealm
IDP_CLIENT_ID=volta
IDP_CLIENT_SECRET=...
IDP_DISPLAY_NAME=Keycloak
```

discovery に失敗した場合（IdP がまだ起動していない等）は auth-server を止めずにエラーを記録し、
IdP ログインだけが使えない状態で起動する（マジックリンクと passkey は動く）。再起動で再取得する。
discovery の `issuer` が `IDP_ISSUER_URL` と食い違う場合は設定ミスとして起動を止める。

## 本番（unlaxer.org）での値と挙動

本番の auth-server env は `BASE_URL=https://auth.unlaxer.org`、`COOKIE_DOMAIN=.unlaxer.org`、
`FORCE_SECURE_COOKIE=true`、`IDP_PROVIDER=google` で、今回の新しい変数はどれも設定していない。

| 項目 | 本番での解決結果 | 以前との比較 |
|---|---|---|
| ログアウトの `return_to` | `COOKIE_DOMAIN` から「https の unlaxer.org とそのサブドメイン」 | 同じ（単体テストで旧判定と突き合わせている）。ただし `https://user@host` 形式の userinfo 付き URL は新たに拒否 |
| ログインの `return_to` | 同上 | **新たに検証する**（以前は無検証＝オープンリダイレクト）。許可外の値は `BASE_URL/` に置き換わる。gateway から来る `https://<svc>.unlaxer.org/...` は従来どおり通る |
| SAML ACS の `return_to`（RelayState） | 同上 | **新たに検証する**。許可外は `/select-tenant` |
| 一時アクセス cookie | `Domain=.unlaxer.org; ... HttpOnly; Secure; SameSite=Lax` | バイト単位で同じ（単体テストあり） |
| IdP | Google の組み込みエンドポイント、`id_token` 検証なし（issuer 未設定） | 同じ。ボタン表記も「Google でログイン」 |
| マイグレーション | 自動適用しない | 同じ。本番 DB は `_sqlx_migrations` が無いので、誤って `AUTH_AUTO_MIGRATE=true` にしても起動拒否で止まる |
| gateway services.json | `<name>.unlaxer.org` | 同じ（`base_domain` 未設定） |

## 既知の制約

- **既定外ポートでの IdP ログイン後の戻り先**: gateway は ForwardAuth に渡す
  `X-Forwarded-Host` からポートを落とす（本番の振る舞いのまま変えていない）。そのため
  `http://localhost:18080/app` で未ログインだと `return_to=http://localhost/app` になり、
  IdP ログイン後にポート 80 側へ戻る。マジックリンクは `BASE_URL/` に戻るので影響しない。
  ローカルでも IdP を使うなら gateway をポート 80（または 443）で公開する。

## マイグレーションの注意

- `AUTH_AUTO_MIGRATE` は sqlx の migrator を使い、適用済みのバージョンとチェックサムを
  `_sqlx_migrations` に記録する。**適用済みの migration ファイルを後から書き換えると、
  次回起動でチェックサム不一致のエラーになる**。スキーマ変更は常に新しい番号のファイルで足す。
- 手でスキーマを作った既存 DB をこの方式に移す手順は用意していない（起動拒否になる）。
  新しい DB で使うこと。
