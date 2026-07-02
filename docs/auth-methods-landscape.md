# 認証・認可手法の全体マップと現状ギャップ分析

> **目的**: 世の中で使われている認証(authn)・認可(authz)手法を体系的に網羅し、
> volta の auth 実装（Rust `auth-core`/`auth-server`、および Java `volta-auth-proxy`）が
> どこまでカバーしているかを特定し、足りない部分・改善余地を優先度付きで示す。
>
> **想定読者**: auth の設計・実装を進めるエンジニア、ロードマップを決める人。
>
> **スコープ方針**: §2 の手法カタログは実装非依存（プロトコル/UX の一般論）。
> §3 のカバレッジは Rust 実装を基準に記載し、Java 版は「spec さえあれば後で追随」という
> 前提で、同じ設計を流用できるよう実装詳細を抽象化して書く。
>
> 最終更新: 2026-07-02

---

## 1. エグゼクティブサマリ

volta の Rust auth は、**フェデレーション RP（OIDC クライアント / SAML SP）＋パスワードレス
（passkey / magic link）＋ TOTP MFA ＋ M2M ＋ マルチテナント運用**という軸で、
すでに商用水準の広さを持つ（本番 `auth.unlaxer.org` は Rust 版で稼働）。

一方で、世の中の auth 手法という物差しで見ると、次の 3 つの「面」がまるごと欠けている：

| 欠けている面 | 具体的に無いもの | 効いてくるユースケース |
|---|---|---|
| ~~A. 自前 OpenID Provider (OP)~~ ✅ **Phase 3 実装済** | `/authorize`(code+PKCE)・discovery・consent・introspection/revocation・refresh(rotation+reuse検知)・`/userinfo`・RP-initiated logout。RS256署名＋実JWKS | 「自社/ネイティブアプリを volta で認可する」土台が完成。実PG検証済 |
| **B. マルチアカウント session ＋ account chooser** | 1 ブラウザに複数 *identity* をぶら下げる仕組み、`prompt=select_account`、Google 風の右上アカウント切替 pane | 「複数 Google アカウントを切り替える」あの UX |
| **C. クロスデバイス / QR サインイン** | Device Authorization Grant (RFC 8628)、QR 承認チャネル、CIBA、hybrid passkey の明示制御 | 「スマホで QR を読んでネイティブアプリ/TV/CLI を認証・認可」 |

加えて、**リスクベース適応認証**（Java 版は `RiskCheckProcessor` を持つが Rust は placeholder）、
**sender-constrained token（DPoP / mTLS-bound）**、**step-up 認証の実配線**、
**passkey の 2FA/step-up 用途・AAGUID メタ表示**などが improvement 余地。

本ドキュメントは §2 でカタログ、§3 でカバレッジ表、§4 でギャップ、§5 で実装ロードマップ（設計）を示す。

---

## 2. 認証・認可手法カタログ（世の中の全体マップ）

認証の世界は「**誰であるかをどう証明するか（authn factors）**」「**その証明をどの
プロトコルで運ぶか（federation/transport）**」「**発行された権限をどう表現・制約するか
（tokens/session）**」「**継続的にどう評価するか（adaptive/continuous）**」の層で整理できる。

### 2.1 Knowledge factor（知識要素）
- **Password** — 最弱。ハッシュは argon2id 推奨（次点 bcrypt / scrypt / PBKDF2）。付随機能: 強度判定、
  breached-password チェック（HIBP k-anonymity）、lockout、reset フロー。
- **PIN** — ローカル（platform authenticator の UV）に閉じるのが今日的。サーバ側 PIN は非推奨。
- **Security questions** — 事実上の非推奨（低エントロピー・ソーシャルで漏れる）。

### 2.2 Possession factor（所持要素）— OTP / push / hardware
- **TOTP (RFC 6238) / HOTP (RFC 4226)** — 認証アプリ。共有秘密＋時刻。
- **Email OTP / SMS OTP** — 配送型ワンタイム。SMS は SIM swap リスクありで factor としては弱め。
- **LINE / messaging OTP** — 地域特化チャネル。
- **Push 承認（decoupled）** — 専用アプリに push、ユーザが承認/拒否。number-matching で
  MFA fatigue 攻撃を緩和。標準化版が **CIBA**（§2.6）。
- **Hardware OTP token** — YubiKey OTP、RSA SecurID など。

### 2.3 Inherence / possession — FIDO2・WebAuthn・passkey
- **WebAuthn / FIDO2** — 公開鍵暗号のチャレンジレスポンス。フィッシング耐性が本質価値。
  - **device-bound credential**（authenticator に固定）vs **passkey = discoverable + synced**
    （クラウド同期、resident key）。
  - **UV（user verification）**: 生体/PIN。**UP（user presence）**: タッチ。
  - **conditional UI（autofill）**: ログイン欄に候補を出す `mediation: conditional`。
  - **attestation**: authenticator の出自証明。**FIDO MDS** で AAGUID→機種メタ照合、
    enterprise attestation でモデル制限。
  - **cross-device (hybrid transport / 旧 caBLE)**: PC の画面に QR→スマホで承認。
  - **backup eligibility / state**: passkey が同期対象か・実際に同期済みか。
  - 用途: **1st factor（passwordless）**、**2nd factor**、**step-up / reauth**。

### 2.4 Passwordless（factor の組み合わせ方）
- **Magic link** — メールのワンタイム URL。
- **Email/SMS OTP ログイン** — コード入力で 1st factor。
- **Passkey 1st factor** — §2.3。
- **“last-used method” 記憶** による摩擦低減。

### 2.5 Federation（authn を外部/自前に委譲）
- **OIDC — Relying Party (RP / client)**: 外部 IdP でログイン（＝ソーシャルログイン）。
  - Discovery、PKCE、nonce、`state`、id_token 検証（iss/aud/exp/nonce/at_hash）、userinfo。
  - **アカウントリンク**（1 ユーザに複数 IdP 紐付け）。
- **OIDC — OpenID Provider (OP / 自前 IdP)**: 自分が IdP になり下流アプリへ ID を発行。
  - Endpoints: `/.well-known/openid-configuration`、`/authorize`、`/token`、`/userinfo`、`/jwks`、
    `/end_session`(RP-initiated logout)、`introspection`、`revocation`、`registration`(DCR)。
  - **grant**: authorization_code(+PKCE)、refresh_token、client_credentials、device_code、
    （legacy: implicit / password — 非推奨）。
  - **prompt**: `none`/`login`/`consent`/`select_account`。**max_age**、**login_hint**、**id_token_hint**、**acr_values**。
  - **consent 画面**、スコープ、audience。
  - **PAR (RFC 9126)**、**JAR/JARM**（署名付き request/response）、**RAR (RFC 9396)**（細粒度認可）。
- **OAuth 2.0 grants（authz）**: authorization_code / client_credentials / refresh_token /
  device_code / **token exchange (RFC 8693, 委譲・impersonation)** / （legacy: implicit, ROPC）。
- **SAML 2.0** — **SP**（外部 IdP を受ける）／**IdP**（自分が発行）。SP-init / IdP-init、
  署名・暗号（XML-DSig/Enc）、SLO（single logout）、metadata。
- **LDAP / Kerberos / AD** — 企業内。SPNEGO、Windows 統合認証。
- **社会的ログイン** — 実体は OIDC/OAuth RP（Google/Apple/Microsoft/GitHub/LINE…）。

### 2.6 クロスデバイス / 分離型認証
- **Device Authorization Grant (RFC 8628)** — 入力困難デバイス（TV/CLI/IoT）。
  `device_code`+`user_code`、ユーザは別端末で verification URI に code 入力、デバイスは polling。
  QR に verification_uri_complete を載せれば「読むだけ」。
- **QR チャネルログイン**（WhatsApp Web / ChatGPT desktop 系）— 未ログイン端末が QR を表示、
  ログイン済みスマホが読んで承認→端末が session を取得。標準化されておらず自前チャネル実装。
  （Device Grant を土台にすると標準寄りにできる。）
- **CIBA (Client-Initiated Backchannel Authentication)** — RP がバックチャネルで認証開始、
  ユーザのスマホに push、承認後トークン。poll / ping / push モード。
- **FIDO hybrid** — §2.3。passkey のクロスデバイス版。

### 2.7 Machine / service 認証
- **client_credentials** — サービス間。client secret / private_key_jwt / mTLS client auth。
- **JWT bearer grant (RFC 7523)** — 事前信頼した JWT でトークン取得。
- **mTLS**（RFC 8705）— 相互 TLS、証明書束縛トークン。
- **Workload identity** — SPIFFE/SPIRE、クラウドの metadata identity、OIDC federation（GitHub Actions 等）。
- **API key** — 単純だが失効/スコープ管理が課題。

### 2.8 Token・session・ライフサイクル
- **Session cookie** — HttpOnly/Secure/SameSite、固定化対策（ログイン時 rotate）、idle/absolute TTL、
  同時 session 管理、revocation。
- **JWT (access/id)** — 署名(HS/RS/ES/EdDSA)、鍵ローテーション＋JWKS、短命化。
- **Refresh token** — **rotation ＋ reuse detection**（盗難検知）、失効。
- **Sender-constrained token** — **DPoP (RFC 9449)** / mTLS-bound。bearer 盗難耐性。
- **Introspection (RFC 7662) / Revocation (RFC 7009)**。
- **Logout** — RP-initiated（`end_session`）、**front-channel** / **back-channel** logout、
  `check_session_iframe`（OIDC Session Management）、global sign-out。
- **Token exchange (RFC 8693)** — 委譲/ダウンスコープ/impersonation。

### 2.9 マルチアカウント / account chooser
- 1 ブラウザに**複数の identity**（別ユーザ）を同時保持し、`/u/0` `/u/1` や `authuser=` で選択。
- `prompt=select_account` でアカウント選択画面を強制。
- Google 風「右上のアカウント pane」＝ multi-session cookie ＋ chooser UI ＋ OP の select_account。
- **テナント切替**（同一 identity 内のワークスペース切替）とは別概念。

### 2.10 適応 / 継続的認証（adaptive & continuous）
- **リスクベース認証** — impossible travel、新デバイス/新 IP、IP 評価、時間帯、velocity。
  結果で allow / step-up / block。
- **Step-up 認証** — 重要操作の直前に factor を追加要求（`acr`/`amr` を上げる）。
- **継続的アクセス評価** — **CAEP / Shared Signals Framework (SSF)**：session 中の状態変化
  （デバイス非準拠、資格失効）を受けて即時失効。
- **bot/abuse 対策** — CAPTCHA、device fingerprint、credential-stuffing 検知。

### 2.11 プロビジョニング / ライフサイクル
- **SCIM 2.0 (RFC 7643/7644)** — IdP からのユーザ/グループ同期。
- **JIT provisioning** — 初回 SSO 時にユーザ生成。
- **招待フロー**、承認ワークフロー、deprovision / offboarding、
  **RBAC / ABAC / ReBAC（関係ベース, Zanzibar 系）**、entitlement 管理。

### 2.12 リカバリ / アカウント回復
- **Recovery codes**（一度きり）、バックアップ factor、
- **social recovery / trusted contacts**、サポート介在回復（本人確認）、
- 全 factor 喪失時の再登録フロー（身元確認とセットで慎重に）。

### 2.13 新興 / 先端
- **Verifiable Credentials** — **OID4VCI**（発行）/ **OID4VP**（提示）、SD-JWT VC、
  **mDL (ISO 18013-5)**、DID。
- **Wallet ベース ID**、EU eIDAS 2.0 / EUDI wallet。
- **Passkey attestation の企業利用**（MDS 連携）、**AI エージェント向け委譲**（token exchange 応用）。

---

## 3. 現状カバレッジ・マトリクス（volta Rust 実装基準）

凡例: ✅ 実装済 / 🟡 部分的・要改善 / ❌ 未実装 / ⛔ 意図的に非対応 / 🧩 別コンポーネント委譲

| # | 手法（§参照） | 状態 | 実装箇所 / 備考 |
|---|---|---|---|
| **知識要素** |
| 3.1 | Password | ⛔ | passwordless-first 設計。`AUTH_PASSWORD_ENABLED=false` 固定。ハッシュ器も非搭載（外部 IdP 委譲） |
| 3.2 | Password reset | ⛔→🟡 | password 無しゆえ reset も無し。ただし `flow/password_reset.rs` に**状態機械の骨格は存在**（将来用） |
| **所持要素** |
| 3.3 | TOTP (RFC 6238) | ✅ | `totp.rs`（SHA-1/6桁/30s/±1窓）、secret は AES-256-GCM 暗号化保管、setup/verify/delete API |
| 3.4 | Recovery codes | ✅ | SHA-256 ハッシュ、一度きり、regenerate API |
| 3.5 | Email OTP | 🟡 | `login_challenge` に `EMAIL_OTP` 状態あり。magic link は別途 ✅。OTP コード配送は notification 経由 |
| 3.6 | SMS OTP / LINE OTP | 🟡 | flow に `SMS_OTP`/`LINE_OTP` 定義あり、notification provider（Twilio/LINE）あり。**ログイン factor としての実配線は要確認** |
| 3.7 | Push 承認 (decoupled) | ❌ | 無し（CIBA も無し, §3.24） |
| **FIDO2 / passkey** |
| 3.8 | WebAuthn 登録 | ✅ | `passkey.rs`、resident key 強制、attestation 検証（webauthn-rs） |
| 3.9 | passkey 認証（discoverable / 非） | ✅ | discover/start・finish、clone 検知（sign counter atomic） |
| 3.10 | conditional UI (autofill) | ✅ | feature `conditional-ui` 有効、`/login` で起動 |
| 3.11 | 複数 credential / transports / AAGUID / backup 追跡 | ✅ | `PasskeyRecord` に列あり |
| 3.12 | passkey を **2FA / step-up** に使用 | ❌ | 現状 passkey は 1st factor 専用。2 要素目・reauth 用途の配線なし |
| 3.13 | AAGUID→機種メタ表示（FIDO MDS） | ✅ | **Phase 4b 実装済**。FIDO MDS 主要 AAGUID の静的マップ（`aaguid.rs`）、passkey 一覧が `authenticator` に機種名（iCloud/YubiKey/Windows Hello…）を返す |
| 3.14 | hybrid / クロスデバイス passkey の明示制御 | 🟡 | ブラウザ/OS 任せ。サーバからの明示的な hint/UX 制御はなし |
| **パスワードレス** |
| 3.15 | Magic link | ✅ | send/verify、15分TTL、単回、ユーザ自動生成 |
| **フェデレーション RP** |
| 3.16 | OIDC RP（ソーシャルログイン） | ✅ | `idp.rs`（Google/GitHub/Microsoft/LinkedIn/Apple）、PKCE S256、nonce、at_hash、`oidc.rs` id_token 検証 |
| 3.17 | 複数 IdP ルーティング（`?provider=`） | 🟡 | backlog P3。基盤はあるが UI ルーティング未完 |
| 3.18 | アカウントリンク（1ユーザ複数IdP） | ❌ | `user.google_sub` 中心。複数 provider 紐付けの明示モデルなし |
| 3.19 | SAML **SP** | 🟡🧩 | ルート・XML-DSig 実装あり。本番は Java sidecar 併用（DD-005） |
| **フェデレーション OP（自前 IdP）** |
| 3.20 | OIDC **OP** / 認可サーバ | ✅ | **Phase 3a+3b 実装済**。3a=RS256署名基盤＋実JWKS。3b=discovery/`/authorize`(code+PKCE+consent)/`/oauth/token`(code,refresh)/`/userinfo`/`/oauth/introspect`/`/oauth/revoke`/`/end_session`＋client登録。`handlers/op.rs`、実PGでフロー通し検証済 |
| 3.21 | authorization_code + PKCE 発行側 | ✅ | **Phase 3b 実装済**。`/authorize`＋`/oauth/token`(code)。PKCE **S256必須**、code単回・短命(120s)・hash保管、consent永続。id_token(RS256, iss/aud/nonce/email) 発行 |
| 3.22 | SAML **IdP** | ❌ | 自分が IdP になる側は無し |
| **クロスデバイス** |
| 3.23 | Device Authorization Grant (RFC 8628) | ✅ | **Phase 1 実装済**。`/oauth/device_authorization`＋`/oauth/token`(device_code polling)＋`/device`承認UI。device_code は hash 保管、user_code 短命、slow_down 制御。`flow/device_grant.rs`＋`store/device_grant.rs`＋migration 028 |
| 3.24 | QR チャネルログイン / CIBA | 🟡 | QR は Device Grant の `verification_uri_complete` で対応（クライアント側でQR描画）。CIBA は未 |
| **Machine** |
| 3.25 | client_credentials | ✅ | `/oauth/token`、constant-time 比較 |
| 3.26 | private_key_jwt / mTLS client auth / JWT bearer | ❌ | client secret のみ |
| 3.27 | Workload identity federation | ❌ | 無し |
| **Token / session** |
| 3.28 | Session cookie（rotate/revoke/multi） | ✅ | `session.rs`、失効・rotation・複数 session・MFA マーカー |
| 3.29 | JWT 署名（HS/RS/ES）＋JWKS＋鍵ローテ | ✅ | `jwt.rs`/`jwks.rs`、rotate/revoke。**Phase 3a で `/.well-known/jwks.json` が実RS256公開鍵を公開**（従来は空配列）。内部セッションJWTはHS256のまま（gateway共有秘密検証）、OP用にRS256鍵を別立て |
| 3.30 | Refresh token（rotation + reuse 検知） | ✅ | **Phase 3b 実装済**。OP の refresh grant で **rotation ＋ reuse 検知**（再利用検知で family 一括失効, OAuth Security BCP）。`oauth_refresh_tokens.family_id`、hash保管。実PG検証済 |
| 3.31 | DPoP / mTLS-bound token | ❌ | 無し（bearer のみ） |
| 3.32 | Introspection / Revocation エンドポイント | ✅ | **Phase 3b 実装済**。`POST /oauth/introspect`(RFC 7662, client認証要)・`POST /oauth/revoke`(RFC 7009, refresh失効) |
| 3.33 | Logout（RP-initiated / front/back-channel） | 🟡 | 自 session logout ✅、**Phase 3b で RP-initiated `/end_session`**（post_logout_redirect_uri は同一オリジン検証）追加。front/back-channel logout はまだ |
| 3.34 | Token exchange (RFC 8693) | ✅ | **Phase 5 実装済**。`/oauth/token`(grant=token-exchange)、access token を down-scope（拡大は拒否）＋`act`委譲クレーム。AIエージェント委譲等に利用。実サーバ検証済 |
| **マルチアカウント** |
| 3.35 | テナント切替 | ✅ | switch-tenant / select-tenant / switch-account |
| 3.36 | マルチ *identity* session（Google風 chooser） | ✅ | **Phase 2 実装済**。`__volta_accounts` cookie に複数 session を保持、`GET /accounts` chooser（使用中/切替/追加/個別・全体サインアウト）。`/login?add=1` で追加。遅延リコンサイル方式でログイン完了8箇所は無改変。`handlers/accounts.rs` |
| 3.37 | `prompt=select_account`（RP側→上流IdP） | ✅ | **Phase 2 実装済**。`/login?add=1` が上流 Google 等へ `prompt=select_account` を付与（`idp.rs` `authorization_url_pkce_prompt`）。自前OPとしての select_account は Phase 3 |
| **適応 / 継続** |
| 3.38 | リスクベース認証 | ✅ | **Phase 4a+4c 実装済**。4a=`risk.rs`エンジン。4c=OIDC callback配線: `__volta_kd` known-deviceクッキー（新デバイス判定, `risk_known_devices`表, migration 030）＋直近session IP比較→`risk::evaluate`→**Block は拒否(LOGIN_BLOCKED監査)**、session に IP/UA 記録。fail-open（store失敗→Allow）。**geo/impossible-travel と step-up強制は今後** |
| 3.39 | Step-up 認証 | 🟡 | `PolicyResult::RequireMfa/RequireReauth` の型はあるが実配線は限定的 |
| 3.40 | CAEP / SSF（継続的評価） | ❌ | 無し |
| 3.41 | bot / abuse（CAPTCHA 等） | 🟡 | rate limit はあり ✅。CAPTCHA/fingerprint なし |
| **プロビジョニング** |
| 3.42 | SCIM 2.0 | ✅ | Users/Groups CRUD（簡易実装、tenant scope は要強化） |
| 3.43 | JIT provisioning | ✅ | magic link / OIDC 初回ログインでユーザ自動生成 |
| 3.44 | 招待 / RBAC | ✅ | invite フロー、4 階層 RBAC（OWNER>ADMIN>MEMBER>VIEWER） |
| 3.45 | ABAC / ReBAC | 🟡 | policy engine は RBAC＋簡易 condition。関係ベースは無し |
| **リカバリ** |
| 3.46 | Recovery codes | ✅ | §3.4 |
| 3.47 | social recovery / 全factor喪失回復 | ❌ | 無し |
| **新興** |
| 3.48 | Verifiable Credentials / mDL / OID4VP | ❌ | 無し（先端・要否要検討） |

### 3.x 数字で見る現状
- 実装済 HTTP エンドポイント **120+**、DB migration **27**、auth flow 状態機械 **9 種**。
- 「1st factor を提供する側（RP＋passwordless）」としては**ほぼ完成域**。
- 「**認可サーバ／IdP になる側（OP）**」は**ゼロ**。ここが最大の空白で、
  §1 の A/B/C はいずれもここに根がある。

---

## 4. ギャップ分析（優先度付き）

各ギャップを **価値（ユーザ要望・戦略的重要度）× コスト（実装/検証）× 依存** で評価。

### P0 — 基盤（他が乗る土台）

**G1. OpenID Provider (OP) コア** … §3.20/3.21
自社/ネイティブアプリを volta で「ログイン・認可」できるようにする土台。
- discovery、`/authorize`（authorization_code + PKCE）、`/token`（code/refresh）、
  `/userinfo`、consent、`/end_session`。
- これが無いと B（account chooser の `select_account`）も C（native 認可）も“標準の形”にできない。
- **依存**: 既存の session/JwtIssuer/policy を再利用可能。DB に `oauth_clients` / `authz_codes` /
  `refresh_tokens` / `consents` を追加。

**G2. マルチアカウント session ＋ account chooser** … §3.36/3.37（＝要望 B）
- 1 ブラウザに複数 identity。cookie を「session リスト」に拡張、`authuser` 選択、chooser UI。
- OP の `prompt=select_account` と接続。
- **依存**: G1 と相互補完だが、chooser 自体は OP なしでも「volta 自身のログイン UI」として先行実装可。

### P1 — 要望直撃・標準ベース

**G3. Device Authorization Grant (RFC 8628) ＋ QR 承認**（＝要望 C）… §3.23/3.24
- `device_authorization` エンドポイント、`user_code`/`device_code`、polling、
  verification UI（承認/拒否）、QR（`verification_uri_complete`）。
- ネイティブアプリ/CLI/TV から「QR 読む→スマホで承認→トークン受領」。
- **依存**: G1 のトークン発行を使うと綺麗（単体でも成立可）。**自己完結度が高く最初の実装スライスに好適**。

**G4. Passkey の 2FA / step-up 用途 ＋ AAGUID メタ**（＝要望 passkey 改善）… §3.12/3.13
- passkey を「2 要素目」「重要操作前の reauth」に使う配線。
- FIDO MDS で AAGUID→機種名/アイコン表示。
- **依存**: 既存 passkey.rs を拡張、step-up 判定（G6）と接続。

**G5. リスクベース適応認証エンジン**（Java パリティ）… §3.38/3.39
- Rust の placeholder を実エンジンに。新デバイス/新IP/impossible travel→step-up/block。
- Java 版 `RiskCheckProcessor` の移植で parity 回復。

### P2 — セキュリティ強化・標準準拠

- **G6. Step-up の実配線**（`acr`/`amr`、`PolicyResult::RequireMfa` の実効化）… §3.39
- **G7. Refresh token（rotation + reuse 検知）** … §3.30（G1 と同時が自然）
- **G8. Introspection / Revocation エンドポイント** … §3.32
- **G9. DPoP（sender-constrained token）** … §3.31
- **G10. アカウントリンク（複数 IdP）** … §3.18
- **G11. front/back-channel logout** … §3.33

### P3 — 拡張・先端（要否判断込み）

- **G12. CIBA** … §3.24（Push 承認基盤ができれば）
- **G13. Token exchange (RFC 8693)**（AI エージェント委譲などに効く）… §3.34
- **G14. SAML IdP / IdP-init** … §3.22
- **G15. ReBAC（Zanzibar 系）/ ABAC 強化** … §3.45
- **G16. social recovery / 全 factor 喪失回復** … §3.47
- **G17. CAEP / SSF 継続的評価** … §3.40
- **G18. Verifiable Credentials（OID4VCI/VP, mDL）** … §3.48（先端・別プロジェクト級）

---

## 5. 実装ロードマップ（設計）

> 方針: **標準ベース（RFC/OIDC）を土台に、要望 A/B/C を最短で満たす**縦スライスから着手。
> 各フェーズは `auth-core`（flow/store/record）＋`auth-server`（handler/route）＋migration＋test の
> 一貫スライスとして切る。Java 版は同 spec を後追い実装できるよう、
> ロジックは flow（tramli 状態機械）に寄せてプロトコル非依存に保つ。

### Phase 1 — Device Grant ＋ QR 承認（要望 C / G3）〔✅ 実装済 2026-07-02〕
自己完結度が高く、既存 JwtIssuer/session を再利用でき、要望に直接刺さるため先頭に置いた。
**実装済み**: 下記エンドポイント・store・flow・migration 028・統合テスト（実PG）。

- **新エンドポイント**
  - `POST /oauth/device_authorization` → `{device_code, user_code, verification_uri, verification_uri_complete, expires_in, interval}`
  - `POST /oauth/token`（`grant_type=urn:ietf:params:oauth:grant-type:device_code`）
    → polling。`authorization_pending` / `slow_down` / `access_denied` / `expired_token`。
  - `GET /device`（`?user_code=` / QR の complete URI）→ 承認 UI（要ログイン session）
  - `POST /device/approve`・`POST /device/deny`
- **store/record**: `device_authorization_grants`（device_code hash, user_code, client_id, scope,
  status[pending/approved/denied/expired], user_id, tenant_id, created_at, expires_at, last_polled_at, interval）
- **flow**: `flow/device_grant.rs`（PENDING→APPROVED/DENIED/EXPIRED、polling は slow_down 制御）
- **QR**: サーバは `verification_uri_complete` を返すのみ（QR 生成はクライアント）。
  ただし利便性のため `GET /device/qr?code=` で SVG/PNG を返すヘルパも可。
- **セキュリティ**: `user_code` は高エントロピー・短命・レート制限、`device_code` は hash 保管、
  承認画面に client 名/scope 明示（consent 兼用）、polling backoff。
- **test**: 発行→承認→token、拒否、期限切れ、slow_down。

### Phase 2 — マルチアカウント session ＋ account chooser（要望 B / G2）〔✅ 実装済 2026-07-02〕
- **cookie モデル拡張**: `__volta_session`（アクティブ）＋ `__volta_accounts`
  （既知 session id リスト）。各 id は SessionStore で都度検証・prune。
- **UI**: `GET /accounts` chooser（使用中バッジ・切替・追加・個別/全体サインアウト）。
  ログイン後ランディングからリンク。
- **エンドポイント**: `GET /accounts`、`POST /accounts/{use,signout,signout-all}`、
  `GET /login?add=1`（別アカウント追加＝上流IdPへ `prompt=select_account`）。
- **設計の肝**: **遅延リコンサイル方式**。ログイン完了8箇所（oidc/magic/passkey/saml/mfa…）を
  一切改変せず、`/login?add=1`（現アクティブを保存）と `/accounts`（アクティブを取込＋検証）
  だけで多アカウントが成立。
- **未**: 別アカウント選択時の step-up 再認証は Phase 4 と接続予定。

### Phase 3 — OpenID Provider (OP) コア（G1）＋ refresh/introspection（G7/G8）

**Phase 3a — 署名基盤〔✅ 実装済 2026-07-02〕**
- OP用 **RS256 鍵**の生成（`op_keys::generate_rsa_pem`）・`signing_keys` 永続・起動時
  ブートストラップ（既存鍵を再利用する冪等設計）。`rotate_key` も実RSA生成に更新。
- `/.well-known/jwks.json` が実公開鍵(JWK: kty/alg/use/kid/n/e)を公開（従来は空配列）。
- `JwtIssuer` に `kid` ヘッダ対応（`new_rsa_with_kid`）、OP issuer を `AppState.op_issuer` に配線。
- **内部セッションJWTは HS256 のまま**（gateway が共有秘密で検証する契約を温存）、OP用に別鍵。
- 実DB通しで検証済（boot→鍵生成→JWKS公開→再起動で同一kid再利用）。

**Phase 3b — OP エンドポイント〔✅ 実装済 2026-07-02〕**
- **discovery**: `/.well-known/openid-configuration`（jwks は 3a を再利用）。
- **`/authorize`**: authorization_code + **PKCE S256必須**、`scope`/`nonce`/`state`/`prompt`
  (`none`/`consent`)、consent 画面＋consent永続、redirect_uri 完全一致検証、未ログインは
  `/login?return_to=`へバウンス。
- **`/oauth/token`**: `authorization_code`（PKCE検証・code単回120s）/ `refresh_token`
  （**rotation + reuse検知→family一括失効**）。id_token(RS256, iss/aud/nonce/email) 発行。
- **`/userinfo`**（Bearer→profile）、**`/oauth/introspect`**(RFC7662)、**`/oauth/revoke`**(RFC7009)、
  **`/end_session`**（RP-initiated logout, 同一オリジン検証）。
- **client登録**: `POST /api/v1/oauth/clients`（admin, secret一度だけ返却, public/confidential）。
- **store/migration**: `oauth_clients` / `oauth_authorization_codes` / `oauth_refresh_tokens` /
  `oauth_consents`（migration 029）。secret/code/token は hash保管。`handlers/op.rs`。
- **検証**: 実PGで discovery→authorize→code→token(id/access/refresh)→userinfo→refresh
  rotation→reuse検知→code単回 を通し確認。store統合test 3本 + 単体。
- **未（3b-cont / Phase5）**: `prompt=select_account`→Phase2 chooser統合、`max_age`/`login_hint`/
  `id_token_hint`、private_key_jwt client認証、front/back-channel logout、DPoP。
- これで Device Grant（Phase 1）と account chooser（Phase 2）が OP として繋がる土台が完成。

### Phase 4 — 適応認証 ＋ passkey step-up（G4/G5/G6）
- **4a risk engine〔✅ 実装済 2026-07-02〕**: `auth-core/src/risk.rs`。signal（新デバイス、
  IP/ASN 変化、geo velocity、時間帯、UA）を加重スコア化→テナント閾値（既定 action=4/block=5,
  Java parity）で `Allow`/`StepUp`/`Block`。**fail-open**（無signalは safe=1）。純粋関数＋単体test。
- **4b AAGUID メタ〔✅ 実装済 2026-07-02〕**: `auth-server/src/aaguid.rs`。FIDO MDS 主要 AAGUID の
  静的マップ、passkey 一覧が機種名を返す（iCloud/YubiKey/Windows Hello…）。
- **4c 配線〔✅ 実装済 2026-07-02〕**: `__volta_kd` known-device cookie（`risk_known_devices`表,
  migration 030, `RiskDeviceStore::check_and_record`）で新デバイス判定、直近 session との IP 比較で
  `ip_changed`、OIDC callback(`complete_oidc`)で `risk::evaluate`→ **`Block` は拒否**（`LOGIN_BLOCKED`
  監査＋ForbiddenでUI通知）、session に IP/UA 記録。**fail-open**（store失敗→Allow, migration前でも安全）。
  RiskDeviceStore 統合test。
- **4c 残（次以降）**: geo/ASN・impossible-travel signal（要 geo データ）、`StepUp` の MFA 強制配線
  （既存 MFA 状態機械統合）、`acr`/`amr` 反映、passkey を 2FA/step-up ceremony として再利用。

### Phase 5 — 標準準拠の仕上げ（G9–G11, G13, G14）
- **token exchange (RFC 8693)〔✅ 実装済 2026-07-02〕**: `/oauth/token`(grant=token-exchange)、
  subject(access) token を検証→ **down-scope のみ許可**（拡大は `invalid_scope`）、`act` 委譲クレーム付与、
  optional audience。`op::token_exchange`。実サーバ検証済。
- **残（follow-up, 各々が独立した中〜大スライス）**:
  - **DPoP (RFC 9449)**: proof-of-possession JWT 検証 + `cnf.jkt` 束縛（要 nonce/replay 対策インフラ）。
  - **front/back-channel logout**: RP への logout 通知（client に logout uri 登録＋通知配信）。
  - **アカウントリンク**: 1 ユーザに複数 IdP identity（`user_identities` 表＋リンク/解除フロー）。
  - **Phase 4c 残**: geo/impossible-travel signal、`StepUp`→MFA 強制、passkey を 2FA/step-up ceremony 化。
  これらはセキュリティ影響が大きく、各々を独立した検証付きスライスとして実装するのが安全。

### Phase 6 — 先端（G17/G18, 要否判断）
- CAEP/SSF、Verifiable Credentials。別トラック扱い。

---

## 6. Java 版（volta-auth-proxy）への適用メモ

- Java 版はすでに `RiskCheckProcessor` / `RiskAndMfaBranch` / `DeviceRevokeToken` を持ち、
  **適応認証（Phase 4）**は Rust より先行している面がある。→ Phase 4 は Java からの移植が近道。
- OP コア（Phase 3）・Device Grant（Phase 1）・account chooser（Phase 2）は Java 版にも同 spec で
  後追い実装する前提。**プロトコル依存を handler に、状態遷移を flow(tramli) に寄せる**構造を守れば、
  Rust `flow/*` の定義を Java の `flow/*` へ 1:1 で写経できる（既存 OIDC/MFA/passkey flow が実績）。
- SAML は本番 Java sidecar 継続（DD-005）と整合。SAML IdP（G14）を将来やる場合は Java 側が有力。

---

## 付録 A. 参照 RFC / 仕様
- OAuth 2.0: RFC 6749、PKCE 7636、Device Grant 8628、Token Introspection 7662、Revocation 7009、
  JWT Bearer 7523、Token Exchange 8693、mTLS 8705、DPoP 9449、PAR 9126、RAR 9396、DCR 7591。
- OIDC: Core、Discovery、Session Management、Front-Channel/Back-Channel Logout、CIBA。
- FIDO2/WebAuthn: W3C WebAuthn L3、CTAP2、FIDO MDS。
- TOTP/HOTP: RFC 6238 / 4226。SCIM: RFC 7643/7644。SAML 2.0。
- VC: OID4VCI / OID4VP / SD-JWT VC / ISO 18013-5 (mDL)。

## 付録 B. 現状カバレッジ一言まとめ
> **「入る側（RP・passwordless・MFA）は完成域、出す側（OP・IdP・認可サーバ）はゼロ。」**
> 要望の account chooser も QR native 認可も、この“出す側”の構築で一気通貫に解ける。
