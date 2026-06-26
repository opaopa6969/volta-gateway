# Passkey フロー図（登録・ログイン・分岐）

auth-server (`auth-server/src/handlers/passkey_flow.rs`) と gateway の ForwardAuth を mermaid で図式化。
ルート定義は `auth-server/src/app.rs`。

> **関連:** UX 設計・原理・Google風設計との比較は [`passkey-ux-design.md`](./passkey-ux-design.md)。
> sign-counter のクローン検知（`signCount=0` は非対応として受理）や `/viz` フロー図の実態反映拡張は同書 / CHANGELOG 参照。

## 1. 全体像：gateway ForwardAuth とログイン state

これが既存の「ログイン state」。gateway は tramli ステートマシンで毎リクエストの認証可否だけを判定する。

```mermaid
flowchart TD
    Req[ブラウザ → 保護サービス] --> GW[volta-gateway :80]
    GW --> V{"/auth/verify<br/>セッション有効?"}
    V -- 有効 --> FWD[バックエンドへ forward]
    V -- 無効 --> RD[302 → /login]
    RD --> LOGIN[ログイン画面]
    LOGIN --> PK[パスキー認証 flow<br/>（下記 3/4）]
    PK -- 成功 --> SESS[セッション Cookie 発行]
    SESS --> Req
```

## 2. パスキー登録（ログイン済みユーザーが追加）

`POST /api/v1/users/{userId}/passkeys/register/start` → `…/register/finish`

**今回の修正点**: `residentKey: required` を強制 → Windows Hello が **discoverable な passkey** を作るので、後述の usernameless ログインに「この PC」が出る。

```mermaid
sequenceDiagram
    participant U as ブラウザ
    participant S as auth-server
    participant A as 認証器(OS)
    U->>S: POST register/start
    S-->>U: CreationChallengeResponse<br/>(residentKey=required, UV=required,<br/>attachment=なし=platform/roaming両可)
    U->>A: navigator.credentials.create()
    Note over A: 「このデバイス(Windows Hello)」<br/>「スマホ」「セキュリティキー」から選択
    A-->>U: 公開鍵 + attestation
    U->>S: POST register/finish
    S->>S: 検証 → Passkey 保存(discoverable)
    S-->>U: 登録完了
```

## 3. ログイン：discoverable（ユーザー名なし＝「パスキーでログイン」）

`POST /auth/passkey/discover/start`（`allowCredentials=[]`） → `…/discover/finish`

```mermaid
sequenceDiagram
    participant U as ブラウザ
    participant S as auth-server
    participant A as 認証器(OS)
    U->>S: POST discover/start
    S-->>U: RequestChallenge<br/>(allowCredentials=[], UV=required)
    U->>A: navigator.credentials.get()
    Note over A: この端末に discoverable passkey が<br/>あれば「この PC」が候補に出る(PIN)<br/>無ければ「スマホ」「セキュリティキー」のみ
    A-->>U: assertion(どの資格情報か含む)
    U->>S: POST discover/finish
    S->>S: user 特定 → assertion 検証
    S-->>U: セッション Cookie
```

## 4. ログイン：ユーザー名先行（allowCredentials 指定）

`POST /auth/passkey/start` → `…/finish`

```mermaid
sequenceDiagram
    participant U as ブラウザ
    participant S as auth-server
    participant A as 認証器(OS)
    U->>S: POST /auth/passkey/start (user 指定)
    S->>S: そのユーザーの登録済み credentialId を取得
    S-->>U: RequestChallenge<br/>(allowCredentials=[ids], UV=required)
    U->>A: navigator.credentials.get()
    A-->>U: assertion
    U->>S: POST /auth/passkey/finish
    S-->>U: セッション Cookie
```

## 5. 認証器の種類と分岐（なぜ「この PC/PIN」が出る/出ない）

```mermaid
flowchart TD
    G["get() / create() の<br/>authenticatorSelection"] --> ATT{attachment}
    ATT -- platform --> P["内蔵<br/>Windows Hello(PIN/生体)<br/>Touch ID"]
    ATT -- cross-platform --> X["外付け"]
    ATT -. 指定なし(本実装) .-> BOTH[両方を提示]
    BOTH --> P
    BOTH --> X
    X --> HY["スマホ(ハイブリッド/QR)"]
    X --> SK["セキュリティキー"]

    P --> RK{"登録時<br/>residentKey"}
    RK -- required(修正後) --> DISC["discoverable<br/>→ usernameless ログインで<br/>『この PC』に出る ✅"]
    RK -- discouraged(修正前) --> NOND["非 discoverable<br/>→ usernameless で出ない ❌<br/>(今回のバグ)"]
```

## 補足：実装の所在（重要）

- 上記フローの**ロジック**は Rust の `auth-server` / `auth-core`（本リポジトリ）。`residentKey=required` 修正もここ。
- ただし **現在 auth.unlaxer.org の本番で稼働している auth backend は Java 版 `volta-auth-proxy`**（`192.168.1.8:7070`）。Rust 版 auth-server は未稼働。
- したがって本番にこの修正を効かせるには「Java 版にも同じ residentKey=required を入れる」か「Rust 版へ移行」のいずれかが必要（`docs/passkey-resident-key.md` 参照）。

## tramli での図示について

tramli (`tramli::MermaidGenerator`) は `FlowDefinition` から `stateDiagram-v2` を自動生成できる。gateway は **per-request の認証可否 SM**（図1の verify→forward/redirect）に tramli を使っており、これが既存の「ログイン state グラフィカル表示」。

パスキーの**多段セレモニー**（図2〜4）は gateway の per-request SM とは別物（auth-server 側の状態遷移）。よって既存 SM に混ぜず、auth-server に独立した `FlowDefinition`（例: `Idle → ChallengeIssued → AwaitingClient → Verifying → Authenticated/Failed`、register/discover/username で分岐）を定義し、同じ `MermaidGenerator` で描くのが筋。既存のログイン state 画面からは「未認証 →/login」エッジでこの新 SM へリンクする形が自然。
