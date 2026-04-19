# volta-gateway ↔ tramli: Feedback Loop

> Japanese follows the English section / 英語のあとに日本語。

This document captures the **`tramli_react`** cycle between volta-gateway and
the upstream [tramli](https://github.com/opaopa6969/tramli) engine. The short
version: volta-gateway is tramli's largest production consumer; every friction
we hit in the Rust port turned into a tramli minor release, and every tramli
release was redeployed here within 24 hours.

---

## Why this file exists

`tramli_react` is a feedback shape, not a codebase. It means:

```
ship in volta-gateway → hit friction → file an issue upstream
     ↑                                              │
     └──── tramli releases fix  ◀──── tramli merges PR
```

The round-trip is short enough that it's worth tracking openly so that:

1. Future contributors know *why* each minor was adopted.
2. tramli owners have a canonical "used in production" witness list.
3. Anyone evaluating tramli for their own proxy can see what real usage looks
   like.

---

## Timeline

| Date       | tramli | volta-gateway commit | Friction we sent upstream                                 | Upstream fix landed in              |
|------------|--------|----------------------|-----------------------------------------------------------|-------------------------------------|
| 2026-04-07 | 3.2    | `c847c2a`            | Needed plugin SPI + lint + diagram + observability hooks  | 3.2 release (Plugin system)         |
| 2026-04-07 | 3.3    | `0e9f4e8`            | "Where is the time going?" — per-transition µs counter    | 3.3 `durationMicros` in logger      |
| 2026-04-07 | 3.4    | `bf7f5c0`            | Minor API smoothing needed for the 96-route refactor      | 3.4 API polish                      |
| 2026-04-07 | 3.5    | `f8e594f`            | Needed "chain mode" + richer telemetry fields             | 3.5 chain mode + telemetry          |
| 2026-04-07 | 3.6    | `ad16aa1`            | `FlowStore` trait + `Builder::strict_mode()`              | 3.6 release                         |
| 2026-04-07 | 3.6.1  | `b7fef15`            | Benchmark noise from telemetry — need a `Noop` sink       | 3.6.1 `NoopTelemetrySink`           |
| 2026-04-17 | 3.8    | `0ccf18f`            | `GuardOutput::Accepted { .. }` boilerplate in every guard | 3.8 `accept_with` + `guard_data!`   |

Earlier ground-truth exchanges are archived in tramli's own
[feedback folder](https://github.com/opaopa6969/tramli/tree/main/docs/feedback)
(files named `volta-auth-proxy-*` — they cover both the Java auth-proxy era
and the Rust port in this repo).

---

## What changed in our code, per upgrade

### 3.2 — Plugin system adopted

volta-gateway's own plugin system (`gateway/src/plugin.rs`) took its
lifecycle shape from tramli's plugin SPI:

```
LOADED ──▶ VALIDATED ──▶ ACTIVE ◀──▶ ERROR
                  │
                  └──▶ REJECTED
```

The built-in plugins (`ApiKeyAuth`, `RateLimitByUser`, `Monetizer`,
`HeaderInjector`) all register against this lifecycle.

### 3.3 — µs transition logs everywhere

Every SM transition now carries `durationMicros`. The request log looks like:

```json
{"transitions":[
  {"from":"RECEIVED","to":"VALIDATED","duration_us":5},
  {"from":"VALIDATED","to":"ROUTED","duration_us":2},
  {"from":"ROUTED","to":"AUTH_CHECKED","duration_us":850},
  {"from":"AUTH_CHECKED","to":"FORWARDED","duration_us":12500}
]}
```

This is what made the benchmark article possible — we could point at a specific
hop and say *that one* costs 850µs.

### 3.5 — chain mode

Let us express `auto().auto().auto()` as a single "chain" that the engine
runs in one `start_flow()` call without returning to the outer loop between
each step. Mapped directly to the `Received → Validated → Routed` auto-chain.

### 3.6 — `FlowStore` + `strict_mode()`

`FlowStore` trait gave us a pluggable persistence story for `auth-core`
flows (OIDC / MFA / Passkey / Invite). `auth_flows` + `auth_flow_transitions`
tables plus optimistic locking plug in as a `FlowStore` impl.

`Builder::strict_mode()` is what `cargo test --workspace` runs with — it
verifies `produces()` declarations at runtime against actual context writes.
Several bugs were caught by this alone.

### 3.6.1 — `NoopTelemetrySink`

For the Traefik comparison in `docs/benchmark-article.md` we needed a
zero-cost baseline. `NoopTelemetrySink` drops all observability work on the
floor; we swap it in during bench, swap it out in production.

### 3.8 — guard ergonomics

Before 3.8, every guard wrote out this:

```rust
GuardOutput::Accepted {
    data: data_types!(AuthData { token: tok.clone() }),
}
```

Now:

```rust
GuardOutput::accept_with(AuthData { token: tok.clone() })
// or with multiple types:
GuardOutput::accepted(guard_data![AuthData { .. }, UserId(42)])
// rejection:
GuardOutput::rejected("invalid token")
// empty:
GuardOutput::accepted_empty()
```

All four `AuthGuard` / `ForwardGuard` / OIDC / MFA guard implementations in
this repo use the new helpers.

---

## Open items still going upstream

These are in `docs/backlog.md` and in tramli's own issue tracker:

- **Per-request `FlowEngine` allocation.** For the proxy we allocate a new
  `FlowEngine<ProxyState>` + `InMemoryFlowStore` per request. At 2µs it's
  invisible; at 100K req/sec a shared engine or arena allocator would help.
- **Processor `Send + Sync` constraint.** Intentional but under-documented.
  We'd like a doc paragraph so others don't trip over `Rc<RefCell<T>>`
  deps.
- **`ObservabilityPlugin` does not yet carry `durationMicros`.** Logger API
  has it (from 3.3), telemetry event does not.

---

## How to send feedback

1. Reproduce in `volta-gateway` (or a minimal repro crate).
2. Open an issue in `opaopa6969/tramli` linking here.
3. Once merged, pin the new minor in the workspace `Cargo.toml`, update
   `CHANGELOG.md` under the "tramli upgrade timeline" section, and add a row
   to the table above.

---

<a id="日本語"></a>

# volta-gateway ↔ tramli: フィードバックループ (日本語)

本ドキュメントは volta-gateway と上流 [tramli](https://github.com/opaopa6969/tramli)
エンジンとの**`tramli_react`**サイクルを記録する。要約: volta-gateway は tramli
の最大の本番利用先であり、Rust ポートで遭遇した摩擦は全て tramli マイナー
リリースとして反映され、tramli リリースは 24 時間以内に本リポジトリに取り
込まれてきた。

## なぜこのファイルがあるか

`tramli_react` はコードベースではなくフィードバック形状:

```
volta-gateway で投入 → 摩擦検出 → 上流に issue
     ↑                                        │
     └─── tramli リリース 反映  ◀── tramli が PR merge
```

この往復を公開で追うことで:

1. 後から来た人が「なぜこのマイナーを採用したか」を辿れる。
2. tramli 側が「本番で使われている証拠」を参照できる。
3. tramli を自社プロキシに採用検討する人が、実運用の形を見られる。

## タイムライン

| 日付       | tramli | volta-gateway コミット | 送り返した摩擦                                            | 反映されたリリース                     |
|------------|--------|------------------------|-----------------------------------------------------------|---------------------------------------|
| 2026-04-07 | 3.2    | `c847c2a`              | Plugin SPI + lint + diagram + observability が必要        | 3.2 (Plugin system)                   |
| 2026-04-07 | 3.3    | `0e9f4e8`              | 「どこで時間がかかっているか」が見たい → 遷移別 µs カウンタ | 3.3 logger の `durationMicros`        |
| 2026-04-07 | 3.4    | `bf7f5c0`              | 96 ルートリファクタ用の API smoothing                      | 3.4 API polish                        |
| 2026-04-07 | 3.5    | `f8e594f`              | chain mode + telemetry フィールド拡充が欲しい              | 3.5 chain mode + telemetry            |
| 2026-04-07 | 3.6    | `ad16aa1`              | `FlowStore` trait + `Builder::strict_mode()`               | 3.6                                    |
| 2026-04-07 | 3.6.1  | `b7fef15`              | ベンチ時の telemetry ノイズ → `Noop` sink が欲しい         | 3.6.1 `NoopTelemetrySink`             |
| 2026-04-17 | 3.8    | `0ccf18f`              | 毎 guard の `GuardOutput::Accepted { .. }` boilerplate     | 3.8 `accept_with` + `guard_data!`     |

これ以前の往復は tramli 本体の
[feedback フォルダ](https://github.com/opaopa6969/tramli/tree/main/docs/feedback)
にある (`volta-auth-proxy-*` — Java auth-proxy 時代と本リポジトリの Rust ポート
期の両方をカバー)。

## 各アップグレードで何が変わったか

### 3.2 — Plugin system 導入

volta-gateway 自身のプラグインシステム (`gateway/src/plugin.rs`) は tramli
Plugin SPI のライフサイクル形状を採用:

```
LOADED ──▶ VALIDATED ──▶ ACTIVE ◀──▶ ERROR
                  │
                  └──▶ REJECTED
```

ビルトイン (`ApiKeyAuth`, `RateLimitByUser`, `Monetizer`, `HeaderInjector`) が
このライフサイクルに乗る。

### 3.3 — 全遷移に µs ログ

```json
{"transitions":[
  {"from":"RECEIVED","to":"VALIDATED","duration_us":5},
  {"from":"VALIDATED","to":"ROUTED","duration_us":2},
  {"from":"ROUTED","to":"AUTH_CHECKED","duration_us":850},
  {"from":"AUTH_CHECKED","to":"FORWARDED","duration_us":12500}
]}
```

benchmark 記事はこれで書けた。「どのホップが 850µs か」を指差せる。

### 3.5 — chain mode

`auto().auto().auto()` を 1 つの chain として engine 内で連続実行できるように。
`Received → Validated → Routed` の auto-chain に直結。

### 3.6 — `FlowStore` + `strict_mode()`

`FlowStore` trait により auth-core フロー (OIDC / MFA / Passkey / Invite) の
永続化を差し替え可能に。`auth_flows` + `auth_flow_transitions` テーブル +
楽観ロックが `FlowStore` impl として差さる。

`Builder::strict_mode()` は `cargo test --workspace` で常時有効にしてあり、
`produces()` 宣言と実際の context 書き込みを runtime で突き合わせる。
複数のバグがこれで摘出された。

### 3.6.1 — `NoopTelemetrySink`

`docs/benchmark-article.md` での Traefik 比較にゼロコスト基線が必要だった。
`NoopTelemetrySink` は observability 処理を全て捨てる。bench 時に差し込み、
本番では外す。

### 3.8 — guard エルゴノミクス

3.8 以前は全 guard が:

```rust
GuardOutput::Accepted {
    data: data_types!(AuthData { token: tok.clone() }),
}
```

3.8 以降:

```rust
GuardOutput::accept_with(AuthData { token: tok.clone() })
// 複数型:
GuardOutput::accepted(guard_data![AuthData { .. }, UserId(42)])
// reject:
GuardOutput::rejected("invalid token")
// 空:
GuardOutput::accepted_empty()
```

本リポジトリの `AuthGuard` / `ForwardGuard` / OIDC / MFA guard は全て新ヘルパ
使用に移行済。

## まだ上流に送り続けている項目

`docs/backlog.md` と tramli 側 issue tracker にある:

- **リクエスト毎の `FlowEngine` 確保。** プロキシ用途では毎 request ごとに
  `FlowEngine<ProxyState>` + `InMemoryFlowStore` を alloc/free している。
  2µs なので今は無視できるが、100K req/sec 帯では共有 engine か arena
  allocator が欲しくなる。
- **Processor の `Send + Sync` 制約。** 意図的だが文書化が薄い。段落 1 つでも
  書いてもらえると `Rc<RefCell<T>>` 依存の人が踏まずに済む。
- **`ObservabilityPlugin` に `durationMicros` が無い。** Logger API は 3.3 で
  入ったが、TelemetryEvent 側はまだ。

## フィードバックの送り方

1. `volta-gateway` (または最小再現クレート) で再現。
2. `opaopa6969/tramli` に issue を立て、本ページへリンク。
3. merge されたらワークスペースの `Cargo.toml` の tramli マイナーを固定、
   `CHANGELOG.md` の "tramli upgrade timeline" セクションを更新、上のタイム
   ライン表に 1 行追加。
