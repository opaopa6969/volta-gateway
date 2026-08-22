# MCP 設計書 — volta-gateway (namespace: `gw`)

> Phase 1 survey: `docs/mcp/survey.json` (decision: `wrap`)
> 割当表: `docs/MCPIFY-phase2-plan.md` 行20 — namespace `gw`, port 9217

## 1. namespace と種別

- **namespace**: `gw`
- **種別**: `wrap` — 既存の gateway admin API (`/admin/*`) と CLI ツールを MCP tool として薄くラップする。新規 HTTP サーバは立てない（gateway プロセスは既存）。
- **リポジトリ**: `volta-workspace/volta-gateway` (Rust 5-crate Cargo workspace)

### vgw との差別化

既存 `vgw` (port 9214, `auth-test/volta-gateway`) は auth-server admin API + gateway **読取系**のみ。
`gw` は gateway **書き込み系**（patch_config, clear_overlay, reload, drain, reset_circuit）+ validate_config + gateway 全 admin API の直接ラップを提供する。

| 能力 | vgw | gw |
|------|-----|-----|
| routes_list (読取) | ✅ | ✅ |
| backends_health (読取) | ✅ | ✅ |
| stats (読取) | ✅ | ✅ |
| metrics (読取) | ✅ | ✅ |
| traefik_convert (CLI) | ✅ | ✅ |
| **get_config (読取)** | ❌ | ✅ |
| **patch_config (書込)** | ❌ | ✅ |
| **clear_overlay (書込)** | ❌ | ✅ |
| **reload (書込)** | ❌ | ✅ |
| **drain (書込)** | ❌ | ✅ |
| **reset_circuit (書込)** | ❌ | ✅ |
| **validate_config (純粋)** | ❌ | ✅ |
| audit/user/tenant (auth-server) | ✅ | ❌ |
| config_schema resource | ❌ | ✅ |
| auth_routes resource | ❌ | ✅ |

## 2. tools 表

| name | 目的 | 入力 schema (要点) | 出力の形 | 副作用 | dry-run | job 型 | 所要時間 | min_role |
|------|------|-------------------|----------|--------|---------|--------|----------|----------|
| `list_routes` | ルーティング表を一覧する | void | `[{host, backends, app_id, public}]` | read | — | no | <1s | MEMBER |
| `list_backends` | バックエンド健全性と CB 状態 | void | `[{url, alive, circuit_state, circuit_failures}]` | read | — | no | <1s | MEMBER |
| `stats` | リクエスト統計 | void | `{requests_total, status{2xx,4xx,5xx}, websocket{total,active}, cache{size,fresh}, mirror{total,errors}}` | read | — | no | <1s | MEMBER |
| `get_config` | 有効設定(base⊕overlay)を取得 | void | `GatewayConfig(JSON)` | read | — | no | <1s | MEMBER |
| `metrics` | Prometheus メトリクス | void | text/plain (Prometheus format) | read | — | no | <1s | MEMBER |
| `patch_config` | JSON Merge Patch 適用・永続化・ホット適用 | `{patch: object, confirm?: bool}` | `{status, hot_applied[], requires_restart[]}` | write | ✅ confirm=false で dry-run | no | <1s | OPERATOR |
| `clear_overlay` | オーバーレイ破棄・ベース YAML に戻す | `{confirm?: bool}` | `{status}` (dry-run 時は `{status:"dry-run", current_overlay: {...}}`) | write | ✅ | no | <1s | OPERATOR |
| `reload` | 設定再読込・ホットスワップ | `{confirm?: bool}` | `{status, routes}` | write | ✅ | no | <1s | OPERATOR |
| `drain` | グレースフルシャットダウン開始 | `{confirm?: bool}` | `{status}` | write | ✅ | no | <1s | OPERATOR |
| `reset_circuit` | 指定バックエンドの CB リセット | `{backend_url: string, confirm?: bool}` | `{status, backend, was_open, circuit_state}` | write | ✅ | no | <1s | OPERATOR |
| `validate_config` | 設定ファイルを静的検証 | `{config_path: string}` | `{valid: bool, errors[]}` | none | — | no | <1s | MEMBER |
| `convert_traefik` | Traefik 設定を gateway YAML に変換 | `{format: "docker-compose"\|"traefik-yaml", input: string}` | YAML string | none | — | no | <1s | MEMBER |

### dry-run の挙動

- `confirm: false`（既定）: 実行せず、何が起こるかのプレビューを返す
  - `patch_config`: patch 適用後の差分サマリを返す（実際の永続化・ホット適用はしない）
  - `clear_overlay`: 現在の overlay 内容を返す
  - `reload`: 現在のルート数と再読込予定を返す
  - `drain`: drain 予定の警告を返す（実際の drain はしない）
  - `reset_circuit`: 現在の CB 状態を返す（リセットはしない）
- `confirm: true`: 実際に実行する

## 3. resources 表

| uri | 内容 | mime |
|-----|------|------|
| `gw://spec` | 能力仕様（機械可読・tools/list から自動生成 + compositions/depends_on） | application/json |
| `gw://guide` | 使い方ガイド | text/markdown |
| `gw://config-schema` | gateway 設定スキーマと全ルートオプションの参照 | application/json |
| `gw://auth-routes` | 126 ルート認証 API のエンドポイント一覧 | application/json |

## 4. prompts / skills

| name | 用途 | locality | applies_when | requires | min_role |
|------|------|----------|-------------|----------|----------|
| `migrate-from-traefik` | Traefik からの移行手順 | global | Traefik 設定を gateway に移行するとき | `[gw__convert_traefik, volta__gateway_routes_diff, volta__gateway_routes_apply]` | OPERATOR |
| `deploy-volta-gateway` | gateway + auth-server のデプロイ手順 | service | gateway をデプロイ・更新するとき | `[gw__reload, gw__list_routes]` | OPERATOR |
| `gateway-ops` | gateway リバースプロキシの運用手順（drain, reload, routes 確認） | service | gateway の運用操作が必要なとき | `[gw__list_routes, gw__list_backends]` | OPERATOR |

skill は `docs/skills/<name>/SKILL.md` に置き、resource `skill://<name>` でも配信する。

## 5. 組み合わせ例

1. **サービス追加フロー**: `catalog__list_services → gw__list_routes` で「どのサービスがどの host で公開されているか」を一覧化 → `gw__list_backends` で死活確認 → `volta__svc_restart` で不調サービスを再起動
2. **設定変更フロー**: `gw__get_config → gw__patch_config(confirm=false)` で dry-run 差分確認 → `gw__patch_config(confirm=true)` で適用 → `gw__list_backends` で新バックエンドの健全性確認
3. **インシデント対応**: `gw__stats` で 5xx スパイク検知 → `gw__list_backends` でサーキットオープンを特定 → `gw__reset_circuit(confirm=true)` で強制リカバリ → `volta__svc_logs` で該当サービスのログ確認
4. **Traefik 移行**: `gw__convert_traefik` で Traefik 設定を変換 → `gw__validate_config` で検証 → `gw__patch_config(confirm=true)` で適用 → `gw__reload(confirm=true)` でホットリロード

## 6. 依存と協調

| 相手 repo | 方向 | 入口 | 合意したいこと | issue-hub |
|-----------|------|------|---------------|-----------|
| `volta-platform` | depends_on | `services.json` (config source) | `gw__patch_config` と `volta__gateway_routes_apply` の二重管理の整理。暫定: 両方提供するが、`volta__gateway_routes_apply` を正とし `gw__patch_config` は overlay 編集用 | issue-hub で協調 |
| `volta-platform` | provides_to | gateway ルーティング表の実体 | `gw__list_routes` は `volta__gateway_routes_apply` の結果を読む側。操作経路が 2 つあるが、読取は冪等なので問題ない | 同上 |
| `auth-test/volta-gateway` (vgw) | 重複 | gateway 読取系 tools | `gw` と `vgw` で読取系が重複するが、`gw` は書き込み系を含む完全版。エージェントは必要に応じて使い分ける。`vgw` は auth-server 系に特化 | issue-hub で通知 |

## 7. 非対応にした候補

| 候補 | 理由 |
|------|------|
| auth-server 126 ルートの MCP 化 | ブラウザ UI（リダイレクト・SSE・cookie）前提で MCP tool に不適。`vgw` が auth-server admin API を既に提供 |
| `volta-bin` 統合バイナリの MCP 化 | 未機能 (#86)。機能したら gateway と同じ admin API になる |
| plugin システムの MCP 化 | Rust プラグイン API はコンパイル時。MCP から操作できない |

## 8. 参加方法

- **manifest**: `volta.service.json` (id: `gw-mcp`, port: 9217)
- **ポート**: 9217（割当表より。`machine_ports` で 9217 が空きを確認済み）
- **ホスト**: 192.168.1.50 (prod)
- **runtime**: systemd (user unit)
- **auth**: `minRole: MEMBER`（読取系は MEMBER、書込系は OPERATOR）
- **gateway admin API アクセス**: `GATEWAY_ADMIN_URL` env (デフォルト `http://127.0.0.1:80`) + `VOLTA_ADMIN_TOKEN` env (Bearer token)
  - gateway は Docker `--network host` で動いているため、MCP サーバも同じホストで動かせば `127.0.0.1:80` でアクセス可能
  - admin API は loopback 限定 + Bearer token 認証

## 9. テスト方針

e2e テスト（Node `--test`）:
1. サーバ起動 → `GET /healthz` が 200
2. `GET /unknown` が 404
3. MCP `tools/list` で全 tool が確認できる
4. `list_routes` / `list_backends` / `stats` / `get_config` / `metrics` が呼べる（gateway が稼働中なら実データ、未稼働ならエラーハンドリング確認）
5. `patch_config(confirm=false)` が dry-run で実行されない
6. `reset_circuit(confirm=false)` が dry-run で実行されない
7. `convert_traefik` が YAML を返す
8. `gw://spec` resource が valid JSON
9. `gw://guide` resource が markdown
10. `gw://config-schema` resource が valid JSON
11. `gw://auth-routes` resource が valid JSON
