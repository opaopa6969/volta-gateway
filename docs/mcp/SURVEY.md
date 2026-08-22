# MCP 化調査 — volta-gateway

> Phase 1（読み取り中心）。設計・実装・issue 登録はしない。

## 概要

`volta-gateway` は Rust 製の auth-aware HTTP/WS/L4 リバースプロキシ（tramli 状態機械駆動）と、Java `volta-auth-proxy` と 1:1 互換の 126 ルート認証サーバ（`auth-server`）を含む 5-crate Cargo workspace。`auth.unlaxer.org` として本番稼働中。volta 基盤のフロントドア。

- **種類**: `service`（常駐サーバ）
- **稼働環境**: docker (gateway :80, host 192.168.1.50) / source (auth-server :7072, host 192.168.1.8)
- **既存 MCP**: なし（`.mcp.json` は issue-broker のみ）
- **volta カタログ登録**: volta-gateway / volta-auth-server として登録済み

## 判定と理由

**判定: `wrap`**（既存 HTTP API を薄く包む）

gateway は既に `/admin/*`（loopback-only, Bearer token 認証）と `/metrics`（Prometheus）と `/healthz` を持つ常駐 HTTP サーバ。MCP 化すべきは gateway の管理操作（ルート一覧・バックエンド健全性・設定の取得/更新・リロード・drain・サーキットブレーカー reset）を tool として薄く包むこと。

126 ルートの認証 API（auth-server 側）は人向けブラウザ UI が主で、エージェントが直接叩く価値は低い（認証フローはステートフル・リダイレクト前提）。gateway の admin API は JSON in/out で副作用が明確、まさに tool 向き。新規サーバは不要。

## 公開候補

| kind | name | io | 副作用 | 長時間 | 対応元 |
|------|------|----|--------|---------|---------|
| tool | `list_routes` | void → `[{host, backends, app_id, public}]` | read | no | `GET /admin/routes` |
| tool | `list_backends` | void → `[{url, alive, circuit_state, circuit_failures}]` | read | no | `GET /admin/backends` |
| tool | `stats` | void → `{requests_total, status{...}, websocket{...}, cache{...}, mirror{...}}` | read | no | `GET /admin/stats` |
| tool | `get_config` | void → `GatewayConfig(JSON)` | read | no | `GET /admin/config` |
| tool | `patch_config` | `JSONMergePatch` → `{status, hot_applied[], requires_restart[]}` | write | no | `PATCH /admin/config` |
| tool | `clear_overlay` | void → `{status}` | write | no | `DELETE /admin/config/overlay` |
| tool | `reload` | void → `{status, routes}` | write | no | `POST /admin/reload` |
| tool | `drain` | void → `{status}` | write | no | `POST /admin/drain` |
| tool | `reset_circuit` | `backend_url` → `{status, backend, was_open, circuit_state}` | write | no | `POST /admin/backends/{id}/reset` |
| tool | `convert_traefik` | `{format, input}` → `YAML string` | none | no | `tools/traefik-to-volta` |
| tool | `validate_config` | `config_path` → `{valid, errors[]}` | none | no | `--validate` flag |
| resource | `spec` | `gw://spec` | — | — | 機械可読仕様 |
| resource | `guide` | `gw://guide` | — | — | 使い方 |
| resource | `config_schema` | `gw://config-schema` | — | — | 設定スキーマ・全ルートオプション |
| resource | `auth_routes` | `gw://auth-routes` | — | — | 126 ルート認証 API 一覧 |
| skill | `migrate-from-traefik` | — | — | — | Traefik 移行手順 (global) |
| skill | `deploy-volta-gateway` | — | — | — | デプロイ手順 (service) |

**namespace 提案**: `gw`

## 組み合わせ例

1. `catalog__list_services` → `gw__list_routes` で「どのサービスがどの host で公開されているか」を一覧化 → `gw__list_backends` で死活確認 → `volta__svc_restart` で不調サービスを再起動
2. `gw__get_config` → `gw__patch_config` でルート追加 → `gw__reload` でホット適用 → `gw__list_backends` で新バックエンド健全性確認
3. `gw__stats` で 5xx スパイク検知 → `gw__list_backends` でサーキットオープン特定 → `gw__reset_circuit` で強制リカバリ → `volta__svc_logs` で該当サービスログ確認

## 依存と協調

| 相手 repo | 向き | 能力 | 現在存在 | 備考 |
|-----------|------|------|----------|------|
| volta-auth-proxy | depends_on | `GET /auth/verify` (ForwardAuth) | yes | gateway は auth-server または Java proxy の /auth/verify に依存。proxy は retired、auth-server が後継 |
| volta-platform | depends_on | services.json (config source) | yes | gateway の config_source.rs が services.json を読む |
| volta-platform | provides_to | gateway ルーティング表の実体 | yes | volta-platform の gateway_routes_apply がルートを反映。gw__list_routes はその結果を読む。二重管理の競合リスク |
| volta-auth-proxy | provides_to | 126-route auth API (auth-server) | yes | auth-server は Java proxy の 1:1 Rust 再実装。SAML 署名検証のみ Java sidecar 残存 (DD-005) |

**協調が要る場合でも Phase 1 では issue を立てない。**

## ライブラリのサーバ化

該当しない（`needed: false`）。gateway は既に常駐サーバ。MCP バックエンドとして追加で必要なのは `volta.service.json`（manifest）と thin MCP ラッパープロセスのみ。推定工数 S。

## リスク

- **admin API は loopback-only が前提**。MCP ファサード（LAN から来る）で公開する場合、admin token (VOLTA_ADMIN_TOKEN) の認証が必須。token 未設定だと書き込み API が 403。
- **patch_config / reload / drain / clear_overlay は破壊的**（ルート変更・トラフィック停止）。`confirm: bool=false` で dry-run を挟む必要がある。
- **gateway と volta-platform の二重管理**。両方がルートを操作でき、競合リスクがある。どちらを正とするかの運用方針が必要。
- **auth-server の 126 ルートはブラウザ UI 前提**（リダイレクト・SSE・cookie）。そのまま MCP tool にするのは不適切。スキップすべき。
- **/admin/* の Host 区別**。ルーティング表に載っている Host 宛の /admin/* はバックエンドに横流しされる（例: auth.unlaxer.org/admin/tenants）。gateway 自身の管理 API は未ルート Host(localhost/生IP) のみ。MCP ラッパーはこの区別を意識する必要がある。

## 持ち主への質問

1. `gw__*` tools の向き先は gateway プロセス(:8080) か、それとも auth-server プロセス(:7072) か。admin API は gateway プロセスのみ。auth-server の管理操作は別途検討が必要か？
2. volta-platform の `gateway_routes_apply` と `gw__patch_config` が両方ルートを変更できる。MCP で公開するのはどちらか？ それとも両方？ 運用上の正をどちらに置くか。
3. admin token を MCP バックエンドにどう渡すか（環境変数? gateway の config に埋め込み? ファサードの secret 注入?）。
4. `drain` はプロセス停止を伴う。MCP tool として公開してよい操作か、それとも人間専用に留めるべきか。
5. `traefik-to-volta` 変換ツールを MCP tool にする場合、変換結果をそのまま `gw__patch_config` に渡すパイプラインが自然か。ワンステップで「Traefik ラベル → gateway ルート追加」を作るか。
