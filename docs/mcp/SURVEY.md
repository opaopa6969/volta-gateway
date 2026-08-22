# MCP 化調査 — volta-gateway

> 調査日: 2026-08-21 | 判定: **wrap** | namespace 候補: `vgw`

## 概要

tramli ステートマシン駆動の認証対応リバースプロキシ（Rust）。5 crate の workspace:

| crate | 役割 |
|-------|------|
| `gateway/` | HTTP 逆プロキシ（30+ 機能: LB, CB, rate limit, TLS/ACME, WebSocket, mTLS, plugin, L4 proxy 等） |
| `auth-core/` | 認証ライブラリ（JWT, session, OIDC/MFA/Passkey SM フロー, RBAC, PostgreSQL DAO） |
| `auth-server/` | Axum 認証 API — Java `volta-auth-proxy` と 1:1 の約 96 ルート |
| `volta-bin/` | 統合バイナリ（gateway + auth-core in-process） |
| `tools/traefik-to-volta/` | Traefik 設定 → volta-gateway YAML 変換 CLI |

既に volta 基盤上で稼働中:
- **gateway**: `192.168.1.50:80` (docker)
- **auth-server**: `192.168.1.8:7072` (source) — `auth.unlaxer.org`

既存の入口: HTTP Admin API（gateway, loopback+Bearer）, REST API（auth-server, 約 96 ルート）, CLI（traefik-to-volta）。MCP なし。`volta.service.json` なし。

## 判定と理由

**`wrap`** — 既存 REST API / Admin API を薄く包んで MCP 化する。

- **gateway 側は重複**: `volta-platform-mcp`（`volta` namespace）が既に `volta__gateway_status` / `volta__gateway_routes_diff` / `volta__gateway_routes_apply` / `volta__gateway_reload` を提供。gateway の運用操作（reload, drain, routes 適用）は platform-mcp に寄せる。本リポジトリの MCP は重複しない読み取り系（metrics, stats, circuit breaker 状態）に限定。
- **auth-server 側に価値**: 約 96 ルートの管理 API（audit, user, tenant, session, device, webhook, policy, SCIM, GDPR 等）が未 MCP 化。インシデント対応（セッション一括無効化）、監査ログ検索、ユーザー検索等の運用自動化でエージェントから呼べる価値がある。既存 REST API を薄く包むため新規プロセス不要。
- **CLI も移行支援で価値**: `traefik-to-volta` は Traefik → volta-gateway 移行を自動化する tool として提供できる。

## 公開候補

### tools（auth-server 系 / wrapper）

| name | io | 副作用 | 長時間 | 対応 |
|------|----|----|------|------|
| `audit_search` | `{tenantId?, limit, cursor} → {entries, next_cursor}` | read | no | `GET /api/v1/admin/audit` |
| `user_search` | `{tenantId?, query, status?} → {users}` | read | no | `GET /api/v1/admin/users` |
| `tenant_list` | `{}` → `{tenants}` | read | no | `GET /api/v1/admin/tenants` |
| `session_list` | `{userId?, tenantId?, limit, cursor} → {sessions, next_cursor}` | read | no | `GET /api/v1/admin/sessions` |
| `session_revoke` | `{sessionId} \| {userId}` → `{status}` | **write** (dry-run前提) | no | `DELETE /admin/sessions/{id}`, `POST /auth/sessions/revoke-all` |
| `device_manage` | list: `{userId}` / delete: `{deviceId}` → `{status}` | write | no | `GET/DELETE /api/v1/users/me/devices` |
| `webhook_manage` | list/create/patch/delete + deliveries 照会 | write | no | `/api/v1/tenants/{id}/webhooks/*` |
| `policy_evaluate` | `{tenantId, subject, action, resource} → {allow, reasons}` | none | no | `POST /api/v1/tenants/{id}/policies/evaluate` |
| `data_export` | `{userId} → {job_id}` → (job 型) | read | **yes** (job型) | `POST /api/v1/users/me/data-export` |

### tools（gateway 系 / 読み取りのみ）

| name | io | 副作用 | 長時間 | 対応 |
|------|----|----|------|------|
| `metrics` | `{}` → Prometheus metrics | read | no | `GET /metrics` |
| `routes_list` | `{}` → `[{host, backends, app_id, public}]` | read | no | `GET /admin/routes` |
| `backends_health` | `{}` → `[{url, alive, circuit_state, circuit_failures}]` | read | no | `GET /admin/backends` |
| `stats` | `{}` → `{requests_total, status, websocket, cache, mirror}` | read | no | `GET /admin/stats` |
| `config_validate` | `{yaml_content} → {valid, errors}` | none | no | `--validate` flag |

### tools（CLI 系）

| name | io | 副作用 | 長時間 | 対応 |
|------|----|----|------|------|
| `traefik_convert` | `{format, input} → {yaml}` | none | no | `traefik-to-volta` CLI |

### resources

| name | uri | 内容 |
|------|-----|------|
| `spec` | `vgw://spec` | 能力の機械可読仕様 |
| `guide` | `vgw://guide` | 使い方 |
| `flows` | `vgw://flows` | 認証フロー定義一覧（tramli FlowDefinition） |
| `parity` | `vgw://parity` | Rust ↔ Java ルートパリティ表 |

### skills

| name | locality | 内容 |
|------|----------|------|
| `gateway-ops` | service | gateway リバースプロキシ運用手順 |
| `add-route` | repo | auth-server ルート追加手順 |
| `traefik-migration` | global | Traefik からの移行手順 |

## 組み合わせ例

1. `vgw__audit_search`（監査ログ検索）→ LLM で異常抽出 → `vgw__session_revoke`（該当セッション無効化）→ 外部通知
2. `vgw__user_search` → `vgw__policy_evaluate`（アクセス権確認）→ `nanori__parse`（名前正規化）でユーザー登録品質向上
3. `vgw__traefik_convert` → `vgw__config_validate` → `volta__gateway_routes_apply` で Traefik から volta-gateway への移行を自動化

## 依存と協調

| 相手 repo | 向き | 能力 | 現存 | 備考 |
|-----------|------|------|------|------|
| `volta-platform` | depends_on | `volta__gateway_routes_apply` / `volta__gateway_reload` | yes | gateway の運用操作は platform-mcp に寄せる。本 MCP は重複しない読み取り系 + auth-server 管理系に限定 |
| `volta-auth-proxy` | provides_to | auth-server が 1:1 置換（約 96 ルート） | yes | Java 側は retired。catalog 上は `volta-auth-server` として別 id 登録済み |
| `tramli` | depends_on | tramli 3.8 / tramli-plugins 3.6.1 | yes | ライブラリ依存。flow 可視化（viz/flows）で協調可能性あり |

## ライブラリのサーバ化

該当しない（`needed: false`）。本リポジトリは既に常駐サーバ（gateway + auth-server）を持つため、新規サーバ化は不要。既存の auth-server プロセスに `/mcp` エンドポイントを追加するか、同一ホストで薄い wrapper プロセスを動かす形になる。

## リスク

- **認証・ネットワーク**: gateway の `/admin/*` と auth-server の管理 API は loopback 限定。MCP ファサード（LAN 越し）からアクセスするには、同一ホスト配置か loopback 制限の緩和 + Bearer 認証が必要。
- **write 系 dry-run**: 既存 API に dry-run 機構がない。`session_revoke` / `device_manage` / `webhook_manage` 等は wrapper 側で `confirm: bool=false` → dry-run を実装する必要がある。
- **長時間処理**: `data_export` は job 型（start → status → result）にする必要がある。
- **DB 依存**: auth-server は PostgreSQL 依存（`DATABASE_URL`）。MCP サーバが直接 DB を触るわけではないが、auth-server プロセスの稼働が前提。
- **SAML**: Rust 側の SAML 署名検証は simplified。本番 SAML は Java sidecar 推奨。SAML 関連の tool 化は避ける。
- **JWKS**: 現在空 keys を返す（HS256 前提）。RS256 運用時の key rotation を考慮。

## 持ち主への質問

1. gateway 読み取り系（metrics/stats/routes/backends）を本リポジトリの MCP に含めるか、`volta-platform-mcp` 側に拡張してもらうか。重複回避なら後者。
2. namespace は `vgw` で統一するか、auth-server 用に別 namespace（例: `vauth`）を切るか。catalog 上は `volta-gateway` と `volta-auth-server` が別 id だが同一リポジトリ。
3. MCP サーバの実装言語・配置: Rust で auth-server に組み込む（axum に `/mcp` 追加）か、別プロセス（Python/Node 薄 wrapper）か。Rust MCP SDK の成熟度要確認。
4. `volta.service.json` をどの catalog id に追加するか（`volta-gateway` or `volta-auth-server` or 新規）。
5. `traefik-to-volta` CLI の tool 化を本 MCP に含めるか、独立 skill として配るか。
