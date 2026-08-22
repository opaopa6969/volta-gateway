# MCP 設計 — auth-test/volta-gateway

> 設計日: 2026-08-22 | namespace: `vgw` | kind: **wrap** | port: 9214

## 1. namespace と種別

- **namespace**: `vgw`
- **種別**: `wrap` — 既存の auth-server REST API と gateway Admin API を薄い Node wrapper プロセスで包んで MCP 化する。Rust 側（auth-server/gateway）のコードは変更しない。
- **新規サービス id**: `vgw-mcp`（既存の `volta-gateway` port 80 / `volta-auth-server` port 7072 とは別プロセス）

## 2. 配置とネットワーク

- **host**: `192.168.1.50`（prod）。gateway と同一ホスト → gateway admin API を loopback で叩ける。
- **port**: 9214（割当表 #17。`volta__machine_ports` で空き確認済み）
- **auth-server**: `192.168.1.8:7072` — Bearer token で LAN 越しアクセス（`require_admin_with_headers` 対応ルートのみ）
- **gateway admin**: `127.0.0.1:80` — loopback + `VOLTA_ADMIN_TOKEN` Bearer
- **認証**:
  - auth-server admin API: `Authorization: Bearer <VGW_AUTH_TOKEN>` 環境変数から（`require_admin_with_headers` は JWT 検証 → ADMIN/OWNER ロール確認）
  - gateway admin API: `Authorization: Bearer <VOLTA_ADMIN_TOKEN>` 環境変数から（loopback + Bearer）
  - MCP サーバ自身: 送信元 IP 制限（127.0.0.1 / 192.168.1.50 / 192.168.1.8）— ファサードからのみ

## 3. tools 表

### auth-server 系（Bearer 対応済みルート — 即実装）

| name | 目的 | 入力 schema 要点 | 出力の形 | 副作用 | dry-run | job型 | 所要 | min_role |
|------|------|-----------------|---------|--------|---------|-------|------|----------|
| `audit_search` | 監査ログを検索する | `{tenantId?, q?, userId?, event?, from?, to?, page?, size?}` | `{entries: [{id,userId,action,ts,ip,meta}], total, page, size}` | read | — | no | <1s | ADMIN |
| `user_search` | ユーザーを検索する | `{tenantId?, q?, status?, page?, size?}` | `{users: [{id,email,name,status,mfa_enabled}], total, page, size}` | read | — | no | <1s | ADMIN |
| `tenant_list` | テナント一覧を取得する | `{q?, page?, size?}` | `{tenants: [{id,name,plan,member_count}], total, page, size}` | read | — | no | <1s | ADMIN |

### gateway 系（loopback・即実装）

| name | 目的 | 入力 schema 要点 | 出力の形 | 副作用 | dry-run | job型 | 所要 | min_role |
|------|------|-----------------|---------|--------|---------|-------|------|----------|
| `metrics` | Prometheus メトリクスを取得する | `{}` | Prometheus text（文字列） | read | — | no | <1s | OPERATOR |
| `routes_list` | gateway のルート一覧を取得する | `{}` | `[{host, backends, app_id, public}]` | read | — | no | <1s | OPERATOR |
| `backends_health` | バックエンド健全性を取得する | `{}` | `[{url, alive, circuit_state, circuit_failures}]` | read | — | no | <1s | OPERATOR |
| `stats` | リクエスト統計を取得する | `{}` | `{requests_total, status:{2xx,4xx,5xx}, websocket, cache, mirror}` | read | — | no | <1s | OPERATOR |

### CLI 系（即実装）

| name | 目的 | 入力 schema 要点 | 出力の形 | 副作用 | dry-run | job型 | 所要 | min_role |
|------|------|-----------------|---------|--------|---------|-------|------|----------|
| `traefik_convert` | Traefik 設定を volta-gateway YAML に変換する | `{format: "docker-compose"\|"traefik-yaml", input: string}` | `{yaml: string, routes: number}` | none | — | no | <1s | MEMBER |

### auth-server 系（cookie-only 認証 — issue-hub で Bearer 対応を依頼、暫定仕様）

以下の tool は auth-server が `require_admin`（cookie only）を使っており、MCP wrapper から Bearer でアクセスできない。issue-hub で auth-server 側の Bearer 対応を依頼し、対応後に追加する。暫定仕様として設計に含めるが実装は後続。

| name | 目的 | 入力 schema 要点 | 出力の形 | 副作用 | dry-run | job型 | min_role | 状態 |
|------|------|-----------------|---------|--------|---------|-------|----------|------|
| `session_list` | セッション一覧を取得する | `{userId?, page?, size?}` | `{sessions: [{id,userId,device,ip,last_active,created_at}], total}` | read | — | no | ADMIN | issue-hub 依頼中 |
| `session_revoke` | セッションを無効化する | `{sessionId? \| userId?, confirm: bool=false}` | `{status, revoked_at} \| {status, count}` | write | yes | no | ADMIN | issue-hub 依頼中 |
| `policy_evaluate` | ポリシーを評価する | `{tenantId, subject, action, resource}` | `{allow: bool, reasons: []}` | none | — | no | ADMIN | issue-hub 依頼中 |
| `data_export_start` | データエクスポートを開始する | `{userId}` | `{job_id}` | read | — | yes | ADMIN | issue-hub 依頼中 |
| `data_export_status` | データエクスポートの状態を取得する | `{job_id}` | `{status, progress}` | read | — | yes | ADMIN | issue-hub 依頼中 |
| `data_export_result` | データエクスポートの結果を取得する | `{job_id}` | `{url, expires_at}` | read | — | yes | ADMIN | issue-hub 依頼中 |
| `device_list` | デバイス一覧を取得する | `{userId}` | `[{deviceId, name, last_seen}]` | read | — | no | ADMIN | issue-hub 依頼中 |
| `device_delete` | デバイスを削除する | `{deviceId, confirm: bool=false}` | `{status}` | write | yes | no | ADMIN | issue-hub 依頼中 |

## 4. resources 表

| uri | 内容 | mime |
|-----|------|------|
| `vgw://spec` | 能力の機械可読仕様（サーバ起動時に tools から生成 + compositions/depends_on 手動） | application/json |
| `vgw://guide` | 使い方ガイド（Markdown） | text/markdown |
| `vgw://flows` | 認証フロー定義一覧（tramli FlowDefinition の名前と遷移） | application/json |
| `vgw://parity` | Rust(auth-server) ↔ Java(volta-auth-proxy) ルートパリティ表 | application/json |

## 5. prompts / skills

| 名前 | 種別 | 用途 | locality | applies_when | requires |
|------|------|------|----------|--------------|----------|
| `gateway-ops` | skill | gateway リバースプロキシ運用手順（drain, reload, routes 確認） | service | gateway の運用操作が必要なとき | `vgw__routes_list`, `vgw__backends_health`, `volta__gateway_reload` |
| `add-route` | skill | auth-server にルートを追加する手順 | repo | auth-server に新規エンドポイントを追加するとき | — |
| `traefik-migration` | skill | Traefik から volta-gateway への移行手順 | global | Traefik 設定を volta-gateway に移行するとき | `vgw__traefik_convert`, `vgw__config_validate`(未実装), `volta__gateway_routes_apply` |

## 6. 組み合わせ例

1. **インシデント対応**: `vgw__audit_search`（監査ログ検索）→ LLM で異常抽出 → `vgw__session_revoke`（該当セッション無効化）→ 外部通知
2. **ユーザー品質向上**: `vgw__user_search` → `vgw__policy_evaluate`（アクセス権確認）→ `nanori__parse`（名前正規化）
3. **Traefik 移行**: `vgw__traefik_convert` → `volta__gateway_routes_diff`（差分確認）→ `volta__gateway_routes_apply`（適用）

## 7. 依存と協調（issue-hub）

| 相手 repo | 向き | 能力 | 合意したいこと | 状態 |
|-----------|------|------|---------------|------|
| `volta-platform` | depends_on | `volta__gateway_routes_apply` / `volta__gateway_reload` | gateway の運用操作は platform-mcp に寄せる。本 MCP は重複しない読み取り系 + auth-server 管理系に限定 | 既存合意済み |
| `volta-auth-proxy` / `auth-test/volta-gateway`（auth-server） | depends_on | auth-server admin API の Bearer 対応 | `require_admin`（cookie only）ルートの Bearer 対応（`session_list`, `session_revoke`, `policy_evaluate`, `data_export`, `device_*`）。暫定: Bearer 対応済みルートのみ実装 | issue-hub で依頼中 |
| `tramli` | depends_on | tramli 3.8 / tramli-plugins 3.6.1 | ライブラリ依存。flow 可視化で協調可能性 | 関連のみ |

## 8. 非対応にした候補と理由

| 候補 | 理由 |
|------|------|
| gateway の reload / drain / routes_apply | `volta-platform-mcp`（`volta` namespace）が既に提供。重複を避ける |
| gateway の config_validate（--validate） | CLI を別プロセスで起動する必要があり、MCP サーバプロセスからは呼びにくい。traefik-migration skill で手順を配る |
| SAML 関連 tool | Rust 側の SAML 署名検証は simplified。本番推奨は Java sidecar。tool 化は避ける |
| webhook 管理 tool | cookie-only 認証で Bearer 非対応。需要が高まれば追加 |
| SCIM 関連 tool | 同上 |

## 9. 参加方法

### volta.service.json

```json
{
  "id": "vgw-mcp",
  "name": "Volta Gateway MCP",
  "description": "volta-gateway と auth-server の運用能力（監査ログ検索・ユーザー/テナント管理・gateway メトリクス・Traefik 移行）を MCP で提供",
  "type": "node",
  "hostname": "vgw-mcp.unlaxer.org",
  "port": 9214,
  "host": "192.168.1.50",
  "runtime": "systemd",
  "exec_start": "/home/opa/vgw-mcp/run.sh",
  "user": "opa",
  "auth": "minRole:OPERATOR",
  "health_check": "/healthz",
  "tags": ["mcp", "gateway", "auth", "ops"],
  "repo_url": "https://github.com/opaopa6969/auth-test/volta-gateway",
  "mcp": {
    "enabled": true,
    "port": 9214,
    "path": "/mcp",
    "namespace": "vgw",
    "min_role": "OPERATOR",
    "timeoutMs": 110000,
    "description": "volta-gateway/auth-server 運用 MCP（監査ログ・ユーザー/テナント検索・gateway メトリクス・Traefik 変換）"
  }
}
```

### 環境変数（EnvironmentFile `/home/opa/volta-secrets/vgw-mcp.env`）

- `VGW_AUTH_TOKEN` — auth-server admin API 用 Bearer token（JWT, ADMIN/OWNER ロール）
- `VOLTA_ADMIN_TOKEN` — gateway admin API 用 Bearer token
- `AUTH_SERVER_URL` — `http://192.168.1.8:7072`（デフォルト）
- `GATEWAY_URL` — `http://127.0.0.1:80`（デフォルト・loopback）
- `TRAEFIK_TO_VOLTA_BIN` — `traefik-to-volta` バイナリパス（ビルド済み）

### runtime

- systemd user unit `deploy/vgw-mcp.service`
- `Restart=on-failure`, `WantedBy=default.target`
- `Environment=PORT=9214`
- `EnvironmentFile=-/home/opa/volta-secrets/vgw-mcp.env`

## 10. テスト方針

e2e テスト（`mcp/test/e2e.mjs`）:
1. サーバ起動 → `GET /healthz` が 200
2. MCP クライアント（`StreamableHTTPClientTransport`）で接続 → `tools/list`
3. `audit_search`（dry-run 相当: read 系なのでそのまま実行）
4. `metrics`（gateway から Prometheus text を取得）
5. `traefik_convert`（サンプル Traefik YAML を変換）
6. `vgw://spec` resource を読む
7. `vgw://guide` resource を読む

テストは auth-server / gateway が稼働している前提（統合テスト）。無くても `/healthz` と `tools/list` は検証可能。
