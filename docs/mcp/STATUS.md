# MCP 化ステータス — auth-test/volta-gateway

> 最終更新: 2026-08-22

## 現在の状態: implemented → registered（deploy 中）

| 項目 | 状態 | 備考 |
|------|------|------|
| Phase 1 survey | done | `docs/mcp/survey.json`, `docs/mcp/SURVEY.md` |
| Phase 2 設計 | done | `docs/mcp/DESIGN.md` |
| MCP サーバ実装 | done | `mcp/server.mjs` (Node, namespace `vgw`, port 9214) |
| e2e テスト | done | `mcp/test/e2e.test.mjs` — 7/7 pass |
| volta.service.json | done | `volta.service.json` (id: `vgw-mcp`, port 9214, host 192.168.1.50) |
| deploy unit | done | `deploy/vgw-mcp.service`, `run.sh` |
| skills | done | `docs/skills/{gateway-ops,add-route,traefik-migration}/SKILL.md` + `skill://` resources |
| README MCP 節 | done | `README.md` に MCP 節追加 |
| issue-hub 協調 | open | issue #258 — auth-server admin API Bearer 対応依頼 |
| volta 登録 (svc_add) | pending | dry-run → 確認 → confirm |
| gateway routes 適用 | pending | dry-run → 確認 → apply |
| healthz 確認 | pending | `https://vgw-mcp.unlaxer.org/healthz` 200 |
| catalog 確認 | pending | `catalog__backend_status` で `vgw` が ready |

## 実装した tools（8 個）

1. `audit_search` — 監査ログ検索（auth-server, Bearer, ADMIN）
2. `user_search` — ユーザー検索（auth-server, Bearer, ADMIN）
3. `tenant_list` — テナント一覧（auth-server, Bearer, ADMIN）
4. `metrics` — Prometheus メトリクス（gateway, loopback, OPERATOR）
5. `routes_list` — ルート一覧（gateway admin, loopback, OPERATOR）
6. `backends_health` — バックエンド健全性（gateway admin, loopback, OPERATOR）
7. `stats` — リクエスト統計（gateway admin, loopback, OPERATOR）
8. `traefik_convert` — Traefik 設定変換（CLI, OPERATOR）

## 未実装の tools（issue-hub #258 で協調中）

以下は auth-server が `require_admin`（cookie only）を使っており、Bearer 非対応のため MCP wrapper からアクセスできない。issue #258 で Bearer 対応を依頼中。

- `session_list`, `session_revoke`
- `policy_evaluate`
- `data_export_start`, `data_export_status`, `data_export_result`
- `device_list`, `device_delete`

## resources（4 個 + 3 skill）

- `vgw://spec` — 能力仕様（tools/list から自動生成）
- `vgw://guide` — 使い方ガイド
- `vgw://flows` — 認証フロー定義一覧
- `vgw://parity` — Rust ↔ Java ルートパリティ表
- `skill://gateway-ops` — gateway 運用手順
- `skill://add-route` — auth-server ルート追加手順
- `skill://traefik-migration` — Traefik 移行手順

## issue-hub

- [#258](https://github.com/opaopa6969/issue-hub/issues/258) — `[mcp] vgw → auth-server: admin API の Bearer 対応依頼`
  - 対象: `GET /api/v1/admin/sessions`, `DELETE /admin/sessions/{id}`, `POST /api/v1/tenants/{id}/policies/evaluate`, `POST /api/v1/users/me/data-export`, `GET/DELETE /api/v1/users/me/devices*`
  - 状態: 暫定仕様で先行リリース。Bearer 対応後に該当 tool を有効化。

## deploy 手順（次にやること）

1. `volta__svc_add(manifest)` dry-run → 差分確認
2. `confirm: true` で登録
3. prod で git clone + `systemctl --user enable --now vgw-mcp`
4. `curl http://127.0.0.1:9214/healthz` が 200 になるまで確認
5. `volta__gateway_routes_diff()` → 自分の 1 件のみ → `volta__gateway_routes_apply(confirm=true)`
6. `https://vgw-mcp.unlaxer.org/healthz` 200 確認
7. `catalog__backend_status` で `vgw` が ready 確認

## 未決事項

1. auth-server Bearer 対応ルートの追加（issue-hub #258 解決後）
2. `config_validate` tool の追加（CLI を別プロセス起動する方法の検討）
3. webhook 管理 tool の追加（cookie-only 認証の問題解決後）

## 持ち主への質問

なし（2026-08-22 に deploy まで進めてよいと了承済み）
