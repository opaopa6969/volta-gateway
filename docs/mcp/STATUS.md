# MCP 化 STATUS — volta-workspace/volta-gateway (namespace: `gw`)

## 進捗

- [x] Phase 1 survey: `docs/mcp/survey.json` (decision: `wrap`)
- [x] DESIGN.md: `docs/mcp/DESIGN.md`
- [x] issue-hub 協調:
  - [#265](https://github.com/opaopa6969/issue-hub/issues/265) — gw ↔ volta: gateway ルート操作の二重管理（暫定: volta__gateway_routes_apply を正）
  - [#267](https://github.com/opaopa6969/issue-hub/issues/267) — gw → vgw: 読取系重複通知（暫定: 両方提供）
- [x] MCP サーバ実装: `mcp/server.mjs` (Node, @modelcontextprotocol/sdk)
- [x] テスト: `mcp/test/e2e.test.mjs` — 16 tests, all pass
- [x] volta.service.json: id `gw-mcp`, port 9217, namespace `gw`
- [x] deploy unit: `deploy/gw-mcp.service`
- [x] run.sh
- [x] skill: `docs/skills/gateway-ops/SKILL.md`, `docs/skills/migrate-from-traefik/SKILL.md`, `docs/skills/deploy-volta-gateway/SKILL.md`
- [x] README に MCP 節追加
- [ ] deploy: svc_add → gateway routes → healthz 200 → backend_status ready

## dry-run 結果

### svc_add (dry-run)

(後で記録)

### gateway_routes_diff

(後で記録)

## 未決事項

- issue-hub #265: `gw__patch_config` と `volta__gateway_routes_apply` の二重管理。暫定案で進行中。
- issue-hub #267: `gw` と `vgw` の読取系重複。暫定案で進行中。
- admin token を MCP バックエンドにどう渡すか: `EnvironmentFile=/home/opa/volta-secrets/gw-mcp.env` で `VOLTA_ADMIN_TOKEN` を注入する想定。

## 持ち主への質問

- なし（暫定案で進行可能）
