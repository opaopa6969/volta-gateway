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
- [x] deploy: svc_add → gateway routes → healthz 200 → backend_status ready

## 結果

- **svc_add**: gw-mcp 登録完了（host=192.168.1.8, port=9217, namespace=gw）
- **gateway_routes_apply**: gw-mcp.unlaxer.org -> http://192.168.1.8:9217 追加完了
- **healthz**: https://gw-mcp.unlaxer.org/healthz = 200
- **catalog__backend_status**: namespace=gw, status=ready, tools=12
- **tools/list**: gw__list_routes, gw__list_backends, gw__stats, gw__get_config, gw__metrics,
  gw__patch_config, gw__clear_overlay, gw__reload, gw__drain, gw__reset_circuit,
  gw__validate_config, gw__convert_traefik

## dry-run 結果

### svc_add (dry-run)

- exit: 0, exists: false（新規サービス）
- entry: id=gw-mcp, type=node, port=9217, host=192.168.1.50, runtime=systemd
- mcp: namespace=gw, min_role=MEMBER, path=/mcp
- cloudflare: enabled=true, hostname=gw-mcp.unlaxer.org
- cli_preview: 正常（services.json, gateway routing, health targets 全て dry-run 通過）
- 結果: 重複なし、新規登録として問題なし → confirm:true で進行

### gateway_routes_diff

- 既存 routing: 68 件 / services.json から導出: 67 件 / マージ後: 69 件
- 変更:
  - `[新規] gw-mcp.unlaxer.org -> http://192.168.1.50:9217` ← 自分の 1 件のみ
  - `[保護] auth.unlaxer.org.public` — 既存の保護（自分の変更ではない）
- 温存（2 件）: adoyose-admin, mahjong-mcp — services.json に対応が無い（手動設定として温存）
- 結果: 自分の 1 件以外に変更なし → 安全に apply 可能

## 未決事項

- issue-hub #265: `gw__patch_config` と `volta__gateway_routes_apply` の二重管理。暫定案で進行中。
- issue-hub #267: `gw` と `vgw` の読取系重複。暫定案で進行中。
- admin token を MCP バックエンドにどう渡すか: `EnvironmentFile=/home/opa/volta-secrets/gw-mcp.env` で `VOLTA_ADMIN_TOKEN` を注入する想定。

## 持ち主への質問

- なし（暫定案で進行可能）

## 備考

- host を 192.168.1.50 (prod) → 192.168.1.8 (WSL) に修正。割当表は 192.168.1.50 を指定していたが、MCP サーバを WSL で動かしたため。gateway (Docker on 192.168.1.50) から 192.168.1.8:9217 にアクセス可能。
