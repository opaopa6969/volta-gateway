---
name: add-route
description: auth-server に新規エンドポイントを追加する手順
volta:
  version: 2
  namespace: vgw
  locality: repo
  applies_when: auth-server に新規エンドポイントを追加するとき
  requires: []
  min_role: ADMIN
  tags: [auth-server, route, development]
---

# auth-server ルート追加手順

1. `auth-server/src/handlers/` 配下の適切なファイル（admin.rs, extra.rs, auth.rs 等）にハンドラ関数を追加する
2. `auth-server/src/app.rs` の `build_router()` にルートを登録する（axum 0.8 書式 `{param}`）
3. 認証ミドルウェアを選択:
   - `require_session` — cookie session 必須（一般ユーザー向け）
   - `require_admin` — cookie session + ADMIN/OWNER ロール（cookie only, Bearer 非対応）
   - `require_admin_with_headers` — Bearer JWT or cookie session + ADMIN/OWNER ロール（MCP から呼ぶならこちら）
4. `cargo test -p volta-auth-server` でテストを実行
5. MCP wrapper に tool を追加する場合は `mcp/server.mjs` に `server.tool(...)` を追加
6. `vgw://spec` resource は自動的に更新される（tools/list から生成）
7. `docs/mcp/DESIGN.md` の tools 表を更新

## 注意

- Bearer 対応が必要な admin ルートは `require_admin_with_headers` を使う（`auth-server/src/helpers.rs:40-59`）
- `require_admin`（cookie only）を使うルートは MCP wrapper からアクセスできない
- issue-hub で Bearer 対応を依頼するか、初めから `require_admin_with_headers` を使う
