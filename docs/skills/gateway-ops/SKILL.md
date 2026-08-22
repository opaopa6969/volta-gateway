---
name: gateway-ops
description: gateway リバースプロキシの運用手順（drain, reload, routes 確認）
volta:
  version: 2
  namespace: vgw
  locality: service
  applies_when: gateway の運用操作が必要なとき
  requires:
    tools: [vgw__routes_list, vgw__backends_health, volta__gateway_reload]
  min_role: OPERATOR
  tags: [gateway, ops, drain, reload]
---

# gateway 運用手順

## ルート確認

`vgw__routes_list` で現在のルート一覧を取得する。各ルートの host, backends, app_id, public が分かる。

## バックエンド健全性

`vgw__backends_health` で各バックエンドの健全性と circuit breaker 状態を確認する。

- `alive: true` — 正常
- `circuit_state: closed` — 正常（回路閉じている = リクエスト通過）
- `circuit_state: open` — 異常検出で回路が開いている = リクエスト遮断中
- `circuit_failures: N` — 連続失敗回数

## reload

`volta__gateway_reload` で設定を再読み込みする。dry-run 既定なので `confirm: true` で実行。

## drain

gateway の graceful drain は `volta__gateway_reload` ではなく、`POST /admin/drain` を叩く必要がある。
これは `vgw` namespace には tool として公開していない（volta-platform-mcp 側で管理）。

## routes 適用

1. `volta__gateway_routes_diff` で差分を確認
2. 意図どおりなら `volta__gateway_routes_apply` に `confirm: true` で適用
3. `https://<hostname>/healthz` が 200 になることを確認
