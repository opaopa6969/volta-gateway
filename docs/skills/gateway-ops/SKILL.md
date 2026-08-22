---
name: gateway-ops
description: gateway リバースプロキシの運用手順（drain, reload, routes 確認）
volta:
  version: 2
  namespace: gw
  locality: service
  applies_when: gateway の運用操作が必要なとき
  requires:
    tools: [gw__list_routes, gw__list_backends, gw__reload]
  min_role: OPERATOR
  export: true
  tags: [gateway, ops, drain, reload]
---

# gateway 運用手順

## ルート確認
`gw__list_routes` で現在のルート一覧を取得。

## バックエンド健全性
`gw__list_backends` で circuit breaker 状態を確認。

## reload
`gw__reload(confirm=false)` で dry-run → `gw__reload(confirm=true)` で実行。

## drain
`gw__drain(confirm=false)` で dry-run → `gw__drain(confirm=true)` で実行。
healthz が 503 になるので、上流 LB/CF が新規トラフィックを止めるのを待つ。

## 設定変更
`gw__get_config` → `gw__patch_config(confirm=false)` で dry-run → `gw__patch_config(confirm=true)` で適用。

## インシデント対応
`gw__stats` で 5xx スパイク検知 → `gw__list_backends` で CB オープン特定 → `gw__reset_circuit(confirm=true)` でリセット → `volta__svc_logs` でログ確認。
