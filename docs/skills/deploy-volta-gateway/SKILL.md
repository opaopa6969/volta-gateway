---
name: deploy-volta-gateway
description: gateway + auth-server のデプロイ・更新手順
volta:
  version: 2
  namespace: gw
  locality: service
  applies_when: gateway をデプロイ・更新するとき
  requires:
    tools: [gw__reload, gw__list_routes, gw__list_backends]
  min_role: OPERATOR
  export: true
  tags: [deploy, gateway, auth-server]
---

# gateway + auth-server デプロイ手順

## 1. ビルド
`cargo build --workspace --release`

## 2. 設定検証
`gw__validate_config` で設定ファイルを検証。

## 3. デプロイ
Docker: `docker compose up -d` または `docker stop volta-gateway && docker run ...`

## 4. 確認
- `gw__list_routes` でルート一覧
- `gw__list_backends` でバックエンド健全性
- `gw__stats` でリクエスト統計

## 5. ホットリロード（設定変更のみ）
`gw__reload(confirm=true)` で設定を再読み込み。

## 6. グレースフルシャットダウン（プロセス更新）
1. `gw__drain(confirm=true)` で drain 開始
2. healthz が 503 になるのを確認
3. 新プロセスを起動（reuse_port で無瞬断）
4. 旧プロセスの in-flight が終わったら終了
