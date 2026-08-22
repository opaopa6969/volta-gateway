---
name: migrate-from-traefik
description: Traefik 設定を volta-gateway に移行する手順
volta:
  version: 2
  namespace: gw
  locality: global
  applies_when: Traefik 設定を volta-gateway に移行するとき
  requires:
    tools: [gw__convert_traefik, gw__validate_config, gw__patch_config, gw__reload]
  min_role: OPERATOR
  export: true
  tags: [traefik, migration, gateway]
---

# Traefik → volta-gateway 移行手順

## 1. 変換
`gw__convert_traefik` に Traefik 設定（docker-compose 形式または traefik-yaml 形式）を渡す。
volta-gateway 用 YAML が返る。

## 2. 検証
`gw__validate_config` で変換後の YAML を静的検証。

## 3. 適用
`gw__patch_config(confirm=false)` で dry-run → `gw__patch_config(confirm=true)` で適用。

## 4. リロード
`gw__reload(confirm=false)` で dry-run → `gw__reload(confirm=true)` でホットリロード。

## 注意
- traefik-to-volta は server.port:8080 と auth.volta_url:http://localhost:7070 を固定出力する
- 実際のポートや auth-server URL は手動で修正する必要がある
- 全ての Traefik middleware に対応しているわけではない
