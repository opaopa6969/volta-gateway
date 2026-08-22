---
name: traefik-migration
description: Traefik 設定を volta-gateway に移行する手順
volta:
  version: 2
  namespace: vgw
  locality: global
  applies_when: Traefik 設定を volta-gateway に移行するとき
  requires:
    tools: [vgw__traefik_convert, volta__gateway_routes_diff, volta__gateway_routes_apply]
  min_role: OPERATOR
  tags: [traefik, migration, gateway]
---

# Traefik → volta-gateway 移行手順

## 前提

- `traefik-to-volta` バイナリがビルド済みで `TRAEFIK_TO_VOLTA_BIN` 環境変数にパスが設定されている
- 元の Traefik 設定ファイル（docker-compose.yml または Traefik dynamic YAML）がある

## 1. 変換

`vgw__traefik_convert` に以下を渡す:

```
format: "docker-compose" | "traefik-yaml"
input: <Traefik 設定ファイルの内容>
```

volta-gateway 用 YAML が返る。

## 2. ポート・URL の修正

traefik-to-volta は以下を固定出力する:
- `server.port: 8080`
- `auth.volta_url: http://localhost:7070`

実際の環境に合わせて手動で修正する:
- `server.port` — 実際の gateway リスニングポート（prod: 80）
- `auth.volta_url` — 実際の auth-server URL（prod: http://192.168.1.8:7072）

## 3. 差分確認

`volta__gateway_routes_diff` で現在の routes との差分を確認する。

## 4. 適用

`volta__gateway_routes_apply` に `confirm: true` で差分を適用する。

## 5. 確認

- `https://<hostname>/healthz` が 200 になることを確認
- `vgw__routes_list` でルートが意図どおりに登録されたか確認

## 対応する Traefik 機能

- `traefik.http.routers.*` — host, rule, service → volta-gateway routing
- `traefik.http.services.*` — loadbalancer, servers → volta-gateway backends
- `traefik.http.middlewares.*` — cors, stripPrefix → volta-gateway cors_origins, strip_prefix

## 対応していない機能

- 一部の Traefik middleware（rate-limit, retry, buffering 等）は変換されない
- TLS 設定は ACME に任せるため変換しない
- TCP/UDP ルータは L4 proxy として別途設定する
