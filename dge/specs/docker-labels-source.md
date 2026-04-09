# Docker Labels Config Source

> Status: Implementing
> Date: 2026-04-09

## 概要

`config_source.rs` の DockerLabelsSource stub を bollard crate で実装。
Docker コンテナの `volta.*` ラベルからルーティング設定を自動検出。

## 方式

- `bollard` crate で Docker Engine API に接続 (Unix socket)
- `load()`: `GET /containers/json` → volta.host ラベルのあるコンテナを RouteEntry に変換
- `watch()`: `GET /events` → container start/stop/die で再読み込み

## ラベル仕様 (既存 parse_labels のまま)

| Label | 用途 | デフォルト |
|-------|------|-----------|
| `volta.host` | ルーティングホスト名 (必須) | — |
| `volta.port` | バックエンドポート | 3000 |
| `volta.public` | 認証スキップ | false |
| `volta.cors_origins` | CORS origins (カンマ区切り) | — |
| `volta.auth_bypass` | 認証バイパスパス (カンマ区切り) | — |
| `volta.app_id` | アプリID | — |
| `volta.strip_prefix` | パスリライト | — |

## 依存追加

```toml
bollard = "0.18"
```

## テスト

既存の `parse_labels` テスト + コンパイルチェック。
Docker 実接続テストは CI 依存 (testcontainers と同じ要件)。
