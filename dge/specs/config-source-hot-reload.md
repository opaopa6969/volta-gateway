# Config Source Hot Reload 統合

> Status: Implementing
> Date: 2026-04-09

## 概要

config_source (Docker labels, services.json, HTTP polling) の watch() から
受信したルートを main.rs の ArcSwap<HotState> にマージして反映。

## 設計

### フロー

```
ConfigSource::watch() → mpsc::Sender<Vec<RouteEntry>>
  → config_source_watcher task → merge routes → HotState::merge_dynamic()
    → ArcSwap::store()
```

### マージ戦略

- YAML config のルートは **static** (常に保持)
- config source のルートは **dynamic** (追加・上書き)
- host が一致する場合は dynamic が優先
- dynamic routes は source が停止/空を返した場合に削除

### 変更箇所

1. `main.rs`: config source watcher タスクを spawn
2. `proxy.rs` (`HotState`): `merge_dynamic_routes()` メソッド追加
3. `config_source.rs`: `spawn_watchers()` ヘルパー追加

## 実装

### main.rs 追加コード (config source watcher)

```rust
// Spawn config source watchers
if !config.config_sources.is_empty() {
    let sources = config_source::create_sources(&config.config_sources);
    config_source::spawn_watchers(sources, hot.clone(), &config);
}
```
