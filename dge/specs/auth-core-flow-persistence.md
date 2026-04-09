# auth-core — Flow Persistence (auth_flows + transitions)

> Status: Implementing
> Date: 2026-04-09
> Depends on: SqlStore Phase 1 ✅

## 課題

tramli の `FlowStore<S>` trait は in-process 専用設計:
- `FlowEngine` は `InMemoryFlowStore<S>` にハードコード
- `get_mut()` は `&mut FlowInstance<S>` を返す (async 不可)
- `FlowInstance` は `std::time::Instant` (非シリアライズ)
- `FlowContext` は `Box<dyn CloneAny>` (型消去)

Java 版は Jackson + JSONB で context をまるごとシリアライズするが、
Rust では同じアプローチが取れない。

## 解決: Persistence Adapter パターン

```
HTTP Handler
  → AuthService (async)
    → FlowPersistence.create() — DB に flow metadata 保存
    → FlowEngine (in-memory) で SM 駆動
    → FlowPersistence.update() — DB に state/version 更新
    → FlowPersistence.record_transition() — 遷移ログ保存
```

### 保存するもの
- **auth_flows**: id, session_id, flow_type, current_state, guard_failure_count, version, timestamps, exit_state, summary (JSONB)
- **auth_flow_transitions**: flow_id, from_state, to_state, trigger, error_detail, timestamp

### 保存しないもの
- FlowContext の中身 (型消去データ) — active な flow の lifetime 中は in-memory で持つ
- completed flow の context は summary JSONB に必要な情報だけ保存

## コンポーネント

### FlowPersistence (store/flow.rs)

```rust
pub struct FlowRecord {
    pub id: Uuid,
    pub session_id: String,
    pub flow_type: String,
    pub current_state: String,
    pub guard_failure_count: i32,
    pub version: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub exit_state: Option<String>,
    pub summary: Option<serde_json::Value>,
}

#[async_trait]
pub trait FlowPersistence: Send + Sync {
    async fn create(&self, record: FlowRecord) -> Result<(), AuthError>;
    async fn find(&self, id: Uuid) -> Result<Option<FlowRecord>, AuthError>;
    async fn update_state(&self, id: Uuid, state: &str, version: i32) -> Result<(), AuthError>;
    async fn complete(&self, id: Uuid, exit_state: &str, summary: Option<serde_json::Value>) -> Result<(), AuthError>;
    async fn record_transition(&self, flow_id: Uuid, from: &str, to: &str, trigger: &str, error: Option<&str>) -> Result<(), AuthError>;
    async fn find_active_by_session(&self, session_id: &str) -> Result<Vec<FlowRecord>, AuthError>;
    async fn cleanup_expired(&self) -> Result<usize, AuthError>;
}
```

PgStore に `FlowPersistence` を追加実装。

## マイグレーション

- `006_create_auth_flows.sql`
- `007_create_auth_flow_transitions.sql`

## テスト

Integration test: create → update_state → record_transition → complete → find
