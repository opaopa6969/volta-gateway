# auth-core Phase 2.5 — Integration Tests (testcontainers + PostgreSQL)

> Status: Draft → Implementing
> Date: 2026-04-09
> Depends on: Phase 2 (Processor DB配線) ✅

## 概要

PgStore の全 DAO trait 実装を testcontainers で起動した PostgreSQL コンテナに対して検証する。

## 方式

- `testcontainers` crate でテスト内に PostgreSQL コンテナを起動
- sqlx の `PgPool` を接続
- `auth-core/migrations/` の SQL を実行してスキーマ作成
- 各 Store trait のメソッドをCRUD順にテスト

## dev-dependencies

```toml
[dev-dependencies]
testcontainers = "0.23"
testcontainers-modules = { version = "0.11", features = ["postgres"] }
```

## テスト構成

`auth-core/tests/pg_store_test.rs` (`#[cfg(feature = "postgres")]`)

### テストケース

| Store | テスト |
|-------|--------|
| UserStore | upsert → find_by_id → find_by_email → find_by_google_sub → update_display_name → soft_delete |
| TenantStore | create → find_by_id → find_by_slug → create_personal (with membership) → find_by_user |
| MembershipStore | create → find → list_by_tenant → update_role → count_active_owners → deactivate |
| InvitationStore | create → find_by_code → list_by_tenant → accept (tx) → cancel |

## 注意

- Docker が必要 (CI で `services: postgres` か testcontainers Docker-in-Docker)
- テスト実行: `cargo test -p volta-auth-core --features postgres -- --ignored`
  (`#[ignore]` 付きで通常テストとは分離)
