# DD-006: volta-auth-proxy-rs リポジトリ戦略

**Date:** 2026-04-09
**Status:** Accepted
**Session:** [DGE座談会](../sessions/2026-04-09-auth-proxy-rs-repo.md)

## Decision

volta-auth-proxy-rs は **volta-gateway リポジトリ内に Cargo workspace** として構成する。
独立リポジトリでも Java 同居でもなく、ハイブリッド方式。

## Structure

```
volta-gateway/
  Cargo.toml (workspace members = ["gateway", "auth-core", "volta"])
  gateway/        ← proxy binary (現在の src/)
    Cargo.toml
    src/
  auth-core/      ← auth library crate (session, JWT, OIDC, MFA, Passkey)
    Cargo.toml
    src/
  volta/          ← unified binary (gateway + auth-core in-process)
    Cargo.toml
    src/main.rs
```

## Rationale

- **再利用性**: auth-core は独立 crate → volta-console, API server から利用可能
- **1 リポジトリ**: CI/CD が統一。gateway と auth の変更を同時に PR できる
- **段階的移行**: auth-core に JWT verify から始めて、OIDC flow を段階的に追加
- **最終形**: volta binary = gateway + auth-core の 1 プロセス (DD-005 Phase 4)

## Alternatives rejected

- **独立リポジトリ**: 依存管理が複雑、並行開発で sync が必要
- **Java 版に同居**: pom.xml + Cargo.toml 混在、ツールチェーン衝突
- **gateway の src/ に直接追加**: auth-core が gateway に結合、再利用不可
