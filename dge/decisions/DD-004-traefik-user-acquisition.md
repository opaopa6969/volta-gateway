# DD-004: Traefik ユーザー獲得戦略

**Date:** 2026-04-08
**Status:** Accepted
**Session:** [DGE座談会](../sessions/2026-04-08-traefik-strategy.md)

## Decision

volta-gateway を standalone 製品として Traefik ユーザー（特にセグメント B: 5-20 サービスの小規模 SaaS）を取り込む。

## 戦略の柱

### 1. ポジショニング
- **売り文句**: 「6.6x 速い」ではなく「認証を気にしなくていい proxy」
- Caddy との差別化は単品比較ではなく volta エコシステム全体
- Traefik の「代替」ではなく「卒業先」

### 2. 移行ファネル
```
認知: ベンチマーク比較記事
興味: Getting Started (3 steps)
試用: --validate で config 検証
移行: traefik-to-volta converter
定着: services.json / Docker labels + hot reload
```

### 3. 技術ロードマップ
```
Phase 1: Standalone 完全化
  - ACME DNS-01 (ワイルドカード)
  - ゼロ設定 HTTPS (host から自動)
  - Docker labels source 本実装

Phase 2: Migration tooling
  - traefik-to-volta config converter
  - Getting Started guide
  - ベンチマーク比較記事

Phase 3: Ecosystem
  - volta-console 統合デモ
  - Plugin system (Wasm)
  - FraudAlert JA3 連携
```

### 4. ターゲットペルソナ
SaaS 創業者、エンジニア 2-5 人チーム。Traefik の labels が 20 行超、ForwardAuth chain が複雑化、新メンバーが設定を理解できない。

## Rationale

- 機能で追いつくだけでは乗り換え理由にならない（大和田）
- 最優先は移行ツール — 試用までは README で十分（ヤン）
- 単品で戦うな、プラットフォームで戦え（大和田）
- ユーザーの実在確認が未了 — 推測ではなく定量調査すべき（今泉）

## Alternatives considered

- C セグメント (50+ services, K8s) を狙う → Traefik/Envoy の牙城、工数膨大
- A セグメント (homelab) を狙う → 金にならない
- Docker labels を実装しない → 日常運用の UX で負ける
