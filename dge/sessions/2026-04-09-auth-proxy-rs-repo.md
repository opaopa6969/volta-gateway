# DGE 座談会: volta-auth-proxy-rs リポジトリ戦略

> Date: 2026-04-09
> Structure: 🗣 座談会
> Characters: ☕ ヤン / ⚔ リヴァイ / 🦈 大和田 / 👤 今泉

## 選択肢

| Option | Pros | Cons |
|--------|------|------|
| A. 独立リポ | 関心分離、独立 CI | 依存管理複雑、3 リポ |
| B. Java 同居 | 段階移行しやすい | pom.xml + Cargo.toml 混在 |
| C. gateway 統合 | 1 バイナリ最終形 | 肥大化、再利用不可 |
| **D. Cargo workspace** | **A+C のいいとこ取り** | — |

## Decision

**D. Cargo workspace** — gateway/ + auth-core/ + volta/ (unified binary)

## Key Insight

- リヴァイ: 「Cargo workspace を使え」
- 大和田: 「単体で再利用できない auth は価値が半減する」
- ヤン: 「workspace なら CI は 1 つ、バージョンは独立、crates.io に auth-core だけ publish できる」

DD-006 として記録。
