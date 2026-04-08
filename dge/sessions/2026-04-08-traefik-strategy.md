# DGE 座談会: Traefik ユーザー獲得戦略

> Date: 2026-04-08
> Structure: 🗣 座談会
> Characters: ☕ ヤン / 👤 今泉 / 🎰 利根川 / 🦈 大和田 / 😈 Red Team

## Key Insights

1. **ターゲットはセグメント B** (5-20 サービスの小規模 SaaS)
2. **売り文句を変える**: 「6.6x 速い」→「認証を気にしなくていい proxy」
3. **最大の脅威は Caddy** (Traefik ではない) — 単品比較では負ける
4. **最優先は移行ツール** (traefik-to-volta converter)
5. **プラットフォームで戦え** — gateway + auth + console の統合

## Gaps (11)

| # | Gap | Category | Severity |
|---|-----|----------|----------|
| STR-1 | ターゲットユーザーの実在確認 | リサーチ | Medium |
| STR-2 | ACME DNS-01 (ワイルドカード) | 機能 | High |
| STR-3 | ゼロ設定 HTTPS | DX | High |
| STR-4 | Docker labels source 本実装 | 機能 | High |
| STR-5 | docker-compose → services.json 自動生成 | ツール | Medium |
| STR-6 | README メッセージング変更 | マーケ | High |
| STR-7 | Getting Started guide | DX | High |
| STR-8 | Caddy 差別化 (エコシステム訴求) | 戦略 | Medium |
| STR-9 | volta-console 統合デモ | マーケ | Medium |
| STR-10 | traefik-to-volta converter | ツール | Critical |
| STR-11 | ベンチマーク比較記事 | マーケ | High |

## Decision

DD-004 として記録。
