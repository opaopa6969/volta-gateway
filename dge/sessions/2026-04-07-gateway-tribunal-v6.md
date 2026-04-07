# DGE 査読劇 v6: volta-gateway — セキュリティ・品質・構造診断

> Date: 2026-04-07
> Structure: ⚖ 査読劇 (tribunal) — Round 6
> Evaluators: 😈 Red Team / ⚔ リヴァイ / 🏥 ハウス
> Subject: volta-gateway v0.1.0 — Phase 1-4 + Phase 5 + Layer 3 完了版

## Verdicts

| Reviewer | Verdict |
|----------|---------|
| 😈 Red Team | **Major Revision** — WebSocket + L4 無制限、ACME + force_https 干渉 |
| ⚔ リヴァイ | **Major Revision** — compression ヘッダ消失バグ、テストゼロ追加、proxy.rs 肥大 |
| 🏥 ハウス | **Major Revision** — compression ヘッダ消失 = 本番事故。テスト不在は構造的問題 |

## Key Insight

**compression でレスポンスヘッダが消失するバグ (GW-36) は Critical。**
`response.into_body()` で body を取得した後、元の headers にアクセスできなくなる。
新しい Response に Set-Cookie, Cache-Control, ETag 等が含まれない。
ユーザーのセッション cookie が消える。CDN キャッシュ制御が壊れる。

**テストが Phase 1 から変わっていない (8テスト据え置き)。**
9 機能追加・0 テスト追加。WebSocket, circuit breaker, compression, CORS, L4 — すべて未検証。

## Gaps (7 new)

| # | Gap | Category | Severity | Action |
|---|-----|----------|----------|--------|
| **GW-36** | **compression でレスポンスヘッダ消失 (Set-Cookie, Cache-Control 等)** | **バグ** | **Critical** | **今すぐ** |
| GW-37 | WebSocket tunnel に同時接続数制限なし (fd 枯渇) | セキュリティ | High | Phase 6 |
| GW-38 | force_https が ACME HTTP-01 チャレンジをブロック | 運用 | High | Phase 6 |
| GW-39 | proxy.rs 肥大化 (600行超、handle() 200行超) | 保守性 | Medium | Phase 7 |
| GW-40 | Phase 5 + Layer 3 のテストがゼロ | 品質 | High | Phase 6 |
| GW-41 | L4 proxy に IP 制限なし + ドキュメント不足 | セキュリティ | Medium | Phase 6 |
| GW-42 | URI parse の unwrap_or_default() で不正ルーティングリスク | セキュリティ | Medium | Phase 6 |

## 自動セキュリティ精査で追加発見 (subagent)

| Issue | Severity | Description |
|-------|----------|-------------|
| IPv6 redirect bug | High | force_https の host パースが IPv6 リテラルで壊れる ([::1 になる) |
| CORS wildcard default | High | cors_origins 未設定 → "*" は意図しないオープン CORS |
| X-Forwarded-For injection | Medium | chain 未検証。攻撃者が偽 IP を注入可能 |
| UDP source validation | Medium | L4 UDP proxy で応答の送信元を検証していない |
| Rate limiter window race | Medium | 同一ミリ秒の並行リクエストで rate limit bypass |
| ACME cache directory | Medium | cache_dir のパーミッション未検証 |
| metrics counter leak | Medium | task panic 時に in_flight counter がデクリメントされない |

## Verdicts 推移

| Reviewer | v1 | v2 | v3 | v4 | v5 | v6 |
|----------|----|----|----|----|-----|-----|
| 🏗️ SRE | — | — | — | Reject | Minor | — |
| 🌐 Proxy | Major | Minor | Accept | Major | Minor | — |
| 🔧 App | — | — | — | Major | Minor | — |
| 😈 Red Team | — | Major | Accept | — | — | **Major** |
| ⚔ リヴァイ | — | — | — | — | — | **Major** |
| 🏥 ハウス | — | — | — | — | — | **Major** |

## 反論結果

| Gap | 反論 | 結論 |
|-----|------|------|
| GW-36 compression ヘッダ | 認める。into_parts() で修正 | **今すぐ修正** |
| GW-37 WebSocket 制限 | 認める。max_websocket_connections 追加 | Phase 6 |
| GW-38 ACME + force_https | 認める。/.well-known/ を除外 | Phase 6 |
| GW-39 proxy.rs 肥大化 | 保留。機能安定後に分割 | Phase 7 |
| GW-40 テスト不足 | 認める。CB, compression, CORS, WS, L4 | Phase 6 |
| GW-41 L4 IP 制限 | 認める。IP 制限 + ドキュメント | Phase 6 |
| GW-42 URI unwrap | 保留。panic する unwrap だけ修正 | Phase 6 |
| SIGHUP file I/O | 反対（優先度低）。NFS シナリオは非現実的 | 放置 |
