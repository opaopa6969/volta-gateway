# auth-server docs

## 構造

| Dir / File | 内容 |
|---|---|
| `sync-from-java-2026-04-14.md` | Java 同期バッチの完了ステータス |
| `backlog.md` | 未実装タスクリスト (P0/P1/P2) — 各項目の spec/arch file へリンク |
| `specs/<item>.md` | 個別タスクの仕様書 (Goal / API / DB / Behavior) |
| `arch/<item>.md` | 設計判断メモ (なぜその実装にしたか / 代替案 / トレードオフ) |
| `tests/` | 統合テスト用の fixture 置き場 (実際の unit test は `auth-server/src/*/tests` 内) |

## Spec / Arch / Test 分担

- **Spec** は「何を実装するか」。目的、API 形状、データベース、期待動作。新人がこれだけ読んで動き始めれば PR を書ける粒度。
- **Arch** は「なぜそう実装したか」。採用理由 / 却下案 / 将来の拡張余地。コードを読んでも分からない判断が入る。
- **Tests** は unit は各モジュール内 (`#[cfg(test)] mod tests`)、integration は `auth-server/tests/*.rs`。

新規項目を起こすときは:
1. `backlog.md` から spec/arch file を作成
2. spec 通りに実装 + unit test
3. backlog の該当項目にチェックとリンク追加
