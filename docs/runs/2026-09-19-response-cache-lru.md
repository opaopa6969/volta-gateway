# 応答キャッシュ容量管理 — Progressive反復1

対象: volta-gateway、issue #184。開始 2026-09-19 17:03 JST。
Builder: Codex (GPT-6)、上限3反復、変更単位は応答キャッシュの追い出しのみ。

## 観測事実

- `AGENTS.md`、README、現行spec、最近8件の変更、worktree一覧、open issues/PR、CIを確認。
- 指定の `docs/product-brief.md` と `CLAUDE.md` は存在しない。
  READMEとspecの既存LRU契約を根拠に、小さな不具合修正を選んだ。
- 開始時のopen issue/PRは0件。main `754a370` のCIは成功。
  提供された専用worktreeはclean。他のworktreeには変更を加えていない。
- `ResponseCache` はhitを追い出し順序に反映せず、容量到達時は作成時刻で削除。
  同一キーの更新でも別キーを削除し、容量0でも1件を保存する。
- 回帰テストを先に追加した修正前の実行は13成功・3失敗。
  失敗: hitした項目の保持、既存キー更新の容量維持、容量0で保存しないこと。

## 仮説・判断・実施内容

頻繁に参照する応答が削除され、不要なバックエンド呼び出しにつながり得る。
実トラフィックでの頻度や性能改善幅は未測定。

既存のHashMap/Mutexと公開APIを維持し、TTL用の作成時刻とは別に最終参照時刻を
保持する最小変更を採用。hit・保存・更新で参照順序を更新し、同一キーの更新は
追加スロット不要とする。容量0は保存しない。依存・YAML設定・公開範囲は変更しない。
容量到達時の走査は既存同様O(n)。新しいLRU基盤や実行基盤は導入しない。

## 更新した終了要件・検証

- hit済み項目の保持とclone間の順序共有。
- 容量到達時の既存キー更新で他項目を保持し、更新も最近の参照として扱う。
- 期限切れを優先削除。hitでTTLを延長しない。容量0は保存しない。
- `cargo test -p volta-gateway`: 383成功、0失敗（lib/binの重複実行を含む）。
- `cargo fmt --check` と `git diff --check`: 成功。
- `cargo clippy -p volta-gateway --all-targets -- -D warnings`: 成功。
- PR CIと独立Judgeの検収結果はPRに記録する。
- accept後のみFinalizerがmergeし、issue closeを確認する。

再現コマンド（専用ビルド出力先）:

```bash
export CARGO_TARGET_DIR=/tmp/volta-gateway-autonomy-cache-target
export CARGO_PROFILE_DEV_DEBUG=0
cargo test -p volta-gateway --test cache_plugin_test cache_
cargo test -p volta-gateway
cargo fmt --check
cargo clippy -p volta-gateway --all-targets -- -D warnings
```

修正前の再現は、base `754a370` の別worktreeに本PRの
`gateway/tests/cache_plugin_test.rs` だけを適用して最初のテストを実行する。
共有ツリーへの上書きや履歴のresetは不要。

## 次の判断・残る不確実性

BuilderはPRを作成し、独立Judgeへ証拠を渡す。acceptまではmergeしない。
SPEC §5.9には今回対象外の設計例と実装の差が残るため、容量引数とYAML設定を
混同しない注記を加えた。次候補はこの設定・機能記述の実装照合。

補償方法: `git revert -m 1 <merge_sha>` を別ブランチで実行し、revert PRで戻す。
本番操作・データ変更・履歴削除はない。
実行時間とJudge/Finalizer結果はPRコメントを最終記録とする。
トークン消費量は本記録作成時点では未取得。

## 情報の取得記録

取得日: 2026-09-19。外部コードや外部仕様は取り込んでいない。
GitHub上の同一repoの運用メタデータだけを `gh` で取得した。
利用条件: GitHub Terms of Serviceに従うAPI利用。
repo READMEはMITを表記するが、GitHub APIのlicenseInfoはnull。
本作業ではライセンスの変更・新たな許諾の推定は行わない。

- repo/README: https://github.com/opaopa6969/volta-gateway/tree/754a370c703311824b87c97d56c79c6c7b581e5b
- 開始時main CI: https://github.com/opaopa6969/volta-gateway/actions/runs/35355751850
- 受入条件: https://github.com/opaopa6969/volta-gateway/issues/184
- 利用条件: https://docs.github.com/en/site-policy/github-terms/github-terms-of-service

取得の再現: `gh issue list --state open`、`gh pr list --state open`、
`gh run list --limit 8`、`gh repo view --json nameWithOwner,visibility,licenseInfo`。
