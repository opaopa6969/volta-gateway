# UDP応答元検証 — Progressive反復2/3 Builder

対象: volta-gateway、issue #188。実施日: 2026-09-19。

## 観測事実

- `AGENTS.md`、README、SPEC、CI定義、設定・L4実装、最近の変更、open issue/PR、worktreeを確認。
- 指定の `docs/product-brief.md` と `CLAUDE.md` は存在しない。
- 現作業ツリーと前jobのworktreeは開始時clean。他の作業ツリーは変更していない。
- PR #187はmerge済み。merge SHA `be4fbc52b129ea2200f649520d81aecb92063f09` の
  main CI `35436485247` は成功。開始時点のopen issue/PRは0件。
- UDP応答待ちは `recv_from` の送信元を無視していた。
- 応答検証だけを修正前の処理に戻して新しい注入テストを実行すると、3件とも
  「別送信元のパケットがクライアントに届いた」で失敗（終了コード101）。

## 仮説・実施内容・判断理由

応答待ち中に別IPや同IP別ポートからパケットを送れば、クライアントへ注入できる。
実ソケットの回帰テストで再現した。

既存のソケット構成を保ち、設定backendの `SocketAddr` と一致する応答だけを受理する。
不一致パケットは破棄して待機を続ける。ループ全体を既存の5秒timeoutで囲み、
不一致パケットで期限を延長しない。空allowlistでも応答元検証は省略しない。
テストでOS割当ポートを安全に使うため、bind済みlistener/socketを受け取る内部関数を分離した。
新規依存、Node/npm、実行基盤、設定形式の変更はない。
SPEC §10.5に応答元とtimeoutの契約を追記した。

## 更新終了要件と検証証拠

- backendのIP・ポートが一致する応答のみ転送。
- 許可リスト外IP、同IP別ポート、空allowlistでの応答注入を拒否し、続く正常応答を転送。
- TCP/UDPそれぞれのallowlist許可・拒否、空リスト時の正常通信を実ソケットで検証。
- 既存の不正CIDR拒否・設定変換のテストも実行。
- `cargo test -p volta-gateway l4_proxy`: 17件成功×lib/bin。
- `cargo test -p volta-gateway`: 415件成功（lib/binの重複を含む）、失敗0。
- `cargo fmt --check`、`git diff --check`: 成功。
- `cargo clippy -p volta-gateway --all-targets -- -D warnings`: 成功。

再現手順:

```bash
export CARGO_TARGET_DIR=/tmp/volta-gateway-autonomy-cache-target
export CARGO_PROFILE_DEV_DEBUG=0
cargo test -p volta-gateway --lib udp_response_
cargo test -p volta-gateway l4_proxy
cargo test -p volta-gateway
cargo fmt --check
cargo clippy -p volta-gateway --all-targets -- -D warnings
git diff --check
```

修正前の再現は使い捨てworktreeで本PRのテストと内部関数分離を維持し、応答待ちだけを
`timeout(Duration::from_secs(5), socket.recv_from(&mut buf))` と
`Ok(Ok((resp_len, _)))` に戻して `cargo test -p volta-gateway --lib udp_response_` を実行する。

## 次の判断・残る不確実性

Builderはcommit・push・PR作成まで。独立Judgeの判定は行わず、mergeもしない。
Judgeは実装と上記証拠を検収し、accept後にFinalizerがPR CI成功を確認して
`gh pr merge --merge --delete-branch` を実施する。
Finalizerは修正merge SHAのmain CI成功、issue #188のclose、関連未完了PRの有無を
GitHubから確認する。これらはBuilder終了時点では未完了。

5秒timeoutはコード構造で維持し、実時間の期限回帰テストは未追加。
既存の逐次UDP処理を維持しており、同時要求の多重化やパケットの暗号学的認証は対象外。
ローカル検証はLinux loopback上で実施。workspace全体とPostgreSQL検証はPR CIへ委ねる。
補償は `git revert -m 1 <merge_sha>` を別ブランチで実行してrevert PRを作成する。

## 情報取得記録

取得日: 2026-09-19。外部コードや資料の取り込みはない。
同一repoのGitHub運用メタデータのみをAPIで取得。利用条件: GitHub Terms of Service。

- 前PR: https://github.com/opaopa6969/volta-gateway/pull/187
- 前merge CI: https://github.com/opaopa6969/volta-gateway/actions/runs/35436485247
- 受入条件: https://github.com/opaopa6969/volta-gateway/issues/188
- 利用条件: https://docs.github.com/en/site-policy/github-terms/github-terms-of-service

取得の再現: `gh pr list --state open`、`gh issue list --state open`、
`gh pr view 187 --json state,mergeCommit,url`、
`gh run view 35436485247 --json headSha,conclusion,url`。
