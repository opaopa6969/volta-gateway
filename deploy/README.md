# 認証サーバーの永続配置

本番の認証サーバーは Cargo の `target/` や checkout 内から実行しない。
2026-10-14 に `target/release/volta-auth-server` の欠落が再起動まで潜伏し、
`203/EXEC` と認証依存サービスの障害になった。`cargo clean` や checkout の掃除が
本番に影響しないよう、検証済みバイナリを `~/.local/lib/volta-auth/bin/` に配置する。
古い `prebuilt-bin/` への自動フォールバックは行わない。

## 初回導入・既存 unit の移行

```bash
cargo build --locked --release -p volta-auth-server
python3 deploy/install-auth-runtime.py target/release/volta-auth-server --install-unit
systemctl --user daemon-reload
systemctl --user restart volta-auth-rust.service
curl --fail --max-time 5 http://127.0.0.1:7072/healthz
```

既存 env、socket（standby の listen address を含む）、fence drop-in は保存する。
installer は enable / start / restart をしない。cold standby では restart しない。
初めて常時稼働させる primary に限り、明示的に
`systemctl --user enable --now volta-auth-rust.socket volta-auth-rust.service` を実行する。

## 更新

毎回ビルド・テスト後、上記 installer で新バイナリをコピーしてから restart する。
以後 `target/` のビルドだけでは本番バイナリは更新されない。
コピーは同じファイルシステム内で atomic replace し、旧版は `.previous` に保存する。
ソースツリーやビルド領域を消しても、実行ファイルと working directory は残る。

## 戻す

バイナリだけのロールバックは、既存 `.previous` を別の場所にコピーして installer に渡す。

```bash
cp ~/.local/lib/volta-auth/bin/volta-auth-server.previous /tmp/volta-auth-server-rollback
python3 deploy/install-auth-runtime.py /tmp/volta-auth-server-rollback
systemctl --user restart volta-auth-rust.service
curl --fail --max-time 5 http://127.0.0.1:7072/healthz
```

unit 移行も戻す場合は `~/.config/systemd/user/volta-auth-rust.service.previous` を
元の名前へ戻して `daemon-reload` する。その場合、旧 `target/release/` の実行ファイルが
存在することを先に確認する。フェンス・socket・DB は変更しない。
