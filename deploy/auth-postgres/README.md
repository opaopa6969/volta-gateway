# auth の本番 PostgreSQL（silver-hawk）

`volta-auth-postgres`（:54329、DB は `volta_auth_rs`。`volta_auth` は Java 時代の残り）。
元は `volta-workspace/volta-auth-proxy/docker-compose.yml`（archived）で動いていたが、
そちらは port が `0.0.0.0` で LAN に出ていて、パスワードも平文で入っていたので、2026-09-15 にここへ移した。

- **公開は loopback だけ**（`127.0.0.1:54329`）。auth-server は 127.0.0.1 で繋ぐ
- standby（p52）は **ssh トンネル**で入る（`../pg-standby/README.md` の「トンネル」）
- パスワードは `~/.config/volta-auth-postgres.env`（git に入れない。`env.example`）

```sh
cd ~/work/volta-workspace/volta-gateway
docker compose --env-file ~/.config/volta-auth-postgres.env -f deploy/auth-postgres/docker-compose.yml up -d
```

`name: volta-auth-proxy` と external volume `volta-auth-proxy_volta_auth_pgdata` は既存のものをそのまま指すので、
この compose で `up -d` してもデータは同じ。バックアップは volta-index `tools/auth-db-backup.sh`（04:30）。
