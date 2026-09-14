# auth PostgreSQL の standby（p52）

> 置き場所について: 本番の `volta-auth-postgres` は `volta-workspace/volta-auth-proxy/docker-compose.yml`（Java 時代の compose、リポジトリは **archived**）で動いている。Rust の auth-server はこのリポジトリが所有するので、standby の配備もここに置く。compose 自体をこちらへ移すのは別課題。

silver-hawk の `volta-auth-postgres`（:54329）を p52 にストリーミング複製する。昇格は手動。

| ファイル | 役割 |
|---|---|
| `bootstrap.sh` | `pg_basebackup -R -S p52_standby` で複製を作り、`hot_standby=on` で起動 |
| `promote.sh` | 手動昇格。`pg_ctl promote` → LAN へ再束縛 |

## primary 側（済み・2026-09-15）

- ロール `replicator`（REPLICATION LOGIN）。パスワードは `~/.config/volta-auth-standby/p52-replicator.secret`（silver-hawk）と `~/volta-auth-standby/replicator.pw`（p52）。**hub を経由せず rrsync 経路で配った**
- `pg_hba.conf`: `host replication replicator 172.20.0.0/16 scram-sha-256`。**p52 の実 IP では絞れない** — silver-hawk の Docker Desktop は公開ポートの送信元を bridge ゲートウェイ（172.20.0.1）に書き換えるため、primary から見た接続元は常に 172.20.0.1 になる（2026-09-15 実測。`192.168.1.61/32` の行は効かず `no pg_hba.conf entry ... from host "172.20.0.1"` で弾かれた）。送信元で守れないぶん、ロールを REPLICATION 専用にし、パスワードは hub を経由させずに配っている
- physical slot `p52_standby`、`max_slot_wal_keep_size=2GB`（p52 不在中も primary の WAL が無限に溜まらない。2GB を超えると slot は `lost` になり、`FORCE=1 ./bootstrap.sh` で作り直す）

## 監視

- primary: `select client_addr, state, sent_lsn, replay_lsn, replay_lag from pg_stat_replication;`
- standby: `select pg_is_in_recovery(), now()-pg_last_xact_replay_timestamp() as lag;`

## 昇格までに要るもの（未）

auth-server（Rust バイナリ + env）を p52 に置く、gateway の ForwardAuth を切替える、hub standby。これらは別 PR。
