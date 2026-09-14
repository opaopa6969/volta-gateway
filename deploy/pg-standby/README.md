# auth PostgreSQL の standby（p52）

> 本番の `volta-auth-postgres` の compose は `../auth-postgres/`（2026-09-15 に archived な volta-auth-proxy から移した）。

silver-hawk の `volta-auth-postgres`（:54329）を p52 にストリーミング複製する。昇格は手動。

| ファイル | 役割 |
|---|---|
| `bootstrap.sh` | `pg_basebackup -R -S p52_standby` で複製を作り、`hot_standby=on` で起動 |
| `promote.sh` | 手動昇格。`pg_ctl promote` → LAN へ再束縛 |
| `pg-tunnel.service` | p52 の user unit。primary（loopback のみ）へ ssh トンネルを張り、`10.52.0.1:54328` に出す |

## primary 側（済み・2026-09-15）

- ロール `replicator`（REPLICATION LOGIN）。パスワードは `~/.config/volta-auth-standby/p52-replicator.secret`（silver-hawk）と `~/volta-auth-standby/replicator.pw`（p52）。**hub を経由せず rrsync 経路で配った**
- `pg_hba.conf`: `host replication replicator 172.20.0.0/16 scram-sha-256`。**p52 の実 IP では絞れない** — silver-hawk の Docker Desktop は公開ポートの送信元を bridge ゲートウェイ（172.20.0.1）に書き換えるため、primary から見た接続元は常に 172.20.0.1 になる（2026-09-15 実測。`192.168.1.61/32` の行は効かず `no pg_hba.conf entry ... from host "172.20.0.1"` で弾かれた）。送信元で守れないぶん、ロールを REPLICATION 専用にし、パスワードは hub を経由させずに配っている
- physical slot `p52_standby`、`max_slot_wal_keep_size=2GB`（p52 不在中も primary の WAL が無限に溜まらない。2GB を超えると slot は `lost` になり、`FORCE=1 ./bootstrap.sh` で作り直す）

## トンネル（2026-09-15〜）

primary の PG は `127.0.0.1:54329` にしか居ない（LAN に出さない）。p52 は専用鍵
（`~/.ssh/id_ed25519_pg_tunnel`、silver-hawk 側は `restrict,port-forwarding,permitopen="127.0.0.1:54329"`）で
ssh トンネルを張り、ダミー IF `volta0`（10.52.0.1、NetworkManager の dummy 接続）の `:54328` に出す。
standby コンテナの `primary_conninfo` は `host=10.52.0.1 port=54328`。rootless docker のコンテナからは
host の loopback に届かない（slirp4netns の `--disable-host-loopback`）が、host の他のアドレスには届く。

- 状態: `systemctl --user status pg-tunnel`、`ss -tln | grep 54328`
- 切れると standby の `pg_stat_wal_receiver.status` が `streaming` でなくなり、primary 側の ha-watch が `standby` の劣化として通知する
- primary から見た接続元は引き続き `172.20.0.1`（Docker Desktop の proxy）。pg_hba の行はそのまま

## 監視

- primary: `select client_addr, state, sent_lsn, replay_lsn, replay_lag from pg_stat_replication;`
- standby: `select pg_is_in_recovery(), now()-pg_last_xact_replay_timestamp() as lag;`

## 昇格までに要るもの（未）

auth-server（Rust バイナリ + env）を p52 に置く、gateway の ForwardAuth を切替える、hub standby。これらは別 PR。
