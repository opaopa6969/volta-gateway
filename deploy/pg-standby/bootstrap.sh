#!/bin/sh
# auth の本番 PostgreSQL(silver-hawk: volta-auth-postgres)の**ストリーミングレプリカ**を
# この箱に作って起動する。p52 で動かす想定(rootless docker、compose plugin 無し → plain docker)。
#
# ★ なぜ ★ auth-server の DB は silver-hawk の 1 台で、消えると認証が全部止まる(2026-09-14 に 2 回)。
#   日次 pg_dump(volta-index #323)は「復元できる物」で、こちらは「追随している物」。昇格すれば
#   数秒〜数十秒前の状態で認証を再開できる。昇格は**手動**(promote.sh)。自動昇格はリース/多数決が
#   要り、split-brain を持ち込むので今はやらない(運用者判断 2026-09-15)。
#
# 前提(primary 側、済み): replicator ロール / pg_hba に host replication replicator <この箱>/32 /
#   physical slot p52_standby / max_slot_wal_keep_size=2GB(この箱が長く不在でも primary を溢れさせない)
#
# 使い方:  ./bootstrap.sh            # 初回。既に volume があれば拒否する(上書きしない)
#          FORCE=1 ./bootstrap.sh    # 作り直す(volume を消してから basebackup)
set -eu
PRIMARY_HOST="${PRIMARY_HOST:-10.52.0.1}"   # ssh トンネル(pg-tunnel.service)の入口。primary は loopback にしか居ない
PRIMARY_PORT="${PRIMARY_PORT:-54328}"
SLOT="${SLOT:-p52_standby}"
NAME="${NAME:-volta-auth-postgres-standby}"
VOL="${VOL:-volta_auth_standby_pgdata}"
IMAGE="${IMAGE:-postgres:16-alpine}"       # primary と同じ major(16.13)。メジャーを揃えないと replay できない
BIND="${BIND:-127.0.0.1:54329}"            # 昇格するまでは LAN に出さない(誤って書き込み先にされない)
PWFILE="${PWFILE:-$HOME/volta-auth-standby/replicator.pw}"

[ -s "$PWFILE" ] || { echo "NG: $PWFILE が無い(replicator のパスワード。rrsync 経路で配る)"; exit 1; }
PGPASSWORD=$(cat "$PWFILE")

if docker volume inspect "$VOL" >/dev/null 2>&1; then
  if [ "${FORCE:-0}" = "1" ]; then
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker volume rm "$VOL" >/dev/null
    echo "既存 volume を削除(FORCE=1)"
  else
    echo "NG: volume $VOL が既にある。作り直すなら FORCE=1"; exit 1
  fi
fi
docker volume create "$VOL" >/dev/null

# 1) basebackup。-R で standby.signal と primary_conninfo を書かせる。-S で slot を掴む(WAL 取りこぼし防止)
#    root で走らせて最後に chown(新規 volume は root 所有で postgres ユーザーが書けないため)
#    ★ パイプで tail しない: POSIX sh に pipefail が無く、basebackup の失敗が握り潰されて
#      **空の datadir で新規初期化されたコンテナが立つ**事故を踏んだ(2026-09-15)
docker run --rm -e PGPASSWORD="$PGPASSWORD" -v "$VOL:/var/lib/postgresql/data" "$IMAGE" sh -c "
  pg_basebackup -h $PRIMARY_HOST -p $PRIMARY_PORT -U replicator -D /var/lib/postgresql/data \
    -R -S $SLOT -X stream --checkpoint=fast --progress --verbose \
  && chown -R postgres:postgres /var/lib/postgresql/data && chmod 700 /var/lib/postgresql/data" \
  || { echo "NG: pg_basebackup 失敗。volume を消す(空の datadir で起動させない)"; docker volume rm "$VOL" >/dev/null; exit 1; }
# basebackup が standby として組み上がった証拠が無ければ起動しない
docker run --rm -v "$VOL:/var/lib/postgresql/data" "$IMAGE" sh -c "test -f /var/lib/postgresql/data/standby.signal && grep -q primary_conninfo /var/lib/postgresql/data/postgresql.auto.conf" \
  || { echo "NG: standby.signal / primary_conninfo が無い"; docker volume rm "$VOL" >/dev/null; exit 1; }

# 2) standby として起動。hot_standby=on で読める(昇格前でも整合性確認に使う)
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --restart unless-stopped \
  -p "$BIND:5432" \
  -e POSTGRES_PASSWORD=unused-data-dir-already-initialized \
  -v "$VOL:/var/lib/postgresql/data" \
  "$IMAGE" postgres -c hot_standby=on >/dev/null
echo "started: $NAME ($BIND)"

# 3) 追随確認
i=0; until docker exec "$NAME" pg_isready -U volta -q 2>/dev/null || [ $i -ge 30 ]; do i=$((i+1)); sleep 2; done
docker exec "$NAME" psql -U volta -d volta_auth -tAc "select 'in_recovery='||pg_is_in_recovery()||' last_replay='||coalesce(pg_last_wal_replay_lsn()::text,'-')"
