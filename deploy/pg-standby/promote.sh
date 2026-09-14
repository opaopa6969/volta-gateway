#!/bin/sh
# standby を primary に昇格する(**手動**)。戻すには primary を作り直す(basebackup)ので、
# 昇格は「元の primary が死んだと判断したとき」だけ。判断は人が行う。
#
# 昇格後にやること(このスクリプトの外):
#   1. auth-server(この箱)を DATABASE_URL=この DB で起動
#   2. gateway の ForwardAuth 先をこの箱に向ける
#   3. 元の primary が戻ってきても**書き込みさせない**(止めるか、この箱の standby にする)
set -eu
NAME="${NAME:-volta-auth-postgres-standby}"
BIND_AFTER="${BIND_AFTER:-0.0.0.0:54329}"   # 昇格後は LAN に出す(auth-server が別の箱でも繋げるように)
docker exec "$NAME" psql -U volta -d volta_auth -tAc "select pg_is_in_recovery()" | grep -q t || { echo "既に primary(recovery ではない)"; exit 0; }
docker exec "$NAME" pg_ctl promote -D /var/lib/postgresql/data -w
docker exec "$NAME" psql -U volta -d volta_auth -tAc "select 'in_recovery='||pg_is_in_recovery()"
# 束縛を LAN に広げる(コンテナを作り直す。データは volume なので残る)
VOL=$(docker inspect "$NAME" --format '{{range .Mounts}}{{.Name}}{{end}}')
IMAGE=$(docker inspect "$NAME" --format '{{.Config.Image}}')
docker rm -f "$NAME" >/dev/null
docker run -d --name "$NAME" --restart unless-stopped -p "$BIND_AFTER:5432" -e POSTGRES_PASSWORD=unused -v "$VOL:/var/lib/postgresql/data" "$IMAGE" >/dev/null
echo "promoted and rebound to $BIND_AFTER"
