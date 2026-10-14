#!/bin/sh
set -eu
umask 077
CONFIRM=0
SOURCE_FENCED=0
for argument in "$@"; do
  case "$argument" in
    --confirm) CONFIRM=1;;
    --confirm-source-fenced) SOURCE_FENCED=1;;
    *) echo "unknown promotion argument" >&2; exit 2;;
  esac
done
NAME="${NAME:-volta-auth-postgres-standby}"
case "${DOCKER_HOST:-}" in unix:///*) ;; *) echo "explicit local Docker socket required" >&2; exit 2;; esac
printf '%s' "${EXPECTED_CONTAINER_ID:-}" | grep -Eq '^[0-9a-f]{64}$' || { echo "full container ID required" >&2; exit 2; }
printf '%s' "${MIN_REPLAY_LSN:-}" | grep -Eq '^[0-9A-Fa-f]{1,8}/[0-9A-Fa-f]{1,8}$' || { echo "valid minimum replay LSN required" >&2; exit 2; }
printf '%s' "$NAME" | grep -Eq '^[a-zA-Z0-9][a-zA-Z0-9_.-]*$' || exit 2
if [ "$CONFIRM" = 1 ] && [ "$SOURCE_FENCED" != 1 ]; then echo "source fence acknowledgement required" >&2; exit 2; fi
STATE="${PROMOTION_STATE_ROOT:-$HOME/.local/state/volta-pg-promotion}"
mkdir -p -m 700 "$STATE"
[ ! -L "$STATE" ] && [ "$(stat -c %a "$STATE")" = 700 ] || exit 2
exec 9>"$STATE/promotion.lock"
flock -n 9 || { echo "another promotion is in progress" >&2; exit 1; }
observed=$(docker --host "$DOCKER_HOST" inspect "$NAME" --format '{{.Id}} {{.State.Running}}')
[ "$observed" = "$EXPECTED_CONTAINER_ID true" ] || { echo "target identity/state drift" >&2; exit 1; }
query() { timeout 75 docker --host "$DOCKER_HOST" exec "$EXPECTED_CONTAINER_ID" psql -v ON_ERROR_STOP=1 -U volta -d postgres -Atc "$1"; }
[ "$(query 'SELECT pg_is_in_recovery()')" = t ] || { echo "target is not a verified standby" >&2; exit 1; }
[ "$(query "SELECT pg_last_wal_replay_lsn() >= '$MIN_REPLAY_LSN'::pg_lsn")" = t ] || { echo "standby has not replayed the required LSN" >&2; exit 1; }
if [ "$CONFIRM" = 0 ]; then echo "dry-run: target verified; no promotion performed"; exit 0; fi
[ "$(query 'SELECT pg_promote(true,60)')" = t ] || { echo "promotion unconfirmed; inspect target before retry" >&2; exit 1; }
[ "$(query 'SELECT pg_is_in_recovery()')" = f ] || { echo "primary state unconfirmed; inspect target before retry" >&2; exit 1; }
echo "promoted in place; container identity, mounts and port bindings unchanged"
