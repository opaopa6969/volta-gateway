#!/bin/sh
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
NODE="${NODE_BIN:-}"
if [ -z "$NODE" ]; then
  for d in "$HOME"/.nvm/versions/node/v2[0-9]*/bin "$HOME"/.nvm/versions/node/v[3-9][0-9]*/bin; do
    [ -x "$d/node" ] && NODE="$d/node"
  done
fi
[ -n "$NODE" ] || NODE="$(command -v node)"
exec "$NODE" "$HERE/mcp/server.mjs" "$@"
