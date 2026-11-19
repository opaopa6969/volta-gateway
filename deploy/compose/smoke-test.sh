#!/usr/bin/env bash
# End-to-end check for the standalone compose example:
#   unauthenticated request is sent to login → dev magic-link login →
#   the backend receives X-Volta-* identity headers.
#
#   VOLTA_PUBLIC_URL=http://localhost:18080 ./deploy/compose/smoke-test.sh [email]
#
# Needs AUTH_EXPOSE_DEV_TOKEN=true on auth-server (the compose default).
set -euo pipefail

url=${VOLTA_PUBLIC_URL:-http://localhost:18080}
email=${1:-dev@example.com}
jar=$(mktemp)
trap 'rm -f "$jar"' EXIT

echo "1) without a session"
read -r code location < <(curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' "$url/whoami")
echo "   $code -> ${location:-<none>}"
case "$location" in
  *"/login?return_to="*) ;;
  *) echo "   expected a redirect to /login" >&2; exit 1 ;;
esac

echo "2) dev magic-link login as $email"
link=$(curl -sf -X POST -H 'content-type: application/json' \
  --data "{\"email\":\"$email\"}" "$url/auth/magic-link/send" |
  sed -n 's/.*"link":"\([^"]*\)".*/\1/p')
[ -n "$link" ] || { echo "   no link returned (AUTH_EXPOSE_DEV_TOKEN unset?)" >&2; exit 1; }
curl -s -c "$jar" -o /dev/null -w '   verify: %{http_code} -> %{redirect_url}\n' "$link"

echo "3) the backend sees the identity headers"
headers=$(curl -sf -b "$jar" "$url/whoami" | tr -d '\r' | grep -i '^X-Volta-' || true)
printf '%s\n' "$headers" | sed 's/^/   /'
printf '%s\n' "$headers" | grep -qi "^X-Volta-Email: $email$" || {
  echo "   X-Volta-Email did not reach the backend" >&2
  exit 1
}
echo "OK"
