#!/usr/bin/env bash
# provision_cf_access_app.sh — create a Cloudflare Access (Zero Trust) application that
# protects ONLY the authorization page (/authorize*), so that browser-based user consent
# is "log in with your Cloudflare account" instead of "paste a shared secret".
#
# Machine paths (/mcp, /token, /.well-known/*) stay OUTSIDE Access on purpose: non-browser
# clients cannot complete an interactive login page, so wrapping them would break the
# client entirely.
#
#   ACC=<account_id> HOST=mcp.example.com bash scripts/provision_cf_access_app.sh
#
# Optional env:
#   CF_TOKEN_FILE   default /etc/cloudflared/cf-api-token   (chmod 600, never in git)
#   APP_PATH        default '/authorize*'
#   APP_NAME        default 'MCP authorize'
#   SESSION_DURATION default 24h
#   POLICY_NAME     default 'Allow account members'
#   USE_EMAIL       if set, policy allows just that one email (instead of all account members)
#   PROBE_MCP_PATH  default /mcp    PROBE_HEALTH_PATH default /health
#   DRY_RUN=1       print the request body and exit (no API call, spends nothing)
#
# Required token permission: Access: Apps and Policies: Write
#   - account-level token, NOT a zone-scoped one
#   - if the token has an IP allow-list, force IPv4 (this script already passes -4);
#     calling from an unlisted IP (e.g. over IPv6) fails with error 9109
# The script self-probes afterwards and DELETEs the app if it broke the machine path.
set -u
API=https://api.cloudflare.com/client/v4
TOK=$(tr -d '\r\n' < "${CF_TOKEN_FILE:-/etc/cloudflared/cf-api-token}")
ACC=${ACC:?set ACC=<cloudflare account id>}
HOST=${HOST:?set HOST=<hostname, e.g. mcp.example.com>}
APP_PATH=${APP_PATH:-'/authorize*'}
APP_NAME=${APP_NAME:-'MCP authorize'}
SESSION_DURATION=${SESSION_DURATION:-24h}
POLICY_NAME=${POLICY_NAME:-'Allow account members'}
USE_EMAIL=${USE_EMAIL:-}
PROBE_MCP_PATH=${PROBE_MCP_PATH:-/mcp}
PROBE_HEALTH_PATH=${PROBE_HEALTH_PATH:-/health}
OUT=${OUT:-/tmp/cf-app-provision}
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126 Safari/537.36'
H_AUTH="Authorization: Bearer $TOK"
mkdir -p "$OUT"

if [ -n "$USE_EMAIL" ]; then
  INCLUDE="[ { \"email\": { \"email\": \"$USE_EMAIL\" } } ]"
else
  INCLUDE="[ { \"cloudflare_account_member\": { \"account_id\": \"$ACC\" } } ]"
fi
BODY="{
    \"name\": \"$APP_NAME\",
    \"domain\": \"$HOST$APP_PATH\",
    \"type\": \"self_hosted\",
    \"session_duration\": \"$SESSION_DURATION\",
    \"app_launcher_visible\": false,
    \"policies\": [ { \"name\": \"$POLICY_NAME\", \"decision\": \"allow\", \"include\": $INCLUDE } ]
  }"

if [ "${DRY_RUN:-0}" = "1" ]; then
  echo "DRY RUN — would POST $API/accounts/$ACC/access/apps"
  echo "$BODY"
  exit 0
fi

echo "=== 1) create Access application: $HOST$APP_PATH ==="
curl -4 -sS -X POST "$API/accounts/$ACC/access/apps" \
  -H "$H_AUTH" -H 'Content-Type: application/json' -d "$BODY" \
  -o "$OUT/app.json" -w 'HTTP=%{http_code}\n'

python3 - "$OUT/app.json" <<'PY'
import json, sys
j = json.load(open(sys.argv[1]))
r = j.get('result') or {}
print('success:', j.get('success'))
for e in j.get('errors') or []:
    print('ERROR', e.get('code'), e.get('message'))
print('app_id:', r.get('id'), '| domain:', r.get('domain'), '| aud:', r.get('aud'))
print('policies:', [(p.get('id'), p.get('decision')) for p in (r.get('policies') or [])])
open(sys.argv[1] + '.id', 'w').write(r.get('id') or '')
open(sys.argv[1] + '.aud', 'w').write(r.get('aud') or '')
PY
APPID=$(cat "$OUT/app.json.id" 2>/dev/null || true)
AUD=$(cat "$OUT/app.json.aud" 2>/dev/null || true)
if [ -z "$APPID" ]; then
  echo "!! not created. 403 code 1010 auth.forbidden = the token lacks"
  echo "   'Access: Apps and Policies: Write' (or holds Read instead of Edit)."
  exit 3
fi
echo "APPID=$APPID"
echo "put these in /etc/mcp-server.env then restart the service:"
echo "  MCP_CF_ACCESS_TEAM=<team>.cloudflareaccess.com"
echo "  MCP_CF_ACCESS_AUD=$AUD"

sleep 3
echo
echo '=== 2) safety probe (the machine path must NOT be wrapped) ==='
MCPCODE=$(curl -4 -sS -o "$OUT/mcp.txt" -w '%{http_code}' -X POST "https://$HOST$PROBE_MCP_PATH" \
  -H "User-Agent: $UA" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}')
echo "POST $PROBE_MCP_PATH -> $MCPCODE (expect 401 from OUR server, not a CF login page)"
head -c 200 "$OUT/mcp.txt"; echo
HEALTH=$(curl -4 -sS -o "$OUT/health.txt" -w '%{http_code}' "https://$HOST$PROBE_HEALTH_PATH" -H "User-Agent: $UA")
echo "GET $PROBE_HEALTH_PATH -> $HEALTH : $(head -c 120 "$OUT/health.txt")"

curl -4 -sS -o /dev/null -D "$OUT/auth.h" -w 'GET /authorize HTTP=%{http_code}\n' -H "User-Agent: $UA" \
  "https://$HOST/authorize?response_type=code&client_id=probe&redirect_uri=https%3A%2F%2Fexample.com%2Fcb&state=x" || true
grep -i -E '^location|^cf-mitigated' "$OUT/auth.h" || echo '(no Location — the app may not have propagated yet)'
TEAM=$(grep -i '^location' "$OUT/auth.h" | grep -o 'https://[a-z0-9-]*\.cloudflareaccess\.com' | head -1 | sed 's|https://||; s|\.cloudflareaccess\.com||')
[ -n "$TEAM" ] && echo "TEAM_FROM_REDIRECT=$TEAM"

echo
if [ "$MCPCODE" != "401" ]; then
  echo "!!! $PROBE_MCP_PATH answered $MCPCODE — the app wrapped the machine path. Rolling back."
  curl -4 -sS -X DELETE "$API/accounts/$ACC/access/apps/$APPID" -H "$H_AUTH" \
    -o "$OUT/del.json" -w 'DELETE HTTP=%{http_code}\n'
  head -c 300 "$OUT/del.json"; echo
  exit 4
fi
echo "OK: machine path untouched; app kept."
