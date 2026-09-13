#!/usr/bin/env bash
# add_cname.sh — point a hostname at a Cloudflare Tunnel (CNAME -> <tunnel-id>.cfargotunnel.com,
# proxied). Idempotent: if the record exists it is PATCHed instead of duplicated.
#
#   ZONE=example.com SUB=mcp TUNNEL_ID=<uuid> bash scripts/add_cname.sh
#   DRY_RUN=1 ... bash scripts/add_cname.sh      # prints the request, does nothing
#
# Token permission: Zone: DNS: Edit  (zone-scoped token is fine here)
# IP-allow-listed tokens must be called over IPv4 — hence -4 everywhere.
set -u
API=https://api.cloudflare.com/client/v4
TOK=$(tr -d '\r\n' < "${CF_TOKEN_FILE:-/etc/cloudflared/cf-api-token}")
ZONE=${ZONE:?set ZONE=<example.com>}
SUB=${SUB:-mcp}
TUNNEL_ID=${TUNNEL_ID:?set TUNNEL_ID=<tunnel uuid>}
PROXIED=${PROXIED:-true}
H_AUTH="Authorization: Bearer $TOK"
TARGET="${TUNNEL_ID}.cfargotunnel.com"

ZID=$(curl -4 -sS "$API/zones?name=$ZONE" -H "$H_AUTH" \
  | python3 -c 'import json,sys; r=(json.load(sys.stdin).get("result") or [{}]); print(r[0].get("id",""))')
[ -n "$ZID" ] || { echo "!! zone $ZONE not found (or token lacks Zone:Read)"; exit 2; }
echo "zone_id=$ZID"

EXIST=$(curl -4 -sS "$API/zones/$ZID/dns_records?type=CNAME&name=$SUB.$ZONE" -H "$H_AUTH" \
  | python3 -c 'import json,sys; r=(json.load(sys.stdin).get("result") or []); print(r[0].get("id","") if r else "")')

BODY="{\"type\":\"CNAME\",\"name\":\"$SUB\",\"content\":\"$TARGET\",\"proxied\":$PROXIED,\"ttl\":1}"
if [ "${DRY_RUN:-0}" = "1" ]; then
  echo "DRY RUN: $([ -n "$EXIST" ] && echo PUT "$API/zones/$ZID/dns_records/$EXIST" || echo POST "$API/zones/$ZID/dns_records")"
  echo "$BODY"; exit 0
fi

if [ -n "$EXIST" ]; then
  echo "updating existing record $EXIST"
  curl -4 -sS -X PUT "$API/zones/$ZID/dns_records/$EXIST" -H "$H_AUTH" \
    -H 'Content-Type: application/json' -d "$BODY" -o /tmp/cname.json -w 'HTTP=%{http_code}\n'
else
  echo "creating record"
  curl -4 -sS -X POST "$API/zones/$ZID/dns_records" -H "$H_AUTH" \
    -H 'Content-Type: application/json' -d "$BODY" -o /tmp/cname.json -w 'HTTP=%{http_code}\n'
fi
python3 -c 'import json; j=json.load(open("/tmp/cname.json"));
r=j.get("result") or {};
print("success:", j.get("success"), "| name:", r.get("name"), "| ->", r.get("content"), "| proxied:", r.get("proxied"));
[print("ERROR", e.get("code"), e.get("message")) for e in (j.get("errors") or [])]'
echo "verify:  curl -4 -sS https://$SUB.$ZONE/health"
