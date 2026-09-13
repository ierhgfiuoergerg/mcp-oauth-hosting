#!/usr/bin/env bash
# run_all.sh — the whole verification suite, offline, in one command.
#   bash tests/run_all.sh
# 1) syntax checks   2) Cloudflare Access JWT verification (offline, self-signed)
# 3) full OAuth flow against a locally started instance of this server
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
PORT=${PORT:-8099}
STATE=$(mktemp -d)/oauth_state.json
TOKEN=$(openssl rand -hex 32)

echo "=== 0) python + deps ==="
if [ -n "${PY:-}" ]; then
  PY_BIN=$PY                       # reuse an existing interpreter (fast path / CI)
  echo "  using $PY_BIN"
else
  [ -d .venv ] || python3 -m venv .venv
  ./.venv/bin/pip install -q --upgrade pip
  ./.venv/bin/pip install -q -r requirements.txt
  PY_BIN=./.venv/bin/python
fi

echo "=== 1) syntax ==="
for f in mcp_server.py oauth_shim.py; do $PY_BIN -m py_compile "$f" && echo "  ok $f"; done
for s in scripts/*.sh deploy/*.sh; do bash -n "$s" && echo "  ok $s"; done

echo "=== 2) Cloudflare Access JWT verification (offline) ==="
$PY_BIN scripts/selftest_cf_jwt.py "$ROOT"

echo "=== 3) live OAuth flow on 127.0.0.1:$PORT ==="
MCP_TOKEN="$TOKEN" KB_DIR="$ROOT/examples/kb" MCP_PUBLIC_BASE="http://127.0.0.1:$PORT" \
MCP_OAUTH_STATE="$STATE" PORT="$PORT" HOST=127.0.0.1 \
  $PY_BIN mcp_server.py > /tmp/mcp-selftest.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT

for i in $(seq 1 30); do
  curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -fsS "http://127.0.0.1:$PORT/health"; echo
$PY_BIN scripts/selftest_oauth.py "http://127.0.0.1:$PORT" "$TOKEN"

echo
echo "ALL GREEN"
