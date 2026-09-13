#!/usr/bin/env bash
# install.sh — put this repo on a Debian/Ubuntu VPS as a hardened systemd service,
# listening on 127.0.0.1 only (front it with cloudflared / ngrok / nginx+TLS).
#
#   sudo bash deploy/install.sh            # installs to /opt/mcp-server
#   MCP_NAME=my-mcp APP_DIR=/opt/my-mcp sudo -E bash deploy/install.sh
#
# Idempotent: re-running upgrades the code and restarts the service; it never
# overwrites an existing /etc/<name>.env (so your key survives upgrades).
set -euo pipefail

NAME=${MCP_NAME:-mcp-server}
APP_DIR=${APP_DIR:-/opt/$NAME}
ENV_FILE=${ENV_FILE:-/etc/$NAME.env}
STATE_DIR=${STATE_DIR:-/var/lib/mcp-oauth}
SRC=$(cd "$(dirname "$0")/.." && pwd)
[ "$(id -u)" = 0 ] || { echo "run me with sudo"; exit 1; }

echo "==> 1/5 systrust: install python + venv"
if command -v apt-get >/dev/null; then
  command -v python3 >/dev/null || { apt-get update -qq; apt-get install -y -qq python3 python3-venv; }
else
  echo "    (not apt-based — install python3 + venv yourself, continuing)"
fi

echo "==> 2/5 copy code to $APP_DIR"
install -d -m 755 "$APP_DIR"
for f in mcp_server.py oauth_shim.py; do install -m 644 "$SRC/$f" "$APP_DIR/$f"; done
install -d -m 755 "$APP_DIR/scripts"
install -m 755 "$SRC"/scripts/*.py "$SRC"/scripts/*.sh "$APP_DIR/scripts/" 2>/dev/null || true
if [ ! -d "$APP_DIR/kb" ]; then install -d -m 755 "$APP_DIR/kb"; cp -n "$SRC"/examples/kb/*.md "$APP_DIR/kb/" 2>/dev/null || true; fi

echo "==> 3/5 python venv + deps"
[ -d "$APP_DIR/.venv" ] || python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install -q --upgrade pip
"$APP_DIR/.venv/bin/pip" install -q "uvicorn>=0.30" "starlette>=0.37" "mcp>=1.0" "pyjwt[crypto]>=2.8"

echo "==> 4/5 env file $ENV_FILE"
install -d -m 700 "$STATE_DIR"
if [ -f "$ENV_FILE" ]; then
  echo "    exists — left untouched (edit it to change settings)"
else
  install -m 600 "$SRC/env.example" "$ENV_FILE"
  TOKEN=$(openssl rand -hex 32)
  sed -i "s|^MCP_TOKEN=.*|MCP_TOKEN=$TOKEN|" "$ENV_FILE"
  sed -i "s|^KB_DIR=.*|KB_DIR=$APP_DIR/kb|" "$ENV_FILE"
  echo
  echo "    !! generated access key (also written to $ENV_FILE):"
  echo "       $TOKEN"
  echo "    !! now set MCP_PUBLIC_BASE and MCP_ALLOWED_HOSTS in $ENV_FILE"
fi

echo "==> 5/5 systemd unit + start"
sed "s|/opt/mcp-server|$APP_DIR|g" "$SRC/deploy/mcp-server.service" > "/etc/systemd/system/$NAME.service"
if ! grep -q "^EnvironmentFile=" "/etc/systemd/system/$NAME.service"; then :; fi
sed -i "s|^EnvironmentFile=.*|EnvironmentFile=$ENV_FILE|" "/etc/systemd/system/$NAME.service"
systemctl daemon-reload
systemctl enable --now "$NAME"
sleep 2
systemctl --no-pager --lines=5 status "$NAME" || true
echo
echo "local check:  curl -s http://127.0.0.1:8081/health"
echo "full check :  python3 scripts/selftest_oauth.py http://127.0.0.1:8081"
