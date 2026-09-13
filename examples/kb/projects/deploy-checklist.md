# Deploying this repo

Checklist used in production:

1. `sudo bash deploy/install.sh` — code to `/opt/mcp-server`, venv, systemd unit, key generated.
2. Edit `/etc/mcp-server.env`: set `MCP_PUBLIC_BASE` and `MCP_ALLOWED_HOSTS`.
3. `cloudflared tunnel create mcp` then `scripts/add_cname.sh` to publish `mcp.example.com`.
4. `python3 scripts/selftest_oauth.py https://mcp.example.com` — all steps must pass.
5. Optional keyless consent: `scripts/provision_cf_access_app.sh`, write the printed
   `MCP_CF_ACCESS_TEAM` / `MCP_CF_ACCESS_AUD`, `systemctl restart mcp-server`.
6. Paste `https://mcp.example.com/mcp` into the client. Done — no header field needed.

Keep `MCP_TOKEN` out of URLs, tickets and chat logs. Rotate by editing the env file and
restarting; clients re-authorize once.
