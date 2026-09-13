# Publishing it: tunnel, CNAME, TLS

Any of these work; the Cloudflare Tunnel path is what the scripts assume because it needs no
inbound ports open and gives free TLS.

## Cloudflare Tunnel (named, persistent)

```bash
# 1) log in once (browser), then create a tunnel
cloudflared tunnel login
cloudflared tunnel create mcp                 # prints the tunnel UUID

# 2) route DNS: CNAME <sub>.<zone> -> <uuid>.cfargotunnel.com (proxied)
ZONE=example.com SUB=mcp TUNNEL_ID=<uuid> bash scripts/add_cname.sh

# 3) ingress: public hostname -> the local service
cat /etc/cloudflared/config.yml
```

```yaml
tunnel: <uuid>
credentials-file: /etc/cloudflared/<uuid>.json
ingress:
  - hostname: mcp.example.com
    service: http://127.0.0.1:8081
    originRequest:
      httpHostHeader: mcp.example.com     # keeps the Host header your allow-list expects
      noTLSVerify: false
  - service: http_status:404
```

```bash
sudo cloudflared service install      # or your own systemd unit
systemctl enable --now cloudflared
curl -s https://mcp.example.com/health
```

**Quick tunnels** (`cloudflared tunnel --url http://127.0.0.1:8081`) are fine for a demo but the
hostname changes on every restart, so a client's saved connector URL breaks. Use a named tunnel for
anything you keep.

## Alternatives

| option | notes |
| --- | --- |
| `nginx` + certbot | full control, needs ports 80/443 open and a reachable DNS A record |
| ngrok | fastest, hostname changes on the free plan (use `--domain`), adds a third party to the path |
| Tailscale Funnel | good if you already run Tailscale; TLS and hostname handled |
| plain VPS + Let's Encrypt | fine; just never expose the app port directly |

Whatever you choose: **the app binds `127.0.0.1`**, TLS ends at the edge, and `MCP_PUBLIC_BASE` must
match the public hostname exactly (no trailing slash) or the OAuth metadata will advertise the wrong
URLs and clients will fail at discovery.

## Verify in this order

```bash
curl -s 127.0.0.1:8081/health                    # app alive
curl -s https://mcp.example.com/health           # tunnel/TLS/host allow-list
curl -s https://mcp.example.com/.well-known/oauth-protected-resource
python3 scripts/selftest_oauth.py https://mcp.example.com
```

If step 2 returns a Cloudflare error page instead of your JSON, check the UA (pitfall 3) before
touching the tunnel.
