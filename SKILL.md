---
name: mcp-oauth-hosting
description: Use when a remote MCP client only accepts one HTTPS URL and fails to connect (no header field for a bearer key), or when publishing a self-hosted MCP server through a tunnel with OAuth discovery and optional Cloudflare Access SSO consent. Ships a drop-in OAuth 2.1 shim, a minimal markdown MCP server, a hardened systemd unit, Cloudflare provisioning scripts and offline self-tests.
---

# Hosting an MCP server for URL-only clients

## The situation this solves

The user has a self-hosted MCP server protected by a static bearer key. The client (the Grok app
does this; several mobile agents too) offers exactly one field: an HTTPS URL. There is no header, no
key, no basic-auth box. The client reports *"couldn't connect to the server"* and the server log shows
`401` on `POST /mcp` with **no** `Authorization` header at all — because the client is waiting for an
OAuth discovery hint that never came.

Do not try to "fix" this by putting the key in the URL. Do not try Cloudflare Access on `/mcp`
either — a non-browser client cannot complete a login page. Add an OAuth 2.1 discovery layer to the
server instead, and scope any SSO to the browser-only consent path.

## Procedure

1. **Reproduce the failure with evidence.**
   ```bash
   curl -si -X POST https://host/mcp \
     -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
     -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | head -5
   ```
   `401` + a browser-ish UA in the payload clients send + no `WWW-Authenticate` = the diagnosis.
2. **Deploy the server and the shim** (`mcp_server.py`, `oauth_shim.py`). Bind `127.0.0.1`, keep the
   key in `/etc/<name>.env` (mode 600), set `MCP_PUBLIC_BASE` to the public https origin.
   `sudo bash deploy/install.sh` does the systemd part with `DynamicUser` + `ProtectSystem=strict`.
3. **Publish it.** Named Cloudflare Tunnel + proxied CNAME (`scripts/add_cname.sh`); never expose the
   app port. Details and alternatives: `references/publishing.md`.
4. **Make the 401 teach the client**: `WWW-Authenticate: Bearer resource_metadata="<base>/.well-known/oauth-protected-resource"`.
   Everything else follows from RFC 9728 → RFC 8414 → RFC 7591 → code+PKCE.
5. **Verify the whole client walk offline first, then over the public host**:
   ```bash
   PY=.venv/bin/python bash tests/run_all.sh            # 9 JWT + 14 OAuth assertions
   python3 scripts/selftest_oauth.py https://host       # against production
   ```
   Paste the bare `https://host/mcp` into the client only after both are green.
6. **Optional keyless consent.** Provision the Access app scoped to `/authorize*`:
   ```bash
   ACC=<account_id> HOST=host bash scripts/provision_cf_access_app.sh
   ```
   It prints `MCP_CF_ACCESS_TEAM` / `MCP_CF_ACCESS_AUD`; write them into the env file and restart.
   The script self-probes and rolls back if `/mcp` stopped returning your own 401.
7. **Rotate the key if it ever travelled** in a URL, ticket, screenshot or chat message.

## Non-negotiables

* Scope SSO/Access to `/authorize*`. Never to `/mcp`, `/token`, `/.well-known/*`.
* Verify the `Cf-Access-Jwt-Assertion` signature server-side (RS256 against the team JWKS, `iss`,
  `exp`, `aud`). An unverified header is a forged identity; the shim falls back to the key form.
* `MCP_PUBLIC_BASE` must equal the public origin exactly (no trailing slash) or discovery advertises
  unreachable URLs.
* Return JSON for `POST /mcp`; an endless SSE stream hangs some clients.
* Never commit an env file, tunnel credentials, or an API token. Keep `.gitignore` ahead of mistakes.

## Verification checklist

| check | expected |
| --- | --- |
| `curl -s /health` over the public host | `{"ok":true,...}` (200, not a 302 to an IdP) |
| `POST /mcp` with no key | 401 **with** `resource_metadata` |
| `selftest_oauth.py https://host` | every step PASS, exit 0 |
| `selftest_cf_jwt.py` | 9/9 (signature decides, not the header) |
| `/authorize` in a browser | consent page (with SSO banner when Access is configured) |
| client connector | `tools/list` returns your tools |

## Reference map

* `references/oauth-shim.md` — endpoint matrix and why each piece exists
* `references/cf-access.md` — path scoping, the API permission ladder, alternatives
* `references/security.md` — what this does and does not protect; hardening order
* `references/pitfalls.md` — ten real failure modes and the fast debugging order
* `references/publishing.md` — tunnel + DNS + TLS verification order
