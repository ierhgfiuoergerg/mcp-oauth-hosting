# mcp-oauth-hosting

**Connect your personal or team knowledge base to any endpoint over MCP — from any client, through a
single HTTPS URL. Read-only by default; optionally let clients submit notes into one inbox folder.
No custom header field, no pasted secret, no OAuth provider to sign up for.**

Point it at a folder of markdown — an Obsidian vault, a wiki export, a `docs/` directory — and it
serves that knowledge base as a remote MCP server with two tools, `search_kb` and `get_doc`. The
knowledge stays on your own machine or VPS; a client only ever needs one URL to reach it.

Because it publishes as **one HTTPS URL and nothing else**, it works from *any* client on any
endpoint — desktop apps, phone and mobile agents, chat assistants such as the Grok app — including
the ones that offer no "add header" box, no bearer-key field and no way to read a local file path.
A static `Authorization: Bearer` key cannot be typed anywhere in those clients; they just say
*"couldn't connect to the server"*.

What those clients *do* support is the standard **OAuth 2.1 discovery flow**:

```
POST /mcp                                    -> 401  WWW-Authenticate: Bearer resource_metadata="..."
GET  /.well-known/oauth-protected-resource    -> which authorization server?
GET  /.well-known/oauth-authorization-server  -> which endpoints?
POST /register                                -> dynamic client registration (RFC 7591)
GET  /authorize                               -> browser opens, the human approves
POST /token                                   -> code + PKCE  ->  bearer token
POST /mcp   Authorization: Bearer <token>     -> tools/list, tools/call
```

So this repo ships a **~380-line drop-in shim** that implements exactly those endpoints on top of
your existing static key — plus a small markdown MCP server to demonstrate it, a systemd unit, and
scripts that publish it through a Cloudflare Tunnel and optionally put **Cloudflare Access** in
front of the consent page so the human authorizes with an SSO login instead of a shared secret.

For a team, that same Access layer puts the consent step behind SSO, so every teammate authorizes
with their own identity instead of passing a shared key around.

```
        client (Grok / any MCP client)                    your VPS
   ┌───────────────────────────────────┐        ┌────────────────────────────┐
   │ https://mcp.example.com/mcp       │        │ 127.0.0.1:8081             │
   │  ├─ no key  → 401 + resource_meta │        │  mcp_server.py             │
   │  ├─ discovers OAuth metadata      │───────▶│   ├─ /health               │
   │  ├─ registers itself              │        │   ├─ /mcp      (bearer)    │
   │  └─ opens /authorize in browser   │        │   └─ oauth_shim.py         │
   └───────────────────────────────────┘        │       /.well-known/*       │
              ▲  302 with ?code                  │       /register /authorize │
              │                                  │       /token    /revoke    │
    Cloudflare Tunnel (proxied CNAME)            └────────────────────────────┘
    optional: Access app on /authorize* only  ──▶  "log in with Cloudflare" consent
```

## Quickstart (5 minutes, local)

```bash
git clone https://github.com/ierhgfiuoergerg/mcp-oauth-hosting.git && cd mcp-oauth-hosting
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt

# Then run it. Note: give the env vars to the *server* process — a `VAR=x cmd1 && cmd2`
# prefix would only reach cmd1, and the server would exit with "MCP_TOKEN is required".
export MCP_TOKEN=$(openssl rand -hex 32)
export KB_DIR=./examples/kb
export MCP_PUBLIC_BASE=http://127.0.0.1:8081
export HOST=127.0.0.1 PORT=8081
./.venv/bin/python mcp_server.py
```

```bash
curl -s localhost:8081/health                         # {"ok":true,"docs":2,...}
curl -si -X POST localhost:8081/mcp | head -3         # 401 + resource_metadata
bash tests/run_all.sh                                 # 61 assertions, all offline
```

Then put it on the internet (TLS is mandatory for every real client):

```bash
sudo bash deploy/install.sh                # /opt/mcp-server + systemd (127.0.0.1 only)
$EDITOR /etc/mcp-server.env                # MCP_PUBLIC_BASE, MCP_ALLOWED_HOSTS
cloudflared tunnel create mcp              # or ngrok / nginx + certbot
ZONE=example.com SUB=mcp TUNNEL_ID=<uuid> bash scripts/add_cname.sh
python3 scripts/selftest_oauth.py https://mcp.example.com
```

Paste `https://mcp.example.com/mcp` into the client. It discovers, registers, opens the consent
page, gets its token and calls your tools.

## Keyless consent with Cloudflare Access (optional)

Typing a secret into a consent page is still "a secret in a browser". Instead, scope an Access
application to **`/authorize*` only**:

```bash
ACC=<account_id> HOST=mcp.example.com bash scripts/provision_cf_access_app.sh
# prints MCP_CF_ACCESS_TEAM / MCP_CF_ACCESS_AUD -> put them in /etc/mcp-server.env, restart
```

`/authorize` is then behind Cloudflare's own SSO (identity verified server-side with the
`Cf-Access-Jwt-Assertion` RS256 signature), so the consent page shows "Authenticated via
Cloudflare Access: you@example.com → **Authorize**" with no key field at all. Everything else —
`/mcp`, `/token`, `/.well-known/*` — is deliberately **outside** Access: non-browser clients cannot
complete an interactive login page, and wrapping them is what breaks the connection.

The provisioning script probes for exactly that mistake and rolls itself back if `/mcp` stops
answering with your own 401.

## Optional: let clients write — into one folder, and only that folder

Set `KB_WRITE_MODE=inbox` and the server additionally exposes `submit_doc(title, content, tags, filename)`.
Useful when a phone-side agent should be able to drop a note into your vault, but you do not want an
LLM-writable filesystem.

Three independent defences, any one of which alone would stop traversal:

1. **No directory parameter exists.** The tool's signature has no path argument at all; the destination
   is a server-side constant (`KB_DIR` + `KB_INBOX_DIR`). There is nothing for a client to point elsewhere.
2. **The filename is sanitised.** `/` and `\` become `-`; control and shell-ish characters are collapsed;
   `..`, leading/trailing dots and length are handled; empty input becomes `untitled`. Invariant, for
   *any* input: no `/`, no `\`, no `..`, not `.`/`..`, non-empty, ≤ 80 chars.
3. **The resolved path is asserted** to sit directly inside the inbox (`target.parent != INBOX_DIR` ⇒ refuse).

Plus: existing files are never overwritten — a name collision appends a timestamp, so the original is
kept. Writes invalidate the index cache, so submitted content is searchable immediately.

```bash
KB_WRITE_MODE=inbox KB_INBOX_DIR=inbox ./... mcp_server.py
```

What a client sends vs where it lands (from `scripts/selftest_inbox.py`):

| `filename` sent by the client | file actually written |
| --- | --- |
| `../../../../tmp/pwned` | `inbox/tmp-pwned.md` |
| `/etc/cron.d/pwned` | `inbox/etc-cron.d-pwned.md` |
| `..%2f..%2fescape` | `inbox/2f..2fescape.md` |
| `....//....//deep-escape` | `inbox/deep-escape.md` |

**Frontmatter is configurable**, because a submitted note has to land in *your* vault, and
vaults disagree about metadata. The defaults are generic (`source: mcp`, no `type`); map them onto
whatever your own linter validates:

```bash
KB_INBOX_TYPE=inbox KB_INBOX_SOURCE=ai KB_INBOX_STATUS=raw   # e.g. a wiki requiring these values
```

Default is `off` — a server that cannot write cannot be talked into writing.

## What you get

| file | what it is |
| --- | --- |
| `oauth_shim.py` | the OAuth 2.1 shim: discovery, DCR, consent page, PKCE token exchange, refresh, revoke. Optional Cloudflare Access identity verification. |
| `mcp_server.py` | minimal Streamable-HTTP MCP server: `search_kb` + `get_doc` over a folder of `.md` files — cached index, credential-shaped files excluded — bearer auth (header / query / path / share-slug), host allow-list, `/health`. With `KB_WRITE_MODE=inbox`, also `submit_doc` scoped to one folder. |
| `deploy/install.sh` + `deploy/mcp-server.service` | hardened systemd install (DynamicUser, `ProtectSystem=strict`, binds 127.0.0.1). |
| `scripts/provision_cf_access_app.sh` | creates the path-scoped Access app via API + safety probe + rollback. |
| `scripts/add_cname.sh` | proxied CNAME → `<tunnel-id>.cfargotunnel.com`, idempotent. |
| `scripts/selftest_oauth.py` | walks the whole flow a URL-only client walks; 14 assertions. |
| `scripts/selftest_cf_jwt.py` | proves signature verification with a locally self-signed JWT (9 assertions, no Cloudflare needed). |
| `scripts/selftest_inbox.py` | self-contained (builds a throwaway KB, starts the server on a spare port, tears it down): 19 assertions covering write scoping, four traversal-shaped filenames, the sibling-prefix containment trap, credential exclusion, cache invalidation. |
| `scripts/test_safe_stem.py` | unit test for the filename sanitiser, extracted from the real source via AST — 18 cases plus a hard invariant that must hold for every input. |
| `tests/run_all.sh` | all of the above, offline, one command. |
| `references/` | the specs, the gotchas, and the security reasoning. |
| `SKILL.md` | the same procedure packaged as an agent skill. |

## Environment

See `env.example` for the annotated list. The important ones:

| variable | meaning |
| --- | --- |
| `MCP_TOKEN` | the access key (64 hex). Required. |
| `MCP_PUBLIC_BASE` | public https origin; enables the OAuth shim. |
| `KB_DIR` | folder of markdown to expose. |
| `MCP_ALLOWED_HOSTS` | host allow-list (`mcp.example.com`, `*.example.com`). |
| `MCP_SHARE_SLUG` | *separate* throwaway key for `/s/<slug>/mcp` URL-embedded access. |
| `MCP_OAUTH_STATE` | where clients/refresh tokens are stored (chmod 600). |
| `MCP_CF_ACCESS_TEAM` / `MCP_CF_ACCESS_AUD` | enable keyless Cloudflare-Access consent. |
| `KB_WRITE_MODE` | `off` (default — strictly read-only) or `inbox` (expose `submit_doc`). |
| `KB_INBOX_DIR` | the one folder `submit_doc` may write to (default `inbox`). |
| `KB_EXCLUDE_DIRS` / `KB_EXCLUDE_GLOBS` | keep credential-shaped documents out of the index even though they live in `KB_DIR`. |
| `KB_MAX_DOC_BYTES` / `KB_MAX_WRITE_BYTES` / `KB_CACHE_TTL` | index size cap (2 MiB), write size cap (512 KiB), cache lifetime (3 s). |
| `KB_INBOX_SOURCE` / `KB_INBOX_TYPE` / `KB_INBOX_STATUS` | frontmatter written into submissions (defaults `mcp` / omitted / `raw`) — set these to match your vault's schema. |

## Things that will bite you

* **Containment checks: use `Path.is_relative_to()`, never `str.startswith()`.** `"/kb-evil/x.md".startswith("/kb")`
  is `True` — a sibling directory whose name merely extends `KB_DIR` would be readable. `scripts/selftest_inbox.py`
  asserts this case explicitly.
* **Wrap `/authorize`, never `/mcp`.** A non-browser client hitting a Cloudflare login page dies.
* **`HTTP 421 "Misdirected Request"`** on a tunnel: the origin received the wrong `Host`/`:authority`
  (h2 → HTTP/1.1 rewrite). Fix the tunnel `originRequest` (`http2Origin`, `originServerName`) — don't
  "fix" it by disabling TLS verification.
* **Python's default UA gets blocked** by Cloudflare on some zones; always test with a browser UA.
* **Follow-zero redirects** (or you lose the 302 + `Location`); response header keys are lowercase.
* **JSON-only responses** keep clients happy: return `application/json` for `POST /mcp` instead of
  opening a server-sent-event stream that never ends.
* **A key-IP allow-list token + IPv6 egress** = Cloudflare error `9109`. Force IPv4 for API calls.
* **Rotate after exposure**: if the key ever travelled through a URL, a ticket or a chat log, treat
  it as burned — edit the env file, restart, clients re-authorize once.

## What this is not

Not an identity provider. The token the client receives *is* your static key, so there is no
per-user authorization, no scopes enforcement beyond what you build, and no audit trail beyond your
logs. If you need real multi-user access control, put a real IdP (or Cloudflare Access on every
path with service tokens) in front of it. See `references/security.md`.

MIT licensed.
