# The OAuth shim — what it implements and why each piece is needed

Source: `oauth_shim.py` (~380 lines). Mounted by `install(app, access_token, base_url)`.

## The trigger: 401 that teaches the client what to do

```
POST /mcp
  ← 401
    WWW-Authenticate: Bearer resource_metadata="https://host/.well-known/oauth-protected-resource"
    {"error":"unauthorized"}
```

Without `resource_metadata` the client can only report *"couldn't connect to the server"*. With it,
RFC 9728 discovery starts. That one header is the difference between a dead end and a working
connector — always send it when `MCP_PUBLIC_BASE` is configured.

## Endpoint matrix

| route | method | answer | notes |
| --- | --- | --- | --- |
| `/.well-known/oauth-protected-resource` | GET | `{resource, authorization_servers, bearer_methods_supported, resource_name}` | also served under any suffix (`/…/mcp`) |
| `/.well-known/oauth-authorization-server` | GET | `{issuer, authorization_endpoint, token_endpoint, registration_endpoint, revocation_endpoint, scopes_supported, code_challenge_methods_supported:["S256","plain"]}` | `/…/openid-configuration` aliases it |
| `/register` | POST | 201 + `client_id`, `redirect_uris`, `grant_types` | RFC 7591. Clients usually register on every connect; the store is a small JSON file. |
| `/authorize` | GET | 200 consent HTML | reads `client_id`, `redirect_uri`, `state`, `code_challenge`, `code_challenge_method`, `scope` |
| `/authorize` | POST | 302 `redirect_uri?code=…&state=…` | wrong key → **401** (never redirect with an error you haven't validated) |
| `/token` | POST | `{access_token, token_type:"Bearer", expires_in, refresh_token, scope}` | `grant_type=authorization_code` (PKCE verified) or `refresh_token` |
| `/revoke` | POST | `{"revoked": true}` | refresh tokens only; the static key itself cannot be revoked this way |

These paths must be **exempt from your bearer check** (they're in `PUBLIC_PATHS`), otherwise the
client can never bootstrap.

## Why the access token is your static key

The client has to end up with *something* that satisfies your existing `Authorization: Bearer`
check. Options:

1. Return the existing key — zero changes elsewhere, and the key is only ever seen over TLS
   between the client and your server. **What this repo does.**
2. Mint a signed JWT and teach your server to verify it. More work (`kid` rotation, clock skew,
   a JWKS endpoint) but allows per-client revocation. Worth it only for multi-user deployments.

If you go with (1), the human-typed secret and the machine token may differ: `install(..., auth_key=)`
lets you keep `MCP_TOKEN` for machines while the consent page demands a different, shareable secret.

## Conversation-checks

* `code` is single-use, expires in 300 s, and is bound to `client_id` + `redirect_uri`.
* PKCE `S256` is computed and compared; plain is accepted for clients that insist.
* `redirect_uri` must have been registered (when the client registered any) — no open redirector.
* Refresh tokens rotate on every use, so a leaked refresh token is detectable by a `invalid_grant`
  on the legitimate client.
* The state file is written atomically (`os.replace`) with mode 600; it contains no key material,
  but it does contain live refresh tokens.

## Consent page variants

```
no Cf-Access-Jwt-Assertion  -> password field ("enter the access key")   ← backwards compatible
valid, verified JWT         -> "Authenticated via Cloudflare Access: <email>" + one button
invalid/forged/expired JWT  -> falls back to the password field          ← never a bypass
```

`cf_identity()` verifies the RS256 signature against `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`
(1 h cache), checks `iss` and `exp`, and `aud` when `MCP_CF_ACCESS_AUD` is set. Details and the
test matrix: `cf-access.md`.

## Testing it

`scripts/selftest_oauth.py <base> [key]` reproduces the exact client walk:

```
0) POST /mcp  -> 401 + resource_metadata      5) Bearer token -> initialize
1) three discovery endpoints -> 200           6) tools/list, tools/call
2) /register -> 201                           7) refresh -> new access + refresh token
3) consent page 200, wrong key -> 401
4) right key -> 302 code+state -> /token 200
```

Implementation notes that cost real debugging time:

* send a **browser User-Agent** — Cloudflare answers urllib's default UA with an interstitial page
* `ProxyHandler({})`, or an environment HTTP proxy swallows the requests
* **do not follow redirects** (custom `HTTPRedirectHandler` returning `None`) or the 302 is invisible
* response header keys are **lowercase** (`h["location"]`, not `h["Location"]`)
