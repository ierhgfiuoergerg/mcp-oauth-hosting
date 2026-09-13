# Cloudflare Access, scoped to one path

## The problem

You want "log in with SSO" instead of "paste a shared secret" for the human approval step.
Cloudflare Access looks like the answer — until you point it at the MCP host and the client dies,
because a non-browser client has no way to complete an interactive login page: it receives HTML
where it expected JSON, and reports a connection failure.

## The shape that works

| path | behind Access? | why |
| --- | --- | --- |
| `/authorize` (+ `*`) | **yes** | it is opened in a browser; the human can log in there |
| `/mcp` | no | machine traffic, bearer/`/t/`/`/s/` auth only |
| `/token` | no | machine traffic |
| `/.well-known/*` | no | discovery happens before any credential exists |
| `/health` | no | keep it probe-able |

Access is only *usable* where a browser is in the loop. Put it anywhere else and you have broken
the connector — hence the provisioning script's post-check and automatic rollback.

## Two halves that must agree

1. **Access app** (`provision_cf_access_app.sh`) — self-hosted app, domain
   `host/authorize*`, policy `allow` with `cloudflare_account_member` (`{account_id}`) or a single
   `email`, session duration 24 h.
2. **Server verification** (`oauth_shim.cf_identity`) — the request arrives with
   `Cf-Access-Jwt-Assertion`; the shim verifies the RS256 signature against the team's public keys
   and matches `iss`/`exp`/`aud`. Only then does the consent page drop the key field.

Never trust the header on its own — an unverified `Cf-Access-Jwt-Assertion` is trivially forged if
the origin is ever reachable directly. `scripts/selftest_cf_jwt.py` proves the signature is what
decides: tampered, other-key, unknown-`kid`, expired, wrong-`iss`, wrong-`aud` all return `None`.

Fill in afterwards:

```
MCP_CF_ACCESS_TEAM=<team>.cloudflareaccess.com    # prefix before .cloudflareaccess.com
MCP_CF_ACCESS_AUD=<app audience tag>              # printed by the provisioning script
```

## API permission ladder (this is where the time goes)

| symptom | meaning |
| --- | --- |
| `GET /accounts/<id>/access/apps` → 403 | token has no Access permission at all |
| `POST /accounts/<id>/access/apps` → `400` (parameters) with an empty body | ✅ **write access present** — a 400 on an empty body is a good sign, not a failure |
| `POST …/access/apps` → `403` `code 1010 auth.forbidden` | token holds *Read* instead of *Edit* — add **Access: Apps and Policies: Write** |
| `403 Authentication error` on `access/organizations` | Zero Trust not enabled for the account yet (open the Zero Trust dashboard once) |
| error `9109` | the token has an **IP allow-list** and you're calling from an unlisted IP (usually IPv6) → force IPv4 (`curl -4`) |
| `GET /accounts/<id>/access/organizations` → 200 | Zero Trust is set up; read the team name from there instead of asking a human |

Also: `/user/tokens/verify` reports *invalid* for account-scoped tokens — verify against
`/accounts/<id>/tokens/verify` instead. And you do **not** need to create a new Zero Trust team if
one already exists; the existing one works fine (that's what `access/organizations` tells you).

## Alternatives if you don't want Cloudflare

* **mTLS** — strong, but few MCP clients let you install a client certificate.
* **Access service tokens** — machine-only (`CF-Access-Client-Id/Secret` headers), so it solves
  the opposite problem: hardening `/mcp`, not replacing the human consent step. It also requires
  header injection, which the URL-only clients cannot do.
* **An email OTP inside your own consent page** — works for humans and stays browser-side; more
  code, and it means running the mail path yourself.
* **A real IdP (Auth0/Keycloak/Ory)** — correct answer for anything multi-user. See `security.md`.
