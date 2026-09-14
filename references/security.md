# Security model — honest version

This shim makes a URL-only client work. It is not an authorization server in the "multi-tenant
identity" sense. Know exactly what you have.

## What it gives you

* The key never appears in the URL a user pastes (they paste the bare `/mcp` endpoint).
* The key travels exactly twice: over TLS, from your server, to the client's token exchange.
  One-time `code` + PKCE means it isn't in the browser history either.
* Optional SSO-based consent (Cloudflare Access) — the human step can be keyless while the machine
  step stays on a 64-hex key.
* Refresh tokens rotate, so a stolen refresh token invalidates the legitimate client's next call
  (a visible tripwire).
* Small, auditable surface: ~380 lines, no external auth service to trust.

## What it does not give you

* **No per-user identity.** Every successful client ends up with the *same* token. Two people
  connecting are indistinguishable in your logs — only IP and client_id differ.
* **No scope enforcement.** `scope` is echoed back; enforcing it is your job.
* **No token expiry that matters.** `expires_in` is cosmetic — the client's token *is* the key, and
  the key doesn't expire. Revocation = rotating `MCP_TOKEN` and restarting.
* **No rate limiting.** Add it (nginx `limit_req`, or Cloudflare rate-limiting rules) if the host is
  on the public internet — brute-forcing a 64-hex key isn't realistic, but hammering `/authorize`
  and `/register` is free for an attacker.
* **No defence against a compromised client.** Whatever holds the token can read whatever you
  expose. Keep the knowledge base free of anything you would not hand to that client.

## Hardening checklist, in the order that actually matters

1. **Rotate after exposure.** If the key ever rode in a URL, a chat message, a screenshot or a
   support ticket: `openssl rand -hex 32` → env file → restart. Clients re-authorize once.
2. **Bind to 127.0.0.1**, terminate TLS in front (tunnel or reverse proxy). Never expose port 8081.
3. **Hardened unit**: `DynamicUser=yes`, `ProtectSystem=strict`, `ProtectHome=true`,
   `ReadWritePaths=/var/lib/mcp-oauth`, knowledge base read-only. Shipped in `deploy/mcp-server.service`.
4. **Rate limit** `/authorize`, `/register` and `/token` (429 + log). Both are unauthenticated by
   design.
5. **Rotate the share slug separately.** `MCP_SHARE_SLUG` exists so a *link* can be revoked without
   breaking every client; never put `MCP_TOKEN` in a URL.
6. **Log the 401s** (IP, UA, path) — that's your only signal of someone else probing.

## Threat notes

| attempt | outcome |
| --- | --- |
| forged `Cf-Access-Jwt-Assertion` header | rejected: RS256 signature verified against the team's JWKS (`kid` must match, `iss`/`exp`/`aud` checked) |
| direct request to the origin bypassing Access | same as above — the header is worthless without a valid signature |
| guessing the key via `/authorize` | 401 per attempt; add rate limiting or you're just measuring their patience |
| leaked refresh token | rotation + storage mode 600 limits the window; rotation makes abuse detectable |
| Host-header / DNS rebinding | `MCP_ALLOWED_HOSTS` allow-list rejects mismatched `Host` |
| traversal via `get_doc` | resolved path must stay under `KB_DIR`, checked with `Path.is_relative_to()` — **not** a string prefix test: `/kb-evil/x.md`.startswith(`/kb`) is True, so a sibling directory would leak |

## Inbox-scoped writes (optional)

`KB_WRITE_MODE=inbox` adds one write tool. The design rule is that **a client cannot influence the
destination path at all**, enforced three independent ways:

1. `submit_doc` has no path/directory parameter — the destination is `KB_DIR / KB_INBOX_DIR`, a
   server-side constant.
2. The filename is reduced by `_safe_stem()` to a fragment with no separator, no `..`, and a length
   cap. The invariant (no `/`, no `\`, no `..`, not `.`/`..`, non-empty, ≤ 80 chars) holds for
   *every* input — `scripts/test_safe_stem.py` asserts it over an attack corpus.
3. The final `target.parent != INBOX_DIR` assertion. Redundant given (2), kept so that a future edit
   to (2) cannot silently open a traversal.

Never-overwrite is part of the design rather than a nicety: a name collision appends a timestamp, so
a submitted document can never destroy an existing one.

Default is `off`. Off means the tool is not advertised at all — a capability that does not exist
cannot be talked out of a model.

Residual risks worth naming: every accepted write is a file in your vault (and, with a syncing
vault, in your git history); the share slug can write too, not just the main key; and exclusion
rules are filename-shaped, so a secret written into innocuously-named file still gets indexed.

## If you need real access control

Move to per-client signed tokens (JWT with `kid`, short TTL, your own JWKS at
`/.well-known/jwks.json`), or front the whole host with a real IdP and use Cloudflare Access
**service tokens** for the machine path. The trade-off is a bigger surface and a dependency on
another platform — for a personal knowledge base behind a tunnel, a single rotatable key plus SSO
consent is a reasonable place to stop.
