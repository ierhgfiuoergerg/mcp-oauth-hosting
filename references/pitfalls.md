# Pitfalls collected from a real deployment

Every item here cost debugging time at least once. They are ordered by how likely they are to
waste your evening.

## 1. "Couldn't connect to the server" (the client says nothing useful)

The server returned `401` **without** `WWW-Authenticate: … resource_metadata="…"`, so the client had
no idea an authorization flow existed. Check with:

```bash
curl -si -X POST https://mcp.example.com/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | head -5
```

## 2. Access wrapped the machine path

If `/mcp` redirects (302) to `*.cloudflareaccess.com`, no non-browser client will ever connect.
Scope the Access app to `/authorize*` only. Verify:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://mcp.example.com/health   # want 200, not 302
```

## 3. Cloudflare blocks Python's default User-Agent

`urllib`'s stock UA can get an interstitial error page, which then gets parsed as "your JSON is
broken". Send a browser UA in tests — and remember that Cloudflare's own bot management may also
challenge datacenter IPs.

## 4. Environment proxy eats the request

A local `http_proxy`/`all_proxy` (very common when a proxy client is installed) silently routes
requests to `127.0.0.1` or to a dead node. `urllib.request.build_opener(urllib.request.ProxyHandler({}))`
bypasses it; `curl --noproxy '*'` is the shell equivalent.

## 5. Redirect followed → no `Location` to assert on

You need the 302 *and* its `Location` header. Custom `HTTPRedirectHandler.redirect_request` returning
`None` stops the follow. Also: header keys come back **lowercase** (`h["location"]`).

## 6. HTTP 421 Misdirected Request behind a tunnel

Cloudflare terminated HTTP/2 and spoke HTTP/1.1 to the origin with a rewritten authority → the origin
rejects it. Fix it in the tunnel's `originRequest` (`originServerName`, `http2Origin`) — do **not**
"fix" it with `noTLSVerify`.

## 7. SSE that never ends

MCP Streamable HTTP allows a server-sent-event stream, but mobile clients happy with JSON sometimes
hang waiting for a stream they can't parse. Return `application/json` for `POST /mcp` and keep `GET`
as a minimal stream.

## 8. Cloudflare API gotchas

* account-scoped token + `/user/tokens/verify` → "invalid" (that endpoint only knows user tokens)
* `403` + `code 1010` on `POST access/apps` → the token has *Read*, not *Edit*
* empty-body POST returning `400` → **good news**, parameters are being validated = write access OK
* error `9109` → token IP allow-list vs IPv6 egress; force IPv4
* Zone DNS edits need `Zone: DNS: Edit`; Access needs `Access: Apps and Policies: Write`
* an existing Zero Trust team is fine — no need to create a new organisation

## 9. Key hygiene

* If the key was ever pasted into a URL, a chat, or a screenshot, treat it as public: rotate.
* Keep a separate `MCP_SHARE_SLUG` for link-based access and empty it when the link is done.
* Generate with `openssl rand -hex 32` (64 hex chars); never a memorable phrase.

## 10. Fast debugging order

```
1. systemctl status <name>            # process up?
2. curl -s 127.0.0.1:8081/health      # app answering locally?
3. curl the same over the public URL  # tunnel + TLS + Access OK?
4. selftest_oauth.py https://host     # full client walk
5. check /authorize returns 200 (a consent page), not a 302 to Cloudflare
6. check the client's own logs: does it send Authorization at all?
```
