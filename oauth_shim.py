#!/usr/bin/env python3
"""oauth_shim.py — drop-in "minimum viable OAuth 2.1" authorization server for a
self-hosted MCP server (or any HTTP API) that authenticates with a static bearer key.

WHY THIS EXISTS
---------------
Some MCP clients (the Grok app, and a few mobile agents) only let the user paste a
single HTTPS URL. They offer no custom-header field, so a static bearer token cannot
be entered anywhere. When such a client hits a 401 it falls back to the standard
OAuth discovery flow:

    POST /mcp                                     -> 401 + WWW-Authenticate: Bearer resource_metadata="..."
    GET  /.well-known/oauth-protected-resource     -> where is the authorization server?
    GET  /.well-known/oauth-authorization-server   -> which endpoints does it expose?
    POST /register                                 -> dynamic client registration (RFC 7591)
    GET  /authorize                                -> browser: the human approves
    POST /token                                    -> authorization_code (+PKCE) -> bearer token

This module implements exactly those endpoints. The token it hands back is simply
your existing static key, so nothing else in your server has to change: the client
keeps calling `Authorization: Bearer <key>` afterwards.

    from oauth_shim import install
    install(app, access_token=TOKEN, base_url="https://mcp.example.com", auth_key=TOKEN)

Everything is optional and inert until you call install() with a public base URL.

Optional Cloudflare Access integration
--------------------------------------
Set MCP_CF_ACCESS_TEAM=<team>.cloudflareaccess.com (and optionally MCP_CF_ACCESS_AUD)
when a Cloudflare Access application sits in front of /authorize. Requests that passed
Access carry `Cf-Access-Jwt-Assertion`; a valid RS256 signature (verified against
https://<team>.cloudflareaccess.com/cdn-cgi/access/certs) means the human is already
authenticated, so the consent page drops the key field and shows a single
"Authorize" button. Anything that fails verification falls back to the key form.
"""
import html
import json
import os
import secrets
import time
from pathlib import Path
from urllib.parse import urlencode, parse_qs

from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

STATE_FILE = Path(os.environ.get("MCP_OAUTH_STATE", "/var/lib/mcp-oauth/oauth_state.json"))
SERVICE_NAME = os.environ.get("MCP_SERVICE_NAME", "private service")
DISPLAY_NAME = os.environ.get("MCP_DISPLAY_NAME", "Private MCP")
SCOPE = os.environ.get("MCP_OAUTH_SCOPE", "mcp.read")

PUBLIC_PATHS = (
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-authorization-server/mcp",
    "/.well-known/openid-configuration",
    "/register",
    "/authorize",
    "/token",
    "/revoke",
)


def is_public_path(path: str) -> bool:
    """Paths that must stay reachable without a bearer token (the client has none yet)."""
    p = path.rstrip("/") or "/"
    if p in PUBLIC_PATHS or path in PUBLIC_PATHS:
        return True
    return p.startswith("/.well-known/oauth-protected-resource")


def _load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"clients": {}, "refresh": {}}


def _save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, STATE_FILE)
    os.chmod(STATE_FILE, 0o600)


CONSENT_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize {display}</title>
<style>
 body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f6f7f9;
      display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}
 .card{{background:#fff;border-radius:16px;padding:28px 26px;max-width:400px;width:88%;
       box-shadow:0 8px 30px rgba(0,0,0,.08)}}
 h1{{font-size:18px;margin:0 0 6px}} p{{color:#666;font-size:13px;line-height:1.6;margin:6px 0 16px}}
 input{{width:100%;box-sizing:border-box;padding:12px;border:1px solid #ddd;border-radius:10px;font-size:14px}}
 button{{width:100%;margin-top:14px;padding:12px;border:0;border-radius:10px;background:#102244;color:#fff;
        font-size:15px;font-weight:600}}
 .who{{color:#999;font-size:12px;word-break:break-all;margin-top:14px}}
 .err{{color:#c0392b;font-size:13px;margin-top:10px}}
 .idp{{background:#f2f7f4;color:#1a7f4b;font-size:13px;border-radius:10px;padding:10px 12px;margin:8px 0 4px}}
</style></head><body><div class="card">
<h1>Authorize {display}</h1>
<p>{client} is requesting read access to {service}.</p>
{body}
<div class="who">client_id: {client_id}</div>
{err}
</div></body></html>"""

# Already authenticated by Cloudflare Access -> no key field, one button.
CF_PAGE_BODY = ('<div class="idp">Authenticated via Cloudflare Access: {ident}</div>'
                '<form method="post">{hidden}<button type="submit">Authorize</button></form>')
KEY_PAGE_BODY = ('<p>Enter the access key to continue.</p>'
                 '<form method="post">{hidden}'
                 '<input name="key" type="password" placeholder="access key" autocomplete="off" autofocus>'
                 '<button type="submit">Authorize</button></form>')

# ── optional Cloudflare Access identity ──────────────────────────────────────
CF_TEAM = os.environ.get("MCP_CF_ACCESS_TEAM", "").strip()
CF_AUD = os.environ.get("MCP_CF_ACCESS_AUD", "").strip()
_cf_jwks_cache: dict = {"ts": 0.0, "keys": []}


def _cf_jwks() -> list:
    import urllib.request

    if CF_TEAM and time.time() - _cf_jwks_cache["ts"] > 3600:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(
            f"https://{CF_TEAM}/cdn-cgi/access/certs",
            headers={"User-Agent": "Mozilla/5.0 (mcp-oauth-shim)"},
        )
        with opener.open(req, timeout=10) as r:
            _cf_jwks_cache["keys"] = json.load(r).get("keys", [])
        _cf_jwks_cache["ts"] = time.time()
    return _cf_jwks_cache["keys"]


def cf_identity(request) -> str | None:
    """Return the Cloudflare-Access-verified identity (email), or None.

    Never trust an unverified header: the JWT signature is checked against the
    team's public keys, and iss/exp (plus aud when MCP_CF_ACCESS_AUD is set) must match.
    """
    token = request.headers.get("cf-access-jwt-assertion")
    if not token or not CF_TEAM:
        return None
    try:
        import jwt

        header = jwt.get_unverified_header(token)
        jwk = next((k for k in _cf_jwks() if k.get("kid") == header.get("kid")), None)
        if not jwk:
            return None
        pub = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
        claims = jwt.decode(
            token, key=pub, algorithms=["RS256"], audience=CF_AUD or None,
            issuer=f"https://{CF_TEAM}", options={"verify_aud": bool(CF_AUD)},
        )
        return str(claims.get("email") or claims.get("sub") or "cf-user")
    except Exception:
        return None


def install(app, access_token: str, base_url: str, auth_key: str | None = None,
            token_ttl: int = 2592000) -> tuple:
    """Mount the OAuth endpoints on a Starlette/FastAPI app.

    access_token : what the client receives as its bearer token (usually your static key)
    base_url     : public https origin, e.g. https://mcp.example.com
    auth_key     : the secret typed into the consent page (defaults to access_token)
    """
    base = base_url.rstrip("/")
    key = (auth_key or access_token).strip()
    state = _load_state()
    codes: dict = {}  # code -> {client_id, redirect_uri, challenge, method, exp, scope}

    def _hidden(p: dict) -> str:
        return "".join(
            f'<input type="hidden" name="{k}" value="{html.escape(str(p[k]))}">'
            for k in ("response_type", "client_id", "redirect_uri", "state",
                      "code_challenge", "code_challenge_method", "scope")
            if p.get(k)
        )

    def _render(client: dict, p: dict, body: str, err: str = "", status: int = 200):
        page = CONSENT_PAGE.format(
            display=html.escape(DISPLAY_NAME), service=html.escape(SERVICE_NAME),
            client=html.escape(client.get("client_name", "A client")),
            client_id=html.escape(p.get("client_id", "-")),
            hidden=_hidden(p), body=body, err=err,
        )
        return HTMLResponse(page, status_code=status)

    def meta(request):
        suffix = request.path_params.get("rest") or ""
        res = f"{base}/{suffix.strip('/')}" if suffix.strip("/") else base
        return JSONResponse({
            "resource": res,
            "authorization_servers": [base],
            "bearer_methods_supported": ["header"],
            "resource_name": SERVICE_NAME,
        })

    def as_meta(request):
        return JSONResponse({
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "registration_endpoint": f"{base}/register",
            "revocation_endpoint": f"{base}/revoke",
            "scopes_supported": [SCOPE],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        })

    async def register(request):
        try:
            body = json.loads(await request.body() or b"{}")
        except Exception:
            body = {}
        cid = "mcp-" + secrets.token_hex(12)
        rec = {
            "client_id": cid,
            "client_name": body.get("client_name") or "unknown",
            "redirect_uris": body.get("redirect_uris") or [],
            "grant_types": body.get("grant_types") or ["authorization_code", "refresh_token"],
            "response_types": body.get("response_types") or ["code"],
            "token_endpoint_auth_method": "none",
            "client_id_issued_at": int(time.time()),
            "scope": body.get("scope") or SCOPE,
        }
        state["clients"][cid] = rec
        _save_state(state)
        return JSONResponse(rec, status_code=201)

    def _params(request, form: dict | None = None) -> dict:
        q = {k: v[0] for k, v in parse_qs(request.url.query).items()}
        if form:
            q.update({k: (v[0] if isinstance(v, list) else v) for k, v in form.items()})
        return q

    async def authorize(request):
        if request.method == "POST":
            p = _params(request, parse_qs((await request.body()).decode()))
        else:
            p = _params(request)
        redirect_uri = p.get("redirect_uri", "")
        client = state["clients"].get(p.get("client_id", ""), {})
        ok_redirect = bool(redirect_uri) and (
            not client.get("redirect_uris") or redirect_uri in client["redirect_uris"])
        ident = cf_identity(request)  # None unless CF Access is configured and verified

        if request.method == "POST":
            if not ident and (p.get("key") or "").strip() != key:
                return _render(client, p, KEY_PAGE_BODY.format(hidden=_hidden(p), ident=""),
                               err='<div class="err">Wrong key, try again.</div>', status=401)
            if not ok_redirect:
                return JSONResponse({"error": "invalid_request",
                                     "error_description": "redirect_uri not registered"},
                                    status_code=400)
            code = secrets.token_urlsafe(32)
            codes[code] = {
                "client_id": p.get("client_id", ""),
                "redirect_uri": redirect_uri,
                "challenge": p.get("code_challenge", ""),
                "method": p.get("code_challenge_method", "plain"),
                "scope": p.get("scope") or SCOPE,
                "exp": time.time() + 300,
            }
            q = {"code": code}
            if p.get("state"):
                q["state"] = p["state"]
            sep = "&" if "?" in redirect_uri else "?"
            return RedirectResponse(f"{redirect_uri}{sep}{urlencode(q)}", status_code=302)

        body = (CF_PAGE_BODY.format(hidden=_hidden(p), ident=html.escape(ident)) if ident
                else KEY_PAGE_BODY.format(hidden=_hidden(p), ident=""))
        return _render(client, p, body)

    async def token(request):
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
        grant = form.get("grant_type", "")
        if grant == "authorization_code":
            rec = codes.pop(form.get("code", ""), None)
            if not rec or rec["exp"] < time.time():
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            verifier = form.get("code_verifier", "")
            if rec["challenge"]:
                import base64
                import hashlib

                if rec["method"] == "S256":
                    digest = hashlib.sha256(verifier.encode()).digest()
                    calc = base64.urlsafe_b64encode(digest).decode().rstrip("=")
                else:
                    calc = verifier
                if calc != rec["challenge"]:
                    return JSONResponse({"error": "invalid_grant",
                                         "error_description": "PKCE verification failed"},
                                        status_code=400)
        elif grant == "refresh_token":
            rt = form.get("refresh_token", "")
            if rt not in state["refresh"]:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            rec = state["refresh"].pop(rt)
        else:
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

        new_rt = "mcprt-" + secrets.token_urlsafe(24)
        state["refresh"][new_rt] = {
            "client_id": form.get("client_id") or rec.get("client_id", ""),
            "ts": int(time.time()),
        }
        _save_state(state)
        return JSONResponse({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": token_ttl,
            "refresh_token": new_rt,
            "scope": rec.get("scope", SCOPE),
        })

    async def revoke(request):
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
        state["refresh"].pop(form.get("token", ""), None)
        _save_state(state)
        return JSONResponse({"revoked": True})

    app.add_route("/.well-known/oauth-protected-resource", meta, methods=["GET"])
    app.add_route("/.well-known/oauth-protected-resource/{rest:path}", meta, methods=["GET"])
    app.add_route("/.well-known/oauth-authorization-server", as_meta, methods=["GET"])
    app.add_route("/.well-known/oauth-authorization-server/{rest:path}", as_meta, methods=["GET"])
    app.add_route("/.well-known/openid-configuration", as_meta, methods=["GET"])
    app.add_route("/register", register, methods=["POST"])
    app.add_route("/authorize", authorize, methods=["GET", "POST"])
    app.add_route("/token", token, methods=["POST"])
    app.add_route("/revoke", revoke, methods=["POST"])
    return PUBLIC_PATHS
