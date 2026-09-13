#!/usr/bin/env python3
"""selftest_oauth.py — end-to-end check of the OAuth flow a URL-only client walks.

    python3 scripts/selftest_oauth.py https://mcp.example.com [access-key]

Runs: discovery -> dynamic registration -> consent page (wrong key must 401) ->
correct key -> 302 with code+state -> /token (PKCE S256) -> initialize ->
tools/list -> refresh. Exit code 0 only if every step passes.

Implementation notes (all learned the hard way against a real Cloudflare-fronted host):
  * send a browser User-Agent — Cloudflare answers Python-urllib's default UA with an
    interstitial error page instead of your JSON
  * ProxyHandler({}) so a local HTTP proxy in the environment doesn't swallow requests
  * follow no redirects (a custom HTTPRedirectHandler) or you lose the 302 + Location
  * response header keys are lower-case
"""
import base64
import hashlib
import json
import os
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "").rstrip("/")
TOKEN = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("MCP_TOKEN", "")
ENV_FILE = os.environ.get("MCP_ENV_FILE", "/etc/mcp-server.env")
UA = {"User-Agent": "Mozilla/5.0 (oauth-selftest)"}
JSON_H = {**UA, "Content-Type": "application/json",
          "Accept": "application/json, text/event-stream"}

if not BASE:
    sys.exit("usage: selftest_oauth.py https://<host> [access-key]")
if not TOKEN and os.path.exists(ENV_FILE):
    m = re.search(r"^MCP_TOKEN=(.*)$", open(ENV_FILE).read(), re.M)
    TOKEN = m.group(1).strip() if m else ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))
PASS = FAIL = 0


def req(url, method="GET", data=None, headers=None, form=False):
    h = dict(UA)
    h.update(headers or {})
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode() if form else json.dumps(data).encode()
    r = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with OPENER.open(r, timeout=25) as resp:
            return resp.status, resp.read().decode(), {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), {k.lower(): v for k, v in e.headers.items()}


def ok(step, cond, extra=""):
    global PASS, FAIL
    PASS, FAIL = PASS + (1 if cond else 0), FAIL + (0 if cond else 1)
    print(("  PASS " if cond else "  FAIL ") + step + (f"  {str(extra)[:160]}" if extra else ""))


print(f"BASE = {BASE}  key={'yes' if TOKEN else 'no'}\n=== 0) unauthenticated probe ===")
s, _, hh = req(f"{BASE}/mcp", "POST", {"jsonrpc": "2.0", "id": 0, "method": "initialize",
                                       "params": {}}, JSON_H)
ok("POST /mcp without key -> 401", s == 401)
ok("401 advertises resource_metadata", "resource_metadata" in (hh.get("www-authenticate") or ""),
   hh.get("www-authenticate"))

print("=== 1) discovery ===")
s, b, _ = req(f"{BASE}/.well-known/oauth-protected-resource")
prm = json.loads(b) if s == 200 else {}
ok("protected-resource 200", s == 200, prm.get("authorization_servers"))
s, _, _ = req(f"{BASE}/.well-known/oauth-protected-resource/mcp")
ok("protected-resource/mcp 200", s == 200)
s, b, _ = req(f"{BASE}/.well-known/oauth-authorization-server")
asm = json.loads(b) if s == 200 else {}
ok("authorization-server 200", s == 200,
   {k: asm.get(k) for k in ("token_endpoint", "registration_endpoint")})

print("=== 2) dynamic client registration ===")
s, b, _ = req(f"{BASE}/register", "POST", {
    "client_name": "selftest",
    "redirect_uris": ["https://example.com/cb", "myapp://oauth"],
    "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"]}, JSON_H)
reg = json.loads(b) if s in (200, 201) else {}
cid = reg.get("client_id")
ok("register 201", s == 201, cid)

print("=== 3) consent page ===")
verifier = secrets.token_urlsafe(48)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
ap = {"response_type": "code", "client_id": cid, "redirect_uri": "myapp://oauth",
      "state": "xyz123", "code_challenge": challenge, "code_challenge_method": "S256",
      "scope": "mcp.read"}
s, b, _ = req(f"{BASE}/authorize?" + urllib.parse.urlencode(ap))
ok("authorize GET 200 (consent)", s == 200 and ("password" in b or "Authorize" in b))
s, _, _ = req(f"{BASE}/authorize", "POST", {**ap, "key": "definitely-wrong"}, form=True)
ok("wrong key -> 401", s == 401)

print("=== 4) correct key -> token exchange ===")
if not TOKEN:
    print("  (no key available, skipped)")
else:
    s, _, h = req(f"{BASE}/authorize", "POST", {**ap, "key": TOKEN}, form=True)
    loc = h.get("location", "")
    code = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("code", [""])[0]
    ok("302 with code + state", s == 302 and bool(code) and "state=xyz123" in loc, loc[:90])
    s, b, _ = req(f"{BASE}/token", "POST", {"grant_type": "authorization_code", "code": code,
                                            "redirect_uri": "myapp://oauth", "client_id": cid,
                                            "code_verifier": verifier}, form=True)
    tok = json.loads(b) if s == 200 else {}
    at, rt = tok.get("access_token"), tok.get("refresh_token")
    ok("token 200 (access_token)", s == 200 and bool(at),
       f"type={tok.get('token_type')} expires_in={tok.get('expires_in')}")
    print("=== 5) call MCP with the token ===")
    s, b, _ = req(f"{BASE}/mcp", "POST", {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                          "params": {"protocolVersion": "2025-06-18",
                                                     "capabilities": {},
                                                     "clientInfo": {"name": "selftest", "version": "0"}}},
                  {**JSON_H, "Authorization": f"Bearer {at}"})
    ok("initialize 200", s == 200, b[:80])
    s, b, _ = req(f"{BASE}/mcp", "POST", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                  {**JSON_H, "Authorization": f"Bearer {at}"})
    ok("tools/list returns tools", s == 200 and "tools" in b, b[:80])
    s, b, _ = req(f"{BASE}/mcp", "POST", {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                          "params": {"name": "search_kb",
                                                     "arguments": {"query": "deploy"}}},
                  {**JSON_H, "Authorization": f"Bearer {at}"})
    ok("tools/call search_kb", s == 200 and '"content"' in b, b[:80])
    print("=== 6) refresh ===")
    s, b, _ = req(f"{BASE}/token", "POST", {"grant_type": "refresh_token", "refresh_token": rt,
                                            "client_id": cid}, form=True)
    ok("refresh 200", s == 200 and "access_token" in b)

print(f"\nRESULT PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
