#!/usr/bin/env python3
"""mcp_server.py — a small, dependency-light MCP server (Streamable HTTP) that reads a
folder of markdown files, with bearer auth, a host allow-list and the OAuth shim mounted.

Endpoints
  GET  /health                     liveness: {"ok": true, "docs": N}
  POST /mcp                        MCP Streamable HTTP (initialize / tools/list / tools/call)
  GET  /mcp                        MCP SSE stream (kept minimal)
  POST /t/<token>/mcp              same as /mcp but the key rides in the path (for clients
  POST /s/<slug>/mcp               with no credential field at all — use a *separate* share
                                   slug, never your main key, and revoke it when done)

Auth accepted on /mcp, first match wins
  Authorization: Bearer <MCP_TOKEN>      X-MCP-Token: <MCP_TOKEN>
  ?token=<MCP_TOKEN>                     /t/<MCP_TOKEN>/mcp     /s/<MCP_SHARE_SLUG>/mcp
Everything else returns 401 with WWW-Authenticate: Bearer resource_metadata="...",
which is what makes OAuth-capable clients (Grok app, etc.) start the authorization flow.

Env (see env.example): MCP_TOKEN (required), MCP_PUBLIC_BASE, KB_DIR, MCP_PATH,
MCP_ALLOWED_HOSTS, MCP_SHARE_SLUG, MCP_SERVICE_NAME, MCP_OAUTH_STATE,
MCP_CF_ACCESS_TEAM, MCP_CF_ACCESS_AUD
"""
import json
import os
import re
import secrets
import sys
from pathlib import Path

from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

import oauth_shim


TOKEN = os.environ.get("MCP_TOKEN", "").strip()
if not TOKEN:
    sys.exit("MCP_TOKEN is required (a long random string, e.g. `openssl rand -hex 32`)")
SLUG = os.environ.get("MCP_SHARE_SLUG", "").strip()
KB_DIR = Path(os.environ.get("KB_DIR", "./kb")).resolve()
MCP_PATH = os.environ.get("MCP_PATH", "/mcp")
PUBLIC_BASE = os.environ.get("MCP_PUBLIC_BASE", "").rstrip("/")
NAME = os.environ.get("MCP_SERVICE_NAME", "knowledge-base")
VERSION = "1.0.0"
PROTOCOL = "2025-06-18"
TOKEN_PREFIX = os.environ.get("MCP_TOKEN_PREFIX", "/t")
SLUG_PREFIX = os.environ.get("MCP_SLUG_PREFIX", "/s")
ALLOWED = [h.strip().lower() for h in os.environ.get("MCP_ALLOWED_HOSTS", "").split(",") if h.strip()]


# ── auth ─────────────────────────────────────────────────────────────────────
def _host_ok(request) -> bool:
    if not ALLOWED:
        return True
    host = (request.headers.get("host") or "").split(":")[0].lower()
    return any(host == a or (a.startswith("*.") and host.endswith(a[1:])) for a in ALLOWED)


def _key_ok(request) -> bool:
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer ") and secrets.compare_digest(auth[7:].strip(), TOKEN):
        return True
    for h in ("x-mcp-token", "x-kb-token"):
        v = request.headers.get(h, "")
        if v and secrets.compare_digest(v.strip(), TOKEN):
            return True
    q = dict(request.query_params)
    if q.get("token") and secrets.compare_digest(q["token"], TOKEN):
        return True
    path = request.url.path
    for prefix, secret in ((TOKEN_PREFIX, TOKEN), (SLUG_PREFIX, SLUG)):
        if secret and path.startswith(prefix + "/"):
            if secrets.compare_digest(path[len(prefix) + 1:].split("/")[0], secret):
                return True
    return False


async def _unauthorized(request):
    headers = {}
    if PUBLIC_BASE:
        headers["WWW-Authenticate"] = (
            f'Bearer resource_metadata="{PUBLIC_BASE}/.well-known/oauth-protected-resource"')
    return JSONResponse({"error": "unauthorized", "hint": "send Authorization: Bearer <key>"},
                        status_code=401, headers=headers)


# ── knowledge base ───────────────────────────────────────────────────────────
def _docs():
    if not KB_DIR.is_dir():
        return []
    return sorted(p for p in KB_DIR.rglob("*.md") if p.is_file())


def _search(query: str, limit: int = 5):
    terms = [t for t in re.split(r"\s+", query.strip().lower()) if t]
    hits = []
    for p in _docs():
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        low = text.lower()
        score = sum(low.count(t) for t in terms)
        if not terms or score:
            idx = min((low.find(t) for t in terms if t in low), default=0)
            hits.append({
                "title": p.stem,
                "path": str(p.relative_to(KB_DIR)),
                "score": score,
                "snippet": re.sub(r"\s+", " ", text[max(0, idx - 80): idx + 220]).strip(),
            })
    hits.sort(key=lambda h: -h["score"])
    return hits[:limit]


def _tools():
    return [
        {
            "name": "search_kb",
            "description": f"Search the {NAME} markdown knowledge base.",
            "inputSchema": {"type": "object", "properties": {
                "query": {"type": "string", "description": "keywords"},
                "limit": {"type": "integer", "default": 5}}, "required": ["query"]},
        },
        {
            "name": "get_doc",
            "description": "Return the full markdown of one document.",
            "inputSchema": {"type": "object", "properties": {
                "path": {"type": "string",
                         "description": "path returned by search_kb, e.g. notes/foo.md"}},
                "required": ["path"]},
        },
    ]


def _call_tool(name, args):
    if name == "search_kb":
        res = _search(str(args.get("query", "")), int(args.get("limit", 5) or 5))
        text = "\n\n".join(f"## {h['title']}\n{h['snippet']}" for h in res) or "no match"
        return [{"type": "text", "text": text}]
    if name == "get_doc":
        rel = str(args.get("path", "")).lstrip("/")
        target = (KB_DIR / rel).resolve()
        if not str(target).startswith(str(KB_DIR)) or not target.is_file():
            return [{"type": "text", "text": "not found"}]
        return [{"type": "text", "text": target.read_text(encoding="utf-8", errors="replace")}]
    return [{"type": "text", "text": f"unknown tool {name}"}]


# ── MCP transport (Streamable HTTP, JSON responses) ──────────────────────────
def _rpc(msg):
    method, mid = msg.get("method"), msg.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": PROTOCOL,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": NAME, "version": VERSION}}}
    if method in ("notifications/initialized", "initialized"):
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": _tools()}}
    if method == "tools/call":
        p = msg.get("params") or {}
        return {"jsonrpc": "2.0", "id": mid,
                "result": {"content": _call_tool(p.get("name"), p.get("arguments") or {})}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    return {"jsonrpc": "2.0", "id": mid,
            "error": {"code": -32601, "message": f"method not found: {method}"}}


async def mcp(request):
    if not _key_ok(request):
        return await _unauthorized(request)
    if request.method == "GET":  # keep-alive SSE channel: minimal but valid
        return Response("event: ping\ndata: {}\n\n", media_type="text/event-stream",
                        headers={"Cache-Control": "no-store"})
    try:
        payload = json.loads(await request.body() or b"{}")
    except Exception:
        return JSONResponse({"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32700, "message": "parse error"}}, status_code=400)
    if isinstance(payload, list):
        out = [r for r in (_rpc(m) for m in payload) if r]
        return JSONResponse(out or {"jsonrpc": "2.0", "id": None, "result": {}})
    out = _rpc(payload)
    if out is None:  # notification: 202, no body
        return Response(status_code=202)
    return JSONResponse(out)


async def health(request):
    return JSONResponse({"ok": True, "docs": len(_docs()), "name": NAME})


def build() -> Starlette:
    app = Starlette(routes=[Route("/health", health, methods=["GET"]),
                            Route(MCP_PATH, mcp, methods=["GET", "POST"]),
                            Route(TOKEN_PREFIX + "/{token}" + MCP_PATH, mcp,
                                  methods=["GET", "POST"]),
                            Route(SLUG_PREFIX + "/{slug}" + MCP_PATH, mcp,
                                  methods=["GET", "POST"])])
    if PUBLIC_BASE:
        # mounts /.well-known/*, /register, /authorize, /token, /revoke
        oauth_shim.install(app, access_token=TOKEN, base_url=PUBLIC_BASE)
    return app


app = build()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"),
                port=int(os.environ.get("PORT", "8081")), log_level="info")
