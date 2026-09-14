#!/usr/bin/env python3
"""mcp_server.py — a small, dependency-light MCP server (Streamable HTTP) that reads a
folder of markdown files, with bearer auth, a host allow-list and the OAuth shim mounted.

Read-only by default. Set KB_WRITE_MODE=inbox to additionally expose submit_doc, which
can write **only** into one inbox subfolder (see the write-scoping section below).

Endpoints
  GET  /health                     liveness: {"ok": true, "docs": N, ...}
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

Tools
  search_kb(query, limit)          keyword search over title/tags/body, cached index
  get_doc(path)                    full markdown of one document (path-scoped to KB_DIR)
  submit_doc(title, content, ...)  only when KB_WRITE_MODE=inbox: writes into INBOX_DIR

Env (see env.example): MCP_TOKEN (required), MCP_PUBLIC_BASE, KB_DIR, MCP_PATH,
MCP_ALLOWED_HOSTS, MCP_SHARE_SLUG, MCP_SERVICE_NAME, MCP_OAUTH_STATE,
MCP_CF_ACCESS_TEAM, MCP_CF_ACCESS_AUD,
KB_WRITE_MODE (off|inbox), KB_INBOX_DIR, KB_EXCLUDE_DIRS, KB_EXCLUDE_GLOBS,
KB_MAX_DOC_BYTES, KB_MAX_WRITE_BYTES, KB_CACHE_TTL
"""
import fnmatch
import hashlib
import json
import os
import re
import secrets
import sys
import time
from datetime import datetime, timezone
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
VERSION = "1.1.0"
PROTOCOL = "2025-06-18"
TOKEN_PREFIX = os.environ.get("MCP_TOKEN_PREFIX", "/t")
SLUG_PREFIX = os.environ.get("MCP_SLUG_PREFIX", "/s")
ALLOWED = [h.strip().lower() for h in os.environ.get("MCP_ALLOWED_HOSTS", "").split(",") if h.strip()]

# ── write scoping ────────────────────────────────────────────────────────────
# off   → read-only (default; a service that cannot write cannot be tricked into writing)
# inbox → additionally expose submit_doc, and NOTHING it accepts can land outside
#         KB_INBOX_DIR: there is no directory parameter, the filename is sanitised, and
#         the resolved path is asserted to sit directly inside the inbox.
WRITE_MODE = os.environ.get("KB_WRITE_MODE", "off").strip().lower()
INBOX_DIRNAME = os.environ.get("KB_INBOX_DIR", "inbox").strip() or "inbox"
INBOX_DIR = (KB_DIR / INBOX_DIRNAME).resolve()

# ── index scoping ────────────────────────────────────────────────────────────
# Credential-shaped documents stay out of the index even when they live in KB_DIR:
# pointing this server at a real notes vault should not publish its recovery codes.
EXCLUDE_DIRS = {d.strip() for d in os.environ.get("KB_EXCLUDE_DIRS", "").split(",") if d.strip()}
_DEFAULT_EXCLUDE_GLOBS = (
    "*recovery-code*,*recovery_codes*,*secret*,*credential*,*password*,*passwd*,"
    "*.env,*token*.md,*apikey*,*api-key*,*private-key*,*id_rsa*"
)
EXCLUDE_GLOBS = [
    g.strip().lower()
    for g in os.environ.get("KB_EXCLUDE_GLOBS", _DEFAULT_EXCLUDE_GLOBS).split(",")
    if g.strip()
]

MAX_DOC_BYTES = int(os.environ.get("KB_MAX_DOC_BYTES", 2 * 1024 * 1024))
MAX_WRITE_BYTES = int(os.environ.get("KB_MAX_WRITE_BYTES", 512 * 1024))
CACHE_TTL = float(os.environ.get("KB_CACHE_TTL", 3))


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


# ── knowledge base: index with cache ─────────────────────────────────────────
def _name_excluded(name: str) -> bool:
    low = name.lower()
    return any(fnmatch.fnmatch(low, g) for g in EXCLUDE_GLOBS)


def _scan() -> tuple:
    """stat-only pass → (signature, [paths]). Reading file contents is the expensive part,
    so the signature is built from (path, mtime_ns, size): unchanged tree ⇒ reuse parse."""
    items = []
    if KB_DIR.exists():
        for p in KB_DIR.rglob("*.md"):
            try:
                rel = p.relative_to(KB_DIR)
            except ValueError:
                continue
            if EXCLUDE_DIRS & set(rel.parts[:-1]):
                continue
            if _name_excluded(p.name):
                continue
            try:
                st = p.stat()
            except OSError:
                continue
            if st.st_size > MAX_DOC_BYTES:
                continue
            items.append((p, st.st_mtime_ns, st.st_size))
    items.sort(key=lambda t: str(t[0]))
    sig = hashlib.sha1("|".join(f"{p}:{m}:{s}" for p, m, s in items).encode()).hexdigest()
    return sig, [p for p, _, _ in items]


_CACHE = {"sig": None, "docs": [], "checked_at": 0.0}


def invalidate_cache():
    """Call after a write so the next read rebuilds the index."""
    _CACHE["sig"] = None
    _CACHE["checked_at"] = 0.0


def _parse(path: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    meta, body = {}, text
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            for line in parts[1].splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    meta[k.strip()] = v.strip()
            body = parts[2].strip()
    return {
        "id": meta.get("id") or path.stem,
        "title": meta.get("title") or path.stem,
        "tags": meta.get("tags", ""),
        "body": body,
        "text": text,
        "path": str(path),
        "rel": str(path.relative_to(KB_DIR)) if str(path).startswith(str(KB_DIR)) else str(path),
    }


def _docs():
    """Cached document list. Within CACHE_TTL, or when the directory signature is
    unchanged, no file content is re-read."""
    now = time.monotonic()
    if _CACHE["sig"] is not None and now - _CACHE["checked_at"] < CACHE_TTL:
        return _CACHE["docs"]
    sig, files = _scan()
    _CACHE["checked_at"] = now
    if sig != _CACHE["sig"]:
        docs = []
        for p in files:
            try:
                docs.append(_parse(p))
            except OSError:
                continue
        _CACHE["docs"], _CACHE["sig"] = docs, sig
    return _CACHE["docs"]


def _search(query: str, limit: int = 5):
    terms = [t for t in re.split(r"\s+", query.strip().lower()) if t]
    hits = []
    for d in _docs():
        blob = f"{d['title']} {d['tags']} {d['body']}".lower()
        score = sum(blob.count(t) for t in terms)
        if not terms or score:
            low = d["body"].lower()
            idx = min((low.find(t) for t in terms if t in low), default=0)
            hits.append({
                "title": d["title"],
                "path": d["rel"],
                "score": score,
                "snippet": re.sub(r"\s+", " ", d["body"][max(0, idx - 80): idx + 220]).strip(),
            })
    hits.sort(key=lambda h: -h["score"])
    return hits[:limit]


# ── write tool (KB_WRITE_MODE=inbox) ─────────────────────────────────────────
_UNSAFE = re.compile(r"[^\w\u4e00-\u9fff.\- ]+", re.UNICODE)


def _safe_stem(raw: str) -> str:
    """Reduce any string to a safe filename stem: no separators, no '..', length-capped.

    Invariant (holds for ALL input): no '/', no '\\\\', no '..', not '.'/'..', non-empty,
    ≤ 80 chars. Tested by scripts/test_safe_stem.py.
    """
    s = (raw or "").strip()
    s = s.replace("/", "-").replace("\\", "-")
    s = _UNSAFE.sub("-", s)
    s = re.sub(r"\s+", "-", s)
    s = re.sub(r"-{2,}", "-", s)
    s = re.sub(r"-+\.", ".", s)
    s = re.sub(r"\.-+", ".", s)
    s = s.strip(".- ")
    return s[:80] or "untitled"


def _submit(args):
    title = str(args.get("title", "")).strip()
    content = args.get("content")
    if not title:
        return {"ok": False, "error": "empty_title", "hint": "title is required"}
    if not isinstance(content, str) or not content.strip():
        return {"ok": False, "error": "empty_content", "hint": "content is required"}
    raw = content.encode("utf-8")
    if len(raw) > MAX_WRITE_BYTES:
        return {"ok": False, "error": "too_large",
                "hint": f"{len(raw)} bytes exceeds the {MAX_WRITE_BYTES} byte limit"}

    stem = _safe_stem(str(args.get("filename") or title))
    INBOX_DIR.mkdir(parents=True, exist_ok=True)
    target = (INBOX_DIR / f"{stem}.md").resolve()

    # Defence in depth: the sanitised stem cannot contain a separator, so this can only
    # fail if the logic above is ever broken — keep the assertion anyway.
    if target.parent != INBOX_DIR:
        return {"ok": False, "error": "path_not_allowed", "hint": "writes are scoped to the inbox"}

    renamed = False
    if target.exists():  # never overwrite: keep the original, suffix a timestamp
        stamp = datetime.now(timezone.utc).astimezone().strftime("%Y%m%d-%H%M%S")
        target = (INBOX_DIR / f"{stem}-{stamp}.md").resolve()
        renamed = True

    tags = ", ".join(t.strip() for t in str(args.get("tags", "")).split(",") if t.strip())
    safe_title = title.replace('"', "'")
    created = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d")
    text = (
        "---\n"
        f'id: {stem}\n'
        f'title: "{safe_title}"\n'
        f'tags: [{tags}]\n'
        "source: mcp\n"
        f'created: "{created}"\n'
        "status: raw\n"
        "---\n\n"
        f"{content.strip()}\n"
    )
    target.write_text(text, encoding="utf-8")
    invalidate_cache()
    return {"ok": True, "id": stem, "title": title, "path": f"{INBOX_DIRNAME}/{target.name}",
            "bytes": len(text.encode("utf-8")), "renamed": renamed}


def _tools():
    tools = [
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
    if WRITE_MODE == "inbox":
        tools.append({
            "name": "submit_doc",
            "description": (f"Submit a markdown document into the '{INBOX_DIRNAME}' folder of "
                            "the knowledge base, for later review. This is the only write "
                            "path and it cannot target any other folder."),
            "inputSchema": {"type": "object", "properties": {
                "title": {"type": "string", "description": "document title (required)"},
                "content": {"type": "string", "description": "markdown body (required)"},
                "tags": {"type": "string", "description": "comma-separated tags"},
                "filename": {"type": "string",
                             "description": "optional filename stem (no extension)"}},
                "required": ["title", "content"]},
        })
    return tools


def _call_tool(name, args):
    if name == "search_kb":
        res = _search(str(args.get("query", "")), int(args.get("limit", 5) or 5))
        text = "\n\n".join(f"## {h['title']}\n{h['path']}\n{h['snippet']}" for h in res) or "no match"
        return [{"type": "text", "text": text}]
    if name == "get_doc":
        rel = str(args.get("path", "")).lstrip("/")
        target = (KB_DIR / rel).resolve()
        # Path containment: is_relative_to() (not a string prefix test, which would let
        # a sibling directory like /kb-evil through when KB_DIR is /kb).
        if not target.is_relative_to(KB_DIR) or not target.is_file():
            return [{"type": "text", "text": "not found"}]
        return [{"type": "text", "text": target.read_text(encoding="utf-8", errors="replace")}]
    if name == "submit_doc" and WRITE_MODE == "inbox":
        return [{"type": "text", "text": json.dumps(_submit(args), ensure_ascii=False)}]
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
    if not _host_ok(request):
        return JSONResponse({"error": "invalid_host"}, status_code=421)
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
    docs = _docs()
    return JSONResponse({
        "ok": True,
        "docs": len(docs),
        "name": NAME,
        "kb_dir": str(KB_DIR),
        "write_mode": WRITE_MODE,
        "inbox": INBOX_DIRNAME if WRITE_MODE == "inbox" else None,
        "inbox_docs": sum(1 for d in docs if d["rel"].startswith(f"{INBOX_DIRNAME}/")),
        "excluded_globs": EXCLUDE_GLOBS,
    })


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
