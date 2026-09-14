#!/usr/bin/env python3
"""End-to-end selftest: inbox write scoping + index cache + credential exclusion.

    scripts/selftest_inbox.py [path/to/mcp_server.py]

Self-contained — it builds a throwaway knowledge base, starts the server on a spare port
with KB_WRITE_MODE=inbox, drives it over plain HTTP JSON-RPC (stdlib only), asserts, then
kills the server and deletes the tree. No mcp SDK required.

What it proves
  1. submit_doc is exposed only in inbox mode, and lands only inside KB_INBOX_DIR
  2. four traversal-shaped filenames cannot escape that folder
  3. nothing is written outside the inbox (checked on disk, not just in the response)
  4. get_doc is confined to KB_DIR — including the sibling-prefix trap (/kb vs /kb-evil),
     which a naive str.startswith() containment check lets through
  5. credential-shaped documents are absent from the index even though they exist on disk
  6. a write is visible to the next search (cache invalidation)
  7. the index cache keeps repeat searches off the disk
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SERVER = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "mcp_server.py"
TOKEN = "selftest-token-0000"
INBOX = "inbox"

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -> {detail}" if detail else ""))
    return ok


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Server:
    """Throwaway KB tree + server process."""

    def __init__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="kb-selftest-"))
        self.kb = self.tmp / "kb"
        self.evil = self.tmp / "kb-evil"          # sibling with a KB_DIR-name prefix
        self.kb.mkdir()
        self.evil.mkdir()
        (self.kb / "inbox").mkdir()

        (self.kb / "deploy-notes.md").write_text(
            "---\ntitle: Deploy Notes\ntags: ops\n---\n\n# Deploy\n\nrun the deploy script\n",
            encoding="utf-8")
        (self.kb / "sub").mkdir()
        (self.kb / "sub" / "deep.md").write_text("# Deep\n\nburied content\n", encoding="utf-8")
        # must never appear in search results
        (self.kb / "google-recovery-codes.md").write_text(
            "# 2FA recovery codes\n\nSECRETCODE-AAAA\n", encoding="utf-8")
        # must never be readable via get_doc
        (self.evil / "secret.md").write_text("TOP-SECRET-SIBLING\n", encoding="utf-8")

        self.port = free_port()
        self.url = f"http://127.0.0.1:{self.port}/mcp"
        env = dict(os.environ)
        env.update({
            "MCP_TOKEN": TOKEN,
            "KB_DIR": str(self.kb),
            "KB_WRITE_MODE": "inbox",
            "KB_INBOX_DIR": INBOX,
            "MCP_PATH": "/mcp",
            "MCP_ALLOWED_HOSTS": "",
            "KB_CACHE_TTL": "3",
            "PORT": str(self.port),            # mcp_server.py reads HOST/PORT in __main__
            "HOST": "127.0.0.1",
        })
        env.pop("MCP_PUBLIC_BASE", None)      # no OAuth shim in the selftest
        env.pop("MCP_SHARE_SLUG", None)
        self.proc = subprocess.Popen([sys.executable, str(SERVER)], env=env, cwd=str(SERVER.parent),
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self._wait_ready()

    def _wait_ready(self, timeout=20):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                out = self.proc.stdout.read() if self.proc.stdout else ""
                raise RuntimeError(f"server exited early:\n{out}")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health", timeout=2):
                    return
            except Exception:
                time.sleep(0.25)
        raise RuntimeError("server did not become ready")

    def rpc(self, method, params=None):
        body = {"jsonrpc": "2.0", "id": 1, "method": method}
        if params is not None:
            body["params"] = params
        req = urllib.request.Request(
            self.url, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "Accept": "application/json",
                     "Authorization": f"Bearer {TOKEN}"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())

    def call(self, tool, args):
        res = self.rpc("tools/call", {"name": tool, "arguments": args})
        return res.get("result", {}).get("content", [{}])[0].get("text", "")

    def health(self):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health", timeout=10) as r:
            return json.loads(r.read())

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        shutil.rmtree(self.tmp, ignore_errors=True)


def main():
    srv = Server()
    try:
        # 1) write tool is exposed in inbox mode
        tools = [t["name"] for t in srv.rpc("tools/list")["result"]["tools"]]
        check("tools/list exposes submit_doc in inbox mode",
              "submit_doc" in tools and "search_kb" in tools and "get_doc" in tools, str(tools))
        h = srv.health()
        check("health reports write_mode=inbox", h.get("write_mode") == "inbox", str(h.get("write_mode")))

        # 2) search + get_doc basics
        out = srv.call("search_kb", {"query": "deploy", "limit": 5})
        check("search_kb finds a real document", "Deploy Notes" in out, out.splitlines()[0] if out else "")
        doc = srv.call("get_doc", {"path": "deploy-notes.md"})
        check("get_doc returns the document", "run the deploy script" in doc)

        # 3) containment: sibling directory sharing KB_DIR's name prefix
        leak = srv.call("get_doc", {"path": f"../{srv.evil.name}/secret.md"})
        check("get_doc blocked: sibling-prefix trap (../kb-evil/secret.md)",
              "TOP-SECRET-SIBLING" not in leak, f"got {leak!r}")
        leak2 = srv.call("get_doc", {"path": "../../../../etc/passwd"})
        check("get_doc blocked: absolute-ish traversal", "root:" not in leak2, f"got {leak2!r}")

        # 4) credential-shaped file exists on disk but is not indexed
        check("control: credential file really is on disk",
              (srv.kb / "google-recovery-codes.md").exists())
        hits = srv.call("search_kb", {"query": "recovery", "limit": 10})
        check("credential-shaped file excluded from the index",
              "SECRETCODE" not in hits and "recovery-codes" not in hits)

        # 5) inbox write, happy path
        res = json.loads(srv.call("submit_doc", {"title": "Selftest Note",
                                                "content": "written by the selftest",
                                                "tags": "test"}))
        target = srv.kb / INBOX / "Selftest-Note.md"
        check("submit_doc writes into the inbox", res.get("ok") is True and target.exists(),
              str(res.get("path")))
        check("written frontmatter is well-formed",
              target.exists() and all(k in target.read_text(encoding="utf-8")
                                      for k in ('title: "Selftest Note"', "status: raw")))

        # 6) four traversal-shaped filenames
        attacks = [("../../../../tmp/pwned", "relative traversal"),
                   ("/etc/cron.d/pwned", "absolute path"),
                   ("..%2f..%2fescape", "encoded slashes"),
                   ("....//....//deep-escape", "dot-slash soup")]
        for fname, label in attacks:
            res = json.loads(srv.call("submit_doc", {"title": f"attack {label}",
                                                    "content": "x", "filename": fname}))
            rel = res.get("path", "")
            on_disk = (srv.kb / INBOX / Path(rel).name).exists() if rel else False
            check(f"write contained ({label})", res.get("ok") is True and rel.startswith(f"{INBOX}/")
                  and on_disk, f"{fname!r} -> {rel!r}")

        # 7) nothing escaped to the filesystem
        outside = list(Path("/tmp").glob("pwned*")) + list(Path("/etc/cron.d").glob("pwned*"))
        check("no file landed outside the inbox", not outside, str(outside))

        # 8) writes are visible to the next search (cache invalidation)
        out = srv.call("search_kb", {"query": "selftest", "limit": 5})
        check("write is searchable immediately (cache invalidated)", f"{INBOX}/" in out)

        # 9) limits
        res = json.loads(srv.call("submit_doc", {"title": "big", "content": "x" * (600 * 1024)}))
        check("oversized body rejected", res.get("ok") is False and res.get("error") == "too_large",
              str(res.get("error")))
        res = json.loads(srv.call("submit_doc", {"title": "empty", "content": "  "}))
        check("empty body rejected", res.get("ok") is False, str(res.get("error")))

        # 10) index cache keeps repeat searches cheap
        t0 = time.perf_counter(); srv.call("search_kb", {"query": "deploy"}); first = time.perf_counter() - t0
        t0 = time.perf_counter(); srv.call("search_kb", {"query": "deploy"}); hot = time.perf_counter() - t0
        time.sleep(4)
        t0 = time.perf_counter(); srv.call("search_kb", {"query": "deploy"}); rescan = time.perf_counter() - t0
        check("index cache serves repeat searches without re-reading files",
              hot < 0.02 and rescan < 0.3,
              f"first {first*1000:.0f}ms / hot {hot*1000:.1f}ms / after-TTL rescan {rescan*1000:.0f}ms")
    finally:
        srv.close()

    failed = [n for n, ok in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} passed")
    if failed:
        print("failed: " + "; ".join(failed))
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
