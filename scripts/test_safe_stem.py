#!/usr/bin/env python3
"""Unit test for mcp_server._safe_stem, extracted from the real source via AST.

    scripts/test_safe_stem.py [path/to/mcp_server.py]

Checks the aggressive cases (traversal, separators, control chars, length) and asserts the
hard invariant holds for every input: no '/', no '\\\\', no '..', not '.'/'..', non-empty,
≤ 80 chars. Exits non-zero on any failure, so it is safe to use in CI.
"""
import ast
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE.parent / "mcp_server.py"

tree = ast.parse(SRC.read_text(encoding="utf-8"))
wanted = {"_UNSAFE", "_safe_stem"}
ns: dict = {"re": re}
for node in tree.body:
    if isinstance(node, ast.Assign) and any(
        isinstance(t, ast.Name) and t.id in wanted for t in node.targets
    ):
        exec(compile(ast.Module([node], []), "<x>", "exec"), ns)
    if isinstance(node, ast.FunctionDef) and node.name in wanted:
        exec(compile(ast.Module([node], []), "<x>", "exec"), ns)

_safe_stem = ns["_safe_stem"]

CASES = [
    ("../../etc/passwd", "etc-passwd"),
    ("/etc/passwd", "etc-passwd"),
    ("..\\..\\windows\\system32", "windows-system32"),
    ("....//....//x", "x"),
    ("a/b/c", "a-b-c"),
    (".", "untitled"),
    ("..", "untitled"),
    ("", "untitled"),
    ("   ", "untitled"),
    ("\x00\x01evil", "evil"),
    ("...", "untitled"),
    ("normal-note", "normal-note"),
    ("notes/2026/report", "notes-2026-report"),
    ("日本語のタイトル", "日本語のタイトル"),
    ("title: with*weird?chars", "title-with-weird-chars"),
    ("../../../../tmp/pwned", "tmp-pwned"),
    ("note\x01\x02.md", "note.md"),
    ("A" * 200, "A" * 80),
]

fails = 0
for raw, expect in CASES:
    got = _safe_stem(raw)
    invariant = (
        "/" not in got
        and "\\" not in got
        and ".." not in got
        and got not in (".", "..")
        and 0 < len(got) <= 80
    )
    ok = got == expect and invariant
    fails += 0 if ok else 1
    print(f"[{'PASS' if ok else 'FAIL'}] {raw!r:38s} -> {got!r:26s}"
          f"{'' if got == expect else '  expected ' + repr(expect)}"
          f"{'' if invariant else '  INVARIANT BROKEN'}")

print(f"\n{len(CASES) - fails}/{len(CASES)} passed")
sys.exit(1 if fails else 0)
