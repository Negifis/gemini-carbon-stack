#!/usr/bin/env python3
"""Fast native code & symbol search with automatic Jev / ripgrep / git-grep / AST fallback."""

from __future__ import annotations

import argparse
import ast
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
from typing import Any

HOOKS_DIR = pathlib.Path(__file__).resolve().parent.parent / "hooks"
sys.path.insert(0, str(HOOKS_DIR))
import runtime_io as rio

SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
        "target",
        ".next",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
    }
)

POLYGLOT_SYMBOL_RE = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?"
    r"(?P<kind>function|class|interface|type|enum|struct|trait|impl|fn|func|def)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
)


def find_jev() -> str | None:
    return shutil.which("jev") or shutil.which("jev.exe") or shutil.which("jev.cmd")


def find_rg() -> str | None:
    on_path = shutil.which("rg") or shutil.which("rg.exe")
    if on_path:
        return on_path
    return None


def iter_source_files(root: str, glob_ext: str = "") -> list[pathlib.Path]:
    exts = {e.strip().lower() for e in glob_ext.split(",") if e.strip()} if glob_ext else set()
    found: list[pathlib.Path] = []
    stack = [os.path.abspath(root)]
    while stack and len(found) < 5000:
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                if entry.name not in SKIP_DIRS:
                    stack.append(entry.path)
            elif entry.is_file(follow_symlinks=False):
                p = pathlib.Path(entry.path)
                if exts and p.suffix.lower() not in exts:
                    continue
                found.append(p)
    return found


def text_search(pattern: str, cwd: str, limit: int = 60, fixed: bool = False, ext: str = "") -> dict[str, Any]:
    root = os.path.abspath(cwd or os.getcwd())
    jev_bin = find_jev()
    rg_bin = find_rg()

    # 1. Use ripgrep if available
    if rg_bin:
        cmd = [rg_bin, "--line-number", "--no-heading", "--color=never", "--max-count", str(limit)]
        if fixed:
            cmd.append("--fixed-strings")
        if ext:
            for e in ext.split(","):
                e = e.strip().lstrip(".")
                if e:
                    cmd.extend(["-g", f"*.{e}"])
        cmd.extend([pattern, root])
        proc = subprocess.run(cmd, timeout=10.0, **rio.subprocess_kwargs())
        out = (proc.stdout or b"").decode("utf-8", errors="replace")
        lines = [ln for ln in out.splitlines() if ln.strip()][:limit]
        return {"engine": "ripgrep", "jev_available": bool(jev_bin), "count": len(lines), "matches": lines}

    # 2. Use `git grep` inside git repositories (fast native C implementation in Git for Windows)
    git_root = rio.git_toplevel(root)
    if git_root:
        args = ["grep", "-n", "-I", "--no-color"]
        args.append("-F" if fixed else "-E")
        args.append(pattern)
        if ext:
            args.append("--")
            for e in ext.split(","):
                e = e.strip().lstrip(".")
                if e:
                    args.append(f"*.{e}")
        rc, out, _ = rio.run_git(root, args, timeout=8.0)
        if rc in (0, 1) and isinstance(out, str):
            lines = [ln for ln in out.splitlines() if ln.strip()][:limit]
            return {"engine": "git-grep", "jev_available": bool(jev_bin), "count": len(lines), "matches": lines}

    # 3. Pure-Python UTF-8 fallback outside git repos
    rx = re.compile(re.escape(pattern) if fixed else pattern, re.IGNORECASE)
    matches: list[str] = []
    for fpath in iter_source_files(root, glob_ext=ext):
        try:
            if fpath.stat().st_size > 1_500_000:
                continue
            for idx, ln in enumerate(fpath.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if rx.search(ln):
                    rel = os.path.relpath(str(fpath), root).replace("\\", "/")
                    matches.append(f"{rel}:{idx}:{ln.strip()[:200]}")
                    if len(matches) >= limit:
                        return {
                            "engine": "python-scan",
                            "jev_available": bool(jev_bin),
                            "count": len(matches),
                            "matches": matches,
                        }
        except OSError:
            continue
    return {"engine": "python-scan", "jev_available": bool(jev_bin), "count": len(matches), "matches": matches}


def symbol_search(query: str, cwd: str, limit: int = 50) -> dict[str, Any]:
    root = os.path.abspath(cwd or os.getcwd())
    q_low = (query or "").strip().lower()
    hits: list[dict[str, Any]] = []

    for fpath in iter_source_files(root, glob_ext=".py,.ts,.tsx,.js,.jsx,.mjs,.go,.rs"):
        rel = os.path.relpath(str(fpath), root).replace("\\", "/")
        suffix = fpath.suffix.lower()
        try:
            if fpath.stat().st_size > 1_000_000:
                continue
            src = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if suffix == ".py":
            try:
                tree = ast.parse(src)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        if not q_low or q_low in node.name.lower():
                            hits.append(
                                {
                                    "kind": "class" if isinstance(node, ast.ClassDef) else "def",
                                    "name": node.name,
                                    "file": rel,
                                    "start_line": node.lineno,
                                    "end_line": getattr(node, "end_lineno", node.lineno),
                                }
                            )
                            if len(hits) >= limit:
                                return {"count": len(hits), "symbols": hits}
                continue
            except SyntaxError:
                pass

        if suffix in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".go", ".rs", ".py"):
            for idx, ln in enumerate(src.splitlines(), 1):
                m = POLYGLOT_SYMBOL_RE.match(ln)
                if m:
                    sname = m.group("name")
                    if not q_low or q_low in sname.lower():
                        hits.append(
                            {
                                "kind": m.group("kind"),
                                "name": sname,
                                "file": rel,
                                "start_line": idx,
                            }
                        )
                        if len(hits) >= limit:
                            return {"count": len(hits), "symbols": hits}

    return {"count": len(hits), "symbols": hits}


def main() -> int:
    parser = argparse.ArgumentParser(prog="code_search")
    sub = parser.add_subparsers(dest="cmd", required=True)

    srch = sub.add_parser("grep", help="Fast repository text/regex search (rg -> git grep -> python fallback)")
    srch.add_argument("pattern")
    srch.add_argument("--cwd", default="")
    srch.add_argument("--fixed", action="store_true")
    srch.add_argument("--ext", default="", help="Comma-separated extensions, e.g. .py,.ts")
    srch.add_argument("--limit", type=int, default=60)

    sym = sub.add_parser("symbols", help="Locate AST / structural symbol definitions with exact line ranges")
    sym.add_argument("query", nargs="?", default="")
    sym.add_argument("--cwd", default="")
    sym.add_argument("--limit", type=int, default=50)

    sub.add_parser("engines", help="Report available search engines (Jev, ripgrep, git-grep)")

    args = parser.parse_args()
    if args.cmd == "grep":
        print(
            json.dumps(
                text_search(args.pattern, cwd=args.cwd, limit=args.limit, fixed=args.fixed, ext=args.ext),
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    if args.cmd == "symbols":
        print(json.dumps(symbol_search(args.query, cwd=args.cwd, limit=args.limit), ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "engines":
        print(
            json.dumps(
                {
                    "jev": find_jev(),
                    "ripgrep": find_rg(),
                    "git": shutil.which("git"),
                    "python_ast": True,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
