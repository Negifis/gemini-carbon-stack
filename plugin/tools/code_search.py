#!/usr/bin/env python3
"""Fast native code & symbol search with automatic Jev / ripgrep / git-grep / AST fallback."""

from __future__ import annotations

import argparse
import ast
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


DEFAULT_WINDOWS_RG_PATH = (
    "C:/tools/ripgrep-15.1.0-x86_64-pc-windows-msvc/ripgrep-15.1.0-x86_64-pc-windows-msvc/rg.exe"
)
_RG_CACHE: str | None | bool = False


def find_rg() -> str | None:
    env_rg = os.environ.get("CARBON_RG_BIN", "").strip()
    if env_rg and os.path.isfile(env_rg):
        return env_rg
    global _RG_CACHE
    if _RG_CACHE is not False:
        return _RG_CACHE  # type: ignore[return-value]
    on_path = shutil.which("rg")
    if on_path:
        _RG_CACHE = on_path
        return on_path
    if os.name == "nt":
        # INVARIANT: Probe fixed off-PATH Windows paths first before bounded `C:/tools/ripgrep*` fallback globs.
        home = pathlib.Path.home()
        local_app = os.environ.get("LOCALAPPDATA", "").strip()
        fixed_candidates: list[pathlib.Path] = [
            pathlib.Path(DEFAULT_WINDOWS_RG_PATH),
            home / "scoop" / "shims" / "rg.exe",
            home / ".cargo" / "bin" / "rg.exe",
            pathlib.Path("C:/Program Files/ripgrep/rg.exe"),
        ]
        if local_app:
            fixed_candidates.append(pathlib.Path(local_app) / "Microsoft" / "WinGet" / "Links" / "rg.exe")
        for cand in fixed_candidates:
            if cand.is_file():
                _RG_CACHE = str(cand)
                return _RG_CACHE
        tools_root = pathlib.Path("C:/tools")
        if tools_root.is_dir():
            try:
                for pat in ("ripgrep*/rg.exe", "ripgrep*/*/rg.exe"):
                    for cand in sorted(tools_root.glob(pat), reverse=True):
                        if cand.is_file():
                            _RG_CACHE = str(cand)
                            return _RG_CACHE
            except OSError:
                pass
    _RG_CACHE = None
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
    srch.add_argument("--pretty", action="store_true")

    sym = sub.add_parser("symbols", help="Locate AST / structural symbol definitions with exact line ranges")
    sym.add_argument("query", nargs="?", default="")
    sym.add_argument("--cwd", default="")
    sym.add_argument("--limit", type=int, default=50)
    sym.add_argument("--pretty", action="store_true")

    eng = sub.add_parser("engines", help="Report available search engines (Jev, ripgrep, git-grep)")
    eng.add_argument("--pretty", action="store_true")

    args = parser.parse_args()
    if args.cmd == "grep":
        rio.print_cli_json(
            text_search(args.pattern, cwd=args.cwd, limit=args.limit, fixed=args.fixed, ext=args.ext),
            pretty=args.pretty,
        )
        return 0
    if args.cmd == "symbols":
        rio.print_cli_json(symbol_search(args.query, cwd=args.cwd, limit=args.limit), pretty=args.pretty)
        return 0
    if args.cmd == "engines":
        rio.print_cli_json(
            {
                "jev": find_jev(),
                "ripgrep": find_rg(),
                "git": shutil.which("git"),
                "python_ast": True,
            },
            pretty=args.pretty,
        )
        return 0
    return 0


if __name__ == "__main__":
    rio.maybe_exec_rust_cli("code-search")
    sys.exit(main())
