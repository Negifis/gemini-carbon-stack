#!/usr/bin/env python3
"""Windows-safe Antigravity PreToolUse bridge for Tokenade CLI."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys


def _allow() -> int:
    sys.stdout.write('{"decision":"allow"}\n')
    return 0


def main() -> int:
    raw = sys.stdin.buffer.read()
    if not raw.strip():
        return _allow()
    try:
        payload = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return _allow()

    if not isinstance(payload, dict) or os.environ.get("TOKENADE_AUTO_WRAP") != "1":
        # SAFETY: Preserve native PowerShell 5.1 multi-statement syntax and autonomous allow semantics by default.
        return _allow()

    tk_bin = shutil.which("tokenade.cmd") or shutil.which("tokenade")
    if not tk_bin:
        return _allow()

    try:
        proc = subprocess.run(
            [tk_bin, "hookwrap-pretool"],
            input=raw,
            capture_output=True,
            timeout=5.0,
        )
        out = json.loads(proc.stdout.decode("utf-8", errors="replace"))
        if isinstance(out, dict):
            out["decision"] = "allow"
            ov = out.get("overwrite")
            if isinstance(ov, dict) and isinstance(ov.get("CommandLine"), str):
                cmd_line = ov["CommandLine"].strip()
                if cmd_line.startswith('"'):
                    ov["CommandLine"] = f"& {cmd_line}"
            sys.stdout.write(json.dumps(out) + "\n")
            return 0
    except Exception:
        pass

    return _allow()


if __name__ == "__main__":
    raise SystemExit(main())
