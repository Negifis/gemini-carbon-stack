#!/usr/bin/env python3
"""Windows-safe Antigravity PreToolUse bridge for Tokenade CLI."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys

# INVARIANT: Keep top-level imports minimal (`json`, `os`, `re`, `subprocess`, `sys` — no `runtime_io`/`pathlib`/`typing`/`shutil`)
# so this hot `PreToolUse` hook stays <3 ms on bypassed commands.
_LEADING_CD_LINE_RE = re.compile(
    r"^(?P<cd>\s*(?:Set-Location|Push-Location|cd(?:\s+/d)?)\s+"
    r"(?:\"[^\"\r\n]+\"|'[^'\r\n]+'|[^\s|;&$\r\n]+)\s*\r?\n)(?P<rest>[\s\S]+)$",
    re.IGNORECASE,
)
_BYPASS_TOKENS = (
    "tokenade",
    "codex_lane.py",
    "gate_inbox.py",
    "cwg_stop.py",
    "cwg_mark.py",
    "cwg_pre_invocation.py",
    "swarm_cache.py",
    "swarm_ctl.py",
    "continuity.py",
    "worktree_guard.py",
    "stack_doctor.py",
    "install.py",
    "chat-bus",
    "chat_bus_cli.py",
)
_DISABLED_VALUES = frozenset({"0", "false", "off", "no"})


def is_auto_wrap_enabled() -> bool:
    return os.environ.get("TOKENADE_AUTO_WRAP", "1").strip().lower() not in _DISABLED_VALUES


def _allow(rewritten_cmd: str | None = None) -> int:
    if rewritten_cmd:
        sys.stdout.write(
            json.dumps({"decision": "allow", "overwrite": {"CommandLine": rewritten_cmd}}, ensure_ascii=False)
            + "\n"
        )
    else:
        sys.stdout.write('{"decision":"allow"}\n')
    return 0


def find_tokenade_bin() -> str | None:
    env_bin = os.environ.get("CARBON_TOKENADE_BIN", "").strip()
    if env_bin and os.path.isfile(env_bin):
        return env_bin
    if os.name == "nt":
        appdata = os.environ.get("APPDATA", "").strip()
        if appdata:
            # INVARIANT: Prefer the compiled Rust `tokenade.exe` binary (~3 ms) over `tokenade.cmd` (~120 ms cmd+node shim).
            native_exe = os.path.join(
                appdata,
                "npm",
                "node_modules",
                "@tokenade",
                "cli",
                "node_modules",
                "@tokenade",
                "cli-win32-x64",
                "tokenade.exe",
            )
            if os.path.isfile(native_exe):
                return native_exe
    import shutil

    return (shutil.which("tokenade.exe") if os.name == "nt" else None) or shutil.which("tokenade")


def _extract_antigravity_command(payload: dict[str, object]) -> str:
    tc = payload.get("toolCall")
    if isinstance(tc, dict):
        for key in ("args", "arguments"):
            sub = tc.get(key)
            if isinstance(sub, dict) and isinstance(sub.get("CommandLine"), str):
                return sub["CommandLine"]
    for top_key in ("toolArgs", "tool_input"):
        sub = payload.get(top_key)
        if isinstance(sub, dict):
            if isinstance(sub.get("CommandLine"), str):
                return sub["CommandLine"]
            if isinstance(sub.get("command"), str):
                return sub["command"]
    return ""


def _should_bypass(cmd: str) -> bool:
    low = cmd.lower()
    return any(tok in low for tok in _BYPASS_TOKENS)


def transform_pretool_payload(payload: dict[str, object]) -> str | None:
    # SAFETY: Enabled by default unless `TOKENADE_AUTO_WRAP` is in `_DISABLED_VALUES` (`0`/`false`/`off`/`no`);
    # leaves multi-statement scripts and protocol CLIs untouched.
    if not is_auto_wrap_enabled():
        return None

    raw_cmd = _extract_antigravity_command(payload)
    if not raw_cmd.strip() or _should_bypass(raw_cmd):
        return None

    prefix_cd = ""
    core_cmd = raw_cmd
    if "\n" in raw_cmd:
        m_cd = _LEADING_CD_LINE_RE.match(raw_cmd)
        if m_cd:
            prefix_cd = m_cd.group("cd")
            core_cmd = m_cd.group("rest")

    stripped_core = core_cmd.strip()
    if not stripped_core or "\n" in stripped_core or "\r" in stripped_core:
        return None
    if os.name == "nt" and ('"' in stripped_core or "`" in stripped_core or stripped_core.endswith("\\")):
        # SAFETY: Windows PowerShell 5.1 (`PSNativeCommandArgumentPassing=Legacy`) strips unescaped `"` and misquotes trailing `\`
        # when passing arguments to native `.exe` binaries (`tokenade.exe`), which can turn quoted string literals into commands.
        return None

    tk_bin = find_tokenade_bin()
    if not tk_bin:
        return None

    bridge_tool = "PowerShell" if os.name == "nt" else "Bash"
    bridge_in = json.dumps(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": bridge_tool,
            "tool_input": {"command": stripped_core},
        },
        ensure_ascii=False,
    ).encode("utf-8")

    run_kw: dict[str, object] = {"input": bridge_in, "capture_output": True, "timeout": 4.0}
    if os.name == "nt":
        run_kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

    try:
        proc = subprocess.run([tk_bin, "hookwrap-pretool"], **run_kw)  # type: ignore[arg-type]
        if proc.returncode != 0 or not proc.stdout or not proc.stdout.strip():
            return None
        out = json.loads(proc.stdout.decode("utf-8", errors="replace"))
    except Exception:
        return None

    if not isinstance(out, dict):
        return None

    wrapped = ""
    hso = out.get("hookSpecificOutput")
    if isinstance(hso, dict):
        upd = hso.get("updatedInput")
        if isinstance(upd, dict) and isinstance(upd.get("command"), str):
            wrapped = upd["command"].strip()
    if not wrapped:
        ov = out.get("overwrite")
        if isinstance(ov, dict) and isinstance(ov.get("CommandLine"), str):
            wrapped = ov["CommandLine"].strip()

    if not wrapped or wrapped == stripped_core:
        return None

    if os.name == "nt" and wrapped[0] in ('"', "'"):
        wrapped = f"& {wrapped}"

    return f"{prefix_cd}{wrapped}" if prefix_cd else wrapped


def main() -> int:
    if not is_auto_wrap_enabled():
        return _allow()
    raw = sys.stdin.buffer.read()
    if not raw.strip():
        return _allow()
    try:
        payload = json.loads(raw.decode("utf-8-sig", errors="replace"))
    except Exception:
        return _allow()
    if not isinstance(payload, dict):
        return _allow()
    return _allow(transform_pretool_payload(payload))


if __name__ == "__main__":
    import pathlib as _pathlib

    sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parent))
    import runtime_io as _rio

    _rio.maybe_exec_rust_cli("tokenade-hook")
    raise SystemExit(main())
