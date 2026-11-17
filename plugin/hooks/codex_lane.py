#!/usr/bin/env python3
"""External Codex CLI independent review lane: health check, circuit breaker, runner, and rollout provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time
import uuid
from typing import Any, NamedTuple

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cwg_common as cwg
import runtime_io as rio

BREAKER_TTL_SECONDS = 1800  # 30 minutes cooldown after quota/auth/capacity outage
DEFAULT_REVIEW_TIMEOUT_SECONDS = 600
DEFAULT_XHIGH_REVIEW_TIMEOUT_SECONDS = 900
TIMEOUT_STEP_SECONDS = 300
MAX_REVIEW_TIMEOUT_SECONDS = 1800
PACKET_TTL_SECONDS = 86400
MAX_DIFF_SNAPSHOT_CHARS = 160_000
_LAST_TIMEOUT_OUTAGE: dict[str, tuple[str, str]] = {}
_LAST_ROLLOUT_TURN_SID: dict[str, str] = {}


class _CodexExecResult(NamedTuple):
    rc: int
    stdout: str
    stderr: str
    has_verdict: bool
    outage: str | None
    network_outage: str | None = None
    sandbox_blocked: str | None = None
    thread_id: str = ""

OUTAGE_PATTERNS = tuple(
    re.compile(pat, re.IGNORECASE)
    for pat in (
        r"(?:hit|reached|exceeded)[^\n]{0,40}usage limit",
        r"usage limit[^\n]{0,30}(?:reached|exceeded|reset)",
        r"rate[ _-]limit[ _-]exceeded",
        r"exceeded[^\n]{0,30}rate limit",
        r"quota exceeded",
        r"insufficient_quota",
        r"model is at capacity",
        r"not logged in",
        r"authentication failed",
        r"401 unauthorized",
        r"429 too many requests",
        r"connection refused",
        r"timed out waiting for model",
        r"workspace routing discovery failed",
    )
)

_RID_TOKEN_PAT = r"[A-Za-z0-9_-]{6,64}"
REVIEW_ID_RE = re.compile(rf"REVIEW_ID\s*:\s*({_RID_TOKEN_PAT})")
_ABORTED_RID_RE = re.compile(rf"^{_RID_TOKEN_PAT}$")


def strip_task_envelope_tail(blob: str) -> str:
    # INVARIANT: Strip trailing `<SYSTEM_MESSAGE>` / `Log: file:///...` lines via O(1) rpartition with zero regex backtracking.
    text = (blob or "").strip()
    if not text:
        return ""
    head, sep, last = text.rpartition("\n")
    if last.strip().lower() == "</system_message>":
        text = head.strip() if sep else ""
    if text:
        head, sep, last = text.rpartition("\n")
        tail_low = last.strip().lower()
        if tail_low.startswith("log:") and tail_low[4:].lstrip().startswith("file:///"):
            text = head.strip() if sep else ""
    return text


def _fallback_reviewer(xhigh: bool) -> str:
    return cwg.XHIGH_NATIVE_REVIEWER if xhigh else "adversarial-reviewer"


def next_timeout_after(timeout_sec: float | int) -> int:
    return min(
        MAX_REVIEW_TIMEOUT_SECONDS,
        max(int(timeout_sec) + TIMEOUT_STEP_SECONDS, DEFAULT_XHIGH_REVIEW_TIMEOUT_SECONDS),
    )


def required_review_timeout(xhigh: bool, saved_next_sec: float | int = 0) -> int:
    base = DEFAULT_XHIGH_REVIEW_TIMEOUT_SECONDS if xhigh else DEFAULT_REVIEW_TIMEOUT_SECONDS
    return min(MAX_REVIEW_TIMEOUT_SECONDS, max(base, int(saved_next_sec or 0)))


def breaker_path() -> pathlib.Path:
    return cwg.gate_dir() / "codex_lane.json"


def packets_dir() -> pathlib.Path:
    return cwg.gate_dir("packets")


def threads_dir() -> pathlib.Path:
    return cwg.gate_dir("threads")


def codex_sessions_dir() -> pathlib.Path:
    override = os.environ.get("CARBON_CODEX_SESSIONS_DIR")
    if override:
        return pathlib.Path(override)
    return pathlib.Path.home() / ".codex" / "sessions"


def find_codex_binary() -> str | None:
    override = os.environ.get("CARBON_CODEX_BIN")
    if override:
        return override if (os.path.isfile(override) or shutil.which(override)) else None
    for name in ("codex.cmd", "codex.exe", "codex"):
        found = shutil.which(name)
        if found:
            return found
    return None


def breaker_status() -> dict[str, Any]:
    data = rio.read_json(breaker_path(), default={})
    if not isinstance(data, dict):
        return {"tripped": False}
    until = float(data.get("tripped_until") or 0.0)
    now = time.time()
    if until > now:
        return {
            "tripped": True,
            "reason": str(data.get("reason") or "codex_outage"),
            "remaining_seconds": int(until - now),
            "tripped_at": data.get("tripped_at"),
        }
    return {"tripped": False}


def trip_breaker(reason: str, ttl: int = BREAKER_TTL_SECONDS) -> None:
    now = time.time()
    rio.write_json(
        breaker_path(),
        {
            "tripped": True,
            "reason": reason[:300],
            "tripped_at": now,
            "tripped_until": now + ttl,
        },
    )
    rio.log_hook_event("gate-events", "codex_breaker_tripped", reason=reason[:200], ttl=ttl)


def reset_breaker() -> None:
    bp = breaker_path()
    if bp.exists():
        try:
            bp.unlink()
        except OSError:
            rio.write_json(bp, {"tripped": False})


def _infer_single_open_session(cwd: str) -> str:
    """Auto-bind to the active session when exactly one open candidate marker matches `cwd`'s git root."""
    target_root = rio.fold_path(rio.git_toplevel(cwd) or cwd)
    if not target_root:
        return ""
    root_prefix = target_root.rstrip("/") + "/"
    matched: list[str] = []
    for mf in rio.state_dir("gate", "markers").glob("*.json"):
        mdata = rio.read_json(mf, default=None)
        if not isinstance(mdata, dict) or mdata.get("closed"):
            continue
        sess = str(mdata.get("session") or "")
        if not sess:
            continue
        mroot = rio.fold_path(str(mdata.get("git_root") or mdata.get("cwd") or ""))
        path_match = mroot == target_root
        if not path_match:
            raw_paths = mdata.get("paths")
            touched_paths = raw_paths if isinstance(raw_paths, list) else []
            for touched in touched_paths:
                ftouched = rio.fold_path(str(touched))
                if ftouched == target_root or ftouched.startswith(root_prefix):
                    path_match = True
                    break
        if path_match and sess not in matched:
            matched.append(sess)
    return matched[0] if len(matched) == 1 else ""


def _candidate_first_ts(session: str) -> float:
    if not session:
        return 0.0
    mdata = rio.read_json(cwg.marker_path(session), default=None)
    if not isinstance(mdata, dict) or mdata.get("closed"):
        return 0.0
    return float(mdata.get("first_ts") or 0.0)


def _thread_state_path(session: str, git_root: str) -> pathlib.Path:
    raw_key = f"{session or 'nosession'}|{rio.fold_path(git_root)}"
    digest = hashlib.sha256(raw_key.encode("utf-8", errors="replace")).hexdigest()[:20]
    return threads_dir() / f"{digest}.json"


def active_thread_state(
    session: str,
    git_root: str,
    candidate_first_ts: float | None = None,
) -> dict[str, Any] | None:
    saved = rio.read_json(_thread_state_path(session, git_root), default=None)
    if not isinstance(saved, dict):
        return None
    cand_ts = _candidate_first_ts(session) if candidate_first_ts is None else float(candidate_first_ts)
    saved_cand_ts = float(saved.get("candidate_first_ts") or 0.0)
    # INVARIANT: Bind thread continuity & timeout escalation strictly to the active candidate (`1h` TTL when no marker is open).
    matched = (
        abs(saved_cand_ts - cand_ts) < 1.0
        if cand_ts > 0.0
        else (saved_cand_ts <= 0.0 and (time.time() - float(saved.get("updated_ts") or 0.0)) < 3600.0)
    )
    return saved if matched else None


def _clear_pending_timeout_resume(session: str, git_root: str) -> None:
    tpath = _thread_state_path(session, git_root)
    saved = rio.read_json(tpath, default=None)
    if not isinstance(saved, dict) or not saved.get("pending_timeout_resume"):
        return
    if saved.get("session_id"):
        saved["pending_timeout_resume"] = False
        saved.pop("next_timeout_seconds", None)
        saved["updated_ts"] = time.time()
        rio.write_json(tpath, saved)
    else:
        cwg.unlink_quiet(tpath)


def _packet_path(review_id: str) -> pathlib.Path:
    return packets_dir() / f"{rio.safe_key(review_id)}.json"


def record_packet(
    review_id: str,
    prompt_text: str,
    cwd: str,
    effort: str = "high",
    phase: str = "ordinary",
    session: str = "",
) -> dict[str, Any]:
    now = time.time()
    eff_session = session or _infer_single_open_session(cwd)
    digest = hashlib.sha256(prompt_text.encode("utf-8", errors="replace")).hexdigest()[:24]
    pkt = {
        "review_id": review_id,
        "prompt_sha256": digest,
        "cwd": rio.normalize_path(cwd),
        "effort": effort.lower(),
        "phase": phase,
        "session": eff_session,
        "created_ts": now,
    }
    rio.write_json(_packet_path(review_id), pkt)
    sweep_expired_gate_files()
    return pkt


def _unlink_packet(review_id: str) -> None:
    if not review_id:
        return
    try:
        p = _packet_path(review_id)
        if p.exists():
            p.unlink()
    except OSError:
        pass


def sweep_expired_gate_files() -> None:
    cutoff = time.time() - PACKET_TTL_SECONDS
    for base_dir in (packets_dir(), threads_dir()):
        for p in base_dir.glob("*.json"):
            try:
                if p.stat().st_mtime < cutoff:
                    p.unlink()
            except OSError:
                pass


CLI_ARG_ERROR_RE = re.compile(
    r"(?:^|\n)\s*(?:usage:\s|error:\s+(?:unexpected|unrecognized)\s+argument|"
    r"[^\n]*:\s*error:\s*(?:unrecognized\s+arguments|argument\s+|the\s+following\s+arguments|invalid\s+int\s+value))",
    re.IGNORECASE,
)

_REVIEW_VAL_FLAGS = frozenset(
    {"--cwd", "--summary", "--diff-file", "--review-id", "--session", "--model", "--resume", "--timeout", "--phase"}
)
_REVIEW_BOOL_FLAGS = frozenset({"--new-session", "--xhigh", "--closure", "--pretty"})


def _fold_ps_line_continuations(cmd_str: str) -> str:
    # INVARIANT: Fold only PowerShell backtick line-continuations (`` ` `` + optional horizontal space + newline) outside quotes;
    # bare newlines and arbitrary backticks remain untouched and rejected as multi-statement / escape hazards.
    if "`" not in cmd_str or ("\n" not in cmd_str and "\r" not in cmd_str):
        return cmd_str
    out: list[str] = []
    quote: str | None = None
    i = 0
    n = len(cmd_str)
    while i < n:
        ch = cmd_str[i]
        if quote is not None:
            out.append(ch)
            if ch == quote:
                if i + 1 < n and cmd_str[i + 1] == quote:
                    out.append(quote)
                    i += 2
                    continue
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "`":
            k = i + 1
            while k < n and cmd_str[k] in (" ", "\t"):
                k += 1
            if k < n and cmd_str[k] == "\r" and k + 1 < n and cmd_str[k + 1] == "\n":
                out.append(" ")
                i = k + 2
                continue
            if k < n and cmd_str[k] == "\n":
                out.append(" ")
                i = k + 1
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def is_direct_codex_invocation(cmd_str: str) -> bool:
    """Return True iff `cmd_str` is a single direct PowerShell invocation of `codex_lane.py (check|review)` or `codex exec`."""
    s = _fold_ps_line_continuations((cmd_str or "").strip()).strip()
    if not s or "\r" in s or "\n" in s or "`" in s or "codex" not in s.lower():
        return False
    m_stdin = re.match(r"^\$null\s*\|\s*", s, re.IGNORECASE)
    if m_stdin:
        s = s[m_stdin.end() :].strip()
    had_call_op = False
    if s.startswith("&") and len(s) > 1 and s[1].isspace():
        had_call_op = True
        s = s[1:].strip()
    if not s:
        return False
    # INVARIANT: In PowerShell, a quoted leading token without `&` is a string expression or parser error, never execution.
    if s[0] in ("'", '"') and not had_call_op:
        return False

    tokens: list[str] = []
    cur: list[str] = []
    in_tok = False
    quote: str | None = None
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if quote is not None:
            if ch == quote:
                # INVARIANT: In PowerShell, doubled quote (`''` or `""`) is an escaped quote literal; `\` is never an escape char.
                if i + 1 < n and s[i + 1] == quote:
                    cur.append(quote)
                    i += 2
                    continue
                quote = None
                i += 1
                continue
            if quote == '"' and ch == "$":
                return False
            cur.append(ch)
            i += 1
            continue

        if ch in ("'", '"'):
            quote = ch
            in_tok = True
            i += 1
            continue
        if ch.isspace():
            if in_tok:
                tokens.append("".join(cur))
                cur = []
                in_tok = False
            i += 1
            continue
        if ch in (";", "|", "&", "<", ">", "(", ")", "$", "#"):
            return False
        cur.append(ch)
        in_tok = True
        i += 1

    if quote is not None:
        return False
    if in_tok:
        tokens.append("".join(cur))
    if len(tokens) < 2:
        return False

    exe_base = os.path.basename(tokens[0].replace("\\", "/")).lower()
    if exe_base.endswith((".exe", ".cmd")):
        exe_base = exe_base[:-4]

    if exe_base == "codex":
        return tokens[1].lower() == "exec"

    if exe_base in ("python", "python3") or re.match(r"^python\d+(?:\.\d+)?$", exe_base):
        idx = 1
        while idx < len(tokens) and tokens[idx].startswith("-"):
            flag = tokens[idx]
            if flag.startswith(("-c", "-m")):
                return False
            idx += 2 if flag == "-X" else 1
        if idx + 1 >= len(tokens):
            return False
        script_base = os.path.basename(tokens[idx].replace("\\", "/")).lower()
        subcmd = tokens[idx + 1].lower()
        if script_base != "codex_lane.py":
            return False
        rem = tokens[idx + 2 :]
        if subcmd == "check":
            return all(t in ("--pretty", "--json") for t in rem)
        if subcmd != "review":
            return False
        j = 0
        while j < len(rem):
            tok = rem[j]
            if tok in _REVIEW_BOOL_FLAGS:
                j += 1
                continue
            opt, sep, inline_val = tok.partition("=")
            if opt in _REVIEW_VAL_FLAGS:
                if sep:
                    val = inline_val
                    step = 1
                elif j + 1 < len(rem):
                    val = rem[j + 1]
                    step = 2
                else:
                    return False
                if opt == "--timeout" and not val.isdigit():
                    return False
                j += step
                continue
            return False
        return True

    return False


SANDBOX_BLOCK_PATTERNS = tuple(
    re.compile(pat, re.IGNORECASE)
    for pat in (
        r"operation not permitted",
        r"permissionerror:\s*\[(?:errno|winerror)",
        r"winerror\s+10013",
        r"eacces:\s*permission denied",
        r"blocked by (?:sandbox|network policy|proxy)",
        r"carbon_stack_home is (?:read-only|not writable)",
    )
)


def detect_sandbox_restriction(output_text: str) -> str | None:
    if not output_text:
        return None
    for pat in SANDBOX_BLOCK_PATTERNS:
        m = pat.search(output_text)
        if m:
            return m.group(0)
    return None


NETWORK_TIMEOUT_PATTERNS = tuple(
    re.compile(pat, re.IGNORECASE)
    for pat in (
        r"connection\s+timed\s+out",
        r"connect\s+timeout",
        r"\betimedout\b",
        r"\beconnreset\b",
        r"\beconnrefused\b",
        r"\behostunreach\b",
        r"\benetunreach\b",
        r"\benotfound\b",
        r"\beai_again\b",
        r"getaddrinfo\b",
        r"temporary\s+failure\s+in\s+name\s+resolution",
        r"failed\s+to\s+lookup\s+address",
        r"tls\s+handshake\s+(?:timeout|eof|failed)",
        r"network\s+is\s+unreachable",
        r"error\s+sending\s+request\s+for\s+url",
        r"stream\s+disconnected\s+before\s+completion",
        r"timed\s+out\s+waiting\s+for\s+model",
    )
)


_CLI_DIAG_LINE_RE = re.compile(
    r"^\s*(?:"
    r"(?:fatal|error|codex(?:\.exe|\.cmd)?|openai|api\s+error|stream\s+error)\s*:"
    r"|\d{4}-\d{2}-\d{2}T\S+\s+(?:ERROR|FATAL)\b"
    r"|caused\s+by\s*:"
    r"|\d+\s*:\s*(?:error|reqwest|hyper|tls|dns|connect|io)"
    r"|reqwest::error"
    r"|permissionerror\s*:"
    r"|oserror\s*:"
    r"|traceback\b"
    r"|thread\s+'[^']+'\s+panicked"
    r")",
    re.IGNORECASE,
)

_STDERR_TOOL_OPEN_RE = re.compile(
    r"^(?:exec\s*$|"
    r".*\bin\s+\S.*\b(?:succeeded|exited)\b.*:\s*$|"
    r"\s*(?:powershell(?:\.exe)?\b[^\n]*\b)?(?:Get-Content|Select-String|cat|type|rg(?:\.exe)?|git\s+(?:diff|show|grep|log))\b)",
    re.IGNORECASE,
)
_STDERR_SECTION_RESET_RE = re.compile(
    r"^(?:thinking|codex|tokens\s+used)\s*$|^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}",
    re.IGNORECASE,
)
_JSONL_EVENT_PREFIXES = ("thread.", "turn.", "item.")


def _extract_cli_error_lines(text: str, excluded_blobs: list[str] | None = None) -> str:
    if not text:
        return ""
    excluded_lines = {
        ln.strip()
        for blob in (excluded_blobs or [])
        if blob
        for ln in blob.splitlines()
        if ln.strip()
    }
    matched: list[str] = []
    in_tool_block = False
    for raw_ln in text.splitlines():
        s_ln = raw_ln.strip()
        if not s_ln:
            continue
        if in_tool_block and _STDERR_SECTION_RESET_RE.match(s_ln):
            in_tool_block = False
        if _STDERR_TOOL_OPEN_RE.match(raw_ln):
            in_tool_block = True
            continue
        if in_tool_block or s_ln in excluded_lines:
            continue
        if _CLI_DIAG_LINE_RE.match(raw_ln):
            matched.append(s_ln)
    return "\n".join(matched)


def _parse_codex_json_stream(raw_stdout: str) -> dict[str, Any]:
    # INVARIANT: Parse `codex exec --json` JSONL stream so CLI/API `error` and `turn.failed` events are structurally
    # separated from `command_execution` tool outputs (`Get-Content`/`rg` reading repository files).
    saw_jsonl = False
    thread_id = ""
    agent_messages: list[str] = []
    cli_errors: list[str] = []
    tool_outputs: list[str] = []
    if not raw_stdout or "{" not in raw_stdout:
        return {
            "saw_jsonl": False,
            "thread_id": "",
            "agent_text": "",
            "cli_errors": cli_errors,
            "tool_outputs": tool_outputs,
        }
    for ln in raw_stdout.splitlines():
        s = ln.strip()
        if not (s.startswith("{") and s.endswith("}")):
            continue
        try:
            rec = json.loads(s)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict):
            continue
        etype = str(rec.get("type") or "")
        if etype != "error" and not etype.startswith(_JSONL_EVENT_PREFIXES):
            continue
        saw_jsonl = True
        if etype == "thread.started":
            tid = str(rec.get("thread_id") or "").strip()
            if tid:
                thread_id = tid
        elif etype == "error":
            emsg = str(rec.get("message") or "").strip()
            if emsg:
                cli_errors.append(emsg)
        elif etype == "turn.failed":
            eobj = rec.get("error")
            emsg = str(eobj.get("message") if isinstance(eobj, dict) else (eobj or rec.get("message") or "")).strip()
            if emsg:
                cli_errors.append(emsg)
        elif etype == "item.completed":
            item = rec.get("item") if isinstance(rec.get("item"), dict) else {}
            itype = str(item.get("type") or "")
            if itype == "agent_message":
                txt = str(item.get("text") or "").strip()
                if txt:
                    agent_messages.append(txt)
            elif itype == "error":
                emsg = str(item.get("message") or "").strip()
                if emsg:
                    cli_errors.append(emsg)
            elif itype in ("command_execution", "mcp_tool_call", "tool_call"):
                for k in ("aggregated_output", "output", "result"):
                    v = item.get(k)
                    if isinstance(v, str) and v.strip():
                        tool_outputs.append(v)
    return {
        "saw_jsonl": saw_jsonl,
        "thread_id": thread_id,
        "agent_text": "\n\n".join(agent_messages),
        "cli_errors": cli_errors,
        "tool_outputs": tool_outputs,
    }


def detect_network_timeout_from_output(output_text: str) -> str | None:
    if not output_text:
        return None
    if CLI_ARG_ERROR_RE.search(output_text):
        return None
    for pat in NETWORK_TIMEOUT_PATTERNS:
        m = pat.search(output_text)
        if m:
            return m.group(0)
    return None


def detect_outage_from_output(output_text: str, exit_code: int = 0) -> str | None:
    if not output_text and exit_code == 0:
        return None
    if CLI_ARG_ERROR_RE.search(output_text or ""):
        return None
    if exit_code == 0 and cwg.extract_review_decision(output_text or "") != (None, None):
        return None
    for pat in OUTAGE_PATTERNS:
        m = pat.search(output_text or "")
        if m:
            return m.group(0)
    return None


def _extract_cli_json_payload(cleaned_text: str) -> dict[str, Any] | None:
    if not cleaned_text:
        return None
    after_hdr = (
        cleaned_text.rsplit("Command output:", 1)[-1].strip()
        if "Command output:" in cleaned_text
        else ""
    )
    last_line = cleaned_text.rsplit("\n", 1)[-1].strip()
    seen: set[str] = set()
    for cand in (cleaned_text, after_hdr, last_line):
        if not cand or cand in seen:
            continue
        seen.add(cand)
        if cand.startswith("{") and cand.endswith("}"):
            try:
                jobj = json.loads(cand)
            except Exception:
                jobj = None
            if isinstance(jobj, dict):
                return jobj
    return None


def inspect_codex_cmd_result(cmd_str: str, g_status: str, blob: str) -> tuple[bool, str | None]:
    """Single-pass check returning `(is_verified_outage, aborted_review_id)` for a direct Codex command."""
    raw_cmd = cmd_str if isinstance(cmd_str, str) else str(cmd_str or "")
    if not is_direct_codex_invocation(raw_cmd):
        return False, None
    cleaned = strip_task_envelope_tail(blob)
    if (
        not cleaned
        or CLI_ARG_ERROR_RE.search(cleaned)
        or cwg.CODEX_CLI_WRAPPER_RE.match(cleaned)
        or cwg.CODEX_REVIEW_OUTPUT_BANNER in cleaned
        or cwg.extract_review_decision(cleaned) != (None, None)
    ):
        return False, None
    is_lane = "codex_lane.py" in raw_cmd.lower()
    jobj = _extract_cli_json_payload(cleaned)
    aborted_rid: str | None = None
    if jobj is not None:
        if is_lane and g_status == "ERROR" and jobj.get("ok") is False:
            cand_rid = str(jobj.get("review_id") or "").strip()
            if _ABORTED_RID_RE.match(cand_rid):
                aborted_rid = cand_rid
        if jobj.get("available") is False and str(jobj.get("lane") or "") == "native-fallback":
            return True, aborted_rid
        err_s = str(jobj.get("error") or "")
        # INVARIANT: A wall-clock thinking timeout (`timeout_after_*s` without `network_outage`) aborts the round (`round_consumed=False`)
        # but is NEVER a Codex outage — the caller must resume the same Codex session rather than escalating to internal Opus/Carbon.
        is_thinking_timeout = bool(
            jobj.get("retry_in_same_lane")
            or (jobj.get("timed_out") and not jobj.get("network_outage"))
            or (err_s.startswith("timeout_after_") and not jobj.get("network_outage"))
        )
        if (
            jobj.get("ok") is False
            and not is_thinking_timeout
            and str(jobj.get("fallback") or "") in cwg.NATIVE_REVIEWERS
        ):
            return True, aborted_rid
    if is_lane:
        return False, aborted_rid
    exit_c = 1 if g_status == "ERROR" else 0
    diag_direct = _extract_cli_error_lines(cleaned) or (cleaned if len(cleaned) <= 2048 else "")
    outage = detect_outage_from_output(diag_direct, exit_code=exit_c) is not None or (
        exit_c != 0 and detect_network_timeout_from_output(diag_direct) is not None
    )
    return outage, None


def is_verified_codex_cmd_outage(cmd_str: str, g_status: str, blob: str) -> bool:
    """Return True iff `cmd_str` actually invoked `codex_lane.py check|review` or `codex exec` and output proves outage."""
    return inspect_codex_cmd_result(cmd_str, g_status, blob)[0]


def extract_aborted_codex_review_id(cmd_str: str, g_status: str, blob: str) -> str | None:
    """Return aborted `review_id` iff a direct `codex_lane.py review` failed with `{"ok": false, "review_id": ...}`."""
    return inspect_codex_cmd_result(cmd_str, g_status, blob)[1]


def record_from_command(command_text: str, output_text: str, exit_code: int = 0) -> None:
    status = "ERROR" if exit_code != 0 else "DONE"
    if not is_verified_codex_cmd_outage(command_text, status, output_text):
        return
    cleaned = strip_task_envelope_tail(output_text)
    jobj = _extract_cli_json_payload(cleaned)
    if isinstance(jobj, dict):
        err_s = str(jobj.get("error") or "")
        # SAFETY: Local review timeouts, transient socket errors, and sandbox blocks must never trip the global 30-minute circuit breaker via PostToolUse.
        if jobj.get("sandbox_blocked") or jobj.get("network_outage") or err_s.startswith("timeout_after_"):
            return
    reason = detect_outage_from_output(cleaned, exit_code=exit_code)
    if not reason:
        return
    trip_breaker(f"CLI reported: {reason}")


def check_health() -> dict[str, Any]:
    b = breaker_status()
    if b.get("tripped"):
        return {
            "available": False,
            "lane": "native-fallback",
            "reason": f"circuit_breaker_open ({b['reason']}, {b['remaining_seconds']}s left)",
        }
    binary = find_codex_binary()
    if not binary:
        return {
            "available": False,
            "lane": "native-fallback",
            "reason": "codex_binary_not_found",
        }
    try:
        proc = subprocess.run(
            [binary, "login", "status"],
            timeout=6.0,
            **rio.subprocess_kwargs(),
        )
        combined = (
            (proc.stdout or b"").decode("utf-8", errors="replace")
            + "\n"
            + (proc.stderr or b"").decode("utf-8", errors="replace")
        ).strip()
        if proc.returncode != 0 or "logged in" not in combined.lower():
            trip_breaker("codex_not_authenticated", ttl=600)
            return {
                "available": False,
                "lane": "native-fallback",
                "reason": f"codex_not_logged_in: {combined}",
            }
        return {
            "available": True,
            "lane": "codex",
            "binary": binary,
            "auth": combined.splitlines()[0] if combined else "authenticated",
        }
    except Exception as exc:
        trip_breaker(f"health_probe_failed:{type(exc).__name__}", ttl=600)
        return {
            "available": False,
            "lane": "native-fallback",
            "reason": f"health_probe_exception:{type(exc).__name__}",
        }


_SAFE_SID_RE = re.compile(r"^[A-Za-z0-9_-]{6,80}$")


def _is_subagent_rollout_meta(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    if payload.get("parent_thread_id"):
        return True
    src = payload.get("source")
    if isinstance(src, dict) and "subagent" in src:
        return True
    tsrc = str(payload.get("thread_source") or "").strip().lower()
    if tsrc and tsrc not in ("user", "cli", "exec"):
        return True
    return False


def _read_rollout_session_meta(rollout_file: pathlib.Path) -> dict[str, Any]:
    try:
        with open(rollout_file, "r", encoding="utf-8", errors="replace") as fh:
            for _ in range(8):
                raw_line = fh.readline()
                if not raw_line:
                    break
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(rec, dict) and rec.get("type") == "session_meta":
                    payload = rec.get("payload")
                    return payload if isinstance(payload, dict) else {}
    except OSError:
        pass
    return {}


def _rollout_message_text(blocks: Any) -> str:
    if isinstance(blocks, list):
        return "\n".join(
            blk["text"]
            for blk in blocks
            if isinstance(blk, dict) and isinstance(blk.get("text"), str)
        ).strip()
    if isinstance(blocks, str):
        return blocks.strip()
    return ""


def _rollout_user_review_ids(rtype: Any, payload: dict[str, Any]) -> list[str]:
    if rtype == "event_msg" and payload.get("type") == "user_message":
        umsg = str(payload.get("message") or "").strip()
        return REVIEW_ID_RE.findall(umsg) if umsg else []
    if rtype == "response_item" and payload.get("type") == "message" and payload.get("role") == "user":
        txt = _rollout_message_text(payload.get("content"))
        return REVIEW_ID_RE.findall(txt) if txt else []
    return []


def _extract_rollout_texts_and_meta(rollout_file: pathlib.Path) -> dict[str, Any] | None:
    records = rio.read_jsonl(rollout_file)
    if not records:
        return None
    try:
        file_mtime = rollout_file.stat().st_mtime
    except OSError:
        file_mtime = 0.0

    turns: list[dict[str, Any]] = []
    current_turn: dict[str, Any] | None = None
    cur_effort = ""
    cur_model = ""
    session_id = ""
    is_subagent = False
    started_ts = 0.0
    completed_ts = 0.0
    last_msg_ts = 0.0

    for rec in records:
        rec_ts = rio.parse_iso_ts(rec.get("timestamp"))
        rtype = rec.get("type")
        payload = rec.get("payload") if isinstance(rec.get("payload"), dict) else {}

        if rtype == "session_meta":
            session_id = str(payload.get("id") or payload.get("session_id") or session_id)
            is_subagent = is_subagent or _is_subagent_rollout_meta(payload)
            started_ts = started_ts or rec_ts or rio.parse_iso_ts(payload.get("timestamp"))
        elif rtype == "turn_context":
            cur_effort = str(payload.get("effort") or cur_effort).lower()
            cur_model = str(payload.get("model") or cur_model)
            if (
                current_turn is not None
                and not current_turn["closed"]
                and not current_turn["assistant_messages"]
            ):
                current_turn["effort"] = cur_effort or current_turn["effort"]
                current_turn["model"] = cur_model or current_turn["model"]
        elif rtype == "event_msg" and payload.get("type") == "task_started":
            if current_turn is not None:
                current_turn["closed"] = True
        elif (
            (rtype == "event_msg" and payload.get("type") == "user_message")
            or (rtype == "response_item" and payload.get("type") == "message" and payload.get("role") == "user")
        ):
            m_ids = _rollout_user_review_ids(rtype, payload)
            if m_ids and not (
                current_turn is not None
                and not current_turn["closed"]
                and current_turn["review_ids"] == m_ids
                and not current_turn["assistant_messages"]
            ):
                if current_turn is not None:
                    current_turn["closed"] = True
                current_turn = {
                    "review_ids": m_ids,
                    "started_ts": rec_ts or started_ts,
                    "completed_ts": 0.0,
                    "effort": cur_effort,
                    "model": cur_model,
                    "assistant_messages": [],
                    "closed": False,
                }
                turns.append(current_turn)
        elif rtype == "response_item" and payload.get("type") == "message" and payload.get("role") == "assistant":
            joined = _rollout_message_text(payload.get("content"))
            if joined:
                msg_ts = rec_ts or file_mtime
                last_msg_ts = msg_ts
                if current_turn is not None and not current_turn["closed"]:
                    current_turn["assistant_messages"].append((msg_ts, joined))
        elif rtype == "event_msg" and payload.get("type") == "task_complete":
            ts_done = rec_ts or rio.parse_iso_ts(payload.get("completed_at")) or file_mtime
            completed_ts = ts_done
            last_msg_ts = ts_done
            last_msg = payload.get("last_agent_message")
            if isinstance(last_msg, str) and last_msg.strip():
                if current_turn is not None and not current_turn["closed"]:
                    current_turn["assistant_messages"].append((ts_done, last_msg.strip()))
            if current_turn is not None:
                current_turn["completed_ts"] = ts_done
                current_turn["closed"] = True

    if not started_ts:
        started_ts = file_mtime
    return {
        "path": str(rollout_file),
        "session_id": session_id,
        "is_subagent": is_subagent,
        "effort": cur_effort,
        "model": cur_model,
        "started_ts": started_ts,
        "completed_ts": completed_ts or last_msg_ts or started_ts,
        "turns": turns,
    }


def _recent_rollout_files(since_ts: float, limit: int = 40, newest_first: bool = False) -> list[pathlib.Path]:
    root = codex_sessions_dir()
    if not root.is_dir():
        return []
    min_mtime = max(0.0, since_ts - 5.0)
    candidates: list[tuple[float, pathlib.Path]] = []
    for rf in root.rglob("rollout-*.jsonl"):
        try:
            mt = rf.stat().st_mtime
            if mt >= min_mtime:
                candidates.append((mt, rf))
        except OSError:
            continue
    candidates.sort(key=lambda pair: pair[0], reverse=newest_first)
    picked = candidates[:limit] if newest_first else candidates[-limit:]
    return [rf for _, rf in picked]


def scan_verified_codex_reviews(
    since_ts: float,
    session: str = "",
    git_root: str = "",
) -> list[dict[str, Any]]:
    """Return nonce- and workspace-bound Codex review verdicts from `~/.codex/sessions` rollout logs."""
    fold_target_root = rio.fold_path(git_root) if git_root else ""
    cwd_root_cache: dict[str, str] = {}
    known_packets: dict[str, dict[str, Any]] = {}
    for pf in packets_dir().glob("*.json"):
        pdata = rio.read_json(pf, default=None)
        if not isinstance(pdata, dict) or not pdata.get("review_id"):
            continue
        if float(pdata.get("created_ts") or 0.0) < since_ts - 2.0:
            continue
        pkt_sess = str(pdata.get("session") or "")
        if session and pkt_sess != session:
            continue
        pkt_cwd = str(pdata.get("cwd") or "")
        if fold_target_root and pkt_cwd:
            if pkt_cwd not in cwd_root_cache:
                cwd_root_cache[pkt_cwd] = rio.fold_path(rio.git_toplevel(pkt_cwd) or pkt_cwd)
            pkt_root = cwd_root_cache[pkt_cwd]
            if pkt_root and pkt_root != fold_target_root:
                continue
        known_packets[str(pdata["review_id"])] = pdata

    if not known_packets:
        return []

    by_review_id: dict[str, dict[str, Any]] = {}
    for rf in _recent_rollout_files(since_ts, limit=40, newest_first=False):
        # INVARIANT: Subagent/guardian rollouts are never eligible sources of gate review verdicts.
        if _is_subagent_rollout_meta(_read_rollout_session_meta(rf)):
            continue
        parsed = _extract_rollout_texts_and_meta(rf)
        if not parsed or parsed.get("is_subagent"):
            continue
        for turn in parsed.get("turns") or []:
            bound_packet = next(
                (known_packets[rid] for rid in (turn.get("review_ids") or []) if rid in known_packets),
                None,
            )
            if bound_packet is None:
                continue

            verdict = None
            kind = None
            verdict_ts = float(turn.get("completed_ts") or parsed["completed_ts"] or 0.0)
            for msg_ts, msg in reversed(turn.get("assistant_messages") or []):
                dec_kind, dec_verdict = cwg.extract_review_decision(msg)
                if dec_kind and dec_verdict:
                    kind = dec_kind
                    verdict = dec_verdict
                    verdict_ts = msg_ts or verdict_ts
                    break

            if verdict and kind:
                pkt_ts = float(
                    bound_packet.get("created_ts") or turn.get("started_ts") or parsed["started_ts"] or 0.0
                )
                eff = str(turn.get("effort") or parsed["effort"] or bound_packet.get("effort") or "high")
                mdl = str(turn.get("model") or parsed["model"] or "")
                eff_verdict_ts = max(pkt_ts, float(verdict_ts or pkt_ts))
                rid_key = str(bound_packet["review_id"])
                rec = {
                    "engine": "codex",
                    "review_id": rid_key,
                    "session_id": parsed["session_id"],
                    "kind": kind,
                    "verdict": verdict,
                    "launch_ts": pkt_ts,
                    "verdict_ts": eff_verdict_ts,
                    "xhigh": eff == "xhigh",
                    "model": mdl,
                    "effort": eff,
                    "rollout_path": parsed["path"],
                }
                prev = by_review_id.get(rid_key)
                if prev is None or eff_verdict_ts >= float(prev.get("verdict_ts") or 0.0):
                    by_review_id[rid_key] = rec
    return sorted(by_review_id.values(), key=lambda r: (float(r["launch_ts"]), float(r["verdict_ts"])))


def _find_rollout_meta_by_sid(
    sid: str,
    recent_files: list[pathlib.Path],
    meta_cache: dict[pathlib.Path, dict[str, Any]],
) -> dict[str, Any]:
    clean_sid = sid.strip()
    if not clean_sid:
        return {}
    name_hits = [rf for rf in recent_files if clean_sid in rf.name]
    rest_recent = [rf for rf in recent_files if clean_sid not in rf.name]
    checked: set[pathlib.Path] = set()

    def _matches(rf: pathlib.Path) -> dict[str, Any] | None:
        checked.add(rf)
        meta = meta_cache.get(rf)
        if meta is None:
            meta = _read_rollout_session_meta(rf)
            meta_cache[rf] = meta
        meta_id = str(meta.get("id") or ("" if _is_subagent_rollout_meta(meta) else meta.get("session_id")) or "")
        return meta if meta_id == clean_sid else None

    for rf in (*name_hits, *rest_recent):
        hit = _matches(rf)
        if hit is not None:
            return hit
    root = codex_sessions_dir()
    if _SAFE_SID_RE.match(clean_sid) and root.is_dir():
        for rf in root.rglob(f"*{clean_sid}*.jsonl"):
            if rf in checked:
                continue
            hit = _matches(rf)
            if hit is not None:
                return hit
    return {}


def _unwrap_primary_session_id(sid: str, since_ts: float = 0.0) -> str:
    # INVARIANT: Codex 0.159+ spawns guardian/subagent rollouts sharing the user prompt; always unwrap to parent thread.
    cur = sid.strip()
    if not cur:
        return ""
    recent_files = _recent_rollout_files(max(0.0, since_ts - 60.0), limit=40, newest_first=True)
    meta_cache: dict[pathlib.Path, dict[str, Any]] = {}
    seen: set[str] = set()
    for _ in range(4):
        if not cur or cur in seen:
            return ""
        seen.add(cur)
        meta = _find_rollout_meta_by_sid(cur, recent_files, meta_cache)
        if not meta or not _is_subagent_rollout_meta(meta):
            return cur
        cur = str(meta.get("parent_thread_id") or "").strip()
    return ""


def _resolve_resume_session(
    git_root: str,
    session: str,
    candidate_first_ts: float,
    explicit_resume: str = "",
    force_new: bool = False,
) -> str:
    if force_new:
        return ""
    if explicit_resume.strip():
        return _unwrap_primary_session_id(explicit_resume.strip(), candidate_first_ts)

    saved = active_thread_state(session, git_root, candidate_first_ts)
    if isinstance(saved, dict) and saved.get("session_id"):
        unwrapped = _unwrap_primary_session_id(str(saved["session_id"]), candidate_first_ts)
        if unwrapped:
            return unwrapped

    if session and candidate_first_ts > 0.0:
        prior = scan_verified_codex_reviews(
            since_ts=candidate_first_ts,
            session=session,
            git_root=git_root,
        )
        for prev in reversed(prior):
            raw_sid = str(prev.get("session_id") or "").strip()
            sid = _unwrap_primary_session_id(raw_sid, candidate_first_ts) if raw_sid else ""
            if sid:
                return sid
    return ""


def _find_session_id_for_review(review_id: str, since_ts: float) -> str:
    if not review_id:
        return ""
    for rf in _recent_rollout_files(since_ts, limit=30, newest_first=True):
        # INVARIANT: Never bind candidate review continuity to Codex internal subagent/guardian rollouts.
        if _is_subagent_rollout_meta(_read_rollout_session_meta(rf)):
            continue
        parsed = _extract_rollout_texts_and_meta(rf)
        if not parsed or not parsed.get("session_id") or parsed.get("is_subagent"):
            continue
        for turn in parsed.get("turns") or []:
            if review_id in (turn.get("review_ids") or []):
                return str(parsed["session_id"])
    return ""


def _find_rollout_turn_state(review_id: str, since_ts: float) -> tuple[bool, str, list[str]]:
    if not review_id:
        return False, "", []
    for rf in _recent_rollout_files(since_ts, limit=30, newest_first=True):
        meta = _read_rollout_session_meta(rf)
        if _is_subagent_rollout_meta(meta):
            continue
        records = rio.read_jsonl(rf)
        if not records:
            continue
        has_rid = False
        in_target_turn = False
        err_msgs: list[str] = []
        tool_outputs: list[str] = []
        for rec in records:
            rec_ts = rio.parse_iso_ts(rec.get("timestamp"))
            rtype = rec.get("type")
            payload = rec.get("payload") if isinstance(rec.get("payload"), dict) else {}
            m_ids = _rollout_user_review_ids(rtype, payload)
            if m_ids:
                if review_id in m_ids:
                    if not in_target_turn:
                        err_msgs = []
                        tool_outputs = []
                    has_rid = True
                    in_target_turn = True
                else:
                    in_target_turn = False
            elif rtype == "event_msg" and payload.get("type") == "task_complete":
                in_target_turn = False
            elif in_target_turn and (rec_ts <= 0.0 or rec_ts >= since_ts - 2.0):
                if rtype == "error":
                    msg = str(payload.get("message") or rec.get("message") or "").strip()
                    if msg:
                        err_msgs.append(msg)
                elif rtype == "event_msg" and payload.get("type") in ("error", "stream_error"):
                    msg = str(payload.get("message") or payload.get("error") or "").strip()
                    if msg:
                        err_msgs.append(msg)
                elif rtype == "response_item" and payload.get("type") in ("function_call_output", "custom_tool_call_output"):
                    tout = payload.get("output")
                    if isinstance(tout, str) and tout.strip():
                        tool_outputs.append(tout)
                elif rtype == "event_msg" and payload.get("type") == "exec_command_end":
                    for k in ("stdout", "stderr", "formatted_output", "aggregated_output"):
                        tout = payload.get(k)
                        if isinstance(tout, str) and tout.strip():
                            tool_outputs.append(tout)
        if has_rid:
            sid = str((meta or {}).get("id") or "").strip()
            if sid:
                _LAST_ROLLOUT_TURN_SID[review_id] = sid
            return True, "\n".join(err_msgs), tool_outputs
    return False, "", []


def _extract_cli_diagnostic_text(
    stdout_text: str,
    stderr_text: str,
    review_id: str,
    since_ts: float,
    is_timeout: bool,
    parsed_json: dict[str, Any] | None = None,
) -> str:
    # INVARIANT: Combine structured `--json` CLI error events (`error`/`turn.failed`), current-turn rollout error events,
    # and non-tool CLI stderr lines while strictly excluding `command_execution`/`function_call_output` file contents.
    jstream = parsed_json if parsed_json is not None else _parse_codex_json_stream(stdout_text)
    found_rollout, rollout_err, rollout_tools = _find_rollout_turn_state(review_id, since_ts)
    excluded_tools = list(jstream.get("tool_outputs") or []) + rollout_tools
    parts: list[str] = []
    for jerr in jstream.get("cli_errors") or []:
        if jerr:
            parts.append(str(jerr))
    if rollout_err:
        parts.append(rollout_err)
    stderr_diag = _extract_cli_error_lines(stderr_text, excluded_blobs=excluded_tools)
    if stderr_diag:
        parts.append(stderr_diag)
    if jstream.get("saw_jsonl") or is_timeout or found_rollout:
        return "\n".join(parts)
    stdout_diag = _extract_cli_error_lines(stdout_text, excluded_blobs=excluded_tools)
    if stdout_diag:
        parts.append(stdout_diag)
    combined = f"{stdout_text}\n{stderr_text}".strip()
    if not parts and len(combined) <= 2048:
        return combined
    return "\n".join(parts)


def _read_diff_file(path: str) -> str:
    raw = pathlib.Path(path).read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16", errors="replace")
    elif raw.startswith(b"\xef\xbb\xbf"):
        text = raw.decode("utf-8-sig", errors="replace")
    else:
        text = raw.decode("utf-8", errors="replace")
    return text.replace("\x00", "")


def _build_codex_exec_cmd(
    binary: str,
    cwd: str,
    effort: str,
    model: str = "",
    resume_session_id: str = "",
) -> list[str]:
    common_opts = [
        "--json",
        "--skip-git-repo-check",
        "-c",
        "mcp_servers={}",
        "-c",
        'sandbox_mode="read-only"',
        "-c",
        f'model_reasoning_effort="{effort}"',
        "--disable",
        "codex_hooks",
    ]
    if model:
        common_opts.extend(["-m", model])
    if resume_session_id:
        # INVARIANT: `codex exec resume` rejects `-s` and `-C`; rely on `-c sandbox_mode="read-only"`, `cwd=cwd`, and `--all`.
        return [binary, "exec", "resume", "--all", *common_opts, resume_session_id, "-"]
    return [binary, "exec", "-s", "read-only", "-C", cwd, *common_opts, "-"]


def build_adversarial_prompt(
    review_id: str,
    scope_summary: str,
    diff_text: str,
    phase: str,
    is_resume: bool = False,
    is_timeout_resume: bool = False,
) -> str:
    if phase == "closure":
        verdict_rule = (
            "Respond in plain text/markdown (not JSON) and conclude with an exact standalone line:\n"
            "CLOSURE_VALIDATION: READY\n"
            "or\n"
            "CLOSURE_VALIDATION: BLOCKED\n"
            "Choose BLOCKED only if concrete correctness, security, data-loss, or contract regressions remain."
        )
    else:
        verdict_rule = (
            "Respond in plain text/markdown (not JSON) and conclude with an exact standalone line:\n"
            "VERDICT: APPROVED\n"
            "or\n"
            "VERDICT: REVISE\n"
            "or (round 3 only when fundamental design trade-offs remain)\n"
            "VERDICT: ESCALATE\n"
            "Approve when no real correctness, security, concurrency, edge-case, or contract defects exist. "
            "Do not invent nitpicks to justify REVISE."
        )
    if is_timeout_resume:
        round_mode = (
            "ROUND_MODE: timeout_continuation (same review thread — your previous review turn hit the wall-clock timeout "
            "before emitting a final verdict; continue from the repository context already inspected in this thread "
            "without starting over, and conclude with your findings and exact standalone verdict line).\n"
        )
    elif is_resume:
        round_mode = (
            "ROUND_MODE: continuation (same review thread — verify whether prior findings are resolved, "
            "check remediation delta for regressions, and do not invent nitpicks on unchanged code).\n"
        )
    else:
        round_mode = ""
    return (
        f"REVIEW_ID: {review_id}\n"
        "ROLE: Independent Adversarial Code Reviewer (Read-Only).\n"
        f"{round_mode}"
        "RULES:\n"
        "1. Do NOT modify any files. Inspect repository files directly if needed for context.\n"
        "2. Verify invariants, failure paths, security boundaries, concurrency, and test coverage.\n"
        "3. Separate confirmed defects ([HIGH]/[MEDIUM]) from non-blocking observations.\n"
        f"4. {verdict_rule}\n\n"
        f"CANDIDATE SUMMARY:\n{scope_summary}\n\n"
        f"GIT DIFF SNAPSHOT:\n{diff_text[:MAX_DIFF_SNAPSHOT_CHARS]}\n"
    )


_coerce_pipe_bytes = rio.coerce_pipe_bytes


def _kill_process_tree(proc: subprocess.Popen[bytes]) -> tuple[bytes, bytes]:
    return rio.reap_process_tree(proc)


def _exec_codex_once(
    cmd: list[str],
    prompt: str,
    cwd: str,
    timeout: float,
    review_id: str,
    xhigh: bool,
) -> _CodexExecResult | None:
    kw = rio.popen_kwargs(stdin_pipe=True)
    proc: subprocess.Popen[bytes] | None = None
    t_start = time.time()
    try:
        proc = rio.spawn_with_kill_job(subprocess.Popen, cmd, cwd=cwd, **kw)
        out_b, err_b = proc.communicate(input=prompt.encode("utf-8"), timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        kill_res = _kill_process_tree(proc) if proc is not None else None
        rem_out, rem_err = (
            (_coerce_pipe_bytes(kill_res[0]), _coerce_pipe_bytes(kill_res[1]))
            if isinstance(kill_res, tuple) and len(kill_res) == 2
            else (b"", b"")
        )
        partial_out = _coerce_pipe_bytes(getattr(exc, "output", None)) + rem_out
        partial_err = _coerce_pipe_bytes(getattr(exc, "stderr", None)) + rem_err
        partial_stdout_txt = partial_out.decode("utf-8", errors="replace")
        partial_stderr_txt = partial_err.decode("utf-8", errors="replace")
        jstream_to = _parse_codex_json_stream(partial_stdout_txt)
        diag_timeout = _extract_cli_diagnostic_text(
            partial_stdout_txt,
            partial_stderr_txt,
            review_id,
            t_start - 1.0,
            is_timeout=True,
            parsed_json=jstream_to,
        )
        provider_outage = detect_outage_from_output(diag_timeout, exit_code=1)
        net_outage = provider_outage or detect_network_timeout_from_output(diag_timeout)
        sb_err = None if net_outage else detect_sandbox_restriction(diag_timeout)
        if sb_err:
            _LAST_TIMEOUT_OUTAGE[review_id] = ("sandbox", "")
            rio.print_cli_json(
                {
                    "ok": False,
                    "review_id": review_id,
                    "sandbox_blocked": True,
                    "round_consumed": False,
                    "error": f"sandbox_restricted ({sb_err}); re-run codex_lane.py review with BypassSandbox=true",
                },
            )
            return None
        if net_outage:
            # SAFETY: Only genuine internet/API/quota failures during a timeout authorize fallback; local thinking timeouts never do.
            _LAST_TIMEOUT_OUTAGE[review_id] = ("network", "")
            if provider_outage:
                trip_breaker(provider_outage)
            rio.log_hook_event(
                "gate-events",
                "codex_review_network_timeout",
                review_id=review_id,
                timeout=int(timeout),
                reason=net_outage,
            )
            rio.print_cli_json(
                {
                    "ok": False,
                    "review_id": review_id,
                    "network_outage": True,
                    "outage_reason": net_outage,
                    "round_consumed": False,
                    "fallback": _fallback_reviewer(xhigh),
                    "error": f"timeout_after_{int(timeout)}s",
                },
            )
            return None
        rio.log_hook_event("gate-events", "codex_review_timeout", review_id=review_id, timeout=int(timeout))
        recommended_timeout = next_timeout_after(timeout)
        cached_rollout_sid = _LAST_ROLLOUT_TURN_SID.pop(review_id, "")
        timeout_sid = (
            _unwrap_primary_session_id(str(jstream_to.get("thread_id") or ""), t_start - 1.0)
            or (_unwrap_primary_session_id(cached_rollout_sid, t_start - 1.0) if cached_rollout_sid else "")
            or _find_session_id_for_review(review_id, t_start - 1.0)
        )
        _LAST_TIMEOUT_OUTAGE[review_id] = ("thinking", timeout_sid)
        payload_to: dict[str, Any] = {
            "ok": False,
            "review_id": review_id,
            "timed_out": True,
            "retry_in_same_lane": True,
            "round_consumed": False,
            "recommended_timeout": recommended_timeout,
            "error": f"timeout_after_{int(timeout)}s",
            "hint": (
                f"Codex did not finish within {int(timeout)}s (thinking timeout, NOT an outage; review round NOT consumed). "
                f"Re-run codex_lane.py review without --timeout to continue the same Codex session with {recommended_timeout}s timeout; "
                "escalating to internal review on a thinking timeout is forbidden."
            ),
        }
        if timeout_sid:
            payload_to["session_id"] = timeout_sid
        rio.print_cli_json(payload_to)
        return None
    except Exception as exc:
        if proc is not None:
            _kill_process_tree(proc)
        if isinstance(exc, PermissionError):
            return _CodexExecResult(2, "", f"PermissionError: [Errno 13] {exc}", False, None, None, f"PermissionError: [Errno 13] {exc}")
        _LAST_TIMEOUT_OUTAGE[review_id] = ("error", "")
        rio.print_cli_json({"ok": False, "review_id": review_id, "error": str(exc)})
        return None
    except BaseException:
        if proc is not None:
            _kill_process_tree(proc)
        raise
    finally:
        if proc is not None:
            rio.close_kill_job(proc, terminate=False)

    raw_stdout_text = (out_b or b"").decode("utf-8", errors="replace")
    stderr_text = (err_b or b"").decode("utf-8", errors="replace")
    jstream_exit = _parse_codex_json_stream(raw_stdout_text)
    stream_tid = str(jstream_exit.get("thread_id") or "")
    stdout_text = str(jstream_exit["agent_text"]) if jstream_exit["saw_jsonl"] else raw_stdout_text
    has_structured_verdict = cwg.extract_review_decision(stdout_text) != (None, None)
    if proc.returncode == 0 and has_structured_verdict:
        return _CodexExecResult(0, stdout_text, stderr_text, True, None, None, None, stream_tid)
    diag_exit = _extract_cli_diagnostic_text(
        raw_stdout_text,
        stderr_text,
        review_id,
        t_start - 1.0,
        is_timeout=False,
        parsed_json=jstream_exit,
    )
    eff_stderr = (
        "\n".join(str(e) for e in (jstream_exit.get("cli_errors") or []) if e) or stderr_text
        if jstream_exit["saw_jsonl"]
        else stderr_text
    )
    outage = detect_outage_from_output(diag_exit, exit_code=proc.returncode)
    net_err = None if outage else (detect_network_timeout_from_output(diag_exit) if proc.returncode != 0 else None)
    sb_exit = None if (outage or net_err or proc.returncode == 0) else detect_sandbox_restriction(diag_exit)
    return _CodexExecResult(proc.returncode, stdout_text, eff_stderr, has_structured_verdict, outage, net_err, sb_exit, stream_tid)


def cmd_review(args: argparse.Namespace) -> int:
    if args.review_id and _packet_path(args.review_id).exists():
        rio.print_cli_json(
            {"ok": False, "error": f"duplicate_review_id:{args.review_id}"},
            pretty=args.pretty,
        )
        return 2

    health = check_health()
    if not health.get("available"):
        rio.print_cli_json(health, pretty=args.pretty)
        return 2

    cwd = os.path.abspath(args.cwd or os.getcwd())
    git_root = rio.git_toplevel(cwd) or cwd
    effort = "xhigh" if args.xhigh else "high"
    phase = "closure" if (args.closure or getattr(args, "phase", "") == "closure") else "ordinary"
    review_id = args.review_id or f"cwg-{uuid.uuid4().hex[:12]}"
    eff_session = args.session or _infer_single_open_session(cwd)
    cand_first_ts = _candidate_first_ts(eff_session)
    resume_sid = _resolve_resume_session(
        git_root=git_root,
        session=eff_session,
        candidate_first_ts=cand_first_ts,
        explicit_resume=args.resume or "",
        force_new=bool(args.new_session),
    )

    if args.diff_file and os.path.isfile(args.diff_file):
        diff_text = _read_diff_file(args.diff_file)
    else:
        rc_git, out, _ = rio.run_git(cwd, ["diff", "HEAD"], timeout=10.0)
        if rc_git == 0 and isinstance(out, str) and out.strip():
            diff_text = out
        else:
            _, out2, _ = rio.run_git(cwd, ["status", "--short"], timeout=5.0)
            diff_text = str(out2 or "")

    scope_summary = args.summary or "Review current repository candidate changes."
    saved_thread = None if args.new_session else active_thread_state(eff_session, git_root, cand_first_ts)
    is_timeout_continuation = bool(saved_thread and saved_thread.get("pending_timeout_resume"))
    saved_next_timeout = 0.0
    if is_timeout_continuation and isinstance(saved_thread, dict):
        try:
            saved_next_timeout = float(saved_thread.get("next_timeout_seconds") or 0.0)
        except (TypeError, ValueError):
            saved_next_timeout = 0.0

    min_required_timeout = float(required_review_timeout(bool(args.xhigh), saved_next_timeout))
    if args.timeout is not None and not os.environ.get("CARBON_CODEX_BIN"):
        # INVARIANT: Reject upfront or shrunk custom `--timeout` in live runs; standard defaults are 600s (HIGH) and 900s (XHIGH).
        if not is_timeout_continuation:
            rio.print_cli_json(
                {
                    "ok": False,
                    "invalid_timeout": True,
                    "error": (
                        "Upfront custom --timeout is forbidden; omit --timeout so codex_lane.py uses the standard "
                        f"{DEFAULT_REVIEW_TIMEOUT_SECONDS}s (HIGH) / {DEFAULT_XHIGH_REVIEW_TIMEOUT_SECONDS}s (--xhigh) timeout."
                    ),
                },
                pretty=args.pretty,
            )
            return 2
        if int(args.timeout) < int(min_required_timeout):
            rio.print_cli_json(
                {
                    "ok": False,
                    "invalid_timeout": True,
                    "error": (
                        f"Custom --timeout {args.timeout}s is below required continuation timeout ({int(min_required_timeout)}s); "
                        "omit --timeout to continue automatically with increased timeout."
                    ),
                },
                pretty=args.pretty,
            )
            return 2

    eff_timeout = float(args.timeout) if args.timeout is not None else min_required_timeout
    exec_res: _CodexExecResult | None = None
    launch_wall_ts = 0.0
    used_resume_sid = ""
    active_review_id = review_id
    attempts = (resume_sid, "") if resume_sid else ("",)
    for attempt_idx, cur_resume_sid in enumerate(attempts):
        active_review_id = (
            review_id
            if (attempt_idx == 0 or args.review_id)
            else f"cwg-{uuid.uuid4().hex[:12]}"
        )
        prompt = build_adversarial_prompt(
            review_id=active_review_id,
            scope_summary=scope_summary,
            diff_text=diff_text,
            phase=phase,
            is_resume=bool(cur_resume_sid),
            is_timeout_resume=bool(cur_resume_sid and is_timeout_continuation),
        )
        record_packet(
            review_id=active_review_id,
            prompt_text=prompt,
            cwd=cwd,
            effort=effort,
            phase=phase,
            session=eff_session,
        )
        if not _packet_path(active_review_id).is_file():
            # SAFETY: Inside Standard Sandbox (`BypassSandbox=false`), `CARBON_STACK_HOME` is read-only; fail fast without
            # hanging on blocked network sockets, without tripping the global breaker, and without granting fallback.
            rio.print_cli_json(
                {
                    "ok": False,
                    "sandbox_blocked": True,
                    "error": "CARBON_STACK_HOME is not writable in sandbox; re-run codex_lane.py review with BypassSandbox=true",
                },
                pretty=args.pretty,
            )
            return 2
        packet_committed = False
        try:
            launch_wall_ts = time.time()
            cmd = _build_codex_exec_cmd(
                health["binary"],
                cwd=cwd,
                effort=effort,
                model=args.model,
                resume_session_id=cur_resume_sid,
            )
            exec_res = _exec_codex_once(
                cmd, prompt, cwd, eff_timeout, active_review_id, args.xhigh
            )
            if exec_res is None:
                timeout_kind, stream_sid = _LAST_TIMEOUT_OUTAGE.pop(active_review_id, ("thinking", ""))
                if timeout_kind == "thinking":
                    # INVARIANT: Persist timed-out Codex thread + elevated timeout so retry resumes the same lane without losing a round.
                    timeout_sid = (
                        stream_sid
                        or _find_session_id_for_review(active_review_id, launch_wall_ts - 1.0)
                        or (_unwrap_primary_session_id(cur_resume_sid, cand_first_ts) if cur_resume_sid else "")
                        or str((saved_thread or {}).get("session_id") or "")
                    )
                    next_to = next_timeout_after(eff_timeout)
                    rio.write_json(
                        _thread_state_path(eff_session, git_root),
                        {
                            "session_id": timeout_sid,
                            "last_review_id": active_review_id,
                            "session": eff_session,
                            "git_root": rio.normalize_path(git_root),
                            "candidate_first_ts": cand_first_ts,
                            "pending_timeout_resume": True,
                            "last_timeout_seconds": int(eff_timeout),
                            "next_timeout_seconds": next_to,
                            "updated_ts": time.time(),
                        },
                    )
                elif timeout_kind == "network":
                    _clear_pending_timeout_resume(eff_session, git_root)
                return 3
            used_resume_sid = cur_resume_sid
            _LAST_ROLLOUT_TURN_SID.pop(active_review_id, None)
            # SAFETY: Fall back once to a fresh primary session if resuming an invalid or verdict-less thread (never on sandbox block).
            if (
                attempt_idx == 0
                and cur_resume_sid
                and not exec_res.has_verdict
                and not exec_res.outage
                and not exec_res.network_outage
                and not exec_res.sandbox_blocked
            ):
                cwg.unlink_quiet(_thread_state_path(eff_session, git_root))
                continue
            if not exec_res.outage and not exec_res.network_outage and exec_res.rc == 0:
                packet_committed = True
            break
        finally:
            if not packet_committed:
                _unlink_packet(active_review_id)

    assert exec_res is not None
    if exec_res.outage or exec_res.network_outage or exec_res.rc != 0:
        if exec_res.sandbox_blocked:
            rio.print_cli_json(
                {
                    "ok": False,
                    "review_id": active_review_id,
                    "exit_code": exec_res.rc,
                    "sandbox_blocked": True,
                    "error": f"sandbox_restricted ({exec_res.sandbox_blocked}); re-run codex_lane.py review with BypassSandbox=true",
                },
                pretty=args.pretty,
            )
            return 2
        eff_outage = exec_res.outage or exec_res.network_outage
        if exec_res.outage:
            trip_breaker(exec_res.outage)
        if eff_outage:
            _clear_pending_timeout_resume(eff_session, git_root)
        err_detail = (exec_res.stderr or exec_res.stdout or "").strip()
        if eff_outage and err_detail and eff_outage not in err_detail:
            err_msg = f"{eff_outage}: {err_detail}"
        else:
            err_msg = (eff_outage or err_detail).strip()
        err_obj: dict[str, Any] = {
            "ok": False,
            "review_id": active_review_id,
            "exit_code": exec_res.rc,
            "error": err_msg,
        }
        if exec_res.network_outage:
            err_obj["network_outage"] = True
            err_obj["outage_reason"] = exec_res.network_outage
        if eff_outage:
            err_obj["fallback"] = _fallback_reviewer(args.xhigh)
        rio.print_cli_json(err_obj, pretty=args.pretty)
        return 2

    actual_sid = (
        (_unwrap_primary_session_id(exec_res.thread_id, cand_first_ts) if exec_res.thread_id else "")
        or _find_session_id_for_review(active_review_id, launch_wall_ts)
        or (_unwrap_primary_session_id(used_resume_sid, cand_first_ts) if used_resume_sid else "")
    )
    if exec_res.has_verdict:
        if actual_sid:
            rio.write_json(
                _thread_state_path(eff_session, git_root),
                {
                    "session_id": actual_sid,
                    "last_review_id": active_review_id,
                    "session": eff_session,
                    "git_root": rio.normalize_path(git_root),
                    "candidate_first_ts": cand_first_ts,
                    "updated_ts": time.time(),
                },
            )
        elif is_timeout_continuation:
            cwg.unlink_quiet(_thread_state_path(eff_session, git_root))

    session_mode = "resumed" if used_resume_sid else "new"
    sys.stdout.write(
        f"REVIEW_ID: {active_review_id}\n"
        f"SESSION_ID: {actual_sid}\n"
        f"SESSION_MODE: {session_mode}\n"
        f"ENGINE: codex ({effort})\n"
        f"{cwg.CODEX_REVIEW_OUTPUT_BANNER}\n"
        f"{exec_res.stdout.strip()}\n"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="codex_lane")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    chk = sub.add_parser("check", help="Check Codex CLI availability, auth, and circuit breaker")
    chk.add_argument("--pretty", action="store_true")
    stp = sub.add_parser("status", help="Show circuit breaker and recent rollout status")
    stp.add_argument("--pretty", action="store_true")
    sub.add_parser("reset", help="Clear circuit breaker")

    rev = sub.add_parser("review", help="Execute isolated read-only Codex adversarial review")
    rev.add_argument("--cwd", default="")
    rev.add_argument("--summary", default="")
    rev.add_argument("--diff-file", default="")
    rev.add_argument("--review-id", default="")
    rev.add_argument("--session", default="")
    rev.add_argument("--model", default="")
    rev.add_argument("--resume", default="")
    rev.add_argument("--new-session", action="store_true")
    rev.add_argument("--xhigh", action="store_true")
    rev.add_argument("--closure", action="store_true")
    rev.add_argument("--phase", choices=("ordinary", "closure"), default="")
    rev.add_argument("--timeout", type=int, default=None)
    rev.add_argument("--pretty", action="store_true")

    args = parser.parse_args()
    if args.subcommand == "check":
        res = check_health()
        rio.print_cli_json(res, pretty=args.pretty)
        return 0 if res.get("available") else 1
    if args.subcommand == "status":
        sweep_expired_gate_files()
        st_obj = {
            "breaker": breaker_status(),
            "binary": find_codex_binary(),
            "sessions_dir_exists": codex_sessions_dir().is_dir(),
            "active_threads": len(list(threads_dir().glob("*.json"))),
        }
        rio.print_cli_json(st_obj, pretty=args.pretty)
        return 0
    if args.subcommand == "reset":
        reset_breaker()
        rio.print_cli_json({"reset": True})
        return 0
    if args.subcommand == "review":
        return cmd_review(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
