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
import signal
import subprocess
import sys
import time
import uuid
from typing import Any, NamedTuple

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cwg_common as cwg
import runtime_io as rio

BREAKER_TTL_SECONDS = 1800  # 30 minutes cooldown after quota/auth/capacity outage
PACKET_TTL_SECONDS = 86400
MAX_DIFF_SNAPSHOT_CHARS = 160_000


class _CodexExecResult(NamedTuple):
    rc: int
    stdout: str
    stderr: str
    has_verdict: bool
    outage: str | None

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

REVIEW_ID_RE = re.compile(r"REVIEW_ID\s*:\s*([A-Za-z0-9_-]{8,64})")
_ABORTED_RID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")


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
    {"--cwd", "--summary", "--diff-file", "--review-id", "--session", "--model", "--resume", "--timeout"}
)
_REVIEW_BOOL_FLAGS = frozenset({"--new-session", "--xhigh", "--closure", "--pretty"})


def is_direct_codex_invocation(cmd_str: str) -> bool:
    """Return True iff `cmd_str` is a single direct PowerShell invocation of `codex_lane.py (check|review)` or `codex exec`."""
    s = (cmd_str or "").strip()
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
        if jobj.get("ok") is False and str(jobj.get("fallback") or "") in cwg.NATIVE_REVIEWERS:
            return True, aborted_rid
    if is_lane:
        return False, aborted_rid
    outage = detect_outage_from_output(cleaned, exit_code=1 if g_status == "ERROR" else 0) is not None
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
    reason = detect_outage_from_output(strip_task_envelope_tail(output_text), exit_code=exit_code) or "codex_outage"
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
        elif rtype == "response_item" and payload.get("type") == "message":
            role = payload.get("role")
            blocks = payload.get("content")
            chunks: list[str] = []
            if isinstance(blocks, list):
                for blk in blocks:
                    if isinstance(blk, dict) and isinstance(blk.get("text"), str):
                        chunks.append(blk["text"])
            elif isinstance(blocks, str):
                chunks.append(blocks)
            joined = "\n".join(chunks).strip()
            if joined:
                if role == "user":
                    m_ids = REVIEW_ID_RE.findall(joined)
                    if m_ids:
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
                elif role == "assistant":
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

    saved = rio.read_json(_thread_state_path(session, git_root), default=None)
    if isinstance(saved, dict) and saved.get("session_id"):
        saved_cand_ts = float(saved.get("candidate_first_ts") or 0.0)
        # INVARIANT: When no candidate marker is open (NO_CHANGE / manual review), reuse same-repo thread for 1h.
        matched_saved = (
            abs(saved_cand_ts - candidate_first_ts) < 1.0
            if candidate_first_ts > 0.0
            else (saved_cand_ts <= 0.0 and (time.time() - float(saved.get("updated_ts") or 0.0)) < 3600.0)
        )
        if matched_saved:
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
    round_mode = (
        "ROUND_MODE: continuation (same review thread — verify whether prior findings are resolved, "
        "check remediation delta for regressions, and do not invent nitpicks on unchanged code).\n"
        if is_resume
        else ""
    )
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


def _kill_process_tree(proc: subprocess.Popen[bytes]) -> None:
    # SAFETY: Reap the full Codex child tree on timeout or cancellation without swallowing KeyboardInterrupt/SystemExit.
    try:
        if os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                    timeout=5.0,
                    **rio.subprocess_kwargs(),
                )
            except Exception:
                pass
        else:
            killpg_fn = getattr(os, "killpg", None)
            if callable(killpg_fn):
                try:
                    killpg_fn(proc.pid, getattr(signal, "SIGKILL", signal.SIGTERM))
                except OSError:
                    pass
    finally:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.communicate(timeout=2.0)
        except Exception:
            pass


def _exec_codex_once(
    cmd: list[str],
    prompt: str,
    cwd: str,
    timeout: float,
    review_id: str,
    xhigh: bool,
) -> _CodexExecResult | None:
    kw = rio.subprocess_kwargs()
    kw.pop("capture_output", None)
    kw["stdin"] = subprocess.PIPE
    kw["stdout"] = subprocess.PIPE
    kw["stderr"] = subprocess.PIPE
    if os.name != "nt":
        kw["start_new_session"] = True
    proc: subprocess.Popen[bytes] | None = None
    try:
        proc = subprocess.Popen(cmd, cwd=cwd, **kw)
        out_b, err_b = proc.communicate(input=prompt.encode("utf-8"), timeout=timeout)
    except subprocess.TimeoutExpired:
        if proc is not None:
            _kill_process_tree(proc)
        trip_breaker(f"codex_exec_timeout_{int(timeout)}s")
        rio.print_cli_json(
            {
                "ok": False,
                "review_id": review_id,
                "fallback": _fallback_reviewer(xhigh),
                "error": f"timeout_after_{int(timeout)}s",
            },
        )
        return None
    except Exception as exc:
        if proc is not None:
            _kill_process_tree(proc)
        trip_breaker(f"codex_exec_error:{type(exc).__name__}")
        rio.print_cli_json({"ok": False, "review_id": review_id, "error": str(exc)})
        return None
    except BaseException:
        if proc is not None:
            _kill_process_tree(proc)
        raise

    stdout_text = (out_b or b"").decode("utf-8", errors="replace")
    stderr_text = (err_b or b"").decode("utf-8", errors="replace")
    has_structured_verdict = cwg.extract_review_decision(stdout_text) != (None, None)
    combined = stdout_text + "\n" + stderr_text
    outage = (
        None
        if (proc.returncode == 0 and has_structured_verdict)
        else detect_outage_from_output(combined, exit_code=proc.returncode)
    )
    return _CodexExecResult(proc.returncode, stdout_text, stderr_text, has_structured_verdict, outage)


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
    phase = "closure" if args.closure else "ordinary"
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
        )
        record_packet(
            review_id=active_review_id,
            prompt_text=prompt,
            cwd=cwd,
            effort=effort,
            phase=phase,
            session=eff_session,
        )
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
                cmd, prompt, cwd, float(args.timeout), active_review_id, args.xhigh
            )
            if exec_res is None:
                return 3
            used_resume_sid = cur_resume_sid
            # SAFETY: Fall back once to a fresh primary session if resuming an invalid or verdict-less thread.
            if (
                attempt_idx == 0
                and cur_resume_sid
                and not exec_res.has_verdict
                and not exec_res.outage
            ):
                tpath = _thread_state_path(eff_session, git_root)
                try:
                    if tpath.exists():
                        tpath.unlink()
                except OSError:
                    pass
                continue
            if not exec_res.outage and exec_res.rc == 0:
                packet_committed = True
            break
        finally:
            if not packet_committed:
                _unlink_packet(active_review_id)

    assert exec_res is not None
    if exec_res.outage or exec_res.rc != 0:
        trip_breaker(exec_res.outage or f"codex_nonzero_exit_{exec_res.rc}")
        err_detail = (exec_res.stderr or exec_res.stdout or "").strip()
        if exec_res.outage and err_detail and exec_res.outage not in err_detail:
            err_msg = f"{exec_res.outage}: {err_detail}"
        else:
            err_msg = (exec_res.outage or err_detail).strip()
        err_obj = {
            "ok": False,
            "review_id": active_review_id,
            "exit_code": exec_res.rc,
            "fallback": _fallback_reviewer(args.xhigh),
            "error": err_msg,
        }
        rio.print_cli_json(err_obj, pretty=args.pretty)
        return 2

    actual_sid = _find_session_id_for_review(active_review_id, launch_wall_ts) or (
        _unwrap_primary_session_id(used_resume_sid, cand_first_ts) if used_resume_sid else ""
    )
    if actual_sid and exec_res.has_verdict:
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
    rev.add_argument("--timeout", type=int, default=240)
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
