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
    rio.write_json(packets_dir() / f"{rio.safe_key(review_id)}.json", pkt)
    sweep_expired_gate_files()
    return pkt


def sweep_expired_gate_files() -> None:
    cutoff = time.time() - PACKET_TTL_SECONDS
    for base_dir in (packets_dir(), threads_dir()):
        for p in base_dir.glob("*.json"):
            try:
                if p.stat().st_mtime < cutoff:
                    p.unlink()
            except OSError:
                pass


def detect_outage_from_output(output_text: str, exit_code: int = 0) -> str | None:
    if not output_text and exit_code == 0:
        return None
    if exit_code == 0 and (
        cwg.VERDICT_LINE_RE.search(output_text or "") or cwg.CLOSURE_LINE_RE.search(output_text or "")
    ):
        return None
    for pat in OUTAGE_PATTERNS:
        m = pat.search(output_text or "")
        if m:
            return m.group(0)
    return None


def record_from_command(command_text: str, output_text: str, exit_code: int = 0) -> None:
    if "codex" not in (command_text or "").lower():
        return
    reason = detect_outage_from_output(output_text, exit_code=exit_code)
    if reason:
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
                "reason": f"codex_not_logged_in: {combined[:160]}",
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
    started_ts = 0.0
    completed_ts = 0.0
    last_msg_ts = 0.0

    for rec in records:
        rec_ts = rio.parse_iso_ts(rec.get("timestamp"))
        rtype = rec.get("type")
        payload = rec.get("payload") if isinstance(rec.get("payload"), dict) else {}

        if rtype == "session_meta":
            session_id = str(payload.get("id") or payload.get("session_id") or session_id)
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
        parsed = _extract_rollout_texts_and_meta(rf)
        if not parsed:
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
                cm = cwg.CLOSURE_LINE_RE.search(msg)
                if cm:
                    kind = "closure"
                    verdict = cm.group(1).upper()
                    verdict_ts = msg_ts or verdict_ts
                    break
                vm = cwg.VERDICT_LINE_RE.search(msg)
                if vm:
                    kind = "ordinary"
                    verdict = vm.group(1).upper()
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
        return explicit_resume.strip()

    saved = rio.read_json(_thread_state_path(session, git_root), default=None)
    if isinstance(saved, dict) and saved.get("session_id"):
        saved_cand_ts = float(saved.get("candidate_first_ts") or 0.0)
        if candidate_first_ts > 0.0:
            if abs(saved_cand_ts - candidate_first_ts) < 1.0:
                return str(saved["session_id"])
        # INVARIANT: When no candidate marker is open (NO_CHANGE / manual review), reuse same-repo thread for 1h.
        elif saved_cand_ts <= 0.0 and (time.time() - float(saved.get("updated_ts") or 0.0)) < 3600.0:
            return str(saved["session_id"])

    if session and candidate_first_ts > 0.0:
        prior = scan_verified_codex_reviews(
            since_ts=candidate_first_ts,
            session=session,
            git_root=git_root,
        )
        for prev in reversed(prior):
            sid = str(prev.get("session_id") or "").strip()
            if sid:
                return sid
    return ""


def _find_session_id_for_review(review_id: str, since_ts: float) -> str:
    if not review_id:
        return ""
    for rf in _recent_rollout_files(since_ts, limit=20, newest_first=True):
        parsed = _extract_rollout_texts_and_meta(rf)
        if not parsed or not parsed.get("session_id"):
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
            "Conclude with an exact standalone line:\n"
            "CLOSURE_VALIDATION: READY\n"
            "or\n"
            "CLOSURE_VALIDATION: BLOCKED\n"
            "Choose BLOCKED only if concrete correctness, security, data-loss, or contract regressions remain."
        )
    else:
        verdict_rule = (
            "Conclude with an exact standalone line:\n"
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


def _exec_codex_once(
    cmd: list[str],
    prompt: str,
    cwd: str,
    timeout: float,
    review_id: str,
    xhigh: bool,
) -> _CodexExecResult | None:
    kw = rio.subprocess_kwargs()
    kw.pop("stdin", None)
    try:
        proc = subprocess.run(
            cmd,
            input=prompt.encode("utf-8"),
            cwd=cwd,
            timeout=timeout,
            **kw,
        )
    except subprocess.TimeoutExpired:
        trip_breaker(f"codex_exec_timeout_{int(timeout)}s")
        print(
            json.dumps(
                {
                    "ok": False,
                    "review_id": review_id,
                    "fallback": "adversarial-reviewer-xhigh" if xhigh else "adversarial-reviewer",
                    "error": f"timeout_after_{int(timeout)}s",
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return None
    except Exception as exc:
        trip_breaker(f"codex_exec_error:{type(exc).__name__}")
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return None

    stdout_text = (proc.stdout or b"").decode("utf-8", errors="replace")
    stderr_text = (proc.stderr or b"").decode("utf-8", errors="replace")
    has_structured_verdict = bool(
        cwg.VERDICT_LINE_RE.search(stdout_text) or cwg.CLOSURE_LINE_RE.search(stdout_text)
    )
    combined = stdout_text + "\n" + stderr_text
    outage = (
        None
        if (proc.returncode == 0 and has_structured_verdict)
        else detect_outage_from_output(combined, exit_code=proc.returncode)
    )
    return _CodexExecResult(proc.returncode, stdout_text, stderr_text, has_structured_verdict, outage)


def cmd_review(args: argparse.Namespace) -> int:
    health = check_health()
    if not health.get("available"):
        print(json.dumps(health, ensure_ascii=False, indent=2))
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
    attempts = (resume_sid, "") if resume_sid else ("",)
    for attempt_idx, cur_resume_sid in enumerate(attempts):
        prompt = build_adversarial_prompt(
            review_id=review_id,
            scope_summary=scope_summary,
            diff_text=diff_text,
            phase=phase,
            is_resume=bool(cur_resume_sid),
        )
        record_packet(
            review_id=review_id,
            prompt_text=prompt,
            cwd=cwd,
            effort=effort,
            phase=phase,
            session=eff_session,
        )
        launch_wall_ts = time.time()
        cmd = _build_codex_exec_cmd(
            health["binary"],
            cwd=cwd,
            effort=effort,
            model=args.model,
            resume_session_id=cur_resume_sid,
        )
        exec_res = _exec_codex_once(
            cmd, prompt, cwd, float(args.timeout), review_id, args.xhigh
        )
        if exec_res is None:
            return 3
        used_resume_sid = cur_resume_sid
        # Graceful single fallback to a fresh session if resuming a deleted/unreadable thread UUID
        if (
            attempt_idx == 0
            and cur_resume_sid
            and exec_res.rc != 0
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
        break

    assert exec_res is not None
    if exec_res.outage or exec_res.rc != 0:
        trip_breaker(exec_res.outage or f"codex_nonzero_exit_{exec_res.rc}")
        print(
            json.dumps(
                {
                    "ok": False,
                    "review_id": review_id,
                    "exit_code": exec_res.rc,
                    "fallback": "adversarial-reviewer-xhigh" if args.xhigh else "adversarial-reviewer",
                    "error": (exec_res.outage or exec_res.stderr[-400:] or exec_res.stdout[-400:]).strip(),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 2

    actual_sid = _find_session_id_for_review(review_id, launch_wall_ts) or used_resume_sid
    if actual_sid:
        rio.write_json(
            _thread_state_path(eff_session, git_root),
            {
                "session_id": actual_sid,
                "last_review_id": review_id,
                "session": eff_session,
                "git_root": rio.normalize_path(git_root),
                "candidate_first_ts": cand_first_ts,
                "updated_ts": time.time(),
            },
        )

    session_mode = "resumed" if used_resume_sid else "new"
    sys.stdout.write(
        f"REVIEW_ID: {review_id}\n"
        f"SESSION_ID: {actual_sid}\n"
        f"SESSION_MODE: {session_mode}\n"
        f"ENGINE: codex ({effort})\n"
        "--- CODEX REVIEW OUTPUT ---\n"
        f"{exec_res.stdout.strip()}\n"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="codex_lane")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    sub.add_parser("check", help="Check Codex CLI availability, auth, and circuit breaker")
    sub.add_parser("status", help="Show circuit breaker and recent rollout status")
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

    args = parser.parse_args()
    if args.subcommand == "check":
        res = check_health()
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("available") else 1
    if args.subcommand == "status":
        sweep_expired_gate_files()
        print(
            json.dumps(
                {
                    "breaker": breaker_status(),
                    "binary": find_codex_binary(),
                    "sessions_dir_exists": codex_sessions_dir().is_dir(),
                    "active_threads": len(list(threads_dir().glob("*.json"))),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    if args.subcommand == "reset":
        reset_breaker()
        print(json.dumps({"reset": True}))
        return 0
    if args.subcommand == "review":
        return cmd_review(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
