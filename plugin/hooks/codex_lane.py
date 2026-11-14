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
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cwg_common as cwg
import runtime_io as rio

BREAKER_TTL_SECONDS = 1800  # 30 minutes cooldown after quota/auth/capacity outage
PACKET_TTL_SECONDS = 86400

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
    matched: list[str] = []
    for mf in rio.state_dir("gate", "markers").glob("*.json"):
        mdata = rio.read_json(mf, default=None)
        if not isinstance(mdata, dict) or mdata.get("closed"):
            continue
        mroot = rio.fold_path(str(mdata.get("git_root") or mdata.get("cwd") or ""))
        if mroot == target_root and mdata.get("session"):
            matched.append(str(mdata["session"]))
    return matched[0] if len(matched) == 1 else ""


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
    sweep_old_packets()
    return pkt


def sweep_old_packets() -> None:
    cutoff = time.time() - PACKET_TTL_SECONDS
    for p in packets_dir().glob("*.json"):
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
    user_texts: list[str] = []
    assistant_texts: list[tuple[float, str]] = []
    effort = ""
    model = ""
    session_id = ""
    started_ts = 0.0
    completed_ts = 0.0

    for rec in records:
        rec_ts = rio.parse_iso_ts(rec.get("timestamp"))
        rtype = rec.get("type")
        payload = rec.get("payload") if isinstance(rec.get("payload"), dict) else {}

        if rtype == "session_meta":
            session_id = str(payload.get("id") or payload.get("session_id") or session_id)
            started_ts = started_ts or rec_ts or rio.parse_iso_ts(payload.get("timestamp"))
        elif rtype == "turn_context":
            effort = str(payload.get("effort") or effort).lower()
            model = str(payload.get("model") or model)
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
                    user_texts.append(joined)
                elif role == "assistant":
                    assistant_texts.append((rec_ts or rollout_file.stat().st_mtime, joined))
        elif rtype == "event_msg" and payload.get("type") == "task_complete":
            completed_ts = rec_ts or rio.parse_iso_ts(payload.get("completed_at")) or rollout_file.stat().st_mtime
            last_msg = payload.get("last_agent_message")
            if isinstance(last_msg, str) and last_msg.strip():
                assistant_texts.append((completed_ts, last_msg.strip()))

    if not started_ts:
        try:
            started_ts = rollout_file.stat().st_mtime
        except OSError:
            started_ts = 0.0
    return {
        "path": str(rollout_file),
        "session_id": session_id,
        "effort": effort,
        "model": model,
        "started_ts": started_ts,
        "completed_ts": completed_ts or (assistant_texts[-1][0] if assistant_texts else started_ts),
        "user_blob": "\n".join(user_texts),
        "assistant_messages": assistant_texts,
    }


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

    root = codex_sessions_dir()
    if not root.is_dir():
        return []

    results: list[dict[str, Any]] = []
    min_mtime = max(0.0, since_ts - 5.0)
    candidates: list[tuple[float, pathlib.Path]] = []
    for rf in root.rglob("rollout-*.jsonl"):
        try:
            mt = rf.stat().st_mtime
            if mt >= min_mtime:
                candidates.append((mt, rf))
        except OSError:
            continue
    candidates.sort(key=lambda pair: pair[0])

    for _, rf in candidates[-40:]:
        parsed = _extract_rollout_texts_and_meta(rf)
        if not parsed:
            continue
        user_blob = parsed["user_blob"]
        matched_ids = REVIEW_ID_RE.findall(user_blob)
        bound_packet = None
        for rid in matched_ids:
            if rid in known_packets:
                bound_packet = known_packets[rid]
                break
        if bound_packet is None:
            continue

        # Inspect final assistant messages in this rollout for VERDICT or CLOSURE_VALIDATION
        verdict = None
        kind = None
        verdict_ts = parsed["completed_ts"]
        for msg_ts, msg in reversed(parsed["assistant_messages"]):
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
            pkt_ts = float(bound_packet.get("created_ts") or parsed["started_ts"] or 0.0)
            eff = parsed["effort"] or bound_packet.get("effort") or "high"
            results.append(
                {
                    "engine": "codex",
                    "review_id": bound_packet["review_id"],
                    "session_id": parsed["session_id"],
                    "kind": kind,
                    "verdict": verdict,
                    "launch_ts": pkt_ts,
                    "verdict_ts": max(pkt_ts, float(verdict_ts or pkt_ts)),
                    "xhigh": eff == "xhigh",
                    "model": parsed["model"],
                    "effort": eff,
                    "rollout_path": parsed["path"],
                }
            )
    return results


def build_adversarial_prompt(
    review_id: str,
    scope_summary: str,
    diff_text: str,
    phase: str,
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
    return (
        f"REVIEW_ID: {review_id}\n"
        "ROLE: Independent Adversarial Code Reviewer (Read-Only).\n"
        "RULES:\n"
        "1. Do NOT modify any files. Inspect repository files directly if needed for context.\n"
        "2. Verify invariants, failure paths, security boundaries, concurrency, and test coverage.\n"
        "3. Separate confirmed defects ([HIGH]/[MEDIUM]) from non-blocking observations.\n"
        f"4. {verdict_rule}\n\n"
        f"CANDIDATE SUMMARY:\n{scope_summary}\n\n"
        f"GIT DIFF SNAPSHOT:\n{diff_text[:32000]}\n"
    )


def cmd_review(args: argparse.Namespace) -> int:
    health = check_health()
    if not health.get("available"):
        print(json.dumps(health, ensure_ascii=False, indent=2))
        return 2

    cwd = os.path.abspath(args.cwd or os.getcwd())
    effort = "xhigh" if args.xhigh else "high"
    phase = "closure" if args.closure else "ordinary"
    review_id = args.review_id or f"cwg-{uuid.uuid4().hex[:12]}"

    diff_text = ""
    if args.diff_file and os.path.isfile(args.diff_file):
        diff_text = pathlib.Path(args.diff_file).read_text(encoding="utf-8", errors="replace")
    else:
        rc, out, _ = rio.run_git(cwd, ["diff", "HEAD"], timeout=10.0)
        if rc == 0 and isinstance(out, str) and out.strip():
            diff_text = out
        else:
            rc2, out2, _ = rio.run_git(cwd, ["status", "--short"], timeout=5.0)
            diff_text = str(out2 or "")

    prompt = build_adversarial_prompt(
        review_id=review_id,
        scope_summary=args.summary or "Review current repository candidate changes.",
        diff_text=diff_text,
        phase=phase,
    )
    record_packet(
        review_id=review_id,
        prompt_text=prompt,
        cwd=cwd,
        effort=effort,
        phase=phase,
        session=args.session or "",
    )

    cmd = [
        health["binary"],
        "exec",
        "--skip-git-repo-check",
        "-s",
        "read-only",
        "-C",
        cwd,
        "-c",
        "mcp_servers={}",
        "-c",
        f'model_reasoning_effort="{effort}"',
        "--disable",
        "codex_hooks",
    ]
    if args.model:
        cmd.extend(["-m", args.model])
    cmd.append("-")  # Read prompt cleanly from stdin bytes and close EOF immediately

    kw = rio.subprocess_kwargs()
    kw.pop("stdin", None)
    try:
        proc = subprocess.run(
            cmd,
            input=prompt.encode("utf-8"),
            timeout=float(args.timeout),
            **kw,
        )
    except subprocess.TimeoutExpired:
        trip_breaker(f"codex_exec_timeout_{args.timeout}s")
        print(
            json.dumps(
                {
                    "ok": False,
                    "review_id": review_id,
                    "fallback": "adversarial-reviewer-xhigh" if args.xhigh else "adversarial-reviewer",
                    "error": f"timeout_after_{args.timeout}s",
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 3
    except Exception as exc:
        trip_breaker(f"codex_exec_error:{type(exc).__name__}")
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 3

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
    if outage or proc.returncode != 0:
        trip_breaker(outage or f"codex_nonzero_exit_{proc.returncode}")
        print(
            json.dumps(
                {
                    "ok": False,
                    "review_id": review_id,
                    "exit_code": proc.returncode,
                    "fallback": "adversarial-reviewer-xhigh" if args.xhigh else "adversarial-reviewer",
                    "error": (outage or stderr_text[-400:] or stdout_text[-400:]).strip(),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 2

    sys.stdout.write(
        f"REVIEW_ID: {review_id}\n"
        f"ENGINE: codex ({effort})\n"
        "--- CODEX REVIEW OUTPUT ---\n"
        f"{stdout_text.strip()}\n"
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
    rev.add_argument("--xhigh", action="store_true")
    rev.add_argument("--closure", action="store_true")
    rev.add_argument("--timeout", type=int, default=240)

    args = parser.parse_args()
    if args.subcommand == "check":
        res = check_health()
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("available") else 1
    if args.subcommand == "status":
        print(
            json.dumps(
                {
                    "breaker": breaker_status(),
                    "binary": find_codex_binary(),
                    "sessions_dir_exists": codex_sessions_dir().is_dir(),
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
