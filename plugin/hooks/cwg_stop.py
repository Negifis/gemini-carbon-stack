#!/usr/bin/env python3
"""Code Work Gate Stop hook: deterministic check, simplify, independent review, and finite closure enforcement."""

from __future__ import annotations

import json
import os
import pathlib
import re
import sys
import time
import urllib.parse
import uuid
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import codex_lane
import cwg_common as cwg
import gate_inbox
import runtime_io as rio

MAX_BLOCKS_PER_CANDIDATE = 3
MAX_BACKGROUND_WAITS = 4
MAX_REVIEW_ROUNDS = 3
MAX_CLOSURE_PASSES = 2

SUBAGENT_URI_RE = re.compile(
    r'"conversationId"\s*:\s*"(?P<cid>[A-Za-z0-9._-]{4,80})"'
    r'(?:.*?"logAbsoluteUri"\s*:\s*"(?P<uri>file:///[^"]+)")?',
    re.DOTALL,
)


def uri_to_path(uri: str) -> str:
    if not uri.startswith("file:///"):
        return uri
    parsed = urllib.parse.unquote(uri[len("file:///") :])
    if os.name == "nt" and len(parsed) >= 2 and parsed[1] == ":":
        return os.path.normpath(parsed)
    return os.path.normpath("/" + parsed)


def catch_up_unmeasured_changes(marker: dict[str, Any]) -> dict[str, Any]:
    """Verify current on-disk fingerprint of recorded durable paths right before evaluating Stop."""
    dpaths = cwg.durable_paths(marker.get("paths"))
    if not dpaths:
        return marker
    now_fp = cwg.content_fingerprint(dpaths)
    marks = list(marker.get("content_marks") or [])
    last_fp = marks[-1].get("fp") if marks and isinstance(marks[-1], dict) else None
    if now_fp != last_fp:
        now = time.time()
        marks.append({"ts": now, "fp": now_fp, "cause": "stop_catchup_unmeasured_edit"})
        updated = dict(marker)
        updated["content_marks"] = marks[-32:]
        updated["last_durable_ts"] = now
        updated["last_ts"] = now
        return updated
    return marker


def candidate_restored_to_clean_head(marker: dict[str, Any]) -> tuple[bool, str]:
    """Allow `no-change` on a persistent candidate ONLY if all recorded durable files match clean HEAD."""
    dpaths = cwg.durable_paths(marker.get("paths"))
    if not dpaths:
        return True, ""
    git_root = str(marker.get("git_root") or "")
    if not git_root or not os.path.isdir(git_root):
        return False, "outside git repository, durable edits cannot be proven restored"
    rc, out, _ = rio.run_git(
        git_root, ["status", "--porcelain=v1", "--"] + dpaths, timeout=4.0
    )
    if rc != 0:
        return False, "git status failed while checking restoration"
    if isinstance(out, str) and out.strip():
        dirty_names = ", ".join(pathlib.PurePosixPath(p).name for p in dpaths[:3])
        return False, f"durable candidate files remain modified in working tree ({dirty_names})"
    return True, ""


def read_checks_evidence(session: str, first_ts: float) -> dict[str, Any]:
    path = cwg.checks_ledger_path(session)
    checks: list[dict[str, Any]] = []
    skills_read: set[str] = set()
    if path.is_file():
        try:
            for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if not raw.strip():
                    continue
                rec = json.loads(raw)
                if not isinstance(rec, dict):
                    continue
                ts = float(rec.get("ts") or 0.0)
                if rec.get("kind") == "skill_read" and rec.get("skill"):
                    skills_read.add(str(rec["skill"]))
                elif rec.get("kind") == "check" and ts >= first_ts - 1.0:
                    checks.append(rec)
        except Exception:
            pass
    passed = [c for c in checks if c.get("passed")]
    failed = [c for c in checks if not c.get("passed")]
    latest_pass_ts = max((float(c.get("ts") or 0.0) for c in passed), default=0.0)
    latest_fail_ts = max((float(c.get("ts") or 0.0) for c in failed), default=0.0)
    return {
        "checks": checks,
        "passed_count": len(passed),
        "failed_count": len(failed),
        "latest_pass_ts": latest_pass_ts,
        "latest_fail_ts": latest_fail_ts,
        "skills_read": skills_read,
    }


def extract_subagent_final_texts(subagent_transcript_path: str | None) -> tuple[str, float, bool]:
    """Read subagent's own system-generated transcript (`send_message` + final `PLANNER_RESPONSE`)."""
    if not subagent_transcript_path:
        return "", 0.0, False
    steps = rio.read_transcript_steps(subagent_transcript_path, max_lines=500)
    if not steps:
        return "", 0.0, False
    chunks: list[str] = []
    last_ts = 0.0
    finished = False
    for st in steps:
        ts = rio.parse_iso_ts(st.get("created_at"))
        if ts:
            last_ts = max(last_ts, ts)
        if st.get("source") == "MODEL" and st.get("type") == "PLANNER_RESPONSE":
            tcs = st.get("tool_calls") or []
            for tc in tcs:
                if isinstance(tc, dict) and tc.get("name") == "send_message":
                    msg = str((tc.get("args") or {}).get("Message") or "").strip()
                    if msg:
                        chunks.append(msg)
                        finished = True
            content = str(st.get("content") or "").strip()
            if content and not tcs:
                chunks.append(content)
                finished = True
    return "\n\n".join(chunks), last_ts, finished


def scan_native_subagents(
    steps: list[dict[str, Any]],
    transcript_path: str | None,
    first_ts: float,
) -> dict[str, Any]:
    """Deterministically bind parent `invoke_subagent` calls to subagent system transcripts & messages."""
    brain_root: pathlib.Path | None = None
    if transcript_path:
        p = pathlib.Path(transcript_path).resolve()
        # .../<brain>/<conv-id>/.system_generated/logs/transcript.jsonl -> brain_root is parents[3]
        if len(p.parents) >= 4 and p.parents[1].name == ".system_generated":
            brain_root = p.parents[3]

    # Collect SYSTEM_MESSAGE deliveries keyed by sender conversationId
    delivered_by_sender: dict[str, list[tuple[float, str]]] = {}
    for st in steps:
        if st.get("source") == "SYSTEM" and st.get("type") == "SYSTEM_MESSAGE":
            m = rio.SUBAGENT_MSG_RE.search(str(st.get("content") or ""))
            if m:
                sender = m.group("sender")
                msg_ts = rio.parse_iso_ts(m.group("ts")) or rio.parse_iso_ts(st.get("created_at"))
                delivered_by_sender.setdefault(sender, []).append((msg_ts, m.group("body").strip()))

    simplify_passes: list[dict[str, Any]] = []
    simplify_failures: int = 0
    reviews: list[dict[str, Any]] = []
    review_failures: list[float] = []
    in_flight_subagents: list[str] = []

    for idx, st in enumerate(steps):
        if st.get("source") != "MODEL" or st.get("type") != "PLANNER_RESPONSE":
            continue
        call_ts = rio.parse_iso_ts(st.get("created_at"))
        if call_ts and call_ts < first_ts - 2.0:
            continue
        tcs = st.get("tool_calls") or []
        sub_calls = [
            tc for tc in tcs if isinstance(tc, dict) and tc.get("name") == "invoke_subagent"
        ]
        if not sub_calls:
            continue

        # Look ahead at immediate MODEL/GENERIC tool responses for conversationId / logAbsoluteUri
        generic_Cursor = idx + 1
        generic_blobs: list[str] = []
        while generic_Cursor < len(steps) and steps[generic_Cursor].get("type") == "GENERIC":
            generic_blobs.append(str(steps[generic_Cursor].get("content") or ""))
            generic_Cursor += 1

        for pos, tc in enumerate(sub_calls):
            args = tc.get("args") if isinstance(tc.get("args"), dict) else {}
            tname = str(args.get("TypeName") or "").strip()
            base_tname = tname.rsplit(":", 1)[-1]
            role_lower = str(args.get("Role") or "").strip().lower()
            is_simplify_subagent = (base_tname == cwg.SIMPLIFY_REVIEWER) or (
                base_tname == "research" and "simplify" in role_lower
            )
            model_arg = str(args.get("Model") or "inherit").strip()
            blob = generic_blobs[pos] if pos < len(generic_blobs) else ("\n".join(generic_blobs))
            sm = SUBAGENT_URI_RE.search(blob)
            if not sm:
                if "error" in blob.lower() or "failed" in blob.lower():
                    if is_simplify_subagent:
                        simplify_failures += 1
                    elif base_tname in cwg.NATIVE_REVIEWERS:
                        review_failures.append(call_ts or time.time())
                continue

            cid = sm.group("cid")
            sub_tp = uri_to_path(sm.group("uri")) if sm.group("uri") else ""
            if not sub_tp and brain_root:
                cand = brain_root / cid / ".system_generated" / "logs" / "transcript.jsonl"
                if cand.exists():
                    sub_tp = str(cand)

            sub_text, sub_end_ts, sub_done = extract_subagent_final_texts(sub_tp)
            delivered = delivered_by_sender.get(cid) or []
            if delivered:
                sub_done = True
                deliv_ts, deliv_body = delivered[-1]
                sub_end_ts = max(sub_end_ts, deliv_ts)
                if deliv_body not in sub_text:
                    sub_text = (sub_text + "\n" + deliv_body).strip()

            if not sub_done:
                in_flight_subagents.append(f"{tname}:{cid[:8]}")
                continue

            eff_launch_ts = call_ts or sub_end_ts or time.time()
            eff_end_ts = max(eff_launch_ts, sub_end_ts or eff_launch_ts)

            if is_simplify_subagent:
                if sub_text.strip():
                    simplify_passes.append({"ts": eff_end_ts, "cid": cid, "text": sub_text[:300]})
                else:
                    simplify_failures += 1

            elif base_tname in cwg.NATIVE_REVIEWERS:
                cm = cwg.CLOSURE_LINE_RE.search(sub_text)
                vm = cwg.VERDICT_LINE_RE.search(sub_text)
                if cm:
                    reviews.append(
                        {
                            "engine": "native",
                            "reviewer": base_tname,
                            "cid": cid,
                            "kind": "closure",
                            "verdict": cm.group(1).upper(),
                            "launch_ts": eff_launch_ts,
                            "verdict_ts": eff_end_ts,
                            "xhigh": base_tname == cwg.XHIGH_NATIVE_REVIEWER,
                            "model": model_arg,
                        }
                    )
                elif vm:
                    reviews.append(
                        {
                            "engine": "native",
                            "reviewer": base_tname,
                            "cid": cid,
                            "kind": "ordinary",
                            "verdict": vm.group(1).upper(),
                            "launch_ts": eff_launch_ts,
                            "verdict_ts": eff_end_ts,
                            "xhigh": base_tname == cwg.XHIGH_NATIVE_REVIEWER,
                            "model": model_arg,
                        }
                    )
                else:
                    review_failures.append(eff_end_ts)

    return {
        "simplify_passes": simplify_passes,
        "simplify_failures": simplify_failures,
        "reviews": reviews,
        "review_failures": review_failures,
        "in_flight_subagents": in_flight_subagents,
    }


def is_review_fresh(review: dict[str, Any], marker: dict[str, Any]) -> bool:
    """An APPROVED or READY review is fresh iff current bytes match bytes present when the review launched."""
    marks = [m for m in (marker.get("content_marks") or []) if isinstance(m, dict)]
    if not marks:
        return True
    launch_ts = float(review.get("launch_ts") or 0.0)

    # INVARIANT: A reviewer only saw content that existed at or before `launch_ts` (never edits during/after review).
    covered_fps = {
        m.get("fp")
        for m in marks
        if not m.get("unknown")
        and m.get("fp") is not None
        and float(m.get("ts") or 0.0) <= launch_ts
    }
    for m in marks:
        mts = float(m.get("ts") or 0.0)
        if m.get("unknown") and mts > launch_ts:
            return False
    current_mark = marks[-1]
    if current_mark.get("unknown") or current_mark.get("fp") is None:
        return False
    if current_mark.get("fp") not in covered_fps:
        return False
    return True


def validate_candidate_closure(
    receipt: dict[str, Any] | None,
    marker: dict[str, Any],
    checks_ev: dict[str, Any],
    sub_ev: dict[str, Any],
    codex_reviews: list[dict[str, Any]],
) -> tuple[bool, str]:
    wclass = cwg.candidate_class(marker)
    floor = cwg.candidate_floor(marker)
    small = cwg.is_small_edit(marker)

    if receipt is None:
        if wclass == cwg.WORK_OPERATIONAL:
            return False, "missing terminal `[gate] operational: <pre-check>; <verified effect>` receipt on last line"
        return False, f"missing terminal `[gate] verified: {floor}; <candidate and checks>` receipt on last line"

    rkind = receipt.get("kind")
    if rkind == "misplaced":
        return False, "`[gate]` receipt must be the very last non-empty line of the final message"
    if rkind == "malformed":
        return False, f"malformed `[gate]` receipt; expected `[gate] {receipt.get('expected')}`"

    if wclass == cwg.WORK_OPERATIONAL:
        if rkind in ("operational", "no-change"):
            return True, rkind
        if rkind == "verified":
            # Allowed when an operational command intentionally wrote untracked external artifacts
            pass
        else:
            return False, f"OPERATIONAL candidate cannot close with `{rkind}`"

    if wclass == cwg.WORK_PERSISTENT:
        if rkind == "operational":
            return False, "PERSISTENT candidate modified durable files and cannot close as `operational`"
        if rkind == "no-change":
            restored, why = candidate_restored_to_clean_head(marker)
            if not restored:
                return False, f"`no-change` rejected: {why}"
            return True, "no-change"

    # Evaluate PERSISTENT closure (`verified`, `pr-ready`, `draft-blocked`)
    declared_risk = str(receipt.get("risk") or floor).upper()
    if rkind == "verified":
        if cwg.RISK_ORDER.get(declared_risk, -1) < cwg.RISK_ORDER.get(floor, 0):
            return (
                False,
                f"declared risk `{declared_risk}` is below candidate path risk floor `{floor}`",
            )
    effective_risk = cwg.max_risk([floor, declared_risk])

    # 1. Deterministic Check Verification (STANDARD / HIGH / XHIGH)
    if effective_risk in ("STANDARD", "HIGH", "XHIGH") and rkind in ("verified", "pr-ready"):
        last_durable = float(marker.get("last_durable_ts") or marker.get("first_ts") or 0.0)
        if len(checks_ev["checks"]) == 0:
            return (
                False,
                f"{effective_risk} candidate has zero executed verification/test commands recorded in runtime",
            )
        if checks_ev["latest_fail_ts"] > checks_ev["latest_pass_ts"]:
            return (
                False,
                "latest validation/test command failed with no subsequent passing verification run",
            )
        if checks_ev["passed_count"] == 0 or checks_ev["latest_pass_ts"] < last_durable - 1.0:
            return (
                False,
                "last passing test/verification command ran BEFORE the latest file edit; re-verify current bytes",
            )

    # 2. Proportionate Simplify Verification (non-small STANDARD, HIGH, XHIGH)
    needs_simplify = (effective_risk in ("HIGH", "XHIGH")) or (
        effective_risk == "STANDARD" and not small
    )
    simplify_ok = len(sub_ev["simplify_passes"]) >= 1
    simplify_exhausted = sub_ev["simplify_failures"] >= 2
    if needs_simplify and not simplify_ok:
        if not (rkind == "draft-blocked" and simplify_exhausted):
            return (
                False,
                f"{effective_risk} candidate requires 1 completed `{cwg.SIMPLIFY_REVIEWER}` subagent pass before closure",
            )

    # 3. Independent Adversarial Review Verification (HIGH / XHIGH, plus any invoked review on lower risks)
    all_reviews = sorted(
        list(sub_ev["reviews"]) + list(codex_reviews),
        key=lambda r: float(r.get("verdict_ts") or 0.0),
    )
    ordinary_reviews = [r for r in all_reviews if r.get("kind") == "ordinary"]
    closure_reviews = [r for r in all_reviews if r.get("kind") == "closure"]

    if len(ordinary_reviews) > MAX_REVIEW_ROUNDS:
        return False, f"ordinary adversarial review exceeded MAX_REVIEW_ROUNDS={MAX_REVIEW_ROUNDS}"
    if len(closure_reviews) > MAX_CLOSURE_PASSES:
        return False, f"closure validation exceeded MAX_CLOSURE_PASSES={MAX_CLOSURE_PASSES}"

    # Normalize early ESCALATE (< round 3) as REVISE per bounded 3-round protocol
    norm_ordinary: list[tuple[dict[str, Any], str]] = []
    for idx, rev in enumerate(ordinary_reviews, start=1):
        v = str(rev.get("verdict") or "")
        if v == "ESCALATE" and idx < MAX_REVIEW_ROUNDS:
            v = "REVISE"
        norm_ordinary.append((rev, v))

    for earlier_rev, earlier_v in norm_ordinary[:-1]:
        if earlier_v == "APPROVED" and is_review_fresh(earlier_rev, marker):
            if effective_risk != "XHIGH" or earlier_rev.get("xhigh"):
                return False, "review rounds continued unnecessarily after a current terminal APPROVED"

    latest_ord_rev, latest_ord_verdict = norm_ordinary[-1] if norm_ordinary else (None, "")
    latest_cls_rev = closure_reviews[-1] if closure_reviews else None
    latest_cls_verdict = str(latest_cls_rev.get("verdict") or "") if latest_cls_rev else ""

    breaker_open = bool(codex_lane.breaker_status().get("tripped"))
    review_unavailable = (len(sub_ev["review_failures"]) >= 2) or (
        breaker_open and len(sub_ev["review_failures"]) >= 1
    )

    if rkind == "verified":
        if latest_ord_verdict and latest_ord_verdict != "APPROVED":
            return False, f"invoked adversarial review ended in `{latest_ord_verdict}`, not `APPROVED`"
        if effective_risk in ("HIGH", "XHIGH"):
            if latest_ord_verdict != "APPROVED" or latest_ord_rev is None:
                return (
                    False,
                    f"{effective_risk} candidate lacks an independent `VERDICT: APPROVED` from Codex lane or `{cwg.XHIGH_NATIVE_REVIEWER if effective_risk == 'XHIGH' else 'adversarial-reviewer'}`",
                )
            if not is_review_fresh(latest_ord_rev, marker):
                return (
                    False,
                    f"{effective_risk} candidate's `APPROVED` verdict is stale: durable candidate content changed after review",
                )
            if effective_risk == "XHIGH" and not latest_ord_rev.get("xhigh"):
                return (
                    False,
                    f"XHIGH candidate's `APPROVED` verdict came from standard lane (`{latest_ord_rev.get('engine')}`), not XHIGH (`codex --xhigh` or `{cwg.XHIGH_NATIVE_REVIEWER}`)",
                )
        return True, "verified"

    if rkind == "pr-ready":
        if latest_ord_verdict != "ESCALATE":
            return False, "`pr-ready` requires round-3 `VERDICT: ESCALATE` followed by `CLOSURE_VALIDATION: READY`"
        if latest_cls_verdict != "READY" or latest_cls_rev is None or not is_review_fresh(latest_cls_rev, marker):
            return False, "`pr-ready` lacks fresh `CLOSURE_VALIDATION: READY`"
        return True, "pr-ready"

    if rkind == "draft-blocked":
        if latest_cls_verdict == "BLOCKED" and latest_cls_rev and is_review_fresh(latest_cls_rev, marker):
            return True, "draft-blocked"
        if review_unavailable or simplify_exhausted:
            return True, "draft-blocked"
        return (
            False,
            "`draft-blocked` requires fresh `CLOSURE_VALIDATION: BLOCKED` after round-3 ESCALATE, or exhausted review/simplify lanes",
        )

    return False, f"unsupported receipt kind `{rkind}`"


def retire_candidate(
    session: str,
    marker_file: pathlib.Path,
    state_file: pathlib.Path,
    state: dict[str, Any],
    receipt_summary: str,
) -> None:
    try:
        if marker_file.exists():
            marker_file.unlink()
    except OSError:
        cur = rio.read_json(marker_file, default={}) or {}
        cur["closed"] = True
        rio.write_json(marker_file, cur)

    state.update(
        {
            "blocks": 0,
            "waits": 0,
            "closed_ts": time.time(),
            "last_receipt": receipt_summary,
            "block_nonce": "",
        }
    )
    rio.write_json(state_file, state)
    cwg.clear_claim(session)


def format_block_message(
    reason: str,
    block_num: int,
    marker: dict[str, Any],
    session: str,
    nonce: str,
) -> str:
    wclass = cwg.candidate_class(marker)
    floor = cwg.candidate_floor(marker)
    small = cwg.is_small_edit(marker)
    inbox_script = rio.normalize_path(rio.plugin_root() / "hooks" / "gate_inbox.py")
    codex_script = rio.normalize_path(rio.plugin_root() / "hooks" / "codex_lane.py")

    if wclass == cwg.WORK_OPERATIONAL:
        guidance = (
            "Для OPERATIONAL-работы завершите ответ последней строкой:\n"
            "`[gate] operational: <предпроверка>; <подтверждённый эффект>`\n"
            "или `[gate] no-change: <причина>`, если изменений не произошло."
        )
    else:
        reqs = cwg.receipt_requirements_summary(floor, small)
        guidance = (
            f"Кандидат `PERSISTENT` (path floor `{floor}`). Обязательные условия: {reqs}.\n"
            f"- Для внешнего ревью HIGH/XHIGH сначала проверьте `python -X utf8 \"{codex_script}\" check`; "
            f"если доступно — запустите `python -X utf8 \"{codex_script}\" review --summary \"...\"` "
            f"{'--xhigh ' if floor == 'XHIGH' else ''}(либо при открытом circuit breaker вызовите субагента "
            f"`{'adversarial-reviewer-xhigh' if floor == 'XHIGH' else 'adversarial-reviewer'}`).\n"
            f"- Завершите финальный ответ строкой `[gate] verified: {floor}; <кандидат и решающие проверки>`."
        )

    return (
        f"[Code Work Gate] Остановка заблокирована ({block_num}/{MAX_BLOCKS_PER_CANDIDATE} для неизменённого кандидата): {reason}.\n"
        f"{guidance}\n"
        f"Если блокировка противоречит проверяемым фактам транскрипта, не уходите в цикл: зафиксируйте отчёт "
        f"`python -X utf8 \"{inbox_script}\" report --session \"{session}\" --nonce \"{nonce}\" "
        f"--block \"{reason[:120]}\" --facts \"<факты>\" --did \"<выполненные проверки>\"` "
        f"и закройте ответ строкой `[gate] anomaly-reported: <id>; <факт>`."
    )


def main() -> int:
    event = rio.parse_event_arg("Stop")
    payload, err = rio.read_hook_stdin()
    if err or payload is None:
        if err:
            rio.log_hook_event("hook-errors", "stdin_error", hook="cwg_stop", error=err)
        rio.emit_stop_allow()
        return 0

    try:
        term_reason = str(payload.get("terminationReason") or "")
        if term_reason in rio.NON_ENFORCEABLE_STOP_REASONS or payload.get("error"):
            rio.emit_stop_allow()
            return 0

        transcript_path = payload.get("transcriptPath")
        steps = rio.read_transcript_steps(transcript_path)
        if rio.is_subagent_session(transcript_path, steps=steps):
            rio.emit_stop_allow()
            return 0

        session = rio.session_key(payload)
        mfile = cwg.marker_path(session)
        if not mfile.is_file():
            # NO_CHANGE task: zero ceremony, immediate allow
            rio.emit_stop_allow()
            return 0

        raw_marker = rio.read_json(mfile, default=None)
        if not isinstance(raw_marker, dict) or raw_marker.get("closed"):
            rio.emit_stop_allow()
            return 0

        marker = catch_up_unmeasured_changes(raw_marker)
        if marker != raw_marker:
            rio.write_json(mfile, marker)

        if cwg.candidate_class(marker) == cwg.WORK_NO_CHANGE:
            rio.emit_stop_allow()
            return 0

        sfile = cwg.enforcement_state_path(session)
        state = rio.read_json(sfile, default={})
        if not isinstance(state, dict):
            state = {}

        ckey = cwg.candidate_key(marker)
        if state.get("candidate_key") != ckey:
            state["candidate_key"] = ckey
            state["blocks"] = 0
            state["waits"] = 0
            state["block_nonce"] = ""

        first_ts = float(marker.get("first_ts") or 0.0)
        assistant_msg = str(payload.get("lastAssistantMessage") or "") or rio.last_assistant_message(steps)
        receipt = cwg.parse_terminal_receipt(assistant_msg)

        # Handle anomaly-reported escape hatch first
        if receipt and receipt.get("kind") == "anomaly-reported":
            ok_anom, anom_note = gate_inbox.verify_anomaly_report(
                str(receipt.get("report_id") or ""),
                session=session,
                expected_nonce=state.get("block_nonce") or None,
            )
            if ok_anom:
                retire_candidate(session, mfile, sfile, state, f"anomaly-reported:{anom_note}")
                rio.log_hook_event("gate-events", "close", session=session, receipt="anomaly-reported", report=anom_note)
                rio.emit_stop_allow()
                return 0
            valid, reason = False, anom_note
        else:
            checks_ev = read_checks_evidence(session, first_ts)
            sub_ev = scan_native_subagents(steps, transcript_path, first_ts)
            codex_revs = codex_lane.scan_verified_codex_reviews(since_ts=first_ts)
            valid, reason = validate_candidate_closure(receipt, marker, checks_ev, sub_ev, codex_revs)

            if valid:
                rkind = str((receipt or {}).get("kind") or "verified")
                retire_candidate(session, mfile, sfile, state, rkind)
                rio.log_hook_event(
                    "gate-events",
                    "close",
                    session=session,
                    receipt=rkind,
                    floor=cwg.candidate_floor(marker),
                )
                rio.emit_stop_allow()
                return 0

            # Allow turn to yield without consuming block budget if background tasks or subagents are still running
            fully_idle = payload.get("fullyIdle", True)
            in_flight = list(sub_ev.get("in_flight_subagents") or [])
            waits = int(state.get("waits") or 0)
            if (fully_idle is False or in_flight) and waits < MAX_BACKGROUND_WAITS:
                state["waits"] = waits + 1
                rio.write_json(sfile, state)
                rio.log_hook_event(
                    "gate-events",
                    "background_wait",
                    session=session,
                    waits=waits + 1,
                    fully_idle=fully_idle,
                    in_flight=in_flight,
                )
                rio.emit_stop_allow()
                return 0

        blocks = int(state.get("blocks") or 0)
        if blocks >= MAX_BLOCKS_PER_CANDIDATE:
            retire_candidate(session, mfile, sfile, state, f"exhausted:{reason[:100]}")
            rio.log_hook_event("gate-events", "exhausted", session=session, reason=reason)
            rio.emit_stop_allow()
            return 0

        nonce = uuid.uuid4().hex[:12]
        state["blocks"] = blocks + 1
        state["last_block_reason"] = reason
        state["last_block_ts"] = time.time()
        state["block_nonce"] = nonce
        rio.write_json(sfile, state)
        rio.log_hook_event(
            "gate-events",
            "block",
            session=session,
            block=blocks + 1,
            reason=reason,
            floor=cwg.candidate_floor(marker),
        )
        msg = format_block_message(
            reason=reason,
            block_num=blocks + 1,
            marker=marker,
            session=session,
            nonce=nonce,
        )
        rio.emit_stop_continue(msg)
    except Exception as exc:
        rio.log_hook_event(
            "hook-errors",
            "exception",
            hook="cwg_stop",
            event=event,
            error=f"{type(exc).__name__}:{exc}",
        )
        rio.emit_stop_allow()
    return 0


if __name__ == "__main__":
    sys.exit(main())
