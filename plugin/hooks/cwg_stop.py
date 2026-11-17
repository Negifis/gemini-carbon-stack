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
MAX_BACKGROUND_WAITS = 8
MAX_TOTAL_BACKGROUND_WAITS = 16
MAX_REVIEW_ROUNDS = 3
# SAFETY: Bound uncounted pre-simplify `REVISE`/`ESCALATE` rounds so broken loops cannot run unboundedly.
MAX_RAW_ORDINARY_ROUNDS = MAX_REVIEW_ROUNDS * 2
MAX_CLOSURE_PASSES = 2
MAX_WORKER_POST_REMINDERS = 2
_CLOSURE_PHASE_FLAG = "--phase closure"

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
        cwg.trim_content_marks(updated, marks)
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
    for rec in rio.read_jsonl(path):
        ts = float(rec.get("ts") or 0.0)
        if rec.get("kind") == "check" and ts >= first_ts - 1.0:
            checks.append(rec)
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
    }


_SYS_MSG_CLOSE_RE = re.compile(r"\s*</SYSTEM_MESSAGE>\s*\Z", re.IGNORECASE)


def _extract_subagent_timed_chunks(
    subagent_transcript_path: str | None,
    parent_cid: str = "",
) -> tuple[list[tuple[float, str, str, bool]], float, bool]:
    """Read subagent's own system transcript into timed `(ts, text, kind, is_signoff)` chunks."""
    if not subagent_transcript_path:
        return [], 0.0, False
    steps = rio.read_transcript_steps(subagent_transcript_path, max_lines=500)
    if not steps:
        return [], 0.0, False
    chunks: list[tuple[float, str, str, bool]] = []
    last_ts = 0.0
    finished = False
    just_sent_to_parent = False
    for idx, st in enumerate(steps):
        ts = rio.parse_iso_ts(st.get("created_at"))
        if ts:
            last_ts = max(last_ts, ts)
        stype = str(st.get("type") or "")
        if stype == "GENERIC":
            continue
        if st.get("source") != "MODEL" or stype != "PLANNER_RESPONSE":
            just_sent_to_parent = False
            continue
        tcs = st.get("tool_calls") or []
        if tcs:
            gen_steps = _collect_generic_results(steps, idx)
            sent_any = False
            only_parent_sends = True
            for pos, tc in enumerate(tcs):
                if not isinstance(tc, dict) or tc.get("name") != "send_message":
                    only_parent_sends = False
                    continue
                g_status, _, g_ts = gen_steps[pos] if pos < len(gen_steps) else ("", "", 0.0)
                if g_status == "ERROR":
                    only_parent_sends = False
                    continue
                targs = tc.get("args") if isinstance(tc.get("args"), dict) else {}
                recip = str(targs.get("Recipient") or "").strip()
                if parent_cid and recip and recip != parent_cid:
                    only_parent_sends = False
                    continue
                msg = str(targs.get("Message") or "").strip()
                if msg:
                    eff_send_ts = max(ts, g_ts) if g_ts > 0.0 else ts
                    chunks.append((eff_send_ts, msg, "send", False))
                    finished = True
                    sent_any = True
            just_sent_to_parent = sent_any and only_parent_sends
        else:
            content = str(st.get("content") or "").strip()
            if content:
                chunks.append((ts, content, "final", just_sent_to_parent))
                finished = True
            just_sent_to_parent = False
    return chunks, last_ts, finished


def _merge_subagent_chunks(
    sub_chunks: list[tuple[float, str, str, bool]],
    delivered: list[tuple[float, str]],
) -> list[tuple[float, str, str, bool]]:
    """Bind host `SYSTEM_MESSAGE` delivery timestamps to matching `send_message` chunks and merge unmatched deliveries."""
    merged: list[tuple[float, int, str, str, bool]] = []
    matched_sub: set[int] = set()
    sub_cursor = 0
    for d_idx, (dts, dbody) in enumerate(delivered):
        matched_idx: int | None = None
        for s_idx in range(sub_cursor, len(sub_chunks)):
            cts, cbody, ckind, _ = sub_chunks[s_idx]
            if ckind == "send" and cbody == dbody and (not cts or not dts or abs(cts - dts) < 300.0):
                matched_idx = s_idx
                sub_cursor = s_idx + 1
                break
        if matched_idx is not None:
            matched_sub.add(matched_idx)
            cts, cbody, ckind, csign = sub_chunks[matched_idx]
            eff_ts = dts if dts > 0.0 else cts
            merged.append((eff_ts, matched_idx * 2, cbody, ckind, csign))
        else:
            merged.append((dts, len(sub_chunks) * 2 + d_idx, dbody, "send", False))

    for s_idx, (cts, cbody, ckind, csign) in enumerate(sub_chunks):
        if s_idx not in matched_sub:
            merged.append((cts, s_idx * 2 + 1, cbody, ckind, csign))

    # INVARIANT: Propagate monotonic floor across missing (`0.0`) timestamps so causal step order is never inverted.
    by_seq = sorted(merged, key=lambda item: item[1])
    floor_ts = 0.0
    normalized: list[tuple[float, int, str, str, bool]] = []
    for ts_val, seq_val, body_val, kind_val, sign_val in by_seq:
        eff = ts_val if ts_val > 0.0 else floor_ts
        if eff > floor_ts:
            floor_ts = eff
        normalized.append((eff, seq_val, body_val, kind_val, sign_val))

    normalized.sort(key=lambda item: (item[0], item[1]))
    return [(ts_val, body_val, kind_val, sign_val) for ts_val, _, body_val, kind_val, sign_val in normalized]


def extract_subagent_final_texts(subagent_transcript_path: str | None) -> tuple[str, float, bool]:
    """Read subagent's own system-generated transcript (`send_message` + final `PLANNER_RESPONSE`)."""
    chunks, last_ts, finished = _extract_subagent_timed_chunks(subagent_transcript_path)
    return "\n\n".join(txt for _, txt, _, _ in chunks), last_ts, finished


SIMPLIFY_COMBINED_NAME_RE = re.compile(
    r"^(?:simplify(?:-reviewer)?|simp-all(?:-[0-9a-f]{2,4})?)(?:-r\d+)?$",
    re.IGNORECASE,
)
SYSTEM_SWARM_ERR_RE = re.compile(
    r'\[Message\]\s+timestamp=\S+\s+sender=system\b[^\n]*Swarm Worker \((?P<name>[A-Za-z0-9._-]+)\)[^\n]*with id "(?P<cid>[A-Za-z0-9._-]+)" encountered an error[^\n]*?:\s*(?P<err>.+)',
    re.IGNORECASE,
)
MODEL_FAILURE_RE = re.compile(
    r"(?:RESOURCE_EXHAUSTED|(?:out\s+of|insufficient|no)\s+quota|"
    r"quota[^\n]{0,30}(?:exceeded|exhausted|reached|depleted|0%)|"
    r"rate[ _-]limit|429\b|503\b|502\b|"
    r"model[^\n]{0,40}(?:unavailable|at\s+capacity|not\s+found|not\s+supported|invalid|unknown)|"
    r"(?:unknown|invalid|unsupported)\s+model|"
    r"overloaded|not\s+eligible|internal\s+server\s+error|deadline[ _-]exceeded|timed?\s*out)",
    re.IGNORECASE,
)
_is_verified_codex_cmd_outage = codex_lane.is_verified_codex_cmd_outage
BG_TASK_ID_RE = rio.BG_TASK_ID_RE
PRE_SIMPLIFY_REVIEW_ERR = (
    "adversarial review ran simultaneously with or before simplify lenses; "
    "complete all simplify lenses BEFORE launching adversarial review "
    "(or run `--closure` / `--phase closure` once simplify finishes)"
)


def _classify_simplify_worker(name: str, brief_or_role: str, output_text: str) -> tuple[str, str | None]:
    """Classify worker as ('lens', <lens>), ('combined', None), or ('other', None) in one pass."""
    parsed = cwg.parse_simplify_verdict(output_text or "")
    has_verdict = bool(parsed.get("verdict"))
    if parsed.get("has_explicit_all"):
        return ("combined", None) if has_verdict else ("other", None)

    explicit = list(parsed.get("explicit_lenses") or [])
    if len(explicit) == 1:
        return ("lens", explicit[0])
    if len(explicit) > 1:
        return ("combined", None) if has_verdict else ("other", None)

    name_lens = cwg.simplify_lens_from_worker_name(name)
    if name_lens:
        return ("lens", name_lens)

    if SIMPLIFY_COMBINED_NAME_RE.match((name or "").strip()):
        return ("combined", None) if has_verdict else ("other", None)

    if cwg.is_simplify_worker_name(name) or "simplify" in (brief_or_role or "").lower():
        low_brief = (brief_or_role or "").lower()
        matched = [lens for lens in cwg.SIMPLIFY_LENSES if re.search(rf"\b{lens}\b", low_brief)]
        if len(matched) == 1:
            return ("lens", matched[0])

    return ("other", None)


def _member_transcript_summary(member_tp: pathlib.Path | None, first_ts: float) -> dict[str, Any]:
    """Inspect a swarm member's system transcript for outputs, completion state, and model/runtime errors."""
    if member_tp is None or not member_tp.is_file():
        return {
            "exists": False,
            "outputs": [],
            "has_error": False,
            "error_ts": 0.0,
            "parked_or_done": False,
            "parked_ts": 0.0,
            "start_ts": 0.0,
        }
    m_steps = rio.read_transcript_steps(str(member_tp), max_lines=600)
    if not m_steps:
        return {
            "exists": True,
            "outputs": [],
            "has_error": False,
            "error_ts": 0.0,
            "parked_or_done": False,
            "parked_ts": 0.0,
            "start_ts": 0.0,
        }

    outputs: list[tuple[float, str]] = []
    has_error = False
    error_ts = 0.0
    start_ts = rio.parse_iso_ts(m_steps[0].get("created_at"))

    for st in m_steps:
        ts = rio.parse_iso_ts(st.get("created_at"))
        stype = str(st.get("type") or "")
        sstatus = str(st.get("status") or "")
        scontent = str(st.get("content") or "")

        # SECURITY INVARIANT: Only model/turn failures count (never GENERIC tool-call errors or SYSTEM brief text).
        if stype == "ERROR_MESSAGE" or (
            st.get("source") == "MODEL" and stype != "GENERIC" and sstatus == "ERROR"
        ):
            if not ts or ts >= first_ts - 2.0:
                has_error = True
                error_ts = max(error_ts, ts or time.time())

        if st.get("source") == "MODEL" and stype == "PLANNER_RESPONSE":
            tcs = st.get("tool_calls") or []
            for tc in tcs:
                if isinstance(tc, dict) and tc.get("name") in ("post_message", "send_message"):
                    targs = tc.get("args") if isinstance(tc.get("args"), dict) else {}
                    txt = str(targs.get("text") or targs.get("Message") or "").strip()
                    if txt and (not ts or ts >= first_ts - 2.0):
                        outputs.append((ts or time.time(), txt))
            if scontent.strip() and not tcs and (not ts or ts >= first_ts - 2.0):
                outputs.append((ts or time.time(), scontent.strip()))

    last_st = m_steps[-1]
    last_type = str(last_st.get("type") or "")
    last_content = str(last_st.get("content") or "")
    prev_called_wait = len(m_steps) >= 2 and any(
        isinstance(tc, dict) and tc.get("name") == "swarm_wait"
        for tc in (m_steps[-2].get("tool_calls") or [])
    )
    parked_or_done = False
    if last_st.get("source") == "MODEL" and last_type == "PLANNER_RESPONSE" and not (last_st.get("tool_calls") or []):
        parked_or_done = True
    elif (
        last_type == "GENERIC"
        and str(last_st.get("status") or "") == "DONE"
        and (
            "waiting for a message" in last_content.lower()
            or "swarm_wait" in last_content.lower()
            or prev_called_wait
        )
    ):
        parked_or_done = True
    elif has_error:
        parked_or_done = True

    parked_ts = (rio.parse_iso_ts(last_st.get("created_at")) or error_ts) if parked_or_done else 0.0

    return {
        "exists": True,
        "outputs": outputs,
        "has_error": has_error,
        "error_ts": error_ts,
        "parked_or_done": parked_or_done,
        "parked_ts": parked_ts,
        "start_ts": start_ts,
    }


def _extract_json_dict(blob: str) -> dict[str, Any] | None:
    pos = blob.find("{")
    if pos < 0:
        return None
    try:
        obj = json.loads(blob[pos:])
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _collect_generic_results(steps: list[dict[str, Any]], planner_idx: int) -> list[tuple[str, str, float]]:
    g_cur = planner_idx + 1
    out: list[tuple[str, str, float]] = []
    while g_cur < len(steps) and steps[g_cur].get("type") == "GENERIC":
        g_st = steps[g_cur]
        g_txt = str(g_st.get("content") or "")
        g_err = str(g_st.get("error") or "").strip()
        if g_err and g_err not in g_txt:
            g_txt = f"{g_txt}\n{g_err}".strip()
        out.append((str(g_st.get("status") or ""), g_txt, rio.parse_iso_ts(g_st.get("created_at"))))
        g_cur += 1
    return out


def scan_swarm_activity(
    steps: list[dict[str, Any]],
    transcript_path: str | None,
    first_ts: float,
    round_start_msg_id: int = 0,
    current_diff_hash: str = "",
    cwd: str = "",
) -> dict[str, Any]:
    """Verify native Antigravity `swarm` workers (`members.json` + `board.jsonl` + member transcripts)."""
    sonnet_lenses: dict[str, float] = {}
    fallback_lenses: dict[str, float] = {}
    sonnet_lenses_end: dict[str, float] = {}
    fallback_lenses_end: dict[str, float] = {}
    sonnet_combined_ts = 0.0
    fallback_combined_ts = 0.0
    sonnet_combined_end_ts = 0.0
    fallback_combined_end_ts = 0.0
    simplify_launch_steps: set[int] = set()
    simplify_history: list[dict[str, Any]] = []
    simplify_events: list[dict[str, Any]] = []
    simplify_failures = 0
    reviews: list[dict[str, Any]] = []
    review_failures: list[float] = []
    in_flight_workers: list[str] = []
    opus_issue_verified = False
    opus_issue_ts = 0.0
    sonnet_issue_verified = False
    codex_cmd_failed = False
    codex_issue_ts = 0.0
    codex_issue_step = -1
    codex_timeout_seen = False
    aborted_codex_reviews: dict[str, float] = {}
    board_head = 0
    multi_lens_spoof = False
    multi_lens_spoof_ts = 0.0
    worker_last_activity: dict[str, float] = {}
    stalled_workers: list[dict[str, Any]] = []

    def _mark_opus_issue(ts_val: float) -> None:
        nonlocal opus_issue_verified, opus_issue_ts
        opus_issue_verified = True
        eff = ts_val or time.time()
        if opus_issue_ts <= 0.0 or eff < opus_issue_ts:
            opus_issue_ts = eff

    def _mark_codex_issue(ts_val: float, step_idx_val: int) -> None:
        nonlocal codex_cmd_failed, codex_issue_ts, codex_issue_step
        if not codex_cmd_failed:
            codex_cmd_failed = True
            codex_issue_ts = ts_val if ts_val > 0.0 else 0.0
            codex_issue_step = step_idx_val
            return
        if ts_val > 0.0 and (codex_issue_ts <= 0.0 or ts_val < codex_issue_ts):
            codex_issue_ts = ts_val
            codex_issue_step = step_idx_val
        elif ts_val == codex_issue_ts and step_idx_val >= 0 and (codex_issue_step < 0 or step_idx_val < codex_issue_step):
            codex_issue_step = step_idx_val

    def _record_model_failure(models: set[str], worker_name: str, ts_val: float) -> None:
        nonlocal sonnet_issue_verified, simplify_failures
        if any(cwg.OPUS_HIGH_MODEL in m for m in models):
            _mark_opus_issue(ts_val)
            review_failures.append(ts_val or time.time())
        if any(cwg.SONNET_HIGH_MODEL in m for m in models):
            sonnet_issue_verified = True
            simplify_failures += 1
        elif not models.isdisjoint(cwg.SIMPLIFY_FALLBACK_MODELS) and cwg.is_simplify_worker_name(worker_name):
            simplify_failures += 1

    requested_models: dict[str, set[str]] = {}
    model_switches: dict[str, list[tuple[float, str, int | None]]] = {}
    coord_call_events: list[tuple[float, str, int]] = []
    host_worker_errors: dict[tuple[str, str], float] = {}
    worker_add_step: dict[str, int] = {}
    pending_codex_tasks: dict[str, tuple[str, float]] = {}
    pending_bg_tasks: set[str] = set()
    idle_unkilled_workers: list[str] = []

    def _inspect_swarm_tool_result(
        tc: dict[str, Any],
        g_status: str,
        blob: str,
        call_ts: float,
        step_pos: int | None,
        allow_missing_avail: bool = True,
    ) -> None:
        nonlocal sonnet_issue_verified
        args = tc.get("args") if isinstance(tc.get("args"), dict) else {}
        action = str(args.get("action") or "").strip().lower()
        wname = str(args.get("name") or "").strip()
        req_model = str(args.get("model") or "").strip().lower()
        mdata = _extract_json_dict(blob)

        if wname and req_model:
            requested_models.setdefault(wname, set()).add(req_model)
        if action == "model" and wname and call_ts:
            model_switches.setdefault(wname, []).append((call_ts, f"[model-switch:{req_model}]", step_pos))

        if action == "models" and mdata is not None:
            avail = set(mdata.get("models") or [])
            quotas = mdata.get("quotas") or {}
            if avail and allow_missing_avail:
                if cwg.OPUS_HIGH_MODEL not in avail:
                    _mark_opus_issue(call_ts)
                if cwg.SONNET_HIGH_MODEL not in avail:
                    sonnet_issue_verified = True
            opus_q = str((quotas.get(cwg.OPUS_HIGH_MODEL) or {}).get("quota_remaining") or "")
            if opus_q in ("0%", "0"):
                _mark_opus_issue(call_ts)
            sonnet_q = str((quotas.get(cwg.SONNET_HIGH_MODEL) or {}).get("quota_remaining") or "")
            if sonnet_q in ("0%", "0"):
                sonnet_issue_verified = True

        err_detail = (str((mdata or {}).get("error") or "") + "\n" + blob).strip()
        json_err = bool(mdata and mdata.get("error"))
        is_err = (g_status == "ERROR") or json_err or (
            mdata is None and ("error" in blob.lower() or "failed" in blob.lower())
        )
        # INVARIANT: Only model/quota/availability failures count (never duplicate worker names or bad args).
        if is_err and req_model and MODEL_FAILURE_RE.search(err_detail):
            _record_model_failure({req_model}, wname, call_ts)

    if transcript_path and rio.has_prefix_slice_gap(steps):
        tail_first = (
            steps[1]
            if (len(steps) > 1 and steps[0].get("step_index") == 0)
            else (steps[0] if steps else None)
        )
        tail_idx = tail_first.get("step_index") if isinstance(tail_first, dict) else None
        tail_ts = rio.parse_iso_ts(tail_first.get("created_at")) if isinstance(tail_first, dict) else 0.0
        if isinstance(tail_idx, int) and tail_idx > 1 and (not tail_ts or tail_ts > first_ts - 2.0):
            # SAFETY: Recover early candidate swarm model/quota signals evicted from `transcript_full.jsonl` tail window via compact `transcript.jsonl` without shifting `steps` indices.
            compact_steps = rio.read_compact_transcript_steps(transcript_path, max_lines=16000)
            for p_idx, p_st in enumerate(compact_steps):
                s_idx = p_st.get("step_index")
                if not isinstance(s_idx, int) or s_idx <= 0 or s_idx >= tail_idx:
                    continue
                if p_st.get("source") == "SYSTEM":
                    p_sys_ts = rio.parse_iso_ts(p_st.get("created_at"))
                    if not p_sys_ts or p_sys_ts >= first_ts - 2.0:
                        for sm in SYSTEM_SWARM_ERR_RE.finditer(str(p_st.get("content") or "")):
                            if MODEL_FAILURE_RE.search(sm.group("err")):
                                key = (sm.group("name"), sm.group("cid"))
                                host_worker_errors[key] = max(host_worker_errors.get(key, 0.0), p_sys_ts or time.time())
                    continue
                if p_st.get("source") != "MODEL" or p_st.get("type") != "PLANNER_RESPONSE":
                    continue
                p_call_ts = rio.parse_iso_ts(p_st.get("created_at"))
                if p_call_ts and p_call_ts < first_ts - 2.0:
                    continue
                p_tcs = p_st.get("tool_calls") or []
                if not any(isinstance(tc, dict) and tc.get("name") == "swarm" for tc in p_tcs):
                    continue
                p_gen = _collect_generic_results(compact_steps, p_idx)
                for p_pos, p_tc in enumerate(p_tcs):
                    if not isinstance(p_tc, dict) or p_tc.get("name") != "swarm":
                        continue
                    g_status, blob, _ = p_gen[p_pos] if p_pos < len(p_gen) else ("", "", 0.0)
                    g_step = compact_steps[p_idx + 1 + p_pos] if (p_idx + 1 + p_pos) < len(compact_steps) else {}
                    trunc = g_step.get("truncated_fields") or []
                    _inspect_swarm_tool_result(
                        p_tc,
                        g_status,
                        blob,
                        p_call_ts,
                        None,
                        allow_missing_avail=("content" not in trunc),
                    )

    for idx, st in enumerate(steps):
        if st.get("source") == "SYSTEM":
            sys_ts = rio.parse_iso_ts(st.get("created_at"))
            sys_txt = str(st.get("content") or "")
            for tid in list(pending_bg_tasks):
                if f'Task id "{tid}" finished' in sys_txt or f'Task id "{tid}" was canceled' in sys_txt:
                    pending_bg_tasks.discard(tid)
            if not sys_ts or sys_ts >= first_ts - 2.0:
                for sm in SYSTEM_SWARM_ERR_RE.finditer(sys_txt):
                    if MODEL_FAILURE_RE.search(sm.group("err")):
                        key = (sm.group("name"), sm.group("cid"))
                        host_worker_errors[key] = max(host_worker_errors.get(key, 0.0), sys_ts or time.time())
                for tid, (bg_cmd, bg_call_ts) in list(pending_codex_tasks.items()):
                    if f'Task id "{tid}" finished with result:' in sys_txt:
                        pending_codex_tasks.pop(tid, None)
                        bg_status = "DONE" if "command exited with code 0" in sys_txt.lower() else "ERROR"
                        is_outage, aborted_rid = codex_lane.inspect_codex_cmd_result(bg_cmd, bg_status, sys_txt)
                        if is_outage:
                            _mark_codex_issue(sys_ts, idx)
                        elif aborted_rid and "timeout_after_" in sys_txt:
                            codex_timeout_seen = True
                        if aborted_rid and aborted_rid not in aborted_codex_reviews:
                            aborted_codex_reviews[aborted_rid] = bg_call_ts
            continue
        if st.get("source") != "MODEL" or st.get("type") != "PLANNER_RESPONSE":
            continue
        call_ts = rio.parse_iso_ts(st.get("created_at"))
        if call_ts and call_ts < first_ts - 2.0:
            continue
        all_tcs = st.get("tool_calls") or []
        if call_ts:
            for tc in all_tcs:
                if not isinstance(tc, dict):
                    continue
                tname = tc.get("name")
                targs = tc.get("args") if isinstance(tc.get("args"), dict) else {}
                if tname == "post_message":
                    coord_call_events.append((call_ts, str(targs.get("text") or "").strip().lower()[:64], idx))
                elif tname == "swarm" and str(targs.get("action") or "").strip().lower() == "add":
                    base_n = str(targs.get("name") or "").strip()
                    tasks_arg = targs.get("tasks") if isinstance(targs.get("tasks"), list) else []
                    n_raw = targs.get("n")
                    n_cnt = int(n_raw) if isinstance(n_raw, int) or (isinstance(n_raw, str) and n_raw.isdigit()) else 1
                    copies = max(1, len(tasks_arg), n_cnt)
                    for copy_idx in range(copies):
                        w_full = (
                            f"{base_n}-{copy_idx + 1}"
                            if (copies > 1 and base_n)
                            else base_n
                        )
                        if w_full:
                            worker_add_step[w_full] = idx
                        hint = f"@{w_full}".lower() if w_full else ""
                        coord_call_events.append((call_ts, hint, idx))
        has_swarm_tc = any(isinstance(tc, dict) and tc.get("name") == "swarm" for tc in all_tcs)
        has_run_cmd_tc = any(isinstance(tc, dict) and tc.get("name") == "run_command" for tc in all_tcs)
        if not has_swarm_tc and not has_run_cmd_tc:
            continue

        generic_steps = _collect_generic_results(steps, idx)

        for pos, tc in enumerate(all_tcs):
            if not isinstance(tc, dict):
                continue
            g_status, blob, g_ts = generic_steps[pos] if pos < len(generic_steps) else ("", "", 0.0)
            if tc.get("name") == "run_command":
                bgm_any = BG_TASK_ID_RE.search(blob)
                if bgm_any:
                    pending_bg_tasks.add(bgm_any.group(1))
                cmd_str = str((tc.get("args") or {}).get("CommandLine") or "")
                if "codex" in cmd_str.lower():
                    res_ts = max(call_ts, g_ts) if g_ts > 0.0 else call_ts
                    is_outage, aborted_rid = codex_lane.inspect_codex_cmd_result(cmd_str, g_status, blob)
                    # INVARIANT: Bind Codex unavailability to the result step (`g_ts`/`idx + 1 + pos`), never the request step.
                    if is_outage:
                        _mark_codex_issue(res_ts, idx + 1 + pos)
                    elif aborted_rid and "timeout_after_" in blob:
                        codex_timeout_seen = True
                    if aborted_rid and aborted_rid not in aborted_codex_reviews:
                        aborted_codex_reviews[aborted_rid] = call_ts
                    if bgm_any and not aborted_rid:
                        pending_codex_tasks[bgm_any.group(1)] = (cmd_str, call_ts)
                continue
            if tc.get("name") != "swarm":
                continue
            _inspect_swarm_tool_result(tc, g_status, blob, call_ts, idx)

    def _build_swarm_result(worker_activity_count: int | None = None) -> dict[str, Any]:
        out: dict[str, Any] = {
            "sonnet_lenses": sonnet_lenses,
            "fallback_lenses": fallback_lenses,
            "sonnet_lenses_end": sonnet_lenses_end,
            "fallback_lenses_end": fallback_lenses_end,
            "sonnet_combined_ts": sonnet_combined_ts,
            "fallback_combined_ts": fallback_combined_ts,
            "sonnet_combined_end_ts": sonnet_combined_end_ts,
            "fallback_combined_end_ts": fallback_combined_end_ts,
            "simplify_launch_steps": simplify_launch_steps,
            "simplify_history": simplify_history,
            "simplify_failures": simplify_failures,
            "reviews": reviews,
            "review_failures": review_failures,
            "in_flight_workers": in_flight_workers,
            "idle_unkilled_workers": idle_unkilled_workers,
            "pending_bg_tasks": sorted(pending_bg_tasks),
            "opus_issue_verified": opus_issue_verified,
            "opus_issue_ts": opus_issue_ts,
            "sonnet_issue_verified": sonnet_issue_verified,
            "codex_cmd_failed": codex_cmd_failed,
            "codex_issue_ts": codex_issue_ts,
            "codex_issue_step": codex_issue_step,
            "codex_timeout_seen": codex_timeout_seen,
            "aborted_codex_reviews": aborted_codex_reviews,
            "board_head": board_head,
            "multi_lens_spoof": multi_lens_spoof,
            "multi_lens_spoof_ts": multi_lens_spoof_ts,
            "stalled_workers": stalled_workers,
        }
        if worker_activity_count is not None:
            out["worker_activity_count"] = worker_activity_count
        return out

    brain_root, conv_cid = rio._swarm_brain_and_cid(transcript_path)
    conv_dir = (brain_root / conv_cid) if (brain_root is not None and conv_cid) else None

    if conv_dir is None or brain_root is None:
        return _build_swarm_result()

    swarm_dir = cwg.swarm_dir(brain_root, conv_dir.name)
    members_map = cwg.load_swarm_members(brain_root, conv_dir.name)
    if not members_map:
        return _build_swarm_result()

    raw_board = rio.read_jsonl(swarm_dir / "board.jsonl")
    board_head = len(raw_board)
    coord_call_events.sort(key=lambda item: item[0])
    c_cursor = 0
    running_board_ts = 0.0
    parsed_board: list[tuple[str, str, float, int | None, int]] = []
    for bp_idx, bp in enumerate(raw_board, start=1):
        poster = str(bp.get("agent") or "")
        btext = str(bp.get("text") or "").strip()
        bseq = cwg._extract_msg_seq(bp, bp_idx)
        raw_bts = rio.parse_iso_ts(bp.get("time"))
        bts = raw_bts
        bstep_idx: int | None = None
        if poster == "coordinator" and raw_bts:
            low_btext = btext.lower()
            probe = c_cursor
            while probe < len(coord_call_events) and coord_call_events[probe][0] < raw_bts - 0.1:
                probe += 1
            for cand_i in range(probe, len(coord_call_events)):
                evt_ts, evt_hint, evt_step = coord_call_events[cand_i]
                if evt_ts - raw_bts >= 1.5:
                    break
                if not evt_hint or evt_hint in low_btext:
                    bts = evt_ts
                    bstep_idx = evt_step
                    c_cursor = cand_i + 1
                    break
        if bts and running_board_ts and bts < running_board_ts:
            # INVARIANT: `board.jsonl` is strictly append-only; clamp whole-second floor truncation to preceding board timestamp.
            bts = running_board_ts
        if bts > running_board_ts:
            running_board_ts = bts
        parsed_board.append((poster, btext, bts, bstep_idx, bseq))

    for mname, minfo in members_map.items():
        if not isinstance(minfo, dict):
            continue
        if cwg.is_swarm_role_member(mname, minfo):
            continue

        cur_model = str(minfo.get("model") or "").strip().lower()
        mcid = str(minfo.get("conversation_id") or "").strip()
        killed = cwg.is_swarm_member_killed(minfo)
        group_prefix = mname.rsplit("-", 1)[0] if re.search(r"-\d+$", mname) else ""

        coord_posts: list[tuple[float, str, int | None, int]] = []
        broadcast_posts: list[tuple[float, str, int | None]] = []
        worker_board_posts: list[tuple[float, str, int]] = []
        mention_pats = rio.swarm_mention_patterns(mname)

        for poster, btext, bts, bstep_idx, bseq in parsed_board:
            if not btext:
                continue
            if poster == "coordinator":
                if any(mp.search(btext) for mp in mention_pats):
                    coord_posts.append((bts, btext, bstep_idx, bseq))
                elif "@all" in btext.lower():
                    broadcast_posts.append((bts, btext, bstep_idx))
            elif poster == mname:
                # INVARIANT: Only posts authored by `mname` itself count as worker output (never coordinator prompts).
                if not bts or bts >= first_ts - 2.0:
                    worker_board_posts.append((bts or time.time(), btext, bseq))

        m_tp = cwg.member_transcript_path(brain_root, mcid) if (brain_root and mcid) else None
        tsum = _member_transcript_summary(m_tp, first_ts)

        prior_reqs = set(requested_models.get(mname, set()))
        if group_prefix:
            prior_reqs |= set(requested_models.get(group_prefix, set()))

        host_err_ts = host_worker_errors.get((mname, mcid), 0.0) if mcid else 0.0
        if tsum["has_error"] or host_err_ts > 0.0:
            cand_models = ({cur_model} if cur_model else set()) | prior_reqs
            _record_model_failure(cand_models, mname, max(tsum["error_ts"], host_err_ts))

        tsum_outs: list[tuple[float, str]] = list(tsum["outputs"])
        t_cursor = 0
        matched_t: set[int] = set()
        combined_outputs: list[tuple[float, str, int]] = []
        for b_idx, (bts, btxt, bseq) in enumerate(worker_board_posts):
            eff_ots = bts
            next_bts = worker_board_posts[b_idx + 1][0] if b_idx + 1 < len(worker_board_posts) else float("inf")
            for tidx in range(t_cursor, len(tsum_outs)):
                ots, otxt = tsum_outs[tidx]
                if otxt == btxt and abs(ots - bts) < 5.0 and ots < next_bts:
                    eff_ots = max(eff_ots, ots)
                    matched_t.add(tidx)
                    t_cursor = tidx + 1
                    break
            combined_outputs.append((eff_ots, btxt, bseq))
        for tidx, (ots, otxt) in enumerate(tsum_outs):
            if tidx not in matched_t:
                combined_outputs.append((ots, otxt, 0))
        combined_outputs.sort(key=lambda pair: pair[0])

        latest_assign_ts = coord_posts[-1][0] if coord_posts else tsum["start_ts"]
        latest_assign_seq = coord_posts[-1][3] if coord_posts else 0
        latest_reply_seq = max((seq for _, _, seq in worker_board_posts), default=0)
        latest_brief = "\n".join(txt for _, txt, _, _ in coord_posts)
        if latest_assign_seq > 0 and worker_board_posts:
            has_reply_since_assign = latest_reply_seq > latest_assign_seq
        else:
            has_reply_since_assign = bool(
                combined_outputs and (not latest_assign_ts or combined_outputs[-1][0] >= latest_assign_ts - 1.0)
            )
        worker_last_activity[mname] = max(
            [latest_assign_ts, tsum["start_ts"], tsum["parked_ts"]] + [ots for ots, _, _ in combined_outputs]
        )
        eff_park_ts = max(tsum["parked_ts"], host_err_ts)
        parked_after_assign = bool(
            (tsum["parked_or_done"] or host_err_ts > 0.0)
            and (not latest_assign_ts or not eff_park_ts or eff_park_ts >= latest_assign_ts - 0.5)
        )

        if not killed and latest_assign_ts >= first_ts - 2.0 and not has_reply_since_assign and not parked_after_assign:
            in_flight_workers.append(f"swarm:{mname}")
            continue
        if not killed:
            idle_unkilled_workers.append(mname)

        if not combined_outputs:
            continue

        windows: list[tuple[float, str, int | None]] = sorted(
            [(ts, txt, st_i) for ts, txt, st_i, _ in coord_posts]
            + list(broadcast_posts)
            + list(model_switches.get(mname, [])),
            key=lambda item: item[0],
        )
        if not windows:
            windows = [(tsum["start_ts"] or first_ts, "", None)]

        bucketed_outputs: dict[int, list[tuple[float, str, int]]] = {}
        for out_ts, out_txt, out_seq in combined_outputs:
            w_idx = 0
            # INVARIANT: Sub-second ISO transcript timestamps are strictly causal (`wts <= out_ts`); whole-second board fallbacks allow <1s floor slack.
            tol = 1e-6 if (out_ts % 1.0) != 0.0 else 0.999
            for cand_idx, (wts, _, _) in enumerate(windows):
                if not wts or wts <= out_ts + tol:
                    w_idx = cand_idx
            bucketed_outputs.setdefault(w_idx, []).append((out_ts, out_txt, out_seq))

        joined_worker_text = "\n\n".join(txt for _, txt, _ in combined_outputs)
        skind, slens = _classify_simplify_worker(mname, latest_brief, joined_worker_text)
        w_step_idx = worker_add_step.get(mname)
        if w_step_idx is None and group_prefix:
            w_step_idx = worker_add_step.get(group_prefix)
        if (skind == "lens" and slens is not None) or skind == "combined":
            if w_step_idx is not None:
                simplify_launch_steps.add(w_step_idx)
            # INVARIANT: Simplify fallback runs strictly on Hydrogen XHigh via swarm (never Carbon), protecting main-agent quota.
            tier = (
                "sonnet"
                if cur_model == cwg.SONNET_HIGH_MODEL
                else ("fallback" if cur_model in cwg.SIMPLIFY_FALLBACK_MODELS else "")
            )
            if tier:
                for w_idx in sorted(bucketed_outputs):
                    win_ts, _, _ = windows[w_idx]
                    win_outs = bucketed_outputs[w_idx]
                    fresh_win_outs: list[tuple[float, str, int]] = []
                    for ots, otxt, obseq in win_outs:
                        if round_start_msg_id > 0 and obseq > 0 and obseq <= round_start_msg_id:
                            continue
                        if current_diff_hash:
                            hm_hash = cwg.extract_diff_hash(otxt)
                            if hm_hash and hm_hash != current_diff_hash:
                                continue
                        fresh_win_outs.append((ots, otxt, obseq))
                    if not fresh_win_outs:
                        continue
                    joined_win = "\n\n".join(otxt for _, otxt, _ in fresh_win_outs)
                    win_parsed = cwg.parse_simplify_verdict(joined_win, default_lens=slens or "")
                    if not win_parsed.get("verdict"):
                        continue
                    s_ts = max(
                        (ots for ots, otxt, _ in fresh_win_outs if cwg.SIMPLIFY_LINE_RE.search(otxt)),
                        default=fresh_win_outs[-1][0],
                    )
                    eff_lts = win_ts or tsum["start_ts"] or first_ts
                    eff_ets = max(eff_lts, s_ts or max((ots for ots, _, _ in fresh_win_outs), default=eff_lts))
                    if win_parsed.get("multi_lens_spoof") or (
                        skind == "combined"
                        and not win_parsed.get("has_explicit_all")
                        and not SIMPLIFY_COMBINED_NAME_RE.match(mname.strip())
                    ):
                        multi_lens_spoof = True
                        multi_lens_spoof_ts = max(multi_lens_spoof_ts, eff_ets)
                    max_seq = max((obseq for _, _, obseq in fresh_win_outs), default=0)
                    simplify_events.append(
                        {
                            "kind": skind,
                            "lens": slens if skind == "lens" else None,
                            "tier": tier,
                            "launch_ts": eff_lts,
                            "end_ts": eff_ets,
                            "seq": max_seq,
                            "clean": bool(win_parsed.get("clean")),
                            "has_explicit_all": bool(win_parsed.get("has_explicit_all")),
                        }
                    )
            continue

        if cur_model not in (cwg.OPUS_HIGH_MODEL, cwg.CARBON_HIGH_MODEL):
            continue
        eng = "internal-opus" if cur_model == cwg.OPUS_HIGH_MODEL else "internal-carbon"
        escalated_from_opus = cwg.OPUS_HIGH_MODEL in prior_reqs
        for w_idx in sorted(bucketed_outputs):
            win_ts, win_brief, win_step_idx = windows[w_idx]
            win_outs = bucketed_outputs[w_idx]
            eff_launch_ts = win_ts or tsum["start_ts"] or first_ts
            eff_end_ts = max(eff_launch_ts, max((ots for ots, _, _ in win_outs), default=eff_launch_ts))
            eff_step_idx = win_step_idx if win_step_idx is not None else w_step_idx
            win_txt = "\n\n".join(otxt for _, otxt, _ in win_outs)
            is_xhigh = (
                ("xhigh" in mname.lower())
                or bool(cwg.REVIEW_TIER_XHIGH_RE.search(latest_brief))
                or bool(cwg.REVIEW_TIER_XHIGH_RE.search(win_brief))
                or bool(cwg.REVIEW_TIER_XHIGH_RE.search(win_txt))
            )

            r_kind: str | None = None
            r_verdict: str | None = None
            r_ts = 0.0
            for ots, otxt, _ in reversed(win_outs):
                r_kind, r_verdict = cwg.extract_review_decision(otxt)
                if r_kind and r_verdict:
                    r_ts = ots
                    break
            if r_kind and r_verdict:
                eff_verdict_ts = max(eff_launch_ts, r_ts or eff_end_ts)
                reviews.append(
                    {
                        "engine": eng,
                        "reviewer": mname,
                        "cid": mcid,
                        "kind": r_kind,
                        "verdict": r_verdict,
                        "launch_ts": eff_launch_ts,
                        "verdict_ts": eff_verdict_ts,
                        "xhigh": is_xhigh,
                        "model": cur_model,
                        "escalated_from_opus": escalated_from_opus,
                        "step_idx": eff_step_idx,
                    }
                )

    # INVARIANT: Replay simplify events in chronological order across all workers so a stale CLEAN in another
    # member entry can never survive or overwrite a later ACTIONABLE_FIXES verdict.
    simplify_events.sort(
        key=lambda ev: (float(ev.get("end_ts") or 0.0), int(ev.get("seq") or 0), float(ev.get("launch_ts") or 0.0))
    )
    for sev in simplify_events:
        sk = sev["kind"]
        sl = sev["lens"]
        tr = sev["tier"]
        eff_lts = float(sev["launch_ts"])
        eff_ets = float(sev["end_ts"])
        if not sev["clean"]:
            if sk == "lens" and sl is not None:
                sonnet_lenses.pop(sl, None)
                sonnet_lenses_end.pop(sl, None)
                fallback_lenses.pop(sl, None)
                fallback_lenses_end.pop(sl, None)
                simplify_history[:] = [
                    item
                    for item in simplify_history
                    if not (item.get("kind") == "lens" and item.get("lens") == sl)
                ]
            else:
                sonnet_combined_ts = 0.0
                sonnet_combined_end_ts = 0.0
                fallback_combined_ts = 0.0
                fallback_combined_end_ts = 0.0
                simplify_history[:] = [
                    item for item in simplify_history if item.get("kind") != "combined"
                ]
            continue
        if sk == "lens" and sl is not None:
            if tr == "sonnet":
                sonnet_lenses[sl] = max(sonnet_lenses.get(sl, 0.0), eff_lts)
                sonnet_lenses_end[sl] = max(sonnet_lenses_end.get(sl, 0.0), eff_ets)
            else:
                fallback_lenses[sl] = max(fallback_lenses.get(sl, 0.0), eff_lts)
                fallback_lenses_end[sl] = max(fallback_lenses_end.get(sl, 0.0), eff_ets)
        elif tr == "sonnet":
            sonnet_combined_ts = max(sonnet_combined_ts, eff_lts)
            sonnet_combined_end_ts = max(sonnet_combined_end_ts, eff_ets)
        else:
            fallback_combined_ts = max(fallback_combined_ts, eff_lts)
            fallback_combined_end_ts = max(fallback_combined_end_ts, eff_ets)
        simplify_history.append(
            {
                "kind": sk,
                "lens": sl if sk == "lens" else None,
                "tier": tr,
                "launch_ts": eff_lts,
                "end_ts": eff_ets,
                "has_explicit_all": bool(sev.get("has_explicit_all")),
            }
        )

    stalled_workers = (
        cwg.detect_stalled_workers(
            members=members_map,
            board_messages=raw_board,
            cwd=cwd or (str(conv_dir) if conv_dir else ""),
            brain_root=brain_root,
            worker_last_activity=worker_last_activity,
            in_flight_names=in_flight_workers,
        )
        if in_flight_workers
        else []
    )
    worker_activity_count = sum(
        1 for poster, btext, _, _, _ in parsed_board if btext and poster and poster != "coordinator"
    )
    return _build_swarm_result(worker_activity_count=worker_activity_count)


def scan_native_subagents(
    steps: list[dict[str, Any]],
    transcript_path: str | None,
    first_ts: float,
) -> dict[str, Any]:
    """Deterministically bind parent `invoke_subagent` calls to subagent system transcripts & messages."""
    brain_root: pathlib.Path | None = None
    parent_cid = ""
    if transcript_path:
        p = pathlib.Path(transcript_path).resolve()
        if len(p.parents) >= 4 and p.parents[1].name == ".system_generated":
            parent_cid = p.parents[2].name
            brain_root = p.parents[3]

    first_idx = steps[0].get("step_index") if steps else None
    head_steps = (
        steps[:5]
        if steps and (first_idx in (None, 0) or not transcript_path or not pathlib.Path(transcript_path).is_file())
        else None
    )
    caller_worker_model = rio.swarm_worker_model(
        transcript_path,
        steps=head_steps,
        conversation_id=parent_cid,
    )

    delivered_by_sender: dict[str, list[tuple[float, str]]] = {}
    for st in steps:
        if st.get("source") == "SYSTEM" and st.get("type") == "SYSTEM_MESSAGE":
            m = rio.SUBAGENT_MSG_RE.search(str(st.get("content") or ""))
            if m:
                sender = m.group("sender")
                msg_ts = rio.parse_iso_ts(m.group("ts")) or rio.parse_iso_ts(st.get("created_at"))
                body = _SYS_MSG_CLOSE_RE.sub("", m.group("body")).strip()
                delivered_by_sender.setdefault(sender, []).append((msg_ts, body))

    fallback_lenses: dict[str, float] = {}
    fallback_lenses_end: dict[str, float] = {}
    fallback_combined_ts = 0.0
    fallback_combined_end_ts = 0.0
    simplify_launch_steps: set[int] = set()
    simplify_history: list[dict[str, Any]] = []
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
        if not any(isinstance(tc, dict) and tc.get("name") == "invoke_subagent" for tc in tcs):
            continue

        generic_steps = _collect_generic_results(steps, idx)

        for pos, tc in enumerate(tcs):
            if not isinstance(tc, dict) or tc.get("name") != "invoke_subagent":
                continue
            args = tc.get("args") if isinstance(tc.get("args"), dict) else {}
            tname = str(args.get("TypeName") or "").strip()
            base_tname = tname.rsplit(":", 1)[-1]
            role_str = str(args.get("Role") or "").strip()
            prompt_str = str(args.get("Prompt") or "").strip()
            is_simplify_subagent = cwg.is_simplify_subagent_call(base_tname, role_str)
            model_arg = str(args.get("Model") or "inherit").strip()
            # INVARIANT: Credit `invoke_subagent` simplify runs only when inherited inside a verified Hydrogen XHigh swarm worker.
            has_simplify_fallback_provenance = bool(
                is_simplify_subagent
                and caller_worker_model in cwg.SIMPLIFY_FALLBACK_MODELS
                and model_arg.lower() in ("", "inherit")
            )
            g_status, blob, _ = generic_steps[pos] if pos < len(generic_steps) else ("", "", 0.0)
            sm = SUBAGENT_URI_RE.search(blob)
            if not sm:
                if g_status == "ERROR" or "error" in blob.lower() or "failed" in blob.lower():
                    if has_simplify_fallback_provenance:
                        simplify_failures += 1
                    elif base_tname in cwg.NATIVE_REVIEWERS:
                        review_failures.append(call_ts or time.time())
                continue

            cid = sm.group("cid")
            sub_tp = uri_to_path(sm.group("uri")) if sm.group("uri") else ""
            if not sub_tp and brain_root:
                cand = cwg.member_transcript_path(brain_root, cid)
                if cand.exists():
                    sub_tp = str(cand)

            sub_chunks, sub_last_ts, sub_done = _extract_subagent_timed_chunks(sub_tp, parent_cid=parent_cid)
            delivered = delivered_by_sender.get(cid) or []
            if delivered:
                sub_done = True
            if not sub_done:
                in_flight_subagents.append(f"{tname}:{cid[:8]}")
                continue

            # INVARIANT: Bind each simplify/review verdict strictly to the timestamp of the message chunk that
            # produced it; coalesce only an immediate post-`send_message` sign-off repeating the identical decision.
            merged_chunks = _merge_subagent_chunks(sub_chunks, delivered)
            sub_text = "\n\n".join(cbody for _, cbody, _, _ in merged_chunks).strip()
            last_chunk_ts = max((cts for cts, _, _, _ in merged_chunks), default=0.0)
            fallback_end_ts = last_chunk_ts or sub_last_ts
            eff_launch_ts = call_ts or fallback_end_ts or time.time()

            if is_simplify_subagent:
                brief_ctx = f"{role_str}\n{prompt_str}"
                chosen_skind = "other"
                chosen_slens: str | None = None
                chosen_sts = 0.0
                has_simplify_verdict = False
                prev_send_sdec: tuple[str, str | None, str] | None = None
                for cts, cbody, ckind, csign in merged_chunks:
                    v_matches = cwg.SIMPLIFY_LINE_RE.findall(cbody)
                    if v_matches:
                        s_verdict = v_matches[-1].upper()
                        sk, sl = _classify_simplify_worker(base_tname, brief_ctx, cbody)
                        if sk == "other":
                            sk, sl = _classify_simplify_worker(base_tname, brief_ctx, sub_text)
                        sdec = (sk, sl, s_verdict)
                        if not (ckind == "final" and csign and sdec == prev_send_sdec):
                            has_simplify_verdict = True
                            chosen_skind, chosen_slens = sk, sl
                            chosen_sts = cts
                        prev_send_sdec = sdec if ckind == "send" else None
                    else:
                        prev_send_sdec = None

                if has_simplify_verdict:
                    eff_end_ts = max(eff_launch_ts, chosen_sts or fallback_end_ts or eff_launch_ts)
                    simplify_launch_steps.add(idx)
                    if has_simplify_fallback_provenance:
                        if chosen_skind == "lens" and chosen_slens is not None:
                            fallback_lenses[chosen_slens] = max(fallback_lenses.get(chosen_slens, 0.0), eff_launch_ts)
                            fallback_lenses_end[chosen_slens] = max(fallback_lenses_end.get(chosen_slens, 0.0), eff_end_ts)
                            simplify_history.append(
                                {
                                    "kind": "lens",
                                    "lens": chosen_slens,
                                    "tier": "fallback",
                                    "launch_ts": eff_launch_ts,
                                    "end_ts": eff_end_ts,
                                }
                            )
                        elif chosen_skind == "combined":
                            fallback_combined_ts = max(fallback_combined_ts, eff_launch_ts)
                            fallback_combined_end_ts = max(fallback_combined_end_ts, eff_end_ts)
                            simplify_history.append(
                                {
                                    "kind": "combined",
                                    "lens": None,
                                    "tier": "fallback",
                                    "launch_ts": eff_launch_ts,
                                    "end_ts": eff_end_ts,
                                }
                            )
                elif not sub_text and has_simplify_fallback_provenance:
                    simplify_failures += 1

            elif base_tname in cwg.NATIVE_REVIEWERS:
                r_kind: str | None = None
                r_verdict: str | None = None
                r_ts = 0.0
                prev_send_dec: tuple[str | None, str | None] = (None, None)
                for cts, cbody, ckind, csign in merged_chunks:
                    dec = cwg.extract_review_decision(cbody)
                    if dec != (None, None):
                        if not (ckind == "final" and csign and dec == prev_send_dec):
                            r_kind, r_verdict = dec
                            r_ts = cts
                        prev_send_dec = dec if ckind == "send" else (None, None)
                    else:
                        prev_send_dec = (None, None)

                if r_kind and r_verdict:
                    eff_verdict_ts = max(eff_launch_ts, r_ts or fallback_end_ts or eff_launch_ts)
                    reviews.append(
                        {
                            "engine": "native",
                            "reviewer": base_tname,
                            "cid": cid,
                            "kind": r_kind,
                            "verdict": r_verdict,
                            "launch_ts": eff_launch_ts,
                            "verdict_ts": eff_verdict_ts,
                            "xhigh": base_tname == cwg.XHIGH_NATIVE_REVIEWER,
                            "model": model_arg,
                            "step_idx": idx,
                        }
                    )
                else:
                    eff_fail_ts = max(eff_launch_ts, fallback_end_ts or eff_launch_ts)
                    review_failures.append(eff_fail_ts)

    return {
        "fallback_lenses": fallback_lenses,
        "fallback_lenses_end": fallback_lenses_end,
        "fallback_combined_ts": fallback_combined_ts,
        "fallback_combined_end_ts": fallback_combined_end_ts,
        "simplify_launch_steps": simplify_launch_steps,
        "simplify_history": simplify_history,
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

    # INVARIANT: A mark with a concrete SHA-256 `fp` is cryptographically measured; only `fp is None` is unmeasured.
    covered_fps = {
        m.get("fp")
        for m in marks
        if m.get("fp")
        and float(m.get("ts") or 0.0) <= launch_ts
    }
    for m in marks:
        mts = float(m.get("ts") or 0.0)
        if not m.get("fp") and m.get("unknown") and mts > launch_ts:
            return False
    current_mark = marks[-1]
    if not current_mark.get("fp"):
        return False
    if current_mark.get("fp") not in covered_fps:
        return False
    return True


def _steps_have_index_gap(step_list: list[dict[str, Any]]) -> bool:
    if len(step_list) < 2:
        return False
    s0 = step_list[0].get("step_index")
    s1 = step_list[1].get("step_index")
    return isinstance(s0, int) and isinstance(s1, int) and s1 > s0 + 1


def _steps_need_compact_fallback(step_list: list[dict[str, Any]] | None) -> bool:
    return not step_list or rio.has_prefix_slice_gap(step_list)


def _extract_transcript_edit_evidence(
    steps: list[dict[str, Any]] | None,
    marker: dict[str, Any],
) -> dict[str, Any]:
    if not steps:
        return {"covered_from_ts": float("inf"), "edit_spans": [], "proven_change_ts": []}
    import cwg_mark

    has_gap = _steps_have_index_gap(steps)
    iter_steps = steps[1:] if has_gap else steps
    covered_from_ts = float("inf")
    for st in iter_steps:
        ts0 = rio.parse_iso_ts(st.get("created_at"))
        if ts0 > 0.0:
            covered_from_ts = ts0
            break

    cwd = str(marker.get("cwd") or "")
    shell_durable = bool(marker.get("shell_durable_edit", True))
    folded_dpaths = {rio.fold_path(p) for p in cwg.durable_paths(marker.get("paths"))}
    edit_spans: list[tuple[float, float]] = []
    proven_change_ts: list[float] = []
    pending_mut_tasks: dict[str, float] = {}
    mut_tools = cwg_mark.EDIT_TOOLS | cwg_mark.SHELL_TOOLS

    for idx, st in enumerate(iter_steps):
        if st.get("source") == "SYSTEM":
            sys_ts = rio.parse_iso_ts(st.get("created_at"))
            sys_txt = str(st.get("content") or "")
            for tid, start_ts in list(pending_mut_tasks.items()):
                if f'Task id "{tid}" finished with result:' in sys_txt:
                    pending_mut_tasks.pop(tid, None)
                    end_ts = max(start_ts, sys_ts) if sys_ts > 0.0 else start_ts
                    edit_spans.append((start_ts, end_ts))
            continue
        if st.get("source") != "MODEL" or st.get("type") != "PLANNER_RESPONSE":
            continue
        call_ts = rio.parse_iso_ts(st.get("created_at"))
        if call_ts <= 0.0:
            continue
        tcs = st.get("tool_calls") or []
        if not any(isinstance(tc, dict) and tc.get("name") in mut_tools for tc in tcs):
            continue
        gen_steps = _collect_generic_results(iter_steps, idx)
        for pos, tc in enumerate(tcs):
            if not isinstance(tc, dict):
                continue
            tname = str(tc.get("name") or "")
            if tname not in mut_tools:
                continue
            g_status, g_blob, g_ts = gen_steps[pos] if pos < len(gen_steps) else ("", "", 0.0)
            end_ts = max(call_ts, g_ts) if g_ts > 0.0 else call_ts
            targs = tc.get("args") if isinstance(tc.get("args"), dict) else {}
            if tname in cwg_mark.EDIT_TOOLS:
                if g_status == "ERROR" or bool(targs.get("ArtifactMetadata")):
                    continue
                tpath = str(targs.get("Path") or "")
                if not tpath or cwg.is_scratch_or_ephemeral(tpath, None, cwd=cwd):
                    continue
                edit_spans.append((call_ts, end_ts))
                if (
                    tname == "edit_file"
                    and g_status == "DONE"
                    and rio.fold_path(tpath) in folded_dpaths
                    and str(targs.get("Target") or "") != str(targs.get("Replacement") or "")
                ):
                    proven_change_ts.append(end_ts)
            else:
                if not shell_durable:
                    continue
                cmd_s = str(targs.get("CommandLine") or "")
                pol = cwg_mark.classify_shell_command(cmd_s)
                if pol in ("READ_ONLY", "BOOKKEEPING", "VALIDATION"):
                    continue
                if pol == "MUTATING" and cwg_mark.is_ephemeral_only_shell_mutation(cmd_s, default_cwd=cwd):
                    continue
                bgm = BG_TASK_ID_RE.search(g_blob)
                if bgm:
                    pending_mut_tasks[bgm.group(1)] = call_ts
                else:
                    edit_spans.append((call_ts, end_ts))

    for start_ts in pending_mut_tasks.values():
        edit_spans.append((start_ts, float("inf")))
    return {
        "covered_from_ts": covered_from_ts,
        "edit_spans": edit_spans,
        "proven_change_ts": sorted(proven_change_ts),
    }


def validate_candidate_closure(
    receipt: dict[str, Any] | None,
    marker: dict[str, Any],
    checks_ev: dict[str, Any],
    sub_ev: dict[str, Any],
    swarm_ev: dict[str, Any],
    codex_reviews: list[dict[str, Any]],
    ctx: dict[str, Any] | None = None,
    steps: list[dict[str, Any]] | None = None,
    transcript_path: str | None = None,
) -> tuple[bool, str]:
    wclass = cwg.candidate_class(marker)
    cctx = ctx or cwg.resolve_candidate_context(marker)
    cwd = cctx["cwd"]
    dpaths = cctx["dpaths"]
    policy = cctx["policy"]
    floor = cctx["floor"]

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

    # 1. Deterministic Check Verification (always fail if a run validation command failed; require check pass when applicable)
    if rkind in ("verified", "pr-ready") and checks_ev["latest_fail_ts"] > checks_ev["latest_pass_ts"]:
        return (
            False,
            "latest validation/test command failed with no subsequent passing verification run",
        )

    if effective_risk == floor and cctx["require_tests"] is not None:
        require_checks = bool(cctx["require_tests"])
    else:
        require_checks = cwg.requires_tests(
            effective_risk, cwd=cwd, paths=dpaths, policy=policy, git_root=cctx["git_root"]
        )

    if require_checks and rkind in ("verified", "pr-ready"):
        last_durable = float(marker.get("last_durable_ts") or marker.get("first_ts") or 0.0)
        if len(checks_ev["checks"]) == 0:
            return (
                False,
                f"{effective_risk} candidate has zero executed verification/test commands recorded in runtime",
            )
        if checks_ev["passed_count"] == 0 or checks_ev["latest_pass_ts"] < last_durable - 1.0:
            return (
                False,
                "last passing test/verification command ran BEFORE the latest file edit; re-verify current bytes",
            )

    # 2. Proportionate Simplify Verification (`HIGH`/`XHIGH` 3 lenses, or `STANDARD` via project opt-in)
    needs_simplify = (
        bool(cctx["needs_simplify"])
        if effective_risk == floor
        else (bool(cctx["needs_simplify"]) or cwg.requires_simplify(effective_risk, policy))
    )
    required_lenses = set(cwg.SIMPLIFY_LENSES)
    raw_sonnet_map: dict[str, float] = dict(swarm_ev.get("sonnet_lenses") or {})
    raw_fallback_map: dict[str, float] = {}
    for src_map in (swarm_ev.get("fallback_lenses") or {}, sub_ev.get("fallback_lenses") or {}):
        for k, v in dict(src_map).items():
            raw_fallback_map[k] = max(raw_fallback_map.get(k, 0.0), float(v or 0.0))

    sonnet_lenses = {k for k, lts in raw_sonnet_map.items() if is_review_fresh({"launch_ts": lts}, marker)}
    fallback_lenses = {k for k, lts in raw_fallback_map.items() if is_review_fresh({"launch_ts": lts}, marker)}

    sonnet_issue = bool(swarm_ev.get("sonnet_issue_verified"))
    simplify_failures = int(swarm_ev.get("simplify_failures") or 0) + int(sub_ev.get("simplify_failures") or 0)
    simplify_exhausted = simplify_failures >= 2
    effective_lenses = (sonnet_lenses | fallback_lenses) if sonnet_issue else sonnet_lenses
    raw_effective_lenses = (set(raw_sonnet_map) | set(raw_fallback_map)) if sonnet_issue else set(raw_sonnet_map)
    stale_simplify_lenses = sorted((raw_effective_lenses & required_lenses) - effective_lenses)
    missing_lenses = sorted(required_lenses - effective_lenses)

    raw_sonnet_combined = float(swarm_ev.get("sonnet_combined_ts") or 0.0)
    raw_fallback_combined = max(
        float(swarm_ev.get("fallback_combined_ts") or 0.0),
        float(sub_ev.get("fallback_combined_ts") or 0.0),
    )
    sonnet_combined_fresh = raw_sonnet_combined > 0.0 and is_review_fresh(
        {"launch_ts": raw_sonnet_combined}, marker
    )
    fallback_combined_fresh = raw_fallback_combined > 0.0 and is_review_fresh(
        {"launch_ts": raw_fallback_combined}, marker
    )
    combined_fresh = sonnet_combined_fresh or (sonnet_issue and fallback_combined_fresh)
    combined_stale = (raw_sonnet_combined > 0.0 and not sonnet_combined_fresh) or (
        sonnet_issue and raw_fallback_combined > 0.0 and not fallback_combined_fresh
    )

    multi_lens_spoof = bool(swarm_ev.get("multi_lens_spoof"))
    fast_path = cwg.is_simplify_fast_path_eligible(
        marker=marker,
        swarm_ev=swarm_ev,
        repo_root=cwd or str(marker.get("git_root") or ""),
    )
    if ctx is not None:
        ctx["fast_path"] = fast_path
    allow_combined = (effective_risk == "STANDARD") or fast_path
    simplify_satisfied = (not missing_lenses) or (allow_combined and combined_fresh and not multi_lens_spoof)
    unstarted_simplify_reason = ""

    if needs_simplify:
        if not simplify_satisfied and not (rkind == "draft-blocked" and simplify_exhausted):
            if effective_risk != "STANDARD" and (
                multi_lens_spoof
                or ((not fast_path) and (combined_fresh or raw_sonnet_combined > 0.0 or raw_fallback_combined > 0.0))
            ):
                return (
                    False,
                    f"{effective_risk} candidate cannot collapse simplify into a single combined lane; "
                    f"run all 3 separate `{cwg.SONNET_HIGH_MODEL}` lenses (`reuse`, `quality`, `efficiency`); "
                    f"missing: {', '.join(missing_lenses)}",
                )
            if not sonnet_issue and (
                (allow_combined and fallback_combined_fresh)
                or (sonnet_lenses | fallback_lenses) >= required_lenses
            ):
                target = (
                    "`simplify-reviewer`"
                    if allow_combined
                    else "all 3 lenses (`reuse`, `quality`, `efficiency`)"
                )
                return (
                    False,
                    f"simplify ran on fallback model without verified `{cwg.SONNET_HIGH_MODEL}` error/quota issue; "
                    f"run {target} on `{cwg.SONNET_HIGH_MODEL}` via `swarm`",
                )
            if stale_simplify_lenses or (allow_combined and combined_stale):
                stale_label = (
                    "combined simplify"
                    if (allow_combined and combined_stale and not stale_simplify_lenses)
                    else f"simplify lenses ({', '.join(stale_simplify_lenses)})"
                )
                reverify_model = cwg.SIMPLIFY_FALLBACK_MODEL if sonnet_issue else cwg.SONNET_HIGH_MODEL
                return (
                    False,
                    f"{stale_label} stale because durable files changed after simplify; "
                    f"re-verify on `{reverify_model}`",
                )
            if effective_risk == "STANDARD":
                unstarted_simplify_reason = (
                    f"STANDARD candidate requires 1 combined `simplify-reviewer` lane (`SIMPLIFY_LENS: ALL`) "
                    f"or all 3 lenses on `{cwg.SONNET_HIGH_MODEL}` (fallback `{cwg.SIMPLIFY_FALLBACK_MODEL}` on Sonnet outage) via `swarm`"
                )
            elif fast_path:
                unstarted_simplify_reason = (
                    f"{effective_risk} candidate qualifies for Swarm 2.0 Fast-Path (<=2 files, <=30 changed lines): "
                    f"run 1 `simplify-reviewer` lane (`SIMPLIFY_LENS: ALL`) or 3 separate lenses on `{cwg.SONNET_HIGH_MODEL}` "
                    f"(fallback `{cwg.SIMPLIFY_FALLBACK_MODEL}` on Sonnet outage) via `swarm`; missing: {', '.join(missing_lenses)}"
                )
            else:
                unstarted_simplify_reason = (
                    f"{effective_risk} candidate requires all 3 separate `{cwg.SONNET_HIGH_MODEL}` simplify lenses "
                    f"(fallback `{cwg.SIMPLIFY_FALLBACK_MODEL}` via `swarm` on Sonnet outage: `reuse`, `quality`, `efficiency`); missing: {', '.join(missing_lenses)}"
                )

    # INVARIANT: Compute simplify completion windows before review checks so all closure paths enforce `simplify -> final/closure review`.
    raw_sonnet_end_map: dict[str, float] = dict(swarm_ev.get("sonnet_lenses_end") or {})
    raw_fallback_end_map: dict[str, float] = {}
    for src_end_map in (swarm_ev.get("fallback_lenses_end") or {}, sub_ev.get("fallback_lenses_end") or {}):
        for k, v in dict(src_end_map).items():
            raw_fallback_end_map[k] = max(raw_fallback_end_map.get(k, 0.0), float(v or 0.0))

    active_simplify_windows: list[tuple[float, float]] = []
    if needs_simplify:
        if allow_combined and combined_fresh and not multi_lens_spoof and missing_lenses:
            if sonnet_combined_fresh:
                c_lts = raw_sonnet_combined
                c_ets = max(c_lts, float(swarm_ev.get("sonnet_combined_end_ts") or c_lts))
            else:
                c_lts = raw_fallback_combined
                c_ets = max(
                    c_lts,
                    float(swarm_ev.get("fallback_combined_end_ts") or 0.0),
                    float(sub_ev.get("fallback_combined_end_ts") or 0.0),
                )
            active_simplify_windows.append((c_lts, c_ets))
        else:
            for k in required_lenses:
                use_fallback = (
                    sonnet_issue
                    and k in fallback_lenses
                    and (k not in sonnet_lenses or raw_fallback_map.get(k, 0.0) >= raw_sonnet_map.get(k, 0.0))
                )
                if use_fallback:
                    lts = float(raw_fallback_map.get(k) or 0.0)
                    ets = max(lts, float(raw_fallback_end_map.get(k) or lts))
                    active_simplify_windows.append((lts, ets))
                elif k in sonnet_lenses:
                    lts = float(raw_sonnet_map.get(k) or 0.0)
                    ets = max(lts, float(raw_sonnet_end_map.get(k) or lts))
                    active_simplify_windows.append((lts, ets))

    max_simplify_launch_ts = max((w[0] for w in active_simplify_windows), default=0.0)
    max_simplify_end_ts = max((w[1] for w in active_simplify_windows), default=0.0)
    all_simplify_steps = set(swarm_ev.get("simplify_launch_steps") or set()) | set(
        sub_ev.get("simplify_launch_steps") or set()
    )
    all_simplify_history = list(swarm_ev.get("simplify_history") or []) + list(sub_ev.get("simplify_history") or [])
    candidate_marks = [m for m in (marker.get("content_marks") or []) if isinstance(m, dict)]
    oldest_mark_ts = min((float(m.get("ts") or 0.0) for m in candidate_marks), default=float("inf"))
    first_ts_val = float(marker.get("first_ts") or 0.0)
    marks_truncated = bool(
        candidate_marks
        and (
            float(marker.get("marks_evicted_through_ts") or 0.0) > 0.0
            or (
                first_ts_val > 0.0
                and oldest_mark_ts > first_ts_val + 1.0
                and int(marker.get("edits") or 0) > len(candidate_marks)
            )
        )
    )
    tx_edits_cache: dict[str, Any] | None = None

    def _get_tx_edits() -> dict[str, Any]:
        nonlocal tx_edits_cache
        if tx_edits_cache is None:
            tx_steps = steps
            if _steps_need_compact_fallback(tx_steps) and transcript_path:
                # INVARIANT: When `transcript_full.jsonl` exceeds the tail-read window, recover full step-0..N edit spans
                # from compact `transcript.jsonl` (~10x smaller) before failing closed on `covered_from_ts`.
                compact_steps = rio.read_compact_transcript_steps(transcript_path)
                if compact_steps:
                    tx_steps = compact_steps
            tx_edits_cache = _extract_transcript_edit_evidence(tx_steps, marker)
        return tx_edits_cache

    def _is_after_simplify(rev_item: dict[str, Any]) -> bool:
        if not (needs_simplify and active_simplify_windows):
            return True
        rev_launch_ts = float(rev_item.get("launch_ts") or 0.0)
        rev_step_idx = rev_item.get("step_idx")
        if rev_step_idx is not None and rev_step_idx in all_simplify_steps:
            return False
        if max_simplify_launch_ts > 0.0 and rev_launch_ts <= max_simplify_launch_ts:
            return False
        if max_simplify_end_ts > 0.0 and rev_launch_ts < max_simplify_end_ts:
            return False
        return True

    def _has_completed_simplify_for_version(rev_item: dict[str, Any]) -> bool:
        if not needs_simplify:
            return True
        if active_simplify_windows and _is_after_simplify(rev_item):
            return True
        rev_launch_ts = float(rev_item.get("launch_ts") or 0.0)
        rev_step_idx = rev_item.get("step_idx")
        if rev_step_idx is not None and rev_step_idx in all_simplify_steps:
            return False

        marks_before = [m for m in candidate_marks if float(m.get("ts") or 0.0) <= rev_launch_ts]
        if marks_before:
            rev_fp = marks_before[-1].get("fp")
            rev_edit_ts = min(
                (float(m.get("ts") or 0.0) for m in marks_before if m.get("fp") == rev_fp),
                default=0.0,
            )
            next_edit_ts = min(
                (
                    float(m.get("ts") or 0.0)
                    for m in candidate_marks
                    if float(m.get("ts") or 0.0) > rev_launch_ts and m.get("fp") != rev_fp
                ),
                default=float("inf"),
            )
        elif marks_truncated:
            tx_ev = _get_tx_edits()
            prior_ends = [ets for sts, ets in tx_ev["edit_spans"] if sts <= rev_launch_ts]
            rev_edit_ts = max([first_ts_val] + prior_ends)
            if tx_ev["covered_from_ts"] > rev_edit_ts + 1.0:
                return False
            later_starts = [sts for sts, _ in tx_ev["edit_spans"] if sts > rev_launch_ts]
            later_marks = [
                float(m.get("ts") or 0.0) for m in candidate_marks if float(m.get("ts") or 0.0) > rev_launch_ts
            ]
            next_edit_ts = min(later_starts + later_marks, default=float("inf"))
        else:
            rev_edit_ts = first_ts_val
            next_edit_ts = min(
                (float(m.get("ts") or 0.0) for m in candidate_marks if float(m.get("ts") or 0.0) > rev_launch_ts),
                default=float("inf"),
            )

        allowed_tiers = {"sonnet", "fallback"} if sonnet_issue else {"sonnet"}
        ver_runs = [
            sr
            for sr in all_simplify_history
            if sr.get("tier") in allowed_tiers
            and (rev_edit_ts - 1e-6) <= float(sr.get("launch_ts") or 0.0) < next_edit_ts
        ]
        if not ver_runs:
            return False
        completed: list[dict[str, Any]] = []
        for sr in ver_runs:
            s_lts = float(sr.get("launch_ts") or 0.0)
            s_ets = max(s_lts, float(sr.get("end_ts") or s_lts))
            if s_lts <= rev_launch_ts < s_ets:
                return False
            if s_lts < rev_launch_ts:
                completed.append(sr)
        if (
            allow_combined
            and not multi_lens_spoof
            and any(sr.get("kind") == "combined" and sr.get("has_explicit_all", True) for sr in completed)
        ):
            return True
        done_lenses = {sr.get("lens") for sr in completed if sr.get("kind") == "lens" and sr.get("lens")}
        return done_lenses >= required_lenses

    def _is_round_after_its_simplify(rev_item: dict[str, Any]) -> bool:
        """Return True iff `rev_item` ran after a completed simplify pass for its candidate version."""
        if _is_after_simplify(rev_item):
            return True
        return _has_completed_simplify_for_version(rev_item)

    codex_bin_missing_cache: bool | None = None
    breaker_info_cache: dict[str, Any] | None = None
    codex_cmd_failed = bool(swarm_ev.get("codex_cmd_failed"))
    codex_issue_ts = float(swarm_ev.get("codex_issue_ts") or 0.0)
    raw_issue_step = swarm_ev.get("codex_issue_step")
    codex_issue_step = int(raw_issue_step) if isinstance(raw_issue_step, int) else -1

    def _codex_bin_missing() -> bool:
        nonlocal codex_bin_missing_cache
        if codex_bin_missing_cache is None:
            codex_bin_missing_cache = codex_lane.find_codex_binary() is None
        return codex_bin_missing_cache

    def _breaker_info() -> dict[str, Any]:
        nonlocal breaker_info_cache
        if breaker_info_cache is None:
            breaker_info_cache = codex_lane.breaker_status()
        return breaker_info_cache

    def _has_codex_issue() -> bool:
        return codex_cmd_failed or bool(_breaker_info().get("tripped")) or _codex_bin_missing()

    def _was_codex_unavailable_at(rev_item: dict[str, Any]) -> bool:
        # INVARIANT: Internal escalation is valid ONLY when launched strictly after Codex unavailability was confirmed.
        if _codex_bin_missing():
            return True
        launch_ts = float(rev_item.get("launch_ts") or 0.0)
        rev_step = rev_item.get("step_idx")
        same_or_earlier_step = isinstance(rev_step, int) and codex_issue_step >= 0 and rev_step <= codex_issue_step
        if codex_cmd_failed:
            ts_ok = codex_issue_ts <= 0.0 or (launch_ts > 0.0 and launch_ts >= codex_issue_ts)
            if not same_or_earlier_step and ts_ok:
                return True
        binfo = _breaker_info()
        if binfo.get("tripped"):
            b_ts = float(binfo.get("tripped_at") or 0.0)
            if b_ts <= 0.0 or (launch_ts > 0.0 and (launch_ts > b_ts or (launch_ts == b_ts and not same_or_earlier_step))):
                return True
        return False

    opus_issue = bool(swarm_ev.get("opus_issue_verified"))
    opus_issue_ts = float(swarm_ev.get("opus_issue_ts") or 0.0)

    def _is_acceptable_carbon_escalation(rev_item: dict[str, Any]) -> bool:
        if not opus_issue:
            return False
        if rev_item.get("escalated_from_opus"):
            return True
        if opus_issue_ts <= 0.0:
            return True
        return float(rev_item.get("launch_ts") or 0.0) >= opus_issue_ts

    def _engine_priority_error(rev_item: dict[str, Any]) -> str:
        inv_eng = str(rev_item.get("engine") or "")
        if inv_eng in ("internal-carbon", "native") and not _is_acceptable_carbon_escalation(rev_item):
            return (
                f"internal review ran on `{rev_item.get('model') or cwg.CARBON_HIGH_MODEL}` "
                f"without a verified `{cwg.OPUS_HIGH_MODEL}` error/quota/availability failure; "
                f"run internal review on `{cwg.OPUS_HIGH_MODEL}` first"
            )
        if inv_eng in ("internal-opus", "internal-carbon", "native") and not _was_codex_unavailable_at(rev_item):
            if _has_codex_issue():
                return (
                    "internal review ran before primary Codex lane (`codex_lane.py`) became unavailable; "
                    "run a fresh review after the verified Codex outage"
                )
            if swarm_ev.get("codex_timeout_seen"):
                return (
                    "internal review ran after a Codex thinking timeout while primary Codex lane (`codex_lane.py`) remained available; "
                    "a thinking timeout is NOT an outage and does NOT consume a review round — re-run `codex_lane.py review` "
                    "without `--timeout` to continue in the same Codex session with an increased timeout"
                )
            return (
                "internal review ran while primary Codex lane (`codex_lane.py`) is available; "
                "run `codex_lane.py review` first and escalate to internal review ONLY when Codex is unavailable"
            )
        return ""

    def _is_acceptable_engine(rev_item: dict[str, Any]) -> bool:
        eng_name = str(rev_item.get("engine") or "")
        return eng_name in ("codex", "internal-opus", "internal-carbon", "native") and not _engine_priority_error(rev_item)

    aborted_codex_map = dict(swarm_ev.get("aborted_codex_reviews") or {})

    def _is_aborted_codex_review(rev_item: dict[str, Any]) -> bool:
        rid = str(rev_item.get("review_id") or "")
        if not rid or rid not in aborted_codex_map:
            return False
        ab_call_ts = float(aborted_codex_map[rid] or 0.0)
        rev_lts = float(rev_item.get("launch_ts") or 0.0)
        return ab_call_ts <= 0.0 or rev_lts >= ab_call_ts - 5.0

    active_codex_reviews = [r for r in codex_reviews if not _is_aborted_codex_review(r)]
    all_reviews = sorted(
        list(sub_ev["reviews"]) + list(swarm_ev["reviews"]) + active_codex_reviews,
        key=lambda r: float(r.get("verdict_ts") or 0.0),
    )
    all_ordinary_reviews = [r for r in all_reviews if r.get("kind") == "ordinary"]
    all_closure_reviews = [r for r in all_reviews if r.get("kind") == "closure"]
    # INVARIANT: Disqualified engine runs (e.g. internal review while Codex is available) must never inflate
    # `MAX_REVIEW_ROUNDS`/`MAX_CLOSURE_PASSES` when the agent subsequently runs eligible Codex rounds.
    raw_ordinary_reviews = [r for r in all_ordinary_reviews if _is_acceptable_engine(r)]
    raw_closure_reviews = [r for r in all_closure_reviews if _is_acceptable_engine(r)]
    ineligible_ordinary_reviews = [r for r in all_ordinary_reviews if not _is_acceptable_engine(r)]

    def _invalidated_at_ts(rev_item: dict[str, Any]) -> float | None:
        if not candidate_marks or is_review_fresh(rev_item, marker):
            return None
        app_lts = float(rev_item.get("launch_ts") or 0.0)
        app_vts = max(app_lts, float(rev_item.get("verdict_ts") or app_lts))
        # INVARIANT: Approval/READY must still be fresh at `verdict_ts`; mid-review edits (`launch_ts < ts <= verdict_ts`)
        # mean the verdict arrived already stale and cannot reset `MAX_REVIEW_ROUNDS`.
        marks_by_verdict = [m for m in candidate_marks if float(m.get("ts") or 0.0) <= app_vts]
        if marks_by_verdict:
            if not is_review_fresh(rev_item, {"content_marks": marks_by_verdict}):
                return None
            covered_fps = {
                m.get("fp")
                for m in marks_by_verdict
                if m.get("fp") and float(m.get("ts") or 0.0) <= app_lts
            }
            for m in candidate_marks:
                mts = float(m.get("ts") or 0.0)
                if mts <= app_vts:
                    continue
                mfp = m.get("fp")
                if (mfp and mfp not in covered_fps) or (not mfp and m.get("unknown")):
                    return mts
            return None
        if not marks_truncated or app_lts < first_ts_val - 2.0 or app_vts >= oldest_mark_ts:
            return None
        tx_ev = _get_tx_edits()
        if tx_ev["covered_from_ts"] > app_lts + 1.0:
            return None
        for sts, ets in tx_ev["edit_spans"]:
            if sts <= app_vts and (ets > app_lts or sts == app_lts):
                return None
        post_edits = [t for t in tx_ev["proven_change_ts"] if app_vts < t < oldest_mark_ts]
        distinct_tail_fps = {m.get("fp") for m in candidate_marks if m.get("fp")}
        if not post_edits and len(distinct_tail_fps) < 2 and not any(m.get("unknown") for m in candidate_marks):
            return None
        return min([oldest_mark_ts] + post_edits)

    def _is_valid_cycle_approval(rev_item: dict[str, Any]) -> bool:
        if str(rev_item.get("verdict") or "") != "APPROVED":
            return False
        if effective_risk == "XHIGH" and not rev_item.get("xhigh"):
            return False
        if not _has_completed_simplify_for_version(rev_item):
            return False
        return True

    def _has_prior_terminal_approval(ord_list: list[dict[str, Any]]) -> bool:
        return any(
            _is_valid_cycle_approval(prev_r) and (_invalidated_at_ts(prev_r) is not None or is_review_fresh(prev_r, marker))
            for prev_r in ord_list[:-1]
        )

    def _is_swarm_v2_closure_ready(
        ord_list: list[dict[str, Any]],
        cls_rev: dict[str, Any],
    ) -> bool:
        if not (needs_simplify and active_simplify_windows):
            return False
        if str(cls_rev.get("verdict") or "") != "READY":
            return False
        if effective_risk == "XHIGH" and not cls_rev.get("xhigh"):
            return False
        if not _is_after_simplify(cls_rev) or not is_review_fresh(cls_rev, marker):
            return False
        if not (1 <= len(ord_list) <= MAX_REVIEW_ROUNDS):
            return False
        if post_simplify_ordinary or post_simplify_ineligible:
            return False
        min_sim_ts = min((w[0] for w in active_simplify_windows), default=0.0)
        if min_sim_ts <= 0.0:
            return False
        if any(float(r.get("launch_ts") or 0.0) >= min_sim_ts for r in ord_list):
            return False
        last_ord = ord_list[-1]
        last_ord_v = str(last_ord.get("verdict") or "")
        if last_ord_v not in ("APPROVED", "REVISE", "ESCALATE"):
            return False
        if last_ord_v != "APPROVED" and len(ord_list) != MAX_REVIEW_ROUNDS:
            return False
        last_ord_vts = max(
            float(last_ord.get("launch_ts") or 0.0),
            float(last_ord.get("verdict_ts") or 0.0),
        )
        return float(cls_rev.get("launch_ts") or 0.0) >= last_ord_vts

    def _is_valid_cycle_closure_ready(
        ord_list: list[dict[str, Any]],
        cls_rev: dict[str, Any],
    ) -> bool:
        if len(ord_list) != MAX_REVIEW_ROUNDS or str(cls_rev.get("verdict") or "") != "READY":
            return False
        if _has_prior_terminal_approval(ord_list):
            return False
        if effective_risk == "XHIGH" and not cls_rev.get("xhigh"):
            return False
        if not _has_completed_simplify_for_version(cls_rev):
            return False
        if not all(_has_completed_simplify_for_version(r) for r in ord_list):
            return False
        last_ord = ord_list[-1]
        if str(last_ord.get("verdict") or "") not in ("REVISE", "ESCALATE"):
            return False
        last_ord_vts = max(
            float(last_ord.get("launch_ts") or 0.0),
            float(last_ord.get("verdict_ts") or 0.0),
        )
        return float(cls_rev.get("launch_ts") or 0.0) >= last_ord_vts

    def _is_version_simplify_measured(rev_item: dict[str, Any]) -> bool:
        rev_launch_ts = float(rev_item.get("launch_ts") or 0.0)
        if any(float(m.get("ts") or 0.0) <= rev_launch_ts for m in candidate_marks):
            return True
        if not marks_truncated:
            return True
        tx_ev = _get_tx_edits()
        prior_ends = [ets for sts, ets in tx_ev["edit_spans"] if sts <= rev_launch_ts]
        rev_edit_ts = max([first_ts_val] + prior_ends)
        return bool(tx_ev["covered_from_ts"] <= rev_edit_ts + 1.0)

    def _counts_toward_round_cap(rev_item: dict[str, Any]) -> bool:
        if not (needs_simplify and active_simplify_windows):
            return True
        if _is_round_after_its_simplify(rev_item):
            return True
        if str(rev_item.get("verdict") or "") == "APPROVED":
            return True
        # SAFETY: Fail closed when truncated marks + transcript gap leave an older round's simplify state unmeasured.
        return not _is_version_simplify_measured(rev_item)

    # INVARIANT: A valid terminal `APPROVED` (within `MAX_REVIEW_ROUNDS`) or round-3 `CLOSURE_VALIDATION: READY`
    # that is later invalidated by post-verdict durable edits starts a fresh `1..MAX_REVIEW_ROUNDS` cycle once
    # post-edit review runs, without laundering over-limit cycles, `BLOCKED` passes, or mid-review edits.
    raw_eligible_reviews = sorted(
        raw_ordinary_reviews + raw_closure_reviews,
        key=lambda r: (float(r.get("verdict_ts") or 0.0), float(r.get("launch_ts") or 0.0)),
    )
    cycle_cutoff_ts = 0.0
    cycle_raw_ordinary: list[dict[str, Any]] = []
    cycle_counted_ordinary_n = 0
    cycle_raw_closure: list[dict[str, Any]] = []
    pending_reset_ts: float | None = None
    pending_reset_kind = ""

    def _within_cycle_ordinary_caps() -> bool:
        return (
            cycle_counted_ordinary_n <= MAX_REVIEW_ROUNDS
            and len(cycle_raw_ordinary) <= MAX_RAW_ORDINARY_ROUNDS
        )

    def _reset_cycle(cutoff: float) -> None:
        nonlocal cycle_cutoff_ts, cycle_raw_ordinary, cycle_counted_ordinary_n, cycle_raw_closure
        nonlocal pending_reset_ts, pending_reset_kind
        cycle_cutoff_ts = cutoff
        cycle_raw_ordinary = []
        cycle_counted_ordinary_n = 0
        cycle_raw_closure = []
        pending_reset_ts = None
        pending_reset_kind = ""

    for rev in raw_eligible_reviews:
        rev_lts = float(rev.get("launch_ts") or 0.0)
        if pending_reset_ts is not None and rev_lts >= pending_reset_ts:
            _reset_cycle(pending_reset_ts)
        if rev.get("kind") == "ordinary":
            cycle_raw_ordinary.append(rev)
            if _counts_toward_round_cap(rev):
                cycle_counted_ordinary_n += 1
            if (
                not cycle_raw_closure
                and _within_cycle_ordinary_caps()
                and not _has_prior_terminal_approval(cycle_raw_ordinary)
                and _is_valid_cycle_approval(rev)
            ):
                pending_reset_ts = _invalidated_at_ts(rev)
                pending_reset_kind = "APPROVED" if pending_reset_ts is not None else ""
            else:
                pending_reset_ts = None
                pending_reset_kind = ""
        else:
            cycle_raw_closure.append(rev)
            valid_so_far = [r for r in cycle_raw_ordinary if _has_completed_simplify_for_version(r)]
            if _within_cycle_ordinary_caps() and _is_valid_cycle_closure_ready(valid_so_far, rev):
                pending_reset_ts = _invalidated_at_ts(rev)
                pending_reset_kind = "READY" if pending_reset_ts is not None else ""
            else:
                pending_reset_ts = None
                pending_reset_kind = ""

    if pending_reset_ts is not None and any(
        float(r.get("launch_ts") or 0.0) >= pending_reset_ts
        for r in ineligible_ordinary_reviews
    ):
        _reset_cycle(pending_reset_ts)

    cycle_ineligible_ordinary = (
        [r for r in ineligible_ordinary_reviews if float(r.get("launch_ts") or 0.0) >= cycle_cutoff_ts]
        if cycle_cutoff_ts > 0.0
        else ineligible_ordinary_reviews
    )

    post_simplify_ordinary = [r for r in cycle_raw_ordinary if _is_round_after_its_simplify(r)]
    post_simplify_closure = [r for r in cycle_raw_closure if _is_round_after_its_simplify(r)]
    post_simplify_ineligible = [r for r in cycle_ineligible_ordinary if _is_round_after_its_simplify(r)]
    fresh_pre_simplify_reviews = [
        r
        for r in (cycle_raw_ordinary + cycle_raw_closure + cycle_ineligible_ordinary)
        if is_review_fresh(r, marker) and not _is_after_simplify(r)
    ]
    had_pre_simplify_review = bool(
        needs_simplify
        and active_simplify_windows
        and (
            fresh_pre_simplify_reviews
            or len(post_simplify_closure) < len(cycle_raw_closure)
        )
    )

    ordinary_reviews = post_simplify_ordinary if (needs_simplify and active_simplify_windows) else cycle_raw_ordinary
    closure_reviews = post_simplify_closure if (needs_simplify and active_simplify_windows) else cycle_raw_closure

    if not _within_cycle_ordinary_caps():
        return False, f"ordinary adversarial review exceeded MAX_REVIEW_ROUNDS={MAX_REVIEW_ROUNDS}"

    needs_review = (
        bool(cctx["needs_review"])
        if effective_risk == floor
        else (bool(cctx["needs_review"]) or cwg.requires_review(effective_risk, policy))
    )

    simplify_partially_started = bool(effective_lenses or raw_sonnet_map or raw_fallback_map)
    if unstarted_simplify_reason and not (rkind == "draft-blocked" and simplify_exhausted):
        if needs_review and not simplify_partially_started:
            if not cycle_raw_ordinary and not cycle_raw_closure:
                if cycle_ineligible_ordinary:
                    prio_err = _engine_priority_error(cycle_ineligible_ordinary[-1])
                    if prio_err:
                        return False, prio_err
                return (
                    False,
                    f"{effective_risk} candidate requires primary independent review first (`codex_lane.py review` -> `{cwg.OPUS_HIGH_MODEL}` -> `{cwg.CARBON_HIGH_MODEL}`) BEFORE simplify (`UNITTEST -> REVIEW -> SIMPLIFY -> --closure`)",
                )
            if cycle_raw_ordinary:
                last_pre_rev = cycle_raw_ordinary[-1]
                last_pre_v = str(last_pre_rev.get("verdict") or "")
                if last_pre_v in ("REVISE", "ESCALATE") and len(cycle_raw_ordinary) < MAX_REVIEW_ROUNDS:
                    return (
                        False,
                        f"invoked adversarial review ended in `{last_pre_v}`, not `APPROVED`; resolve findings with `codex_lane.py review` BEFORE running simplify",
                    )
                if last_pre_v == "APPROVED" and not is_review_fresh(last_pre_rev, marker):
                    return (
                        False,
                        f"{effective_risk} candidate's primary `APPROVED` verdict is stale: run primary `codex_lane.py review` BEFORE simplify",
                    )
                if effective_risk == "XHIGH" and last_pre_v == "APPROVED" and not last_pre_rev.get("xhigh"):
                    return (
                        False,
                        f"XHIGH candidate's primary `APPROVED` verdict came from standard tier, not XHIGH; run XHIGH review BEFORE simplify",
                    )
        return False, unstarted_simplify_reason

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

    total_review_failures = list(sub_ev.get("review_failures") or []) + list(swarm_ev.get("review_failures") or [])
    review_unavailable = (len(total_review_failures) >= 2) or (
        len(total_review_failures) >= 1 and opus_issue and _has_codex_issue()
    )

    closure_ready_rev: dict[str, Any] | None = None
    if (
        latest_cls_rev is not None
        and is_review_fresh(latest_cls_rev, marker)
        and _is_after_simplify(latest_cls_rev)
        and (
            _is_valid_cycle_closure_ready(ordinary_reviews, latest_cls_rev)
            or _is_swarm_v2_closure_ready(cycle_raw_ordinary, latest_cls_rev)
        )
    ):
        closure_ready_rev = latest_cls_rev

    if (
        closure_ready_rev is None
        and pending_reset_kind != "READY"
        and rkind != "draft-blocked"
        and len(cycle_raw_closure) > MAX_CLOSURE_PASSES
    ):
        return False, f"closure validation exceeded MAX_CLOSURE_PASSES={MAX_CLOSURE_PASSES}"

    if rkind == "verified":
        if closure_ready_rev is not None:
            return True, "verified"
        if pending_reset_kind == "READY":
            return (
                False,
                f"{effective_risk} candidate's `CLOSURE_VALIDATION: READY` verdict is stale: durable candidate content changed after review",
            )
        if len(ordinary_reviews) == MAX_REVIEW_ROUNDS and latest_ord_verdict in ("REVISE", "ESCALATE"):
            if len(post_simplify_closure) < len(cycle_raw_closure):
                return False, PRE_SIMPLIFY_REVIEW_ERR
            if latest_cls_verdict == "BLOCKED" and latest_cls_rev and is_review_fresh(latest_cls_rev, marker):
                return (
                    False,
                    f"invoked adversarial review ended in `{latest_ord_verdict}` and closure validation returned `BLOCKED`, not `READY`",
                )
            return (
                False,
                f"invoked adversarial review ended in `{latest_ord_verdict}`, not `APPROVED` "
                f"(all {MAX_REVIEW_ROUNDS} ordinary rounds used; run `{_CLOSURE_PHASE_FLAG}` for `CLOSURE_VALIDATION: READY`)",
            )
        if latest_ord_verdict and latest_ord_verdict != "APPROVED":
            return False, f"invoked adversarial review ended in `{latest_ord_verdict}`, not `APPROVED`"
        if not needs_review and not ordinary_reviews and all_ordinary_reviews:
            last_any = all_ordinary_reviews[-1]
            last_any_v = str(last_any.get("verdict") or "")
            if last_any_v and last_any_v != "APPROVED":
                return False, f"invoked adversarial review ended in `{last_any_v}`, not `APPROVED`"
            prio_err = _engine_priority_error(last_any)
            if prio_err:
                return False, prio_err
        if needs_review:
            if latest_ord_verdict != "APPROVED" or latest_ord_rev is None:
                if post_simplify_ineligible:
                    prio_err = _engine_priority_error(post_simplify_ineligible[-1])
                    if prio_err:
                        return False, prio_err
                if had_pre_simplify_review:
                    return False, PRE_SIMPLIFY_REVIEW_ERR
                if (
                    raw_ordinary_reviews
                    and str(raw_ordinary_reviews[-1].get("verdict") or "") == "APPROVED"
                    and not is_review_fresh(raw_ordinary_reviews[-1], marker)
                ):
                    return (
                        False,
                        f"{effective_risk} candidate's `APPROVED` verdict is stale: durable candidate content changed after review",
                    )
                return (
                    False,
                    f"{effective_risk} candidate lacks an independent `VERDICT: APPROVED` from Codex lane (`codex_lane.py review`, or internal `{cwg.OPUS_HIGH_MODEL}` -> `{cwg.CARBON_HIGH_MODEL}` only on verified outage)",
                )
            if not is_review_fresh(latest_ord_rev, marker):
                return (
                    False,
                    f"{effective_risk} candidate's `APPROVED` verdict is stale: durable candidate content changed after review",
                )
            if not _is_after_simplify(latest_ord_rev):
                return False, PRE_SIMPLIFY_REVIEW_ERR
            eng = str(latest_ord_rev.get("engine") or "")
            if effective_risk == "XHIGH" and not latest_ord_rev.get("xhigh"):
                return (
                    False,
                    f"XHIGH candidate's `APPROVED` verdict came from standard tier (`{eng}`), not XHIGH (`codex --xhigh` or internal `{cwg.OPUS_HIGH_MODEL}` with `REVIEW_TIER: XHIGH`)",
                )
        return True, "verified"

    if rkind == "pr-ready":
        if closure_ready_rev is not None:
            return True, "pr-ready"
        if had_pre_simplify_review and (
            len(ordinary_reviews) < MAX_REVIEW_ROUNDS or len(post_simplify_closure) < len(cycle_raw_closure)
        ):
            return False, PRE_SIMPLIFY_REVIEW_ERR
        if len(ordinary_reviews) < MAX_REVIEW_ROUNDS or latest_ord_verdict not in ("ESCALATE", "REVISE"):
            return False, "`pr-ready` requires round-3 `ESCALATE`/`REVISE` followed by fresh `CLOSURE_VALIDATION: READY`"
        return False, "`pr-ready` lacks fresh `CLOSURE_VALIDATION: READY` from an eligible review engine"

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


def _merge_sticky_outage_state(state: dict[str, Any], swarm_ev: dict[str, Any]) -> None:
    # INVARIANT: Propagate the earliest confirmed candidate outage timestamp bidirectionally between `state` and `swarm_ev`
    # so a later in-window Opus failure never overwrites an earlier evicted Opus outage that authorized a Carbon fallback review.
    if swarm_ev.get("sonnet_issue_verified") or state.get("sonnet_issue_verified"):
        state["sonnet_issue_verified"] = True
        swarm_ev["sonnet_issue_verified"] = True
    if swarm_ev.get("opus_issue_verified") or state.get("opus_issue_verified"):
        state["opus_issue_verified"] = True
        swarm_ev["opus_issue_verified"] = True
        obs_opus_ts = float(swarm_ev.get("opus_issue_ts") or 0.0)
        prev_opus_ts = float(state.get("opus_issue_ts") or 0.0)
        eff_opus_ts = (
            min(obs_opus_ts, prev_opus_ts)
            if (obs_opus_ts > 0.0 and prev_opus_ts > 0.0)
            else (obs_opus_ts or prev_opus_ts)
        )
        state["opus_issue_ts"] = eff_opus_ts
        swarm_ev["opus_issue_ts"] = eff_opus_ts


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
            "total_waits": 0,
            "notify_reminders": 0,
            "closed_ts": time.time(),
            "last_receipt": receipt_summary,
            "block_nonce": "",
            "candidate_first_ts": 0.0,
            "sonnet_issue_verified": False,
            "opus_issue_verified": False,
            "opus_issue_ts": 0.0,
        }
    )
    rio.write_json(state_file, state)
    cwg.clear_claim(session)
    cwg.clear_swarm_rounds(session)


def _has_notified_anomaly_handler(
    steps: list[dict[str, Any]],
    handler_session: str,
    first_ts: float,
    report_id: str,
    session: str = "",
) -> bool:
    target = rio.safe_key(handler_session, "")
    rid_low = (report_id or "").strip().lower()
    if not target or not rid_low:
        return True
    if session and gate_inbox.bus_has_anomaly_notification(session, target, first_ts, rid_low):
        return True
    notify_tools = frozenset(
        {
            "send_message",
            "mcp_chat-bus_peers_chat_send",
            "peers_chat_send",
            "chat_send",
            "call_mcp_tool",
            "run_command",
        }
    )
    for idx, st in enumerate(steps):
        if st.get("source") != "MODEL" or st.get("type") != "PLANNER_RESPONSE":
            continue
        call_ts = rio.parse_iso_ts(st.get("created_at"))
        if call_ts and call_ts < first_ts - 2.0:
            continue
        tcs = st.get("tool_calls") or []
        if not any(isinstance(tc, dict) and tc.get("name") in notify_tools for tc in tcs):
            continue
        generic_steps = _collect_generic_results(steps, idx)
        for pos, tc in enumerate(tcs):
            if not isinstance(tc, dict) or pos >= len(generic_steps):
                continue
            tname = str(tc.get("name") or "")
            if tname not in notify_tools:
                continue
            g_status, g_blob, _ = generic_steps[pos]
            if g_status != "DONE":
                continue
            g_json = _extract_json_dict(g_blob)
            if g_json is not None and (g_json.get("ok") is False or g_json.get("error")):
                continue
            args = tc.get("args") or {}
            if not isinstance(args, dict):
                continue
            if tname == "send_message":
                recip = rio.safe_key(str(args.get("Recipient") or ""), "")
                msg = str(args.get("Message") or "").lower()
                if recip == target and rid_low in msg:
                    return True
            elif tname == "run_command":
                cmd_low = str(args.get("CommandLine") or "").lower()
                if "chat_bus_cli" in cmd_low and "send" in cmd_low and target.lower() in cmd_low and rid_low in cmd_low:
                    return True
            else:
                eff_args = args
                if tname == "call_mcp_tool":
                    if str(args.get("ToolName") or "").strip() != "chat_send":
                        continue
                    sub_args = args.get("Arguments")
                    eff_args = sub_args if isinstance(sub_args, dict) else {}
                to_val = str(eff_args.get("to") or "").strip().lower()
                msg = str(eff_args.get("message") or "").lower()
                if rid_low in msg and (target.lower() in to_val or "anomaly" in to_val):
                    return True
    return False


def _enforce_swarm_worker_post_before_stop(
    payload: dict[str, Any],
    session: str,
    transcript_path: str | None,
) -> bool:
    # SAFETY: Block active swarm workers from ending a turn with plain assistant text and zero `post_message` after a board assignment.
    if not transcript_path:
        return False
    head_steps = rio.read_transcript_head(transcript_path, head_lines=8)
    winfo = rio.resolve_swarm_worker_assignment(transcript_path, steps=head_steps, conversation_id=session)
    if winfo is None:
        return False
    raw_board = rio.read_jsonl(winfo["board_path"])
    if not raw_board:
        return False

    wname = str(winfo["worker_name"])
    last_assign_seq, last_reply_seq = rio.latest_board_assign_and_reply_seq(
        raw_board, wname, added_by=str(winfo.get("added_by") or "")
    )
    if last_assign_seq <= 0 or last_reply_seq >= last_assign_seq:
        return False

    w_steps = rio.read_transcript_steps(transcript_path, max_lines=400)
    turn = rio.inspect_worker_turn_after_wake(w_steps, last_assign_seq)
    if turn["max_wake_seq"] > 0 and not turn["woke_for_assign"]:
        return False
    if turn["has_error"] or turn["called_post"] or turn["pending_bg"]:
        return False
    if payload.get("fullyIdle") is False and any(
        isinstance(tc, dict) and tc.get("name") == "invoke_subagent" for tc in turn["last_model_tcs"]
    ):
        return False

    wsfile = cwg.enforcement_state_path(session)
    wstate = rio.read_json(wsfile, default={})
    if not isinstance(wstate, dict):
        wstate = {}
    rem_count = (
        int(wstate.get("worker_post_reminders") or 0)
        if int(wstate.get("worker_post_assign_seq") or 0) == last_assign_seq
        else 0
    )
    if rem_count >= MAX_WORKER_POST_REMINDERS:
        return False
    wstate["worker_post_assign_seq"] = last_assign_seq
    wstate["worker_post_reminders"] = rem_count + 1
    rio.write_json(wsfile, wstate)
    rio.log_hook_event(
        "gate-events",
        "worker_unposted_stop_block",
        session=session,
        worker=wname,
        coordinator=winfo["coordinator"],
        assign_seq=last_assign_seq,
        reminder=rem_count + 1,
    )
    rio.emit_stop_continue(
        f"[Swarm Worker Stop Guard] Получено задание на доске (#{last_assign_seq} для @{wname}), "
        "но ход завершается без вызова `post_message`. Обычный текст ответа не попадает на доску роя "
        "и приводит к вечному зависанию координатора в `swarm_wait`.\n"
        "Вызовите `post_message(text=\"@coordinator ...\")` с вашим результатом перед завершением хода."
    )
    return True


def format_block_message(
    reason: str,
    block_num: int,
    marker: dict[str, Any],
    session: str,
    nonce: str,
    ctx: dict[str, Any] | None = None,
) -> str:
    wclass = cwg.candidate_class(marker)
    cctx = ctx or cwg.resolve_candidate_context(marker)
    policy = cctx["policy"]
    req_tests = cctx["require_tests"]
    has_tests = (
        bool(req_tests)
        if req_tests is not None
        else cwg.requires_tests(
            cctx["floor"], cwd=cctx["cwd"], paths=cctx["dpaths"], policy=policy, git_root=cctx["git_root"]
        )
    )
    floor = cctx["floor"]
    inbox_script = rio.normalize_path(rio.plugin_root() / "hooks" / "gate_inbox.py")
    codex_script = rio.normalize_path(rio.plugin_root() / "hooks" / "codex_lane.py")

    if wclass == cwg.WORK_OPERATIONAL:
        guidance = (
            "Для OPERATIONAL-работы завершите ответ последней строкой:\n"
            "`[gate] operational: <предпроверка>; <подтверждённый эффект>`\n"
            "или `[gate] no-change: <причина>`, если изменений не произошло."
        )
    else:
        reqs = cwg.receipt_requirements_summary(floor, policy, has_tests=has_tests)
        xhigh_hint = " с `REVIEW_TIER: XHIGH`" if floor == "XHIGH" else ""
        is_fast_path = (
            bool(cctx["fast_path"])
            if "fast_path" in cctx
            else cwg.is_simplify_fast_path_eligible(
                marker=marker,
                repo_root=str(marker.get("git_root") or marker.get("cwd") or ""),
            )
        )
        if cctx["needs_simplify"]:
            if floor == "STANDARD" or is_fast_path:
                fp_note = "STANDARD по политике проекта" if floor == "STANDARD" else "Swarm 2.0 Fast-Path: <=2 файлов и <=30 строк"
                simplify_hint = (
                    f"- Для simplify ({fp_note}) запустите 1 объединённый read-only воркер `simplify-reviewer` "
                    f"(`SIMPLIFY_LENS: ALL`) на `{cwg.SONNET_HIGH_MODEL}` через `swarm(action=\"add\", name=\"simplify-reviewer\", model=\"{cwg.SONNET_HIGH_MODEL}\")` "
                    f"(при сбое/0% квоты Sonnet — `model=\"{cwg.SIMPLIFY_FALLBACK_MODEL}\"`).\n"
                )
            else:
                simplify_hint = (
                    f"- Для simplify (`{floor}`) запустите строго 3 отдельные параллельные линзы (`reuse`, `quality`, `efficiency`) "
                    f"на `{cwg.SONNET_HIGH_MODEL}` через `swarm(action=\"add\", ..., model=\"{cwg.SONNET_HIGH_MODEL}\")` "
                    f"(при сбое/0% квоты Sonnet — `model=\"{cwg.SIMPLIFY_FALLBACK_MODEL}\"`, никогда не `{cwg.CARBON_HIGH_MODEL}`).\n"
                )
        else:
            simplify_hint = ""

        if cctx["needs_review"]:
            phase_flag = f"{_CLOSURE_PHASE_FLAG} " if (_CLOSURE_PHASE_FLAG in reason or "--closure" in reason) else ""
            xhigh_flag = "--xhigh " if floor == "XHIGH" else ""
            cls_mode_note = " в режиме `CLOSURE_VALIDATION: READY|BLOCKED`" if phase_flag else ""
            kill_note = " (перед `--closure` пакетно завершите `waiting` воркеров через `swarm(action=\"kill\", ...)`)" if phase_flag else ""
            review_hint = (
                f"- Для независимого ревью сначала проверьте `python -X utf8 \"{codex_script}\" check`; "
                f"если доступно — запустите `python -X utf8 \"{codex_script}\" review --session \"{session}\" {phase_flag}{xhigh_flag}--summary \"...\"`{kill_note} "
                f"(при недоступности Codex запустите внутреннее ревью{cls_mode_note} на `{cwg.OPUS_HIGH_MODEL}`{xhigh_hint} через `swarm`, с эскалацией на `{cwg.CARBON_HIGH_MODEL}` при ошибке/квоте Opus).\n"
            )
        else:
            review_hint = ""

        guidance = (
            f"Кандидат `PERSISTENT` (риск `{floor}`). Обязательные условия: {reqs}.\n"
            f"{simplify_hint}"
            f"{review_hint}"
            f"- Завершите финальный ответ строкой `[gate] verified: {floor}; <кандидат и решающие проверки>`."
        )

    # SAFETY: Strip PowerShell metacharacters (backticks, quotes, `$`, newlines) from CLI/tool hint arguments so
    # copy-pasted `gate_inbox.py report --block "..."` commands never suffer PS escape corruption (`R -> \r, `A -> \a).
    safe_reason = re.sub(r"[`'\"$\\\r\n]+", "", reason).strip() or "gate_block"
    handler_sess = gate_inbox.get_handler_session()
    bus_cli = rio.chat_bus_cli_path()
    if handler_sess and handler_sess != session:
        escape_tail = (
            f"отправьте уведомление дежурному чату аномалий через `chat-bus` "
            f"(`python -X utf8 \"{bus_cli}\" send --from-chat \"{session}\" --to \"{handler_sess}\" "
            f"--message \"[GATE_ANOMALY <id>] session={session}; block={safe_reason[:80]}; facts=...\"` с `BypassSandbox=true`; "
            f"внутри того же проекта также допустим `send_message(Recipient=\"{handler_sess}\", ...)`) "
            f"и закройте ответ строкой `[gate] anomaly-reported: <id>; <факт>` "
            f"(ссылка для отчёта: `[Чат аномалий](conversation://{handler_sess})`)."
        )
    else:
        escape_tail = "и закройте ответ строкой `[gate] anomaly-reported: <id>; <факт>`."

    return (
        f"[Code Work Gate] Остановка заблокирована ({block_num}/{MAX_BLOCKS_PER_CANDIDATE} для неизменённого кандидата): {reason}.\n"
        f"{guidance}\n"
        f"Если блокировка противоречит проверяемым фактам транскрипта, не уходите в цикл: зафиксируйте отчёт (с `BypassSandbox=true`) "
        f"`python -X utf8 \"{inbox_script}\" report --session \"{session}\" --nonce \"{nonce}\" "
        f"--block \"{safe_reason[:120]}\" --facts \"<факты>\" --did \"<выполненные проверки>\"`, "
        f"{escape_tail}"
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

        # Fast exit on NO_CHANGE sessions before touching multi-thousand-line transcript files
        session = rio.session_key(payload)
        transcript_path = payload.get("transcriptPath")
        if _enforce_swarm_worker_post_before_stop(payload, session, transcript_path):
            return 0
        mfile = cwg.marker_path(session)
        if not mfile.is_file():
            rio.emit_stop_allow()
            return 0

        raw_marker = rio.read_json(mfile, default=None)
        if not isinstance(raw_marker, dict) or raw_marker.get("closed"):
            rio.emit_stop_allow()
            return 0

        steps = rio.read_transcript_steps(transcript_path)
        if rio.is_subagent_session(transcript_path, steps=steps):
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
            state["total_waits"] = 0
            state["notify_reminders"] = 0
            state["block_nonce"] = ""

        first_ts = float(marker.get("first_ts") or 0.0)
        if float(state.get("candidate_first_ts") or 0.0) != first_ts:
            state["candidate_first_ts"] = first_ts
            state["sonnet_issue_verified"] = False
            state["opus_issue_verified"] = False
            state["opus_issue_ts"] = 0.0
        assistant_msg = str(payload.get("lastAssistantMessage") or "") or rio.last_assistant_message(steps)
        receipt = cwg.parse_terminal_receipt(assistant_msg)
        cctx: dict[str, Any] | None = None

        if receipt and receipt.get("kind") == "anomaly-reported":
            ok_anom, anom_note = gate_inbox.verify_anomaly_report(
                str(receipt.get("report_id") or ""),
                session=session,
                expected_nonce=state.get("block_nonce") or None,
            )
            if ok_anom:
                handler_sess = gate_inbox.get_handler_session()
                if handler_sess and handler_sess != session:
                    if _has_notified_anomaly_handler(steps, handler_sess, first_ts, anom_note, session=session):
                        gate_inbox.mark_handler_notified(anom_note)
                    elif int(state.get("notify_reminders") or 0) < 1:
                        # SAFETY: Preserve `state["block_nonce"]` and cap reminder at 1 so the filed report stays valid and finite.
                        state["notify_reminders"] = int(state.get("notify_reminders") or 0) + 1
                        rio.write_json(sfile, state)
                        rio.log_hook_event(
                            "gate-events",
                            "notify_handler_reminder",
                            session=session,
                            report=anom_note,
                            handler_session=handler_sess,
                        )
                        bus_cli = rio.chat_bus_cli_path()
                        rio.emit_stop_continue(
                            f"[Code Work Gate] Отчёт об аномалии `{anom_note}` сохранён, но дежурный чат аномалий "
                            f"`{handler_sess}` ещё не уведомлён.\n"
                            f"Отправьте уведомление через `chat-bus` (`python -X utf8 \"{bus_cli}\" send --from-chat \"{session}\" "
                            f"--to \"{handler_sess}\" --message \"[GATE_ANOMALY {anom_note}] session={session}; block=...; facts=...\"` "
                            f"с `BypassSandbox=true` — работает между разными проектами; внутри одного проекта допустим `send_message`) "
                            f"и повторите закрытие строкой `[gate] anomaly-reported: {anom_note}; <факт>` "
                            f"(`[Чат аномалий](conversation://{handler_sess})`)."
                        )
                        return 0
                retire_candidate(session, mfile, sfile, state, f"anomaly-reported:{anom_note}")
                rio.log_hook_event("gate-events", "close", session=session, receipt="anomaly-reported", report=anom_note)
                rio.emit_stop_allow()
                return 0
            valid, reason = False, anom_note
            cctx = cwg.resolve_candidate_context(marker)
        else:
            checks_ev = read_checks_evidence(session, first_ts)
            sub_ev = scan_native_subagents(steps, transcript_path, first_ts)
            eff_cwd = str(marker.get("git_root") or marker.get("cwd") or rio.effective_cwd(payload) or "")
            swarm_ev = scan_swarm_activity(
                steps,
                transcript_path,
                first_ts,
                round_start_msg_id=int(marker.get("round_start_msg_id") or 0),
                current_diff_hash=str(marker.get("current_diff_hash") or ""),
                cwd=eff_cwd,
            )
            _merge_sticky_outage_state(state, swarm_ev)
            codex_revs = codex_lane.scan_verified_codex_reviews(
                since_ts=first_ts,
                session=session,
                git_root=str(marker.get("git_root") or ""),
            )
            cctx = cwg.resolve_candidate_context(marker)
            valid, reason = validate_candidate_closure(
                receipt,
                marker,
                checks_ev,
                sub_ev,
                swarm_ev,
                codex_revs,
                ctx=cctx,
                steps=steps,
                transcript_path=transcript_path,
            )

            if valid:
                rkind = str((receipt or {}).get("kind") or "verified")
                retire_candidate(session, mfile, sfile, state, rkind)
                rio.log_hook_event(
                    "gate-events",
                    "close",
                    session=session,
                    receipt=rkind,
                    floor=cctx["floor"],
                )
                rio.emit_stop_allow()
                return 0

            stalled_workers = list(swarm_ev.get("stalled_workers") or [])
            if stalled_workers:
                stalled_desc = ", ".join(
                    f"{sw['worker']} ({sw['idle_sec']}s >= {sw['timeout_sec']}s)"
                    for sw in stalled_workers
                )
                reason = (
                    f"[Swarm Stall Watchdog] Зависли in-flight воркеры без новых сообщений в `board.jsonl` "
                    f"и активности в `.swarm/`: {stalled_desc}. Перезапустите или перепинайте зависшего воркера вместо ожидания."
                )
            else:
                fully_idle = payload.get("fullyIdle", True)
                in_flight = (
                    list(sub_ev.get("in_flight_subagents") or [])
                    + list(swarm_ev.get("in_flight_workers") or [])
                    + [f"bg:{t}" for t in (swarm_ev.get("pending_bg_tasks") or [])]
                )
                # SAFETY: Unkilled `waiting` swarm workers keep host `fullyIdle=False` even after replying; require real `in_flight` work.
                effective_not_idle = (fully_idle is False) and not bool(swarm_ev.get("idle_unkilled_workers"))
                # Only worker/subagent output advances `progress_sig` (never coordinator turn count), plus a hard per-candidate cap.
                progress_sig = (
                    f"{swarm_ev.get('worker_activity_count', 0)}:"
                    f"{len(sub_ev.get('reviews', []))}:"
                    f"{len(sub_ev.get('fallback_lenses', {}))}:"
                    f"{1 if (swarm_ev.get('sonnet_combined_ts') or swarm_ev.get('fallback_combined_ts') or sub_ev.get('fallback_combined_ts')) else 0}"
                )
                waits = 0 if state.get("last_wait_progress") != progress_sig else int(state.get("waits") or 0)
                total_waits = int(state.get("total_waits") or 0)
                if (
                    (effective_not_idle or in_flight)
                    and waits < MAX_BACKGROUND_WAITS
                    and total_waits < MAX_TOTAL_BACKGROUND_WAITS
                ):
                    state["waits"] = waits + 1
                    state["total_waits"] = total_waits + 1
                    state["last_wait_progress"] = progress_sig
                    rio.write_json(sfile, state)
                    rio.log_hook_event(
                        "gate-events",
                        "background_wait",
                        session=session,
                        waits=waits + 1,
                        total_waits=total_waits + 1,
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
            floor=cctx["floor"],
        )
        msg = format_block_message(
            reason=reason,
            block_num=blocks + 1,
            marker=marker,
            session=session,
            nonce=nonce,
            ctx=cctx,
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
    rio.maybe_exec_rust_cli("cwg-stop")
    sys.exit(main())
