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
    for rec in rio.read_jsonl(path):
        ts = float(rec.get("ts") or 0.0)
        if rec.get("kind") == "skill_read" and rec.get("skill"):
            skills_read.add(str(rec["skill"]))
        elif rec.get("kind") == "check" and ts >= first_ts - 1.0:
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


SIMPLIFY_COMBINED_NAME_RE = re.compile(r"^simplify(?:-reviewer)?(?:-r\d+)?$", re.IGNORECASE)
SYSTEM_SWARM_ERR_RE = re.compile(
    r'\[Message\]\s+timestamp=\S+\s+sender=system\b[^\n]*Swarm Worker \((?P<name>[A-Za-z0-9._-]+)\)[^\n]*with id "(?P<cid>[A-Za-z0-9._-]+)" encountered an error[^\n]*?:\s*(?P<err>.+)',
    re.IGNORECASE,
)
MODEL_FAILURE_RE = re.compile(
    r"(?:RESOURCE_EXHAUSTED|quota[^\n]{0,30}(?:exceeded|exhausted|reached|0%)|"
    r"rate[ _-]limit|429\b|503\b|502\b|"
    r"model[^\n]{0,40}(?:unavailable|at\s+capacity|not\s+found|not\s+supported|invalid|unknown)|"
    r"(?:unknown|invalid|unsupported)\s+model|"
    r"overloaded|not\s+eligible|internal\s+server\s+error|deadline[ _-]exceeded|timed?\s*out)",
    re.IGNORECASE,
)


def _classify_simplify_worker(name: str, brief_or_role: str, output_text: str) -> tuple[str, str | None]:
    """Classify worker as ('lens', <lens>), ('combined', None), or ('other', None) in one pass."""
    text = output_text or ""
    has_verdict = bool(cwg.SIMPLIFY_LINE_RE.search(text))
    if cwg.SIMPLIFY_COMBINED_LENS_RE.search(text):
        return ("combined", None) if has_verdict else ("other", None)

    explicit = {m.lower() for m in cwg.SIMPLIFY_LENS_LINE_RE.findall(text)}
    if len(explicit) == 1:
        return ("lens", next(iter(explicit)))
    if len(explicit) > 1:
        return ("combined", None) if has_verdict else ("other", None)

    low_name = (name or "").lower()
    for lens in cwg.SIMPLIFY_LENSES:
        if lens in low_name:
            return ("lens", lens)

    if SIMPLIFY_COMBINED_NAME_RE.match((name or "").strip()):
        return ("combined", None) if has_verdict else ("other", None)

    if "simplify" in low_name or "simplify" in (brief_or_role or "").lower():
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


def scan_swarm_activity(
    steps: list[dict[str, Any]],
    transcript_path: str | None,
    first_ts: float,
) -> dict[str, Any]:
    """Verify native Antigravity `swarm` workers (`members.json` + `board.jsonl` + member transcripts)."""
    sonnet_lenses: dict[str, float] = {}
    fallback_lenses: dict[str, float] = {}
    sonnet_combined_ts = 0.0
    fallback_combined_ts = 0.0
    simplify_failures = 0
    reviews: list[dict[str, Any]] = []
    review_failures: list[float] = []
    in_flight_workers: list[str] = []
    opus_issue_verified = False
    opus_issue_ts = 0.0
    sonnet_issue_verified = False
    board_head = 0

    def _mark_opus_issue(ts_val: float) -> None:
        nonlocal opus_issue_verified, opus_issue_ts
        opus_issue_verified = True
        eff = ts_val or time.time()
        if opus_issue_ts <= 0.0 or eff < opus_issue_ts:
            opus_issue_ts = eff

    requested_models: dict[str, set[str]] = {}
    model_switches: dict[str, list[tuple[float, str]]] = {}
    coord_call_events: list[tuple[float, str]] = []
    host_worker_errors: dict[tuple[str, str], float] = {}

    # 1. Inspect parent `swarm` / `post_message` tool calls and host `sender=system` worker error notifications
    for idx, st in enumerate(steps):
        if st.get("source") == "SYSTEM":
            sys_ts = rio.parse_iso_ts(st.get("created_at"))
            if not sys_ts or sys_ts >= first_ts - 2.0:
                for sm in SYSTEM_SWARM_ERR_RE.finditer(str(st.get("content") or "")):
                    if MODEL_FAILURE_RE.search(sm.group("err")):
                        key = (sm.group("name"), sm.group("cid"))
                        host_worker_errors[key] = max(host_worker_errors.get(key, 0.0), sys_ts or time.time())
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
                    coord_call_events.append((call_ts, str(targs.get("text") or "").strip().lower()[:64]))
                elif tname == "swarm" and str(targs.get("action") or "").strip().lower() == "add":
                    base_n = str(targs.get("name") or "").strip()
                    tasks_arg = targs.get("tasks") if isinstance(targs.get("tasks"), list) else []
                    n_raw = targs.get("n")
                    n_cnt = int(n_raw) if isinstance(n_raw, int) or (isinstance(n_raw, str) and n_raw.isdigit()) else 1
                    copies = max(1, len(tasks_arg), n_cnt)
                    for copy_idx in range(copies):
                        hint = (
                            f"@{base_n}-{copy_idx + 1}".lower()
                            if (copies > 1 and base_n)
                            else (f"@{base_n}".lower() if base_n else "")
                        )
                        coord_call_events.append((call_ts, hint))
        if not any(isinstance(tc, dict) and tc.get("name") == "swarm" for tc in all_tcs):
            continue

        g_cur = idx + 1
        generic_steps: list[tuple[str, str]] = []
        while g_cur < len(steps) and steps[g_cur].get("type") == "GENERIC":
            generic_steps.append((str(steps[g_cur].get("status") or ""), str(steps[g_cur].get("content") or "")))
            g_cur += 1

        for pos, tc in enumerate(all_tcs):
            if not isinstance(tc, dict) or tc.get("name") != "swarm":
                continue
            args = tc.get("args") if isinstance(tc.get("args"), dict) else {}
            action = str(args.get("action") or "").strip().lower()
            wname = str(args.get("name") or "").strip()
            req_model = str(args.get("model") or "").strip().lower()
            g_status, blob = generic_steps[pos] if pos < len(generic_steps) else ("", "")
            mdata = _extract_json_dict(blob)

            if wname and req_model:
                requested_models.setdefault(wname, set()).add(req_model)
            if action == "model" and wname and call_ts:
                model_switches.setdefault(wname, []).append((call_ts, f"[model-switch:{req_model}]"))

            if action == "models" and mdata is not None:
                avail = set(mdata.get("models") or [])
                quotas = mdata.get("quotas") or {}
                if avail:
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
            # SECURITY INVARIANT: Only model/quota/availability failures count (never duplicate worker names or bad args).
            if is_err and MODEL_FAILURE_RE.search(err_detail):
                if cwg.OPUS_HIGH_MODEL in req_model:
                    _mark_opus_issue(call_ts)
                    review_failures.append(call_ts or time.time())
                elif cwg.SONNET_HIGH_MODEL in req_model:
                    sonnet_issue_verified = True
                    simplify_failures += 1

    # 2. Locate `<brain>/<convId>/.system_generated/swarm/{members.json, board.jsonl}`
    conv_dir: pathlib.Path | None = None
    brain_root: pathlib.Path | None = None
    if transcript_path:
        p = pathlib.Path(transcript_path).resolve()
        if len(p.parents) >= 4 and p.parents[1].name == ".system_generated":
            conv_dir = p.parents[2]
            brain_root = p.parents[3]

    if conv_dir is None:
        return {
            "sonnet_lenses": sonnet_lenses,
            "fallback_lenses": fallback_lenses,
            "sonnet_combined_ts": sonnet_combined_ts,
            "fallback_combined_ts": fallback_combined_ts,
            "simplify_failures": simplify_failures,
            "reviews": reviews,
            "review_failures": review_failures,
            "in_flight_workers": in_flight_workers,
            "opus_issue_verified": opus_issue_verified,
            "opus_issue_ts": opus_issue_ts,
            "sonnet_issue_verified": sonnet_issue_verified,
            "board_head": board_head,
        }

    swarm_dir = cwg.swarm_dir(brain_root, conv_dir.name)
    members_map = cwg.load_swarm_members(brain_root, conv_dir.name)
    if not members_map:
        return {
            "sonnet_lenses": sonnet_lenses,
            "fallback_lenses": fallback_lenses,
            "sonnet_combined_ts": sonnet_combined_ts,
            "fallback_combined_ts": fallback_combined_ts,
            "simplify_failures": simplify_failures,
            "reviews": reviews,
            "review_failures": review_failures,
            "in_flight_workers": in_flight_workers,
            "opus_issue_verified": opus_issue_verified,
            "opus_issue_ts": opus_issue_ts,
            "sonnet_issue_verified": sonnet_issue_verified,
            "board_head": board_head,
        }

    raw_board = rio.read_jsonl(swarm_dir / "board.jsonl")
    board_head = len(raw_board)
    coord_call_events.sort(key=lambda item: item[0])
    c_cursor = 0
    running_board_ts = 0.0
    parsed_board: list[tuple[str, str, float]] = []
    for bp in raw_board:
        poster = str(bp.get("agent") or "")
        btext = str(bp.get("text") or "").strip()
        raw_bts = rio.parse_iso_ts(bp.get("time"))
        bts = raw_bts
        if poster == "coordinator" and raw_bts:
            low_btext = btext.lower()
            probe = c_cursor
            while probe < len(coord_call_events) and coord_call_events[probe][0] < raw_bts - 0.1:
                probe += 1
            for cand_i in range(probe, len(coord_call_events)):
                evt_ts, evt_hint = coord_call_events[cand_i]
                if evt_ts - raw_bts >= 1.5:
                    break
                if not evt_hint or evt_hint in low_btext:
                    bts = evt_ts
                    c_cursor = cand_i + 1
                    break
        if bts and running_board_ts and bts < running_board_ts:
            # `board.jsonl` is strictly append-only; clamp whole-second floor truncation to preceding board timestamp.
            bts = running_board_ts
        if bts > running_board_ts:
            running_board_ts = bts
        parsed_board.append((poster, btext, bts))

    for mname, minfo in members_map.items():
        if not isinstance(minfo, dict):
            continue
        if cwg.is_swarm_role_member(mname, minfo):
            continue

        cur_model = str(minfo.get("model") or "").strip().lower()
        mcid = str(minfo.get("conversation_id") or "").strip()
        killed = cwg.is_swarm_member_killed(minfo)
        group_prefix = mname.rsplit("-", 1)[0] if re.search(r"-\d+$", mname) else ""

        # Coordinator assignment posts targeting this worker (`coord_posts` drives in-flight; `broadcast_posts` also updates launch windows)
        coord_posts: list[tuple[float, str]] = []
        broadcast_posts: list[tuple[float, str]] = []
        worker_board_posts: list[tuple[float, str]] = []
        mention_pats = [re.compile(rf"(?<![A-Za-z0-9_-])@{re.escape(mname)}(?![A-Za-z0-9_-])", re.IGNORECASE)]
        if group_prefix:
            mention_pats.append(re.compile(rf"(?<![A-Za-z0-9_-])@{re.escape(group_prefix)}(?![A-Za-z0-9_-])", re.IGNORECASE))

        for poster, btext, bts in parsed_board:
            if not btext:
                continue
            if poster == "coordinator":
                if any(mp.search(btext) for mp in mention_pats):
                    coord_posts.append((bts, btext))
                elif "@all" in btext.lower():
                    broadcast_posts.append((bts, btext))
            elif poster == mname:
                # SECURITY INVARIANT: Only posts authored by `mname` itself count as worker output (never coordinator prompts).
                if not bts or bts >= first_ts - 2.0:
                    worker_board_posts.append((bts or time.time(), btext))

        m_tp = cwg.member_transcript_path(brain_root, mcid) if (brain_root and mcid) else None
        tsum = _member_transcript_summary(m_tp, first_ts)

        prior_reqs = set(requested_models.get(mname, set()))
        if group_prefix:
            prior_reqs |= set(requested_models.get(group_prefix, set()))

        host_err_ts = host_worker_errors.get((mname, mcid), 0.0) if mcid else 0.0
        if tsum["has_error"] or host_err_ts > 0.0:
            eff_err_ts = max(tsum["error_ts"], host_err_ts)
            if cur_model == cwg.OPUS_HIGH_MODEL or cwg.OPUS_HIGH_MODEL in prior_reqs:
                _mark_opus_issue(eff_err_ts)
                review_failures.append(eff_err_ts or time.time())
            if cur_model == cwg.SONNET_HIGH_MODEL or cwg.SONNET_HIGH_MODEL in prior_reqs:
                sonnet_issue_verified = True
                simplify_failures += 1

        # Combine worker board posts and worker transcript outputs, upgrading whole-second board times with exact transcript timestamps
        tsum_outs: list[tuple[float, str]] = list(tsum["outputs"])
        t_cursor = 0
        matched_t: set[int] = set()
        combined_outputs: list[tuple[float, str]] = []
        for bts, btxt in worker_board_posts:
            eff_ots = bts
            for tidx in range(t_cursor, len(tsum_outs)):
                ots, otxt = tsum_outs[tidx]
                if otxt == btxt and abs(ots - bts) < 5.0:
                    eff_ots = max(eff_ots, ots)
                    matched_t.add(tidx)
                    t_cursor = tidx + 1
                    break
            combined_outputs.append((eff_ots, btxt))
        for tidx, (ots, otxt) in enumerate(tsum_outs):
            if tidx not in matched_t:
                combined_outputs.append((ots, otxt))
        combined_outputs.sort(key=lambda pair: pair[0])

        latest_assign_ts = coord_posts[-1][0] if coord_posts else tsum["start_ts"]
        latest_brief = "\n".join(txt for _, txt in coord_posts)
        has_reply_since_assign = bool(
            combined_outputs and (not latest_assign_ts or combined_outputs[-1][0] >= latest_assign_ts - 1.0)
        )
        eff_park_ts = max(tsum["parked_ts"], host_err_ts)
        parked_after_assign = bool(
            (tsum["parked_or_done"] or host_err_ts > 0.0)
            and (not latest_assign_ts or not eff_park_ts or eff_park_ts >= latest_assign_ts - 0.5)
        )

        if not killed and latest_assign_ts >= first_ts - 2.0 and not has_reply_since_assign and not parked_after_assign:
            in_flight_workers.append(f"swarm:{mname}")
            continue

        if not combined_outputs:
            continue

        # Group outputs by coordinator assignment/broadcast/switch window for both simplify lenses and adversarial reviewers
        windows: list[tuple[float, str]] = sorted(
            list(coord_posts) + list(broadcast_posts) + list(model_switches.get(mname, [])),
            key=lambda pair: pair[0],
        )
        if not windows:
            windows = [(tsum["start_ts"] or first_ts, "")]

        bucketed_outputs: dict[int, list[tuple[float, str]]] = {}
        for out_ts, out_txt in combined_outputs:
            w_idx = 0
            for cand_idx, (wts, _) in enumerate(windows):
                if not wts or wts <= out_ts + 0.5:
                    w_idx = cand_idx
            bucketed_outputs.setdefault(w_idx, []).append((out_ts, out_txt))

        joined_worker_text = "\n\n".join(txt for _, txt in combined_outputs)
        skind, slens = _classify_simplify_worker(mname, latest_brief, joined_worker_text)
        if skind == "lens" and slens is not None:
            for w_idx in sorted(bucketed_outputs):
                win_ts, _ = windows[w_idx]
                win_txt = "\n\n".join(otxt for _, otxt in bucketed_outputs[w_idx])
                if cwg.SIMPLIFY_LINE_RE.search(win_txt):
                    eff_lts = win_ts or tsum["start_ts"] or first_ts
                    if cur_model == cwg.SONNET_HIGH_MODEL:
                        sonnet_lenses[slens] = max(sonnet_lenses.get(slens, 0.0), eff_lts)
                    elif cur_model == cwg.CARBON_HIGH_MODEL:
                        fallback_lenses[slens] = max(fallback_lenses.get(slens, 0.0), eff_lts)
            continue

        if skind == "combined":
            for w_idx in sorted(bucketed_outputs):
                win_ts, _ = windows[w_idx]
                win_txt = "\n\n".join(otxt for _, otxt in bucketed_outputs[w_idx])
                if cwg.SIMPLIFY_LINE_RE.search(win_txt):
                    eff_lts = win_ts or tsum["start_ts"] or first_ts
                    if cur_model == cwg.SONNET_HIGH_MODEL:
                        sonnet_combined_ts = max(sonnet_combined_ts, eff_lts)
                    elif cur_model == cwg.CARBON_HIGH_MODEL:
                        fallback_combined_ts = max(fallback_combined_ts, eff_lts)
            continue

        if cur_model not in (cwg.OPUS_HIGH_MODEL, cwg.CARBON_HIGH_MODEL):
            continue
        eng = "internal-opus" if cur_model == cwg.OPUS_HIGH_MODEL else "internal-carbon"
        escalated_from_opus = cwg.OPUS_HIGH_MODEL in prior_reqs
        for w_idx in sorted(bucketed_outputs):
            win_ts, win_brief = windows[w_idx]
            win_outs = bucketed_outputs[w_idx]
            eff_launch_ts = win_ts or tsum["start_ts"] or first_ts
            eff_end_ts = max(eff_launch_ts, max((ots for ots, _ in win_outs), default=eff_launch_ts))
            win_txt = "\n\n".join(otxt for _, otxt in win_outs)
            is_xhigh = (
                ("xhigh" in mname.lower())
                or bool(cwg.REVIEW_TIER_XHIGH_RE.search(latest_brief))
                or bool(cwg.REVIEW_TIER_XHIGH_RE.search(win_brief))
                or bool(cwg.REVIEW_TIER_XHIGH_RE.search(win_txt))
            )

            cls_matches = cwg.CLOSURE_LINE_RE.findall(win_txt)
            ord_matches = cwg.VERDICT_LINE_RE.findall(win_txt)
            if cls_matches:
                reviews.append(
                    {
                        "engine": eng,
                        "reviewer": mname,
                        "cid": mcid,
                        "kind": "closure",
                        "verdict": cls_matches[-1].upper(),
                        "launch_ts": eff_launch_ts,
                        "verdict_ts": eff_end_ts,
                        "xhigh": is_xhigh,
                        "model": cur_model,
                        "escalated_from_opus": escalated_from_opus,
                    }
                )
            elif ord_matches:
                reviews.append(
                    {
                        "engine": eng,
                        "reviewer": mname,
                        "cid": mcid,
                        "kind": "ordinary",
                        "verdict": ord_matches[-1].upper(),
                        "launch_ts": eff_launch_ts,
                        "verdict_ts": eff_end_ts,
                        "xhigh": is_xhigh,
                        "model": cur_model,
                        "escalated_from_opus": escalated_from_opus,
                    }
                )

    worker_activity_count = sum(
        1 for poster, btext, _ in parsed_board if btext and poster and poster != "coordinator"
    )
    return {
        "sonnet_lenses": sonnet_lenses,
        "fallback_lenses": fallback_lenses,
        "sonnet_combined_ts": sonnet_combined_ts,
        "fallback_combined_ts": fallback_combined_ts,
        "simplify_failures": simplify_failures,
        "reviews": reviews,
        "review_failures": review_failures,
        "in_flight_workers": in_flight_workers,
        "opus_issue_verified": opus_issue_verified,
        "opus_issue_ts": opus_issue_ts,
        "sonnet_issue_verified": sonnet_issue_verified,
        "board_head": board_head,
        "worker_activity_count": worker_activity_count,
    }


def scan_native_subagents(
    steps: list[dict[str, Any]],
    transcript_path: str | None,
    first_ts: float,
) -> dict[str, Any]:
    """Deterministically bind parent `invoke_subagent` calls to subagent system transcripts & messages."""
    brain_root: pathlib.Path | None = None
    if transcript_path:
        p = pathlib.Path(transcript_path).resolve()
        if len(p.parents) >= 4 and p.parents[1].name == ".system_generated":
            brain_root = p.parents[3]

    delivered_by_sender: dict[str, list[tuple[float, str]]] = {}
    for st in steps:
        if st.get("source") == "SYSTEM" and st.get("type") == "SYSTEM_MESSAGE":
            m = rio.SUBAGENT_MSG_RE.search(str(st.get("content") or ""))
            if m:
                sender = m.group("sender")
                msg_ts = rio.parse_iso_ts(m.group("ts")) or rio.parse_iso_ts(st.get("created_at"))
                delivered_by_sender.setdefault(sender, []).append((msg_ts, m.group("body").strip()))

    fallback_lenses: dict[str, float] = {}
    fallback_combined_ts = 0.0
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

        generic_Cursor = idx + 1
        generic_steps: list[tuple[str, str]] = []
        while generic_Cursor < len(steps) and steps[generic_Cursor].get("type") == "GENERIC":
            generic_steps.append(
                (str(steps[generic_Cursor].get("status") or ""), str(steps[generic_Cursor].get("content") or ""))
            )
            generic_Cursor += 1

        for pos, tc in enumerate(tcs):
            if not isinstance(tc, dict) or tc.get("name") != "invoke_subagent":
                continue
            args = tc.get("args") if isinstance(tc.get("args"), dict) else {}
            tname = str(args.get("TypeName") or "").strip()
            base_tname = tname.rsplit(":", 1)[-1]
            role_str = str(args.get("Role") or "").strip()
            prompt_str = str(args.get("Prompt") or "").strip()
            is_simplify_subagent = (
                base_tname in cwg.SIMPLIFY_LENS_AGENTS
                or base_tname == cwg.SIMPLIFY_REVIEWER
                or (base_tname == "research" and "simplify" in role_str.lower())
            )
            model_arg = str(args.get("Model") or "inherit").strip()
            g_status, blob = generic_steps[pos] if pos < len(generic_steps) else ("", "")
            sm = SUBAGENT_URI_RE.search(blob)
            if not sm:
                if g_status == "ERROR" or "error" in blob.lower() or "failed" in blob.lower():
                    if is_simplify_subagent:
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
                if sub_text.strip() and cwg.SIMPLIFY_LINE_RE.search(sub_text):
                    skind, slens = _classify_simplify_worker(base_tname, f"{role_str}\n{prompt_str}", sub_text)
                    if skind == "lens" and slens is not None:
                        fallback_lenses[slens] = max(fallback_lenses.get(slens, 0.0), eff_launch_ts)
                    elif skind == "combined":
                        fallback_combined_ts = max(fallback_combined_ts, eff_launch_ts)
                elif not sub_text.strip():
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
        "fallback_lenses": fallback_lenses,
        "fallback_combined_ts": fallback_combined_ts,
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


def validate_candidate_closure(
    receipt: dict[str, Any] | None,
    marker: dict[str, Any],
    checks_ev: dict[str, Any],
    sub_ev: dict[str, Any],
    swarm_ev: dict[str, Any],
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

    # 2. Proportionate 3-Lens Simplify Verification on `claude-sonnet-5-5-high` (non-small STANDARD, HIGH, XHIGH)
    needs_simplify = (effective_risk in ("HIGH", "XHIGH")) or (
        effective_risk == "STANDARD" and not small
    )
    required_lenses = set(cwg.SIMPLIFY_LENSES)
    raw_sonnet_map: dict[str, float] = dict(swarm_ev.get("sonnet_lenses") or {})
    raw_fallback_map: dict[str, float] = {}
    for src_map in (swarm_ev.get("fallback_lenses") or {}, sub_ev.get("fallback_lenses") or {}):
        for k, v in dict(src_map).items():
            raw_fallback_map[k] = max(raw_fallback_map.get(k, 0.0), float(v or 0.0))

    sonnet_lenses = {k for k, lts in raw_sonnet_map.items() if is_review_fresh({"launch_ts": lts}, marker)}
    fallback_lenses = {k for k, lts in raw_fallback_map.items() if is_review_fresh({"launch_ts": lts}, marker)}
    stale_sonnet_lenses = sorted((set(raw_sonnet_map) & required_lenses) - sonnet_lenses)

    sonnet_issue = bool(swarm_ev.get("sonnet_issue_verified"))
    simplify_failures = int(swarm_ev.get("simplify_failures") or 0) + int(sub_ev.get("simplify_failures") or 0)
    simplify_exhausted = simplify_failures >= 2
    effective_lenses = (sonnet_lenses | fallback_lenses) if sonnet_issue else sonnet_lenses
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

    if needs_simplify:
        simplify_satisfied = (not missing_lenses) or (effective_risk == "STANDARD" and combined_fresh)
        if not simplify_satisfied and not (rkind == "draft-blocked" and simplify_exhausted):
            if effective_risk != "STANDARD" and (
                combined_fresh or raw_sonnet_combined > 0.0 or raw_fallback_combined > 0.0
            ):
                return (
                    False,
                    f"{effective_risk} candidate cannot collapse simplify into a single combined lane; "
                    f"run all 3 separate `{cwg.SONNET_HIGH_MODEL}` lenses (`reuse`, `quality`, `efficiency`); "
                    f"missing: {', '.join(missing_lenses)}",
                )
            if not sonnet_issue and (
                (effective_risk == "STANDARD" and fallback_combined_fresh)
                or (sonnet_lenses | fallback_lenses) >= required_lenses
            ):
                target = (
                    "`simplify-reviewer`"
                    if effective_risk == "STANDARD"
                    else "all 3 lenses (`reuse`, `quality`, `efficiency`)"
                )
                return (
                    False,
                    f"simplify ran on fallback model without verified `{cwg.SONNET_HIGH_MODEL}` error/quota issue; "
                    f"run {target} on `{cwg.SONNET_HIGH_MODEL}` via `swarm`",
                )
            if stale_sonnet_lenses or (effective_risk == "STANDARD" and combined_stale):
                stale_label = (
                    "combined simplify"
                    if (effective_risk == "STANDARD" and combined_stale and not stale_sonnet_lenses)
                    else f"simplify lenses ({', '.join(stale_sonnet_lenses)})"
                )
                return (
                    False,
                    f"{stale_label} stale because durable files changed after simplify; "
                    f"re-verify on `{cwg.SONNET_HIGH_MODEL}`",
                )
            if effective_risk == "STANDARD":
                return (
                    False,
                    f"STANDARD candidate requires 1 combined `simplify-reviewer` lane (`SIMPLIFY_LENS: ALL`) "
                    f"or all 3 lenses on `{cwg.SONNET_HIGH_MODEL}` via `swarm`",
                )
            return (
                False,
                f"{effective_risk} candidate requires all 3 separate `{cwg.SONNET_HIGH_MODEL}` simplify lenses "
                f"(`reuse`, `quality`, `efficiency`); missing: {', '.join(missing_lenses)}",
            )

    # 3. Independent Adversarial Review Verification (Codex lane unchanged; internal `claude-opus-5-5-high` -> `gemini-4-carbon-high`)
    all_reviews = sorted(
        list(sub_ev["reviews"]) + list(swarm_ev["reviews"]) + list(codex_reviews),
        key=lambda r: float(r.get("verdict_ts") or 0.0),
    )
    ordinary_reviews = [r for r in all_reviews if r.get("kind") == "ordinary"]
    closure_reviews = [r for r in all_reviews if r.get("kind") == "closure"]

    if len(ordinary_reviews) > MAX_REVIEW_ROUNDS:
        return False, f"ordinary adversarial review exceeded MAX_REVIEW_ROUNDS={MAX_REVIEW_ROUNDS}"
    if len(closure_reviews) > MAX_CLOSURE_PASSES:
        return False, f"closure validation exceeded MAX_CLOSURE_PASSES={MAX_CLOSURE_PASSES}"

    norm_ordinary: list[tuple[dict[str, Any], str]] = []
    for idx, rev in enumerate(ordinary_reviews, start=1):
        v = str(rev.get("verdict") or "")
        if v == "ESCALATE" and idx < MAX_REVIEW_ROUNDS:
            v = "REVISE"
        norm_ordinary.append((rev, v))

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

    def _is_acceptable_engine(rev_item: dict[str, Any]) -> bool:
        eng_name = str(rev_item.get("engine") or "")
        if eng_name in ("codex", "internal-opus"):
            return True
        if eng_name in ("internal-carbon", "native") and _is_acceptable_carbon_escalation(rev_item):
            return True
        return False

    for earlier_rev, earlier_v in norm_ordinary[:-1]:
        if earlier_v == "APPROVED" and is_review_fresh(earlier_rev, marker) and _is_acceptable_engine(earlier_rev):
            if effective_risk != "XHIGH" or earlier_rev.get("xhigh"):
                return False, "review rounds continued unnecessarily after a current terminal APPROVED"

    latest_ord_rev, latest_ord_verdict = norm_ordinary[-1] if norm_ordinary else (None, "")
    latest_cls_rev = closure_reviews[-1] if closure_reviews else None
    latest_cls_verdict = str(latest_cls_rev.get("verdict") or "") if latest_cls_rev else ""

    breaker_open = bool(codex_lane.breaker_status().get("tripped"))
    total_review_failures = list(sub_ev.get("review_failures") or []) + list(swarm_ev.get("review_failures") or [])
    review_unavailable = (len(total_review_failures) >= 2) or (
        breaker_open and opus_issue and len(total_review_failures) >= 1
    )

    closure_ready_rev: dict[str, Any] | None = None
    if (
        len(ordinary_reviews) == MAX_REVIEW_ROUNDS
        and latest_ord_verdict in ("REVISE", "ESCALATE")
        and latest_cls_verdict == "READY"
        and latest_cls_rev is not None
        and is_review_fresh(latest_cls_rev, marker)
        and _is_acceptable_engine(latest_cls_rev)
        and (effective_risk != "XHIGH" or latest_cls_rev.get("xhigh"))
    ):
        closure_ready_rev = latest_cls_rev

    if rkind == "verified":
        if closure_ready_rev is not None:
            return True, "verified"
        if latest_ord_verdict and latest_ord_verdict != "APPROVED":
            return False, f"invoked adversarial review ended in `{latest_ord_verdict}`, not `APPROVED`"
        if effective_risk in ("HIGH", "XHIGH"):
            if latest_ord_verdict != "APPROVED" or latest_ord_rev is None:
                return (
                    False,
                    f"{effective_risk} candidate lacks an independent `VERDICT: APPROVED` from Codex lane or internal `{cwg.OPUS_HIGH_MODEL}` (escalating to `{cwg.CARBON_HIGH_MODEL}` only on verified Opus issue)",
                )
            if not is_review_fresh(latest_ord_rev, marker):
                return (
                    False,
                    f"{effective_risk} candidate's `APPROVED` verdict is stale: durable candidate content changed after review",
                )
            eng = str(latest_ord_rev.get("engine") or "")
            if eng in ("internal-carbon", "native") and not _is_acceptable_carbon_escalation(latest_ord_rev):
                return (
                    False,
                    f"internal review ran on `{latest_ord_rev.get('model') or cwg.CARBON_HIGH_MODEL}` without a verified `{cwg.OPUS_HIGH_MODEL}` error/quota/availability failure; run internal review on `{cwg.OPUS_HIGH_MODEL}` first",
                )
            if effective_risk == "XHIGH" and not latest_ord_rev.get("xhigh"):
                return (
                    False,
                    f"XHIGH candidate's `APPROVED` verdict came from standard tier (`{eng}`), not XHIGH (`codex --xhigh` or internal `{cwg.OPUS_HIGH_MODEL}` with `REVIEW_TIER: XHIGH`)",
                )
        return True, "verified"

    if rkind == "pr-ready":
        if len(ordinary_reviews) < MAX_REVIEW_ROUNDS or latest_ord_verdict not in ("ESCALATE", "REVISE"):
            return False, "`pr-ready` requires round-3 `ESCALATE`/`REVISE` followed by fresh `CLOSURE_VALIDATION: READY`"
        if closure_ready_rev is None:
            return False, "`pr-ready` lacks fresh `CLOSURE_VALIDATION: READY` from an eligible review engine"
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
            "total_waits": 0,
            "closed_ts": time.time(),
            "last_receipt": receipt_summary,
            "block_nonce": "",
        }
    )
    rio.write_json(state_file, state)
    cwg.clear_claim(session)
    cwg.clear_swarm_rounds(session)


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
        xhigh_hint = " с `REVIEW_TIER: XHIGH`" if floor == "XHIGH" else ""
        if floor == "STANDARD" and not small:
            simplify_hint = (
                f"- Для simplify (`STANDARD > 3` строк) запустите 1 объединённый read-only воркер `simplify-reviewer` "
                f"(`SIMPLIFY_LENS: ALL`) на `{cwg.SONNET_HIGH_MODEL}` через `swarm(action=\"add\", name=\"simplify-reviewer\", model=\"{cwg.SONNET_HIGH_MODEL}\")`.\n"
            )
        elif floor in ("HIGH", "XHIGH"):
            simplify_hint = (
                f"- Для simplify (`{floor}`) запустите строго 3 отдельные параллельные линзы (`reuse`, `quality`, `efficiency`) "
                f"на `{cwg.SONNET_HIGH_MODEL}` через `swarm(action=\"add\", ..., model=\"{cwg.SONNET_HIGH_MODEL}\")`.\n"
            )
        else:
            simplify_hint = ""
        guidance = (
            f"Кандидат `PERSISTENT` (path floor `{floor}`). Обязательные условия: {reqs}.\n"
            f"{simplify_hint}"
            f"- Для внешнего ревью HIGH/XHIGH сначала проверьте `python -X utf8 \"{codex_script}\" check`; "
            f"если доступно — запустите `python -X utf8 \"{codex_script}\" review --session \"{session}\" --summary \"...\"` "
            f"{'--xhigh ' if floor == 'XHIGH' else ''}(при недоступности Codex запустите внутреннее ревью на `{cwg.OPUS_HIGH_MODEL}`{xhigh_hint} через `swarm`, с эскалацией на `{cwg.CARBON_HIGH_MODEL}` при ошибке/квоте Opus).\n"
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

        # Fast exit on NO_CHANGE sessions before touching multi-thousand-line transcript files
        session = rio.session_key(payload)
        mfile = cwg.marker_path(session)
        if not mfile.is_file():
            rio.emit_stop_allow()
            return 0

        raw_marker = rio.read_json(mfile, default=None)
        if not isinstance(raw_marker, dict) or raw_marker.get("closed"):
            rio.emit_stop_allow()
            return 0

        transcript_path = payload.get("transcriptPath")
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
            state["block_nonce"] = ""

        first_ts = float(marker.get("first_ts") or 0.0)
        assistant_msg = str(payload.get("lastAssistantMessage") or "") or rio.last_assistant_message(steps)
        receipt = cwg.parse_terminal_receipt(assistant_msg)

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
            swarm_ev = scan_swarm_activity(steps, transcript_path, first_ts)
            codex_revs = codex_lane.scan_verified_codex_reviews(
                since_ts=first_ts,
                session=session,
                git_root=str(marker.get("git_root") or ""),
            )
            valid, reason = validate_candidate_closure(
                receipt, marker, checks_ev, sub_ev, swarm_ev, codex_revs
            )

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

            fully_idle = payload.get("fullyIdle", True)
            in_flight = list(sub_ev.get("in_flight_subagents") or []) + list(
                swarm_ev.get("in_flight_workers") or []
            )
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
                (fully_idle is False or in_flight)
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
