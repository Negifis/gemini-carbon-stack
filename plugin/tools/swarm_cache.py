#!/usr/bin/env python3
"""Deterministic Antigravity swarm prompt-cache TTL tracker and incremental diff generator."""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import re
import sys
import time
from typing import Any

HOOKS_DIR = pathlib.Path(__file__).resolve().parent.parent / "hooks"
sys.path.insert(0, str(HOOKS_DIR))
import cwg_common as cwg
import runtime_io as rio

EMPTY_TREE_OID = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
MAX_SWARM_WORKER_NAME_LEN = 24
MAX_ROUND_HISTORY = 16
_ROUND_SUFFIX_RE = re.compile(r"-r\d+$", re.IGNORECASE)


def _base_worker_name(worker_name: str) -> str:
    return _ROUND_SUFFIX_RE.sub("", (worker_name or "").strip())


def _rotated_worker_name(base_name: str, round_num: int) -> str:
    # INVARIANT: Native Antigravity `swarm(action="add")` rejects worker names > 24 chars; keep full `<lens>` intact via `simp-<lens>-<hash>-r<N>`.
    suffix = f"-r{round_num}"
    limit = max(1, MAX_SWARM_WORKER_NAME_LEN - len(suffix))
    stem = _base_worker_name(base_name or "worker").rstrip("-") or "w"
    low_stem = stem.lower()
    if low_stem.startswith("simplify-efficie-") and len(stem) == 21:
        stem = f"simp-efficiency-{stem[-4:]}"
        low_stem = stem.lower()
    if len(stem) <= limit:
        return f"{stem}{suffix}"
    if limit <= 5:
        return f"{stem[:limit]}{suffix}"
    digest = hashlib.sha256(stem.encode("utf-8")).hexdigest()[:4]
    if cwg.is_simplify_worker_name(low_stem):
        tag = cwg.simplify_lens_from_worker_name(low_stem) or "all"
        for dlen in (4, 3, 2):
            compact = f"simp-{tag}-{digest[:dlen]}"
            if len(compact) <= limit:
                return f"{compact}{suffix}"
    prefix = stem[: limit - 5].rstrip("-") or "w"
    return f"{prefix}-{digest}{suffix}"


def resolve_brain_root(brain_root_arg: str = "") -> pathlib.Path:
    return rio.resolve_brain_root(brain_root_arg)


def _matches_label(worker_name: str, label: str, model: str = "") -> bool:
    clean = (label or "").strip().lower()
    if not clean:
        return True
    low = (worker_name or "").strip().lower()
    model_low = (model or "").strip().lower()
    is_simplify = cwg.is_simplify_worker_name(low) or bool(cwg.simplify_lens_from_worker_name(low))
    if clean == "simplify":
        if not is_simplify:
            return False
        return not model_low or model_low in cwg.SIMPLIFY_ALLOWED_MODELS
    if clean == "review":
        if model_low and (model_low in cwg.HYDROGEN_MODEL_BY_LEVEL.values() or cwg.FLASH_MODEL_RE.search(model_low)):
            return False
        return not is_simplify and (
            model_low == cwg.OPUS_HIGH_MODEL
            or "review" in low
            or "adversarial" in low
            or "critic" in low
            or "verifier" in low
        )
    return clean in low


def _summarize_diff_stat(diff_text: str) -> str:
    if not diff_text:
        return "0 files changed"
    files = 0
    adds = 0
    dels = 0
    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            files += 1
        elif line.startswith("+") and not line.startswith("+++ "):
            adds += 1
        elif line.startswith("-") and not line.startswith("--- "):
            dels += 1
    return f"{files} file(s) changed, {adds} insertion(s)(+), {dels} deletion(s)(-)"


def _inspect_worker_transcript(worker_tp: pathlib.Path) -> dict[str, Any]:
    resolved = rio.resolve_transcript_path(str(worker_tp)) or worker_tp
    t_bytes = 0
    if resolved.is_file():
        try:
            t_bytes = resolved.stat().st_size
        except OSError:
            t_bytes = 0

    steps = rio.read_jsonl(resolved, max_lines=120) if resolved.is_file() else []
    last_model_ts = 0.0
    model_turns = 0
    last_input_tokens = 0
    last_cache_read_tokens = 0
    last_output_tokens = 0

    for st in steps:
        if st.get("source") != "MODEL":
            continue
        model_turns += 1
        ts = rio.parse_iso_ts(st.get("created_at"))
        if ts:
            last_model_ts = max(last_model_ts, ts)
        if "input_tokens" in st or "cache_read_tokens" in st:
            last_input_tokens = int(st.get("input_tokens") or 0)
            last_cache_read_tokens = int(st.get("cache_read_tokens") or 0)
            last_output_tokens = int(st.get("output_tokens") or 0)

    return {
        "transcript_path": rio.normalize_path(resolved),
        "transcript_bytes": t_bytes,
        "last_model_ts": last_model_ts,
        "model_turns": model_turns,
        "last_input_tokens": last_input_tokens,
        "last_cache_read_tokens": last_cache_read_tokens,
        "last_context_tokens": last_input_tokens + last_cache_read_tokens,
        "last_output_tokens": last_output_tokens,
    }


def inspect_swarm_workers(
    session: str,
    brain_root: pathlib.Path,
    ttl_seconds: int = cwg.SWARM_CACHE_SAFE_TTL_SECONDS,
    label: str = "",
    now_ts: float | None = None,
    current_round: int = 0,
) -> dict[str, Any]:
    now = float(now_ts) if now_ts is not None else time.time()
    members = cwg.load_swarm_members(brain_root, session)

    active: list[dict[str, Any]] = []
    killed_count = 0

    for name, meta in sorted(members.items()):
        if not isinstance(meta, dict):
            continue
        if cwg.is_swarm_role_member(name, meta):
            continue
        model = str(meta.get("model") or "").strip().lower()
        if cwg.is_swarm_member_killed(meta):
            if _matches_label(name, label, model):
                killed_count += 1
            continue
        if not _matches_label(name, label, model):
            continue

        cid = str(meta.get("conversation_id") or meta.get("conversationId") or "").strip()
        tinfo = (
            _inspect_worker_transcript(cwg.member_transcript_path(brain_root, cid))
            if cid
            else {
                "transcript_path": "",
                "transcript_bytes": 0,
                "last_model_ts": 0.0,
                "model_turns": 0,
                "last_input_tokens": 0,
                "last_cache_read_tokens": 0,
                "last_context_tokens": 0,
                "last_output_tokens": 0,
            }
        )

        last_ts = float(tinfo["last_model_ts"] or 0.0)
        if last_ts <= 0.0:
            cache_state = "NEW"
            age_s = 0.0
            rem_s = float(ttl_seconds)
            rec_action = "wait_or_assign"
        else:
            age_s = round(max(0.0, now - last_ts), 1)
            rem_s = round(max(0.0, float(ttl_seconds) - age_s), 1)
            if age_s <= ttl_seconds:
                cache_state = "WARM"
                rec_action = "resume_in_place"
            else:
                cache_state = "EXPIRED"
                rec_action = "rotate_incremental"

        active.append(
            {
                "name": name,
                "base_name": _base_worker_name(name),
                "conversation_id": cid,
                "model": model,
                "cache_state": cache_state,
                "age_seconds": age_s,
                "remaining_ttl_seconds": rem_s,
                "recommended_action": rec_action,
                **tinfo,
            }
        )

    expired = [w for w in active if w["cache_state"] == "EXPIRED"]
    warm = [w for w in active if w["cache_state"] == "WARM"]

    if not active:
        if current_round == 1:
            overall = "initial_spawn"
        elif current_round >= 2 or killed_count > 0:
            overall = "spawn_incremental"
        else:
            overall = "initial_spawn"
    elif expired:
        overall = "rotate_incremental"
    elif warm:
        overall = "resume_in_place"
    else:
        overall = "wait_or_assign"

    return {
        "session": session,
        "label": label or "all",
        "anthropic_ephemeral_ttl_seconds": cwg.ANTHROPIC_EPHEMERAL_TTL_SECONDS,
        "safe_ttl_seconds": ttl_seconds,
        "active_count": len(active),
        "killed_count": killed_count,
        "overall_action": overall,
        "expired_workers": [w["name"] for w in expired],
        "warm_workers": [w["name"] for w in warm],
        "workers": active,
    }


def _git_diff_pair(git_root: str, old_oid: str, new_oid: str, paths: list[str]) -> tuple[str, str]:
    args = ["diff", old_oid, new_oid]
    if paths:
        args.append("--")
        args.extend(paths)
    rc, out, err = rio.run_git(git_root, args, timeout=15.0)
    if rc != 0:
        detail = (err or out or "").strip() or f"rc={rc}"
        return "", f"git_diff_failed:{detail}"
    return str(out or ""), ""


def _write_scratch_text(path: pathlib.Path, content: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")
    return rio.normalize_path(path)


def _sync_round_diffs(
    git_root: str,
    head_oid: str,
    cur_tree_oid: str,
    prev_tree_oid: str,
    rel_paths: list[str],
    scratch_dir: pathlib.Path,
    clean_label: str,
    cur_round: int,
    regen: bool,
) -> tuple[str, str, str, str]:
    full_file = scratch_dir / f"{clean_label}_r{cur_round}_full.diff"
    need_full = regen or not full_file.is_file()
    full_diff = ""
    if need_full:
        full_diff, full_err = _git_diff_pair(git_root, head_oid, cur_tree_oid, rel_paths)
        if full_err:
            return "", "", "", full_err

    inc_file = scratch_dir / f"{clean_label}_r{cur_round}_incremental.diff" if (cur_round >= 2 and prev_tree_oid) else None
    need_inc = bool(inc_file is not None and (regen or not inc_file.is_file()))
    inc_diff = ""
    if need_inc:
        inc_diff, inc_err = _git_diff_pair(git_root, prev_tree_oid, cur_tree_oid, rel_paths)
        if inc_err:
            return "", "", "", inc_err

    full_diff_path = (
        _write_scratch_text(full_file, full_diff or "# No diff against HEAD.\n")
        if need_full
        else rio.normalize_path(full_file)
    )
    if inc_file is None:
        return full_diff_path, "", "", ""

    if need_inc:
        header = (
            f"# Incremental diff Round {cur_round - 1} -> Round {cur_round}\n"
            f"# Trees: {prev_tree_oid[:12]}..{cur_tree_oid[:12]}\n"
        )
        inc_diff_path = _write_scratch_text(
            inc_file,
            header + (inc_diff if inc_diff else "# No textual changes since previous round.\n"),
        )
    else:
        inc_diff_path = rio.normalize_path(inc_file)
        inc_diff = inc_file.read_text(encoding="utf-8", errors="replace")
    return full_diff_path, inc_diff_path, _summarize_diff_stat(inc_diff), ""


def prepare_round(
    session: str,
    cwd: str,
    brain_root: pathlib.Path,
    label: str = "simplify",
    ttl_seconds: int = cwg.SWARM_CACHE_SAFE_TTL_SECONDS,
    paths: list[str] | None = None,
    reset: bool = False,
    now_ts: float | None = None,
) -> dict[str, Any]:
    now = float(now_ts) if now_ts is not None else time.time()
    clean_label = rio.safe_key(label or "simplify", "simplify")
    git_root = rio.git_toplevel(cwd)
    if not git_root:
        return {"ok": False, "error": f"not_in_git_repo:{cwd}"}

    head_oid = rio.git_head_oid(git_root) or EMPTY_TREE_OID
    cur_tree_oid, tree_err = rio.capture_worktree_tree_oid(git_root)
    if not cur_tree_oid:
        return {"ok": False, "error": tree_err}

    git_root_resolved = pathlib.Path(git_root).resolve()
    rel_paths: list[str] = []
    for raw_p in paths or []:
        if not raw_p or not raw_p.strip():
            continue
        p_abs = os.path.abspath(raw_p if os.path.isabs(raw_p) else os.path.join(git_root, raw_p))
        try:
            rel_paths.append(pathlib.Path(p_abs).resolve().relative_to(git_root_resolved).as_posix())
        except ValueError:
            rel_paths.append(raw_p.replace("\\", "/"))

    skey = rio.safe_key(session)
    marker = rio.read_json(cwg.marker_path(skey), default={})
    marker_first_ts = float(marker.get("first_ts") or 0.0) if isinstance(marker, dict) else 0.0

    rounds_file = cwg.swarm_rounds_path(skey)
    state = rio.read_json(rounds_file, default={})
    if not isinstance(state, dict) or state.get("session") != session:
        state = {"session": session, "marker_first_ts": marker_first_ts, "lanes": {}}
    elif marker_first_ts and abs(float(state.get("marker_first_ts") or 0.0) - marker_first_ts) > 1.0:
        state = {"session": session, "marker_first_ts": marker_first_ts, "lanes": {}}

    lanes = state.setdefault("lanes", {})
    lane_key = f"{rio.fold_path(git_root)}|{clean_label}"
    history: list[dict[str, Any]] = [] if reset else list(lanes.get(lane_key) or [])

    changed_tree = not history or history[-1].get("tree_oid") != cur_tree_oid
    changed_paths = bool(history and history[-1].get("paths") != rel_paths)
    if changed_tree:
        next_round = (int(history[-1]["round"]) + 1) if history else 1
        history.append(
            {
                "round": next_round,
                "tree_oid": cur_tree_oid,
                "paths": rel_paths,
                "ts": round(now, 3),
            }
        )
        history = history[-MAX_ROUND_HISTORY:]
    elif changed_paths:
        history[-1] = {**history[-1], "paths": rel_paths}

    cur_round = int(history[-1]["round"])
    prev_tree_oid = str(history[-2]["tree_oid"]) if len(history) >= 2 else ""

    scratch_dir = brain_root / session / "scratch" / rio.project_key(git_root, known_git_root=git_root)
    full_diff_path, incremental_diff_path, incremental_stat, diff_err = _sync_round_diffs(
        git_root=git_root,
        head_oid=head_oid,
        cur_tree_oid=cur_tree_oid,
        prev_tree_oid=prev_tree_oid,
        rel_paths=rel_paths,
        scratch_dir=scratch_dir,
        clean_label=clean_label,
        cur_round=cur_round,
        regen=changed_tree or changed_paths,
    )
    if diff_err:
        return {"ok": False, "error": diff_err}

    if changed_tree or changed_paths:
        lanes[lane_key] = history
        state["marker_first_ts"] = marker_first_ts or float(state.get("marker_first_ts") or 0.0)
        rio.write_json(rounds_file, state)

    worker_status = inspect_swarm_workers(
        session=session,
        brain_root=brain_root,
        ttl_seconds=ttl_seconds,
        label=clean_label,
        now_ts=now,
        current_round=cur_round,
    )

    next_names = {
        w["name"]: _rotated_worker_name(w["base_name"], cur_round)
        for w in worker_status["workers"]
        if w["cache_state"] == "EXPIRED"
    }

    marker_doc = rio.read_json(cwg.marker_path(session), default=None)
    diff_metrics = cwg.compute_diff_metrics(
        marker=marker_doc if isinstance(marker_doc, dict) else {},
        repo_root=git_root or cwd,
    )
    fast_path_eligible = cwg.is_simplify_fast_path_eligible(diff_stats=diff_metrics)

    return {
        "ok": True,
        "session": session,
        "label": clean_label,
        "git_root": rio.normalize_path(git_root),
        "head_oid": head_oid,
        "round": cur_round,
        "current_tree_oid": cur_tree_oid,
        "previous_tree_oid": prev_tree_oid,
        "full_diff_path": full_diff_path,
        "incremental_diff_path": incremental_diff_path,
        "incremental_stat": incremental_stat,
        "diff_metrics": diff_metrics,
        "fast_path_eligible": fast_path_eligible,
        "overall_action": worker_status["overall_action"],
        "next_worker_names": next_names,
        "worker_status": worker_status,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="swarm_cache",
        description="Inspect Antigravity swarm worker prompt-cache TTL and prepare incremental diffs.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    st = sub.add_parser("status", help="Inspect active swarm workers and 5m ephemeral cache TTL state")
    st.add_argument("--session", required=True)
    st.add_argument("--ttl", type=int, default=cwg.SWARM_CACHE_SAFE_TTL_SECONDS)
    st.add_argument("--label", default="")
    st.add_argument("--brain-root", default="")
    st.add_argument("--pretty", action="store_true")

    pr = sub.add_parser("prepare", help="Record round worktree OID and write full/incremental diff under scratch/")
    pr.add_argument("--session", required=True)
    pr.add_argument("--cwd", default=".")
    pr.add_argument("--label", default="simplify")
    pr.add_argument("--ttl", type=int, default=cwg.SWARM_CACHE_SAFE_TTL_SECONDS)
    pr.add_argument("--brain-root", default="")
    pr.add_argument("--reset", action="store_true")
    pr.add_argument("--paths", nargs="*", default=[])
    pr.add_argument("--pretty", action="store_true")

    args = parser.parse_args()
    broot = resolve_brain_root(args.brain_root)

    if args.cmd == "status":
        out = inspect_swarm_workers(
            session=args.session,
            brain_root=broot,
            ttl_seconds=args.ttl,
            label=args.label,
        )
        rio.print_cli_json(out, pretty=args.pretty)
        return 0

    out = prepare_round(
        session=args.session,
        cwd=args.cwd,
        brain_root=broot,
        label=args.label,
        ttl_seconds=args.ttl,
        paths=list(args.paths or []),
        reset=bool(args.reset),
    )
    rio.print_cli_json(out, pretty=args.pretty)
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
