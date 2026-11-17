#!/usr/bin/env python3
"""Continuity subsystem: canonical checkpoints, compaction recovery, loop guard, correction tracking, and output lint."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import sys
import time
from typing import Any

HOOKS_DIR = pathlib.Path(__file__).resolve().parent
TOOLS_DIR = HOOKS_DIR.parent / "tools"
sys.path.insert(0, str(HOOKS_DIR))
sys.path.insert(0, str(TOOLS_DIR))

import runtime_io as rio

READ_REPEAT_DENY_LIMIT = 3
CMD_REPEAT_WARN_LIMIT = 3
CMD_REPEAT_DENY_LIMIT = 4
HANDOFF_MAX_CHARS = 900
MAX_LINT_BLOCKS_PER_EPISODE = 2
TREE_LOCK_TTL_SECONDS = 1800  # 30 minutes active heartbeat window

TEST_RUNNER_RE = re.compile(
    r"\b(?:pytest|py\.test|unittest|npm\s+test|pnpm\s+test|yarn\s+test|cargo\s+test|go\s+test|dotnet\s+test)\b",
    re.IGNORECASE,
)

CANONICAL_SECTIONS = (
    "GOAL",
    "STATUS",
    "AUTHORITATIVE STATE",
    "SUPERSEDED / CANCELLED",
    "COMPLETED",
    "CURRENT STATE",
    "DELEGATED / OWNERS",
    "NEXT ACTION",
    "ACCEPTANCE",
    "BLOCKERS",
    "STOP CONDITION",
)

STRONG_CORRECTION_RE = re.compile(
    r"(?:"
    r"\b(?:нет,\s*(?:не\s+так|переделай|отмени|убери|верни)|не\s+возвращай|вместо\s+этого\s+сделай|отменяю\s+требование|забудь\s+предыдущ)"
    r"|\b(?:no,\s*(?:instead|revert|undo|drop\s+that|wrong\s+approach)|do\s+not\s+bring\s+back|discard\s+the\s+previous|stop\s+doing\s+that)\b"
    r")",
    re.IGNORECASE,
)

EDIT_RESIDUE_RE = re.compile(
    r"(?:"
    r"в\s+предыдущей\s+(?:версии|попытке)\s+я\s+(?:сделал|написал)"
    r"|сначала\s+я\s+реализовал\s+[^.\n]{3,60},\s*но\s+затем\s+исправил"
    r"|как\s+я\s+уже\s+писал\s+до\s+исправления"
    r"|in\s+my\s+earlier\s+(?:attempt|draft)\s+I\s+(?:wrote|used)"
    r"|initially\s+I\s+implemented\s+[^.\n]{3,60},\s*but\s+now\s+I\s+changed\s+it"
    r")",
    re.IGNORECASE,
)

LINT_WAIVER_RE = re.compile(r"\[lint\]\s*intentional\s*:", re.IGNORECASE)


def continuity_dir(*parts: str) -> pathlib.Path:
    return rio.state_dir("continuity", *parts)


def session_state_path(session: str) -> pathlib.Path:
    return continuity_dir("sessions") / f"{session}.json"


def checkpoint_path(pkey: str) -> pathlib.Path:
    return continuity_dir("checkpoints") / f"{pkey}.md"


def workspace_checkpoint_path(cwd: str) -> pathlib.Path:
    return pathlib.Path(cwd) / ".agents" / "CHECKPOINT.md"


def resolve_checkpoint_file(
    cwd: str,
    workspace_paths: list[str] | None = None,
    pkey: str | None = None,
    session: str = "",
) -> pathlib.Path | None:
    ws_cp = workspace_checkpoint_path(cwd) if cwd else None
    has_ws = bool(ws_cp and ws_cp.is_file())
    eff_pkey = pkey or rio.project_key(cwd, workspace_paths, session=session)
    cp_file = checkpoint_path(eff_pkey)
    has_state = cp_file.is_file()
    if has_ws and ws_cp is not None and has_state:
        try:
            return ws_cp if ws_cp.stat().st_mtime_ns >= cp_file.stat().st_mtime_ns else cp_file
        except OSError:
            return ws_cp
    if has_ws and ws_cp is not None:
        return ws_cp
    return cp_file if has_state else None


def handoff_path(pkey: str) -> pathlib.Path:
    return continuity_dir("handoffs") / f"{pkey}.json"


def workspace_handoff_path(cwd: str) -> pathlib.Path:
    return pathlib.Path(cwd) / ".agents" / "handoff.json"


def _resolve_handoff(
    cwd: str,
    workspace_paths: list[str] | None = None,
    pkey: str | None = None,
    session: str = "",
) -> tuple[pathlib.Path | None, dict[str, Any] | None]:
    ws_ho = workspace_handoff_path(cwd) if cwd else None
    has_ws = bool(ws_ho and ws_ho.is_file())
    eff_pkey = pkey or rio.project_key(cwd, workspace_paths, session=session)
    ho_file = handoff_path(eff_pkey)
    has_state = ho_file.is_file()
    if not has_ws and not has_state:
        return None, None

    ws_raw = rio.read_json(ws_ho, default=None) if (has_ws and ws_ho is not None) else None
    ws_dict = ws_raw if isinstance(ws_raw, dict) else None
    st_raw = rio.read_json(ho_file, default=None) if has_state else None
    st_dict = st_raw if isinstance(st_raw, dict) else None

    if has_ws and ws_ho is not None and has_state:
        if ws_dict is not None and st_dict is None:
            return ws_ho, ws_dict
        if st_dict is not None and ws_dict is None:
            return ho_file, st_dict
        if ws_dict is not None and st_dict is not None and "updated_ts" in ws_dict and "updated_ts" in st_dict:
            try:
                if float(ws_dict["updated_ts"]) >= float(st_dict["updated_ts"]):
                    return ws_ho, ws_dict
                return ho_file, st_dict
            except (TypeError, ValueError):
                pass
        try:
            if ws_ho.stat().st_mtime_ns >= ho_file.stat().st_mtime_ns:
                return ws_ho, ws_dict
            return ho_file, st_dict
        except OSError:
            return ws_ho, ws_dict
    if has_ws and ws_ho is not None:
        return ws_ho, ws_dict
    return ho_file, st_dict


def resolve_handoff_file(
    cwd: str,
    workspace_paths: list[str] | None = None,
    pkey: str | None = None,
    session: str = "",
) -> pathlib.Path | None:
    return _resolve_handoff(cwd, workspace_paths, pkey=pkey, session=session)[0]


def load_handoff(
    cwd: str,
    workspace_paths: list[str] | None = None,
    pkey: str | None = None,
    session: str = "",
) -> dict[str, Any] | None:
    return _resolve_handoff(cwd, workspace_paths, pkey=pkey, session=session)[1]


def _checkpoint_supersedes_closed_handoff(cp_file: pathlib.Path, ho_path: pathlib.Path | None) -> bool:
    if ho_path is None:
        return True
    try:
        return cp_file.stat().st_mtime_ns > ho_path.stat().st_mtime_ns
    except OSError:
        return False


def active_constraints(
    cwd: str,
    workspace_paths: list[str] | None = None,
    pkey: str | None = None,
    session: str = "",
) -> tuple[str, str]:
    eff_pkey = pkey or rio.project_key(cwd, workspace_paths, session=session)
    ho_path, raw_ho = _resolve_handoff(cwd, workspace_paths, pkey=eff_pkey, session=session)
    ho_closed = isinstance(raw_ho, dict) and is_closed_status(str(raw_ho.get("status") or ""))
    if isinstance(raw_ho, dict) and not ho_closed:
        decs, sups = handoff_constraints(raw_ho)
        return "; ".join(decs)[:400], "; ".join(sups)[:300]
    cp_file = resolve_checkpoint_file(cwd, workspace_paths, pkey=eff_pkey, session=session)
    if cp_file is not None and (
        raw_ho is None or (ho_closed and _checkpoint_supersedes_closed_handoff(cp_file, ho_path))
    ):
        secs = parse_checkpoint_sections(cp_file.read_text(encoding="utf-8", errors="replace"))
        if not is_closed_status(str(secs.get("STATUS") or "")):
            auth = secs.get("AUTHORITATIVE STATE", "").strip()
            sup = secs.get("SUPERSEDED / CANCELLED", "").strip()
            return ("" if auth == "—" else auth[:400]), ("" if sup == "—" else sup[:300])
    return "", ""


def _collect_git_brief(cwd: str) -> dict[str, Any]:
    git_root = rio.git_toplevel(cwd)
    if not git_root:
        return {}
    rc_b, branch, _ = rio.run_git(git_root, ["rev-parse", "--abbrev-ref", "HEAD"])
    rc_s, st_out, _ = rio.run_git(git_root, ["status", "--short"])
    rc_d, diff_out, _ = rio.run_git(git_root, ["diff", "--stat"])
    st_lines = [ln.strip() for ln in st_out.splitlines() if ln.strip()] if rc_s == 0 else []
    diff_lines = [ln.strip() for ln in diff_out.splitlines() if ln.strip()] if rc_d == 0 else []
    return {
        "git_root": rio.normalize_path(git_root),
        "branch": branch.strip() if rc_b == 0 else "",
        "status_short": st_lines[:6],
        "status_total": len(st_lines),
        "diff_stat": diff_lines[:6],
    }


def _gate_marker_file(session: str) -> pathlib.Path:
    return rio.state_dir("gate", "markers") / f"{rio.safe_key(session)}.json"


def _open_candidate_brief(session: str) -> str:
    if not session:
        return ""
    marker = rio.read_json(_gate_marker_file(session), default=None)
    if not isinstance(marker, dict) or marker.get("closed"):
        return ""
    paths = [str(p) for p in (marker.get("paths") or []) if p and p != "<shell-mutation>"]
    if paths:
        file_names = ", ".join(pathlib.PurePosixPath(rio.normalize_path(p)).name for p in paths[:4])
        return f"PERSISTENT files={len(paths)} ({file_names})"
    if marker.get("operational"):
        return "OPERATIONAL"
    return ""


def tree_lock_path(pkey: str) -> pathlib.Path:
    return rio.state_dir("hygiene", "tree_locks") / f"{pkey}.json"


def session_index_path() -> pathlib.Path:
    return rio.state_dir("hygiene") / "sessions.jsonl"


def load_session_state(session: str) -> dict[str, Any]:
    raw = rio.read_json(session_state_path(session), default=None)
    if isinstance(raw, dict):
        return raw
    return {
        "session": session,
        "generation": 1,
        "last_user_hash": "",
        "last_step_count": 0,
        "correction_active": False,
        "strong_correction_streak": 0,
        "lint_blocks": 0,
        "tool_counts": {},
        "pending_warnings": [],
        "updated_ts": time.time(),
    }


def save_session_state(session: str, state: dict[str, Any]) -> None:
    state["updated_ts"] = time.time()
    rio.write_json(session_state_path(session), state)


def touch_tree_lock(
    session: str,
    cwd: str,
    workspace_paths: list[str] | None = None,
    release: bool = False,
    known_git_root: str | None = None,
) -> str | None:
    """Maintain non-blocking multi-session worktree lock and warn if another live session shares this checkout."""
    git_root = known_git_root if known_git_root is not None else (rio.git_toplevel(cwd) if cwd else None)
    if not git_root:
        return None
    pkey = rio.project_key(git_root, workspace_paths, known_git_root=git_root, session=session)
    lp = tree_lock_path(pkey)
    now = time.time()
    existing = rio.read_json(lp, default={})
    holders: dict[str, dict[str, Any]] = {}
    if isinstance(existing, dict) and isinstance(existing.get("holders"), dict):
        for sid, meta in existing["holders"].items():
            if isinstance(meta, dict) and now - float(meta.get("ts") or 0.0) < TREE_LOCK_TTL_SECONDS:
                holders[sid] = meta

    if release:
        holders.pop(session, None)
        rio.write_json(lp, {"git_root": rio.normalize_path(git_root), "holders": holders})
        return None

    other_sessions = [sid for sid in holders if sid != session]
    holders[session] = {"ts": now, "cwd": rio.normalize_path(cwd)}
    rio.write_json(lp, {"git_root": rio.normalize_path(git_root), "holders": holders})

    if other_sessions:
        return (
            f"[Session Hygiene] Внимание: это рабочее дерево (`{pathlib.Path(git_root).name}`) сейчас открыто "
            f"в другой активной сессии ({', '.join(s[:12] for s in other_sessions[:2])}). "
            "Не перезаписывайте чужие незакоммиченные изменения; для параллельной кодовой работы используйте изолированный worktree (`chip_handoff.py open`)."
        )
    return None


def parse_checkpoint_sections(markdown_text: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current = ""
    for line in (markdown_text or "").splitlines():
        m = re.match(r"^##\s+(.+?)\s*$", line)
        if m:
            current = m.group(1).strip().upper()
            sections.setdefault(current, [])
        elif current:
            sections[current].append(line)
    return {k: "\n".join(v).strip() for k, v in sections.items()}


def format_canonical_checkpoint(fields: dict[str, str], project_label: str = "") -> str:
    lines = [
        f"# Canonical Engineering State{f' — {project_label}' if project_label else ''}",
        f"_Updated: {time.strftime('%Y-%m-%d %H:%M:%S %z')}_",
        "",
    ]
    for sec in CANONICAL_SECTIONS:
        val = (fields.get(sec) or fields.get(sec.lower()) or "—").strip()
        lines.append(f"## {sec}")
        lines.append(val)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


_HANDOFF_PRIORITY_INDEX = 2
_HANDOFF_MIN_TRUNCATE_REMAINING = 40
_CLOSED_STATUS_RE = re.compile(r"^(?:done|completed|closed|cancelled|finished)\b", re.IGNORECASE)


def is_closed_status(status: str) -> bool:
    return bool(_CLOSED_STATUS_RE.match((status or "").strip()))


def handoff_items(ho: dict[str, Any], key: str) -> list[str]:
    val = ho.get(key)
    if isinstance(val, str):
        return [s.strip() for s in val.split(";") if s.strip()]
    if not isinstance(val, (list, tuple)):
        return []
    return [str(x).strip() for x in val if str(x).strip()]


def handoff_constraints(ho: dict[str, Any]) -> tuple[list[str], list[str]]:
    return handoff_items(ho, "decisions"), handoff_items(ho, "superseded")


def _bound_handoff_lines(lines: list[str], max_chars: int = HANDOFF_MAX_CHARS) -> str:
    if max_chars <= 0:
        return "\n".join(lines)
    out: list[str] = []
    total = 0
    for idx, line in enumerate(lines):
        sep = 1 if out else 0
        if total + sep + len(line) <= max_chars:
            out.append(line)
            total += sep + len(line)
        else:
            if idx <= _HANDOFF_PRIORITY_INDEX and total + sep + _HANDOFF_MIN_TRUNCATE_REMAINING <= max_chars:
                rem = max_chars - total - sep - 3
                out.append(line[: max(20, rem)] + "...")
            break
    return "\n".join(out)


def _format_git_line(git_brief: dict[str, Any], status_cap: int = 140, include_diff: bool = False) -> str:
    st_items = ", ".join(git_brief.get("status_short") or []) or "clean"
    git_line = f"- GIT: branch={git_brief.get('branch') or '?'} changed=[{st_items[:status_cap]}]"
    if include_diff:
        diff_items = "; ".join(git_brief.get("diff_stat") or [])
        if diff_items:
            git_line += f" diff=[{diff_items[:120]}]"
    return git_line


def compact_recovery_digest(cp_text: str, mode: str = "lead", max_chars: int = HANDOFF_MAX_CHARS) -> str:
    secs = parse_checkpoint_sections(cp_text)
    if not secs:
        return ""
    header = (
        "[Continuity — AUTHORITATIVE RECOVERY (после сжатия/перезапуска)]"
        if mode == "authoritative"
        else "[Continuity — Предыдущий Checkpoint проекта (проверьте git status)]"
    )
    picked = [header]
    for key in (
        "GOAL",
        "STATUS",
        "AUTHORITATIVE STATE",
        "SUPERSEDED / CANCELLED",
        "NEXT ACTION",
        "BLOCKERS",
        "CURRENT STATE",
    ):
        val = " ".join(secs.get(key, "").split())
        if val and val != "—":
            picked.append(f"- **{key}**: {val[:200]}")
    return _bound_handoff_lines(picked, max_chars=max_chars)


def build_repo_handoff(
    cwd: str,
    session: str = "",
    workspace_paths: list[str] | None = None,
    mode: str = "lead",
    max_chars: int = HANDOFF_MAX_CHARS,
    pkey: str | None = None,
) -> str:
    """Build a bounded structured handoff from handoff.json / CHECKPOINT.md / live git + gate state."""
    eff_pkey = pkey or rio.project_key(cwd, workspace_paths, session=session)
    ho_path, raw_ho = _resolve_handoff(cwd, workspace_paths, pkey=eff_pkey, session=session)
    ho_closed = isinstance(raw_ho, dict) and is_closed_status(str(raw_ho.get("status") or ""))
    cand = _open_candidate_brief(session)
    ho = None if (mode == "lead" and not cand and ho_closed) else raw_ho

    cp_text = ""
    if raw_ho is None or ho_closed:
        cp_file = resolve_checkpoint_file(cwd, workspace_paths, pkey=eff_pkey, session=session)
        if cp_file is not None and (raw_ho is None or _checkpoint_supersedes_closed_handoff(cp_file, ho_path)):
            ho = None
            cp_text = cp_file.read_text(encoding="utf-8", errors="replace")
            if mode == "lead" and not cand:
                cp_secs = parse_checkpoint_sections(cp_text)
                if is_closed_status(str(cp_secs.get("STATUS") or "")):
                    cp_text = ""

    git_brief = _collect_git_brief(cwd) if (mode == "authoritative" or ho is not None or cp_text) else {}

    if ho is not None:
        header = (
            "[Continuity — AUTHORITATIVE RECOVERY (handoff)]"
            if mode == "authoritative"
            else "[Continuity — Active Repo Handoff (проверьте git status)]"
        )
        lines = [header]
        if ho.get("goal"):
            lines.append(f"- GOAL: {' '.join(str(ho['goal']).split())[:180]}")
        if ho.get("status"):
            lines.append(f"- STATUS: {' '.join(str(ho['status']).split())[:80]}")
        decs, sups = handoff_constraints(ho)
        if decs:
            lines.append(f"- AUTHORITATIVE STATE: {'; '.join(decs)[:220]}")
        if sups:
            lines.append(f"- SUPERSEDED / CANCELLED: {'; '.join(sups)[:180]}")
        rems = handoff_items(ho, "remaining")
        if rems:
            lines.append(f"- NEXT ACTION: {'; '.join(rems)[:180]}")
        if git_brief:
            lines.append(_format_git_line(git_brief, status_cap=140, include_diff=True))
        if cand:
            lines.append(f"- GATE: {cand}")
        return _bound_handoff_lines(lines, max_chars=max_chars)

    if cp_text:
        cp_digest = compact_recovery_digest(
            cp_text,
            mode=mode,
            max_chars=max_chars - (160 if (git_brief or cand) else 0),
        )
        lines = [cp_digest] if cp_digest else []
        if git_brief and lines:
            lines.append(_format_git_line(git_brief, status_cap=120))
        if cand and lines:
            lines.append(f"- GATE: {cand}")
        return _bound_handoff_lines(lines, max_chars=max_chars)

    if mode == "authoritative" and (cand or (git_brief and git_brief.get("status_short"))):
        lines = ["[Continuity — AUTHORITATIVE RECOVERY (live repo state)]"]
        if git_brief:
            lines.append(_format_git_line(git_brief, status_cap=160))
            diff_items = "; ".join(git_brief.get("diff_stat") or [])
            if diff_items:
                lines.append(f"- DIFF: {diff_items[:160]}")
        if cand:
            lines.append(f"- GATE: {cand}")
        return _bound_handoff_lines(lines, max_chars=max_chars)

    return ""


def _gate_marker_mtime_ns(session: str) -> int:
    if not session:
        return 0
    mp = _gate_marker_file(session)
    try:
        return mp.stat().st_mtime_ns if mp.is_file() else 0
    except OSError:
        return 0


def _mutation_sync_token(session: str) -> str:
    return f"{rio.read_mutation_stamp(session)}:{_gate_marker_mtime_ns(session)}"


def handle_session_start(payload: dict[str, Any]) -> None:
    if rio.is_subagent_session(payload.get("transcriptPath")):
        rio.emit_json({})
        return

    session = rio.session_key(payload)
    cwd = rio.effective_cwd(payload)
    wps = payload.get("workspacePaths") if isinstance(payload.get("workspacePaths"), list) else None
    git_root = (rio.git_toplevel(cwd) or "") if cwd else ""
    pkey = rio.project_key(cwd, wps, known_git_root=git_root, session=session)
    source = str(payload.get("source") or "new").lower()

    rio.append_jsonl(
        session_index_path(),
        {
            "ts": time.time(),
            "session": session,
            "project_key": pkey,
            "cwd": rio.normalize_path(cwd),
            "model": payload.get("modelName") or "",
            "source": source,
        },
    )

    blocks: list[str] = []
    if git_root:
        lock_warn = touch_tree_lock(session, cwd, wps, known_git_root=git_root)
        state = load_session_state(session)
        state["locked_git_root"] = git_root
        save_session_state(session, state)
        if lock_warn:
            blocks.append(lock_warn)

    mode = "authoritative" if source in ("resume", "reload", "compact") else "lead"
    handoff_digest = build_repo_handoff(cwd, session=session, workspace_paths=wps, mode=mode, pkey=pkey)
    if handoff_digest:
        blocks.append(handoff_digest)

    if blocks:
        rio.emit_inject_system("\n\n".join(blocks))
    else:
        rio.emit_json({})


def detect_compaction(payload: dict[str, Any], state: dict[str, Any], steps: list[dict[str, Any]]) -> bool:
    init_steps = int(payload.get("initialNumSteps") or 0)
    prev_steps = int(state.get("last_step_count") or 0)
    if prev_steps > 12 and 0 < init_steps < prev_steps // 2:
        return True
    # Also detect Antigravity SYSTEM / CHECKPOINT step near tail of transcript
    for st in steps[-4:]:
        if st.get("source") == "SYSTEM" and st.get("type") == "CHECKPOINT":
            cp_idx = int(st.get("step_index") or 0)
            if cp_idx > int(state.get("last_compaction_step") or -1):
                state["last_compaction_step"] = cp_idx
                return True
    return False


def handle_pre_invocation(payload: dict[str, Any]) -> None:
    transcript_path = payload.get("transcriptPath")
    steps = rio.read_transcript_steps(transcript_path, max_lines=12)
    if rio.is_subagent_session(transcript_path, steps=steps):
        rio.emit_json({})
        return

    session = rio.session_key(payload)
    cwd = rio.effective_cwd(payload)
    wps = payload.get("workspacePaths") if isinstance(payload.get("workspacePaths"), list) else None
    state = load_session_state(session)

    injected: list[str] = []

    # Deliver pending warnings (e.g. loop guard warnings)
    for w in state.get("pending_warnings") or []:
        injected.append(str(w))
    state["pending_warnings"] = []

    # Detect new user turn & corrections
    user_input = str(payload.get("lastUserInput") or "").strip()
    user_hash = hashlib.sha256(user_input.encode("utf-8", errors="replace")).hexdigest()[:16] if user_input else ""
    if user_hash and user_hash != state.get("last_user_hash"):
        state["last_user_hash"] = user_hash
        state["generation"] = int(state.get("generation") or 1) + 1
        state["tool_counts"] = {}
        state["lint_blocks"] = 0

        if STRONG_CORRECTION_RE.search(user_input):
            state["correction_active"] = True
            streak = int(state.get("strong_correction_streak") or 0) + 1
            state["strong_correction_streak"] = streak
            if streak >= 2:
                injected.append(
                    "[Continuity — Clean-Room Rebuild Escalation] Два сильных корректирующих указания подряд. "
                    "Остановите инкрементальные заплатки: зафиксируйте обновлённый `AUTHORITATIVE STATE` и отменённые требования в `SUPERSEDED / CANCELLED` "
                    "(через `/rebuild` или `continuity.py checkpoint`), перепроверьте состояние файлов с диска и стройте финальный ответ без упоминания отвергнутых черновиков."
                )
            else:
                injected.append(
                    "[Continuity — Замена требования] Пользователь отменил или изменил прежний подход. "
                    "Обновите активные требования, поместите отменённое в `SUPERSEDED / CANCELLED`, не возвращайте старую гипотезу и не описывайте отвергнутый черновик в финальном ответе."
                )
        else:
            state["correction_active"] = False
            state["strong_correction_streak"] = 0

    # Detect context compaction and restore authoritative handoff
    if detect_compaction(payload, state, steps):
        recovery = build_repo_handoff(cwd, session=session, workspace_paths=wps, mode="authoritative")
        if recovery:
            injected.append(recovery)

    state["last_step_count"] = max(int(payload.get("initialNumSteps") or 0), len(steps))
    save_session_state(session, state)

    if injected:
        rio.emit_inject_system("\n\n".join(injected))
    else:
        rio.emit_json({})


def tool_signature(tool_name: str, args: dict[str, Any]) -> str | None:
    if tool_name == "read_file":
        p = rio.fold_path(str(args.get("Path") or ""))
        if not p:
            return None
        sline = args.get("StartLine") or 1
        eline = args.get("EndLine") or "end"
        boff = args.get("ByteOffset") or 0
        mtime = 0
        try:
            if os.path.isfile(args.get("Path") or ""):
                mtime = os.stat(str(args.get("Path"))).st_mtime_ns
        except OSError:
            pass
        return f"read:{p}:{sline}:{eline}:{boff}:{mtime}"

    if tool_name == "run_command":
        cmd = " ".join(str(args.get("CommandLine") or "").strip().split())
        if not cmd:
            return None
        digest = hashlib.sha256(cmd.encode("utf-8", errors="replace")).hexdigest()[:20]
        return f"cmd:{digest}"
    return None


def handle_pre_tool(payload: dict[str, Any]) -> None:
    session = rio.session_key(payload)
    tc = payload.get("toolCall") if isinstance(payload.get("toolCall"), dict) else {}
    tool_name = str(tc.get("name") or "")
    args = tc.get("args") if isinstance(tc.get("args"), dict) else {}

    sig = tool_signature(tool_name, args)
    if not sig:
        rio.emit_pre_tool("allow")
        return

    state = load_session_state(session)
    mut_tok = _mutation_sync_token(session)
    if mut_tok != str(state.get("last_mutation_token") or "0:0"):
        # INVARIANT: Sync loop-guard generation with monotonic edit stamp + gate marker so PostToolUse spawns are unnecessary.
        state["last_mutation_token"] = mut_tok
        state["generation"] = int(state.get("generation") or 1) + 1
        state["tool_counts"] = {}

    counts: dict[str, int] = dict(state.get("tool_counts") or {})
    new_count = int(counts.get(sig) or 0) + 1
    counts[sig] = new_count
    # Bound dictionary size
    if len(counts) > 120:
        counts = dict(list(counts.items())[-80:])
    state["tool_counts"] = counts

    if tool_name == "read_file" and new_count >= READ_REPEAT_DENY_LIMIT:
        save_session_state(session, state)
        rio.log_hook_event("continuity-events", "loop_guard_deny_read", session=session, sig=sig, count=new_count)
        rio.emit_pre_tool(
            "deny",
            reason=(
                f"[Continuity Loop Guard] Повторное чтение неизменившегося диапазона файла ({new_count}-й раз подряд "
                "в одном поколении без правок). Используйте уже прочитанное содержимое или прочитайте другой диапазон строк."
            ),
        )
        return

    if tool_name == "run_command":
        cmd_str = str(args.get("CommandLine") or "")
        is_test_runner = bool(TEST_RUNNER_RE.search(cmd_str))
        if not is_test_runner:
            if new_count == CMD_REPEAT_WARN_LIMIT:
                warns = list(state.get("pending_warnings") or [])
                warns.append(
                    f"[Continuity Loop Guard] Одинаковая команда `run_command` вызвана {new_count} раза подряд без изменений кода. "
                    "Проверьте первопричину вместо повторения идентичного вызова; следующий повтор будет заблокирован."
                )
                state["pending_warnings"] = warns[-4:]
            elif new_count >= CMD_REPEAT_DENY_LIMIT:
                save_session_state(session, state)
                rio.log_hook_event("continuity-events", "loop_guard_deny_cmd", session=session, sig=sig, count=new_count)
                rio.emit_pre_tool(
                    "deny",
                    reason=(
                        f"[Continuity Loop Guard] Заблокирован непродуктивный цикл: идентичная команда `run_command` "
                        f"запущена {new_count}-й раз подряд без изменений состояния. Измените диагностику или устраните первопричину."
                    ),
                )
                return

    save_session_state(session, state)
    rio.emit_pre_tool("allow")


def handle_post_tool(payload: dict[str, Any]) -> None:
    if payload.get("error"):
        rio.emit_json({})
        return
    session = rio.session_key(payload)
    tc = payload.get("toolCall") if isinstance(payload.get("toolCall"), dict) else {}
    tool_name = str(tc.get("name") or "")
    args = tc.get("args") if isinstance(tc.get("args"), dict) else {}

    state = load_session_state(session)
    if tool_name in ("edit_file", "write_file"):
        state["generation"] = int(state.get("generation") or 1) + 1
        state["tool_counts"] = {}
        save_session_state(session, state)
    elif tool_name == "run_command":
        import cwg_mark

        if cwg_mark.classify_shell_command(str(args.get("CommandLine") or "")) == "MUTATING":
            state["generation"] = int(state.get("generation") or 1) + 1
            state["tool_counts"] = {}
            save_session_state(session, state)
    rio.emit_json({})


def handle_stop(payload: dict[str, Any]) -> None:
    term_reason = str(payload.get("terminationReason") or "")
    if term_reason in rio.NON_ENFORCEABLE_STOP_REASONS or payload.get("error"):
        rio.emit_stop_allow()
        return

    session = rio.session_key(payload)
    cwd = rio.effective_cwd(payload)
    state = load_session_state(session)
    locked_root = str(state.get("locked_git_root") or "")
    if not state.get("correction_active"):
        if locked_root:
            touch_tree_lock(session, cwd, release=True, known_git_root=locked_root)
            state["locked_git_root"] = ""
            save_session_state(session, state)
        rio.emit_stop_allow()
        return

    transcript_path = payload.get("transcriptPath")
    steps = rio.read_transcript_steps(transcript_path, max_lines=40)
    if rio.is_subagent_session(transcript_path, steps=steps):
        rio.emit_stop_allow()
        return

    msg = str(payload.get("lastAssistantMessage") or "") or rio.last_assistant_message(steps)
    lint_blocks = int(state.get("lint_blocks") or 0)
    if (
        msg
        and not LINT_WAIVER_RE.search(msg)
        and EDIT_RESIDUE_RE.search(msg)
        and lint_blocks < MAX_LINT_BLOCKS_PER_EPISODE
    ):
        state["lint_blocks"] = lint_blocks + 1
        save_session_state(session, state)
        rio.log_hook_event("continuity-events", "output_lint_block", session=session, count=lint_blocks + 1)
        rio.emit_stop_continue(
            "[Continuity Output Lint] Финальный ответ после коррекции пользователя содержит описание "
            "отвергнутых попыток/черновиков. Перепишите ответ начисто по текущему состоянию результата "
            "(либо добавьте `[lint] intentional: <причина>`, если сравнение версий запрошено пользователем)."
        )
        return
    state["correction_active"] = False
    if locked_root:
        touch_tree_lock(session, cwd, release=True, known_git_root=locked_root)
        state["locked_git_root"] = ""
    save_session_state(session, state)
    rio.emit_stop_allow()


def _cli_cwd_and_pkey(args: argparse.Namespace) -> tuple[str, str]:
    sess = str(getattr(args, "session", "") or "")
    raw_cwd = str(getattr(args, "cwd", "") or "").strip()
    if raw_cwd:
        cwd = os.path.abspath(raw_cwd)
    else:
        cur = os.getcwd()
        cwd = "" if rio.is_plugin_runtime_dir(cur) else os.path.abspath(cur)
    return cwd, rio.project_key(cwd, session=sess)


def cmd_checkpoint(args: argparse.Namespace) -> int:
    cwd, pkey = _cli_cwd_and_pkey(args)
    cp_file = checkpoint_path(pkey)

    existing_secs: dict[str, str] = {}
    if cp_file.is_file():
        existing_secs = parse_checkpoint_sections(cp_file.read_text(encoding="utf-8", errors="replace"))

    mapping = {
        "GOAL": args.goal,
        "STATUS": args.status,
        "AUTHORITATIVE STATE": args.authoritative,
        "SUPERSEDED / CANCELLED": args.superseded,
        "COMPLETED": args.completed,
        "CURRENT STATE": args.current,
        "DELEGATED / OWNERS": args.delegated,
        "NEXT ACTION": args.next_action,
        "ACCEPTANCE": args.acceptance,
        "BLOCKERS": args.blockers,
        "STOP CONDITION": args.stop_condition,
    }
    merged = dict(existing_secs)
    for sec, val in mapping.items():
        if val is not None:
            merged[sec] = val

    label = pathlib.Path(cwd).name if cwd else pkey
    rendered = format_canonical_checkpoint(merged, project_label=label)
    cp_file.parent.mkdir(parents=True, exist_ok=True)
    cp_file.write_text(rendered, encoding="utf-8")

    mirrored = False
    if args.mirror_workspace and cwd:
        ws_cp = workspace_checkpoint_path(cwd)
        ws_cp.parent.mkdir(parents=True, exist_ok=True)
        ws_cp.write_text(rendered, encoding="utf-8")
        mirrored = True

    print(
        json.dumps(
            {
                "ok": True,
                "project_key": pkey,
                "checkpoint_path": str(cp_file),
                "mirrored_workspace": mirrored,
            },
            ensure_ascii=False,
        )
    )
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    cwd, pkey = _cli_cwd_and_pkey(args)
    target = resolve_checkpoint_file(cwd, pkey=pkey, session=getattr(args, "session", "") or "")
    if target is None:
        print(json.dumps({"exists": False, "project_key": pkey}))
        return 0
    text = target.read_text(encoding="utf-8", errors="replace")
    print(
        json.dumps(
            {
                "exists": True,
                "project_key": pkey,
                "path": str(target),
                "sections": parse_checkpoint_sections(text),
            },
            ensure_ascii=False,
        )
    )
    return 0


def _merge_handoff_items(existing: list[str], incoming: list[str] | None, replace: bool) -> list[str]:
    if incoming is None:
        return existing
    cleaned = [item.strip() for raw in incoming for item in raw.split(";") if item.strip()]
    if replace:
        return cleaned[:12]
    merged = list(existing)
    for item in cleaned:
        if item not in merged:
            merged.append(item)
    return merged[:12]


def cmd_handoff(args: argparse.Namespace) -> int:
    cwd, pkey = _cli_cwd_and_pkey(args)
    sess = args.session or ""
    ho_file = handoff_path(pkey)
    ws_ho = workspace_handoff_path(cwd) if cwd else None
    has_updates = any(
        val is not None
        for val in (args.goal, args.status, args.decision, args.superseded, args.remaining)
    )

    if args.clear:
        for path in (ho_file, ws_ho):
            try:
                if path is not None and path.is_file():
                    path.unlink()
            except OSError:
                pass
        print(json.dumps({"ok": True, "cleared": True, "project_key": pkey}, ensure_ascii=False))
        return 0

    if not has_updates or args.show:
        resolved_path, existing = _resolve_handoff(cwd, pkey=pkey, session=sess)
        digest = build_repo_handoff(cwd, session=sess, mode="authoritative", pkey=pkey)
        print(
            json.dumps(
                {
                    "exists": existing is not None,
                    "project_key": pkey,
                    "path": str(resolved_path or ho_file),
                    "handoff": existing,
                    "digest": digest,
                },
                ensure_ascii=False,
            )
        )
        return 0

    existing = load_handoff(cwd, pkey=pkey, session=sess) or {}
    updated = {
        "goal": args.goal if args.goal is not None else str(existing.get("goal") or ""),
        "status": args.status if args.status is not None else str(existing.get("status") or "in_progress"),
        "decisions": _merge_handoff_items(handoff_items(existing, "decisions"), args.decision, args.replace),
        "superseded": _merge_handoff_items(handoff_items(existing, "superseded"), args.superseded, args.replace),
        "remaining": _merge_handoff_items(handoff_items(existing, "remaining"), args.remaining, args.replace),
        "git": _collect_git_brief(cwd) if cwd else {},
        "updated_ts": time.time(),
    }
    rio.write_json(ho_file, updated)
    mirrored = False
    if args.mirror_workspace and ws_ho is not None:
        rio.write_json(ws_ho, updated)
        mirrored = True
    digest = build_repo_handoff(cwd, session=sess, mode="authoritative", pkey=pkey)
    print(
        json.dumps(
            {
                "ok": True,
                "project_key": pkey,
                "handoff_path": str(ho_file),
                "mirrored_workspace": mirrored,
                "digest_chars": len(digest),
            },
            ensure_ascii=False,
        )
    )
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] in ("checkpoint", "show", "handoff"):
        parser = argparse.ArgumentParser(prog="continuity")
        sub = parser.add_subparsers(dest="subcmd", required=True)

        cp = sub.add_parser("checkpoint")
        cp.add_argument("--cwd", default="")
        cp.add_argument("--session", default="")
        cp.add_argument("--goal", default=None)
        cp.add_argument("--status", default=None)
        cp.add_argument("--authoritative", default=None)
        cp.add_argument("--superseded", default=None)
        cp.add_argument("--completed", default=None)
        cp.add_argument("--current", default=None)
        cp.add_argument("--delegated", default=None)
        cp.add_argument("--next-action", dest="next_action", default=None)
        cp.add_argument("--acceptance", default=None)
        cp.add_argument("--blockers", default=None)
        cp.add_argument("--stop-condition", dest="stop_condition", default=None)
        cp.add_argument("--mirror-workspace", action="store_true")

        sh = sub.add_parser("show")
        sh.add_argument("--cwd", default="")
        sh.add_argument("--session", default="")

        ho = sub.add_parser("handoff")
        ho.add_argument("--cwd", default="")
        ho.add_argument("--session", default="")
        ho.add_argument("--goal", default=None)
        ho.add_argument("--status", default=None)
        ho.add_argument("--decision", "--decisions", dest="decision", action="append", default=None)
        ho.add_argument("--superseded", action="append", default=None)
        ho.add_argument("--remaining", "--next", dest="remaining", action="append", default=None)
        ho.add_argument("--replace", action="store_true")
        ho.add_argument("--clear", action="store_true")
        ho.add_argument("--show", action="store_true")
        ho.add_argument("--mirror-workspace", action="store_true")

        parsed = parser.parse_args()
        if parsed.subcmd == "checkpoint":
            return cmd_checkpoint(parsed)
        if parsed.subcmd == "handoff":
            return cmd_handoff(parsed)
        return cmd_show(parsed)

    event = rio.parse_event_arg()
    payload, err = rio.read_hook_stdin()
    if err or payload is None:
        if err:
            rio.log_hook_event("hook-errors", "stdin_error", hook="continuity", event=event, error=err)
        rio.emit_default_for_event(event)
        return 0

    actual_event = event or str(payload.get("hookEventName") or "")
    try:
        if actual_event == "SessionStart":
            handle_session_start(payload)
        elif actual_event == "PreInvocation":
            handle_pre_invocation(payload)
        elif actual_event == "PreToolUse":
            handle_pre_tool(payload)
        elif actual_event == "PostToolUse":
            handle_post_tool(payload)
        elif actual_event == "Stop":
            handle_stop(payload)
        else:
            rio.emit_default_for_event(actual_event)
    except Exception as exc:
        rio.log_hook_event(
            "hook-errors",
            "exception",
            hook="continuity",
            event=actual_event,
            error=f"{type(exc).__name__}:{exc}",
        )
        rio.emit_default_for_event(actual_event)
    return 0


if __name__ == "__main__":
    rio.maybe_exec_rust_cli("continuity")
    sys.exit(main())
