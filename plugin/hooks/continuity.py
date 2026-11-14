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

import carbon_memory
import gate_inbox
import runtime_io as rio

READ_REPEAT_DENY_LIMIT = 3
CMD_REPEAT_WARN_LIMIT = 3
CMD_REPEAT_DENY_LIMIT = 4
CHECKPOINT_EDIT_NUDGE = 8
MAX_LINT_BLOCKS_PER_EPISODE = 2
TREE_LOCK_TTL_SECONDS = 1800  # 30 minutes active heartbeat window

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

WEAK_CORRECTION_RE = re.compile(
    r"(?:"
    r"\b(?:поправь|измени\s+требование|уточнение:\s*теперь|лучше\s+сделай\s+иначе)"
    r"|\b(?:actually,\s*(?:use|change|let's\s+switch)|correction:|update\s+requirement)\b"
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


def resolve_checkpoint_file(cwd: str, workspace_paths: list[str] | None = None) -> pathlib.Path | None:
    if cwd:
        ws_cp = pathlib.Path(cwd) / ".agents" / "CHECKPOINT.md"
        if ws_cp.is_file():
            return ws_cp
    pkey = rio.project_key(cwd, workspace_paths)
    cp_file = checkpoint_path(pkey)
    return cp_file if cp_file.is_file() else None


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
        "edits_since_checkpoint": 0,
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


def touch_tree_lock(session: str, cwd: str, workspace_paths: list[str] | None = None, release: bool = False) -> str | None:
    """Maintain non-blocking multi-session worktree lock and warn if another live session shares this checkout."""
    git_root = rio.git_toplevel(cwd)
    if not git_root:
        return None
    pkey = rio.project_key(git_root, workspace_paths)
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


def compact_recovery_digest(cp_text: str, mode: str = "lead") -> str:
    secs = parse_checkpoint_sections(cp_text)
    if not secs:
        return ""
    header = (
        "[Continuity — AUTHORITATIVE RECOVERY (после сжатия/перезапуска)]"
        if mode == "authoritative"
        else "[Continuity — Предыдущий Checkpoint проекта (проверьте актуальность по git status)]"
    )
    picked = [header]
    for key in (
        "GOAL",
        "STATUS",
        "AUTHORITATIVE STATE",
        "SUPERSEDED / CANCELLED",
        "COMPLETED",
        "CURRENT STATE",
        "DELEGATED / OWNERS",
        "NEXT ACTION",
        "BLOCKERS",
    ):
        val = secs.get(key, "").strip()
        if val and val != "—":
            picked.append(f"- **{key}**: {val[:500]}")
    return "\n".join(picked)


def handle_session_start(payload: dict[str, Any]) -> None:
    if rio.is_subagent_session(payload.get("transcriptPath")):
        rio.emit_json({})
        return

    session = rio.session_key(payload)
    cwd = rio.effective_cwd(payload)
    wps = payload.get("workspacePaths") if isinstance(payload.get("workspacePaths"), list) else None
    pkey = rio.project_key(cwd, wps)
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
    lock_warn = touch_tree_lock(session, cwd, wps)
    if lock_warn:
        blocks.append(lock_warn)

    cp_file = checkpoint_path(pkey)
    workspace_cp = pathlib.Path(cwd) / ".agents" / "CHECKPOINT.md"
    chosen_cp = workspace_cp if workspace_cp.is_file() else (cp_file if cp_file.is_file() else None)
    if chosen_cp is not None:
        cp_text = chosen_cp.read_text(encoding="utf-8", errors="replace")
        mode = "authoritative" if source in ("resume", "reload", "compact") else "lead"
        digest = compact_recovery_digest(cp_text, mode=mode)
        if digest:
            blocks.append(digest)

    mem_card = carbon_memory.startup_memory_card(cwd=cwd, limit=5)
    if mem_card:
        blocks.append(mem_card)

    inbox_note = gate_inbox.unresolved_summary(limit=3)
    if inbox_note:
        blocks.append(inbox_note)

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
    steps = rio.read_transcript_steps(transcript_path, max_lines=60)
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
        elif WEAK_CORRECTION_RE.search(user_input):
            state["correction_active"] = True
            injected.append(
                "[Continuity] Уточнение требований зафиксировано: опирайтесь на новую спецификацию как единственно актуальную."
            )
        else:
            state["correction_active"] = False
            state["strong_correction_streak"] = 0

    # Detect context compaction and restore authoritative state
    if detect_compaction(payload, state, steps):
        chosen_cp = resolve_checkpoint_file(cwd, wps)
        if chosen_cp is not None:
            digest = compact_recovery_digest(
                chosen_cp.read_text(encoding="utf-8", errors="replace"),
                mode="authoritative",
            )
            if digest:
                injected.append(digest)

    # Periodic checkpoint nudge on long edit streaks
    edits_since = int(state.get("edits_since_checkpoint") or 0)
    if edits_since >= CHECKPOINT_EDIT_NUDGE:
        state["edits_since_checkpoint"] = 0
        cp_script = rio.normalize_path(pathlib.Path(__file__).resolve())
        injected.append(
            f"[Continuity] Выполнено >= {CHECKPOINT_EDIT_NUDGE} правок без обновления checkpoint. "
            f"Для длительной задачи обновите каноническое состояние (`python -X utf8 \"{cp_script}\" checkpoint ...` или `/checkpoint`)."
        )

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
        is_test_runner = bool(
            re.search(r"\b(?:pytest|py\.test|unittest|npm\s+test|pnpm\s+test|yarn\s+test|cargo\s+test|go\s+test|dotnet\s+test)\b", cmd_str, re.IGNORECASE)
        )
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
    cwd = rio.effective_cwd(payload)
    tc = payload.get("toolCall") if isinstance(payload.get("toolCall"), dict) else {}
    tool_name = str(tc.get("name") or "")
    args = tc.get("args") if isinstance(tc.get("args"), dict) else {}

    state = load_session_state(session)
    if tool_name in ("edit_file", "write_file"):
        state["generation"] = int(state.get("generation") or 1) + 1
        state["tool_counts"] = {}
        state["edits_since_checkpoint"] = int(state.get("edits_since_checkpoint") or 0) + 1
        save_session_state(session, state)
        touch_tree_lock(session, cwd)
    elif tool_name == "run_command":
        import cwg_mark

        if cwg_mark.classify_shell_command(str(args.get("CommandLine") or "")) == "MUTATING_OR_UNKNOWN":
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
    state = load_session_state(session)
    if not state.get("correction_active"):
        rio.emit_stop_allow()
        return

    transcript_path = payload.get("transcriptPath")
    steps = rio.read_transcript_steps(transcript_path, max_lines=80)
    if rio.is_subagent_session(transcript_path, steps=steps):
        rio.emit_stop_allow()
        return

    if state.get("correction_active"):
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
        save_session_state(session, state)

    touch_tree_lock(session, cwd, release=True)
    rio.emit_stop_allow()


def cmd_checkpoint(args: argparse.Namespace) -> int:
    cwd = os.path.abspath(args.cwd or os.getcwd())
    pkey = rio.project_key(cwd)
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

    rendered = format_canonical_checkpoint(merged, project_label=pathlib.Path(cwd).name)
    cp_file.parent.mkdir(parents=True, exist_ok=True)
    cp_file.write_text(rendered, encoding="utf-8")

    if args.mirror_workspace:
        ws_cp = pathlib.Path(cwd) / ".agents" / "CHECKPOINT.md"
        ws_cp.parent.mkdir(parents=True, exist_ok=True)
        ws_cp.write_text(rendered, encoding="utf-8")

    if args.session:
        sid = rio.safe_key(args.session)
        st = load_session_state(sid)
        st["edits_since_checkpoint"] = 0
        save_session_state(sid, st)

    print(
        json.dumps(
            {
                "ok": True,
                "project_key": pkey,
                "checkpoint_path": str(cp_file),
                "mirrored_workspace": bool(args.mirror_workspace),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    cwd = os.path.abspath(args.cwd or os.getcwd())
    pkey = rio.project_key(cwd)
    cp_file = checkpoint_path(pkey)
    ws_cp = pathlib.Path(cwd) / ".agents" / "CHECKPOINT.md"
    target = ws_cp if ws_cp.is_file() else cp_file
    if not target.is_file():
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
            indent=2,
        )
    )
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] in ("checkpoint", "show"):
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

        parsed = parser.parse_args()
        if parsed.subcmd == "checkpoint":
            return cmd_checkpoint(parsed)
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
    sys.exit(main())
