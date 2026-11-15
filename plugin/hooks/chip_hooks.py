#!/usr/bin/env python3
"""Lifecycle hooks (`PreInvocation`, `PostToolUse`, `Stop`) connecting `chip_handoff` to parent & child sessions."""

from __future__ import annotations

import pathlib
import sys
from typing import Any

HOOKS_DIR = pathlib.Path(__file__).resolve().parent
TOOLS_DIR = HOOKS_DIR.parent / "tools"
sys.path.insert(0, str(HOOKS_DIR))
sys.path.insert(0, str(TOOLS_DIR))

import chip_handoff as ch
import runtime_io as rio

MAX_CHIP_STOP_REMINDERS = 2


def handle_pre_invocation(payload: dict[str, Any]) -> None:
    if not any(ch.chips_dir().glob("*.json")):
        rio.emit_json({})
        return
    if rio.is_subagent_session(payload.get("transcriptPath")):
        rio.emit_json({})
        return
    pending_cards = [
        c for c in ch.load_all_cards() if c.get("status") == "handed-off" and not c.get("parent_notified")
    ]
    if not pending_cards:
        rio.emit_json({})
        return

    session = rio.session_key(payload)
    cwd = rio.effective_cwd(payload)
    git_root: str | None = None

    notifications: list[str] = []
    with rio.file_lock(ch.chip_lock_path()):
        for pending in pending_cards:
            cid = str(pending.get("chip_id") or "")
            if not cid:
                continue
            card = rio.read_json(ch.card_path(cid), default=None)
            if not isinstance(card, dict) or card.get("status") != "handed-off" or card.get("parent_notified"):
                continue
            matches_parent = bool(card.get("parent_session") and card.get("parent_session") == session)
            if not matches_parent and not card.get("parent_session"):
                if git_root is None:
                    git_root = rio.normalize_path(rio.git_toplevel(cwd) or "")
                matches_parent = bool(git_root and card.get("repo_root") == git_root)
            if matches_parent:
                script_norm = rio.normalize_path(TOOLS_DIR / "chip_handoff.py")
                notifications.append(
                    f"[Chip Handoff Ready] Дочерняя задача `{cid}` ({card.get('title')}) передала результат: "
                    f"«{card.get('summary', '')}» (ветка `{card.get('chip_branch') or 'operational'}`). "
                    f"Проверьте результат и закройте чип: `python -X utf8 \"{script_norm}\" close --chip \"{cid}\" --accept [--merge]` "
                    f"или `--rework \"<замечания>\"`."
                )
                card["parent_notified"] = True
                rio.write_json(ch.card_path(cid), card)

    if notifications:
        rio.emit_inject_system("\n".join(notifications))
    else:
        rio.emit_json({})


def handle_stop(payload: dict[str, Any]) -> None:
    term_reason = str(payload.get("terminationReason") or "")
    if term_reason in rio.NON_ENFORCEABLE_STOP_REASONS or payload.get("error"):
        rio.emit_stop_allow()
        return

    cwd = rio.effective_cwd(payload)
    if not cwd or not any(ch.chips_dir().glob("*.json")):
        rio.emit_stop_allow()
        return
    child_card = ch.find_card_for_cwd(cwd)
    if child_card and child_card.get("status") in ("open", "rework"):
        rem = int(child_card.get("stop_reminders") or 0)
        if rem < MAX_CHIP_STOP_REMINDERS:
            cid = str(child_card["chip_id"])
            child_card["stop_reminders"] = rem + 1
            with rio.file_lock(ch.chip_lock_path()):
                rio.write_json(ch.card_path(cid), child_card)
            script_norm = rio.normalize_path(TOOLS_DIR / "chip_handoff.py")
            rio.emit_stop_continue(
                f"[Chip Handoff] Эта сессия работает внутри изолированного чипа `{cid}` ({child_card.get('title')}), "
                f"но результат ещё не передан родителю (`status={child_card.get('status')}`). "
                f"Закоммитьте проверенные изменения и выполните `python -X utf8 \"{script_norm}\" finish --chip \"{cid}\" --message \"...\"`."
            )
            return

    rio.emit_stop_allow()


def main() -> int:
    event = rio.parse_event_arg()
    payload, err = rio.read_hook_stdin()
    if err or payload is None:
        rio.emit_default_for_event(event)
        return 0
    actual_event = event or str(payload.get("hookEventName") or "")
    try:
        if actual_event == "PreInvocation":
            handle_pre_invocation(payload)
        elif actual_event == "Stop":
            handle_stop(payload)
        else:
            rio.emit_default_for_event(actual_event)
    except Exception as exc:
        rio.log_hook_event("hook-errors", "exception", hook="chip_hooks", error=f"{type(exc).__name__}:{exc}")
        rio.emit_default_for_event(actual_event)
    return 0


if __name__ == "__main__":
    sys.exit(main())
