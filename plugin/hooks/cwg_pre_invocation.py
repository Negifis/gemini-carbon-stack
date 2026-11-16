#!/usr/bin/env python3
"""Code Work Gate PreInvocation hook: delivers queued candidate transition notes and anomaly handler inbox."""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cwg_common as cwg
import gate_inbox
import runtime_io as rio


def main() -> int:
    rio.parse_event_arg("PreInvocation")
    payload, err = rio.read_hook_stdin()
    if err or payload is None:
        if err:
            rio.log_hook_event("hook-errors", "stdin_error", hook="cwg_pre_invocation", error=err)
        rio.emit_json({})
        return 0

    try:
        session = rio.session_key(payload)
        has_pending = cwg.pending_notes_path(session).is_file()
        handler_cfg = gate_inbox.get_handler_config() if session != "unknown" else {}
        handler_sess = gate_inbox.get_handler_session(handler_cfg)
        is_handler = bool(handler_sess and session == handler_sess)
        if not has_pending and not is_handler:
            rio.emit_json({})
            return 0
        if rio.is_subagent_session(payload.get("transcriptPath")):
            rio.emit_json({})
            return 0

        notes = cwg.pop_pending_notes(session) if has_pending else []
        if is_handler:
            digest = gate_inbox.format_handler_digest(cfg=handler_cfg)
            if digest:
                notes.append(digest)
        if notes:
            rio.emit_inject_system("\n\n".join(notes))
        else:
            rio.emit_json({})
    except Exception as exc:
        rio.log_hook_event(
            "hook-errors",
            "exception",
            hook="cwg_pre_invocation",
            error=f"{type(exc).__name__}:{exc}",
        )
        rio.emit_json({})
    return 0


if __name__ == "__main__":
    sys.exit(main())
