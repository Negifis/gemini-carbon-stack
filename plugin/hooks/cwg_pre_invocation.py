#!/usr/bin/env python3
"""Code Work Gate PreInvocation hook: delivers queued candidate transition notes cleanly."""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cwg_common as cwg
import runtime_io as rio


def main() -> int:
    event = rio.parse_event_arg("PreInvocation")
    payload, err = rio.read_hook_stdin()
    if err or payload is None:
        if err:
            rio.log_hook_event("hook-errors", "stdin_error", hook="cwg_pre_invocation", error=err)
        rio.emit_json({})
        return 0

    try:
        if rio.is_subagent_session(payload.get("transcriptPath")):
            rio.emit_json({})
            return 0
        session = rio.session_key(payload)
        notes = cwg.pop_pending_notes(session)
        if notes:
            rio.emit_inject_system("\n".join(notes))
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
