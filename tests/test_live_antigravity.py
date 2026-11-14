#!/usr/bin/env python3
"""Live Windows `cmd /c` hook execution & Antigravity plugin validation tests against `hooks.json`."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN_DIR = REPO_ROOT / "plugin"


class LiveHooksJsonExecutionTestCase(unittest.TestCase):
    def test_01_every_hooks_json_command_runs_via_windows_cmd_with_exact_cwd(self) -> None:
        """Antigravity executes hook commands via `cmd /c <command>` with cwd = directory containing `hooks.json`."""
        hooks_cfg = json.loads((PLUGIN_DIR / "hooks.json").read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory(prefix="live-hooks-cmd-") as td:
            env = dict(
                os.environ,
                CARBON_STACK_HOME=os.path.join(td, "stack-home"),
                PLUGIN_ROOT=str(PLUGIN_DIR),
                PLUGIN_DATA=os.path.join(td, "plugin-data"),
            )
            sample_payloads = {
                "SessionStart": {"conversationId": "live-cmd-test", "cwd": td, "hookEventName": "SessionStart"},
                "PreInvocation": {"conversationId": "live-cmd-test", "cwd": td, "hookEventName": "PreInvocation", "initialNumSteps": 2},
                "PreToolUse": {
                    "conversationId": "live-cmd-test",
                    "cwd": td,
                    "hookEventName": "PreToolUse",
                    "toolCall": {"id": "c1", "name": "read_file", "args": {"Path": str(PLUGIN_DIR / "plugin.json")}},
                },
                "PostToolUse": {
                    "conversationId": "live-cmd-test",
                    "cwd": td,
                    "hookEventName": "PostToolUse",
                    "toolCall": {"id": "c1", "name": "read_file", "args": {"Path": str(PLUGIN_DIR / "plugin.json")}},
                    "error": "",
                },
                "Stop": {
                    "conversationId": "live-cmd-test",
                    "cwd": td,
                    "hookEventName": "Stop",
                    "terminationReason": "NO_TOOL_CALL",
                    "fullyIdle": True,
                },
            }

            executed = 0
            for group_name, group_spec in hooks_cfg.items():
                self.assertIsInstance(group_spec, dict, msg=group_name)
                for event_name, entries in group_spec.items():
                    if event_name == "enabled":
                        continue
                    for entry in entries:
                        handlers = entry["hooks"] if event_name in ("PreToolUse", "PostToolUse") else [entry]
                        for h in handlers:
                            cmd_str = h["command"]
                            shell_cmd = ["cmd", "/c", cmd_str] if os.name == "nt" else ["sh", "-c", cmd_str]
                            proc = subprocess.run(
                                shell_cmd,
                                cwd=str(PLUGIN_DIR),
                                input=json.dumps(sample_payloads[event_name]).encode("utf-8"),
                                capture_output=True,
                                env=env,
                                timeout=12,
                            )
                            self.assertEqual(
                                proc.returncode,
                                0,
                                msg=f"{group_name}.{event_name} failed: {proc.stderr.decode('utf-8', 'replace')}",
                            )
                            parsed = json.loads(proc.stdout.decode("utf-8"))
                            self.assertIsInstance(parsed, dict)
                            if event_name == "PreToolUse":
                                self.assertIn(parsed.get("decision"), ("allow", "deny", "ask", "force_ask"))
                            elif event_name == "Stop":
                                self.assertIn(parsed.get("decision"), ("allow", "continue"))
                            elif event_name == "PostToolUse":
                                self.assertEqual(parsed, {})
                            executed += 1

            self.assertGreaterEqual(executed, 12)


if __name__ == "__main__":
    unittest.main()
