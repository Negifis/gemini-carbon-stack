#!/usr/bin/env python3
"""Tests for Continuity (checkpoints, compaction, restart, loop guard, output lint) & Secret-Safe Memory."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
HOOKS_DIR = REPO_ROOT / "plugin" / "hooks"
TOOLS_DIR = REPO_ROOT / "plugin" / "tools"


class ContinuityAndMemoryTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="cont-mem-test-")
        self.root = pathlib.Path(self.tmp.name)
        self.stack_home = self.root / "stack-home"
        self.workspace = self.root / "proj"
        self.workspace.mkdir(parents=True)
        subprocess.run(["git", "init", "-b", "main"], cwd=str(self.workspace), check=True, capture_output=True)
        (self.workspace / "main.py").write_text("x = 1\n", encoding="utf-8")

        self.transcript = self.root / "transcript_full.jsonl"
        self.transcript.write_text(
            json.dumps({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "content": "Start"}) + "\n",
            encoding="utf-8",
        )
        self.env = dict(
            os.environ,
            CARBON_STACK_HOME=str(self.stack_home),
            PLUGIN_ROOT=str(REPO_ROOT / "plugin"),
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_continuity_hook(self, event: str, extra: dict) -> dict:
        payload = {
            "conversationId": "conv-continuity-01",
            "workspacePaths": [str(self.workspace)],
            "transcriptPath": str(self.transcript),
            "hookEventName": event,
            "cwd": str(self.workspace),
        }
        payload.update(extra)
        proc = subprocess.run(
            [sys.executable, "-X", "utf8", str(HOOKS_DIR / "continuity.py"), "--event", event],
            input=json.dumps(payload).encode("utf-8"),
            capture_output=True,
            env=self.env,
            timeout=10,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr.decode())
        return json.loads(proc.stdout.decode("utf-8"))

    def test_01_memory_recall_supersede_secret_guard_and_nlm_export(self) -> None:
        # 1. Store valid GOTCHA
        p1 = subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                str(TOOLS_DIR / "carbon_memory.py"),
                "remember",
                "--category",
                "GOTCHA",
                "--cwd",
                str(self.workspace),
                "--text",
                "Close piped stdin on Windows when calling codex exec.",
            ],
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertEqual(p1.returncode, 0, msg=p1.stderr)
        mem_id = json.loads(p1.stdout)["id"]

        # 2. Negative check: secret pattern MUST be rejected!
        p_sec = subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                str(TOOLS_DIR / "carbon_memory.py"),
                "remember",
                "--category",
                "COMMAND",
                "--cwd",
                str(self.workspace),
                "--text",
                "Use api_key=sk-live-1234567890abcdefghijklmnop for auth",
            ],
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertEqual(p_sec.returncode, 2)
        self.assertIn("Secret guard rejected", p_sec.stderr)

        # 3. Supersede old entry and ensure old entry does NOT appear in active recall
        p_sup = subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                str(TOOLS_DIR / "carbon_memory.py"),
                "supersede",
                "--id",
                mem_id,
                "--cwd",
                str(self.workspace),
                "--text",
                "Use codex_lane.py review which handles stdin EOF and mcp_servers={} automatically.",
            ],
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertEqual(p_sup.returncode, 0, msg=p_sup.stderr)

        p_rec = subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                str(TOOLS_DIR / "carbon_memory.py"),
                "recall",
                "--query",
                "codex",
                "--cwd",
                str(self.workspace),
            ],
            capture_output=True,
            text=True,
            env=self.env,
        )
        recalled = json.loads(p_rec.stdout)["entries"]
        self.assertEqual(len(recalled), 1)
        self.assertIn("codex_lane.py", recalled[0]["content"])
        self.assertNotEqual(recalled[0]["id"], mem_id)

        # 4. Export NotebookLM-compatible Markdown pack
        p_exp = subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                str(TOOLS_DIR / "carbon_memory.py"),
                "export-nlm",
                "--cwd",
                str(self.workspace),
            ],
            capture_output=True,
            text=True,
            env=self.env,
        )
        exp_info = json.loads(p_exp.stdout)
        self.assertTrue(exp_info["ok"])
        self.assertTrue(pathlib.Path(exp_info["export_path"]).is_file())

    def test_02_compaction_and_restart_preserve_requirements_and_cancelled_items(self) -> None:
        subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                str(HOOKS_DIR / "continuity.py"),
                "checkpoint",
                "--cwd",
                str(self.workspace),
                "--goal",
                "Migrate storage to SQLite WAL",
                "--authoritative",
                "Use builtin sqlite3 FTS5 only; zero external paid DB",
                "--superseded",
                "Cancelled Redis cache hypothesis — do NOT reintroduce",
                "--next-action",
                "Run test suite",
            ],
            check=True,
            capture_output=True,
            env=self.env,
        )

        # Session restart recovery (`SessionStart` with `source="resume"`)
        start_out = self.run_continuity_hook("SessionStart", {"source": "resume"})
        injected_text = start_out["injectSteps"][0]["systemMessage"]["systemMessage"]
        self.assertIn("AUTHORITATIVE RECOVERY", injected_text)
        self.assertIn("Use builtin sqlite3 FTS5 only", injected_text)
        self.assertIn("Cancelled Redis cache hypothesis", injected_text)

        # Simulate long session (initialNumSteps=30) followed by compaction drop (initialNumSteps=4)
        self.run_continuity_hook("PreInvocation", {"initialNumSteps": 30, "lastUserInput": "Continue work"})
        compact_out = self.run_continuity_hook("PreInvocation", {"initialNumSteps": 4, "lastUserInput": "Continue work"})
        comp_msg = compact_out["injectSteps"][0]["systemMessage"]["systemMessage"]
        self.assertIn("Use builtin sqlite3 FTS5 only", comp_msg)
        self.assertIn("Cancelled Redis cache hypothesis", comp_msg)

    def test_03_loop_guard_detects_repeated_identical_tool_calls(self) -> None:
        target = str(self.workspace / "main.py")
        call = {"toolCall": {"id": "r1", "name": "read_file", "args": {"Path": target, "StartLine": 1, "EndLine": 10}}}
        self.assertEqual(self.run_continuity_hook("PreToolUse", call)["decision"], "allow")
        self.assertEqual(self.run_continuity_hook("PreToolUse", call)["decision"], "allow")
        third = self.run_continuity_hook("PreToolUse", call)
        self.assertEqual(third["decision"], "deny")
        self.assertIn("Loop Guard", third["reason"])

        # Editing a file bumps generation and resets read allowance
        self.run_continuity_hook(
            "PostToolUse",
            {"toolCall": {"id": "e1", "name": "edit_file", "args": {"Path": target}}, "error": ""},
        )
        self.assertEqual(self.run_continuity_hook("PreToolUse", call)["decision"], "allow")

    def test_04_correction_detection_and_output_lint(self) -> None:
        corr = self.run_continuity_hook(
            "PreInvocation",
            {"initialNumSteps": 5, "lastUserInput": "Нет, переделай: убери старый кеш и используй только SQLite."},
        )
        self.assertIn("Замена требования", corr["injectSteps"][0]["systemMessage"]["systemMessage"])

        # Final answer containing edit-history narration gets blocked once by Output Lint
        bad_stop = self.run_continuity_hook(
            "Stop",
            {
                "terminationReason": "NO_TOOL_CALL",
                "lastAssistantMessage": "В предыдущей версии я сделал Redis, но теперь исправил на SQLite.",
            },
        )
        self.assertEqual(bad_stop["decision"], "continue")
        self.assertIn("Output Lint", bad_stop["reason"])

        # Clean rewritten answer passes immediately
        clean_stop = self.run_continuity_hook(
            "Stop",
            {
                "terminationReason": "NO_TOOL_CALL",
                "lastAssistantMessage": "Хранилище реализовано на базе SQLite WAL.",
            },
        )
        self.assertEqual(clean_stop, {"decision": "allow"})

    def _write_transcript_steps(self, steps: list[dict]) -> None:
        self.transcript.write_text(
            "\n".join(json.dumps(s, ensure_ascii=False) for s in steps) + "\n",
            encoding="utf-8",
        )

    def test_05_progress_visibility_ignores_worker_messages_and_resets_on_visible_content(self) -> None:
        import time

        now = time.time()
        iso = lambda dt: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + dt))
        steps = [
            {"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": iso(0), "content": "Выполни сложную миграцию"},
            {"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": iso(5), "content": "", "tool_calls": [{"name": "post_message", "args": {"text": "worker ping"}}]},
            {"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": iso(10), "content": "", "tool_calls": [{"name": "send_message", "args": {"Recipient": "sub-1", "Message": "do x"}}]},
            {"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": iso(15), "content": "", "tool_calls": [{"name": "read_board", "args": {"since": 1}}]},
            {"step_index": 4, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": iso(20), "content": "", "tool_calls": [{"name": "swarm_wait", "args": {"since": 1}}]},
        ]
        self._write_transcript_steps(steps)

        # CLI `continuity.py progress` reports zero visible updates and worker silence
        prog = subprocess.run(
            [sys.executable, "-X", "utf8", str(HOOKS_DIR / "continuity.py"), "progress", "--transcript", str(self.transcript)],
            capture_output=True,
            text=True,
            env=self.env,
            check=True,
        )
        rep = json.loads(prog.stdout)
        self.assertEqual(rep["visible_updates_count"], 0)
        self.assertEqual(rep["silent_worker_comms"], 4)
        self.assertEqual(rep["trigger"], "complex_start")

        out1 = self.run_continuity_hook("PreInvocation", {"initialNumSteps": len(steps), "lastUserInput": "Выполни сложную миграцию"})
        msg1 = out1["injectSteps"][0]["systemMessage"]["systemMessage"]
        self.assertIn("[Progress Visibility", msg1)
        self.assertIn("пользователю не видны", msg1)

        # Adding a visible Russian progress update alongside tool_calls resets silence counters
        steps.append(
            {
                "step_index": 5,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": iso(25),
                "content": "Изучил модуль и перешёл к реализации изменений.",
                "tool_calls": [{"name": "read_file", "args": {"Path": "main.py"}}],
            }
        )
        self._write_transcript_steps(steps)
        out2 = self.run_continuity_hook("PreInvocation", {"initialNumSteps": len(steps), "lastUserInput": "Выполни сложную миграцию"})
        self.assertEqual(out2, {})

        # Negative: Stop after correction still runs cleanly without NameError on touch_tree_lock
        self.run_continuity_hook("PreInvocation", {"initialNumSteps": len(steps), "lastUserInput": "Нет, переделай без кеша"})
        stop_ok = self.run_continuity_hook(
            "Stop",
            {"terminationReason": "NO_TOOL_CALL", "lastAssistantMessage": "Готово, кеш удалён."},
        )
        self.assertEqual(stop_ok, {"decision": "allow"})

    def test_06_progress_visibility_lifecycle_triggers_cooldown_and_subagent_immunity(self) -> None:
        import time

        sys.path.insert(0, str(HOOKS_DIR))
        import continuity

        now = time.time()
        iso = lambda dt: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + dt))
        turn = "Реализуй новый контур"

        # 1. Short simple task (2 read steps) -> zero nags
        short_steps = [
            {"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": iso(0), "content": turn},
            {"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": iso(2), "content": "", "tool_calls": [{"name": "read_file", "args": {"Path": "a.py"}}]},
            {"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": iso(4), "content": "", "tool_calls": [{"name": "read_file", "args": {"Path": "b.py"}}]},
        ]
        self._write_transcript_steps(short_steps)
        self.assertEqual(self.run_continuity_hook("PreInvocation", {"initialNumSteps": 3, "lastUserInput": turn}), {})

        # 2. Visible start -> stage_complete (`install.py` sync after edits) + cooldown checks
        stage_steps = short_steps + [
            {"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": iso(6), "content": "Начинаю правки модулей.", "tool_calls": [{"name": "edit_file", "args": {"Path": "a.py"}}]},
            {"step_index": 4, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": iso(8), "content": "", "tool_calls": [{"name": "run_command", "args": {"CommandLine": "python -X utf8 install.py"}}]},
        ]
        self.assertEqual(continuity.analyze_progress_visibility(stage_steps, now_ts=now + 10)["trigger"], "stage_complete")

        # 3. Hypothesis change (failed test -> subsequent edit)
        hyp_steps = stage_steps[:4] + [
            {"step_index": 4, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": iso(8), "content": "", "tool_calls": [{"name": "run_command", "args": {"CommandLine": "pytest -q"}}]},
            {"step_index": 5, "source": "MODEL", "type": "GENERIC", "created_at": iso(9), "content": "Command exited with code 1."},
            {"step_index": 6, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": iso(12), "content": "", "tool_calls": [{"name": "edit_file", "args": {"Path": "a.py"}}]},
        ]
        self.assertEqual(continuity.analyze_progress_visibility(hyp_steps, now_ts=now + 15)["trigger"], "hypothesis_change")

        # 4. Cooldown suppression: emit nudge once, verify next non-critical step within cooldown does not nag
        self._write_transcript_steps(hyp_steps)
        nudge_hyp = self.run_continuity_hook("PreInvocation", {"initialNumSteps": len(hyp_steps), "lastUserInput": turn})
        self.assertIn("Смена гипотезы", nudge_hyp["injectSteps"][0]["systemMessage"]["systemMessage"])
        hyp_steps.append({"step_index": 7, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": iso(16), "content": "", "tool_calls": [{"name": "edit_file", "args": {"Path": "a.py"}}]})
        self._write_transcript_steps(hyp_steps)
        self.assertEqual(self.run_continuity_hook("PreInvocation", {"initialNumSteps": len(hyp_steps), "lastUserInput": turn}), {})

        # 5. Urgent `blocker` breaks cooldown immediately, and `verification_start` fires with Swarm UI pill when swarm active
        hyp_steps.append({"step_index": 8, "source": "SYSTEM", "type": "SYSTEM_MESSAGE", "created_at": iso(18), "content": "RESOURCE_EXHAUSTED (code 429): Individual quota reached"})
        self._write_transcript_steps(hyp_steps)
        nudge_blk = self.run_continuity_hook("PreInvocation", {"initialNumSteps": len(hyp_steps), "lastUserInput": turn})
        self.assertIn("Блокер", nudge_blk["injectSteps"][0]["systemMessage"]["systemMessage"])

        verify_steps = hyp_steps[:4] + [
            {"step_index": 4, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": iso(10), "content": "", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-reuse", "brief": "Simplify review"}}]},
        ]
        vrep = continuity.analyze_progress_visibility(verify_steps, now_ts=now + 12)
        self.assertEqual(vrep["trigger"], "verification_start")
        self.assertIn("sidecar://swarm/swarm_board/", vrep["trigger_message"])

        # 6. Worker/subagent transcript is completely ignored by PreInvocation progress tracker
        worker_tp = self.root / "worker_transcript_full.jsonl"
        worker_steps = [
            {"step_index": 0, "source": "SYSTEM", "type": "SYSTEM_MESSAGE", "created_at": iso(0), "content": "[Message] timestamp=2026-11-14T10:00:00Z sender=coord content=<swarm_worker> check files"},
            {"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": iso(2), "content": "", "tool_calls": [{"name": "post_message", "args": {"text": "done"}}]},
            {"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": iso(4), "content": "", "tool_calls": [{"name": "swarm_wait", "args": {"since": 1}}]},
            {"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": iso(6), "content": "", "tool_calls": [{"name": "swarm_wait", "args": {"since": 2}}]},
        ]
        worker_tp.write_text("\n".join(json.dumps(s) for s in worker_steps) + "\n", encoding="utf-8")
        wout = self.run_continuity_hook("PreInvocation", {"transcriptPath": str(worker_tp), "initialNumSteps": 4, "lastUserInput": "check"})
        self.assertEqual(wout, {})


if __name__ == "__main__":
    unittest.main()
