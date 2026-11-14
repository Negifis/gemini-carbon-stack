#!/usr/bin/env python3
"""Unit, subprocess protocol, and negative tests for Code Work Gate & Codex/Native provenance."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
HOOKS_DIR = REPO_ROOT / "plugin" / "hooks"


def iso_now(ts: float | None = None) -> str:
    val = ts if ts is not None else time.time()
    return datetime.fromtimestamp(val, tz=timezone.utc).isoformat().replace("+00:00", "Z")


class GateSubprocessTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="cwg-test-")
        self.root = pathlib.Path(self.tmp.name)
        self.stack_home = self.root / "stack-home"
        self.codex_sessions = self.root / "codex-sessions"
        self.brain = self.root / "brain"
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(parents=True)
        self.codex_sessions.mkdir(parents=True)

        subprocess.run(["git", "init", "-b", "main"], cwd=str(self.workspace), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=str(self.workspace), check=True)
        subprocess.run(["git", "config", "user.email", "test@local"], cwd=str(self.workspace), check=True)
        (self.workspace / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(self.workspace), check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=str(self.workspace), check=True, capture_output=True)

        self.conv_id = "11111111-2222-3333-4444-555555555555"
        self.logs_dir = self.brain / self.conv_id / ".system_generated" / "logs"
        self.logs_dir.mkdir(parents=True)
        self.transcript = self.logs_dir / "transcript.jsonl"
        self.steps: list[dict] = [
            {
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "status": "DONE",
                "created_at": iso_now(),
                "content": "Fix the bug",
            }
        ]
        self._flush_transcript()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _flush_transcript(self) -> None:
        text = "\n".join(json.dumps(s, ensure_ascii=False) for s in self.steps) + "\n"
        self.transcript.write_text(text, encoding="utf-8")
        self.transcript.with_name("transcript_full.jsonl").write_text(text, encoding="utf-8")

    def add_final_response(self, content: str) -> None:
        self.steps.append(
            {
                "step_index": len(self.steps),
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "status": "DONE",
                "created_at": iso_now(),
                "content": content,
            }
        )
        self._flush_transcript()

    def add_subagent_exchange(self, type_name: str, reply_text: str, model: str = "inherit") -> str:
        sub_id = f"sub-{len(self.steps):04d}-aaaa-bbbb-cccccccccccc"
        sub_logs = self.brain / sub_id / ".system_generated" / "logs"
        sub_logs.mkdir(parents=True, exist_ok=True)
        now_iso = iso_now()
        sub_steps = [
            {
                "step_index": 0,
                "source": "SYSTEM",
                "type": "SYSTEM_MESSAGE",
                "status": "DONE",
                "created_at": now_iso,
                "content": f"[Message] timestamp={now_iso} sender={self.conv_id} priority=MESSAGE_PRIORITY_HIGH content=Review candidate",
            },
            {
                "step_index": 1,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "status": "DONE",
                "created_at": iso_now(),
                "content": reply_text,
            },
        ]
        sub_tp = sub_logs / "transcript_full.jsonl"
        sub_tp.write_text("\n".join(json.dumps(x) for x in sub_steps) + "\n", encoding="utf-8")
        (sub_logs / "transcript.jsonl").write_text(sub_tp.read_text(encoding="utf-8"), encoding="utf-8")

        uri = "file:///" + (sub_logs / "transcript.jsonl").resolve().as_posix()
        self.steps.append(
            {
                "step_index": len(self.steps),
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "status": "DONE",
                "created_at": now_iso,
                "tool_calls": [
                    {
                        "name": "invoke_subagent",
                        "args": {"TypeName": type_name, "Role": "Reviewer", "Prompt": "Review current diff carefully", "Model": model},
                    }
                ],
            }
        )
        self.steps.append(
            {
                "step_index": len(self.steps),
                "source": "MODEL",
                "type": "GENERIC",
                "status": "DONE",
                "created_at": iso_now(),
                "content": json.dumps({"conversationId": sub_id, "logAbsoluteUri": uri}),
            }
        )
        self._flush_transcript()
        return sub_id

    def run_hook(self, script_name: str, event: str, payload: dict | str) -> tuple[int, dict]:
        env = dict(
            os.environ,
            CARBON_STACK_HOME=str(self.stack_home),
            CARBON_CODEX_SESSIONS_DIR=str(self.codex_sessions),
            PLUGIN_ROOT=str(REPO_ROOT / "plugin"),
        )
        if isinstance(payload, dict):
            base = {
                "conversationId": self.conv_id,
                "workspacePaths": [str(self.workspace)],
                "transcriptPath": str(self.transcript),
                "artifactDirectoryPath": str(self.brain / self.conv_id),
                "hookEventName": event,
                "cwd": str(self.workspace),
            }
            base.update(payload)
            raw_in = json.dumps(base).encode("utf-8")
        else:
            raw_in = payload.encode("utf-8")

        proc = subprocess.run(
            [sys.executable, "-X", "utf8", str(HOOKS_DIR / script_name), "--event", event],
            input=raw_in,
            capture_output=True,
            env=env,
            timeout=10,
        )
        self.assertEqual(proc.returncode, 0, msg=f"Hook {script_name} exited nonzero: {proc.stderr.decode()}")
        out_str = proc.stdout.decode("utf-8").strip()
        return proc.returncode, json.loads(out_str)

    def test_01_no_change_task_allows_immediately(self) -> None:
        self.add_final_response("Проверил архитектуру, изменений не требуется.")
        _, out = self.run_hook("cwg_stop.py", "Stop", {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True})
        self.assertEqual(out, {"decision": "allow"})

    def test_02_malformed_stdin_fails_open_with_valid_protojson(self) -> None:
        _, pre_out = self.run_hook("cwg_mark.py", "PreToolUse", "{broken-json")
        self.assertEqual(pre_out, {"decision": "allow"})
        _, stop_out = self.run_hook("cwg_stop.py", "Stop", "{broken-json")
        self.assertEqual(stop_out, {"decision": "allow"})
        err_log = self.stack_home / "state" / "logs" / "hook-errors.jsonl"
        self.assertTrue(err_log.is_file())

    def test_03_small_standard_edit_proportionate_verification(self) -> None:
        app = self.workspace / "app.py"
        app.write_text("def add(a, b):\n    return int(a) + int(b)\n", encoding="utf-8")
        self.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {
                "toolCall": {
                    "id": "t1",
                    "name": "edit_file",
                    "args": {
                        "Path": str(app),
                        "Target": "    return a + b",
                        "Replacement": "    return int(a) + int(b)",
                    },
                },
                "error": "",
            },
        )
        # Negative check: without running any test command, forged receipt is blocked!
        self.add_final_response("Готово.\n[gate] verified: STANDARD; app.py, pytest passed")
        _, blocked = self.run_hook("cwg_stop.py", "Stop", {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True})
        self.assertEqual(blocked["decision"], "continue")
        self.assertIn("zero executed verification", blocked["reason"])

        # Negative check: a FAILING test command still blocks closure!
        self.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {"toolCall": {"id": "t2", "name": "run_command", "args": {"CommandLine": "pytest -q"}}, "error": "exit status 1"},
        )
        _, blocked_fail = self.run_hook("cwg_stop.py", "Stop", {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True})
        self.assertEqual(blocked_fail["decision"], "continue")
        self.assertIn("failed", blocked_fail["reason"])

        # Positive check: once test command genuinely passes, small edit (<=3 lines) passes WITHOUT simplify subagent!
        self.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {"toolCall": {"id": "t3", "name": "run_command", "args": {"CommandLine": "pytest -q"}}, "error": ""},
        )
        _, allowed = self.run_hook("cwg_stop.py", "Stop", {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True})
        self.assertEqual(allowed, {"decision": "allow"})

    def test_04_ordinary_standard_edit_requires_simplify(self) -> None:
        app = self.workspace / "app.py"
        big_code = "\n".join([f"def fn_{i}(x):\n    return x + {i}" for i in range(6)]) + "\n"
        app.write_text(big_code, encoding="utf-8")
        self.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {"toolCall": {"id": "w1", "name": "write_file", "args": {"Path": str(app), "Content": big_code}}, "error": ""},
        )
        self.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {"toolCall": {"id": "c1", "name": "run_command", "args": {"CommandLine": "python -m unittest"}}, "error": ""},
        )
        self.add_final_response("Реализовано.\n[gate] verified: STANDARD; app.py, unittest ok")
        _, blk = self.run_hook("cwg_stop.py", "Stop", {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True})
        self.assertEqual(blk["decision"], "continue")
        self.assertIn("simplify-reviewer", blk["reason"])

        self.add_subagent_exchange("simplify-reviewer", "Checked all 3 lenses.\nSIMPLIFY_VERDICT: CLEAN")
        self.add_final_response("Реализовано и упрощено.\n[gate] verified: STANDARD; app.py, unittest + simplify ok")
        _, ok = self.run_hook("cwg_stop.py", "Stop", {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True})
        self.assertEqual(ok, {"decision": "allow"})

    def test_05_high_and_xhigh_provenance_and_post_approval_invalidation(self) -> None:
        auth_file = self.workspace / "auth_guard.py"
        auth_file.write_text("def verify_token(tok):\n    return tok == 'valid'\n", encoding="utf-8")
        self.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {"toolCall": {"id": "h1", "name": "write_file", "args": {"Path": str(auth_file), "Content": auth_file.read_text()}}, "error": ""},
        )
        self.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {"toolCall": {"id": "h2", "name": "run_command", "args": {"CommandLine": "pytest"}}, "error": ""},
        )
        self.add_subagent_exchange("simplify-reviewer", "SIMPLIFY_VERDICT: CLEAN")

        # Negative 1: Forged self-attested review in assistant message is rejected!
        self.add_final_response("Codex проверил: VERDICT: APPROVED\n[gate] verified: HIGH; auth_guard.py, pytest + review")
        _, forged_blk = self.run_hook("cwg_stop.py", "Stop", {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True})
        self.assertEqual(forged_blk["decision"], "continue")
        self.assertIn("lacks an independent `VERDICT: APPROVED`", forged_blk["reason"])

        # Record real Codex packet + rollout JSONL at high effort
        sys.path.insert(0, str(HOOKS_DIR))
        import codex_lane
        os.environ["CARBON_STACK_HOME"] = str(self.stack_home)
        codex_lane.record_packet("cwg-testrev001", "REVIEW_ID: cwg-testrev001", str(self.workspace), effort="high")
        rollout = self.codex_sessions / "rollout-2026-11-14T09-00-00-test.jsonl"
        now_iso = iso_now()
        rollout_records = [
            {"type": "session_meta", "timestamp": now_iso, "payload": {"id": "sess-codex-1", "timestamp": now_iso}},
            {"type": "turn_context", "timestamp": now_iso, "payload": {"model": "gpt-6.1-sol", "effort": "high"}},
            {
                "type": "response_item",
                "timestamp": now_iso,
                "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-testrev001"}]},
            },
            {
                "type": "event_msg",
                "timestamp": iso_now(time.time() + 0.2),
                "payload": {"type": "task_complete", "last_agent_message": "No defects found.\nVERDICT: APPROVED"},
            },
        ]
        rollout.write_text("\n".join(json.dumps(r) for r in rollout_records) + "\n", encoding="utf-8")

        # Negative 2: Claiming XHIGH when Codex ran at `high` (not `xhigh`) is rejected!
        self.add_final_response("Проверено.\n[gate] verified: XHIGH; auth_guard.py")
        _, xhigh_blk = self.run_hook("cwg_stop.py", "Stop", {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True})
        self.assertEqual(xhigh_blk["decision"], "continue")
        self.assertIn("not XHIGH", xhigh_blk["reason"])

        # Negative 3: Editing the file AFTER approval invalidates the approval!
        time.sleep(0.05)
        auth_file.write_text("def verify_token(tok):\n    return bool(tok)\n", encoding="utf-8")
        self.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {"toolCall": {"id": "h3", "name": "write_file", "args": {"Path": str(auth_file), "Content": auth_file.read_text()}}, "error": ""},
        )
        self.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {"toolCall": {"id": "h4", "name": "run_command", "args": {"CommandLine": "pytest"}}, "error": ""},
        )
        self.add_final_response("Обновлено после ревью.\n[gate] verified: HIGH; auth_guard.py")
        _, stale_blk = self.run_hook("cwg_stop.py", "Stop", {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True})
        self.assertEqual(stale_blk["decision"], "continue")
        self.assertIn("stale", stale_blk["reason"])

        # Positive: Fresh XHIGH review via adversarial-reviewer-xhigh approves updated bytes!
        self.add_subagent_exchange(
            "adversarial-reviewer-xhigh",
            "ENGINE: native-subagent (adversarial-reviewer-xhigh)\nVERDICT: APPROVED",
            model="pro",
        )
        # Running a read-only command after approval must NOT invalidate it!
        self.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {"toolCall": {"id": "h5", "name": "run_command", "args": {"CommandLine": "git status --short"}}, "error": ""},
        )
        self.add_final_response("Проверено XHIGH.\n[gate] verified: XHIGH; auth_guard.py, pytest + xhigh review")
        _, final_ok = self.run_hook("cwg_stop.py", "Stop", {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True})
        self.assertEqual(final_ok, {"decision": "allow"})

    def test_06_finite_block_budget_prevents_infinite_loop(self) -> None:
        doc = self.workspace / "README.md"
        doc.write_text("# Doc\n", encoding="utf-8")
        self.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {"toolCall": {"id": "d1", "name": "write_file", "args": {"Path": str(doc), "Content": "# Doc\n"}}, "error": ""},
        )
        self.add_final_response("Забыл квитанцию.")
        # Blocks 1, 2, 3 -> "continue"; 4th attempt -> finite exhaustion -> "allow"!
        for _ in range(3):
            _, res = self.run_hook("cwg_stop.py", "Stop", {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True})
            self.assertEqual(res["decision"], "continue")
        _, fourth = self.run_hook("cwg_stop.py", "Stop", {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True})
        self.assertEqual(fourth, {"decision": "allow"})

    def test_07_circuit_breaker_background_wait_and_anomaly_escape(self) -> None:
        env = dict(
            os.environ,
            CARBON_STACK_HOME=str(self.stack_home),
            PLUGIN_ROOT=str(REPO_ROOT / "plugin"),
        )
        # 1. Failed codex command with quota error trips circuit breaker -> check returns native-fallback
        self.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {
                "toolCall": {"id": "cx1", "name": "run_command", "args": {"CommandLine": "codex exec -s read-only -"}},
                "error": "Error: usage limit exceeded (429 Too Many Requests)",
            },
        )
        chk = subprocess.run(
            [sys.executable, "-X", "utf8", str(HOOKS_DIR / "codex_lane.py"), "check"],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(chk.returncode, 1)
        chk_json = json.loads(chk.stdout)
        self.assertFalse(chk_json["available"])
        self.assertEqual(chk_json["lane"], "native-fallback")

        # 2. Open candidate; `fullyIdle: False` yields allow without consuming block budget
        doc = self.workspace / "NOTES.md"
        doc.write_text("# Notes\n", encoding="utf-8")
        self.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {"toolCall": {"id": "n1", "name": "write_file", "args": {"Path": str(doc), "Content": "# Notes\n"}}, "error": ""},
        )
        self.add_final_response("Ожидаю фоновую задачу...")
        _, bg_wait = self.run_hook("cwg_stop.py", "Stop", {"terminationReason": "NO_TOOL_CALL", "fullyIdle": False})
        self.assertEqual(bg_wait, {"decision": "allow"})

        # 3. Normal idle Stop without receipt blocks with nonce 1/3; test anomaly escape hatch
        _, blk1 = self.run_hook("cwg_stop.py", "Stop", {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True})
        self.assertEqual(blk1["decision"], "continue")
        self.assertIn("(1/3", blk1["reason"])

        state_file = self.stack_home / "state" / "gate" / "states" / f"{self.conv_id}.json"
        nonce = json.loads(state_file.read_text(encoding="utf-8"))["block_nonce"]

        # Negative: wrong nonce rejected by gate_inbox
        bad_rep = subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                str(HOOKS_DIR / "gate_inbox.py"),
                "report",
                "--session",
                self.conv_id,
                "--nonce",
                "wrong-nonce",
                "--block",
                "missing receipt",
                "--facts",
                "transcript shows check",
                "--did",
                "verified manually",
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(bad_rep.returncode, 2)

        # Positive: genuine block nonce files report and closes candidate cleanly
        good_rep = subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                str(HOOKS_DIR / "gate_inbox.py"),
                "report",
                "--session",
                self.conv_id,
                "--nonce",
                nonce,
                "--block",
                "missing receipt",
                "--facts",
                "transcript verified",
                "--did",
                "filed anomaly",
            ],
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
        rep_id = json.loads(good_rep.stdout)["report_id"]
        self.add_final_response(f"Закрыто по репорту.\n[gate] anomaly-reported: {rep_id}; transcript verified")
        _, anom_ok = self.run_hook("cwg_stop.py", "Stop", {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True})
        self.assertEqual(anom_ok, {"decision": "allow"})

    def test_08_domain_rate_limit_words_do_not_trip_codex_breaker(self) -> None:
        sys.path.insert(0, str(HOOKS_DIR))
        import codex_lane

        review_body = (
            "[MEDIUM] Rate limit bucket capacity allows fractional float; usage limit per user resets.\n"
            "VERDICT: REVISE"
        )
        self.assertIsNone(codex_lane.detect_outage_from_output(review_body, exit_code=0))
        self.assertIsNotNone(
            codex_lane.detect_outage_from_output("ERROR: You have hit your usage limit for today", exit_code=1)
        )


if __name__ == "__main__":
    unittest.main()
