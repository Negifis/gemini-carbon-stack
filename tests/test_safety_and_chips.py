#!/usr/bin/env python3
"""Tests for Safety Guards (dirty worktree, Windows NTFS junctions, subagent packet & nesting, comment density) & Chip Handoff."""

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


class SafetyAndChipsTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="safety-chips-test-")
        self.root = pathlib.Path(self.tmp.name)
        self.stack_home = self.root / "stack-home"
        self.repo = self.root / "repo"
        self.repo.mkdir(parents=True)

        subprocess.run(["git", "init", "-b", "main"], cwd=str(self.repo), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=str(self.repo), check=True)
        subprocess.run(["git", "config", "user.email", "test@local"], cwd=str(self.repo), check=True)
        (self.repo / "service.py").write_text("VALUE = 1\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(self.repo), check=True)
        subprocess.run(["git", "commit", "-m", "base"], cwd=str(self.repo), check=True, capture_output=True)

        self.transcript = self.root / "parent_transcript.jsonl"
        self.transcript.write_text(
            json.dumps({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "content": "Work"}) + "\n",
            encoding="utf-8",
        )
        self.env = dict(
            os.environ,
            CARBON_STACK_HOME=str(self.stack_home),
            PLUGIN_ROOT=str(REPO_ROOT / "plugin"),
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_safety_hook(self, tool_name: str, args: dict, transcript_override: pathlib.Path | None = None) -> dict:
        payload = {
            "conversationId": "parent-session-01",
            "workspacePaths": [str(self.repo)],
            "transcriptPath": str(transcript_override or self.transcript),
            "hookEventName": "PreToolUse",
            "cwd": str(self.repo),
            "toolCall": {"id": "tc1", "name": tool_name, "args": args},
        }
        proc = subprocess.run(
            [sys.executable, "-X", "utf8", str(HOOKS_DIR / "safety_guards.py"), "--event", "PreToolUse"],
            input=json.dumps(payload).encode("utf-8"),
            capture_output=True,
            env=self.env,
            timeout=10,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr.decode())
        return json.loads(proc.stdout.decode("utf-8"))

    def test_01_dirty_worktree_and_bare_worktree_remove_blocked(self) -> None:
        # User has uncommitted changes in service.py
        (self.repo / "service.py").write_text("VALUE = 42  # user uncommitted work\n", encoding="utf-8")

        res_reset = self.run_safety_hook("run_command", {"CommandLine": "git reset --hard HEAD"})
        self.assertEqual(res_reset["decision"], "deny")
        self.assertIn("Dirty Worktree Protection", res_reset["reason"])

        res_wt = self.run_safety_hook("run_command", {"CommandLine": "git worktree remove ../some-wt"})
        self.assertEqual(res_wt["decision"], "deny")
        self.assertIn("Worktree Safety Guard", res_wt["reason"])

    def test_02_windows_junction_safe_worktree_remove_and_wip_snapshot(self) -> None:
        # Create shared external asset folder that will be junctioned into a linked worktree
        shared_deps = self.root / "shared_node_modules"
        shared_deps.mkdir()
        precious_file = shared_deps / "keep_me.js"
        precious_file.write_text("export const SAFE = true;\n", encoding="utf-8")

        wt_dir = self.root / "wt-feature"
        subprocess.run(
            ["git", "worktree", "add", "-b", "feat-junc", str(wt_dir), "HEAD"],
            cwd=str(self.repo),
            check=True,
            capture_output=True,
        )
        # Create a dirty uncommitted file inside the worktree
        (wt_dir / "uncommitted_feature.py").write_text("FEATURE = 'saved_in_wip'\n", encoding="utf-8")

        # Create a directory junction (on Windows) or symlink inside the worktree
        link_path = wt_dir / "node_modules"
        if os.name == "nt":
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(link_path), str(shared_deps)],
                check=True,
                capture_output=True,
            )
        else:
            os.symlink(str(shared_deps), str(link_path))

        proc = subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                str(TOOLS_DIR / "worktree_guard.py"),
                "remove",
                "--worktree",
                str(wt_dir),
                "--repo",
                str(self.repo),
            ],
            capture_output=True,
            text=True,
            env=self.env,
            timeout=15,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr + proc.stdout)
        result = json.loads(proc.stdout)
        self.assertTrue(result["ok"])
        self.assertFalse(wt_dir.exists())
        # CRITICAL: Target file behind the Windows NTFS junction MUST still exist untouched!
        self.assertTrue(precious_file.is_file())
        # CRITICAL: Dirty uncommitted file MUST be preserved in refs/wip/...!
        wip_ref = result["snapshot"]["ref"]
        self.assertTrue(wip_ref.startswith("refs/wip/"))
        show = subprocess.run(
            ["git", "show", f"{wip_ref}:uncommitted_feature.py"],
            cwd=str(self.repo),
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("saved_in_wip", show.stdout)

    def test_03_subagent_delegation_injects_canonical_constraints_and_blocks_nesting(self) -> None:
        subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                str(HOOKS_DIR / "continuity.py"),
                "checkpoint",
                "--cwd",
                str(self.repo),
                "--authoritative",
                "Keep public function signature unchanged",
                "--superseded",
                "Do not add external HTTP dependencies",
            ],
            check=True,
            capture_output=True,
            env=self.env,
        )

        # Parent delegation automatically receives `[Canonical Constraints]` via PreToolUse `overwrite`
        parent_res = self.run_safety_hook(
            "invoke_subagent",
            {"TypeName": "code-explorer", "Role": "Explorer", "Prompt": "Inspect service.py callers and return summary"},
        )
        self.assertEqual(parent_res["decision"], "allow")
        self.assertIn("overwrite", parent_res)
        self.assertIn("Keep public function signature unchanged", parent_res["overwrite"]["Prompt"])
        self.assertIn("Do not add external HTTP dependencies", parent_res["overwrite"]["Prompt"])

        # Subagent session attempting nested subagent call is denied!
        sub_transcript = self.root / "subagent_transcript.jsonl"
        sub_transcript.write_text(
            json.dumps(
                {
                    "step_index": 0,
                    "source": "SYSTEM",
                    "type": "SYSTEM_MESSAGE",
                    "content": "[Message] timestamp=2026-11-14T09:00:00Z sender=11111111-2222-3333-4444-555555555555 content=Task",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        nested_res = self.run_safety_hook(
            "invoke_subagent",
            {"TypeName": "research", "Role": "Nested", "Prompt": "Try spawning nested agent"},
            transcript_override=sub_transcript,
        )
        self.assertEqual(nested_res["decision"], "deny")
        self.assertIn("Subagent Nesting Guard", nested_res["reason"])

    def test_04_comment_density_and_self_narration_guard_with_fail_open_cap(self) -> None:
        target = str(self.repo / "service.py")
        narration = self.run_safety_hook(
            "edit_file",
            {
                "Path": target,
                "Target": "VALUE = 1",
                "Replacement": "# Added this to fix the issue per review\nVALUE = 2",
            },
        )
        self.assertEqual(narration["decision"], "deny")
        self.assertIn("Comment Density Guard", narration["reason"])

        # Strike 2 also denies; Strike 3 fails open so legitimate edge cases never deadlock
        strike2 = self.run_safety_hook(
            "edit_file",
            {"Path": target, "Target": "VALUE = 1", "Replacement": "# Updated per review\nVALUE = 2"},
        )
        self.assertEqual(strike2["decision"], "deny")
        strike3 = self.run_safety_hook(
            "edit_file",
            {"Path": target, "Target": "VALUE = 1", "Replacement": "# Updated per review\nVALUE = 2"},
        )
        self.assertEqual(strike3["decision"], "allow")

    def test_05_chip_handoff_open_finish_parent_notification_recover_and_accept(self) -> None:
        # 1. Open chip
        p_open = subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                str(TOOLS_DIR / "chip_handoff.py"),
                "open",
                "--title",
                "Добавить валидатор",
                "--session",
                "parent-session-01",
                "--cwd",
                str(self.repo),
            ],
            capture_output=True,
            text=True,
            env=self.env,
            check=True,
        )
        opened = json.loads(p_open.stdout)
        chip_id = opened["chip_id"]
        wt = pathlib.Path(opened["worktree"])
        self.assertTrue(wt.is_dir())

        # 2. Child commits work in isolated chip worktree and calls `finish`
        (wt / "validator.py").write_text("def is_positive(n: int) -> bool:\n    return n > 0\n", encoding="utf-8")
        subprocess.run(["git", "add", "validator.py"], cwd=str(wt), check=True)
        subprocess.run(["git", "commit", "-m", "add validator"], cwd=str(wt), check=True, capture_output=True)

        p_fin = subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                str(TOOLS_DIR / "chip_handoff.py"),
                "finish",
                "--chip",
                chip_id,
                "--message",
                "validator.py implemented and tested",
            ],
            capture_output=True,
            text=True,
            env=self.env,
            check=True,
        )
        self.assertEqual(json.loads(p_fin.stdout)["status"], "handed-off")

        # 3. Parent PreInvocation receives automatic handoff notification
        p_hook = subprocess.run(
            [sys.executable, "-X", "utf8", str(HOOKS_DIR / "chip_hooks.py"), "--event", "PreInvocation"],
            input=json.dumps(
                {
                    "conversationId": "parent-session-01",
                    "transcriptPath": str(self.transcript),
                    "cwd": str(self.repo),
                }
            ).encode("utf-8"),
            capture_output=True,
            env=self.env,
            check=True,
        )
        hook_out = json.loads(p_hook.stdout.decode("utf-8"))
        self.assertIn(chip_id, hook_out["injectSteps"][0]["systemMessage"]["systemMessage"])

        # 4. Parent accepts and merges chip, verifying worktree is cleaned up and file merged!
        p_close = subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                str(TOOLS_DIR / "chip_handoff.py"),
                "close",
                "--chip",
                chip_id,
                "--accept",
                "--merge",
            ],
            capture_output=True,
            text=True,
            env=self.env,
            check=True,
        )
        closed = json.loads(p_close.stdout)
        self.assertTrue(closed["merged"])
        self.assertFalse(wt.exists())
        self.assertTrue((self.repo / "validator.py").is_file())


if __name__ == "__main__":
    unittest.main()
