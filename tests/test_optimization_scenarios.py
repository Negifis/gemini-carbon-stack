#!/usr/bin/env python3
"""Integration & scenario tests for Gemini Carbon Stack context optimization & gate proportionality."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time
import unittest
from unittest import mock

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
HOOKS_DIR = REPO_ROOT / "plugin" / "hooks"
TOOLS_DIR = REPO_ROOT / "plugin" / "tools"
TESTS_DIR = REPO_ROOT / "tests"

sys.path.insert(0, str(HOOKS_DIR))
sys.path.insert(0, str(TESTS_DIR))
import continuity as cont  # noqa: E402
import cwg_common as cwg  # noqa: E402
import cwg_mark  # noqa: E402
import safety_guards as guards  # noqa: E402
import test_runtime_and_gate as trg  # noqa: E402


def _extract_injected_text(hook_out: dict) -> str:
    parts: list[str] = []
    for step in hook_out.get("injectSteps") or []:
        sm = step.get("systemMessage")
        if isinstance(sm, dict):
            parts.append(str(sm.get("systemMessage") or ""))
        elif isinstance(sm, str):
            parts.append(sm)
    return "\n".join(parts)


class OptimizationScenariosTestCase(unittest.TestCase):
    def setUp(self) -> None:
        # Compose GateSubprocessTestCase harness without re-executing its 16 inherited test_* methods.
        self._h = trg.GateSubprocessTestCase("test_01_no_change_task_allows_immediately")
        self._h.setUp()
        self.addCleanup(self._h.tearDown)

    def test_01_light_standalone_addon_without_tests_or_swarm(self) -> None:
        addon_dir = self._h.root / "MyAddon"
        addon_dir.mkdir(parents=True, exist_ok=True)
        toc = addon_dir / "MyAddon.toc"
        lua = addon_dir / "core.lua"
        toc.write_text("## Interface: 110002\ncore.lua\n", encoding="utf-8")
        lua.write_text("local f = CreateFrame('Frame')\n", encoding="utf-8")

        self._h.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {
                "cwd": str(addon_dir),
                "workspacePaths": [str(addon_dir)],
                "toolCall": {
                    "id": "l1",
                    "name": "edit_file",
                    "args": {
                        "Path": str(lua),
                        "Target": "Frame",
                        "Replacement": "Frame\nlocal x = 1\nlocal y = 2\nlocal z = 3\nlocal w = 4",
                    },
                },
                "error": "",
            },
        )
        # Routine STANDARD candidate should NOT inject noisy transition banners
        _, pre_notes = self._h.run_hook(
            "cwg_pre_invocation.py",
            "PreInvocation",
            {"cwd": str(addon_dir), "workspacePaths": [str(addon_dir)]},
        )
        self.assertEqual(pre_notes, {})

        # Multi-line standalone Lua edit closes cleanly as STANDARD without fake tests or swarm
        self._h.add_final_response("Обновил обработчик.\n[gate] verified: STANDARD; core.lua (addon)")
        _, ok = self._h.run_hook(
            "cwg_stop.py",
            "Stop",
            {
                "cwd": str(addon_dir),
                "workspacePaths": [str(addon_dir)],
                "terminationReason": "NO_TOOL_CALL",
                "fullyIdle": True,
            },
        )
        self.assertEqual(ok, {"decision": "allow"})

        # Yet if a validation command runs and FAILS, even addon edits stay blocked until fixed
        lua.write_text("local broken =\n", encoding="utf-8")
        self._h.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {
                "cwd": str(addon_dir),
                "workspacePaths": [str(addon_dir)],
                "toolCall": {"id": "l2", "name": "write_file", "args": {"Path": str(lua), "Content": "local broken =\n"}},
                "error": "",
            },
        )
        self._h.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {
                "cwd": str(addon_dir),
                "workspacePaths": [str(addon_dir)],
                "toolCall": {"id": "l3", "name": "run_command", "args": {"CommandLine": "npm run lint"}},
                "error": "syntax error",
            },
        )
        _, blk_fail = self._h.run_hook(
            "cwg_stop.py",
            "Stop",
            {
                "cwd": str(addon_dir),
                "workspacePaths": [str(addon_dir)],
                "terminationReason": "NO_TOOL_CALL",
                "fullyIdle": True,
            },
        )
        self.assertEqual(blk_fail["decision"], "continue")
        self.assertIn("failed", blk_fail["reason"])

        # Project policy `low_risk_globs` classifies addon files as LOW
        (addon_dir / ".agents").mkdir(exist_ok=True)
        (addon_dir / ".agents" / "carbon-gate.json").write_text(
            json.dumps({"low_risk_globs": ["*.lua", "*.toc"]}), encoding="utf-8"
        )
        pol = cwg.load_project_gate_policy([str(lua)], cwd=str(addon_dir))
        self.assertEqual(cwg.classify_path_risk(str(lua), policy=pol), "LOW")

    def test_02_medium_token_boundary_and_project_policy_opt_in(self) -> None:
        # Token-boundary accuracy: `author.py` is STANDARD, while `auth_guard.py` and `user_auth.py` are HIGH
        self.assertEqual(cwg.classify_path_risk(str(self._h.workspace / "author.py")), "STANDARD")
        self.assertEqual(cwg.classify_path_risk(str(self._h.workspace / "auth_guard.py")), "HIGH")
        self.assertEqual(cwg.classify_path_risk(str(self._h.workspace / "user_auth.py")), "HIGH")

        author = self._h.workspace / "author.py"
        formatter = self._h.workspace / "formatter.py"
        author.write_text("\n".join(f"def field_{i}():\n    return {i}" for i in range(6)) + "\n", encoding="utf-8")
        formatter.write_text("\n".join(f"def fmt_{i}(v):\n    return str(v)" for i in range(5)) + "\n", encoding="utf-8")

        for idx, fpath in enumerate((author, formatter)):
            self._h.run_hook(
                "cwg_mark.py",
                "PostToolUse",
                {"toolCall": {"id": f"m{idx}", "name": "write_file", "args": {"Path": str(fpath), "Content": fpath.read_text()}}, "error": ""},
            )
        # Missing local unittest blocks
        self._h.add_final_response("Готово.\n[gate] verified: STANDARD; author.py, formatter.py")
        _, blk_notest = self._h.run_hook("cwg_stop.py", "Stop", {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True})
        self.assertEqual(blk_notest["decision"], "continue")
        self.assertIn("zero executed verification", blk_notest["reason"])

        # With local unittest passing, closes without swarm simplify/review
        self._h.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {"toolCall": {"id": "m_tst", "name": "run_command", "args": {"CommandLine": "python -X utf8 -m unittest"}}, "error": ""},
        )
        self._h.add_final_response("Готово.\n[gate] verified: STANDARD; author.py, formatter.py, unittest ok")
        _, ok_med = self._h.run_hook("cwg_stop.py", "Stop", {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True})
        self.assertEqual(ok_med, {"decision": "allow"})

        # Enable .github/** XHIGH glob + full review/simplify opt-in on STANDARD via .agents/carbon-gate.json
        (self._h.workspace / ".agents").mkdir(exist_ok=True)
        (self._h.workspace / ".agents" / "carbon-gate.json").write_text(
            json.dumps(
                {
                    "xhigh_risk_globs": [".github/**"],
                    "require_simplify_on_standard": True,
                    "require_review_on_standard": True,
                }
            ),
            encoding="utf-8",
        )
        opt_pol = cwg.load_project_gate_policy(cwd=str(self._h.workspace))
        self.assertEqual(cwg.classify_path_risk(str(self._h.workspace / ".github" / "workflows" / "ci.yml"), opt_pol), "XHIGH")
        author.write_text(author.read_text() + "\ndef updated():\n    return True\n", encoding="utf-8")
        self._h.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {"toolCall": {"id": "m2", "name": "write_file", "args": {"Path": str(author), "Content": author.read_text()}}, "error": ""},
        )
        self._h.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {"toolCall": {"id": "m_tst2", "name": "run_command", "args": {"CommandLine": "python -X utf8 -m unittest"}}, "error": ""},
        )
        self._h.add_swarm_worker(
            name="simplify-reviewer",
            model="claude-sonnet-5-5-high",
            brief="Combined STANDARD simplify.",
            worker_post="@coordinator\nSIMPLIFY_LENS: ALL\nSIMPLIFY_VERDICT: CLEAN",
        )
        self._h.add_final_response("Упрощено.\n[gate] verified: STANDARD; author.py")
        _, blk_rev = self._h.run_hook("cwg_stop.py", "Stop", {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True})
        self.assertEqual(blk_rev["decision"], "continue")
        self.assertIn("VERDICT: APPROVED", blk_rev["reason"])

        self._h.add_swarm_worker(
            name="internal-reviewer",
            model="claude-opus-5-5-high",
            brief="Opt-in STANDARD review.",
            worker_post="@coordinator\nVERDICT: APPROVED",
        )
        self._h.add_final_response("Одобрено.\n[gate] verified: STANDARD; author.py, unittest + simplify + opus review")
        _, ok_optin = self._h.run_hook("cwg_stop.py", "Stop", {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True})
        self.assertEqual(ok_optin, {"decision": "allow"})

    def test_03_complex_high_gate_and_single_line_transition_note(self) -> None:
        hook_file = self._h.workspace / "hooks" / "custom_hook.py"
        hook_file.parent.mkdir(parents=True, exist_ok=True)
        hook_file.write_text("def run():\n    return {'decision': 'allow'}\n", encoding="utf-8")
        self._h.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {"toolCall": {"id": "c_h1", "name": "write_file", "args": {"Path": str(hook_file), "Content": hook_file.read_text()}}, "error": ""},
        )
        _, note_res = self._h.run_hook("cwg_pre_invocation.py", "PreInvocation", {})
        injected = _extract_injected_text(note_res)
        self.assertIn("`HIGH`", injected)
        self.assertEqual(len(injected.strip().splitlines()), 1)

    def test_04_clean_session_start_handoff_and_compaction_recovery(self) -> None:
        env = dict(os.environ, CARBON_STACK_HOME=str(self._h.stack_home))

        # Populate carbon_memory to ensure clean fresh SessionStart does NOT dump startup memory card
        subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                str(TOOLS_DIR / "carbon_memory.py"),
                "remember",
                "--cwd",
                str(self._h.workspace),
                "--category",
                "GOTCHA",
                "--text",
                "Old project gotcha: should not be dumped into clean new sessions automatically",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
        _, fresh_start = self._h.run_hook("continuity.py", "SessionStart", {"source": "new"})
        self.assertEqual(fresh_start, {})

        # Weak phrasing no longer triggers correction warnings
        _, weak_pre = self._h.run_hook(
            "continuity.py",
            "PreInvocation",
            {"lastUserInput": "поправь, пожалуйста, цвет кнопки", "initialNumSteps": 2},
        )
        self.assertEqual(weak_pre, {})

        # Create minimal repo handoff & check bounded recovery digest
        ho_proc = subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                str(HOOKS_DIR / "continuity.py"),
                "handoff",
                "--cwd",
                str(self._h.workspace),
                "--goal",
                "Optimize context consumption",
                "--status",
                "in_progress",
                "--decision",
                "Use risk-based gate without line threshold",
                "--superseded",
                "Drop 3-line gate heuristic",
                "--remaining",
                "Run install.py --diagnose",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
        ho_out = json.loads(ho_proc.stdout)
        self.assertTrue(ho_out["ok"])
        self.assertLessEqual(ho_out["digest_chars"], 900)

        # Resume injects bounded authoritative handoff recovery
        _, res_start = self._h.run_hook("continuity.py", "SessionStart", {"source": "resume"})
        res_txt = _extract_injected_text(res_start)
        self.assertLessEqual(len(res_txt), 900)
        self.assertIn("AUTHORITATIVE RECOVERY", res_txt)
        self.assertIn("Use risk-based gate without line threshold", res_txt)
        self.assertIn("Drop 3-line gate heuristic", res_txt)
        self.assertIn("GIT: branch=", res_txt)

        # Compaction detection in PreInvocation restores bounded handoff
        self._h.steps.append({"step_index": 25, "source": "SYSTEM", "type": "CHECKPOINT", "status": "DONE", "content": "compacted"})
        self._h._flush_transcript()
        _, comp_pre = self._h.run_hook(
            "continuity.py",
            "PreInvocation",
            {"lastUserInput": "continue", "initialNumSteps": 4},
        )
        comp_txt = _extract_injected_text(comp_pre)
        self.assertLessEqual(len(comp_txt), 900)
        self.assertIn("AUTHORITATIVE RECOVERY", comp_txt)

    def test_05_conservative_5_state_classifier_and_measured_non_git_snapshot(self) -> None:
        cases = [
            ("Get-ChildItem | Select-Object -First 5", "READ_ONLY"),
            ("cd tests; git status --short", "READ_ONLY"),
            ('python -X utf8 continuity.py handoff --cwd "."', "BOOKKEEPING"),
            ("cd tests; pytest -q", "VALIDATION"),
            ("python -X utf8 install.py --diagnose", "VALIDATION"),
            ('python -X utf8 -c "print(42)"', "UNCERTAIN"),
            ("Get-Content $(Get-Date)", "UNCERTAIN"),
            ("echo pytest", "UNCERTAIN"),
            ("rg --pre x.bat foo", "UNCERTAIN"),
            ('python -X utf8 -c "open(\'x.txt\',\'w\').write(\'hi\')"', "MUTATING"),
            ("Get-Content a.txt > b.txt", "MUTATING"),
            ("git reset --hard", "MUTATING"),
            ("python -X utf8 install.py", "MUTATING"),
            ("git diff --output=out.diff", "MUTATING"),
        ]
        for cmd, expected in cases:
            self.assertEqual(cwg_mark.classify_shell_command(cmd), expected, msg=cmd)

        # Non-git directory PreToolUse + PostToolUse measurement
        non_git = self._h.root / "standalone_dir"
        non_git.mkdir(parents=True, exist_ok=True)
        (non_git / "data.txt").write_text("alpha\n", encoding="utf-8")

        # Read-only python probe (UNCERTAIN + 0 delta) must NOT open OPERATIONAL candidate
        self._h.run_hook(
            "cwg_mark.py",
            "PreToolUse",
            {
                "cwd": str(non_git),
                "workspacePaths": [str(non_git)],
                "toolCall": {"id": "ng1", "name": "run_command", "args": {"CommandLine": 'python -X utf8 -c "print(42)"'}},
            },
        )
        self._h.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {
                "cwd": str(non_git),
                "workspacePaths": [str(non_git)],
                "toolCall": {"id": "ng1", "name": "run_command", "args": {"CommandLine": 'python -X utf8 -c "print(42)"'}},
                "error": "",
            },
        )
        marker_file = self._h.stack_home / "state" / "gate" / "markers" / f"{self._h.conv_id}.json"
        self.assertFalse(marker_file.exists())

        # Python script actually writing a new file in non-git dir MUST open PERSISTENT candidate
        self._h.run_hook(
            "cwg_mark.py",
            "PreToolUse",
            {
                "cwd": str(non_git),
                "workspacePaths": [str(non_git)],
                "toolCall": {"id": "ng2", "name": "run_command", "args": {"CommandLine": "python -X utf8 helper.py"}},
            },
        )
        (non_git / "created.txt").write_text("created\n", encoding="utf-8")
        self._h.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {
                "cwd": str(non_git),
                "workspacePaths": [str(non_git)],
                "toolCall": {"id": "ng2", "name": "run_command", "args": {"CommandLine": "python -X utf8 helper.py"}},
                "error": "",
            },
        )
        marker = json.loads(marker_file.read_text(encoding="utf-8"))
        self.assertTrue(any(p.endswith("created.txt") for p in marker.get("paths", [])))

    def test_06_compact_cli_outputs_and_untruncated_errors(self) -> None:
        env = dict(os.environ, CARBON_STACK_HOME=str(self._h.stack_home), PLUGIN_ROOT=str(REPO_ROOT / "plugin"))
        doc_proc = subprocess.run(
            [sys.executable, "-X", "utf8", str(TOOLS_DIR / "stack_doctor.py"), "--cwd", str(self._h.workspace), "--compact"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
        self.assertEqual(len(doc_proc.stdout.strip().splitlines()), 1)
        doc_json = json.loads(doc_proc.stdout)
        self.assertNotIn("skills", doc_json)
        self.assertNotIn("model_routing", doc_json)
        self.assertIn("counts", doc_json)

        # Fake codex passing `login status` and failing `exec` with >700-char stderr preserves full head & tail
        fake_dir = self._h.root / "fake_bin"
        fake_dir.mkdir(exist_ok=True)
        head_tok = "HEAD_ERR_MARKER_001"
        tail_tok = "TAIL_ERR_MARKER_999"
        long_err = f"{head_tok} " + ("X" * 700) + f" {tail_tok}"
        fake_py = fake_dir / "fake_codex.py"
        fake_py.write_text(
            (
                "import sys\n"
                "if len(sys.argv) >= 2 and sys.argv[1] == 'login':\n"
                "    print('Logged in using ChatGPT')\n"
                "    sys.exit(0)\n"
                f"sys.stderr.write({long_err!r} + '\\n')\n"
                "sys.exit(1)\n"
            ),
            encoding="utf-8",
        )
        fake_cmd = fake_dir / "codex.cmd"
        fake_cmd.write_text(f'@echo off\r\n"{sys.executable}" -X utf8 "{fake_py}" %*\r\n', encoding="utf-8")

        err_env = dict(
            env,
            CARBON_CODEX_BIN=str(fake_cmd),
            CARBON_CODEX_SESSIONS_DIR=str(self._h.codex_sessions),
        )
        rev_proc = subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                str(HOOKS_DIR / "codex_lane.py"),
                "review",
                "--cwd",
                str(self._h.workspace),
                "--summary",
                "test error non-truncation",
                "--session",
                self._h.conv_id,
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=err_env,
        )
        self.assertEqual(rev_proc.returncode, 2)
        rev_json = json.loads(rev_proc.stdout)
        self.assertIn(head_tok, rev_json["error"])
        self.assertIn(tail_tok, rev_json["error"])

    def test_07_adversarial_security_regressions(self) -> None:
        # 1. PowerShell trailing backslash inside quotes & scriptblocks & git branch mutations
        self.assertEqual(cwg_mark.classify_shell_command(r'Get-ChildItem "C:\repo\" > "C:\repo\target.py"'), "MUTATING")
        self.assertEqual(
            cwg_mark.classify_shell_command(r'Test-Path "C:\repo\" (Remove-Item "C:\repo\target.py") "x"'),
            "MUTATING",
        )
        self.assertEqual(cwg_mark.classify_shell_command("Get-ChildItem | Where-Object { python mutate.py }"), "UNCERTAIN")
        self.assertEqual(cwg_mark.classify_shell_command("where { python mutate.py }"), "UNCERTAIN")
        self.assertEqual(cwg_mark.classify_shell_command("git branch --show-current"), "READ_ONLY")
        self.assertEqual(cwg_mark.classify_shell_command("git branch -vv"), "READ_ONLY")
        self.assertEqual(cwg_mark.classify_shell_command("git branch new-feature"), "MUTATING")
        self.assertEqual(cwg_mark.classify_shell_command("git branch -f main HEAD~1"), "MUTATING")
        self.assertEqual(cwg_mark.classify_shell_command("git branch\ngit status"), "READ_ONLY")
        self.assertEqual(cwg_mark.classify_shell_command('Get-Item "a\'b" "$(Set-Content target.py x)" "c\'d"'), "MUTATING")
        self.assertEqual(cwg_mark.classify_shell_command("Get-Content a.py>b.py"), "MUTATING")
        self.assertEqual(cwg_mark.classify_shell_command(r'Get-ChildItem "C:\repo\">"C:\repo\target.py"'), "MUTATING")
        self.assertEqual(cwg_mark.classify_shell_command("Get-ChildItem *> out.txt"), "MUTATING")
        self.assertEqual(cwg_mark.classify_shell_command("Get-ChildItem 3> warn.txt"), "MUTATING")
        self.assertEqual(cwg_mark.classify_shell_command("Get-ChildItem >> $null"), "READ_ONLY")
        self.assertEqual(cwg_mark.classify_shell_command('Get-Item "$(Get-Content a.py > target.py)"'), "MUTATING")

        # 2. Non-git snapshot exceeding NON_GIT_SCAN_MAX_DEPTH must mark unmeasured & open OPERATIONAL gate
        deep_root = self._h.root / "non_git_deep"
        deep_leaf = deep_root / "a" / "b" / "c" / "d" / "e"
        deep_leaf.mkdir(parents=True, exist_ok=True)
        (deep_leaf / "hidden.py").write_text("x = 1\n", encoding="utf-8")
        deep_snap = cwg_mark.take_git_snapshot(str(deep_root))
        self.assertTrue(deep_snap["unmeasured"])

        self._h.run_hook(
            "cwg_mark.py",
            "PreToolUse",
            {"cwd": str(deep_root), "workspacePaths": [str(deep_root)], "toolCall": {"id": "d1", "name": "run_command", "args": {"CommandLine": "python -X utf8 gen.py"}}},
        )
        self._h.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {"cwd": str(deep_root), "workspacePaths": [str(deep_root)], "toolCall": {"id": "d1", "name": "run_command", "args": {"CommandLine": "python -X utf8 gen.py"}}, "error": ""},
        )
        deep_marker = json.loads((self._h.stack_home / "state" / "gate" / "markers" / f"{self._h.conv_id}.json").read_text(encoding="utf-8"))
        self.assertTrue(deep_marker.get("operational"))

        # 3. Glob /**/ direct-child match, parent-path isolation, and cross-repo cwd policy scoping
        parent_scratch = self._h.root / "scratch"
        repo_a = parent_scratch / "repoA"
        repo_b = parent_scratch / "repoB"
        repo_a.mkdir(parents=True, exist_ok=True)
        repo_b.mkdir(parents=True, exist_ok=True)
        (repo_a / ".agents").mkdir(exist_ok=True)
        (repo_a / ".agents" / "carbon-gate.json").write_text(
            json.dumps(
                {
                    "default_code_risk": "LOW",
                    "low_risk_globs": ["scratch/**"],
                    "xhigh_risk_globs": ["payments/**/*.py"],
                    "require_tests_on_standard": False,
                    "require_simplify_on_standard": True,
                }
            ),
            encoding="utf-8",
        )
        # Direct child payments/charge.py matches payments/**/*.py; scratch/** above policy_root does not downgrade repoA/src/app.py if standard,
        # while default_code_risk LOW and standard policy flags apply to repoA ONLY (not repoB/app.py!).
        pol_cross = cwg.load_project_gate_policy(hints=[str(repo_b / "app.py")], cwd=str(repo_a))
        self.assertEqual(cwg.classify_path_risk(str(repo_b / "app.py"), pol_cross), "STANDARD")
        cctx_cross = cwg.resolve_candidate_context({"cwd": str(repo_a), "paths": [str(repo_b / "app.py")]}, include_tests=False)
        self.assertEqual(cctx_cross["policy"]["policy_root"], "")
        self.assertFalse(cctx_cross["needs_simplify"])
        self.assertTrue(cwg._glob_to_regex("payments/**/*.py").match("payments/charge.py"))
        pol_a = cwg.load_project_gate_policy(cwd=str(repo_a))
        self.assertEqual(cwg.classify_path_risk(str(repo_a / "payments" / "charge.py"), pol_a), "XHIGH")
        # Under normal repo without default_code_risk: LOW, ancestor dir named "scratch" must NOT trigger low_risk_globs: ["scratch/**"]
        pol_strict = {"default_code_risk": "STANDARD", "low_risk_globs": ["scratch/**"], "policy_root": cwg.rio.normalize_path(str(repo_a))}
        self.assertEqual(cwg.classify_path_risk(str(repo_a / "billing.py"), pol_strict), "STANDARD")
        # Mixed-repo candidate (repoA doc with require_tests_on_standard=false + repoB service.py) keeps monotonic STANDARD + tests=True
        cctx_mixed = cwg.resolve_candidate_context(
            {"cwd": str(repo_a), "paths": [str(repo_a / "README.md"), str(repo_b / "service.py")]},
            include_tests=True,
        )
        self.assertEqual(cctx_mixed["floor"], "STANDARD")
        self.assertTrue(cctx_mixed["require_tests"])
        # Deep paths (>= 7 segments below repoA) still resolve repoA's `.agents/carbon-gate.json`
        deep_repo_a_file = repo_a / "a" / "b" / "c" / "d" / "e" / "f" / "g" / "app.py"
        deep_repo_a_file.parent.mkdir(parents=True, exist_ok=True)
        deep_repo_a_file.write_text("x = 1\n", encoding="utf-8")
        pol_deep = cwg.load_project_gate_policy(hints=[str(deep_repo_a_file)])
        self.assertEqual(cwg.classify_path_risk(str(deep_repo_a_file), pol_deep), "LOW")
        # Nested package `.agents/carbon-gate.json` cannot be downgraded by outer repoA doc edit
        nested_pkg = repo_a / "subpkg"
        (nested_pkg / ".agents").mkdir(parents=True, exist_ok=True)
        (nested_pkg / ".agents" / "carbon-gate.json").write_text(
            json.dumps({"default_code_risk": "HIGH"}), encoding="utf-8"
        )
        cctx_nested = cwg.resolve_candidate_context(
            {"cwd": str(repo_a), "paths": [str(repo_a / "README.md"), str(nested_pkg / "charge.py")]},
            include_tests=False,
        )
        self.assertEqual(cctx_nested["floor"], "HIGH")
        self.assertTrue(cwg.load_project_gate_policy(hints=[str(repo_a), str(repo_b)]).get("_multi_root"))

        # 4. continuity.py handoff --decisions / --next CLI aliases and non-list JSON resilience
        env = dict(os.environ, CARBON_STACK_HOME=str(self._h.stack_home), PLUGIN_ROOT=str(REPO_ROOT / "plugin"))
        ho_proc = subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                str(HOOKS_DIR / "continuity.py"),
                "handoff",
                "--cwd",
                str(repo_b),
                "--goal",
                "CLI alias test",
                "--status",
                "IN_PROGRESS",
                "--decisions",
                "keep compact",
                "--superseded",
                "old flag",
                "--next",
                "verify stop",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
        self.assertTrue(json.loads(ho_proc.stdout)["ok"])
        loaded = json.loads(
            subprocess.check_output(
                [sys.executable, "-X", "utf8", str(HOOKS_DIR / "continuity.py"), "handoff", "--cwd", str(repo_b), "--show"],
                stdin=subprocess.DEVNULL,
                text=True,
                env=env,
            )
        )
        self.assertEqual(loaded["handoff"]["decisions"], ["keep compact"])
        self.assertEqual(loaded["handoff"]["remaining"], ["verify stop"])
        (repo_b / ".agents").mkdir(exist_ok=True)
        (repo_b / ".agents" / "handoff.json").write_text(
            json.dumps({"goal": "Manual", "status": "in_progress", "decisions": "alpha; beta", "superseded": 123}),
            encoding="utf-8",
        )
        decs, sups = cont.handoff_constraints(cont.load_handoff(str(repo_b)) or {})
        self.assertEqual(decs, ["alpha", "beta"])
        self.assertEqual(sups, [])
        ws_cp = cont.workspace_checkpoint_path(str(repo_b))
        ws_cp.parent.mkdir(parents=True, exist_ok=True)
        ws_cp.write_text(
            "# CHECKPOINT\n## STATUS\nIN_PROGRESS\n## AUTHORITATIVE STATE\nstale checkpoint\n",
            encoding="utf-8",
        )
        subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                str(HOOKS_DIR / "continuity.py"),
                "handoff",
                "--cwd",
                str(repo_b),
                "--status",
                "COMPLETED",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
        # Newer state handoff beats older manual .agents/handoff.json, and closed handoff never resurrects older CHECKPOINT.md;
        # a subsequent newer CHECKPOINT.md written after closing the handoff does supersede the closed handoff.
        with mock.patch.dict(os.environ, {"CARBON_STACK_HOME": str(self._h.stack_home)}):
            self.assertEqual((cont.load_handoff(str(repo_b)) or {}).get("status"), "COMPLETED")
            self.assertEqual(cont.build_repo_handoff(str(repo_b), mode="lead"), "")
            self.assertEqual(cont.active_constraints(str(repo_b)), ("", ""))
            time.sleep(0.02)
            ws_cp.write_text(
                "# CHECKPOINT\n## STATUS\nIN_PROGRESS\n## AUTHORITATIVE STATE\nfresh checkpoint\n",
                encoding="utf-8",
            )
            self.assertEqual(cont.active_constraints(str(repo_b))[0], "fresh checkpoint")
            self.assertIn("fresh checkpoint", cont.build_repo_handoff(str(repo_b), mode="authoritative"))

    def test_08_workspaceless_isolation_scratch_ephemeral_ops_and_hook_budget(self) -> None:
        plugin_dir = REPO_ROOT / "plugin"
        env = dict(
            os.environ,
            CARBON_STACK_HOME=str(self._h.stack_home),
            PLUGIN_ROOT=str(plugin_dir),
        )

        # 1. Workspace-less sessions do not inherit plugin_root as cwd/project_key and never collide
        for sid in ("chat-alpha-001", "chat-beta-002"):
            tp = self._h.brain / sid / ".system_generated" / "logs" / "transcript.jsonl"
            tp.parent.mkdir(parents=True, exist_ok=True)
            tp.write_text(
                json.dumps({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "content": "Hi"}) + "\n",
                encoding="utf-8",
            )
            pl = {
                "conversationId": sid,
                "workspacePaths": [],
                "cwd": str(plugin_dir),
                "transcriptPath": str(tp),
                "hookEventName": "SessionStart",
            }
            proc = subprocess.run(
                [sys.executable, "-X", "utf8", str(HOOKS_DIR / "continuity.py"), "--event", "SessionStart"],
                input=json.dumps(pl).encode("utf-8"),
                capture_output=True,
                cwd=str(plugin_dir),
                env=env,
                check=True,
            )
            self.assertEqual(json.loads(proc.stdout.decode("utf-8")), {})

        sess_rows = [
            json.loads(ln)
            for ln in (self._h.stack_home / "state" / "hygiene" / "sessions.jsonl").read_text(encoding="utf-8").splitlines()
            if ln.strip()
        ]
        by_sid = {r["session"]: r for r in sess_rows}
        self.assertEqual(by_sid["chat-alpha-001"]["cwd"], "")
        self.assertEqual(by_sid["chat-beta-002"]["cwd"], "")
        self.assertNotEqual(by_sid["chat-alpha-001"]["project_key"], by_sid["chat-beta-002"]["project_key"])
        self.assertTrue(by_sid["chat-alpha-001"]["project_key"].startswith("ephemeral-"))
        self.assertNotIn("gemini-carbon-stack", by_sid["chat-alpha-001"]["project_key"])

        # CLI `continuity.py handoff --session <sid>` without --cwd from plugin_dir isolates by session & never writes plugin_dir/.agents
        cli_ho = subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                str(HOOKS_DIR / "continuity.py"),
                "handoff",
                "--session",
                "chat-alpha-001",
                "--goal",
                "Isolated no-ws goal",
                "--mirror-workspace",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            cwd=str(plugin_dir),
            env=env,
            check=True,
        )
        cli_ho_res = json.loads(cli_ho.stdout)
        self.assertEqual(cli_ho_res["project_key"], by_sid["chat-alpha-001"]["project_key"])
        self.assertFalse(cli_ho_res["mirrored_workspace"])
        self.assertFalse((plugin_dir / ".agents" / "handoff.json").exists())

        # Installed plugin dir is never scanned as a fallback user project, while real Git and non-Git dirs still are
        with mock.patch.dict(os.environ, {"PLUGIN_ROOT": str(plugin_dir)}):
            snap_plugin = cwg_mark.take_git_snapshot(str(plugin_dir), workspace_paths=[])
            self.assertTrue(snap_plugin.get("no_project"))
            self.assertEqual(snap_plugin.get("entries"), {})
            self.assertFalse(snap_plugin.get("unmeasured"))

            snap_git = cwg_mark.take_git_snapshot(str(self._h.workspace), workspace_paths=[str(self._h.workspace)])
            self.assertTrue(snap_git["in_git"])

            non_git_proj = self._h.root / "plain_addon"
            non_git_proj.mkdir(parents=True, exist_ok=True)
            (non_git_proj / "core.lua").write_text("x = 1\n", encoding="utf-8")
            snap_plain = cwg_mark.take_git_snapshot(str(non_git_proj), workspace_paths=[str(non_git_proj)])
            self.assertFalse(snap_plain["in_git"])
            self.assertFalse(snap_plain["unmeasured"])
            self.assertEqual(len(snap_plain["entries"]), 1)

        # 2. Local diagnostic operations inside brain/<cid>/scratch (incl. 2>$null & ancestor $HOME cwd) do NOT open false OPERATIONAL
        fake_home = self._h.root / "fake_home"
        diag_sid = "diag-winupdate-900k"
        diag_art = fake_home / ".gemini" / "antigravity" / "brain" / diag_sid
        diag_scratch = diag_art / "scratch" / "cbs_logs"
        diag_tp = diag_art / ".system_generated" / "logs" / "transcript.jsonl"
        diag_tp.parent.mkdir(parents=True, exist_ok=True)
        diag_tp.write_text(
            "\n".join(
                [
                    json.dumps({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "content": "Diagnose CBS"}),
                    json.dumps({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "content": "Причина найдена."}),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        diag_tp.with_name("transcript_full.jsonl").write_text(diag_tp.read_text(encoding="utf-8"), encoding="utf-8")

        ext_log = self._h.root / "CBS.log"
        ext_log.write_text("2026-11-15 CBS entry\n", encoding="utf-8")
        scratch_cmd = (
            "$ErrorActionPreference = 'Continue'\n"
            f"$scratch = '{diag_scratch}'\n"
            "New-Item -ItemType Directory -Path $scratch -Force | Out-Null\n"
            f"Copy-Item '{ext_log}' \"$scratch\\CBS.log\"\n"
            "expand.exe 'C:\\Windows\\Logs\\CBS\\persist.cab' -F:* \"$scratch\"\n"
            "Get-ChildItem $scratch > \"$scratch\\list.txt\"\n"
            "Remove-Item \"$scratch\\list.txt\" -Force 2>$null"
        )
        for ev in ("PreToolUse", "PostToolUse"):
            pl = {
                "conversationId": diag_sid,
                "workspacePaths": [],
                "cwd": str(fake_home),  # ancestor $HOME cwd containing .gemini/antigravity/brain/<cid>/scratch
                "artifactDirectoryPath": str(diag_art),
                "transcriptPath": str(diag_tp),
                "hookEventName": ev,
                "toolCall": {"id": "sc1", "name": "run_command", "args": {"CommandLine": scratch_cmd}},
                "error": "",
            }
            subprocess.run(
                [sys.executable, "-X", "utf8", str(HOOKS_DIR / "cwg_mark.py"), "--event", ev],
                input=json.dumps(pl).encode("utf-8"),
                capture_output=True,
                cwd=str(plugin_dir),
                env=env,
                check=True,
            )
        self.assertFalse((self._h.stack_home / "state" / "gate" / "markers" / f"{diag_sid}.json").exists())
        stop_proc = subprocess.run(
            [sys.executable, "-X", "utf8", str(HOOKS_DIR / "cwg_stop.py"), "--event", "Stop"],
            input=json.dumps(
                {
                    "conversationId": diag_sid,
                    "workspacePaths": [],
                    "cwd": str(plugin_dir),
                    "artifactDirectoryPath": str(diag_art),
                    "transcriptPath": str(diag_tp),
                    "hookEventName": "Stop",
                    "terminationReason": "NO_TOOL_CALL",
                    "fullyIdle": True,
                }
            ).encode("utf-8"),
            capture_output=True,
            cwd=str(plugin_dir),
            env=env,
            check=True,
        )
        self.assertEqual(json.loads(stop_proc.stdout.decode("utf-8")), {"decision": "allow"})

        apos_art = r"C:\Users\O'Brien\.gemini\antigravity\brain\apos-cid"
        apos_cmd = (
            "$s = Join-Path 'C:\\Users\\O''Brien\\.gemini\\antigravity\\brain\\apos-cid' 'scratch'\n"
            "New-Item -ItemType Directory -Path $s -Force | Out-Null\n"
            "Set-Content -Path \"$s\\note.txt\" -Value 'ok'"
        )
        self.assertTrue(cwg_mark.is_ephemeral_only_shell_mutation(apos_cmd, artifact_dir=apos_art))
        external_target = self._h.root / "outside_precious.txt"
        self.assertEqual(
            cwg_mark.classify_shell_command(
                f'Write-Host "$(if (Test-Path \'{external_target}\') {{ Remove-Item \'{external_target}\' -Force }})"'
            ),
            "MUTATING",
        )
        self.assertEqual(
            cwg_mark.classify_shell_command(
                'Write-Host "$(if ($true) { Invoke-RestMethod https://example.com/api -Method \'POST\' })"'
            ),
            "MUTATING",
        )

        # Real external file, comma-array, PS provider, quoted HTTP method, --output, system, or opaque-script mutations STILL open OPERATIONAL!
        for idx, dangerous_cmd in enumerate(
            [
                f"Set-Location '{diag_scratch}'; Remove-Item '{external_target}' -Force",
                f"Remove-Item \"{diag_scratch}\\a.txt\",\"{external_target}\" -Force",
                f"Set-Location '{diag_scratch}'; Remove-Item 'HKCU:\\Software\\MyKey' -Recurse -Force",
                f"Set-Location '{diag_scratch}'; Remove-Item 'FileSystem::{external_target}' -Force",
                f"New-Item -ItemType Directory -Path '{diag_scratch}' -Force; git -C '{self._h.workspace}' diff --output='{external_target}'",
                f"New-Item -ItemType Directory -Path '{diag_scratch}' -Force; Stop-Service wuauserv",
                f"Set-Location '{diag_scratch}'; curl.exe -X \"POST\" https://example.com/api",
                f"Set-Location '{diag_scratch}'; Invoke-RestMethod https://example.com/api -Method 'POST'",
                f"Set-Location '{diag_scratch}'; wget https://example.com/api -Method 'POST'",
                f"Set-Location '{diag_scratch}'; curl.exe -XPOST https://example.com/api",
                f"Set-Location '{diag_scratch}'; Invoke-WebRequest https://example.com/a.bin -OutFile '{external_target}'",
                f"Set-Location '{diag_scratch}'; \"C:\\Python313\\python.exe\" deploy_external.py",
                f"if (Test-Path '{diag_scratch}') {{ python '{diag_scratch}\\deploy.py' }}",
                f"Write-Host \"Result: $(python '{diag_scratch}\\deploy.py')\"",
                f"Set-Location '{diag_scratch}'; Write-Output \"$(.\\deploy.ps1)\"",
                f"Get-ChildItem '{diag_scratch}' | ForEach-Object .\\deploy.ps1",
                f"Get-ChildItem '{diag_scratch}' | % {{ & $_.FullName }}",
                f"$s = '{diag_scratch}'; $q = \"' \"; Set-Content -Value $q -Path '{external_target}' -Exclude $q\"$s\\fake.txt\"",
                f"Set-Location '{diag_scratch}'; .\\deploy.ps1",
                f"Remove-Item '{diag_tp}' -Force",  # .system_generated tampering is NOT scratch-exempt!
                f"Move-Item '{ext_log}' '{diag_scratch}\\moved.log'",
            ]
        ):
            msid = f"mut-guard-{idx}"
            mtp = self._h.brain / msid / ".system_generated" / "logs" / "transcript.jsonl"
            mtp.parent.mkdir(parents=True, exist_ok=True)
            mtp.write_text(diag_tp.read_text(encoding="utf-8"), encoding="utf-8")
            mtp.with_name("transcript_full.jsonl").write_text(diag_tp.read_text(encoding="utf-8"), encoding="utf-8")
            for ev in ("PreToolUse", "PostToolUse"):
                subprocess.run(
                    [sys.executable, "-X", "utf8", str(HOOKS_DIR / "cwg_mark.py"), "--event", ev],
                    input=json.dumps(
                        {
                            "conversationId": msid,
                            "workspacePaths": [],
                            "cwd": str(plugin_dir),
                            "artifactDirectoryPath": str(diag_art),
                            "transcriptPath": str(mtp),
                            "hookEventName": ev,
                            "toolCall": {"id": f"m{idx}", "name": "run_command", "args": {"CommandLine": dangerous_cmd}},
                            "error": "",
                        }
                    ).encode("utf-8"),
                    capture_output=True,
                    cwd=str(plugin_dir),
                    env=env,
                    check=True,
                )
            m_doc = json.loads(
                (self._h.stack_home / "state" / "gate" / "markers" / f"{msid}.json").read_text(encoding="utf-8")
            )
            self.assertTrue(m_doc.get("operational"), msg=f"Missed operational mutation: {dangerous_cmd}")

        # 3. Hook budget & Loop Guard generation sync via monotonic mutation stamp (including scratch edits & subagents)
        hooks_cfg = json.loads((plugin_dir / "hooks.json").read_text(encoding="utf-8"))
        self.assertEqual(list(hooks_cfg.keys()), ["carbon-stack"])
        self.assertIn("run_command", hooks_cfg["carbon-stack"]["PreToolUse"][0]["matcher"])
        self.assertEqual(hooks_cfg["carbon-stack"]["PostToolUse"][0]["matcher"], "edit_file|write_file|run_command")

        app_py = self._h.workspace / "app.py"
        scratch_probe = self._h.brain / self._h.conv_id / "scratch" / "probe.py"
        read_call = {"toolCall": {"id": "lg1", "name": "read_file", "args": {"Path": str(app_py), "StartLine": 1, "EndLine": 2}}}
        for expected in ("allow", "allow", "deny"):
            _, out = self._h.run_hook("continuity.py", "PreToolUse", read_call)
            self.assertEqual(out["decision"], expected)
        # Even a scratch write_file recorded by cwg_mark PostToolUse advances mutation stamp and resets Loop Guard
        self._h.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {"toolCall": {"id": "ed1", "name": "write_file", "args": {"Path": str(scratch_probe), "Content": "x = 1\n"}}, "error": ""},
        )
        _, after_edit_out = self._h.run_hook("continuity.py", "PreToolUse", read_call)
        self.assertEqual(after_edit_out["decision"], "allow")

        # INVARIANT: Tokenade CLI wrappers are unwrapped before classification and safety guards.
        self.assertEqual(
            cwg_mark.classify_shell_command(
                '"C:\\tools\\tokenade.exe" wrap --shell powershell \'git status --short\''
            ),
            "READ_ONLY",
        )
        self.assertEqual(
            cwg_mark.classify_shell_command(
                '"C:\\tools\\tokenade.exe" wrap --shell powershell \'python -X utf8 -m unittest discover -s tests -v\''
            ),
            "VALIDATION",
        )
        self.assertEqual(
            cwg_mark.classify_shell_command(
                "tokenade wrap 'Remove-Item C:\\outside.txt -Force'; git status"
            ),
            "MUTATING",
        )
        for ro_tk in ("tokenade map", "tokenade skeleton app.py", "tokenade query main", "tokenade healthcheck"):
            self.assertEqual(cwg_mark.classify_shell_command(ro_tk), "READ_ONLY", msg=ro_tk)
        tk_dec, _ = guards.guard_shell_command("tokenade wrap 'git worktree remove C:\\wt'", str(self._h.workspace))
        self.assertEqual(tk_dec, "deny")
        bt_dec, _ = guards.guard_shell_command('tokenade wrap "git worktree re`move C:\\wt"', str(self._h.workspace))
        self.assertEqual(bt_dec, "deny")
        apo_dec, _ = guards.guard_shell_command('Write-Output "\'$(git worktree re`move C:\\wt)\'"', str(self._h.workspace))
        self.assertEqual(apo_dec, "deny")
        bt_repo = self._h.root / "repo`a"
        self._h._init_git_repo(bt_repo, {"f.py": "x = 1\n"}, "init bt")
        (bt_repo / "f.py").write_text("x = 2\n", encoding="utf-8")
        clean_cwd = self._h.root / "clean_repo"
        self._h._init_git_repo(clean_cwd, {"c.py": "c = 1\n"}, "init clean")
        lit_bt_dec, _ = guards.guard_shell_command(f"git -C '{bt_repo}' reset --hard", str(clean_cwd))
        self.assertEqual(lit_bt_dec, "deny")
        smuggled_tk = '& "C:\\tools\\$(git reset --hard | Out-Null)tokenade.cmd" wrap \'git status --short\''
        self.assertEqual(cwg_mark.classify_shell_command(smuggled_tk), "MUTATING")
        (self._h.workspace / "app.py").write_text("dirty = 1\n", encoding="utf-8")
        smug_dec, _ = guards.guard_shell_command(smuggled_tk, str(self._h.workspace))
        self.assertEqual(smug_dec, "deny")

        # INVARIANT: `swarm_wait` is blocked when all active swarm workers have already posted replies to the board,
        # while `cwg_stop.py` still honors pending non-Codex background `run_command` tasks alongside idle unkilled workers.
        self._h.add_swarm_worker(
            name="simp-reuse-done",
            model="claude-sonnet-5-5-high",
            brief="Check reuse",
            worker_post="@coordinator\nSIMPLIFY_LENS: REUSE\nSIMPLIFY_VERDICT: CLEAN",
        )
        _, sw_wait_out = self._h.run_hook(
            "safety_guards.py",
            "PreToolUse",
            {"toolCall": {"id": "sw1", "name": "swarm_wait", "args": {"since": 1}}},
        )
        self.assertEqual(sw_wait_out["decision"], "deny")
        self.assertIn("[Swarm Wait Guard]", sw_wait_out["reason"])

        self._h.run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {"toolCall": {"id": "w_bg", "name": "write_file", "args": {"Path": str(app_py), "Content": "dirty = 1\n"}}, "error": ""},
        )
        now_iso = trg.iso_now()
        self._h.steps.extend(
            [
                {
                    "step_index": len(self._h.steps),
                    "source": "MODEL",
                    "type": "PLANNER_RESPONSE",
                    "status": "DONE",
                    "created_at": now_iso,
                    "tool_calls": [{"name": "run_command", "args": {"CommandLine": "python -X utf8 -m unittest -v"}}],
                },
                {
                    "step_index": len(self._h.steps) + 1,
                    "source": "MODEL",
                    "type": "GENERIC",
                    "status": "DONE",
                    "created_at": now_iso,
                    "content": "Tool is running as a background task with task id: bg-unittest-01\n",
                },
            ]
        )
        self._h._flush_transcript()
        self._h.add_final_response("Waiting for background test task...")
        _, bg_allow = self._h.run_hook("cwg_stop.py", "Stop", {"terminationReason": "NO_TOOL_CALL", "fullyIdle": False})
        self.assertEqual(bg_allow, {"decision": "allow"})

        self._h.steps.append(
            {
                "step_index": len(self._h.steps),
                "source": "SYSTEM",
                "type": "SYSTEM_MESSAGE",
                "status": "DONE",
                "created_at": trg.iso_now(),
                "content": 'Task id "bg-unittest-01" finished with result:\nCommand exited with code 0.\n',
            }
        )
        self._h._flush_transcript()
        _, idle_worker_blk = self._h.run_hook(
            "cwg_stop.py", "Stop", {"terminationReason": "NO_TOOL_CALL", "fullyIdle": False}
        )
        self.assertEqual(idle_worker_blk["decision"], "continue")

    def test_09_tokenade_hook_antigravity_bridge_and_code_search_off_path_rg(self) -> None:
        sys.path.insert(0, str(TOOLS_DIR))
        import code_search
        import runtime_io as rio
        import tokenade_hook

        fake_tk = self._h.root / "fake_tokenade.py"
        fake_tk.write_text("# stub\n", encoding="utf-8")

        captured_bridge_inputs: list[dict] = []

        def _fake_tk_run(cmd, **kw):
            req = json.loads((kw.get("input") or b"{}").decode("utf-8"))
            captured_bridge_inputs.append(req)
            inner_c = req["tool_input"]["command"]
            if "\n" in inner_c:
                return subprocess.CompletedProcess(cmd, 0, b"", b"")
            esc = inner_c.replace("'", "''")
            out_obj = {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "updatedInput": {
                        "command": f"& 'C:/tools/tokenade.exe' wrap --shell powershell '{esc}'"
                    },
                }
            }
            return subprocess.CompletedProcess(cmd, 0, json.dumps(out_obj).encode("utf-8"), b"")

        with (
            mock.patch.dict(os.environ, {"CARBON_TOKENADE_BIN": str(fake_tk)}, clear=False),
            mock.patch.object(tokenade_hook.subprocess, "run", side_effect=_fake_tk_run),
        ):
            # 1. Enabled by default even when TOKENADE_AUTO_WRAP is unset; translates Antigravity `toolCall.args.CommandLine`
            os.environ.pop("TOKENADE_AUTO_WRAP", None)
            rw_cd = tokenade_hook.transform_pretool_payload(
                {
                    "event": "PreToolUse",
                    "toolCall": {
                        "name": "run_command",
                        "args": {"CommandLine": 'Set-Location "C:\\repo"\n$null | npm test'},
                    },
                }
            )
            self.assertIsNotNone(rw_cd)
            assert rw_cd is not None
            self.assertTrue(rw_cd.startswith('Set-Location "C:\\repo"\n'))
            self.assertIn("wrap --shell powershell '$null | npm test'", rw_cd)
            # Round-trip unwrap preserves exact original command and gate `VALIDATION` recognition!
            self.assertEqual(rio.unwrap_tokenade_command(rw_cd), 'Set-Location "C:\\repo"\n$null | npm test')
            self.assertEqual(cwg_mark.classify_shell_command(rw_cd), "VALIDATION")

            # 2. Protocol CLIs (`codex_lane.py`, `install.py`, `chat-bus`, etc.) and multiline scripts are never wrapped
            self.assertIsNone(
                tokenade_hook.transform_pretool_payload(
                    {
                        "toolCall": {
                            "name": "run_command",
                            "args": {"CommandLine": "$null | python -X utf8 codex_lane.py review --cwd C:/repo"},
                        }
                    }
                )
            )
            self.assertIsNone(
                tokenade_hook.transform_pretool_payload(
                    {
                        "toolCall": {
                            "name": "run_command",
                            "args": {"CommandLine": "$a = 1\n$b = 2\nWrite-Output $a"},
                        }
                    }
                )
            )

            # 3. Explicit `TOKENADE_AUTO_WRAP=0` disables wrapping cleanly
            with mock.patch.dict(os.environ, {"TOKENADE_AUTO_WRAP": "0"}):
                self.assertIsNone(
                    tokenade_hook.transform_pretool_payload(
                        {"toolCall": {"name": "run_command", "args": {"CommandLine": "npm test"}}}
                    )
                )

            # 3b. Commands with `"` or trailing `\` in `stripped_core` on Windows bypass wrapping (preventing PS 5.1 quote stripping)
            unsafe_double_quote_cases = (
                'Write-Output "a b"',
                'Write-Output "SAFE; Write-Output EXECUTED"',
                'Write-Output ""; $x=42; Write-Output $x',
            )
            if os.name == "nt":
                for unsafe_ps51 in (*unsafe_double_quote_cases, "git status C:\\repo\\"):
                    self.assertIsNone(
                        tokenade_hook.transform_pretool_payload(
                            {"toolCall": {"name": "run_command", "args": {"CommandLine": unsafe_ps51}}}
                        ),
                        msg=f"expected PS 5.1 unsafe command to stay unwrapped: {unsafe_ps51}",
                    )
            self.assertEqual(len(captured_bridge_inputs), 1)
            self.assertEqual(captured_bridge_inputs[0]["tool_input"]["command"], "$null | npm test")

        # 3c. End-to-end execution parity in real Windows PowerShell 5.1 (`powershell.exe`) + real Tokenade CLI (if installed)
        import shutil

        ps51_bin = shutil.which("powershell.exe") if os.name == "nt" else None
        real_tk_bin = tokenade_hook.find_tokenade_bin() if os.name == "nt" else None
        if ps51_bin and real_tk_bin:
            parity_cases = [
                *unsafe_double_quote_cases,
                "Write-Output 'a b'",
                "Write-Output 'SAFE; Write-Output EXECUTED'",
                "Write-Output ''; $x=42; Write-Output $x",
                "Write-Output C:\\repo\\",
                f'Set-Location "{self._h.root}"\nWrite-Output \'cd-ok; still literal\'',
            ]
            with mock.patch.dict(os.environ, {"TOKENADE_AUTO_WRAP": "1"}, clear=False):
                for raw_ps_cmd in parity_cases:
                    rewritten = tokenade_hook.transform_pretool_payload(
                        {"toolCall": {"name": "run_command", "args": {"CommandLine": raw_ps_cmd}}}
                    )
                    eff_ps_cmd = rewritten or raw_ps_cmd
                    base_res = subprocess.run(
                        [ps51_bin, "-NoProfile", "-NonInteractive", "-Command", raw_ps_cmd],
                        capture_output=True,
                        text=True,
                        timeout=15.0,
                    )
                    wrap_res = subprocess.run(
                        [ps51_bin, "-NoProfile", "-NonInteractive", "-Command", eff_ps_cmd],
                        capture_output=True,
                        text=True,
                        timeout=15.0,
                    )
                    self.assertEqual(wrap_res.returncode, base_res.returncode, msg=raw_ps_cmd)
                    self.assertEqual(wrap_res.stdout, base_res.stdout, msg=raw_ps_cmd)

        # 4. `code_search.find_rg()` honors `CARBON_RG_BIN` and off-PATH Windows fallback without leaking `_RG_CACHE`
        fake_rg = self._h.root / "custom_rg.exe"
        fake_rg.write_text("MZ", encoding="utf-8")
        with mock.patch.dict(os.environ, {"CARBON_RG_BIN": str(fake_rg)}):
            self.assertEqual(code_search.find_rg(), str(fake_rg))
        with (
            mock.patch.object(code_search, "_RG_CACHE", False),
            mock.patch.dict(os.environ, {"CARBON_RG_BIN": ""}),
            mock.patch.object(code_search.shutil, "which", return_value=None),
        ):
            if os.name == "nt" and pathlib.Path(code_search.DEFAULT_WINDOWS_RG_PATH).is_file():
                self.assertIsNotNone(code_search.find_rg())


if __name__ == "__main__":
    unittest.main()
