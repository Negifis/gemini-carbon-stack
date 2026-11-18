#!/usr/bin/env python3
"""Unit and integration tests for Swarm 2.0 architecture."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
HOOKS_DIR = REPO_ROOT / "plugin" / "hooks"
TOOLS_DIR = REPO_ROOT / "plugin" / "tools"

for _p in (str(HOOKS_DIR), str(TOOLS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import cwg_common as cwg
import cwg_stop
import gate_inbox
import safety_guards
import stack_doctor


def _iso_ts(ts: float | None = None) -> str:
    val = time.time() if ts is None else ts
    return datetime.fromtimestamp(val, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SwarmV2TestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="swarm2-test-")
        self.root = pathlib.Path(self.tmp.name)
        self.brain = self.root / "brain"
        self.stack_home = self.root / "stack-home"
        self.workspace = self.root / "workspace"
        self.brain.mkdir(parents=True)
        self.stack_home.mkdir(parents=True)
        self.workspace.mkdir(parents=True)
        self.conv_id = "22222222-3333-4444-5555-666666666666"
        self.logs_dir = self.brain / self.conv_id / ".system_generated" / "logs"
        self.logs_dir.mkdir(parents=True)
        self.transcript = self.logs_dir / "transcript.jsonl"
        self.steps: list[dict] = [
            {
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "status": "DONE",
                "created_at": _iso_ts(),
                "content": "Build Swarm 2.0 features",
            }
        ]
        self._flush_transcript()

        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "CARBON_STACK_HOME": str(self.stack_home),
                "ANTIGRAVITY_BRAIN_ROOT": str(self.brain),
            },
        )
        self._env_patch.start()

    def tearDown(self) -> None:
        self._env_patch.stop()
        try:
            self.tmp.cleanup()
        except PermissionError:
            shutil.rmtree(self.tmp.name, ignore_errors=True)

    def _flush_transcript(self) -> None:
        self.transcript.write_text(
            "".join(json.dumps(s, ensure_ascii=False) + "\n" for s in self.steps),
            encoding="utf-8",
        )

    def _init_git(self, files: dict[str, str]) -> None:
        subprocess.run(["git", "init", "-b", "main"], cwd=str(self.workspace), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=str(self.workspace), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "t@local"], cwd=str(self.workspace), check=True, capture_output=True)
        for rel, body in files.items():
            fp = self.workspace / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(body, encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(self.workspace), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=str(self.workspace), check=True, capture_output=True)

    def _run_hook(self, script: str, event: str, payload: dict) -> dict:
        cmd = [sys.executable, "-X", "utf8", str(HOOKS_DIR / script), "--event", event]
        proc = subprocess.run(
            cmd,
            input=json.dumps(payload, ensure_ascii=False),
            text=True,
            encoding="utf-8",
            capture_output=True,
            env={**os.environ},
            check=True,
        )
        return json.loads(proc.stdout.strip())

    def _run_ctl(self, *args: str) -> tuple[int, dict]:
        cmd = [sys.executable, "-X", "utf8", str(TOOLS_DIR / "swarm_ctl.py"), *args]
        proc = subprocess.run(
            cmd,
            text=True,
            encoding="utf-8",
            capture_output=True,
            env={**os.environ},
        )
        data = json.loads(proc.stdout.strip()) if proc.stdout.strip() else {}
        return proc.returncode, data

    def _load_marker(self) -> dict | None:
        doc = cwg.rio.read_json(cwg.marker_path(self.conv_id), default=None)
        return doc if isinstance(doc, dict) else None

    def _swarm_dir(self) -> pathlib.Path:
        d = self.brain / self.conv_id / ".system_generated" / "swarm"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _append_board(self, agent: str, text: str, ts: float | None = None) -> int:
        sdir = self._swarm_dir()
        bfile = sdir / "board.jsonl"
        rows = [ln for ln in bfile.read_text(encoding="utf-8").splitlines() if ln.strip()] if bfile.exists() else []
        seq = len(rows) + 1
        eff_ts = time.time() if ts is None else ts
        tstr = datetime.fromtimestamp(eff_ts).strftime("%Y-%m-%d %H:%M:%S")
        rows.append(json.dumps({"seq": seq, "agent": agent, "text": text, "time": tstr}, ensure_ascii=False))
        bfile.write_text("\n".join(rows) + "\n", encoding="utf-8")
        return seq

    def _mark_edit(self, rel_path: str, content: str, tool: str = "write_file") -> None:
        fp = self.workspace / rel_path
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(content, encoding="utf-8")
        self._run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {
                "session_id": self.conv_id,
                "cwd": str(self.workspace),
                "transcriptPath": str(self.transcript),
                "toolCall": {
                    "name": tool,
                    "args": {"Path": str(fp), "Content": content},
                },
            },
        )

    def _mark_tests_passed(self) -> None:
        self._run_hook(
            "cwg_mark.py",
            "PostToolUse",
            {
                "session_id": self.conv_id,
                "cwd": str(self.workspace),
                "transcriptPath": str(self.transcript),
                "toolCall": {
                    "name": "run_command",
                    "args": {"CommandLine": "python -X utf8 -m unittest discover -s tests -v"},
                },
                "toolResult": {"exitCode": 0, "output": "Ran 10 tests\nOK"},
            },
        )

    def test_01_anom_94b1b435_verdict_parser_variants_and_template_rejection(self) -> None:
        # Single-line period/comma/semicolon/space & case-insensitive
        p1 = gate_inbox.parse_simplify_verdict("@coordinator SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN.")
        self.assertEqual(p1["lens"], "reuse")
        self.assertEqual(p1["verdict"], "CLEAN")
        self.assertTrue(p1["clean"])

        p2 = gate_inbox.parse_simplify_verdict("SIMPLIFY_LENS: QUALITY, SIMPLIFY_VERDICT: FINDINGS_REPORTED;")
        self.assertEqual(p2["lens"], "quality")
        self.assertEqual(p2["verdict"], "FINDINGS_REPORTED")
        self.assertFalse(p2["clean"])

        p3 = gate_inbox.parse_simplify_verdict("simplify_lens: efficiency simplify_verdict: actionable_fixes")
        self.assertEqual(p3["lens"], "efficiency")
        self.assertEqual(p3["verdict"], "ACTIONABLE_FIXES")

        # Markdown-wrapped tokens + combined ALL
        p4 = gate_inbox.parse_simplify_verdict("**SIMPLIFY_LENS**: REUSE **SIMPLIFY_VERDICT**: `CLEAN`")
        self.assertEqual(p4["lens"], "reuse")
        self.assertEqual(p4["verdict"], "CLEAN")
        self.assertTrue(p4["clean"])

        p5 = gate_inbox.parse_simplify_verdict("**SIMPLIFY_LENS:** __ALL__ ; **SIMPLIFY_VERDICT:** **CLEAN**")
        self.assertEqual(p5["lens"], "all")
        self.assertTrue(p5["combined"])
        self.assertTrue(p5["has_explicit_all"])
        self.assertTrue(p5["clean"])

        p6 = gate_inbox.parse_simplify_verdict("`SIMPLIFY_LENS: ALL` `SIMPLIFY_VERDICT: CLEAN`")
        self.assertEqual(p6["lens"], "all")
        self.assertTrue(p6["clean"])

        p_anom = gate_inbox.parse_simplify_verdict(
            "@coordinator\n"
            "All flags and tokens (`DIFF_HASH: <current_diff_hash>`, `VERDICT: APPROVED`, `SIMPLIFY_LENS: ALL`, `CLOSURE_VALIDATION: READY|BLOCKED`) are consistent.\n"
            "DIFF_HASH: 061484edee70341e\n"
            "SIMPLIFY_LENS: REUSE\n"
            "SIMPLIFY_VERDICT: CLEAN"
        )
        self.assertEqual(p_anom["lens"], "reuse")
        self.assertFalse(p_anom["has_explicit_all"])
        self.assertFalse(p_anom["combined"])
        self.assertTrue(p_anom["clean"])

        # Prompt templates and alternations MUST NOT match as real verdicts
        for tpl in (
            "Respond with SIMPLIFY_VERDICT: CLEAN or ACTIONABLE_FIXES.",
            "`SIMPLIFY_VERDICT: CLEAN` (or `SIMPLIFY_VERDICT: ACTIONABLE_FIXES`)",
            "SIMPLIFY_LENS: REUSE|QUALITY|EFFICIENCY and SIMPLIFY_VERDICT: CLEAN|FINDINGS_REPORTED|ACTIONABLE_FIXES",
            "SIMPLIFY_VERDICT: CLEAN или ACTIONABLE_FIXES",
            "__SIMPLIFY_VERDICT__: __CLEAN__ or __SIMPLIFY_VERDICT__: __ACTIONABLE_FIXES__",
            "**SIMPLIFY_VERDICT:** **ACTIONABLE_FIXES** or **SIMPLIFY_VERDICT:** **CLEAN**",
            "SIMPLIFY_LENS: QUALITY, REUSE",
        ):
            pt = gate_inbox.parse_simplify_verdict(tpl)
            self.assertEqual(pt["verdict"], "", msg=f"Template spoofed verdict: {tpl}")
            self.assertFalse(pt["clean"])

    def test_02_warm_pool_watermark_round_start_msg_id_and_diff_hash(self) -> None:
        msgs = [
            {"seq": 1, "agent": "coordinator", "text": "@simplify-reuse Check round 1"},
            {"seq": 2, "agent": "simplify-reuse", "text": "DIFF_HASH: hash1\nSIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."},
            {"seq": 3, "agent": "simplify-quality", "text": "DIFF_HASH: hash1\n**SIMPLIFY_LENS**: QUALITY, **SIMPLIFY_VERDICT**: `CLEAN`"},
            {"seq": 4, "agent": "simplify-efficiency", "text": "DIFF_HASH: hash1\nSIMPLIFY_LENS: EFFICIENCY; SIMPLIFY_VERDICT: CLEAN"},
        ]
        res_r1 = gate_inbox.validate_warm_worker_verdicts(msgs, round_start_msg_id=0, current_diff_hash="hash1")
        self.assertTrue(res_r1["satisfied"])

        # New edit advances round_start_msg_id=4 and current_diff_hash="hash2": stale msgs <=4 must be rejected
        res_stale = gate_inbox.validate_warm_worker_verdicts(msgs, round_start_msg_id=4, current_diff_hash="hash2", fast_path=True)
        self.assertFalse(res_stale["satisfied"])
        self.assertGreaterEqual(res_stale["stale_rejected"], 3)

        # Even if a worker replies at seq=5 with wrong DIFF_HASH=hash1, reject it
        msgs.append({"seq": 5, "agent": "simplify-reviewer", "text": "DIFF_HASH: hash1\nSIMPLIFY_LENS: ALL. SIMPLIFY_VERDICT: CLEAN."})
        res_wrong_hash = gate_inbox.validate_warm_worker_verdicts(msgs, round_start_msg_id=4, current_diff_hash="hash2", fast_path=True)
        self.assertFalse(res_wrong_hash["satisfied"])

        # Re-wake waiting worker via @mention at seq=6; worker replies at seq=7 with matching DIFF_HASH=hash2 -> satisfied!
        msgs.append({"seq": 6, "agent": "coordinator", "text": "@simplify-reviewer Check updated diff hash2"})
        msgs.append({"seq": 7, "agent": "simplify-reviewer", "text": "DIFF_HASH: hash2\nSIMPLIFY_LENS: ALL. SIMPLIFY_VERDICT: CLEAN."})
        res_r2 = gate_inbox.validate_warm_worker_verdicts(msgs, round_start_msg_id=4, current_diff_hash="hash2", fast_path=True)
        self.assertTrue(res_r2["satisfied"])
        msgs_revoked = list(msgs) + [
            {"seq": 8, "agent": "simplify-reviewer", "text": "DIFF_HASH: hash2\nSIMPLIFY_VERDICT: ACTIONABLE_FIXES."}
        ]
        res_revoked = gate_inbox.validate_warm_worker_verdicts(
            msgs_revoked, round_start_msg_id=4, current_diff_hash="hash2", fast_path=True
        )
        self.assertFalse(res_revoked["satisfied"])

        # Same-second Warm Pool re-wake in cwg_stop.scan_swarm_activity
        self._init_git({"app.py": "def ok():\n    return 1\n"})
        self._mark_edit("app.py", "def ok():\n    return 2\n")
        sdir = self._swarm_dir()
        mfile = sdir / "members.json"
        mfile.write_text(
            json.dumps(
                {
                    "members": {
                        "simplify-reviewer": {
                            "conversation_id": "sw-warm-1",
                            "model": cwg.SONNET_HIGH_MODEL,
                            "role": "worker",
                            "wake_mode": "mentions",
                            "killed": False,
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        t_same = time.time()
        self._append_board("coordinator", "@simplify-reviewer round 1", ts=t_same)
        self._append_board("simplify-reviewer", "SIMPLIFY_LENS: ALL. SIMPLIFY_VERDICT: CLEAN.", ts=t_same)
        # Re-edit bumps round_start_msg_id=2 on marker
        self._mark_edit("app.py", "def ok():\n    return 3\n")
        marker = cwg.rio.read_json(cwg.marker_path(self.conv_id), default=None)
        self.assertEqual(marker["round_start_msg_id"], 2)
        ev_before_rewake = cwg_stop.scan_swarm_activity(
            self.steps,
            str(self.transcript),
            float(marker["first_ts"]),
            round_start_msg_id=int(marker["round_start_msg_id"]),
            current_diff_hash=str(marker["current_diff_hash"]),
            cwd=str(self.workspace),
        )
        self.assertEqual(ev_before_rewake["sonnet_combined_ts"], 0.0)

        # Same-second @mention wake WITHOUT reply yet -> in_flight (not falsely marked replied!)
        self._append_board("coordinator", "@simplify-reviewer round 2", ts=t_same)
        ev_inflight = cwg_stop.scan_swarm_activity(
            self.steps,
            str(self.transcript),
            float(marker["first_ts"]),
            round_start_msg_id=int(marker["round_start_msg_id"]),
            current_diff_hash=str(marker["current_diff_hash"]),
            cwd=str(self.workspace),
        )
        self.assertIn("swarm:simplify-reviewer", ev_inflight["in_flight_workers"])

        # Worker posts round 2 CLEAN at same second (higher seq=4 > 3)
        self._append_board("simplify-reviewer", "SIMPLIFY_LENS: ALL. SIMPLIFY_VERDICT: CLEAN.", ts=t_same)
        ev_r2 = cwg_stop.scan_swarm_activity(
            self.steps,
            str(self.transcript),
            float(marker["first_ts"]),
            round_start_msg_id=int(marker["round_start_msg_id"]),
            current_diff_hash=str(marker["current_diff_hash"]),
            cwd=str(self.workspace),
        )
        self.assertGreater(ev_r2["sonnet_combined_ts"], 0.0)

    def test_03_swarm_v2_pipeline_order_and_fast_path(self) -> None:
        # 1) Large HIGH change (>2 files, >30 lines): Logic-first order + 3 lenses required
        self._init_git(
            {
                "auth_a.py": "def a():\n    return 0\n",
                "auth_b.py": "def b():\n    return 0\n",
                "auth_c.py": "def c():\n    return 0\n",
            }
        )
        self._mark_edit("auth_a.py", "\n".join(f"def a{i}(): return {i}" for i in range(15)) + "\n")
        self._mark_edit("auth_b.py", "\n".join(f"def b{i}(): return {i}" for i in range(15)) + "\n")
        self._mark_edit("auth_c.py", "\n".join(f"def c{i}(): return {i}" for i in range(15)) + "\n")
        self._mark_tests_passed()

        marker = cwg.rio.read_json(cwg.marker_path(self.conv_id), default=None)
        self.assertFalse(cwg.is_simplify_fast_path_eligible(marker=marker, repo_root=str(self.workspace)))
        t0 = float(marker["first_ts"])
        cctx = cwg.resolve_candidate_context(marker)
        receipt = {"kind": "verified", "risk": "HIGH"}
        checks_ev = cwg_stop.read_checks_evidence(self.conv_id, t0)
        empty_sub = {"reviews": [], "fallback_lenses": {}, "fallback_lenses_end": {}, "fallback_combined_ts": 0.0, "fallback_combined_end_ts": 0.0, "simplify_launch_steps": set(), "simplify_history": [], "simplify_failures": 0, "review_failures": [], "in_flight_subagents": []}
        empty_sw = {"sonnet_lenses": {}, "fallback_lenses": {}, "sonnet_lenses_end": {}, "fallback_lenses_end": {}, "sonnet_combined_ts": 0.0, "fallback_combined_ts": 0.0, "sonnet_combined_end_ts": 0.0, "fallback_combined_end_ts": 0.0, "simplify_launch_steps": set(), "simplify_history": [], "simplify_failures": 0, "reviews": [], "review_failures": [], "in_flight_workers": [], "idle_unkilled_workers": [], "pending_bg_tasks": [], "opus_issue_verified": False, "opus_issue_ts": 0.0, "sonnet_issue_verified": False, "codex_cmd_failed": False, "codex_issue_ts": 0.0, "codex_issue_step": -1, "aborted_codex_reviews": {}, "multi_lens_spoof": False}

        # Step A: Nothing run yet -> blocks asking for PRIMARY REVIEW BEFORE simplify!
        ok0, why0 = cwg_stop.validate_candidate_closure(receipt, marker, checks_ev, empty_sub, empty_sw, [], ctx=cctx)
        self.assertFalse(ok0)
        self.assertIn("primary independent review", why0.lower())
        self.assertIn("BEFORE simplify", why0)

        # Step B: Primary review ends in REVISE -> blocks asking to resolve findings BEFORE simplify!
        rev1_revise = [{"engine": "codex", "kind": "ordinary", "verdict": "REVISE", "launch_ts": t0 + 10.0, "verdict_ts": t0 + 12.0, "xhigh": False}]
        ok1, why1 = cwg_stop.validate_candidate_closure(receipt, marker, checks_ev, empty_sub, empty_sw, rev1_revise, ctx=cctx)
        self.assertFalse(ok1)
        self.assertIn("REVISE", why1)
        self.assertIn("BEFORE running simplify", why1)

        # Step C: Primary review Round 2 APPROVED -> blocks now asking for 3 simplify lenses!
        revs_approved = rev1_revise + [{"engine": "codex", "kind": "ordinary", "verdict": "APPROVED", "launch_ts": t0 + 20.0, "verdict_ts": t0 + 22.0, "xhigh": False}]
        ok2, why2 = cwg_stop.validate_candidate_closure(receipt, marker, checks_ev, empty_sub, empty_sw, revs_approved, ctx=cctx)
        self.assertFalse(ok2)
        self.assertIn("all 3 separate", why2)

        # Step D: Attempting SIMPLIFY_LENS: ALL on >2 files / >30 lines fails!
        sw_combined_large = {**empty_sw, "sonnet_combined_ts": t0 + 30.0, "sonnet_combined_end_ts": t0 + 35.0, "simplify_history": [{"kind": "combined", "lens": None, "tier": "sonnet", "launch_ts": t0 + 30.0, "end_ts": t0 + 35.0, "has_explicit_all": True}]}
        ok_col, why_col = cwg_stop.validate_candidate_closure(receipt, marker, checks_ev, empty_sub, sw_combined_large, revs_approved, ctx=cctx)
        self.assertFalse(ok_col)
        self.assertIn("cannot collapse simplify", why_col)

        # Step E: All 3 separate lenses complete -> without --closure, blocks prompting --closure; WITH --closure READY -> CLOSES!
        sw_3lenses = {
            **empty_sw,
            "sonnet_lenses": {"reuse": t0 + 30.0, "quality": t0 + 30.0, "efficiency": t0 + 30.0},
            "sonnet_lenses_end": {"reuse": t0 + 35.0, "quality": t0 + 35.0, "efficiency": t0 + 35.0},
            "simplify_history": [
                {"kind": "lens", "lens": l, "tier": "sonnet", "launch_ts": t0 + 30.0, "end_ts": t0 + 35.0}
                for l in cwg.SIMPLIFY_LENSES
            ],
        }
        ok3, why3 = cwg_stop.validate_candidate_closure(receipt, marker, checks_ev, empty_sub, sw_3lenses, revs_approved, ctx=cctx)
        self.assertFalse(ok3)
        self.assertIn("--closure", why3)

        revs_final = revs_approved + [{"engine": "codex", "kind": "closure", "verdict": "READY", "launch_ts": t0 + 40.0, "verdict_ts": t0 + 42.0, "xhigh": False}]
        ok4, why4 = cwg_stop.validate_candidate_closure(receipt, marker, checks_ev, empty_sub, sw_3lenses, revs_final, ctx=cctx)
        self.assertTrue(ok4, msg=why4)

        # Codex Finding #3: ACTIONABLE_FIXES must NEVER close gate and must clear prior CLEAN in same round
        sdir = self._swarm_dir()
        (sdir / "members.json").write_text(
            json.dumps(
                {
                    "members": {
                        "simplify-reviewer": {
                            "conversation_id": "sw-act-fix",
                            "model": cwg.SONNET_HIGH_MODEL,
                            "role": "worker",
                            "wake_mode": "mentions",
                            "killed": False,
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        self._append_board("coordinator", "@simplify-reviewer Check fast-path diff", ts=t0 + 25.0)
        self._append_board("simplify-reviewer", "SIMPLIFY_LENS: ALL. SIMPLIFY_VERDICT: CLEAN.", ts=t0 + 26.0)
        self._append_board("coordinator", "@simplify-reviewer Re-check lines", ts=t0 + 27.0)
        self._append_board("simplify-reviewer", "SIMPLIFY_LENS: ALL. SIMPLIFY_VERDICT: ACTIONABLE_FIXES.", ts=t0 + 28.0)
        ev_act = cwg_stop.scan_swarm_activity(self.steps, str(self.transcript), t0, cwd=str(self.workspace))
        self.assertEqual(ev_act["sonnet_combined_ts"], 0.0)
        ok_act, why_act = cwg_stop.validate_candidate_closure(
            receipt,
            {
                **marker,
                "paths": [cwg.rio.normalize_path(self.workspace / "auth_a.py")],
                "diff_metrics": {"files_count": 1, "additions": 6, "deletions": 2, "total_lines": 8, "source": "explicit"},
            },
            checks_ev,
            empty_sub,
            ev_act,
            revs_final,
            ctx=cctx,
        )
        self.assertFalse(ok_act, msg=why_act)

        # Codex Round 2 Finding #3: chronological replay independent of members.json order
        for order in (
            ("simplify-a", "simplify-b"),
            ("simplify-b", "simplify-a"),
        ):
            ordered_members = {
                name: {
                    "conversation_id": f"sw-ord-{name}",
                    "model": cwg.SONNET_HIGH_MODEL,
                    "role": "worker",
                    "wake_mode": "mentions",
                    "killed": False,
                }
                for name in order
            }
            (sdir / "members.json").write_text(json.dumps({"members": ordered_members}), encoding="utf-8")
            (sdir / "board.jsonl").write_text("", encoding="utf-8")
            self._append_board("coordinator", "@simplify-b check clean", ts=t0 + 39.0)
            self._append_board("simplify-b", "SIMPLIFY_LENS: ALL. SIMPLIFY_VERDICT: CLEAN.", ts=t0 + 40.0)
            self._append_board("coordinator", "@simplify-a check fix", ts=t0 + 49.0)
            self._append_board("simplify-a", "SIMPLIFY_LENS: ALL. SIMPLIFY_VERDICT: ACTIONABLE_FIXES.", ts=t0 + 50.0)
            ev_ord = cwg_stop.scan_swarm_activity(self.steps, str(self.transcript), t0, cwd=str(self.workspace))
            self.assertEqual(ev_ord["sonnet_combined_ts"], 0.0, msg=f"Order leaked stale CLEAN: {order}")

        # Codex Finding #1 partial commit: >2 candidate durable paths prevents git partial-commit Fast-Path bypass
        marker_partial = {
            **marker,
            "paths": [
                cwg.rio.normalize_path(self.workspace / "auth_a.py"),
                cwg.rio.normalize_path(self.workspace / "auth_b.py"),
                cwg.rio.normalize_path(self.workspace / "auth_c.py"),
            ],
        }
        self.assertFalse(
            cwg.is_simplify_fast_path_eligible(
                marker=marker_partial,
                repo_root=str(self.workspace),
            )
        )

        # 2) Small HIGH diff (1 file, 5 lines): Fast-Path SIMPLIFY_LENS: ALL allowed!
        self.assertTrue(cwg.is_simplify_fast_path_eligible(diff_stats={"files_count": 1, "additions": 10, "deletions": 5}))
        self.assertFalse(cwg.is_simplify_fast_path_eligible(diff_stats={"files_count": 1, "additions": 20, "deletions": 15}))
        self.assertFalse(cwg.is_simplify_fast_path_eligible(diff_stats={"files_count": 3, "additions": 2, "deletions": 1}))

        small_marker = {
            **marker,
            "paths": [cwg.rio.normalize_path(self.workspace / "auth_a.py")],
            "diff_metrics": {"files_count": 1, "additions": 6, "deletions": 2, "total_lines": 8, "source": "explicit"},
        }
        ok_fp, why_fp = cwg_stop.validate_candidate_closure(
            receipt, small_marker, checks_ev, empty_sub, sw_combined_large, revs_final, ctx=cctx
        )
        self.assertTrue(ok_fp, msg=why_fp)

    def test_04_cursor_guard_in_safety_guards(self) -> None:
        # 16 messages (>15 threshold)
        for i in range(1, 17):
            self._append_board("scout-1", f"Finding #{i}")

        payload_no_cursor = {
            "session_id": self.conv_id,
            "cwd": str(self.workspace),
            "transcriptPath": str(self.transcript),
            "toolCall": {"name": "read_board", "args": {}},
        }
        # First read allowed and saves cursor=16
        r1 = self._run_hook("safety_guards.py", "PreToolUse", payload_no_cursor)
        self.assertEqual(r1["decision"], "allow")

        # Second read without `since` denied with hint since=16
        r2 = self._run_hook("safety_guards.py", "PreToolUse", payload_no_cursor)
        self.assertEqual(r2["decision"], "deny")
        self.assertIn("Swarm Cursor Guard", r2["reason"])
        self.assertIn("since=16", r2["reason"])

        # Passing `since=16` is allowed
        payload_with_cursor = {
            **payload_no_cursor,
            "toolCall": {"name": "read_board", "args": {"since": 16}},
        }
        r3 = self._run_hook("safety_guards.py", "PreToolUse", payload_with_cursor)
        self.assertEqual(r3["decision"], "allow")

    def test_05_stall_watchdog_in_safety_guards_and_cwg_stop(self) -> None:
        sdir = self._swarm_dir()
        stale_ts = time.time() - 35.0
        wcid = "swm-stall-1"
        (sdir / "members.json").write_text(
            json.dumps(
                {
                    "members": {
                        "scout-auth": {
                            "conversation_id": wcid,
                            "model": cwg.HYDROGEN_MODEL_BY_LEVEL["medium"],
                            "role": "worker",
                            "wake_mode": "working",
                            "killed": False,
                            "assigned_ts": stale_ts,
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        self._append_board("coordinator", "@scout-auth Inspect auth module", ts=stale_ts)

        with mock.patch.dict(os.environ, {"SWARM_STALL_TIMEOUT_SEC": "10"}):
            # safety_guards PreToolUse swarm_wait detects stall
            decision, reason = safety_guards.guard_swarm_wait(
                {
                    "session_id": self.conv_id,
                    "cwd": str(self.workspace),
                    "transcriptPath": str(self.transcript),
                }
            )
            self.assertEqual(decision, "deny")
            self.assertIn("Swarm Stall Watchdog", reason or "")
            self.assertIn("scout-auth", reason or "")

            # cwg_stop scan_swarm_activity reports stalled worker
            ev = cwg_stop.scan_swarm_activity(self.steps, str(self.transcript), stale_ts - 5.0, cwd=str(self.workspace))
            self.assertEqual(len(ev["stalled_workers"]), 1)
            self.assertEqual(ev["stalled_workers"][0]["worker"], "scout-auth")

            # Recent .swarm/artifacts/scout-auth-1.md activity clears stall!
            art = self.workspace / ".swarm" / "artifacts" / "scout-auth-1.md"
            art.parent.mkdir(parents=True, exist_ok=True)
            art.write_text("# Report\n", encoding="utf-8")
            decision2, _ = safety_guards.guard_swarm_wait(
                {
                    "session_id": self.conv_id,
                    "cwd": str(self.workspace),
                    "transcriptPath": str(self.transcript),
                }
            )
            self.assertEqual(decision2, "allow")

    def test_06_swarm_ctl_and_file_ownership_guard(self) -> None:
        self._init_git(
            {
                "src/api/routes.py": "def r(): pass\n",
                "src/api/auth.py": "def a(): pass\n",
                "src/ui/app.py": "def ui(): pass\n",
            }
        )
        # Set disjoint ownership
        rc1, d1 = self._run_ctl("ownership", "set", "--worker", "builder-api", "--paths", "src/api/**", "--cwd", str(self.workspace))
        self.assertEqual(rc1, 0, msg=d1)
        rc_dup, d_dup = self._run_ctl("ownership", "set", "--worker", "builder-ui", "--paths", "src/api/auth.py", "--cwd", str(self.workspace))
        self.assertNotEqual(rc_dup, 0)
        self.assertEqual(d_dup.get("error"), "ownership_overlap")
        rc2, d2 = self._run_ctl("ownership", "set", "--worker", "builder-ui", "--paths", "src/ui/**", "--cwd", str(self.workspace))
        self.assertEqual(rc2, 0, msg=d2)

        # File Ownership Guard via SWARM_WORKER_NAME env & transcript tag
        with mock.patch.dict(os.environ, {"SWARM_WORKER_NAME": "builder-api"}):
            allow_own = self._run_hook(
                "safety_guards.py",
                "PreToolUse",
                {
                    "session_id": "worker-sess-api",
                    "cwd": str(self.workspace),
                    "toolCall": {"name": "edit_file", "args": {"Path": str(self.workspace / "src/api/routes.py")}},
                },
            )
            self.assertEqual(allow_own["decision"], "allow")

            allow_art = self._run_hook(
                "safety_guards.py",
                "PreToolUse",
                {
                    "session_id": "worker-sess-api",
                    "cwd": str(self.workspace),
                    "toolCall": {"name": "write_file", "args": {"Path": str(self.workspace / ".swarm/artifacts/builder-api-1.md")}},
                },
            )
            self.assertEqual(allow_art["decision"], "allow")

            deny_foreign = self._run_hook(
                "safety_guards.py",
                "PreToolUse",
                {
                    "session_id": "worker-sess-api",
                    "cwd": str(self.workspace),
                    "toolCall": {"name": "edit_file", "args": {"Path": str(self.workspace / "src/ui/app.py")}},
                },
            )
            self.assertEqual(deny_foreign["decision"], "deny")
            self.assertIn("File Ownership Guard", deny_foreign["reason"])

            # Codex Finding #1: workers CANNOT overwrite .swarm/ownership.json
            deny_manifest = self._run_hook(
                "safety_guards.py",
                "PreToolUse",
                {
                    "session_id": "worker-sess-api",
                    "cwd": str(self.workspace),
                    "toolCall": {"name": "write_file", "args": {"Path": str(self.workspace / ".swarm/ownership.json")}},
                },
            )
            self.assertEqual(deny_manifest["decision"], "deny")
            self.assertIn("File Ownership Guard", deny_manifest["reason"])

            # Codex Finding #2: Copy-Item, cp, Remove-Item, cd + rm, and opaque python -c shell mutations blocked
            for bad_cmd in (
                "Copy-Item src/api/routes.py src/ui/app.py",
                "cp src/api/routes.py src/ui/app.py",
                "Remove-Item src/ui/app.py",
                "Set-Location src/ui; rm app.py",
                'python -c "open(\'src/ui/app.py\',\'w\').write(\'x\')"',
                "Set-Content .swarm/ownership.json '{}'",
                "python plugin/tools/swarm_ctl.py ownership clear",
                'python plugin/tools/swarm_ctl.py ownership "clear"',
                "python -X utf8 plugin/tools/swarm_ctl.py ownership set --worker builder-ui --paths src/**",
                'Set-Content -Path src/api/routes.py -Value "$(Remove-Item src/ui/app.py)"',
                'Set-Location "$(Remove-Item src/ui/app.py)"',
                "Set-Location (Remove-Item src/ui/app.py)",
                "cd (Remove-Item src/ui/app.py)",
                "Remove-Item src/api/routes.py,src/ui/app.py",
            ):
                deny_sh = self._run_hook(
                    "safety_guards.py",
                    "PreToolUse",
                    {
                        "session_id": "worker-sess-api",
                        "cwd": str(self.workspace),
                        "toolCall": {"name": "run_command", "args": {"CommandLine": bad_cmd}},
                    },
                )
                self.assertEqual(deny_sh["decision"], "deny", msg=f"Shell command bypassed guard: {bad_cmd}")
                self.assertIn("File Ownership Guard", deny_sh["reason"])

            # Read-only validation, quoted '>' in rg, and owned Copy-Item remain allowed
            self.assertTrue(cwg.glob_matches_path("src/[ab].py", "src/a.py"))
            for ok_cmd in (
                "Copy-Item src/api/routes.py src/api/routes_copy.py",
                'rg "a > b" src/api/',
                "python -X utf8 -m unittest discover -s tests -v",
            ):
                allow_sh = self._run_hook(
                    "safety_guards.py",
                    "PreToolUse",
                    {
                        "session_id": "worker-sess-api",
                        "cwd": str(self.workspace),
                        "toolCall": {"name": "run_command", "args": {"CommandLine": ok_cmd}},
                    },
                )
                self.assertEqual(allow_sh["decision"], "allow", msg=f"Safe worker cmd blocked: {ok_cmd}")

            # Defense-in-depth: swarm_ctl mutating commands refuse non-coordinator worker env
            rc_worker_clr, d_worker_clr = self._run_ctl("ownership", "clear", "--cwd", str(self.workspace))
            self.assertEqual(rc_worker_clr, 2)
            self.assertEqual(d_worker_clr.get("error"), "coordinator_only")

        # Coordinator is unrestricted
        allow_coord = self._run_hook(
            "safety_guards.py",
            "PreToolUse",
            {
                "session_id": self.conv_id,
                "cwd": str(self.workspace),
                "transcriptPath": str(self.transcript),
                "toolCall": {"name": "edit_file", "args": {"Path": str(self.workspace / "src/ui/app.py")}},
            },
        )
        self.assertEqual(allow_coord["decision"], "allow")

        # verify-git-diff catches out-of-scope edits by worker
        (self.workspace / "src/ui/app.py").write_text("def ui(): return 1\n", encoding="utf-8")
        rc_v_bad, d_v_bad = self._run_ctl("ownership", "verify-git-diff", "--worker", "builder-api", "--cwd", str(self.workspace))
        self.assertEqual(rc_v_bad, 2, msg=d_v_bad)
        self.assertTrue(d_v_bad["violations"])
        rc_v_ok, d_v_ok = self._run_ctl("ownership", "verify-git-diff", "--worker", "builder-ui", "--cwd", str(self.workspace))
        self.assertEqual(rc_v_ok, 0, msg=d_v_ok)

        # Worktree create / status / cleanup + board summary
        rc_wc, d_wc = self._run_ctl("worktree", "create", "--worker", "builder-api", "--cwd", str(self.workspace))
        self.assertEqual(rc_wc, 0, msg=d_wc)
        self.assertTrue(pathlib.Path(d_wc["worktree"]).is_dir())
        rc_ws, d_ws = self._run_ctl("worktree", "status", "--cwd", str(self.workspace))
        self.assertEqual(rc_ws, 0)
        self.assertEqual(d_ws["count"], 1)
        rc_wl, d_wl = self._run_ctl("worktree", "cleanup", "--worker", "builder-api", "--delete-branch", "--cwd", str(self.workspace))
        self.assertEqual(rc_wl, 0, msg=d_wl)

        # Codex Finding #5: board summary retains native members.json workers (even without local .swarm/members.json)
        sdir = self._swarm_dir()
        (sdir / "members.json").write_text(
            json.dumps(
                {
                    "members": {
                        "coordinator": {"role": "coordinator"},
                        "builder-api": {"role": "worker", "model": cwg.HYDROGEN_MODEL_BY_LEVEL["high"], "wake_mode": "waiting", "killed": False},
                    }
                }
            ),
            encoding="utf-8",
        )
        self._append_board("coordinator", "Start phase 1")
        self._append_board("builder-api", "Done API. See .swarm/artifacts/builder-api-1.md")
        rc_bs, d_bs = self._run_ctl("board", "summary", "--since", "1", "--session", self.conv_id, "--cwd", str(self.workspace))
        self.assertEqual(rc_bs, 0)
        self.assertEqual(d_bs["head_seq"], 2)
        self.assertEqual(d_bs["recent_count"], 1)
        self.assertIn("builder-api", d_bs["workers"])
        self.assertEqual(d_bs["workers"]["builder-api"]["last_seq"], 2)

        # Codex Finding #4: save_ownership_manifest write failure surfaces non-zero rc and ok=False
        import swarm_ctl

        with (
            mock.patch.object(cwg.rio, "write_json", return_value=False),
            mock.patch.object(cwg.rio, "print_cli_json") as pjson,
        ):
            ns = swarm_ctl.build_parser().parse_args(
                ["ownership", "set", "--worker", "builder-fail", "--paths", "src/other/**", "--cwd", str(self.workspace)]
            )
            rc_fail = swarm_ctl.cmd_ownership_set(ns)
        self.assertNotEqual(rc_fail, 0)
        self.assertFalse(pjson.call_args[0][0]["ok"])

        rc_clr, _ = self._run_ctl("ownership", "clear", "--cwd", str(self.workspace))
        self.assertEqual(rc_clr, 0)
        self.assertFalse(cwg.ownership_manifest_path(self.workspace).exists())

    def test_07_ephemeral_swarm_paths_and_stack_doctor(self) -> None:
        self._mark_edit(".swarm/artifacts/scout-auth-1.md", "# Findings\n")
        marker = cwg.rio.read_json(cwg.marker_path(self.conv_id), default=None)
        self.assertTrue(marker is None or cwg.candidate_class(marker) == cwg.WORK_NO_CHANGE)

        doc = stack_doctor.run_diagnostics(cwd=str(REPO_ROOT), compact=True)
        sv2 = doc.get("swarm_v2") or {}
        self.assertTrue(sv2.get("swarm_ctl"))
        self.assertTrue(sv2.get("swarm_orchestration_skill"))
        self.assertTrue(sv2.get("guards_matcher_ok"))
        self.assertTrue(sv2.get("gitignore_has_swarm"))

        import codex_lane

        self.assertEqual(codex_lane.DEFAULT_REVIEW_TIMEOUT_SECONDS, 600)
        self.assertEqual(codex_lane.DEFAULT_XHIGH_REVIEW_TIMEOUT_SECONDS, 900)

        # Latest non-CLEAN reply overrides prior CLEAN inside same Warm Pool round
        override_msgs = [
            {"seq": 2, "agent": "simplify-reuse", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."},
            {"seq": 3, "agent": "simplify-reuse", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."},
        ]
        res_ov = gate_inbox.validate_warm_worker_verdicts(override_msgs, round_start_msg_id=1)
        self.assertNotIn("reuse", res_ov["lenses"])
        self.assertFalse(res_ov["satisfied"])

        # INVARIANT: Multi-byte UTF-8 Cyrillic prose before inline tags must neither match nor panic on char boundaries.
        ru_msg = "Проверьте SIMPLIFY_VERDICT: CLEAN и `SIMPLIFY_LENS: ALL` в строке.\nSIMPLIFY_LENS: QUALITY\nSIMPLIFY_VERDICT: CLEAN"
        parsed_ru = cwg.parse_simplify_verdict(ru_msg)
        self.assertEqual(parsed_ru["lens"], "quality")
        self.assertFalse(parsed_ru["has_explicit_all"])
        self.assertTrue(parsed_ru["clean"])


if __name__ == "__main__":
    unittest.main()
