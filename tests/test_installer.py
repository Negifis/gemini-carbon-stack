#!/usr/bin/env python3
"""Tests for `install.py`: dry-run, foreign conflict protection, idempotent re-install, diagnose, and rollback."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
INSTALL_SCRIPT = REPO_ROOT / "install.py"


class InstallerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="carbon-installer-test-")
        self.root = pathlib.Path(self.tmp.name)
        self.cfg_dir = self.root / "gemini-config"
        self.stack_home = self.root / "carbon-stack"
        self.cfg_dir.mkdir(parents=True)
        # Simulate pre-existing Antigravity config.json that MUST NEVER be modified
        self.user_cfg = self.cfg_dir / "config.json"
        self.user_cfg.write_text('{"userSettings": {"theme": "dark"}}\n', encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_installer(self, *args: str) -> tuple[int, dict]:
        proc = subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                str(INSTALL_SCRIPT),
                "--target-config-dir",
                str(self.cfg_dir),
                "--stack-home",
                str(self.stack_home),
                *args,
            ],
            capture_output=True,
            text=True,
            timeout=25,
        )
        return proc.returncode, json.loads(proc.stdout)

    def test_01_dry_run_writes_nothing(self) -> None:
        rc, out = self.run_installer("--dry-run")
        self.assertEqual(rc, 0)
        self.assertTrue(out["dry_run"])
        self.assertFalse((self.cfg_dir / "plugins" / "gemini-carbon-stack").exists())

    def test_02_foreign_file_conflict_protected(self) -> None:
        foreign = self.cfg_dir / "rules" / "uiux-design.md"
        foreign.parent.mkdir(parents=True, exist_ok=True)
        foreign.write_text("# User Custom Unrelated Frontend Rule\n", encoding="utf-8")

        rc, out = self.run_installer()
        self.assertNotEqual(rc, 0)
        self.assertEqual(out["stage"], "conflict_check")
        self.assertIn("User Custom Unrelated Frontend Rule", foreign.read_text(encoding="utf-8"))

    def test_03_install_idempotency_diagnose_and_rollback(self) -> None:
        before_user_cfg = self.user_cfg.read_text(encoding="utf-8")

        # 1. Fresh install
        rc1, out1 = self.run_installer()
        self.assertEqual(rc1, 0, msg=str(out1))
        self.assertFalse(out1["already_up_to_date"])
        self.assertTrue((self.cfg_dir / "plugins" / "gemini-carbon-stack" / "plugin.json").is_file())
        self.assertTrue((self.cfg_dir / "rules" / "uiux-design.md").is_file())

        # 2. Idempotent second install -> already_up_to_date=True, zero duplicate hooks/backups
        rc2, out2 = self.run_installer()
        self.assertEqual(rc2, 0)
        self.assertTrue(out2["already_up_to_date"])
        self.assertIsNone(out2["backup_id"])

        # 3. Diagnose passes
        rc_diag, diag = self.run_installer("--diagnose")
        self.assertEqual(rc_diag, 0)
        self.assertTrue(diag["in_sync_with_source"])

        # 4. User's config.json remained 100% untouched byte-for-byte
        self.assertEqual(self.user_cfg.read_text(encoding="utf-8"), before_user_cfg)

        # 5. Rollback restores clean pre-install state (removes newly created plugin_dir and glob_rule)
        rc_rb, rb = self.run_installer("--rollback", "latest")
        self.assertEqual(rc_rb, 0)
        self.assertFalse(rb["plugin_dir_exists_now"])
        self.assertFalse(rb["glob_rule_exists_now"])
        self.assertEqual(self.user_cfg.read_text(encoding="utf-8"), before_user_cfg)


if __name__ == "__main__":
    unittest.main()
