#!/usr/bin/env python3
"""Unit and integration tests for `plugin/tools/claude_chat_importer.py`."""

from __future__ import annotations

import json
import os
import pathlib
import sqlite3
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "plugin" / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import claude_chat_importer as cci


def _write_jsonl(path: pathlib.Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


class ClaudeChatImporterTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="carbon-claude-import-test-")
        self.root = pathlib.Path(self.tmp.name)
        self.claude_dir = self.root / "claude_projects"
        self.agy_dir = self.root / "antigravity"
        self.claude_dir.mkdir(parents=True)
        self.agy_dir.mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _populate_fixture_sessions(self) -> None:
        proj_main = self.claude_dir / "C--Users-developer"
        proj_bench = self.claude_dir / "D--SkyrimAI-bench"

        # INVARIANT: Continuation chains sharing custom-title merge chronologically into the latest UUID.
        _write_jsonl(
            proj_main / "11111111-1111-4111-8111-111111111111.jsonl",
            [
                {"type": "custom-title", "customTitle": "Mikrotik WireGuard Setup"},
                {
                    "type": "user",
                    "uuid": "u-1",
                    "cwd": r"C:\Users\developer",
                    "timestamp": "2026-03-01T10:00:00.100Z",
                    "message": {"content": "Настрой Mikrotik WireGuard туннель"},
                },
                {
                    "type": "assistant",
                    "timestamp": "2026-03-01T10:00:05.200Z",
                    "message": {
                        "content": [
                            {"type": "thinking", "thinking": "Проверим интерфейсы RouterOS"},
                            {"type": "text", "text": "Создадим интерфейс wg0 на Mikrotik."},
                            {
                                "type": "tool_use",
                                "id": "tool-1",
                                "name": "Bash",
                                "input": {"command": "ssh admin@192.168.88.1 /interface/wireguard/print"},
                            },
                        ]
                    },
                },
                {
                    "type": "user",
                    "uuid": "u-tool-res",
                    "timestamp": "2026-03-01T10:00:06.000Z",
                    "message": {
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": "tool-1",
                                "content": "0 R name=wg0 listen-port=13231",
                            }
                        ]
                    },
                },
            ],
        )

        _write_jsonl(
            proj_main / "22222222-2222-4222-8222-222222222222.jsonl",
            [
                {"type": "custom-title", "customTitle": "Mikrotik WireGuard Setup"},
                {
                    "type": "user",
                    "uuid": "u-bridge",
                    "cwd": r"C:\Users\developer",
                    "timestamp": "2026-03-02T10:00:00.000Z",
                    "message": {
                        "content": "This session is being continued from a previous conversation that ran out of context."
                    },
                },
                {
                    "type": "user",
                    "uuid": "u-2",
                    "cwd": r"C:\Users\developer",
                    "timestamp": "2026-03-02T10:01:00.000Z",
                    "message": {"content": "Добавь маршрут для подсети 10.10.0.0/24"},
                },
                {
                    "type": "assistant",
                    "timestamp": "2026-03-02T10:01:04.000Z",
                    "message": {"content": "Маршрут для 10.10.0.0/24 добавлен через wg0."},
                },
            ],
        )

        # INVARIANT: Sessions exceeding CHECKPOINT_TURN_THRESHOLD insert a CHECKPOINT step (step_type=23).
        long_records: list[dict] = [{"type": "ai-title", "aiTitle": "Skyrim AI Deep Refactor"}]
        for idx in range(18):
            long_records.append(
                {
                    "type": "user",
                    "uuid": f"long-u-{idx}",
                    "cwd": r"D:\SkyrimAI",
                    "timestamp": f"2026-03-03T12:{idx:02d}:00.000Z",
                    "message": {"content": f"Шаг рефакторинга Skyrim номер {idx + 1}"},
                }
            )
            long_records.append(
                {
                    "type": "assistant",
                    "timestamp": f"2026-03-03T12:{idx:02d}:10.000Z",
                    "message": {"content": f"Выполнен шаг {idx + 1} для модуля Skyrim."},
                }
            )
        _write_jsonl(proj_main / "33333333-3333-4333-8333-333333333333.jsonl", long_records)

        # SAFETY: Filtered noise sessions (ping, untitled roleplay shim, zero-assistant, and -bench project)
        _write_jsonl(
            proj_main / "44444444-4444-4444-8444-444444444444.jsonl",
            [
                {
                    "type": "user",
                    "uuid": "ping-1",
                    "timestamp": "2026-03-04T09:00:00Z",
                    "message": {"content": "Say exactly: PONG"},
                },
                {
                    "type": "assistant",
                    "timestamp": "2026-03-04T09:00:01Z",
                    "message": {"content": "PONG"},
                },
            ],
        )
        _write_jsonl(
            proj_main / "55555555-5555-4555-8555-555555555555.jsonl",
            [
                {
                    "type": "user",
                    "uuid": "shim-1",
                    "timestamp": "2026-03-04T09:05:00Z",
                    "message": {"content": "<<SYSTEM>>\nТы — стражник Вайтрана."},
                },
                {
                    "type": "assistant",
                    "timestamp": "2026-03-04T09:05:01Z",
                    "message": {"content": "Когда-то и меня вела дорога приключений."},
                },
            ],
        )
        _write_jsonl(
            proj_main / "66666666-6666-4666-8666-666666666666.jsonl",
            [
                {
                    "type": "user",
                    "uuid": "empty-1",
                    "timestamp": "2026-03-04T09:10:00Z",
                    "message": {"content": "Без ответа"},
                }
            ],
        )
        _write_jsonl(
            proj_bench / "77777777-7777-4777-8777-777777777777.jsonl",
            [
                {
                    "type": "user",
                    "uuid": "bench-1",
                    "timestamp": "2026-03-04T09:15:00Z",
                    "message": {"content": "Benchmark run"},
                },
                {
                    "type": "assistant",
                    "timestamp": "2026-03-04T09:15:01Z",
                    "message": {"content": "Benchmark result"},
                },
            ],
        )

    def test_01_filtering_and_continuation_chain_merge(self) -> None:
        self._populate_fixture_sessions()
        dry = cci.run_import(
            claude_projects_dir=str(self.claude_dir),
            antigravity_dir=str(self.agy_dir),
            dry_run=True,
        )
        self.assertTrue(dry["ok"])
        self.assertTrue(dry["dry_run"])
        self.assertEqual(dry["sessions_count"], 3)
        by_id = {s["conversation_id"]: s for s in dry["sessions"]}
        self.assertIn("11111111-1111-4111-8111-111111111111", by_id)
        self.assertIn("22222222-2222-4222-8222-222222222222", by_id)
        self.assertIn("33333333-3333-4333-8333-333333333333", by_id)
        # INVARIANT: Latest part in chain keeps clean title and merged 2 turns (synthetic continuation bridge skipped).
        self.assertEqual(by_id["22222222-2222-4222-8222-222222222222"]["title"], "Mikrotik WireGuard Setup")
        self.assertEqual(by_id["22222222-2222-4222-8222-222222222222"]["turns"], 2)
        self.assertIn("ч. 1/2", by_id["11111111-1111-4111-8111-111111111111"]["title"])

    def test_02_full_import_all_five_layers_and_verify(self) -> None:
        self._populate_fixture_sessions()

        # SAFETY: Seed a pre-existing native summary and pb entry to verify non-destructive preservation.
        native_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        native_raw = cci.encode_cascade_summary(
            title="Native Session",
            step_count=2,
            last_mod_sec=1700000000,
            last_mod_nanos=0,
            trajectory_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            created_sec=1700000000,
            created_nanos=0,
            last_user_sec=1700000000,
            last_user_nanos=0,
            last_user_step_idx=0,
            traj_meta_bytes=cci.encode_trajectory_metadata(native_id, 1700000000, 0, "init-native"),
        )
        cci.update_agyhub_summaries_pb({native_id: native_raw}, antigravity_dir=str(self.agy_dir))

        res = cci.run_import(
            claude_projects_dir=str(self.claude_dir),
            antigravity_dir=str(self.agy_dir),
            dry_run=False,
            create_backup=True,
        )
        self.assertTrue(res["ok"])
        self.assertEqual(res["sessions_count"], 3)
        self.assertEqual(res["with_checkpoint"], 1)
        self.assertTrue(os.path.isfile(os.path.join(res["backup_dir"], "agyhub_summaries_proto.pb")))

        ver = cci.verify_import(
            claude_projects_dir=str(self.claude_dir),
            antigravity_dir=str(self.agy_dir),
        )
        self.assertTrue(ver["ok"], msg=str(ver["errors"]))
        self.assertEqual(ver["sessions_verified"], 3)
        self.assertEqual(ver["with_checkpoint"], 1)
        self.assertEqual(ver["pb_total_entries"], 4)

        sum_db = self.agy_dir / "conversation_summaries.db"
        conn = sqlite3.connect(sum_db)
        try:
            mikrotik_hits = conn.execute(
                "SELECT count(distinct conversation_id) FROM conversations_fts WHERE conversations_fts MATCH 'Mikrotik'"
            ).fetchone()[0]
            skyrim_hits = conn.execute(
                "SELECT count(distinct conversation_id) FROM conversations_fts WHERE conversations_fts MATCH 'Skyrim'"
            ).fetchone()[0]
            self.assertEqual(mikrotik_hits, 2)
            self.assertEqual(skyrim_hits, 1)
        finally:
            conn.close()

    def test_03_sync_pb_only_and_native_db_overwrite_guard(self) -> None:
        self._populate_fixture_sessions()
        cci.run_import(
            claude_projects_dir=str(self.claude_dir),
            antigravity_dir=str(self.agy_dir),
        )

        # WORKAROUND: Simulate running language_server.exe overwriting agyhub_summaries_proto.pb with a single native entry.
        (self.agy_dir / "agyhub_summaries_proto.pb").unlink()
        cci.update_agyhub_summaries_pb(
            {"native-only": b"\x0a\x04test"},
            antigravity_dir=str(self.agy_dir),
        )
        ver = cci.verify_import(
            claude_projects_dir=str(self.claude_dir),
            antigravity_dir=str(self.agy_dir),
        )
        self.assertTrue(ver["ok"], msg=str(ver["errors"]))
        self.assertEqual(ver["resynced_pb"], 3)

        # SAFETY: Verify native conversation DB with foreign trajectory_id is protected against overwrite.
        foreign_cid = "99999999-9999-4999-8999-999999999999"
        cci.write_conversation_db(
            antigravity_dir=str(self.agy_dir),
            conv_id=foreign_cid,
            trajectory_id="foreign-native-trajectory-id",
            traj_meta_bytes=b"\x12\x04main",
            db_steps=[],
            last_mod_epoch=1700000000.0,
        )
        with self.assertRaises(RuntimeError):
            cci.write_conversation_db(
                antigravity_dir=str(self.agy_dir),
                conv_id=foreign_cid,
                trajectory_id="different-import-trajectory-id",
                traj_meta_bytes=b"\x12\x04main",
                db_steps=[],
                last_mod_epoch=1700000000.0,
            )

        # SAFETY: Simulate user continuing an imported chat in Antigravity (updating trajectory_id) and re-running import.
        cont_db = self.agy_dir / "conversations" / "22222222-2222-4222-8222-222222222222.db"
        conn = sqlite3.connect(cont_db)
        try:
            conn.execute("UPDATE trajectory_meta SET trajectory_id = 'live-continued-trajectory-id'")
            conn.commit()
        finally:
            conn.close()
        rerun = cci.run_import(
            claude_projects_dir=str(self.claude_dir),
            antigravity_dir=str(self.agy_dir),
            create_backup=False,
        )
        self.assertTrue(rerun["ok"])
        self.assertEqual(rerun["preserved_active"], 1)


if __name__ == "__main__":
    unittest.main()
