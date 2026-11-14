#!/usr/bin/env python3
"""Gate anomaly inbox: nonce-authenticated escape hatch when a hook block contradicts verified facts."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time
import uuid
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cwg_common as cwg
import runtime_io as rio


def inbox_dir() -> pathlib.Path:
    return cwg.gate_dir("inbox")


def unresolved_summary(limit: int = 5) -> str:
    items: list[dict[str, Any]] = []
    for p in sorted(inbox_dir().glob("*.json")):
        rec = rio.read_json(p, default=None)
        if isinstance(rec, dict) and not rec.get("resolved"):
            items.append(rec)
    if not items:
        return ""
    shown = items[-limit:]
    parts = [f"{r.get('id')} ({r.get('block', '')[:60]})" for r in shown]
    return f"[Gate Inbox] {len(items)} unresolved anomaly report(s): " + ", ".join(parts)


def verify_anomaly_report(report_id: str, session: str, expected_nonce: str | None) -> tuple[bool, str]:
    safe_id = rio.safe_key(report_id, "")
    if not safe_id:
        return False, "invalid anomaly report id"
    p = inbox_dir() / f"{safe_id}.json"
    rec = rio.read_json(p, default=None)
    if not isinstance(rec, dict):
        return False, f"anomaly report '{report_id}' does not exist in gate inbox"
    if rec.get("session") and rio.safe_key(str(rec["session"])) != session:
        return False, f"anomaly report '{report_id}' belongs to a different session"
    if expected_nonce and rec.get("nonce") != expected_nonce:
        return False, f"anomaly report '{report_id}' nonce does not match the latest gate block nonce"
    if not str(rec.get("facts") or "").strip():
        return False, f"anomaly report '{report_id}' lacks verified transcript facts"
    return True, str(rec["id"])


def cmd_report(args: argparse.Namespace) -> int:
    session = rio.safe_key(args.session, "unknown")
    st = rio.read_json(cwg.enforcement_state_path(session), default={}) or {}
    active_nonce = st.get("block_nonce")
    if active_nonce and args.nonce != active_nonce:
        sys.stderr.write(
            f"Nonce mismatch: expected active block nonce '{active_nonce}', got '{args.nonce}'. "
            "An anomaly report may only be filed after at least 1 Stop block on the current candidate.\n"
        )
        return 2
    if not active_nonce:
        sys.stderr.write("Cannot file anomaly report before the gate has issued a block nonce.\n")
        return 2

    report_id = f"anom-{uuid.uuid4().hex[:8]}"
    record = {
        "id": report_id,
        "created_ts": time.time(),
        "session": session,
        "nonce": args.nonce,
        "block": args.block.strip(),
        "facts": args.facts.strip(),
        "did": args.did.strip(),
        "transcript": args.transcript or "",
        "resolved": False,
    }
    rio.write_json(inbox_dir() / f"{report_id}.json", record)
    rio.log_hook_event("gate-events", "anomaly_filed", session=session, report_id=report_id)
    print(json.dumps({"ok": True, "report_id": report_id}, ensure_ascii=False))
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    rows = []
    for p in sorted(inbox_dir().glob("*.json")):
        rec = rio.read_json(p, default=None)
        if isinstance(rec, dict) and (args.all or not rec.get("resolved")):
            rows.append(rec)
    print(json.dumps({"count": len(rows), "reports": rows}, ensure_ascii=False, indent=2))
    return 0


def cmd_resolve(args: argparse.Namespace) -> int:
    p = inbox_dir() / f"{rio.safe_key(args.id)}.json"
    rec = rio.read_json(p, default=None)
    if not isinstance(rec, dict):
        sys.stderr.write(f"Report not found: {args.id}\n")
        return 1
    rec["resolved"] = True
    rec["resolved_ts"] = time.time()
    rec["resolution_note"] = args.note or "resolved"
    rio.write_json(p, rec)
    print(json.dumps({"ok": True, "id": rec["id"]}))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="gate_inbox")
    sub = parser.add_subparsers(dest="cmd", required=True)

    rep = sub.add_parser("report")
    rep.add_argument("--session", required=True)
    rep.add_argument("--nonce", required=True)
    rep.add_argument("--block", required=True)
    rep.add_argument("--facts", required=True)
    rep.add_argument("--did", required=True)
    rep.add_argument("--transcript", default="")

    lst = sub.add_parser("list")
    lst.add_argument("--all", action="store_true")

    res = sub.add_parser("resolve")
    res.add_argument("--id", required=True)
    res.add_argument("--note", default="")

    args = parser.parse_args()
    if args.cmd == "report":
        return cmd_report(args)
    if args.cmd == "list":
        return cmd_list(args)
    if args.cmd == "resolve":
        return cmd_resolve(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
