#!/usr/bin/env python3
"""Gate anomaly inbox: nonce-authenticated escape hatch and cross-chat anomaly handler routing."""

from __future__ import annotations

import argparse
import pathlib
import sys
import time
import uuid
from typing import Any, Callable

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cwg_common as cwg
import runtime_io as rio


def inbox_dir() -> pathlib.Path:
    return cwg.gate_dir("inbox")


def report_path(report_id: str) -> pathlib.Path | None:
    safe_id = rio.safe_key(report_id, "")
    return (inbox_dir() / f"{safe_id}.json") if safe_id else None


def _load_report(report_id: str) -> tuple[pathlib.Path | None, dict[str, Any] | None]:
    p = report_path(report_id)
    if p is None:
        return None, None
    rec = rio.read_json(p, default=None)
    return p, (rec if isinstance(rec, dict) else None)


def handler_config_path() -> pathlib.Path:
    return cwg.gate_dir() / "anomaly_handler.json"


def get_handler_config() -> dict[str, Any]:
    cfg = rio.read_json(handler_config_path(), default=None)
    return cfg if isinstance(cfg, dict) else {}


def get_handler_session(cfg: dict[str, Any] | None = None) -> str:
    source = cfg if cfg is not None else get_handler_config()
    raw = str(source.get("handler_session") or "").strip()
    return rio.safe_key(raw, "") if raw else ""


def set_handler_config(session: str = "", stack_repo: str = "", clear: bool = False) -> dict[str, Any]:
    cfg_path = handler_config_path()
    if clear:
        if cfg_path.exists():
            try:
                cfg_path.unlink()
            except OSError:
                rio.write_json(cfg_path, {})
        return {"ok": True, "handler_session": "", "cleared": True}

    clean_sess = rio.safe_key(session, "")
    if not clean_sess or clean_sess == "unknown":
        return {"ok": False, "error": "valid --session conversation ID is required"}

    cfg = {
        "handler_session": clean_sess,
        "stack_repo": rio.normalize_path(stack_repo) if stack_repo else "",
        "installed_plugin": rio.normalize_path(rio.plugin_root()),
        "updated_ts": time.time(),
    }
    rio.write_json(cfg_path, cfg)
    rio.log_hook_event("gate-events", "anomaly_handler_set", handler_session=clean_sess)
    return {"ok": True, **cfg}


def _load_reports(include_resolved: bool = False) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for p in inbox_dir().glob("*.json"):
        rec = rio.read_json(p, default=None)
        if isinstance(rec, dict) and (include_resolved or not rec.get("resolved")):
            items.append(rec)
    items.sort(key=lambda r: (float(r.get("created_ts") or 0.0), str(r.get("id") or "")))
    return items


def unresolved_reports() -> list[dict[str, Any]]:
    return _load_reports(include_resolved=False)


def unresolved_summary(limit: int = 5, handler_session: str | None = None) -> str:
    items = unresolved_reports()
    if not items:
        return ""
    shown = items[-limit:]
    parts = [f"{r.get('id')} ({r.get('block', '')[:60]})" for r in shown]
    handler_sess = get_handler_session() if handler_session is None else handler_session
    suffix = f" -> handler: conversation://{handler_sess}" if handler_sess else ""
    return f"[Gate Inbox] {len(items)} unresolved anomaly report(s): " + ", ".join(parts) + suffix


def format_handler_digest(limit: int = 10, cfg: dict[str, Any] | None = None) -> str:
    items = unresolved_reports()
    if not items:
        return ""
    eff_cfg = cfg if cfg is not None else get_handler_config()
    repo_hint = str(eff_cfg.get("stack_repo") or rio.normalize_path(rio.plugin_root()))
    inbox_script = rio.normalize_path(rio.plugin_root() / "hooks" / "gate_inbox.py")
    lines = [
        f"[Gate Anomaly Handler — {len(items)} unresolved report(s) awaiting root-cause fix]",
        f"Stack repo: {repo_hint}",
    ]
    for rec in items[-limit:]:
        rid = str(rec.get("id") or "")
        sess = str(rec.get("session") or "")
        blk = str(rec.get("block") or "")[:140]
        facts = str(rec.get("facts") or "")[:180]
        tp = str(rec.get("transcript") or "")
        tp_part = f" | transcript={tp}" if tp else ""
        lines.append(f"- {rid} (from session={sess}): block=\"{blk}\" | facts=\"{facts}\"{tp_part}")
    lines.append(
        f"Action: inspect `{inbox_script} show --id <id>`, fix root cause + add test in `{repo_hint}`, "
        f"run `install.py --force` + tests, then mark `{inbox_script} resolve --id <id> --note \"...\"`."
    )
    return "\n".join(lines)


def _discover_session_transcript(session: str) -> str:
    if not session or session == "unknown":
        return ""
    tp = rio.resolve_transcript_path(str(rio.member_transcript_path(rio.resolve_brain_root(), session)))
    return rio.normalize_path(tp) if tp is not None else ""


def _capture_session_forensics(session: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    mdata = rio.read_json(cwg.marker_path(session), default=None)
    if isinstance(mdata, dict):
        out["marker"] = {
            "cwd": mdata.get("cwd") or "",
            "git_root": mdata.get("git_root") or "",
            "paths": list(mdata.get("paths") or [])[:25],
            "first_ts": mdata.get("first_ts"),
            "last_durable_ts": mdata.get("last_durable_ts"),
            "edits": mdata.get("edits"),
            "operational": bool(mdata.get("operational")),
        }
    checks = rio.read_jsonl(cwg.checks_ledger_path(session), max_lines=50)
    out["checks_count"] = len(checks)
    return out


def _mutate_report(
    report_id: str, mutator: Callable[[dict[str, Any]], bool]
) -> tuple[dict[str, Any] | None, str]:
    p = report_path(report_id)
    if p is None:
        return None, "not_found"
    # SAFETY: Serialize concurrent report updates (`mark_handler_notified` vs `cmd_resolve`) to prevent lost fields.
    with rio.file_lock(p.parent / f".{p.stem}.lock", timeout=3.0) as locked:
        if not locked:
            return None, "lock_timeout"
        rec = rio.read_json(p, default=None)
        if not isinstance(rec, dict):
            return None, "not_found"
        if mutator(rec) and not rio.write_json(p, rec):
            return None, "write_failed"
        return rec, "ok"


def _set_notified(rec: dict[str, Any]) -> bool:
    if rec.get("notified_handler"):
        return False
    rec["notified_handler"] = True
    rec["notified_ts"] = time.time()
    return True


def mark_handler_notified(report_id: str) -> None:
    _mutate_report(report_id, _set_notified)


def verify_anomaly_report(report_id: str, session: str, expected_nonce: str | None) -> tuple[bool, str]:
    p, rec = _load_report(report_id)
    if p is None:
        return False, "invalid anomaly report id"
    if rec is None:
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
    transcript = (args.transcript or "").strip() or _discover_session_transcript(session)
    handler_sess = get_handler_session()
    record: dict[str, Any] = {
        "id": report_id,
        "created_ts": time.time(),
        "session": session,
        "nonce": args.nonce,
        "block": args.block.strip(),
        "facts": args.facts.strip(),
        "did": args.did.strip(),
        "transcript": transcript,
        "forensics": _capture_session_forensics(session),
        "handler_session": handler_sess,
        "notified_handler": handler_sess == session if handler_sess else False,
        "resolved": False,
    }
    rpath = report_path(report_id)
    assert rpath is not None
    rio.write_json(rpath, record)
    rio.log_hook_event(
        "gate-events",
        "anomaly_filed",
        session=session,
        report_id=report_id,
        handler_session=handler_sess,
    )

    resp: dict[str, Any] = {"ok": True, "report_id": report_id}
    if handler_sess and handler_sess != session:
        msg_payload = (
            f"[GATE_ANOMALY {report_id}] session={session}; "
            f"block={record['block'][:160]}; facts={record['facts'][:220]}; did={record['did'][:160]}"
        )
        resp["handler_session"] = handler_sess
        resp["handler_uri"] = f"conversation://{handler_sess}"
        resp["notify_required"] = True
        resp["send_message_payload"] = msg_payload
    rio.print_cli_json(resp, pretty=False)
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    rows = _load_reports(include_resolved=bool(args.all))
    rio.print_cli_json(
        {"count": len(rows), "handler_session": get_handler_session() or None, "reports": rows},
        pretty=True,
    )
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    _, rec = _load_report(args.id)
    if rec is None:
        sys.stderr.write(f"Report not found: {args.id}\n")
        return 1
    rio.print_cli_json(rec, pretty=True)
    return 0


def cmd_resolve(args: argparse.Namespace) -> int:
    resolved_by = rio.safe_key(args.by, "") if getattr(args, "by", "") else (get_handler_session() or "")
    note = args.note or "resolved"

    def _apply_resolve(rec: dict[str, Any]) -> bool:
        rec["resolved"] = True
        rec["resolved_ts"] = time.time()
        rec["resolved_by"] = resolved_by
        rec["resolution_note"] = note
        return True

    rec, status = _mutate_report(args.id, _apply_resolve)
    if rec is None:
        msg = (
            f"Report not found: {args.id}\n"
            if status == "not_found"
            else f"Failed to update report ({status}): {args.id}\n"
        )
        sys.stderr.write(msg)
        return 1
    rio.log_hook_event("gate-events", "anomaly_resolved", report_id=rec["id"], resolved_by=rec["resolved_by"])
    rio.print_cli_json({"ok": True, "id": rec["id"], "resolved_by": rec["resolved_by"]}, pretty=False)
    return 0


def cmd_set_handler(args: argparse.Namespace) -> int:
    res = set_handler_config(session=args.session, stack_repo=args.repo, clear=args.clear)
    rio.print_cli_json(res, pretty=False)
    return 0 if res.get("ok") else 2


def cmd_handler() -> int:
    cfg = get_handler_config()
    rio.print_cli_json({"configured": bool(cfg.get("handler_session")), **cfg}, pretty=True)
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

    shw = sub.add_parser("show")
    shw.add_argument("--id", required=True)

    res = sub.add_parser("resolve")
    res.add_argument("--id", required=True)
    res.add_argument("--note", default="")
    res.add_argument("--by", default="")

    shd = sub.add_parser("set-handler")
    shd.add_argument("--session", default="")
    shd.add_argument("--repo", default="")
    shd.add_argument("--clear", action="store_true")

    sub.add_parser("handler")

    args = parser.parse_args()
    if args.cmd == "report":
        return cmd_report(args)
    if args.cmd == "list":
        return cmd_list(args)
    if args.cmd == "show":
        return cmd_show(args)
    if args.cmd == "resolve":
        return cmd_resolve(args)
    if args.cmd == "set-handler":
        return cmd_set_handler(args)
    if args.cmd == "handler":
        return cmd_handler()
    return 0


if __name__ == "__main__":
    sys.exit(main())
