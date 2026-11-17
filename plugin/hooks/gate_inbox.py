#!/usr/bin/env python3
"""Gate anomaly inbox: nonce-authenticated escape hatch and cross-chat anomaly handler routing."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import pathlib
import re
import sqlite3
import sys
import time
import uuid
from typing import Any, Callable, Iterator

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cwg_common as cwg
import runtime_io as rio

SIMPLIFY_LINE_RE = cwg.SIMPLIFY_LINE_RE
SIMPLIFY_LENS_LINE_RE = cwg.SIMPLIFY_LENS_LINE_RE
SIMPLIFY_COMBINED_LENS_RE = cwg.SIMPLIFY_COMBINED_LENS_RE
parse_simplify_verdict = cwg.parse_simplify_verdict
extract_simplify_verdict = cwg.extract_simplify_verdict


def validate_warm_worker_verdicts(
    messages: list[dict[str, Any]],
    round_start_msg_id: int = 0,
    current_diff_hash: str = "",
    members: dict[str, Any] | None = None,
    fast_path: bool = False,
) -> dict[str, Any]:
    lenses: dict[str, dict[str, Any]] = {}
    combined: dict[str, Any] | None = None
    all_verdicts: list[dict[str, Any]] = []
    stale_rejected = 0
    multi_lens_spoof = False
    target_hash = (current_diff_hash or "").strip()

    for idx, raw in enumerate(messages or [], start=1):
        if not isinstance(raw, dict):
            continue
        agent = str(raw.get("agent") or raw.get("worker") or raw.get("sender") or "").strip()
        role = str(raw.get("role") or "").strip().lower()
        if not role and members and agent in members and isinstance(members[agent], dict):
            role = str(members[agent].get("role") or "").strip().lower()
        if role == "coordinator" or agent.lower() == "coordinator":
            continue

        seq = cwg._extract_msg_seq(raw, idx)
        if round_start_msg_id > 0 and seq <= round_start_msg_id:
            stale_rejected += 1
            continue

        text = str(raw.get("text") or raw.get("content") or "")
        msg_hash = str(raw.get("diff_hash") or raw.get("current_diff_hash") or "").strip() or cwg.extract_diff_hash(text)
        if target_hash and msg_hash and msg_hash != target_hash:
            stale_rejected += 1
            continue

        default_lens = ""
        low_agent = agent.lower()
        for candidate_lens in cwg.SIMPLIFY_LENSES:
            if candidate_lens in low_agent:
                default_lens = candidate_lens
                break
        parsed = parse_simplify_verdict(text, default_lens=default_lens)
        if not parsed.get("verdict"):
            continue
        entry = {
            **parsed,
            "agent": agent,
            "seq": seq,
            "diff_hash": msg_hash,
            "ts": float(raw.get("ts") or 0.0),
        }
        all_verdicts.append(entry)
        if parsed.get("multi_lens_spoof"):
            multi_lens_spoof = True
            continue
        if parsed.get("clean"):
            if parsed.get("has_explicit_all"):
                combined = entry
            elif parsed.get("lens") in cwg.SIMPLIFY_LENSES:
                lenses[str(parsed["lens"])] = entry
        else:
            if parsed.get("has_explicit_all") or not parsed.get("lens"):
                combined = None
            elif parsed.get("lens") in cwg.SIMPLIFY_LENSES:
                lenses.pop(str(parsed["lens"]), None)

    missing_lenses = [lens for lens in cwg.SIMPLIFY_LENSES if lens not in lenses]
    satisfied = (not multi_lens_spoof) and (
        (not missing_lenses) or (fast_path and combined is not None and bool(combined.get("clean")))
    )
    return {
        "lenses": lenses,
        "combined": combined,
        "all_verdicts": all_verdicts,
        "stale_rejected": stale_rejected,
        "missing_lenses": missing_lenses,
        "multi_lens_spoof": multi_lens_spoof,
        "satisfied": satisfied,
    }


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
    try:
        cfg_path = handler_config_path()
    except OSError as exc:
        return {"ok": False, "error": f"cannot access gate state directory: {exc}"}
    if clear:
        if cfg_path.exists():
            try:
                cfg_path.unlink()
            except OSError:
                if not rio.write_json(cfg_path, {}):
                    return {"ok": False, "error": f"failed to clear {cfg_path}"}
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
    if not rio.write_json(cfg_path, cfg):
        return {"ok": False, "error": f"failed to persist handler config to {cfg_path}"}
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


_BUS_SNAPSHOT_RE = re.compile(r"^snapshot-[0-9a-f]{12}-\d{12}-[0-9a-f]{8}\.db$")
_BUS_REPORT_RE = re.compile(
    r"\[[A-Z0-9_-]{4,}(?:\s+[^\]]*)?\]|GATE_ANOMALY|\banom-[0-9a-f]{6,}\b|"
    r"\bdeadlock\b|\bcwg_stop\b|\bcodex_lane\b|\bsafety_guards\b|аномал",
    re.IGNORECASE,
)
_ANOM_ID_RE = re.compile(r"\banom-[0-9a-f]{6,}\b", re.IGNORECASE)


def _readonly_chat_bus_db_path() -> pathlib.Path | None:
    bus_dir = rio.stack_home() / "state" / "chat-bus"
    if not bus_dir.is_dir():
        return None
    ptr = rio.read_json(bus_dir / "snapshot_current.json", default=None)
    if isinstance(ptr, dict):
        snap_name = str(ptr.get("file") or "").strip()
        if _BUS_SNAPSHOT_RE.match(snap_name):
            snap_path = bus_dir / snap_name
            if snap_path.is_file():
                return snap_path
    main_db = bus_dir / "bus.db"
    return main_db if main_db.is_file() else None


@contextmanager
def _ro_bus_conn() -> Iterator[sqlite3.Connection | None]:
    db_path = _readonly_chat_bus_db_path()
    if db_path is None:
        yield None
        return
    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True, timeout=1.0)
    except sqlite3.Error:
        yield None
        return
    try:
        yield conn
    finally:
        conn.close()


def unhandled_bus_reports(handler_session: str | None = None, limit: int = 10) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    hsess = rio.safe_key(handler_session, "") if handler_session is not None else get_handler_session()
    if not hsess:
        return []
    resolved_cache: dict[str, bool] = {}
    newest_first: list[dict[str, Any]] = []
    with _ro_bus_conn() as conn:
        if conn is None:
            return []
        try:
            cur = conn.execute(
                "SELECT msg_id, thread_id, from_id, from_title, body, status, created_ts "
                "FROM messages WHERE to_id = ? AND status IN ('unread', 'delivered') AND acked_ts <= 0 "
                "ORDER BY created_ts DESC, msg_id DESC",
                (hsess,),
            )
            while len(newest_first) < limit:
                batch = cur.fetchmany(64)
                if not batch:
                    break
                for msg_id, thread_id, from_id, from_title, body, status, created_ts in batch:
                    body_s = str(body or "").strip()
                    if not body_s or not _BUS_REPORT_RE.search(body_s):
                        continue
                    anom_ids = [m.lower() for m in _ANOM_ID_RE.findall(body_s)]
                    if anom_ids:
                        for aid in anom_ids:
                            if aid not in resolved_cache:
                                resolved_cache[aid] = (_load_report(aid)[1] or {}).get("resolved") is True
                        if all(resolved_cache[aid] for aid in anom_ids):
                            continue
                    newest_first.append(
                        {
                            "msg_id": str(msg_id or ""),
                            "thread_id": str(thread_id or ""),
                            "from_id": str(from_id or ""),
                            "from_title": str(from_title or ""),
                            "body": body_s,
                            "status": str(status or ""),
                            "created_ts": float(created_ts or 0.0),
                        }
                    )
                    if len(newest_first) >= limit:
                        break
        except sqlite3.Error:
            return []
    newest_first.reverse()
    return newest_first


def bus_has_anomaly_notification(
    from_session: str,
    handler_session: str,
    since_ts: float,
    report_id: str,
) -> bool:
    fsess = rio.safe_key(from_session, "")
    hsess = rio.safe_key(handler_session, "")
    rid_low = (report_id or "").strip().lower()
    if not fsess or not hsess or not rid_low:
        return False
    with _ro_bus_conn() as conn:
        if conn is None:
            return False
        try:
            row = conn.execute(
                "SELECT 1 FROM messages WHERE from_id = ? AND to_id = ? AND created_ts >= ? AND LOWER(body) LIKE ? LIMIT 1",
                (fsess, hsess, max(0.0, since_ts - 5.0), f"%{rid_low}%"),
            ).fetchone()
            return row is not None
        except sqlite3.Error:
            return False


def format_handler_digest(limit: int = 10, cfg: dict[str, Any] | None = None) -> str:
    eff_cfg = cfg if cfg is not None else get_handler_config()
    hsess = get_handler_session(eff_cfg)
    items = unresolved_reports()
    bus_items = unhandled_bus_reports(handler_session=hsess, limit=limit) if hsess else []
    if not items and not bus_items:
        return ""
    repo_hint = str(eff_cfg.get("stack_repo") or rio.normalize_path(rio.plugin_root()))
    inbox_script = rio.normalize_path(rio.plugin_root() / "hooks" / "gate_inbox.py")
    total_cnt = len(items) + len(bus_items)
    lines = [
        f"[Gate Anomaly Handler — {total_cnt} unresolved report(s)/bus message(s) awaiting root-cause fix]",
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
    for bmsg in bus_items:
        one_line = " ".join(bmsg["body"].split())[:240]
        lines.append(
            f"- [chat-bus {bmsg['msg_id']}] (from session={bmsg['from_id']} \"{bmsg['from_title'][:60]}\"): {one_line}"
        )
    lines.append(
        f"Action: inspect `{inbox_script} show --id <id>` (or chat-bus message), fix root cause + add test in `{repo_hint}`, "
        f"run `install.py --force` + tests, then mark `{inbox_script} resolve --id <id> --note \"...\"` "
        f"(and reply via `chat_bus_cli.py reply --from-chat {hsess or '<handler>'} --message-id <msg_id> --message \"...\"` for chat-bus reports)."
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
    try:
        rpath = report_path(report_id)
    except OSError as exc:
        sys.stderr.write(
            f"Failed to access gate inbox directory ({exc}); CARBON_STACK_HOME is not writable in this environment.\n"
        )
        return 1
    assert rpath is not None
    # SAFETY: Fail closed when `write_json` returns False (e.g. read-only filesystem/sandbox) instead of emitting a phantom report_id.
    if not rio.write_json(rpath, record):
        sys.stderr.write(
            f"Failed to persist anomaly report to {rpath}; CARBON_STACK_HOME is read-only or not writable in this environment.\n"
        )
        return 1
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
        bus_cli = rio.chat_bus_cli_path()
        resp["handler_session"] = handler_sess
        resp["handler_uri"] = f"conversation://{handler_sess}"
        resp["notify_required"] = True
        resp["send_message_payload"] = msg_payload
        resp["chat_bus_cli_hint"] = (
            f'python -X utf8 "{bus_cli}" send --from-chat "{session}" --to "{handler_sess}" --message "{msg_payload}"'
        )
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
