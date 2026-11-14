#!/usr/bin/env python3
"""Local secret-guarded durable engineering memory (SQLite + FTS5) with NotebookLM export compatibility."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import sqlite3
import sys
import time
from typing import Any

HOOKS_DIR = pathlib.Path(__file__).resolve().parent.parent / "hooks"
sys.path.insert(0, str(HOOKS_DIR))
import runtime_io as rio

VALID_CATEGORIES = ("GOTCHA", "RISK", "DECISION", "CONSTRAINT", "COMMAND")

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("openai_or_sk_key", re.compile(r"\bsk-(?:proj-|live-|test-)?[0-9A-Za-z_-]{20,}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{24,}\b|\bgithub_pat_[0-9A-Za-z_]{30,}\b")),
    ("gitlab_token", re.compile(r"\bglpat-[0-9A-Za-z_-]{16,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{16,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key_pem", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("bearer_jwt", re.compile(r"\bBearer\s+eyJ[0-9A-Za-z_-]{15,}\.[0-9A-Za-z_-]{15,}\.[0-9A-Za-z_-]{10,}\b")),
    ("prefixed_pat_token", re.compile(r"\b(?:hf|npm|pypi)_[0-9A-Za-z_-]{20,}\b")),
    ("uri_password", re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]{4,}@[^\s/]+", re.IGNORECASE)),
    (
        "secret_assignment",
        re.compile(
            r"(?:^|(?<![A-Za-z0-9]))[A-Za-z0-9_-]{0,32}?"
            r"(?:api[_-]?key|secret(?:[_-]?access)?[_-]?key|access[_-]?key|access[_-]?token|auth[_-]?token|"
            r"(?:hf|gh|npm|pypi|slack|discord|bot|bearer|refresh|session)[_-]?token|"
            r"password|passwd|pwd|client[_-]?secret|private[_-]?key)"
            r"[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9/+._~!$%@&*=-]{10,}[\"']?",
            re.IGNORECASE,
        ),
    ),
)


def memory_db_path() -> pathlib.Path:
    return rio.state_dir("memory") / "memory.db"


def nlm_export_dir() -> pathlib.Path:
    return rio.state_dir("memory", "nlm_export")


def detect_external_nlm_bridge() -> dict[str, Any]:
    cli = shutil.which("nlm-memory") or shutil.which("nlm-memory.cmd")
    codex_bridge = pathlib.Path.home() / ".codex" / "notebooklm-sync"
    return {
        "nlm_memory_cli": cli,
        "codex_nlm_bridge_exists": codex_bridge.exists(),
        "available": bool(cli or codex_bridge.exists()),
    }


def scan_for_secrets(text: str) -> str | None:
    for label, pat in SECRET_PATTERNS:
        if pat.search(text or ""):
            return label
    return None


def connect_db() -> sqlite3.Connection:
    db_file = memory_db_path()
    conn = sqlite3.connect(str(db_file), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS memories (
            id TEXT PRIMARY KEY,
            scope TEXT NOT NULL,
            project_key TEXT NOT NULL,
            category TEXT NOT NULL,
            content TEXT NOT NULL,
            evidence TEXT NOT NULL DEFAULT '',
            tags TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'ACTIVE',
            superseded_by TEXT NOT NULL DEFAULT '',
            created_ts REAL NOT NULL,
            updated_ts REAL NOT NULL
        );
        """
    )
    conn.execute(
        """
        CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
            id UNINDEXED,
            category,
            content,
            tags,
            evidence
        );
        """
    )
    return conn


def remember_entry(
    category: str,
    content: str,
    scope: str = "project",
    cwd: str = "",
    evidence: str = "",
    tags: str = "",
) -> dict[str, Any]:
    cat = category.strip().upper()
    if cat not in VALID_CATEGORIES:
        raise ValueError(f"Invalid category '{category}'. Must be one of: {', '.join(VALID_CATEGORIES)}")
    body = content.strip()
    if len(body) < 8:
        raise ValueError("Memory content must be at least 8 characters of concrete engineering fact.")

    secret_hit = scan_for_secrets(f"{body}\n{evidence}\n{tags}")
    if secret_hit:
        raise ValueError(f"Secret guard rejected memory entry (matched pattern: {secret_hit}). Never store credentials.")

    sc = scope.strip().lower()
    if sc not in ("project", "global"):
        raise ValueError("Scope must be 'project' or 'global'.")
    pkey = "global" if sc == "global" else rio.project_key(cwd or os.getcwd())
    now = time.time()
    entry_id = "mem-" + hashlib.sha256(f"{pkey}|{cat}|{body}".encode("utf-8")).hexdigest()[:12]

    with connect_db() as conn:
        existing = conn.execute(
            "SELECT id, status FROM memories WHERE id = ?", (entry_id,)
        ).fetchone()
        if existing:
            conn.execute(
                """
                UPDATE memories
                SET evidence = ?, tags = ?, status = 'ACTIVE', superseded_by = '', updated_ts = ?
                WHERE id = ?
                """,
                (evidence.strip(), tags.strip(), now, entry_id),
            )
            conn.execute("DELETE FROM memories_fts WHERE id = ?", (entry_id,))
        else:
            conn.execute(
                """
                INSERT INTO memories (id, scope, project_key, category, content, evidence, tags, status, superseded_by, created_ts, updated_ts)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', '', ?, ?)
                """,
                (entry_id, sc, pkey, cat, body, evidence.strip(), tags.strip(), now, now),
            )
        conn.execute(
            "INSERT INTO memories_fts (id, category, content, tags, evidence) VALUES (?, ?, ?, ?, ?)",
            (entry_id, cat, body, tags.strip(), evidence.strip()),
        )
    return {
        "ok": True,
        "id": entry_id,
        "scope": sc,
        "project_key": pkey,
        "category": cat,
        "deduplicated": bool(existing),
    }


def supersede_entry(
    old_id: str,
    new_content: str = "",
    category: str = "",
    cwd: str = "",
    evidence: str = "",
    tags: str = "",
) -> dict[str, Any]:
    now = time.time()
    with connect_db() as conn:
        row = conn.execute("SELECT * FROM memories WHERE id = ?", (old_id.strip(),)).fetchone()
        if not row:
            raise ValueError(f"Memory id '{old_id}' not found.")

    replacement_id = ""
    if new_content.strip():
        res = remember_entry(
            category=category or row["category"],
            content=new_content,
            scope=row["scope"],
            cwd=cwd or os.getcwd(),
            evidence=evidence,
            tags=tags or row["tags"],
        )
        replacement_id = res["id"]

    with connect_db() as conn:
        conn.execute(
            "UPDATE memories SET status = 'SUPERSEDED', superseded_by = ?, updated_ts = ? WHERE id = ?",
            (replacement_id or "retired", now, old_id.strip()),
        )
        conn.execute("DELETE FROM memories_fts WHERE id = ?", (old_id.strip(),))

    return {"ok": True, "superseded_id": old_id.strip(), "replacement_id": replacement_id}


def recall_entries(
    query: str = "",
    cwd: str = "",
    limit: int = 8,
    include_superseded: bool = False,
) -> list[dict[str, Any]]:
    pkey = rio.project_key(cwd or os.getcwd())
    status_clause = "" if include_superseded else "AND m.status = 'ACTIVE'"
    rows: list[sqlite3.Row] = []

    with connect_db() as conn:
        tokens = re.findall(r"[A-Za-zА-Яа-яЁё0-9_]{2,}", query or "")
        if tokens and not include_superseded:
            fts_q = " OR ".join(f'"{tok}"' for tok in tokens[:8])
            sql = f"""
                SELECT m.*
                FROM memories_fts f
                JOIN memories m ON m.id = f.id
                WHERE memories_fts MATCH ?
                  AND m.project_key IN (?, 'global')
                  {status_clause}
                ORDER BY bm25(memories_fts), m.updated_ts DESC
                LIMIT ?
            """
            rows = conn.execute(sql, (fts_q, pkey, int(limit))).fetchall()

        if not rows:
            sql_recent = f"""
                SELECT m.*
                FROM memories m
                WHERE m.project_key IN (?, 'global')
                  {status_clause}
                ORDER BY CASE WHEN m.project_key = ? THEN 0 ELSE 1 END, m.updated_ts DESC
                LIMIT ?
            """
            rows = conn.execute(sql_recent, (pkey, pkey, int(limit))).fetchall()

    return [dict(r) for r in rows]


def startup_memory_card(cwd: str, limit: int = 5) -> str:
    items = recall_entries(query="", cwd=cwd, limit=limit, include_superseded=False)
    if not items:
        return ""
    lines = ["[Project Memory] Подтверждённые инженерные факты проекта:"]
    for item in items:
        scope_tag = "global" if item["scope"] == "global" else "project"
        lines.append(f"- [{item['category']}] ({item['id']}, {scope_tag}) {item['content']}")
    return "\n".join(lines)


def export_notebooklm_bundle(cwd: str = "") -> dict[str, Any]:
    pkey = rio.project_key(cwd or os.getcwd()) if cwd else ""
    with connect_db() as conn:
        if pkey:
            rows = conn.execute(
                "SELECT * FROM memories WHERE project_key IN (?, 'global') ORDER BY status ASC, updated_ts DESC",
                (pkey,),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM memories ORDER BY project_key, status ASC, updated_ts DESC").fetchall()

    target_name = f"{pkey or 'all-projects'}.md"
    out_path = nlm_export_dir() / target_name
    active = [dict(r) for r in rows if r["status"] == "ACTIVE"]
    superseded = [dict(r) for r in rows if r["status"] != "ACTIVE"]

    md_lines = [
        f"# Gemini Carbon Engineering Memory Export ({pkey or 'all'})",
        "",
        f"- Exported UTC: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        f"- Active entries: {len(active)}",
        f"- Superseded entries: {len(superseded)}",
        "- External NotebookLM sync status: local export only (external `nlm-memory` bridge not installed; not synced remotely).",
        "",
        "## Active Engineering Facts",
        "",
    ]
    for r in active:
        md_lines.append(f"### [{r['category']}] `{r['id']}` ({r['scope']})")
        md_lines.append(r["content"])
        if r["evidence"]:
            md_lines.append(f"- Evidence: {r['evidence']}")
        if r["tags"]:
            md_lines.append(f"- Tags: {r['tags']}")
        md_lines.append("")

    if superseded:
        md_lines.extend(["## Superseded / Retired (Do Not Resurface)", ""])
        for r in superseded:
            md_lines.append(
                f"- `{r['id']}` [{r['category']}] -> `{r['superseded_by']}`: ~~{r['content']}~~"
            )
        md_lines.append("")

    out_path.write_text("\n".join(md_lines), encoding="utf-8")
    bridge = detect_external_nlm_bridge()
    return {
        "ok": True,
        "export_path": str(out_path),
        "active_count": len(active),
        "superseded_count": len(superseded),
        "external_nlm_bridge": bridge,
    }


def memory_stats(cwd: str = "") -> dict[str, Any]:
    pkey = rio.project_key(cwd or os.getcwd())
    with connect_db() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM memories").fetchone()["c"]
        active = conn.execute("SELECT COUNT(*) AS c FROM memories WHERE status = 'ACTIVE'").fetchone()["c"]
        proj_active = conn.execute(
            "SELECT COUNT(*) AS c FROM memories WHERE status = 'ACTIVE' AND project_key = ?",
            (pkey,),
        ).fetchone()["c"]
    return {
        "db_path": str(memory_db_path()),
        "project_key": pkey,
        "total_entries": total,
        "active_entries": active,
        "project_active_entries": proj_active,
        "external_nlm_bridge": detect_external_nlm_bridge(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="carbon_memory")
    sub = parser.add_subparsers(dest="cmd", required=True)

    rem = sub.add_parser("remember", help="Store a verified, secret-free engineering fact")
    rem.add_argument("--category", required=True, choices=VALID_CATEGORIES)
    rem.add_argument("--text", required=True)
    rem.add_argument("--scope", default="project", choices=("project", "global"))
    rem.add_argument("--evidence", default="")
    rem.add_argument("--tags", default="")
    rem.add_argument("--cwd", default="")

    sup = sub.add_parser("supersede", help="Retire an obsolete memory entry and optionally record its replacement")
    sup.add_argument("--id", required=True)
    sup.add_argument("--text", default="")
    sup.add_argument("--category", default="")
    sup.add_argument("--evidence", default="")
    sup.add_argument("--tags", default="")
    sup.add_argument("--cwd", default="")

    rec = sub.add_parser("recall", help="Query active project + global engineering facts")
    rec.add_argument("--query", default="")
    rec.add_argument("--limit", type=int, default=8)
    rec.add_argument("--include-superseded", action="store_true")
    rec.add_argument("--cwd", default="")

    exp = sub.add_parser("export-nlm", help="Export NotebookLM-compatible Markdown memory pack")
    exp.add_argument("--cwd", default="")

    st = sub.add_parser("stats", help="Show local memory store metrics and bridge status")
    st.add_argument("--cwd", default="")

    sub.add_parser("doctor", help="Verify SQLite FTS5 health and secret guard")

    args = parser.parse_args()
    try:
        if args.cmd == "remember":
            print(
                json.dumps(
                    remember_entry(
                        category=args.category,
                        content=args.text,
                        scope=args.scope,
                        cwd=args.cwd,
                        evidence=args.evidence,
                        tags=args.tags,
                    ),
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        if args.cmd == "supersede":
            print(
                json.dumps(
                    supersede_entry(
                        old_id=args.id,
                        new_content=args.text,
                        category=args.category,
                        cwd=args.cwd,
                        evidence=args.evidence,
                        tags=args.tags,
                    ),
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        if args.cmd == "recall":
            items = recall_entries(
                query=args.query,
                cwd=args.cwd,
                limit=args.limit,
                include_superseded=args.include_superseded,
            )
            print(json.dumps({"count": len(items), "entries": items}, ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "export-nlm":
            print(json.dumps(export_notebooklm_bundle(cwd=args.cwd), ensure_ascii=False, indent=2))
            return 0
        if args.cmd in ("stats", "doctor"):
            info = memory_stats(cwd=getattr(args, "cwd", ""))
            info["secret_guard_ok"] = scan_for_secrets("api_key=sk-live-1234567890abcdefghijklmnop") is not None
            print(json.dumps(info, ensure_ascii=False, indent=2))
            return 0
    except ValueError as ve:
        sys.stderr.write(f"[carbon_memory] {ve}\n")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
