#!/usr/bin/env python3
"""Code Work Gate shared classification, risk floors, fingerprints, claims, and receipts."""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import time
from typing import Any

import runtime_io as rio

WORK_NO_CHANGE = "NO_CHANGE"
WORK_OPERATIONAL = "OPERATIONAL"
WORK_PERSISTENT = "PERSISTENT"

RISK_LEVELS = ("LOW", "STANDARD", "HIGH", "XHIGH")
RISK_ORDER = {name: idx for idx, name in enumerate(RISK_LEVELS)}

SHELL_MUTATION_SENTINEL = "<shell-mutation>"

SMALL_EDIT_MAX_LINES = 3
SMALL_EDIT_MAX_FILES = 1

DOC_EXTENSIONS = frozenset(
    {".md", ".mdx", ".txt", ".rst", ".adoc", ".csv", ".tsv"}
)

# Agent runtime configs, hooks, rules, security/auth, schema/migrations, CI/CD, locks, build contracts
HIGH_RISK_PATTERNS = tuple(
    re.compile(pat, re.IGNORECASE)
    for pat in (
        r"(^|/)\.gemini/config/",
        r"(^|/)\.agents?/",
        r"(^|/)hooks\.json$",
        r"(^|/)plugin\.json$",
        r"(^|/)mcp_config\.json$",
        r"(^|/)hooks/[^/]+\.(py|ps1|sh|mjs|js|ts)$",
        r"(^|/)rules/[^/]+\.md$",
        r"(^|/)agents/[^/]+\.md$",
        r"(^|/)\.github/workflows/",
        r"(^|/)\.gitlab-ci\.ya?ml$",
        r"(^|/)(dockerfile|docker-compose[^/]*\.ya?ml)$",
        r"(^|/)(migrations?|alembic|prisma/migrations|db/migrate)/",
        r"(^|/)(auth|oauth|jwt|crypto|security|permissions?|rbac|acl|secrets?|vault|signing)(/|_|-|\.)",
        r"(^|/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|cargo\.lock|poetry\.lock|uv\.lock|go\.sum)$",
        r"(^|/)(pyproject\.toml|cargo\.toml|go\.mod|tsconfig\.json|webpack\.config\.|vite\.config\.)$",
        r"(^|/)install\.py$",
    )
)

CHIP_TREES_RE = re.compile(r"/\.gemini/carbon-stack/state/chips/trees/", re.IGNORECASE)

ALWAYS_EPHEMERAL_PATTERNS = tuple(
    re.compile(pat, re.IGNORECASE)
    for pat in (
        r"/\.gemini/antigravity/brain/[^/]+/scratch/",
        r"/\.gemini/antigravity/brain/[^/]+/browser_sandbox/",
        r"/\.gemini/antigravity/brain/[^/]+/\.system_generated/",
        r"/\.gemini/carbon-stack/state/",
    )
)

OS_TEMP_PATTERNS = tuple(
    re.compile(pat, re.IGNORECASE)
    for pat in (
        r"(^|/)(?:tmp|var/tmp)/",
        r"/appdata/local/temp/",
    )
)

# Terminal receipt grammar: must appear on the final non-empty line of the assistant message.
RECEIPT_LINE_RE = re.compile(
    r"^\[gate\]\s+"
    r"(?P<kind>verified|operational|no-change|pr-ready|draft-blocked|anomaly-reported)\s*:\s*"
    r"(?P<body>.+?)\s*$",
    re.IGNORECASE,
)

VERIFIED_BODY_RE = re.compile(
    r"^(?P<risk>LOW|STANDARD|HIGH|XHIGH)\s*;\s*(?P<summary>.+?)\s*$",
    re.IGNORECASE,
)

OPERATIONAL_BODY_RE = re.compile(
    r"^(?P<precheck>[^;]+?)\s*;\s*(?P<effect>.+?)\s*$",
)

ANOMALY_BODY_RE = re.compile(
    r"^(?P<report_id>[A-Za-z0-9_-]{6,32})\s*;\s*(?P<fact>.+?)\s*$",
)

# Verdict control lines inside independent review outputs
VERDICT_LINE_RE = re.compile(
    r"^\s*(?:\*{0,2})VERDICT(?:\*{0,2})\s*:\s*(?:\*{0,2})(APPROVED|REVISE|ESCALATE)(?:\*{0,2})\b",
    re.MULTILINE,
)
CLOSURE_LINE_RE = re.compile(
    r"^\s*(?:\*{0,2})CLOSURE_VALIDATION(?:\*{0,2})\s*:\s*(?:\*{0,2})(READY|BLOCKED)(?:\*{0,2})\b",
    re.MULTILINE,
)
SIMPLIFY_LINE_RE = re.compile(
    r"^\s*(?:\*{0,2})SIMPLIFY_VERDICT(?:\*{0,2})\s*:\s*(?:\*{0,2})(CLEAN|FINDINGS_REPORTED|ACTIONABLE_FIXES)(?:\*{0,2})\b",
    re.IGNORECASE | re.MULTILINE,
)
SIMPLIFY_LENS_LINE_RE = re.compile(
    r"^\s*(?:\*{0,2})SIMPLIFY_LENS(?:\*{0,2})\s*:\s*(?:\*{0,2})(REUSE|QUALITY|EFFICIENCY)(?:\*{0,2})\b",
    re.IGNORECASE | re.MULTILINE,
)
REVIEW_TIER_XHIGH_RE = re.compile(
    r"\bREVIEW_TIER\s*:\s*XHIGH\b",
    re.IGNORECASE,
)

SONNET_HIGH_MODEL = "claude-sonnet-5-5-high"
OPUS_HIGH_MODEL = "claude-opus-5-5-high"
CARBON_HIGH_MODEL = "gemini-4-carbon-high"

SIMPLIFY_LENSES = ("reuse", "quality", "efficiency")
SIMPLIFY_LENS_AGENTS = frozenset(
    {
        "simplify-reuse-reviewer",
        "simplify-quality-reviewer",
        "simplify-efficiency-reviewer",
    }
)
NATIVE_REVIEWERS = frozenset({"adversarial-reviewer", "adversarial-reviewer-xhigh"})
XHIGH_NATIVE_REVIEWER = "adversarial-reviewer-xhigh"
SIMPLIFY_REVIEWER = "simplify-reviewer"


def gate_dir(*parts: str) -> pathlib.Path:
    return rio.state_dir("gate", *parts)


def marker_path(session: str) -> pathlib.Path:
    return gate_dir("markers") / f"{session}.json"


def enforcement_state_path(session: str) -> pathlib.Path:
    return gate_dir("states") / f"{session}.json"


def checks_ledger_path(session: str) -> pathlib.Path:
    return gate_dir("checks") / f"{session}.jsonl"


def launches_ledger_path(session: str) -> pathlib.Path:
    return gate_dir("launches") / f"{session}.jsonl"


def pending_notes_path(session: str) -> pathlib.Path:
    return gate_dir("notes") / f"{session}.json"


def snapshot_path(session: str, call_id: str) -> pathlib.Path:
    return gate_dir("snapshots") / f"{session}-{rio.safe_key(call_id, 'call')}.json"


def claim_path(session: str) -> pathlib.Path:
    return gate_dir("claims") / f"{session}.json"


def is_scratch_or_ephemeral(
    path: str | None,
    artifact_dir: str | None = None,
    workspace_paths: list[str] | None = None,
    cwd: str | None = None,
) -> bool:
    norm = rio.normalize_path(path)
    if not norm:
        return True
    folded = rio.fold_path(norm)
    if artifact_dir:
        art = rio.fold_path(artifact_dir)
        if art and (folded == art or folded.startswith(art + "/")):
            return True
    # INVARIANT: Isolated chip worktrees live under `state/chips/trees/` and hold real durable repository files.
    if CHIP_TREES_RE.search(norm):
        return False
    for pat in ALWAYS_EPHEMERAL_PATTERNS:
        if pat.search(norm):
            return True

    # Files inside the active workspace or cwd are project files, even when the workspace itself lives under %TEMP% or /tmp
    roots: list[str] = []
    for wp in workspace_paths or []:
        if wp:
            roots.append(rio.fold_path(wp))
    if cwd:
        roots.append(rio.fold_path(cwd))
    for r in roots:
        if r and (folded == r or folded.startswith(r + "/")):
            return False

    for pat in OS_TEMP_PATTERNS:
        if pat.search(norm):
            return True
    return False


def path_risk_floor(path: str) -> str:
    if path == SHELL_MUTATION_SENTINEL:
        return "LOW"
    norm = rio.normalize_path(path)
    for pat in HIGH_RISK_PATTERNS:
        if pat.search(norm):
            return "HIGH"
    ext = pathlib.PurePosixPath(norm).suffix.lower()
    base = pathlib.PurePosixPath(norm).name.lower()
    if ext in DOC_EXTENSIONS and not base.startswith(("agents.", "gemini.", "claude.")):
        return "LOW"
    return "STANDARD"


def max_risk(levels: list[str] | tuple[str, ...]) -> str:
    best = "LOW"
    for lv in levels:
        up = (lv or "LOW").upper()
        if RISK_ORDER.get(up, 0) > RISK_ORDER.get(best, 0):
            best = up
    return best


def durable_paths(paths: list[str] | None) -> list[str]:
    if not paths:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for p in paths:
        if not p or p == SHELL_MUTATION_SENTINEL:
            continue
        key = rio.fold_path(p)
        if key not in seen:
            seen.add(key)
            out.append(rio.normalize_path(p))
    return out


def candidate_class(marker: dict[str, Any] | None) -> str:
    if not marker or marker.get("closed"):
        return WORK_NO_CHANGE
    if durable_paths(marker.get("paths")):
        return WORK_PERSISTENT
    if marker.get("operational"):
        return WORK_OPERATIONAL
    return WORK_NO_CHANGE


def candidate_floor(marker: dict[str, Any] | None) -> str:
    dpaths = durable_paths((marker or {}).get("paths"))
    if not dpaths:
        return "LOW"
    floors = [path_risk_floor(p) for p in dpaths]
    if (marker or {}).get("unattributed_floor"):
        floors.append(str(marker["unattributed_floor"]))
    return max_risk(floors)


def is_small_edit(marker: dict[str, Any] | None) -> bool:
    if not marker:
        return False
    dpaths = durable_paths(marker.get("paths"))
    if len(dpaths) != SMALL_EDIT_MAX_FILES:
        return False
    if candidate_floor(marker) != "STANDARD":
        return False
    if marker.get("shell_durable_edit"):
        return False
    changed_lines = int(marker.get("changed_lines") or 0)
    return 0 < changed_lines <= SMALL_EDIT_MAX_LINES


def content_fingerprint(paths: list[str], max_file_bytes: int = 4_000_000) -> str | None:
    """Deterministic SHA-256 over normalized durable candidate paths and their exact on-disk bytes."""
    dpaths = sorted(durable_paths(paths), key=rio.fold_path)
    if not dpaths:
        return "empty"
    hasher = hashlib.sha256()
    for p in dpaths:
        key = rio.fold_path(p)
        hasher.update(key.encode("utf-8", errors="replace") + b"\0")
        if not os.path.exists(p):
            hasher.update(b"MISSING\0")
            continue
        if not os.path.isfile(p):
            hasher.update(b"NONFILE\0")
            continue
        try:
            st = os.stat(p)
            if st.st_size > max_file_bytes:
                return None
            with open(p, "rb") as fh:
                blob = fh.read()
            blob_hash = hashlib.sha256(blob).hexdigest()
            hasher.update(f"BLOB:{len(blob)}:{blob_hash}\0".encode("ascii"))
        except OSError:
            return None
    return hasher.hexdigest()


def parse_terminal_receipt(message: str | None) -> dict[str, Any] | None:
    """Parse `[gate] <kind>: ...` strictly from the last non-empty line of the assistant message."""
    if not message or not message.strip():
        return None
    non_empty = [ln.strip() for ln in message.splitlines() if ln.strip()]
    if not non_empty:
        return None
    last_line = non_empty[-1]
    m = RECEIPT_LINE_RE.match(last_line)
    if not m:
        # Detect misplaced receipt earlier in message for actionable diagnostic
        for earlier in non_empty[:-1]:
            if RECEIPT_LINE_RE.match(earlier):
                return {"kind": "misplaced", "raw": earlier}
        return None
    kind = m.group("kind").lower()
    body = m.group("body").strip()
    result: dict[str, Any] = {"kind": kind, "body": body, "raw": last_line, "risk": None}

    if kind == "verified":
        vm = VERIFIED_BODY_RE.match(body)
        if not vm:
            return {"kind": "malformed", "expected": "verified: <LOW|STANDARD|HIGH|XHIGH>; <candidate and checks>", "raw": last_line}
        result["risk"] = vm.group("risk").upper()
        result["summary"] = vm.group("summary").strip()
    elif kind == "operational":
        om = OPERATIONAL_BODY_RE.match(body)
        if not om:
            return {"kind": "malformed", "expected": "operational: <pre-check>; <verified effect>", "raw": last_line}
        result["precheck"] = om.group("precheck").strip()
        result["effect"] = om.group("effect").strip()
    elif kind == "anomaly-reported":
        am = ANOMALY_BODY_RE.match(body)
        if not am:
            return {"kind": "malformed", "expected": "anomaly-reported: <report-id>; <verified transcript fact>", "raw": last_line}
        result["report_id"] = am.group("report_id")
        result["fact"] = am.group("fact").strip()
    return result


def queue_pending_note(session: str, note: str) -> None:
    if not note:
        return
    p = pending_notes_path(session)
    existing = rio.read_json(p, default={"notes": []})
    notes = list(existing.get("notes") or []) if isinstance(existing, dict) else []
    if note not in notes:
        notes.append(note)
    rio.write_json(p, {"notes": notes[-6:], "updated_ts": time.time()})


def pop_pending_notes(session: str) -> list[str]:
    p = pending_notes_path(session)
    data = rio.read_json(p, default=None)
    if not isinstance(data, dict) or not data.get("notes"):
        return []
    try:
        p.unlink()
    except OSError:
        rio.write_json(p, {"notes": []})
    return [str(x) for x in data.get("notes") or [] if x]


def publish_claim(session: str, paths: list[str] | None = None, shell_active: bool = False, cwd: str = "") -> None:
    now = time.time()
    p = claim_path(session)
    cur = rio.read_json(p, default={})
    if not isinstance(cur, dict):
        cur = {}
    claimed = set(cur.get("paths") or [])
    for item in paths or []:
        if item and item != SHELL_MUTATION_SENTINEL:
            claimed.add(rio.fold_path(item))
    cur.update(
        {
            "session": session,
            "paths": sorted(claimed)[-200:],
            "shell_active": bool(shell_active),
            "cwd": rio.normalize_path(cwd),
            "updated_ts": now,
        }
    )
    rio.write_json(p, cur)


def clear_claim(session: str) -> None:
    p = claim_path(session)
    try:
        if p.exists():
            p.unlink()
    except OSError:
        pass


def claimed_by_other_sessions(my_session: str, paths: list[str], ttl: float = 600.0) -> set[str]:
    claims_dir = gate_dir("claims")
    now = time.time()
    others: set[str] = set()
    wanted = {rio.fold_path(p) for p in paths}
    for entry in claims_dir.glob("*.json"):
        data = rio.read_json(entry, default=None)
        if not isinstance(data, dict):
            continue
        if now - float(data.get("updated_ts") or 0.0) > ttl:
            try:
                entry.unlink()
            except OSError:
                pass
            continue
        if data.get("session") == my_session:
            continue
        for cp in data.get("paths") or []:
            if cp in wanted:
                others.add(cp)
    return others


def candidate_key(marker: dict[str, Any]) -> str:
    marks = marker.get("content_marks") or []
    latest_fp = marks[-1].get("fp") if marks and isinstance(marks[-1], dict) else "none"
    dpaths = ",".join(sorted(rio.fold_path(p) for p in durable_paths(marker.get("paths"))))
    first_ts = marker.get("first_ts") or 0
    op = bool(marker.get("operational"))
    return hashlib.sha256(f"{first_ts}|{op}|{dpaths}|{latest_fp}".encode("utf-8")).hexdigest()[:20]


def receipt_requirements_summary(floor: str, small: bool) -> str:
    if floor == "LOW":
        return "honest content/render check (no simplify lenses or adversarial review required)"
    if floor == "STANDARD":
        if small:
            return "decisive check execution (small edit <=3 lines: simplify lenses exempt)"
        return (
            f"decisive test/check execution + 3 simplify lenses (reuse, quality, efficiency on `{SONNET_HIGH_MODEL}`)"
        )
    if floor == "HIGH":
        return (
            f"decisive test/check execution + 3 simplify lenses (`{SONNET_HIGH_MODEL}`) + "
            f"1 independent APPROVED review (Codex lane or internal `{OPUS_HIGH_MODEL}` -> fallback `{CARBON_HIGH_MODEL}`)"
        )
    return (
        f"decisive test/check execution + 3 simplify lenses (`{SONNET_HIGH_MODEL}`) + "
        f"1 XHIGH APPROVED review (Codex --xhigh or internal `{OPUS_HIGH_MODEL}` [XHIGH] -> fallback `{CARBON_HIGH_MODEL}`)"
    )
