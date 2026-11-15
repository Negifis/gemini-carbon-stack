#!/usr/bin/env python3
"""Code Work Gate shared classification, risk floors, fingerprints, claims, and receipts."""

from __future__ import annotations

import fnmatch
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
        r"(?:^|/|_|-)(?:auth|oauth\d*|jwt|crypto|security|permissions?|rbac|acl|secrets?|vault|signing)(?:/|_|-|\.|$)",
        r"(^|/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|cargo\.lock|poetry\.lock|uv\.lock|go\.sum)$",
        r"(^|/)(pyproject\.toml|cargo\.toml|go\.mod|tsconfig\.json|webpack\.config\.|vite\.config\.)$",
        r"(^|/)install\.py$",
    )
)

CHIP_TREES_RE = re.compile(r"/\.gemini/carbon-stack/state/chips/trees/", re.IGNORECASE)
SYSTEM_GENERATED_RE = re.compile(r"/\.system_generated(?:/|$)", re.IGNORECASE)

USER_SCRATCH_PATTERNS = tuple(
    re.compile(pat, re.IGNORECASE)
    for pat in (
        r"/\.gemini/antigravity/brain/[^/]+/scratch(?:/|$)",
        r"/\.gemini/antigravity/brain/[^/]+/browser_sandbox(?:/|$)",
    )
)

ALWAYS_EPHEMERAL_PATTERNS = USER_SCRATCH_PATTERNS + tuple(
    re.compile(pat, re.IGNORECASE)
    for pat in (
        r"/\.gemini/antigravity/brain/[^/]+/\.system_generated(?:/|$)",
        r"/\.gemini/carbon-stack/state(?:/|$)",
    )
)

OS_TEMP_PATTERNS = tuple(
    re.compile(pat, re.IGNORECASE)
    for pat in (
        r"(^|/)(?:tmp|var/tmp)(?:/|$)",
        r"/appdata/local/temp(?:/|$)",
    )
)

# Terminal receipt grammar: must appear on the final non-empty line of the assistant message.
RECEIPT_LINE_RE = re.compile(
    r"^\[gate\]\s+"
    r"(?P<kind>verified|operational|no-change|pr-ready|draft-blocked|anomaly-reported)\s*:\s*"
    r"(?P<body>\S.*)$",
    re.IGNORECASE,
)

VERIFIED_BODY_RE = re.compile(
    r"^(?P<risk>LOW|STANDARD|HIGH|XHIGH)\s*;\s*(?P<summary>\S.*)$",
    re.IGNORECASE,
)

OPERATIONAL_BODY_RE = re.compile(
    r"^(?P<precheck>[^;]*\S[^;]*);\s*(?P<effect>\S.*)$",
)

ANOMALY_BODY_RE = re.compile(
    r"^(?P<report_id>[A-Za-z0-9_-]{6,32})\s*;\s*(?P<fact>\S.*)$",
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
SIMPLIFY_COMBINED_LENS_RE = re.compile(
    r"^\s*(?:\*{0,2})SIMPLIFY_LENS(?:\*{0,2})\s*:\s*(?:\*{0,2})(ALL|COMBINED)(?:\*{0,2})\b",
    re.IGNORECASE | re.MULTILINE,
)
REVIEW_TIER_XHIGH_RE = re.compile(
    r"\bREVIEW_TIER\s*:\s*XHIGH\b",
    re.IGNORECASE,
)

SONNET_HIGH_MODEL = "claude-sonnet-5-5-high"
OPUS_HIGH_MODEL = "claude-opus-5-5-high"
CARBON_HIGH_MODEL = "gemini-4-carbon-high"
HYDROGEN_LOW_MODEL = "gemini-4-hydrogen-low"
HYDROGEN_MEDIUM_MODEL = "gemini-4-hydrogen-medium"
HYDROGEN_HIGH_MODEL = "gemini-4-hydrogen-high"
HYDROGEN_XHIGH_MODEL = "gemini-4-hydrogen-xhigh"
HYDROGEN_MODEL_BY_LEVEL = {
    "low": HYDROGEN_LOW_MODEL,
    "medium": HYDROGEN_MEDIUM_MODEL,
    "high": HYDROGEN_HIGH_MODEL,
    "xhigh": HYDROGEN_XHIGH_MODEL,
}
FLASH_MODEL_RE = re.compile(r"\bflash(?:[-_]lite)?\b", re.IGNORECASE)

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
ANTHROPIC_EPHEMERAL_TTL_SECONDS = 300
SWARM_CACHE_SAFE_TTL_SECONDS = 270


def gate_dir(*parts: str) -> pathlib.Path:
    return rio.state_dir("gate", *parts)


def marker_path(session: str) -> pathlib.Path:
    return gate_dir("markers") / f"{session}.json"


def enforcement_state_path(session: str) -> pathlib.Path:
    return gate_dir("states") / f"{session}.json"


def checks_ledger_path(session: str) -> pathlib.Path:
    return gate_dir("checks") / f"{session}.jsonl"


def pending_notes_path(session: str) -> pathlib.Path:
    return gate_dir("notes") / f"{session}.json"


def snapshot_path(session: str, call_id: str) -> pathlib.Path:
    return gate_dir("snapshots") / f"{session}-{rio.safe_key(call_id, 'call')}.json"


def claim_path(session: str) -> pathlib.Path:
    return gate_dir("claims") / f"{session}.json"


def swarm_rounds_path(session: str) -> pathlib.Path:
    return gate_dir("swarm_rounds") / f"{session}.json"


def is_session_scratch_path(
    path: str | None,
    artifact_dir: str | None = None,
    workspace_paths: list[str] | None = None,
) -> bool:
    """Return True iff `path` is inside Antigravity's session-scoped scratch/artifact space (excluding state/.system_generated)."""
    norm = rio.normalize_path(path)
    if not norm or CHIP_TREES_RE.search(norm) or SYSTEM_GENERATED_RE.search(norm):
        return False
    folded = rio.fold_path(norm)

    scratch_root = ""
    if artifact_dir:
        art = rio.fold_path(artifact_dir)
        if art and (folded == art or folded.startswith(art + "/")):
            scratch_root = art
    if not scratch_root:
        for pat in USER_SCRATCH_PATTERNS:
            m = pat.search(norm)
            if m:
                scratch_root = rio.fold_path(norm[: m.end()].rstrip("/"))
                break
    if not scratch_root:
        return False

    # Exclude only when an explicit workspace was opened INSIDE the scratch directory itself (never ancestor $HOME)
    for wp in workspace_paths or []:
        if wp:
            fwp = rio.fold_path(wp)
            if fwp and fwp.startswith(scratch_root + "/") and (folded == fwp or folded.startswith(fwp + "/")):
                return False
    return True


def is_scratch_or_ephemeral(
    path: str | None,
    artifact_dir: str | None = None,
    workspace_paths: list[str] | None = None,
    cwd: str | None = None,
) -> bool:
    norm = rio.normalize_path(path)
    if not norm:
        return True
    if CHIP_TREES_RE.search(norm):
        return False
    if is_session_scratch_path(norm, artifact_dir=artifact_dir, workspace_paths=workspace_paths):
        return True
    folded = rio.fold_path(norm)
    state_root = rio.fold_path(rio.stack_home() / "state")
    if state_root and (folded == state_root or folded.startswith(state_root + "/")):
        return True
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


DEFAULT_GATE_POLICY: dict[str, Any] = {
    "default_code_risk": "STANDARD",
    "low_risk_globs": [],
    "high_risk_globs": [],
    "xhigh_risk_globs": [],
    "require_simplify_on_standard": False,
    "require_review_on_standard": False,
    "require_tests_on_standard": None,
}


GATE_POLICY_WALK_DEPTH = 16
TEST_HARNESS_WALK_DEPTH = 8
TEST_HARNESS_SAMPLE_PATHS = 8


def _resolve_against_cwd(path: str, cwd: str) -> str:
    return str(pathlib.Path(cwd) / path) if (cwd and not os.path.isabs(path)) else path


def _find_gate_policy_root(
    hints: list[str] | None = None,
    dir_cache: dict[str, dict[str, Any] | None] | None = None,
) -> tuple[pathlib.Path | None, dict[str, Any]]:
    seen_dirs: set[str] = set()
    probe_dirs: list[pathlib.Path] = []
    for raw in hints or []:
        if not raw:
            continue
        p = pathlib.Path(raw)
        cur = p if p.is_dir() else p.parent
        for _ in range(GATE_POLICY_WALK_DEPTH):
            key = rio.fold_path(str(cur))
            if key in seen_dirs:
                break
            seen_dirs.add(key)
            probe_dirs.append(cur)
            if cur.parent == cur:
                break
            cur = cur.parent

    for d in probe_dirs:
        dkey = rio.fold_path(str(d))
        if dir_cache is not None and dkey in dir_cache:
            cached = dir_cache[dkey]
            if cached is not None:
                return d, cached
            continue
        cfg = d / ".agents" / "carbon-gate.json"
        raw_cfg: dict[str, Any] | None = None
        if cfg.is_file():
            parsed = rio.read_json(cfg, default=None)
            if isinstance(parsed, dict):
                raw_cfg = parsed
        if dir_cache is not None:
            dir_cache[dkey] = raw_cfg
        if raw_cfg is not None:
            return d, raw_cfg
    return None, {}


def _parse_gate_policy(root: pathlib.Path | None, raw: dict[str, Any]) -> dict[str, Any]:
    policy = dict(DEFAULT_GATE_POLICY)
    policy["policy_root"] = rio.normalize_path(str(root)) if root is not None else ""
    if not raw:
        return policy
    default_risk = str(raw.get("default_code_risk") or "STANDARD").upper()
    if default_risk in RISK_ORDER:
        policy["default_code_risk"] = default_risk
    for key in ("low_risk_globs", "high_risk_globs", "xhigh_risk_globs"):
        val = raw.get(key)
        if isinstance(val, list):
            policy[key] = [str(x).strip() for x in val if str(x).strip()]
    for key in ("require_simplify_on_standard", "require_review_on_standard"):
        if key in raw:
            policy[key] = bool(raw.get(key))
    if "require_tests_on_standard" in raw and raw["require_tests_on_standard"] is not None:
        policy["require_tests_on_standard"] = bool(raw["require_tests_on_standard"])
    return policy


def load_project_gate_policy(
    hints: list[str] | str | None = None,
    cwd: str = "",
    dir_cache: dict[str, dict[str, Any] | None] | None = None,
) -> dict[str, Any]:
    """Load optional per-repo `.agents/carbon-gate.json` overrides with safe defaults."""
    explicit_hints: list[str] = []
    if isinstance(hints, str) and hints:
        explicit_hints.append(hints)
    elif isinstance(hints, list):
        explicit_hints.extend(str(h) for h in hints if h)

    cache = dir_cache if dir_cache is not None else {}
    if not explicit_hints:
        root, raw = _find_gate_policy_root([cwd] if cwd else [], dir_cache=cache)
        return _parse_gate_policy(root, raw)

    resolved_hints = [_resolve_against_cwd(h, cwd) for h in explicit_hints]
    if len(resolved_hints) == 1:
        h0 = resolved_hints[0]
        root, raw = _find_gate_policy_root([h0], dir_cache=cache)
        if root is not None:
            return _parse_gate_policy(root, raw)
        if cwd:
            c_root, c_raw = _find_gate_policy_root([cwd], dir_cache=cache)
            if c_root is not None and _is_under_root(rio.normalize_path(h0), rio.normalize_path(str(c_root)))[0]:
                return _parse_gate_policy(c_root, c_raw)
        return _parse_gate_policy(None, {})

    # INVARIANT: For multi-file hints, resolve nearest policy per parent directory so nested or cross-repo policies stay monotonic.
    parent_pols: dict[str, dict[str, Any]] = {}
    for h in resolved_hints:
        hp = pathlib.Path(h)
        pkey = rio.fold_path(str(hp if hp.is_dir() else hp.parent))
        if pkey not in parent_pols:
            parent_pols[pkey] = load_project_gate_policy(hints=[h], cwd=cwd, dir_cache=cache)
    distinct_roots = {str(p.get("policy_root") or "") for p in parent_pols.values()}
    if len(distinct_roots) == 1:
        return next(iter(parent_pols.values()))
    base = _parse_gate_policy(None, {})
    base["_multi_root"] = True
    return base


def _is_under_root(norm_path: str, root: str) -> tuple[bool, str]:
    rn = rio.normalize_path(root).rstrip("/").lower()
    if not rn:
        return norm_path.startswith("/"), norm_path.lstrip("/")
    prefix = rn + "/"
    low = norm_path.lower()
    if low.startswith(prefix):
        return True, low[len(prefix) :]
    if low == rn:
        return True, ""
    return False, low


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    parts: list[str] = ["^"]
    i = 0
    n = len(pattern)
    while i < n:
        if pattern.startswith("**/", i):
            parts.append("(?:.+/)?")
            i += 3
        elif pattern.startswith("**", i):
            parts.append(".*")
            i += 2
        elif pattern[i] == "*":
            parts.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            parts.append("[^/]")
            i += 1
        else:
            parts.append(re.escape(pattern[i]))
            i += 1
    parts.append("$")
    return re.compile("".join(parts))


def _posix_full_match(path_str: str, pattern: str) -> bool:
    p = pathlib.PurePosixPath(path_str)
    if hasattr(p, "full_match"):
        return bool(p.full_match(pattern))
    return bool(_glob_to_regex(pattern).match(path_str))


def _match_glob_patterns(path: str, patterns: list[str], root: str = "") -> bool:
    if not patterns:
        return False
    norm = rio.normalize_path(path).lower()
    rel = norm
    if root:
        inside, rel = _is_under_root(norm, root)
        if not inside or not rel:
            return False
    base = pathlib.PurePosixPath(rel).name
    for raw_pat in patterns:
        pat = raw_pat.strip().replace("\\", "/").lower()
        while pat.startswith("./"):
            pat = pat[2:]
        pat = pat.lstrip("/")
        if not pat:
            continue
        if "/" not in pat and fnmatch.fnmatchcase(base, pat):
            return True
        if root:
            if _posix_full_match(rel, pat):
                return True
        else:
            if _posix_full_match(norm, pat) or _posix_full_match(norm, f"**/{pat}"):
                return True
    return False


def classify_path_risk(path: str, policy: dict[str, Any] | None = None) -> str:
    if path == SHELL_MUTATION_SENTINEL:
        return "LOW"
    pol = policy or DEFAULT_GATE_POLICY
    pol_root = str(pol.get("policy_root") or "")
    norm = rio.normalize_path(path)
    if policy is None or pol.get("_multi_root") or (pol_root and not _is_under_root(norm, pol_root)[0]):
        # INVARIANT: Never apply repoA's `.agents/carbon-gate.json` globs or defaults to a path outside repoA.
        pol = load_project_gate_policy(hints=[path])
        pol_root = str(pol.get("policy_root") or "")
    if _match_glob_patterns(norm, list(pol.get("xhigh_risk_globs") or ()), root=pol_root):
        return "XHIGH"
    for pat in HIGH_RISK_PATTERNS:
        if pat.search(norm):
            return "HIGH"
    if _match_glob_patterns(norm, list(pol.get("high_risk_globs") or ()), root=pol_root):
        return "HIGH"
    ext = pathlib.PurePosixPath(norm).suffix.lower()
    base = pathlib.PurePosixPath(norm).name.lower()
    if ext in DOC_EXTENSIONS and not base.startswith(("agents.", "gemini.", "claude.")):
        return "LOW"
    if _match_glob_patterns(norm, list(pol.get("low_risk_globs") or ()), root=pol_root):
        return "LOW"
    default_code = str(pol.get("default_code_risk") or "STANDARD").upper()
    return default_code if default_code in RISK_ORDER else "STANDARD"


def _is_fast_test_code_path(path: str) -> bool:
    norm = rio.normalize_path(path).lower()
    base = pathlib.PurePosixPath(norm).name
    return norm.endswith(".py") or base.startswith("test_") or "_test." in base or ".test." in base or ".spec." in base


def workspace_has_test_harness(
    cwd: str = "",
    paths: list[str] | None = None,
    git_root: str | None = None,
) -> bool:
    """Detect whether the repository or touched code has an applicable local verification/test harness."""
    dpaths = durable_paths(paths)
    if any(_is_fast_test_code_path(p) for p in dpaths):
        return True

    roots: list[pathlib.Path] = []
    if cwd:
        top = rio.git_toplevel(cwd) if git_root is None else git_root
        if top:
            roots.append(pathlib.Path(top))
        roots.append(pathlib.Path(cwd))
    non_doc = [
        p for p in dpaths if pathlib.PurePosixPath(rio.normalize_path(p)).suffix.lower() not in DOC_EXTENSIONS
    ]
    non_doc_set = set(non_doc)
    sample_paths = (non_doc + [p for p in dpaths if p not in non_doc_set])[:TEST_HARNESS_SAMPLE_PATHS]
    for p in sample_paths:
        pp = pathlib.Path(p)
        cur = pp if pp.is_dir() else pp.parent
        for _ in range(TEST_HARNESS_WALK_DEPTH):
            roots.append(cur)
            if cur.parent == cur:
                break
            cur = cur.parent

    seen: set[str] = set()
    test_dirs = ("tests", "test", "__tests__", "spec")
    harness_files = ("pytest.ini", "conftest.py", "tox.ini", "pyproject.toml", "Cargo.toml", "go.mod", "tsconfig.json")
    for root in roots:
        if not root.is_dir():
            continue
        rk = rio.fold_path(str(root))
        if rk in seen:
            continue
        seen.add(rk)
        for dname in test_dirs:
            if (root / dname).is_dir():
                return True
        for fname in harness_files:
            if (root / fname).is_file():
                return True
        pkg_json = root / "package.json"
        if pkg_json.is_file():
            pkg = rio.read_json(pkg_json, default={})
            scripts = pkg.get("scripts") if isinstance(pkg, dict) else None
            if isinstance(scripts, dict):
                test_cmd = str(scripts.get("test") or "").strip().lower()
                if test_cmd and "no test specified" not in test_cmd:
                    return True
    return False


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


def unlink_quiet(path: pathlib.Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def clear_claim(session: str) -> None:
    unlink_quiet(claim_path(session))


def clear_swarm_rounds(session: str) -> None:
    unlink_quiet(swarm_rounds_path(session))


swarm_dir = rio.swarm_dir
member_transcript_path = rio.member_transcript_path
load_swarm_members = rio.load_swarm_members
is_swarm_role_member = rio.is_swarm_role_member
is_swarm_member_killed = rio.is_swarm_member_killed


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


def requires_simplify(risk: str, policy: dict[str, Any] | None = None) -> bool:
    pol = policy or DEFAULT_GATE_POLICY
    up = str(risk or "LOW").upper()
    return up in ("HIGH", "XHIGH") or (up == "STANDARD" and bool(pol.get("require_simplify_on_standard")))


def requires_review(risk: str, policy: dict[str, Any] | None = None) -> bool:
    pol = policy or DEFAULT_GATE_POLICY
    up = str(risk or "LOW").upper()
    return up in ("HIGH", "XHIGH") or (up == "STANDARD" and bool(pol.get("require_review_on_standard")))


def standard_requires_tests(
    cwd: str = "",
    paths: list[str] | None = None,
    policy: dict[str, Any] | None = None,
    git_root: str | None = None,
) -> bool:
    """Return whether a `STANDARD` candidate requires test execution, probing workspace only when unset."""
    pol = policy or DEFAULT_GATE_POLICY
    cfg = pol.get("require_tests_on_standard")
    if cfg is not None:
        return bool(cfg)
    return workspace_has_test_harness(cwd=cwd, paths=paths, git_root=git_root)


def _resolve_path_policies(
    dpaths: list[str],
    cwd: str = "",
    policy: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[tuple[str, dict[str, Any], str]]]:
    dir_cache: dict[str, dict[str, Any] | None] = {}
    if not dpaths:
        pol = policy if policy is not None else load_project_gate_policy(cwd=cwd, dir_cache=dir_cache)
        return pol, []
    if policy is not None and not policy.get("_multi_root"):
        resolved = [_resolve_against_cwd(p, cwd) for p in dpaths]
        return policy, [(ap, policy, classify_path_risk(ap, policy=policy)) for ap in resolved]

    parent_cache: dict[str, dict[str, Any]] = {}
    items: list[tuple[str, dict[str, Any], str]] = []
    for p in dpaths:
        abs_p = _resolve_against_cwd(p, cwd)
        parent_key = rio.fold_path(str(pathlib.Path(abs_p).parent))
        p_pol = parent_cache.get(parent_key)
        if p_pol is None:
            p_pol = load_project_gate_policy(hints=[abs_p], cwd=cwd, dir_cache=dir_cache)
            parent_cache[parent_key] = p_pol
        items.append((abs_p, p_pol, classify_path_risk(abs_p, policy=p_pol)))

    distinct_roots = {str(p_pol.get("policy_root") or "") for _, p_pol, _ in items}
    if len(distinct_roots) == 1:
        return items[0][1], items
    multi = _parse_gate_policy(None, {})
    multi["_multi_root"] = True
    return multi, items


def requires_tests(
    risk: str,
    cwd: str = "",
    paths: list[str] | None = None,
    policy: dict[str, Any] | None = None,
    git_root: str | None = None,
    resolved_items: list[tuple[str, dict[str, Any], str]] | None = None,
) -> bool:
    up = str(risk or "LOW").upper()
    if up in ("HIGH", "XHIGH"):
        return True
    if up != "STANDARD":
        return False

    if resolved_items is not None:
        items = resolved_items
        pol = policy or DEFAULT_GATE_POLICY
        dpaths = [p for p, _, _ in items]
    else:
        dpaths = durable_paths(paths)
        if not dpaths or (policy is not None and not policy.get("_multi_root")):
            pol = policy if policy is not None else load_project_gate_policy(dpaths, cwd=cwd)
            if not pol.get("_multi_root"):
                return standard_requires_tests(cwd=cwd, paths=dpaths, policy=pol, git_root=git_root)
        pol, items = _resolve_path_policies(dpaths, cwd=cwd, policy=policy)

    if not items or not pol.get("_multi_root"):
        return standard_requires_tests(cwd=cwd, paths=dpaths, policy=pol, git_root=git_root)

    if any(p_risk in ("HIGH", "XHIGH") for _, _, p_risk in items):
        return True
    std_items = [(p, p_pol) for p, p_pol, p_risk in items if p_risk == "STANDARD"]
    if not std_items:
        std_items = [(p, p_pol) for p, p_pol, _ in items]

    unconfigured: list[tuple[str, dict[str, Any]]] = []
    for p, p_pol in std_items:
        cfg = p_pol.get("require_tests_on_standard")
        if cfg is True:
            return True
        if cfg is False:
            continue
        if _is_fast_test_code_path(p):
            return True
        unconfigured.append((p, p_pol))
    if not unconfigured:
        return False

    seen_parents: set[str] = set()
    norm_cwd = rio.normalize_path(cwd) if cwd else ""
    for p, p_pol in unconfigured:
        parent = str(pathlib.Path(p).parent)
        pkey_dir = rio.fold_path(parent)
        if pkey_dir in seen_parents:
            continue
        seen_parents.add(pkey_dir)
        pol_root = str(p_pol.get("policy_root") or "")
        eff_git_root: str | None = None
        if pol_root and (pathlib.Path(pol_root) / ".git").exists():
            eff_git_root = pol_root
        elif git_root and _is_under_root(rio.normalize_path(p), git_root)[0]:
            eff_git_root = git_root
        elif git_root == "" and norm_cwd and pkey_dir == rio.fold_path(norm_cwd):
            eff_git_root = ""
        if workspace_has_test_harness(cwd=parent, paths=[p], git_root=eff_git_root):
            return True
    return False


def resolve_candidate_context(
    marker: dict[str, Any] | None,
    include_tests: bool = True,
) -> dict[str, Any]:
    cwd = str((marker or {}).get("cwd") or "")
    dpaths = durable_paths((marker or {}).get("paths"))
    policy, items = _resolve_path_policies(dpaths, cwd=cwd)
    floors = [r for _, _, r in items]
    if (marker or {}).get("unattributed_floor"):
        floors.append(str((marker or {})["unattributed_floor"]))
    floor = max_risk(floors) if floors else "LOW"
    git_root = str(marker["git_root"]) if isinstance(marker, dict) and "git_root" in marker else None
    if items:
        needs_simplify = requires_simplify(floor, policy) or any(
            requires_simplify(p_risk, p_pol) for _, p_pol, p_risk in items
        )
        needs_review = requires_review(floor, policy) or any(
            requires_review(p_risk, p_pol) for _, p_pol, p_risk in items
        )
        if policy.get("_multi_root") and (needs_simplify or needs_review):
            policy = dict(
                policy,
                require_simplify_on_standard=needs_simplify,
                require_review_on_standard=needs_review,
            )
    else:
        needs_simplify = requires_simplify(floor, policy)
        needs_review = requires_review(floor, policy)
    req_tests = (
        requires_tests(
            floor,
            cwd=cwd,
            paths=dpaths,
            policy=policy,
            git_root=git_root,
            resolved_items=items,
        )
        if include_tests
        else None
    )
    return {
        "cwd": cwd,
        "git_root": git_root,
        "dpaths": dpaths,
        "policy": policy,
        "floor": floor,
        "require_tests": req_tests,
        "needs_simplify": needs_simplify,
        "needs_review": needs_review,
    }


def receipt_requirements_summary(
    floor: str,
    policy: dict[str, Any] | None = None,
    has_tests: bool = True,
) -> str:
    pol = policy if isinstance(policy, dict) else DEFAULT_GATE_POLICY
    if floor == "LOW":
        return "honest content/render check (no simplify or adversarial review required)"
    if floor == "STANDARD":
        parts = ["local verification/test execution" if has_tests else "self-check (run any applicable check)"]
        if pol.get("require_simplify_on_standard"):
            parts.append(f"simplify on `{SONNET_HIGH_MODEL}`")
        if pol.get("require_review_on_standard"):
            parts.append("independent APPROVED review")
        return " + ".join(parts)
    if floor == "HIGH":
        return (
            f"decisive test/check execution + 3 separate simplify lenses (`{SONNET_HIGH_MODEL}`) + "
            f"1 independent APPROVED review (Codex lane or internal `{OPUS_HIGH_MODEL}` -> fallback `{CARBON_HIGH_MODEL}`)"
        )
    return (
        f"decisive test/check execution + 3 separate simplify lenses (`{SONNET_HIGH_MODEL}`) + "
        f"1 XHIGH APPROVED review (Codex --xhigh or internal `{OPUS_HIGH_MODEL}` [XHIGH] -> fallback `{CARBON_HIGH_MODEL}`)"
    )
