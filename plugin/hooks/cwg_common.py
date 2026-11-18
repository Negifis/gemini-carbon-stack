#!/usr/bin/env python3
"""Code Work Gate shared classification, risk floors, fingerprints, claims, and receipts."""

from __future__ import annotations

import fnmatch
import hashlib
import json
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
MAX_CONTENT_MARKS = 512

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
        r"(?:^|/)\.swarm(?:/|$)",
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
_PLAIN_ORD_VERDICTS = frozenset({"APPROVED", "REVISE", "ESCALATE"})
_PLAIN_CLS_VERDICTS = frozenset({"READY", "BLOCKED"})
CODEX_REVIEW_OUTPUT_BANNER = "--- CODEX REVIEW OUTPUT ---"
CODEX_CLI_WRAPPER_RE = re.compile(
    r"\AREVIEW_ID:\s*[A-Za-z0-9_-]+[ \t]*\r?\n"
    r"(?:(?:SESSION_ID|SESSION_MODE|ENGINE):[^\r\n]*\r?\n){0,3}"
    + re.escape(CODEX_REVIEW_OUTPUT_BANNER)
    + r"[ \t]*\r?\n"
)
_SWARM_MENTION_LINE_RE = re.compile(r"\A@[A-Za-z0-9_-]+(?:[ \t]+@[A-Za-z0-9_-]+)*[ \t]*\r?\n")
_JSON_NUM_TOKEN = r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?"
_JSON_ARRAY_START_RE = re.compile(
    r"\A\[[ \t]*(?:"
    r"[\{\[\"]"
    r"|\][ \t]*(?:\r?\n|$)"
    r"|(?:true|false|null)[ \t]*(?:,|\][ \t]*(?:\r?\n|$)|\r?\n|$)"
    r"|" + _JSON_NUM_TOKEN + r"[ \t]*(?:,|\][ \t]*(?:\r?\n|$)|\r?\n|$)"
    r"|\r?\n|$)"
)


def _decision_from_json_dict(obj: dict[str, Any]) -> tuple[str | None, str | None]:
    # INVARIANT: Inspect ONLY top-level decision keys (`closure_validation`/`verdict`), never nested finding text.
    for key in ("closure_validation", "CLOSURE_VALIDATION"):
        raw_cls = obj.get(key)
        if isinstance(raw_cls, str) and raw_cls.strip():
            s = raw_cls.strip()
            cm = CLOSURE_LINE_RE.search(s)
            if cm:
                return ("closure", cm.group(1).upper())
            up = s.strip("*` \t\r\n").upper()
            if up in _PLAIN_CLS_VERDICTS:
                return ("closure", up)
    for key in ("verdict", "VERDICT"):
        raw_ord = obj.get(key)
        if isinstance(raw_ord, str) and raw_ord.strip():
            s = raw_ord.strip()
            cm2 = CLOSURE_LINE_RE.search(s)
            if cm2:
                return ("closure", cm2.group(1).upper())
            vm = VERDICT_LINE_RE.search(s)
            if vm:
                return ("ordinary", vm.group(1).upper())
            up = s.strip("*` \t\r\n").upper()
            if up in _PLAIN_ORD_VERDICTS:
                return ("ordinary", up)
            if up in _PLAIN_CLS_VERDICTS:
                return ("closure", up)
    return (None, None)


def _advance_json_depth(line: str, depth: int, in_str: bool, esc: bool) -> tuple[int, bool, bool]:
    for ch in line:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth = max(0, depth - 1)
    return (depth, in_str, esc)


def _strip_unfenced_json_blocks(lines: list[str]) -> str:
    # SAFETY: Exclude unfenced line-anchored `{...}` / `[...]` blocks from plain-text fallback
    # so malformed JSON payloads after prose cannot leak embedded `VERDICT:` lines.
    kept: list[str] = []
    depth = 0
    in_str = False
    esc = False
    for ln in lines:
        if depth == 0 and not in_str:
            lstripped = ln.lstrip(" \t")
            if lstripped.startswith("{") or _JSON_ARRAY_START_RE.match(lstripped):
                depth, in_str, esc = _advance_json_depth(lstripped, 0, False, False)
                continue
            kept.append(ln)
            continue
        depth, in_str, esc = _advance_json_depth(ln, depth, in_str, esc)
    return "\n".join(kept).strip()


def _extract_terminal_json_dict(text: str) -> tuple[dict[str, Any] | None, str]:
    # SAFETY: Accept ONLY a syntactically complete RFC 8259 JSON object occupying the entire review payload
    # (after optional byte-0 CLI wrapper / `@mention`) or a complete terminal markdown JSON fence; strip all
    # fenced blocks and unfenced JSON blocks from `prose_fallback` so embedded lines never spoof plain-text regexes.
    body = (text or "").strip()
    if not body:
        return (None, "")
    wrapper_m = CODEX_CLI_WRAPPER_RE.match(body)
    if wrapper_m:
        body = body[wrapper_m.end() :].strip()
    mention_m = _SWARM_MENTION_LINE_RE.match(body)
    if mention_m:
        body = body[mention_m.end() :].strip()
    if not body:
        return (None, "")

    if body.startswith("{"):
        if not body.endswith("}"):
            return (None, "")
        try:
            obj = json.loads(body)
        except Exception:
            return (None, "")
        return (obj if isinstance(obj, dict) else None, "")
    if _JSON_ARRAY_START_RE.match(body):
        return (None, "")

    if "```" in body:
        lines = body.splitlines()
        fence_indices = [i for i, ln in enumerate(lines) if ln.strip().startswith("```")]
        n_fences = len(fence_indices)
        has_terminal_fence = (
            n_fences >= 2
            and n_fences % 2 == 0
            and fence_indices[-1] == len(lines) - 1
            and lines[-1].strip() == "```"
        )
        excluded_ranges: list[tuple[int, int]] = [
            (fence_indices[k], fence_indices[k + 1]) for k in range(0, n_fences - 1, 2)
        ]
        if n_fences % 2 == 1:
            excluded_ranges.append((fence_indices[-1], len(lines) - 1))

        json_candidate: dict[str, Any] | None = None
        if has_terminal_fence:
            open_idx = fence_indices[-2]
            fence_hdr = lines[open_idx].strip().lower()
            fenced = "\n".join(lines[open_idx + 1 : -1]).strip()
            if fence_hdr in ("```", "```json") and fenced.startswith("{") and fenced.endswith("}"):
                try:
                    parsed = json.loads(fenced)
                except Exception:
                    parsed = None
                if isinstance(parsed, dict):
                    json_candidate = parsed

        kept_lines: list[str] = []
        r_idx = 0
        n_ranges = len(excluded_ranges)
        for idx, ln in enumerate(lines):
            while r_idx < n_ranges and idx > excluded_ranges[r_idx][1]:
                r_idx += 1
            if r_idx < n_ranges and excluded_ranges[r_idx][0] <= idx <= excluded_ranges[r_idx][1]:
                continue
            kept_lines.append(ln)
        return (json_candidate, _strip_unfenced_json_blocks(kept_lines))
    return (None, _strip_unfenced_json_blocks(body.splitlines()))


def extract_review_decision(text: str) -> tuple[str | None, str | None]:
    """Extract `(kind, verdict)` from plain-text control lines or a complete top-level JSON review payload."""
    stripped = (text or "").strip()
    if not stripped:
        return (None, None)

    json_obj, prose_fallback = _extract_terminal_json_dict(stripped)
    if json_obj is not None:
        dec = _decision_from_json_dict(json_obj)
        if dec != (None, None) or not prose_fallback:
            return dec
    if not prose_fallback:
        return (None, None)

    cls_matches = CLOSURE_LINE_RE.findall(prose_fallback)
    if cls_matches:
        return ("closure", cls_matches[-1].upper())
    ord_matches = VERDICT_LINE_RE.findall(prose_fallback)
    if ord_matches:
        return ("ordinary", ord_matches[-1].upper())
    return (None, None)


FAST_PATH_MAX_FILES = 2
FAST_PATH_MAX_LINES = 30
BOARD_CURSOR_THRESHOLD = 15
DEFAULT_SWARM_STALL_TIMEOUT_SEC = 240

_MD_EDGE = r"(?:\*{1,2}|__|`)?"
_MD_WRAP = r"(?:(?:\*{1,2}|__|`)\s*){0,2}"
_ALL_SIMPLIFY_TOKENS = r"(?:CLEAN|FINDINGS_REPORTED|ACTIONABLE_FIXES|REUSE|QUALITY|EFFICIENCY|ALL|COMBINED)"
_SIMPLIFY_ALT_TAIL = (
    rf"(?!\s*{_MD_WRAP}"
    rf"(?:\||/(?!/)"
    rf"|\(?\s*\b(?:or|или)\b\s+(?:{_MD_WRAP}SIMPLIFY_(?:VERDICT|LENS){_MD_WRAP}\s*:\s*{_MD_WRAP})?{_ALL_SIMPLIFY_TOKENS}\b"
    rf"|,\s*{_MD_WRAP}(?:(?:or|или)\b\s+)?{_ALL_SIMPLIFY_TOKENS}\b))"
)
_SIMPLIFY_TEMPLATE_PAIR_RE = re.compile(
    rf"{_MD_WRAP}SIMPLIFY_(?:VERDICT|LENS){_MD_WRAP}\s*:\s*{_MD_WRAP}{_ALL_SIMPLIFY_TOKENS}{_MD_WRAP}"
    rf"\s*(?:\(|,|\||/)?\s*(?:\bor\b|\bили\b|\|)\s*"
    rf"{_MD_WRAP}SIMPLIFY_(?:VERDICT|LENS){_MD_WRAP}\s*:\s*{_MD_WRAP}{_ALL_SIMPLIFY_TOKENS}{_MD_WRAP}\)?",
    re.IGNORECASE,
)


def _compile_simplify_tag_re(key: str, choices: str) -> re.Pattern[str]:
    return re.compile(
        rf"(?<![A-Za-z0-9_])(?<!\(or )(?<!\(or `)(?<!\bor )(?<!\bor `)(?<!\bили )"
        rf"{_MD_WRAP}{key}{_MD_WRAP}\s*:\s*{_MD_WRAP}"
        rf"({choices})(?:(?![A-Za-z0-9_])|(?=__(?![A-Za-z0-9_]))){_SIMPLIFY_ALT_TAIL}",
        re.IGNORECASE,
    )


SIMPLIFY_LINE_RE = _compile_simplify_tag_re(
    "SIMPLIFY_VERDICT",
    "CLEAN|FINDINGS_REPORTED|ACTIONABLE_FIXES",
)
SIMPLIFY_LENS_LINE_RE = _compile_simplify_tag_re(
    "SIMPLIFY_LENS",
    "REUSE|QUALITY|EFFICIENCY",
)
SIMPLIFY_COMBINED_LENS_RE = _compile_simplify_tag_re(
    "SIMPLIFY_LENS",
    "ALL|COMBINED",
)
def _skip_md_and_ws(s: str, i: int) -> int:
    n = len(s)
    while i < n:
        ch = s[i]
        if ch.isspace() or ch in ("*", "`"):
            i += 1
        elif ch == "_" and i + 1 < n and s[i + 1] == "_":
            i += 2
        else:
            break
    return i


def _is_simplify_line_prefix_clean(prefix: str) -> bool:
    # INVARIANT: Single-pass O(L) scanner (zero regex backtracking) rejecting inline prose citations (`anom-d6ceeff0`) while allowing `@mention`, bullets, and prior tags.
    trimmed = prefix.lstrip()
    s = trimmed[2:] if len(trimmed) >= 2 and trimmed[0] in "-*+>" and trimmed[1].isspace() else trimmed
    n = len(s)
    i = 0
    while True:
        i = _skip_md_and_ws(s, i)
        if i >= n:
            return True
        if s[i] == "@":
            i += 1
            start = i
            while i < n and (s[i].isalnum() or s[i] in "_-"):
                i += 1
            if i == start or (i < n and not s[i].isspace()):
                return False
            continue
        up_tail = s[i : i + 16].upper()
        klen = 0
        for k in ("SIMPLIFY_VERDICT", "SIMPLIFY_LENS", "DIFF_HASH"):
            if up_tail.startswith(k):
                klen = len(k)
                break
        if klen == 0:
            return False
        i = _skip_md_and_ws(s, i + klen)
        if i >= n or s[i] != ":":
            return False
        i = _skip_md_and_ws(s, i + 1)
        vstart = i
        while i < n and (s[i].isalnum() or s[i] in "_.:-"):
            i += 1
        if i == vstart:
            return False
        while True:
            nxt = _skip_md_and_ws(s, i)
            if nxt < n and s[nxt] in ",.;|/-":
                i = nxt + 1
            else:
                i = nxt
                break


def _find_simplify_tag_matches(tag_re: re.Pattern[str], text: str) -> list[str]:
    out: list[str] = []
    for m in tag_re.finditer(text):
        start = m.start()
        nl = text.rfind("\n", 0, start)
        line_before = text[nl + 1 : start]
        c_idx = line_before.rfind("content=")
        eff_prefix = line_before[c_idx + len("content=") :] if c_idx >= 0 else line_before
        if _is_simplify_line_prefix_clean(eff_prefix):
            out.append(m.group(1))
    return out


REVIEW_TIER_XHIGH_RE = re.compile(
    r"\bREVIEW_TIER\s*:\s*XHIGH\b",
    re.IGNORECASE,
)
DIFF_HASH_RE = re.compile(r"\bDIFF_HASH\s*:\s*([A-Za-z0-9_.:-]+)", re.IGNORECASE)


def extract_diff_hash(text: str) -> str:
    matches = DIFF_HASH_RE.findall(text or "")
    return matches[-1].strip() if matches else ""

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
SIMPLIFY_FALLBACK_MODEL = HYDROGEN_XHIGH_MODEL
SIMPLIFY_FALLBACK_MODELS = frozenset({HYDROGEN_XHIGH_MODEL})
SIMPLIFY_ALLOWED_MODELS = frozenset({SONNET_HIGH_MODEL}) | SIMPLIFY_FALLBACK_MODELS
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
SIMPLIFY_AGENT_TYPES = SIMPLIFY_LENS_AGENTS | frozenset({SIMPLIFY_REVIEWER})
COMPACT_SIMPLIFY_WORKER_RE = re.compile(
    r"^simp-(?:reuse|quality|efficiency|efficie|all)(?:$|[-_][a-z0-9._-]*$)",
    re.IGNORECASE,
)
ANTHROPIC_EPHEMERAL_TTL_SECONDS = 300
SWARM_CACHE_SAFE_TTL_SECONDS = 270


def is_simplify_worker_name(name: str | None) -> bool:
    low = (name or "").strip().lower()
    if not low:
        return False
    return "simplify" in low or bool(COMPACT_SIMPLIFY_WORKER_RE.match(low))


def simplify_lens_from_worker_name(name: str | None) -> str:
    low = (name or "").strip().lower()
    if not low:
        return ""
    for lens in SIMPLIFY_LENSES:
        if lens in low:
            return lens
    if "efficie" in low and is_simplify_worker_name(low):
        return "efficiency"
    return ""


def swarm_stall_timeout_sec() -> float:
    raw = str(os.environ.get("SWARM_STALL_TIMEOUT_SEC") or "").strip()
    if not raw:
        return float(DEFAULT_SWARM_STALL_TIMEOUT_SEC)
    try:
        parsed = float(raw)
    except ValueError:
        return float(DEFAULT_SWARM_STALL_TIMEOUT_SEC)
    return parsed if parsed > 0.0 else float(DEFAULT_SWARM_STALL_TIMEOUT_SEC)


def parse_simplify_verdict(text: str, default_lens: str = "") -> dict[str, Any]:
    cleaned = _SIMPLIFY_TEMPLATE_PAIR_RE.sub(" ", text or "")
    has_combined = bool(_find_simplify_tag_matches(SIMPLIFY_COMBINED_LENS_RE, cleaned))
    explicit_lenses = [m.lower() for m in _find_simplify_tag_matches(SIMPLIFY_LENS_LINE_RE, cleaned)]
    unique_lenses = list(dict.fromkeys(explicit_lenses))
    verdict_matches = _find_simplify_tag_matches(SIMPLIFY_LINE_RE, cleaned)
    verdict = verdict_matches[-1].upper() if verdict_matches else ""
    multi_lens_spoof = (not has_combined) and len(unique_lenses) > 1
    if has_combined:
        lens = "all"
    elif len(unique_lenses) == 1:
        lens = unique_lenses[0]
    elif multi_lens_spoof:
        lens = "combined"
    else:
        lens = (default_lens or "").strip().lower()
    return {
        "lens": lens,
        "verdict": verdict,
        "clean": verdict == "CLEAN",
        "combined": has_combined or multi_lens_spoof or lens in ("all", "combined"),
        "has_explicit_all": has_combined,
        "multi_lens_spoof": multi_lens_spoof,
        "explicit_lenses": unique_lenses,
    }


extract_simplify_verdict = parse_simplify_verdict


def _normalize_diff_metrics(raw: dict[str, Any], default_source: str) -> dict[str, Any]:
    files_count = int(raw.get("files_count", raw.get("files", 0)) or 0)
    additions = max(0, int(raw.get("additions") or 0))
    deletions = max(0, int(raw.get("deletions") or 0))
    total_lines = raw.get("total_lines")
    total = max(0, int(total_lines)) if total_lines is not None else (additions + deletions)
    return {
        "files_count": files_count,
        "additions": additions,
        "deletions": deletions,
        "total_lines": total,
        "source": str(raw.get("source") or default_source),
    }


def _probe_untracked_file_lines(fp: pathlib.Path) -> tuple[bool, int]:
    """Check binary header first (4 KiB) then count lines in chunks without loading whole file."""
    with fp.open("rb") as fh:
        head = fh.read(4096)
        if not head:
            return False, 0
        if b"\x00" in head:
            return True, 0
        newlines = head.count(b"\n")
        last_byte = head[-1:]
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            newlines += chunk.count(b"\n")
            last_byte = chunk[-1:]
        return False, newlines + (0 if last_byte in (b"\n", b"\r") else 1)


def compute_diff_metrics(
    marker: dict[str, Any] | None = None,
    repo_root: str | pathlib.Path | None = None,
    diff_stats: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if isinstance(diff_stats, dict) and diff_stats:
        return _normalize_diff_metrics(diff_stats, "explicit")

    m = marker if isinstance(marker, dict) else {}
    saved = m.get("diff_metrics")
    if isinstance(saved, dict) and saved and (not repo_root or saved.get("source") == "explicit"):
        return _normalize_diff_metrics(saved, "marker")

    if repo_root:
        root_str = str(repo_root)
        rc, out, _ = rio.run_git(root_str, ["rev-parse", "--verify", "HEAD"])
        diff_args = ["diff", "--numstat", "HEAD"] if rc == 0 and out.strip() else ["diff", "--numstat"]
        rc_d, out_d, _ = rio.run_git(root_str, diff_args)
        rc_u, out_u, _ = rio.run_git(root_str, ["ls-files", "--others", "--exclude-standard"])
        git_files: set[str] = set()
        adds = 0
        dels = 0
        has_binary = False
        if rc_d == 0 and out_d:
            for line in out_d.splitlines():
                parts = line.split("\t", 2)
                if len(parts) != 3:
                    continue
                a_raw, d_raw, rel = parts
                if is_ephemeral_path(rel, cwd=root_str):
                    continue
                git_files.add(rio.normalize_path(rel))
                if a_raw == "-" or d_raw == "-":
                    has_binary = True
                else:
                    adds += int(a_raw or 0)
                    dels += int(d_raw or 0)
        if rc_u == 0 and out_u:
            root_path = pathlib.Path(root_str)
            for rel in out_u.splitlines():
                rel = rel.strip()
                if not rel or is_ephemeral_path(rel, cwd=root_str):
                    continue
                git_files.add(rio.normalize_path(rel))
                fp = root_path / rel
                try:
                    if fp.is_file():
                        f_bin, f_lines = _probe_untracked_file_lines(fp)
                        if f_bin:
                            has_binary = True
                        else:
                            adds += f_lines
                except OSError:
                    continue
        if git_files:
            candidate_dpaths = durable_paths(list(m.get("paths") or []))
            all_files = set(git_files)
            for cp in candidate_dpaths:
                rel_cp = resolve_repo_rel_path(cp, root_str)
                if rel_cp:
                    all_files.add(rel_cp)
            total = (adds + dels) if not has_binary else max(adds + dels, FAST_PATH_MAX_LINES + 1)
            return {
                "files_count": max(len(all_files), len(candidate_dpaths)),
                "additions": adds,
                "deletions": dels,
                "total_lines": total,
                "source": "git",
            }

    if isinstance(saved, dict) and saved:
        return _normalize_diff_metrics(saved, "marker")

    dpaths = durable_paths(list(m.get("paths") or []))
    changed_lines = max(0, int(m.get("changed_lines") or 0))
    return {
        "files_count": len(dpaths),
        "additions": changed_lines,
        "deletions": 0,
        "total_lines": changed_lines,
        "source": "marker-fallback",
    }


def is_simplify_fast_path_eligible(
    marker: dict[str, Any] | None = None,
    swarm_ev: dict[str, Any] | None = None,
    diff_stats: dict[str, Any] | None = None,
    repo_root: str | pathlib.Path | None = None,
) -> bool:
    if isinstance(swarm_ev, dict) and swarm_ev.get("multi_lens_spoof"):
        return False
    m = marker if isinstance(marker, dict) else {}
    effective_root = repo_root or m.get("repo_root") or m.get("cwd")
    metrics = compute_diff_metrics(marker=m, repo_root=effective_root, diff_stats=diff_stats)
    files_count = int(metrics.get("files_count") or 0)
    total_lines = int(metrics.get("total_lines") or 0)
    if files_count <= 0:
        files_count = len(durable_paths(list(m.get("paths") or [])))
    return 0 < files_count <= FAST_PATH_MAX_FILES and total_lines <= FAST_PATH_MAX_LINES


def _swarm_board_candidates(
    session: str = "",
    cwd: str = "",
    transcript_path: str = "",
) -> list[pathlib.Path]:
    candidates: list[pathlib.Path] = []
    seen: set[str] = set()

    def _add(p: pathlib.Path | None) -> None:
        if p is None:
            return
        k = rio.fold_path(p)
        if k not in seen:
            seen.add(k)
            candidates.append(p)

    tp_brain, tp_cid = rio._swarm_brain_and_cid(transcript_path or None, session or None)
    eff_session = tp_cid or (session or "").strip()
    if tp_brain is not None and eff_session:
        _add(rio.swarm_dir(tp_brain, eff_session) / "board.jsonl")
    if eff_session:
        _add(rio.swarm_dir(rio.resolve_brain_root(""), eff_session) / "board.jsonl")
    if cwd:
        cwd_path = pathlib.Path(cwd)
        _add(cwd_path / ".swarm" / "board.jsonl")
        if not (cwd_path / ".git").exists() and not (cwd_path / ".swarm" / "board.jsonl").is_file():
            top = rio.git_toplevel(cwd)
            if top:
                _add(pathlib.Path(top) / ".swarm" / "board.jsonl")
    return candidates


def _extract_msg_seq(row: dict[str, Any], fallback: int) -> int:
    raw = row.get("seq")
    if raw is None:
        raw = row.get("msg_id", row.get("id"))
    if raw is None:
        return fallback
    try:
        return int(raw)
    except (TypeError, ValueError):
        return fallback


def _resolve_board_path_and_rows(
    session: str = "",
    cwd: str = "",
    transcript_path: str = "",
) -> tuple[pathlib.Path | None, list[dict[str, Any]]]:
    candidates = _swarm_board_candidates(session=session, cwd=cwd, transcript_path=transcript_path)
    best_existing: pathlib.Path | None = None
    best_rows: list[dict[str, Any]] = []
    best_head = -1
    for cand in candidates:
        if cand.is_file():
            rows = rio.read_jsonl(cand)
            head = max(
                (_extract_msg_seq(r, idx) for idx, r in enumerate(rows, start=1) if isinstance(r, dict)),
                default=0,
            )
            if rows and head > best_head:
                best_existing = cand
                best_rows = rows
                best_head = head
            elif best_existing is None:
                best_existing = cand
                best_rows = rows
    if best_existing is not None:
        return best_existing, best_rows
    return (candidates[0] if candidates else None), []


def resolve_swarm_board_path(
    session: str = "",
    cwd: str = "",
    transcript_path: str = "",
) -> pathlib.Path | None:
    bp, _ = _resolve_board_path_and_rows(session=session, cwd=cwd, transcript_path=transcript_path)
    return bp


def load_swarm_board_messages(
    session: str = "",
    cwd: str = "",
    transcript_path: str = "",
    board_path: str | pathlib.Path | None = None,
) -> tuple[pathlib.Path | None, list[dict[str, Any]]]:
    if board_path:
        bp: pathlib.Path | None = pathlib.Path(board_path)
        if not bp.is_file():
            return bp, []
        rows = rio.read_jsonl(bp)
    else:
        bp, rows = _resolve_board_path_and_rows(session=session, cwd=cwd, transcript_path=transcript_path)
        if bp is None or not rows:
            return bp, []
    normalized: list[dict[str, Any]] = []
    for idx, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            continue
        item = dict(row)
        item["_seq"] = _extract_msg_seq(item, idx)
        normalized.append(item)
    return bp, normalized


def swarm_board_head_seq(
    session: str = "",
    cwd: str = "",
    transcript_path: str = "",
    board_path: str | pathlib.Path | None = None,
) -> int:
    _, msgs = load_swarm_board_messages(
        session=session,
        cwd=cwd,
        transcript_path=transcript_path,
        board_path=board_path,
    )
    return max((int(m.get("_seq") or 0) for m in msgs), default=0)


def ownership_manifest_path(cwd: str | pathlib.Path) -> pathlib.Path:
    p = pathlib.Path(str(cwd))
    if (p / ".swarm" / "ownership.json").is_file() or (p / ".git").exists():
        return p / ".swarm" / "ownership.json"
    root = rio.git_toplevel(str(cwd)) or str(cwd)
    return pathlib.Path(root) / ".swarm" / "ownership.json"


def load_ownership_manifest(cwd: str | pathlib.Path) -> dict[str, Any]:
    path = ownership_manifest_path(cwd)
    doc = rio.read_json(path, default=None)
    if not isinstance(doc, dict):
        return {"workers": {}}
    workers = doc.get("workers")
    if not isinstance(workers, dict):
        return {"workers": {}}
    return doc


def save_ownership_manifest(cwd: str | pathlib.Path, manifest: dict[str, Any]) -> tuple[bool, pathlib.Path]:
    path = ownership_manifest_path(cwd)
    return bool(rio.write_json(path, manifest)), path


def normalize_glob_pattern(pattern: str) -> str:
    p = str(pattern or "").strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    p = p.lstrip("/")
    while "//" in p:
        p = p.replace("//", "/")
    if p.endswith("/") and len(p) > 1:
        p = f"{p}**"
    return p


def _split_glob_segments(pattern: str) -> list[str]:
    norm = normalize_glob_pattern(pattern)
    if not norm:
        return []
    return [seg for seg in norm.split("/") if seg]


def _seg_patterns_intersect(p1: str, p2: str) -> bool:
    a, b = p1.lower(), p2.lower()
    if "[" in a or "[" in b:
        return True
    memo: dict[tuple[int, int], bool] = {}

    def _dp(i: int, j: int) -> bool:
        key = (i, j)
        if key in memo:
            return memo[key]
        res = False
        if i == len(a) and j == len(b):
            res = True
        elif i < len(a) and a[i] == "*":
            res = _dp(i + 1, j) or (j < len(b) and _dp(i, j + 1))
        elif j < len(b) and b[j] == "*":
            res = _dp(i, j + 1) or (i < len(a) and _dp(i + 1, j))
        elif i < len(a) and j < len(b):
            ca, cb = a[i], b[j]
            if ca == "?" or cb == "?" or ca == cb:
                res = _dp(i + 1, j + 1)
        memo[key] = res
        return res

    return _dp(0, 0)


def glob_matches_path(pattern: str, rel_path: str) -> bool:
    pat_segs = _split_glob_segments(pattern)
    rel_norm = normalize_glob_pattern(rel_path)
    if rel_norm.endswith("**"):
        rel_norm = rel_norm[:-2].rstrip("/")
    path_segs = [seg for seg in rel_norm.split("/") if seg]
    if not pat_segs or not path_segs:
        return False
    memo: dict[tuple[int, int], bool] = {}

    def _match(pi: int, si: int) -> bool:
        key = (pi, si)
        if key in memo:
            return memo[key]
        res = False
        if pi == len(pat_segs) and si == len(path_segs):
            res = True
        elif pi < len(pat_segs) and pat_segs[pi] == "**":
            res = _match(pi + 1, si) or (si < len(path_segs) and _match(pi, si + 1))
        elif pi < len(pat_segs) and si < len(path_segs):
            if fnmatch.fnmatchcase(path_segs[si].lower(), pat_segs[pi].lower()):
                res = _match(pi + 1, si + 1)
        memo[key] = res
        return res

    return _match(0, 0)


def globs_may_overlap(g1: str, g2: str, existing_files: list[str] | None = None) -> bool:
    s1 = _split_glob_segments(g1)
    s2 = _split_glob_segments(g2)
    if not s1 or not s2:
        return False
    memo: dict[tuple[int, int], bool] = {}

    def _dp(i: int, j: int) -> bool:
        key = (i, j)
        if key in memo:
            return memo[key]
        res = False
        if i == len(s1) and j == len(s2):
            res = True
        elif i < len(s1) and s1[i] == "**":
            res = _dp(i + 1, j) or (j < len(s2) and _dp(i, j + 1))
        elif j < len(s2) and s2[j] == "**":
            res = _dp(i, j + 1) or (i < len(s1) and _dp(i + 1, j))
        elif i < len(s1) and j < len(s2):
            if _seg_patterns_intersect(s1[i], s2[j]):
                res = _dp(i + 1, j + 1)
        memo[key] = res
        return res

    if _dp(0, 0):
        return True
    for rel in existing_files or ():
        if glob_matches_path(g1, rel) and glob_matches_path(g2, rel):
            return True
    return False


def _list_repo_rel_files(repo_root: str) -> list[str]:
    if not repo_root:
        return []
    out_files: set[str] = set()
    rc, tracked, _ = rio.run_git(repo_root, ["ls-files"])
    if rc == 0 and tracked:
        for ln in tracked.splitlines():
            norm = normalize_glob_pattern(ln)
            if norm and not norm.startswith(".swarm/"):
                out_files.add(norm)
    rc_u, untracked, _ = rio.run_git(repo_root, ["ls-files", "--others", "--exclude-standard"])
    if rc_u == 0 and untracked:
        for ln in untracked.splitlines():
            norm = normalize_glob_pattern(ln)
            if norm and not norm.startswith(".swarm/"):
                out_files.add(norm)
    return sorted(out_files)


def detect_ownership_overlaps(
    manifest: dict[str, Any],
    repo_root: str = "",
) -> list[dict[str, str]]:
    workers = manifest.get("workers") if isinstance(manifest, dict) else {}
    if not isinstance(workers, dict) or len(workers) < 2:
        return []
    existing_files = _list_repo_rel_files(repo_root) if repo_root else []
    names = sorted(workers.keys())
    conflicts: list[dict[str, str]] = []
    for idx, w1 in enumerate(names):
        p1_list = workers[w1].get("paths") if isinstance(workers[w1], dict) else []
        for w2 in names[idx + 1 :]:
            p2_list = workers[w2].get("paths") if isinstance(workers[w2], dict) else []
            for g1 in p1_list or []:
                for g2 in p2_list or []:
                    if globs_may_overlap(str(g1), str(g2), existing_files=existing_files):
                        conflicts.append(
                            {
                                "worker_a": w1,
                                "glob_a": str(g1),
                                "worker_b": w2,
                                "glob_b": str(g2),
                            }
                        )
    return conflicts


def resolve_repo_rel_info(file_path: str | pathlib.Path, repo_root: str | pathlib.Path) -> tuple[bool, str, str]:
    root_abs = pathlib.Path(repo_root).resolve()
    raw = str(file_path or "").strip()
    if not raw:
        return False, "", ""
    p = pathlib.Path(raw)
    if not p.is_absolute():
        p = root_abs / p
    try:
        resolved = p.resolve()
        rel = normalize_glob_pattern(resolved.relative_to(root_abs).as_posix())
        return True, rel, str(resolved)
    except ValueError:
        return False, normalize_glob_pattern(raw), raw


def resolve_repo_rel_path(file_path: str | pathlib.Path, repo_root: str | pathlib.Path) -> str:
    _, rel, _ = resolve_repo_rel_info(file_path, repo_root)
    return rel


def path_matches_any_glob(rel_path: str, globs: list[str]) -> bool:
    return any(glob_matches_path(g, rel_path) for g in globs if str(g).strip())


def detect_stalled_workers(
    members: dict[str, Any],
    board_messages: list[dict[str, Any]],
    cwd: str = "",
    brain_root: pathlib.Path | None = None,
    worker_last_activity: dict[str, float] | None = None,
    in_flight_names: list[str] | None = None,
    now_ts: float | None = None,
    timeout_sec: float | None = None,
) -> list[dict[str, Any]]:
    active_set = {
        str(x).split(":", 1)[-1]
        for x in (in_flight_names or [])
        if str(x).strip()
    }
    if in_flight_names is not None and not active_set:
        return []
    threshold = float(timeout_sec) if timeout_sec is not None else swarm_stall_timeout_sec()
    now = float(now_ts) if now_ts is not None else time.time()
    repo_root = ""
    if cwd:
        cwd_p = pathlib.Path(cwd)
        if (cwd_p / ".swarm").is_dir() or (cwd_p / ".git").exists():
            repo_root = cwd
        else:
            repo_root = rio.git_toplevel(cwd) or cwd
    artifacts_dir = (pathlib.Path(repo_root) / ".swarm" / "artifacts") if repo_root else None
    artifact_files = list(artifacts_dir.glob("*")) if (artifacts_dir and artifacts_dir.is_dir()) else []

    mention_pats_by_worker = {
        mname: rio.swarm_mention_patterns(mname, include_group=False)[0]
        for mname in (members or {})
    }
    board_ts_by_worker: dict[str, float] = {}
    coord_mention_by_worker: dict[str, float] = {}
    for msg in board_messages or []:
        if not isinstance(msg, dict):
            continue
        ts = rio.parse_iso_ts(msg.get("time") or msg.get("ts") or msg.get("created_at"))
        if ts <= 0.0:
            continue
        agent = str(msg.get("agent") or msg.get("worker") or "").strip()
        text = str(msg.get("text") or "")
        if agent == "coordinator":
            for mname, mp in mention_pats_by_worker.items():
                if mp.search(text):
                    coord_mention_by_worker[mname] = max(coord_mention_by_worker.get(mname, 0.0), ts)
        elif agent:
            board_ts_by_worker[agent] = max(board_ts_by_worker.get(agent, 0.0), ts)

    stalled: list[dict[str, Any]] = []
    for name, meta in sorted((members or {}).items()):
        if not isinstance(meta, dict):
            continue
        if rio.is_swarm_role_member(name, meta) or rio.is_swarm_member_killed(meta):
            continue
        already_replied = (
            coord_mention_by_worker.get(name, 0.0) > 0.0
            and board_ts_by_worker.get(name, 0.0) >= coord_mention_by_worker.get(name, 0.0)
        )
        if already_replied and name not in active_set:
            continue
        if in_flight_names is not None and name not in active_set:
            continue
        is_working_state = (
            name in active_set
            or str(meta.get("wake_mode") or "").lower() == "working"
            or str(meta.get("desired_state") or "").lower() == "working"
        )
        if not is_working_state:
            continue

        candidates_ts: list[float] = []
        if worker_last_activity and worker_last_activity.get(name, 0.0) > 0.0:
            candidates_ts.append(float(worker_last_activity[name]))
        if board_ts_by_worker.get(name, 0.0) > 0.0:
            candidates_ts.append(board_ts_by_worker[name])
        if coord_mention_by_worker.get(name, 0.0) > 0.0:
            candidates_ts.append(coord_mention_by_worker[name])
        for k in ("last_activity_ts", "assigned_ts", "updated_at", "started_at"):
            val = rio.parse_iso_ts(meta.get(k)) if not isinstance(meta.get(k), (int, float)) else float(meta.get(k) or 0.0)
            if val > 0.0:
                candidates_ts.append(val)

        cid = str(meta.get("conversation_id") or "").strip()
        if cid and brain_root is not None:
            tp = rio.member_transcript_path(brain_root, cid)
            if tp.exists():
                try:
                    candidates_ts.append(tp.stat().st_mtime)
                except OSError:
                    pass
        safe_name = rio.safe_key(name, name)
        for af in artifact_files:
            low_af = af.name.lower()
            if name.lower() in low_af or safe_name.lower() in low_af:
                try:
                    candidates_ts.append(af.stat().st_mtime)
                except OSError:
                    pass

        if not candidates_ts:
            continue
        last_act = max(candidates_ts)
        idle_sec = max(0.0, now - last_act)
        if idle_sec >= threshold:
            stalled.append(
                {
                    "worker": name,
                    "idle_sec": round(idle_sec, 1),
                    "timeout_sec": round(threshold, 1),
                    "last_activity_ts": last_act,
                    "cid": cid,
                }
            )
    return stalled


def is_simplify_subagent_call(sub_type: str, role: str = "") -> bool:
    base = (sub_type or "").strip().lower().rsplit(":", 1)[-1]
    if base in SIMPLIFY_AGENT_TYPES:
        return True
    return base in ("research", "self") and is_simplify_worker_name(role)


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


is_ephemeral_path = is_scratch_or_ephemeral


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


MAX_FINGERPRINT_FILE_BYTES = 32_000_000


def sha256_file_bounded(path: str, max_bytes: int = MAX_FINGERPRINT_FILE_BYTES) -> tuple[int, str] | None:
    # INVARIANT: Stream in 64 KiB chunks and re-enforce `max_bytes` on actual bytes read so concurrent growth cannot spike heap or bypass size bounds.
    with open(path, "rb") as fh:
        st = os.fstat(fh.fileno())
        if st.st_size > max_bytes:
            return None
        hasher = hashlib.sha256()
        total = 0
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                return None
            hasher.update(chunk)
    return total, hasher.hexdigest()


def content_fingerprint(paths: list[str], max_file_bytes: int = MAX_FINGERPRINT_FILE_BYTES) -> str | None:
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
            bounded = sha256_file_bounded(p, max_file_bytes)
            if bounded is None:
                return None
            blob_len, blob_hash = bounded
            hasher.update(f"BLOB:{blob_len}:{blob_hash}\0".encode("ascii"))
        except OSError:
            return None
    return hasher.hexdigest()


def trim_content_marks(marker: dict[str, Any], marks: list[dict[str, Any]]) -> None:
    if len(marks) > MAX_CONTENT_MARKS:
        evicted_last = marks[-MAX_CONTENT_MARKS - 1]
        ev_ts = float(evicted_last.get("ts") or 0.0) if isinstance(evicted_last, dict) else 0.0
        prev_ev = float(marker.get("marks_evicted_through_ts") or 0.0)
        if ev_ts > prev_ev:
            marker["marks_evicted_through_ts"] = ev_ts
        marker["content_marks"] = marks[-MAX_CONTENT_MARKS:]
    else:
        marker["content_marks"] = marks


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
            parts.append(f"simplify on `{SONNET_HIGH_MODEL}` (fallback `{SIMPLIFY_FALLBACK_MODEL}`)")
        if pol.get("require_review_on_standard"):
            parts.append("independent APPROVED review")
        return " + ".join(parts)
    if floor == "HIGH":
        return (
            f"decisive test/check execution -> primary independent APPROVED review (`codex_lane.py` -> `{OPUS_HIGH_MODEL}` -> `{CARBON_HIGH_MODEL}`) -> "
            f"simplify once (`SIMPLIFY_LENS: ALL` fast-path if <=2 files & <=30 lines, else 3 separate lenses on `{SONNET_HIGH_MODEL}`, fallback `{SIMPLIFY_FALLBACK_MODEL}`) -> "
            f"batch kill workers -> final `--closure` check"
        )
    return (
        f"decisive test/check execution -> primary XHIGH APPROVED review (`codex_lane.py --xhigh` -> `{OPUS_HIGH_MODEL}` -> `{CARBON_HIGH_MODEL}`) -> "
        f"simplify once (`SIMPLIFY_LENS: ALL` fast-path if <=2 files & <=30 lines, else 3 separate lenses on `{SONNET_HIGH_MODEL}`, fallback `{SIMPLIFY_FALLBACK_MODEL}`) -> "
        f"batch kill workers -> final `--closure` check"
    )
