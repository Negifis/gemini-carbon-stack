#!/usr/bin/env python3
"""Code Work Gate PreToolUse & PostToolUse marker for Google Antigravity 2.0."""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import stat
import sys
import time
import uuid
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import codex_lane
import cwg_common as cwg
import runtime_io as rio

EDIT_TOOLS = frozenset({"edit_file", "write_file"})
SHELL_TOOLS = frozenset({"run_command"})

CACHE_PATH_RE = re.compile(
    r"(^|/)(__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.coverage|node_modules/\.cache|\.swarm)(/|$)|\.pyc$",
    re.IGNORECASE,
)

def _exe_pat(names_pat: str, ext_pat: str = r"(?:\.exe)?", allow_dq_vars: bool = False) -> str:
    # INVARIANT: Allow quoted/path-qualified Windows executables while keeping `dq_char` branches disjoint (O(N)) and blocking `$`/backticks on allowlists.
    dq_char = r'(?:`[^\r\n]|""|[^"`\r\n])' if allow_dq_vars else r'[^"`$\r\n]'
    dq_sep = r"`?[/\\]" if allow_dq_vars else r"[/\\]"
    return (
        r"(?:"
        rf"'(?:(?:''|[^'\r\n])*[/\\])?(?:{names_pat}){ext_pat}'(?=$|[\s|;&])"
        rf'|"(?:{dq_char}*{dq_sep})?(?:{names_pat}){ext_pat}"(?=$|[\s|;&])'
        rf"|(?:[^\s|;&\"'`$()\r\n]*[/\\])?(?:{names_pat}){ext_pat}(?![\w.-])"
        r")"
    )


def _py_interp_pat(allow_dq_vars: bool = False) -> str:
    py_tok = _exe_pat(r"python(?:\d+(?:\.\d+)?)?", allow_dq_vars=allow_dq_vars)
    launcher_tok = _exe_pat("py", allow_dq_vars=allow_dq_vars)
    return rf"(?:{py_tok}|{launcher_tok}(?:\s+-3(?:\.\d+)?)?)"


_EXT_PY = r"\.py"
_EXT_CMD_EXE = r"(?:\.cmd|\.exe)?"
_PY_INTERP_PAT = _py_interp_pat()
_PY_MUT_INTERP_PAT = _py_interp_pat(allow_dq_vars=True)
_PY_SAFE_FLAGS_PAT = r"(?:-(?:X\s+utf8|[uBEsSO])\s+)*"
_PY_ANY_FLAGS_PAT = r"(?:-(?:X\s+(?!-\w+\s)\S+|\w+)\s+)*"
_PY_MUT_CLAUSE_PREFIX = (
    rf"^\s*(?:\$[A-Za-z_]\w*\s*=\s*)?(?:\$null\s*\|\s*)?(?:&\s*)?{_PY_MUT_INTERP_PAT}\s+{_PY_ANY_FLAGS_PAT}"
)
_INSTALL_DIAG_TAIL = r"[^\r\n|;&]*(?<!\S)(?:--diagnose|--dry-run)(?=$|[\s|;&])"
_WT_MUT_TAIL = r"[^\r\n;|&]*\b(?:snapshot|remove|restore)\b"
_CHIP_MUT_TAIL = r"[^\r\n;|&]*--merge\b"

_BK_SCRIPTS_TOK = _exe_pat("carbon_memory|gate_inbox|chip_handoff|swarm_cache|swarm_ctl", _EXT_PY)
_CONTINUITY_TOK = _exe_pat("continuity", _EXT_PY)
_CODEX_LANE_TOK = _exe_pat("codex_lane", _EXT_PY)
_GIT_TOK = _exe_pat("git")
_RG_TOK = _exe_pat("rg")
_CODEX_TOK = _exe_pat("codex", _EXT_CMD_EXE)
_AGY_TOK = _exe_pat("agy", _EXT_CMD_EXE)
_TOKENADE_TOK = _exe_pat("tokenade", _EXT_CMD_EXE)
_RO_SCRIPTS_TOK = _exe_pat("code_search|stack_doctor", _EXT_PY)
_WT_GUARD_TOK = _exe_pat("worktree_guard", _EXT_PY)
_WT_GUARD_MUT_TOK = _exe_pat("worktree_guard", _EXT_PY, allow_dq_vars=True)
_CHIP_MUT_TOK = _exe_pat("chip_handoff", _EXT_PY, allow_dq_vars=True)
_INSTALL_TOK = _exe_pat("install", _EXT_PY)
_INSTALL_MUT_TOK = _exe_pat("install", _EXT_PY, allow_dq_vars=True)
_RUNNERS_TOK = _exe_pat(r"pytest|py\.test|mypy|flake8")
_RUFF_TOK = _exe_pat("ruff")

BOOKKEEPING_CMD_RE = re.compile(
    rf"^\s*(?:\$null\s*\|\s*)?(?:&\s*)?{_PY_INTERP_PAT}\s+{_PY_SAFE_FLAGS_PAT}"
    rf"(?:{_BK_SCRIPTS_TOK}|{_CONTINUITY_TOK}\s+(?:checkpoint|show|handoff)\b|{_CODEX_LANE_TOK}\s+(?:check|status|reset|review)\b)"
    r"(?:\s+[^|;&\r\n]*)?$",
    re.IGNORECASE,
)

NAV_SEGMENT_RE = re.compile(
    r"^\s*(?:cd|chdir|Set-Location|sl|Push-Location|pushd|Pop-Location|popd)\b(?:\s+[^|;&\r\n]*)?$",
    re.IGNORECASE,
)

PS_SAFE_FILTER_RE = re.compile(
    r"^\s*(?:Select-Object|select|Where-Object|where|Measure-Object|measure|Sort-Object|sort|"
    r"Format-Table|ft|Format-List|fl|Out-String|ConvertFrom-Json|ConvertTo-Json|Get-Unique)\b(?:\s+[^|;&\r\n]*)?$",
    re.IGNORECASE,
)

READ_ONLY_CMD_RE = re.compile(
    r"^\s*(?:\$null\s*\|\s*)?(?:"
    r"(?:"
    rf"(?:&\s*)?{_GIT_TOK}\s+(?:--no-pager\s+)?(?:-C\s+[\"']?[^\"'|;&\r\n]+[\"']?\s+)?(?:status|diff|log|show|rev-parse|ls-files|ls-tree|check-ignore|remote\s+-v|worktree\s+list)"
    rf"|(?:&\s*)?{_RG_TOK}"
    r"|findstr(?:\.exe)?\b"
    r"|where(?:\.exe)?\b"
    r"|Get-ChildItem\b|gci\b|Get-Content\b|gc\b|Select-String\b|sls\b|Get-Command\b|gcm\b|Test-Path\b|Get-Item\b|gi\b"
    r"|Get-ItemProperty\b|gp\b|Get-ItemPropertyValue\b|gpv\b|Get-CimInstance\b|gcim\b|Get-WmiObject\b|gwmi\b"
    r"|Get-WinEvent\b|Get-EventLog\b|Get-Process\b|gps\b|Get-Service\b|gsv\b|Get-Location\b|gl\b|Write-Output\b"
    rf"|(?:&\s*)?{_CODEX_TOK}\s+(?:--version|login\s+status|exec\b[^|;&\r\n]*-s\s+read-only\b)"
    rf"|(?:&\s*)?{_AGY_TOK}\s+(?:--help|--version|plugin\s+(?:list|help)|mcp\s+(?:list|help)|models\b)"
    rf"|(?:&\s*)?{_TOKENADE_TOK}\s+(?:--version|--help|help|map|query|skeleton|semantic|ask|sem|impact|expand-ref|gain|dashboard|healthcheck|detect|measure|statusline)\b"
    rf"|(?:&\s*)?{_PY_INTERP_PAT}\s+{_PY_SAFE_FLAGS_PAT}(?:{_RO_SCRIPTS_TOK}|{_WT_GUARD_TOK}\s+(?:audit|status)\b)"
    r")(?:\s+[^|;&\r\n]*)?"
    rf"|(?:&\s*)?{_GIT_TOK}\s+(?:--no-pager\s+)?(?:-C\s+[\"']?[^\"'|;&\r\n]+[\"']?\s+)?branch(?:\s+(?:--list|-l|-a|--all|-r|--remotes|-v|-vv|--show-current|--no-color))*"
    r")$",
    re.IGNORECASE,
)

VALIDATION_SEGMENT_RE = re.compile(
    r"^\s*(?:\$null\s*\|\s*)?(?:&\s*)?(?:"
    rf"{_RUNNERS_TOK}"
    rf"|{_RUFF_TOK}\s+check\b"
    rf"|{_PY_INTERP_PAT}\s+{_PY_SAFE_FLAGS_PAT}(?:-m\s+(?:pytest|unittest|py_compile|compileall|mypy|ruff|flake8)\b|{_INSTALL_TOK}\s+{_INSTALL_DIAG_TAIL})"
    r"|npm(?:\.cmd)?\s+(?:test|run\s+(?:test|lint|build|typecheck|check))\b"
    r"|pnpm(?:\.cmd)?\s+(?:test|lint|build|typecheck)\b"
    r"|yarn(?:\.cmd)?\s+(?:test|lint|build|typecheck)\b"
    r"|npx(?:\.cmd)?\s+(?:tsc|vitest|jest|eslint|playwright\s+test)\b"
    r"|cargo(?:\.exe)?\s+(?:test|check|clippy)\b"
    r"|go(?:\.exe)?\s+(?:test|vet)\b"
    r"|dotnet(?:\.exe)?\s+(?:test|build)\b"
    rf"|{_AGY_TOK}\s+plugin\s+validate\b"
    r")",
    re.IGNORECASE,
)

MUTATING_CMDLET_RE = re.compile(
    r"(?:^|[;|&({\s])(?:Set-Content|sc|Add-Content|ac|Out-File|Export-Csv|Export-Clixml|"
    r"Remove-Item|ri|rm|del|erase|Move-Item|mi|mv|Copy-Item|ci|cp|New-Item|ni|mkdir|md|"
    r"Rename-Item|rni|ren|Clear-Content|clc|Tee-Object|rmdir|rd|touch|chmod|chown|mklink|"
    r"Expand-Archive|Compress-Archive|expand(?:\.exe)?|robocopy(?:\.exe)?|xcopy(?:\.exe)?)\b",
    re.IGNORECASE,
)

MUTATING_GIT_RE = re.compile(
    r"\bgit(?:\.exe)?[^\S\r\n]+(?:--no-pager[^\S\r\n]+)?(?:-C[^\S\r\n]+\S+[^\S\r\n]+)?"
    r"(?:(?:add|commit|checkout|restore|reset|clean|merge|rebase|cherry-pick|stash|apply|am|"
    r"rm|mv|init|clone|pull|push|fetch|worktree[^\S\r\n]+(?:add|remove|prune)|tag[^\S\r\n]+-d)\b"
    r"|branch[^\S\r\n]+(?:(?:-[A-Za-z]*[fFdDmMcC]|--force|--delete|--move|--copy|--set-upstream-to|--unset-upstream)\b|[^-\s|;&\r\n]))",
    re.IGNORECASE,
)

MUTATING_PKG_RE = re.compile(
    r"\b(?:pip|pip3|uv\s+pip|npm|pnpm|yarn|cargo|poetry)\b[^\r\n;|&]*"
    r"\b(?:install|uninstall|add|remove|upgrade|publish)\b",
    re.IGNORECASE,
)

MUTATING_STACK_RE = re.compile(
    rf"(?:\bworktree_guard\.py\b{_WT_MUT_TAIL}|\bchip_handoff\.py\b{_CHIP_MUT_TAIL})",
    re.IGNORECASE,
)

MUTATING_STACK_SEG_RE = re.compile(
    rf"{_PY_MUT_CLAUSE_PREFIX}(?:{_WT_GUARD_MUT_TOK}{_WT_MUT_TAIL}|{_CHIP_MUT_TOK}{_CHIP_MUT_TAIL})",
    re.IGNORECASE,
)

INSTALL_PY_RE = re.compile(
    rf"{_PY_MUT_CLAUSE_PREFIX}{_INSTALL_MUT_TOK}(?!{_INSTALL_DIAG_TAIL})",
    re.IGNORECASE,
)

SYSTEM_OR_NET_MUTATING_RE = re.compile(
    r"(?:"
    r"\b(?:Stop-Service|Start-Service|Restart-Service|Set-Service|New-Service|Suspend-Service|Resume-Service|"
    r"Stop-Process|spps|taskkill|Register-ScheduledTask|Unregister-ScheduledTask|Set-ScheduledTask|Start-ScheduledTask|"
    r"Set-ItemProperty|sp|New-ItemProperty|Remove-ItemProperty|rp|Rename-ItemProperty|rnp|Clear-ItemProperty|clp|Set-Item|"
    r"Invoke-CimMethod|Invoke-WmiMethod|Invoke-Command|icm|Invoke-Expression|iex|Start-Process|saps|"
    r"bcdedit|diskpart|pnputil|sfc|takeown|icacls|setx|msiexec|cscript|wscript)\b"
    r"|\bschtasks(?:\.exe)?\s+/(?:create|delete|change|run|end)\b"
    r"|\bsc(?:\.exe)?\s+(?:stop|start|pause|continue|control|sdset|config|create|delete|failure)\b"
    r"|\bnet(?:\.exe)?\s+(?:stop|start|user|localgroup|share|use)\b"
    r"|\breg(?:\.exe)?\s+(?:add|delete|import|restore|load|unload|copy)\b"
    r"|\bdism(?:\.exe)?\b[^\r\n;|&]*/(?:online|cleanup-image|enable-feature|disable-feature|add-package|remove-package|restorehealth)\b"
    r"|\[Environment\]::SetEnvironmentVariable"
    r"|\[(?:System\.)?IO\.(?:File|Directory)\]::(?:Write|Append|Delete|Copy|Move|Create|Replace|OpenWrite)"
    r"|\bNew-Object\b[^\r\n;|&]*\bNet\.WebClient\b"
    r"|\b(?:ssh|scp|rsync|sftp)\b"
    r")",
    re.IGNORECASE,
)

HTTP_CMD_RE = re.compile(
    r"\b(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm|curl(?:\.exe)?|wget(?:\.exe)?)\b",
    re.IGNORECASE,
)
HTTP_MUTATING_RE = re.compile(
    r"(?:"
    r"-Method\s+[\"']?(?!GET\b|HEAD\b)[A-Za-z]+"
    r"|-(?:OutFile|Body|InFile|Form)\b"
    r"|(?:--method(?:=|\s+)|-X\s*|--request(?:=|\s+))[\"']?(?!GET\b|HEAD\b)[A-Za-z]+"
    r"|(?:\s|^)(?:-d|--data|--data-raw|--data-binary|--post-data|--post-file|--form|-F|--upload-file|-T|-O|--remote-name)\b"
    r")",
    re.IGNORECASE,
)

INLINE_PY_RE = re.compile(
    rf"(?:^|[;&|({{\s]){_PY_MUT_INTERP_PAT}\s+{_PY_ANY_FLAGS_PAT}-c\b",
    re.IGNORECASE,
)
INLINE_PY_WRITE_RE = re.compile(
    r"\.write(?:_text|_bytes|lines)?\b|open\s*\(|\b(?:unlink|remove|rename|replace|rmdir|shutil|subprocess|os\.system|"
    r"urllib|http\.client|requests|httpx|socket|winreg|ctypes|sqlite3|runpy)\b|\.(?:mkdir|makedirs|touch)\s*\(",
    re.IGNORECASE,
)


def _strip_null_pipe(cmd: str) -> str:
    return rio.unwrap_tokenade_command(cmd)


_PS_DQ_PAT = r'"(?:`[\s\S]|""|[^"`])*"'
_PS_SQ_PAT = r"'(?:''|[^'])*'"
_PS_QUOTED_RE = re.compile(f"{_PS_DQ_PAT}|({_PS_SQ_PAT})")


def _strip_single_quoted(text: str) -> str:
    # INVARIANT: Match PowerShell double-quoted strings first so apostrophes inside "..." never pair as '...'.
    return _PS_QUOTED_RE.sub(lambda m: "''" if m.group(1) is not None else m.group(0), text)


def _strip_quoted(text: str) -> str:
    # INVARIANT: In Windows PowerShell 5.1 double quotes escape ONLY via backtick (`.) or doubled quote (""), never backslash (\).
    return _PS_QUOTED_RE.sub('""', text)


def _extract_ps_subexprs(text: str) -> list[str]:
    # SAFETY: Extract all unescaped PowerShell $(...) bodies (including inside "..." and @"..."@) in linear O(N) time.
    if "$(" not in text:
        return []
    out: list[str] = []
    modes: list[str] = []
    subs: list[list[Any]] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        mode = modes[-1] if modes else "top"
        if mode == "hsq":
            if ch == "'" and i > 0 and text[i - 1] in ("\n", "\r") and i + 1 < n and text[i + 1] == "@":
                if subs:
                    subs[-1][1].append("'@")
                modes.pop()
                i += 2
                continue
            if subs:
                subs[-1][1].append(ch)
            i += 1
            continue
        if mode == "hdq":
            if ch == "`" and i + 1 < n:
                if subs:
                    subs[-1][1].append(text[i : i + 2])
                i += 2
                continue
            if ch == "$" and i + 1 < n and text[i + 1] == "(":
                modes.append("sub")
                subs.append([1, []])
                i += 2
                continue
            if ch == '"' and i > 0 and text[i - 1] in ("\n", "\r") and i + 1 < n and text[i + 1] == "@":
                if subs:
                    subs[-1][1].append('"@')
                modes.pop()
                i += 2
                continue
            if subs:
                subs[-1][1].append(ch)
            i += 1
            continue
        if mode == "sq":
            if ch == "'" and i + 1 < n and text[i + 1] == "'":
                if subs:
                    subs[-1][1].append("''")
                i += 2
                continue
            if subs:
                subs[-1][1].append(ch)
            if ch == "'":
                modes.pop()
            i += 1
            continue
        if mode == "dq":
            if (ch == "`" and i + 1 < n) or (ch == '"' and i + 1 < n and text[i + 1] == '"'):
                if subs:
                    subs[-1][1].append(text[i : i + 2])
                i += 2
                continue
            if ch == "$" and i + 1 < n and text[i + 1] == "(":
                modes.append("sub")
                subs.append([1, []])
                i += 2
                continue
            if subs:
                subs[-1][1].append(ch)
            if ch == '"':
                modes.pop()
            i += 1
            continue
        if ch == "`" and i + 1 < n:
            if subs:
                subs[-1][1].append(text[i : i + 2])
            i += 2
            continue
        if ch == "$" and i + 1 < n and text[i + 1] == "(":
            if subs:
                subs[-1][1].append(' "" ')
            modes.append("sub")
            subs.append([1, []])
            i += 2
            continue
        if ch == "@" and i + 2 < n and text[i + 1] in ("'", '"'):
            nl_len = 1 if text[i + 2] == "\n" else (2 if text[i + 2] == "\r" and i + 3 < n and text[i + 3] == "\n" else 0)
            if nl_len:
                if subs:
                    subs[-1][1].append(text[i : i + 2 + nl_len])
                modes.append("hsq" if text[i + 1] == "'" else "hdq")
                i += 2 + nl_len
                continue
        if ch in ("'", '"'):
            if subs:
                subs[-1][1].append(ch)
            modes.append("sq" if ch == "'" else "dq")
            i += 1
            continue
        if mode == "sub":
            if ch == "(":
                subs[-1][0] += 1
                subs[-1][1].append("(")
                i += 1
                continue
            if ch == ")":
                if subs[-1][0] > 1:
                    subs[-1][0] -= 1
                    subs[-1][1].append(")")
                else:
                    modes.pop()
                    body = "".join(subs.pop()[1]).strip()
                    if body:
                        out.append(body)
                i += 1
                continue
            subs[-1][1].append(ch)
        i += 1
    while subs:
        body = "".join(subs.pop()[1]).strip()
        if body:
            out.append(body)
    return out


def _split_shell_segments(core: str, split_subclauses: bool = False) -> list[tuple[str, str]]:
    """Split pre-stripped command text on top-level `;`, newline, `&&`, `||`, and `|` preserving PS quote boundaries."""
    parts: list[tuple[str, str]] = []
    cur: list[str] = []
    quote: str | None = None
    prev_op = ""
    one_char_seps = (";", "\n", "\r", "|", "(", ")", "{", "}") if split_subclauses else (";", "\n", "\r", "|")
    i = 0
    n = len(core)
    while i < n:
        ch = core[i]
        if quote:
            cur.append(ch)
            if quote == "'" and ch == "'" and i + 1 < n and core[i + 1] == "'":
                cur.append(core[i + 1])
                i += 2
                continue
            if quote == '"' and (
                (ch == "`" and i + 1 < n) or (ch == '"' and i + 1 < n and core[i + 1] == '"')
            ):
                cur.append(core[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ('"', "'"):
            quote = ch
            cur.append(ch)
            i += 1
            continue
        sep_len = 0
        next_op = ";"
        if ch in ("&", "|") and i + 1 < n and core[i + 1] == ch:
            sep_len = 2
            next_op = ch * 2
        elif split_subclauses and ch == "$" and i + 1 < n and core[i + 1] == "(":
            sep_len = 2
        elif ch in one_char_seps:
            sep_len = 1
            next_op = "|" if ch == "|" else ";"
        if sep_len:
            seg = "".join(cur).strip()
            if seg:
                parts.append((prev_op, seg))
            prev_op = next_op
            cur = []
            i += sep_len
            continue
        cur.append(ch)
        i += 1
    tail = "".join(cur).strip()
    if tail:
        parts.append((prev_op, tail))
    return parts


def _split_ps_clauses(core: str) -> list[str]:
    return [seg for _, seg in _split_shell_segments(core, split_subclauses=True)]


def _all_ps_clauses(core: str, subexprs: list[str] | None = None) -> list[str]:
    subs = _extract_ps_subexprs(core) if subexprs is None else subexprs
    clauses = _split_ps_clauses(core)
    for sub in subs:
        clauses.extend(_split_ps_clauses(sub))
    return clauses


_OUTPUT_FLAG_RE = re.compile(r"(?:^|\s)(?:--output(?:=|\s)|-o(?:\s|$)|-outfile(?:\s|$))", re.IGNORECASE)


def _shell_scan_surfaces(
    core: str,
    no_single: str,
    unquoted: str,
    subexprs: list[str] | None = None,
) -> tuple[str, str, str]:
    subs = _extract_ps_subexprs(core) if subexprs is None else subexprs
    if not subs:
        return unquoted, unquoted, no_single
    sub_raw = " ; ".join(subs)
    sub_no_single = _strip_single_quoted(sub_raw)
    sub_unquoted = _strip_quoted(sub_raw)
    return (
        f"{unquoted} {sub_unquoted}".strip(),
        f"{unquoted} {sub_no_single}".strip(),
        f"{no_single} {sub_no_single}".strip(),
    )


def _has_non_cmdlet_mutation(
    core: str,
    unquoted_surface: str,
    scan_surface: str,
    no_single_surface: str,
    subexprs: list[str] | None = None,
) -> bool:
    if HTTP_CMD_RE.search(unquoted_surface) and HTTP_MUTATING_RE.search(core):
        return True
    if (
        MUTATING_GIT_RE.search(scan_surface)
        or MUTATING_PKG_RE.search(scan_surface)
        or MUTATING_STACK_RE.search(scan_surface)
        or SYSTEM_OR_NET_MUTATING_RE.search(no_single_surface)
    ):
        return True
    low_core = core.lower()
    if not any(k in low_core for k in ("install.py", "worktree_guard.py", "chip_handoff.py")):
        return False
    # INVARIANT: Match quoted script paths (`install.py`, `worktree_guard.py`, `chip_handoff.py`) on raw clauses before `_strip_quoted` erases `'...'`.
    return any(INSTALL_PY_RE.match(cl) or MUTATING_STACK_SEG_RE.match(cl) for cl in _all_ps_clauses(core, subexprs))


def _has_output_flag(seg: str, seg_unq: str) -> bool:
    return not VALIDATION_SEGMENT_RE.match(seg) and bool(_OUTPUT_FLAG_RE.search(seg_unq))


def _has_mutating_shell_pattern(
    core: str,
    segments: list[tuple[str, str]],
    no_single: str,
    unquoted: str,
    subexprs: list[str] | None = None,
) -> bool:
    if INLINE_PY_RE.search(core) and INLINE_PY_WRITE_RE.search(core):
        return True
    subs = _extract_ps_subexprs(core) if subexprs is None else subexprs
    unquoted_surface, scan_surface, no_single_surface = _shell_scan_surfaces(core, no_single, unquoted, subs)
    has_file_redirect = bool(
        re.search(r"(?<!>)>>?(?!>)\s*(?!\$null\b|nul\b|/dev/null\b|&[1-6]\b)\S+", unquoted_surface, re.IGNORECASE)
    )
    if (
        has_file_redirect
        or MUTATING_CMDLET_RE.search(scan_surface)
        or _has_non_cmdlet_mutation(core, unquoted_surface, scan_surface, no_single_surface, subs)
    ):
        return True
    all_segs = [seg for _, seg in segments]
    for sub in subs:
        all_segs.extend(_split_ps_clauses(sub))
    for seg in all_segs:
        if _has_output_flag(seg, _strip_quoted(seg)):
            return True
    return False


def _is_bookkeeping_segment(seg: str) -> bool:
    low = seg.lower()
    return "--merge" not in low and "--mirror-workspace" not in low and bool(BOOKKEEPING_CMD_RE.match(seg))


def _classify_non_mutating_segments(segments: list[tuple[str, str]]) -> str:
    if not segments:
        return "READ_ONLY"
    val_count = 0
    last_val_idx = -1
    saw_bookkeeping = False
    has_or_chain = False
    n_segs = len(segments)
    for idx, (op, seg) in enumerate(segments):
        if op == "||":
            has_or_chain = True
        if op in ("", ";", "&&") and seg.strip().lower() == "$null" and idx + 1 < n_segs and segments[idx + 1][0] == "|":
            continue
        if idx > 0 and op == "|" and PS_SAFE_FILTER_RE.match(seg):
            continue
        if _is_bookkeeping_segment(seg):
            saw_bookkeeping = True
            continue
        if VALIDATION_SEGMENT_RE.match(seg):
            is_null_pipe = (
                op == "|"
                and idx > 0
                and segments[idx - 1][0] in ("", ";", "&&")
                and segments[idx - 1][1].strip().lower() == "$null"
            )
            if op not in ("", ";", "&&") and not is_null_pipe:
                return "UNCERTAIN"
            val_count += 1
            last_val_idx = idx
            continue
        if READ_ONLY_CMD_RE.match(seg) or NAV_SEGMENT_RE.match(seg):
            continue
        return "UNCERTAIN"
    if val_count:
        # SAFETY: Conditional `||`, trailing segments/pipes, or multiple runners can skip or mask a test exit code.
        return "VALIDATION" if (not has_or_chain and val_count == 1 and last_val_idx == n_segs - 1) else "UNCERTAIN"
    if saw_bookkeeping:
        return "BOOKKEEPING"
    return "READ_ONLY"


def _has_validation_segment(cmd: str) -> bool:
    core = _strip_null_pipe(cmd)
    return bool(core) and any(VALIDATION_SEGMENT_RE.match(seg) for _, seg in _split_shell_segments(core))


def classify_shell_command(cmd: str) -> str:
    """Conservatively classify PowerShell command into READ_ONLY, BOOKKEEPING, VALIDATION, UNCERTAIN, or MUTATING."""
    core = _strip_null_pipe(cmd)
    if not core:
        return "READ_ONLY"

    no_single = _strip_single_quoted(core)
    unquoted = _strip_quoted(core)
    segments = _split_shell_segments(core)
    subexprs = _extract_ps_subexprs(core)
    if _has_mutating_shell_pattern(core, segments, no_single, unquoted, subexprs):
        return "MUTATING"

    has_dynamic_syntax = (
        bool(INLINE_PY_RE.search(core))
        or bool(subexprs)
        or "(" in unquoted
        or ")" in unquoted
        or "{" in unquoted
        or "}" in unquoted
        or "`" in unquoted
        or bool(re.search(r"(?:^|\s)--pre(?:=|\s|$)", unquoted, re.IGNORECASE))
    )
    if has_dynamic_syntax:
        return "UNCERTAIN"

    return _classify_non_mutating_segments(segments)


def resolve_command_cwd(cmd: str, default_cwd: str, session: str = "") -> str:
    fallback_root = ""
    if session:
        existing = rio.read_json(cwg.marker_path(session), default=None)
        if isinstance(existing, dict) and not existing.get("closed"):
            fallback_root = str(existing.get("git_root") or "")
    return rio.resolve_command_cwd(cmd, default_cwd, fallback_dir=fallback_root)


NON_GIT_SCAN_MAX_FILES = 400
NON_GIT_SCAN_MAX_DEPTH = 4
NON_GIT_SKIP_DIRS = frozenset(
    {".git", ".gemini", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv", "venv"}
)


MAX_HASHED_SNAPSHOT_BYTES = 2_000_000


def _file_entry_token(
    full: str, prefix: str = "", stat_result: os.stat_result | None = None
) -> str:
    try:
        st = stat_result if stat_result is not None else os.lstat(full)
        if stat.S_ISLNK(st.st_mode) or getattr(st, "st_reparse_tag", 0) != 0:
            return f"{prefix}link:{st.st_size}:{st.st_mtime_ns}"
        if not stat.S_ISREG(st.st_mode):
            return f"{prefix}dir:{st.st_mtime_ns}"
        if st.st_size <= MAX_HASHED_SNAPSHOT_BYTES:
            with open(full, "rb") as fh:
                digest = hashlib.sha256(fh.read()).hexdigest()[:20]
            return f"{prefix}{st.st_size}:{digest}"
        return f"{prefix}large:{st.st_size}:{st.st_mtime_ns}"
    except FileNotFoundError:
        return f"{prefix}absent"
    except OSError:
        return f"{prefix}stat_err"


def _scan_non_git_snapshot(cwd: str) -> dict[str, Any]:
    norm_cwd = rio.normalize_path(cwd)

    def _unmeasured() -> dict[str, Any]:
        return {"in_git": False, "cwd": norm_cwd, "unmeasured": True}

    if not cwd or not os.path.isdir(cwd):
        return _unmeasured()

    abs_cwd = os.path.abspath(cwd)
    prefix_len = len(abs_cwd) if abs_cwd.endswith(("\\", "/")) else len(abs_cwd) + 1
    candidates: list[tuple[str, os.stat_result]] = []
    stack: list[tuple[str, int]] = [(abs_cwd, 0)]
    try:
        # INVARIANT: Enforce NON_GIT_SCAN_MAX_FILES before reading/hashing any file bytes, and mark truncated depth unmeasured.
        while stack:
            cur_dir, depth = stack.pop()
            with os.scandir(cur_dir) as it:
                for ent in it:
                    is_junction = getattr(ent, "is_junction", None)
                    if ent.is_symlink() or (callable(is_junction) and is_junction()):
                        continue
                    name = ent.name
                    if ent.is_dir(follow_symlinks=False):
                        if name in NON_GIT_SKIP_DIRS:
                            continue
                        if depth >= NON_GIT_SCAN_MAX_DEPTH:
                            return _unmeasured()
                        stack.append((ent.path, depth + 1))
                    elif ent.is_file(follow_symlinks=False):
                        rel = ent.path[prefix_len:].replace("\\", "/")
                        if CACHE_PATH_RE.search(rel):
                            continue
                        if len(candidates) >= NON_GIT_SCAN_MAX_FILES:
                            return _unmeasured()
                        candidates.append((ent.path, ent.stat(follow_symlinks=False)))
        entries = {
            rio.normalize_path(fpath): _file_entry_token(fpath, prefix="F:", stat_result=st)
            for fpath, st in candidates
        }
    except OSError:
        return _unmeasured()
    return {"in_git": False, "cwd": norm_cwd, "entries": entries, "unmeasured": False}


def _in_explicit_workspaces(path: str, workspace_paths: list[str] | None) -> bool:
    if not path or not workspace_paths:
        return False
    folded = rio.fold_path(path)
    for wp in workspace_paths:
        if isinstance(wp, str) and wp.strip():
            fwp = rio.fold_path(wp)
            if fwp and (folded == fwp or folded.startswith(fwp + "/")):
                return True
    return False


def take_git_snapshot(
    cwd: str,
    artifact_dir: str | None = None,
    workspace_paths: list[str] | None = None,
    known_git_root: str | None = None,
) -> dict[str, Any]:
    if not cwd or (rio.is_plugin_runtime_dir(cwd) and not _in_explicit_workspaces(cwd, workspace_paths)):
        # INVARIANT: Never treat or scan the installed plugin bundle directory as a fallback user project.
        return {"in_git": False, "cwd": "", "entries": {}, "unmeasured": False, "no_project": True}
    if cwg.is_session_scratch_path(cwd, artifact_dir=artifact_dir, workspace_paths=workspace_paths):
        return {
            "in_git": False,
            "cwd": rio.normalize_path(cwd),
            "entries": {},
            "unmeasured": False,
            "ephemeral_cwd": True,
        }
    if known_git_root is not None:
        root = known_git_root if (known_git_root and (pathlib.Path(known_git_root) / ".git").exists()) else rio.git_toplevel(cwd)
    else:
        root = rio.git_toplevel(cwd)
    if not root:
        return _scan_non_git_snapshot(cwd)
    rc_h, head_out, _ = rio.run_git(root, ["rev-parse", "--verify", "-q", "HEAD"], timeout=3.0)
    head = head_out.strip() if rc_h == 0 and isinstance(head_out, str) else ""
    rc_s, status_bytes, _ = rio.run_git(
        root, ["status", "--porcelain=v1", "-z", "-uall"], timeout=5.0, text=False
    )
    if rc_s != 0 or not isinstance(status_bytes, (bytes, bytearray)):
        return {"in_git": True, "root": rio.normalize_path(root), "head": head, "unmeasured": True}

    entries: dict[str, str] = {}
    records = bytes(status_bytes).split(b"\0")
    i = 0
    while i < len(records):
        rec = records[i]
        i += 1
        if len(rec) < 4:
            continue
        xy = rec[:2].decode("ascii", errors="replace")
        rel = rec[3:].decode("utf-8", errors="replace")
        # INVARIANT: `git status --porcelain=v1 -z` emits an extra NUL-terminated original-path slot after rename/copy entries.
        if "R" in xy or "C" in xy:
            if i < len(records):
                i += 1
        if CACHE_PATH_RE.search(rel.replace("\\", "/")):
            continue
        full = os.path.normpath(os.path.join(root, rel))
        entries[rio.normalize_path(full)] = _file_entry_token(full, prefix=f"{xy}:")

    return {
        "in_git": True,
        "root": rio.normalize_path(root),
        "head": head,
        "entries": entries,
        "unmeasured": False,
    }


def _strip_git_xy_prefix(tok: str) -> str:
    return tok[3:] if len(tok) >= 3 and tok[2] == ":" else tok


def _git_entry_unchanged_on_disk(path: str, b_tok: str, a_tok: str | None = None) -> bool:
    b_xy = b_tok[:2] if len(b_tok) >= 3 and b_tok[2] == ":" else ""
    b_ctok = _strip_git_xy_prefix(b_tok)
    if b_ctok == "stat_err" or b_ctok.startswith(("link:", "dir:", "large:")):
        return False
    if b_ctok == "absent" and "D" not in b_xy:
        return False
    if a_tok is not None:
        a_xy = a_tok[:2] if len(a_tok) >= 3 and a_tok[2] == ":" else ""
        if b_ctok == "absent":
            return "D" in a_xy and _strip_git_xy_prefix(a_tok) == "absent"
        return _strip_git_xy_prefix(a_tok) == b_ctok
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return b_ctok == "absent"
    except OSError:
        return False
    if (
        b_ctok == "absent"
        or stat.S_ISLNK(st.st_mode)
        or not stat.S_ISREG(st.st_mode)
        or getattr(st, "st_reparse_tag", 0) != 0
        or st.st_size > MAX_HASHED_SNAPSHOT_BYTES
        or not b_ctok.startswith(f"{st.st_size}:")
    ):
        return False
    return _file_entry_token(path, stat_result=st) == b_ctok


def diff_git_snapshots(before: dict[str, Any] | None, after: dict[str, Any] | None) -> tuple[list[str], bool]:
    """Return `(changed_durable_paths, unmeasured)`."""
    if not isinstance(before, dict) or not isinstance(after, dict):
        return [], True
    if before.get("unmeasured") or after.get("unmeasured"):
        return [], True
    if bool(before.get("in_git")) != bool(after.get("in_git")):
        return [], True
    if not before.get("in_git"):
        if rio.fold_path(before.get("cwd")) != rio.fold_path(after.get("cwd")):
            return [], True
    elif rio.fold_path(before.get("root")) != rio.fold_path(after.get("root")):
        return [], True

    changed: set[str] = set()
    b_entries: dict[str, str] = before.get("entries") or {}
    a_entries: dict[str, str] = after.get("entries") or {}
    if not after.get("in_git"):
        for path, tok in a_entries.items():
            if b_entries.get(path) != tok:
                changed.add(path)
        for path in b_entries:
            if path not in a_entries:
                changed.add(path)
        return sorted(changed), False

    # INVARIANT: Pure `git add` / `git commit` of already-dirty working-tree files keeps on-disk SHA-256 identical
    # and must be treated as OPERATIONAL rather than reopening a PERSISTENT code-edit candidate.
    unchanged_clean: set[str] = set()
    for path, tok in a_entries.items():
        b_tok = b_entries.get(path)
        if b_tok is None or not _git_entry_unchanged_on_disk(path, b_tok, tok):
            changed.add(path)
    for path, b_tok in b_entries.items():
        if path not in a_entries:
            if _git_entry_unchanged_on_disk(path, b_tok):
                unchanged_clean.add(path)
            else:
                changed.add(path)

    # INVARIANT: Files modified & committed during a shell command leave status clean, so diff HEAD transitions explicitly.
    b_head = str(before.get("head") or "")
    a_head = str(after.get("head") or "")
    root = str(after.get("root") or "")
    if a_head and a_head != b_head and root:
        diff_args = ["diff-tree", "--no-commit-id", "--name-only", "-r", "-z"]
        if b_head:
            diff_args.extend([b_head, a_head])
        else:
            diff_args.extend(["--root", a_head])
        rc, out, _ = rio.run_git(root, diff_args, timeout=4.0, text=False)
        if rc != 0 or not isinstance(out, (bytes, bytearray)):
            return sorted(changed), True
        for rel_b in bytes(out).split(b"\0"):
            if not rel_b:
                continue
            rel = rel_b.decode("utf-8", errors="replace")
            if not CACHE_PATH_RE.search(rel.replace("\\", "/")):
                norm_p = rio.normalize_path(os.path.join(root, rel))
                if norm_p not in unchanged_clean:
                    changed.add(norm_p)

    return sorted(changed), False


def estimate_changed_lines(tool_name: str, args: dict[str, Any]) -> int:
    if tool_name == "edit_file":
        target = str(args.get("Target") or "")
        repl = str(args.get("Replacement") or "")
        t_lines = target.splitlines()
        r_lines = repl.splitlines()
        # Count lines actually differing between Target and Replacement
        prefix = 0
        while prefix < len(t_lines) and prefix < len(r_lines) and t_lines[prefix] == r_lines[prefix]:
            prefix += 1
        suffix = 0
        while (
            suffix < (len(t_lines) - prefix)
            and suffix < (len(r_lines) - prefix)
            and t_lines[len(t_lines) - 1 - suffix] == r_lines[len(r_lines) - 1 - suffix]
        ):
            suffix += 1
        changed_t = max(0, len(t_lines) - prefix - suffix)
        changed_r = max(0, len(r_lines) - prefix - suffix)
        return max(1, max(changed_t, changed_r))
    if tool_name == "write_file":
        content = str(args.get("Content") or "")
        return max(1, len(content.splitlines()))
    return 10


def _refresh_swarm_round_fields(
    marker: dict[str, Any],
    session: str,
    repo_root: str,
    fp: str | None,
) -> None:
    marker["round_id"] = int(marker.get("round_id") or 0) + 1
    marker["round_start_msg_id"] = cwg.swarm_board_head_seq(session=session, cwd=repo_root)
    marker["current_diff_hash"] = fp or ""
    fresh_probe = {"paths": list(marker.get("paths") or []), "changed_lines": int(marker.get("changed_lines") or 0)}
    marker["diff_metrics"] = cwg.compute_diff_metrics(marker=fresh_probe, repo_root=repo_root)


def update_candidate_marker(
    session: str,
    cwd: str,
    durable_new_paths: list[str],
    operational_mutation: bool = False,
    changed_lines_delta: int = 0,
    shell_durable_edit: bool = False,
    unknown_barrier: bool = False,
    cause_label: str = "",
    known_git_root: str | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    now = time.time()
    mp = cwg.marker_path(session)
    before = rio.read_json(mp, default=None)
    eff_cwd = cwd or (str(pathlib.Path(durable_new_paths[0]).parent) if durable_new_paths else "")
    if not isinstance(before, dict) or before.get("closed"):
        git_top = (
            known_git_root
            if (known_git_root is not None and (not known_git_root or (pathlib.Path(known_git_root) / ".git").exists()))
            else ((rio.git_toplevel(eff_cwd) or "") if eff_cwd else "")
        )
        marker: dict[str, Any] = {
            "session": session,
            "first_ts": now,
            "last_ts": now,
            "last_durable_ts": now if durable_new_paths else 0.0,
            "cwd": rio.normalize_path(eff_cwd),
            "git_root": rio.normalize_path(git_top),
            "paths": [],
            "operational": False,
            "changed_lines": 0,
            "edits": 0,
            "shell_durable_edit": False,
            "content_marks": [],
            "closed": False,
        }
        before_open = None
    else:
        marker = dict(before)
        before_open = dict(before)
        if not marker.get("cwd") and eff_cwd:
            marker["cwd"] = rio.normalize_path(eff_cwd)
            if not marker.get("git_root"):
                git_top = (
                    known_git_root
                    if (known_git_root is not None and (not known_git_root or (pathlib.Path(known_git_root) / ".git").exists()))
                    else (rio.git_toplevel(eff_cwd) or "")
                )
                marker["git_root"] = rio.normalize_path(git_top)

    marker["last_ts"] = now
    if durable_new_paths:
        merged_paths = cwg.durable_paths(list(marker.get("paths") or []) + durable_new_paths)
        marker["paths"] = merged_paths
        marker["last_durable_ts"] = now
        marker["edits"] = int(marker.get("edits") or 0) + 1
        marker["changed_lines"] = int(marker.get("changed_lines") or 0) + max(1, changed_lines_delta)
        if shell_durable_edit:
            marker["shell_durable_edit"] = True
        fp = cwg.content_fingerprint(merged_paths)
        marks = list(marker.get("content_marks") or [])
        mark_obj: dict[str, Any] = {"ts": now, "fp": fp, "cause": cause_label[:120]}
        if not fp and unknown_barrier:
            mark_obj["unknown"] = True
        changed_fp = not marks or marks[-1].get("fp") != fp or mark_obj.get("unknown") or marks[-1].get("unknown")
        if changed_fp:
            marks.append(mark_obj)
        cwg.trim_content_marks(marker, marks)
        if changed_fp or not marker.get("round_id"):
            _refresh_swarm_round_fields(
                marker,
                session,
                str(marker.get("git_root") or marker.get("cwd") or eff_cwd),
                fp,
            )
    elif operational_mutation:
        marker["operational"] = True
        dpaths = cwg.durable_paths(marker.get("paths"))
        if dpaths:
            marks = list(marker.get("content_marks") or [])
            fp = cwg.content_fingerprint(dpaths)
            last_fp = marks[-1].get("fp") if marks and isinstance(marks[-1], dict) else None
            if not fp:
                marks.append({"ts": now, "fp": None, "unknown": True, "cause": cause_label[:120]})
                cwg.trim_content_marks(marker, marks)
                _refresh_swarm_round_fields(
                    marker,
                    session,
                    str(marker.get("git_root") or marker.get("cwd") or eff_cwd),
                    None,
                )
            elif fp != last_fp:
                marks.append({"ts": now, "fp": fp, "cause": cause_label[:120]})
                marker["last_durable_ts"] = now
                cwg.trim_content_marks(marker, marks)
                _refresh_swarm_round_fields(
                    marker,
                    session,
                    str(marker.get("git_root") or marker.get("cwd") or eff_cwd),
                    fp,
                )
            elif marks and marks[-1].get("unknown"):
                # INVARIANT: Clear legacy unknown flag when SHA-256 fingerprint is confirmed identical.
                cleaned = dict(marks[-1])
                cleaned.pop("unknown", None)
                marks[-1] = cleaned
                cwg.trim_content_marks(marker, marks)

    rio.write_json(mp, marker)
    return before_open, marker


def build_transition_note(
    before: dict[str, Any] | None,
    after: dict[str, Any],
    ctx: dict[str, Any] | None = None,
) -> str | None:
    new_class = cwg.candidate_class(after)
    if new_class != cwg.WORK_PERSISTENT:
        return None
    cctx = ctx or cwg.resolve_candidate_context(after, include_tests=False)
    if not (cctx["needs_simplify"] or cctx["needs_review"]):
        return None

    policy = cctx["policy"]
    dpaths = cctx["dpaths"]
    new_floor = cctx["floor"]
    old_class = cwg.candidate_class(before)
    if old_class == new_class and before:
        old_cctx = cwg.resolve_candidate_context(before, include_tests=False)
        if (
            old_cctx["floor"] == new_floor
            and bool(old_cctx["needs_simplify"]) == bool(cctx["needs_simplify"])
            and bool(old_cctx["needs_review"]) == bool(cctx["needs_review"])
        ):
            return None

    req_tests = cctx["require_tests"]
    if req_tests is None:
        req_tests = cwg.requires_tests(
            new_floor, cwd=cctx["cwd"], paths=dpaths, policy=policy, git_root=cctx["git_root"]
        )

    shown = ", ".join(pathlib.PurePosixPath(p).name for p in dpaths[-3:])
    reqs = cwg.receipt_requirements_summary(new_floor, policy, has_tests=bool(req_tests))
    return (
        f"[Code Work Gate] `{new_floor}` ({len(dpaths)}ф: {shown}): {reqs}. "
        f"Финал: `[gate] verified: {new_floor}; <кандидат и проверки>`."
    )


def capture_direct_codex_packet(cmd: str, cwd: str, session: str) -> None:
    if "codex" not in cmd.lower() or "exec" not in cmd.lower():
        return
    if "codex_lane.py" in cmd.lower():
        return  # codex_lane.py records its own packet
    m = codex_lane.REVIEW_ID_RE.search(cmd)
    rid = m.group(1) if m else None
    if not rid:
        return
    eff = "xhigh" if "xhigh" in cmd.lower() else "high"
    codex_lane.record_packet(review_id=rid, prompt_text=cmd, cwd=cwd, effort=eff, session=session)


_PS_BOOL_SWITCHES = frozenset(
    {
        "-force",
        "-recurse",
        "-r",
        "-confirm",
        "-whatif",
        "-passthru",
        "-verbose",
        "-debug",
        "-noclobber",
        "-append",
        "-nonewline",
        "-asbytestream",
        "-raw",
        "-container",
    }
)
_PS_NON_PATH_VALUE_FLAGS = frozenset(
    {
        "-itemtype",
        "-type",
        "-value",
        "-encoding",
        "-erroraction",
        "-ea",
        "-warningaction",
        "-wa",
        "-informationaction",
        "-outvariable",
        "-ov",
        "-errorvariable",
        "-ev",
        "-filter",
        "-include",
        "-exclude",
        "-depth",
        "-delimiter",
        "-stream",
    }
)
_PS_PATH_FLAGS = frozenset({"-path", "-p", "-literalpath", "-lp", "-filepath"})
_PS_DEST_FLAGS = frozenset({"-destination", "-dest", "-destinationpath"})
_PS_SAFE_BARE_PAT = r"[A-Za-z0-9_./\\:-]+"
_PS_SAFE_BARE_RE = re.compile(rf"^{_PS_SAFE_BARE_PAT}$")
_PS_VAR_NAME_PAT = r"[A-Za-z_]\w*(?::[A-Za-z_]\w*)?"
_PS_VAR_REF_RE = re.compile(rf"(?<!`)\$(?:\{{({_PS_VAR_NAME_PAT})\}}|({_PS_VAR_NAME_PAT}))")
_PS_DQ_LITERAL_PAT = r'"[^"`$]*"'
_PS_ASSIGN_RE = re.compile(r"^\s*\$(?P<var>[A-Za-z_]\w*)\s*=\s*(?P<rhs>\S[\s\S]*)$")
_PS_JOIN_PATH_RE = re.compile(
    rf"^Join-Path\s+(?:-Path\s+)?(?P<p1>{_PS_SQ_PAT}|{_PS_DQ_LITERAL_PAT}|{_PS_SAFE_BARE_PAT})\s+"
    rf"(?:-ChildPath\s+)?(?P<p2>{_PS_SQ_PAT}|{_PS_DQ_LITERAL_PAT}|{_PS_SAFE_BARE_PAT})\s*$",
    re.IGNORECASE,
)
_PS_REDIRECT_TOKEN_RE = re.compile(
    rf"(?:(?<!\S)[1-6*])?(?<!>)>>?(?!>)\s*(?:({_PS_DQ_PAT})|({_PS_SQ_PAT})|([^\s|;&\"']+))(?=$|[\s|;&])"
)
_MAX_VAR_VALUE_LEN = 1024
_MAX_EXPANDED_SEG_LEN = 8192
_SCRIPT_EXTS = (".ps1", ".bat", ".cmd", ".vbs", ".wsf", ".exe", ".com", ".msi")
_INTERPRETER_BASENAMES = frozenset(
    {
        "python",
        "python.exe",
        "python3",
        "python3.exe",
        "py",
        "py.exe",
        "node",
        "node.exe",
        "deno",
        "deno.exe",
        "bun",
        "bun.exe",
        "pwsh",
        "pwsh.exe",
        "powershell",
        "powershell.exe",
        "cmd",
        "cmd.exe",
        "bash",
        "bash.exe",
        "sh",
        "sh.exe",
        "wsl",
        "wsl.exe",
    }
)


def _unquote_ps_literal(raw: str) -> str:
    s = raw.strip()
    if len(s) >= 2 and s[0] == "'" and s[-1] == "'":
        return s[1:-1].replace("''", "'")
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return re.sub(r"`([\s\S])", r"\1", s[1:-1].replace('""', '"'))
    return s


def _is_safe_var_value(val: str) -> bool:
    return len(val) <= _MAX_VAR_VALUE_LEN and not any(ch in val for ch in ('"', "`", "$", "\r", "\n"))


def _expand_vars_outside_single_quotes(text: str, vars_map: dict[str, str]) -> str:
    if not vars_map or "$" not in text:
        return text

    def _sub_in_dq(chunk: str) -> str:
        return _PS_VAR_REF_RE.sub(lambda m: vars_map.get((m.group(1) or m.group(2) or "").lower(), m.group(0)), chunk)

    def _sub_unquoted(chunk: str, left_adj_quote: bool, right_adj_quote: bool) -> str:
        def _repl(m: re.Match[str]) -> str:
            key = (m.group(1) or m.group(2) or "").lower()
            if key not in vars_map:
                return m.group(0)
            s_idx, e_idx = m.start(), m.end()
            if (s_idx == 0 and left_adj_quote) or (e_idx == len(chunk) and right_adj_quote):
                return m.group(0)
            if (s_idx > 0 and chunk[s_idx - 1] in ("'", '"')) or (e_idx < len(chunk) and chunk[e_idx] in ("'", '"')):
                return m.group(0)
            val = vars_map[key]
            if _PS_SAFE_BARE_RE.fullmatch(val):
                return val
            return "'" + val.replace("'", "''") + "'"

        return _PS_VAR_REF_RE.sub(_repl, chunk)

    out: list[str] = []
    last = 0
    matches = list(_PS_QUOTED_RE.finditer(text))
    for idx, m in enumerate(matches):
        out.append(_sub_unquoted(text[last : m.start()], left_adj_quote=(idx > 0), right_adj_quote=True))
        if m.group(1) is not None:
            out.append(m.group(0))
        else:
            out.append(_sub_in_dq(m.group(0)))
        last = m.end()
    out.append(_sub_unquoted(text[last:], left_adj_quote=bool(matches), right_adj_quote=False))
    return "".join(out)


def _ps_tokens(seg: str) -> list[str]:
    tokens: list[str] = []
    cur: list[str] = []
    quote: str | None = None
    i = 0
    n = len(seg)
    while i < n:
        ch = seg[i]
        if quote:
            if quote == "'" and ch == "'" and i + 1 < n and seg[i + 1] == "'":
                cur.append("'")
                i += 2
                continue
            if quote == '"' and ch == '"' and i + 1 < n and seg[i + 1] == '"':
                cur.append('"')
                i += 2
                continue
            if quote == '"' and ch == "`" and i + 1 < n:
                cur.append(seg[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
                i += 1
                continue
            cur.append(ch)
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            i += 1
            continue
        if ch.isspace():
            if cur:
                tokens.append("".join(cur))
                cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    if quote is not None:
        return []
    if cur:
        tokens.append("".join(cur))
    return tokens


def _resolve_ps_path(raw_path: str, cur_cwd: str) -> str | None:
    cleaned = (raw_path or "").strip()
    if not cleaned or "$" in cleaned or "`" in cleaned or "," in cleaned:
        return None
    # Reject PowerShell provider prefixes (`HKCU:\`, `FileSystem::`, `Env:`, NTFS ADS) outside a Windows drive `C:\`
    if ":" in cleaned and not re.match(r"^[A-Za-z]:[\\/]", cleaned):
        return None
    if os.name == "nt":
        is_abs = bool(re.match(r"^[A-Za-z]:[\\/]", cleaned)) or cleaned.startswith("\\\\")
    else:
        is_abs = os.path.isabs(cleaned)
    if is_abs:
        return os.path.abspath(cleaned)
    if cur_cwd:
        return os.path.abspath(os.path.join(cur_cwd, cleaned))
    return None


def _resolve_ephemeral_target(
    raw_path: str,
    cur_cwd: str,
    artifact_dir: str | None,
    workspace_paths: list[str] | None,
) -> str | None:
    cleaned = (raw_path or "").strip()
    if not cleaned or "$" in cleaned or "`" in cleaned or "," in cleaned:
        return None
    if ":" in cleaned and not re.match(r"^[A-Za-z]:[\\/]", cleaned):
        return None
    norm_slashes = cleaned.replace("\\", "/")
    parts = [pt for pt in norm_slashes.split("/") if pt]
    if any(("*" in pt or "?" in pt) for pt in parts[:-1]):
        return None
    if parts and ("*" in parts[-1] or "?" in parts[-1]):
        parent_str = str(pathlib.PurePosixPath(norm_slashes).parent)
        cleaned = cur_cwd if (not parent_str or parent_str == ".") else parent_str
    resolved = _resolve_ps_path(cleaned, cur_cwd)
    if resolved is None:
        return None
    if not cwg.is_session_scratch_path(resolved, artifact_dir=artifact_dir, workspace_paths=workspace_paths):
        return None
    return resolved


def _parse_cmdlet_args(
    toks: list[str],
    allow_dest: bool = False,
    extra_flag: str = "",
) -> tuple[list[str], list[str], list[str], str, bool] | None:
    """Parse `(path_vals, dest_vals, positionals, extra_val, saw_value_flag)` or None on unsupported flag."""
    path_vals: list[str] = []
    dest_vals: list[str] = []
    positionals: list[str] = []
    extra_val = ""
    saw_value_flag = False
    idx = 1
    while idx < len(toks):
        tk = toks[idx]
        low_tk = tk.lower()
        if low_tk in _PS_BOOL_SWITCHES:
            idx += 1
        elif low_tk in _PS_NON_PATH_VALUE_FLAGS:
            if idx + 1 >= len(toks):
                return None
            if low_tk == "-value":
                saw_value_flag = True
            idx += 2
        elif low_tk in _PS_PATH_FLAGS:
            if idx + 1 >= len(toks):
                return None
            path_vals.append(toks[idx + 1])
            idx += 2
        elif allow_dest and low_tk in _PS_DEST_FLAGS:
            if idx + 1 >= len(toks):
                return None
            dest_vals.append(toks[idx + 1])
            idx += 2
        elif extra_flag and low_tk in (extra_flag, "-n" if extra_flag == "-name" else extra_flag):
            if idx + 1 >= len(toks):
                return None
            extra_val = toks[idx + 1]
            idx += 2
        elif tk.startswith("-"):
            return None
        else:
            positionals.append(tk)
            idx += 1
    return path_vals, dest_vals, positionals, extra_val, saw_value_flag


_PS_CONTROL_KW_RE = re.compile(
    r"^\s*(?:(?:if|elseif|else|try|catch|finally|do|while|switch|ForEach-Object|foreach|for)\b|%(?=\s|$))\s*",
    re.IGNORECASE,
)


def _has_opaque_script_or_exec(cmd: str) -> bool:
    core = _strip_null_pipe(cmd)
    if not core:
        return False
    for raw_clause in _all_ps_clauses(core):
        s = raw_clause.strip()
        while s:
            m_kw = _PS_CONTROL_KW_RE.match(s)
            if not m_kw:
                break
            s = s[m_kw.end() :].strip()
        if not s:
            continue
        m_assign = _PS_ASSIGN_RE.match(s)
        if m_assign:
            s = m_assign.group("rhs").strip()
        if s.startswith(("&", ". ")) or re.match(r"^\.[\\/]", s):
            return True
        if (
            INLINE_PY_RE.match(s)
            or BOOKKEEPING_CMD_RE.match(s)
            or VALIDATION_SEGMENT_RE.match(s)
            or READ_ONLY_CMD_RE.match(s)
            or NAV_SEGMENT_RE.match(s)
            or PS_SAFE_FILTER_RE.match(s)
        ):
            continue
        toks = _ps_tokens(s)
        if not toks:
            continue
        head_raw = toks[0]
        if head_raw in ("&", ".") or (head_raw.startswith("&") and len(head_raw) > 1):
            return True
        head_norm = head_raw.replace("\\", "/").lower()
        base = pathlib.PurePosixPath(head_norm).name
        if base in _INTERPRETER_BASENAMES or head_norm.endswith(_SCRIPT_EXTS):
            return True
    return False


def _references_scratch_space(cmd: str, artifact_dir: str | None) -> bool:
    norm_cmd = cmd.replace("\\", "/").lower()
    if artifact_dir:
        art = rio.normalize_path(artifact_dir).lower()
        if art and art in norm_cmd:
            return True
    return any(pat.search(norm_cmd) for pat in cwg.USER_SCRATCH_PATTERNS)


def extract_ps_redirections(seg: str) -> tuple[str, list[str]]:
    """Extract unquoted PowerShell redirection targets, returning `(cleaned_seg, non_null_targets)`."""
    if ">" not in _strip_quoted(seg):
        return seg, []
    redir_spans: list[tuple[int, int]] = []
    targets: list[str] = []
    q_spans = [(m.start(), m.end()) for m in _PS_QUOTED_RE.finditer(seg)]
    for rm in _PS_REDIRECT_TOKEN_RE.finditer(seg):
        if any(qs <= rm.start() < qe for qs, qe in q_spans):
            continue
        raw_tgt = rm.group(1) or rm.group(2) or rm.group(3) or ""
        tgt = _unquote_ps_literal(raw_tgt)
        redir_spans.append((rm.start(), rm.end()))
        if tgt and tgt.lower() not in ("$null", "nul", "/dev/null") and not re.match(r"^&[1-6]$", tgt):
            targets.append(tgt)
    if not redir_spans:
        return seg, []
    buf: list[str] = []
    prev_idx = 0
    for rs, re_end in redir_spans:
        buf.append(seg[prev_idx:rs])
        prev_idx = re_end
    buf.append(seg[prev_idx:])
    return "".join(buf).strip(), targets


def is_ephemeral_only_shell_mutation(
    cmd: str,
    artifact_dir: str | None = None,
    workspace_paths: list[str] | None = None,
    default_cwd: str = "",
) -> bool:
    """Return True iff every mutating effect in `cmd` is strictly confined to session-scoped brain scratch files."""
    core = _strip_null_pipe(cmd)
    if not core or len(core) > _MAX_EXPANDED_SEG_LEN:
        return False
    subexprs = _extract_ps_subexprs(core)
    if subexprs or INLINE_PY_RE.search(core):
        return False
    no_single = _strip_single_quoted(core)
    unquoted = _strip_quoted(core)
    unquoted_surface, scan_surface, no_single_surface = _shell_scan_surfaces(core, no_single, unquoted, subexprs)

    if _has_non_cmdlet_mutation(core, unquoted_surface, scan_surface, no_single_surface, subexprs):
        return False

    vars_map: dict[str, str] = {}
    raw_segments = _split_shell_segments(core)
    cur_cwd = default_cwd
    cwd_stack: list[str] = []
    saw_ephemeral_mutation = False

    for op, raw_seg in raw_segments:
        seg = _expand_vars_outside_single_quotes(raw_seg, vars_map).strip()
        if not seg:
            continue
        if len(seg) > _MAX_EXPANDED_SEG_LEN:
            return False

        m_assign = _PS_ASSIGN_RE.match(seg)
        if m_assign and op != "|":
            var_name = m_assign.group("var").lower()
            vars_map.pop(var_name, None)
            rhs = m_assign.group("rhs").strip()
            if re.fullmatch(_PS_SQ_PAT, rhs) or (
                re.fullmatch(_PS_DQ_PAT, rhs) and "$" not in rhs and "`" not in rhs
            ):
                val = _unquote_ps_literal(rhs)
                if not _is_safe_var_value(val):
                    return False
                vars_map[var_name] = val
                continue
            m_jp = _PS_JOIN_PATH_RE.match(rhs)
            if m_jp:
                p1 = _unquote_ps_literal(m_jp.group("p1"))
                p2 = _unquote_ps_literal(m_jp.group("p2"))
                joined = os.path.join(p1, p2)
                if _is_safe_var_value(p1) and _is_safe_var_value(p2) and _is_safe_var_value(joined):
                    vars_map[var_name] = joined
                    continue
            if rhs.lower() in ("$true", "$false", "$null") or rhs.isdigit():
                continue
            seg = rhs

        if re.match(r"^\s*Out-Null\s*$", seg, re.IGNORECASE):
            continue
        if op == "|" and PS_SAFE_FILTER_RE.match(seg):
            continue

        if NAV_SEGMENT_RE.match(seg):
            if "," in _strip_quoted(seg):
                return False
            toks = _ps_tokens(seg)
            if not toks:
                return False
            nav_cmd = toks[0].lower()
            if nav_cmd in ("pop-location", "popd"):
                if not cwd_stack:
                    return False
                cur_cwd = cwd_stack.pop()
                continue
            pos = [t for t in toks[1:] if not t.startswith("-") and t.lower() != "/d"]
            if len(pos) != 1:
                return False
            next_cwd = _resolve_ps_path(pos[0], cur_cwd)
            if not next_cwd:
                return False
            if nav_cmd in ("push-location", "pushd"):
                cwd_stack.append(cur_cwd)
            cur_cwd = next_cwd
            continue

        seg_unq = _strip_quoted(seg)
        if "," in seg_unq or _has_output_flag(seg, seg_unq):
            return False

        # Extract and validate any unquoted file redirections (`>` / `>>`, `2>$null`, `*>` etc.)
        if ">" in seg_unq:
            cleaned_seg, redir_targets = extract_ps_redirections(seg)
            if cleaned_seg != seg:
                for tgt in redir_targets:
                    if _resolve_ephemeral_target(tgt, cur_cwd, artifact_dir, workspace_paths) is None:
                        return False
                    saw_ephemeral_mutation = True
                seg = cleaned_seg
                if not seg:
                    continue
                seg_unq = _strip_quoted(seg)

        if "$(" in _strip_single_quoted(seg) or any(ch in seg_unq for ch in ("(", ")", "{", "}", "`", ">", ",")):
            return False

        if READ_ONLY_CMD_RE.match(seg):
            continue

        toks = _ps_tokens(seg)
        if not toks:
            return False
        head = toks[0].lower()

        if head in (
            "new-item",
            "ni",
            "mkdir",
            "md",
            "set-content",
            "sc",
            "add-content",
            "ac",
            "out-file",
            "export-csv",
            "export-clixml",
            "tee-object",
            "clear-content",
            "clc",
        ):
            parsed = _parse_cmdlet_args(toks, allow_dest=False, extra_flag="-name" if head in ("new-item", "ni") else "")
            if parsed is None:
                return False
            path_vals, _, positionals, child_name, saw_value = parsed
            is_content_cmd = head in ("set-content", "sc", "add-content", "ac")
            if path_vals:
                max_extra_pos = 1 if (is_content_cmd and not saw_value) else 0
                if len(positionals) > max_extra_pos:
                    return False
            else:
                if not positionals:
                    return False
                if is_content_cmd:
                    max_pos = 1 if saw_value else 2
                    if len(positionals) > max_pos:
                        return False
                    path_vals = [positionals[0]]
                else:
                    path_vals = positionals
            if child_name:
                if os.path.isabs(child_name) or "$" in child_name or ":" in child_name:
                    return False
                path_vals = [os.path.join(p, child_name) for p in path_vals]
            for pv in path_vals:
                if _resolve_ephemeral_target(pv, cur_cwd, artifact_dir, workspace_paths) is None:
                    return False
            saw_ephemeral_mutation = True
            continue

        if head in ("copy-item", "ci", "cp", "expand-archive"):
            parsed = _parse_cmdlet_args(toks, allow_dest=True)
            if parsed is None:
                return False
            src_vals, dest_vals, positionals, _, _ = parsed
            if dest_vals:
                max_pos = 0 if src_vals else 1
                if len(positionals) > max_pos:
                    return False
            elif src_vals and len(positionals) == 1:
                dest_vals = [positionals[0]]
            elif not src_vals and len(positionals) == 2:
                dest_vals = [positionals[1]]
            else:
                return False
            for dv in dest_vals:
                if _resolve_ephemeral_target(dv, cur_cwd, artifact_dir, workspace_paths) is None:
                    return False
            saw_ephemeral_mutation = True
            continue

        if head in ("expand", "expand.exe"):
            pos = [t for t in toks[1:] if not t.startswith(("-", "/"))]
            if len(pos) != 2:
                return False
            if _resolve_ephemeral_target(pos[-1], cur_cwd, artifact_dir, workspace_paths) is None:
                return False
            saw_ephemeral_mutation = True
            continue

        if head in (
            "remove-item",
            "ri",
            "rm",
            "del",
            "erase",
            "rmdir",
            "rd",
            "move-item",
            "mi",
            "mv",
            "rename-item",
            "rni",
            "ren",
        ):
            parsed = _parse_cmdlet_args(
                toks,
                allow_dest=True,
                extra_flag="-newname" if head in ("rename-item", "rni", "ren") else "",
            )
            if parsed is None:
                return False
            p_vals, d_vals, positionals, new_name, _ = parsed
            all_paths = p_vals + d_vals + positionals
            if head in ("rename-item", "rni", "ren"):
                if not new_name and len(all_paths) == 2 and not d_vals:
                    all_paths, new_name = [all_paths[0]], all_paths[1]
                if len(all_paths) != 1 or not new_name or "$" in new_name or "," in new_name:
                    return False
                src_res = _resolve_ephemeral_target(all_paths[0], cur_cwd, artifact_dir, workspace_paths)
                if src_res is None:
                    return False
                dst_cand = new_name if (os.name == "nt" and re.match(r"^[A-Za-z]:[\\/]", new_name) or os.path.isabs(new_name)) else os.path.join(os.path.dirname(src_res), new_name)
                if _resolve_ephemeral_target(dst_cand, cur_cwd, artifact_dir, workspace_paths) is None:
                    return False
            elif head in ("move-item", "mi", "mv"):
                if len(all_paths) != 2:
                    return False
                for ap in all_paths:
                    if _resolve_ephemeral_target(ap, cur_cwd, artifact_dir, workspace_paths) is None:
                        return False
            else:
                if not all_paths or d_vals:
                    return False
                for ap in all_paths:
                    if _resolve_ephemeral_target(ap, cur_cwd, artifact_dir, workspace_paths) is None:
                        return False
            saw_ephemeral_mutation = True
            continue

        return False

    return saw_ephemeral_mutation


def handle_pre_tool(payload: dict[str, Any]) -> None:
    tc = payload.get("toolCall") if isinstance(payload.get("toolCall"), dict) else {}
    tool_name = str(tc.get("name") or "")
    if tool_name not in SHELL_TOOLS:
        rio.emit_pre_tool("allow")
        return

    args = tc.get("args") if isinstance(tc.get("args"), dict) else {}
    cmd = str(args.get("CommandLine") or "")
    policy = classify_shell_command(cmd)
    has_direct_codex = "codex" in cmd.lower() and "exec" in cmd.lower() and "codex_lane.py" not in cmd.lower()
    if policy in ("READ_ONLY", "BOOKKEEPING") and not has_direct_codex:
        rio.emit_pre_tool("allow")
        return

    if rio.is_subagent_session(payload.get("transcriptPath")):
        rio.emit_pre_tool("allow")
        return

    session = rio.session_key(payload)
    cwd = rio.effective_cwd(payload)
    call_id = str(tc.get("id") or uuid.uuid4().hex[:10])
    if has_direct_codex:
        capture_direct_codex_packet(cmd, cwd, session)
    if policy not in ("READ_ONLY", "BOOKKEEPING"):
        wps = payload.get("workspacePaths") if isinstance(payload.get("workspacePaths"), list) else None
        cmd_cwd = resolve_command_cwd(cmd, cwd, session=session)
        cwg.publish_claim(session, shell_active=True, cwd=cmd_cwd)
        snap = take_git_snapshot(cmd_cwd, artifact_dir=payload.get("artifactDirectoryPath"), workspace_paths=wps)
        snap["cmd_cwd"] = cmd_cwd
        snap["policy"] = policy
        snap["cmd"] = cmd[:240]
        snap["ts"] = time.time()
        rio.write_json(cwg.snapshot_path(session, call_id), snap)

    rio.emit_pre_tool("allow")


def handle_post_tool(payload: dict[str, Any]) -> None:
    tc = payload.get("toolCall") if isinstance(payload.get("toolCall"), dict) else {}
    tool_name = str(tc.get("name") or "")
    if tool_name not in EDIT_TOOLS and tool_name not in SHELL_TOOLS:
        rio.emit_json({})
        return

    args = tc.get("args") if isinstance(tc.get("args"), dict) else {}
    error_text = str(payload.get("error") or "").strip()
    failed = bool(error_text)
    wps = payload.get("workspacePaths") if isinstance(payload.get("workspacePaths"), list) else None
    art_dir = payload.get("artifactDirectoryPath")
    session = rio.session_key(payload)

    if tool_name in EDIT_TOOLS:
        if failed:
            rio.emit_json({})
            return
        target_path = str(args.get("Path") or "")
        if not target_path:
            rio.emit_json({})
            return
        # Advance Loop Guard mutation stamp for subagent and scratch edits too without spawning continuity PostToolUse
        rio.bump_mutation_stamp(session)
        if bool(args.get("ArtifactMetadata")):
            rio.emit_json({})
            return
        cwd = rio.effective_cwd(payload)
        if cwg.is_scratch_or_ephemeral(target_path, art_dir, workspace_paths=wps, cwd=cwd):
            rio.emit_json({})
            return
        if rio.is_subagent_session(payload.get("transcriptPath")):
            rio.emit_json({})
            return
        cwg.publish_claim(session, paths=[target_path], cwd=cwd)
        before, after = update_candidate_marker(
            session=session,
            cwd=cwd,
            durable_new_paths=[target_path],
            changed_lines_delta=estimate_changed_lines(tool_name, args),
            cause_label=f"{tool_name}:{pathlib.Path(target_path).name}",
        )
        cctx = cwg.resolve_candidate_context(after, include_tests=False)
        note = build_transition_note(before, after, ctx=cctx)
        if note:
            cwg.queue_pending_note(session, note)
        rio.log_hook_event(
            "gate-events",
            "mark_edit",
            session=session,
            tool=tool_name,
            path=rio.normalize_path(target_path),
            floor=cctx["floor"],
        )
        rio.emit_json({})
        return

    cmd = str(args.get("CommandLine") or "")
    policy = classify_shell_command(cmd)
    if not failed and policy == "MUTATING":
        rio.bump_mutation_stamp(session)
    if not failed and policy in ("READ_ONLY", "BOOKKEEPING"):
        rio.emit_json({})
        return

    if rio.is_subagent_session(payload.get("transcriptPath")):
        rio.emit_json({})
        return

    if failed:
        codex_lane.record_from_command(cmd, error_text, exit_code=1)

    if policy == "VALIDATION" or (failed and policy == "UNCERTAIN" and _has_validation_segment(cmd)):
        rio.append_jsonl(
            cwg.checks_ledger_path(session),
            {
                "kind": "check",
                "passed": not failed,
                "cmd": cmd[:240],
                "error": error_text[:200] if failed else "",
                "ts": time.time(),
                "step_idx": payload.get("stepIdx"),
            },
        )

    if policy in ("READ_ONLY", "BOOKKEEPING"):
        rio.emit_json({})
        return

    cwd = rio.effective_cwd(payload)
    call_id = str(tc.get("id") or "call")
    snap_file = cwg.snapshot_path(session, call_id)
    before_snap = rio.read_json(snap_file, default=None)
    if snap_file.exists():
        try:
            snap_file.unlink()
        except OSError:
            pass
    if isinstance(before_snap, dict) and "cmd_cwd" in before_snap:
        cmd_cwd = str(before_snap.get("cmd_cwd") or "")
        prev_git_root = str(before_snap.get("root") or "") if before_snap.get("in_git") else None
    else:
        cmd_cwd = resolve_command_cwd(cmd, cwd, session=session)
        prev_git_root = None
    after_snap = take_git_snapshot(cmd_cwd, artifact_dir=art_dir, workspace_paths=wps, known_git_root=prev_git_root)
    snap_git_root = str(after_snap.get("root") or "") if after_snap.get("in_git") else ("" if not cmd_cwd else None)
    changed_paths, unmeasured = diff_git_snapshots(before_snap, after_snap)

    # Exclude files actively claimed by a different concurrent session
    if changed_paths:
        others = cwg.claimed_by_other_sessions(session, changed_paths)
        changed_paths = [
            p
            for p in changed_paths
            if rio.fold_path(p) not in others
            and not cwg.is_scratch_or_ephemeral(p, art_dir, workspace_paths=wps, cwd=cmd_cwd)
        ]

    cwg.publish_claim(session, paths=changed_paths, shell_active=False, cwd=cmd_cwd)

    if changed_paths:
        rio.bump_mutation_stamp(session)
        before, after = update_candidate_marker(
            session=session,
            cwd=cmd_cwd,
            durable_new_paths=changed_paths,
            changed_lines_delta=10,
            shell_durable_edit=True,
            unknown_barrier=unmeasured,
            cause_label=f"run_command:{cmd[:60]}",
            known_git_root=snap_git_root,
        )
        cctx = cwg.resolve_candidate_context(after, include_tests=False)
        note = build_transition_note(before, after, ctx=cctx)
        if note:
            cwg.queue_pending_note(session, note)
        rio.log_hook_event(
            "gate-events",
            "mark_shell_durable",
            session=session,
            files=len(changed_paths),
            floor=cctx["floor"],
        )
    elif not failed:
        has_opaque = policy == "UNCERTAIN" and _has_opaque_script_or_exec(cmd)
        opaque_unmeasured = bool(
            has_opaque
            and (
                after_snap.get("ephemeral_cwd")
                or after_snap.get("no_project")
                or _references_scratch_space(cmd, art_dir)
            )
        )
        is_mutating_non_ephemeral = bool(
            policy == "MUTATING"
            and not is_ephemeral_only_shell_mutation(cmd, artifact_dir=art_dir, workspace_paths=wps, default_cwd=cwd)
        )
        if is_mutating_non_ephemeral or (policy == "UNCERTAIN" and (unmeasured or opaque_unmeasured)):
            before, after = update_candidate_marker(
                session=session,
                cwd=cmd_cwd,
                durable_new_paths=[],
                operational_mutation=True,
                unknown_barrier=unmeasured or opaque_unmeasured,
                cause_label=f"run_command:{cmd[:60]}",
                known_git_root=snap_git_root,
            )
            note = build_transition_note(before, after)
            if note:
                cwg.queue_pending_note(session, note)
            rio.log_hook_event("gate-events", "mark_operational", session=session, policy=policy, cmd=cmd[:80])

    rio.emit_json({})


def main() -> int:
    event = rio.parse_event_arg()
    payload, err = rio.read_hook_stdin()
    if err or payload is None:
        if err:
            rio.log_hook_event("hook-errors", "stdin_error", hook="cwg_mark", event=event, error=err)
        rio.emit_default_for_event(event)
        return 0

    actual_event = event or str(payload.get("hookEventName") or "")
    try:
        if actual_event == "PreToolUse":
            handle_pre_tool(payload)
        elif actual_event == "PostToolUse":
            handle_post_tool(payload)
        else:
            rio.emit_default_for_event(actual_event)
    except Exception as exc:
        rio.log_hook_event(
            "hook-errors",
            "exception",
            hook="cwg_mark",
            event=actual_event,
            error=f"{type(exc).__name__}:{exc}",
        )
        rio.emit_default_for_event(actual_event)
    return 0


if __name__ == "__main__":
    sys.exit(main())
