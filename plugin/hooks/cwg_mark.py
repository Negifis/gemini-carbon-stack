#!/usr/bin/env python3
"""Code Work Gate PreToolUse & PostToolUse marker for Google Antigravity 2.0."""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
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
SUBAGENT_TOOLS = frozenset({"invoke_subagent"})

CACHE_PATH_RE = re.compile(
    r"(^|/)(__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.coverage|node_modules/\.cache)(/|$)|\.pyc$",
    re.IGNORECASE,
)

BOOKKEEPING_CMD_RE = re.compile(
    r"^\s*(?:\$null\s*\|\s*)?(?:&\s*)?(?:python|py(?:\s+-3)?)(?:\.exe)?\s+(?:-X\s+utf8\s+)?"
    r"(?:[\"']?[^\s|;&\"']*(?:carbon_memory\.py|continuity\.py\s+(?:checkpoint|show)|gate_inbox\.py|chip_handoff\.py|codex_lane\.py\s+(?:check|status|reset|review))[\"']?)(?:\s+[^|;&\r\n]*)?$",
    re.IGNORECASE,
)

READ_ONLY_CMD_RE = re.compile(
    r"^\s*(?:\$null\s*\|\s*)?(?:"
    r"git(?:\.exe)?\s+(?:--no-pager\s+)?(?:-C\s+[\"']?[^\"'|;&\r\n]+[\"']?\s+)?(?:status|diff|log|show|rev-parse|ls-files|ls-tree|check-ignore|remote\s+-v|worktree\s+list|branch(?:\s+(?:--list|-a|-r|--show-current))?)"
    r"|rg(?:\.exe)?\b"
    r"|findstr(?:\.exe)?\b"
    r"|where(?:\.exe)?\b"
    r"|Get-ChildItem\b|Get-Content\b|Select-String\b|Get-Command\b|Test-Path\b|Get-Item\b"
    r"|codex(?:\.cmd|\.exe)?\s+(?:--version|login\s+status|exec\b[^|;&\r\n]*-s\s+read-only\b)"
    r"|agy(?:\.exe|\.cmd)?\s+(?:--help|--version|plugin\s+(?:list|help))"
    r"|(?:python|py(?:\s+-3)?)(?:\.exe)?\s+(?:-X\s+utf8\s+)?[\"']?[^\s|;&\"']*(?:code_search\.py|stack_doctor\.py|worktree_guard\.py[\"']?\s+(?:audit|status))\b"
    r")(?:\s+[^|;&\r\n]*)?$",
    re.IGNORECASE,
)

VALIDATION_SEGMENT_RE = re.compile(
    r"^\s*(?:\$null\s*\|\s*)?(?:&\s*)?(?:"
    r"(?:pytest|py\.test|mypy|ruff\s+check|flake8)(?:\.exe)?\b"
    r"|(?:python|py(?:\s+-3)?)(?:\.exe)?\s+(?:-X\s+utf8\s+)?(?:-m\s+(?:pytest|unittest|py_compile|compileall|mypy|ruff|flake8)\b|[\"']?[^\s|;&\"']*install\.py[\"']?\s+[^\r\n|;&]*(?:--diagnose|--dry-run)\b)"
    r"|npm(?:\.cmd)?\s+(?:test|run\s+(?:test|lint|build|typecheck|check))\b"
    r"|pnpm(?:\.cmd)?\s+(?:test|lint|build|typecheck)\b"
    r"|yarn(?:\.cmd)?\s+(?:test|lint|build|typecheck)\b"
    r"|npx(?:\.cmd)?\s+(?:tsc|vitest|jest|eslint|playwright\s+test)\b"
    r"|cargo(?:\.exe)?\s+(?:test|check|clippy)\b"
    r"|go(?:\.exe)?\s+(?:test|vet)\b"
    r"|dotnet(?:\.exe)?\s+(?:test|build)\b"
    r"|[\"']?[^\s|;&\"']*agy(?:\.exe|\.cmd)?[\"']?\s+plugin\s+validate\b"
    r")",
    re.IGNORECASE,
)

SKILL_MD_RE = re.compile(r"[/\\]skills[/\\](?P<skill>[A-Za-z0-9._-]+)[/\\]SKILL\.md$", re.IGNORECASE)


def _strip_single_quoted(text: str) -> str:
    return re.sub(r"'(?:''|[^'])*'", "''", text)


def _strip_quoted(text: str) -> str:
    return re.sub(r"\"(?:\\.|[^\"])*\"|'(?:''|[^'])*'", '""', text)


def _has_shell_chaining(stripped: str) -> bool:
    core = re.sub(r"^\s*\$null\s*\|\s*", "", stripped, flags=re.IGNORECASE)
    # PowerShell executes `$(...)` subexpressions both outside quotes and inside double-quoted strings.
    if re.search(r"\$\(", _strip_single_quoted(core)):
        return True
    unquoted = _strip_quoted(core)
    return bool(re.search(r"[;\r\n`]|&&|\|\||(?<![|])\|(?![|])", unquoted))


def _split_shell_segments(stripped: str) -> list[str]:
    core = re.sub(r"^\s*\$null\s*\|\s*", "", stripped, flags=re.IGNORECASE)
    # Split on top-level `;` or newlines to detect validation runners inside `cd dir; pytest`
    parts: list[str] = []
    cur: list[str] = []
    quote: str | None = None
    for ch in core:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
        elif ch in ('"', "'"):
            quote = ch
            cur.append(ch)
        elif ch in (";", "\n", "\r"):
            seg = "".join(cur).strip()
            if seg:
                parts.append(seg)
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return parts


def classify_shell_command(cmd: str) -> str:
    stripped = (cmd or "").strip()
    if not stripped:
        return "READ_ONLY"
    has_file_redirect = bool(
        re.search(r"(?<![0-9])>>?\s*(?!\$null\b|nul\b|/dev/null\b|&[12]\b)\S+", _strip_quoted(stripped), re.IGNORECASE)
    )
    chained = _has_shell_chaining(stripped)
    unquoted = _strip_quoted(stripped)
    has_subshell_parens = "(" in unquoted or ")" in unquoted
    has_unsafe_ro_flag = bool(
        re.search(r"(?:^|\s)(?:--output(?:=|\s)|-o(?:\s|$)|--pre(?:=|\s))", unquoted, re.IGNORECASE)
    )
    if not chained and not has_file_redirect and not has_subshell_parens:
        if "--merge" not in stripped.lower() and BOOKKEEPING_CMD_RE.match(stripped):
            return "BOOKKEEPING"
        if not has_unsafe_ro_flag and READ_ONLY_CMD_RE.match(stripped):
            return "READ_ONLY"
    if not has_file_redirect:
        segments = _split_shell_segments(stripped)
        if segments and any(VALIDATION_SEGMENT_RE.match(seg) for seg in segments):
            return "VALIDATION"
    return "MUTATING_OR_UNKNOWN"


def resolve_command_cwd(cmd: str, default_cwd: str, session: str = "") -> str:
    fallback_root = ""
    if session:
        existing = rio.read_json(cwg.marker_path(session), default=None)
        if isinstance(existing, dict) and not existing.get("closed"):
            fallback_root = str(existing.get("git_root") or "")
    return rio.resolve_command_cwd(cmd, default_cwd, fallback_dir=fallback_root)


def take_git_snapshot(cwd: str) -> dict[str, Any]:
    root = rio.git_toplevel(cwd)
    if not root:
        return {"in_git": False, "cwd": rio.normalize_path(cwd)}
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
        if "R" in xy or "C" in xy:
            # In porcelain v1 -z, rename/copy has original path in next NUL slot
            if i < len(records):
                i += 1
        if CACHE_PATH_RE.search(rel.replace("\\", "/")):
            continue
        full = os.path.normpath(os.path.join(root, rel))
        norm = rio.normalize_path(full)
        token = f"{xy}:"
        if os.path.isfile(full):
            try:
                st = os.stat(full)
                if st.st_size <= 2_000_000:
                    with open(full, "rb") as fh:
                        digest = hashlib.sha256(fh.read()).hexdigest()[:20]
                    token += f"{st.st_size}:{digest}"
                else:
                    token += f"{st.st_size}:{st.st_mtime_ns}"
            except OSError:
                token += "stat_err"
        else:
            token += "absent"
        entries[norm] = token

    return {
        "in_git": True,
        "root": rio.normalize_path(root),
        "head": head,
        "entries": entries,
    }


def diff_git_snapshots(before: dict[str, Any] | None, after: dict[str, Any] | None) -> tuple[list[str], bool]:
    """Return `(changed_durable_paths, unmeasured)`."""
    if not isinstance(before, dict) or not isinstance(after, dict):
        return [], True
    if not before.get("in_git") or not after.get("in_git"):
        return [], True
    if before.get("unmeasured") or after.get("unmeasured"):
        return [], True
    if rio.fold_path(before.get("root")) != rio.fold_path(after.get("root")):
        return [], True

    changed: set[str] = set()
    b_entries: dict[str, str] = before.get("entries") or {}
    a_entries: dict[str, str] = after.get("entries") or {}
    for path, tok in a_entries.items():
        if b_entries.get(path) != tok:
            changed.add(path)
    for path in b_entries:
        if path not in a_entries:
            # Either deleted, restored, or committed; check if HEAD moved
            changed.add(path)

    # Also detect files committed if HEAD moved during command
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
        if rc == 0 and isinstance(out, (bytes, bytearray)):
            for rel_b in bytes(out).split(b"\0"):
                if not rel_b:
                    continue
                rel = rel_b.decode("utf-8", errors="replace")
                if not CACHE_PATH_RE.search(rel.replace("\\", "/")):
                    changed.add(rio.normalize_path(os.path.join(root, rel)))

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


def update_candidate_marker(
    session: str,
    cwd: str,
    durable_new_paths: list[str],
    operational_mutation: bool = False,
    changed_lines_delta: int = 0,
    shell_durable_edit: bool = False,
    unknown_barrier: bool = False,
    cause_label: str = "",
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    now = time.time()
    mp = cwg.marker_path(session)
    before = rio.read_json(mp, default=None)
    if not isinstance(before, dict) or before.get("closed"):
        marker: dict[str, Any] = {
            "session": session,
            "first_ts": now,
            "last_ts": now,
            "last_durable_ts": now if durable_new_paths else 0.0,
            "cwd": rio.normalize_path(cwd),
            "git_root": rio.normalize_path(rio.git_toplevel(cwd) or ""),
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
        if not marks or marks[-1].get("fp") != fp or mark_obj.get("unknown") or marks[-1].get("unknown"):
            marks.append(mark_obj)
        marker["content_marks"] = marks[-32:]
    elif operational_mutation:
        marker["operational"] = True
        dpaths = cwg.durable_paths(marker.get("paths"))
        if dpaths:
            marks = list(marker.get("content_marks") or [])
            fp = cwg.content_fingerprint(dpaths)
            last_fp = marks[-1].get("fp") if marks and isinstance(marks[-1], dict) else None
            if not fp:
                marks.append({"ts": now, "fp": None, "unknown": True, "cause": cause_label[:120]})
                marker["content_marks"] = marks[-32:]
            elif fp != last_fp:
                marks.append({"ts": now, "fp": fp, "cause": cause_label[:120]})
                marker["last_durable_ts"] = now
                marker["content_marks"] = marks[-32:]
            elif marks and marks[-1].get("unknown"):
                # Clear legacy unknown flag when SHA-256 fingerprint is confirmed identical
                cleaned = dict(marks[-1])
                cleaned.pop("unknown", None)
                marks[-1] = cleaned
                marker["content_marks"] = marks[-32:]

    rio.write_json(mp, marker)
    return before_open, marker


def build_transition_note(before: dict[str, Any] | None, after: dict[str, Any]) -> str | None:
    new_class = cwg.candidate_class(after)
    if new_class == cwg.WORK_NO_CHANGE:
        return None
    old_class = cwg.candidate_class(before)
    old_floor = cwg.candidate_floor(before)
    new_floor = cwg.candidate_floor(after)
    old_small = cwg.is_small_edit(before)
    new_small = cwg.is_small_edit(after)

    if old_class == new_class and old_floor == new_floor and old_small == new_small:
        return None

    if new_class == cwg.WORK_OPERATIONAL:
        return (
            "[Code Work Gate] Открыт OPERATIONAL-кандидат (мутация через shell без затронутых файлов репозитория). "
            "Завершите финальный ответ строкой `[gate] operational: <предпроверка>; <подтверждённый эффект>` "
            "или `[gate] no-change: <причина>`, если состояние не изменилось."
        )

    dpaths = cwg.durable_paths(after.get("paths"))
    shown = ", ".join(pathlib.PurePosixPath(p).name for p in dpaths[-3:])
    reqs = cwg.receipt_requirements_summary(new_floor, new_small)
    transition = (
        "открыт"
        if old_class != cwg.WORK_PERSISTENT
        else f"повышен риск до {new_floor}"
        if old_floor != new_floor
        else "вышел за пределы малой правки"
    )
    return (
        f"[Code Work Gate] Кандидат {transition}: PERSISTENT, уровень риска `{new_floor}` "
        f"(файлов: {len(dpaths)} — {shown}). Требуется: {reqs}. "
        f"Завершите финальный ответ строкой `[gate] verified: {new_floor}; <кандидат и решающие проверки>`."
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


def handle_pre_tool(payload: dict[str, Any]) -> None:
    steps = rio.read_transcript_steps(payload.get("transcriptPath"), max_lines=5)
    if rio.is_subagent_session(payload.get("transcriptPath"), steps=steps):
        rio.emit_pre_tool("allow")
        return

    session = rio.session_key(payload)
    cwd = rio.effective_cwd(payload)
    tc = payload.get("toolCall") if isinstance(payload.get("toolCall"), dict) else {}
    tool_name = str(tc.get("name") or "")
    call_id = str(tc.get("id") or uuid.uuid4().hex[:10])
    args = tc.get("args") if isinstance(tc.get("args"), dict) else {}

    if tool_name in EDIT_TOOLS:
        target_path = str(args.get("Path") or "")
        is_artifact = bool(args.get("ArtifactMetadata"))
        wps = payload.get("workspacePaths") if isinstance(payload.get("workspacePaths"), list) else None
        if target_path and not is_artifact and not cwg.is_scratch_or_ephemeral(
            target_path, payload.get("artifactDirectoryPath"), workspace_paths=wps, cwd=cwd
        ):
            cwg.publish_claim(session, paths=[target_path], cwd=cwd)

    elif tool_name in SHELL_TOOLS:
        cmd = str(args.get("CommandLine") or "")
        capture_direct_codex_packet(cmd, cwd, session)
        policy = classify_shell_command(cmd)
        if policy not in ("READ_ONLY", "BOOKKEEPING"):
            cmd_cwd = resolve_command_cwd(cmd, cwd, session=session)
            cwg.publish_claim(session, shell_active=True, cwd=cmd_cwd)
            snap = take_git_snapshot(cmd_cwd)
            snap["policy"] = policy
            snap["cmd"] = cmd[:240]
            snap["ts"] = time.time()
            rio.write_json(cwg.snapshot_path(session, call_id), snap)

    elif tool_name in SUBAGENT_TOOLS:
        rio.append_jsonl(
            cwg.launches_ledger_path(session),
            {
                "phase": "pre",
                "ts": time.time(),
                "call_id": call_id,
                "step_idx": payload.get("stepIdx"),
                "type_name": str(args.get("TypeName") or ""),
                "role": str(args.get("Role") or ""),
                "model": str(args.get("Model") or "inherit"),
                "workspace": str(args.get("Workspace") or "inherit"),
            },
        )

    rio.emit_pre_tool("allow")


def handle_post_tool(payload: dict[str, Any]) -> None:
    tc = payload.get("toolCall") if isinstance(payload.get("toolCall"), dict) else {}
    tool_name = str(tc.get("name") or "")
    args = tc.get("args") if isinstance(tc.get("args"), dict) else {}
    error_text = str(payload.get("error") or "").strip()
    failed = bool(error_text)

    # Fast exit on ordinary `read_file` calls before touching transcript files
    if tool_name == "read_file":
        if not failed:
            sm = SKILL_MD_RE.search(str(args.get("Path") or ""))
            if sm and not rio.is_subagent_session(payload.get("transcriptPath")):
                rio.append_jsonl(
                    cwg.checks_ledger_path(rio.session_key(payload)),
                    {
                        "kind": "skill_read",
                        "skill": sm.group("skill").lower(),
                        "ts": time.time(),
                        "step_idx": payload.get("stepIdx"),
                    },
                )
        rio.emit_json({})
        return

    steps = rio.read_transcript_steps(payload.get("transcriptPath"), max_lines=5)
    if rio.is_subagent_session(payload.get("transcriptPath"), steps=steps):
        rio.emit_json({})
        return

    session = rio.session_key(payload)
    cwd = rio.effective_cwd(payload)
    call_id = str(tc.get("id") or "call")

    if tool_name in SUBAGENT_TOOLS:
        rio.append_jsonl(
            cwg.launches_ledger_path(session),
            {
                "phase": "post",
                "ts": time.time(),
                "call_id": call_id,
                "step_idx": payload.get("stepIdx"),
                "type_name": str(args.get("TypeName") or ""),
                "model": str(args.get("Model") or "inherit"),
                "failed": failed,
                "error": error_text[:240] if failed else "",
            },
        )
        rio.emit_json({})
        return

    if tool_name in EDIT_TOOLS:
        if failed:
            rio.emit_json({})
            return
        target_path = str(args.get("Path") or "")
        is_artifact = bool(args.get("ArtifactMetadata"))
        wps = payload.get("workspacePaths") if isinstance(payload.get("workspacePaths"), list) else None
        if target_path and not is_artifact and not cwg.is_scratch_or_ephemeral(
            target_path, payload.get("artifactDirectoryPath"), workspace_paths=wps, cwd=cwd
        ):
            cwg.publish_claim(session, paths=[target_path], cwd=cwd)
            before, after = update_candidate_marker(
                session=session,
                cwd=cwd,
                durable_new_paths=[target_path],
                changed_lines_delta=estimate_changed_lines(tool_name, args),
                cause_label=f"{tool_name}:{pathlib.Path(target_path).name}",
            )
            note = build_transition_note(before, after)
            if note:
                cwg.queue_pending_note(session, note)
            rio.log_hook_event(
                "gate-events",
                "mark_edit",
                session=session,
                tool=tool_name,
                path=rio.normalize_path(target_path),
                floor=cwg.candidate_floor(after),
            )
        rio.emit_json({})
        return

    if tool_name in SHELL_TOOLS:
        cmd = str(args.get("CommandLine") or "")
        policy = classify_shell_command(cmd)
        if failed:
            codex_lane.record_from_command(cmd, error_text, exit_code=1)

        if policy == "VALIDATION":
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

        snap_file = cwg.snapshot_path(session, call_id)
        before_snap = rio.read_json(snap_file, default=None)
        if snap_file.exists():
            try:
                snap_file.unlink()
            except OSError:
                pass
        cmd_cwd = resolve_command_cwd(cmd, cwd, session=session)
        after_snap = take_git_snapshot(cmd_cwd)
        changed_paths, unmeasured = diff_git_snapshots(before_snap, after_snap)

        # Exclude files actively claimed by a different concurrent session
        wps = payload.get("workspacePaths") if isinstance(payload.get("workspacePaths"), list) else None
        if changed_paths:
            others = cwg.claimed_by_other_sessions(session, changed_paths)
            changed_paths = [
                p
                for p in changed_paths
                if rio.fold_path(p) not in others
                and not cwg.is_scratch_or_ephemeral(
                    p, payload.get("artifactDirectoryPath"), workspace_paths=wps, cwd=cmd_cwd
                )
            ]

        cwg.publish_claim(session, paths=changed_paths, shell_active=False, cwd=cmd_cwd)

        if changed_paths:
            before, after = update_candidate_marker(
                session=session,
                cwd=cmd_cwd,
                durable_new_paths=changed_paths,
                changed_lines_delta=10,
                shell_durable_edit=True,
                unknown_barrier=unmeasured,
                cause_label=f"run_command:{cmd[:60]}",
            )
            note = build_transition_note(before, after)
            if note:
                cwg.queue_pending_note(session, note)
            rio.log_hook_event(
                "gate-events",
                "mark_shell_durable",
                session=session,
                files=len(changed_paths),
                floor=cwg.candidate_floor(after),
            )
        elif policy == "MUTATING_OR_UNKNOWN" and not failed:
            before, after = update_candidate_marker(
                session=session,
                cwd=cmd_cwd,
                durable_new_paths=[],
                operational_mutation=True,
                unknown_barrier=unmeasured,
                cause_label=f"run_command:{cmd[:60]}",
            )
            note = build_transition_note(before, after)
            if note:
                cwg.queue_pending_note(session, note)
            rio.log_hook_event("gate-events", "mark_operational", session=session, cmd=cmd[:80])

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
