#!/usr/bin/env python3
"""PreToolUse safety & quality guards: subagent packet & nesting, and dirty-worktree/junction safety."""

from __future__ import annotations

import os
import pathlib
import re
import sys
from typing import Any

HOOKS_DIR = pathlib.Path(__file__).resolve().parent
TOOLS_DIR = HOOKS_DIR.parent / "tools"
sys.path.insert(0, str(HOOKS_DIR))

import cwg_common as cwg
import runtime_io as rio

HYDROGEN_POLICY_MSG = (
    "[Model Policy Guard] Модели Gemini Flash отключены. Используйте `Gemini 4 Hydrogen` с уровнем размышления по сложности задачи: "
    f"`{cwg.HYDROGEN_MODEL_BY_LEVEL['low']}` (атомарный smoke-check, <=150 строк перевода), "
    f"`{cwg.HYDROGEN_MODEL_BY_LEVEL['medium']}` (стандартный UI/перевод/разведка), "
    f"`{cwg.HYDROGEN_MODEL_BY_LEVEL['high']}` (сложные многошаговые сценарии и спецификации) "
    f"или `{cwg.HYDROGEN_MODEL_BY_LEVEL['xhigh']}` (тяжёлая отладка состояний и гонок)."
)

BARE_WORKTREE_REMOVE_RE = re.compile(
    r"\bgit(?:\.exe)?\s+(?:[^\n;|&]*\s+)?worktree\s+remove\b",
    re.IGNORECASE,
)

DESTRUCTIVE_GIT_RE = re.compile(
    r"\bgit(?:\.exe)?\s+(?:[^\n;|&]*\s+)?"
    r"(?:reset\s+--hard|checkout\s+--\s+\.|restore\s+(?:--staged\s+--worktree\s+|--worktree\s+)?\.|clean\s+-[a-zA-Z]*f[a-zA-Z]*)",
    re.IGNORECASE,
)

_CMD_BACKTICK_RE = re.compile(r"`([A-Za-z0-9_-])")


def _strip_cmd_backticks(text: str) -> str:
    # SAFETY: Normalize PowerShell backtick-escaped command tokens in `norm_cmd` while `stripped` preserves literal paths for `resolve_command_cwd`.
    if "`" not in text:
        return text
    return _CMD_BACKTICK_RE.sub(r"\1", text)


def _extract_codex_review_timeout_opts(cmd_str: str) -> dict[str, str] | None:
    import codex_lane
    import cwg_mark

    folded = codex_lane._fold_ps_line_continuations(cmd_str)
    for _, seg_str in cwg_mark._split_shell_segments(folded):
        seg = cwg_mark._ps_tokens(seg_str)
        for idx, tok in enumerate(seg):
            if os.path.basename(tok.replace("\\", "/")).lower() != "codex_lane.py":
                continue
            if idx + 1 >= len(seg) or seg[idx + 1].lower() != "review":
                continue
            opts: dict[str, str] = {}
            rem = seg[idx + 2 :]
            j = 0
            while j < len(rem):
                rtok = rem[j]
                low_rtok = rtok.lower()
                if low_rtok in codex_lane._REVIEW_BOOL_FLAGS:
                    opts[low_rtok] = "1"
                    j += 1
                    continue
                opt, sep, inline_val = rtok.partition("=")
                low_opt = opt.lower()
                if low_opt in codex_lane._REVIEW_VAL_FLAGS:
                    if sep:
                        opts[low_opt] = inline_val
                        j += 1
                    elif j + 1 < len(rem) and not rem[j + 1].startswith("--"):
                        opts[low_opt] = rem[j + 1]
                        j += 2
                    else:
                        opts[low_opt] = ""
                        j += 1
                    continue
                j += 1
            if "--timeout" in opts:
                return opts
    return None


def _check_codex_review_timeout_policy(
    norm_cmd: str,
    stripped: str,
    cwd: str,
    session: str,
) -> tuple[str, str | None]:
    low_cmd = norm_cmd.lower()
    if "codex_lane.py" not in low_cmd or "--timeout" not in low_cmd:
        return "allow", None
    parsed_opts = _extract_codex_review_timeout_opts(norm_cmd) or _extract_codex_review_timeout_opts(stripped)
    if parsed_opts is None:
        return "allow", None
    import codex_lane

    raw_to = parsed_opts["--timeout"].strip()

    base_cwd = rio.resolve_command_cwd(stripped, cwd)
    raw_cwd_opt = parsed_opts.get("--cwd", "").strip()
    if raw_cwd_opt:
        eff_cwd = (
            os.path.abspath(raw_cwd_opt)
            if os.path.isabs(raw_cwd_opt)
            else os.path.abspath(os.path.join(base_cwd, raw_cwd_opt))
        )
    else:
        eff_cwd = base_cwd
    git_root = rio.git_toplevel(eff_cwd) or eff_cwd

    raw_sess_opt = parsed_opts.get("--session", "").strip()
    eff_session = raw_sess_opt if raw_sess_opt else (session if session != "unknown" else "")
    has_new_sess = bool(parsed_opts.get("--new-session"))
    is_xhigh = bool(parsed_opts.get("--xhigh"))
    tstate = None if has_new_sess else codex_lane.active_thread_state(eff_session, git_root)
    # INVARIANT: Forbid custom upfront `--timeout` on `codex_lane.py review`; standard defaults are 600s (HIGH) and 900s (XHIGH).
    if not tstate or not tstate.get("pending_timeout_resume"):
        return (
            "deny",
            "[Codex Timeout Policy] Запрещено передавать свой `--timeout` заранее при вызове `codex_lane.py review`: "
            f"штатный таймаут уже составляет 10 минут (`{codex_lane.DEFAULT_REVIEW_TIMEOUT_SECONDS}s`) для `HIGH` "
            f"и 15 минут (`{codex_lane.DEFAULT_XHIGH_REVIEW_TIMEOUT_SECONDS}s`) для `--xhigh`. "
            "Запустите `codex_lane.py review` без флага `--timeout`.",
        )

    req_min = codex_lane.required_review_timeout(is_xhigh, tstate.get("next_timeout_seconds") or 0)
    if not raw_to.isdigit() or int(raw_to) < req_min:
        return (
            "deny",
            f"[Codex Timeout Policy] После незавершённого таймаута Codex нельзя занижать `--timeout` до `{raw_to}s` "
            f"(требуется `>= {req_min}s`). Уберите флаг `--timeout` — `codex_lane.py review` автоматически продолжит "
            f"сохранённую сессию с таймаутом `{req_min}s` без потери раунда.",
        )
    if int(raw_to) > codex_lane.MAX_REVIEW_TIMEOUT_SECONDS:
        return (
            "deny",
            f"[Codex Timeout Policy] Значение `--timeout {raw_to}` превышает потолок `{codex_lane.MAX_REVIEW_TIMEOUT_SECONDS}s`. "
            "Уберите флаг `--timeout` для автоматического продолжения сессии.",
        )
    return "allow", None


def guard_shell_command(cmd: str, cwd: str, session: str = "") -> tuple[str, str | None]:
    stripped = rio.unwrap_tokenade_command(cmd or "")
    if not stripped:
        return "allow", None
    norm_cmd = _strip_cmd_backticks(stripped)

    to_dec, to_reason = _check_codex_review_timeout_policy(norm_cmd, stripped, cwd, session)
    if to_dec != "allow":
        return to_dec, to_reason

    # 1. Block unsafe bare `git worktree remove` (unless invoked inside worktree_guard.py itself)
    if BARE_WORKTREE_REMOVE_RE.search(norm_cmd) and "worktree_guard.py" not in norm_cmd:
        guard_script = rio.normalize_path(TOOLS_DIR / "worktree_guard.py")
        return (
            "deny",
            "[Worktree Safety Guard] Прямой вызов `git worktree remove` на Windows опасен (Git рекурсивно обходит NTFS junctions вроде `node_modules`/`.venv` и может удалить файлы основного дерева, а незакоммиченные правки теряются). "
            f"Используйте безопасную обёртку: `python -X utf8 \"{guard_script}\" remove --worktree <path>`.",
        )

    # 2. Protect uncommitted dirty worktree from destructive git wipe commands
    if DESTRUCTIVE_GIT_RE.search(norm_cmd):
        eff_cwd = rio.resolve_command_cwd(stripped, cwd)
        git_root = rio.git_toplevel(eff_cwd, include_home_root=True)
        if git_root:
            if rio.is_unapproved_home_git_root(eff_cwd, git_root) and (
                rio.fold_path(os.path.abspath(eff_cwd)) != rio.fold_path(git_root)
            ):
                return (
                    "deny",
                    "[Dirty Worktree Protection] Разрушающая Git-команда запущена во вложенном каталоге без собственного `.git` и поднимется в корневой `$HOME/.git`, "
                    "что грозит безвозвратной потерей файлов домашнего каталога.",
                )
            rc, st_out, _ = rio.run_git(git_root, ["status", "--porcelain=v1"], timeout=4.0)
            if (rc == 0 and str(st_out or "").strip()) or rc == 124:
                guard_script = rio.normalize_path(TOOLS_DIR / "worktree_guard.py")
                return (
                    "deny",
                    "[Dirty Worktree Protection] Рабочее дерево содержит незакоммиченные изменения, которые будут безвозвратно уничтожены этой командой. "
                    f"Сначала сохраните снимок состояния без изменения индекса: `python -X utf8 \"{guard_script}\" snapshot --label before-reset`, "
                    "либо откатывайте только конкретные собственные хунки.",
                )

    return "allow", None


def _is_simplify_swarm_target(name: str, brief: str) -> bool:
    if cwg.is_simplify_worker_name(name):
        return True
    low_brief = (brief or "").lower()
    return "simplify_lens:" in low_brief or "simplify_verdict:" in low_brief


def _is_adversarial_review_swarm_target(name: str, model: str, brief: str) -> bool:
    if _is_simplify_swarm_target(name, brief):
        return False
    low_model = (model or "").strip().lower()
    if low_model not in (cwg.OPUS_HIGH_MODEL, cwg.CARBON_HIGH_MODEL):
        return False
    low_name = (name or "").strip().lower()
    low_brief = (brief or "").lower()
    return (
        "review" in low_name
        or "verdict:" in low_brief
        or "closure_validation:" in low_brief
    )


def _pending_codex_timeout_escalation_deny(
    payload: dict[str, Any] | None,
    target_label: str,
) -> str | None:
    if not isinstance(payload, dict):
        return None
    import codex_lane

    session = rio.session_key(payload)
    if not session or session == "unknown":
        return None
    cwd = rio.effective_cwd(payload)
    git_root = rio.git_toplevel(cwd) or cwd
    tstate = codex_lane.active_thread_state(session, git_root)
    if not tstate or not tstate.get("pending_timeout_resume"):
        return None
    if codex_lane.breaker_status().get("tripped") or not codex_lane.find_codex_binary():
        return None
    next_to = int(tstate.get("next_timeout_seconds") or codex_lane.DEFAULT_XHIGH_REVIEW_TIMEOUT_SECONDS)
    sid_note = str(tstate.get("session_id") or "auto")
    # INVARIANT: Block switching to internal review after a non-network Codex thinking timeout while Codex remains healthy.
    return (
        f"[Codex Timeout Policy] Переключение на внутреннее ревью (`{target_label}`) после таймаута размышления Codex запрещено: "
        "локальный таймаут не является сбоем Codex и не расходует раунд ревью. "
        f"Повторите вызов `codex_lane.py review` без флага `--timeout`, чтобы продолжить ту же сессию Codex (`{sid_note}`) "
        f"с увеличенным таймаутом (`{next_to}s`)."
    )


def guard_swarm_invocation(
    args: dict[str, Any],
    payload: dict[str, Any] | None = None,
) -> tuple[str, str | None]:
    action = str(args.get("action") or "").strip().lower()
    if action not in ("add", "model"):
        return "allow", None
    model = str(args.get("model") or "").strip()
    if model and cwg.FLASH_MODEL_RE.search(model):
        return "deny", HYDROGEN_POLICY_MSG
    name_str = str(args.get("name") or "")
    brief_str = str(args.get("brief") or "")
    if _is_simplify_swarm_target(name_str, brief_str):
        if not model or model.lower() not in cwg.SIMPLIFY_ALLOWED_MODELS:
            # SAFETY: Never allow simplify workers to default to or target Carbon, preserving main-agent quota.
            return (
                "deny",
                f"[Simplify Model Policy] Линзы simplify запрещено запускать на `{model or 'inherit (Carbon)'}`, "
                f"чтобы не сжигать лимиты `{cwg.CARBON_HIGH_MODEL}`. Используйте `{cwg.SONNET_HIGH_MODEL}`, "
                f"а при исчерпании квоты/сбое Sonnet — `{cwg.SIMPLIFY_FALLBACK_MODEL}` через "
                f"`swarm(action='add', ..., model='{cwg.SIMPLIFY_FALLBACK_MODEL}')`.",
            )
    caller_worker = resolve_swarm_worker_identity(payload) if payload else ""
    is_non_coord_worker = bool(caller_worker and caller_worker.lower() not in rio.COORDINATOR_ROLE_NAMES)
    if (
        action == "add"
        and _is_adversarial_review_swarm_target(name_str, model, brief_str)
        and not is_non_coord_worker
    ):
        esc_deny = _pending_codex_timeout_escalation_deny(payload, model or name_str)
        if esc_deny:
            return "deny", esc_deny
    return "allow", None


def guard_subagent_invocation(
    payload: dict[str, Any], args: dict[str, Any]
) -> tuple[str, str | None, dict[str, Any] | None]:
    transcript_path = payload.get("transcriptPath")
    prompt = str(args.get("Prompt") or "").strip()
    role = str(args.get("Role") or "").strip()
    req_model = str(args.get("Model") or "").strip().lower()
    sub_type = str(args.get("TypeName") or "").strip().lower()
    base_sub_type = sub_type.rsplit(":", 1)[-1]
    is_simplify_sub = cwg.is_simplify_subagent_call(base_sub_type, role)

    if req_model and cwg.FLASH_MODEL_RE.search(req_model):
        suffix = (
            "Для `browser` запустите swarm-воркера на `gemini-4-hydrogen-<low|medium|high|xhigh>`, который вызовет `invoke_subagent(TypeName='browser', Model='inherit')` (либо передайте `Model='inherit'` внутри Hydrogen-сессии)."
            if base_sub_type == "browser"
            else "Запустите задачу через `swarm(action='add', model='gemini-4-hydrogen-<low|medium|high|xhigh>')` или передайте `Model='inherit'` внутри Hydrogen-сессии."
        )
        return "deny", f"{HYDROGEN_POLICY_MSG} {suffix}", None

    steps_head = rio.read_transcript_head(transcript_path, head_lines=8)
    is_delegated = rio.is_subagent_session(transcript_path, steps=steps_head)
    worker_model = rio.swarm_worker_model(
        transcript_path,
        steps=steps_head,
        conversation_id=payload.get("conversationId") or payload.get("session_id"),
    )
    is_swarm_worker = bool(worker_model)

    if not is_swarm_worker and base_sub_type in cwg.NATIVE_REVIEWERS:
        esc_deny = _pending_codex_timeout_escalation_deny(payload, base_sub_type)
        if esc_deny:
            return "deny", esc_deny, None

    if is_simplify_sub and not (worker_model in cwg.SIMPLIFY_FALLBACK_MODELS and req_model in ("", "inherit")):
        # SAFETY: Direct `invoke_subagent` from a Carbon session inherits Carbon and burns primary quota; enforce swarm Hydrogen fallback.
        return (
            "deny",
            f"[Simplify Model Policy] Прямой вызов субагента `{base_sub_type}` из не-Hydrogen сессии наследует "
            f"`{cwg.CARBON_HIGH_MODEL}` и сжигает квоту основной модели. Запускайте simplify через "
            f"`swarm(action='add', ..., model='{cwg.SONNET_HIGH_MODEL}')`, а при исчерпании квоты/сбое Sonnet — "
            f"через `swarm(action='add', ..., model='{cwg.SIMPLIFY_FALLBACK_MODEL}')`.",
            None,
        )

    allow_swarm_delegation = bool(
        is_swarm_worker and req_model in ("", "inherit") and (base_sub_type == "browser" or is_simplify_sub)
    )
    if is_delegated and not allow_swarm_delegation and "[allow-nested-subagent]" not in prompt:
        return (
            "deny",
            "[Subagent Nesting Guard] Вложенный запуск субагента изнутри субагента заблокирован во избежание каскадного размножения контекстов. "
            "Завершите свою ограниченную задачу и верните результат родительскому агенту.",
            None,
        )

    # 3. Require bounded actionable prompt
    if len(prompt) < 16:
        return (
            "deny",
            "[Subagent Delegation Guard] Промпт субагента слишком короткий и не содержит границ задачи и ожидаемого результата.",
            None,
        )

    # 4. Propagate active Handoff / Checkpoint constraints automatically
    if "[Canonical Constraints]" not in prompt:
        import continuity

        eff_cwd = rio.effective_cwd(payload)
        wps = payload.get("workspacePaths") if isinstance(payload.get("workspacePaths"), list) else None
        active_req, cancelled_req = continuity.active_constraints(eff_cwd, wps, session=rio.session_key(payload))
        extra_lines: list[str] = []
        if active_req:
            extra_lines.append(f"- Active Requirements: {active_req}")
        if cancelled_req:
            extra_lines.append(f"- Cancelled / Do NOT Reintroduce: {cancelled_req}")
        if extra_lines:
            enriched = prompt + "\n\n[Canonical Constraints]\n" + "\n".join(extra_lines)
            return "allow", None, {"Prompt": enriched}

    return "allow", None, None


_SWARM_TAG_RE = re.compile(r"<swarm_worker>\s*You are\s+([A-Za-z0-9._-]+)", re.IGNORECASE)


def _resolve_brain_root_for_payload(payload: dict[str, Any]) -> pathlib.Path:
    tp = payload.get("transcriptPath")
    if tp:
        try:
            p = pathlib.Path(str(tp)).resolve()
            if len(p.parents) >= 4 and p.parents[1].name == ".system_generated":
                return p.parents[3]
        except OSError:
            pass
    return rio.resolve_brain_root()


def resolve_swarm_worker_identity(payload: dict[str, Any]) -> str:
    tc = payload.get("toolCall") if isinstance(payload.get("toolCall"), dict) else {}
    for container in (payload, tc):
        for key in ("worker_name", "workerName", "agent_name", "agentName"):
            val = str(container.get(key) or "").strip()
            if val:
                return "" if val.lower() in rio.COORDINATOR_ROLE_NAMES else val
    for key in rio.WORKER_ENV_KEYS:
        val = str(os.environ.get(key) or "").strip()
        if val:
            return "" if val.lower() in rio.COORDINATOR_ROLE_NAMES else val

    session = rio.session_key(payload)
    tp = payload.get("transcriptPath")
    is_user_root = False
    if tp:
        head_steps = rio.read_transcript_head(str(tp), head_lines=5)
        for st in head_steps[:3]:
            if isinstance(st, dict):
                m = _SWARM_TAG_RE.search(str(st.get("content") or ""))
                if m:
                    cand_w = m.group(1).strip()
                    return "" if cand_w.lower() in rio.COORDINATOR_ROLE_NAMES else cand_w
        winfo = rio.resolve_swarm_worker_assignment(str(tp), steps=head_steps, conversation_id=session)
        if winfo is not None:
            return str(winfo["worker_name"])
        if head_steps and isinstance(head_steps[0], dict):
            s0 = head_steps[0]
            is_user_root = str(s0.get("type") or "") == "USER_INPUT" and str(s0.get("source") or "") in (
                "USER_EXPLICIT",
                "USER",
            )

    raw_id = ""
    for container in (payload, tc):
        for key in ("agent_id", "agentId", "worker_id", "workerId"):
            cand = str(container.get(key) or "").strip()
            if cand:
                raw_id = cand
                break
        if raw_id:
            break
    if not raw_id:
        raw_id = str(os.environ.get("AGENT_ID") or "").strip()

    brain_root = _resolve_brain_root_for_payload(payload)
    lookup_cids = [c for c in (raw_id, session) if c and c != "unknown"]
    if lookup_cids and (raw_id or not is_user_root):
        cand_coords = (session,) if session and session != "unknown" else ()
        for cid in lookup_cids:
            reg = rio._resolve_registered_swarm_worker(brain_root, cid, cand_coords)
            if reg is not None:
                return str(reg["worker_name"])
    return "" if raw_id.lower() in rio.COORDINATOR_ROLE_NAMES else raw_id


def _prior_board_read_in_transcript(tp: str | None) -> bool:
    if not tp:
        return False
    steps = rio.read_transcript_steps(str(tp), max_lines=400)
    for st in steps:
        if not isinstance(st, dict):
            continue
        for call in st.get("tool_calls") or []:
            if isinstance(call, dict) and str(call.get("name") or "") == "read_board":
                return True
    return False


def _cursor_state_path(session: str) -> pathlib.Path:
    return cwg.gate_dir("board_cursors") / f"{rio.safe_key(session)}.json"


def _coerce_nonneg_int(raw: Any) -> int:
    try:
        return int(raw) if raw is not None and str(raw).strip() != "" else 0
    except (TypeError, ValueError):
        return 0


def guard_read_board(
    payload: dict[str, Any],
    args: dict[str, Any],
    cwd: str,
) -> tuple[str, str | None]:
    session = rio.session_key(payload)
    tp = str(payload.get("transcriptPath") or "")
    _, messages = cwg.load_swarm_board_messages(session=session, cwd=cwd, transcript_path=tp)
    head_seq = max((int(m.get("_seq") or 0) for m in messages), default=0)

    raw_since = args.get("since")
    if raw_since is None:
        raw_since = args.get("after", args.get("cursor"))
    since_val = _coerce_nonneg_int(raw_since)

    cpath = _cursor_state_path(session)
    state = rio.read_json(cpath, default=None)
    if not isinstance(state, dict):
        state = {}
    last_seen = int(state.get("last_seen_id") or 0)
    read_count = int(state.get("read_count") or 0)

    if read_count == 0 and _prior_board_read_in_transcript(tp):
        read_count = 1
        if last_seen <= 0:
            last_seen = head_seq or len(messages)

    if len(messages) > cwg.BOARD_CURSOR_THRESHOLD and since_val <= 0 and (read_count > 0 or last_seen > 0):
        suggested = max(last_seen, head_seq) if last_seen <= 0 else last_seen
        return (
            "deny",
            f"[Swarm Cursor Guard] В `board.jsonl` накопилось {len(messages)} сообщений (> {cwg.BOARD_CURSOR_THRESHOLD}), "
            f"и доска уже читалась в этой сессии. Повторный `read_board` без курсора раздувает контекст — "
            f"передайте `since={suggested}` (текущий head=#{head_seq}).",
        )

    rio.write_json(
        cpath,
        {
            "session": session,
            "last_seen_id": max(last_seen, head_seq),
            "read_count": read_count + 1,
            "total_messages": len(messages),
        },
    )
    return "allow", None


def _ownership_target_path(args: dict[str, Any]) -> str:
    for key in ("Path", "TargetFile", "FilePath", "path", "file_path"):
        val = str(args.get(key) or "").strip()
        if val:
            return val
    return ""


_COPY_VERBS = frozenset({"copy-item", "cpi", "copy", "cp"})
_MOVE_VERBS = frozenset({"move-item", "mi", "move", "mv", "rename-item", "rni", "ren"})
_DELETE_OR_WRITE_VERBS = frozenset(
    {
        "remove-item",
        "ri",
        "rm",
        "del",
        "erase",
        "rmdir",
        "rd",
        "new-item",
        "ni",
        "touch",
        "set-content",
        "sc",
        "add-content",
        "ac",
        "out-file",
        "tee-object",
        "tee",
    }
)
_KNOWN_FILE_MUTATION_VERBS = _COPY_VERBS | _MOVE_VERBS | _DELETE_OR_WRITE_VERBS


def _classify_ownership_target(raw_path: str, repo_root: str) -> tuple[bool, str, bool]:
    in_repo, rel, probe_path = cwg.resolve_repo_rel_info(raw_path, repo_root)
    # SAFETY: Within `.swarm/`, only worker artifacts (`.swarm/artifacts/**`) are writable by workers;
    # `.swarm/ownership.json` and swarm metadata stay protected under File Ownership Guard.
    if rel == ".swarm" or rel.startswith(".swarm/"):
        return in_repo, rel, rel.startswith(".swarm/artifacts/")
    is_ephemeral = cwg.is_scratch_or_ephemeral(probe_path, cwd=repo_root)
    return in_repo, rel, is_ephemeral


def _find_ownership_manifest_root(start_dir: str) -> str:
    try:
        cur = pathlib.Path(start_dir).resolve()
    except OSError:
        return ""
    for d in (cur, *cur.parents):
        try:
            if (d / ".swarm" / "ownership.json").is_file():
                return str(d)
        except OSError:
            continue
    return ""


def _is_isolated_worker_worktree(eff_cwd: str, target_path: str, manifest_root: str, worker: str) -> bool:
    safe_worker = rio.safe_key(worker, "")
    if not safe_worker or not manifest_root:
        return False
    wt_dir = (pathlib.Path(manifest_root) / ".swarm" / "worktrees" / safe_worker).resolve()
    wt_fold = rio.fold_path(wt_dir)
    if not wt_fold:
        return False
    cwd_fold = rio.fold_path(pathlib.Path(eff_cwd).resolve()) if eff_cwd else ""
    if cwd_fold != wt_fold and not cwd_fold.startswith(wt_fold + "/"):
        return False
    if not target_path:
        return True
    t_path = pathlib.Path(target_path)
    if not t_path.is_absolute():
        t_path = pathlib.Path(eff_cwd) / t_path
    t_fold = rio.fold_path(t_path.resolve())
    return t_fold == wt_fold or t_fold.startswith(wt_fold + "/")


def _resolve_target_against_cwd(raw_target: str, seg_cwd: str) -> str:
    p = pathlib.Path(raw_target)
    if p.is_absolute() or not seg_cwd:
        return raw_target
    return str(pathlib.Path(seg_cwd) / p)


def _flagged_values(flagged: dict[str, list[str]], keys: frozenset[str] | tuple[str, ...]) -> list[str]:
    out: list[str] = []
    for k in keys:
        out.extend(flagged.get(k) or [])
    return out


def _extract_file_verb_targets(tokens: list[str], seg_cwd: str, cwg_mark_mod: Any) -> list[str]:
    if not tokens:
        return []
    verb = pathlib.Path(tokens[0]).name.lower()
    if verb not in _KNOWN_FILE_MUTATION_VERBS:
        return []
    path_flags = cwg_mark_mod._PS_PATH_FLAGS | cwg_mark_mod._PS_DEST_FLAGS | {"-newname"}
    val_flags = cwg_mark_mod._PS_NON_PATH_VALUE_FLAGS | {"-width"}
    rest = tokens[1:]
    flagged: dict[str, list[str]] = {}
    positional: list[str] = []
    idx = 0
    while idx < len(rest):
        tok = rest[idx]
        low = tok.lower()
        if low in path_flags and idx + 1 < len(rest):
            flagged.setdefault(low, []).append(rest[idx + 1])
            idx += 2
            continue
        if low in val_flags and idx + 1 < len(rest):
            idx += 2
            continue
        if tok.startswith("-"):
            idx += 1
            continue
        positional.append(tok)
        idx += 1

    raw_targets: list[str] = []
    if verb in _COPY_VERBS:
        dests = _flagged_values(flagged, cwg_mark_mod._PS_DEST_FLAGS)
        if dests:
            raw_targets.extend(dests)
        elif positional:
            raw_targets.append(positional[-1])
    elif verb in _MOVE_VERBS:
        src_paths = _flagged_values(flagged, cwg_mark_mod._PS_PATH_FLAGS)
        raw_targets.extend(src_paths)
        raw_targets.extend(_flagged_values(flagged, cwg_mark_mod._PS_DEST_FLAGS))
        for new_name in flagged.get("-newname") or []:
            src_list = src_paths or positional[:1]
            if src_list and "/" not in new_name and "\\" not in new_name:
                parent_dir = str(pathlib.Path(_resolve_target_against_cwd(src_list[0], seg_cwd)).parent)
                raw_targets.append(str(pathlib.Path(parent_dir) / new_name))
            else:
                raw_targets.append(new_name)
        raw_targets.extend(positional)
    else:
        raw_targets.extend(_flagged_values(flagged, cwg_mark_mod._PS_PATH_FLAGS))
        raw_targets.extend(positional)
    return [_resolve_target_against_cwd(t, seg_cwd) for t in raw_targets if t.strip()]


_READONLY_SWARM_CTL_SUBCMDS = {
    ("ownership", "verify-git-diff"),
    ("worktree", "status"),
    ("board", "summary"),
}
_NESTED_SUBEXPR_RE = re.compile(
    r"\$\(|\&\(|\@\(|`|\b(?:Invoke-Expression|iex)\b",
    re.IGNORECASE,
)


def _is_blocked_worker_swarm_ctl(tokens: list[str], seg_text: str, cwg_mark_mod: Any) -> bool:
    clean_toks = [t.replace('"', "").replace("'", "") for t in tokens]
    matched_idx: int | None = None
    for idx, tok in enumerate(clean_toks):
        norm = tok.lstrip("&.").replace("\\", "/").lower()
        name = pathlib.Path(norm).name.lower() if norm else ""
        if name in ("swarm_ctl", "swarm_ctl.py") or norm == "plugin.tools.swarm_ctl":
            matched_idx = idx
            break

    if matched_idx is None:
        stripped_low = re.sub(r"[\"'`]", "", seg_text).lower()
        return bool(re.search(r"\bswarm_ctl(?:\.py)?\b[^\n;|&]*\b(?:ownership|worktree)\b", stripped_low))

    invokers = cwg_mark_mod._INTERPRETER_BASENAMES | {"swarm_ctl", "swarm_ctl.py", "env", "&", "."}
    first_name = pathlib.Path(clean_toks[0].lstrip("&.")).name.lower() if clean_toks else ""
    rest = clean_toks[matched_idx + 1 :]
    pos: list[str] = []
    i = 0
    while i < len(rest):
        tok = rest[i]
        low = tok.lower()
        if not pos and low == "--cwd" and i + 1 < len(rest):
            i += 2
            continue
        if not pos and low.startswith("--cwd="):
            i += 1
            continue
        if tok.startswith("-"):
            break
        pos.append(low)
        i += 1

    # SAFETY: allow swarm_ctl as read target (e.g. git diff / Get-Content) only when it is not invoked and has no subcommand tokens.
    if matched_idx > 0 and first_name not in invokers and (not pos or pos[0] not in ("ownership", "worktree", "board")):
        return False
    return tuple(pos[:2]) not in _READONLY_SWARM_CTL_SUBCMDS


def _guard_worker_shell_ownership(
    cmd_text: str,
    eff_cwd: str,
    manifest_root: str,
    worker: str,
    owned: list[str],
) -> tuple[str, str | None]:
    import cwg_mark

    core = cwg_mark._strip_null_pipe(cmd_text)
    if not core:
        return "allow", None
    unquoted_core = cwg_mark._strip_quoted(core)
    if (
        cwg_mark._extract_ps_subexprs(core)
        or _NESTED_SUBEXPR_RE.search(cwg_mark._strip_single_quoted(core))
        or any(ch in unquoted_core for ch in ("(", ")", "{", "}"))
    ):
        return (
            "deny",
            f"[File Ownership Guard] Вложенные shell-выражения, скобочные группы и подстановки (`(...)`, `{{...}}`, `$(...)`, backticks, `iex`) "
            f"запрещены для воркера `{worker}` при активном `.swarm/ownership.json`.",
        )
    cur_cwd = eff_cwd or manifest_root
    segments = cwg_mark._split_shell_segments(core)
    if not segments:
        segments = [(cur_cwd, core)]

    for _, seg_text in segments:
        tokens = cwg_mark._ps_tokens(seg_text)
        if _is_blocked_worker_swarm_ctl(tokens, seg_text, cwg_mark):
            return (
                "deny",
                f"[File Ownership Guard] Воркер `{worker}` не может изменять манифест `.swarm/ownership.json` "
                "или структуру worktrees (`ownership set|clear`, `worktree create|cleanup` разрешены только координатору).",
            )

        seg_cwd = cur_cwd
        cleaned_seg, raw_redir_targets = cwg_mark.extract_ps_redirections(seg_text)
        redir_targets = [_resolve_target_against_cwd(rt, seg_cwd) for rt in raw_redir_targets]

        verb = pathlib.Path(tokens[0]).name.lower() if tokens else ""
        if verb in ("cd", "chdir", "set-location", "sl", "push-location", "pushd"):
            nav_pos: list[str] = []
            nav_ok = bool(cwg_mark.NAV_SEGMENT_RE.match(cleaned_seg)) and not redir_targets
            if nav_ok:
                ni = 1
                while ni < len(tokens):
                    nt = tokens[ni]
                    nlow = nt.lower()
                    if nlow in ("-path", "-p", "-literalpath", "-lp"):
                        if ni + 1 >= len(tokens):
                            nav_ok = False
                            break
                        nav_pos.append(tokens[ni + 1])
                        ni += 2
                    elif nlow == "-passthru":
                        ni += 1
                    elif nt.startswith("-"):
                        nav_ok = False
                        break
                    else:
                        nav_pos.append(nt)
                        ni += 1
            if not nav_ok or len(nav_pos) > 1 or (
                nav_pos and any(ch in nav_pos[0] for ch in ("$", ",", "(", ")", "{", "}", "`"))
            ):
                return (
                    "deny",
                    f"[File Ownership Guard] Недопустимые аргументы или выражения в команде смены каталога `{verb}` воркера `{worker}`.",
                )
            if nav_pos:
                p = pathlib.Path(nav_pos[0])
                cur_cwd = str((p if p.is_absolute() else (pathlib.Path(cur_cwd) / p)).resolve())
            continue

        verb_targets = _extract_file_verb_targets(tokens, seg_cwd, cwg_mark)

        for candidate in redir_targets + verb_targets:
            if any(ch in candidate for ch in ("$", ",", "`")):
                return (
                    "deny",
                    f"[File Ownership Guard] Переменные и списки путей через запятую (`$`, `,`) в shell-целях "
                    f"запрещены для воркера `{worker}` при активном `.swarm/ownership.json`.",
                )
            if _is_isolated_worker_worktree(eff_cwd, candidate, manifest_root, worker):
                continue
            _, rel, is_ephemeral = _classify_ownership_target(candidate, manifest_root)
            if is_ephemeral:
                continue
            if not owned or not cwg.path_matches_any_glob(rel, owned):
                return (
                    "deny",
                    f"[File Ownership Guard] Shell-операция воркера `{worker}` затрагивает `{rel}` вне owned_paths={owned}. "
                    "Выполняйте запись только в свои файлы или через изолированный worktree.",
                )

        if verb in _KNOWN_FILE_MUTATION_VERBS:
            if not verb_targets:
                return (
                    "deny",
                    f"[File Ownership Guard] Не удалось определить целевой путь файловой команды `{verb}` воркера `{worker}`. "
                    "Используйте явный путь внутри `owned_paths` или `edit_file`/`write_file`.",
                )
            continue

        seg_to_check = cleaned_seg if redir_targets else seg_text
        if seg_to_check and cwg_mark.classify_shell_command(seg_to_check) not in ("READ_ONLY", "BOOKKEEPING", "VALIDATION"):
            return (
                "deny",
                f"[File Ownership Guard] Произвольная или непроверяемая shell-мутация воркера `{worker}` запрещена при активном `.swarm/ownership.json`: "
                f"используйте `edit_file`/`write_file` в рамках owned_paths={owned} или изолированный worktree (`swarm_ctl.py worktree create`).",
            )
    return "allow", None


def guard_file_ownership(
    payload: dict[str, Any],
    tool_name: str,
    args: dict[str, Any],
    cwd: str,
) -> tuple[str, str | None]:
    target_path = _ownership_target_path(args)
    eff_cwd = cwd or (str(pathlib.Path(target_path).parent) if target_path else "")
    manifest_root = _find_ownership_manifest_root(eff_cwd) if eff_cwd else ""
    if not manifest_root:
        return "allow", None
    manifest_doc = rio.read_json(pathlib.Path(manifest_root) / ".swarm" / "ownership.json", default=None)
    manifest = manifest_doc if isinstance(manifest_doc, dict) else {"workers": {}}
    workers = manifest.get("workers")
    if not isinstance(workers, dict) or not workers:
        return "allow", None

    worker = resolve_swarm_worker_identity(payload)
    cmd_text = str(args.get("CommandLine") or "") if tool_name == "run_command" else ""
    is_coord = not worker or worker.lower() in rio.COORDINATOR_ROLE_NAMES
    is_swarm_ctl_fix = is_coord and "swarm_ctl" in cmd_text and "ownership" in cmd_text
    if not is_swarm_ctl_fix:
        # INVARIANT: PreToolUse runs pure syntactic overlap checks (O(W^2*G^2)) without spawning `git ls-files`.
        overlaps = cwg.detect_ownership_overlaps(manifest, repo_root="")
        if overlaps:
            pair = overlaps[0]
            return (
                "deny",
                f"[File Ownership Guard] Пересечение `owned_paths` в `.swarm/ownership.json`: "
                f"`{pair['worker_a']}` ({pair['glob_a']}) vs `{pair['worker_b']}` ({pair['glob_b']}). "
                "Устраните пересечение через `swarm_ctl.py ownership set` или выделите изолированные `worktree create`.",
            )

    if is_coord:
        return "allow", None

    entry = workers.get(worker)
    owned = list(entry.get("paths") or []) if isinstance(entry, dict) else []

    if tool_name in ("edit_file", "write_file") and target_path:
        if _is_isolated_worker_worktree(eff_cwd, target_path, manifest_root, worker):
            return "allow", None
        _, rel, is_ephemeral = _classify_ownership_target(target_path, manifest_root)
        if is_ephemeral:
            return "allow", None
        if not owned or not cwg.path_matches_any_glob(rel, owned):
            return (
                "deny",
                f"[File Ownership Guard] Воркер `{worker}` не владеет путём `{rel}` (owned_paths={owned}). "
                "Запись за пределы `owned_paths` запрещена — правьте только свои файлы или запросите `worktree create` у координатора.",
            )

    if tool_name == "run_command" and cmd_text:
        return _guard_worker_shell_ownership(cmd_text, eff_cwd, manifest_root, worker, owned)
    return "allow", None


def _is_worker_silently_parked(
    brain_root: pathlib.Path,
    minfo: dict[str, Any],
    last_assign_seq: int,
) -> bool:
    wake_mode = str(minfo.get("wake_mode") or "").strip().lower()
    mstate = str(minfo.get("state") or "").strip().lower()
    if (mstate == "waiting" or wake_mode in ("mentions", "all", "waiting")) and int(
        minfo.get("wait_since") or 0
    ) >= last_assign_seq:
        return True

    w_cid = str(minfo.get("conversation_id") or minfo.get("conversationId") or "").strip()
    if not w_cid:
        return False
    w_steps = rio.read_transcript_steps(str(rio.member_transcript_path(brain_root, w_cid)), max_lines=60)
    if not w_steps:
        return False
    turn = rio.inspect_worker_turn_after_wake(w_steps, last_assign_seq)
    if not turn["woke_for_assign"] or not turn["has_tail"] or turn["called_post"] or turn["pending_bg"]:
        return False
    if turn["has_error"]:
        return True
    return bool(turn["saw_model"] and turn["terminal_parked"])


def guard_swarm_wait(
    payload: dict[str, Any],
    args: dict[str, Any] | None = None,
) -> tuple[str, str | None]:
    # SAFETY: Prevent coordinator deadlock when calling `swarm_wait` after all active workers have already posted, parked without posting, or stalled.
    tp = payload.get("transcriptPath")
    if rio.is_subagent_session(tp):
        return "allow", None
    session = rio.session_key(payload)
    if not session or session == "unknown":
        return "allow", None
    brain_root = _resolve_brain_root_for_payload(payload)
    members = rio.load_swarm_members(brain_root, session)
    if not members:
        return "allow", None
    raw_board = rio.read_jsonl(rio.swarm_dir(brain_root, session) / "board.jsonl")
    if not raw_board:
        return "allow", None

    eff_args = args if isinstance(args, dict) else ((payload.get("toolCall") or {}).get("args") or {})
    since_val = _coerce_nonneg_int(eff_args.get("since") if isinstance(eff_args, dict) else None)

    active_workers: list[str] = []
    in_flight: list[str] = []
    unposted_parked: list[str] = []
    for mname, minfo in members.items():
        if not isinstance(minfo, dict) or rio.is_swarm_role_member(mname, minfo) or rio.is_swarm_member_killed(minfo):
            continue
        active_workers.append(mname)
        last_assign_seq, last_reply_seq = rio.latest_board_assign_and_reply_seq(
            raw_board, mname, added_by=str(minfo.get("added_by") or "")
        )
        if last_assign_seq == 0 or last_reply_seq < last_assign_seq:
            if last_assign_seq > 0 and _is_worker_silently_parked(brain_root, minfo, last_assign_seq):
                unposted_parked.append(mname)
            else:
                in_flight.append(mname)

    if in_flight:
        stalled = cwg.detect_stalled_workers(
            members=members,
            board_messages=raw_board,
            cwd=rio.effective_cwd(payload),
            brain_root=brain_root,
            in_flight_names=in_flight,
        )
        if stalled:
            desc = ", ".join(f"`{s['worker']}` ({s['idle_sec']}s >= {s['timeout_sec']}s)" for s in stalled)
            return (
                "deny",
                f"[Swarm Stall Watchdog] Зависли in-flight воркеры без новых сообщений на доске и активности в `.swarm/`: {desc}. "
                "Не уходите в немое ожидание `swarm_wait`: проверьте `.swarm/artifacts/`, перепинайте через `@mention` или перезапустите зависшего воркера.",
            )

    if active_workers and not in_flight:
        head_seq = int(raw_board[-1].get("seq") or len(raw_board))
        if unposted_parked:
            since_note = f", since={since_val}" if since_val > 0 else ""
            return (
                "deny",
                f"[Swarm Wait Guard] Активных работающих воркеров не осталось (head=#{head_seq}{since_note}), а воркер(ы) "
                f"({', '.join(unposted_parked)}) завершили ход в `waiting` без вызова `post_message` после задания. "
                "Вызов `swarm_wait` сейчас приведёт к вечному зависанию: разбудите воркера через "
                "`post_message('@<name> Call post_message with your result')` или перезапустите его.",
            )
        return (
            "deny",
            f"[Swarm Wait Guard] Все активные воркеры роя ({', '.join(active_workers)}) уже опубликовали ответы на доске "
            f"(head=#{head_seq}). Вызов `swarm_wait` сейчас приведёт к вечному ожиданию. "
            "Не вызывайте `read_board` и `swarm_wait` в одном ходе: обработайте полученные сообщения и завершите воркеров через `swarm(action='kill', ...)`.",
        )
    return "allow", None


def main() -> int:
    payload, err = rio.read_hook_stdin()
    if err or payload is None:
        if err:
            rio.log_hook_event("hook-errors", "stdin_error", hook="safety_guards", error=err)
        rio.emit_pre_tool("allow")
        return 0

    try:
        session = rio.session_key(payload)
        cwd = rio.effective_cwd(payload)
        tc = payload.get("toolCall") if isinstance(payload.get("toolCall"), dict) else {}
        tool_name = str(tc.get("name") or "")
        args = tc.get("args") if isinstance(tc.get("args"), dict) else {}

        if tool_name == "run_command":
            decision, reason = guard_shell_command(str(args.get("CommandLine") or ""), cwd, session=session)
            if decision != "allow":
                rio.log_hook_event("hygiene-events", "shell_guard_deny", session=session, reason=reason or "")
                rio.emit_pre_tool(decision, reason=reason)
                return 0
            decision, reason = guard_file_ownership(payload, tool_name, args, cwd)
            if decision != "allow":
                rio.log_hook_event("hygiene-events", "ownership_guard_deny", session=session, reason=reason or "")
                rio.emit_pre_tool(decision, reason=reason)
                return 0

        elif tool_name == "read_board":
            decision, reason = guard_read_board(payload, args, cwd)
            if decision != "allow":
                rio.log_hook_event("hygiene-events", "cursor_guard_deny", session=session, reason=reason or "")
                rio.emit_pre_tool(decision, reason=reason)
                return 0

        elif tool_name in ("edit_file", "write_file"):
            decision, reason = guard_file_ownership(payload, tool_name, args, cwd)
            if decision != "allow":
                rio.log_hook_event("hygiene-events", "ownership_guard_deny", session=session, reason=reason or "")
                rio.emit_pre_tool(decision, reason=reason)
                return 0

        elif tool_name == "swarm":
            decision, reason = guard_swarm_invocation(args, payload=payload)
            if decision != "allow":
                rio.log_hook_event("hygiene-events", "model_guard_deny", session=session, reason=reason or "")
                rio.emit_pre_tool(decision, reason=reason)
                return 0

        elif tool_name == "swarm_wait":
            decision, reason = guard_swarm_wait(payload, args)
            if decision != "allow":
                rio.log_hook_event("hygiene-events", "swarm_wait_guard_deny", session=session, reason=reason or "")
                rio.emit_pre_tool(decision, reason=reason)
                return 0

        elif tool_name == "invoke_subagent":
            decision, reason, overwrite = guard_subagent_invocation(payload, args)
            if decision != "allow":
                ev = "model_guard_deny" if "[Model Policy Guard]" in (reason or "") else "subagent_guard_deny"
                rio.log_hook_event("hygiene-events", ev, session=session, reason=reason or "")
                rio.emit_pre_tool(decision, reason=reason)
                return 0
            if overwrite:
                rio.emit_pre_tool("allow", overwrite=overwrite)
                return 0

        rio.emit_pre_tool("allow")
    except Exception as exc:
        rio.log_hook_event(
            "hook-errors",
            "exception",
            hook="safety_guards",
            error=f"{type(exc).__name__}:{exc}",
        )
        rio.emit_pre_tool("allow")
    return 0


if __name__ == "__main__":
    sys.exit(main())
