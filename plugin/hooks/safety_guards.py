#!/usr/bin/env python3
"""PreToolUse safety & quality guards: comment density, subagent packet & nesting, and dirty-worktree/junction safety."""

from __future__ import annotations

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

CODE_EXTENSIONS = frozenset(
    {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rs", ".java", ".c", ".cpp", ".cs", ".ps1", ".sh"}
)

EXEMPT_COMMENT_RE = re.compile(
    r"(?:\b(?:SAFETY|INVARIANT|WORKAROUND|WHY|TODO|FIXME|NOTE)\s*:|"
    r"type:\s*ignore|noqa\b|pragma:\s*no\s*cover|eslint-disable|@ts-expect-error|@ts-ignore|"
    r"^#!\s*/|-\*- coding:)",
    re.IGNORECASE,
)

SELF_NARRATION_COMMENT_RE = re.compile(
    r"^\s*(?:#|//)\s*(?:"
    r"(?:added|updated|changed|modified|removed|fixed)\s+(?:this|the|to\s+fix|per\s+review|as\s+requested)\b"
    r"|(?:добавлен[оаы]?|изменен[оаы]?|исправлен[оаы]?|удален[оаы]?|обновлен[оаы]?)\s+(?:для|по\s+результатам|после|чтобы\s+исправить)\b"
    r")",
    re.IGNORECASE,
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

COMMENT_DENSITY_MIN_LINES = 14
COMMENT_DENSITY_MAX_RATIO = 0.42
MAX_COMMENT_STRIKES_PER_FILE = 2


def strikes_path(session: str) -> pathlib.Path:
    return rio.state_dir("hygiene", "comment_strikes") / f"{session}.json"


def record_and_check_strike(session: str, file_path: str) -> int:
    sp = strikes_path(session)
    data = rio.read_json(sp, default={})
    if not isinstance(data, dict):
        data = {}
    key = rio.fold_path(file_path)
    cnt = int(data.get(key) or 0) + 1
    data[key] = cnt
    rio.write_json(sp, data)
    return cnt


def check_comment_hygiene(tool_name: str, args: dict[str, Any]) -> str | None:
    path = str(args.get("Path") or "")
    if not path or args.get("ArtifactMetadata"):
        return None
    ext = pathlib.PurePosixPath(rio.normalize_path(path)).suffix.lower()
    if ext not in CODE_EXTENSIONS:
        return None

    if tool_name == "edit_file":
        before_set = {ln.strip() for ln in str(args.get("Target") or "").splitlines() if ln.strip()}
        added_lines = [
            ln for ln in str(args.get("Replacement") or "").splitlines() if ln.strip() and ln.strip() not in before_set
        ]
    elif tool_name == "write_file":
        added_lines = [ln for ln in str(args.get("Content") or "").splitlines() if ln.strip()]
    else:
        return None

    if not added_lines:
        return None

    # 1. Immediate check for LLM changelog/self-narration comments
    for ln in added_lines:
        if SELF_NARRATION_COMMENT_RE.search(ln) and not EXEMPT_COMMENT_RE.search(ln):
            return (
                f"Обнаружен комментарий-самоописание истории правок (`{ln.strip()[:70]}`). "
                "Код не должен содержать changelog-заметок модели; оставляйте только объяснения неочевидных инвариантов (`WHY:` / `INVARIANT:` / `SAFETY:`)."
            )

    # 2. Density check on substantial code additions
    if len(added_lines) < COMMENT_DENSITY_MIN_LINES:
        return None

    comment_prefix = ("#",) if ext in (".py", ".ps1", ".sh") else ("//",)
    in_docstring = False
    code_count = 0
    comment_count = 0

    for raw in added_lines:
        stripped = raw.strip()
        if ext == ".py" and (stripped.startswith('"""') or stripped.startswith("'''")):
            delim = stripped[:3]
            if stripped.count(delim) == 1:
                in_docstring = not in_docstring
            continue
        if in_docstring:
            continue
        if stripped.startswith(comment_prefix):
            if not EXEMPT_COMMENT_RE.search(stripped):
                comment_count += 1
        else:
            code_count += 1

    total = code_count + comment_count
    if total >= COMMENT_DENSITY_MIN_LINES and (comment_count / total) > COMMENT_DENSITY_MAX_RATIO:
        pct = int(round(100 * comment_count / total))
        return (
            f"Избыточная плотность строчных комментариев ({comment_count}/{total} строк, {pct}% > {int(COMMENT_DENSITY_MAX_RATIO*100)}%). "
            "Уберите пересказ очевидного кода; при необходимости документировать нетривиальное ограничение используйте префиксы `INVARIANT:`, `SAFETY:` или `WORKAROUND:`."
        )
    return None


def guard_shell_command(cmd: str, cwd: str) -> tuple[str, str | None]:
    stripped = (cmd or "").strip()
    if not stripped:
        return "allow", None

    # 1. Block unsafe bare `git worktree remove` (unless invoked inside worktree_guard.py itself)
    if BARE_WORKTREE_REMOVE_RE.search(stripped) and "worktree_guard.py" not in stripped:
        guard_script = rio.normalize_path(TOOLS_DIR / "worktree_guard.py")
        return (
            "deny",
            "[Worktree Safety Guard] Прямой вызов `git worktree remove` на Windows опасен (Git рекурсивно обходит NTFS junctions вроде `node_modules`/`.venv` и может удалить файлы основного дерева, а незакоммиченные правки теряются). "
            f"Используйте безопасную обёртку: `python -X utf8 \"{guard_script}\" remove --worktree <path>`.",
        )

    # 2. Protect uncommitted dirty worktree from destructive git wipe commands
    if DESTRUCTIVE_GIT_RE.search(stripped):
        eff_cwd = rio.resolve_command_cwd(stripped, cwd)
        git_root = rio.git_toplevel(eff_cwd)
        if git_root:
            rc, st_out, _ = rio.run_git(git_root, ["status", "--porcelain=v1"], timeout=4.0)
            if rc == 0 and str(st_out or "").strip():
                guard_script = rio.normalize_path(TOOLS_DIR / "worktree_guard.py")
                return (
                    "deny",
                    "[Dirty Worktree Protection] Рабочее дерево содержит незакоммиченные изменения, которые будут безвозвратно уничтожены этой командой. "
                    f"Сначала сохраните снимок состояния без изменения индекса: `python -X utf8 \"{guard_script}\" snapshot --label before-reset`, "
                    "либо откатывайте только конкретные собственные хунки.",
                )

    return "allow", None


def guard_swarm_invocation(args: dict[str, Any]) -> tuple[str, str | None]:
    action = str(args.get("action") or "").strip().lower()
    model = str(args.get("model") or "").strip()
    if action in ("add", "model") and model and cwg.FLASH_MODEL_RE.search(model):
        return "deny", HYDROGEN_POLICY_MSG
    return "allow", None


def guard_subagent_invocation(
    payload: dict[str, Any], args: dict[str, Any]
) -> tuple[str, str | None, dict[str, Any] | None]:
    transcript_path = payload.get("transcriptPath")
    prompt = str(args.get("Prompt") or "").strip()
    req_model = str(args.get("Model") or "").strip().lower()
    sub_type = str(args.get("TypeName") or "").strip().lower()

    # 1. Block deprecated Gemini Flash tiers (`flash` / `flash_lite`)
    if req_model and cwg.FLASH_MODEL_RE.search(req_model):
        suffix = (
            "Для `browser` запустите swarm-воркера на `gemini-4-hydrogen-<low|medium|high|xhigh>`, который вызовет `invoke_subagent(TypeName='browser', Model='inherit')` (либо передайте `Model='inherit'` внутри Hydrogen-сессии)."
            if sub_type == "browser"
            else "Запустите задачу через `swarm(action='add', model='gemini-4-hydrogen-<low|medium|high|xhigh>')` или передайте `Model='inherit'` внутри Hydrogen-сессии."
        )
        return "deny", f"{HYDROGEN_POLICY_MSG} {suffix}", None

    # 2. Prevent recursive subagent nesting unless top-level swarm worker delegates `browser` with `inherit`
    steps_head = rio.read_transcript_steps(transcript_path, max_lines=5)
    is_delegated = rio.is_subagent_session(transcript_path, steps=steps_head)
    is_swarm_worker = rio.is_swarm_worker_session(
        transcript_path,
        steps=steps_head,
        conversation_id=payload.get("conversationId") or payload.get("session_id"),
    )
    allow_swarm_browser = bool(is_swarm_worker and sub_type == "browser" and req_model in ("", "inherit"))
    if is_delegated and not allow_swarm_browser and "[allow-nested-subagent]" not in prompt:
        return (
            "deny",
            "[Subagent Nesting Guard] Вложенный запуск субагента изнутри субагента заблокирован во избежание каскадного размножения контекстов. "
            "Завершите свою ограниченную задачу и верните результат родительскому агенту.",
            None,
        )

    # 2. Require bounded actionable prompt
    if len(prompt) < 16:
        return (
            "deny",
            "[Subagent Delegation Guard] Промпт субагента слишком короткий и не содержит границ задачи и ожидаемого результата.",
            None,
        )

    # 3. Propagate active Canonical Checkpoint AUTHORITATIVE STATE & SUPERSEDED constraints automatically
    if "[Canonical Constraints]" not in prompt:
        import continuity

        wps = payload.get("workspacePaths") if isinstance(payload.get("workspacePaths"), list) else None
        chosen = continuity.resolve_checkpoint_file(rio.effective_cwd(payload), wps)
        if chosen is not None:
            secs = continuity.parse_checkpoint_sections(chosen.read_text(encoding="utf-8", errors="replace"))
            auth = secs.get("AUTHORITATIVE STATE", "").strip()
            sup = secs.get("SUPERSEDED / CANCELLED", "").strip()
            extra_lines: list[str] = []
            if auth and auth != "—":
                extra_lines.append(f"- Active Requirements: {auth[:400]}")
            if sup and sup != "—":
                extra_lines.append(f"- Cancelled / Do NOT Reintroduce: {sup[:300]}")
            if extra_lines:
                enriched = prompt + "\n\n[Canonical Constraints]\n" + "\n".join(extra_lines)
                return "allow", None, {"Prompt": enriched}

    return "allow", None, None


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

        if tool_name in ("edit_file", "write_file"):
            violation = check_comment_hygiene(tool_name, args)
            if violation:
                strike = record_and_check_strike(session, str(args.get("Path") or "unknown"))
                if strike <= MAX_COMMENT_STRIKES_PER_FILE:
                    rio.log_hook_event(
                        "hygiene-events",
                        "comment_guard_deny",
                        session=session,
                        strike=strike,
                        path=rio.normalize_path(args.get("Path")),
                    )
                    rio.emit_pre_tool(
                        "deny",
                        reason=f"[Comment Density Guard — попытка {strike}/{MAX_COMMENT_STRIKES_PER_FILE}] {violation}",
                    )
                    return 0

        elif tool_name == "run_command":
            decision, reason = guard_shell_command(str(args.get("CommandLine") or ""), cwd)
            if decision != "allow":
                rio.log_hook_event("hygiene-events", "shell_guard_deny", session=session, reason=reason or "")
                rio.emit_pre_tool(decision, reason=reason)
                return 0

        elif tool_name == "swarm":
            decision, reason = guard_swarm_invocation(args)
            if decision != "allow":
                rio.log_hook_event("hygiene-events", "model_guard_deny", session=session, reason=reason or "")
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
