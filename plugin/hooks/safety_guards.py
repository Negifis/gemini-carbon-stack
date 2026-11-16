#!/usr/bin/env python3
"""PreToolUse safety & quality guards: subagent packet & nesting, and dirty-worktree/junction safety."""

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

BARE_WORKTREE_REMOVE_RE = re.compile(
    r"\bgit(?:\.exe)?\s+(?:[^\n;|&]*\s+)?worktree\s+remove\b",
    re.IGNORECASE,
)

DESTRUCTIVE_GIT_RE = re.compile(
    r"\bgit(?:\.exe)?\s+(?:[^\n;|&]*\s+)?"
    r"(?:reset\s+--hard|checkout\s+--\s+\.|restore\s+(?:--staged\s+--worktree\s+|--worktree\s+)?\.|clean\s+-[a-zA-Z]*f[a-zA-Z]*)",
    re.IGNORECASE,
)

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


def _is_simplify_swarm_target(name: str, brief: str) -> bool:
    if "simplify" in (name or "").strip().lower():
        return True
    low_brief = (brief or "").lower()
    return "simplify_lens:" in low_brief or "simplify_verdict:" in low_brief


def guard_swarm_invocation(args: dict[str, Any]) -> tuple[str, str | None]:
    action = str(args.get("action") or "").strip().lower()
    if action not in ("add", "model"):
        return "allow", None
    model = str(args.get("model") or "").strip()
    if model and cwg.FLASH_MODEL_RE.search(model):
        return "deny", HYDROGEN_POLICY_MSG
    if _is_simplify_swarm_target(str(args.get("name") or ""), str(args.get("brief") or "")):
        if not model or model.lower() not in cwg.SIMPLIFY_ALLOWED_MODELS:
            # SAFETY: Never allow simplify workers to default to or target Carbon, preserving main-agent quota.
            return (
                "deny",
                f"[Simplify Model Policy] Линзы simplify запрещено запускать на `{model or 'inherit (Carbon)'}`, "
                f"чтобы не сжигать лимиты `{cwg.CARBON_HIGH_MODEL}`. Используйте `{cwg.SONNET_HIGH_MODEL}`, "
                f"а при исчерпании квоты/сбое Sonnet — `{cwg.SIMPLIFY_FALLBACK_MODEL}` через "
                f"`swarm(action='add', ..., model='{cwg.SIMPLIFY_FALLBACK_MODEL}')`.",
            )
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

    steps_head = rio.read_transcript_steps(transcript_path, max_lines=5)
    is_delegated = rio.is_subagent_session(transcript_path, steps=steps_head)
    worker_model = rio.swarm_worker_model(
        transcript_path,
        steps=steps_head,
        conversation_id=payload.get("conversationId") or payload.get("session_id"),
    )
    is_swarm_worker = bool(worker_model)

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
