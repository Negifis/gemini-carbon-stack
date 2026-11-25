# Gemini Carbon Engineering Stack (Plugin Bundle)

Нативная инженерная система для **Gemini 4 Carbon** в среде **Google Antigravity 2.0** (`agy`).

Состав бандла:
- `hooks.json` + `bin/carbon-stack.exe` — единый нативный Rust-бинарник для Code Work Gate, Continuity, Loop Guard, Comment Density Guard, Worktree Safety Guard, Chip Handoff, межмодельного контура Codex (`codex-lane`) и локальных утилит стека.
- `rules/AGENTS.md` — компактная инженерная конституция Gemini Carbon.
- `agents/` — независимые read-only субагенты (`adversarial-reviewer`, `adversarial-reviewer-xhigh`, `simplify-reviewer`, `simplify-reuse-reviewer`, `simplify-quality-reviewer`, `simplify-efficiency-reviewer`, `code-explorer`, `translator`).
- `skills/` — прогрессивные навыки и slash-команды (`/task-start`, `/checkpoint`, `/rebuild`, `/import-claude-chats`, `/adversarial-review`, `/verify-ready`, `/stack-doctor` и др.).
- `bin/carbon-stack.exe <subcmd>` + `tools/` — локальная FTS5-память (`carbon-memory`), импортер истории чатов Claude Code (`claude-chat-importer`), многосессионный handoff (`chip-handoff`), поиск (`code-search`), защита worktree (`worktree-guard`), диагностика (`stack-doctor`, `install --diagnose`), инспекция дескрипторов Windows (`tools/file-holders.ps1`) и векторизация SVG (`tools/vectorize.mjs`).
