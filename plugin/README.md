# Gemini Carbon Engineering Stack (Plugin Bundle)

Нативная инженерная система для **Gemini 4 Carbon** в среде **Google Antigravity 2.0** (`agy`).

Состав бандла:
- `hooks.json` + `hooks/` — Code Work Gate, Continuity, Loop Guard, Comment Density Guard, Worktree Safety Guard и Chip Handoff.
- `rules/AGENTS.md` — компактная инженерная конституция Gemini Carbon.
- `agents/` — независимые read-only субагенты (`adversarial-reviewer`, `adversarial-reviewer-xhigh`, `simplify-reviewer`, `code-explorer`, `translator`).
- `skills/` — прогрессивные навыки и slash-команды (`/task-start`, `/checkpoint`, `/rebuild`, `/adversarial-review`, `/verify-ready`, `/stack-doctor` и др.).
- `tools/` — локальная FTS5-память (`carbon_memory.py`), многосессионный handoff (`chip_handoff.py`), поиск (`code_search.py`), защита worktree (`worktree_guard.py`) и диагностика (`stack_doctor.py`).
