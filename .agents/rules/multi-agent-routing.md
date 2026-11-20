---
trigger: model_decision
description: "Load ONLY when delegating to swarm workers, Hydrogen browser/translator subagents, or parallel git worktree chips."
---

# Multi-Agent & Swarm 2.0 Routing Rules

1. **Запрет `Gemini Flash` и асимметричная матрица Swarm 2.0:** никогда не передавайте `Model="flash"`, `flash_lite` или `gemini-3.8-flash-*`.
   - **Координатор:** `Orchestrator (Neon)` (`gemini-pro-orchestrator-neon`) — планирование, владение файлами, слияние, гейт.
   - **Механические/быстрые роли и стандартная разведка:** `Gemini 4 Hydrogen` (`-low` / `-medium` / `-high` / `-xhigh` — `browser`, `translator`, стандартные скауты и простые `Disjoint Builders`).
   - **Сложная разведка, отладка, UI и тесты (`Gemini 4 Neon` `low..xhigh`):** `-low` (массовый синтаксис/схемы), `-medium`/`-high` (`test-author`), `-high`/`-xhigh` (`frontend-ui-builder`, `repo-architect-scout`, сложные `Disjoint Builders`), `-xhigh` (`root-cause-debugger` и primary fallback для `simplify`).
   - **Simplify:** `Claude Sonnet 5.5 High` (`SIMPLIFY_LENS: ALL` Fast-Path при `<= 2` файлов и `<= 30` строк; иначе 3 параллельные линзы; fallback — `gemini-4-neon-xhigh`, вторичный резерв — `gemini-4-hydrogen-xhigh`, никогда Carbon).
   - **Логика и безопасность:** `carbon-stack codex-lane review` (`gpt-6.2-sol` на `high` для `HIGH`; `--xhigh` на `gpt-6.2-astra` для `XHIGH`; при подтверждённом сбое Codex — `claude-opus-5-5-high` -> `gemini-4-neon-xhigh` для `HIGH` или `gemini-4-carbon-high` для `XHIGH`).
2. **Владение файлами (`File Ownership Guard`):** перед параллельной разработкой разделите файлы через `carbon-stack swarm-ctl ownership set --worker <name> --paths <globs>` (либо `worktree create` при пересечении модулей/тестов, либо `workspace: "share"`/`"branch"` / `carbon-stack chip-handoff open`). Интеграция принадлежит координатору.
3. **Тёплый пул (`Warm Pool`), `Pointer-on-Board` и `Cursor Guard`:** будите живых `waiting` воркеров через `post_message` `@mention` вместо холодного респавна и делайте пакетный `kill` перед `--closure`. Объёмные отчёты сохраняйте в `.swarm/artifacts/<worker>-<round>.md` (`<= 12` строк + путь на доске). При `> 15` сообщениях передавайте `read_board(since=<last_seen_id>)` (или `carbon-stack swarm-ctl board summary --since <id>`).
4. **Защита `swarm_wait` и `Stall Watchdog`:** никогда не вызывайте `read_board` и `swarm_wait` в одном ходе; при зависании `in_flight` воркера сверх `SWARM_STALL_TIMEOUT_SEC` (`240` с) перезапускайте только зависший воркер. Подробные шаблоны — в скилле `swarm-orchestration`.
5. **Делегирование `browser` с не-Hydrogen координатора:** запустите `swarm` воркер с `model="gemini-4-hydrogen-<level>"`, который вызовет `invoke_subagent(TypeName="browser", Model="inherit")`; проверяйте результат строго по `BROWSER_HOST_FACTS`.
