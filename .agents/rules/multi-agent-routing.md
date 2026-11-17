---
trigger: model_decision
description: "Load ONLY when delegating to swarm workers, Hydrogen browser/translator subagents, or parallel git worktree chips."
---

# Multi-Agent & Swarm 2.0 Routing Rules

1. **Запрет `Gemini Flash` и асимметричная матрица Swarm 2.0:** никогда не передавайте `Model="flash"`, `flash_lite` или `gemini-3.8-flash-*`.
   - **Координатор:** `Orchestrator (Argon)` — планирование, владение файлами, слияние, гейт.
   - **Скауты (`3+` подсистем / `5+` файлов) и `Disjoint Builders`:** `Gemini 4 Hydrogen` (`-medium` / `-high`, `-low` для smoke/короткого перевода, `-xhigh` для сложных гонок и fallback-линз `simplify`).
   - **Simplify:** `Claude Sonnet 5.5 High` / Argon (`SIMPLIFY_LENS: ALL` Fast-Path при `<= 2` файлов и `<= 30` строк; иначе 3 параллельные линзы; fallback — `gemini-4-hydrogen-xhigh`, никогда Carbon).
   - **Логика и безопасность:** `codex_lane.py review` (при подтверждённом сбое Codex — `claude-opus-5-5-high` -> `gemini-4-carbon-high`).
2. **Владение файлами (`File Ownership Guard`):** перед параллельной разработкой разделите файлы через `swarm_ctl.py ownership set --worker <name> --paths <globs>` (либо `worktree create` при пересечении модулей/тестов, либо `workspace: "share"`/`"branch"` / `chip_handoff.py open`). Интеграция принадлежит координатору.
3. **Тёплый пул (`Warm Pool`), `Pointer-on-Board` и `Cursor Guard`:** будите живых `waiting` воркеров через `post_message` `@mention` вместо холодного респавна и делайте пакетный `kill` перед `--closure`. Объёмные отчёты сохраняйте в `.swarm/artifacts/<worker>-<round>.md` (`<= 12` строк + путь на доске). При `> 15` сообщениях передавайте `read_board(since=<last_seen_id>)` (или `swarm_ctl.py board summary --since <id>`).
4. **Защита `swarm_wait` и `Stall Watchdog`:** никогда не вызывайте `read_board` и `swarm_wait` в одном ходе; при зависании `in_flight` воркера сверх `SWARM_STALL_TIMEOUT_SEC` (`240` с) перезапускайте только зависший воркер. Подробные шаблоны — в скилле `swarm-orchestration`.
5. **Делегирование `browser` с не-Hydrogen координатора:** запустите `swarm` воркер с `model="gemini-4-hydrogen-<level>"`, который вызовет `invoke_subagent(TypeName="browser", Model="inherit")`; проверяйте результат строго по `BROWSER_HOST_FACTS`.
