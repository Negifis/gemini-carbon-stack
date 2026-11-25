---
trigger: model_decision
description: "Load ONLY when delegating to swarm workers, Hydrogen browser/translator subagents, or parallel git worktree chips."
---

# Multi-Agent & Swarm 2.0 Routing

1. **Запрет `gemini-3.8-flash-*` и матрица моделей:** никогда не используйте `flash`, `flash_lite` или `gemini-3.8-flash-*` в субагентах/рое.
   - **Прямой инженер (сложная архитектура, интеграция, фиксы по ревью Codex `R1 → R4`):** прямой **`Gemini 4 Neon (High/XHigh)`** (`gemini-4-neon-high`/`gemini-4-neon-xhigh`).
   - **Координатор (планирование и рутина):** `Orchestrator (Neon)` допустим только для планирования и рутинных правок (его Execution Mode выполняется на лёгком `gemini-flash-worker-agy`), либо `Gemini 4 Carbon` для оркестрации.
   - **Быстрые / механические роли:** `Gemini 4 Hydrogen` (`low`..`xhigh` — `browser`, `translator`, быстрые скауты, простые параллельные билдеры).
   - **Сложная разведка, отладка, UI, тесты и архитектура:** `Gemini 4 Neon` (`low`..`xhigh`).
   - **Обязательный `Simplify` (фиксированные линзы Claude через `swarm`):** `claude-sonnet-5-5-high` (фоллбэк только при подтверждённом сбое/0% квоты: `gemini-4-neon-xhigh` → `gemini-4-hydrogen-xhigh`; нативный `invoke_subagent(..., Model="inherit")` лишь при отказе всех 3 уровней роя) — `STANDARD`: 1× `simplify-reviewer`; `HIGH`/`XHIGH`: 1× 3 параллельные линзы `simplify-reuse`, `simplify-quality`, `simplify-efficiency` ДО ревью. `PreToolUse` автоматически инжектирует фиксированные промпты из `plugin/agents/simplify-*.md`; после сбора отчётов воркеры обязательно закрываются через `swarm(action="kill", ...)`.
   - **Независимое ревью:** `carbon-stack codex-lane review --intent "..."` (fallback только при сбое Codex: `claude-opus-5-5-high` → `gemini-4-neon-xhigh` [`HIGH`] / `gemini-4-carbon-high` [`XHIGH`]).
   - **UI/UX визуальное ревью *(только UI)*:** read-only `visual-qa-reviewer` (с веб-поиском и `mobbin_mobbin`) до `VISUAL_REVIEW_VERDICT: APPROVED`.
2. **Evidence, not authority & лимит ширины:** предпочитайте `<= 3` параллельных субагента; каждый вывод проверяйте родителем по реальному коду/диффу/выводу команд. В брифы передавайте `BUSINESS_INTENT`, релевантные плагины, MCP, скиллы и read-only веб-поиск.
3. **Изоляция параллельных записей и доска:** для параллельной разработки разделяйте пути или изолируйте воркеров (`workspace: "share"`/`"branch"`, `carbon-stack swarm-ctl worktree create`, или `carbon-stack chip-handoff open`). Объёмные отчёты пишите в `.swarm/artifacts/<worker>-<round>.md` (`<= 12` строк на доске); будите живых `waiting` ревью-/билдер-воркеров через `@mention`; используйте `read_board(since=<id>)` и никогда не вызывайте `read_board` и `swarm_wait` в одном ходе.
4. **Делегирование `browser` с не-Hydrogen координатора:** при необходимости спавните `swarm` воркер на `gemini-4-hydrogen-*`, вызывающий `invoke_subagent(TypeName="browser", Model="inherit")`; проверяйте результат по `BROWSER_HOST_FACTS`.
