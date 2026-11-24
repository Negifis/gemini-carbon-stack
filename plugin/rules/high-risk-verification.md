---
trigger: glob
globs: "**/rust/src/cwg_*.rs, **/rust/src/codex_lane.rs, **/rust/src/safety_guards.rs, **/rust/src/comment_density_guard.rs, **/rust/src/installer.rs, **/rust/src/gate_inbox.rs, **/rust/src/chip_hooks.rs, **/rust/src/continuity_hook.rs, **/bin/carbon-stack*, **/hooks.json, **/plugin.json, **/mcp_config.json, **/*auth*, **/*crypto*, **/*jwt*, **/*secret*, **/*permission*, **/*rbac*, **/*acl*, **/*security*, **/migrations/**, **/.github/workflows/**, **/Dockerfile*"
---

# High-Risk (`HIGH` / `XHIGH`) Verification Rules

Правила для критических компонентов (хуки, манифесты, безопасность, авторизация, миграции, CI/CD, секреты). Подробности флагов — `~/.gemini/reference/codex-routing.md`.

0. **Малые кандидаты и инварианты до кода:**
   - До первой правки сформулируйте `3–5` инвариантов (контракты, границы изоляции, формат доказательств) и держите размер кандидата **`<= 30–40 KB`** (~500–1,000 строк) в атомарных коммитах/worktree (`схема/контракт -> ядро -> интеграция`). Кандидат `> 80 KB` делите через `scope split` ДО ревью.
   - На **Раунде 2+ запрещены заплатки по примеру:** при обходе эвристики/regex/окна времени меняйте сам механизм доказательства (структурный парсер, метаданные, инвариант в типе/БД).
1. **Линейный цикл верификации:**
   - **Шаг 1 (тесты):** доведите локальные тесты и линтеры до зелёного состояния; никогда не отключайте проверки.
   - **Шаг 2 (обязательный `simplify` ДО ревью — 1 прогон в 3 линзы):** запустите параллельно в одном ходе 3 фиксированных субагента через `invoke_subagent(..., Model="inherit")`: `simplify-reuse-reviewer`, `simplify-quality-reviewer`, `simplify-efficiency-reviewer`. Промпты линз фиксированы в `plugin/agents/simplify-*.md` — не пишите произвольные инструкции линз и не заменяйте их на `swarm`-брифы, передавайте только пакет изменений (diff/файлы/инварианты). Примените только эквивалентные по поведению улучшения, при правках перепрогоните тесты. Пропуск блокирует как 1-й раунд `codex-lane review`, так и `Stop`; после ревью `simplify` не повторяется.
   - **Шаг 3 (`carbon-stack codex-lane review`, `1..4` раунда, `BLOCKING_THRESHOLD = HIGH`):** `$null | carbon-stack codex-lane review --cwd <repo> --session <id> --intent "..." --summary "..."` (`BypassSandbox=true`; `HIGH` → `gpt-6.2-sol` `medium`; `--xhigh` → `gpt-6.2-astra` `ultra`). Пакет компактный (`<= 15 KB`, `git diff --stat`, inline diff `< 25 KB`, явный `[TRUNCATED]` при обрезке; Раунды `2..4` шлют только дельту + `ANTI-BOOMERANG LEDGER`; `LARGE_DIFF_WARNING` при R1 `> 80 KB` или delta `> 40 KB`). `VERDICT: APPROVED` мгновенно закрывает гейт (`[gate] verified: HIGH|XHIGH; ...`).
   - **Протокол `REVISE` и Anti-Overengineering:** до правки сформулируйте инвариант/владеющий слой, найдите всех потребителей (`rg`/`tokenade impact`/`codebase-memory`) и прочтите блоки целиком; по каждой находке решите `FIX` (структурно + красный→зелёный тест) или `DISPOSE` (`carbon-stack codex-lane dispose`, если фикс требует больше кода, чем задача, или новой подсистемы ради редкого/синтетического edge-case, либо конфликтует с целью / Class C–D).
   - **Шаг 4 (`Round 4: ESCALATE` -> конечное закрытие):** 1 фокусный проход исследования, затем `<= 2` проходов `--closure` (фикс + перепрогон тестов: `READY` → `verified`/`pr-ready`; 2-й `BLOCKED` → терминальный `[gate] draft-blocked`). Циклов сброса нет.
2. **Свежесть байтов:** любая правка после `APPROVED`/`READY` требует перезапуска затронутых тестов и дельта-раунда по `interdiff`.
