---
trigger: glob
globs: "**/rust/src/cwg_*.rs, **/rust/src/codex_lane.rs, **/rust/src/safety_guards.rs, **/rust/src/tokenade_hook.rs, **/rust/src/installer.rs, **/rust/src/gate_inbox.rs, **/rust/src/chip_hooks.rs, **/rust/src/continuity_hook.rs, **/bin/carbon-stack*, **/hooks.json, **/plugin.json, **/mcp_config.json, **/*auth*, **/*crypto*, **/*jwt*, **/*secret*, **/*permission*, **/*rbac*, **/*acl*, **/*security*, **/migrations/**, **/.github/workflows/**, **/Dockerfile*"
---

# High-Risk (`HIGH` / `XHIGH`) Verification Rules

Правила для критических компонентов (хуки, манифесты, безопасность, авторизация, миграции, CI/CD, секреты). Подробности флагов — `~/.gemini/reference/codex-routing.md`.

0. **Малые кандидаты и инварианты до кода:**
   - До первой правки сформулируйте `3–5` инвариантов (контракты, границы изоляции, формат доказательств) и держите размер кандидата **`<= 30–40 KB`** (~500–1,000 строк) в атомарных коммитах/worktree (`схема/контракт -> ядро -> интеграция`). Кандидат `> 80 KB` делите через `scope split` ДО ревью.
   - На **Раунде 2+ запрещены заплатки по примеру:** при обходе эвристики/regex/окна времени меняйте сам механизм доказательства (структурный парсер, метаданные, инвариант в типе/БД).
1. **Линейный цикл верификации:**
   - **Шаг 1 (тесты):** доведите локальные тесты и линтеры до зелёного состояния; никогда не отключайте проверки.
   - **Шаг 2 (совещательный `simplify` ДО ревью — рекомендуется 1 раз):** для компактного диффа (`<= 2` ф. и `<= 30` ст.) запустите 1 воркера `simplify-reviewer`; для крупного — 3 линзы (`REUSE`, `QUALITY`, `EFFICIENCY` на `claude-sonnet-5-5-high`, fallback `gemini-4-neon-xhigh`, вторично `gemini-4-hydrogen-xhigh`, никогда Carbon). Применяйте только эквивалентные по поведению улучшения, завершите воркеров (`swarm kill`) и при правках перепрогоните тесты. `simplify` не блокирует `Stop` и не повторяется после ревью.
   - **Шаг 3 (`carbon-stack codex-lane review`, `1..4` раунда, `BLOCKING_THRESHOLD = HIGH`):** `$null | carbon-stack codex-lane review --cwd <repo> --session <id> --intent "..." --summary "..."` (`BypassSandbox=true`; `HIGH` → `gpt-6.2-sol` `high`; `--xhigh` → `gpt-6.2-astra` `ultra`). Пакет компактный (`<= 15 KB`, `git diff --stat`, inline diff `< 25 KB`, явный `[TRUNCATED]` при обрезке; Раунды `2..4` шлют только дельту + `ANTI-BOOMERANG LEDGER`). `VERDICT: APPROVED` мгновенно закрывает гейт (`[gate] verified: HIGH|XHIGH; ...`).
   - **Протокол `REVISE`:** до правки сформулируйте инвариант/владеющий слой, найдите всех потребителей (`rg`/`tokenade impact`/`codebase-memory`) и прочтите блоки целиком; по каждой находке решите `FIX` (структурно + красный→зелёный тест) или `DISPOSE` (`carbon-stack codex-lane dispose` при конфликте с целью / Class C–D).
   - **Шаг 4 (`Round 4: ESCALATE` -> конечное закрытие):** 1 фокусный проход исследования, затем **`REMEDIATE`** (`<= 2` проходов `--closure`: `READY` → `verified`/`pr-ready`; 2-й `BLOCKED` → терминальный `[gate] draft-blocked`) либо **`REDESIGN`** (1 `carbon-stack codex-lane research-reset` / `redesign-reset` на кандидата).
2. **Свежесть байтов:** любая правка после `APPROVED`/`READY` требует перезапуска затронутых тестов и дельта-раунда по `interdiff`.
