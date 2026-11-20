# Gemini Carbon Engineering Stack

Самостоятельная нативная инженерная операционная система для **Gemini 4 Carbon** в среде исполнения **Google Antigravity 2.0** (`hub-2.32.1` + `agy` CLI `1.2.10` на Windows NT).

Спроектирована как функциональный эквивалент гарантий `Negifis/claude-code-stack` (ревизия `5310f797208af6462dad48eb944869c92a1edf14`), переосмысленный под реальные механизмы Antigravity (`hooks.json` protojson contract, системные транскрипты `transcript_full.jsonl` и `.system_generated/swarm/`, межмодельную маршрутизацию `Claude Sonnet 5.5 High` / `Claude Opus 5.5 High` / `Gemini 4 Carbon High` / `Gemini 4 Neon (Low..XHigh)` / `Gemini 4 Hydrogen (Low..XHigh)` / `OpenAI Codex CLI`, встроенных субагентов `browser` / `image-generator` / `research` и плагинную архитектуру `~/.gemini/config/plugins/`).

## Структура репозитория

- `rust/` — нативный Rust-крейт `carbon-stack` (единый бинарник хуков, CLI-инструментов, установщика `carbon-stack install` и модульных тестов `cargo test`).
- `install.sh` — кроссплатформенная обёртка (`--with-toolchains`), вызывающая нативный `carbon-stack install`.
- `templates/` и `.env.example` — обезличенные шаблоны конфигурации экономии токенов:
  - `templates/mcp_config.json` — ленивая загрузка (`"eager": false`) и жёсткая фильтрация `"enabledTools"` для **Serena MCP** (`uvx --from git+https://github.com/oraios/serena serena start-mcp-server --context=antigravity --agent-interface=tools --project-from-cwd`, 8 read-only LSP-инструментов вместо 24) и **Context7 MCP** (`npx -y @upstash/context7-mcp`, 2 инструмента).
  - `templates/hooks.json` — CLI-хук **Tokenade** (`carbon-stack.exe tokenade-hook`) для автоматического сжатия шумного вывода терминала с прозрачной распаковкой обёрток `tokenade wrap`/`raw` внутри `cwg_mark.rs` и `safety_guards.rs`.
  - `templates/antigravity-cli-settings.json` — конфигурация `agy` CLI с маршрутизацией на `Orchestrator (Neon)` и отключённым автосписанием кредитов (`"useG1Credits": false`).
  - `templates/GEMINI.md` — тонкий глобальный контекст (< 40 строк) с запретом чтения lock-файлов/сборок/бинарников и приоритетом символьного LSP-поиска.
- `.agents/` — проектные скоупированные правила (`high-risk-verification.md` `trigger: glob`, `multi-agent-routing.md` `trigger: model_decision`) и прогрессивные навыки (`token-optimization`).
- `plugin/` — нативный плагин-бандл Antigravity (`gemini-carbon-stack`):
  - `plugin.json`, `hooks.json` — манифест плагина и 4 группы runtime-хуков (`continuity`, `safety-and-quality-guards`, `chip-handoff`, `code-work-gate`).
  - `bin/carbon-stack.exe` — скомпилированный Rust-бинарник риск-ориентированного гейта, межмодельной верификации (`codex-lane` + `swarm` `members.json`/`board.jsonl`), минимального `handoff` (`continuity`), защиты от циклов, безопасности git worktree, локальной FTS5-памяти (`carbon-memory`), импортера сессий Claude Code (`claude-chat-importer`), оркестратора изолированных задач (`chip-handoff`), AST/git-grep поиска (`code-search`), контроля 5-минутного TTL кэша `swarm` (`swarm-cache`), безопасного управления worktrees/junctions (`worktree-guard`), самодиагностики (`stack-doctor`) и установщика (`install`).
  - `tools/` — диагностика файловых дескрипторов Windows (`file-holders.ps1`) и векторизация SVG (`vectorize.mjs`).
  - `rules/` — компактная всегда активная конституция `AGENTS.md` (35 строк) и селективные правила по нативным триггерам Antigravity (`high-risk-verification.md` `glob`, `multi-agent-routing.md` `model_decision`, `deep-audit.md` `manual`).
  - `agents/` — 12 специализированных субагентов и ролей роя (`simplify-reviewer`, `simplify-reuse-reviewer`, `simplify-quality-reviewer`, `simplify-efficiency-reviewer`, `adversarial-reviewer`, `adversarial-reviewer-xhigh`, `code-explorer`, `translator`, `root-cause-debugger`, `frontend-ui-builder`, `repo-architect-scout`, `test-author`).
  - `skills/` — 21 прогрессивный навык и slash-команда (`/task-start`, `/checkpoint`, `/rebuild`, `/import-claude-chats`, `/adversarial-review`, `/verify-ready`, `/stack-doctor`, `token-optimization` и профильные дисциплины) с компактными описаниями.
  - Опциональная проектная политика `.agents/carbon-gate.json` для переопределения порогов риска (`default_code_risk`, `*_risk_globs`, `require_*_on_standard`).
- `rules/uiux-design.md` — контекстное правило фронтенда (`trigger: glob`), активируемое только на файлах UI/разметки.
- `ARCHITECTURE.md` — описание архитектуры, межмодельной маршрутизации и реальных границ гарантий.
- `MIGRATION_MATRIX.md` — полная техническая матрица решений (`NATIVE`, `ADAPT`, `KEEP`, `MERGE`, `REMOVE`, `UNAVAILABLE`).

## **Swarm 2.0 Architecture**

- **Трёхфазный конвейер (`swarm-orchestration`):**
  1. **Scout Swarm (Разведка):** параллельные скауты на `Gemini 4 Hydrogen` (`medium`/`high` для модулей) и `Gemini 4 Neon` (`repo-architect-scout`, `root-cause-debugger` на `high`/`xhigh`) с `serena` LSP пишут отчёты в `.swarm/artifacts/<worker>-<round>.md` (`Pointer-on-Board`: `<= 12` строк на доске).
  2. **Disjoint Builder Swarm (Реализация):** координатор `Orchestrator (Neon)` задаёт непересекающиеся `owned_paths` в `.swarm/ownership.json` или изолированные `git worktree` (`.swarm/worktrees/<worker>`) через CLI `carbon-stack swarm-ctl`; простые/механические билдеры работают на `Gemini 4 Hydrogen`, сложные модули и `frontend-ui-builder`/`test-author` — на `Gemini 4 Neon` (`medium..xhigh`); `File Ownership Guard` в `safety_guards.rs` блокирует запись за пределами зоны воркера.
  3. **Finite Verification Gate (`TESTS -> SIMPLIFY (1) -> KILL -> REVIEW 1..4 -> APPROVED`, потолок `MAX_TOTAL_GATE_ROUNDS = 7`, `MAX_REDESIGN_RESETS = 1`):** сначала локальные тесты и один консультативный проход `simplify` ДО ревью (`MAX_SIMPLIFY_PASSES = 1`: `SIMPLIFY_LENS: ALL` Fast-Path при `<= 2` файлов и `<= 30` изменённых строк, иначе 3 параллельные линзы), пакетный `kill` simplify-воркеров и независимое ревью `carbon-stack codex-lane review` (`1..4` раунда в одной сессии, `MAX_REVIEW_ROUNDS = 4`, порог блокировки `CRITICAL`/`HIGH`, Раунды `2..4` проверяют только `interdiff` и открытые блокеры). **`VERDICT: APPROVED` на любом раунде `1..4` сразу закрывает гейт** без повторного `simplify` и без `--closure`. Только при `Round 4: ESCALATE` выполняется один проход исследования: при `REMEDIATE` — до 2 попыток `carbon-stack codex-lane review --closure` в той же сессии (`CLOSURE_VALIDATION: READY` -> `verified`/`pr-ready`; 2-й `BLOCKED` -> финальный терминальный `[gate] draft-blocked`), а при архитектурном `REDESIGN` — максимум **1 конечный `carbon-stack codex-lane redesign-reset`** на кандидата (сброс раундов + чистая сессия упрощения и ревьюера; повторный сброс запрещён).
- **Гигиена и устойчивость роя:**
  - **Warm Pool (`gate_inbox.rs` + `cwg_stop.rs`):** переиспользование `waiting` воркеров через `@mention` со строгой проверкой `round_start_msg_id` и `current_diff_hash`.
  - **Cursor Guard:** при `> 15` сообщениях в `board.jsonl` повторный `read_board` без `since=<last_seen_id>` блокируется хуком `PreToolUse`.
  - **Stall Watchdog:** `in_flight` воркеры без активности дольше `SWARM_STALL_TIMEOUT_SEC` (по умолчанию `240` с) диагностируются явно вместо вечного ожидания.

## Быстрый старт и эксплуатация

```powershell
# Предпросмотр установки без записи на диск
.\plugin\bin\carbon-stack.exe install --dry-run

# Установка (идемпотентно, с автоматическим backup перед изменениями)
.\plugin\bin\carbon-stack.exe install

# Полная диагностика установленного стека и Language Server
.\plugin\bin\carbon-stack.exe install --diagnose

# Откат к предыдущему состоянию
.\plugin\bin\carbon-stack.exe install --rollback latest

# Запуск всех модульных и интеграционных Rust-тестов
cargo test --manifest-path rust/Cargo.toml
```
