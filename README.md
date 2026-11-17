# Gemini Carbon Engineering Stack

Самостоятельная нативная инженерная операционная система для **Gemini 4 Carbon** в среде исполнения **Google Antigravity 2.0** (`hub-2.32.1` + `agy` CLI `1.2.10` на Windows NT).

Спроектирована как функциональный эквивалент гарантий `Negifis/claude-code-stack` (ревизия `5310f797208af6462dad48eb944869c92a1edf14`), переосмысленный под реальные механизмы Antigravity (`hooks.json` protojson contract, системные транскрипты `transcript_full.jsonl` и `.system_generated/swarm/`, межмодельную маршрутизацию `Claude Sonnet 5.5 High` / `Claude Opus 5.5 High` / `Gemini 4 Carbon High` / `Gemini 4 Hydrogen (Low..XHigh)` / `OpenAI Codex CLI`, встроенных субагентов `browser` / `image-generator` / `research` и плагинную архитектуру `~/.gemini/config/plugins/`).

## Структура репозитория

- `install.py` / `install.sh` — безопасный идемпотентный установщик с preflight-проверками, валидацией через `agy plugin validate`, резервным копированием, `--dry-run`, `--diagnose`, `--rollback` и кроссплатформенной обёрткой `install.sh` (`--with-toolchains`).
- `templates/` и `.env.example` — обезличенные шаблоны конфигурации экономии токенов:
  - `templates/mcp_config.json` — ленивая загрузка (`"eager": false`) и жёсткая фильтрация `"enabledTools"` для **Serena MCP** (`uvx --from git+https://github.com/oraios/serena serena start-mcp-server --context=antigravity --agent-interface=tools --project-from-cwd`, 8 read-only LSP-инструментов вместо 24) и **Context7 MCP** (`npx -y @upstash/context7-mcp`, 2 инструмента).
  - `templates/hooks.json` — CLI-хук **Tokenade** (`@tokenade/cli`, `tokenade hookwrap-pretool`) для автоматического сжатия шумного вывода терминала с прозрачной распаковкой обёрток `tokenade wrap`/`raw` внутри `cwg_mark.py` и `safety_guards.py`.
  - `templates/antigravity-cli-settings.json` — конфигурация `agy` CLI с маршрутизацией на `Orchestrator (Argon)` и отключённым автосписанием кредитов (`"useG1Credits": false`).
  - `templates/GEMINI.md` — тонкий глобальный контекст (< 40 строк) с запретом чтения lock-файлов/сборок/бинарников и приоритетом символьного LSP-поиска.
- `.agents/` — проектные скоупированные правила (`high-risk-verification.md` `trigger: glob`, `multi-agent-routing.md` `trigger: model_decision`) и прогрессивные навыки (`token-optimization`).
- `plugin/` — нативный плагин-бандл Antigravity (`gemini-carbon-stack`):
  - `plugin.json`, `hooks.json` — манифест плагина и 4 группы runtime-хуков (`continuity`, `safety-and-quality-guards`, `chip-handoff`, `code-work-gate`).
  - `hooks/` — исполняемые модули риск-ориентированного гейта, межмодельной верификации (`codex_lane.py` + `swarm` `members.json`/`board.jsonl`), минимального `handoff` (`continuity.py`), защиты от циклов, безопасности git worktree и межсессионной передачи задач.
  - `tools/` — локальная FTS5-память с защитой от секретов (`carbon_memory.py`), импортер интерактивных сессий Claude Code во все 5 слоёв хранения Antigravity (`claude_chat_importer.py`), оркестратор изолированных задач (`chip_handoff.py`), быстрый AST/git-grep поиск (`code_search.py`), контроль 5-минутного TTL кэша `swarm` и инкрементальных диффов (`swarm_cache.py`), безопасное управление worktrees/junctions (`worktree_guard.py`), самодиагностика (`stack_doctor.py`), диагностика файловых дескрипторов Windows (`file-holders.ps1`) и векторизация SVG (`vectorize.mjs`).
  - `rules/` — компактная всегда активная конституция `AGENTS.md` (35 строк) и селективные правила по нативным триггерам Antigravity (`high-risk-verification.md` `glob`, `multi-agent-routing.md` `model_decision`, `deep-audit.md` `manual`).
  - `agents/` — 8 специализированных read-only субагентов (`simplify-reviewer`, `simplify-reuse-reviewer`, `simplify-quality-reviewer`, `simplify-efficiency-reviewer`, `adversarial-reviewer`, `adversarial-reviewer-xhigh`, `code-explorer`, `translator`).
  - `skills/` — 21 прогрессивный навык и slash-команда (`/task-start`, `/checkpoint`, `/rebuild`, `/import-claude-chats`, `/adversarial-review`, `/verify-ready`, `/stack-doctor`, `token-optimization` и профильные дисциплины) с компактными описаниями.
  - Опциональная проектная политика `.agents/carbon-gate.json` для переопределения порогов риска (`default_code_risk`, `*_risk_globs`, `require_*_on_standard`).
- `rules/uiux-design.md` — контекстное правило фронтенда (`trigger: glob`), активируемое только на файлах UI/разметки.
- `tests/` — полный набор модульных, негативных и live-интеграционных тестов.
- `ARCHITECTURE.md` — описание архитектуры, межмодельной маршрутизации и реальных границ гарантий.
- `MIGRATION_MATRIX.md` — полная техническая матрица решений (`NATIVE`, `ADAPT`, `KEEP`, `MERGE`, `REMOVE`, `UNAVAILABLE`).

## **Swarm 2.0 Architecture**

- **Трёхфазный конвейер (`swarm-orchestration`):**
  1. **Scout Swarm (Разведка):** параллельные read-only скауты на `Gemini 4 Hydrogen` с `serena` LSP пишут отчёты в `.swarm/artifacts/<worker>-<round>.md` (`Pointer-on-Board`: `<= 12` строк на доске).
  2. **Disjoint Builder Swarm (Реализация):** координатор `Orchestrator (Argon)` задаёт непересекающиеся `owned_paths` в `.swarm/ownership.json` или изолированные `git worktree` (`.swarm/worktrees/<worker>`) через CLI `plugin/tools/swarm_ctl.py`; `File Ownership Guard` в `safety_guards.py` блокирует запись за пределами зоны воркера.
  3. **Verification Gate (`UNITTEST -> REVIEW -> SIMPLIFY -> KILL -> --CLOSURE`):** сначала локальные тесты и первичный `codex_lane.py review`; после закрытия функциональных замечаний — однократный `simplify` (`SIMPLIFY_LENS: ALL` Fast-Path при `<= 2` файлов и `<= 30` изменённых строк, иначе 3 параллельные линзы), затем пакетный `kill` воркеров и финальный `codex_lane.py review --closure`.
- **Гигиена и устойчивость роя:**
  - **Warm Pool (`gate_inbox.py` + `cwg_stop.py`):** переиспользование `waiting` воркеров через `@mention` со строгой проверкой `round_start_msg_id` и `current_diff_hash`.
  - **Cursor Guard:** при `> 15` сообщениях в `board.jsonl` повторный `read_board` без `since=<last_seen_id>` блокируется хуком `PreToolUse`.
  - **Stall Watchdog:** `in_flight` воркеры без активности дольше `SWARM_STALL_TIMEOUT_SEC` (по умолчанию `240` с) диагностируются явно вместо вечного ожидания.

## Быстрый старт и эксплуатация

```powershell
# Предпросмотр установки без записи на диск
python -X utf8 install.py --dry-run

# Установка (идемпотентно, с автоматическим backup перед изменениями)
python -X utf8 install.py

# Полная диагностика установленного стека и Language Server
python -X utf8 install.py --diagnose

# Откат к предыдущему состоянию
python -X utf8 install.py --rollback latest

# Запуск всех тестовых наборов
python -X utf8 -m unittest discover -s tests -v
```
