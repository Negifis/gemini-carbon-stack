# Gemini Carbon Engineering Stack

Самостоятельная нативная инженерная операционная система для **Gemini 4 Carbon** в среде исполнения **Google Antigravity 2.0** (`hub-2.32.1` + `agy` CLI `1.2.10` на Windows NT).

Спроектирована как функциональный эквивалент гарантий `Negifis/claude-code-stack` (ревизия `5310f797208af6462dad48eb944869c92a1edf14`), переосмысленный под реальные механизмы Antigravity (`hooks.json` protojson contract, системные транскрипты `transcript_full.jsonl` и `.system_generated/swarm/`, межмодельную маршрутизацию `Claude Sonnet 5.5 High` / `Claude Opus 5.5 High` / `Gemini 4 Carbon High` / `Gemini 4 Hydrogen (Low..XHigh)` / `OpenAI Codex CLI`, встроенных субагентов `browser` / `image-generator` / `research` и плагинную архитектуру `~/.gemini/config/plugins/`).

## Структура репозитория

- `install.py` — безопасный идемпотентный установщик с preflight-проверками, валидацией через `agy plugin validate`, резервным копированием, `--dry-run`, `--diagnose` и `--rollback`.
- `plugin/` — нативный плагин-бандл Antigravity (`gemini-carbon-stack`):
  - `plugin.json`, `hooks.json` — манифест плагина и 4 группы runtime-хуков (`continuity`, `safety-and-quality-guards`, `chip-handoff`, `code-work-gate`).
  - `hooks/` — исполняемые модули гейта, межмодельной верификации (`codex_lane.py` + `swarm` `members.json`/`board.jsonl`), continuity, защиты от циклов, контроля плотности комментариев, безопасности git worktree и межсессионной передачи задач.
  - `tools/` — локальная FTS5-память с защитой от секретов (`carbon_memory.py`), оркестратор изолированных задач (`chip_handoff.py`), быстрый AST/git-grep поиск (`code_search.py`), контроль 5-минутного TTL кэша `swarm` и инкрементальных диффов (`swarm_cache.py`), безопасное управление worktrees/junctions (`worktree_guard.py`), самодиагностика (`stack_doctor.py`), диагностика файловых дескрипторов Windows (`file-holders.ps1`) и векторизация SVG (`vectorize.mjs`).
  - `rules/AGENTS.md` — компактная глобальная конституция Gemini Carbon и правила Windows PowerShell 5.1.
  - `agents/` — 8 специализированных read-only субагентов (`simplify-reviewer`, `simplify-reuse-reviewer`, `simplify-quality-reviewer`, `simplify-efficiency-reviewer`, `adversarial-reviewer`, `adversarial-reviewer-xhigh`, `code-explorer`, `translator`).
  - `skills/` — 19 прогрессивных навыков и slash-команд (`/task-start`, `/checkpoint`, `/rebuild`, `/adversarial-review`, `/verify-ready`, `/stack-doctor` и профильные дисциплины).
- `rules/uiux-design.md` — контекстное правило фронтенда (`trigger: glob`), активируемое только на файлах UI/разметки.
- `tests/` — полный набор модульных, негативных и live-интеграционных тестов.
- `ARCHITECTURE.md` — описание архитектуры, межмодельной маршрутизации и реальных границ гарантий.
- `MIGRATION_MATRIX.md` — полная техническая матрица решений (`NATIVE`, `ADAPT`, `KEEP`, `MERGE`, `REMOVE`, `UNAVAILABLE`).

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
