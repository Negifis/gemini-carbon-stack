# Архитектура Gemini Carbon Engineering Stack

## 1. Среда исполнения и точки интеграции

Целевой хост — **Google Antigravity 2.0** (`Language Server hub-2.32.1`, CLI `agy 1.2.10`, ОС `Windows NT 10.0.26340.0`, `Python 3.13`, `Git 2.49`, внешний `codex-cli 0.160.0`). Автономный `gemini` CLI в системе не установлен, поэтому стек интегрируется напрямую в документированный контур плагинов и кастомизаций Antigravity:

- `~/.gemini/config/plugins/gemini-carbon-stack/` — атомарный плагин (включается автоматически при обнаружении Language Server без прямого редактирования приватного `~/.gemini/config/config.json`).
  - `rules/AGENTS.md` (`always_on`) — компактная глобальная конституция (~3.4 KB) без дублирования `SKILL.md`.
  - `rules/high-risk-verification.md` (`glob`) — строгие критерии и отпечатки SHA-256 для критичных путей и конфигов агента.
  - `rules/multi-agent-routing.md` (`model_decision`) — правила `swarm`, TTL prompt cache и маршрутизации `Claude`/`Codex`/`Hydrogen`.
  - `rules/deep-audit.md` (`manual`) — глубокий ручной аудит и инварианты среды.
- `~/.gemini/config/rules/uiux-design.md` — glob-правило (`trigger: glob`), подключаемое только при открытии/редактировании фронтенд-файлов.
- `~/.gemini/carbon-stack/` — изолированное хранилище runtime-состояния (`state/gate`, `state/continuity`, `state/memory`, `state/chips`, `state/hygiene`, `state/logs`) и резервных копий установщика (`backups/`).

## 2. Межмодельная маршрутизация и пропорциональность гейта

В Antigravity 2.0 помимо основного координатора **Gemini 4 Carbon (High)** (`gemini-4-carbon-high`) доступны модели семейства Claude (`claude-sonnet-5-5-high`, `claude-opus-5-5-high`), быстрая линейка **`Gemini 4 Hydrogen`** (`gemini-4-hydrogen-{low,medium,high,xhigh}`) и внешний OpenAI Codex CLI (`gpt-6.1-sol`). Поскольку `invoke_subagent` принимает только Gemini-тиры, закрепление моделей Claude и `Gemini 4 Hydrogen` выполняется через нативный инструмент `swarm` (при этом `Gemini Flash` запрещён и блокируется хуком `safety_guards.py`):

1. **Пропорциональный риск (без эвристики `<= 3` строк):** уровень риска определяется типом затронутых компонентов, характером операции и опциональным контрактом `.agents/carbon-gate.json` (`default_code_risk`, `*_risk_globs`, `require_*_on_standard`). Обычные правки `STANDARD` требуют только релевантных локальных проверок/тестов (`workspace_has_test_harness`) и закрываются без автоматического `swarm`/ревью; автономные статичные файлы/аддоны без тест-харнесса не требуют фиктивных тестов (но любая упавшая запущенная проверка блокирует закрытие).
2. **Simplify (`Claude Sonnet 5.5 (High)`):** для `HIGH`/`XHIGH` — строго **3 отдельные параллельные линзы** (`simplify-reuse`, `simplify-quality`, `simplify-efficiency`) без схлопывания; для `STANDARD` — только при явном opt-in проекта через `.agents/carbon-gate.json` (`require_simplify_on_standard: true`, достаточно 1 объединённого воркера `simplify-reviewer`). Резервный `gemini-4-hydrogen-xhigh` через `swarm` допускается только при подтверждённом исчерпании квоты или сбое Sonnet (запуск `simplify` на Carbon заблокирован для защиты квоты основной модели).
3. **Внешнее adversarial-ревью (`HIGH`/`XHIGH` или opt-in проекта):** `codex_lane.py review` (OpenAI Codex CLI; в рамках одного кандидата гейта повторные раунды и `--closure` автоматически продолжаются в одной сессии через `codex exec resume <session_id>`, с привязкой к открытому кандидату).
4. **Внутреннее adversarial-ревью и TTL-маршрутизация раундов (`swarm_cache.py`):** при открытом circuit breaker Codex или прямом внутреннем ревью запускается на **`Claude Opus 5.5 (High)`** (`claude-opus-5-5-high`) с автоматической эскалацией на **`Gemini 4 Carbon (High)`** (`gemini-4-carbon-high`) при ошибке или 0% квоты Opus. Поскольку upstream prompt cache Anthropic в Antigravity имеет 5-минутный ephemeral TTL (`300s`, безопасный порог `270s`), `swarm_cache.py prepare` направляет следующий раунд в тот же чат (`post_message`) только пока кэш тёплый (`<= 270s`), а при истечении TTL завершает раздутый чат (`kill`) и запускает `<name>-r<N>` с инкрементальным диффом и списком прошлых замечаний.
5. **Вспомогательные роли (`browser`, `translator`, локальная разведка):** вместо `Gemini Flash` везде применяется **`Gemini 4 Hydrogen`** с выбором уровня размышления (`low` / `medium` / `high` / `xhigh`) по сложности задачи.

## 3. Поток событий Lifecycle Hooks (`hooks.json`)

| Событие Antigravity | Подключённые обработчики | Назначение и контракт ответа (protojson) |
|---|---|---|
| `SessionStart` | `continuity.py` | Регистрация сессии, проверка совместного владения worktree (`tree_locks`), краткое восстановление из `handoff.json`/`CHECKPOINT.md` при `resume`/`compact` или активном незавершённом worktree (без авто-дампа памяти на чистых стартах) -> `{"injectSteps": [...]}` |
| `PreInvocation` | `continuity.py`, `chip_hooks.py`, `cwg_pre_invocation.py` | Детекция сильных коррекций пользователя и сжатия контекста (`compaction` -> `build_repo_handoff` <= 900 символов), доставка уведомлений о готовых чипах и 1-строчной сводки гейта только для `HIGH`/`XHIGH` (или opt-in) -> `{"injectSteps": [...]}` |
| `PreToolUse` | `continuity.py`, `safety_guards.py`, `cwg_mark.py` | Loop Guard на `read_file|run_command` (блокировка 3-го чтения неизменённого файла и 4-го повтора одинаковой команды), защита от голого `git worktree remove` и `git reset --hard`, защита от вложенных субагентов, запрет `Gemini Flash`, инжекция активных ограничений `handoff`/`checkpoint` в промпт субагента, снимок git и bounded non-git директорий для shell-команд (кроме `READ_ONLY`/`BOOKKEEPING`) -> `{"decision": "allow"\|"deny", "overwrite": ...}` |
| `PostToolUse` | `continuity.py`, `chip_hooks.py`, `cwg_mark.py` | Сброс поколения чтения после правок и `MUTATING`-команд (без срабатывания на `read_file`), запись фактического прогона проверок/тестов (`checks/*.jsonl`), 5-состояний классификатор shell (`READ_ONLY`, `BOOKKEEPING`, `VALIDATION`, `UNCERTAIN`, `MUTATING`) + измеренная дельта снимков (0-дельта `UNCERTAIN` не открывает `OPERATIONAL`), SHA-256 `content_marks` -> `{}` |
| `Stop` | `continuity.py`, `chip_hooks.py`, `cwg_stop.py` | Пост-коррекционный Output Lint, проверка сдачи дочернего чипа, пропорциональная финальная проверка Code Work Gate и независимого `VERDICT: APPROVED` для `HIGH`/`XHIGH`/opt-in -> `{"decision": "allow"\|"continue"}` |

## 4. Происхождение доказательств (Zero Self-Attestation)

`cwg_stop.py` не доверяет утверждениям модели в её собственном ответе:
1. **Тесты и проверки:** подтверждаются записями `PostToolUse` (`error == ""`) в `state/gate/checks/<session>.jsonl` с временной меткой не старее последней правки файлов.
2. **Внешнее ревью Codex:** подтверждается посессионным и пошаговым (`turns`) сканированием rollout-файлов `~/.codex/sessions/**/rollout-*.jsonl`, где каждый раунд (включая дописанные в тот же файл ходы `codex exec resume`) привязан к своему токену `REVIEW_ID`, `created_ts` из `state/gate/packets/` и проверке `effort == "xhigh"` для `XHIGH`.
3. **Внутреннее ревью Opus -> Carbon и 3 линзы Sonnet:** подтверждаются системными файлами Language Server `<brain>/<convId>/.system_generated/swarm/members.json` (фактическая модель воркера), `board.jsonl` (фильтрация строго `post.agent == member_name`, исключающая эхо промпта координатора) и транскриптами самих воркеров. Одобрение от `gemini-4-carbon-high` принимается только при наличии системного свидетельства ошибки или нулевой квоты `claude-opus-5-5-high`.
4. **Инвалидация после правок:** любое изменение байтов затронутых файлов после запуска ревьюера меняет SHA-256 в `content_marks` и делает прежний `APPROVED` недействительным.

## 5. Реальные границы гарантий

- Хуки Antigravity выполняются синхронно с таймаутом и работают в режиме fail-open при повреждении входного JSON или системном сбое (с записью в `hook-errors.jsonl`).
- При системных причинах остановки (`USER_CANCELED`, `ERROR`, `MAX_INVOCATIONS`, `MAX_TOKEN_BUDGET_EXCEEDED`) `Stop`-хук возвращает `allow`.
- Приватный мост `nlm-memory` в системе отсутствует: долговременная память работает локально на SQLite WAL + FTS5 (`carbon_memory.py`) с экспортом пакетов `export-nlm`.
