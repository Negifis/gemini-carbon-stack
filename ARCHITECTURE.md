# Архитектура Gemini Carbon Engineering Stack

## 1. Среда исполнения и точки интеграции

Целевой хост — **Google Antigravity 2.0** (`Language Server hub-2.32.1`, CLI `agy 1.2.10`, ОС `Windows NT 10.0.26340.0`, `Python 3.13`, `Git 2.49`, внешний `codex-cli 0.160.0`). Автономный `gemini` CLI в системе не установлен, поэтому стек интегрируется напрямую в документированный контур плагинов и кастомизаций Antigravity:

- `~/.gemini/config/plugins/gemini-carbon-stack/` — атомарный плагин (включается автоматически при обнаружении Language Server без прямого редактирования приватного `~/.gemini/config/config.json`).
- `~/.gemini/config/rules/uiux-design.md` — glob-правило (`trigger: glob`), подключаемое только при открытии/редактировании фронтенд-файлов.
- `~/.gemini/carbon-stack/` — изолированное хранилище runtime-состояния (`state/gate`, `state/continuity`, `state/memory`, `state/chips`, `state/hygiene`, `state/logs`) и резервных копий установщика (`backups/`).

## 2. Межмодельная маршрутизация проверок

В Antigravity 2.0 помимо основного координатора **Gemini 4 Carbon (High)** (`gemini-4-carbon-high`) доступны модели семейства Claude (`claude-sonnet-5-5-high`, `claude-opus-5-5-high`) и внешний OpenAI Codex CLI (`gpt-6.1-sol`). Поскольку `invoke_subagent` принимает только Gemini-тиры, а ключ `model:` во frontmatter `agents/*.md` отклоняется Language Server, закрепление моделей Claude и горячая эскалация выполняются через нативный инструмент `swarm`:

1. **Simplify (3 параллельные линзы):** `simplify-reuse`, `simplify-quality`, `simplify-efficiency` запускаются на **`Claude Sonnet 5.5 (High)`** (`claude-sonnet-5-5-high`) с резервным переключением на `gemini-4-carbon-high` при подтверждённом исчерпании квоты или ошибке Sonnet.
2. **Внешнее adversarial-ревью (основной контур):** `codex_lane.py review` (OpenAI Codex CLI, без изменений).
3. **Внутреннее adversarial-ревью (при открытом circuit breaker Codex или прямом внутреннем ревью):** запускается на **`Claude Opus 5.5 (High)`** (`claude-opus-5-5-high`) с автоматической эскалацией на **`Gemini 4 Carbon (High)`** (`gemini-4-carbon-high`), если с Opus зафиксирована ошибка, нулевая квота или недоступность.

## 3. Поток событий Lifecycle Hooks (`hooks.json`)

| Событие Antigravity | Подключённые обработчики | Назначение и контракт ответа (protojson) |
|---|---|---|
| `SessionStart` | `continuity.py` | Регистрация сессии, проверка совместного владения worktree (`tree_locks`), загрузка `CHECKPOINT.md`, карточки локальной памяти `carbon_memory` и сводки `gate_inbox` -> `{"injectSteps": [...]}` |
| `PreInvocation` | `continuity.py`, `chip_hooks.py`, `cwg_pre_invocation.py` | Детекция коррекций пользователя и сжатия контекста (`compaction`), доставка уведомлений о готовых чипах и 1-строчного статуса открытого кандидата гейта -> `{"injectSteps": [...]}` |
| `PreToolUse` | `continuity.py`, `safety_guards.py`, `cwg_mark.py` | Loop Guard (блокировка 3-го чтения неизменённого файла и 4-го повтора одинаковой команды), защита от голого `git worktree remove` и `git reset --hard`, контроль плотности комментариев, защита от вложенных субагентов, автоматическая инжекция `AUTHORITATIVE STATE` в промпт субагента через `overwrite`, снимок Git перед shell-командой -> `{"decision": "allow"\|"deny", "overwrite": ...}` |
| `PostToolUse` | `continuity.py`, `chip_hooks.py`, `cwg_mark.py` | Сброс поколения чтения после правок, запись фактического прогона проверок/тестов (`checks/*.jsonl`), вычисление файловой дельты и SHA-256 отпечатков кандидата (`content_marks`), фиксация отказов `codex_lane` -> `{}` |
| `Stop` | `continuity.py`, `chip_hooks.py`, `cwg_stop.py` | Пост-коррекционный Output Lint, проверка сдачи дочернего чипа, финальная проверка Code Work Gate (реальные тесты + 3 линзы `claude-sonnet-5-5-high` + свежесть и подлинность `VERDICT: APPROVED` в rollout-логе Codex или системном реестре `.system_generated/swarm/` `claude-opus-5-5-high` -> `gemini-4-carbon-high`, бюджет 3 блокировки) -> `{"decision": "allow"\|"continue"}` |

## 4. Происхождение доказательств (Zero Self-Attestation)

`cwg_stop.py` не доверяет утверждениям модели в её собственном ответе:
1. **Тесты и проверки:** подтверждаются записями `PostToolUse` (`error == ""`) в `state/gate/checks/<session>.jsonl` с временной меткой не старее последней правки файлов.
2. **Внешнее ревью Codex:** подтверждается сканированием rollout-файлов `~/.codex/sessions/**/rollout-*.jsonl`, связанных по токену `REVIEW_ID` из `state/gate/packets/`, с проверкой `effort == "xhigh"` для `XHIGH`.
3. **Внутреннее ревью Opus -> Carbon и 3 линзы Sonnet:** подтверждаются системными файлами Language Server `<brain>/<convId>/.system_generated/swarm/members.json` (фактическая модель воркера), `board.jsonl` (фильтрация строго `post.agent == member_name`, исключающая эхо промпта координатора) и транскриптами самих воркеров. Одобрение от `gemini-4-carbon-high` принимается только при наличии системного свидетельства ошибки или нулевой квоты `claude-opus-5-5-high`.
4. **Инвалидация после правок:** любое изменение байтов затронутых файлов после запуска ревьюера меняет SHA-256 в `content_marks` и делает прежний `APPROVED` недействительным.

## 5. Прозрачность прогресса в Antigravity 2.0

- **Единственный рабочий канал промежуточных отчётов:** вывод краткого русского Markdown в `PLANNER_RESPONSE.content` **в одном шаге с `tool_calls`** мгновенно отображается в основном `Chat Canvas` без остановки автономного цикла (`NO_TOOL_CALL` возникает только при пустых `tool_calls`), а при создании `swarm` дополняется нативной ссылкой `[Open the Swarm UI](sidecar://swarm/swarm_board/?auto_open=false)`.
- **Детерминированный трекер (`continuity.py`):** на каждом `PreInvocation` инспектирует `transcript_full.jsonl` (не считая `post_message`, `send_message`, `swarm`, `swarm_wait`, `read_board` информированием пользователя) и подаёт точечное `systemMessage`-напоминание при длительной тишине, смене гипотезы, блокере/429, переключении модели или старте финальной проверки с cooldown и без блокировок в `Stop`.
- **Фактические ограничения хоста:** `PostToolUse` по контракту `hooks.json` возвращает строго `{}` и не может напрямую публиковать текст в чат; во время выполнения одного синхронного `tool_call` (до возврата результата или перехода команды в фон) новые шаги модели не вызываются, поэтому отчёт о старте проверки отправляется в момент её запуска.

## 6. Реальные границы гарантий

- Хуки Antigravity выполняются синхронно с таймаутом и работают в режиме fail-open при повреждении входного JSON или системном сбое (с записью в `hook-errors.jsonl`).
- При системных причинах остановки (`USER_CANCELED`, `ERROR`, `MAX_INVOCATIONS`, `MAX_TOKEN_BUDGET_EXCEEDED`) `Stop`-хук возвращает `allow`.
- Приватный мост `nlm-memory` в системе отсутствует: долговременная память работает локально на SQLite WAL + FTS5 (`carbon_memory.py`) с экспортом пакетов `export-nlm`.
