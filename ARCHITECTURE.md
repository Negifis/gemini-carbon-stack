# Архитектура Gemini Carbon Engineering Stack

## 1. Среда исполнения и точки интеграции

Целевой хост — **Google Antigravity 2.0** (`Language Server hub-2.32.1`, CLI `agy 1.2.10`, ОС `Windows NT 10.0.26340.0`, `Python 3.13`, `Git 2.49`, внешний `codex-cli 0.160.0`). Автономный `gemini` CLI в системе не установлен, поэтому стек интегрируется напрямую в документированный контур плагинов и кастомизаций Antigravity:

- `~/.gemini/config/plugins/gemini-carbon-stack/` — атомарный плагин (включается автоматически при обнаружении Language Server без прямого редактирования приватного `~/.gemini/config/config.json`).
- `~/.gemini/config/rules/uiux-design.md` — glob-правило (`trigger: glob`), подключаемое только при открытии/редактировании фронтенд-файлов.
- `~/.gemini/carbon-stack/` — изолированное хранилище runtime-состояния (`state/gate`, `state/continuity`, `state/memory`, `state/chips`, `state/hygiene`, `state/logs`) и резервных копий установщика (`backups/`).

## 2. Поток событий Lifecycle Hooks (`hooks.json`)

| Событие Antigravity | Подключённые обработчики | Назначение и контракт ответа (protojson) |
|---|---|---|
| `SessionStart` | `continuity.py` | Регистрация сессии, проверка совместного владения worktree (`tree_locks`), загрузка `CHECKPOINT.md`, карточки локальной памяти `carbon_memory` и сводки `gate_inbox` -> `{"injectSteps": [...]}` |
| `PreInvocation` | `continuity.py`, `chip_hooks.py`, `cwg_pre_invocation.py` | Детекция коррекций пользователя и сжатия контекста (`compaction`), доставка уведомлений о готовых чипах и 1-строчного статуса открытого кандидата гейта -> `{"injectSteps": [...]}` |
| `PreToolUse` | `continuity.py`, `safety_guards.py`, `cwg_mark.py` | Loop Guard (блокировка 3-го чтения неизменённого файла и 4-го повтора одинаковой команды), защита от голого `git worktree remove` и `git reset --hard`, контроль плотности комментариев, защита от вложенных субагентов, автоматическая инжекция `AUTHORITATIVE STATE` в промпт субагента через `overwrite`, снимок Git перед shell-командой -> `{"decision": "allow"\|"deny", "overwrite": ...}` |
| `PostToolUse` | `continuity.py`, `chip_hooks.py`, `cwg_mark.py` | Сброс поколения чтения после правок, запись фактического прогона проверок/тестов (`checks/*.jsonl`), вычисление файловой дельты и SHA-256 отпечатков кандидата (`content_marks`), фиксация отказов `codex_lane` -> `{}` |
| `Stop` | `continuity.py`, `chip_hooks.py`, `cwg_stop.py` | Пост-коррекционный Output Lint, проверка сдачи дочернего чипа, финальная проверка Code Work Gate (реальные тесты + `simplify-reviewer` + свежесть и подлинность `VERDICT: APPROVED` в rollout-логе Codex или системном транскрипте субагента, бюджет 3 блокировки) -> `{"decision": "allow"\|"continue"}` |

## 3. Происхождение доказательств (Zero Self-Attestation)

В отличие от текстовых инструкций, `cwg_stop.py` не доверяет утверждениям модели в её собственном ответе:
1. **Тесты и проверки:** подтверждаются записями `PostToolUse` (`error == ""`) в `state/gate/checks/<session>.jsonl` с временной меткой не старее последней правки файлов.
2. **Внешнее ревью Codex:** подтверждается сканированием реальных rollout-файлов `~/.codex/sessions/**/rollout-*.jsonl`, связанных по криптографическому токену `REVIEW_ID` из `state/gate/packets/`, с проверкой `effort == "xhigh"` для `XHIGH`.
3. **Нативное ревью и Simplify:** подтверждается связкой вызова `invoke_subagent` в родительском `transcript_full.jsonl` с системным транскриптом самого субагента (`brain/<subagent-id>/.system_generated/logs/transcript_full.jsonl`) и системным сообщением `SYSTEM_MESSAGE`.
4. **Инвалидация после правок:** любое изменение байтов затронутых файлов после ревью меняет SHA-256 в `content_marks` и делает прежний `APPROVED` недействительным.

## 4. Реальные границы гарантий

- Хуки Antigravity выполняются синхронно с таймаутом и должны быть отказоустойчивыми (fail-open при повреждении входного JSON или системном сбое, с обязательной записью в `hook-errors.jsonl`).
- При принудительных системных причинах остановки (`USER_CANCELED`, `ERROR`, `MAX_INVOCATIONS`, `MAX_TOKEN_BUDGET_EXCEEDED`) `Stop`-хук намеренно возвращает `allow`, не препятствуя отмене пользователем или системным лимитам.
- Внешний приватный мост `nlm-memory` для облачной синхронизации с NotebookLM в системе отсутствует: долговременная память полностью работает локально на SQLite WAL + FTS5 (`carbon_memory.py`), а пакеты для будущего импорта в NotebookLM формируются локально командой `export-nlm`.
