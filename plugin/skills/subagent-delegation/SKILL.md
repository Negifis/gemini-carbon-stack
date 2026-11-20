---
name: subagent-delegation
description: Detailed protocol for multi-worker swarm orchestration and Hydrogen browser/translator delegation. Do NOT load when working without subagents.
---

# Subagent Delegation & Multi-Model Routing (Gemini Carbon)

## 1. Когда НЕ нужно делегировать

Gemini 4 Carbon (High) обладает глубоким рассуждением и большим окном контекста. **Выполняйте работу напрямую без субагентов**, если:
- нужно прочитать 1–6 известных файлов или найти символ через `carbon-stack code-search`;
- правка локализована в одном модуле (`<= 3` строк);
- требуется последовательная отладка, где каждый следующий шаг зависит от предыдущего.

## 2. Матрица межмодельной маршрутизации Antigravity 2.0

*Важное ограничение среды (подтверждено эмпирически на Language Server `hub-2.32.1`):* `invoke_subagent` принимает только Gemini-тиры (`inherit`, `flash_lite`, `flash`, `pro`), а ключ `model:` во frontmatter `agents/*.md` отбрасывает агента при загрузке плагина. Использование `flash` / `flash_lite` / `gemini-3.8-flash-*` в стеке **отключено и блокируется хуком `safety_guards.rs`**. Точное закрепление моделей семейства Claude (`claude-sonnet-5-5-high`, `claude-opus-5-5-high`), **`Gemini 4 Neon`** (`gemini-4-neon-{low,medium,high,xhigh}`) и **`Gemini 4 Hydrogen`** (`gemini-4-hydrogen-{low,medium,high,xhigh}`), а также живое переключение при исчерпании квоты выполняются через нативный `swarm`.

| Задача | Инструмент / Агент | Модель / Маршрут |
|---|---|---|
| Широкая разведка незнакомой подсистемы (>10 файлов) | `invoke_subagent(TypeName="code-explorer")` или `research` | `inherit` |
| Глубокий архитектурный аудит, контракты, перфоманс | `swarm(action="add", ..., model="gemini-4-neon-high"\|"-xhigh")` (`repo-architect-scout`) | **`Gemini 4 Neon`** (`high` / `xhigh`) |
| Глубокая отладка гонок, флаков, утечек, визуал+логи | `swarm(action="add", name="root-cause-debugger", model="gemini-4-neon-xhigh")` | **`Gemini 4 Neon (XHigh)`** |
| Сложные UI/фронтенд-билдеры (UI-to-Code) и тесты | `swarm(action="add", ..., model="gemini-4-neon-medium"\|"-high")` (`frontend-ui-builder`, `test-author` в `owned_paths`) | **`Gemini 4 Neon`** (`medium` / `high` / `xhigh`) |
| Локальная разведка, простые билдеры, быстрые хелперы | `swarm(action="add", ..., model="gemini-4-hydrogen-<уровень>")` | **`Gemini 4 Hydrogen`** (`low` / `medium` / `high`) |
| Живая проверка веб-интерфейса и визуальных состояний | `swarm(action="add", name="browser-qa", model="gemini-4-hydrogen-<уровень>")` -> внутри `invoke_subagent(TypeName="browser", Model="inherit")` (либо напрямую `Model="inherit"`, если текущая сессия уже на Hydrogen) | **`Gemini 4 Hydrogen`** (`low`–`xhigh` по сложности сценария) |
| Генерация растровых иллюстраций / иконок | `invoke_subagent(TypeName="image-generator")` | по умолчанию |
| Перевод технической документации | `swarm(action="add", ..., model="gemini-4-hydrogen-<уровень>")` (либо `invoke_subagent(TypeName="translator", Model="inherit")` внутри Hydrogen-сессии) | **`Gemini 4 Hydrogen`** (`low` / `medium` / `high` по объёму и плотности терминов) |
| **Simplify (`STANDARD > 3` строк / Fast-Path)** | `swarm(action="add", name="simplify-reviewer", model="claude-sonnet-5-5-high")` | **1 объединённый `Claude Sonnet 5.5 (High)`** (`SIMPLIFY_LENS: ALL`; fallback -> `gemini-4-neon-xhigh`, вторично `gemini-4-hydrogen-xhigh`, никогда не Carbon) |
| **Simplify (`HIGH` / `XHIGH` — 3 линзы)** | `swarm(action="add", ..., model="claude-sonnet-5-5-high")` | **3 отдельные линзы `Claude Sonnet 5.5 (High)`** (без схлопывания; fallback -> `gemini-4-neon-xhigh`, вторично `gemini-4-hydrogen-xhigh`, никогда не Carbon) |
| **Внешнее adversarial-ревью (`HIGH` / `XHIGH`)** | `carbon-stack codex-lane review` (`--xhigh` для `XHIGH`) | **OpenAI Codex CLI** (`gpt-6.2-sol` на `high` для `HIGH`; `gpt-6.2-astra` на `xhigh` для `XHIGH`) |
| **Внутреннее adversarial-ревью (`HIGH` / `XHIGH`)** | `swarm(action="add", ..., model="claude-opus-5-5-high")` | **`Claude Opus 5.5 (High)`** -> эскалация на **`gemini-4-neon-xhigh`** для `HIGH` или **`gemini-4-carbon-high`** для `XHIGH` при проблеме с Opus |
| Программный fan-out по множеству независимых модулей | `run_workflow` (`parallel` / `pipeline`) | по задаче |
| Параллельная разработка нескольких подсистем | `swarm` (`workspace="share"` или `"branch"`) | `gemini-4-neon-high` / `gemini-4-hydrogen-high` |

### Выбор уровня размышления `Gemini 4 Neon` (пришёл на смену Argon)

| Модель `swarm` | Сложность задачи | Основные роли и сценарии |
|---|---|---|
| `gemini-4-neon-low` | Массовые структурированные правки | Миграции конфигов/схем/локалей, форматирование и типовые правки с низкой вероятностью галлюцинаций |
| `gemini-4-neon-medium` | Точечный код и тесты *(и `test-author`)* | Изолированные багфиксы по стектрейсу, CRUD-эндпоинты, unit/regression-тесты |
| `gemini-4-neon-high` *(default)* | Сложные модули и UI *(и `frontend-ui-builder`, `repo-architect-scout`)* | Многофайловый рефакторинг, UI-to-Code по макетам/скриншотам, `Disjoint Builders` в Rust/TS/async |
| `gemini-4-neon-xhigh` | Глубокая отладка, fallback `simplify` и `HIGH`-ревью | `root-cause-debugger` (гонки, флаки, утечки, визуал+логи), primary fallback `simplify` и эскалация `internal-neon` на `HIGH` |

### Выбор уровня размышления `Gemini 4 Hydrogen`

| Модель `swarm` | Сложность задачи | Примеры для `browser`, `translator` и хелперов |
|---|---|---|
| `gemini-4-hydrogen-low` | Механические / атомарные операции | Одиночное открытие URL и скриншот/smoke-check; перевод `<= 150` строк, UI-меток или короткого README-блока; шаблонная выборка фактов |
| `gemini-4-hydrogen-medium` | Стандартные задачи *(по умолчанию)* | Интерактивная UI-проверка (клики, формы, `loading`/`empty`/`populated`/`error`, консоль, desktop/mobile); перевод многостраничной документации и `SKILL.md`; разведка смежного модуля (`5–10` файлов) |
| `gemini-4-hydrogen-high` | Сложные многошаговые задачи | Многошаговые SPA/E2E-сценарии (логин, каскадные формы, таблицы/модалки, воспроизведение UI-регрессий); перевод плотных архитектурных спецификаций; простые `Disjoint Builders` |
| `gemini-4-hydrogen-xhigh` | Вторичный fallback `simplify` и UI-отладка | Вторичный резерв для `simplify` (если недоступны Sonnet и Neon) и сложные browser/WebSocket сценарии |

## 3. Жёсткие правила делегирования

1. **Контракт задачи:** каждый вызов обязан указывать точную границу файлов, запрет на редактирование для ревьюеров и точный формат выходных маркеров (`SIMPLIFY_LENS`, `VERDICT`). Активные ограничения `AUTHORITATIVE STATE` и `SUPERSEDED / CANCELLED` автоматически подставляются хуком `safety_guards.rs` в `invoke_subagent`, а для `swarm` включаются в `brief`.
2. **Единоличное владение записью:** никогда не назначайте двум пишущим агентам пересекающиеся файлы в одном рабочем дереве; для параллельной записи используйте `workspace="share"` / `"branch"` или `carbon-stack chip-handoff open`.
3. **Уборка завершённых swarm-воркеров и запрет пакетного `read_board` + `swarm_wait`:** никогда не вызывайте `read_board` и `swarm_wait` в одном ходе — сначала вызовите `read_board`, и если все воркеры ответили, сразу завершите их через `swarm(action="kill", name=...)` (их системные транскрипты и записи в `board.jsonl`/`members.json` сохраняются для проверки `cwg_stop.rs`, а холостые воркеры не удерживают `fullyIdle=False` и не блокируют `swarm_wait`).
