---
name: subagent-delegation
description: Multi-model subagent, workflow, and swarm routing for Gemini 4 Carbon in Antigravity: Sonnet 5.5 High simplify lenses, Codex external review, Opus 5.5 High -> Carbon High internal review escalation, and strict scope ownership.
---

# Subagent Delegation & Multi-Model Routing (Gemini Carbon)

## 1. Когда НЕ нужно делегировать

Gemini 4 Carbon (High) обладает глубоким рассуждением и большим окном контекста. **Выполняйте работу напрямую без субагентов**, если:
- нужно прочитать 1–6 известных файлов или найти символ через `code_search.py`;
- правка локализована в одном модуле (`<= 3` строк);
- требуется последовательная отладка, где каждый следующий шаг зависит от предыдущего.

## 2. Матрица межмодельной маршрутизации Antigravity 2.0

*Важное ограничение среды (подтверждено эмпирически на Language Server `hub-2.32.1`):* `invoke_subagent` принимает только Gemini-тиры (`inherit`, `flash_lite`, `flash`, `pro`), а ключ `model:` во frontmatter `agents/*.md` отбрасывает агента при загрузке плагина. Точное закрепление моделей семейства Claude (`claude-sonnet-5-5-high`, `claude-opus-5-5-high`) и живое переключение при исчерпании квоты выполняются через нативный `swarm`.

| Задача | Инструмент / Агент | Модель / Маршрут |
|---|---|---|
| Широкая разведка незнакомой подсистемы (>10 файлов) | `invoke_subagent(TypeName="code-explorer")` или `research` | `inherit` (`gemini-4-carbon-high`) |
| Живая проверка веб-интерфейса и визуальных состояний | `invoke_subagent(TypeName="browser")` | `flash` |
| Генерация растровых иллюстраций / иконок | `invoke_subagent(TypeName="image-generator")` | по умолчанию |
| Перевод объёмной документации | `invoke_subagent(TypeName="translator")` | `flash` или `inherit` |
| **Simplify — 3 линзы (`reuse`, `quality`, `efficiency`)** | `swarm(action="add", ..., model="claude-sonnet-5-5-high")` | **`Claude Sonnet 5.5 (High)`** (fallback -> `gemini-4-carbon-high` / `simplify-*-reviewer` при сбое/0% квоты Sonnet) |
| **Внешнее adversarial-ревью (`HIGH` / `XHIGH`)** | `codex_lane.py review` (`--xhigh` для `XHIGH`) | **OpenAI Codex CLI** (`gpt-6.1-sol`, без изменений) |
| **Внутреннее adversarial-ревью (`HIGH` / `XHIGH`)** | `swarm(action="add", ..., model="claude-opus-5-5-high")` | **`Claude Opus 5.5 (High)`** -> эскалация на **`Gemini 4 Carbon (High)`** (`swarm(action="model", ..., model="gemini-4-carbon-high")` или `adversarial-reviewer*`) при проблеме с Opus |
| Программный fan-out по множеству независимых модулей | `run_workflow` (`parallel` / `pipeline`) | по задаче |
| Параллельная разработка нескольких подсистем | `swarm` (`workspace="share"` или `"branch"`) | `inherit` |

## 3. Жёсткие правила делегирования

1. **Контракт задачи:** каждый вызов обязан указывать точную границу файлов, запрет на редактирование для ревьюеров и точный формат выходных маркеров (`SIMPLIFY_LENS`, `VERDICT`). Активные ограничения `AUTHORITATIVE STATE` и `SUPERSEDED / CANCELLED` автоматически подставляются хуком `safety_guards.py` в `invoke_subagent`, а для `swarm` включаются в `brief`.
2. **Единоличное владение записью:** никогда не назначайте двум пишущим агентам пересекающиеся файлы в одном рабочем дереве; для параллельной записи используйте `workspace="share"` / `"branch"` или `chip_handoff.py open`.
3. **Уборка завершённых swarm-воркеров и видимость в чате:** при старте `swarm` однократно вставьте `open_board` (`[Open the Swarm UI](sidecar://swarm/swarm_board/?auto_open=false)`) в видимый текст чата, перед `swarm_wait` по значимым вехам кратко сообщайте статус пользователю (`AGENTS.md §6` — доска воркеров не видна в основном чате), а после получения отчётов вызывайте `swarm(action="kill", name=...)`: транскрипты и записи в `board.jsonl`/`members.json` сохраняются для `cwg_stop.py`.
