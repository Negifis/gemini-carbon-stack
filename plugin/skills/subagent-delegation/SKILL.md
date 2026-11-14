---
name: subagent-delegation
description: Native subagent, workflow, and swarm routing for Gemini 4 Carbon in Antigravity: when to execute directly vs delegate, model selection, scope ownership, and failure containment.
---

# Subagent Delegation & Model Routing (Gemini Carbon)

## 1. Когда НЕ нужно делегировать

Gemini 4 Carbon (High) обладает глубоким рассуждением и большим окном контекста. **Выполняйте работу напрямую без субагентов**, если:
- нужно прочитать 1–6 известных файлов или найти символ через `code_search.py`;
- правка локализована в одном модуле;
- требуется последовательная отладка, где каждый следующий шаг зависит от предыдущего.

## 2. Матрица нативных агентов и инструментов оркестрации Antigravity

| Задача | Инструмент / Агент | Модель / Режим |
|---|---|---|
| Широкая разведка незнакомой подсистемы (>10 файлов) | `invoke_subagent(TypeName="code-explorer")` или встроенный `research` | `inherit` (Carbon) |
| Живая проверка веб-интерфейса и DOM/визуальных состояний | `invoke_subagent(TypeName="browser")` | `flash` (по умолчанию для `browser`) |
| Генерация растровых иллюстраций / иконок | `invoke_subagent(TypeName="image-generator")` | по умолчанию |
| Перевод объёмной документации без засорения контекста | `invoke_subagent(TypeName="translator")` | `flash` или `inherit` |
| Единый simplify-проход (Reuse + Quality + Efficiency) | `invoke_subagent(TypeName="simplify-reviewer")` | `inherit` |
| Независимое ревью `HIGH` (основной внешний движок) | `codex_lane.py review` (межсемейная проверка OpenAI Codex) | `high` |
| Независимое ревью `HIGH` (нативный fallback при outage Codex) | `invoke_subagent(TypeName="adversarial-reviewer")` | `inherit` или `pro` |
| Усиленное ревью `XHIGH` | `codex_lane.py review --xhigh` или `adversarial-reviewer-xhigh` | `xhigh` / `Model="pro"` (Hydrogen XHigh) |
| Программный fan-out по множеству независимых модулей | `run_workflow` (Python-скрипт с `parallel` / `pipeline`) | по задаче |
| Командная параллельная разработка нескольких подсистем | `swarm` (`workspace="share"` или `"branch"`) | `inherit` |

## 3. Жёсткие правила делегирования

1. **Контракт задачи:** каждый вызов субагента обязан указывать (а) точную границу файлов/модулей, (б) ожидаемый формат ответа, (в) критерий завершения. Активные ограничения `AUTHORITATIVE STATE` и `SUPERSEDED / CANCELLED` автоматически подставляются хуком `safety_guards.py`.
2. **Единоличное владение записью:** никогда не назначайте двум пишущим агентам пересекающиеся файлы в одном рабочем дереве; для параллельной записи используйте `Workspace="share"` / `"branch"` или `chip_handoff.py open`.
3. **Независимость ревью:** ревьюер (`adversarial-reviewer*`, `simplify-reviewer`, `codex_lane`) никогда не редактирует код.
4. **Обработка сбоев без циклов:** после вызова `invoke_subagent` не опрашивайте статус в цикле — дождитесь реактивного уведомления системы. При сбое субагента максимум 1 повтор с исправленным входом либо переход на документированный fallback.
