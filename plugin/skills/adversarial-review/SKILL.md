---
name: adversarial-review
description: Run independent read-only adversarial code review (`/adversarial-review`) using the external OpenAI Codex lane when healthy, with deterministic circuit-breaker fallback to the native `adversarial-reviewer` subagent.
---

# `/adversarial-review` — Независимое критическое ревью кода

Один независимый review-движок на раунд, максимум 3 обычных раунда, строгая проверка происхождения вердикта.

## Шаг 1. Проверка доступности внешнего движка Codex

```powershell
python -X utf8 "<PLUGIN_ROOT>/hooks/codex_lane.py" check
```

## Шаг 2А. Если `available: true` — запуск изолированного Codex-ревью

Для `HIGH`:
```powershell
python -X utf8 "<PLUGIN_ROOT>/hooks/codex_lane.py" review `
  --cwd "<путь к репозиторию>" `
  --summary "<цель изменений, затронутые контракты и выполненные тесты>"
```
Для `XHIGH` добавьте флаг `--xhigh` (при post-ESCALATE валидации закрытия — `--closure`).
`codex_lane.py` автоматически закрывает `stdin`, отключает лишние MCP-серверы, фиксирует криптографический `REVIEW_ID` и сохраняет rollout-лог в `~/.codex/sessions/` для проверки хуком `cwg_stop.py`.

## Шаг 2Б. Если `available: false` (или `codex_lane.py review` вернул код `2`/`3` и открыл circuit breaker)

Не повторяйте упавший внешний вызов в цикле. Переключитесь на нативный независимый read-only субагент:
- Для `HIGH`: `invoke_subagent(TypeName="adversarial-reviewer", Role="Independent Adversarial Review", Prompt="...")`
- Для `XHIGH`: `invoke_subagent(TypeName="adversarial-reviewer-xhigh", Model="pro", Role="XHIGH Adversarial Review", Prompt="...")`

**Честность атрибуции:** никогда не выдавайте вердикт нативного субагента или собственный анализ Carbon за внешний отчёт Codex.

## Шаг 3. Обработка вердикта

- `VERDICT: APPROVED` -> ревью завершено. Не запускайте лишних раундов; не редактируйте файлы кандидата без повторного ревью.
- `VERDICT: REVISE` -> устраните реальные подтверждённые дефекты, перезапустите тесты и выполните следующий раунд.
- `VERDICT: ESCALATE` (на 3-м раунде) -> выполните до 2 проходов `CLOSURE_VALIDATION` (`READY` -> `[gate] pr-ready`, `BLOCKED` -> `[gate] draft-blocked`).
