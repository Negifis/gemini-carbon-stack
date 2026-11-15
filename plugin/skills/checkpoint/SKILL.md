---
name: checkpoint
description: Triggered by /checkpoint to save repo-backed handoff state (goal, decisions, remaining steps) via continuity.py.
---

# `/checkpoint` — Сохранение минимального handoff-состояния

Фиксируйте состояние на диске только в ключевых точках (пауза, передача между сессиями, сложный этап), не копируя исходники и длинные логи:

## Компактный repo-backed handoff (рекомендуется)

```powershell
python -X utf8 "<PLUGIN_ROOT>/hooks/continuity.py" handoff `
  --cwd "<рабочая директория>" `
  --status "<IN_PROGRESS | VERIFYING | BLOCKED | COMPLETED>" `
  --goal "<цель задачи>" `
  --decisions "<принятые решения и инварианты>" `
  --superseded "<отменённые гипотезы — не возвращать>" `
  --next "<следующий конкретный шаг>"
```

## Полный канонический чекпоинт (при необходимости длинного многоэтапного трекинга)

```powershell
python -X utf8 "<PLUGIN_ROOT>/hooks/continuity.py" checkpoint `
  --cwd "<рабочая директория>" `
  --goal "<цель>" --status "<IN_PROGRESS | BLOCKED | COMPLETED>" `
  --authoritative "<действующие требования>" --superseded "<отменённое>" `
  --completed "<проверенные шаги>" --next-action "<следующий шаг>"
```

Добавьте `--mirror-workspace`, чтобы сохранить `.agents/CHECKPOINT.md` в репозитории.
