---
name: checkpoint
description: Save or update the Canonical Engineering State checkpoint (`/checkpoint`) so goals, active constraints, cancelled hypotheses, progress, and next actions survive context compaction and restarts.
---

# `/checkpoint` — Сохранение канонического состояния

Зафиксируйте актуальное состояние задачи на основе **реальных фактов на диске** (`git status`, пройденные тесты, открытые чипы):

```powershell
python -X utf8 "<PLUGIN_ROOT>/hooks/continuity.py" checkpoint `
  --cwd "<рабочая директория>" `
  --goal "<цель задачи>" `
  --status "<IN_PROGRESS | VERIFYING | BLOCKED | COMPLETED>" `
  --authoritative "<действующие требования и архитектурные контракты>" `
  --superseded "<отменённые требования и опровергнутые гипотезы>" `
  --completed "<завершённые и проверенные шаги>" `
  --current "<ветка, изменённые файлы, результаты последних проверок>" `
  --delegated "<активные субагенты или чипы>" `
  --next-action "<следующий конкретный шаг>" `
  --acceptance "<критерии готовности>" `
  --blockers "<блокеры или 'нет'>" `
  --stop-condition "<условие завершения>"
```

Если пользователь попросил сохранить видимый чекпоинт прямо в репозитории проекта, добавьте флаг `--mirror-workspace` (запишет копию в `.agents/CHECKPOINT.md`). После записи выведите пользователю краткую сводку сохранённого состояния.
