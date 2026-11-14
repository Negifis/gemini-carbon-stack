---
name: canonical-state
description: Canonical task state management, compaction resilience, requirement replacement, and post-correction output hygiene for long-running multi-step engineering tasks.
---

# Canonical State & Compaction Resilience

Этот навык объединяет управление каноническим состоянием задачи, защиту от потери контекста при сжатии (`compaction`) и чистоту финального ответа после корректировок пользователя.

## 1. Каноническая структура состояния

Хранится автоматически по ключу проекта в `~/.gemini/carbon-stack/state/continuity/checkpoints/<project-key>.md` (и при `--mirror-workspace` в `.agents/CHECKPOINT.md`). Обновляется командой `/checkpoint` или напрямую:

```powershell
python -X utf8 "<PLUGIN_ROOT>/hooks/continuity.py" checkpoint `
  --cwd "<путь>" `
  --goal "<актуальная цель>" `
  --status "IN_PROGRESS" `
  --authoritative "<действующие требования и архитектурные решения>" `
  --superseded "<отменённые требования и опровергнутые гипотезы — НЕ ВОЗВРАЩАТЬ>" `
  --completed "<что уже реализовано и проверено>" `
  --current "<текущее состояние файлов, ошибок и тестов>" `
  --delegated "<субагенты / чипы и их зоны ответственности>" `
  --next-action "<следующий конкретный шаг>" `
  --acceptance "<критерии приёмки>" `
  --blockers "<блокеры или 'нет'>" `
  --stop-condition "<условие полного завершения>"
```

## 2. Поведение при сжатии контекста и перезапуске

- При `SessionStart` и при обнаружении сжатия контекста в `PreInvocation` хук `continuity.py` автоматически инжектирует сохранённый блок состояния.
- Раздел **`AUTHORITATIVE STATE`** имеет приоритет над старыми воспоминаниями истории диалога.
- Раздел **`SUPERSEDED / CANCELLED`** содержит явно отменённые пользователем требования и опровергнутые гипотезы — их запрещено возвращать в код или план после сжатия контекста.
- Перед продолжением правок после перезапуска всегда сверяйте `CURRENT STATE` с фактическим `git status --short` и `git diff`.

## 3. Замена требований и чистота ответа (Output Lint)

- Когда пользователь отменяет или меняет требование («нет, переделай», «вместо этого...»), старое требование переносится в `SUPERSEDED / CANCELLED`.
- При двух сильных корректировках подряд выполните процедуру `/rebuild` (чистая пересборка состояния от файлов на диске).
- В финальном ответе описывайте **только итоговое действующее решение** без пересказа отвергнутых черновиков («в предыдущей попытке я написал X, но потом исправил на Y»), иначе `continuity.py` на `Stop` попросит переписать ответ начисто.

См. шаблоны в `references/checkpoint-template.md` и `references/subagent-packet.md`.
