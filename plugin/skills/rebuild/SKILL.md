---
name: rebuild
description: Clean-room context recovery and state reconstruction (`/rebuild`) after context compaction, session restart, or repeated user corrections: reconciles canonical checkpoint against actual disk/git state and purges discarded hypotheses.
---

# `/rebuild` — Чистое восстановление контекста и состояния

Выполните эту процедуру при возобновлении прерванной задачи, после тяжёлого сжатия контекста или после серии корректировок пользователя:

1. **Чтение сохранённого канонического состояния и памяти:**
   ```powershell
   python -X utf8 "<PLUGIN_ROOT>/hooks/continuity.py" show --cwd "<путь>"
   python -X utf8 "<PLUGIN_ROOT>/tools/carbon_memory.py" recall --cwd "<путь>"
   python -X utf8 "<PLUGIN_ROOT>/tools/chip_handoff.py" recover
   ```
2. **Сверка с истиной на диске:**
   - Проверьте `git status --short`, `git diff --stat` и последние коммиты (`git log -n 5 --oneline`).
   - Если сохранённый чекпоинт расходится с реальными байтами на диске — приоритет у фактического состояния файлов и последних явных указаний пользователя.
3. **Отсечение отменённых ветвей (`Clean-Room Reset`):**
   - Явно перенесите все отклонённые подходы и старые требования в `SUPERSEDED / CANCELLED` через `continuity.py checkpoint`.
   - Продолжайте работу строго от подтверждённой чистой базы без возврата к отменённым идеям.
