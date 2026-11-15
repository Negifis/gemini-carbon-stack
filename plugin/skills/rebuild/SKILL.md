---
name: rebuild
description: Triggered by /rebuild to reconcile stale handoff state with live git status/diff after interrupted sessions.
---

# `/rebuild` — Чистое восстановление состояния

Выполните при возобновлении прерванной задачи, после сжатия контекста или серии корректировок пользователя:

1. **Прочитайте минимальный repo-backed handoff и состояние чипов:**
   ```powershell
   python -X utf8 "<PLUGIN_ROOT>/hooks/continuity.py" handoff --cwd "<путь>" --show
   python -X utf8 "<PLUGIN_ROOT>/tools/chip_handoff.py" recover
   ```
2. **Сверьте с живым состоянием репозитория:** `git status --short`, `git diff --stat`, `git log -n 5 --oneline`. При расхождениях приоритет всегда у фактических байтов на диске и последних указаний пользователя.
3. **Зафиксируйте обновлённые решения и отменённые ветви:** обновите `handoff` (`--decision`/`--decisions`, `--superseded`, `--remaining`/`--next`) через `continuity.py handoff` и продолжайте от чистой базы.
