---
name: rebuild
description: "Reconcile stale handoff state with live git status/diff after interrupted sessions."
---

# `/rebuild` — Чистое восстановление состояния

Выполните при возобновлении прерванной задачи, после сжатия контекста или серии корректировок пользователя:

1. **Прочитайте минимальный repo-backed handoff и состояние чипов:**
   ```powershell
   & "<PLUGIN_ROOT>/bin/carbon-stack.exe" continuity handoff --cwd "<путь>" --show
   & "<PLUGIN_ROOT>/bin/carbon-stack.exe" chip-handoff recover
   ```
2. **Сверьте с живым состоянием репозитория:** `git status --short`, `git diff --stat`, `git log -n 5 --oneline`. При расхождениях приоритет всегда у фактических байтов на диске и последних указаний пользователя.
3. **Зафиксируйте обновлённые решения и отменённые ветви:** обновите `handoff` (`--decision`/`--decisions`, `--superseded`, `--remaining`/`--next`) через `carbon-stack continuity handoff` и продолжайте от чистой базы.
