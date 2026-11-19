---
name: stack-doctor
description: Triggered by /stack-doctor to run health diagnostics on gemini-carbon-stack installation, hooks, Codex lane, and Language Server.
---

# `/stack-doctor` — Диагностика инженерного стека

Запустите комплексную самодиагностику стека:

```powershell
& "<PLUGIN_ROOT>/bin/carbon-stack.exe" stack-doctor --cwd "<рабочая директория>"
```

При необходимости дополнительно проверьте:
- Статус установщика и резервных копий: `& "<REPO_ROOT>/plugin/bin/carbon-stack.exe" install --diagnose`
- Очередь аномалий гейта: `& "<PLUGIN_ROOT>/bin/carbon-stack.exe" gate-inbox list`
- Здоровье внешнего ревью-движка Codex: `& "<PLUGIN_ROOT>/bin/carbon-stack.exe" codex-lane check`

Сообщите пользователю статус каждого контура (Plugin & LS Ingestion, Hooks, Codex Lane, Local FTS5 Memory, Active Chips, Gate Inbox) и конкретную команду исправления, если какой-либо контур деградировал.
