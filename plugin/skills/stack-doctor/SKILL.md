---
name: stack-doctor
description: Triggered by /stack-doctor to run health diagnostics on gemini-carbon-stack installation, hooks, Codex lane, and Language Server.
---

# `/stack-doctor` — Диагностика инженерного стека

Запустите комплексную самодиагностику стека:

```powershell
python -X utf8 "<PLUGIN_ROOT>/tools/stack_doctor.py" --cwd "<рабочая директория>"
```

При необходимости дополнительно проверьте:
- Статус установщика и резервных копий: `python -X utf8 "<REPO_ROOT>/install.py" --diagnose`
- Очередь аномалий гейта: `python -X utf8 "<PLUGIN_ROOT>/hooks/gate_inbox.py" list`
- Здоровье внешнего ревью-движка Codex: `python -X utf8 "<PLUGIN_ROOT>/hooks/codex_lane.py" check`

Сообщите пользователю статус каждого контура (Plugin & LS Ingestion, Hooks, Codex Lane, Local FTS5 Memory, Active Chips, Gate Inbox) и конкретную команду исправления, если какой-либо контур деградировал.
