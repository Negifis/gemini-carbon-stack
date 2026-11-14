---
name: stack-doctor
description: Run comprehensive diagnostics (`/stack-doctor`) on the Gemini Carbon Engineering Stack: validates plugin installation, live Antigravity Language Server ingestion, hooks, Codex lane, local FTS5 memory, active chips, and gate inbox.
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
