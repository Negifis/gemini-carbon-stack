---
trigger: model_decision
description: "Load ONLY when delegating to swarm workers, Hydrogen browser/translator subagents, or parallel git worktree chips."
---

# Multi-Agent & Hydrogen Routing Rules

1. **Запрет `Gemini Flash`:** никогда не передавайте `Model="flash"`, `flash_lite` или `gemini-3.8-flash-*`. Для вспомогательных ролей (`browser`, `translator`, разведка) используйте **`Gemini 4 Hydrogen`** (`gemini-4-hydrogen-low` для smoke/короткого перевода, `-medium` для UI QA/доков, `-high` для сложных SPA, `-xhigh` для гонок состояния).
2. **Делегирование `browser` с не-Hydrogen координатора:** запустите через `swarm` воркера с `model="gemini-4-hydrogen-<level>"`, который вызовет `invoke_subagent(TypeName="browser", Model="inherit")`; проверяйте результат строго по `BROWSER_HOST_FACTS`.
3. **Одно владение файлом:** при параллельной разработке выдавайте каждому пишущему воркеру `workspace: "share"` / `"branch"` или изолированный worktree через `chip_handoff.py open`. Интеграция изменений в рабочее дерево принадлежит только координатору.
