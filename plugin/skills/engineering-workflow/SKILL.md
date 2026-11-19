---
name: engineering-workflow
description: Playbook for large multi-module refactors or dirty-worktree conflict resolution. Do NOT load for routine edits or bounded follow-ups.
---

# Engineering Workflow (для крупных многомодульных задач)

1. **Ориентация:** проверьте `git status --short`, активные чипы (`carbon-stack chip-handoff status`), при необходимости вспомните факты через `carbon-stack carbon-memory recall --query "<тема>"`. Ищите определения через `carbon-stack code-search` и читайте целевые диапазоны строк (`StartLine`/`EndLine`).
2. **Границы и изоляция:** зафиксируйте затронутые контракты и инварианты. Выделяйте отдельный git worktree (`carbon-stack chip-handoff open`) только для параллельной кодовой работы или грязного дерева, мешающего основной ветке.
3. **Реализация и верификация:** один исполнитель владеет файлом; устраняйте первопричину; запускайте релевантные проверки после последней правки; для `HIGH`/`XHIGH` выполняйте 3 линзы `simplify` и `/adversarial-review` перед квитанцией `[gate]`.
