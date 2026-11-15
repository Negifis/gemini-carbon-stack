---
name: task-start
description: Triggered by /task-start to audit tree locks, recall project memory, and initialize handoff before a multi-session feature.
---

# `/task-start` — Запуск работы над инженерной задачей

При вызове `/task-start` (или начале крупной задачи/issue) выполните компактный старт:

1. **Проверка рабочего дерева и веток:**
   - Запустите `git status --short --branch` и `worktree_guard.py audit`.
   - Если в дереве есть чужие/пользовательские незакоммиченные изменения, решите: работать аккуратно в непересекающихся файлах или выделить изолированный worktree через `chip_handoff.py open`.
2. **Извлечение знаний проекта:**
   - Выполните `carbon_memory.py recall --query "<ключевые слова задачи>" --cwd "<путь>"`.
3. **Быстрая разведка точек входа:**
   - Найдите целевые модули и существующие тесты через `code_search.py symbols` / `code_search.py grep`.
4. **Фиксация стартового канонического состояния (для многошаговых задач):**
   - Запишите `GOAL`, `AUTHORITATIVE STATE`, `ACCEPTANCE` и `NEXT ACTION` через `continuity.py checkpoint`.
5. Немедленно переходите к выполнению первого шага (не останавливаясь на пустом отчёте о старте, если требования ясны).
