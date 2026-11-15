---
name: chip-handoff
description: Parallel git-worktree child-task workflow (chip_handoff.py). Load ONLY when splitting concurrent coding tasks across worktrees.
---

# Chip Handoff & Multi-Session Orchestration

Подсистема гарантирует, что независимая задача (выполняемая в отдельной сессии `agy` CLI, отдельном окне Antigravity или изолированном субагенте) **не потеряется**, не повредит рабочее дерево родителя и пройдёт приёмку родителем.

## 1. Жизненный цикл чипа

1. **Регистрация и выделение изолированного worktree (`open`):**
   ```powershell
   python -X utf8 "<PLUGIN_ROOT>/tools/chip_handoff.py" open `
     --title "<краткое название>" `
     --expected "<ожидаемый результат и тесты>" `
     --session "<parent-conversation-id>" `
     --cwd "<путь к репозиторию>"
   ```
   Команда создаёт уникальный `chip_id`, ветку `chip/<slug>-<id>`, изолированный git worktree и возвращает готовый `handoff_brief` для передачи исполнителю (субагенту или CLI-сессии `agy -p`).

2. **Завершение работы исполнителем (`finish`):**
   После коммита проверенных изменений в ветке чипа исполнитель вызывает:
   ```powershell
   python -X utf8 "<PLUGIN_ROOT>/tools/chip_handoff.py" finish `
     --chip "<chip_id>" `
     --message "<сводка изменений и результаты тестов>"
   ```
   Чип переходит в `handed-off`, создаётся резервный `.bundle`, а родительская сессия автоматически получает уведомление на следующем `PreInvocation`.

3. **Проверка и закрытие родителем (`close`):**
   Родитель проверяет коммиты/дифф (`git log`/`git diff` по `chip_branch`) и принимает решение:
   ```powershell
   # Принять (опционально слить в текущую ветку через --merge и безопасно удалить worktree)
   python -X utf8 "<PLUGIN_ROOT>/tools/chip_handoff.py" close --chip "<chip_id>" --accept --merge

   # Вернуть на доработку
   python -X utf8 "<PLUGIN_ROOT>/tools/chip_handoff.py" close --chip "<chip_id>" --rework "<что исправить>"
   ```

4. **Восстановление зависших задач (`recover`):**
   ```powershell
   python -X utf8 "<PLUGIN_ROOT>/tools/chip_handoff.py" recover
   ```
   Показывает все незакрытые чипы, число коммитов сверх базы, незакоммиченные файлы и путь к `.bundle`.
