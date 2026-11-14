# Subagent Delegation Packet Template

При вызове `invoke_subagent` формируйте компактный самодостаточный пакет:

```markdown
## Task Boundary
<Точная задача и список файлов/директорий в зоне анализа или работы>

## Context & Verified Facts
- <Подтверждённые факты с путями file:line>
- <Что уже исключено, чтобы субагент не дублировал поиск>

## Active Constraints
- <Действующие требования из AUTHORITATIVE STATE>
- <Отменённые подходы из SUPERSEDED / CANCELLED>

## Expected Deliverable & Completion Condition
<Точный формат ответа и условие завершения без лишних шагов>
```
