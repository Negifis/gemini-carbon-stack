# Canonical Checkpoint Template

```markdown
# Canonical Engineering State — <Project>

## GOAL
Однозначная конечная инженерная цель задачи.

## STATUS
IN_PROGRESS | VERIFYING | BLOCKED | COMPLETED

## AUTHORITATIVE STATE
- Действующие требования пользователя.
- Принятые архитектурные контракты и инварианты.

## SUPERSEDED / CANCELLED
- Отменённые требования и опровергнутые гипотезы (строго не возвращать).

## COMPLETED
- Проверенные завершённые этапы с указанием файлов/тестов.

## CURRENT STATE
- Текущая ветка, изменённые файлы, статус последних тестов и ревью.

## DELEGATED / OWNERS
- Активные субагенты или `chip_handoff` задачи и их ожидаемый выход.

## NEXT ACTION
Следующий атомарный проверочный или кодовый шаг.

## ACCEPTANCE
Проверяемые условия готовности.

## BLOCKERS
Нет (или конкретный внешний блокер).

## STOP CONDITION
Проверенный результат + валидная квитанция `[gate]`.
```
