---
name: canonical-state
description: Schema reference for multi-session handoff files and requirement-replacement recovery. Do NOT load on single-session tasks.
---

# Canonical State & Minimal Handoff

Механизм компактной передачи состояния между компакциями и сессиями без записи состояния после каждого вызова инструмента.

## 1. Минимальный repo-backed handoff (`handoff.json` + живой `git`)

Команда `/checkpoint` или `carbon-stack continuity handoff` сохраняет компактные метаданные (цель, статус, принятые решения, отменённые требования, следующие шаги) в `state/continuity/handoffs/<pkey>.json`.

При восстановлении (`SessionStart --source resume` или обнаружение `SYSTEM / CHECKPOINT` компакции в `PreInvocation`) `carbon-stack continuity` собирает минимальный дайджест прямо из живого репозитория:
- ветка, ограниченный `git status --short` и `git diff --stat`;
- открытый кандидат гейта (`task_class`, `risk`, затронутые файлы);
- записанные решения, `SUPERSEDED` и `NEXT ACTION` (строго без исходников и длинных логов).

## 2. Замена требований и чистота ответа (Output Lint)

- При явной отмене требования пользователем («отмена», «вместо этого...») перенесите отклонённый вариант в `superseded` и не возвращайте его после сжатия контекста.
- В финальном ответе описывайте итоговое решение без пересказа отвергнутых черновиков (при необходимости сравнения добавьте `[lint] intentional: <причина>`).

См. шаблоны в `references/checkpoint-template.md` и `references/subagent-packet.md`.
