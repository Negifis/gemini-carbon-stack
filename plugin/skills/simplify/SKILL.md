---
name: simplify
description: Post-implementation code simplification protocol for Gemini Carbon: eliminates duplication, accidental complexity, dead branches, and hot-path inefficiencies before independent review or closure.
---

# Code Simplification Protocol

Выполняйте упрощение после того, как функциональность реализована и базовые тесты проходят, но **до** запуска независимого adversarial-ревью (`HIGH`/`XHIGH`), чтобы ревьюер проверял уже чистый финальный код.

## 1. Пропорциональный выбор режима

- **Малая правка (`<= 3` строк в 1 файле, `STANDARD`) или `LOW`:** проверьте дифф самостоятельно без вызова субагента.
- **Обычный `STANDARD`, `HIGH` и `XHIGH`:** вызовите единый read-only субагент `simplify-reviewer` через `invoke_subagent(TypeName="simplify-reviewer", Role="Candidate Diff Simplification", Prompt="...")`, передав ему путь к репозиторию и краткую цель изменений. (Если текущая сессия была открыта до установки плагина, допустим эквивалентный read-only вызов `invoke_subagent(TypeName="research", Role="Simplify Reviewer", Prompt="...")`.)
  - В отличие от старых многоагентных схем из 3 отдельных ревьюеров, `simplify-reviewer` проверяет все три линзы (`REUSE`, `QUALITY`, `EFFICIENCY`) за один проход по диффу без тройного расхода токенов на чтение одних и тех же файлов.

## 2. Правила применения правок

- Применяйте только те замечания `simplify-reviewer`, которые реально сокращают дублирование, убирают мёртвый код, упрощают ветвление или устраняют лишние аллокации/подпроцессы **без изменения внешних контрактов**.
- После внесения правок обязательно перезапустите тесты, чтобы подтвердить сохранение поведения.
- Не запускайте `simplify-reviewer` повторно по кругу: один качественный проход закрывает требование гейта для текущего кандидата.
