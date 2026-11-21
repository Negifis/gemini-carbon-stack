---
name: verify-ready
description: Triggered by /verify-ready to audit pre-closure readiness (risk level, checks, Sonnet lenses, and review SHA-256 freshness).
---

# `/verify-ready` — Проверка готовности результата перед закрытием

1. **Целостность задачи и чистота дерева:** сверьте результат с исходным бизнес-намерением пользователя (`BUSINESS_INTENT`) и критериями успеха (ни одна запрошенная возможность не вырезана из-за избыточной перестраховки); проверьте `git status --short` и `git diff --stat` (нет временных файлов, секретов и лишних правок).
2. **Решающие проверки и условный Design Gate:** тесты/проверки сборки и типов прошли успешно **после самой последней правки файлов**. Если изменялись визуальные UI/дизайн-файлы (`*.tsx`/`*.css`/`DESIGN.md`/Flutter UI-виджеты), сняты реальные скриншоты в браузере и получен независимый `VISUAL_REVIEW_VERDICT: APPROVED` (плюс `UX_REVIEW_VERDICT: APPROVED` при UX-аудите).
3. **Соответствие уровню риска Code Work Gate:**
   - `LOW`: проверены разметка и ссылки.
   - `STANDARD`: пройдены применимые локальные тесты/проверки (без авто-`swarm`, если политика `.agents/carbon-gate.json` не требует `simplify`).
   - `HIGH` / `XHIGH` (линейный конечный пайплайн `Finite Gate` из `development-verification`, `MAX_TOTAL_GATE_ROUNDS = 7`, `MAX_REDESIGN_RESETS = 1`): 1) тесты -> 2) консультативный проход `simplify` 1 раз ДО ревью (`MAX_SIMPLIFY_PASSES = 1`: `SIMPLIFY_LENS: ALL` при `<= 2` ф. и `<= 30` ст. либо 3 линзы `reuse`, `quality`, `efficiency`; при `ACTIONABLE_FIXES` — правка и перезапуск тестов без повторного `simplify`) -> 3) пакетный `kill` `waiting` simplify-воркеров -> 4) независимое прагматичное ревью `carbon-stack codex-lane review --intent "..."` (`1..4` раунда в одной сессии, `MAX_REVIEW_ROUNDS = 4`, `BLOCKING_THRESHOLD = HIGH`, только дефекты Класса A с `PRESERVES_INTENT: YES`; отклонённые замечания Класса C/D зафиксированы в `codex-lane dispose`; **`VERDICT: APPROVED` на любом раунде `1..4` сразу закрывает гейт** без повторного `simplify` и без `--closure`; только при `Round 4: ESCALATE` — однократный проход исследования: `REMEDIATE` в той же сессии до 2 попыток `--closure` -> `CLOSURE_VALIDATION: READY` / терминальный `[gate] draft-blocked`, либо при архитектурном `REDESIGN` — 1 конечный `carbon-stack codex-lane redesign-reset` с обнулением раундов и чистой сессией ревьюера).
4. **Чипы и квитанция:** убедитесь через `carbon-stack chip-handoff status`, что дочерние чипы закрыты, и завершите ответ строкой `[gate] ...`.
