---
name: verify-ready
description: Triggered by /verify-ready to audit pre-closure readiness (risk level, checks, Sonnet lenses, and review SHA-256 freshness).
---

# `/verify-ready` — Проверка готовности результата перед закрытием

1. **Чистота дерева:** проверьте `git status --short` и `git diff --stat` (нет временных файлов, секретов и лишних правок).
2. **Решающие проверки:** тесты/проверки сборки и типов прошли успешно **после самой последней правки файлов**.
3. **Соответствие уровню риска Code Work Gate:**
   - `LOW`: проверены разметка и ссылки.
   - `STANDARD`: пройдены применимые локальные тесты/проверки (без авто-`swarm`, если политика `.agents/carbon-gate.json` не требует `simplify`).
   - `HIGH` / `XHIGH` (канонический 5-шаговый пайплайн Swarm 2.0 `Logic-First` из `development-verification`): 1) тесты -> 2) первичное ревью `VERDICT: APPROVED` -> 3) `simplify` один раз (`SIMPLIFY_LENS: ALL` при `<= 2` ф. и `<= 30` ст. либо 3 линзы `reuse`, `quality`, `efficiency`; при правках — перезапуск тестов и допроверка всех активных линз через Warm Pool `@mention` с `DIFF_HASH: <current_diff_hash>`) -> 4) пакетный `kill` `waiting` simplify-воркеров -> 5) финальная closure-проверка на текущем SHA-256 (`codex_lane.py review --closure` `CLOSURE_VALIDATION: READY` либо внутренний `CLOSURE_VALIDATION: READY|BLOCKED` при недоступности Codex с последующим `kill` `internal-reviewer`).
4. **Чипы и квитанция:** убедитесь через `chip_handoff.py status`, что дочерние чипы закрыты, и завершите ответ строкой `[gate] ...`.
