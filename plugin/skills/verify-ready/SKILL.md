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
   - `HIGH` / `XHIGH` (пайплайн методом бутерброда из `development-verification`): 1) тесты -> 2) первичное ревью `carbon-stack codex-lane review` (`1..3` раунда до `APPROVED` либо эскалации на 3-м раунде) -> 3) `simplify` (`SIMPLIFY_LENS: ALL` при `<= 2` ф. и `<= 30` ст. либо 3 линзы `reuse`, `quality`, `efficiency`; при правках — перезапуск тестов и допроверка через Warm Pool `@mention` с `DIFF_HASH: <current_diff_hash>`) -> 4) пакетный `kill` `waiting` simplify-воркеров -> 5) финальная эскалация `--closure` на текущем SHA-256 (`carbon-stack codex-lane review --closure` -> `CLOSURE_VALIDATION: READY`, максимум 2 прохода с повторным `simplify` между ними; после 2 блокировок `BLOCKED` обязателен режим исследования и `carbon-stack codex-lane research-reset` в новых сессиях).
4. **Чипы и квитанция:** убедитесь через `carbon-stack chip-handoff status`, что дочерние чипы закрыты, и завершите ответ строкой `[gate] ...`.
