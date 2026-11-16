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
   - `HIGH` / `XHIGH`: строго последовательно пройдены: 1) тесты -> 2) 3 отдельные simplify-линзы (`claude-sonnet-5-5-high`, при сбое/0% квоты Sonnet — `gemini-4-hydrogen-xhigh` через `swarm`; завершены ДО старта ревью) -> 3) свежий `VERDICT: APPROVED` с приоритетом `codex_lane.py review` (и только при недоступности Codex — эскалация на `claude-opus-5-5-high` -> `gemini-4-carbon-high` при сбое Opus) на текущем SHA-256 файлов; завершённые воркеры остановлены (`kill`).
4. **Чипы и квитанция:** убедитесь через `chip_handoff.py status`, что дочерние чипы закрыты, и завершите ответ строкой `[gate] ...`.
