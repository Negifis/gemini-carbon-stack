---
name: verify-ready
description: Pre-closure readiness check (`/verify-ready`): audits current candidate risk floor, executed runtime checks, simplify pass, review freshness against file SHA-256 fingerprints, and dirty/chip state before concluding.
---

# `/verify-ready` — Проверка готовности результата перед закрытием

Выполните перед формированием финального ответа по сложной задаче:

1. **Проверьте чистоту и полноту изменений:**
   - `git status --short` и `git diff --stat` — нет ли забытых временных файлов, отладочных принтов, секретов или случайно задетых пользовательских файлов.
2. **Проверьте актуальность тестов:**
   - Все решающие тесты и проверки типов были запущены и прошли успешно **после самой последней правки файлов**.
3. **Проверьте выполнение требований Code Work Gate по уровню риска:**
   - `LOW`: проверена разметка и ссылки.
   - `STANDARD` (не малая правка): пройден `simplify-reviewer`.
   - `HIGH` / `XHIGH`: пройден `simplify-reviewer` + получен свежий `VERDICT: APPROVED` от `codex_lane.py` или `adversarial-reviewer(-xhigh)` на текущем SHA-256 содержимого файлов.
4. **Проверьте незакрытые делегированные задачи:**
   - `chip_handoff.py status` — все дочерние чипы приняты (`accepted`) или явно задокументированы.
5. Сформируйте лаконичный финальный ответ с корректной последней строкой `[gate] ...`.
