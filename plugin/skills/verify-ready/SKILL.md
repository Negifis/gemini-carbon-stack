---
name: verify-ready
description: Pre-closure readiness check (`/verify-ready`): audits current candidate risk floor, executed runtime checks, 3 Sonnet High simplify lenses, Codex / Opus High -> Carbon High review freshness against SHA-256 fingerprints, and dirty/chip state.
---

# `/verify-ready` — Проверка готовности результата перед закрытием

Выполните перед формированием финального ответа по сложной задаче:

1. **Проверьте чистоту и полноту изменений:**
   - `git status --short` и `git diff --stat` — нет ли забытых временных файлов, отладочных принтов, секретов или задетых пользовательских файлов.
2. **Проверьте актуальность тестов:**
   - Все решающие тесты и проверки типов были запущены и прошли успешно **после самой последней правки файлов**.
3. **Проверьте выполнение требований Code Work Gate по уровню риска:**
   - `LOW`: проверена разметка и ссылки.
   - `STANDARD` (не малая правка `> 3` строк): пройден 1 объединённый `simplify-reviewer` (или 3 линзы) на `claude-sonnet-5-5-high`.
   - `HIGH` / `XHIGH`: пройдены строго 3 отдельные simplify-линзы (`claude-sonnet-5-5-high`) + получен свежий `VERDICT: APPROVED` от `codex_lane.py` либо от внутреннего `claude-opus-5-5-high` (или эскалированного `gemini-4-carbon-high` при подтверждённом сбое Opus) на текущем SHA-256 содержимого файлов, а завершённые `swarm`-воркеры остановлены через `kill`.
4. **Проверьте незакрытые делегированные задачи:**
   - `chip_handoff.py status` — все дочерние чипы приняты (`accepted`) или явно задокументированы.
5. Сформируйте лаконичный финальный ответ с корректной последней строкой `[gate] ...`.
