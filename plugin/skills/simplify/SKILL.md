---
name: simplify
description: Triggered by /simplify or HIGH/XHIGH verification (3 parallel Claude Sonnet 5.5 High lenses and swarm_cache.py TTL incremental diffs).
---

# Code Simplification Protocol — Sonnet High

Применяется после прохождения базовых тестов для `HIGH`/`XHIGH`, проектов с `"require_simplify_on_standard": true` в `.agents/carbon-gate.json` или при явном вызове `/simplify`. Для обычных `STANDARD`-задач не обязателен.

## 1. Режимы запуска

- **По запросу `/simplify` или для `STANDARD` с политикой проекта (Mode A):** 1 объединённый read-only воркер `simplify-reviewer` на **`Claude Sonnet 5.5 (High)`** (`model="claude-sonnet-5-5-high"`), покрывающий `REUSE`, `QUALITY`, `EFFICIENCY` (`SIMPLIFY_LENS: ALL`, `SIMPLIFY_VERDICT: CLEAN|ACTIONABLE_FIXES`).
- **`HIGH` и `XHIGH` (Mode B — строго 3 параллельные линзы):** 3 отдельные read-only линзы на **`Claude Sonnet 5.5 (High)`** через `swarm`:
  1. `simplify-reuse` — дублирование логики, констант и переизобретение утилит (`SIMPLIFY_LENS: REUSE`).
  2. `simplify-quality` — чистота потока управления, мёртвые ветки и гигиена инвариантов (`SIMPLIFY_LENS: QUALITY`).
  3. `simplify-efficiency` — лишний I/O, повторные `stat()`/подпроцессы и аллокации (`SIMPLIFY_LENS: EFFICIENCY`).

## 2. Инкрементальные диффы и 5-минутный TTL (`swarm_cache.py`)

```powershell
python -X utf8 "<PLUGIN_ROOT>/tools/swarm_cache.py" prepare --session "<conversation-id>" --cwd "<repo_path>" --label simplify
```

- **Раунд 1 (`initial_spawn`):** передайте воркерам `<full_diff_path>` и список затронутых файлов.
- **Раунд 2+ (`<= 270s` vs `> 270s`):** при `resume_in_place` продолжайте в тех же чатах через `post_message(...)` с `<incremental_diff_path>`; при `rotate_incremental` закройте старых воркеров (`swarm(action="kill", ...)`) и запустите `<name>-r<N>` только с инкрементальным диффом и замечаниями прошлого раунда.
- При подтверждённом сбое/нулевой квоте `claude-sonnet-5-5-high` переключайтесь на `gemini-4-carbon-high` (или субагенты `simplify-*-reviewer`). После правок перезапустите тесты.
