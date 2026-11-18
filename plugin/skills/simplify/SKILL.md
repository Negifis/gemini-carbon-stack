---
name: simplify
description: "Triggered by /simplify or HIGH/XHIGH verification (Swarm 2.0 Fast-Path SIMPLIFY_LENS: ALL or 3 parallel Claude Sonnet 5.5 High lenses via Warm Pool)."
---

# Code Simplification Protocol — Swarm 2.0

Применяется после прохождения базовых тестов и первичного ревью для `HIGH`/`XHIGH`, проектов с `"require_simplify_on_standard": true` в `.agents/carbon-gate.json` или при явном вызове `/simplify`. Для обычных `STANDARD`-задач не обязателен.

## 1. Режимы запуска

- **Mode A (`/simplify`, `STANDARD` с политикой проекта или Swarm 2.0 Fast-Path на `HIGH`/`XHIGH` при `<= 2` файлах и `<= 30` изменённых строках):** 1 объединённый read-only воркер `simplify-reviewer` на **`Claude Sonnet 5.5 (High)`** (`model="claude-sonnet-5-5-high"`, fallback `model="gemini-4-hydrogen-xhigh"` при 0% квоты/сбое Sonnet), покрывающий `REUSE`, `QUALITY`, `EFFICIENCY` за один проход (`SIMPLIFY_LENS: ALL`, `SIMPLIFY_VERDICT: CLEAN|ACTIONABLE_FIXES`, `DIFF_HASH: <current_diff_hash>`).
- **Mode B (`HIGH` и `XHIGH` при `> 2` файлах или `> 30` изменённых строках — строго 3 параллельные линзы):** 3 отдельные read-only линзы на **`Claude Sonnet 5.5 (High)`** через `swarm`:
  1. `simplify-reuse` — дублирование логики, констант и переизобретение утилит (`SIMPLIFY_LENS: REUSE`).
  2. `simplify-quality` — чистота потока управления, мёртвые ветки и гигиена инвариантов (`SIMPLIFY_LENS: QUALITY`).
  3. `simplify-efficiency` — лишний I/O, повторные `stat()`/подпроцессы и аллокации (`SIMPLIFY_LENS: EFFICIENCY`).

## 2. Тёплый пул (`Warm Pool`) и инкрементальные диффы (`swarm_cache.py`)

```powershell
python -X utf8 "<PLUGIN_ROOT>/tools/swarm_cache.py" prepare --session "<conversation-id>" --cwd "<repo_path>" --label simplify
```

- **Раунд 1 (`initial_spawn`):** передайте воркерам `<full_diff_path>`, список затронутых файлов и текущий `DIFF_HASH: <current_diff_hash>`.
- **Раунд 2+ (`Warm Pool` через `@mention` вместо `kill` + `spawn`):** пока воркеры находятся в статусе `waiting`, будите **тех же** воркеров через `post_message("@simplify-reuse @simplify-quality @simplify-efficiency ...")` (или `@simplify-reviewer` для Fast-Path), передавая только `<incremental_diff_path>` и новый `DIFF_HASH: <current_diff_hash>`. Не убивайте и не пересоздавайте `-r2`/`-r3` между раундами (холодная ротация допустима только если воркер завис по `Stall Watchdog` или был убит).
- **Пакетный `kill` один раз перед closure-проверкой:** после получения `SIMPLIFY_VERDICT: CLEAN` по актуальному `DIFF_HASH: <current_diff_hash>` пакетно завершите всех `waiting` simplify-воркеров (`swarm(action="kill", ...)`) один раз перед финальной closure-проверкой (`codex_lane.py review --closure` либо внутренним `CLOSURE_VALIDATION: READY|BLOCKED` при недоступности Codex).
- **При подтверждённом сбое/нулевой квоте `claude-sonnet-5-5-high`** переключайтесь строго на **`Gemini 4 Hydrogen (XHigh)`** (`swarm(action="add", ..., model="gemini-4-hydrogen-xhigh")`), никогда не на `gemini-4-carbon-high` и не на прямой `invoke_subagent` из Carbon-сессии (чтобы не сжигать квоту Carbon). Любая правка файлов после `simplify` инвалидирует все линзы раунда в `cwg_stop.py`: перезапустите тесты и разбудите **все** активные simplify-воркеры в одном `post_message` с новым `DIFF_HASH: <current_diff_hash>`.
- **Порядок Swarm 2.0 (`Logic-First`, см. `development-verification`):** `unittest` -> первичное ревью `VERDICT: APPROVED` -> `simplify` один раз -> пакетный `kill` simplify-воркеров -> финальный `--closure` (`CLOSURE_VALIDATION: READY`, либо внутреннее closure-ревью при недоступности Codex). Никогда не запускайте `simplify` и `adversarial-review` параллельно.
