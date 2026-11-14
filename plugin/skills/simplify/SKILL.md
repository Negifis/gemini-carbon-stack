---
name: simplify
description: Post-implementation code simplification protocol pinned to Claude Sonnet 5.5 High (`claude-sonnet-5-5-high`) via native Antigravity swarm: 1 combined lane on non-small STANDARD, strictly 3 parallel lenses (Reuse, Quality, Efficiency) on HIGH/XHIGH, with TTL-aware incremental diff rotation and Gemini Carbon High fallback.
---

# Code Simplification Protocol — Sonnet High (по уровню риска + TTL)

Выполняйте упрощение после того, как функциональность реализована и базовые тесты проходят, но **до** запуска независимого adversarial-ревью (`HIGH`/`XHIGH`), чтобы ревьюер проверял уже чистый финальный код.

## 1. Пропорциональный выбор режима

- **Малая правка (`<= 3` строк в 1 файле, `STANDARD`) или `LOW`:** проверьте дифф самостоятельно без запуска воркеров.
- **Обычный `STANDARD > 3` строк (Mode A — 1 объединённый воркер):** запустите **1 read-only воркера** `simplify-reviewer` на **`Claude Sonnet 5.5 (High)`** (`model="claude-sonnet-5-5-high"`), покрывающего `REUSE`, `QUALITY` и `EFFICIENCY` в одном структурированном отчёте (`SIMPLIFY_LENS: ALL`, `SIMPLIFY_VERDICT: CLEAN|ACTIONABLE_FIXES`). Запуск всех 3 отдельных линз также допускается, но на `STANDARD` не обязателен.
- **`HIGH` и `XHIGH` (Mode B — строго 3 параллельные линзы, без схлопывания):** запустите **3 отдельные независимые read-only линзы** на **`Claude Sonnet 5.5 (High)`** через нативный `swarm` (`cwg_stop.py` отклонит 1 объединённый воркер на `HIGH`/`XHIGH`):
  1. `simplify-reuse` — дублирование логики, констант, валидации и переизобретение утилит (`SIMPLIFY_LENS: REUSE`).
  2. `simplify-quality` — чистота потока управления, мёртвые импорты/ветки, именование, гигиена комментариев (`SIMPLIFY_LENS: QUALITY`).
  3. `simplify-efficiency` — лишние обходы ФС, повторные `stat()`/подпроцессы, алгоритмическая сложность и память (`SIMPLIFY_LENS: EFFICIENCY`).

## 2. Запуск и учёт 5-минутного TTL кэша (`swarm_cache.py`)

Перед запуском или новым раундом подготовьте раундовый дифф и проверьте TTL активных воркеров:
```powershell
python -X utf8 "<PLUGIN_ROOT>/tools/swarm_cache.py" prepare --session "<conversation-id>" --cwd "<repo_path>" --label simplify
```

- **Раунд 1 (`initial_spawn`):** проверьте `swarm(action="models", all=True)`, задайте `swarm(action="title", title="simplify")` и запустите:
  - для `STANDARD > 3` строк: `swarm(action="add", name="simplify-reviewer", model="claude-sonnet-5-5-high", workspace="inherit", brief="Strictly read-only combined simplify review of <repo_path> (diff: <full_diff_path>, files: <changed_files>). Cover REUSE, QUALITY, and EFFICIENCY concisely. Note: shell is Windows PowerShell 5.1 (never use bash heredoc <<, &&, sed, pyflakes, or python slice [a:b]). End post with SIMPLIFY_LENS: ALL and SIMPLIFY_VERDICT: CLEAN|ACTIONABLE_FIXES.")`
  - для `HIGH`/`XHIGH`: добавьте 3 отдельные линзы (`name="simplify"`, `tasks=[REUSE, QUALITY, EFFICIENCY]` или `simplify-reuse`, `simplify-quality`, `simplify-efficiency` с `model="claude-sonnet-5-5-high"` и той же ссылкой на `<full_diff_path>`).
- **Раунд 2+ (`WARM` vs `EXPIRED`, порог `<= 270s`):**
  - Если `overall_action == "resume_in_place"` (возраст кэша `<= 270s`): отправьте запрос на проверку дельты (`<incremental_diff_path>`) **в те же чаты** через `post_message(...)`.
  - Если `overall_action == "rotate_incremental"` (5-минутный TTL истёк, `> 270s`): **не будите остывший раздутый чат** — закройте устаревших воркеров `swarm(action="kill", name=...)` и создайте `<name>-r<N>` с кратким списком замечаний прошлого раунда и путём к компактному инкрементальному диффу (`<incremental_diff_path>`).
- Глубина шагов и инструментального исследования воркеров не урезается. Освобождайте завершённых воркеров через `swarm(action="kill", ...)` только после получения финальных `CLEAN`.

## 3. Эскалация при недоступности Sonnet High

Если `swarm(action="models", all=True)` показывает квоту `0%` у `claude-sonnet-5-5-high` либо воркер вернул ошибку модели/квоты:
- переключите воркер на `gemini-4-carbon-high` через `swarm(action="model", name="...", model="gemini-4-carbon-high")` либо вызовите резервный субагент (`simplify-reviewer` для `STANDARD`; `simplify-reuse-reviewer`, `simplify-quality-reviewer`, `simplify-efficiency-reviewer` для `HIGH`/`XHIGH`).
- Хук `cwg_stop.py` проверяет `members.json` и системные транскрипты и принимает fallback-модель только при подтверждённом сбое/исчерпании квоты `claude-sonnet-5-5-high`.

## 4. Правила применения правок

- Применяйте только конкретные замечания, сохраняющие внешние контракты, затем обязательно перезапустите решающие тесты.
