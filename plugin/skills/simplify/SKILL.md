---
name: simplify
description: "Triggered by /simplify or HIGH/XHIGH verification (Swarm 2.0 Fast-Path SIMPLIFY_LENS: ALL or 3 parallel Claude Sonnet 5.5 High lenses via Warm Pool)."
---

# Code Simplification Protocol — Finite Gate (`claude-code-stack` Advisory Polish)

Применяется строго один раз как консультативный проход полировки **после прохождения базовых тестов и ДО запуска независимого ревью** для `HIGH`/`XHIGH`, проектов с `"require_simplify_on_standard": true` в `.agents/carbon-gate.json` или при явном вызове `/simplify`. Для обычных `STANDARD`-задач не обязателен. Жёсткий потолок на кандидата: **`MAX_SIMPLIFY_PASSES = 1`** (1 консультативный проход даёт >93% полезного результата без пустых `CLEAN`-перепроверок и регрессий второго прохода; повторные проходы блокируются `safety_guards.rs`).

## 1. Режимы запуска

- **Mode A (`/simplify`, `STANDARD` с политикой проекта или Swarm 2.0 Fast-Path на `HIGH`/`XHIGH` при `<= 2` файлах и `<= 30` изменённых строках):** 1 объединённый read-only воркер `simplify-reviewer` на **`Claude Sonnet 5.5 (High)`** (`model="claude-sonnet-5-5-high"`, primary fallback `model="gemini-4-neon-xhigh"`, вторичный резерв `model="gemini-4-hydrogen-xhigh"` при 0% квоты/сбое Sonnet), покрывающий `REUSE`, `QUALITY`, `EFFICIENCY` за один проход (`SIMPLIFY_LENS: ALL`, `SIMPLIFY_VERDICT: CLEAN|ACTIONABLE_FIXES`, `DIFF_HASH: <current_diff_hash>`).
- **Mode B (`HIGH` и `XHIGH` при `> 2` файлах или `> 30` изменённых строках — строго 3 параллельные линзы):** 3 отдельные read-only линзы на **`Claude Sonnet 5.5 (High)`** через `swarm`:
  1. `simplify-reuse` — дублирование логики, констант и переизобретение утилит (`SIMPLIFY_LENS: REUSE`).
  2. `simplify-quality` — чистота потока управления, мёртвые ветки и гигиена инвариантов (`SIMPLIFY_LENS: QUALITY`).
  3. `simplify-efficiency` — лишний I/O, повторные `stat()`/подпроцессы и аллокации (`SIMPLIFY_LENS: EFFICIENCY`).

## 2. Тёплый пул (`Warm Pool`) и инкрементальные диффы (`carbon-stack swarm-cache`)

```powershell
& "<PLUGIN_ROOT>/bin/carbon-stack.exe" swarm-cache prepare --session "<conversation-id>" --cwd "<repo_path>" --label simplify
```

- **Раунд 1 (`initial_spawn`):** вызывайте `swarm-cache prepare` без `--paths` (частичные срезы `--paths`, чужие репозитории и кандидаты с непокрытыми файлами вне `git_root` / `assume-unchanged` завершаются ошибкой `"partial_or_uncovered_candidate_diff"` без создания diff-файла; при наличии активных раундов `swarm-cache prepare` вердикты `SIMPLIFY_VERDICT: CLEAN|ACTIONABLE_FIXES` обязаны содержать явный совпадающий `DIFF_HASH: <current_diff_hash>`, а если самый первый полнорепозиторный `swarm-cache prepare` без `--paths` вернул `"partial_or_uncovered_candidate_diff"` с `"direct_read_allowed": true`, допускается прямое чтение файлов без `DIFF_HASH`); передайте воркерам `<full_diff_path>`, список затронутых файлов и `DIFF_HASH: <current_diff_hash>`.
- **Раунд 2+ (`Warm Pool` через `@mention` вместо `kill` + `spawn`):** пока воркеры находятся в статусе `waiting`, будите **тех же** воркеров через `post_message("@simplify-reuse @simplify-quality @simplify-efficiency ...")` (или `@simplify-reviewer` для Fast-Path), передавая `<full_diff_path>` при `"head_changed": true` (смена базы `HEAD`; в этом случае `<incremental_diff_path>` также содержит полный diff относительно нового `HEAD`) либо `<incremental_diff_path>` при неизменном `HEAD`, и новый `DIFF_HASH: <current_diff_hash>` (при смене `HEAD` он перевыпускается с привязкой к новой базе). Не убивайте и не пересоздавайте `-r2`/`-r3` между раундами (холодная ротация допустима только если воркер завис по `Stall Watchdog` или был убит).
- **Пакетный `kill` один раз перед переходом к ревью:** после завершения единственного консультативного прохода `simplify` (`SIMPLIFY_VERDICT: CLEAN` либо внесение принятых точечных правок `ACTIONABLE_FIXES` + прогон тестов; `MAX_SIMPLIFY_PASSES = 1` на весь кандидат) пакетно завершите всех `waiting` simplify-воркеров (`swarm(action="kill", ...)`) один раз перед запуском независимого ревью (`carbon-stack codex-lane review`).
- **При подтверждённом сбое/нулевой квоте `claude-sonnet-5-5-high`** переключайтесь на **`Gemini 4 Neon (XHigh)`** (`swarm(action="add", ..., model="gemini-4-neon-xhigh")`, вторичный резерв — `gemini-4-hydrogen-xhigh`), никогда не на `gemini-4-carbon-high` и не на прямой `invoke_subagent` из основной сессии (чтобы не сжигать квоту основной модели). Правки по `ACTIONABLE_FIXES` и по замечаниям последующего независимого ревью (`VERDICT: REVISE` / `--closure`) **не инвалидируют** ранее пройденный на кандидате проход `simplify` в `cwg_stop.rs` — никогда не запускайте `simplify` повторно.
- **Линейный порядок (`Finite Gate`, см. `development-verification`):** `cargo test` / тесты -> консультативный проход `simplify` ДО ревью (`MAX_SIMPLIFY_PASSES = 1`) -> пакетный `kill` simplify-воркеров -> независимое ревью `carbon-stack codex-lane review` (`1..4` раунда; `VERDICT: APPROVED` сразу закрывает гейт!). Никогда не запускайте `simplify` и `adversarial-review` параллельно и никогда не запускайте `simplify` после `APPROVED`.
