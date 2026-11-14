---
name: simplify
description: Post-implementation 3-lens code simplification protocol (Reuse, Quality, Efficiency) pinned to Claude Sonnet 5.5 High (`claude-sonnet-5-5-high`) via native Antigravity swarm, with fallback to Gemini Carbon High when Sonnet is unavailable.
---

# Code Simplification Protocol — 3 Sonnet High Lenses

Выполняйте упрощение после того, как функциональность реализована и базовые тесты проходят, но **до** запуска независимого adversarial-ревью (`HIGH`/`XHIGH`), чтобы ревьюер проверял уже чистый финальный код.

## 1. Пропорциональный выбор режима

- **Малая правка (`<= 3` строк в 1 файле, `STANDARD`) или `LOW`:** проверьте дифф самостоятельно без запуска воркеров.
- **Обычный `STANDARD`, `HIGH` и `XHIGH`:** запустите параллельно **3 независимые read-only линзы** на модели **`Claude Sonnet 5.5 (High)` (`claude-sonnet-5-5-high`)** через нативный инструмент `swarm`:
  1. `simplify-reuse` — дублирование логики, констант, валидации и переизобретение существующих утилит репозитория (`SIMPLIFY_LENS: REUSE`).
  2. `simplify-quality` — чистота потока управления, мёртвые импорты/ветки, именование, гигиена комментариев (`SIMPLIFY_LENS: QUALITY`).
  3. `simplify-efficiency` — лишние обходы ФС, повторные `stat()`/подпроцессы, алгоритмическая сложность и ограничение памяти (`SIMPLIFY_LENS: EFFICIENCY`).

## 2. Запуск 3 линз в `swarm`

Перед первым вызовом проверьте доступность и квоту `claude-sonnet-5-5-high` через `swarm(action="models", all=True)`, задайте заголовок `swarm(action="title", title="simplify lenses")` и добавьте 3 read-only воркера (`workspace="inherit"`):

```python
swarm(
    action="add",
    name="simplify",
    model="claude-sonnet-5-5-high",
    tasks=[
        "LENS: REUSE. Check only code reuse, duplicated logic/helpers/constants. End post with `SIMPLIFY_LENS: REUSE` and `SIMPLIFY_VERDICT: CLEAN|ACTIONABLE_FIXES`.",
        "LENS: QUALITY. Check only control-flow clarity, dead code/imports, comment hygiene. End post with `SIMPLIFY_LENS: QUALITY` and `SIMPLIFY_VERDICT: CLEAN|ACTIONABLE_FIXES`.",
        "LENS: EFFICIENCY. Check only hot-path I/O, subprocesses, algorithmic complexity, memory bounds. End post with `SIMPLIFY_LENS: EFFICIENCY` and `SIMPLIFY_VERDICT: CLEAN|ACTIONABLE_FIXES`.",
    ],
    brief="Strictly read-only simplify review of <repo_path> (<changed_files>). Do NOT edit or stage any files. Post concise findings to @coordinator on the board.",
)
```
*(Допустимо также добавить их поименно как `simplify-reuse`, `simplify-quality`, `simplify-efficiency` с `model="claude-sonnet-5-5-high"`.)*
Если одна из линз вернула `ACTIONABLE_FIXES`, оставьте воркеров `swarm` активными и после правок отправьте запрос на подтверждение дельты **в те же самые чаты** через `post_message(...)` (не более 2 проходов на линзу за кандидата). Освобождайте воркеров (`swarm(action="kill", name=...)`) только после получения финальных `SIMPLIFY_VERDICT: CLEAN` по кандидату.

## 3. Эскалация при недоступности Sonnet High

Если `swarm(action="models", all=True)` показывает квоту `0%` у `claude-sonnet-5-5-high` либо воркер вернул ошибку модели/квоты:
- переключите воркер на `gemini-4-carbon-high` через `swarm(action="model", name="...", model="gemini-4-carbon-high")` либо вызовите 3 резервных read-only субагента `simplify-reuse-reviewer`, `simplify-quality-reviewer`, `simplify-efficiency-reviewer`.
- Хук `cwg_stop.py` проверяет `members.json` и `board.jsonl` и принимает fallback-модель только при подтверждённом сбое/исчерпании квоты `claude-sonnet-5-5-high`.

## 4. Правила применения правок

- Применяйте только конкретные замечания, сохраняющие внешние контракты, затем обязательно перезапустите тесты.
