---
name: adversarial-review
description: Triggered by /adversarial-review or HIGH/XHIGH changes requiring independent read-only review (codex_lane.py or Claude Opus 5.5 High swarm).
---

# `/adversarial-review` — Независимое критическое ревью кода

Один независимый review-движок на раунд, максимум 3 обычных раунда, строгая криптографическая/системная проверка происхождения вердикта хуком `cwg_stop.py`.

## Шаг 1. Основной внешний контур — OpenAI Codex CLI (без изменений)

Сначала проверьте состояние внешнего контура Codex:
```powershell
python -X utf8 "<PLUGIN_ROOT>/hooks/codex_lane.py" check
```
Если `available: true`, запустите изолированное read-only ревью Codex:
```powershell
python -X utf8 "<PLUGIN_ROOT>/hooks/codex_lane.py" review `
  --cwd "<путь к репозиторию>" `
  --session "<conversation-id>" `
  --summary "<цель изменений, затронутые контракты и выполненные тесты>"
```
Для `XHIGH` добавьте `--xhigh` (при post-ESCALATE проверке — `--closure`).

- **Единая сессия чата в рамках кандидата:** 1-й раунд открывает новую сессию Codex и сохраняет её `session_id` в `state/gate/threads/`; все последующие раунды (`REVISE` -> раунды 2/3 и пост-эскалационный `--closure`) по тому же кандидату (`--session` + `git_root`) **автоматически продолжаются в том же самом чате** через `codex exec resume <session_id>` (`SESSION_MODE: resumed`). Передавайте `--new-session` только для принудительного сброса, а `--resume <id>` — для явного выбора сессии.

## Шаг 2. Внутренний межсемейный контур — `Claude Opus 5.5 (High)` -> эскалация на `Gemini 4 Carbon (High)`

Используется при открытом circuit breaker / недоступности Codex либо при прямом запросе внутреннего ревью в Antigravity:

1. Проверьте квоту `claude-opus-5-5-high` через `swarm(action="models", all=True)`.
2. Если `claude-opus-5-5-high` доступен — запустите read-only воркера в `swarm`, закреплённого на **`claude-opus-5-5-high`**:
   ```python
   swarm(
       action="add",
       name="internal-reviewer",  # или internal-reviewer-xhigh для XHIGH
       model="claude-opus-5-5-high",
       workspace="inherit",
       brief="Strictly read-only adversarial code review of <repo_path> (<files>, diff: <full_diff_path>). Do NOT modify any files. Note: shell is Windows PowerShell 5.1 (never use << heredoc, &&, sed, pyflakes, or python slice [a:b]). Verify invariants, security boundaries, failure modes, and tests. Post your report to @coordinator ending with exact standalone line `VERDICT: APPROVED` or `VERDICT: REVISE` (for XHIGH include `REVIEW_TIER: XHIGH`).",
   )
   ```
   Перед повторным раундом (`REVISE` -> Раунд 2/3) запустите `python -X utf8 "<PLUGIN_ROOT>/tools/swarm_cache.py" prepare --session "<conversation-id>" --cwd "<repo_path>" --label review`: пока кэш воркера тёплый (`<= 270s`, `resume_in_place`), направляйте дельту в тот же чат через `post_message("@internal-reviewer ...")`; если 5-минутный TTL кэша истёк (`> 270s`, `rotate_incremental`), не будите остывший чат — закройте его (`swarm(action="kill", name="internal-reviewer")`) и запустите `internal-reviewer-r<N>` с кратким списком замечаний предыдущего раунда и `<incremental_diff_path>`. Освобождайте воркера (`swarm(action="kill", ...)`) только после финального вердикта по кандидату (`APPROVED` или завершения `--closure`).
3. **Эскалация на `gemini-4-carbon-high`, если с Opus что-то не так:**
   - Если `claude-opus-5-5-high` имеет квоту `0%`, недоступен, вернул `ERROR_MESSAGE` / `RESOURCE_EXHAUSTED` или завис:
   - Переключите воркер на месте вызовом `swarm(action="model", name="internal-reviewer", model="gemini-4-carbon-high")` (сохраняя его контекст) либо вызовите резервный субагент `adversarial-reviewer` / `adversarial-reviewer-xhigh`.
   - **Гарантия от обхода:** `cwg_stop.py` проверяет `.system_generated/swarm/members.json` и системные транскрипты и **отклоняет** вердикт `gemini-4-carbon-high`, если в runtime нет подтверждённого сбоя или нулевой квоты `claude-opus-5-5-high`.

## Шаг 3. Обработка вердикта

- `VERDICT: APPROVED` -> ревью завершено (для внутреннего `swarm` закройте воркера через `kill`). Не запускайте лишних раундов; любая правка файлов после этого изменит SHA-256 и инвалидирует вердикт.
- `VERDICT: REVISE` -> устраните подтверждённые дефекты, перезапустите тесты и выполните следующий раунд **в той же сессии ревьюера** (автоматический `codex exec resume` для Codex либо `post_message` существующему воркеру `swarm`).
- `VERDICT: ESCALATE` (на 3-м раунде) -> выполните до 2 проходов `CLOSURE_VALIDATION` в той же сессии (`--closure` для Codex / `post_message` в `swarm`): `READY` -> `[gate] pr-ready`, `BLOCKED` -> `[gate] draft-blocked`.
