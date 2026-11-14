---
name: adversarial-review
description: Run independent read-only adversarial code review (`/adversarial-review`): primary external OpenAI Codex lane (`codex_lane.py`) unchanged; internal review lane on Claude Opus 5.5 High (`claude-opus-5-5-high`) with automatic escalation to Gemini 4 Carbon High (`gemini-4-carbon-high`) on Opus error/quota/stall.
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
       brief="Strictly read-only adversarial code review of <repo_path> (<files>). Do NOT modify any files. Verify invariants, security boundaries, failure modes, and tests. Post your report to @coordinator ending with exact standalone line `VERDICT: APPROVED` or `VERDICT: REVISE` (for XHIGH include `REVIEW_TIER: XHIGH`).",
   )
   ```
   После получения вердикта освободите воркера через `swarm(action="kill", name="internal-reviewer")`.
3. **Эскалация на `gemini-4-carbon-high`, если с Opus что-то не так:**
   - Если `claude-opus-5-5-high` имеет квоту `0%`, недоступен, вернул `ERROR_MESSAGE` / `RESOURCE_EXHAUSTED` или завис:
   - Переключите воркер на месте вызовом `swarm(action="model", name="internal-reviewer", model="gemini-4-carbon-high")` (сохраняя его контекст) либо вызовите резервный субагент `adversarial-reviewer` / `adversarial-reviewer-xhigh`.
   - **Гарантия от обхода:** `cwg_stop.py` проверяет `.system_generated/swarm/members.json` и системные транскрипты и **отклоняет** вердикт `gemini-4-carbon-high`, если в runtime нет подтверждённого сбоя или нулевой квоты `claude-opus-5-5-high`.

## Шаг 3. Обработка вердикта

- `VERDICT: APPROVED` -> ревью завершено. Не запускайте лишних раундов; любая правка файлов после этого изменит SHA-256 и инвалидирует вердикт.
- `VERDICT: REVISE` -> устраните подтверждённые дефекты, перезапустите тесты и выполните следующий раунд.
- `VERDICT: ESCALATE` (на 3-м раунде) -> выполните до 2 проходов `CLOSURE_VALIDATION` (`READY` -> `[gate] pr-ready`, `BLOCKED` -> `[gate] draft-blocked`).
