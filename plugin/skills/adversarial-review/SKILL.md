---
name: adversarial-review
description: Triggered by /adversarial-review or HIGH/XHIGH changes requiring independent read-only review (carbon-stack codex-lane or Claude Opus 5.5 High swarm).
---

# `/adversarial-review` — Независимое критическое ревью кода

Один независимый review-движок на раунд, максимум 3 обычных раунда, строгая криптографическая/системная проверка происхождения вердикта хуком `cwg_stop.rs`.
**Инвариант порядка Swarm 2.0 (`Logic-First`, см. `development-verification`):** для `HIGH`/`XHIGH` сначала проходят локальные тесты (`unittest`), затем **первичное независимое ревью (`VERDICT: APPROVED`)**, затем **один проход `simplify`**, пакетный `kill` `waiting` simplify-воркеров и финальная closure-проверка (`carbon-stack codex-lane review --closure` `CLOSURE_VALIDATION: READY`, либо внутреннее closure-ревью `CLOSURE_VALIDATION: READY|BLOCKED` при недоступности Codex с последующим `kill` `internal-reviewer`).

## Шаг 1. Приоритет №1 (всегда основной контур) — OpenAI Codex CLI (`carbon-stack codex-lane`)

Всегда начинайте с проверки и запуска внешнего контура Codex (переход на внутренние модели при доступном Codex запрещён и блокируется `cwg_stop.rs`).
**Важно (`BypassSandbox: true`):** вызовы `carbon-stack codex-lane review` и `carbon-stack codex-lane reset` обязательно запускайте **вне песочницы** (`BypassSandbox: true`), так как им требуются исходящий HTTPS-доступ к API OpenAI и запись пакетов в `CARBON_STACK_HOME` (сетевой/файловый отказ песочницы помечается как `sandbox_blocked: true` и не взводит глобальный 30-минутный circuit breaker):
```powershell
& "<PLUGIN_ROOT>/bin/carbon-stack.exe" codex-lane check
```
Если `available: true`, запустите изолированное read-only ревью Codex (с `BypassSandbox: true`):
```powershell
& "<PLUGIN_ROOT>/bin/carbon-stack.exe" codex-lane review `
  --cwd "<путь к репозиторию>" `
  --session "<conversation-id>" `
  --summary "<цель изменений, затронутые контракты и выполненные тесты>"
```
По умолчанию на `HIGH` запускается `gpt-6.2-sol` (`effort="high"`), а при передаче `--xhigh` (`XHIGH`) — `gpt-6.2-astra` (`effort="xhigh"`; при поиске `XHIGH`-вердикта в rollout проверяется именно модель Astra, а Sol остаётся на `HIGH`). Для `XHIGH` добавьте `--xhigh` (включая финальный `--xhigh --closure`; дефолтный таймаут 10–15 мин: `600s` обычно и `900s` для `--xhigh`; для финальной проверки после `simplify` или после 3-го раунда `ESCALATE` добавьте `--closure`). Не передавайте укороченные пользовательские `--timeout` заранее: если Codex не успел уложиться в таймаут (не из-за падения сети/квоты), это **не считается раундом ревью и не является поводом переключаться на внутренние модели** — повторите `carbon-stack codex-lane review`, и сохранённая сессия автоматически продолжится с увеличенным таймаутом (`15+` мин).

- **Единая сессия чата в рамках кандидата:** 1-й раунд открывает новую сессию Codex и сохраняет её `session_id` в `state/gate/threads/`; все последующие раунды (`REVISE` -> раунды 2/3 и финальный/пост-эскалационный `--closure`) по тому же кандидату (`--session` + `git_root`) **автоматически продолжаются в том же самом чате** через `codex exec resume <session_id>` (`SESSION_MODE: resumed`). Передавайте `--new-session` только для принудительного сброса, а `--resume <id>` — для явного выбора сессии.

## Шаг 2. Приоритет №2 (только при подтверждённой недоступности Codex) — `Claude Opus 5.5 (High)` -> эскалация на `Gemini 4 Carbon (High)`

Используется **ИСКЛЮЧИТЕЛЬНО** при открытом circuit breaker / подтверждённом сбое или недоступности `carbon-stack codex-lane` (`available: false`):

1. Проверьте квоту `claude-opus-5-5-high` через `swarm(action="models", all=True)`.
2. Если `claude-opus-5-5-high` доступен — подготовьте дифф `& "<PLUGIN_ROOT>/bin/carbon-stack.exe" swarm-cache prepare --session "<conversation-id>" --cwd "<repo_path>" --label review` и запустите read-only воркера в `swarm`, закреплённого на **`claude-opus-5-5-high`**:
   ```python
   swarm(
       action="add",
       name="internal-reviewer",  # или internal-reviewer-xhigh для XHIGH
       model="claude-opus-5-5-high",
       workspace="inherit",
       brief="Strictly read-only adversarial code review of <repo_path> (<files>, diff: <full_diff_path>). Do NOT modify any files. Note: shell is Windows PowerShell 5.1 (never use << heredoc, &&, sed, pyflakes, or python slice [a:b]). Verify invariants, security boundaries, failure modes, and tests. Post your report to @coordinator ending with exact standalone line `VERDICT: APPROVED` or `VERDICT: REVISE` (for XHIGH include `REVIEW_TIER: XHIGH`).",
   )
   ```
   В Раунде 2+ (`REVISE` -> Раунд 2/3) и на финальном шаге `CLOSURE_VALIDATION` повторно запустите `carbon-stack swarm-cache prepare ... --label review` и будите того же `waiting`-воркера в **Warm Pool** через `post_message("@internal-reviewer ...")` с `<incremental_diff_path>` (холодная ротация `-r<N>` допустима только если воркер завис по `Stall Watchdog` или был убит). Завершите `internal-reviewer` через `swarm(action="kill", ...)` после финального `CLOSURE_VALIDATION` (либо сразу после `APPROVED` только на задачах без `simplify`/closure).
3. **Эскалация на `gemini-4-carbon-high`, если с Opus что-то не так:**
   - Если `claude-opus-5-5-high` имеет квоту `0%`, недоступен, вернул `ERROR_MESSAGE` / `RESOURCE_EXHAUSTED` или завис:
   - Переключите воркер на месте вызовом `swarm(action="model", name="internal-reviewer", model="gemini-4-carbon-high")` (сохраняя его контекст) либо вызовите резервный субагент `adversarial-reviewer` / `adversarial-reviewer-xhigh`.
   - **Гарантия от обхода:** `cwg_stop.rs` проверяет `.system_generated/swarm/members.json` и системные транскрипты и **отклоняет** вердикт `gemini-4-carbon-high`, если в runtime нет подтверждённого сбоя или нулевой квоты `claude-opus-5-5-high`.

## Шаг 3. Обработка вердикта

- `VERDICT: APPROVED` -> первичное ревью пройдено; переходите к однократному проходу `simplify` и финальной проверке закрытия (`--closure` для Codex либо `post_message` внутреннему ревьюеру в `swarm` на получение `CLOSURE_VALIDATION: READY|BLOCKED` при недоступности Codex, после чего выполните пакетный `kill`). Не запускайте лишних обычных раундов; любая правка файлов после вердикта изменит SHA-256 и потребует перезапуска тестов и проверки свежести.
- `VERDICT: REVISE` -> устраните подтверждённые дефекты, перезапустите тесты и выполните следующий раунд **в той же сессии ревьюера** (автоматический `codex exec resume` для Codex либо `post_message` существующему воркеру `swarm`).
- `VERDICT: ESCALATE` (на 3-м раунде) или переход к closure после `APPROVED` -> выполните проход `simplify` на текущем SHA-256, завершите simplify-воркеров и проведите до **2 раундов эскалации `CLOSURE_VALIDATION`** в той же сессии ревьюера (`--closure` для Codex / `post_message` в `swarm`): `READY` -> `[gate] verified` (или `pr-ready`). Если 1-й `--closure` вернул `BLOCKED` — исправьте проблему, прогоните тесты, снова выполните `simplify` (метод бутерброда) и запустите 2-й `--closure`.
- **Жёсткий стоп после 2 блокировок `CLOSURE_VALIDATION: BLOCKED` -> Режим исследования (`research-reset`):** третьего прохода `--closure` в том же цикле не существует (`carbon-stack codex-lane`, `safety_guards.rs` и `cwg_stop.rs` блокируют продолжение ревью и линз). Изучите через доступные плагины и интернет актуальную документацию, рекомендации и лучшие практики по блокирующей проблеме (`search_web`, `tokenade search/web`, `Context7`, `Developer Knowledge` / `Gemini Docs`, субагент `research`), примите решение — переделать и рефакторить (`--decision refactor`) или продолжить доработку текущего решения на базе исследования (`--decision refine`), завершите всех swarm-воркеров (`kill`) и выполните `& "<PLUGIN_ROOT>/bin/carbon-stack.exe" codex-lane research-reset --cwd "<repo>" --session "<conversation-id>" --decision <refactor|refine> --findings "<резюме исследования и решения>"`. Раунды обнуляются, а новый цикл упрощения и ревью запускается строго в **новых сессиях** (либо закройте черновик `[gate] draft-blocked`, если пользователь запросил паузу).
