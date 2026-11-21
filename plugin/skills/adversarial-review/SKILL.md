---
name: adversarial-review
description: Triggered by /adversarial-review or HIGH/XHIGH changes requiring independent read-only review (carbon-stack codex-lane or Claude Opus 5.5 High swarm).
---

# `/adversarial-review` — Прагматичное независимое состязательное ревью кода

**Ключевой принцип:** *ревью защищает реализацию бизнес-требований, а не защищает систему от самих бизнес-требований.*
Один независимый review-движок на раунд, максимум 4 обычных раунда (`MAX_REVIEW_ROUNDS = 4`, `BLOCKING_THRESHOLD = HIGH`: блокируют только подтверждённые дефекты Класса A уровня `CRITICAL`/`HIGH` с `PRESERVES_INTENT: YES` и конкретным триггером `file:line`), строгая проверка происхождения вердикта хуком `cwg_stop.rs`.
**Линейный конечный порядок (`Finite Gate`, см. `development-verification`):** для `HIGH`/`XHIGH` сначала проходят локальные тесты (`cargo test` / `pytest` / `npm test`), затем **консультативный проход `simplify` строго 1 раз ДО ревью** (`MAX_SIMPLIFY_PASSES = 1` на весь кандидат) + пакетный `kill` `waiting` simplify-воркеров, и затем **независимое ревью (`1..4` раунда)**. **`VERDICT: APPROVED` на любом раунде `1..4` немедленно закрывает гейт** (`[gate] verified: HIGH|XHIGH; ...`) без повторного `simplify` и без `--closure`. Только после `Round 4: ESCALATE` и одного прохода исследования выбирается `REMEDIATE` (та же сессия, максимум `2` попытки `--closure`, `MAX_TOTAL_GATE_ROUNDS = 7`) либо архитектурный `REDESIGN` (`carbon-stack codex-lane redesign-reset`, максимум `1` раз на кандидата — `MAX_REDESIGN_RESETS = 1`, обнуляющий раунды и начинающий чистую сессию ревьюера).

## 4-классовая контекстная калибровка рисков, порог `HIGH` и соразмерность защитных мер

- **Класс A (Реальные дефекты реализации — БЛОКЕР при `CRITICAL`/`HIGH`):** конкретный **реалистично достижимый** баг продакшена/пользователя/агента, сломанный бизнес-сценарий, утечка секретов, дыра auth/прав, порча данных или сломанный откат с точным `file:line`, реалистичным триггером и подтверждением `PRESERVES_INTENT: YES`. **Искусственные «adversarial-головоломки»** (синтетические строки/комбинации флагов, сконструированные исключительно для обхода regex/эвристики без реалистичного сценария эксплуатации) **не могут** иметь уровень `HIGH`/`CRITICAL` — они относятся к `MEDIUM`/`LOW` (не блокируют) или к Классу D.
- **Класс B (Соразмерная защита запрошенных возможностей — СОХРАНЯЕТ ФУНКЦИОНАЛЬНОСТЬ):** если пользователь запросил внешние AI/LLM API, сетевых агентов, интеграции со сторонними сервисами (Bitrix24/Jira/вебхуки/MCP) или операции с production-инфраструктурой — ревью предлагает **только соразмерные меры** (scoped-секреты, таймауты, TLS/HMAC, least-privilege RBAC, аудит-логи, лимиты, dry-run/подтверждения), но **никогда** не требует изоляции от интернета, перехода на локальные модели или удаления нужной бизнес-возможности.
- **Класс C (Риск бизнес-модели / противоречие задаче — НЕ БЛОКЕР):** риск самой выбранной бизнес-модели либо рекомендация, меняющая требования / ломающая нужный сценарий / ухудшающая UX. Не может вызывать `REVISE`/`BLOCKED` (максимум краткая пометка `INFO` внутри `APPROVED`).
- **Класс D (Субъективные предпочтения, синтетические головоломки и гипотетические угрозы — `LOW`/`INFO`, НЕ БЛОКЕР):** вкусовая архитектура, умозрительные атаки и искусственные regex-головоломки без реалистичного триггера, необязательный рефакторинг.
- **Дисциплина малых батчей, инвариантов до кода и запрета «заплаток по примеру»:** крупные задачи режьте на атомарные коммиты/этапы (`схема/контракт -> реализация -> интеграция`) и формулируйте `3–5` ключевых инвариантов до первой правки; на Раунде `2+` при обходе эвристики/regex/окна времени меняйте сам механизм доказательства (структурный парсер, явные метаданные, инвариант в типе/БД), а не дописывайте очередную заплатку в regex.

## Шаг 1. Приоритет №1 (всегда основной контур) — OpenAI Codex CLI (`carbon-stack codex-lane`)

Всегда начинайте с проверки и запуска внешнего контура Codex (переход на внутренние модели при доступном Codex запрещён и блокируется `cwg_stop.rs`).
**Важно (`BypassSandbox: true`):** вызовы `carbon-stack codex-lane review` и `carbon-stack codex-lane reset` обязательно запускайте **вне песочницы** (`BypassSandbox: true`), так как им требуются исходящий HTTPS-доступ к API OpenAI и запись пакетов в `CARBON_STACK_HOME` (сетевой/файловый отказ песочницы помечается как `sandbox_blocked: true` и не взводит глобальный 30-минутный circuit breaker):
```powershell
& "<PLUGIN_ROOT>/bin/carbon-stack.exe" codex-lane check
```
Если `available: true`, запустите изолированное read-only ревью Codex (с `BypassSandbox: true`), передав `--intent` с исходной бизнес-целью и принятыми возможностями (если `--intent` не задан, `codex-lane` автоматически извлечёт его из сохранённого треда, `.agents/handoff.json` или `USER_INPUT` транскрипта):
```powershell
& "<PLUGIN_ROOT>/bin/carbon-stack.exe" codex-lane review `
  --cwd "<путь к репозиторию>" `
  --session "<conversation-id>" `
  --intent "<исходный бизнес-запрос пользователя, обязательные возможности и критерии успеха>" `
  --summary "<цель изменений, затронутые контракты и выполненные тесты>"
```
По умолчанию на `HIGH` запускается `gpt-6.2-sol` (`effort="high"`), а при передаче `--xhigh` (`XHIGH`) — `gpt-6.2-astra` (`effort="xhigh"`; при поиске `XHIGH`-вердикта в rollout проверяется именно модель Astra, а Sol остаётся на `HIGH`). Для `XHIGH` добавьте `--xhigh` (дефолтный таймаут 10–15 мин: `600s` обычно и `900s` для `--xhigh`; флаг `--closure` передавайте **только** при эскалации после 4-го раунда `ESCALATE`). Не передавайте укороченные пользовательские `--timeout` заранее: если Codex не успел уложиться в таймаут (не из-за падения сети/квоты), это **не считается раундом ревью и не является поводом переключаться на внутренние модели** — повторите `carbon-stack codex-lane review`, и сохранённая сессия автоматически продолжится с увеличенным таймаутом (`15+` мин).

- **Единая сессия чата, interdiff и Settled-Scope Freeze:** 1-й раунд открывает новую сессию Codex и сохраняет её `session_id`, `last_reviewed_tree_oid` и журнал замечаний в `state/gate/threads/`; все последующие раунды (`REVISE` -> раунды `2..4` и пост-эскалационный `--closure`) по тому же кандидату (`--session` + `git_root`) **автоматически продолжаются в том же самом чате** через `codex exec resume <session_id>` (`SESSION_MODE: resumed`) с передачей `REMEDIATION INTERDIFF SINCE PREVIOUS ROUND` и запретом поднимать новые стилевые/неблокирующие претензии к уже проверенному коду (`Settled-Scope Freeze`). Передавайте `--new-session` только для принудительного сброса, а `--resume <id>` — для явного выбора сессии.

## Шаг 2. Приоритет №2 (только при подтверждённой недоступности Codex) — `Claude Opus 5.5 (High)` -> эскалация на `Gemini 4 Neon (XHigh)` [`HIGH`] / `Gemini 4 Carbon (High)` [`XHIGH`]

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
   В Раунде 2+ (`REVISE` -> Раунд 2/3) и на пост-эскалационном шаге `CLOSURE_VALIDATION` повторно запустите `carbon-stack swarm-cache prepare ... --label review` и будите того же `waiting`-воркера в **Warm Pool** через `post_message("@internal-reviewer ...")` с `<incremental_diff_path>` (холодная ротация `-r<N>` допустима только если воркер завис по `Stall Watchdog` или был убит). Сразу завершите `internal-reviewer` через `swarm(action="kill", ...)` после `VERDICT: APPROVED` либо после финального `CLOSURE_VALIDATION`.
3. **Эскалация, если с Opus что-то не так:**
   - Если `claude-opus-5-5-high` имеет квоту `0%`, недоступен, вернул `ERROR_MESSAGE` / `RESOURCE_EXHAUSTED` или завис:
   - Для **`HIGH`**: переключите воркер на **`gemini-4-neon-xhigh`** (`swarm(action="model", name="internal-reviewer", model="gemini-4-neon-xhigh")` или `adversarial-reviewer`, с резервом `gemini-4-carbon-high`).
   - Для **`XHIGH`**: переключите воркер на **`gemini-4-carbon-high`** (`swarm(action="model", name="internal-reviewer-xhigh", model="gemini-4-carbon-high")` либо `adversarial-reviewer-xhigh`; `internal-neon` для `XHIGH` не принимается).
   - **Гарантия от обхода:** `cwg_stop.rs` проверяет `.system_generated/swarm/members.json` и системные транскрипты и **отклоняет** вердикт `gemini-4-neon-xhigh` / `gemini-4-carbon-high`, если в runtime нет подтверждённого сбоя или нулевой квоты `claude-opus-5-5-high` (а для `XHIGH` отклоняет `internal-neon`).

## Шаг 3. Обработка вердикта, осмысленное отклонение и анти-бумеранг (`dispose`)

- `VERDICT: APPROVED` -> **гейт пройден!** Немедленно закрывайте ход финальной квитанцией `[gate] verified: HIGH|XHIGH; <кандидат, тесты и ревью>` (завершив `internal-reviewer`, если ревью шло во внутреннем `swarm`). Повторный `simplify` и вызов `--closure` после обычного `APPROVED` не требуются и блокируются как лишние раунды; любая последующая правка файлов изменит SHA-256 и потребует перезапуска тестов и проверки свежести.
- `VERDICT: REVISE` -> для каждого замечания проверьте его по 4 классам относительно `BUSINESS_INTENT`:
  - Реальные дефекты **Класса A** и соразмерные меры **Класса B** исправьте и перезапустите тесты (повторный `simplify` не запускайте).
  - Замечания **Класса C / D** (противоречат исходному бизнес-запросу, предлагают несоразмерный компромисс, не дают практической ценности или выходят за рамки задачи) **обоснованно отклоните** через `carbon-stack codex-lane dispose` (команда классифицируется как `BOOKKEEPING` и автоматически подмешивается в промпт следующих раундов в секцию `ANTI-BOOMERANG LEDGER — DO NOT RE-RAISE`, чтобы отклонённые по существу пункты не возвращались в следующих циклах):
    ```powershell
    $null | & "<PLUGIN_ROOT>/bin/carbon-stack.exe" codex-lane dispose `
      --cwd "<путь к репозиторию>" `
      --session "<conversation-id>" `
      --finding "<краткая формулировка замечания>" `
      --category "<intent-conflict|accepted-risk|no-practical-gain|deferred-improvement>" `
      --reason "<содержательное обоснование относительно бизнес-намерения и принятых соразмерных защит>"
    ```
  - Затем выполните следующий раунд **в той же сессии ревьюера** (автоматический `codex exec resume` с interdiff + реестром `dispose` для Codex либо `post_message` существующему воркеру `swarm` с явным списком `dispose`).
- `VERDICT: ESCALATE` (на 4-м раунде) -> выполните **однократный** проход исследования через доступные плагины и интернет (`search_web`, `tokenade search/web`, `Context7`, `Developer Knowledge` / `Gemini Docs`, субагент `research`), внесите целевое исправление (`REMEDIATE` или `REDESIGN`), перезапустите тесты и проведите до **2 попыток `CLOSURE_VALIDATION`** в той же сессии ревьюера (`--closure` для Codex / `post_message` в `swarm` без повторного `simplify`), проверяющих только исходные открытые блокеры и дельту восстановления: `CLOSURE_VALIDATION: READY` -> `[gate] verified` (или `pr-ready`).
- **Конечный сброс при `REDESIGN` (`MAX_REDESIGN_RESETS = 1`) и жёсткий стоп после `2` блокировок `CLOSURE_VALIDATION: BLOCKED` (`[gate] draft-blocked`):** после `Round 4: ESCALATE` + исследования при выборе архитектурного `REDESIGN` допускается максимум **1** `carbon-stack codex-lane redesign-reset` на кандидата (обнуляет раунды и начинает чистую сессию ревьюера и `simplify`; повторный сброс запрещён). Для `REMEDIATE` третьего прохода `--closure` не существует: если `2`-я попытка `--closure` вернула `BLOCKED`, `carbon-stack codex-lane`, `safety_guards.rs` и `cwg_stop.rs` блокируют дальнейшие запуски — завершите всех swarm-воркеров (`kill`) и закройте ход терминальной квитанцией `[gate] draft-blocked: <причина и оставшиеся блокеры>` с передачей решения пользователю.
