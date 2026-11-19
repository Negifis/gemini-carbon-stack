---
name: development-verification
description: Edge-case reference for Code Work Gate (XHIGH review tiers, pr-ready, draft-blocked, carbon-stack gate-inbox anomalies, .agents/carbon-gate.json). Do NOT load for standard tasks.
---

# Development Verification & Code Work Gate

Контракт верификации, контролируемый runtime-хуками `cwg_mark.rs` и `cwg_stop.rs`.

## 1. Классы работы и политика риска

| Класс | Когда открывается | Требование к закрытию |
|---|---|---|
| `NO_CHANGE` | Чтение, диагностика, подтверждённое non-mutating выполнение | Квитанция не требуется; `Stop` пропускает сразу |
| `OPERATIONAL` | Подтверждённая мутация через `run_command` без изменения файлов (или не измеренное `UNCERTAIN` действие) | `[gate] operational: <предпроверка>; <подтверждённый эффект>` или `[gate] no-change: <причина>` |
| `PERSISTENT` | Изменение файлов через `edit_file`, `write_file` или файловую дельту `run_command` | `[gate] verified: <RISK>; <кандидат и решающие проверки>` (или граничный исход) |

Риск определяется **не числом изменённых строк**, а затронутыми компонентами, характером операции и политикой проекта (`.agents/carbon-gate.json`):

- **`LOW`** (документация, текстовые заметки, статические метаданные/ассеты, `low_risk_globs`): проверка содержимого/ссылок.
- **`STANDARD`** (обычный код, скрипты, UI, тесты, аддоны вне критических путей):
  - Автоматический `swarm`/независимое ревью **не требуются** по умолчанию.
  - Релевантные локальные тесты/проверки обязательны, если проект содержит тестовую инфраструктуру или правки затронули исполняемый код (либо задано `"require_tests_on_standard": true`); любой упавший прогон после правки блокирует закрытие до устранения.
  - Строгие проекты могут включить `"require_simplify_on_standard": true` / `"require_review_on_standard": true` в `.agents/carbon-gate.json`.
- **`HIGH`** (security/auth/jwt/crypto/secrets/rbac/permissions, БД-миграции, CI/CD/Docker, runtime-хуки/манифесты плагина/`carbon-stack install`, `high_risk_globs`):
  - Канонический 5-шаговый пайплайн Swarm 2.0 `Logic-First`: 1) решающие тесты -> 2) первичное независимое ревью `VERDICT: APPROVED` (`carbon-stack codex-lane review`; при недоступности Codex — внутренний `claude-opus-5-5-high` -> `gemini-4-carbon-high` при сбое/0% квоты Opus) -> 3) `simplify` один раз (`SIMPLIFY_LENS: ALL` при `<= 2` файлах и `<= 30` строках либо 3 линзы `reuse`, `quality`, `efficiency` на `claude-sonnet-5-5-high`, fallback `gemini-4-hydrogen-xhigh`; при правках по `simplify` — перезапуск тестов и допроверка всех активных линз через Warm Pool `@mention` с актуальным `DIFF_HASH: <current_diff_hash>`) -> 4) пакетный `kill` всех `waiting` simplify-воркеров -> 5) финальная проверка закрытия `carbon-stack codex-lane review --closure` (`CLOSURE_VALIDATION: READY`; при подтверждённой недоступности Codex — внутреннее closure-ревью в том же `waiting` `internal-reviewer` через `post_message` с `CLOSURE_VALIDATION: READY|BLOCKED` и последующим `kill` `internal-reviewer`).
- **`XHIGH`** (`xhigh_risk_globs`, критические протоколы/конкурентные границы безопасности): то же, что `HIGH`, но с `carbon-stack codex-lane review --xhigh` на модели `gpt-6.2-astra` (включая `--xhigh --closure`; `gpt-6.2-sol` остаётся на `HIGH`) или внутренним `REVIEW_TIER: XHIGH` при подтверждённом сбое Codex.

## 2. Свежесть доказательств, конечность и граничные исходы

- SHA-256 отпечаток (`content_marks`) аннулирует прежний `APPROVED` при любой последующей правке.
- `[gate] no-change: <причина>` на `PERSISTENT`-кандидате допустимо только при полном возврате файлов к чистому `HEAD`.
- Максимум **3 обычных раунда** ревью до эскалации (дисквалифицированные запуски внутреннего ревью при доступном Codex и локальные таймауты размышления Codex не расходуют лимит раундов) и строго **не более 2 раундов closure validation (`CLOSURE_VALIDATION: READY|BLOCKED`)** методом бутерброда (`Review 1..3 -> Simplify -> Closure #1 -> [при BLOCKED: Fix + Tests -> Simplify -> Closure #2]`), плюс **3 блокировки `Stop`** на неизменный кандидат.
- **Режим исследования после 2 блокировок `CLOSURE_VALIDATION: BLOCKED` (`carbon-stack codex-lane research-reset`):** после двух `BLOCKED` продолжение ревью и линз `simplify` в текущем цикле жёстко блокируется (`carbon-stack codex-lane`, `safety_guards.rs`, `cwg_stop.rs`). Агент обязан изучить актуальную документацию и лучшие практики через плагины/интернет (`search_web`, `tokenade search/web`, `Context7`, `Developer Knowledge` / `Gemini Docs`, субагент `research`), выбрать сценарий `refactor` (перепроектировать с нуля) или `refine` (целевая доработка по найденным практикам), завершить ожидающих swarm-воркеров (`kill`) и выполнить `carbon-stack codex-lane research-reset --cwd <repo> --session <id> --decision <refactor|refine> --findings "..."` — это проверяет факт пост-блокировочного исследования в `transcript.jsonl`, очищает треды ревью и `swarm_rounds`, обнуляет счётчики раундов и требует запуска следующего цикла упрощения и ревью в **чистых новых сессиях**.
- **Маршрутизация аномалий (`carbon-stack gate-inbox`)**: при объективной аномалии зафиксируйте nonce-репорт `carbon-stack gate-inbox report`, отправьте живое уведомление дежурному чату аномалий (`carbon-stack gate-inbox handler` / `set-handler --session <conv-id> --repo <path>`) через `send_message(Recipient="<handler_session>", Message="[GATE_ANOMALY <id>] ...")` и закройте ответ `[gate] anomaly-reported: <id>; <факт>`. В самом дежурном чате аномалий (`PreInvocation` инжектирует дайджест открытых репортов) разбирайте `carbon-stack gate-inbox show --id <id>`, устраняйте первопричину в репозитории стека + синхронизируйте `carbon-stack install --force` + тесты и закрывайте репорт `carbon-stack gate-inbox resolve --id <id> --note "..."`.
