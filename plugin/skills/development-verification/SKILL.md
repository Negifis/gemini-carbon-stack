---
name: development-verification
description: Edge-case reference for Code Work Gate (XHIGH review tiers, pr-ready, draft-blocked, gate_inbox.py anomalies, .agents/carbon-gate.json). Do NOT load for standard tasks.
---

# Development Verification & Code Work Gate

Контракт верификации, контролируемый runtime-хуками `cwg_mark.py` и `cwg_stop.py`.

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
- **`HIGH`** (security/auth/jwt/crypto/secrets/rbac/permissions, БД-миграции, CI/CD/Docker, runtime-хуки/манифесты плагина/`install.py`, `high_risk_globs`):
  - Решающие тесты после последней правки + строго **3 отдельные simplify-линзы** (`reuse`, `quality`, `efficiency` на `claude-sonnet-5-5-high`, fallback `gemini-4-hydrogen-xhigh` через `swarm` при сбое/0% квоты Sonnet) + `1` свежий независимый `VERDICT: APPROVED` (`codex_lane.py review` или внутренний `claude-opus-5-5-high` -> `gemini-4-carbon-high` при сбое Opus).
- **`XHIGH`** (`xhigh_risk_globs`, критические протоколы/конкурентные границы безопасности): то же, что `HIGH`, но с `codex_lane.py review --xhigh` или `REVIEW_TIER: XHIGH`.

## 2. Свежесть доказательств, конечность и граничные исходы

- SHA-256 отпечаток (`content_marks`) аннулирует прежний `APPROVED` при любой последующей правке.
- `[gate] no-change: <причина>` на `PERSISTENT`-кандидате допустимо только при полном возврате файлов к чистому `HEAD`.
- Максимум **3 обычных раунда** ревью (дисквалифицированные запуски внутреннего ревью при доступном Codex не расходуют лимит раундов), **2 раунда closure validation** без `READY` (`pr-ready` / `draft-blocked`; полученный свежий `CLOSURE_VALIDATION: READY` после раунда 3 закрывает кандидат) и **3 блокировки `Stop`** на неизменный кандидат.
- **Маршрутизация аномалий (`gate_inbox.py`)**: при объективной аномалии зафиксируйте nonce-репорт `gate_inbox.py report`, отправьте живое уведомление дежурному чату аномалий (`gate_inbox.py handler` / `set-handler --session <conv-id> --repo <path>`) через `send_message(Recipient="<handler_session>", Message="[GATE_ANOMALY <id>] ...")` и закройте ответ `[gate] anomaly-reported: <id>; <факт>`. В самом дежурном чате аномалий (`PreInvocation` инжектирует дайджест открытых репортов) разбирайте `gate_inbox.py show --id <id>`, устраняйте первопричину в репозитории стека + синхронизируйте `install.py --force` + тесты и закрывайте репорт `gate_inbox.py resolve --id <id> --note "..."`.
