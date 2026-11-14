---
name: development-verification
description: Authoritative specification of the Code Work Gate: task classes (NO_CHANGE, OPERATIONAL, PERSISTENT), risk floors (LOW/STANDARD/HIGH/XHIGH), Sonnet High 3-lens simplify, Codex + Opus High -> Carbon High review provenance, and bounded closure receipts.
---

# Development Verification & Code Work Gate

Этот навык определяет точный контракт верификации, который принудительно проверяется runtime-хуками `cwg_mark.py` и `cwg_stop.py`.

## 1. Классы работы

| Класс | Когда открывается | Требование к закрытию |
|---|---|---|
| `NO_CHANGE` | Чтение, диагностика, поиск, ответы без изменения файлов и без мутирующих shell-команд | Квитанция не требуется; хук `Stop` пропускает ответ сразу |
| `OPERATIONAL` | Мутирующая команда `run_command` без изменения отслеживаемых артефактов репозитория | `[gate] operational: <что проверено до запуска>; <подтверждённый эффект>` или `[gate] no-change: <причина>` |
| `PERSISTENT` | Изменение файлов через `edit_file`, `write_file` или файловую дельту `run_command` | `[gate] verified: <RISK>; <кандидат и решающие проверки>` (либо граничный исход ниже) |

## 2. Матрица риска `PERSISTENT`

- **`LOW`** (чистая документация `.md/.txt/.rst` вне конфигураций агента): проверка корректности текста, ссылок и разметки.
- **`STANDARD`** (обычный исходный код, тесты, скрипты):
  - Малая правка (`1` файл, `<= 3` изменённых строк через `edit_file`): обязателен реальный успешный запуск проверок (`pytest`, `unittest`, `tsc`, `cargo test` и т.п.) после последней правки; simplify-воркеры не требуются.
  - Обычная правка (`> 3` строк или >1 файла): успешный запуск проверок после последней правки + **1 объединённый воркер `simplify-reviewer`** (`SIMPLIFY_LENS: ALL`, либо все 3 отдельные линзы) на **`claude-sonnet-5-5-high`** через `swarm` (с fallback на `gemini-4-carbon-high` только при подтверждённом сбое/исчерпании квоты Sonnet).
- **`HIGH`** (авторизация/криптография/права, миграции/схемы, CI/CD, `pyproject.toml`/lock-файлы, `hooks.json`/`plugin.json`/правила/хуки/субагенты):
  - Реальные проверки + строго **3 отдельные simplify-линзы** (`reuse`, `quality`, `efficiency` на `claude-sonnet-5-5-high`, без схлопывания в 1 воркер) + `1` свежий независимый `VERDICT: APPROVED`, полученный **строго после** последнего изменения байтов кандидата:
    - основной внешний контур: `codex_lane.py review` (без изменений);
    - внутренний контур (при открытом circuit breaker Codex или прямом внутреннем ревью): **`claude-opus-5-5-high`** через `swarm` с автоматической эскалацией на **`gemini-4-carbon-high`**, если с Opus зафиксирована ошибка/нулевая квота.
- **`XHIGH`** (критичные архитектурные, протокольные, конкурентные или security-изменения):
  - То же, что `HIGH`, но `VERDICT: APPROVED` должен прийти из XHIGH-профиля: `codex_lane.py review --xhigh` либо внутренний `claude-opus-5-5-high` с маркером `REVIEW_TIER: XHIGH` (с эскалацией на `gemini-4-carbon-high` / `adversarial-reviewer-xhigh` только при подтверждённом сбое Opus).

## 3. Свежесть доказательств и защита от подделки

- Кандидат отслеживается по SHA-256 отпечатку содержимого затронутых файлов (`content_marks`). Любая правка файла после получения `VERDICT: APPROVED` меняет SHA-256 и **автоматически инвалидирует старый вердикт**.
- Для `swarm`-ревью и simplify-линз `cwg_stop.py` проверяет системные файлы Language Server (`.system_generated/swarm/members.json`, `board.jsonl` с фильтрацией строго `post.agent == member_name` и транскрипты воркеров), исключая подмену модели или эхо промпта координатора.
- Квитанция `[gate] no-change: <причина>` на `PERSISTENT`-кандидате принимается только если все затронутые файлы полностью возвращены к чистому состоянию `HEAD`.

## 4. Конечность процесса и граничные квитанции

- Максимум **3 обычных раунда** ревью на кандидата. Немедленно прекращайте ревью после первого `VERDICT: APPROVED`.
- Если 3-й раунд завершился `VERDICT: ESCALATE`, выполните не более **2 раундов closure validation** (`READY` -> `[gate] pr-ready`, `BLOCKED` -> `[gate] draft-blocked`).
- Хук `Stop` ограничен бюджетом **3 блокировки** на неизменный отпечаток кандидата и никогда не создаёт бесконечных циклов. При объективной аномалии используйте nonce-репорт `gate_inbox.py report` -> `[gate] anomaly-reported: <report-id>; <факт>`.
