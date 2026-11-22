---
name: enterprise-1c-bitrix-jira
description: "Bitrix24 REST/CRM, 1C/BSL (bsl-ls/v8std), Jira DC/JSM, and local Hurl/Schemathesis/Newman testing."
---

# Enterprise Integrations: Bitrix24, 1С/BSL, Jira DC & API Testing

## 1. Bitrix24 (REST API, CRM, Open Lines, Webhooks)

- **Документация методов, событий и приложений (активна сразу):**
  - Вызывайте `b24-dev-mcp` (`bitrix-search` → `bitrix-method-details` / `bitrix-event-details` / `bitrix-app-development-doc-details`). Не пишите сигнатуры REST-методов (`crm.*`, `imopenlines.*`, `imconnector.*`, `tasks.*`) по памяти — проверяйте точные параметры и ошибки.
- **Живой портал Bitrix24:**
  - `bitrix24` MCP (`bit2beat/bitrix24-mcp`, локально в `C:\Users\in\mcp-servers\bitrix24-mcp`, подключается через `B24_DEFAULT_WEBHOOK` в `mcp-gate.env`).
  - Для Открытых линий (`imopenlines.*`, `imconnector.*`) и пакетных выборок используйте `b24_call` / `b24_batch`.
  - У вебхуков нет протокольного RO-флага — перед любыми write-вызовами к продовому порталу запрашивайте подтверждение и используйте вебхук с минимальными scopes.

## 2. 1С:Предприятие / BSL / Метаданные

- **Статический анализ, типы, ссылки и граф вызовов BSL (активен сразу):**
  - `bsl-ls` MCP (`bsl-language-server` v1.0.7 со встроенным JRE 21 и 10 read-only тулами: `analyze_file`, `call_hierarchy`, `definition`, `document_symbols`, `find_references`, `global_member_info`, `global_member_search`, `hover`, `type_at_position`, `type_info`).
  - Массовая CLI-проверка каталога модулей:
    ```powershell
    $null | & "C:\tools\bsl-language-server\bsl-language-server\bsl-language-server.exe" analyze -s <src_dir> -o <report_dir> -r json -q
    ```
- **Стандарты и синтаксис платформы:**
  - `v8std` (`https://ai.v8std.ru/mcp`) — стандарты ИТС, АПК/ACC и расшифровка диагностик BSL LS / EDT.
  - `1c-syntax-helper` (`http://localhost:8000/mcp`) — локальный справочник платформы (поднимается из `C:\Users\in\mcp-servers\1c-syntax-helper-mcp\start_mcp_server.ps1`).
- **Крупные выгрузки метаданных и 1C:EDT (при появлении задач по полным конфигурациям):**
  - Без запущенной 1C:EDT по выгрузкам XML/EDT: `Regsorm/code-index-mcp` (`bsl-indexer-windows-x64.zip`).
  - Внутри запущенной 1C:EDT 2026+: плагин `fedukhin-sys/1C_EDT_MCP_PUBLIC` (107 тулов, Apache-2.0, обезличивание 152-ФЗ).

## 3. Jira Software Data Center / JSM / Confluence (`jira.lemnos.ru`)

- Инстанс `https://jira.lemnos.ru` — self-hosted **Jira Software Data Center** (REST API v2, PAT).
- Основной MCP: `atlassian` (`sooperset/mcp-atlassian==0.24.7` через `mcp_env_exec.py --atlassian`):
  - Работает с Cloud и Server/DC (в отличие от облачного `atlassian-twg-cli`).
  - По умолчанию включены `READ_ONLY_MODE=true` и JSM-тулсеты (`jira_service_desk`, `jira_forms`, `jira_metrics` — очереди, SLA, формы ProForma).
  - Для защиты клиентских тикетов JSM задавайте `JIRA_INTERNAL_ONLY_PROJECTS` в `mcp-gate.env`.

## 4. OpenAPI и локальное тестирование API

- **Контрактный фаззинг по `openapi.yaml`/`openapi.json`:** `schemathesis run <spec> --url http://localhost:<port>` (автоматически находит 500-ки и дрейф схем).
- **Повторяемые HTTP-сценарии и цепочки с ассертами:** `hurl --test <file.hurl>` (чистые текстовые файлы в git, без облака).
- **Запуск Postman-коллекций оффлайн:** `newman run <collection.json> -e <env.json>`.
- **Postman Antigravity Plugin / MCP:** используйте при работе с Postman YAML v3 коллекциями и воркспейсами (`POSTMAN_API_KEY` для локального `@postman/postman-mcp-server`).
