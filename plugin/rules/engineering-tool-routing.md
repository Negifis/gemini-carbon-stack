---
trigger: model_decision
description: "Auto-load when working with GitLab (gitlab.lemnos.ru), codebase architecture/impact analysis, frontend/browser QA, API testing, infrastructure/DevOps/DBs (Proxmox, K8s, Nomad, Zabbix, Grafana, Docker, PG/MSSQL, Trivy), 1C/BSL, Bitrix24, Jira/JSM, architectural diagrams, or data/OSS research."
---

# Engineering Tool Capability Router

Выбирайте инструмент автоматически по домену задачи, без просьбы пользователя. Все MCP подключены лениво (`eager: false`): перед первым вызовом `call_mcp_tool` читайте `.json`-схему тула из `<appDataDir>/mcp/<server>/<tool>.json` (каталог `<appDataDir>` берётся из системного контекста текущего клиента: IDE — `~/.gemini/antigravity/mcp`, CLI — `~/.gemini/antigravity-cli/mcp`).

| Домен / ситуация | Основной инструмент (и fallback) | Подробный протокол |
| :--- | :--- | :--- |
| **Архитектура, граф вызовов, blast radius** | L0 `code-search` (`rg`) → L1 `tokenade` → L2 **`codebase-memory`** (`get_architecture`, `trace_path`, `detect_changes`, `query_graph`, + **CBM Lens**) → L3 `serena` (Dart/Flutter, дженерики) / `bsl-ls` (1С) / `ast-grep` CLI | Скилл `code-graph-intelligence` |
| **GitLab (`gitlab.lemnos.ru`)** | **`gitlab` MCP** (`@zereight/mcp-gitlab`: `core` + `discover_tools` для `pipelines`/`workitems`/`variables`/`releases`; для `execute_graphql` нужен `GITLAB_TOOLS`) + **`glab` CLI** (длинные job-логи и большие диффы) | Скилл `gitlab-workflow`, агент `gitlab-delivery-analyst` |
| **UI/UX, дизайн, браузерный QA и перфоманс** | **До/во время вёрстки:** `modern-web-guidance-plugin` (`npx.cmd -y modern-web-guidance@latest search\|retrieve`, скилл `modern-web-guidance`) + **`mobbin`** (`mobbin_mobbin` MCP: `search_screens`/`search_flows`/`search_sections`/`list_collections`/`get_collection_contents` + скиллы `best-practices`/`search`/`redesign-screen`/`plain-writing`) + `frontend-ui-builder` + `frontend-design`, `critique-*`, `web-design-guidelines`, `accessibility-audit`, `responsive-design` (`vercel-*`/`shadcn-ui`/`taste-design`/`figma` по стеку). **После:** реальные скриншоты (`browser` на `Hydrogen` + `BROWSER_HOST_FACTS`, `playwright`, `chrome-devtools` `get_css_styles`/`lighthouse_audit`/`performance_start_trace`, `odiff`) + независимое read-only состязательное визуальное ревью (`visual-qa-reviewer` / `visual-design-critic` + `ux-adversarial-auditor` с веб-поиском и `mobbin_mobbin`) до `VISUAL_REVIEW_VERDICT: APPROVED` *(строго только для UI/дизайн-файлов — 0 накладных расходов вне UI)* | Скилл `uiux-and-browser-qa`, правило `uiux-design.md` |
| **API и OpenAPI тестирование** | Локально без облака: **`hurl`** (`.hurl` сценарии), **`schemathesis`** (фаззинг OpenAPI), **`newman`** (Postman JSON); при наличии аккаунта — Postman plugin/MCP | Скилл `enterprise-1c-bitrix-jira` |
| **Инфра, DevOps, БД, AppSec (RO-first)** | **Активны сейчас:** **`trivy` MCP** (SCA/IaC/SBOM/secrets) + `semgrep` MCP (SAST) + `nomad` CLI (`nomad job validate`) + `duckdb` MCP (SQL по логам). **RO-профили (через `mcp-gate.env`):** `kubernetes`, `grafana` (Grafana+Prom+Loki+Alloy+Blackbox), `nomad`, `proxmox`, `zabbix`, `postgres` (`dbhub`), `mssql`, `ssh` | Скилл `infra-sre-ops`, агент `infra-sre-diagnostician` |
| **Bitrix24, 1С/BSL, Jira DC / JSM** | **Bitrix24:** `b24-dev-mcp` (доки) + `bitrix24` (`b24_call`/`b24_batch`). **1С/BSL:** `bsl-ls` MCP (10 тулов) + `bsl-language-server analyze` + `v8std` + `1c-syntax-helper`. **Jira DC (`jira.lemnos.ru`):** `atlassian` MCP (RO + JSM) | Скилл `enterprise-1c-bitrix-jira` |
| **Редактируемые диаграммы** | Primary: `drawio-skill` + локальный `drawio` CLI (`draw.io.exe` v32+, оффлайн PNG/SVG/PDF + self-check); code-first для git: **`d2` CLI**; editorial SVG: `diagram-design` | Скиллы `drawio-skill`, `diagram-design` |
| **Исследования и аналитика данных** | **`deepwiki` MCP** (архитектура публичных GitHub-репо), `context7` (доки библиотек), `exa` → `tokenade search`/`fetch`, **`duckdb` MCP** (`execute_query` по CSV/Parquet/JSON/NDJSON/логам), `memory` + `carbon-memory` + `notebooklm-mcp` | Глобальный гейт `GEMINI.md` |

## Инварианты поведения

1. **Авто-подтягивание плагинов, MCP и скиллов без напоминания пользователя:** при старте любой доменной задачи самостоятельно сверьте её домен с установленными плагинами, `<mcp_servers>` и `<skills>` (не читая лишние `SKILL.md` вне домена). При делегировании в `swarm` / `invoke_subagent` явно пробрасывайте в бриф воркеров релевантные плагины, MCP, скиллы и веб-поиск (`search_web`/`exa`/`tokenade search`).
2. **Перед правкой крупного кода** проверьте blast radius (`codebase-memory` `detect_changes` / `tokenade impact`).
3. **При задачах по Charon / GitLab** самостоятельно соберите контекст связанных issues/work items/MR/pipelines через `gitlab` MCP и архитектуру через `codebase-memory`.
4. **Для инфры и БД** начинайте строго с read-only; любые мутации продакшн-инфраструктуры или БД — только после явного подтверждения пользователя.
5. **При нехватке инструмента** проверьте `search_marketplace`, `exa` и `deepwiki` перед обходными костылями.
