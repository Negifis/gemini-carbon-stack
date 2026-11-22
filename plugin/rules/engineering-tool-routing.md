---
trigger: model_decision
description: "Auto-load for GitLab, architecture/impact analysis, UI/browser QA, API tests, SRE/DB/infra, 1C/BSL, Bitrix24, Jira, diagrams, or OSS/data research."
---

# Engineering Tool Capability Router

Выбирайте инструмент автоматически по домену задачи. Все MCP подключены с `"eager": false`: перед первым `call_mcp_tool` читайте схему тула в `<appDataDir>/mcp/<server>/<tool>.json` (см. `~/.gemini/reference/environment.md`).

| Домен | Основной инструмент (и fallback) | Протокол |
|---|---|---|
| **Архитектура, граф, blast radius** | L0 `carbon-stack code-search` (`rg`) → L1 `tokenade` → L2 `codebase-memory` (`get_architecture`, `trace_path`, `detect_changes`, `query_graph`) → L3 `serena` (Dart/дженерики) / `bsl-ls` (1С) / `ast-grep` | Скилл `code-graph-intelligence` |
| **GitLab (`gitlab.lemnos.ru`)** | `gitlab` MCP (`core` + `discover_tools`) + `glab` CLI (длинные job-логи и диффы) | Скилл `gitlab-workflow` |
| **UI/UX и браузерный QA** *(только UI)* | До вёрстки: `modern-web-guidance-plugin` + `mobbin` (`mobbin_mobbin`) + `frontend-design`, `ui-design-system`, `ui-critique`, `accessibility-audit`, `responsive-design` (`vercel-react-best-practices`/`shadcn-ui`/`figma`). После: `browser` (`Hydrogen` + `BROWSER_HOST_FACTS`), `playwright`, `chrome-devtools`, `odiff`, read-only `visual-qa-reviewer` (`VISUAL_REVIEW_VERDICT: APPROVED`) | Скилл `uiux-and-browser-qa`, правило `uiux-design.md` |
| **API / OpenAPI тестирование** | `hurl`, `schemathesis`, `newman` | Скилл `enterprise-1c-bitrix-jira` |
| **Инфра, DevOps, БД, AppSec (RO-first)** | Активные: `trivy` MCP, `semgrep` MCP, `nomad` CLI, `duckdb` MCP. RO-профили (`mcp-gate.env`): `kubernetes`, `grafana`, `nomad`, `proxmox`, `zabbix`, `mssql`, `ssh` (`postgres` — `@bytebase/dbhub` `search_objects`/`execute_sql`, по умолчанию отключён) | Скилл `infra-sre-ops` |
| **Bitrix24, 1С/BSL, Jira DC / JSM** | `b24-dev-mcp` + `bitrix24`; `bsl-ls` MCP + `bsl-language-server` + `v8std` + `1c-syntax-helper`; `atlassian` MCP | Скилл `enterprise-1c-bitrix-jira` |
| **Диаграммы** | `drawio-skill` + `draw.io.exe` v32+, либо editorial SVG через `diagram-design` | Скиллы `drawio-skill`, `diagram-design` |
| **Доки, память и веб-поиск** | `deepwiki`, `context7`, `exa` → `tokenade search`/`fetch`, `duckdb`; память: `nlm-memory` + `carbon-stack carbon-memory` | Скиллы `current-docs`, `project-memory` |

## Инварианты поведения

1. Проверяйте blast radius перед крупной правкой (`tokenade impact` / `codebase-memory` `detect_changes` / `rg`).
2. Для Charon/GitLab собирайте контекст issues/MR/pipelines через `gitlab` MCP и архитектуру через `codebase-memory`.
3. В инфре и БД начинайте строго с read-only; мутации — только с явного подтверждения.
4. При нехватке инструмента проверьте `search_marketplace`, `exa` и `deepwiki` до костылей.
