---
name: gitlab-workflow
description: "Self-hosted gitlab.lemnos.ru workflows via gitlab MCP (issues, MRs, pipelines) and glab CLI."
---

# GitLab Self-Hosted Workflow (`gitlab.lemnos.ru`)

Протокол полноценной работы с `gitlab.lemnos.ru` (GitLab 19.4.0-ee, REST v4 + GraphQL + KAS) через `gitlab` MCP (`@zereight/mcp-gitlab`) и `glab` CLI.

## 1. Разделение ролей: `gitlab` MCP vs `glab` CLI

- **`gitlab` MCP (`call_mcp_tool(ServerName="gitlab", ...)`):**
  - Стартует в компактном профиле `core` + `discover_tools` (экономит контекст).
  - Работает через `mcp_env_exec.py --gitlab` (`GITLAB_API_URL=https://gitlab.lemnos.ru/api/v4`, `GITLAB_IS_OLD=true`, безопасный дефолт **`GITLAB_PERMISSION_MODE=readonly`**, `GITLAB_MCP_COMPACT_RESULTS=true`). Для write-операций оператор явно задаёт `GITLAB_PERMISSION_MODE=modify` в `mcp-gate.env`.
  - Используйте для чтения: issues, **GraphQL Work Items** (`discover_tools` → `workitems`), MR метаданных/diff/approvals/threads, статуса pipelines/jobs, CI/CD variables, releases, wikis (для `execute_graphql` нужен `GITLAB_TOOLS=execute_graphql` в `mcp-gate.env`, т.к. он не входит в группы `discover_tools`).
  - Для среза больших JSON-ответов передавайте `jmespath` там, где тул поддерживает фильтрацию.
- **`glab` CLI (`run_command`, `$null | glab ...`):**
  - Используйте для потоковых/длинных job-логов (`glab ci trace <job-id> -R <repo>`), больших MR-диффов (`glab mr diff <iid> -R <repo>`) и массовых терминальных выборок.

## 2. Типовые сценарии

1. **Старт задачи по Charon / проекту GitLab:**
   - Найдите связанные issues / work items и открытые MR в проекте (напр. `project_id=78` для Charon или по пути группы/проекта).
   - Проверьте последние дискуссии/комментарии ревью и статус последнего pipeline на целевой ветке.
   - Сопоставьте контекст задачи с графом кода (`codebase-memory`) перед планированием правок.
2. **Диагностика упавшего Pipeline / CI:**
   - Через `gitlab` MCP получите список pipelines и упавших jobs (при необходимости активируйте группу `pipelines` через `discover_tools`).
   - Выгрузите хвост лога проблемного job (через `gitlab` MCP или `glab ci trace`), локализуйте первопричину в коде и проверьте `.gitlab-ci.yml` через CI lint.
3. **Код-ревью и обсуждения MR (read-only по умолчанию):**
   - Получите diff MR, существующие треды (`mr_discussions`) и свяжите затронутые функции с `codebase-memory` (`detect_changes` / `trace_path`) для проверки побочных эффектов.
   - По умолчанию возвращайте структурированный текст замечаний пользователю в чат (в режиме `GITLAB_PERMISSION_MODE=readonly` внешняя запись заблокирована). Публикацию inline-комментариев, тредов, draft notes, создание issues/MR или релизов выполняйте **только по отдельному явному поручению пользователя** (при включённом `GITLAB_PERMISSION_MODE=modify` в `mcp-gate.env`).
4. **Релизы и CI/CD:**
   - Используйте тулы `releases` и `variables` (`discover_tools`), предварительно проверяя список изменений (`git log` / закрытые MR) и не печатая значения защищённых CI-переменных в чат.

## 3. Известные особенности `gitlab.lemnos.ru` (19.4.0-ee)

- Встроенный сервер `/api/v4/mcp` на 19.4.0-ee отклоняет классические PAT / Project Tokens с `401/403` и не поддерживает выбор тулсетов (появляется в 19.5+) — поэтому основным контуром используется `@zereight/mcp-gitlab` с `GITLAB_IS_OLD=true` (`Private-Token`).
- Если текущий токен имеет scope только одного проекта (например, `project_78_bot`), для работы с другими проектами укажите user PAT в `C:\Users\in\.gemini\secrets\mcp-gate.env` как `GITLAB_PERSONAL_ACCESS_TOKEN=...`.
