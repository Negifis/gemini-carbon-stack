---
name: code-graph-intelligence
description: "4-layer code discovery (rg, tokenade, codebase-memory, serena/bsl-ls) for architecture and blast radius."
---

# Code Graph Intelligence (CBM + Lens + Serena + Tokenade)

Используйте этот протокол при исследовании архитектуры больших репозиториев (Charon и др.), поиске сквозных процессов, анализе влияния изменений (blast radius) и планировании рефакторинга.

## 1. Иерархия выбора инструмента (без дублирования)

| Слой | Инструмент | Когда выбирать |
| :--- | :--- | :--- |
| **L0** | `carbon-stack code-search` (`rg`) | Точные строки, тексты ошибок, env-переменные, конфиги |
| **L1** | `tokenade map \| skeleton \| query \| impact \| semantic` | Быстрая структура каталога, сигнатуры файлов, 1-hop file impact, локальный семантический поиск |
| **L2** | **`codebase-memory` MCP (`CBM`)** | Call graph (1–15 хопов), `detect_changes` (blast radius + risk), кросс-сервисные `HTTP`/`gRPC`/`GraphQL`/`async` вызовы, инфра-топология (`Docker`/`K8s`/`HCL`/`SQL`/`CI`), Cypher-запросы |
| **L3** | **`serena` MCP** / **`bsl-ls` MCP** | Компиляторная точность для **Dart/Flutter** (нет Hybrid LSP в CBM), сложных дженериков, `get_diagnostics_for_file`; `bsl-ls` — для **1С/BSL** |
| **L2.5** | **`ast-grep` CLI** | Структурный поиск по AST и безопасные массовые codemod-замены |

## 2. Стандартный рабочий цикл `codebase-memory`

1. **Проверка индекса:** вызовите `list_projects` / `index_status`.
2. **Индексация (безопасно на Windows):**
   - Убедитесь, что в корне монорепо есть `.cbmignore` (исключающий `node_modules/`, `build/`, `.dart_tool/`, `target/`, `codex-worktrees/`, тяжёлые бинарники/медиа).
   - Для крупных репозиториев вызывайте `index_repository(repo_path="<path>", async=true)` и проверяйте готовность через `index_repository(repo_path="<path>", status=true)`.
   - Если CLI-индексация возвращает ошибку блокировки SQLite, не убивайте чужой процесс — подождите завершения запроса и повторите.
3. **Архитектурная разведка:**
   - Обзор модулей, кластеров и точек входа: `get_architecture`.
   - Поиск символов/маршрутов по графу: `search_graph`.
   - Сквозная трассировка (например, в Charon: `panel`/`messenger`/`mobile-flutter` → `backend` API → `Bitrix`/`WeChat`/`Telegram` коннекторы → `license-server`/`update-agent`/`Nomad`): `trace_path` (`mode`: `calls`, `data_flow`, `cross_service`, `topology`, `deploy`, `run`).
   - Произвольные структурные запросы: `get_graph_schema` → `query_graph` (Cypher).
4. **Анализ влияния до и после правок (Blast Radius):**
   - Запустите `detect_changes` по текущему `git diff` или целевой ветке: получите список затронутых вызывающих функций, риски и покрытие тестами.
   - Для сравнения архитектуры между ветками/снимками используйте `compare_graphs`.

## 3. Визуальная инспекция в CBM Lens

Если пользователю или команде нужна интерактивная 3D-карта модулей, циклов, hotspots или просмотр маршрутов поверх той же SQLite-БД без повторной индексации:
```powershell
$null | codebase-memory-mcp daemon start --open --port=9749
```
Управление: `codebase-memory-mcp daemon status` / `daemon stop` (локальный loopback `http://127.0.0.1:9749`).

## 4. Интеграция со Swarm 2.0

- Скауты (`code-explorer`, `repo-architect-scout`) обязаны использовать `codebase-memory` + `tokenade` до чтения исходников целиком и передавать координатору непересекающиеся срезы `owned_paths` на основе реального графа зависимостей.
- Перед запуском `test-author` передавайте ему затронутые узлы из `detect_changes`, чтобы тесты закрывали реальный blast radius.
