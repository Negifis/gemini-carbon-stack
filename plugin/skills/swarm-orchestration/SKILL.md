---
name: swarm-orchestration
description: Swarm 2.0 three-phase orchestration (Scout Swarm, Disjoint Builder Swarm, Asymmetric Verification Gate), Warm Pool reuse, Pointer-on-Board, and File Ownership Guard via carbon-stack swarm-ctl.
---

# Swarm 2.0 Orchestration Playbook

Трёхфазный конвейер роя для параллельной разведки, бесконфликтной разработки и экономной верификации.

## 1. Инварианты Swarm 2.0

- **Согласованность участников и авто-проброс инструментов:** каждый бриф воркера (скаута, билдера, ревьюера, арбитра) обязан включать краткий **`BUSINESS_INTENT`** (исходная цель пользователя, обязательные возможности и критерии успеха) и явно перечислять релевантные домену установленные плагины, MCP-серверы, скиллы и веб-поиск (`search_web`/`exa`/`tokenade search`) — без ожидания напоминания пользователя. Все замечания оцениваются относительно `BUSINESS_INTENT`, а не локальных вкусов отдельного воркера.
- **Pointer-on-Board (`<= 12` строк в `board.jsonl`):** объёмные отчёты скаутов и дифф-разборы сохраняются в `.swarm/artifacts/<worker>-<round>.md`; на доску публикуется выжимка до 12 строк + путь к артефакту.
- **Cursor Guard:** при `> 15` сообщениях на доске повторный `read_board` обязан передавать `since=<last_seen_id>` (или используйте `.\plugin\bin\carbon-stack.exe swarm-ctl board summary --since <id> --session <sid> --cwd <repo>`).
- **Warm Pool & Batch Kill:** не пересоздавайте ревью-/билдер-воркеров на каждый фикс — будите живых `waiting` воркеров через `post_message` `@mention`. Пакетное `swarm(action="kill", ...)` для simplify-воркеров выполняется сразу после единственного прохода перед переходом к ревью (`MAX_SIMPLIFY_PASSES = 1` на весь кандидат).
- **Stall Watchdog:** `in_flight` воркер без сообщений и активности в `.swarm/` дольше `SWARM_STALL_TIMEOUT_SEC` (по умолчанию `240` с) диагностируется `[Swarm Stall Watchdog]` вместо немого ожидания.

## 2. Асимметричная матрица моделей

| Фаза / Роль | Модель / Контур | Назначение |
| :--- | :--- | :--- |
| **Координатор** | `Orchestrator (Neon)` (`gemini-pro-orchestrator-neon`) | Декомпозиция, владение файлами, слияние, гейт |
| **Фаза 1 — Scout Swarm (стандарт)** | `gemini-4-hydrogen-medium` / `-high` (`code-explorer`, `gitlab-delivery-analyst`) | Параллельное исследование 3+ подсистем/5+ файлов, сбор контекста issues/MR/CI из `gitlab.lemnos.ru` |
| **Фаза 1 — Architect / Debugger / SRE** | `gemini-4-neon-high` / `-xhigh` (`repo-architect-scout`, `root-cause-debugger`, `infra-sre-diagnostician`) | Граф зависимостей (`codebase-memory`), межмодульные контракты/перфоманс, глубокая корневая отладка, RO-диагностика инцидентов (Proxmox/K8s/Nomad/Zabbix/Grafana/БД/Trivy) |
| **Фаза 2 — Simple Disjoint Builders** | `gemini-4-hydrogen-medium` / `-high` | Простые/механические `owned_paths`, массовые правки без сложной архитектуры |
| **Фаза 2 — Complex / UI / Tests** | `gemini-4-neon-medium`..`-xhigh` (`frontend-ui-builder`, `test-author`, сложные модули) | Сложная логика в `owned_paths`/`worktree`, UI-to-Code по макетам/скриншотам, юнит-/регрессионные тесты |
| **Фаза 3a — Simplify (`<= 2` ф. и `<= 30` ст.)** | 1 воркер `claude-sonnet-5-5-high` (`SIMPLIFY_LENS: ALL`) | Консультативная полировка 1 раз ДО ревью (`MAX_SIMPLIFY_PASSES = 1`; fallback `gemini-4-neon-xhigh`, резерв `gemini-4-hydrogen-xhigh`) |
| **Фаза 3a — Simplify (`> 2` ф. или `> 30` ст.)** | 3 линзы `claude-sonnet-5-5-high` (`REUSE`, `QUALITY`, `EFFICIENCY`) | Консультативная параллельная полировка 1 раз ДО ревью (`MAX_SIMPLIFY_PASSES = 1`) |
| **Фаза 3b — Independent Logic Review** | `carbon-stack codex-lane review` (fallback `claude-opus-5-5-high` -> `gemini-4-neon-xhigh` [`HIGH`] / `gemini-4-carbon-high` [`XHIGH`]) | `1..4` раунда в одной сессии (`MAX_REVIEW_ROUNDS = 4`, `BLOCKING_THRESHOLD = HIGH`); `VERDICT: APPROVED` **немедленно закрывает гейт** |
| **Фаза 3c — Escalation Closure *(только при `Round 4: ESCALATE`)* ** | `carbon-stack codex-lane review --closure` | 1 проход исследования + до 2 попыток `CLOSURE_VALIDATION: READY` (2-й `BLOCKED` -> `[gate] draft-blocked`) |

## 3. Трёхфазный протокол

### Фаза 1 — Scout Swarm (Разведка)
Запускается при исследовании `3+` подсистем или `5+` незнакомых файлов:
1. Назначьте скаутам разные зоны (`scout-<zone>`) и запретите правки файлов.
2. Обяжите использовать 4-слойную навигацию (`code-search` → `tokenade` → `codebase-memory` для графа/blast radius → `serena`/`bsl-ls` для LSP) вместо чтения длинных файлов целиком; для GitLab-контекста выделяйте `gitlab-delivery-analyst`, для инфра-инцидентов — `infra-sre-diagnostician`.
3. Каждый скаут пишет полный разбор в `.swarm/artifacts/scout-<zone>.md` и постит краткую сводку на доску.

**Шаблон промпта скаута:**
```text
Роль: Read-only Scout зоны `<zone>` (`<paths_or_globs>`).
Инструменты: приоритетно `serena` (`get_symbols_overview`, `find_symbol`) и `rg`. Не правь код.
Вывод: сохрани детальный разбор в `.swarm/artifacts/scout-<zone>-1.md`. На доску отправь `@coordinator` (строго <=12 строк): ключевые символы, инварианты, риски и путь `.swarm/artifacts/scout-<zone>-1.md`.
```

### Фаза 2 — Disjoint Builder Swarm (Разработка)
Запускается при параллельной реализации независимых модулей:
1. Разделите зоны ответственности **без пересечений** перед спавном воркеров:
   ```powershell
   $null | .\plugin\bin\carbon-stack.exe swarm-ctl ownership set --worker builder-a --paths "src/api/**" --cwd <repo>
   $null | .\plugin\bin\carbon-stack.exe swarm-ctl ownership set --worker builder-b --paths "tests/api/**" --cwd <repo>
   ```
   При необходимости менять пересекающиеся модули или гонять конфликтующие тесты изолируйте воркеров через worktree:
   ```powershell
   $null | .\plugin\bin\carbon-stack.exe swarm-ctl worktree create --worker builder-a --cwd <repo>
   ```
2. `safety_guards.rs` автоматически блокирует любые `edit_file` / `write_file` / shell-записи воркера за пределами его `owned_paths` (артефакты `.swarm/artifacts/**` разрешены всегда).
3. По завершении проверьте чистоту границ и очистите worktree:
   ```powershell
   $null | .\plugin\bin\carbon-stack.exe swarm-ctl ownership verify-git-diff --strict --cwd <repo>
   $null | .\plugin\bin\carbon-stack.exe swarm-ctl worktree cleanup --cwd <repo>
   $null | .\plugin\bin\carbon-stack.exe swarm-ctl ownership clear --cwd <repo>
   ```

**Шаблон промпта билдера:**
```text
Роль: Disjoint Builder `<name>`.
Разрешённые файлы: `<owned_globs>` (или worktree `<worktree_path>`). Запрещено править файлы вне зоны.
Задача: <конкретное изменение и локальный тест>.
Вывод: лог/детали в `.swarm/artifacts/<name>-1.md`. На доску `@coordinator` (<=12 строк): список изменённых файлов, результат теста, путь к артефакту.
```

### Фаза 3 — Finite Verification Gate (`UNITTEST -> SIMPLIFY (1) -> KILL -> REVIEW (1..4) -> APPROVED`)
1. Прогоните локальные тесты проекта (например, `$null | cargo test --manifest-path rust/Cargo.toml`, `pytest`, `npm test` или `flutter test`).
2. Подготовьте дифф-метрики ДО ревью: `.\plugin\bin\carbon-stack.exe swarm-cache prepare --session <sid> --cwd <repo> --label simplify`.
   - Если `fast_path_eligible == true` (`<= 2` файлов и `<= 30` строк `additions + deletions`), запустите 1 воркер `simplify-reviewer` (`SIMPLIFY_LENS: ALL`).
   - Иначе запустите 3 параллельные линзы (`reuse`, `quality`, `efficiency`).
   - При правках по `ACTIONABLE_FIXES` перезапустите тесты без повторного запуска `simplify` (`MAX_SIMPLIFY_PASSES = 1` на весь кандидат).
3. Выполните пакетный `swarm(action="kill", ...)` всех `waiting` simplify-воркеров сразу перед запуском ревью.
4. Запустите `carbon-stack codex-lane review --session <sid> --intent "<бизнес-цель и принятые возможности>" --summary "..."` (`1..4` раунда в одной сессии, `MAX_REVIEW_ROUNDS = 4`, `BLOCKING_THRESHOLD = HIGH`, Раунды `2–4` получают только `interdiff` + открытые блокеры + реестр отклонённых замечаний `dispose`). Замечания, противоречащие `BUSINESS_INTENT` или не дающие практической пользы (Класс C/D), обоснованно фиксируйте через `carbon-stack codex-lane dispose --session <sid> --cwd <repo> --finding "..." --category intent-conflict|accepted-risk|no-practical-gain|deferred-improvement --reason "..."` (анти-бумеранг). **`VERDICT: APPROVED` на любом раунде `1..4` сразу закрывает гейт** (`[gate] verified: HIGH|XHIGH; ...`) без повторного `simplify` и без `--closure`. Только при `Round 4: ESCALATE` выполните однократный проход исследования (`REMEDIATE`/`REDESIGN`) и до 2 попыток `--closure` (`READY` -> `verified`/`pr-ready`; 2-й `BLOCKED` -> финальный `[gate] draft-blocked`).
5. **Условный Design Gate *(только при правке визуальных UI/дизайн-файлов)*:** после скриншотов в браузере (desktop+mobile, light/dark) запустите независимых read-only критиков (`visual-design-critic` + `ux-adversarial-auditor` или `visual-qa-reviewer`) с явным доступом к `search_web`/`exa`/`tokenade search`, `mobbin_mobbin`, `modern-web-guidance` и `critique-*` до `VISUAL_REVIEW_VERDICT: APPROVED` (и `UX_REVIEW_VERDICT: APPROVED`).

**Шаблон тёплого воркера simplify (`REUSE|QUALITY|EFFICIENCY` или `ALL`):**
```text
Read-only аудит линзы `<LENS>` для `<incremental_diff_path>` (или `<paths>`). Код не менять.
Учитывай BUSINESS_INTENT: <цель пользователя>. Не предлагай убирать запрошенную функциональность.
Детали пиши в `.swarm/artifacts/<worker>-r<N>.md`. Ответ в `board.jsonl` завершай строками:
DIFF_HASH: <current_diff_hash>
SIMPLIFY_LENS: <REUSE|QUALITY|EFFICIENCY|ALL>
SIMPLIFY_VERDICT: <CLEAN|ACTIONABLE_FIXES>
```
