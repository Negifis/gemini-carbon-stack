---
name: swarm-orchestration
description: Swarm 2.0 three-phase orchestration (Scout Swarm, Disjoint Builder Swarm, Asymmetric Verification Gate), Warm Pool reuse, Pointer-on-Board, and File Ownership Guard via carbon-stack swarm-ctl.
---

# Swarm 2.0 Orchestration Playbook

Трёхфазный конвейер роя для параллельной разведки, бесконфликтной разработки и экономной верификации.

## 1. Инварианты Swarm 2.0

- **Pointer-on-Board (`<= 12` строк в `board.jsonl`):** объёмные отчёты скаутов и дифф-разборы сохраняются в `.swarm/artifacts/<worker>-<round>.md`; на доску публикуется выжимка до 12 строк + путь к артефакту.
- **Cursor Guard:** при `> 15` сообщениях на доске повторный `read_board` обязан передавать `since=<last_seen_id>` (или используйте `.\plugin\bin\carbon-stack.exe swarm-ctl board summary --since <id> --session <sid> --cwd <repo>`).
- **Warm Pool & Batch Kill:** не пересоздавайте воркеров на каждый фикс — будите живых `waiting` воркеров через `post_message` `@mention` (`validate_warm_worker_verdicts` / `cwg_stop.rs` сверяют вердикт строго по `round_start_msg_id` и `current_diff_hash`). Пакетное `swarm(action="kill", ...)` выполняется один раз перед `--closure`.
- **Stall Watchdog:** `in_flight` воркер без сообщений и активности в `.swarm/` дольше `SWARM_STALL_TIMEOUT_SEC` (по умолчанию `240` с) диагностируется `[Swarm Stall Watchdog]` вместо немого ожидания.

## 2. Асимметричная матрица моделей

| Фаза / Роль | Модель / Контур | Назначение |
| :--- | :--- | :--- |
| **Координатор** | `Orchestrator (Argon)` | Декомпозиция, владение файлами, слияние, гейт |
| **Фаза 1 — Scout Swarm** | `gemini-4-hydrogen-medium` / `-high` | Параллельное исследование 3+ подсистем или 5+ файлов |
| **Фаза 2 — Disjoint Builders** | `gemini-4-hydrogen-high` | Реализация непересекающихся `owned_paths` или `worktree` |
| **Фаза 3a — Primary Logic Review** | `carbon-stack codex-lane review` (fallback `claude-opus-5-5-high` -> `gemini-4-carbon-high`) | Проверка логики и багов ДО `simplify` |
| **Фаза 3b — Simplify (`<= 2` ф. и `<= 30` ст.)** | 1 воркер `claude-sonnet-5-5-high` (`SIMPLIFY_LENS: ALL`) | Fast-Path (fallback `gemini-4-hydrogen-xhigh`) |
| **Фаза 3b — Simplify (`> 2` ф. или `> 30` ст.)** | 3 линзы `claude-sonnet-5-5-high` (`REUSE`, `QUALITY`, `EFFICIENCY`) | Параллельная полировка один раз после `APPROVED` |
| **Фаза 3c — Final Closure** | `carbon-stack codex-lane review --closure` | Финальное подтверждение `CLOSURE_VALIDATION: READY` |

## 3. Трёхфазный протокол

### Фаза 1 — Scout Swarm (Разведка)
Запускается при исследовании `3+` подсистем или `5+` незнакомых файлов:
1. Назначьте скаутам разные зоны (`scout-<zone>`) и запретите правки файлов.
2. Обяжите использовать `serena` LSP (`get_symbols_overview`, `find_symbol`, `find_referencing_symbols`) вместо чтения длинных файлов целиком.
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

### Фаза 3 — Verification Gate (`UNITTEST -> REVIEW -> SIMPLIFY -> KILL -> --CLOSURE`)
1. Прогоните локальные тесты проекта (например, `$null | cargo test --manifest-path rust/Cargo.toml`, `pytest`, `npm test` или `flutter test`).
2. Запустите первичный `carbon-stack codex-lane review --session <sid> --summary "..."`; закройте функциональные замечания (`REVISE` -> фикс -> тест -> повторный `review` до `APPROVED`).
3. Подготовьте дифф-метрики: `.\plugin\bin\carbon-stack.exe swarm-cache prepare --session <sid> --cwd <repo> --label simplify`.
   - Если `fast_path_eligible == true` (`<= 2` файлов и `<= 30` строк `additions + deletions`), запустите 1 воркер `simplify-reviewer` (`SIMPLIFY_LENS: ALL`).
   - Иначе запустите 3 параллельные линзы (`reuse`, `quality`, `efficiency`).
   - При последующем раунде будите тех же `waiting` воркеров через `post_message` `@mention` вместо холодного респавна.
4. Перед `--closure` выполните пакетный `swarm(action="kill", ...)` всех `waiting` воркеров (кроме активно продолжающих работу) и закройте гейт через `carbon-stack codex-lane review --session <sid> --closure --summary "..."`.

**Шаблон тёплого воркера simplify (`REUSE|QUALITY|EFFICIENCY` или `ALL`):**
```text
Read-only аудит линзы `<LENS>` для `<incremental_diff_path>` (или `<paths>`). Код не менять.
Детали пиши в `.swarm/artifacts/<worker>-r<N>.md`. Ответ в `board.jsonl` завершай строками:
SIMPLIFY_LENS: <REUSE|QUALITY|EFFICIENCY|ALL>
SIMPLIFY_VERDICT: <CLEAN|ACTIONABLE_FIXES>
```
