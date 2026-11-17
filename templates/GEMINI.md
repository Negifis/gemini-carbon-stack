# Gemini Carbon Global Context (Antigravity 2.0)

Тонкие глобальные инварианты экономии контекста, безопасности дерева и маршрутизации моделей. Детальные регламенты загружаются прогрессивно из `skills/` и контекстных `rules/`.

## 1. Гигиена контекста и чтения файлов

- Запрещено читать целиком lock-файлы (`package-lock.json`, `uv.lock`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`), директории сборки и зависимостей (`dist/`, `build/`, `.next/`, `node_modules/`, `.venv/`, `target/`), бинарники и дампы БД.
- Вместо чтения длинных файлов целиком используйте символьную LSP-навигацию (`serena`: `get_symbols_overview`, `find_symbol`, `find_referencing_symbols`), `tokenade skeleton` / `tokenade query`, `code_search.py` или `git grep -n`, затем читайте узкие диапазоны (`StartLine`/`EndLine`).
- Не перечитывайте неизменённые файлы в рамках одной сессии.

## 2. Делегирование и маршрутизация моделей

- Объёмный ресерч по репозиторию делегируйте в `invoke_subagent` (`code-explorer` / `research`), а проверку живого веб-интерфейса — в субагент `browser` на `Gemini 4 Hydrogen`.
- Модели `Gemini Flash` запрещены — используйте `Gemini 4 Hydrogen` (`low..xhigh`). Овердрафт кредитов (`useG1Credits`) отключён (`false`).
- Для **Swarm 2.0** (разведка `3+` подсистем, параллельные билдеры, гейт) подключайте скилл `swarm-orchestration`: `swarm_ctl.py` для непересекающихся `owned_paths`/`worktree`, `.swarm/artifacts/*.md` (`<= 12` строк на доске) и `read_board(since=<id>)`.
- Верификация `HIGH`/`XHIGH` идёт по порядку `unittest -> codex_lane.py review -> simplify (ALL при <=2 ф. и <=30 ст.) -> batch kill -> --closure`, с переиспользованием `waiting` воркеров через `@mention`.

## 3. Короткие команды проверок и терминала (PowerShell 5.1)

- Оболочка `run_command` — Windows PowerShell 5.1 (без `&&`/`||`, `<<`, `/dev/null`). Закрывайте `stdin` у CLI (`$null | ...`).
- Тесты и проверки: `python -X utf8 -m unittest discover -s tests -v`, `python -X utf8 install.py --diagnose`, `npx tsc --noEmit`, `npm test` (для шумного вывода используйте `tokenade wrap`).
