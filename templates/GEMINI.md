# Gemini Carbon Global Context (Antigravity 2.0)

Тонкие глобальные инварианты экономии контекста, безопасности дерева и маршрутизации моделей. Детальные регламенты загружаются прогрессивно из `skills/` и контекстных `rules/`.

## 1. Гигиена контекста и чтения файлов

- Запрещено читать целиком lock-файлы (`package-lock.json`, `uv.lock`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`), директории сборки и зависимостей (`dist/`, `build/`, `.next/`, `node_modules/`, `.venv/`, `target/`), бинарники и дампы БД.
- Вместо чтения длинных файлов целиком или залпов по `4–8` файлов `[1-800]` используйте символьную LSP-навигацию (`serena`: `get_symbols_overview`, `find_symbol`, `find_referencing_symbols`), `tokenade skeleton` / `tokenade query`, `carbon-stack code-search` или `git grep -n`, затем читайте узкие диапазоны (`StartLine`/`EndLine`).
- Не читайте превентивно посторонние `SKILL.md` и вложенные `AGENTS.md` пакетов, в которых вы не правите код; не нарезайте `steps/*/output.txt` через `read_file` (фильтруйте вывод на месте через `tokenade wrap` / `<cmd> | tokenade exec`) и не перечитывайте неизменённые файлы.

## 2. Делегирование и маршрутизация моделей

- При поиске шире `2–3` файлов или в незнакомой подсистеме делегируйте разведку в `invoke_subagent` (`code-explorer` / `research`, возвращая только краткую выжимку `path:line-range`), а проверку живого веб-интерфейса — в субагент `browser` на `Gemini 4 Hydrogen`.
- Модели `Gemini Flash` запрещены — используйте **`Gemini 4 Neon`** (`low..xhigh`) для сложных билдеров/отладки/UI-to-Code и **`Gemini 4 Hydrogen`** (`low..xhigh`) для быстрых/механических задач (`browser`, `translator`, скауты). Овердрафт кредитов (`useG1Credits`) отключён (`false`).
- Для **Swarm 2.0** (разведка `3+` подсистем, параллельные билдеры, гейт) подключайте скилл `swarm-orchestration`: `carbon-stack swarm-ctl` для непересекающихся `owned_paths`/`worktree`, `.swarm/artifacts/*.md` (`<= 12` строк на доске) и `read_board(since=<id>)`.
- Верификация `HIGH`/`XHIGH` идёт методом бутерброда `tests -> carbon-stack codex-lane review (1..3, эскалация Opus -> Neon XHigh [HIGH] / Carbon [XHIGH]) -> simplify (ALL при <=2 ф. и <=30 ст., fallback Neon XHigh / Hydrogen XHigh) -> batch kill -> --closure (до 2 раундов)`; после 2 `BLOCKED` обязателен режим исследования и `carbon-stack codex-lane research-reset` с запуском новых сессий.

## 3. Короткие команды проверок и терминала (PowerShell 5.1)

- Оболочка `run_command` — Windows PowerShell 5.1 (без `&&`/`||`, `<<`, `/dev/null`). Закрывайте `stdin` у CLI (`$null | ...`).
- Тесты и проверки: `cargo test --manifest-path rust/Cargo.toml`, `.\plugin\bin\carbon-stack.exe install --diagnose`, `npx tsc --noEmit`, `npm test` (для шумного вывода используйте `tokenade wrap`).
