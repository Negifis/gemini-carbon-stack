# Gemini Carbon Engineering Constitution

Инварианты **Gemini 4 Carbon** в **Antigravity 2.0**. Детали процедур — в `skills/` и контекстных `rules/`.

## 1. Инженерная дисциплина

- Доводите задачу до проверенного результата; устраняйте первопричину, не глушите ошибки и не ослабляйте тесты.
- Меняйте только нужное по задаче, без попутного рефакторинга. Проверяйте `git status --short`; отделяйте факты от гипотез.
- Локальные обратимые действия выполняйте автономно; спрашивайте только перед необратимым/внешним (`git push`, удаление данных, оплата) или при неясных требованиях.

## 2. Безопасность дерева и Windows PowerShell 5.1

- Не трогайте чужие правки. Запрещены `git reset --hard`, `checkout -- .`, `restore .`, `clean -fd` в грязном дереве и голый `git worktree remove` (используйте `carbon-stack worktree-guard`). Параллельную разработку изолируйте (`workspace: "share"|"branch"` или `carbon-stack chip-handoff`).
- Оболочка `run_command` — PowerShell 5.1: без `&&`/`||`, `<<`, `/dev/null` (`$null`) и GNU-утилит (`sed`/`awk`/`head`/`tail`). Закрывайте `stdin` у CLI (`$null | ...`), не пайпьте тесты в `Select-Object`. Для команд вне workspace / с сетью (`git` по внешним worktree, `glab`, `ssh`, `carbon-stack codex-lane review`) сразу передавайте `BypassSandbox=true` без холостых падений.
- Запрещено читать целиком lock-файлы (`package-lock.json`, `uv.lock`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`), артефакты сборки (`dist/`, `build/`, `.next/`, `node_modules/`, `.venv/`, `target/`), бинарники и дампы БД.
- Ищите символьно (`serena`: `get_symbols_overview`, `find_symbol`, `find_referencing_symbols`) и точечно (`tokenade skeleton`/`query`, `carbon-stack code-search`, `git grep -n`), читайте узкие диапазоны (`StartLine`/`EndLine`), не перечитывайте неизменённые файлы. Не открывайте превентивно смежные `SKILL.md` или пакетные `AGENTS.md` чужих подпапок, не читайте залпом по `4–8` файлов `[1-800]` и не нарезайте `steps/*/output.txt` через `read_file` (сжимайте вывод через `tokenade wrap` / `tokenade exec`). Модели `Gemini Flash` запрещены — используйте `Gemini 4 Neon` (`low..xhigh`) для сложных билдеров/отладки и `Gemini 4 Hydrogen` (`low..xhigh`) для быстрых/механических задач.

## 3. Оркестрация и контекст

- Работайте в штатном Orchestrator (`Plan <-> Execute`). Для понятных follow-up задач сразу передавайте краткий план в `exit_plan_mode`, чтобы чтение и правку сделал исполнитель. При поиске шире `2–3` файлов или в незнакомой подсистеме сразу делегируйте разведку в `invoke_subagent` (`code-explorer`/`research` с кратким ответом `path:line-range`), а проверку живого UI — в `browser` на `Gemini 4 Hydrogen`.
- Для многосессионного handoff используйте компактный `carbon-stack continuity handoff` (без копирования исходников и логов).
- **Swarm 2.0:** при `3+` подсистемах или параллельных правках загружайте `swarm-orchestration`, делите файлы через `carbon-stack swarm-ctl` (или `worktree`), храните отчёты в `.swarm/artifacts/*.md` (`<= 12` строк в `board.jsonl`) и читайте доску с курсором (`since=<id>`).
- **Конечный пайплайн гейта на `HIGH`/`XHIGH` (`Nothing wraps it in another loop`, логика `claude-code-stack` + эмпирические лимиты 80% Pareto по чатам стека, максимум `1 + 4 + 2 = 7` раундов и `MAX_REDESIGN_RESETS = 1`):** тесты -> `simplify` **строго 1 раз до ревью** (`SIMPLIFY_LENS: ALL` если `<= 2` ф. и `<= 30` ст., иначе 3 линзы; совещательный проход `MAX_SIMPLIFY_PASSES = 1` без повторных прогонов, пакетный `kill` воркеров) -> `carbon-stack codex-lane review` (`1..4` раунда в одной сессии, `MAX_REVIEW_ROUNDS = 4`, порог блокировки строго `CRITICAL`/`HIGH`, Раунды `2..4` проверяют только `interdiff` + открытые блокеры на замороженном скоупе). `VERDICT: APPROVED` на любом раунде `1..4` **мгновенно закрывает гейт** (`[gate] verified: HIGH|XHIGH; ...`) без повторного `simplify` и без `--closure`. Только при `Round 4: ESCALATE` выполняется **один** фокусный проход исследования по докам/Context7/вебу: при `REMEDIATE` — до **2 проходов** (`MAX_CLOSURE_PASSES = 2`) `carbon-stack codex-lane review --closure` в той же сессии по дельте (`CLOSURE_VALIDATION: READY` -> `pr-ready`/`verified`; 2-й `BLOCKED` -> **терминальный `[gate] draft-blocked`**); при архитектурном `REDESIGN` — максимум **1 конечный `carbon-stack codex-lane redesign-reset`** на кандидата с обнулением раундов и чистой сессией ревьюера (повторный сброс запрещён).

## 4. Code Work Gate (по риску компонентов и операции, не по числу строк)

- `NO_CHANGE`: завершается без `[gate]`.
- `OPERATIONAL` (мутация shell без правки файлов проекта): `[gate] operational: <предпроверка>; <эффект>` (или `[gate] no-change: <причина>`).
- `PERSISTENT` (правка файлов; квитанция — последняя строка):
  - `LOW` (доки/заметки/статика): проверка содержимого -> `[gate] verified: LOW; <итог>`.
  - `STANDARD` (обычный код, скрипты, UI, аддоны): локальные проверки/тесты после правки (если применимы), без авто-`swarm`/ревью -> `[gate] verified: STANDARD; <кандидат и проверки>`.
  - `HIGH`/`XHIGH` (auth/crypto/секреты/права, миграции, CI/CD, хуки/манифесты плагина/`rust/src/**`/`bin/carbon-stack*`, `.agents/carbon-gate.json`): линейный конечный гейт (`MAX_TOTAL_GATE_ROUNDS = 7`, `MAX_REDESIGN_RESETS = 1`): тесты -> `simplify` **1 раз до ревью** (`SIMPLIFY_LENS: ALL` Fast-Path при `<= 2` ф. и `<= 30` ст., иначе 3 раздельные линзы `claude-sonnet-5-5-high` / fallback `gemini-4-neon-xhigh`, вторичный резерв `gemini-4-hydrogen-xhigh`; `MAX_SIMPLIFY_PASSES = 1`; пакетный `kill`) -> тесты при правках -> `carbon-stack codex-lane review` (`1..4` раунда в одной сессии, порог `CRITICAL`/`HIGH`, Раунды `2..4` только по `interdiff`; эскалация на `claude-opus-5-5-high` -> `gemini-4-neon-xhigh` [`HIGH`] / `gemini-4-carbon-high` [`XHIGH`] только при сбое). `VERDICT: APPROVED` сразу завершает работу (`[gate] verified: HIGH|XHIGH; ...`). При `Round 4: ESCALATE` — 1 фокусное исследование: `REMEDIATE` в текущей сессии (`<= 2` проходов `--closure`: `READY` -> `pr-ready`/`verified`, 2-й `BLOCKED` -> терминальный `[gate] draft-blocked`), либо при архитектурном `REDESIGN` — максимум 1 `redesign-reset` с обнулением раундов и чистой сессией ревьюера.

## 5. Общение и код

- Русский язык; перед сложной задачей обозначьте подход. Во время работы пишите в чат только при значимых открытиях/смене курса/блокерах; в конце — результат, проверки и ограничения.
- В коде комментируйте только инварианты (`INVARIANT:`, `SAFETY:`, `WORKAROUND:`).
