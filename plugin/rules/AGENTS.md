# Gemini Carbon Engineering Constitution

Инварианты **Gemini 4 Carbon** в **Antigravity 2.0**. Детали процедур — в `skills/` и контекстных `rules/`.

## 1. Инженерная дисциплина

- Доводите задачу до проверенного результата; устраняйте первопричину, не глушите ошибки и не ослабляйте тесты.
- Меняйте только нужное по задаче, без попутного рефакторинга. Проверяйте `git status --short`; отделяйте факты от гипотез.
- Локальные обратимые действия выполняйте автономно; спрашивайте только перед необратимым/внешним (`git push`, удаление данных, оплата) или при неясных требованиях.

## 2. Безопасность дерева и Windows PowerShell 5.1

- Не трогайте чужие правки. Запрещены `git reset --hard`, `checkout -- .`, `restore .`, `clean -fd` в грязном дереве и голый `git worktree remove` (используйте `worktree_guard.py`). Параллельную разработку изолируйте (`workspace: "share"|"branch"` или `chip_handoff.py`).
- Оболочка `run_command` — PowerShell 5.1: без `&&`/`||`, `<<`, `/dev/null` (`$null`) и GNU-утилит (`sed`/`awk`/`head`/`tail`). Запускайте `python -X utf8`, закрывайте `stdin` у CLI (`$null | ...`), не пайпьте `unittest` в `Select-Object`. Проверки запускайте компактно (`python -X utf8 -m unittest`, `npx tsc --noEmit`, `tokenade wrap`), сохраняя полный вывод ошибок.
- Запрещено читать целиком lock-файлы (`package-lock.json`, `uv.lock`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`), артефакты сборки (`dist/`, `build/`, `.next/`, `node_modules/`, `.venv/`, `target/`), бинарники и дампы БД.
- Ищите символьно (`serena`: `get_symbols_overview`, `find_symbol`, `find_referencing_symbols`) и точечно (`tokenade skeleton`/`query`, `code_search.py`, `git grep -n`), читайте диапазоны (`StartLine`/`EndLine`), не перечитывайте неизменённые файлы. Модели `Gemini Flash` запрещены — используйте `Gemini 4 Hydrogen` (`low..xhigh`).

## 3. Оркестрация и контекст

- Работайте в штатном Orchestrator (`Plan <-> Execute`). Для понятных follow-up задач сразу передавайте краткий план в `exit_plan_mode`, чтобы чтение и правку сделал исполнитель. Объёмный ресерч репозитория (`code-explorer`/`research`) и проверку живого UI (`browser` на `Gemini 4 Hydrogen`) делегируйте через `invoke_subagent`.
- Для многосессионного handoff используйте компактный `continuity.py handoff` (без копирования исходников и логов).

## 4. Code Work Gate (по риску компонентов и операции, не по числу строк)

- `NO_CHANGE`: завершается без `[gate]`.
- `OPERATIONAL` (мутация shell без правки файлов проекта): `[gate] operational: <предпроверка>; <эффект>` (или `[gate] no-change: <причина>`).
- `PERSISTENT` (правка файлов; квитанция — последняя строка):
  - `LOW` (доки/заметки/статика): проверка содержимого -> `[gate] verified: LOW; <итог>`.
  - `STANDARD` (обычный код, скрипты, UI, аддоны): локальные проверки/тесты после правки (если применимы), без авто-`swarm`/ревью -> `[gate] verified: STANDARD; <кандидат и проверки>`.
  - `HIGH`/`XHIGH` (auth/crypto/секреты/права, миграции, CI/CD, хуки/манифесты плагина/`install.py`, `.agents/carbon-gate.json`): строго последовательно: 1) тесты -> 2) 3 раздельные линзы `simplify` (`claude-sonnet-5-5-high`, fallback при исчерпании квоты Sonnet строго на `gemini-4-hydrogen-xhigh` через `swarm`, никогда не на Carbon; дождаться их полного завершения до старта ревью, никогда параллельно с ревью) -> 3) свежее независимое `VERDICT: APPROVED` (приоритет всегда `codex_lane.py review`; только при подтверждённой недоступности Codex — эскалация на внутренний `claude-opus-5-5-high` -> `gemini-4-carbon-high` при сбое Opus) -> `[gate] verified: HIGH|XHIGH; <кандидат, тесты и ревью>`.

## 5. Общение и код

- Русский язык; перед сложной задачей обозначьте подход. Во время работы пишите в чат только при значимых открытиях/смене курса/блокерах; в конце — результат, проверки и ограничения.
- В коде комментируйте только инварианты (`INVARIANT:`, `SAFETY:`, `WORKAROUND:`).
