# Gemini Carbon Engineering Stack

Нативная инженерная операционная система для **Gemini 4 Neon / Carbon** в среде **Google Antigravity 2.0** (`agy` CLI + нативный Rust-бинарник `carbon-stack`).

Спроектирована как компактный эквивалент гарантий `claude-code-stack`, адаптированный под нативные механизмы Antigravity (`hooks.json`, `transcript.jsonl`, `.system_generated/swarm/`, `OpenAI Codex CLI` и плагины `~/.gemini/config/plugins/`).

## Структура репозитория

- `rust/` — нативный Rust-крейт `carbon-stack` (единый бинарник хуков, CLI-инструментов, установщика `carbon-stack install` и модульных тестов `cargo test`).
- `install.sh` — кроссплатформенная обёртка (`--with-toolchains`), автоматически собирающая `carbon-stack` при отсутствии или обновлении `rust/` и вызывающая `carbon-stack install`.
- `templates/` и `.env.example` — обезличенные шаблоны конфигурации:
  - `templates/mcp_config.json` — ленивая загрузка (`"eager": false`) и фильтрация `"enabledTools"` для **Serena MCP** и **Context7 MCP**.
  - `templates/antigravity-cli-settings.json` — конфигурация `agy` CLI с маршрутизацией на `Orchestrator (Neon)` и `"useG1Credits": false`.
  - `templates/GEMINI.md` — тонкий глобальный контекст (`16` строк) для `Turn-0` токен-диеты.
- `plugin/` — нативный плагин-бандл Antigravity (`gemini-carbon-stack`):
  - `plugin.json`, `hooks.json` — манифест плагина и 5 групп runtime-хуков (`SessionStart`, `PreInvocation`, `PreToolUse`, `PostToolUse`, `Stop`).
  - `bin/carbon-stack.exe` — релизный Rust-бинарник гейта (`cwg_*`), независимого ревью (`codex-lane`), `continuity`, защитных хуков (`safety_guards`, `comment_density_guard`), локальной FTS5-памяти (`carbon-memory`), импортера сессий Claude Code (`claude-chat-importer`), оркестратора worktree-задач (`chip-handoff`), поиска (`code-search`), кэша роя (`swarm-cache`), безопасного управления worktrees (`worktree-guard`), самодиагностики (`stack-doctor`) и установщика (`install`).
  - `tools/` — `file-holders.ps1` и `vectorize.mjs`.
  - `rules/` — компактная конституция `AGENTS.md` и селективные правила (`high-risk-verification.md` `glob`, `multi-agent-routing.md` `model_decision`, `engineering-tool-routing.md` `model_decision`, `deep-audit.md` `manual`).
  - `agents/` — `8` профильных субагентов (`adversarial-reviewer`, `adversarial-reviewer-xhigh`, `simplify-reviewer`, `simplify-reuse-reviewer`, `simplify-quality-reviewer`, `simplify-efficiency-reviewer`, `code-explorer`, `translator`).
  - `skills/` — `25` прогрессивных навыков и slash-команд с компактными описаниями (`Turn-0 <= 6,500 tok`).
- `rules/uiux-design.md` — контекстное правило фронтенда (`trigger: model_decision`).

## Finite Verification & Swarm Architecture

- **Линейный конечный контур (`HIGH` / `XHIGH`):**
  1. Детерминированные проверки/тесты -> обязательный однократный проход `simplify` фиксированными линзами Claude через `swarm` (`claude-sonnet-5-5-high`, фоллбэк только при подтверждённом сбое/0% квоты: `gemini-4-neon-xhigh` → `gemini-4-hydrogen-xhigh`; `STANDARD`: `1× simplify-reviewer`; `HIGH`/`XHIGH`: 3 параллельные линзы `simplify-reuse`, `simplify-quality`, `simplify-efficiency` ДО ревью; фиксированные промпты из `plugin/agents/simplify-*.md` инжектируются `PreToolUse`; проверяется на `Stop` и перед 1-м раундом `codex-lane review`).
  2. Независимое состязательное ревью `carbon-stack codex-lane review` (`gpt-6.2-sol` / `medium` для `HIGH`; `--xhigh` -> `gpt-6.2-astra` / `ultra` для `XHIGH`; `1..4` раунда, порог блокировки `CRITICAL`/`HIGH`). **`VERDICT: APPROVED` на любом раунде `1..4` сразу закрывает гейт.**
  3. При `Round 4: ESCALATE` -> 1 сфокусированный проход исследования -> до `2` проходов `carbon-stack codex-lane review --closure` (`CLOSURE_VALIDATION: READY` -> `[gate] verified` / `[gate] pr-ready`; 2-й `BLOCKED` -> терминальный `[gate] draft-blocked`). Циклов сброса (`redesign-reset`/`research-reset`) нет.
- **Гигиена роя и дерева:**
  - `Swarm Wait Guard` + `Stall Watchdog` предотвращают вечное ожидание завершившихся/зависших воркеров, сохраняя поддержку активных `working`-воркеров при межагентной координации.
  - `worktree-guard` делает снимок-страховку перед удалением грязного/конфликтного worktree и запрещает разрушительный `git worktree remove --force`.

## Быстрый старт и эксплуатация

```powershell
# Предпросмотр установки без записи на диск
.\plugin\bin\carbon-stack.exe install --dry-run

# Установка (идемпотентно, с бэкапом и ротацией до 10 копий)
.\plugin\bin\carbon-stack.exe install

# Диагностика установленного стека и MCP-конфигов
carbon-stack install --diagnose
carbon-stack stack-doctor --json

# Откат к предыдущему состоянию
carbon-stack install --rollback latest

# Запуск всех Rust-тестов
cargo test --manifest-path rust/Cargo.toml
```
