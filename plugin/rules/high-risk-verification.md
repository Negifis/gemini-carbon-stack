---
trigger: glob
globs: "**/hooks/**, **/hooks.json, **/plugin.json, **/mcp_config.json, **/install.py, **/*auth*, **/*crypto*, **/*jwt*, **/*secret*, **/*permission*, **/*rbac*, **/*acl*, **/*security*, **/migrations/**, **/.github/workflows/**, **/Dockerfile*"
---

# High-Risk (`HIGH` / `XHIGH`) Verification Rules

Вы работаете с критическими или высокорисковыми компонентами (хуки, манифесты, безопасность, авторизация, миграции, CI/CD, секреты):

1. **Порядок Swarm 2.0 (сначала логика, потом одна полировка):**
   - **Шаг 1 (`unittest`):** доведите локальные тесты и линтеры до зелёного состояния.
   - **Шаг 2 (первичный `codex_lane.py review`):** `python -X utf8 plugin/hooks/codex_lane.py review --cwd <repo> --session <id> --summary "..."` (`--xhigh` для `XHIGH`; дефолтный таймаут 10–15 мин: `600s` / `900s`). Не задавайте укороченный `--timeout` заранее: при локальном таймауте (`timeout_after_*s` без сетевого/квотного сбоя) раунд **не теряется** и переключение на внутренний контур запрещено — повторите вызов `codex_lane.py review` для продолжения той же сессии с увеличенным таймаутом. Закройте функциональные замечания (`REVISE` -> правки -> тест -> `APPROVED`) **до** запуска `simplify`. (Эскалация на `claude-opus-5-5-high` -> `gemini-4-carbon-high` разрешена только при подтверждённом сбое/недоступности Codex.)
   - **Шаг 3 (`simplify` один раз):** вызовите `swarm_cache.py prepare --session <id> --cwd <repo> --label simplify`. Если `fast_path_eligible` (`<= 2` файлов и `<= 30` изменённых строк) — достаточно 1 воркера `simplify-reviewer` (`SIMPLIFY_LENS: ALL`) на `claude-sonnet-5-5-high`. Иначе запустите 3 параллельные read-only линзы (`REUSE`, `QUALITY`, `EFFICIENCY`; fallback строго `gemini-4-hydrogen-xhigh`, никогда Carbon). При правках после замечаний будите живых `waiting` воркеров через `@mention` (`Warm Pool`, вердикты сверяются с `round_start_msg_id` и `current_diff_hash`).
   - **Шаг 4 (финал):** выполните пакетный `swarm(action="kill", ...)` и завершите гейт через `python -X utf8 plugin/hooks/codex_lane.py review --cwd <repo> --session <id> --closure --summary "..."` (`CLOSURE_VALIDATION: READY`).
2. **TTL кэша (`270s`) и свежесть SHA-256:** тёплый воркер (`<= 270s`, статус `waiting`) продолжайте через `post_message`; остывший (`> 270s`) перезапускайте с `<name>-r<N>`. Любая правка файлов после `APPROVED` аннулирует вердикт и требует перепрогона тестов и финальной проверки.
