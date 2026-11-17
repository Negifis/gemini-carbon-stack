---
trigger: glob
globs: "**/hooks/**, **/hooks.json, **/plugin.json, **/mcp_config.json, **/install.py, **/*auth*, **/*crypto*, **/*jwt*, **/*secret*, **/*permission*, **/*rbac*, **/*acl*, **/*security*, **/migrations/**, **/.github/workflows/**, **/Dockerfile*"
---

# High-Risk (`HIGH` / `XHIGH`) Verification Rules

Вы работаете с критическими или высокорисковыми компонентами (хуки, манифесты, безопасность, авторизация, миграции, CI/CD, секреты):

1. **Полная изоляция упрощения (3 раздельные линзы СТРОГО ПЕРЕД ревью):** после реализации и прохождения локальных тестов вызовите `swarm_cache.py prepare --session <id> --cwd <repo> --label simplify`, запустите **строго 3 параллельные read-only линзы** на `claude-sonnet-5-5-high` (`simplify-reuse`, `simplify-quality`, `simplify-efficiency`; при подтверждённом сбое/0% квоты Sonnet — fallback строго на `gemini-4-hydrogen-xhigh` через `swarm`, никогда не на Carbon) и **дождитесь их полного завершения до запуска adversarial-ревью** (запрещено запускать `simplify` и ревью одновременно в одном ходе). Каждый воркер должен завершить пост строками `SIMPLIFY_LENS: <REUSE|QUALITY|EFFICIENCY>` и `SIMPLIFY_VERDICT: <CLEAN|ACTIONABLE_FIXES>`.
2. **Независимое adversarial-ревью (только после завершения всех 3 линз `simplify`):**
   - **Приоритет №1 (всегда основной контур):** `python -X utf8 plugin/hooks/codex_lane.py review --cwd <repo> --session <id> --summary "..."` (`--xhigh` для `XHIGH`). Повторные раунды в том же кандидате автоматически продолжаются через `codex exec resume`.
   - **Приоритет №2 (только при подтверждённой недоступности/сбое Codex):** внутренний `claude-opus-5-5-high` через `swarm`, с эскалацией на `gemini-4-carbon-high` (или субагент `adversarial-reviewer`) только при подтверждённом системном сбое/исчерпании квоты И Codex, И Opus.
3. **TTL кэша (`270s`) и свежесть SHA-256:** тёплый чат воркера (`<= 270s`) продолжайте через `post_message`; остывший (`> 270s`) закрывайте (`kill`) и запускайте `<name>-r<N>` с инкрементальным диффом. Любая правка файлов после `APPROVED` аннулирует вердикт и требует перепрогона тестов и ревью.
