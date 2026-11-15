---
trigger: glob
globs: "**/hooks/**, **/hooks.json, **/plugin.json, **/mcp_config.json, **/install.py, **/*auth*, **/*crypto*, **/*jwt*, **/*secret*, **/*permission*, **/*rbac*, **/*acl*, **/*security*, **/migrations/**, **/.github/workflows/**, **/Dockerfile*"
---

# High-Risk (`HIGH` / `XHIGH`) Verification Rules

Вы работаете с критическими или высокорисковыми компонентами (хуки, манифесты, безопасность, авторизация, миграции, CI/CD, секреты):

1. **Полная изоляция упрощения (3 раздельные линзы):** после реализации и прохождения локальных тестов вызовите `swarm_cache.py prepare --session <id> --cwd <repo> --label simplify` и запустите **строго 3 параллельные read-only линзы** на `claude-sonnet-5-5-high` (`simplify-reuse`, `simplify-quality`, `simplify-efficiency`), без схлопывания в один воркер. Каждый воркер должен завершить пост строками `SIMPLIFY_LENS: <REUSE|QUALITY|EFFICIENCY>` и `SIMPLIFY_VERDICT: <CLEAN|ACTIONABLE_FIXES>`.
2. **Независимое adversarial-ревью:**
   - Основной контур: `python -X utf8 plugin/hooks/codex_lane.py review --cwd <repo> --session <id> --summary "..."` (используйте `--xhigh` для `XHIGH`). Повторные раунды в том же кандидате автоматически продолжаются через `codex exec resume`.
   - Резервный внутренний контур (только при недоступности Codex): `claude-opus-5-5-high` через `swarm`, с эскалацией на `gemini-4-carbon-high` лишь при системном сбое/исчерпании квоты Opus.
3. **TTL кэша (`270s`) и свежесть SHA-256:** тёплый чат воркера (`<= 270s`) продолжайте через `post_message`; остывший (`> 270s`) закрывайте (`kill`) и запускайте `<name>-r<N>` с инкрементальным диффом. Любая правка файлов после `APPROVED` аннулирует вердикт и требует перепрогона тестов и ревью.
