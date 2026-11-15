---
name: current-docs
description: External library/SDK version verification via manifests and Context7 MCP. Load ONLY when checking unfamiliar or version-sensitive APIs.
---

# Current Documentation Verification

Никогда не полагайтесь на устаревшую память обучения для быстро меняющихся API, SDK, CLI-флагов и конфигурационных схем.

## Порядок проверки

1. **Установите точную локальную версию:** сначала проверьте `package.json` / lock-файл, `pyproject.toml`, `Cargo.toml`, `go.mod`, `--help` бинарника или `pip show` / `npm ls`, чтобы знать фактическую мажорную и минорную версию в окружении.
2. **Проверьте локальные встроенные схемы и исходники:** для системных расширений Antigravity читайте встроенную документацию (`agy-customizations`, `antigravity_guide`), а для установленных пакетов — их реальные `.d.ts` / Python-сигнатуры в `node_modules` или `site-packages`.
3. **Запросите актуальную документацию через Context7 MCP:** прочитайте схему ленивых инструментов `context7_context7` (`resolve-library-id` -> `query-docs`) и запросите документацию под установленную версию библиотеки.
4. **Веб-поиск (`search_web`) как резерв:** используйте с приоритетом официального домена разработчика, когда библиотека не представлена в Context7 или речь о свежем релизе/issue.
