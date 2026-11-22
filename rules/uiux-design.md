---
trigger: model_decision
description: "Auto-load ONLY for visual UI/UX, design, layout, styling, component rendering, design-system, or browser visual QA tasks."
---

# Frontend UI/UX & Live Browser Verification Rules

Загружается **только** для визуальных UI/UX- и дизайн-задач (новые экраны/компоненты, редизайн, вёрстка, стили, токены, интеракции).

1. **Автоматическое подключение дизайн-плагинов и скиллов до и во время вёрстки:**
   - **`modern-web-guidance-plugin`** (`npx.cmd -y modern-web-guidance@latest search` / `retrieve`) — первым шагом для HTML/CSS/JS-паттернов (диалоги, поповеры, селекты, фокус/скролл, dark mode, a11y, container queries, анимации).
   - **`mobbin`** (`mobbin_mobbin` MCP: `search_screens`, `search_flows`, `search_sections`, `list_collections`, `get_collection_contents` + скиллы `best-practices`, `search`, `redesign-screen`, `plain-writing`) — продакшн-референсы внутри дизайн-системы проекта.
   - **`frontend-design` и профильные скиллы:** `ui-design-system`, `ui-critique`, `web-design-guidelines`, `accessibility-audit`, `responsive-design`; стековые — только по месту (`vercel-react-best-practices`, `shadcn-ui`, `figma`). Переиспользуйте токены и компоненты проекта без лишних зависимостей.
2. **Живая проверка в браузере (обязательно до приёмки):** соберите и откройте экран в реальном браузере (`browser` на `Gemini 4 Hydrogen` с `BROWSER_HOST_FACTS`, `playwright`, `chrome-devtools` `take_screenshot`/`get_css_styles`/`lighthouse_audit`, `odiff`).
3. **Независимое визуальное UI/UX-ревью (вместо самоосмотра):**
   - Для нетривиальных визуальных/UX-изменений снимите реальные скриншоты затронутых состояний (desktop + mobile, поддерживаемые темы light/dark и локали), приложите гайды `modern-web-guidance` (и `odiff` при сверке с макетом) и передайте строго read-only ревьюеру `visual-qa-reviewer` (`~/.gemini/config/agents/visual-qa-reviewer.md`) с доступом к веб-поиску (`search_web`/`exa`/`tokenade search`), `mobbin_mobbin` и `ui-critique`/a11y.
   - Устраняйте найденные `P0`/`P1`, переснимайте скриншоты и повторяйте приёмку до `VISUAL_REVIEW_VERDICT: APPROVED`.
4. **Состояния, a11y и тексты:** проверяйте `empty`, `loading`, `error`, переполнение, клавиатуру/touch (`focus-visible`, WAI-ARIA, возврат фокуса), контраст, CLS, `prefers-reduced-motion` и честность UI-подписей без заглушек.
