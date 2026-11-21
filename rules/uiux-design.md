---
trigger: model_decision
description: "Auto-load ONLY for visual UI/UX, design, layout, styling, component rendering, design-system, or browser visual QA tasks — do NOT load for backend, CLI, SQL, infra, or non-visual logic/unit-test edits."
---

# Frontend UI/UX & Live Browser Verification Rules

Эти правила загружаются по смыслу задачи (`trigger: model_decision`) **автоматически** (без напоминания пользователя) **только** для визуальных UI/UX- и дизайн-задач (новые экраны/компоненты, редизайн, вёрстка, стили, токены, интеракции).

1. **Автоматическое подключение дизайн-плагинов до и во время визуальной разработки (без напоминания пользователя):**
   - **`modern-web-guidance-plugin`** (`npx.cmd -y modern-web-guidance@latest search` / `retrieve`) — первым шагом при работе с HTML/CSS/JS-паттернами (диалоги, поповеры, кастомные селекты, фокус/скролл, dark mode, a11y, container queries, анимации).
   - **`mobbin`** (`mobbin_mobbin` MCP: `search_screens`, `search_flows`, `search_sections`, `list_collections`, `get_collection_contents` + скиллы плагина `mobbin`: `best-practices`, `search`, `redesign-screen`, `plain-writing`) — при проектировании новых экранов и редизайне для опоры на реальные продакшн-референсы строго внутри дизайн-системы проекта.
   - **`frontend-design` и профильные скиллы по стеку (загружать точечно по задаче):** переиспользуйте токены и компоненты проекта; подключайте `frontend-design`, `web-design-guidelines`, `accessibility-audit`, `responsive-design` и `critique-*` (`critique-visual-hierarchy`, `critique-composition`, `critique-typography`, `critique-brand-consistency`), а стековые — только где применимо (`vercel-react-best-practices`/`vercel-composition-patterns`/`vercel-react-view-transitions` для React/Next.js, `shadcn-ui` при использовании shadcn, `taste-design`/`design-md` при дизайн-спеке, `figma` при наличии макетов Figma). Не добавляйте новые UI-зависимости без обоснования.
2. **Никогда не выдавайте сгенерированную вёрстку за проверенный UI без запуска:** соберите и откройте экран в реальном браузере (`browser` на `Gemini 4 Hydrogen` с `BROWSER_HOST_FACTS`, `playwright`, `chrome-devtools` `get_css_styles`/`lighthouse_audit`/`performance_start_trace`, `odiff`).
3. **Состязательное визуальное UI/UX-ревью (вместо самоосмотра глазами):**
   - Для нетривиальных визуальных/UX-изменений не принимайте результат единоличным самоосмотром. Снимите реальные скриншоты затронутых состояний по поддерживаемым проектом матрицам (desktop + mobile, поддерживаемые темы light/dark и локали), соберите релевантные гайды `modern-web-guidance` (и при сравнении с макетом — `odiff`) заранее на стороне основного агента и передайте всё на независимое strictly read-only состязательное ревью (`visual-design-critic` + `ux-adversarial-auditor` в `swarm` или `visual-qa-reviewer`, протокол в `~/.gemini/config/agents/visual-qa-reviewer.md`).
   - Ревьюерам дизайна обязательно предоставлять read-only доступ к веб-поиску лучших практик (`search_web` / `exa` / `tokenade search`), `mobbin_mobbin` и дизайн-скиллам критики/a11y.
   - Устраняйте найденные `P0`/`P1`, переснимайте скриншоты и повторяйте приёмку до `APPROVED`.
4. **Проверяйте реальные состояния и доступность:** `empty`, `loading`, `error`, переполнение текстом, клавиатурная и touch-навигация (`focus-visible`, валидные WAI-ARIA роли и возврат фокуса), контрастность в поддерживаемых темах, отсутствие CLS и наложений, осмысленная анимация с `prefers-reduced-motion`, адаптивность (desktop + mobile).
5. **Честность UI-текстов и терминологии:** подписи кнопок, статусы и ошибки точно отражают фактическое поведение системы и словарь проекта, без декоративных заглушек.
