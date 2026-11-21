---
name: uiux-and-browser-qa
description: Frontend UI states, accessibility, and live browser subagent QA (BROWSER_HOST_FACTS). Load ONLY for web/app UI work.
---

# UI/UX Engineering & Live Browser Verification

Используйте этот навык **только для фронтенд-, веб- и UI-задач**. Не применяйте его к чистому backend/CLI-коду.

## 1. Проектирование и реализация интерфейса

- **Автоматические дизайн-плагины до и во время вёрстки (без напоминания пользователя):**
  - **`modern-web-guidance-plugin`** (`npx.cmd -y modern-web-guidance@latest search` / `retrieve`, скилл `modern-web-guidance`) — первым шагом для современных HTML/CSS/JS-паттернов (диалоги, поповеры, кастомные селекты, фокус/скролл, dark mode, a11y, container queries, анимации).
  - **`mobbin`** (`mobbin_mobbin` MCP: `search_screens`, `search_flows`, `search_sections`, `list_collections`, `get_collection_contents` + скиллы `best-practices`, `search`, `redesign-screen`, `plain-writing`) — при проектировании новых экранов и редизайне для опоры на продакшн-референсы строго внутри дизайн-системы проекта.
  - **Система дизайна и профильные скиллы:** опирайтесь на токены проекта и `frontend-design`, `web-design-guidelines`, `accessibility-audit`, `responsive-design`, `critique-*` (`critique-visual-hierarchy`, `critique-composition`, `critique-typography`, `critique-brand-consistency`), а стековые подключайте по факту стека (`vercel-react-best-practices`, `vercel-composition-patterns`, `vercel-react-view-transitions`, `shadcn-ui`, `taste-design`/`design-md`, `figma`).
- **Все реальные состояния экрана:** каждый интерактивный экран или компонент должен корректно отображать:
  1. `loading` (скелетон или ненавязчивый индикатор без скачка layout shift),
  2. `empty` (понятное пустое состояние с целевым действием),
  3. `populated` (включая длинные строки, переполнение, локализованный русский текст),
  4. `error` (конкретная причина и способ повторить/исправить).
- **Доступность и клавиатура:** семантические теги (`button`, `nav`, `main`, `dialog`), видимый `:focus-visible`, корректные `aria-label` для иконочных кнопок, достаточный цветовой контраст и адаптивность на узком экране (`375px`) и десктопе (`1280px+`).
- Для интерактивных визуализаций и диаграмм прямо в чате Antigravity используйте встроенный навык `generative_ui`.

## 2. Замкнутый цикл проверки: разработал → открыл → диагностировал → исправил → перепроверил

**Сгенерированный JSX/HTML/CSS без запуска не считается проверенным интерфейсом.**

1. **Распределение инструментов QA (без дублирования):**
   - **`browser` subagent** (на `Gemini 4 Hydrogen`, никогда не `Flash`, сверка по `BROWSER_HOST_FACTS`) — интерактивная проверка живого UI и пользовательских потоков;
   - **`playwright` MCP (`--headless`)** — чистые детерминированные E2E по accessibility tree, скриншоты (`toHaveScreenshot()`) и a11y (`@axe-core/playwright`);
   - **`chrome-devtools` MCP (`1.13.0`) + `chrome-devtools` CLI** — глубокая диагностика: `get_css_styles`, console/network, `lighthouse_audit` (a11y/SEO/BP), `performance_start_trace` + `performance_analyze_insight` (CWV/LCP/CLS), heap snapshots;
   - **`odiff` CLI + `visual-qa-reviewer`** — быстрый SIMD pixel-diff эталона/макета vs фактического скриншота и независимая визуальная приёмка.
2. Для сложной генерации интерфейсов по макетам/скриншотам или отладки визуально-стейтовых багов в рое делегируйте реализацию в **`frontend-ui-builder`** (`swarm(action="add", ..., model="gemini-4-neon-high"|"gemini-4-neon-xhigh")` с выделенными `owned_paths`) или диагностику в `root-cause-debugger` (`gemini-4-neon-xhigh`).
3. Соберите фронтенд (`npm run build` / typecheck) и при необходимости поднимите локальный dev-сервер в фоне (`run_command` с `IsDaemon: true`).
4. Делегируйте визуальную и интерактивную проверку встроенному субагенту `browser` **на `Gemini 4 Hydrogen` (никогда не `Model="flash"`)**:
   - Если текущая сессия работает не на Hydrogen (например, на `Gemini 4 Carbon`), запустите `swarm`-воркера `browser-qa` на модели по сложности сценария:
     - `gemini-4-hydrogen-low` — одиночный smoke-check URL и скриншот;
     - `gemini-4-hydrogen-medium` — стандартная интерактивная QA (клики, формы, `loading`/`empty`/`populated`/`error`, консоль, desktop/mobile);
     - `gemini-4-hydrogen-high` — многошаговые SPA/auth-потоки, каскадные формы, воспроизведение регрессий;
     - `gemini-4-hydrogen-xhigh` — тяжёлая отладка гонок состояния, WebSocket/streaming UI.
   - Воркер `browser-qa` вызывает `invoke_subagent(TypeName="browser", Model="inherit")`, передав точный URL, сценарий кликов/ввода, проверку консоли на ошибки и проверку desktop/mobile размеров (либо вызывайте `Model="inherit"` напрямую, если сама сессия уже запущена на Hydrogen).
5. Если нужно сравнить рендер с макетом или загрузить файл, положите его в `browser_sandbox/{references,uploads}/<filename>` **той же сессии-вызывателя** (для swarm-воркера — в `<brain>/<worker_conv_id>/browser_sandbox/...`), а для точной карты различий прогоните `odiff <ref.png> <actual.png> <diff.png>`.
6. Сверяйте отчёт `browser` с системным сообщением `BROWSER_HOST_FACTS` (посещённые origin и путь к скриншоту в сессии вызывателя), осматривайте скриншот мультимодально через `read_file`, и при выявлении дефектов исправляйте код и повторяйте цикл проверки до чистого результата.

## 3. Условный Design Gate (строго только при правке UI/дизайн-файлов)

При изменении визуальных файлов (`*.tsx`, `*.jsx`, `*.vue`, `*.svelte`, `*.css`, `*.scss`, `*.html`, `DESIGN.md`, дизайн-токенов, Flutter UI-виджетов — с исключением pure-logic/API/hooks/store/tests/docs/backend/CLI/SQL/infra) `design_gate` проверяет структурное закрытие Design Gate (отключение в проекте: `"design_gate": false` в `.agents/carbon-gate.json`):
1. В текущей сессии сняты реальные скриншоты отрендеренного UI (desktop + mobile, поддерживаемые темы light/dark, ключевые состояния) одним из **структурных** способов:
   - встроенный `browser` субагент (`BROWSER_HOST_FACTS`),
   - нативные MCP-инструменты `browser_take_screenshot` (`playwright`) / `take_screenshot` (`chrome-devtools`),
   - для CLI-скриптов (Playwright CLI, Android, Flutter, кастомные раннеры) — явная регистрация снятых файлов командой `carbon-stack design-gate record-screenshot --session <id> --path <shot.png> [--viewport desktop] [--theme dark]` (проверяет магический заголовок PNG/JPEG/WebP, `mtime` и SHA-256; вывод stdout/текст команд не гадается).
2. Проведено **независимое read-only состязательное визуальное UI/UX-ревью** (`visual-qa-reviewer` или swarm `visual-design-critic` + `ux-adversarial-auditor` в `workspace: "inherit"` с подтверждённой read-only историей без записей в транскрипте; самоосмотр основного агента не засчитывается), причём ревьюер инспектирует свежий скриншот через `read_file` после захвата (или указывает 8-символьный префикс его `sha256` из `record-screenshot`), а в бриф ему явно выдаются read-only веб-поиск (`search_web`/`exa`/`tokenade search`), `mobbin_mobbin`, `modern-web-guidance` и скиллы `critique-*`/`accessibility-audit`.
3. Все `P0`/`P1` устранены, скриншоты пересняты и получен явный вердикт **`VISUAL_REVIEW_VERDICT: APPROVED`** (и **`UX_REVIEW_VERDICT: APPROVED`**, если запускался UX-аудитор).
