---
name: uiux-and-browser-qa
description: "Frontend UI states, accessibility, and live browser QA via Hydrogen, Playwright, and visual-qa-reviewer."
---

# UI/UX Engineering & Live Browser Verification

Use ONLY for frontend, web, or UI tasks (zero overhead on backend/CLI/SQL/infra).

## 1. Designing & Implementing UI

- **Design plugins & skills before/during layout:**
  - **`modern-web-guidance-plugin`** (`npx.cmd -y modern-web-guidance@latest search|retrieve`) for HTML/CSS/ARIA patterns (dialogs, popovers, selects, focus/scroll, dark mode, container queries).
  - **`mobbin`** (`mobbin_mobbin` MCP: `search_screens`, `search_flows`, `search_sections` + skills `best-practices`, `search`, `redesign-screen`, `plain-writing`) for production references aligned with project tokens.
  - Project design tokens + `frontend-design`, `ui-design-system`, `ui-critique`, `web-design-guidelines`, `accessibility-audit`, `responsive-design`; stack-specific skills (`vercel-react-best-practices`, `shadcn-ui`, `figma`) only when used in the project.
- **Required UI states:** verify `loading`, `empty`, `populated` (long text, overflow, localized copy), and `error` (clear recovery).
- **Accessibility & responsiveness:** semantic HTML, `:focus-visible`, ARIA roles/focus restoration, contrast across supported themes, `375px` mobile + `1280px+` desktop, `prefers-reduced-motion`, zero unexpected CLS.

## 2. Closed-Loop Live Verification

Generated JSX/HTML/CSS is unverified until built, opened in a live browser, and visually inspected:
1. Build frontend & launch local server (`run_command` with `IsDaemon: true` if needed).
2. Capture real screenshots across viewports (`375px` + `1280px+`) and supported themes (`light`/`dark`):
   - **`browser` subagent** on **`Gemini 4 Hydrogen`** (never Flash; via Hydrogen `swarm` worker if parent is not Hydrogen), verified against `BROWSER_HOST_FACTS`, OR
   - **`playwright` MCP / CLI** (`toHaveScreenshot()`, `@axe-core/playwright`), OR
   - **`chrome-devtools` MCP** (`take_screenshot`, `get_css_styles`, console/network checks, `lighthouse_audit`, `performance_start_trace`).
   - Use `odiff <ref.png> <actual.png> <diff.png>` when comparing against mockups/references (store refs/uploads inside `browser_sandbox/{references,uploads}/`).
3. For non-trivial visual/UX edits, pass screenshots + pre-fetched `modern-web-guidance` context (plus read-only `mobbin_mobbin`, `ui-critique`, and web research access) to strictly read-only **`visual-qa-reviewer`** until **`VISUAL_REVIEW_VERDICT: APPROVED`**.
