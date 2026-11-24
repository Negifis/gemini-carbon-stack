---
name: verify-ready
description: "Pre-closure readiness audit: intent match, checks, review freshness, and compact scope check."
---

# `/verify-ready` — Pre-Closure Readiness Audit

1. **Intent & Diff Hygiene (`<= 30–40 KB`):** verify output matches `BUSINESS_INTENT` (no requested capability stripped out); inspect `git status --short` and `git diff --stat` (no stray binaries/temp files/disabled checks, coherent compact candidate).
2. **Fresh Checks:** affected tests, type checks, and linters ran and passed **after the final file edit** (any pre-existing out-of-scope failure handed off explicitly, never ignored or suppressed).
3. **Gate Risk Alignment (`development-verification`):**
   - `LOW`: content/links/deterministic check verified.
   - `STANDARD`: affected local tests/linters green → mandatory 1× `simplify-reviewer` via `invoke_subagent(..., Model="inherit")` (re-test if accepted edits were applied).
   - `HIGH` / `XHIGH`: tests green → mandatory 1× 3-lens `simplify` (`simplify-reuse-reviewer`, `simplify-quality-reviewer`, `simplify-efficiency-reviewer` via `invoke_subagent(..., Model="inherit")`) before review → independent review via `carbon-stack codex-lane review --intent "..."` (`1..4` rounds, `DISPOSE` recorded for intent conflicts/noise; `VERDICT: APPROVED` closes gate; after `Round 4: ESCALATE` → 1 research pass → `<= 2` `--closure` passes -> `verified`/`pr-ready` or terminal `[gate] draft-blocked`).
   - If visual UI files changed meaningfully: live browser screenshots checked + `VISUAL_REVIEW_VERDICT: APPROVED` from read-only `visual-qa-reviewer`.
4. **Handoffs, Memory & Receipt:** confirm child chips closed via `carbon-stack chip-handoff status`, record any confirmed `DECISION`/`GOTCHA` via `nlm-memory remember`, and finish with exact final `[gate]` receipt.
