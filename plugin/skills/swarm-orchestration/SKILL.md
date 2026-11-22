---
name: swarm-orchestration
description: "Swarm 2.0 multi-worker orchestration for parallel exploration, disjoint worktrees, and advisory polish."
---

# Swarm 2.0 Orchestration Playbook

Three-phase orchestration for parallel discovery, isolated disjoint building, and advisory review/polish.

## 1. Core Invariants

- **Bounded parallelism & parent verification:** prefer `<= 3` concurrent workers/subagents; every worker report is evidence, never self-validating authority — inspect diffs, files, and command output before integrating or relying on claims.
- **Context & `BUSINESS_INTENT` propagation:** every worker brief states `BUSINESS_INTENT` plus relevant plugins, MCP servers, skills, and read-only web access (`search_web`/`exa`/`tokenade search`) without waiting to be asked.
- **No `Gemini Flash`:** never pass `flash`, `flash_lite`, or `gemini-3.8-flash-*`.
- **Pointer-on-Board:** write verbose scout/review details into `.swarm/artifacts/<worker>-<round>.md` and post a `<= 12`-line summary + path on the board; read incrementally with `read_board(since=<last_seen_id>)`, and never call `read_board` and `swarm_wait` in the same turn.
- **Stall timeout:** idle `in_flight` workers past `SWARM_STALL_TIMEOUT_SEC` (`240`s) are surfaced via `[Swarm Stall Watchdog]` — restart only the stalled worker rather than polling blindly.

## 2. Model Routing Matrix

| Phase / Role | Model Tier | Use Case |
|---|---|---|
| Coordinator | `Orchestrator (Neon)` / `Gemini 4 Carbon` | Task slicing, worktree isolation, integration, verification |
| Fast Scouts & Mechanical Builders | `gemini-4-hydrogen-medium` / `-high` | Multi-subsystem exploration (`3+` areas), `browser` QA, `translator`, straightforward edits |
| Architecture, Debugging, UI, Tests | `gemini-4-neon-medium`..`-xhigh` | Call graphs/contracts, race/flakiness debugging, complex UI-to-code, unit/E2E tests |
| Advisory Simplify (once before review) | `claude-sonnet-5-5-high` (fallback `gemini-4-neon-xhigh`, then `gemini-4-hydrogen-xhigh`) | Combined `simplify-reviewer` (`<=2` files / `<=30` LOC) or 3 parallel lenses |
| Logic Review Escalation | `claude-opus-5-5-high` → `gemini-4-neon-xhigh` (`HIGH`) / `gemini-4-carbon-high` (`XHIGH`) | Only after verified `codex-lane` outage |

## 3. Disjoint Building & Worktree Isolation

Divide files cleanly before spawning writers — one writer per file or isolated worktree:

```powershell
# Preferred when builders may touch overlapping modules or shared tests:
$null | carbon-stack swarm-ctl worktree create --worker builder-a --cwd "<repo>"
# Optional ownership bookkeeping:
$null | carbon-stack swarm-ctl ownership set --worker builder-a --paths "src/api/**" --cwd "<repo>"
$null | carbon-stack swarm-ctl ownership verify-git-diff --strict --cwd "<repo>"
$null | carbon-stack swarm-ctl worktree cleanup --cwd "<repo>"
```

Kill completed workers cleanly via `swarm(action="kill", ...)` before moving from simplify/building to final review or closure.

## 4. Inline Specialist Swarm Briefs

Instead of loading global catalog agent definitions, include the focused role template directly inside `swarm(action="add", brief=...)`:

- **`frontend-ui-builder` (`gemini-4-neon-high` / `-xhigh`):** Build UI strictly inside project design tokens/components; cover `loading`, `empty`, `populated`, `error` states, desktop+mobile responsiveness, keyboard/ARIA accessibility; use `modern-web-guidance`, `mobbin_mobbin`, `frontend-design`, `ui-design-system`; stay inside `<owned_paths>` / `<worktree>`; verify build + tests before reporting.
- **`test-author` (`gemini-4-neon-medium` / `-high`):** Write contract/regression tests anchored in requirements (never fitted to broken code), verify bug tests fail before fix and pass after fix, stay inside `<test_owned_paths>`.
- **`repo-architect-scout` (`gemini-4-neon-high` / `-xhigh`, read-only):** Map module contracts, blast radius (`rg`, `tokenade`, `codebase-memory`, `serena`), failure modes, and disjoint slice plan (`<= 30–40 KB` per step) into `.swarm/artifacts/`.
- **`root-cause-debugger` (`gemini-4-neon-xhigh`):** Reproduce failure, inspect `git log`/`git blame` and full code blocks, falsify hypotheses with targeted logging/tests, fix owning layer (or report root cause if read-only) with red→green regression proof.
- **`gitlab-delivery-analyst` (`gemini-4-hydrogen-high`, read-only):** Summarize `gitlab.lemnos.ru` issues, MR diffs/threads, and failing CI job logs (`gitlab` MCP + `glab` CLI) into `.swarm/artifacts/`.
- **`infra-sre-diagnostician` (`gemini-4-neon-high` / `-xhigh`, strictly read-only):** Triage Proxmox, K8s/Nomad, Grafana/Loki/Prometheus, Zabbix, PostgreSQL/MSSQL, SSH, Trivy read-only; never mutate live infra.
