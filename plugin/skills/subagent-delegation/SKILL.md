---
name: subagent-delegation
description: "Multi-worker swarm routing, Hydrogen browser/translator delegation, and parent verification rules."
---

# Subagent Delegation & Multi-Model Routing

## 1. When NOT to Delegate

Work directly without spawning subagents when:
- editing/reading `<= 3–4` known files with clear callers/tests;
- fixing a localized, well-understood issue or running sequential debugging where each step depends on the previous one.

Delegate exploration when scope spans `> 3–4` files or an unfamiliar subsystem (`code-explorer` / `research`), and prefer **`<= 3` concurrent subagents** unless each extra lane has a disjoint deliverable.

## 2. Parent Verification Invariant ("Evidence, Not Authority")

A subagent's report is a lead/evidence — never self-validating truth. Before relying on any claim or integrating code, inspect the actual `git diff`, file lines, or command/test output in the parent session.

## 3. Antigravity 2.0 Model Routing Matrix

`invoke_subagent` exposes tier choices (`inherit`, `flash_lite`, `flash`, `pro`), while `swarm` pins explicit models. **`gemini-3.8-flash-*` (`flash`, `flash_lite`) is banned across the stack.** `Orchestrator (Neon)` is acceptable only for planning and routine edits (its Execution Mode runs on the lightweight `gemini-flash-worker-agy`); **use direct `Gemini 4 Neon (High/XHigh)` for complex architecture and Codex review fixes (`R1 -> R4`)**.

| Task | Tool / Agent | Model |
|---|---|---|
| Unfamiliar subsystem mapping (`> 3–4` files) | `invoke_subagent(TypeName="code-explorer")` or `research` | `inherit` |
| Architecture/contracts, races/flakiness, SRE, tests | `swarm` (`repo-architect-scout`, `root-cause-debugger`, `infra-sre-diagnostician`, `test-author`) | `gemini-4-neon-medium`..`-xhigh` |
| Complex UI-to-Code | `swarm` (`frontend-ui-builder` in disjoint worktree/paths) | `gemini-4-neon-high` / `-xhigh` |
| Fast scouts / mechanical disjoint builders | `swarm` | `gemini-4-hydrogen-medium` / `-high` |
| Live UI / browser verification | `swarm` (`gemini-4-hydrogen-*`) -> `invoke_subagent(TypeName="browser", Model="inherit")` (or direct `inherit` if already on Hydrogen) | `gemini-4-hydrogen-low`..`-xhigh` |
| Technical translation | `swarm` (`gemini-4-hydrogen-*`) or direct `translator` | `gemini-4-hydrogen-low`..`-high` |
| Mandatory simplify (`STANDARD`: 1×; `HIGH`/`XHIGH`: 3 parallel lenses before review) | `swarm` (`simplify-reviewer` or `simplify-{reuse,quality,efficiency}`; `PreToolUse` injects fixed Claude prompts from `plugin/agents/simplify-*.md`; kill after completion; native `invoke_subagent` only if all 3 swarm tiers fail) | `claude-sonnet-5-5-high` → `gemini-4-neon-xhigh` → `gemini-4-hydrogen-xhigh` |
| Independent review (`HIGH`/`XHIGH`) | `carbon-stack codex-lane review` (fallback on Codex outage: `claude-opus-5-5-high` -> `gemini-4-neon-xhigh` [`HIGH`] / `gemini-4-carbon-high` [`XHIGH`]) | OpenAI Codex / Opus escalation |

## 4. Isolation & Cleanup Rules

1. Never assign overlapping writable files to concurrent agents in one tree; isolate writers via `workspace: "share"|"branch"`, `carbon-stack swarm-ctl worktree create`, or `carbon-stack chip-handoff open`.
2. Pass `BUSINESS_INTENT`, relevant plugins/MCP/skills, exact file boundaries, and read-only constraints in every worker brief.
3. Kill completed workers cleanly via `swarm(action="kill", ...)` instead of leaving idle workers; never call `read_board` and `swarm_wait` in the same turn.
