---
name: adversarial-review
description: "Pragmatic independent adversarial code review (codex-lane primary, Opus/Neon fallback) with finite closure."
---

# `/adversarial-review` — Pragmatic Independent Review

**Core principle:** *Review protects the implementation of business requirements — never protects the system from the business requirements themselves.* Machine-level Codex CLI details live in `~/.gemini/reference/codex-routing.md`.

## 1. Pre-Review Hygiene (`<= 30–40 KB`)

- State `3–5` core invariants before coding and split work into atomic commits/worktrees **`<= 30–40 KB`** (~500–1,000 LOC). Split candidates `> 80 KB` before launching Round 1.
- Complete local tests/checks first; optionally run one advisory `simplify` pass before Round 1 (`simplify` skill).
- Never use `gemini-3.8-flash-*` (`flash`/`flash_lite`); run complex architecture and Codex review fixes (`R1 -> R4`) on direct **`Gemini 4 Neon (High/XHigh)`** (not `Orchestrator (Neon)`, whose Execution Mode delegates to `gemini-flash-worker-agy`).

## 2. Primary Review: OpenAI Codex (`carbon-stack codex-lane`)

Always verify Codex availability first (`BypassSandbox=true` required for OpenAI HTTPS API calls & `CARBON_STACK_HOME` state):

```powershell
$null | carbon-stack codex-lane check
```

If `available: true`, run isolated single-lane review with `--intent`:

```powershell
$null | carbon-stack codex-lane review `
  --cwd "<repo_path>" `
  --session "<conversation-id>" `
  --intent "<original user goal, required capabilities, acceptance bar>" `
  --summary "<changes made, touched contracts, verified checks>"
```

- **`HIGH`** uses `gpt-6.2-sol` (`effort=high`); **`XHIGH`** (`--xhigh`) uses `gpt-6.2-astra` (`effort=ultra`).
- **Compact packet + clean delta resume:** Round 1 sends concise context + `git diff --stat` (inline diff only if `< 25 KB`; explicit `[TRUNCATED]` marker when capped); Rounds `2..4` and `--closure` automatically resume the same Codex thread with lean remediation interdiff and active `ANTI-BOOMERANG LEDGER`. Do not wrap with short custom `--timeout` values; a local timeout does not burn rounds or permit fallback.

## 3. Fallback Engine (Only on Verified Codex Outage / Unavailability)

Only when `codex-lane check` reports unavailable/open breaker or live Codex outage:
1. Run read-only `claude-opus-5-5-high` via `swarm` (`internal-reviewer`), passing full `BUSINESS_INTENT` and diff (`carbon-stack swarm-cache prepare --session "<id>" --cwd "<repo>" --label review`). Note PowerShell 5.1 syntax rules in the brief (e.g., use `[a..b]` instead of `[a:b]` slicing).
2. If `claude-opus-5-5-high` has 0% quota/error, escalate to `gemini-4-neon-xhigh` (`HIGH`) or `gemini-4-carbon-high` (`XHIGH`) (`adversarial-reviewer` / `adversarial-reviewer-xhigh`), then `swarm kill` reviewers cleanly on completion.

## 4. Handling Verdicts & `REVISE` Protocol

- **`VERDICT: APPROVED`** (rounds `1..4`) -> immediately finish and emit `[gate] verified: HIGH|XHIGH; <candidate and checks>`.
- **`VERDICT: REVISE`** -> **before touching code:**
  1. Formulate the structural invariant & owning layer (at **Round 2+**, replace bypassed regex/heuristic mechanisms structurally — never patch another symptom branch).
  2. Locate all callers/consumers (`carbon-stack code-search`, `tokenade impact`, `codebase-memory`) and read affected blocks cleanly.
  3. Decide per finding:
     - **`FIX`:** real `CRITICAL`/`HIGH` implementation bugs or missing proportional safeguards (`PRESERVES_INTENT: YES`, concrete `file:line` trigger) -> fix owning layer + add red→green regression test + rerun affected checks.
     - **`DISPOSE`:** findings conflicting with `BUSINESS_INTENT`, requesting feature removal, synthetic non-reachable puzzles, or style/taste noise -> record disposition so Codex never boomerangs it:
       ```powershell
       $null | carbon-stack codex-lane dispose `
         --cwd "<repo_path>" --session "<conversation-id>" `
         --finding "<short title>" --category "<intent-conflict|accepted-risk|no-practical-gain|deferred-improvement>" `
         --reason "<evidence-backed rationale>"
       ```
- **`Round 4: ESCALATE`** -> execute **one** focused research pass, then fix + re-test and run `<= 2` `--closure` passes in the same session (`READY` -> `verified`/`pr-ready`; 2nd `BLOCKED` -> `[gate] draft-blocked`). No reset cycles.
