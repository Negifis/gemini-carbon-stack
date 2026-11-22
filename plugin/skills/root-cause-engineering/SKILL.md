---
name: root-cause-engineering
description: "Root-cause protocol for bugs, failing/flaky tests, lint/type regressions, or unclear runtime failures."
---

# Root-Cause Engineering Protocol

Apply for any bug, failing/flaky test, lint/type regression, unclear failure, or performance regression.

1. **Reproduce or characterize the failure:**
   - Capture exact command, error output, observed behavior, and expected behavior.
   - Check memory first (`nlm-memory recall "<symptom>"` / `carbon-stack carbon-memory recall`) — known gotchas surface in under a second.
   - Do not edit files blindly before isolating the failure boundary.
2. **Identify ownership:**
   - Locate the authoritative source of truth (contract, schema, state machine, lifecycle, type definition, config, or IPC boundary) using `carbon-stack code-search` (`rg`), `tokenade impact`, `codebase-memory`, or `serena`/`bsl-ls`.
   - Follow callers, callees, and state transitions across coherent code blocks rather than isolated snippets.
3. **Search existing patterns:**
   - Inspect sibling code paths, existing helpers, tests, and prior commits (`git log` / `git blame`).
4. **Form the root cause before editing:**
   - Which invariant failed, why here, and why did existing checks miss it?
   - For a failing test, lint, or type check: determine whether code or check is wrong from requirements, contracts, and `git log` / `git blame`. **Suspect the code first** when a previously passing check turns red.
   - On `REVISE` rounds, **never** add symptom branches/regex tweaks under an already-bypassed heuristic — replace the mechanism structurally at the owning layer.
5. **Fix the cause cleanly:**
   - Enforce invariants in types, validation, data flow, lifecycle, or storage ownership rather than caller patches or broad `except`/fallback masks.
   - Fix regressions and lint/type errors in source code; only fix check config when its resolver/path/version is factually broken (never silence or exclude rules).
   - Change tests only when asserted behavior was proven wrong or intentionally altered; never bend assertions/snapshots to match broken output.
6. **Verify both ways & record:**
   - Write/update a regression test that fails before the fix and passes after it.
   - Run narrow checks first, then affected suites.
   - Record confirmed root causes (`GOTCHA`) or open hazards (`RISK`) with `nlm-memory remember` / `carbon-stack carbon-memory remember`.
