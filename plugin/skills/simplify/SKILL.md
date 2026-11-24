---
name: simplify
description: "Mandatory single-pass code simplification using fixed Claude lens agents: 1x simplify-reviewer on STANDARD, 3 parallel lenses on HIGH/XHIGH before review."
---

# Mandatory Code Simplification (`/simplify`)

A bounded, behavior-preserving polish pass over the changed scope: clearer, more maintainable code that fits the repository. Enforced by `Code Work Gate` on `Stop` and before Round 1 `carbon-stack codex-lane review`.

## 1. Mandatory Passes by Risk

- **`LOW`:** never required (docs, comments, tests-only, static assets).
- **`STANDARD`:** **1 mandatory pass in 1 combined lens** via `invoke_subagent`:
  - `invoke_subagent(TypeName="simplify-reviewer", Role="Simplify Reviewer", Model="inherit", Prompt="<scope packet>")`
- **`HIGH` and `XHIGH`:** **1 mandatory pass in 3 parallel lenses BEFORE Round 1 `codex-lane review`** via `invoke_subagent` (launched together in one turn):
  1. `invoke_subagent(TypeName="simplify-reuse-reviewer", Role="Simplify Reuse Lens", Model="inherit", Prompt="<scope packet>")`
  2. `invoke_subagent(TypeName="simplify-quality-reviewer", Role="Simplify Quality Lens", Model="inherit", Prompt="<scope packet>")`
  3. `invoke_subagent(TypeName="simplify-efficiency-reviewer", Role="Simplify Efficiency Lens", Model="inherit", Prompt="<scope packet>")`

## 2. Fixed Prompts Only (No Custom Lens Prompts)

- The lens instructions are **fixed** in `plugin/agents/simplify-*.md` (ported from `claude-code-stack`). **Never** invent arbitrary lens instructions or substitute ad-hoc `swarm` briefs.
- Pass **only the bounded candidate packet** in `Prompt`:
  - repository / working directory (`cwd`) and changed files / `git diff` range;
  - core invariants that must hold (`BUSINESS_INTENT`, public contracts, nearby helpers worth knowing);
  - never tell a lens what to find or how its report should turn out.

## 3. Apply, Verify & Finite Failure Rule

1. Run **once** after local tests pass (and **before** Round 1 independent review on `HIGH`/`XHIGH`). Never repeat after review approval or during `REVISE` / `--closure` rounds.
2. Review returned findings critically; apply only concrete, behavior-preserving improvements (reject aesthetic churn, speculative abstractions, semantic changes, or test weakening).
3. If edits were applied, rerun affected tests/checks so final bytes are verified before closing (`STANDARD`) or launching `codex-lane review` (`HIGH`/`XHIGH`).
4. If a required simplify subagent fails, retry it once. After 2 failures on a required lens, record `SIMPLIFY_UNAVAILABLE` and finish finitely with `[gate] draft-blocked`.
