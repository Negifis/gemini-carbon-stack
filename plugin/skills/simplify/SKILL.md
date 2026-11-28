---
name: simplify
description: "Mandatory single-pass code simplification with fixed Claude lens prompts via swarm (claude-sonnet-5-5-high -> gemini-4-neon-xhigh -> gemini-4-hydrogen-xhigh): 1x simplify-reviewer on STANDARD, 3 parallel lenses on HIGH/XHIGH before review."
---

# Mandatory Code Simplification (`/simplify`)

A bounded, behavior-preserving polish pass over the changed scope: clearer, more maintainable code that fits the repository. Enforced by `Code Work Gate` (`PreToolUse` fixed-prompt injection & model priority guard, `Stop` gate, and Round 1 `carbon-stack codex-lane review` guard).

## 1. Mandatory Passes by Risk (Call `swarm` Directly)

This skill explicitly authorizes invoking the native `swarm` tool for mandatory simplification so exact models can be pinned (`invoke_subagent` only accepts Gemini tiers):

- **`LOW`:** never required (docs, comments, tests-only, static assets).
- **`STANDARD`:** **1 mandatory pass in 1 combined lens** via `swarm` (if all 3 `HIGH`/`XHIGH` lenses already completed for the candidate, they strictly satisfy `STANDARD` without running an extra `simplify-reviewer`):
  - `swarm(action="add", name="simplify-reviewer", model="claude-sonnet-5-5-high", brief="<scope packet>")`
- **`HIGH` and `XHIGH`:** **1 mandatory pass in 3 parallel lenses BEFORE Round 1 `codex-lane review`** via `swarm` (launched together in one turn):
  1. `swarm(action="add", name="simplify-reuse", model="claude-sonnet-5-5-high", brief="<scope packet>")`
  2. `swarm(action="add", name="simplify-quality", model="claude-sonnet-5-5-high", brief="<scope packet>")`
  3. `swarm(action="add", name="simplify-efficiency", model="claude-sonnet-5-5-high", brief="<scope packet>")`

## 2. Model Priority & Verified-Outage Fallback Chain

1. **Primary (mandatory first try):** `claude-sonnet-5-5-high` (`Claude Sonnet 5.5 (High)`).
2. **Fallback #1 (ONLY after verified Sonnet error / 0% quota / unavailability):** `gemini-4-neon-xhigh` (`Gemini 4 Neon (XHigh)`). Use `swarm(action="model", name="<worker>", model="gemini-4-neon-xhigh")` for a waiting worker, or `swarm(action="add", name="<worker>-2", model="gemini-4-neon-xhigh", brief="<scope packet>")`.
3. **Fallback #2 (ONLY after verified Sonnet AND Neon failures):** `gemini-4-hydrogen-xhigh` (`Gemini 4 Hydrogen (XHigh)`).
4. **Last-resort native fallback (ONLY when all 3 swarm tiers fail):** `invoke_subagent(TypeName="simplify-reviewer" | "simplify-{reuse,quality,efficiency}-reviewer", Model="inherit", Prompt="<scope packet>")`.
5. **Strictly forbidden:** `flash`/`flash_lite`/`gemini-3.8-flash-*`, `claude-opus-*`, `gemini-4-carbon-*`, empty model, or skipping Sonnet without verified failure evidence.

## 3. Fixed Prompts Only (Auto-Injected via `PreToolUse`)

- The lens instructions are **fixed** verbatim from `plugin/agents/simplify-*.md` (ported from `claude-code-stack`). `PreToolUse` (`safety_guards.rs`) deterministically rewrites `brief` via `overwrite` to prepend `[FIXED_SIMPLIFY_LENS: <lane>]`, the verbatim Claude lens prompt, and the swarm board reporting rule.
- **Never** invent arbitrary lens prompts or non-canonical worker names (unknown `simplify-*` names are denied).
- Pass **only the bounded candidate packet** in `brief`:
  - repository / working directory (`cwd`) and changed files / `git diff` range;
  - core invariants that must hold (`BUSINESS_INTENT`, public contracts, nearby helpers worth knowing);
  - never tell a lens what to find or how its report should turn out.

## 4. Collect, Apply, Kill & Verify

1. Run **once** after local tests pass (and **before** Round 1 independent review on `HIGH`/`XHIGH`). Never repeat after review approval or during `REVISE` / `--closure` rounds.
2. Wait for worker posts (`swarm_wait(since=<last_seq>, mentions_only=false)`), read findings via `read_board(since=<last_seq>)`, and **kill all simplify workers** via `swarm(action="kill", name="...")` immediately after collecting their reports (unkilled simplify workers block both `codex-lane review` and `Stop`).
3. Review findings critically; apply only concrete, behavior-preserving improvements (reject aesthetic churn, speculative abstractions, semantic changes, or test weakening).
4. If edits were applied, rerun affected tests/checks so final bytes are verified before closing (`STANDARD`) or launching `codex-lane review` (`HIGH`/`XHIGH`).
5. If a required simplify lens fails across retries (`>= 2` failures after all 3 swarm tiers degrade, or `>= 3` failures), record `SIMPLIFY_UNAVAILABLE` and finish finitely with `[gate] draft-blocked`.
