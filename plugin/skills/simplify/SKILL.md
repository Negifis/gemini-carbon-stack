---
name: simplify
description: "Advisory single-pass code simplification (Reuse, Quality, Efficiency) before review via Sonnet or Neon."
---

# Advisory Code Simplification (`/simplify`)

Advisory single-pass polish run **after local tests pass and BEFORE Round 1 independent review** on `HIGH`/`XHIGH` work (or complex `STANDARD` changes). Simplification does not hard-block `Stop` and never runs again after `APPROVED` or during review remediation.

## 1. Execution Modes

- **Compact diff (`<= 2` files & `<= 30` changed lines):** spawn 1 combined read-only worker (`simplify-reviewer`) on `claude-sonnet-5-5-high` (fallback `gemini-4-neon-xhigh`, secondary `gemini-4-hydrogen-xhigh`, never Carbon) covering Reuse, Quality, and Efficiency together.
- **Larger candidate (`> 2` files or `> 30` changed lines):** spawn 3 parallel read-only workers via `swarm` (`claude-sonnet-5-5-high`, fallback `gemini-4-neon-xhigh`):
  1. `simplify-reuse` — duplicated helpers, literals, validation/query shapes, reinvented repo/stdlib utilities.
  2. `simplify-quality` — deep nesting, dead branches/imports, sloppy comments, error/validation boundaries (`explicit` > `clever`).
  3. `simplify-efficiency` — redundant loops/I-O/stat/subprocesses, repeated parsing, missing cleanup, quadratic scans.

Prepare diff context before spawning:
```powershell
$null | carbon-stack swarm-cache prepare --session "<conversation-id>" --cwd "<repo_path>" --label simplify
```

## 2. Lens Worker Brief Template

Use this concise brief template for each lens worker (no separate `.md` agent needed):

```text
Strictly read-only <REUSE|QUALITY|EFFICIENCY> simplification review of <repo_path> (diff: <diff_path>, files: <paths>).
Preserve `BUSINESS_INTENT`: <goal>. Do not propose removing requested features or rewriting unrelated modules.
Report up to 5 concrete findings under `### <Lens>`. Each finding MUST state: `file:line`, defect, exact behavior-preserving edit shape, **why behavior is preserved**, and verification needed (or `No actionable <lens> simplifications.`).
Save long notes to `.swarm/artifacts/<worker>-1.md` and end board summary with `SIMPLIFY_VERDICT: CLEAN|ACTIONABLE_FIXES`.
```

## 3. Apply & Cleanup

1. Review returned findings critically (reject speculative rewrites or risky edge-case changes).
2. Apply accepted edits cleanly, rerun affected tests, and kill all `waiting` simplify workers via `swarm(action="kill", ...)` before starting `codex-lane review`.
