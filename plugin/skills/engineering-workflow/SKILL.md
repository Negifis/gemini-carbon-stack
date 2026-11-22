---
name: engineering-workflow
description: "Core engineering standards before non-trivial code, config, schema, migration, or architecture changes."
---

# Engineering Workflow

Prefer root-cause fixes over symptom treatment. Apply before any non-trivial code, config, schema, migration, or API change.

## 1. Engineering Standards

- **No hacks or suppression:** Do not add broad fallbacks, silent error suppression, arbitrary sleeps/retries, hardcoded special cases, compatibility shims, or unsafe casts (`as any`) unless explicitly justified. Checks get no exceptions.
- If a workaround is unavoidable, include all five elements:
  1. `WORKAROUND:` label
  2. root cause explanation
  3. risk / limitation
  4. planned structural replacement
  5. smallest useful guard or regression test so it never becomes invisible debt
- Bounded retries are allowed only for documented transient failures with explicit limits and backoff — never masking permanent errors.

## 2. Repository Safety & Owning-Layer Fixes

- **Minimal in surface, complete in responsibility:** fix the owning layer, not every call site separately.
- Keep public APIs, generated files, schemas, migrations, and tests consistent with source definitions.
- Do not introduce new production dependencies without clear need and explanation.
- Preserve type safety, input validation, and useful diagnostic error context.
- Never skip, weaken, or suppress a test, lint rule, or type check (`eslint-disable`, `# noqa`, `# type: ignore`, `@ts-ignore`, `skip`/`xfail`, `--no-verify`), and never fit a test to broken code. Re-enable any disabled check found (`development-verification` §4).
- Change or remove a test only when its asserted behavior is proven wrong or intentionally changed (`root-cause-engineering`), stating which in the change.

## 3. Search Before Inventing

Before adding new helpers, types, endpoints, or configs, search existing implementations:
1. L0 exact text / symbols: `carbon-stack code-search grep|symbols` (`rg`)
2. L1 structure & dependents: `tokenade map | skeleton | query | impact`
3. L2 cross-module graph: `codebase-memory` (`get_architecture`, `trace_path`, `detect_changes`)
4. L3 compiler-exact LSP (`serena` / `bsl-ls`) and `nlm-memory recall "<topic>"` for prior decisions and constraints.

## 4. Development Workflow

1. Inspect coherent blocks of affected code, callers, tests, and config before editing (avoid tiny disconnected snippets). Recall prior decisions via `nlm-memory recall`.
2. For non-trivial tasks, state `3–5` key invariants first and slice changes into atomic commits or worktrees **`<= 30–40 KB`** (~500–1,000 LOC: `schema/contract -> core -> integration`).
3. Isolate parallel writers (`workspace: "share"|"branch"` or `carbon-stack chip-handoff open`); one writer per file.
4. Implement the smallest responsible fix at the owning layer.
5. Add or update contract/regression tests; run narrow checks first, then affected suites.
6. Record confirmed architectural decisions, root causes, or constraints with `nlm-memory remember` (or `carbon-stack carbon-memory remember`).

## 5. Writing Tests

- Tests record verified contract behavior, never whatever broken code currently outputs.
- Take expected values from specifications, requirements, or independent calculation; review snapshot diffs against requirements before accepting.
- A bug regression test MUST fail on unfixed code and pass after the fix — verify it both ways.
