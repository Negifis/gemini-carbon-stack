---
name: task-start
description: "Start non-trivial tasks: audit worktrees, recall memory, locate targets, and initialize handoff."
---

# `/task-start` — Engineering Task Initialization

Run a compact orientation sequence before editing non-trivial features or multi-file tasks:

1. **Inspect tree & worktrees:** Run `git status --short --branch` and `carbon-stack worktree-guard audit`; if unrelated dirty changes exist, isolate work cleanly in disjoint files or `carbon-stack chip-handoff open`.
2. **Recall prior decisions & constraints:** Query `nlm-memory recall "<keywords>"` (and `carbon-stack carbon-memory recall --query "<keywords>" --cwd "<path>"` offline).
3. **Locate entrypoints & contracts:** Map target symbols, callers, and tests via `carbon-stack code-search`, `tokenade map`/`impact`, and `codebase-memory`.
4. **State invariants, slices & handoff:** Formulate `3–5` core invariants, keep work sliced into `<= 30–40 KB` (~500–1,000 LOC) stages, and for multi-session work save `GOAL`, `AUTHORITATIVE STATE`, `ACCEPTANCE`, and `NEXT ACTION` via `carbon-stack continuity handoff`.
5. Proceed immediately into execution rather than stopping after orientation.
