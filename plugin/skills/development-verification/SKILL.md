---
name: development-verification
description: "Code Work Gate verification: Operational Track, risk floors, test/disabled-check rules, and finite closure."
---

# Development Verification & Code Work Gate

Single code-work completion contract aligned with `cwg_mark.rs` and `cwg_stop.rs`. Never wrap this gate in extra outer loops.

## 1. Work Classification

- **`NO_CHANGE`:** read-only inspection, diagnosis, planning — closes without a `[gate]` receipt.
- **`OPERATIONAL`:** live system action via shell or throwaway script outside repositories (`C:/tmp`, session scratchpad) — follows **Operational Track** (§2); auto-retires at Stop cleanly without blocking. Unintended lasting edits restored cleanly back to `opening_head` (`git merge-tree` / `kept_commit_blocker` clean) also auto-retire (`undo-clean`).
- **`PERSISTENT`:** any lasting change to repository source, config, migrations, docs, or executable instructions — follows risk floors (§3) and closes with `[gate] verified: <RISK>; <candidate and checks>` (or closure receipt).

## 2. Operational Track

Before mutating a live system (server, DB, remote account, service):
1. Confirm exact target from the live system itself (disk, host, DB, account) — never from memory.
2. Establish reversibility (backup, snapshot, export, rollback path, or explicit blast-radius statement).
3. Run read-only precheck / dry-run first when available.
4. For irreversible wide-blast-radius changes, validate the plan before execution (never post-hoc).

After running: verify actual system state matches expected outcome and separate verified facts from assumptions. Never run `simplify` or code review on executed throwaway scripts. Close with `[gate] operational: <precheck>; <verified effect>` (or `no-change` if nothing changed).

## 3. Risk Floors (`PERSISTENT`)

Determine risk by blast radius, data sensitivity, reversibility, and security boundary — not raw line count:
- **`LOW`:** docs, comments, tests-only, static assets — run relevant deterministic checks; no independent review.
- **`STANDARD`:** bounded logic or UI edits outside critical paths — run affected tests/linters (`require_tests_on_standard` if configured) + **mandatory 1× `simplify-reviewer`** via `swarm(action="add", name="simplify-reviewer", model="claude-sonnet-5-5-high", ...)` (fallback `gemini-4-neon-xhigh` -> `gemini-4-hydrogen-xhigh` only on verified outage; `PreToolUse` injects fixed Claude prompt from `plugin/agents/simplify-reviewer.md`; a completed 3-lens pass `simplify-reuse`/`simplify-quality`/`simplify-efficiency` also satisfies `STANDARD` so no extra `simplify-reviewer` pass is needed; kill worker(s) after completion; rerun tests if accepted edits were applied). Keep diffs compact (`<= 30–40 KB` per step).
- **`HIGH`:** auth/permissions/secrets/crypto, DB migrations/schemas, CI/CD/deploy/release, plugin runtime hooks/manifests (`rust/src/**`, `hooks.json`, `mcp_config.json`), or wide cross-component diffs — affected checks + **mandatory 1× 3-lens simplify before review** (`simplify-reuse`, `simplify-quality`, `simplify-efficiency` via `swarm` on `claude-sonnet-5-5-high`, fallback `gemini-4-neon-xhigh` -> `gemini-4-hydrogen-xhigh`, killed before review) + independent review (`carbon-stack codex-lane review`, fallback `adversarial-reviewer` only on verified Codex outage; `1..4` rounds, `BLOCKING_THRESHOLD = HIGH`, `VERDICT: APPROVED` closes immediately).
- **`XHIGH`:** fragile concurrency/state machines, security/hook enforcement invariants, complex cryptography, or critical multi-component boundaries — same track (**mandatory 1× 3-lens simplify before review** via `swarm` Sonnet -> Neon -> Hydrogen + `--xhigh` review on `gpt-6.2-astra` `ultra` in Codex, or `adversarial-reviewer-xhigh` fallback).

## 4. Candidate Verification & Disabled Checks

- Bind evidence to final file bytes (`cwg_stop.rs` tracks content SHA-256 `content_marks`; any edit after `APPROVED`/`READY` invalidates the verdict and requires re-testing + delta review; clean upstream merges via `git merge-tree` and pure git integration commands stay clean).
- Never ignore failing checks (unit, integration, e2e, lint, types, build — including pre-existing or flaky):
  - Failures caused by or inside task scope: fix root cause in source (`root-cause-engineering`).
  - Pre-existing out-of-scope failures: hand off to a worktree subagent or `carbon-stack chip-handoff open` (verify reproduction on base revision without mixing fixes into current candidate). Parent verifies every handoff result.
- **Disabled checks are hidden failures:** never add skip/xfail markers, `eslint-disable`, `# noqa`, `# type: ignore`, `@ts-ignore`, linter exclusions, or `--no-verify`; re-enable any encountered in touched scope and fix underlying causes.
- Unavailable checks (missing service/credentials): state honestly what could not run and why; never report unrun checks as passing.

## 5. Finite Review & Autonomous Closure

- **Mandatory `simplify` (`simplify` skill):** enforced via `PreToolUse` (fixed Claude prompt injection + model priority), `Stop`, and Round 1 `codex-lane review` — `STANDARD`: 1× `simplify-reviewer` (a completed 3-lens pass also satisfies `STANDARD`); `HIGH`/`XHIGH`: 1× 3 parallel fixed lenses (`simplify-reuse`, `simplify-quality`, `simplify-efficiency`) via `swarm(action="add", model="claude-sonnet-5-5-high", ...)` (fallback `gemini-4-neon-xhigh` -> `gemini-4-hydrogen-xhigh` only on verified failure; native `invoke_subagent(..., Model="inherit")` only if all 3 swarm tiers fail; kill workers before review/closure; never repeated after review; exhausted retries allow finite `[gate] draft-blocked` with `SIMPLIFY_UNAVAILABLE`).
- **Review loop (`1..4` rounds, `BLOCKING_THRESHOLD = HIGH`):** only `CRITICAL`/`HIGH` defects with concrete reachable triggers (and broken acceptance criteria) block. Dismiss `Class C/D` / intent-conflicting noise via `carbon-stack codex-lane dispose`.
- **After `Round 4: ESCALATE`:** freeze open blockers, run **one** focused evidence pass (code, tests, Context7, web), then fix + re-test and run `<= 2` `--closure` passes in the same session (`CLOSURE_VALIDATION: READY` -> `[gate] verified` / `[gate] pr-ready`; 2nd `BLOCKED` -> terminal `[gate] draft-blocked: <blocker and handoff>`). No reset cycles.
- **Comment hygiene (`comment-density-guard`):** `PreToolUse` rejects overly dense/narration comments on code edits; keep comments limited to `INVARIANT:`, `SAFETY:`, and `WORKAROUND:`.
- **Active production incident:** apply smallest reversible mitigation + smoke check to stop user harm first, then complete proportionate verification and report both states distinctly.

## 6. Terminal Receipts & Anomalies

End `PERSISTENT` completions with one factual final line:
- `[gate] verified: <LOW|STANDARD|HIGH|XHIGH>; <candidate and checks>`
- `[gate] pr-ready: <branch/PR and closure summary>` | `[gate] draft-blocked: <blocker and handoff>`

If a Stop block contradicts facts verifiable in the transcript: run `carbon-stack gate-inbox report` (using the nonce from the block), notify handler chat `a508fe71-2b38-458a-b726-7529ddc212ac` (`send_message` or `chat-bus`), and close with `[gate] anomaly-reported: <id>; <fact>`.
