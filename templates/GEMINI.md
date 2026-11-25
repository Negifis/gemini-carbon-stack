# Global Context (Antigravity 2.0)

Core engineering and Code Work Gate rules live in `gemini-carbon-stack` (`AGENTS.md`); on-demand machine paths, lazy MCP catalog, Semgrep cascades, and Codex flags live in `~/.gemini/reference/environment.md` and `~/.gemini/reference/codex-routing.md` (read only when needed).

## Navigation & CLI Tools (`tokenade`, `read_file`)

- Native `read_file` directly supports text, images, PDF, video, and audio (`StartLine`/`EndLine` for code). Use it normally for media and focused file reads.
- Invoke `tokenade` explicitly when discovering unfamiliar structure or extracting passages from Office docs/huge files (auto-wrap hook is off):
  - `tokenade map [path]` / `skeleton <files...>` / `query <sym...>` / `impact <file>` / `semantic "<query>"` (batch multiple files in one call).
  - `tokenade read <doc> --prompt "q1, q2"` for Office/PDF text extraction across multiple questions in one round-trip.
  - `tokenade search "<q1>" ...` / `tokenade web <u1> ...` / piped `cmd | tokenade exec --lang python --script '<=20L>'` to keep noisy output out of context.

## Verification & Host Defaults

- **Windows PowerShell 5.1 (`run_command`):** no `&&`, `||`, `<<`, `/dev/null` (`$null`), or GNU `sed`/`awk`/`head`/`tail`; close stdin (`$null | <cmd>`).
- **Verification (`Code Work Gate`):** `LOW` (deterministic check), `STANDARD` (affected tests -> mandatory `1× simplify-reviewer` via `swarm` on `claude-sonnet-5-5-high`, fallback `gemini-4-neon-xhigh` -> `gemini-4-hydrogen-xhigh`), `HIGH`/`XHIGH` (decisive tests -> mandatory `1×` 3 fixed lenses `simplify-reuse`, `simplify-quality`, `simplify-efficiency` via `swarm` Sonnet -> Neon -> Hydrogen BEFORE review -> `carbon-stack codex-lane review` `1..4` rounds, `APPROVED` closes immediately; after `Round 4: ESCALATE` -> 1 focused research pass -> `<= 2` `--closure` passes -> `verified`/`pr-ready` or terminal `[gate] draft-blocked`). No reset cycles.
