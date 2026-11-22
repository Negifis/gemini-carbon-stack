---
name: token-optimization
description: "Context efficiency via serena LSP, codebase-memory, explicit tokenade CLI, and eager:false MCP."
---

# Token & Context Optimization Playbook

## 1. Structural & Symbolic Code Navigation

Locate definitions and blast radius before reading full blocks:
1. L0–L1: `carbon-stack code-search` (`rg`), `tokenade map [path]`, `tokenade skeleton <files...>`, `tokenade query <sym>`, `tokenade impact <file>`.
2. L2–L3: `codebase-memory` (`get_architecture`, `trace_path`, `detect_changes`) and `serena` (`get_symbols_overview`, `find_symbol`, `find_referencing_symbols`).
3. Read coherent blocks via `read_file` (`StartLine`/`EndLine`), never blind `[1-800]` dumps, lockfiles, build dirs, or `steps/*/output.txt`. Edit with native `edit_file`/`write_file`.

## 2. Explicit `tokenade` CLI (No Auto-Wrap Hook)

`tokenade-hook` automatic `CommandLine` wrapping is disabled to prevent shell/quoting breakage; invoke `tokenade` explicitly when needed:
- `tokenade read <office-doc> --prompt "q1, q2"` for PDF/Office passage extraction across multiple questions in one call.
- `tokenade search "<q1>" "<q2>"` and `tokenade web <u1> <u2>` for concurrent compact web lookups.
- `cmd | tokenade exec --lang python --script '<=20L>'` to filter/aggregate noisy command output before it enters context.

## 3. Lazy MCP Config Discipline

- Keep **all** servers across `~/.gemini/config/mcp_config.json`, `~/.gemini/antigravity/mcp_config.json`, `~/.gemini/antigravity-cli/mcp_config.json`, and plugin `mcp_config.json` manifests at `"eager": false` (except essential minimal tools if required), with no duplicate server registrations and secrets isolated in `~/.gemini/secrets/mcp-gate.env`.
- Restrict large MCP toolsets via `"enabledTools"` (e.g. `serena`: 8 read-only LSP tools; `context7`: `["resolve-library-id", "query-docs"]`).
