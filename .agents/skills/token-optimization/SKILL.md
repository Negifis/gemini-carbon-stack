---
name: token-optimization
description: Playbook for token and context efficiency using Serena MCP symbolic navigation, Tokenade CLI log compaction, Context7 lazy docs, and subagent delegation. Load ONLY when optimizing token usage or configuring MCP/Tokenade tooling.
---

# Token & Context Optimization Playbook

## 1. Symbolic Code Navigation (`serena` MCP & `code_search.py`)

Prefer LSP symbol lookup over reading full source files:

1. **File symbol outline:** call `serena` `get_symbols_overview` (or `tokenade skeleton <file>`) to inspect classes, functions, and line spans before calling `read_file`.
2. **Definition & call-graph lookup:** call `serena` `find_symbol`, `find_referencing_symbols`, `find_implementations`, or `find_declaration` (fallback: `python -X utf8 plugin/tools/code_search.py symbols <query>`).
3. **Targeted line-range reads:** once the symbol span is known, call `read_file` with `StartLine` and `EndLine` (`<= 120` lines).
4. **All edits stay on native tools:** always perform file modifications via Antigravity's native `edit_file` / `write_file` so `code-work-gate` and `Loop Guard` track every change deterministically.

## 2. Terminal Log Compaction (`@tokenade/cli`)

- Global CLI hook (`~/.gemini/config/hooks.json`) wires `tokenade hookwrap-pretool` for `agy` CLI sessions, while `cwg_mark.py` and `safety_guards.py` transparently unwrap `tokenade wrap` / `tokenade raw` commands.
- Useful read-only Tokenade commands (recognized as `READ_ONLY` by Code Work Gate):
  - `tokenade map` — compact repository structure map.
  - `tokenade skeleton <path>` — function/class signatures without bodies.
  - `tokenade query <symbol>` — locate symbol definitions across files.
  - `tokenade expand-ref <hash>` — recover folded terminal output bytes on demand.
  - `tokenade healthcheck` / `tokenade gain` — verify wiring and inspect local token savings.

## 3. Lazy MCP Loading & Tool Filtering (`mcp_config.json`)

- Keep all MCP servers in `~/.gemini/config/mcp_config.json` and `~/.gemini/antigravity-cli/mcp_config.json` set to `"eager": false` so tool schemas load on demand via `call_mcp_tool`.
- Restrict multi-tool servers via `"enabledTools"`:
  - `serena`: `["activate_project", "get_symbols_overview", "find_symbol", "find_referencing_symbols", "find_implementations", "find_declaration", "search_for_pattern", "get_diagnostics_for_file"]` (8 read-only LSP tools instead of 24).
  - `context7`: `["resolve-library-id", "query-docs"]`.
