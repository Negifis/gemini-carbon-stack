---
name: current-docs
description: "Version-pinned external SDK/API verification via manifests, Context7 MCP, and web search cascade."
---

# Current Documentation Verification

Never write external library, framework, CLI, or SDK integration code from stale training memory. Verify installed versions and current official APIs first.

1. **Pin Exact Local Version:** Read the project manifest/lockfile (`package.json`, `Cargo.toml`, `pyproject.toml`, `pubspec.yaml`, `go.mod`) or `<cli> --help` / `pip show` / `npm ls` to establish exact major/minor versions.
2. **Check Local Types & Builtins:** Inspect installed `.d.ts` / Python/Rust source signatures or Antigravity builtin docs (`agy-customizations`, `antigravity_guide`) directly on disk.
3. **Version-Pinned Context7 Lookup (`ServerName="context7"`):**
   - Inspect `~/.gemini/antigravity/mcp/context7/*.json` if needed, then call `resolve-library-id` -> `query-docs` (passing `/org/project/<version>` when manifest-pinned). Limit to focused queries with zero secrets.
4. **Web & GitHub Cascade:** For OSS internals or docs missing in Context7, check `deepwiki` (`read_wiki_structure` -> `ask_wiki_question`), `exa` (`web_search_exa` / `web_fetch_exa`), or `$null | tokenade search "<query>"` + `fetch`.
5. **Reuse Before Wrapping:** Search existing project client wrappers, error types, and retry helpers before adding new glue.
