---
name: stack-doctor
description: "Health diagnostics for gemini-carbon-stack installation, hooks, Codex lane, and Language Server."
---

# `/stack-doctor` — Engineering Stack Health Check

Run end-to-end diagnostics via the installed `carbon-stack` binary:

```powershell
$null | carbon-stack stack-doctor --cwd "<workspace>"
```

Additional targeted checks:
- Installer & backups: `$null | carbon-stack install --diagnose`
- Gate anomaly inbox: `$null | carbon-stack gate-inbox list`
- External Codex reviewer health: `$null | carbon-stack codex-lane check`

Report status across Plugin & LS Ingestion, Hooks, Codex Lane, Memory (`nlm-memory` / FTS5), Active Chips, and Gate Inbox, plus exact remediation commands if anything degraded.
