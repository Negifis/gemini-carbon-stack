---
name: windows-and-stack-ops
description: "Windows PowerShell 5.1 rules, file-holders.ps1, carbon-stack worktree-guard, and swarm-cache CLI."
---

# Windows Runtime & Stack Operations

Rules for **Windows NT + PowerShell 5.1 + Python 3.12 + Git for Windows**.

## 1. Windows PowerShell 5.1 & Local Environment

| Avoid (Linux/bash habits) | Use in Windows PowerShell 5.1 |
|---|---|
| `cmd1 && cmd2` or `cmd1 \|\| cmd2` | `cmd1; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; cmd2` |
| `python - <<'EOF' ... EOF` or `< file` | `@' ... '@ \| C:\Users\in\AppData\Local\Programs\Python\Python312\python.exe -` |
| Colon range syntax inside `[...]` | PowerShell range `(Get-Content f)[10..20]` or `read_file(Path=..., StartLine=11, EndLine=21)` |
| GNU `sed`, `awk`, `head`, `tail` | `read_file`, `rg`, `carbon-stack code-search`, `git grep -n`, `Select-String`, `Select-Object -First/-Last` |
| `python -m pyflakes ...` | `python -X utf8 -m py_compile ...` or `ast.parse` |
| `2>/dev/null` or piped `unittest \| Select-Object` | `$null \| ...` / `2>$null`, run `unittest` directly |

- **Machine paths & PATH shadowing:** Verify which executable runs when native and npm/venv installs coexist. Use Python 3.12 (`C:\Users\in\AppData\Local\Programs\Python\Python312\python.exe`), Ripgrep (`C:\tools\ripgrep-15.1.0-x86_64-pc-windows-msvc\ripgrep-15.1.0-x86_64-pc-windows-msvc\rg.exe`, also in `PATH`), and Rust GNU toolchain (`+stable-x86_64-pc-windows-gnu`). Close `stdin` on CLIs (`$null | <cmd>`).

## 2. Carbon Stack Utilities

```powershell
# Code & symbol search (wraps rg cleanly):
$null | carbon-stack code-search symbols "<name>" --cwd "<path>"
$null | carbon-stack code-search grep "<pattern>" --cwd "<path>"

# Swarm diff cache & incremental interdiffs:
$null | carbon-stack swarm-cache status --session "<id>" --label simplify
$null | carbon-stack swarm-cache prepare --session "<id>" --cwd "<path>" --label simplify

# File-lock holders (ERROR_SHARING_VIOLATION):
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Users\in\.gemini\config\plugins\gemini-carbon-stack\tools\file-holders.ps1" -Path "<file>"

# Safe worktree snapshots, NTFS junction detachment, and removal:
$null | carbon-stack worktree-guard audit --cwd "<path>"
$null | carbon-stack worktree-guard snapshot --worktree "<path>" --label "pre-op"
$null | carbon-stack worktree-guard remove --worktree "<path>"
```
