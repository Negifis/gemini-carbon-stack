---
name: windows-and-stack-ops
description: Windows NT / PowerShell 5.1 operational patterns, stdin pipe discipline, Restart Manager file-lock inspection (`file-holders.ps1`), NTFS junction safety (`worktree_guard.py`), fast native search (`code_search.py`), and TTL-aware swarm incremental diffs (`swarm_cache.py`).
---

# Windows Runtime & Stack Operations

Практические правила работы в окружении **Windows NT + PowerShell 5.1 + Python 3.13 + Git for Windows**.

## 1. Особенности Windows PowerShell 5.1 и предотвращение сбоев команд

| Частая ошибка из bash/Linux | Правильно в Windows PowerShell 5.1 |
|---|---|
| `cmd1 && cmd2` или `cmd1 \|\| cmd2` | `cmd1; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; cmd2` |
| `python - <<'EOF' ... EOF` или `< file` | `@' ... '@ \| python -X utf8 -` |
| `(Get-Content f)[10:20]` (срез Python) | `(Get-Content f)[10..20]` или `read_file(Path=..., StartLine=11, EndLine=21)` |
| `sed`, `awk`, `head`, `tail`, `rg` | `read_file`, `code_search.py`, `git grep -n`, `Select-String`, `Select-Object -First/-Last` |
| `python -m pyflakes ...` | `python -X utf8 -m py_compile ...` или `ast.parse` (пакет `pyflakes` не установлен) |
| `2>/dev/null` или `python ...` без кодировки | `2>$null` / `$null \| ...` и всегда `python -X utf8` |
| `python -m unittest ... 2>&1 \| Select-Object` | Запускайте `python -X utf8 -m unittest ...` напрямую (вывод `OK` в `stderr` порождает `NativeCommandError`) |

- В `run_command` пайп `stdin` открыт для интерактивного ввода. Для утилит, ожидающих EOF на stdin (`codex exec`, фильтры), закрывайте вход явно: `$null | <команда>` в PowerShell или `stdin=subprocess.DEVNULL` в Python.

## 2. Встроенные утилиты стека (`<PLUGIN_ROOT>/tools/`)

- **Контроль 5-минутного TTL кэша `swarm` и генерация инкрементального диффа:**
  ```powershell
  python -X utf8 "<PLUGIN_ROOT>/tools/swarm_cache.py" status --session "<id>" --label simplify
  python -X utf8 "<PLUGIN_ROOT>/tools/swarm_cache.py" prepare --session "<id>" --cwd "<путь>" --label simplify
  ```
- **Поиск символов и кода (замена отсутствующим `rg`/`jev`):**
  ```powershell
  python -X utf8 "<PLUGIN_ROOT>/tools/code_search.py" symbols "<имя>" --cwd "<путь>"
  python -X utf8 "<PLUGIN_ROOT>/tools/code_search.py" grep "<шаблон>" --cwd "<путь>"
  ```
- **Кто держит заблокированный файл на Windows (`ERROR_SHARING_VIOLATION`):**
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File "<PLUGIN_ROOT>/tools/file-holders.ps1" -Path "<путь к файлу>"
  ```
- **Безопасная работа с git worktrees и снимками грязного дерева:**
  ```powershell
  python -X utf8 "<PLUGIN_ROOT>/tools/worktree_guard.py" audit --cwd "<путь>"
  python -X utf8 "<PLUGIN_ROOT>/tools/worktree_guard.py" snapshot --worktree "<путь>" --label "pre-op"
  python -X utf8 "<PLUGIN_ROOT>/tools/worktree_guard.py" remove --worktree "<путь>"
  ```
