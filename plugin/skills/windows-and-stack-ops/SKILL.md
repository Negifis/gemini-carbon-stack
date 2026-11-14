---
name: windows-and-stack-ops
description: Windows NT / PowerShell 5.1 operational patterns, stdin pipe discipline, Restart Manager file-lock inspection (`file-holders.ps1`), NTFS junction safety (`worktree_guard.py`), and fast native search (`code_search.py`).
---

# Windows Runtime & Stack Operations

Практические правила работы в окружении **Windows NT + PowerShell 5.1 + Python 3.13 + Git for Windows**.

## 1. Особенности PowerShell 5.1 и подпроцессов

- В Windows PowerShell `5.1` оператор `&&` недоступен (в отличие от `pwsh` 7): разделяйте команды через `;` с проверкой `$LASTEXITCODE` либо выполняйте многошаговую логику однострочником `python -X utf8 -c "..."`.
- Всегда передавайте `-X utf8` при запуске Python-скриптов, чтобы исключить сбои `cp1251`/`cp866` на кириллице и спецсимволах.
- В `run_command` пайп `stdin` открыт для интерактивного ввода. Для утилит, ожидающих EOF на stdin (`codex exec`, фильтры), закрывайте вход явно: `$null | <команда>` в PowerShell или `stdin=subprocess.DEVNULL` в Python.

## 2. Встроенные утилиты стека (`<PLUGIN_ROOT>/tools/`)

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
