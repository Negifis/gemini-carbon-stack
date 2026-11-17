---
name: import-claude-chats
description: Triggered by /import-claude-chats to import interactive Claude Code sessions (~/.claude/projects) into Google Antigravity across all 5 storage layers with continuation merging, checkpointing, and FTS5 indexing.
---

# `/import-claude-chats` — Импорт истории чатов Claude Code в Google Antigravity

Переносит интерактивные диалоги из `~/.claude/projects` во все 5 слоёв хранения Antigravity (`conversations/<id>.db`, `annotations/<id>.pbtxt`, `conversation_summaries.db` + FTS5 `conversations_fts`, `agyhub_summaries_proto.pb` и `brain/<id>/.system_generated/logs/transcript*.jsonl`) без модификации исходных файлов Claude Code.

## 1. Предпросмотр (`--dry-run`)

Проверьте список обнаруженных интерактивных сессий и склеенных цепочек продолжений перед записью:

```powershell
python -X utf8 "<PLUGIN_ROOT>/tools/claude_chat_importer.py" --dry-run --json
```

## 2. Полный импорт и верификация

Выполните идемпотентный импорт (автоматически создаёт резервную копию в `<antigravity_dir>/backups/pre_claude_import`) и проверку целостности всех 5 слоёв:

```powershell
python -X utf8 "<PLUGIN_ROOT>/tools/claude_chat_importer.py" --json
python -X utf8 "<PLUGIN_ROOT>/tools/claude_chat_importer.py" --verify --json
```

Для выборочного импорта конкретных папок проектов передайте `--projects "<PROJECT_FOLDER_1>,<PROJECT_FOLDER_2>"`.

## 3. Синхронизация `agyhub_summaries_proto.pb` после закрытия Antigravity

Пока запущен `language_server.exe`, он периодически сбрасывает свой оперативный снимок сводок в `agyhub_summaries_proto.pb`. Если после перезапуска Antigravity новые чаты не отобразились, закройте Antigravity и выполните быструю синхронизацию из SQLite:

```powershell
python -X utf8 "<PLUGIN_ROOT>/tools/claude_chat_importer.py" --sync-pb-only
```
