---
name: project-memory
description: CLI reference for carbon_memory.py (SQLite FTS5 durable facts and export-nlm). Load ONLY when storing, superseding, or recalling memory entries.
---

# Project & Global Engineering Memory

Локальное долговременное хранилище подтверждённых инженерных знаний (`~/.gemini/carbon-stack/state/memory/memory.db`, SQLite WAL + FTS5) с защитой от записи секретов и экспортом в формат, совместимый с NotebookLM.

## 1. Когда записывать в память

Записывайте **только подтверждённые на практике факты**, которые сэкономят время в будущих сессиях:
- `GOTCHA` — неочевидная ловушка среды, API или сборки (например: CLI зависает при открытом piped stdin на Windows).
- `RISK` — хрупкий инвариант или опасная зона кодовой базы.
- `DECISION` — принятое архитектурное решение и причина выбора.
- `CONSTRAINT` — жёсткое ограничение проекта или пользователя.
- `COMMAND` — проверенная команда сборки, тестов, миграции или диагностики.

## 2. Основные команды

```powershell
# Поиск релевантных знаний проекта и глобального уровня
python -X utf8 "<PLUGIN_ROOT>/tools/carbon_memory.py" recall --query "<запрос>" --cwd "<путь>"

# Сохранение подтверждённого факта (секреты и токены автоматически блокируются)
python -X utf8 "<PLUGIN_ROOT>/tools/carbon_memory.py" remember `
  --category GOTCHA `
  --scope project `
  --cwd "<путь>" `
  --text "<сжатая формулировка факта>" `
  --evidence "<файл/тест/команда>"

# Замена устаревшего факта новым (старый получает статус SUPERSEDED и больше не всплывает)
python -X utf8 "<PLUGIN_ROOT>/tools/carbon_memory.py" supersede `
  --id "mem-xxxxxxxxxxxx" `
  --text "<обновлённый факт>"

# Экспорт Markdown-пакета для последующей синхронизации с NotebookLM
python -X utf8 "<PLUGIN_ROOT>/tools/carbon_memory.py" export-nlm --cwd "<путь>"
```

## 3. Правила безопасности и честности

- Никогда не передавайте в `remember` API-ключи, пароли, токены, приватные ключи или строки подключения с учётными данными (`carbon_memory.py` отклонит их с кодом `2`).
- Если внешний мост `nlm-memory` отсутствует в системе, никогда не заявляйте об облачной синхронизации с NotebookLM — сообщайте честно о сохранении в локальную FTS5-базу (и локальном экспорте `export-nlm`, если он выполнялся).
