---
trigger: model_decision
description: "Load ONLY when delegating to swarm workers, Hydrogen browser/translator subagents, or parallel git worktree chips."
---

# Multi-Agent & Hydrogen Routing Rules

1. **Запрет `Gemini Flash` и защита квоты Carbon:** никогда не передавайте `Model="flash"`, `flash_lite` или `gemini-3.8-flash-*`. Для вспомогательных ролей (`browser`, `translator`, разведка) используйте **`Gemini 4 Hydrogen`** (`gemini-4-hydrogen-low` для smoke/короткого перевода, `-medium` для UI QA/доков, `-high` для сложных SPA, `-xhigh` для гонок состояния и **fallback-линз `simplify` при исчерпании квоты Sonnet** — прямой вызов `simplify-*-reviewer` из Carbon-сессии заблокирован хуком `safety_guards.py`).
2. **Делегирование `browser` с не-Hydrogen координатора:** запустите через `swarm` воркера с `model="gemini-4-hydrogen-<level>"`, который вызовет `invoke_subagent(TypeName="browser", Model="inherit")`; проверяйте результат строго по `BROWSER_HOST_FACTS`.
3. **Одно владение файлом:** при параллельной разработке выдавайте каждому пишущему воркеру `workspace: "share"` / `"branch"` или изолированный worktree через `chip_handoff.py open`. Интеграция изменений в рабочее дерево принадлежит только координатору.
4. **Защита от вечного ожидания `swarm_wait`:** никогда не вызывайте `read_board` и `swarm_wait` в одной пачке tool calls (одном ходе): `read_board` сдвигает `last_read_seq` до текущего `head`, после чего `swarm_wait` засыпает в ожидании уже несуществующих сообщений. Сначала вызовите только `read_board`, проверьте ответы всех воркеров, убейте завершивших через `swarm(action="kill", ...)` и вызывайте `swarm_wait` только если часть воркеров ещё работает.
