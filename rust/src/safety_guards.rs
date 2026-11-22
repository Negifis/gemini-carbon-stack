use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::cwg_common;
use crate::rio::{self, json_truthy, resolve_command_cwd, val_to_i64, val_to_str};

fn hydrogen_policy_msg() -> String {
    format!(
        "[Model Policy Guard] Модели Gemini Flash отключены. Используйте `Gemini 4 Hydrogen` с уровнем размышления по сложности задачи: `{}` (атомарный smoke-check, <=150 строк перевода), `{}` (стандартный UI/перевод/разведка), `{}` (сложные многошаговые сценарии и спецификации) или `{}` (тяжёлая отладка состояний и гонок).",
        cwg_common::HYDROGEN_LOW_MODEL,
        cwg_common::HYDROGEN_MEDIUM_MODEL,
        cwg_common::HYDROGEN_HIGH_MODEL,
        cwg_common::HYDROGEN_XHIGH_MODEL,
    )
}

fn bare_worktree_remove_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\bgit(?:\.exe)?\s+(?:[^\n;|&]*\s+)?worktree\s+remove\b")
            .expect("bare_worktree_remove_re")
    })
}

fn destructive_git_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\bgit(?:\.exe)?\s+(?:[^\n;|&]*\s+)?(?:reset\s+--hard|checkout\s+--\s+\.|restore\s+(?:--staged\s+--worktree\s+|--worktree\s+)?\.|clean\s+-[a-zA-Z]*f[a-zA-Z]*)",
        )
        .expect("destructive_git_re")
    })
}

fn cmd_backtick_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"`([A-Za-z0-9_-])").expect("cmd_backtick_re"))
}

fn abspath_lexical(p: &Path) -> PathBuf {
    rio::resolve_abs_path(p)
}

fn abspath_lexical_str(raw: &str) -> String {
    abspath_lexical(Path::new(raw)).to_string_lossy().into_owned()
}

fn strip_cmd_backticks(text: &str) -> String {
    // SAFETY: Normalize PowerShell backtick-escaped command tokens in `norm_cmd` while `stripped` preserves literal paths.
    if !text.contains('`') {
        return text.to_string();
    }
    cmd_backtick_re().replace_all(text, "$1").into_owned()
}

pub fn guard_shell_command_with_session(
    cmd: &str,
    cwd: &str,
    _session: &str,
) -> (String, Option<String>) {
    let stripped = rio::unwrap_tokenade_command(cmd);
    if stripped.is_empty() {
        return ("allow".to_string(), None);
    }
    let norm_cmd = strip_cmd_backticks(&stripped);

    let low_norm_cmd = norm_cmd.to_lowercase();
    if bare_worktree_remove_re().is_match(&norm_cmd)
        && !low_norm_cmd.contains("worktree_guard")
        && !low_norm_cmd.contains("worktree-guard")
    {
        let cs_bin = rio::normalize_path(&rio::carbon_stack_bin_path().to_string_lossy());
        return (
            "deny".to_string(),
            Some(format!(
                "[Worktree Safety Guard] Прямой вызов `git worktree remove` на Windows опасен (Git рекурсивно обходит NTFS junctions вроде `node_modules`/`.venv` и может удалить файлы основного дерева, а незакоммиченные правки теряются). Используйте безопасную обёртку: `& \"{}\" worktree-guard remove --worktree <path>`.",
                cs_bin
            )),
        );
    }

    if destructive_git_re().is_match(&norm_cmd) {
        let eff_cwd = resolve_command_cwd(&stripped, cwd, "");
        if let Some(git_root) = rio::git_toplevel(&eff_cwd, true) {
            if rio::is_unapproved_home_git_root(&eff_cwd, &git_root)
                && rio::fold_path(&abspath_lexical_str(&eff_cwd)) != rio::fold_path(&git_root)
            {
                return (
                    "deny".to_string(),
                    Some(
                        "[Dirty Worktree Protection] Разрушающая Git-команда запущена во вложенном каталоге без собственного `.git` и поднимется в корневой `$HOME/.git`, что грозит безвозвратной потерей файлов домашнего каталога."
                            .to_string(),
                    ),
                );
            }
            let (rc, st_out, _) = rio::run_git(&git_root, &["status", "--porcelain=v1"], 4.0);
            if (rc == 0 && !st_out.trim().is_empty()) || rc == 124 {
                let cs_bin = rio::normalize_path(&rio::carbon_stack_bin_path().to_string_lossy());
                return (
                    "deny".to_string(),
                    Some(format!(
                        "[Dirty Worktree Protection] Рабочее дерево содержит незакоммиченные изменения, которые будут безвозвратно уничтожены этой командой. Сначала сохраните снимок состояния без изменения индекса: `& \"{}\" worktree-guard snapshot --label before-reset`, либо откатывайте только конкретные собственные хунки.",
                        cs_bin
                    )),
                );
            }
        }
    }

    ("allow".to_string(), None)
}

#[cfg(test)]
pub fn guard_shell_command(cmd: &str, cwd: &str) -> (String, Option<String>) {
    guard_shell_command_with_session(cmd, cwd, "")
}

pub fn guard_swarm_invocation_with_payload(
    args: &Value,
    _payload: Option<&Value>,
) -> (String, Option<String>) {
    let action = val_to_str(args.get("action")).trim().to_lowercase();
    if action != "add" && action != "model" {
        return ("allow".to_string(), None);
    }
    let model = val_to_str(args.get("model")).trim().to_string();
    if !model.is_empty() && cwg_common::is_flash_model(&model) {
        return ("deny".to_string(), Some(hydrogen_policy_msg()));
    }
    ("allow".to_string(), None)
}

#[cfg(test)]
pub fn guard_swarm_invocation(args: &Value) -> (String, Option<String>) {
    guard_swarm_invocation_with_payload(args, None)
}

fn active_constraints(cwd: &str, workspace_paths: &[String], session: &str) -> (String, String) {
    crate::continuity_hook::active_constraints(cwd, workspace_paths, None, session)
}

pub fn guard_subagent_invocation_with_payload(
    payload: &Value,
    args: &Value,
) -> (String, Option<String>, Option<Value>) {
    let transcript_path = payload
        .get("transcriptPath")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let prompt = val_to_str(args.get("Prompt")).trim().to_string();
    let req_model = val_to_str(args.get("Model")).trim().to_lowercase();
    let sub_type = val_to_str(args.get("TypeName")).trim().to_lowercase();
    let base_sub_type = sub_type.rsplit(':').next().unwrap_or("");

    if !req_model.is_empty() && cwg_common::is_flash_model(&req_model) {
        let suffix = if base_sub_type == "browser" {
            "Для `browser` запустите swarm-воркера на `gemini-4-hydrogen-<low|medium|high|xhigh>`, который вызовет `invoke_subagent(TypeName='browser', Model='inherit')` (либо передайте `Model='inherit'` внутри Hydrogen-сессии)."
        } else {
            "Запустите задачу через `swarm(action='add', model='gemini-4-hydrogen-<low|medium|high|xhigh>')` или передайте `Model='inherit'` внутри Hydrogen-сессии."
        };
        return (
            "deny".to_string(),
            Some(format!("{} {}", hydrogen_policy_msg(), suffix)),
            None,
        );
    }

    let steps_head = rio::read_transcript_head(transcript_path, 8);
    let is_delegated = rio::is_subagent_session(transcript_path, Some(&steps_head));
    let conv_id = payload
        .get("conversationId")
        .or_else(|| payload.get("session_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let is_swarm_worker =
        rio::swarm_worker_model(transcript_path, Some(&steps_head), conv_id).is_some();

    let allow_swarm_delegation = is_swarm_worker
        && (req_model.is_empty() || req_model == "inherit")
        && base_sub_type == "browser";
    if is_delegated && !allow_swarm_delegation && !prompt.contains("[allow-nested-subagent]") {
        return (
            "deny".to_string(),
            Some(
                "[Subagent Nesting Guard] Вложенный запуск субагента изнутри субагента заблокирован во избежание каскадного размножения контекстов. Завершите свою ограниченную задачу и верните результат родительскому агенту."
                    .to_string(),
            ),
            None,
        );
    }

    if prompt.chars().count() < 16 {
        return (
            "deny".to_string(),
            Some(
                "[Subagent Delegation Guard] Промпт субагента слишком короткий и не содержит границ задачи и ожидаемого результата."
                    .to_string(),
            ),
            None,
        );
    }

    if !prompt.contains("[Canonical Constraints]") {
        let eff_cwd = rio::effective_cwd(payload);
        let wps: Vec<String> = payload
            .get("workspacePaths")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let session = rio::session_key(payload);
        let (active_req, cancelled_req) = active_constraints(&eff_cwd, &wps, &session);
        let mut extra_lines = Vec::new();
        if !active_req.is_empty() {
            extra_lines.push(format!("- Active Requirements: {}", active_req));
        }
        if !cancelled_req.is_empty() {
            extra_lines.push(format!("- Cancelled / Do NOT Reintroduce: {}", cancelled_req));
        }
        if !extra_lines.is_empty() {
            let enriched = format!(
                "{}\n\n[Canonical Constraints]\n{}",
                prompt,
                extra_lines.join("\n")
            );
            return ("allow".to_string(), None, Some(json!({"Prompt": enriched})));
        }
    }

    ("allow".to_string(), None, None)
}

#[cfg(test)]
pub fn guard_subagent_invocation(args: &Value) -> (String, Option<String>) {
    let empty_payload = Value::Object(Map::new());
    let (dec, reason, _) = guard_subagent_invocation_with_payload(&empty_payload, args);
    (dec, reason)
}

fn resolve_brain_root_for_payload(payload: &Value) -> PathBuf {
    if let Some(tp) = payload.get("transcriptPath").and_then(|v| v.as_str()) {
        if !tp.is_empty() {
            let p = fs::canonicalize(tp).unwrap_or_else(|_| abspath_lexical(Path::new(tp)));
            let is_sysgen = p
                .ancestors()
                .nth(2)
                .and_then(|a| a.file_name())
                .and_then(|n| n.to_str())
                == Some(".system_generated");
            if is_sysgen {
                if let Some(brain) = p.ancestors().nth(4) {
                    return brain.to_path_buf();
                }
            }
        }
    }
    rio::resolve_brain_root("")
}

fn worker_turn_after_wake(brain_root: &Path, minfo: &Value, last_assign_seq: i64) -> Option<(Value, bool)> {
    let w_cid = minfo
        .get("conversation_id")
        .or_else(|| minfo.get("conversationId"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if w_cid.is_empty() {
        return None;
    }
    let tp = rio::member_transcript_path(brain_root, w_cid);
    let w_steps = rio::read_transcript_steps(&tp.to_string_lossy(), 60);
    if w_steps.is_empty() {
        return None;
    }
    let turn = rio::inspect_worker_turn_after_wake(&w_steps, last_assign_seq);
    // INVARIANT: An earlier error followed by recovery work (peer post / tool calls) is NOT terminal; treat error as terminal ONLY when the latest transcript step itself is an error.
    let last_step_is_error = w_steps.last().is_some_and(|st| {
        let ssource = st.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let stype = st.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let sstatus = st.get("status").and_then(|v| v.as_str()).unwrap_or("");
        stype == "ERROR_MESSAGE" || (ssource == "MODEL" && stype != "GENERIC" && sstatus == "ERROR")
    });
    Some((turn, last_step_is_error))
}

fn turn_is_terminally_finished(turn: &Value, last_step_is_error: bool) -> bool {
    let pending_nonempty = turn
        .get("pending_bg")
        .and_then(|v| v.as_array())
        .map_or(false, |a| !a.is_empty());
    if !json_truthy(turn.get("woke_for_assign")) || !json_truthy(turn.get("has_tail")) || pending_nonempty {
        return false;
    }
    last_step_is_error
        || (json_truthy(turn.get("saw_model")) && json_truthy(turn.get("terminal_parked")))
}

fn is_worker_silently_parked(brain_root: &Path, minfo: &Value, last_assign_seq: i64) -> bool {
    let wake_mode = val_to_str(minfo.get("wake_mode")).trim().to_lowercase();
    let mstate = val_to_str(minfo.get("state")).trim().to_lowercase();
    let wait_since = val_to_i64(minfo.get("wait_since"));
    if (mstate == "waiting" || matches!(wake_mode.as_str(), "mentions" | "all" | "waiting"))
        && wait_since >= last_assign_seq
    {
        return true;
    }
    let Some((turn, last_err)) = worker_turn_after_wake(brain_root, minfo, last_assign_seq) else {
        return false;
    };
    !json_truthy(turn.get("called_post")) && turn_is_terminally_finished(&turn, last_err)
}

fn is_worker_turn_terminally_parked(brain_root: &Path, minfo: &Value, last_assign_seq: i64) -> bool {
    worker_turn_after_wake(brain_root, minfo, last_assign_seq)
        .is_some_and(|(turn, last_err)| turn_is_terminally_finished(&turn, last_err))
}

pub fn guard_swarm_wait(payload: &Value, args: Option<&Value>) -> (String, Option<String>) {
    // SAFETY: Prevent coordinator deadlock when calling `swarm_wait` after all active workers have already posted, parked without posting, or stalled.
    let tp = payload
        .get("transcriptPath")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if rio::is_subagent_session(tp, None) {
        return ("allow".to_string(), None);
    }
    let session = rio::session_key(payload);
    if session.is_empty() || session == "unknown" {
        return ("allow".to_string(), None);
    }
    let brain_root = resolve_brain_root_for_payload(payload);
    let members = rio::load_swarm_members(&brain_root, &session);
    if members.is_empty() {
        return ("allow".to_string(), None);
    }
    let board_path = rio::swarm_dir(&brain_root, &session).join("board.jsonl");
    let raw_board = rio::read_jsonl(&board_path, Some(400));
    if raw_board.is_empty() {
        return ("allow".to_string(), None);
    }

    let eff_args = args.or_else(|| payload.get("toolCall").and_then(|t| t.get("args")));
    let since_val = val_to_i64(eff_args.and_then(|a| a.get("since")));

    let mut active_workers: Vec<String> = Vec::new();
    let mut in_flight: Vec<String> = Vec::new();
    let mut unposted_parked: Vec<String> = Vec::new();

    for (mname, minfo) in &members {
        if !minfo.is_object()
            || rio::is_swarm_role_member(mname, Some(minfo))
            || rio::is_swarm_member_killed(Some(minfo))
        {
            continue;
        }
        active_workers.push(mname.clone());
        let added_by = minfo
            .get("added_by")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let (last_assign_seq, last_reply_seq) =
            rio::latest_board_assign_and_reply_seq(&raw_board, mname, added_by);
        if last_assign_seq == 0 || last_reply_seq < last_assign_seq {
            // INVARIANT: Always run transcript-backed silent-park detection before trusting `state == "working"` so a finished worker with stale `members.json` cannot deadlock `swarm_wait`.
            if last_assign_seq > 0 && is_worker_silently_parked(&brain_root, minfo, last_assign_seq)
            {
                unposted_parked.push(mname.clone());
            } else {
                in_flight.push(mname.clone());
            }
        } else {
            let mstate = val_to_str(minfo.get("state")).trim().to_ascii_lowercase();
            // INVARIANT: After a peer-to-peer post (`last_reply_seq >= last_assign_seq`), keep `state == "working"` in-flight ONLY while its transcript has not terminally parked.
            if mstate == "working"
                && !is_worker_turn_terminally_parked(&brain_root, minfo, last_assign_seq)
            {
                in_flight.push(mname.clone());
            }
        }
    }

    if !in_flight.is_empty() {
        let eff_cwd = rio::effective_cwd(payload);
        let empty_act = HashMap::new();
        let stalled = cwg_common::detect_stalled_workers(cwg_common::StallDetectInput {
            members: &members,
            board_messages: &raw_board,
            cwd: &eff_cwd,
            brain_root: Some(&brain_root),
            worker_last_activity: &empty_act,
            in_flight_names: &in_flight,
            now_ts: None,
            timeout_sec: None,
        });
        if !stalled.is_empty() {
            let desc: String = stalled
                .iter()
                .map(|s| {
                    format!(
                        "`{}` ({}s >= {}s)",
                        val_to_str(s.get("worker")),
                        val_to_str(s.get("idle_sec")),
                        val_to_str(s.get("timeout_sec")),
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            return (
                "deny".to_string(),
                Some(format!(
                    "[Swarm Stall Watchdog] Зависли in-flight воркеры без новых сообщений на доске и активности в `.swarm/`: {}. Не уходите в немое ожидание `swarm_wait`: проверьте `.swarm/artifacts/`, перепинайте через `@mention` или перезапустите зависшего воркера.",
                    desc
                )),
            );
        }
    }

    if !active_workers.is_empty() && in_flight.is_empty() {
        let head_seq = raw_board
            .last()
            .and_then(|b| b.get("seq"))
            .and_then(|v| v.as_i64())
            .filter(|&x| x != 0)
            .unwrap_or(raw_board.len() as i64);
        if !unposted_parked.is_empty() {
            let since_note = if since_val > 0 {
                format!(", since={}", since_val)
            } else {
                String::new()
            };
            return (
                "deny".to_string(),
                Some(format!(
                    "[Swarm Wait Guard] Активных работающих воркеров не осталось (head=#{}{}), а воркер(ы) ({}) завершили ход в `waiting` без вызова `post_message` после задания. Вызов `swarm_wait` сейчас приведёт к вечному зависанию: разбудите воркера через `post_message('@<name> Call post_message with your result')` или перезапустите его.",
                    head_seq,
                    since_note,
                    unposted_parked.join(", "),
                )),
            );
        }
        return (
            "deny".to_string(),
            Some(format!(
                "[Swarm Wait Guard] Все активные воркеры роя ({}) уже опубликовали ответы на доске (head=#{}). Вызов `swarm_wait` сейчас приведёт к вечному ожиданию. Не вызывайте `read_board` и `swarm_wait` в одном ходе: обработайте полученные сообщения и завершите воркеров через `swarm(action='kill', ...)`.",
                active_workers.join(", "),
                head_seq,
            )),
        );
    }

    ("allow".to_string(), None)
}

pub fn evaluate_pre_tool_use(payload: &Value) -> (String, Option<String>, Option<Value>) {
    let session = rio::session_key(payload);
    let cwd = rio::effective_cwd(payload);
    let tc = payload.get("toolCall").and_then(|v| v.as_object());
    let tool_name = tc
        .and_then(|m| m.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let args = tc
        .and_then(|m| m.get("args"))
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));

    match tool_name {
        "run_command" => {
            let cmd = val_to_str(args.get("CommandLine"));
            let (dec, reason) = guard_shell_command_with_session(&cmd, &cwd, &session);
            if dec != "allow" {
                rio::log_hook_event(
                    "hygiene-events",
                    "shell_guard_deny",
                    json!({"session": session, "reason": reason.as_deref().unwrap_or("")}),
                );
                return (dec, reason, None);
            }
        }
        "swarm" => {
            let (dec, reason) = guard_swarm_invocation_with_payload(&args, Some(payload));
            if dec != "allow" {
                rio::log_hook_event(
                    "hygiene-events",
                    "model_guard_deny",
                    json!({"session": session, "reason": reason.as_deref().unwrap_or("")}),
                );
                return (dec, reason, None);
            }
        }
        "swarm_wait" => {
            let (dec, reason) = guard_swarm_wait(payload, Some(&args));
            if dec != "allow" {
                rio::log_hook_event(
                    "hygiene-events",
                    "swarm_wait_guard_deny",
                    json!({"session": session, "reason": reason.as_deref().unwrap_or("")}),
                );
                return (dec, reason, None);
            }
        }
        "invoke_subagent" => {
            let (dec, reason, overwrite) = guard_subagent_invocation_with_payload(payload, &args);
            if dec != "allow" {
                let ev = if reason
                    .as_deref()
                    .unwrap_or("")
                    .contains("[Model Policy Guard]")
                {
                    "model_guard_deny"
                } else {
                    "subagent_guard_deny"
                };
                rio::log_hook_event(
                    "hygiene-events",
                    ev,
                    json!({"session": session, "reason": reason.as_deref().unwrap_or("")}),
                );
                return (dec, reason, None);
            }
            if overwrite.is_some() {
                return ("allow".to_string(), None, overwrite);
            }
        }
        _ => {}
    }

    ("allow".to_string(), None, None)
}

pub fn run_cli(_args: &[String]) -> i32 {
    match rio::read_hook_stdin() {
        Ok(payload) => {
            let (decision, reason, overwrite) = evaluate_pre_tool_use(&payload);
            rio::emit_pre_tool(&decision, reason.as_deref(), overwrite);
            0
        }
        Err(err) => {
            rio::log_hook_event(
                "hook-errors",
                "stdin_error",
                json!({"hook": "safety_guards", "error": err}),
            );
            rio::emit_pre_tool("allow", None, None);
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    struct HomeGuard(Option<std::ffi::OsString>);

    impl HomeGuard {
        fn enter(temp_home: &Path) -> Self {
            let _ = fs::create_dir_all(temp_home);
            let guard = Self(env::var_os("CARBON_STACK_HOME"));
            unsafe { env::set_var("CARBON_STACK_HOME", temp_home) };
            guard
        }
    }

    impl Drop for HomeGuard {
        fn drop(&mut self) {
            match self.0.take() {
                Some(v) => unsafe { env::set_var("CARBON_STACK_HOME", v) },
                None => unsafe { env::remove_var("CARBON_STACK_HOME") },
            }
        }
    }

    #[test]
    fn test_all_regexes_compile() {
        let _ = bare_worktree_remove_re();
        let _ = destructive_git_re();
        let _ = cmd_backtick_re();
    }

    #[test]
    fn test_guard_shell_worktree_and_dirty_protection() {
        let (dec_wt, reason_wt) = guard_shell_command("git worktree remove ../wt-1", ".");
        assert_eq!(dec_wt, "deny");
        assert!(reason_wt.unwrap().contains("Worktree Safety Guard"));

        let (dec_ok, _) = guard_shell_command("git status", ".");
        assert_eq!(dec_ok, "allow");

        let dir = env::temp_dir().join(format!("carbon-sg-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let (rc_init, _, _) = rio::run_git(&dir.to_string_lossy(), &["init"], 5.0);
        if rc_init == 0 {
            fs::write(dir.join("dirty.txt"), "uncommitted\n").unwrap();
            let (dec_dirty, reason_dirty) =
                guard_shell_command("git reset --hard", &dir.to_string_lossy());
            assert_eq!(dec_dirty, "deny");
            assert!(reason_dirty.unwrap().contains("Dirty Worktree Protection"));
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_guard_model_policies_swarm_and_subagent() {
        let (dec_flash_sw, reason_flash_sw) = guard_swarm_invocation(&json!({
            "action": "add",
            "name": "worker-1",
            "model": "gemini-3-flash-lite",
        }));
        assert_eq!(dec_flash_sw, "deny");
        assert!(reason_flash_sw.unwrap().contains("Model Policy Guard"));

        let (dec_non_flash, _) = guard_swarm_invocation(&json!({
            "action": "add",
            "name": "worker-1",
            "model": "gemini-4-neon-xhigh",
        }));
        assert_eq!(dec_non_flash, "allow");

        let (dec_sub_flash, _) = guard_subagent_invocation(&json!({
            "TypeName": "research",
            "Model": "gemini-3-flash",
            "Prompt": "Inspect codebase callers and report back",
        }));
        assert_eq!(dec_sub_flash, "deny");

        let (dec_sub_short, _) = guard_subagent_invocation(&json!({
            "TypeName": "research",
            "Prompt": "too short",
        }));
        assert_eq!(dec_sub_short, "deny");
    }

    #[test]
    fn test_pre_tool_use_drops_cursor_ownership_and_post_message_and_keeps_wait_guard() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = env::temp_dir().join(format!("carbon-swg-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let _home_guard = HomeGuard::enter(&root.join("carbon-home"));
        let sid = format!("test-swg-sess-{}", std::process::id());
        let brain_root = root.join("brain");
        let tp = brain_root
            .join(&sid)
            .join(".system_generated")
            .join("logs")
            .join("transcript.jsonl");
        let swarm_path = brain_root
            .join(&sid)
            .join(".system_generated")
            .join("swarm");
        fs::create_dir_all(tp.parent().unwrap()).unwrap();
        fs::create_dir_all(&swarm_path).unwrap();
        fs::write(
            &tp,
            "{\"step_index\":0,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"Run\"}\n",
        )
        .unwrap();
        fs::write(
            swarm_path.join("members.json"),
            r#"{"members":{"worker-a":{"role":"worker","state":"waiting"}}}"#,
        )
        .unwrap();
        let mut board_lines = String::new();
        for i in 1..=16 {
            let agent = if i == 1 { "coordinator" } else { "worker-a" };
            let text = if i == 1 { "@worker-a do work" } else { "done" };
            board_lines.push_str(&format!(
                "{{\"seq\":{},\"agent\":\"{}\",\"text\":\"{}\"}}\n",
                i, agent, text
            ));
        }
        fs::write(swarm_path.join("board.jsonl"), &board_lines).unwrap();

        for (tname, args) in [
            ("read_board", json!({})),
            ("post_message", json!({"text": "@worker-a ping"})),
            ("edit_file", json!({"Path": root.join("src/b.rs").to_string_lossy()})),
        ] {
            let payload = json!({
                "conversationId": sid,
                "transcriptPath": tp.to_string_lossy(),
                "toolCall": {"name": tname, "args": args}
            });
            assert_eq!(evaluate_pre_tool_use(&payload).0, "allow");
        }

        let sw_wait = json!({
            "conversationId": sid,
            "transcriptPath": tp.to_string_lossy(),
            "toolCall": {"name": "swarm_wait", "args": {"since": 16}}
        });
        let (dec_wait, reason_wait, _) = evaluate_pre_tool_use(&sw_wait);
        assert_eq!(dec_wait, "deny");
        assert!(reason_wait.unwrap().contains("Swarm Wait Guard"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_guard_swarm_wait_working_after_peer_post_and_waiting_deadlock() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = env::temp_dir().join(format!("carbon-swg-working-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let _home_guard = HomeGuard::enter(&root.join("carbon-home"));
        let sid = format!("test-swg-work-{}", std::process::id());
        let brain_root = root.join("brain");
        let tp = brain_root
            .join(&sid)
            .join(".system_generated")
            .join("logs")
            .join("transcript.jsonl");
        let swarm_path = brain_root
            .join(&sid)
            .join(".system_generated")
            .join("swarm");
        fs::create_dir_all(tp.parent().unwrap()).unwrap();
        fs::create_dir_all(&swarm_path).unwrap();
        fs::write(
            &tp,
            "{\"step_index\":0,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"Run\"}\n",
        )
        .unwrap();

        let now_iso = crate::win32_sqlite::format_iso_utc(crate::win32_sqlite::now_sec());
        let fresh_board = format!(
            "{{\"seq\":1,\"agent\":\"coordinator\",\"time\":\"{0}\",\"text\":\"@worker-a implement module and sync with @worker-b\"}}\n\
             {{\"seq\":2,\"agent\":\"worker-a\",\"time\":\"{0}\",\"text\":\"@worker-b schema ready, continuing implementation\"}}\n",
            now_iso
        );
        fs::write(swarm_path.join("board.jsonl"), &fresh_board).unwrap();

        let payload = json!({
            "conversationId": sid,
            "cwd": root.to_string_lossy(),
            "transcriptPath": tp.to_string_lossy(),
        });
        let args = json!({"since": 2});

        // Active worker still in `state == "working"` after a peer-to-peer post (`last_reply_seq >= last_assign_seq`) -> allow.
        fs::write(
            swarm_path.join("members.json"),
            r#"{"members":{"worker-a":{"role":"worker","state":"working"}}}"#,
        )
        .unwrap();
        let (dec_work, reason_work) = guard_swarm_wait(&payload, Some(&args));
        assert_eq!(dec_work, "allow");
        assert!(reason_work.is_none());

        // Same peer-to-peer board once worker finishes into `state == "waiting"` -> deny (deadlock prevention preserved).
        fs::write(
            swarm_path.join("members.json"),
            r#"{"members":{"worker-a":{"role":"worker","state":"waiting"}}}"#,
        )
        .unwrap();
        let (dec_wait, reason_wait) = guard_swarm_wait(&payload, Some(&args));
        assert_eq!(dec_wait, "deny");
        assert!(reason_wait.unwrap().contains("Swarm Wait Guard"));

        // Truly stalled `"working"` worker still triggers `[Swarm Stall Watchdog]`.
        fs::write(
            swarm_path.join("members.json"),
            r#"{"members":{"worker-a":{"role":"worker","state":"working"}}}"#,
        )
        .unwrap();
        let stale_board = concat!(
            "{\"seq\":1,\"agent\":\"coordinator\",\"time\":\"2020-01-01T00:00:00Z\",\"text\":\"@worker-a implement module\"}\n",
            "{\"seq\":2,\"agent\":\"worker-a\",\"time\":\"2020-01-01T00:00:10Z\",\"text\":\"@worker-b schema ready\"}\n"
        );
        fs::write(swarm_path.join("board.jsonl"), stale_board).unwrap();
        let (dec_stall, reason_stall) = guard_swarm_wait(&payload, Some(&args));
        assert_eq!(dec_stall, "deny");
        assert!(reason_stall.unwrap().contains("Swarm Stall Watchdog"));

        // Stale `state == "working"` whose transcript already terminally parked WITHOUT `post_message` -> deny (`Swarm Wait Guard`), NOT allow!
        let w_cid = format!("worker-silent-{}", std::process::id());
        let w_tp = brain_root
            .join(&w_cid)
            .join(".system_generated")
            .join("logs")
            .join("transcript.jsonl");
        fs::create_dir_all(w_tp.parent().unwrap()).unwrap();
        let assign_board = format!(
            "{{\"seq\":1,\"agent\":\"coordinator\",\"time\":\"{0}\",\"text\":\"@worker-a finish module\"}}\n",
            now_iso
        );
        fs::write(swarm_path.join("board.jsonl"), &assign_board).unwrap();
        fs::write(
            swarm_path.join("members.json"),
            format!(
                r#"{{"members":{{"worker-a":{{"role":"worker","state":"working","conversation_id":"{}"}}}}}}"#,
                w_cid
            ),
        )
        .unwrap();
        fs::write(
            &w_tp,
            concat!(
                "{\"step_index\":0,\"source\":\"SYSTEM\",\"type\":\"SYSTEM_MESSAGE\",\"status\":\"DONE\",\"content\":\"[swarm] new board message #1\"}\n",
                "{\"step_index\":1,\"source\":\"MODEL\",\"type\":\"PLANNER_RESPONSE\",\"status\":\"DONE\",\"content\":\"Done locally.\",\"tool_calls\":[]}\n"
            ),
        )
        .unwrap();
        let (dec_silent, reason_silent) = guard_swarm_wait(&payload, Some(&json!({"since": 1})));
        assert_eq!(dec_silent, "deny");
        assert!(reason_silent.unwrap().contains("Swarm Wait Guard"));

        // Stale `state == "working"` after a peer post whose transcript ALSO terminally parked -> deny!
        fs::write(swarm_path.join("board.jsonl"), &fresh_board).unwrap();
        fs::write(
            &w_tp,
            concat!(
                "{\"step_index\":0,\"source\":\"SYSTEM\",\"type\":\"SYSTEM_MESSAGE\",\"status\":\"DONE\",\"content\":\"[swarm] new board message #1\"}\n",
                "{\"step_index\":1,\"source\":\"MODEL\",\"type\":\"PLANNER_RESPONSE\",\"status\":\"DONE\",\"content\":\"Posting peer sync.\",\"tool_calls\":[{\"name\":\"post_message\"}]}\n",
                "{\"step_index\":2,\"source\":\"MODEL\",\"type\":\"PLANNER_RESPONSE\",\"status\":\"DONE\",\"content\":\"Finished turn.\",\"tool_calls\":[]}\n"
            ),
        )
        .unwrap();
        let (dec_parked_post, reason_parked_post) = guard_swarm_wait(&payload, Some(&args));
        assert_eq!(dec_parked_post, "deny");
        assert!(reason_parked_post.unwrap().contains("Swarm Wait Guard"));

        // Codex C3 R2 #2: worker recovered after an earlier error, posted a peer message, and is actively continuing work (`state == "working"`, non-terminal latest step) -> MUST allow!
        fs::write(
            &w_tp,
            concat!(
                "{\"step_index\":0,\"source\":\"SYSTEM\",\"type\":\"SYSTEM_MESSAGE\",\"status\":\"DONE\",\"content\":\"[swarm] new board message #1\"}\n",
                "{\"step_index\":1,\"source\":\"MODEL\",\"type\":\"ERROR_MESSAGE\",\"status\":\"ERROR\",\"content\":\"transient tool error\"}\n",
                "{\"step_index\":2,\"source\":\"MODEL\",\"type\":\"PLANNER_RESPONSE\",\"status\":\"DONE\",\"content\":\"Recovered, syncing peer.\",\"tool_calls\":[{\"name\":\"post_message\"}]}\n",
                "{\"step_index\":3,\"source\":\"MODEL\",\"type\":\"PLANNER_RESPONSE\",\"status\":\"DONE\",\"content\":\"Continuing edit.\",\"tool_calls\":[{\"name\":\"edit_file\"}]}\n"
            ),
        )
        .unwrap();
        let (dec_recovered, reason_recovered) = guard_swarm_wait(&payload, Some(&args));
        assert_eq!(dec_recovered, "allow", "recovered working worker must be allowed, got: {:?}", reason_recovered);
        assert!(reason_recovered.is_none());

        let _ = fs::remove_dir_all(&root);
    }
}
