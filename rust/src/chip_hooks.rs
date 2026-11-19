use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

use crate::rio::{self, json_truthy, val_to_i64, val_to_str};

pub const MAX_CHIP_STOP_REMINDERS: i64 = 2;

fn display_title(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => "None".to_string(),
        Some(other) => other.to_string(),
    }
}

pub fn chips_dir() -> PathBuf {
    let dir = rio::state_dir().join("chips").join("cards");
    let _ = fs::create_dir_all(&dir);
    dir
}

pub fn chip_lock_path() -> PathBuf {
    let dir = rio::state_dir().join("chips");
    let _ = fs::create_dir_all(&dir);
    dir.join(".chips.lock")
}

pub fn card_path(chip_id: &str) -> PathBuf {
    chips_dir().join(format!("{}.json", rio::safe_key(chip_id, "default")))
}

fn has_any_chip_card() -> bool {
    let dir = chips_dir();
    let Ok(entries) = fs::read_dir(&dir) else {
        return false;
    };
    entries
        .flatten()
        .any(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
}

pub fn load_all_cards() -> Vec<Value> {
    let dir = chips_dir();
    let Ok(entries) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    paths.sort();

    let mut cards = Vec::new();
    for p in paths {
        if let Some(Value::Object(m)) = rio::read_json(&p) {
            if json_truthy(m.get("chip_id")) {
                cards.push(Value::Object(m));
            }
        }
    }
    cards
}

pub fn find_card_for_cwd(cwd: &str) -> Option<Value> {
    let folded = rio::fold_path(cwd);
    if folded.is_empty() {
        return None;
    }
    for card in load_all_cards() {
        let wt = val_to_str(card.get("worktree"));
        if !wt.is_empty() {
            let fwt = rio::fold_path(&wt);
            if !fwt.is_empty() && (folded == fwt || folded.starts_with(&format!("{}/", fwt))) {
                return Some(card);
            }
        }
    }
    None
}

pub fn evaluate_pre_invocation(payload: &Value) -> Option<String> {
    if !has_any_chip_card() {
        return None;
    }
    let tp = payload
        .get("transcriptPath")
        .or_else(|| payload.get("transcript_path"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if rio::is_subagent_session(tp, None) {
        return None;
    }
    let pending_cards: Vec<Value> = load_all_cards()
        .into_iter()
        .filter(|c| {
            val_to_str(c.get("status")) == "handed-off" && !json_truthy(c.get("parent_notified"))
        })
        .collect();
    if pending_cards.is_empty() {
        return None;
    }

    let session = rio::session_key(payload);
    let cwd = rio::effective_cwd(payload);
    let mut git_root: Option<String> = None;

    let notifications = rio::with_file_lock(&chip_lock_path(), 5.0, 30.0, |acquired| {
        let mut out: Vec<String> = Vec::new();
        if !acquired {
            return out;
        }
        for pending in &pending_cards {
            let cid = val_to_str(pending.get("chip_id"));
            if cid.is_empty() {
                continue;
            }
            let cpath = card_path(&cid);
            let Some(Value::Object(mut card)) = rio::read_json(&cpath) else {
                continue;
            };
            if val_to_str(card.get("status")) != "handed-off"
                || json_truthy(card.get("parent_notified"))
            {
                continue;
            }
            let parent_session = val_to_str(card.get("parent_session"));
            let mut matches_parent = !parent_session.is_empty() && parent_session == session;
            if !matches_parent && parent_session.is_empty() {
                let gr = git_root.get_or_insert_with(|| {
                    rio::git_toplevel(&cwd, false)
                        .map(|g| rio::normalize_path(&g))
                        .unwrap_or_default()
                });
                matches_parent = !gr.is_empty() && val_to_str(card.get("repo_root")) == *gr;
            }
            if matches_parent {
                let cs_bin = rio::normalize_path(&rio::carbon_stack_bin_path().to_string_lossy());
                let title = display_title(card.get("title"));
                let summary = val_to_str(card.get("summary"));
                let branch_raw = val_to_str(card.get("chip_branch"));
                let branch = if branch_raw.is_empty() {
                    "operational"
                } else {
                    branch_raw.as_str()
                };
                out.push(format!(
                    "[Chip Handoff Ready] Дочерняя задача `{}` ({}) передала результат: «{}» (ветка `{}`). Проверьте результат и закройте чип: `& \"{}\" chip-handoff close --chip \"{}\" --accept [--merge]` или `--rework \"<замечания>\"`.",
                    cid, title, summary, branch, cs_bin, cid
                ));
                card.insert("parent_notified".to_string(), Value::Bool(true));
                let _ = rio::write_json(&cpath, &Value::Object(card));
            }
        }
        out
    });

    if notifications.is_empty() {
        None
    } else {
        Some(notifications.join("\n"))
    }
}

pub fn decide_stop(payload: &Value) -> Option<String> {
    let term_reason = payload
        .get("terminationReason")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if rio::NON_ENFORCEABLE_STOP_REASONS.contains(&term_reason) || json_truthy(payload.get("error"))
    {
        return None;
    }

    let cwd = rio::effective_cwd(payload);
    if cwd.is_empty() || !has_any_chip_card() {
        return None;
    }
    let Some(Value::Object(mut child_card)) = find_card_for_cwd(&cwd) else {
        return None;
    };
    let status = val_to_str(child_card.get("status"));
    if status == "open" || status == "rework" {
        let rem = val_to_i64(child_card.get("stop_reminders"));
        if rem < MAX_CHIP_STOP_REMINDERS {
            let cid = val_to_str(child_card.get("chip_id"));
            if cid.is_empty() {
                return None;
            }
            child_card.insert("stop_reminders".to_string(), json!(rem + 1));
            rio::with_file_lock(&chip_lock_path(), 5.0, 30.0, |acquired| {
                if acquired {
                    let _ = rio::write_json(&card_path(&cid), &Value::Object(child_card.clone()));
                }
            });
            let cs_bin = rio::normalize_path(&rio::carbon_stack_bin_path().to_string_lossy());
            let title = display_title(child_card.get("title"));
            return Some(format!(
                "[Chip Handoff] Эта сессия работает внутри изолированного чипа `{}` ({}), но результат ещё не передан родителю (`status={}`). Закоммитьте проверенные изменения и выполните `& \"{}\" chip-handoff finish --chip \"{}\" --message \"...\"`.",
                cid, title, status, cs_bin, cid
            ));
        }
    }
    None
}

pub fn evaluate_stop(payload: &Value) {
    match decide_stop(payload) {
        Some(reason) => rio::emit_stop_continue(&reason),
        None => rio::emit_stop_allow(),
    }
}

pub fn run_cli(args: &[String]) -> i32 {
    let event = rio::parse_event_arg(args, "");
    let payload = match rio::read_hook_stdin() {
        Ok(v) => v,
        Err(_) => {
            rio::emit_default_for_event(&event);
            return 0;
        }
    };
    let actual_event = if !event.is_empty() {
        event
    } else {
        val_to_str(payload.get("hookEventName"))
    };
    match actual_event.as_str() {
        "PreInvocation" => match evaluate_pre_invocation(&payload) {
            Some(msg) => rio::emit_inject_system(&msg, None),
            None => rio::emit_json(&json!({})),
        },
        "Stop" => evaluate_stop(&payload),
        other => rio::emit_default_for_event(other),
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pre_invocation_and_stop_for_chip_cards() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp_dir = std::env::temp_dir().join(format!("chip-hooks-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp_dir);
        let wt_dir = tmp_dir.join("wt-1");
        fs::create_dir_all(&wt_dir).unwrap();
        let prev = std::env::var_os("CARBON_STACK_HOME");
        std::env::set_var("CARBON_STACK_HOME", &tmp_dir);

        let cid = "chip-demo-12345678";
        let wt_norm = rio::normalize_path(&wt_dir.to_string_lossy());
        let card = json!({
            "chip_id": cid,
            "title": "Demo Chip",
            "status": "open",
            "parent_session": "parent-01",
            "worktree": wt_norm,
            "stop_reminders": 0,
            "parent_notified": false,
        });
        rio::write_json(&card_path(cid), &card).unwrap();

        let stop_payload = json!({
            "cwd": wt_dir.to_string_lossy(),
            "terminationReason": "NO_TOOL_CALL",
        });
        let r1 = decide_stop(&stop_payload).unwrap();
        assert!(r1.contains(cid));
        let r2 = decide_stop(&stop_payload).unwrap();
        assert!(r2.contains(cid));
        assert_eq!(decide_stop(&stop_payload), None);

        let mut handed = card;
        handed["status"] = json!("handed-off");
        handed["summary"] = json!("All tests passed");
        handed["chip_branch"] = json!("chip/demo-12345678");
        rio::write_json(&card_path(cid), &handed).unwrap();

        let pre_payload = json!({
            "conversationId": "parent-01",
            "cwd": tmp_dir.to_string_lossy(),
        });
        let msg = evaluate_pre_invocation(&pre_payload).unwrap();
        assert!(msg.contains(cid));
        assert!(msg.contains("All tests passed"));
        assert_eq!(evaluate_pre_invocation(&pre_payload), None);

        match prev {
            Some(v) => std::env::set_var("CARBON_STACK_HOME", v),
            None => std::env::remove_var("CARBON_STACK_HOME"),
        }
        let _ = fs::remove_dir_all(&tmp_dir);
    }
}
