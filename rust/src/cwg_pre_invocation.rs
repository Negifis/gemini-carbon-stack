use serde_json::{json, Value};

use crate::cwg_common;
use crate::gate_inbox;
use crate::rio;

pub fn evaluate_pre_invocation(payload: &Value) -> Option<String> {
    let session = rio::session_key(payload);
    let has_pending = cwg_common::pending_notes_path(&session).is_file();
    let handler_cfg = if session != "unknown" {
        gate_inbox::get_handler_config()
    } else {
        json!({})
    };
    let handler_sess = gate_inbox::get_handler_session_from_cfg(Some(&handler_cfg));
    let is_handler = !handler_sess.is_empty() && session == handler_sess;
    if !has_pending && !is_handler {
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

    let mut notes = if has_pending {
        cwg_common::pop_pending_notes(&session)
    } else {
        Vec::new()
    };
    if is_handler {
        let digest = gate_inbox::format_handler_digest(10, Some(&handler_cfg));
        if !digest.is_empty() {
            notes.push(digest);
        }
    }
    if notes.is_empty() {
        None
    } else {
        Some(notes.join("\n\n"))
    }
}

pub fn run_cli(args: &[String]) -> i32 {
    let _ = rio::parse_event_arg(args, "PreInvocation");
    let payload = match rio::read_hook_stdin() {
        Ok(v) => v,
        Err(err) => {
            rio::log_hook_event(
                "hook-errors",
                "stdin_error",
                json!({
                    "hook": "cwg_pre_invocation",
                    "error": err,
                }),
            );
            rio::emit_json(&json!({}));
            return 0;
        }
    };
    match evaluate_pre_invocation(&payload) {
        Some(msg) => rio::emit_inject_system(&msg, None),
        None => rio::emit_json(&json!({})),
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_evaluate_pre_invocation_pops_notes_and_skips_subagents() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp_dir = std::env::temp_dir().join(format!("cwg-pre-inv-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();
        let prev = std::env::var_os("CARBON_STACK_HOME");
        std::env::set_var("CARBON_STACK_HOME", &tmp_dir);

        let sid = "sess-preinv-01";
        cwg_common::queue_pending_note(sid, "[Code Work Gate] Tier: `HIGH`");

        let sub_tp = tmp_dir.join("sub_transcript.jsonl");
        fs::write(
            &sub_tp,
            "{\"step_index\":0,\"source\":\"SYSTEM\",\"type\":\"SYSTEM_MESSAGE\",\"content\":\"[Message] timestamp=2026-11-17T00:00:00Z sender=parent-01 priority=HIGH content=work\"}\n",
        )
        .unwrap();

        let sub_payload = json!({
            "conversationId": sid,
            "transcriptPath": sub_tp.to_string_lossy(),
        });
        assert_eq!(evaluate_pre_invocation(&sub_payload), None);

        let main_tp = tmp_dir.join("main_transcript.jsonl");
        fs::write(
            &main_tp,
            "{\"step_index\":0,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"hi\"}\n",
        )
        .unwrap();
        let main_payload = json!({
            "conversationId": sid,
            "transcriptPath": main_tp.to_string_lossy(),
        });
        let got = evaluate_pre_invocation(&main_payload).unwrap();
        assert!(got.contains("HIGH"));
        assert_eq!(evaluate_pre_invocation(&main_payload), None);

        match prev {
            Some(v) => std::env::set_var("CARBON_STACK_HOME", v),
            None => std::env::remove_var("CARBON_STACK_HOME"),
        }
        let _ = fs::remove_dir_all(&tmp_dir);
    }
}
