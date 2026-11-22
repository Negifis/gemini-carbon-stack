use serde_json::{json, Map, Value};
use std::fs;
use crate::{cwg_common as cc, gate_inbox as gi, rio, win32_sqlite::format_iso_utc};

pub fn evaluate_pre_invocation(payload: &Value) -> Option<String> {
    let s = rio::session_key(payload);
    let has_p = cc::pending_notes_path(&s).is_file();
    let hc = if s != "unknown" { gi::get_handler_config() } else { json!({}) };
    let hs = gi::get_handler_session_from_cfg(Some(&hc));
    let is_h = !hs.is_empty() && s == hs;
    let has_c = cc::marker_path(&s).is_file() || cc::has_pending_marker_deltas(&s);
    if !has_p && !is_h && !has_c { return None; }
    let tp = payload.get("transcriptPath").or_else(|| payload.get("transcript_path")).and_then(|v| v.as_str()).unwrap_or("");
    if rio::is_subagent_session(tp, None) { return None; }
    let mut notes = if has_p { cc::pop_pending_notes(&s) } else { Vec::new() };
    let dir = cc::gate_dir().join("pre_inv");
    let _ = fs::create_dir_all(&dir);
    let sp = dir.join(format!("{}.json", rio::safe_key(&s, "default")));
    let mut st: Map<String, Value> = match rio::read_json(&sp) { Some(Value::Object(m)) => m, _ => Map::new() };
    let mut chg = false;
    if is_h {
        let dg = gi::format_handler_digest(10, Some(&hc));
        let prev = rio::val_to_str(st.get("last_handler_digest_sha"));
        if dg.is_empty() { if !prev.is_empty() { st.remove("last_handler_digest_sha"); chg = true; } }
        else { let sha = rio::sha256_hex(dg.as_bytes()); if sha != prev { notes.push(dg); st.insert("last_handler_digest_sha".into(), json!(sha)); chg = true; } }
    }
    if has_c && !notes.iter().any(|n| n.contains("[Code Work Gate]")) {
        if let Some(m) = cc::read_active_marker_with_pending(&s).filter(|m| cc::candidate_class(m) == cc::WORK_PERSISTENT) {
            let c = cc::resolve_candidate_context(&m, true);
            let fl = rio::val_to_str(c.get("floor"));
            let dp = cc::durable_paths_from_val(c.get("dpaths"));
            let (n, pol) = (dp.len(), c.get("policy"));
            let ht = c.get("require_tests").and_then(|v| v.as_bool()).unwrap_or_else(|| cc::requires_tests(&fl, &rio::val_to_str(c.get("cwd")), &dp, pol, &rio::val_to_str(c.get("git_root"))));
            let reqs = cc::receipt_requirements_summary(&fl, pol, ht);
            let ts = rio::val_to_f64(m.get("first_ts"));
            let since = (ts > 0.0).then(|| format_iso_utc(ts)).filter(|x| x.len() >= 16).map_or_else(String::new, |x| format!(", open since {}", &x[11..16]));
            let ui = payload.get("lastUserInput").and_then(|v| v.as_str()).unwrap_or("").trim();
            let uh = if ui.is_empty() { String::new() } else { rio::sha256_hex(ui.as_bytes())[..16].to_string() };
            let key = format!("{}|{}|{}|{}", uh, cc::candidate_key(&m), fl, n);
            if key != rio::val_to_str(st.get("last_open_reminder_key")) {
                notes.push(format!("[gate] Open candidate: PERSISTENT, path floor {} ({} lasting file{}{}). Requires {}. End the final message with `[gate] verified: {}; <candidate and decisive checks>` (or pr-ready/draft-blocked after autonomous closure); a closing message without a receipt is blocked.", fl, n, if n == 1 { "" } else { "s" }, since, reqs, fl));
                st.insert("last_open_reminder_key".into(), json!(key)); chg = true;
            }
        }
    }
    if chg { let _ = rio::write_json(&sp, &Value::Object(st)); }
    (!notes.is_empty()).then(|| notes.join("\n\n"))
}

pub fn run_cli(args: &[String]) -> i32 {
    let _ = rio::parse_event_arg(args, "PreInvocation");
    if let Ok(p) = rio::read_hook_stdin() { match evaluate_pre_invocation(&p) { Some(m) => rio::emit_inject_system(&m, None), None => rio::emit_json(&json!({})) } }
    else { rio::log_hook_event("hook-errors", "stdin_error", json!({"hook": "cwg_pre_invocation"})); rio::emit_json(&json!({})); }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cwg_common, gate_inbox};

    #[test]
    fn test_evaluate_pre_invocation_pops_notes_and_skips_subagents() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp_dir = std::env::temp_dir().join(format!("cwg-pre-inv-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();
        let prev = std::env::var_os("CARBON_STACK_HOME");
        unsafe { std::env::set_var("CARBON_STACK_HOME", &tmp_dir) };

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

        unsafe {
            match prev {
                Some(v) => std::env::set_var("CARBON_STACK_HOME", v),
                None => std::env::remove_var("CARBON_STACK_HOME"),
            }
        }
        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_handler_digest_dedup_and_open_persistent_reminder() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp_dir = std::env::temp_dir().join(format!("cwg-pre-inv-rem-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();
        let prev = std::env::var_os("CARBON_STACK_HOME");
        unsafe { std::env::set_var("CARBON_STACK_HOME", &tmp_dir) };

        let main_tp = tmp_dir.join("main.jsonl");
        fs::write(
            &main_tp,
            "{\"step_index\":0,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"fix bug\"}\n",
        )
        .unwrap();

        let handler_sid = "handler-sess-01";
        let _ = gate_inbox::set_handler_config(handler_sid, "", false);
        rio::write_json(
            &cwg_common::enforcement_state_path("sess-reporter"),
            &json!({"block_nonce": "nonce1"}),
        )
        .unwrap();
        let (rc1, resp1, err1) = gate_inbox::file_report(
            "sess-reporter",
            "nonce1",
            "block reason",
            "facts one",
            "cargo test",
            "",
        );
        assert_eq!(rc1, 0, "file_report 1 failed: {:?}", err1);
        assert!(resp1.unwrap().get("report_id").is_some());
        let handler_payload = json!({
            "conversationId": handler_sid,
            "transcriptPath": main_tp.to_string_lossy(),
        });
        let d1 = evaluate_pre_invocation(&handler_payload).unwrap();
        assert!(d1.contains("Gate Anomaly Handler") && d1.contains("sess-reporter"));
        assert_eq!(evaluate_pre_invocation(&handler_payload), None);
        rio::write_json(
            &cwg_common::enforcement_state_path("sess-reporter-2"),
            &json!({"block_nonce": "nonce2"}),
        )
        .unwrap();
        let (rc2, resp2, err2) = gate_inbox::file_report(
            "sess-reporter-2",
            "nonce2",
            "block reason 2",
            "facts two",
            "cargo test",
            "",
        );
        assert_eq!(rc2, 0, "file_report 2 failed: {:?}", err2);
        assert!(resp2.unwrap().get("report_id").is_some());
        let d2 = evaluate_pre_invocation(&handler_payload).unwrap();
        assert!(d2.contains("sess-reporter-2"));

        let cand_sid = "sess-persistent-rem";
        let target_file = tmp_dir.join("mod.rs");
        fs::write(&target_file, "pub fn a() {}\n").unwrap();
        let target_norm = rio::normalize_path(&target_file.to_string_lossy());
        let base_marker = json!({
            "session": cand_sid,
            "class": cwg_common::WORK_PERSISTENT,
            "closed": false,
            "first_ts": 1700000100.0,
            "last_ts": 1700000100.0,
            "last_durable_ts": 1700000100.0,
            "edits": 1,
            "cwd": rio::normalize_path(&tmp_dir.to_string_lossy()),
            "paths": [target_norm],
        });
        rio::write_json(&cwg_common::marker_path(cand_sid), &base_marker).unwrap();

        let p1 = json!({
            "conversationId": cand_sid,
            "transcriptPath": main_tp.to_string_lossy(),
            "lastUserInput": "turn 1"
        });
        let rem1 = evaluate_pre_invocation(&p1).unwrap();
        assert!(rem1.contains("[gate] Open candidate: PERSISTENT, path floor STANDARD (1 lasting file"));
        assert_eq!(evaluate_pre_invocation(&p1), None);

        let p2 = json!({
            "conversationId": cand_sid,
            "transcriptPath": main_tp.to_string_lossy(),
            "lastUserInput": "turn 2"
        });
        assert!(evaluate_pre_invocation(&p2).is_some());

        cwg_common::queue_pending_note(cand_sid, "[Code Work Gate] Transition");
        let p3 = json!({
            "conversationId": cand_sid,
            "transcriptPath": main_tp.to_string_lossy(),
            "lastUserInput": "turn 3"
        });
        let got_p3 = evaluate_pre_invocation(&p3).unwrap();
        assert!(got_p3.contains("[Code Work Gate] Transition"));
        assert!(!got_p3.contains("[gate] Open candidate:"));

        let op_sid = "sess-operational-rem";
        rio::write_json(
            &cwg_common::marker_path(op_sid),
            &json!({
                "session": op_sid,
                "class": cwg_common::WORK_OPERATIONAL,
                "operational": true,
                "closed": false,
                "first_ts": 1700000100.0,
                "paths": [],
            }),
        )
        .unwrap();
        let op_payload = json!({
            "conversationId": op_sid,
            "transcriptPath": main_tp.to_string_lossy(),
            "lastUserInput": "op turn"
        });
        assert_eq!(evaluate_pre_invocation(&op_payload), None);

        unsafe {
            match prev {
                Some(v) => std::env::set_var("CARBON_STACK_HOME", v),
                None => std::env::remove_var("CARBON_STACK_HOME"),
            }
        }
        let _ = fs::remove_dir_all(&tmp_dir);
    }
}
