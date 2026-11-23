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
            let first_ts_ms: i64 = if ts.is_finite() && ts > 0.0 { (ts * 1000.0).round() as i64 } else { 0 };
            let cand_key = format!("{}|{}", first_ts_ms, fl);
            let ui = rio::strip_user_request_wrapper(
                payload.get("lastUserInput").and_then(|v| v.as_str()).unwrap_or(""),
            );
            let ui_hash = (!ui.is_empty()).then(|| rio::sha256_hex(ui.as_bytes())[..16].to_string());
            let tx_step = rio::last_user_input_step(tp);
            let tx_idx = tx_step.as_ref().map(|(idx, _)| *idx);
            let (cur_step, cur_hash): (Option<i64>, Option<String>) = if ui.is_empty() {
                match tx_step {
                    Some((idx, content)) => {
                        let t = rio::strip_user_request_wrapper(&content);
                        (Some(idx), (!t.is_empty()).then(|| rio::sha256_hex(t.as_bytes())[..16].to_string()))
                    }
                    None => (None, None),
                }
            } else {
                match tx_step {
                    Some((idx, content)) if rio::strip_user_request_wrapper(&content) == ui => (Some(idx), ui_hash),
                    _ => (None, ui_hash),
                }
            };
            let prev_cand = rio::val_to_str(st.get("last_open_reminder_cand"));
            let prev_step = st.get("last_open_reminder_step").and_then(|v| v.as_i64());
            let prev_base_step = st.get("last_open_reminder_base_step").and_then(|v| v.as_i64());
            let prev_hash = rio::val_to_str(st.get("last_open_reminder_ui_hash"));
            // INVARIANT: A monotonic transcript step `<= prev_base_step` cannot supersede or clobber a pending `lastUserInput` reminder that arrived before the transcript flushed.
            let same_turn = if prev_cand != cand_key {
                false
            } else {
                match (prev_step, cur_step) {
                    (Some(ps), Some(cs)) => cs <= ps,
                    (None, Some(cs)) => {
                        if prev_base_step.is_some_and(|bs| cs <= bs) {
                            true
                        } else if !prev_hash.is_empty() && cur_hash.as_deref() == Some(prev_hash.as_str()) {
                            st.insert("last_open_reminder_step".into(), json!(cs));
                            st.remove("last_open_reminder_base_step");
                            chg = true;
                            true
                        } else {
                            false
                        }
                    }
                    (Some(_), None) => !prev_hash.is_empty() && cur_hash.as_deref() == Some(prev_hash.as_str()),
                    (None, None) => cur_hash.as_deref().unwrap_or("") == prev_hash.as_str(),
                }
            };
            if !same_turn {
                notes.push(format!("[gate] Open candidate: PERSISTENT, path floor {} ({} lasting file{}{}). Requires {}. End the final message with `[gate] verified: {}; <candidate and decisive checks>` (or pr-ready/draft-blocked after autonomous closure); a closing message without a receipt is blocked.", fl, n, if n == 1 { "" } else { "s" }, since, reqs, fl));
                st.insert("last_open_reminder_cand".into(), json!(cand_key));
                match cur_step {
                    Some(cs) => {
                        st.insert("last_open_reminder_step".into(), json!(cs));
                        st.remove("last_open_reminder_base_step");
                    }
                    None => {
                        st.remove("last_open_reminder_step");
                        match tx_idx {
                            Some(bs) => { st.insert("last_open_reminder_base_step".into(), json!(bs)); }
                            None => { st.remove("last_open_reminder_base_step"); }
                        }
                    }
                }
                match cur_hash {
                    Some(ch) => { st.insert("last_open_reminder_ui_hash".into(), json!(ch)); }
                    None => { st.remove("last_open_reminder_ui_hash"); }
                }
                st.remove("last_open_reminder_key");
                chg = true;
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

    #[test]
    fn test_open_reminder_dedups_across_edits_without_last_user_input() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp_dir =
            std::env::temp_dir().join(format!("cwg-pre-inv-dedup-reg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp_dir);
        let stack_home = tmp_dir.join("stack");
        let work_dir = tmp_dir.join("work");
        fs::create_dir_all(&stack_home).unwrap();
        fs::create_dir_all(&work_dir).unwrap();
        let prev = std::env::var_os("CARBON_STACK_HOME");
        unsafe { std::env::set_var("CARBON_STACK_HOME", &stack_home) };

        let tp = tmp_dir.join("transcript.jsonl");
        let turn1_transcript = concat!(
            "{\"step_index\":0,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"init\"}\n",
            "{\"step_index\":1,\"source\":\"MODEL\",\"type\":\"PLANNER_RESPONSE\",\"content\":\"ok\"}\n",
            "{\"step_index\":5,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"edit files\"}\n"
        );
        fs::write(&tp, turn1_transcript).unwrap();

        let f1 = work_dir.join("step1.rs");
        let f2 = work_dir.join("step2.rs");
        let f3 = work_dir.join("step3.rs");
        let f4 = work_dir.join("step4.rs");
        let high_file = work_dir.join("rust").join("src").join("cwg_pre_invocation.rs");
        fs::create_dir_all(high_file.parent().unwrap()).unwrap();
        fs::write(&f1, "pub fn s1() {}\n").unwrap();
        fs::write(&f2, "pub fn s2() {}\n").unwrap();
        fs::write(&f3, "pub fn s3() {}\n").unwrap();
        fs::write(&f4, "pub fn s4() {}\n").unwrap();
        fs::write(&high_file, "pub fn high_risk() {}\n").unwrap();

        let f1_norm = rio::normalize_path(&f1.to_string_lossy());
        let f2_norm = rio::normalize_path(&f2.to_string_lossy());
        let f3_norm = rio::normalize_path(&f3.to_string_lossy());
        let f4_norm = rio::normalize_path(&f4.to_string_lossy());
        let high_norm = rio::normalize_path(&high_file.to_string_lossy());
        let cwd_norm = rio::normalize_path(&work_dir.to_string_lossy());

        let sid = "sess-dedup-antigravity";
        let first_ts = 1700000200.0;
        let payload_omitted = json!({
            "conversationId": sid,
            "transcriptPath": tp.to_string_lossy(),
        });
        let payload_empty = json!({
            "conversationId": sid,
            "transcriptPath": tp.to_string_lossy(),
            "lastUserInput": "",
        });

        // Edit 1 (STANDARD, 1 file): emits exactly 1 reminder.
        let m1 = json!({
            "session": sid,
            "class": cwg_common::WORK_PERSISTENT,
            "closed": false,
            "first_ts": first_ts,
            "last_ts": first_ts,
            "last_durable_ts": first_ts,
            "edits": 1,
            "cwd": &cwd_norm,
            "paths": [&f1_norm],
            "content_marks": [{"path": &f1_norm, "fp": "fp-edit-1"}],
        });
        rio::write_json(&cwg_common::marker_path(sid), &m1).unwrap();
        let rem1 = evaluate_pre_invocation(&payload_omitted).unwrap();
        assert!(rem1.contains("[gate] Open candidate: PERSISTENT, path floor STANDARD"));

        // Edit 2 (STANDARD, 2 files, bumped timestamps & latest_fp): must NOT re-fire.
        let m2 = json!({
            "session": sid,
            "class": cwg_common::WORK_PERSISTENT,
            "closed": false,
            "first_ts": first_ts,
            "last_ts": first_ts + 10.0,
            "last_durable_ts": first_ts + 10.0,
            "edits": 2,
            "cwd": &cwd_norm,
            "paths": [&f1_norm, &f2_norm],
            "content_marks": [
                {"path": &f1_norm, "fp": "fp-edit-1"},
                {"path": &f2_norm, "fp": "fp-edit-2"}
            ],
        });
        assert_ne!(cc::candidate_key(&m1), cc::candidate_key(&m2));
        rio::write_json(&cwg_common::marker_path(sid), &m2).unwrap();
        assert_eq!(evaluate_pre_invocation(&payload_omitted), None);

        // Edit 3 (STANDARD, 3 files, explicit empty lastUserInput): must NOT re-fire.
        let m3 = json!({
            "session": sid,
            "class": cwg_common::WORK_PERSISTENT,
            "closed": false,
            "first_ts": first_ts,
            "last_ts": first_ts + 20.0,
            "last_durable_ts": first_ts + 20.0,
            "edits": 3,
            "cwd": &cwd_norm,
            "paths": [&f1_norm, &f2_norm, &f3_norm],
            "content_marks": [
                {"path": &f1_norm, "fp": "fp-edit-1"},
                {"path": &f2_norm, "fp": "fp-edit-2"},
                {"path": &f3_norm, "fp": "fp-edit-3"}
            ],
        });
        rio::write_json(&cwg_common::marker_path(sid), &m3).unwrap();
        assert_eq!(evaluate_pre_invocation(&payload_empty), None);

        // Floor escalation STANDARD -> HIGH: emits 1 new HIGH reminder.
        let m_high1 = json!({
            "session": sid,
            "class": cwg_common::WORK_PERSISTENT,
            "closed": false,
            "first_ts": first_ts,
            "last_ts": first_ts + 30.0,
            "last_durable_ts": first_ts + 30.0,
            "edits": 4,
            "cwd": &cwd_norm,
            "paths": [&f1_norm, &f2_norm, &f3_norm, &high_norm],
            "content_marks": [
                {"path": &f3_norm, "fp": "fp-edit-3"},
                {"path": &high_norm, "fp": "fp-edit-4"}
            ],
        });
        rio::write_json(&cwg_common::marker_path(sid), &m_high1).unwrap();
        let rem_high = evaluate_pre_invocation(&payload_omitted).unwrap();
        assert!(rem_high.contains("[gate] Open candidate: PERSISTENT, path floor HIGH"));

        // Another edit while staying at HIGH: must NOT re-fire.
        let m_high2 = json!({
            "session": sid,
            "class": cwg_common::WORK_PERSISTENT,
            "closed": false,
            "first_ts": first_ts,
            "last_ts": first_ts + 40.0,
            "last_durable_ts": first_ts + 40.0,
            "edits": 5,
            "cwd": &cwd_norm,
            "paths": [&f1_norm, &f2_norm, &f3_norm, &high_norm, &f4_norm],
            "content_marks": [
                {"path": &high_norm, "fp": "fp-edit-4"},
                {"path": &f4_norm, "fp": "fp-edit-5"}
            ],
        });
        rio::write_json(&cwg_common::marker_path(sid), &m_high2).unwrap();
        assert_eq!(evaluate_pre_invocation(&payload_omitted), None);

        // Append new USER_INPUT (step_index: 12): emits 1 reminder for the new user turn, then dedups.
        let turn2_transcript = format!(
            "{}{}",
            turn1_transcript,
            "{\"step_index\":12,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"continue checks\"}\n"
        );
        fs::write(&tp, turn2_transcript).unwrap();
        let rem_turn2 = evaluate_pre_invocation(&payload_omitted).unwrap();
        assert!(rem_turn2.contains("[gate] Open candidate: PERSISTENT, path floor HIGH"));
        assert_eq!(evaluate_pre_invocation(&payload_omitted), None);

        // New candidate (different first_ts in the same turn) resets reminder once, then dedups.
        let m_new_cand = json!({
            "session": sid,
            "class": cwg_common::WORK_PERSISTENT,
            "closed": false,
            "first_ts": first_ts + 500.0,
            "last_ts": first_ts + 500.0,
            "last_durable_ts": first_ts + 500.0,
            "edits": 1,
            "cwd": &cwd_norm,
            "paths": [&f1_norm],
            "content_marks": [{"path": &f1_norm, "fp": "fp-new-1"}],
        });
        rio::write_json(&cwg_common::marker_path(sid), &m_new_cand).unwrap();
        let rem_new = evaluate_pre_invocation(&payload_omitted).unwrap();
        assert!(rem_new.contains("[gate] Open candidate: PERSISTENT, path floor STANDARD"));
        assert_eq!(evaluate_pre_invocation(&payload_omitted), None);

        // Regression for Wave A1 R1 #1: `lastUserInput` arrives ahead of transcript flush,
        // then transcript records that exact turn, then `lastUserInput` disappears — must emit
        // strictly once for the turn, while a subsequent new turn emits once again.
        let p_lag_b = json!({
            "conversationId": sid,
            "transcriptPath": tp.to_string_lossy(),
            "lastUserInput": "message B"
        });
        assert!(evaluate_pre_invocation(&p_lag_b).is_some());
        assert_eq!(evaluate_pre_invocation(&p_lag_b), None);
        // Even if `lastUserInput` disappears BEFORE step 20 flushes (transcript still at step 12),
        // the stale step 12 MUST NOT re-fire or clobber the pending "message B" state.
        assert_eq!(evaluate_pre_invocation(&payload_omitted), None);

        // Transcript flushes step 20 with "message B": must NOT re-fire whether lastUserInput is present or omitted.
        let turn_b_transcript = format!(
            "{}{}{}",
            turn1_transcript,
            "{\"step_index\":12,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"continue checks\"}\n",
            "{\"step_index\":20,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"message B\"}\n"
        );
        fs::write(&tp, &turn_b_transcript).unwrap();
        assert_eq!(evaluate_pre_invocation(&payload_omitted), None);
        assert_eq!(evaluate_pre_invocation(&p_lag_b), None);

        // Another turn with identical text "message B" at step 25 MUST fire once (new step_index).
        let turn_b2_transcript = format!(
            "{}{}",
            turn_b_transcript,
            "{\"step_index\":25,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"message B\"}\n"
        );
        fs::write(&tp, &turn_b2_transcript).unwrap();
        assert!(evaluate_pre_invocation(&payload_omitted).is_some());
        assert_eq!(evaluate_pre_invocation(&p_lag_b), None);
        assert_eq!(evaluate_pre_invocation(&payload_omitted), None);

        unsafe {
            match prev {
                Some(v) => std::env::set_var("CARBON_STACK_HOME", v),
                None => std::env::remove_var("CARBON_STACK_HOME"),
            }
        }
        let _ = fs::remove_dir_all(&tmp_dir);
    }
}
