use serde_json::json;

use crate::{
    chip_hooks, continuity_hook, cwg_mark, cwg_pre_invocation, cwg_stop, rio, safety_guards,
};

pub fn run_unified_hook(args: &[String]) -> i32 {
    let event = rio::parse_event_arg(args, "");
    let payload = match rio::read_hook_stdin() {
        Ok(val) => val,
        Err(err) => {
            rio::log_hook_event(
                "hook-errors",
                "stdin_error",
                json!({
                    "hook": "carbon-stack",
                    "event": event,
                    "error": err,
                }),
            );
            rio::emit_default_for_event(&event);
            return 0;
        }
    };

    let actual_event = if !event.is_empty() {
        event
    } else {
        payload
            .get("hookEventName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };

    match actual_event.as_str() {
        "SessionStart" => {
            crate::installer::try_auto_heal_default_stage_retire();
            let (sys_msg, user_md) = continuity_hook::evaluate_session_start(&payload);
            if let Some(msg) = sys_msg {
                rio::emit_inject_system(&msg, user_md.as_deref());
            } else {
                rio::emit_json(&json!({}));
            }
        }
        "PreInvocation" => {
            crate::installer::try_auto_heal_default_stage_retire();
            let mut blocks: Vec<String> = Vec::new();
            if let Some(s) = continuity_hook::evaluate_pre_invocation(&payload) {
                if !s.trim().is_empty() {
                    blocks.push(s);
                }
            }
            if let Some(s) = chip_hooks::evaluate_pre_invocation(&payload) {
                if !s.trim().is_empty() {
                    blocks.push(s);
                }
            }
            if let Some(s) = cwg_pre_invocation::evaluate_pre_invocation(&payload) {
                if !s.trim().is_empty() {
                    blocks.push(s);
                }
            }
            if blocks.is_empty() {
                rio::emit_json(&json!({}));
            } else {
                rio::emit_inject_system(&blocks.join("\n\n"), None);
            }
        }
        "PreToolUse" => {
            let (sg_dec, sg_reason, sg_overwrite) = safety_guards::evaluate_pre_tool_use(&payload);
            if sg_dec != "allow" {
                rio::emit_pre_tool(&sg_dec, sg_reason.as_deref(), sg_overwrite);
                return 0;
            }
            let effective_payload = if let Some(ref ov) = sg_overwrite {
                let mut cloned = payload.clone();
                if let Some(tc_obj) = cloned.get_mut("toolCall").and_then(|v| v.as_object_mut()) {
                    tc_obj.insert("args".to_string(), ov.clone());
                }
                cloned
            } else {
                payload.clone()
            };
            let (lg_dec, lg_reason) = continuity_hook::evaluate_pre_tool_use(&effective_payload);
            if lg_dec != "allow" {
                rio::emit_pre_tool(&lg_dec, lg_reason.as_deref(), None);
                return 0;
            }
            cwg_mark::record_pre_tool_use(&effective_payload);
            rio::emit_pre_tool("allow", None, sg_overwrite);
        }
        "PostToolUse" => {
            return cwg_mark::evaluate_post_tool_use(&payload);
        }
        "Stop" => {
            if let Some(cont_reason) = continuity_hook::decide_stop(&payload) {
                rio::emit_stop_continue(&cont_reason);
                return 0;
            }
            if let Some(chip_reason) = chip_hooks::decide_stop(&payload) {
                rio::emit_stop_continue(&chip_reason);
                return 0;
            }
            if let Some(gate_reason) = cwg_stop::decide_stop(&payload) {
                rio::emit_stop_continue(&gate_reason);
                return 0;
            }
            rio::emit_stop_allow();
        }
        other => {
            rio::emit_default_for_event(other);
        }
    }
    0
}
