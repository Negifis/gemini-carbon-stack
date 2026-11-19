use regex::Regex;
use serde_json::{json, Value};
use std::env;
use std::path::Path;
use std::sync::OnceLock;

use crate::rio;
use crate::win32_sqlite::run_command_with_job;

const BYPASS_TOKENS: &[&str] = &[
    "tokenade",
    "carbon-stack",
    "codex_lane.py",
    "gate_inbox.py",
    "cwg_stop.py",
    "cwg_mark.py",
    "cwg_pre_invocation.py",
    "swarm_cache.py",
    "swarm_ctl.py",
    "continuity.py",
    "worktree_guard.py",
    "stack_doctor.py",
    "install.py",
    "chat-bus",
    "chat_bus_cli.py",
];

const DISABLED_VALUES: &[&str] = &["0", "false", "off", "no"];

fn leading_cd_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // INVARIANT: Strip only a single leading directory-change line so the wrapped core remains single-line.
        Regex::new(
            r#"(?i)\A(?P<cd>\s*(?:Set-Location|Push-Location|cd(?:\s+/d)?)\s+(?:"[^"\r\n]+"|'[^'\r\n]+'|[^\s|;&$\r\n]+)\s*\r?\n)(?P<rest>[\s\S]+)\z"#,
        )
        .expect("leading_cd_line_re")
    })
}

fn is_auto_wrap_value(raw: &str) -> bool {
    let low = raw.trim().to_lowercase();
    !DISABLED_VALUES.contains(&low.as_str())
}

pub fn is_auto_wrap_enabled() -> bool {
    let raw = env::var("TOKENADE_AUTO_WRAP").unwrap_or_else(|_| "1".to_string());
    is_auto_wrap_value(&raw)
}

fn which_in_path(name: &str) -> Option<String> {
    crate::rio::which_in_path(name)
}

pub fn find_tokenade_bin() -> Option<String> {
    for env_key in ["CARBON_TOKENADE_BIN", "TOKENADE_BIN"] {
        if let Ok(val) = env::var(env_key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() && Path::new(trimmed).is_file() {
                return Some(trimmed.to_string());
            }
        }
    }
    #[cfg(windows)]
    {
        if let Ok(appdata) = env::var("APPDATA") {
            let trimmed = appdata.trim();
            if !trimmed.is_empty() {
                // INVARIANT: Prefer the compiled Rust `tokenade.exe` binary (~3 ms) over `tokenade.cmd` (~120 ms cmd+node shim).
                let native_exe = std::path::PathBuf::from(trimmed)
                    .join("npm")
                    .join("node_modules")
                    .join("@tokenade")
                    .join("cli")
                    .join("node_modules")
                    .join("@tokenade")
                    .join("cli-win32-x64")
                    .join("tokenade.exe");
                if native_exe.is_file() {
                    return Some(native_exe.to_string_lossy().into_owned());
                }
            }
        }
        if let Some(found) = which_in_path("tokenade.exe") {
            return Some(found);
        }
    }
    which_in_path("tokenade")
}

fn extract_antigravity_command(payload: &Value) -> String {
    if let Some(tc) = payload.get("toolCall").and_then(|v| v.as_object()) {
        for key in ["args", "arguments"] {
            if let Some(sub) = tc.get(key).and_then(|v| v.as_object()) {
                if let Some(cmd) = sub.get("CommandLine").and_then(|v| v.as_str()) {
                    return cmd.to_string();
                }
            }
        }
    }
    for top_key in ["toolArgs", "tool_input"] {
        if let Some(sub) = payload.get(top_key).and_then(|v| v.as_object()) {
            if let Some(cmd) = sub.get("CommandLine").and_then(|v| v.as_str()) {
                return cmd.to_string();
            }
            if let Some(cmd) = sub.get("command").and_then(|v| v.as_str()) {
                return cmd.to_string();
            }
        }
    }
    String::new()
}

fn should_bypass(cmd: &str) -> bool {
    let low = cmd.to_lowercase();
    BYPASS_TOKENS.iter().any(|tok| low.contains(tok))
}

pub fn transform_pretool_payload(payload: &Value) -> Option<String> {
    // SAFETY: Enabled by default unless `TOKENADE_AUTO_WRAP` is in `DISABLED_VALUES` (`0`/`false`/`off`/`no`); leaves multi-statement scripts and protocol CLIs untouched.
    if !is_auto_wrap_enabled() {
        return None;
    }
    if let Some(tool_name) = payload
        .get("toolCall")
        .and_then(|v| v.get("name"))
        .and_then(|v| v.as_str())
    {
        if !tool_name.is_empty() && tool_name != "run_command" {
            return None;
        }
    }

    let raw_cmd = extract_antigravity_command(payload);
    if raw_cmd.trim().is_empty() || should_bypass(&raw_cmd) {
        return None;
    }

    let mut prefix_cd = String::new();
    let mut core_cmd = raw_cmd.as_str();
    if raw_cmd.contains('\n') {
        if let Some(caps) = leading_cd_line_re().captures(&raw_cmd) {
            if let (Some(cd_m), Some(rest_m)) = (caps.name("cd"), caps.name("rest")) {
                prefix_cd = cd_m.as_str().to_string();
                core_cmd = rest_m.as_str();
            }
        }
    }

    let stripped_core = core_cmd.trim();
    if stripped_core.is_empty() || stripped_core.contains('\n') || stripped_core.contains('\r') {
        return None;
    }

    #[cfg(windows)]
    if stripped_core.contains('"') || stripped_core.contains('`') || stripped_core.ends_with('\\') {
        // SAFETY: Windows PowerShell 5.1 (`PSNativeCommandArgumentPassing=Legacy`) strips unescaped `"` and misquotes trailing `\` when passing arguments to native `.exe` binaries (`tokenade.exe`).
        return None;
    }

    let tk_bin = find_tokenade_bin()?;
    let bridge_tool = if cfg!(windows) { "PowerShell" } else { "Bash" };
    let bridge_req = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": bridge_tool,
        "tool_input": {"command": stripped_core},
    });
    let bridge_in = serde_json::to_vec(&bridge_req).ok()?;

    let res = run_command_with_job(
        &tk_bin,
        &["hookwrap-pretool".to_string()],
        None,
        &[],
        Some(&bridge_in),
        Some(4000),
    )
    .ok()?;
    if res.timed_out || res.code != 0 || res.stdout.is_empty() {
        return None;
    }
    let stdout_text = String::from_utf8_lossy(&res.stdout);
    if stdout_text.trim().is_empty() {
        return None;
    }
    let out: Value = serde_json::from_str(&stdout_text).ok()?;
    if !out.is_object() {
        return None;
    }

    let mut wrapped = out
        .get("hookSpecificOutput")
        .and_then(|v| v.get("updatedInput"))
        .and_then(|v| v.get("command"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if wrapped.is_empty() {
        wrapped = out
            .get("overwrite")
            .and_then(|v| v.get("CommandLine"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
    }

    if wrapped.is_empty() || wrapped == stripped_core {
        return None;
    }

    #[cfg(windows)]
    if wrapped.starts_with('"') || wrapped.starts_with('\'') {
        wrapped = format!("& {}", wrapped);
    }

    if prefix_cd.is_empty() {
        Some(wrapped)
    } else {
        Some(format!("{}{}", prefix_cd, wrapped))
    }
}

pub fn evaluate_pre_tool_use(payload: &Value) -> Value {
    if let Some(rewritten) = transform_pretool_payload(payload) {
        json!({
            "decision": "allow",
            "overwrite": {
                "CommandLine": rewritten
            }
        })
    } else {
        json!({"decision": "allow"})
    }
}

pub fn run_cli(_args: &[String]) -> i32 {
    if !is_auto_wrap_enabled() {
        rio::emit_pre_tool("allow", None, None);
        return 0;
    }
    match rio::read_hook_stdin() {
        Ok(payload) => {
            let out = evaluate_pre_tool_use(&payload);
            rio::emit_json(&out);
            0
        }
        Err(_) => {
            rio::emit_pre_tool("allow", None, None);
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leading_cd_line_regex_compiles_and_splits() {
        let cmd = "Set-Location \"C:\\repo\"\n$null | npm test";
        let caps = leading_cd_line_re().captures(cmd).unwrap();
        assert_eq!(caps.name("cd").unwrap().as_str(), "Set-Location \"C:\\repo\"\n");
        assert_eq!(caps.name("rest").unwrap().as_str(), "$null | npm test");
        assert!(!leading_cd_line_re().is_match("git status"));
    }

    #[test]
    fn test_auto_wrap_disabled_values() {
        assert!(!is_auto_wrap_value("0"));
        assert!(!is_auto_wrap_value("FALSE"));
        assert!(!is_auto_wrap_value(" off "));
        assert!(!is_auto_wrap_value("No"));
        assert!(is_auto_wrap_value("1"));
        assert!(is_auto_wrap_value("true"));
    }

    #[test]
    fn test_bypass_protocol_multiline_non_shell_and_windows_quotes() {
        let bypass_payload = json!({
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": "$null | python -X utf8 codex_lane.py review --cwd C:/repo"}
            }
        });
        assert_eq!(evaluate_pre_tool_use(&bypass_payload), json!({"decision": "allow"}));

        let multiline_payload = json!({
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": "$a = 1\n$b = 2\nWrite-Output $a"}
            }
        });
        assert_eq!(evaluate_pre_tool_use(&multiline_payload), json!({"decision": "allow"}));

        let edit_payload = json!({
            "toolCall": {
                "name": "edit_file",
                "args": {"Path": "src/main.rs"}
            }
        });
        assert_eq!(evaluate_pre_tool_use(&edit_payload), json!({"decision": "allow"}));

        #[cfg(windows)]
        {
            for unsafe_cmd in [
                "Write-Output \"a b\"",
                "Write-Output `a",
                "git status C:\\repo\\",
            ] {
                let p = json!({
                    "toolCall": {
                        "name": "run_command",
                        "args": {"CommandLine": unsafe_cmd}
                    }
                });
                assert_eq!(evaluate_pre_tool_use(&p), json!({"decision": "allow"}));
            }
        }
    }
}
