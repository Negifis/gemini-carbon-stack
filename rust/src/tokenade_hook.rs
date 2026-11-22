use serde_json::{json, Value};
use std::env;
use std::path::Path;

use crate::rio;

pub fn is_auto_wrap_enabled() -> bool {
    // INVARIANT: CommandLine auto-wrap is permanently disabled; invoke tokenade explicitly via CLI.
    false
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
        if let Some(found) = rio::which_in_path("tokenade.exe") {
            return Some(found);
        }
    }
    rio::which_in_path("tokenade")
}

pub fn transform_pretool_payload(_payload: &Value) -> Option<String> {
    None
}

pub fn evaluate_pre_tool_use(_payload: &Value) -> Value {
    json!({"decision": "allow"})
}

pub fn run_cli(_args: &[String]) -> i32 {
    rio::emit_pre_tool("allow", None, None);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_wrap_permanently_disabled() {
        assert!(!is_auto_wrap_enabled());
        for sample in [
            json!({
                "toolCall": {
                    "name": "run_command",
                    "args": {"CommandLine": "git status"}
                }
            }),
            json!({
                "toolCall": {
                    "name": "run_command",
                    "args": {"CommandLine": "cargo test --offline"}
                }
            }),
            json!({
                "toolCall": {
                    "name": "edit_file",
                    "args": {"Path": "src/main.rs"}
                }
            }),
        ] {
            assert_eq!(transform_pretool_payload(&sample), None);
            assert_eq!(evaluate_pre_tool_use(&sample), json!({"decision": "allow"}));
        }
    }
}
