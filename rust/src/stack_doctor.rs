use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::chip_hooks;
use crate::code_search;
use crate::codex_lane;
use crate::continuity_hook;
use crate::cwg_common;
use crate::gate_inbox;
use crate::rio;
use crate::swarm_cache;
use crate::tokenade_hook;
use crate::win32_sqlite::{run_command_with_job, SqlParam, SqliteConn, SQLITE_OPEN_READONLY};

const HOOK_EVENTS: &[&str] = &[
    "SessionStart",
    "PreInvocation",
    "PreToolUse",
    "PostToolUse",
    "Stop",
];
const REQUIRED_GUARD_TOOLS: &[&str] = &["read_board", "edit_file", "write_file", "swarm_wait"];

fn hook_target_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:bin[/\\]carbon-stack(?:\.exe)?|(?:hooks|tools)[/\\][A-Za-z0-9._-]+\.(?:py|ps1|sh|mjs|js))"#,
        )
        .expect("hook_target_re")
    })
}

fn process_ls_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)language_server").expect("process_ls_re"))
}

pub fn find_agy_cli() -> Option<String> {
    for name in ["agy", "agy.exe"] {
        if let Some(found) = code_search::which_in_path(name) {
            return Some(found);
        }
    }
    #[cfg(windows)]
    {
        let default_win = rio::home_dir()
            .join("AppData")
            .join("Local")
            .join("agy")
            .join("bin")
            .join("agy.exe");
        if default_win.is_file() {
            return Some(default_win.to_string_lossy().into_owned());
        }
    }
    None
}

pub fn find_rust_binary() -> Option<String> {
    if let Ok(pure) = env::var("CARBON_PURE_PYTHON") {
        let low = pure.trim().to_ascii_lowercase();
        if matches!(low.as_str(), "1" | "true" | "yes") {
            return None;
        }
    }
    if let Ok(ov) = env::var("CARBON_STACK_BIN") {
        let trimmed = ov.trim();
        if !trimmed.is_empty() && Path::new(trimmed).is_file() {
            return Some(trimmed.to_string());
        }
    }
    let exe_name = if cfg!(windows) {
        "carbon-stack.exe"
    } else {
        "carbon-stack"
    };
    let plug_bin = rio::plugin_root().join("bin").join(exe_name);
    if plug_bin.is_file() {
        return Some(plug_bin.to_string_lossy().into_owned());
    }
    if let Ok(cur) = env::current_exe() {
        if cur
            .file_name()
            .and_then(|s| s.to_str())
            .map_or(false, |n| n.eq_ignore_ascii_case(exe_name))
            && cur.is_file()
        {
            return Some(cur.to_string_lossy().into_owned());
        }
    }
    None
}

fn scan_language_server_processes() -> Vec<Value> {
    let mut found: Vec<Value> = Vec::new();
    #[cfg(windows)]
    {
        let args = vec![
            "/FO".to_string(),
            "CSV".to_string(),
            "/NH".to_string(),
        ];
        if let Ok(res) = run_command_with_job("tasklist", &args, None, &[], None, Some(3000)) {
            if !res.timed_out && res.code == 0 {
                for line in res.stdout_str().lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || !process_ls_re().is_match(trimmed) {
                        continue;
                    }
                    let cols: Vec<&str> = trimmed
                        .split(',')
                        .map(|c| c.trim().trim_matches('"'))
                        .collect();
                    let name = cols.first().copied().unwrap_or("language_server");
                    let pid = cols.get(1).and_then(|s| s.parse::<u32>().ok());
                    found.push(json!({ "name": name, "pid": pid }));
                }
            }
        }
    }
    #[cfg(not(windows))]
    {
        if let Ok(entries) = fs::read_dir("/proc") {
            for ent in entries.flatten() {
                let fname = ent.file_name().to_string_lossy().into_owned();
                if let Ok(pid) = fname.parse::<u32>() {
                    let comm_path = ent.path().join("comm");
                    if let Ok(comm) = fs::read_to_string(comm_path) {
                        let name = comm.trim();
                        if process_ls_re().is_match(name) {
                            found.push(json!({ "name": name, "pid": pid }));
                        }
                    }
                }
            }
        } else if let Ok(res) = run_command_with_job(
            "ps",
            &["-eo".to_string(), "pid,comm".to_string()],
            None,
            &[],
            None,
            Some(3000),
        ) {
            if !res.timed_out && res.code == 0 {
                for line in res.stdout_str().lines() {
                    if process_ls_re().is_match(line) {
                        let mut parts = line.split_whitespace();
                        let pid = parts.next().and_then(|s| s.parse::<u32>().ok());
                        let name = parts.next().unwrap_or("language_server");
                        found.push(json!({ "name": name, "pid": pid }));
                    }
                }
            }
        }
    }
    found
}

fn query_ls_rpc_via_curl(addr: &str, csrf: &str, plugin_name: &str) -> Option<Value> {
    let curl_bin = code_search::which_in_path("curl.exe")
        .or_else(|| code_search::which_in_path("curl"))?;
    let candidates: Vec<String> = if addr.starts_with("http") {
        vec![addr.to_string()]
    } else {
        vec![format!("http://{}", addr), format!("https://{}", addr)]
    };

    for base in candidates {
        let url = format!(
            "{}/exa.language_server_pb.LanguageServerService/GetAllPlugins",
            base.trim_end_matches('/')
        );
        let args = vec![
            "-sS".to_string(),
            "-k".to_string(),
            "--max-time".to_string(),
            "3".to_string(),
            "-X".to_string(),
            "POST".to_string(),
            "-H".to_string(),
            "Content-Type: application/json".to_string(),
            "-H".to_string(),
            "Connect-Protocol-Version: 1".to_string(),
            "-H".to_string(),
            format!("x-codeium-csrf-token: {}", csrf),
            "-d".to_string(),
            "{}".to_string(),
            url,
        ];
        let Ok(res) = run_command_with_job(&curl_bin, &args, None, &[], None, Some(4000)) else {
            continue;
        };
        if res.timed_out || res.code != 0 || res.stdout.is_empty() {
            continue;
        }
        let Ok(body) = serde_json::from_str::<Value>(&res.stdout_str()) else {
            continue;
        };
        let plugins = body
            .get("plugins")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        for item in plugins {
            let meta = item.get("plugin").and_then(|v| v.as_object());
            let name = item
                .get("name")
                .and_then(|v| v.as_str())
                .or_else(|| meta.and_then(|m| m.get("name")).and_then(|v| v.as_str()))
                .or_else(|| item.get("id").and_then(|v| v.as_str()))
                .unwrap_or("");
            if name == plugin_name {
                let plugin_path = item
                    .get("path")
                    .and_then(|v| v.as_str())
                    .or_else(|| meta.and_then(|m| m.get("path")).and_then(|v| v.as_str()))
                    .unwrap_or("");
                let mut rule_triggers = Map::new();
                if let Some(rules_arr) = item.get("rules").and_then(|v| v.as_array()) {
                    for r in rules_arr {
                        if let Some(robj) = r.as_object() {
                            let ps = robj
                                .get("scope")
                                .and_then(|v| v.get("projectScope"))
                                .and_then(|v| v.as_object());
                            let raw_path = ps
                                .and_then(|p| p.get("filePath"))
                                .or_else(|| robj.get("absolutePath"))
                                .or_else(|| robj.get("memoryId"))
                                .or_else(|| robj.get("path"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let rname = robj
                                .get("name")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string())
                                .filter(|s| !s.is_empty())
                                .or_else(|| {
                                    Path::new(raw_path)
                                        .file_name()
                                        .and_then(|s| s.to_str())
                                        .map(|s| s.to_string())
                                })
                                .unwrap_or_else(|| "?".to_string());
                            let trig = ps
                                .and_then(|p| p.get("trigger"))
                                .or_else(|| robj.get("trigger"))
                                .cloned()
                                .unwrap_or_else(|| Value::String("unknown".to_string()));
                            rule_triggers.insert(rname, trig);
                        }
                    }
                }
                let has_hooks = item.get("hooksJson").is_some()
                    || item.get("hooks").is_some()
                    || (!plugin_path.is_empty()
                        && Path::new(plugin_path).join("hooks.json").is_file());
                return Some(json!({
                    "connected": true,
                    "ingested": true,
                    "enabled": !item.get("disabled").and_then(|v| v.as_bool()).unwrap_or(false),
                    "skills_count": item.get("skills").and_then(|v| v.as_array()).map_or(0, |a| a.len()),
                    "agents_count": item.get("agents").and_then(|v| v.as_array()).map_or(0, |a| a.len()),
                    "rules_count": item.get("rules").and_then(|v| v.as_array()).map_or(0, |a| a.len()),
                    "rule_triggers": rule_triggers,
                    "has_hooks": has_hooks,
                    "errors": item.get("errors").cloned().unwrap_or_else(|| json!([])),
                }));
            }
        }
        return Some(json!({
            "connected": true,
            "ingested": false,
        }));
    }
    None
}

pub fn probe_language_server(plugin_name: &str) -> Value {
    let addr = env::var("ANTIGRAVITY_LS_ADDRESS").unwrap_or_default();
    let csrf = env::var("ANTIGRAVITY_CSRF_TOKEN").unwrap_or_default();
    let processes = scan_language_server_processes();
    let process_running = !processes.is_empty();

    if !addr.trim().is_empty() && !csrf.trim().is_empty() {
        if let Some(mut rpc_info) = query_ls_rpc_via_curl(addr.trim(), csrf.trim(), plugin_name) {
            if let Some(obj) = rpc_info.as_object_mut() {
                obj.insert("process_running".to_string(), json!(process_running));
                obj.insert("processes".to_string(), json!(processes));
            }
            return rpc_info;
        }
        return json!({
            "connected": false,
            "reason": "rpc_unreachable",
            "env_configured": true,
            "process_running": process_running,
            "processes": processes,
        });
    }

    json!({
        "connected": false,
        "reason": "outside_live_ls_env",
        "env_configured": false,
        "process_running": process_running,
        "processes": processes,
    })
}

fn list_skill_names(bundle_dir: &Path) -> Vec<String> {
    let skills_dir = bundle_dir.join("skills");
    let Ok(entries) = fs::read_dir(skills_dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter(|e| e.path().is_dir() && e.path().join("SKILL.md").is_file())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    names.sort();
    names
}

fn list_md_names(dir: &Path, strip_ext: bool) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .and_then(|s| s.to_str())
                    .map_or(false, |s| s.eq_ignore_ascii_case("md"))
        })
        .filter_map(|p| {
            let target = if strip_ext {
                p.file_stem()
            } else {
                p.file_name()
            };
            target.and_then(|s| s.to_str()).map(|s| s.to_string())
        })
        .collect();
    names.sort();
    names
}

fn collect_hook_commands(val: &Value, out: &mut Vec<String>) {
    match val {
        Value::Array(arr) => {
            for item in arr {
                collect_hook_commands(item, out);
            }
        }
        Value::Object(map) => {
            if let Some(cmd) = map.get("command").and_then(|v| v.as_str()) {
                out.push(cmd.to_string());
            }
            if let Some(inner) = map.get("hooks") {
                collect_hook_commands(inner, out);
            }
        }
        _ => {}
    }
}

fn inspect_hooks_json(bundle_dir: &Path, hooks_val: Option<&Value>) -> (Value, bool) {
    let Some(Value::Object(root)) = hooks_val else {
        return (
            json!({
                "present": false,
                "group": Value::Null,
                "events_present": [],
                "missing_events": HOOK_EVENTS,
                "guards_matcher_ok": false,
                "commands_ok": false,
                "missing_targets": [],
            }),
            false,
        );
    };

    let (group_name, group_obj) = if let Some(Value::Object(m)) = root.get("carbon-stack") {
        (Some("carbon-stack"), Some(m))
    } else if let Some(Value::Object(m)) = root.get("safety-and-quality-guards") {
        (Some("safety-and-quality-guards"), Some(m))
    } else {
        (None, None)
    };

    let mut events_present: Vec<String> = Vec::new();
    let mut missing_events: Vec<String> = Vec::new();
    let mut commands: Vec<String> = Vec::new();
    let mut safety_matcher = String::new();

    if let Some(grp) = group_obj {
        for &ev in HOOK_EVENTS {
            if let Some(ev_val) = grp.get(ev) {
                let non_empty = ev_val.as_array().map_or(false, |a| !a.is_empty());
                if non_empty {
                    events_present.push(ev.to_string());
                    collect_hook_commands(ev_val, &mut commands);
                } else {
                    missing_events.push(ev.to_string());
                }
            } else {
                missing_events.push(ev.to_string());
            }
        }
        if let Some(pre_arr) = grp.get("PreToolUse").and_then(|v| v.as_array()) {
            if let Some(first_obj) = pre_arr.first().and_then(|v| v.as_object()) {
                safety_matcher = first_obj
                    .get("matcher")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
            }
        }
    } else {
        for &ev in HOOK_EVENTS {
            missing_events.push(ev.to_string());
        }
    }

    let guards_matcher_ok = REQUIRED_GUARD_TOOLS
        .iter()
        .all(|t| safety_matcher.contains(t));

    let mut missing_targets: Vec<String> = Vec::new();
    for cmd in &commands {
        for mat in hook_target_re().find_iter(cmd) {
            let rel = mat.as_str().replace('\\', "/");
            let candidate = bundle_dir.join(&rel);
            let exists = if rel.to_ascii_lowercase().starts_with("bin/carbon-stack") {
                candidate.is_file()
                    || bundle_dir.join("bin").join("carbon-stack.exe").is_file()
                    || bundle_dir.join("bin").join("carbon-stack").is_file()
            } else {
                candidate.is_file()
            };
            if !exists && !missing_targets.contains(&rel) {
                missing_targets.push(rel);
            }
        }
    }

    let info = json!({
        "present": true,
        "group": group_name,
        "events_present": events_present,
        "missing_events": missing_events,
        "guards_matcher_ok": guards_matcher_ok,
        "commands_checked": commands.len(),
        "commands_ok": !commands.is_empty() && missing_targets.is_empty(),
        "missing_targets": missing_targets,
    });
    (info, guards_matcher_ok)
}

fn detect_external_nlm_bridge() -> Value {
    let cli = code_search::which_in_path("nlm-memory")
        .or_else(|| code_search::which_in_path("nlm-memory.cmd"));
    let codex_bridge = rio::home_dir().join(".codex").join("notebooklm-sync");
    let bridge_exists = codex_bridge.exists();
    json!({
        "nlm_memory_cli": cli,
        "codex_nlm_bridge_exists": bridge_exists,
        "available": cli.is_some() || bridge_exists,
    })
}

fn memory_stats(cwd: &str) -> Value {
    let pkey = rio::project_key(cwd, &[], "", "");
    let db_file = rio::state_dir().join("memory").join("memory.db");
    let db_path_str = db_file.to_string_lossy().into_owned();
    let bridge = detect_external_nlm_bridge();

    if !db_file.is_file() {
        return json!({
            "db_path": db_path_str,
            "project_key": pkey,
            "total_entries": 0,
            "active_entries": 0,
            "project_active_entries": 0,
            "external_nlm_bridge": bridge,
        });
    }

    match SqliteConn::open(&db_file, SQLITE_OPEN_READONLY) {
        Ok(conn) => {
            let total = conn
                .query("SELECT COUNT(*) FROM memories", &[])
                .ok()
                .and_then(|rows| rows.first().and_then(|r| r.first()).map(|v| v.as_i64()))
                .unwrap_or(0);
            let active = conn
                .query("SELECT COUNT(*) FROM memories WHERE status = 'ACTIVE'", &[])
                .ok()
                .and_then(|rows| rows.first().and_then(|r| r.first()).map(|v| v.as_i64()))
                .unwrap_or(0);
            let proj_active = conn
                .query(
                    "SELECT COUNT(*) FROM memories WHERE status = 'ACTIVE' AND project_key = ?",
                    &[SqlParam::Text(pkey.clone())],
                )
                .ok()
                .and_then(|rows| rows.first().and_then(|r| r.first()).map(|v| v.as_i64()))
                .unwrap_or(0);
            json!({
                "db_path": db_path_str,
                "project_key": pkey,
                "total_entries": total,
                "active_entries": active,
                "project_active_entries": proj_active,
                "external_nlm_bridge": bridge,
            })
        }
        Err(err) => json!({
            "db_path": db_path_str,
            "project_key": pkey,
            "total_entries": 0,
            "active_entries": 0,
            "project_active_entries": 0,
            "read_only_fallback": true,
            "error": err,
            "external_nlm_bridge": bridge,
        }),
    }
}

fn collect_swarm_cache_stats() -> Value {
    let brain_root = swarm_cache::resolve_brain_root("");
    let mut sessions_count: usize = 0;
    if let Ok(entries) = fs::read_dir(&brain_root) {
        for ent in entries.flatten() {
            let p = ent.path();
            if p.is_dir()
                && p.join(".system_generated")
                    .join("swarm")
                    .join("members.json")
                    .is_file()
            {
                sessions_count += 1;
            }
        }
    }
    json!({
        "brain_root": rio::normalize_path(&brain_root.to_string_lossy()),
        "brain_root_exists": brain_root.is_dir(),
        "prompt_cache_ttl_seconds": cwg_common::SWARM_CACHE_SAFE_TTL_SECONDS,
        "swarm_sessions_count": sessions_count,
    })
}

fn collect_continuity_status(eff_cwd: &str) -> Value {
    let cp = continuity_hook::resolve_checkpoint_file(eff_cwd, &[], None, "");
    let ho = continuity_hook::load_handoff(eff_cwd, &[], None, "");
    let handoff_status = ho
        .as_ref()
        .and_then(|v| v.get("status"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    json!({
        "checkpoint_exists": cp.is_some(),
        "checkpoint_path": cp.map(|p| rio::normalize_path(&p.to_string_lossy())),
        "handoff_exists": ho.is_some(),
        "handoff_status": handoff_status,
    })
}

pub fn collect_doctor_report(cwd: &str, plugin_dir: Option<&str>, compact: bool) -> Value {
    let installed_dir = rio::home_dir()
        .join(".gemini")
        .join("config")
        .join("plugins")
        .join("gemini-carbon-stack");

    let bundle_dir = match plugin_dir {
        Some(raw) if !raw.trim().is_empty() => PathBuf::from(raw.trim()),
        _ => {
            if installed_dir.is_dir() {
                installed_dir.clone()
            } else {
                rio::plugin_root()
            }
        }
    };

    let plugin_json = rio::read_json(&bundle_dir.join("plugin.json"));
    let hooks_json_val = rio::read_json(&bundle_dir.join("hooks.json"));
    let skills = list_skill_names(&bundle_dir);
    let agents = list_md_names(&bundle_dir.join("agents"), true);
    let rules = list_md_names(&bundle_dir.join("rules"), false);

    let plugin_manifest = match plugin_json.as_ref().and_then(|v| v.as_object()) {
        Some(obj) => json!({
            "present": true,
            "name": obj.get("name").cloned().unwrap_or(Value::Null),
            "display_name": obj.get("displayName").cloned().unwrap_or(Value::Null),
            "version": obj.get("version").cloned().unwrap_or(Value::Null),
        }),
        None => json!({
            "present": false,
            "name": Value::Null,
            "display_name": Value::Null,
            "version": Value::Null,
        }),
    };

    let (hooks_info, swarm_guards_ok) = inspect_hooks_json(&bundle_dir, hooks_json_val.as_ref());

    let agy_bin = find_agy_cli();
    let mut agy_validate_ok: Option<bool> = None;
    let mut agy_validate_msg = String::new();
    if let Some(ref agy) = agy_bin {
        if bundle_dir.is_dir() {
            let args = vec![
                "plugin".to_string(),
                "validate".to_string(),
                bundle_dir.to_string_lossy().into_owned(),
            ];
            if let Ok(res) = run_command_with_job(agy, &args, None, &[], None, Some(10_000)) {
                agy_validate_ok = Some(!res.timed_out && res.code == 0);
                let combined = format!("{}\n{}", res.stdout_str(), res.stderr_str());
                agy_validate_msg = combined.trim().to_string();
            }
        }
    }

    let err_log = rio::state_dir().join("logs").join("hook-errors.jsonl");
    let recent_errors = rio::read_jsonl(&err_log, None).len();

    let mcp_cfg_path = rio::home_dir()
        .join(".gemini")
        .join("config")
        .join("mcp_config.json");
    let mcp_cfg = rio::read_json(&mcp_cfg_path);
    let mcp_servers = mcp_cfg
        .as_ref()
        .and_then(|v| v.get("mcpServers"))
        .and_then(|v| v.as_object());
    let mut mcp_server_names: Vec<String> = mcp_servers
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    mcp_server_names.sort();
    let serena_cfg = mcp_servers.and_then(|m| m.get("serena")).and_then(|v| v.as_object());
    let serena_lazy_filtered = serena_cfg.map_or(false, |s| {
        s.get("eager").and_then(|v| v.as_bool()) == Some(false)
            && s.get("enabledTools")
                .and_then(|v| v.as_array())
                .map_or(false, |a| !a.is_empty())
    });

    let cli_settings_path = rio::home_dir()
        .join(".gemini")
        .join("antigravity-cli")
        .join("settings.json");
    let cli_settings = rio::read_json(&cli_settings_path);
    let cli_use_g1_credits_safe = cli_settings
        .as_ref()
        .and_then(|v| v.get("useG1Credits"))
        .and_then(|v| v.as_bool())
        == Some(false);

    let token_opt_info = json!({
        "tokenade_cli": tokenade_hook::find_tokenade_bin(),
        "tokenade_auto_wrap": tokenade_hook::is_auto_wrap_enabled(),
        "ripgrep_cli": code_search::find_rg(),
        "uvx_cli": code_search::which_in_path("uvx").or_else(|| code_search::which_in_path("uvx.exe")),
        "mcp_servers": mcp_server_names,
        "serena_lazy_filtered": serena_lazy_filtered,
        "cli_use_g1_credits_safe": cli_use_g1_credits_safe,
    });

    let eff_cwd = if cwd.trim().is_empty() {
        env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default()
    } else {
        cwd.trim().to_string()
    };

    let mem = memory_stats(&eff_cwd);
    let codex_info = json!({
        "binary": codex_lane::find_codex_binary(),
        "breaker": codex_lane::breaker_status(),
    });
    let active_chips = chip_hooks::load_all_cards()
        .into_iter()
        .filter(|c| c.get("status").and_then(|v| v.as_str()) != Some("accepted"))
        .count();

    let handler_sess = gate_inbox::get_handler_session();
    let inbox_summary = gate_inbox::unresolved_summary(&handler_sess);
    let inbox_text = inbox_summary
        .get("summary")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let ls_info = probe_language_server("gemini-carbon-stack");
    let rust_bin = find_rust_binary();

    let swarm_ctl_ok =
        bundle_dir.join("tools").join("swarm_ctl.py").is_file() || rust_bin.is_some();
    let swarm_skill_ok = skills.iter().any(|s| s == "swarm-orchestration");

    let git_check_dir = PathBuf::from(&eff_cwd);
    let mut gitignore_file = git_check_dir.join(".gitignore");
    if !gitignore_file.is_file() {
        if let Some(parent) = bundle_dir.parent() {
            let parent_gi = parent.join(".gitignore");
            if parent_gi.is_file() {
                gitignore_file = parent_gi;
            }
        }
    }
    let gitignore_has_swarm = if gitignore_file.is_file() {
        fs::read_to_string(&gitignore_file)
            .map(|txt| txt.contains(".swarm/"))
            .unwrap_or(false)
    } else {
        false
    };

    let swarm_v2_info = json!({
        "swarm_ctl": swarm_ctl_ok,
        "swarm_orchestration_skill": swarm_skill_ok,
        "guards_matcher_ok": swarm_guards_ok,
        "fast_path_limits": {
            "max_files": cwg_common::FAST_PATH_MAX_FILES,
            "max_lines": cwg_common::FAST_PATH_MAX_LINES,
        },
        "cursor_threshold": cwg_common::BOARD_CURSOR_THRESHOLD,
        "stall_timeout_sec": cwg_common::swarm_stall_timeout_sec(),
        "gitignore_has_swarm": gitignore_has_swarm,
    });

    let hook_groups_count = hooks_json_val
        .as_ref()
        .and_then(|v| v.as_object())
        .map_or(0, |m| m.len());

    let ok = plugin_json.as_ref().map_or(false, |v| v.is_object())
        && hooks_json_val.as_ref().map_or(false, |v| v.is_object())
        && skills.len() >= 10
        && agents.len() >= 4
        && !rules.is_empty()
        && swarm_ctl_ok
        && swarm_skill_ok
        && swarm_guards_ok
        && agy_validate_ok != Some(false);

    let mut report = Map::new();
    report.insert("ok".to_string(), json!(ok));
    report.insert(
        "installed_in_global_config".to_string(),
        json!(installed_dir.is_dir()),
    );
    report.insert(
        "bundle_dir".to_string(),
        json!(rio::normalize_path(&bundle_dir.to_string_lossy())),
    );
    report.insert(
        "stack_home".to_string(),
        json!(rio::normalize_path(&rio::stack_home().to_string_lossy())),
    );
    report.insert(
        "rust_engine".to_string(),
        json!({
            "available": rust_bin.is_some(),
            "binary": rust_bin,
            "version": env!("CARGO_PKG_VERSION"),
        }),
    );
    report.insert("agy_cli".to_string(), json!(agy_bin));
    report.insert(
        "agy_plugin_validate".to_string(),
        json!({
            "ok": agy_validate_ok,
            "output": agy_validate_msg,
        }),
    );
    report.insert("language_server".to_string(), ls_info);
    report.insert("plugin_manifest".to_string(), plugin_manifest);
    report.insert("hooks_json".to_string(), hooks_info);
    report.insert(
        "counts".to_string(),
        json!({
            "hook_groups": hook_groups_count,
            "skills": skills.len(),
            "agents": agents.len(),
            "rules": rules.len(),
        }),
    );
    report.insert("rules".to_string(), json!(rules));
    report.insert("swarm_v2".to_string(), swarm_v2_info);
    report.insert("codex_lane".to_string(), codex_info);
    report.insert("continuity".to_string(), collect_continuity_status(&eff_cwd));
    report.insert("swarm_cache".to_string(), collect_swarm_cache_stats());
    report.insert("token_optimization".to_string(), token_opt_info);
    report.insert("memory".to_string(), mem);
    report.insert("active_chips".to_string(), json!(active_chips));
    report.insert(
        "gate_anomaly_handler".to_string(),
        if handler_sess.is_empty() {
            Value::Null
        } else {
            Value::String(handler_sess)
        },
    );
    report.insert(
        "gate_inbox".to_string(),
        Value::String(if inbox_text.is_empty() {
            "clean".to_string()
        } else {
            inbox_text.to_string()
        }),
    );
    report.insert("gate_inbox_summary".to_string(), inbox_summary);
    report.insert("logged_hook_errors".to_string(), json!(recent_errors));

    if !compact || !ok {
        report.insert("skills".to_string(), json!(skills));
        report.insert("agents".to_string(), json!(agents));
        let mut hydrogen_levels = BTreeMap::new();
        hydrogen_levels.insert("low", cwg_common::HYDROGEN_LOW_MODEL);
        hydrogen_levels.insert("medium", cwg_common::HYDROGEN_MEDIUM_MODEL);
        hydrogen_levels.insert("high", cwg_common::HYDROGEN_HIGH_MODEL);
        hydrogen_levels.insert("xhigh", cwg_common::HYDROGEN_XHIGH_MODEL);
        report.insert(
            "model_routing".to_string(),
            json!({
                "pipeline_order": "unittest -> primary review -> simplify once -> batch kill -> --closure",
                "simplify_lenses": {
                    "lenses": cwg_common::SIMPLIFY_LENSES,
                    "standard_mode": "opt_in single_combined (simplify-reviewer) via .agents/carbon-gate.json",
                    "high_xhigh_mode": "fast_path ALL (<=2 files & <=30 lines) else three_parallel_lenses (reuse, quality, efficiency)",
                    "primary_model": cwg_common::SONNET_HIGH_MODEL,
                    "fallback_model": cwg_common::SIMPLIFY_FALLBACK_MODEL,
                    "prompt_cache_ttl_seconds": cwg_common::SWARM_CACHE_SAFE_TTL_SECONDS,
                },
                "external_review": "codex-cli (primary logic review + final --closure)",
                "internal_review": {
                    "primary_model": cwg_common::OPUS_HIGH_MODEL,
                    "escalation_model": cwg_common::CARBON_HIGH_MODEL,
                },
                "auxiliary_hydrogen": {
                    "replaces": "gemini-flash (disabled)",
                    "models_by_complexity": hydrogen_levels,
                    "roles": ["browser", "translator", "scout_swarm", "disjoint_builder", "simplify_fallback"],
                },
            }),
        );
    }

    Value::Object(report)
}

pub fn run_diagnostics(cwd: &str, compact: bool) -> Value {
    collect_doctor_report(cwd, None, compact)
}

pub fn format_doctor_text(report: &Value) -> String {
    let ok = report.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    let bundle = report
        .get("bundle_dir")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let stack_home = report
        .get("stack_home")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let counts = report.get("counts");
    let skills = counts
        .and_then(|c| c.get("skills"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let agents = counts
        .and_then(|c| c.get("agents"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let rules = counts
        .and_then(|c| c.get("rules"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let rust_bin = report
        .get("rust_engine")
        .and_then(|r| r.get("binary"))
        .and_then(|v| v.as_str())
        .unwrap_or("none");
    let rg_cli = report
        .get("token_optimization")
        .and_then(|t| t.get("ripgrep_cli"))
        .and_then(|v| v.as_str())
        .unwrap_or("none");
    let codex_bin = report
        .get("codex_lane")
        .and_then(|c| c.get("binary"))
        .and_then(|v| v.as_str())
        .unwrap_or("none");
    let gate_inbox = report
        .get("gate_inbox")
        .and_then(|v| v.as_str())
        .unwrap_or("clean");
    let hook_errs = report
        .get("logged_hook_errors")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    format!(
        "status: {}\nbundle_dir: {}\nstack_home: {}\nrust_engine: {}\nripgrep: {}\ncodex: {}\ncounts: skills={}, agents={}, rules={}\ngate_inbox: {}\nlogged_hook_errors: {}\n",
        if ok { "OK" } else { "DEGRADED" },
        bundle,
        stack_home,
        rust_bin,
        rg_cli,
        codex_bin,
        skills,
        agents,
        rules,
        gate_inbox,
        hook_errs
    )
}

fn eprintln_line(msg: &str) {
    let mut err = std::io::stderr().lock();
    let _ = writeln!(err, "{}", msg);
}

fn take_flag_value(args: &[String], idx: &mut usize, prefix: &str) -> Result<Option<String>, String> {
    let tok = &args[*idx];
    if tok == prefix {
        if *idx + 1 >= args.len() {
            return Err(format!("missing value for {}", prefix));
        }
        *idx += 1;
        return Ok(Some(args[*idx].clone()));
    }
    let eq_prefix = format!("{}=", prefix);
    if let Some(val) = tok.strip_prefix(&eq_prefix) {
        return Ok(Some(val.to_string()));
    }
    Ok(None)
}

pub fn run_cli(args: &[String]) -> i32 {
    let mut cwd = String::new();
    let mut plugin_dir: Option<String> = None;
    let mut compact = false;
    let mut pretty = false;
    let mut text_mode = false;
    let mut i = 0;

    while i < args.len() {
        let tok = &args[i];
        if tok == "-h" || tok == "--help" {
            eprintln_line(
                "usage: stack_doctor [--cwd DIR] [--plugin-dir DIR] [--compact] [--pretty] [--text] [--json]",
            );
            return 0;
        }
        match take_flag_value(args, &mut i, "--cwd") {
            Ok(Some(v)) => {
                cwd = v;
                i += 1;
                continue;
            }
            Ok(None) => {}
            Err(e) => {
                eprintln_line(&format!("stack_doctor: {}", e));
                return 2;
            }
        }
        match take_flag_value(args, &mut i, "--plugin-dir") {
            Ok(Some(v)) => {
                plugin_dir = Some(v);
                i += 1;
                continue;
            }
            Ok(None) => {}
            Err(e) => {
                eprintln_line(&format!("stack_doctor: {}", e));
                return 2;
            }
        }
        match tok.as_str() {
            "--compact" => compact = true,
            "--pretty" => pretty = true,
            "--text" => text_mode = true,
            "--json" => text_mode = false,
            other => {
                eprintln_line(&format!("stack_doctor: unknown argument '{}'", other));
                return 2;
            }
        }
        i += 1;
    }

    let report = collect_doctor_report(&cwd, plugin_dir.as_deref(), compact);
    if text_mode {
        let txt = format_doctor_text(&report);
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(txt.as_bytes());
        let _ = out.flush();
    } else {
        rio::print_cli_json(&report, pretty);
    }
    if report.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::win32_sqlite::TEST_ENV_LOCK;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(prefix: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir = env::temp_dir().join(format!("{}-{}-{}", prefix, std::process::id(), nanos));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn test_all_regexes_compile() {
        assert!(hook_target_re().is_match("bin\\carbon-stack.exe hook --event Stop"));
        assert!(hook_target_re().is_match("python -X utf8 hooks/cwg_stop.py"));
        assert!(process_ls_re().is_match("language_server_windows_x64.exe"));
    }

    #[test]
    fn test_collect_doctor_report_with_mock_bundle() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempDir::new("sd-bundle");
        let stack_home_dir = tmp.0.join("stack_home");
        let bundle = tmp.0.join("plugin");
        let ws = tmp.0.join("workspace");
        fs::create_dir_all(bundle.join("bin")).unwrap();
        fs::create_dir_all(bundle.join("tools")).unwrap();
        fs::create_dir_all(bundle.join("rules")).unwrap();
        fs::create_dir_all(bundle.join("agents")).unwrap();
        fs::create_dir_all(&ws).unwrap();

        fs::write(
            bundle.join("plugin.json"),
            r#"{"name":"gemini-carbon-stack","displayName":"Gemini Carbon","version":"1.0.0"}"#,
        )
        .unwrap();
        fs::write(bundle.join("bin").join("carbon-stack.exe"), b"MZ").unwrap();
        fs::write(bundle.join("tools").join("swarm_ctl.py"), "# ctl\n").unwrap();
        fs::write(bundle.join("rules").join("AGENTS.md"), "# Rules\n").unwrap();
        for i in 0..4 {
            fs::write(bundle.join("agents").join(format!("agent-{}.md", i)), "# A\n").unwrap();
        }
        let mut skill_names = vec!["swarm-orchestration".to_string()];
        for i in 0..9 {
            skill_names.push(format!("skill-{}", i));
        }
        for s in &skill_names {
            let sdir = bundle.join("skills").join(s);
            fs::create_dir_all(&sdir).unwrap();
            fs::write(sdir.join("SKILL.md"), "# Skill\n").unwrap();
        }
        fs::write(
            bundle.join("hooks.json"),
            r#"{
              "carbon-stack": {
                "SessionStart": [{"type":"command","command":"bin\\carbon-stack.exe hook --event SessionStart"}],
                "PreInvocation": [{"type":"command","command":"bin\\carbon-stack.exe hook --event PreInvocation"}],
                "PreToolUse": [{"matcher":"read_board|edit_file|write_file|swarm_wait","hooks":[{"type":"command","command":"bin\\carbon-stack.exe hook --event PreToolUse"}]}],
                "PostToolUse": [{"type":"command","command":"bin\\carbon-stack.exe hook --event PostToolUse"}],
                "Stop": [{"type":"command","command":"bin\\carbon-stack.exe hook --event Stop"}]
              }
            }"#,
        )
        .unwrap();
        fs::write(ws.join(".gitignore"), ".swarm/\n").unwrap();

        let prev_home = env::var_os("CARBON_STACK_HOME");
        let prev_bin = env::var_os("CARBON_STACK_BIN");
        env::set_var("CARBON_STACK_HOME", &stack_home_dir);
        env::set_var(
            "CARBON_STACK_BIN",
            bundle.join("bin").join("carbon-stack.exe"),
        );

        let report = collect_doctor_report(
            &ws.to_string_lossy(),
            Some(&bundle.to_string_lossy()),
            false,
        );
        assert_eq!(report["plugin_manifest"]["present"], true);
        assert_eq!(report["hooks_json"]["present"], true);
        assert_eq!(report["hooks_json"]["commands_ok"], true);
        assert_eq!(report["hooks_json"]["guards_matcher_ok"], true);
        assert_eq!(report["counts"]["skills"], 10);
        assert_eq!(report["counts"]["agents"], 4);
        assert_eq!(report["counts"]["rules"], 1);
        assert_eq!(report["swarm_v2"]["gitignore_has_swarm"], true);
        assert_eq!(report["rust_engine"]["available"], true);
        assert!(report["model_routing"].is_object());

        let compact = collect_doctor_report(
            &ws.to_string_lossy(),
            Some(&bundle.to_string_lossy()),
            true,
        );
        if compact["ok"] == true {
            assert!(compact.get("skills").is_none());
            assert!(compact.get("model_routing").is_none());
        }

        let txt = format_doctor_text(&report);
        assert!(txt.contains("bundle_dir:"));
        assert!(txt.contains("rust_engine:"));

        match prev_home {
            Some(v) => env::set_var("CARBON_STACK_HOME", v),
            None => env::remove_var("CARBON_STACK_HOME"),
        }
        match prev_bin {
            Some(v) => env::set_var("CARBON_STACK_BIN", v),
            None => env::remove_var("CARBON_STACK_BIN"),
        }
    }
}
