use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant, UNIX_EPOCH};

use crate::win32_sqlite::{now_sec, run_command_with_job};

pub const WORKER_ENV_KEYS: &[&str] = &[
    "SWARM_WORKER_NAME",
    "WORKER_NAME",
    "AGY_SWARM_WORKER",
    "AGY_WORKER_NAME",
];

pub const COORDINATOR_ROLE_NAMES: &[&str] = &["coordinator", "main", "primary", "root", "lead"];

pub const NON_ENFORCEABLE_STOP_REASONS: &[&str] = &[
    "ERROR",
    "USER_CANCELED",
    "MAX_INVOCATIONS",
    "MAX_FORCED_INVOCATIONS",
    "MAX_TOKEN_BUDGET_EXCEEDED",
    "TERMINAL_CUSTOM_HOOK",
];

static TMP_SEQ: AtomicU64 = AtomicU64::new(1);

pub fn subagent_msg_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?s)\[Message\]\s+timestamp=(?P<ts>\S+)\s+sender=(?P<sender>[A-Za-z0-9._-]{4,80})(?:\s+priority=\S+)?\s+content=(?P<body>.*)",
        )
        .expect("subagent_msg_re")
    })
}

fn swarm_board_wake_body_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\A\[swarm\]\s+new board message\s+#\d+\s*(?:</SYSTEM_MESSAGE>)?\s*\z")
            .expect("swarm_board_wake_body_re")
    })
}

fn swarm_wake_seq_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:\[swarm\]\s+new board message|recorded on the board as)\s+#(\d+)")
            .expect("swarm_wake_seq_re")
    })
}

fn swarm_role_member_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\A(?:narrator|monitor)(?:-\d+)?\z").expect("swarm_role_member_re")
    })
}

fn bg_task_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // INVARIANT: Anchor strictly to Antigravity's host preamble before any synchronous exit/stdout banner so child process stdout cannot spoof a background task ID.
        Regex::new(
            r"(?i)\A(?:\s*A pre-tool hook[^\r\n]*\r?\n|\s*Created At:[^\r\n]*\r?\n|\s*)*(?:Tool is )?running as a background task with task id:\s*(\S+)",
        )
        .expect("bg_task_id_re")
    })
}

fn safe_key_clean_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[^A-Za-z0-9._-]+").expect("safe_key_clean_re"))
}

fn safe_key_alnum_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[^A-Za-z0-9]+").expect("safe_key_alnum_re"))
}

fn compact_json_scalar_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\A(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)\z")
            .expect("compact_json_scalar_re")
    })
}

fn swarm_group_suffix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"-\d+\z").expect("swarm_group_suffix_re"))
}

pub(crate) fn leading_null_pipe_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\A\s*\$null\s*\|\s*").expect("leading_null_pipe_re"))
}

fn tokenade_wrap_seg_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // INVARIANT: Match `\r\n` atomically in `lead` and consume only horizontal `[ \t]*` so CRLF line breaks before a wrapped command are preserved instead of collapsing to bare `\r`.
        Regex::new(
            r#"(?i)(?P<lead>\A|\r\n|[;\r\n|&])[ \t]*(?:\$null\s*\|\s*)?(?:&\s*)?(?:'(?:''|[^'\r\n])*tokenade(?:\.cmd|\.exe)?'|"[^"`$\r\n]*tokenade(?:\.cmd|\.exe)?"|[^\s|;&"'`$()\r\n]*tokenade(?:\.cmd|\.exe)?)\s+(?:wrap|exec-compact|raw|bypass|noproxy|shellwrap)\b(?:\s+--shell\s+[A-Za-z0-9_.-]+)?\s+(?P<inner>'(?:''|[^'])*'|"(?:`[\s\S]|""|[^"`])*"|[^|;&"'\r\n]+?)(?P<ws_tail>\s*)(?:[;\r\n|&]|\z)"#,
        )
        .expect("tokenade_wrap_seg_re")
    })
}

pub fn resolve_abs_path(p: &Path) -> PathBuf {
    let base = if p.is_absolute() {
        p.to_path_buf()
    } else {
        let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        cwd.join(p)
    };
    let mut out = PathBuf::new();
    let mut has_root = false;
    for comp in base.components() {
        match comp {
            Component::Prefix(pre) => out.push(pre.as_os_str()),
            Component::RootDir => {
                out.push(Component::RootDir.as_os_str());
                has_root = true;
            }
            Component::CurDir => {}
            Component::ParentDir => {
                let can_pop = matches!(out.components().next_back(), Some(Component::Normal(_)));
                if can_pop {
                    out.pop();
                } else if !has_root {
                    out.push(Component::ParentDir.as_os_str());
                }
            }
            Component::Normal(seg) => out.push(seg),
        }
    }
    out
}

fn expand_tilde(raw: &str) -> PathBuf {
    if raw == "~" {
        return home_dir();
    }
    if let Some(rest) = raw.strip_prefix("~/").or_else(|| raw.strip_prefix("~\\")) {
        return home_dir().join(rest);
    }
    PathBuf::from(raw)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn val_to_str(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

pub fn val_to_i64(v: Option<&Value>) -> i64 {
    match v {
        Some(Value::Number(n)) => n
            .as_i64()
            .or_else(|| n.as_u64().map(|u| u.min(i64::MAX as u64) as i64))
            .or_else(|| n.as_f64().map(|f| f as i64))
            .unwrap_or(0),
        Some(Value::String(s)) => s.trim().parse::<i64>().unwrap_or(0),
        Some(Value::Bool(b)) => i64::from(*b),
        _ => 0,
    }
}

pub fn val_to_f64(v: Option<&Value>) -> f64 {
    match v {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::String(s)) => s.trim().parse::<f64>().unwrap_or(0.0),
        Some(Value::Bool(b)) => {
            if *b {
                1.0
            } else {
                0.0
            }
        }
        _ => 0.0,
    }
}

pub fn json_truthy(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map_or(false, |x| x != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(m)) => !m.is_empty(),
        _ => false,
    }
}

pub fn truncate_chars(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

pub fn meta_mtime_sec(meta: &fs::Metadata) -> Option<f64> {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs_f64())
}

pub fn meta_mtime_ns(meta: &fs::Metadata) -> u128 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos())
}

pub fn file_mtime_sec(path: &Path) -> Option<f64> {
    fs::metadata(path).ok().and_then(|m| meta_mtime_sec(&m))
}

pub fn file_mtime_ns(path: &Path) -> Option<u128> {
    fs::metadata(path).ok().map(|m| meta_mtime_ns(&m)).filter(|&n| n > 0)
}

pub fn find_agy_cli() -> Option<String> {
    for name in ["agy.exe", "agy.cmd", "agy"] {
        if let Some(found) = which_in_path(name) {
            return Some(found);
        }
    }
    let default_win = home_dir()
        .join("AppData")
        .join("Local")
        .join("agy")
        .join("bin")
        .join("agy.exe");
    if default_win.is_file() {
        return Some(default_win.to_string_lossy().into_owned());
    }
    None
}

pub fn home_dir() -> PathBuf {
    if let Some(up) = env::var_os("USERPROFILE") {
        if !up.is_empty() {
            return PathBuf::from(up);
        }
    }
    if let Some(h) = env::var_os("HOME") {
        if !h.is_empty() {
            return PathBuf::from(h);
        }
    }
    if let (Some(hd), Some(hp)) = (env::var_os("HOMEDRIVE"), env::var_os("HOMEPATH")) {
        if !hd.is_empty() && !hp.is_empty() {
            let mut combined = PathBuf::from(hd);
            combined.push(hp);
            return combined;
        }
    }
    env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

pub fn stack_home() -> PathBuf {
    let p = match env::var("CARBON_STACK_HOME") {
        Ok(val) if !val.trim().is_empty() => PathBuf::from(val.trim()),
        _ => home_dir().join(".gemini").join("carbon-stack"),
    };
    let _ = fs::create_dir_all(&p);
    p
}

fn state_subdir(parts: &[&str]) -> PathBuf {
    let mut target = stack_home().join("state");
    for part in parts {
        target.push(part);
    }
    let _ = fs::create_dir_all(&target);
    target
}

pub fn state_dir() -> PathBuf {
    state_subdir(&[])
}

pub fn plugin_root() -> PathBuf {
    if let Ok(env_root) = env::var("PLUGIN_ROOT") {
        let trimmed = env_root.trim();
        if !trimmed.is_empty() {
            return resolve_abs_path(&expand_tilde(trimmed));
        }
    }
    if let Ok(exe) = env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            let is_bin = exe_dir
                .file_name()
                .and_then(|n| n.to_str())
                .map_or(false, |n| n.eq_ignore_ascii_case("bin"));
            if is_bin {
                if let Some(parent) = exe_dir.parent() {
                    return resolve_abs_path(parent);
                }
            }
        }
        for anc in exe.ancestors() {
            let cand = anc.join("plugin");
            if cand.join("plugin.json").is_file() || cand.is_dir() {
                return resolve_abs_path(&cand);
            }
        }
    }
    if let Ok(cwd) = env::current_dir() {
        for anc in cwd.ancestors() {
            let cand = anc.join("plugin");
            if cand.join("plugin.json").is_file() {
                return resolve_abs_path(&cand);
            }
        }
    }
    if let Some(manifest_dir) = option_env!("CARGO_MANIFEST_DIR") {
        if let Some(repo) = Path::new(manifest_dir).parent() {
            let cand = repo.join("plugin");
            if cand.is_dir() {
                return resolve_abs_path(&cand);
            }
        }
    }
    resolve_abs_path(
        &home_dir()
            .join(".gemini")
            .join("config")
            .join("plugins")
            .join("gemini-carbon-stack"),
    )
}

pub fn carbon_stack_bin_path() -> PathBuf {
    let bin_name = if cfg!(windows) {
        "carbon-stack.exe"
    } else {
        "carbon-stack"
    };
    plugin_root().join("bin").join(bin_name)
}

pub fn chat_bus_cli_path() -> PathBuf {
    let proot = plugin_root();
    let parent = proot.parent().unwrap_or_else(|| Path::new("."));
    parent.join("chat-bus").join("tools").join("chat_bus_cli.py")
}

pub fn parse_event_arg(args: &[String], default_ev: &str) -> String {
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--event" {
            if i + 1 < args.len() {
                let val = &args[i + 1];
                return if val.is_empty() {
                    default_ev.to_string()
                } else {
                    val.clone()
                };
            }
            return default_ev.to_string();
        }
        if let Some(val) = arg.strip_prefix("--event=") {
            return if val.is_empty() {
                default_ev.to_string()
            } else {
                val.to_string()
            };
        }
        i += 1;
    }
    default_ev.to_string()
}

pub fn normalize_path(path: &str) -> String {
    let trimmed = path.trim().trim_matches('"');
    if trimmed.is_empty() {
        return String::new();
    }
    let clean_prefix = if let Some(rest) = trimmed
        .strip_prefix(r"\\?\UNC\")
        .or_else(|| trimmed.strip_prefix("//?/UNC/"))
    {
        format!("//{}", rest)
    } else if let Some(rest) = trimmed
        .strip_prefix(r"\\?\")
        .or_else(|| trimmed.strip_prefix("//?/"))
    {
        rest.to_string()
    } else {
        trimmed.to_string()
    };
    let expanded = expand_tilde(&clean_prefix);
    let resolved = resolve_abs_path(&expanded);
    let mut norm = resolved.to_string_lossy().replace('\\', "/");
    #[cfg(windows)]
    {
        let bytes = norm.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
            let lower = (bytes[0] as char).to_ascii_lowercase();
            norm.replace_range(0..1, &lower.to_string());
        }
    }
    while norm.ends_with('/') && norm != "/" && norm != "//" {
        let bytes = norm.as_bytes();
        if bytes.len() == 3 && bytes[1] == b':' && bytes[2] == b'/' {
            break;
        }
        norm.pop();
    }
    norm
}

pub fn fold_path(path: &str) -> String {
    let norm = normalize_path(path);
    #[cfg(windows)]
    {
        norm.to_lowercase()
    }
    #[cfg(not(windows))]
    {
        norm
    }
}

pub fn quote_ps_literal(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('\'');
    for ch in raw.chars() {
        if matches!(ch, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
            out.push(ch);
        }
        out.push(ch);
    }
    out.push('\'');
    out
}

pub fn safe_key(value: &str, fallback: &str) -> String {
    let raw = value.trim();
    if raw.is_empty() {
        return fallback.to_string();
    }
    let cleaned = safe_key_clean_re().replace_all(raw, "_");
    if cleaned.len() <= 72
        && !cleaned
            .trim_matches(|c| c == '.' || c == '_' || c == '-')
            .is_empty()
    {
        return cleaned.into_owned();
    }
    let digest = sha256_hex(raw.as_bytes());
    let alnum = safe_key_alnum_re().replace_all(raw, "");
    let prefix: String = alnum.chars().take(24).collect();
    let prefix_eff = if prefix.is_empty() {
        "key".to_string()
    } else {
        prefix
    };
    format!("{}-{}", prefix_eff, &digest[..16])
}

pub fn is_plugin_runtime_dir(path: &str) -> bool {
    let norm = normalize_path(path);
    if norm.is_empty() {
        return false;
    }
    let folded = fold_path(&norm);
    let proot = fold_path(&plugin_root().to_string_lossy());
    if !proot.is_empty() && (folded == proot || folded.starts_with(&(proot + "/"))) {
        return true;
    }
    let low = format!("/{}", norm.to_lowercase().trim_start_matches('/'));
    if low.contains("/.gemini/config/plugins/") || low.ends_with("/.gemini/config/plugins") {
        return true;
    }
    #[cfg(windows)]
    if low.contains("/appdata/local/programs/antigravity") {
        return true;
    }
    false
}

pub fn project_key(
    cwd: &str,
    workspace_paths: &[String],
    known_git_root: &str,
    session: &str,
) -> String {
    let mut candidate = String::new();
    let mut has_explicit_ws = false;
    for wp in workspace_paths {
        let trimmed = wp.trim();
        if !trimmed.is_empty() {
            candidate = trimmed.to_string();
            has_explicit_ws = true;
            break;
        }
    }
    if candidate.is_empty() && !cwd.trim().is_empty() {
        let cand_str = cwd.trim();
        if !is_plugin_runtime_dir(cand_str) {
            candidate = cand_str.to_string();
        }
    }

    // INVARIANT: Workspace-less chats must never share the installed plugin directory's project_key.
    if candidate.is_empty() {
        let sid = safe_key(session, "ephemeral");
        let digest = sha256_hex(format!("ephemeral-session:{}", sid).as_bytes());
        let sid_prefix: String = sid.chars().take(24).collect();
        return format!("ephemeral-{}-{}", sid_prefix, &digest[..12]);
    }

    let mut git_root = if !known_git_root.trim().is_empty() {
        Some(known_git_root.trim().to_string())
    } else {
        git_toplevel(&candidate, false)
    };
    if let Some(ref gr) = git_root {
        if is_plugin_runtime_dir(gr) && !has_explicit_ws {
            git_root = None;
        }
    }
    let anchor = fold_path(git_root.as_deref().unwrap_or(&candidate));
    let base = anchor
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("root");
    let digest = sha256_hex(anchor.as_bytes());
    let base_key: String = safe_key(base, "default").chars().take(32).collect();
    format!("{}-{}", base_key, &digest[..12])
}

fn value_nonempty_string(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(true) => Some("true".to_string()),
        _ => None,
    }
}

pub fn session_key(payload: &Value) -> String {
    let Some(obj) = payload.as_object() else {
        return "unknown".to_string();
    };
    if let Some(conv) =
        value_nonempty_string(obj.get("conversationId")).or_else(|| value_nonempty_string(obj.get("session_id")))
    {
        return safe_key(&conv, "unknown");
    }
    if let Some(tp) =
        value_nonempty_string(obj.get("transcriptPath")).or_else(|| value_nonempty_string(obj.get("transcript_path")))
    {
        return safe_key(&tp, "unknown");
    }
    "unknown".to_string()
}

pub fn effective_cwd(payload: &Value) -> String {
    let current = || -> String {
        env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default()
    };
    let Some(obj) = payload.as_object() else {
        let cwd0 = current();
        return if is_plugin_runtime_dir(&cwd0) {
            String::new()
        } else {
            cwd0
        };
    };

    let mut valid_wps: Vec<String> = Vec::new();
    if let Some(wps) = obj.get("workspacePaths").and_then(|v| v.as_array()) {
        for wp in wps {
            if let Some(s) = wp.as_str() {
                if !s.trim().is_empty() && Path::new(s).is_dir() {
                    valid_wps.push(resolve_abs_path(Path::new(s)).to_string_lossy().into_owned());
                }
            }
        }
    }

    if let Some(raw_cwd) = obj.get("cwd").and_then(|v| v.as_str()) {
        if !raw_cwd.trim().is_empty() && Path::new(raw_cwd).is_dir() {
            let abs_cwd = resolve_abs_path(Path::new(raw_cwd))
                .to_string_lossy()
                .into_owned();
            if !is_plugin_runtime_dir(&abs_cwd) {
                return abs_cwd;
            }
            let folded_cwd = fold_path(&abs_cwd);
            for wp in &valid_wps {
                let fwp = fold_path(wp);
                if folded_cwd == fwp || folded_cwd.starts_with(&(fwp + "/")) {
                    return abs_cwd;
                }
            }
        }
    }

    if let Some(first) = valid_wps.first() {
        return first.clone();
    }

    let fallback = current();
    if is_plugin_runtime_dir(&fallback) {
        String::new()
    } else {
        fallback
    }
}

pub fn read_hook_stdin() -> Result<Value, String> {
    let mut raw = Vec::new();
    std::io::stdin()
        .read_to_end(&mut raw)
        .map_err(|e| format!("stdin_read_error:{}", e))?;
    if raw.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(Value::Object(Map::new()));
    }
    let text = std::str::from_utf8(&raw).map_err(|e| format!("invalid_json:{}", e))?;
    let stripped = text.strip_prefix('\u{feff}').unwrap_or(text);
    if stripped.trim().is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    let data: Value =
        serde_json::from_str(stripped).map_err(|e| format!("invalid_json:{}", e))?;
    if !data.is_object() {
        return Err("payload_not_object".to_string());
    }
    Ok(data)
}

pub fn dump_cli_json(payload: &Value, pretty: bool) -> String {
    if pretty {
        serde_json::to_string_pretty(payload).unwrap_or_else(|_| "null".to_string())
    } else {
        serde_json::to_string(payload).unwrap_or_else(|_| "null".to_string())
    }
}

pub fn print_cli_json(payload: &Value, pretty: bool) {
    let mut line = dump_cli_json(payload, pretty);
    line.push('\n');
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(line.as_bytes());
    let _ = out.flush();
}

pub fn emit_json(obj: &Value) {
    print_cli_json(obj, false);
}

pub fn emit_default_for_event(event: &str) {
    if event == "PreToolUse" || event == "Stop" {
        emit_json(&json!({"decision": "allow"}));
    } else {
        emit_json(&json!({}));
    }
}

pub fn emit_inject_system(message: &str, user_markdown: Option<&str>) {
    let has_md = user_markdown.map_or(false, |s| !s.is_empty());
    if message.is_empty() && !has_md {
        emit_json(&json!({}));
        return;
    }
    let mut sys_obj = Map::new();
    sys_obj.insert("systemMessage".to_string(), Value::String(message.to_string()));
    if let Some(md) = user_markdown {
        if !md.is_empty() {
            sys_obj.insert("metadata".to_string(), json!({"user_markdown": md}));
        }
    }
    emit_json(&json!({"injectSteps": [{"systemMessage": Value::Object(sys_obj)}]}));
}

pub fn emit_pre_tool(decision: &str, reason: Option<&str>, overwrite: Option<Value>) {
    let mut out = Map::new();
    out.insert("decision".to_string(), Value::String(decision.to_string()));
    if let Some(r) = reason {
        if !r.is_empty() {
            out.insert("reason".to_string(), Value::String(r.to_string()));
        }
    }
    if let Some(ow) = overwrite {
        let non_empty = match &ow {
            Value::Null => false,
            Value::Object(m) => !m.is_empty(),
            Value::Array(a) => !a.is_empty(),
            Value::String(s) => !s.is_empty(),
            Value::Bool(b) => *b,
            Value::Number(_) => true,
        };
        if non_empty {
            out.insert("overwrite".to_string(), ow);
        }
    }
    emit_json(&Value::Object(out));
}

pub fn emit_stop_allow() {
    emit_json(&json!({"decision": "allow"}));
}

pub fn emit_stop_continue(reason: &str) {
    emit_json(&json!({"decision": "continue", "reason": reason}));
}

pub fn read_json(path: &Path) -> Option<Value> {
    let raw = fs::read_to_string(path).ok()?;
    let stripped = raw.strip_prefix('\u{feff}').unwrap_or(&raw);
    serde_json::from_str(stripped).ok()
}

pub fn write_atomic_bytes(path: &Path, payload: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let base_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("data");
    let pid = std::process::id();
    let mut tmp_path = PathBuf::new();
    let mut tmp_file: Option<File> = None;
    for _ in 0..16 {
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let cand = parent.join(format!(".{}.{}.{}.tmp", base_name, pid, seq));
        match OpenOptions::new().write(true).create_new(true).open(&cand) {
            Ok(fh) => {
                tmp_path = cand;
                tmp_file = Some(fh);
                break;
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                // WORKAROUND: Re-create parent directory if concurrent pruning removed it between `create_dir_all` and `open`.
                let _ = fs::create_dir_all(parent);
                continue;
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    let mut fh = tmp_file.ok_or_else(|| "failed to allocate temp file".to_string())?;
    let write_res = fh.write_all(payload).and_then(|_| fh.flush());
    drop(fh);
    if let Err(e) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(e.to_string());
    }

    let mut last_err = String::new();
    for attempt in 0..5 {
        match fs::rename(&tmp_path, path) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = e.to_string();
                thread::sleep(Duration::from_millis(10 * (attempt + 1)));
            }
        }
    }
    let _ = fs::remove_file(&tmp_path);
    Err(last_err)
}

pub fn write_json(path: &Path, data: &Value) -> Result<(), String> {
    let payload = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    write_atomic_bytes(path, payload.as_bytes())
}

pub fn append_jsonl(path: &Path, record: &Value, max_bytes: u64) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    if let Ok(meta) = fs::metadata(path) {
        if meta.len() > max_bytes {
            let fname = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("log.jsonl");
            let rotated = path.with_file_name(format!("{}.1", fname));
            let _ = fs::rename(path, rotated);
        }
    }
    let mut line = serde_json::to_string(record).map_err(|e| e.to_string())?;
    line.push('\n');
    let mut fh = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    fh.write_all(line.as_bytes()).map_err(|e| e.to_string())
}

pub fn log_hook_event(stream: &str, event_type: &str, extra: Value) {
    #[cfg(test)]
    {
        // INVARIANT: Unit/integration tests must never append to the live user's `~/.gemini/carbon-stack/state/logs/*.jsonl`.
        let cur = match env::var("CARBON_STACK_HOME") {
            Ok(val) if !val.trim().is_empty() => PathBuf::from(val.trim()),
            _ => return,
        };
        let prod = home_dir().join(".gemini").join("carbon-stack");
        if fold_path(&cur.to_string_lossy()) == fold_path(&prod.to_string_lossy()) {
            return;
        }
    }
    let mut rec = Map::new();
    let ts_ms = (now_sec() * 1000.0).round() / 1000.0;
    rec.insert("ts".to_string(), json!(ts_ms));
    rec.insert(
        "type".to_string(),
        Value::String(event_type.to_string()),
    );
    if let Value::Object(fields) = extra {
        for (k, v) in fields {
            rec.insert(k, v);
        }
    }
    let target = state_subdir(&["logs"]).join(format!("{}.jsonl", stream));
    let _ = append_jsonl(&target, &Value::Object(rec), 2_000_000);
}

pub(crate) fn kernel_companion_lock_path(lock_path: &Path) -> PathBuf {
    crate::win32_sqlite::companion_lock_path(lock_path, "k")
}

pub(crate) fn v2_lease_path(state_root: &Path) -> PathBuf {
    state_root.join(".v2_alive.lease")
}

pub(crate) fn lock_epoch_path(state_root: &Path) -> PathBuf {
    state_root.join(".lock_epoch")
}

fn enclosing_state_dir(path: &Path) -> PathBuf {
    let default_state = state_dir();
    for anc in path.ancestors() {
        if anc == default_state {
            return default_state;
        }
        if anc.file_name().and_then(|s| s.to_str()) == Some("state")
            && (anc.join(".lock_epoch").exists()
                || anc.join(".v2_alive.lease").exists()
                || anc.join("gate").is_dir()
                || anc.join("chips").is_dir()
                || anc.parent().map_or(false, |p| p.join("backups").is_dir()))
        {
            return anc.to_path_buf();
        }
    }
    default_state
}

fn acquire_v2_shared_lease(state_root: &Path, deadline: Instant) -> Option<(File, bool)> {
    let _ = fs::create_dir_all(state_root);
    let lfh = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(v2_lease_path(state_root))
        .ok()?;
    loop {
        match lfh.try_lock_shared() {
            Ok(()) => {
                let is_v1 = fs::read_to_string(lock_epoch_path(state_root))
                    .map(|s| s.trim() == "v1")
                    .unwrap_or(false);
                return Some((lfh, is_v1));
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return None;
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(std::fs::TryLockError::Error(_)) => return None,
        }
    }
}

struct LegacyV1Guard<'a> {
    path: &'a Path,
    v2_lease: File,
    acquired: bool,
}

impl Drop for LegacyV1Guard<'_> {
    fn drop(&mut self) {
        if self.acquired {
            let _ = fs::remove_file(self.path);
        }
        let _ = self.v2_lease.unlock();
    }
}

fn with_legacy_v1_file_lock<T, F: FnOnce(bool) -> T>(
    lock_path: &Path,
    deadline: Instant,
    stale_sec: f64,
    v2_lease: File,
    f: F,
) -> T {
    // INVARIANT: Keep `v2_lease` (`LOCK_SH` on `.v2_alive.lease`) held across `O_CREAT | O_EXCL` acquisition, `f(acquired)`, and `unlink` so `perform_install` (`LOCK_EX` on `.v2_alive.lease`) can never clear `.lock_epoch` while a `v2` caller has observed `is_v1_epoch == true` and is entering or holding a `v1` lock.
    let mut acquired = false;
    loop {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(lock_path)
        {
            Ok(mut fh) => {
                let _ = writeln!(fh, "{} {}", std::process::id(), now_sec());
                acquired = true;
                break;
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                if fs::metadata(lock_path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|mt| mt.elapsed().ok())
                    .is_some_and(|age| age.as_secs_f64() > stale_sec)
                {
                    let _ = fs::remove_file(lock_path);
                    continue;
                }
                if Instant::now() >= deadline {
                    break;
                }
                thread::sleep(Duration::from_millis(15));
            }
            Err(_) => break,
        }
    }
    let _guard = LegacyV1Guard {
        path: lock_path,
        v2_lease,
        acquired,
    };
    f(acquired)
}

struct LockGuard<'a> {
    legacy_path: &'a Path,
    legacy_token: Option<crate::win32_sqlite::LegacyLockToken>,
    kernel_file: Option<File>,
    v2_lease: Option<File>,
    acquired: bool,
}

impl Drop for LockGuard<'_> {
    fn drop(&mut self) {
        if self.acquired {
            // INVARIANT: Release `legacy_token` (`SetFileInformationByHandle` on Windows; `rmdir` on Unix) BEFORE unlocking `kernel_file` (`<lock_path>.k`), and unlock `v2_lease` (`LOCK_SH` on `.v2_alive.lease`) LAST so `perform_rollback`'s `LOCK_EX` never observes an unswept `v2` directory.
            if let Some(tok) = self.legacy_token.take() {
                crate::win32_sqlite::release_legacy_lock_token(self.legacy_path, tok);
            }
            if let Some(kfh) = self.kernel_file.take() {
                let _ = kfh.unlock();
            }
        }
        if let Some(lfh) = self.v2_lease.take() {
            let _ = lfh.unlock();
        }
    }
}

pub fn with_file_lock<T, F: FnOnce(bool) -> T>(
    lock_path: &Path,
    timeout_sec: f64,
    stale_sec: f64,
    f: F,
) -> T {
    // INVARIANT: Coordinate with `perform_rollback` via shared kernel lease `.v2_alive.lease` + `.lock_epoch`, then serialize `v2` peers on `<lock_path>.k` and acquire `<lock_path>` (`share_mode(3)` + `SetFileInformationByHandle` on Windows; directory `mkdir`/`rmdir` + `RENAME_EXCHANGE`/`RENAME_SWAP` on Unix).
    if let Some(parent) = lock_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let _ = fs::create_dir_all(parent);
    }
    let deadline = Instant::now() + Duration::from_secs_f64(timeout_sec.max(0.0));
    let state_root = enclosing_state_dir(lock_path);
    let Some((v2_lease_fh, is_v1_epoch)) = acquire_v2_shared_lease(&state_root, deadline) else {
        return f(false);
    };
    if is_v1_epoch {
        return with_legacy_v1_file_lock(lock_path, deadline, stale_sec, v2_lease_fh, f);
    }
    let kpath = kernel_companion_lock_path(lock_path);
    let kfh_opt = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&kpath)
        .ok();
    let mut acquired = false;
    let mut held_kernel: Option<File> = None;
    let mut held_legacy: Option<crate::win32_sqlite::LegacyLockToken> = None;
    if let Some(kfh) = kfh_opt {
        loop {
            match kfh.try_lock() {
                Ok(()) => {
                    let mut retry_legacy = true;
                    let mut fatal_legacy_err = false;
                    while retry_legacy {
                        retry_legacy = false;
                        if crate::win32_sqlite::has_pending_unix_crash_slots(lock_path) {
                            match crate::win32_sqlite::reconcile_unix_crash_slots(
                                lock_path, stale_sec,
                            ) {
                                crate::win32_sqlite::UnixDirReclaim::ReclaimedRetry => {}
                                crate::win32_sqlite::UnixDirReclaim::NotStale => break,
                                #[cfg(any(target_os = "linux", target_os = "macos", test))]
                                crate::win32_sqlite::UnixDirReclaim::AcquiredDir => break,
                            }
                        }
                        match crate::win32_sqlite::create_legacy_lock_exclusive(lock_path) {
                            Ok(tok) => {
                                held_legacy = Some(tok);
                                acquired = true;
                            }
                            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                                match crate::win32_sqlite::try_reclaim_stale_legacy_lock(
                                    lock_path, stale_sec,
                                ) {
                                    #[cfg(not(windows))]
                                    crate::win32_sqlite::LegacyLockReclaim::Acquired(tok) => {
                                        held_legacy = Some(tok);
                                        acquired = true;
                                    }
                                    crate::win32_sqlite::LegacyLockReclaim::ReclaimedRetry => {
                                        retry_legacy = true;
                                    }
                                    crate::win32_sqlite::LegacyLockReclaim::NotStale => {}
                                }
                            }
                            Err(e)
                                if cfg!(windows)
                                    && e.kind() == ErrorKind::PermissionDenied
                                    && !lock_path.is_dir() =>
                            {
                                // INVARIANT: On Windows NTFS, `CreateFileW(CREATE_NEW)` transiently returns `PermissionDenied` while a displaced `v1` lock is in `STATUS_DELETE_PENDING`; retry until `deadline`.
                            }
                            Err(_) => {
                                fatal_legacy_err = true;
                            }
                        }
                    }
                    if acquired {
                        held_kernel = Some(kfh);
                        break;
                    }
                    let _ = kfh.unlock();
                    if fatal_legacy_err || Instant::now() >= deadline {
                        break;
                    }
                    thread::sleep(Duration::from_millis(15));
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    thread::sleep(Duration::from_millis(15));
                }
                Err(std::fs::TryLockError::Error(_)) => break,
            }
        }
    }
    let _guard = LockGuard {
        legacy_path: lock_path,
        legacy_token: held_legacy,
        kernel_file: held_kernel,
        v2_lease: Some(v2_lease_fh),
        acquired,
    };
    f(acquired)
}

pub fn parse_iso_ts(raw: &str) -> f64 {
    crate::win32_sqlite::parse_iso_ts(raw)
}

fn parse_jsonl_lines<S: AsRef<str>>(lines: &[S]) -> Vec<Value> {
    let mut items = Vec::new();
    for raw in lines {
        let s = raw.as_ref();
        if s.trim().is_empty() {
            continue;
        }
        if let Ok(val) = serde_json::from_str::<Value>(s) {
            if val.is_object() {
                items.push(val);
            }
        }
    }
    items
}

pub fn read_jsonl(path: &Path, max_lines: Option<usize>) -> Vec<Value> {
    if !path.is_file() {
        return Vec::new();
    }
    if max_lines == Some(1) {
        let Ok(fh) = File::open(path) else {
            return Vec::new();
        };
        let mut reader = BufReader::new(fh);
        let mut buf = Vec::new();
        if reader.read_until(b'\n', &mut buf).is_err() || buf.is_empty() {
            return Vec::new();
        }
        let first_line = String::from_utf8_lossy(&buf).into_owned();
        return parse_jsonl_lines(&[first_line]);
    }

    let Ok(meta) = fs::metadata(path) else {
        return Vec::new();
    };
    let size = meta.len();

    if let Some(n) = max_lines {
        if n > 0 && size > 131072 {
            let Ok(mut fh) = File::open(path) else {
                return Vec::new();
            };
            let mut first_raw = Vec::new();
            {
                let mut reader = BufReader::new(&mut fh);
                if reader.read_until(b'\n', &mut first_raw).is_err() || first_raw.is_empty() {
                    return Vec::new();
                }
            }
            let first_end = first_raw.len() as u64;
            let first_line = String::from_utf8_lossy(&first_raw).into_owned();
            if first_end >= size {
                return parse_jsonl_lines(&[first_line]);
            }
            let window = 65536u64.max((n as u64).saturating_mul(2048));
            let seek_pos = first_end.max(size.saturating_sub(window));
            if fh.seek(SeekFrom::Start(seek_pos)).is_err() {
                return Vec::new();
            }
            let mut tail_bytes = Vec::new();
            if fh.read_to_end(&mut tail_bytes).is_err() {
                return Vec::new();
            }
            let tail_chunk = String::from_utf8_lossy(&tail_bytes);
            let mut tail_lines: Vec<&str> = tail_chunk.lines().collect();
            if seek_pos > first_end && !tail_lines.is_empty() {
                tail_lines.remove(0);
            }
            let keep = n.saturating_sub(1);
            let tail_slice = if tail_lines.len() > keep {
                &tail_lines[tail_lines.len() - keep..]
            } else {
                &tail_lines[..]
            };
            let mut picked = Vec::with_capacity(1 + tail_slice.len());
            picked.push(first_line);
            for tl in tail_slice {
                picked.push((*tl).to_string());
            }
            return parse_jsonl_lines(&picked);
        }
    }

    let Ok(raw_bytes) = fs::read(path) else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&raw_bytes);
    let lines: Vec<&str> = text.lines().collect();
    if let Some(n) = max_lines {
        if n > 0 && lines.len() > n {
            let keep = n.saturating_sub(1);
            let mut picked = Vec::with_capacity(1 + keep);
            picked.push(lines[0]);
            picked.extend_from_slice(&lines[lines.len() - keep..]);
            return parse_jsonl_lines(&picked);
        }
    }
    parse_jsonl_lines(&lines)
}

pub fn read_jsonl_with_rotated(path: &Path, max_lines: Option<usize>) -> Vec<Value> {
    // INVARIANT: `append_jsonl` rotates `name.jsonl` -> `name.jsonl.1` when size exceeds `max_bytes`; read the newest entries from `.1` before the active file so pre-rotation records remain visible across rotation boundaries.
    let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let rot_path = (!fname.is_empty()).then(|| path.with_file_name(format!("{}.1", fname)));
    let cur = read_jsonl(path, max_lines);
    let Some(rot) = rot_path.filter(|p| p.is_file()) else {
        return cur;
    };
    if let Some(n) = max_lines {
        if n > 0 && cur.len() >= n {
            return cur;
        }
        let rem = n.saturating_sub(cur.len());
        if rem == 0 {
            return cur;
        }
        let mut rot_recs = read_jsonl(&rot, Some(rem.saturating_add(1)));
        if rot_recs.len() > rem {
            let drop_n = rot_recs.len() - rem;
            rot_recs.drain(0..drop_n);
        }
        rot_recs.extend(cur);
        return rot_recs;
    }
    let mut combined = read_jsonl(&rot, None);
    combined.extend(cur);
    combined
}

pub fn resolve_transcript_path(transcript_path: &str) -> Option<PathBuf> {
    if transcript_path.is_empty() {
        return None;
    }
    let p = PathBuf::from(transcript_path);
    if p.file_name().and_then(|s| s.to_str()) == Some("transcript.jsonl") {
        let full = p.with_file_name("transcript_full.jsonl");
        if full.is_file() {
            return Some(full);
        }
    }
    if p.is_file() {
        Some(p)
    } else {
        None
    }
}

fn decode_compact_arg_map(raw_args: &Map<String, Value>) -> Option<Map<String, Value>> {
    let mut decoded = Map::with_capacity(raw_args.len());
    for (k, v) in raw_args {
        let s = v.as_str()?;
        if s.is_empty() {
            return None;
        }
        let first = s.as_bytes()[0];
        if first != b'"' && first != b'[' && first != b'{' && !compact_json_scalar_re().is_match(s)
        {
            return None;
        }
        let parsed: Value = serde_json::from_str(s).ok()?;
        decoded.insert(k.clone(), parsed);
    }
    Some(decoded)
}

pub fn decode_compact_step_args(steps: &mut [Value]) {
    // INVARIANT: Antigravity's compact `transcript.jsonl` encodes every `tool_calls[*].args` value as a JSON string (`map<string, string>`), whereas `transcript_full.jsonl` stores decoded JSON values; decode once at the reader boundary so downstream parsers never strip user quotes.
    let mut pending: Vec<(usize, usize, Map<String, Value>)> = Vec::new();
    for (si, st) in steps.iter().enumerate() {
        let Some(tcs) = st.get("tool_calls").and_then(|v| v.as_array()) else {
            continue;
        };
        for (ti, tc) in tcs.iter().enumerate() {
            let Some(raw_args) = tc.get("args").and_then(|v| v.as_object()) else {
                continue;
            };
            if raw_args.is_empty() {
                continue;
            }
            let Some(decoded_map) = decode_compact_arg_map(raw_args) else {
                return;
            };
            pending.push((si, ti, decoded_map));
        }
    }
    for (si, ti, decoded_map) in pending {
        if let Some(tcs) = steps[si].get_mut("tool_calls").and_then(|v| v.as_array_mut()) {
            if let Some(tc_obj) = tcs.get_mut(ti).and_then(|v| v.as_object_mut()) {
                tc_obj.insert("args".to_string(), Value::Object(decoded_map));
            }
        }
    }
}

fn read_decoded_transcript(tp: &Path, max_lines: usize) -> Vec<Value> {
    let mut steps = read_jsonl(tp, Some(max_lines));
    if tp.file_name().and_then(|s| s.to_str()) == Some("transcript.jsonl") && !steps.is_empty() {
        decode_compact_step_args(&mut steps);
    }
    steps
}

pub fn read_transcript_steps(transcript_path: &str, max_lines: usize) -> Vec<Value> {
    let Some(tp) = resolve_transcript_path(transcript_path) else {
        return Vec::new();
    };
    read_decoded_transcript(&tp, max_lines)
}

pub fn read_compact_transcript_steps(transcript_path: &str, max_lines: usize) -> Vec<Value> {
    if transcript_path.is_empty() {
        return Vec::new();
    }
    let tp = Path::new(transcript_path).with_file_name("transcript.jsonl");
    read_decoded_transcript(&tp, max_lines)
}

fn parse_step_index_after_key(after_key: &str) -> Option<i64> {
    let num_start = after_key.trim_start().strip_prefix(':')?.trim_start();
    let digits_len = num_start
        .bytes()
        .take_while(|b| b.is_ascii_digit() || *b == b'-')
        .count();
    if digits_len == 0 {
        return None;
    }
    num_start[..digits_len].parse::<i64>().ok()
}

fn line_matches_wanted_step_index(line: &str, wanted: &HashSet<i64>) -> bool {
    let needle = "\"step_index\"";
    // INVARIANT: Antigravity JSONL emits `"step_index"` as the leading key; test it in O(1) first so multi-MB non-matching lines never scan `content` payloads.
    if let Some(after_brace) = line.trim_start().strip_prefix('{') {
        if let Some(after_key) = after_brace.trim_start().strip_prefix(needle) {
            if let Some(idx) = parse_step_index_after_key(after_key) {
                return wanted.contains(&idx);
            }
        }
    }
    let mut rest = line;
    while let Some(pos) = rest.find(needle) {
        rest = &rest[pos + needle.len()..];
        if let Some(idx) = parse_step_index_after_key(rest) {
            if wanted.contains(&idx) {
                return true;
            }
        }
    }
    false
}

pub fn read_full_transcript_steps_by_indices(
    transcript_path: &str,
    wanted: &HashSet<i64>,
) -> HashMap<i64, Value> {
    // INVARIANT: Stream sibling `transcript_full.jsonl` in O(1) memory only for exact `step_index` entries whose compact `transcript.jsonl` `content` was truncated (e.g. `swarm(action="models", all=true)` quotas > 4 KiB).
    let mut out = HashMap::new();
    if transcript_path.is_empty() || wanted.is_empty() {
        return out;
    }
    let orig = Path::new(transcript_path);
    let sibling_full = orig.with_file_name("transcript_full.jsonl");
    let full_tp = if sibling_full.is_file() {
        sibling_full
    } else if orig.file_name().and_then(|s| s.to_str()) != Some("transcript.jsonl")
        && orig.is_file()
    {
        orig.to_path_buf()
    } else {
        return out;
    };
    let Ok(fh) = File::open(&full_tp) else {
        return out;
    };
    let mut reader = BufReader::with_capacity(64 * 1024, fh);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let line = String::from_utf8_lossy(&buf);
                if !line_matches_wanted_step_index(&line, wanted) {
                    continue;
                }
                if let Ok(val) = serde_json::from_str::<Value>(line.trim()) {
                    if let Some(idx) = val.get("step_index").and_then(Value::as_i64) {
                        if wanted.contains(&idx) {
                            out.insert(idx, val);
                            if out.len() == wanted.len() {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

pub fn read_transcript_head(transcript_path: &str, head_lines: usize) -> Vec<Value> {
    let Some(tp) = resolve_transcript_path(transcript_path) else {
        return Vec::new();
    };
    if head_lines == 0 {
        return Vec::new();
    }
    let Ok(fh) = File::open(&tp) else {
        return Vec::new();
    };
    let mut reader = BufReader::new(fh);
    let mut raw_lines = Vec::with_capacity(head_lines);
    for _ in 0..head_lines {
        let mut buf = Vec::new();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => raw_lines.push(String::from_utf8_lossy(&buf).into_owned()),
        }
    }
    let mut steps = parse_jsonl_lines(&raw_lines);
    if tp.file_name().and_then(|s| s.to_str()) == Some("transcript.jsonl") && !steps.is_empty() {
        decode_compact_step_args(&mut steps);
    }
    steps
}

fn is_system_message(step: &Value) -> bool {
    step.get("source").and_then(|v| v.as_str()) == Some("SYSTEM")
        && step.get("type").and_then(|v| v.as_str()) == Some("SYSTEM_MESSAGE")
}

pub fn has_prefix_slice_gap(items: &[Value]) -> bool {
    if items.is_empty() || !items[0].is_object() {
        return false;
    }
    let s0 = items[0].get("step_index").and_then(|v| v.as_i64());
    if let Some(i0) = s0 {
        if i0 > 0 {
            return true;
        }
    }
    if items.len() < 2 || !items[1].is_object() {
        return false;
    }
    let s1 = items[1].get("step_index").and_then(|v| v.as_i64());
    if let (Some(i0), Some(i1)) = (s0, s1) {
        return i1 > i0 + 1;
    }
    items[0].get("source").and_then(|v| v.as_str()) == Some("SYSTEM_SDK")
        && !matches!(
            items[1].get("source").and_then(|v| v.as_str()),
            Some("SYSTEM_SDK") | Some("USER_EXPLICIT")
        )
}

fn leading_system_messages(
    transcript_path: &str,
    steps: Option<&[Value]>,
    max_lines: usize,
) -> Vec<Value> {
    // INVARIANT: Read true prefix lines (`read_transcript_head`) whenever `steps` is omitted or has a tail-slice gap, and never cross a `step_index` gap.
    let head_buf: Vec<Value>;
    let items: &[Value] = match steps {
        None => {
            head_buf = read_transcript_head(transcript_path, max_lines);
            &head_buf
        }
        Some(given) => {
            if !transcript_path.is_empty() && has_prefix_slice_gap(given) {
                let fetched = read_transcript_head(transcript_path, max_lines);
                if !fetched.is_empty() {
                    head_buf = fetched;
                    &head_buf
                } else {
                    given
                }
            } else {
                given
            }
        }
    };

    let mut out = Vec::new();
    let mut prev_idx: Option<i64> = None;
    for st in items {
        if !st.is_object() {
            break;
        }
        if let Some(cur_idx) = st.get("step_index").and_then(|v| v.as_i64()) {
            let broken = match prev_idx {
                None => cur_idx > 0,
                Some(p) => cur_idx > p + 1,
            };
            if broken {
                break;
            }
            prev_idx = Some(cur_idx);
        }
        if st.get("source").and_then(|v| v.as_str()) == Some("SYSTEM_SDK") {
            if !out.is_empty() {
                break;
            }
            continue;
        }
        if is_system_message(st) {
            out.push(st.clone());
        } else {
            break;
        }
    }
    out
}

pub fn subagent_parent_id(transcript_path: &str, steps: Option<&[Value]>) -> Option<String> {
    for st in leading_system_messages(transcript_path, steps, 8) {
        let content = st.get("content").and_then(|v| v.as_str()).unwrap_or("");
        if let Some(caps) = subagent_msg_re().captures(content) {
            let sender = caps.name("sender").map_or("", |m| m.as_str());
            if sender.eq_ignore_ascii_case("system") {
                continue;
            }
            return Some(sender.to_string());
        }
        if content.trim_start().starts_with("<swarm_worker>")
            || content.contains("post_message")
            || content.contains("swarm_wait")
        {
            return Some("swarm-coordinator".to_string());
        }
    }
    None
}

pub fn resolve_brain_root(override_dir: &str) -> PathBuf {
    let env_raw = env::var("ANTIGRAVITY_BRAIN_ROOT").unwrap_or_default();
    let raw = if !override_dir.trim().is_empty() {
        override_dir.trim()
    } else {
        env_raw.trim()
    };
    if !raw.is_empty() {
        return resolve_abs_path(&expand_tilde(raw));
    }
    resolve_abs_path(&home_dir().join(".gemini").join("antigravity").join("brain"))
}

pub fn swarm_dir(brain_root: &Path, session: &str) -> PathBuf {
    brain_root.join(session).join(".system_generated").join("swarm")
}

pub fn member_transcript_path(brain_root: &Path, cid: &str) -> PathBuf {
    brain_root
        .join(cid)
        .join(".system_generated")
        .join("logs")
        .join("transcript.jsonl")
}

pub fn load_swarm_members(brain_root: &Path, session: &str) -> Map<String, Value> {
    let path = swarm_dir(brain_root, session).join("members.json");
    let array_to_map = |arr: &[Value]| -> Map<String, Value> {
        let mut out = Map::new();
        for item in arr {
            if let Some(name) = item.get("name").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                out.insert(name.to_string(), item.clone());
            }
        }
        out
    };
    match read_json(&path) {
        Some(Value::Array(arr)) => array_to_map(&arr),
        Some(Value::Object(doc)) => match doc.get("members") {
            Some(Value::Object(members)) => members.clone(),
            Some(Value::Array(arr)) => array_to_map(arr),
            _ => doc,
        },
        _ => Map::new(),
    }
}

pub fn is_swarm_role_member(name: &str, meta: Option<&Value>) -> bool {
    let role_val = meta
        .and_then(|v| v.get("role"))
        .and_then(|v| v.as_str())
        .unwrap_or("worker")
        .trim()
        .to_lowercase();
    name == "coordinator"
        || matches!(role_val.as_str(), "coordinator" | "narrator" | "monitor")
        || swarm_role_member_re().is_match(name)
}

pub fn swarm_worker_names(members: &Map<String, Value>) -> Vec<&str> {
    members
        .iter()
        .filter(|(n, m)| m.is_object() && !is_swarm_role_member(n, Some(m)))
        .map(|(n, _)| n.as_str())
        .collect()
}

pub fn is_swarm_member_killed(meta: Option<&Value>) -> bool {
    let Some(Value::Object(m)) = meta else {
        return false;
    };
    if json_truthy(m.get("killed")) {
        return true;
    }
    let phase = m
        .get("phase")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_uppercase();
    if phase == "KILLED" {
        return true;
    }
    let desired = m
        .get("desired_state")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_uppercase();
    desired == "KILLED"
}

pub fn swarm_brain_and_cid(transcript_path: &str, conversation_id: &str) -> (Option<PathBuf>, String) {
    let req_cid = conversation_id.trim();
    let mut derived_brain: Option<PathBuf> = None;
    let mut derived_cid = String::new();
    if !transcript_path.is_empty() {
        let tp = resolve_abs_path(Path::new(transcript_path));
        if tp.components().count() >= 5 {
            let parent_is_logs = tp
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str())
                == Some("logs");
            let grand_is_sysgen = tp
                .ancestors()
                .nth(2)
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str())
                == Some(".system_generated");
            if parent_is_logs && grand_is_sysgen {
                if let (Some(cid_name), Some(brain_path)) = (
                    tp.ancestors()
                        .nth(3)
                        .and_then(|p| p.file_name())
                        .and_then(|s| s.to_str()),
                    tp.ancestors().nth(4),
                ) {
                    derived_cid = cid_name.to_string();
                    derived_brain = Some(brain_path.to_path_buf());
                }
            }
        }
    }
    if !req_cid.is_empty() && !derived_cid.is_empty() && req_cid != derived_cid {
        return (None, String::new());
    }
    let worker_cid = if !req_cid.is_empty() {
        req_cid
    } else {
        derived_cid.as_str()
    };
    if worker_cid.is_empty() {
        return (None, String::new());
    }
    if derived_brain.is_none() {
        let env_dir = env::var("ANTIGRAVITY_BRAIN_ROOT")
            .unwrap_or_default()
            .trim()
            .to_string();
        let cand_brain = resolve_brain_root(&env_dir);
        if !env_dir.is_empty() || cand_brain.is_dir() {
            derived_brain = Some(cand_brain);
        }
    }
    (derived_brain, worker_cid.to_string())
}

fn find_active_worker_entry<'a>(
    members: &'a Map<String, Value>,
    worker_cid: &str,
) -> Option<(&'a str, &'a Value)> {
    for (name, meta) in members {
        if !meta.is_object()
            || is_swarm_member_killed(Some(meta))
            || is_swarm_role_member(name, Some(meta))
        {
            continue;
        }
        let cid = meta
            .get("conversation_id")
            .or_else(|| meta.get("conversationId"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if cid == worker_cid {
            return Some((name.as_str(), meta));
        }
    }
    None
}

fn resolve_registered_swarm_worker(
    brain_root: Option<&Path>,
    worker_cid: &str,
    candidate_sessions: &[String],
) -> Option<Value> {
    let brain = brain_root?;
    if worker_cid.is_empty() {
        return None;
    }
    let mut seen: HashSet<String> = HashSet::new();

    let pack = |coord_sid: &str, name: &str, meta: &Value| -> Value {
        let raw_model = meta
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("registered")
            .trim()
            .to_lowercase();
        let model = if raw_model.is_empty() {
            "registered".to_string()
        } else {
            raw_model
        };
        let added_by = meta
            .get("added_by")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let board_path = swarm_dir(brain, coord_sid)
            .join("board.jsonl")
            .to_string_lossy()
            .into_owned();
        json!({
            "coordinator": coord_sid,
            "worker_name": name,
            "model": model,
            "added_by": added_by,
            "board_path": board_path,
        })
    };

    for sid in candidate_sessions {
        let clean_sid = sid.trim();
        if clean_sid.is_empty() || !seen.insert(clean_sid.to_string()) {
            continue;
        }
        let members = load_swarm_members(brain, clean_sid);
        if let Some((name, meta)) = find_active_worker_entry(&members, worker_cid) {
            return Some(pack(clean_sid, name, meta));
        }
    }

    // INVARIANT: Peer-sender step-0 on >128KB transcripts may omit step-1 coordinator sender; scan swarm registries on disk.
    let Ok(entries) = fs::read_dir(brain) else {
        return None;
    };
    for ent in entries.flatten() {
        let dir_path = ent.path();
        if !dir_path.is_dir() {
            continue;
        }
        let mf = dir_path
            .join(".system_generated")
            .join("swarm")
            .join("members.json");
        if !mf.is_file() {
            continue;
        }
        let Some(sid) = dir_path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !seen.insert(sid.to_string()) {
            continue;
        }
        let members = load_swarm_members(brain, sid);
        if let Some((name, meta)) = find_active_worker_entry(&members, worker_cid) {
            return Some(pack(sid, name, meta));
        }
    }
    None
}

pub fn resolve_swarm_worker_assignment(
    transcript_path: &str,
    steps: Option<&[Value]>,
    conversation_id: &str,
) -> Option<Value> {
    let lead = leading_system_messages(transcript_path, steps, 8);
    if lead.is_empty() {
        return None;
    }
    let mut candidate_sids = Vec::new();
    let mut saw_swarm_wake = false;
    for st in &lead {
        let content = st.get("content").and_then(|v| v.as_str()).unwrap_or("");
        if let Some(caps) = subagent_msg_re().captures(content) {
            let sender = caps.name("sender").map_or("", |m| m.as_str());
            if !sender.eq_ignore_ascii_case("system") {
                candidate_sids.push(sender.to_string());
            }
            let body = caps.name("body").map_or("", |m| m.as_str());
            if swarm_board_wake_body_re().is_match(body) {
                saw_swarm_wake = true;
            }
        } else if content.trim_start().starts_with("<swarm_worker>") {
            saw_swarm_wake = true;
        }
    }
    if !saw_swarm_wake {
        return None;
    }
    let (brain_root, worker_cid) = swarm_brain_and_cid(transcript_path, conversation_id);
    resolve_registered_swarm_worker(brain_root.as_deref(), &worker_cid, &candidate_sids)
}

pub fn swarm_worker_model(
    transcript_path: &str,
    steps: Option<&[Value]>,
    conversation_id: &str,
) -> Option<String> {
    let info = resolve_swarm_worker_assignment(transcript_path, steps, conversation_id)?;
    info.get("model")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}

fn is_mention_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

pub fn text_contains_mention(text: &str, name: &str) -> bool {
    if name.is_empty() || text.len() <= name.len() {
        return false;
    }
    let tb = text.as_bytes();
    let nb = name.as_bytes();
    let nlen = nb.len();
    for (idx, &b) in tb.iter().enumerate() {
        if b != b'@' || idx + 1 + nlen > tb.len() {
            continue;
        }
        if idx > 0 && is_mention_ident_byte(tb[idx - 1]) {
            continue;
        }
        if !tb[idx + 1..idx + 1 + nlen].eq_ignore_ascii_case(nb) {
            continue;
        }
        if idx + 1 + nlen < tb.len() && is_mention_ident_byte(tb[idx + 1 + nlen]) {
            continue;
        }
        return true;
    }
    false
}

pub fn text_mentions_swarm_worker(text: &str, wname: &str) -> bool {
    if text.is_empty() || wname.is_empty() {
        return false;
    }
    if text_contains_mention(text, wname) {
        return true;
    }
    if swarm_group_suffix_re().is_match(wname) {
        if let Some((group_prefix, _)) = wname.rsplit_once('-') {
            if !group_prefix.is_empty() && text_contains_mention(text, group_prefix) {
                return true;
            }
        }
    }
    false
}

pub fn latest_board_assign_and_reply_seq(
    raw_board: &[Value],
    wname: &str,
    added_by: &str,
) -> (i64, i64) {
    let clean_added = added_by.trim();
    let mut last_assign_seq: i64 = 0;
    let mut last_reply_seq: i64 = 0;
    for (idx, bp) in raw_board.iter().enumerate() {
        let seq = bp
            .get("seq")
            .and_then(|v| v.as_i64())
            .filter(|&x| x != 0)
            .unwrap_or((idx + 1) as i64);
        let poster = bp.get("agent").and_then(|v| v.as_str()).unwrap_or("");
        let btext = bp.get("text").and_then(|v| v.as_str()).unwrap_or("");
        let is_assigner =
            poster == "coordinator" || (!clean_added.is_empty() && poster == clean_added);
        if is_assigner
            && (text_mentions_swarm_worker(btext, wname) || text_contains_mention(btext, "all"))
        {
            last_assign_seq = seq;
        } else if poster == wname {
            last_reply_seq = seq;
        }
    }
    (last_assign_seq, last_reply_seq)
}

pub fn inspect_worker_turn_after_wake(w_steps: &[Value], last_assign_seq: i64) -> Value {
    let mut last_wake_idx: isize = -1;
    let mut max_wake_seq: i64 = 0;
    for (idx, st) in w_steps.iter().enumerate() {
        if is_system_message(st) {
            let content = st.get("content").and_then(|v| v.as_str()).unwrap_or("");
            let mut step_max: Option<i64> = None;
            for caps in swarm_wake_seq_re().captures_iter(content) {
                if let Some(Ok(n)) = caps.get(1).map(|m| m.as_str().parse::<i64>()) {
                    step_max = Some(step_max.map_or(n, |cur| cur.max(n)));
                }
            }
            if let Some(hit) = step_max {
                max_wake_seq = max_wake_seq.max(hit);
                last_wake_idx = idx as isize;
            }
        }
    }

    let tail: &[Value] = if last_wake_idx >= 0 {
        &w_steps[(last_wake_idx as usize + 1)..]
    } else {
        w_steps
    };

    let mut saw_model = false;
    let mut called_post = false;
    let mut has_error = false;
    let mut pending_bg: BTreeSet<String> = BTreeSet::new();
    let mut last_model_tcs: Vec<Value> = Vec::new();

    for st in tail {
        let ssource = st.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let stype = st.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let sstatus = st.get("status").and_then(|v| v.as_str()).unwrap_or("");
        let scontent = st.get("content").and_then(|v| v.as_str()).unwrap_or("");
        if ssource == "SYSTEM" && !pending_bg.is_empty() {
            let done_ids: Vec<String> = pending_bg
                .iter()
                .filter(|tid| {
                    scontent.contains(&format!("Task id \"{}\" finished", tid))
                        || scontent.contains(&format!("Task id \"{}\" was canceled", tid))
                })
                .cloned()
                .collect();
            for tid in done_ids {
                pending_bg.remove(&tid);
            }
        }
        if stype == "ERROR_MESSAGE"
            || (ssource == "MODEL" && stype != "GENERIC" && sstatus == "ERROR")
        {
            has_error = true;
        }
        if ssource == "MODEL" && stype == "PLANNER_RESPONSE" {
            saw_model = true;
            last_model_tcs = st
                .get("tool_calls")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if last_model_tcs
                .iter()
                .any(|tc| tc.get("name").and_then(|v| v.as_str()) == Some("post_message"))
            {
                called_post = true;
            }
        } else if stype == "GENERIC" {
            if let Some(tid) = extract_bg_task_id(scontent) {
                pending_bg.insert(tid);
            }
        }
    }

    let mut terminal_parked = false;
    if let Some(last_st) = tail.last() {
        let last_source = last_st.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let last_type = last_st.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let last_status = last_st.get("status").and_then(|v| v.as_str()).unwrap_or("");
        let last_tcs_empty = last_st
            .get("tool_calls")
            .and_then(|v| v.as_array())
            .map_or(true, |a| a.is_empty());
        if last_source == "MODEL"
            && last_type == "PLANNER_RESPONSE"
            && last_status == "DONE"
            && last_tcs_empty
        {
            terminal_parked = true;
        } else {
            let prev_called_wait = tail.len() >= 2
                && tail[tail.len() - 2]
                    .get("tool_calls")
                    .and_then(|v| v.as_array())
                    .map_or(false, |a| {
                        a.iter()
                            .any(|tc| tc.get("name").and_then(|n| n.as_str()) == Some("swarm_wait"))
                    });
            let last_content_lower = last_st
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            terminal_parked = last_type == "GENERIC"
                && last_status == "DONE"
                && (last_content_lower.contains("waiting for a message") || prev_called_wait);
        }
    }

    let pending_vec: Vec<Value> = pending_bg.into_iter().map(Value::String).collect();
    json!({
        "last_wake_idx": last_wake_idx,
        "max_wake_seq": max_wake_seq,
        "woke_for_assign": max_wake_seq >= last_assign_seq && last_wake_idx >= 0,
        "has_tail": !tail.is_empty(),
        "saw_model": saw_model,
        "called_post": called_post,
        "has_error": has_error,
        "pending_bg": pending_vec,
        "last_model_tcs": last_model_tcs,
        "terminal_parked": terminal_parked,
    })
}

pub fn is_subagent_session(transcript_path: &str, steps: Option<&[Value]>) -> bool {
    subagent_parent_id(transcript_path, steps).is_some()
}

pub fn last_assistant_message(steps: &[Value]) -> String {
    for step in steps.iter().rev() {
        let source = step.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let stype = step.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if source == "MODEL" && stype == "PLANNER_RESPONSE" {
            let content = step.get("content").and_then(|v| v.as_str()).unwrap_or("");
            if !content.trim().is_empty() {
                return content.to_string();
            }
            if json_truthy(step.get("tool_calls")) {
                return String::new();
            }
        }
        if source == "USER_EXPLICIT" && stype == "USER_INPUT" {
            break;
        }
    }
    String::new()
}

fn bytes_contain_ascii_ci(haystack: &[u8], needle_lower: &[u8]) -> bool {
    let n = needle_lower.len();
    if n == 0 {
        return true;
    }
    if haystack.len() < n {
        return false;
    }
    let first = needle_lower[0];
    let first_up = first.to_ascii_uppercase();
    let last = needle_lower[n - 1];
    let last_up = last.to_ascii_uppercase();
    let limit = haystack.len() - n;
    let mut i = 0;
    while i <= limit {
        let b = haystack[i];
        if b == first || b == first_up {
            let b_end = haystack[i + n - 1];
            if (b_end == last || b_end == last_up)
                && haystack[i..i + n].eq_ignore_ascii_case(needle_lower)
            {
                return true;
            }
        }
        i += 1;
    }
    false
}

enum UserInputMatch {
    Preferred(i64, String),
    Fallback(i64, String),
    None,
}

fn inspect_user_input_line(raw: &[u8]) -> UserInputMatch {
    let mut slice = raw;
    if slice.starts_with(&[0xEF, 0xBB, 0xBF]) {
        slice = &slice[3..];
    }
    while let Some(&last) = slice.last() {
        if last == b'\r' || last == b'\n' || last == b' ' || last == b'\t' {
            slice = &slice[..slice.len() - 1];
        } else {
            break;
        }
    }
    while let Some(&first) = slice.first() {
        if first == b' ' || first == b'\t' || first == b'\r' || first == b'\n' {
            slice = &slice[1..];
        } else {
            break;
        }
    }
    if slice.is_empty() || slice[0] != b'{' || !bytes_contain_ascii_ci(slice, b"user_input") {
        return UserInputMatch::None;
    }
    let parsed = serde_json::from_slice::<Value>(slice).ok().or_else(|| {
        let lossy = String::from_utf8_lossy(slice);
        serde_json::from_str::<Value>(&lossy).ok()
    });
    let Some(val) = parsed else {
        return UserInputMatch::None;
    };
    let Some(obj) = val.as_object() else {
        return UserInputMatch::None;
    };
    let stype = val_to_str(obj.get("type"));
    if !stype.trim().eq_ignore_ascii_case("USER_INPUT") {
        return UserInputMatch::None;
    }
    let step_idx = val_to_i64(obj.get("step_index"));
    let content = val_to_str(obj.get("content"));
    let source = val_to_str(obj.get("source"));
    let src_trimmed = source.trim();
    if src_trimmed.is_empty() || src_trimmed.eq_ignore_ascii_case("USER_EXPLICIT") {
        UserInputMatch::Preferred(step_idx, content)
    } else {
        UserInputMatch::Fallback(step_idx, content)
    }
}

fn check_user_input_line(
    line: &[u8],
    fallback: &mut Option<(i64, String)>,
) -> Option<(i64, String)> {
    match inspect_user_input_line(line) {
        UserInputMatch::Preferred(idx, content) => Some((idx, content)),
        UserInputMatch::Fallback(idx, content) => {
            if fallback.is_none() {
                *fallback = Some((idx, content));
            }
            None
        }
        UserInputMatch::None => None,
    }
}

fn last_user_input_step_from_file(path: &Path, chunk_size: usize) -> Option<(i64, String)> {
    // INVARIANT: Scan backward from EOF in fixed-size byte chunks (splitting strictly on raw `b'\n'` before UTF-8/JSON decoding) so 20–50 MB transcripts are never read from byte 0 on every `PreInvocation`.
    let mut fh = File::open(path).ok()?;
    let file_len = fh.seek(SeekFrom::End(0)).ok()?;
    if file_len == 0 {
        return None;
    }
    let step_bytes = chunk_size.max(1);
    let mut pos: u64 = file_len;
    let mut pending_frags: Vec<Vec<u8>> = Vec::new();
    let mut pending_len: usize = 0;
    let mut fallback: Option<(i64, String)> = None;

    while pos > 0 {
        let read_len = (pos.min(step_bytes as u64)) as usize;
        pos -= read_len as u64;
        fh.seek(SeekFrom::Start(pos)).ok()?;
        let mut buf = vec![0u8; read_len];
        fh.read_exact(&mut buf).ok()?;

        let Some(last_nl) = buf.iter().rposition(|&b| b == b'\n') else {
            pending_len = pending_len.saturating_add(buf.len());
            pending_frags.push(buf);
            continue;
        };

        let right = &buf[last_nl + 1..];
        if !pending_frags.is_empty() {
            let mut combined = Vec::with_capacity(right.len().saturating_add(pending_len));
            combined.extend_from_slice(right);
            for frag in pending_frags.drain(..).rev() {
                combined.extend_from_slice(&frag);
            }
            pending_len = 0;
            if let Some(hit) = check_user_input_line(&combined, &mut fallback) {
                return Some(hit);
            }
        } else if !right.is_empty() {
            if let Some(hit) = check_user_input_line(right, &mut fallback) {
                return Some(hit);
            }
        }

        let mut end = last_nl;
        loop {
            match buf[..end].iter().rposition(|&b| b == b'\n') {
                Some(prev_nl) => {
                    if let Some(hit) = check_user_input_line(&buf[prev_nl + 1..end], &mut fallback)
                    {
                        return Some(hit);
                    }
                    end = prev_nl;
                }
                None => {
                    if pos == 0 {
                        if end > 0 {
                            if let Some(hit) = check_user_input_line(&buf[..end], &mut fallback) {
                                return Some(hit);
                            }
                        }
                    } else if end > 0 {
                        pending_frags.push(buf[..end].to_vec());
                        pending_len = end;
                    }
                    break;
                }
            }
        }
    }

    if !pending_frags.is_empty() {
        let mut combined = Vec::with_capacity(pending_len);
        for frag in pending_frags.drain(..).rev() {
            combined.extend_from_slice(&frag);
        }
        if let Some(hit) = check_user_input_line(&combined, &mut fallback) {
            return Some(hit);
        }
    }

    fallback
}

pub fn strip_user_request_wrapper(raw: &str) -> &str {
    let mut s = raw.trim();
    if let Some(cs_end) = s.find("</CONTEXT_SUMMARY>") {
        if s[..cs_end].trim_start().starts_with("<CONTEXT_SUMMARY>") {
            s = s[cs_end + "</CONTEXT_SUMMARY>".len()..].trim_start();
        }
    }
    if let Some(after_open) = s.strip_prefix("<USER_REQUEST>") {
        let body_end = after_open
            .find("</USER_REQUEST>\n<ADDITIONAL_METADATA>")
            .or_else(|| after_open.find("</USER_REQUEST>\r\n<ADDITIONAL_METADATA>"))
            .or_else(|| after_open.rfind("</USER_REQUEST>"));
        if let Some(end) = body_end {
            return after_open[..end].trim();
        }
    }
    s
}

pub fn last_user_input_step(transcript_path: &str) -> Option<(i64, String)> {
    let tp = resolve_transcript_path(transcript_path)?;
    last_user_input_step_from_file(&tp, 64 * 1024)
}

pub fn extract_bg_task_id(text: &str) -> Option<String> {
    let header_end = text
        .find("Command output:")
        .into_iter()
        .chain(text.find("Command exited with code"))
        .chain(text.find("Log output:"))
        .min()
        .unwrap_or(text.len());
    bg_task_id_re()
        .captures(&text[..header_end])
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum PsQuoteKind {
    Single,
    Double,
    Bare,
}

fn split_ps_top_level_statements(cmd: &str) -> Vec<&str> {
    let bytes = cmd.as_bytes();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    let mut in_sq = false;
    let mut in_dq = false;
    let mut paren_depth = 0usize;
    let mut brace_depth = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if in_sq {
            if b == b'\'' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                    i += 2;
                    continue;
                }
                in_sq = false;
            }
            i += 1;
            continue;
        }
        if in_dq {
            if b == b'`' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_dq = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' => in_sq = true,
            b'"' => in_dq = true,
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            b';' | b'\r' | b'\n' if paren_depth == 0 && brace_depth == 0 => {
                let seg = cmd[start..i].trim();
                if !seg.is_empty() {
                    out.push(seg);
                }
                start = i + 1;
            }
            b'&' if paren_depth == 0
                && brace_depth == 0
                && i + 1 < bytes.len()
                && bytes[i + 1] == b'&' =>
            {
                let seg = cmd[start..i].trim();
                if !seg.is_empty() {
                    out.push(seg);
                }
                i += 2;
                start = i;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    let tail = cmd[start..].trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

fn parse_ps_token_at(s: &str) -> Option<(String, PsQuoteKind, &str)> {
    let trimmed = s.trim_start_matches([' ', '\t']);
    let bytes = trimmed.as_bytes();
    let first = *bytes.first()?;
    if first == b'\'' {
        let mut val = String::new();
        let mut i = 1usize;
        while i < bytes.len() {
            if bytes[i] == b'\'' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                    val.push('\'');
                    i += 2;
                    continue;
                }
                return Some((val, PsQuoteKind::Single, &trimmed[i + 1..]));
            }
            let ch = trimmed[i..].chars().next()?;
            val.push(ch);
            i += ch.len_utf8();
        }
        return None;
    }
    if first == b'"' {
        let mut val = String::new();
        let mut i = 1usize;
        while i < bytes.len() {
            if bytes[i] == b'`' && i + 1 < bytes.len() {
                let ch = trimmed[i + 1..].chars().next()?;
                val.push(ch);
                i += 1 + ch.len_utf8();
                continue;
            }
            if bytes[i] == b'"' {
                return Some((val, PsQuoteKind::Double, &trimmed[i + 1..]));
            }
            let ch = trimmed[i..].chars().next()?;
            val.push(ch);
            i += ch.len_utf8();
        }
        return None;
    }
    let mut i = 0usize;
    while i < bytes.len() {
        if matches!(
            bytes[i],
            b' ' | b'\t' | b';' | b'|' | b'&' | b'>' | b'<' | b'\r' | b'\n' | b')' | b'}'
        ) {
            break;
        }
        i += 1;
    }
    if i == 0 {
        return None;
    }
    Some((trimmed[..i].to_string(), PsQuoteKind::Bare, &trimmed[i..]))
}

fn has_unquoted_shell_meta(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    let mut in_sq = false;
    let mut in_dq = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_sq {
            if b == b'\'' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                    i += 2;
                    continue;
                }
                in_sq = false;
            }
            i += 1;
            continue;
        }
        if in_dq {
            if b == b'`' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
                return true;
            }
            if b == b'"' {
                in_dq = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' => in_sq = true,
            b'"' => in_dq = true,
            b'|' | b'>' | b'<' | b'`' | b'(' | b')' | b'{' | b'}' | b'&' | b';' | b'\r' | b'\n' => {
                return true;
            }
            b'@' if i + 1 < bytes.len() && matches!(bytes[i + 1], b'"' | b'\'') => return true,
            b'$' if i + 1 < bytes.len() && bytes[i + 1] == b'(' => return true,
            _ => {}
        }
        i += 1;
    }
    in_sq || in_dq
}

fn expand_ps_path_token(
    raw: &str,
    kind: PsQuoteKind,
    vars: &HashMap<String, String>,
) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if kind == PsQuoteKind::Single {
        return Some(trimmed.to_string());
    }
    if trimmed.contains("$(") || trimmed.contains('`') {
        return None;
    }
    if !trimmed.contains('$') {
        return Some(trimmed.to_string());
    }
    let after_dollar = trimmed.strip_prefix('$')?;
    let (var_name, rest) = if let Some(braced) = after_dollar.strip_prefix('{') {
        let close = braced.find('}')?;
        (&braced[..close], &braced[close + 1..])
    } else {
        let len = after_dollar
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .count();
        (&after_dollar[..len], &after_dollar[len..])
    };
    if var_name.is_empty()
        || (!rest.is_empty() && !rest.starts_with('\\') && !rest.starts_with('/'))
        || rest.contains('$')
    {
        return None;
    }
    let base = vars.get(&var_name.to_ascii_lowercase())?;
    let mut joined = base.clone();
    joined.push_str(rest);
    let out = joined.trim().to_string();
    (!out.is_empty()).then_some(out)
}

fn strip_leading_null_pipe(s: &str) -> &str {
    if let Some(m) = leading_null_pipe_re().find(s) {
        &s[m.end()..]
    } else {
        s
    }
}

fn is_readonly_ps_preamble_cmd(word: &str) -> bool {
    // SAFETY: Allow ONLY pure built-in PowerShell utility/management cmdlets plus the built-in `pwd` alias (`Get-Location` in PowerShell / builtin in POSIX shells; never external binaries like `rg`/`whoami`/`hostname`) so preamble skipping cannot hide `--pre` preprocessors or PATH hijacks.
    matches!(
        word.to_ascii_lowercase().as_str(),
        "write-output"
            | "write-host"
            | "get-location"
            | "pwd"
            | "test-path"
            | "resolve-path"
            | "split-path"
            | "join-path"
            | "get-childitem"
            | "get-item"
            | "get-itemproperty"
            | "get-content"
            | "select-string"
            | "get-date"
    )
}

fn is_safe_ps_preamble_env_var(name_low: &str) -> bool {
    !matches!(
        name_low,
        "path"
            | "pathext"
            | "psmodulepath"
            | "comspec"
            | "ripgrep_config_path"
            | "node_options"
            | "ld_preload"
            | "ld_library_path"
            | "dyld_insert_libraries"
            | "dyld_library_path"
            | "pythonstartup"
            | "pythonpath"
            | "pythonhome"
    ) && !name_low.starts_with("git_")
        && !name_low.starts_with("carbon_")
}

fn parse_ps_preamble_stmt(stmt: &str, vars: &mut HashMap<String, String>) -> bool {
    let s = strip_leading_null_pipe(stmt).trim();
    if s.is_empty() {
        return true;
    }
    if let Some(after_dollar) = s.strip_prefix('$') {
        let (is_env, ident_src) = if after_dollar
            .as_bytes()
            .get(..4)
            .is_some_and(|b| b.eq_ignore_ascii_case(b"env:"))
        {
            (true, &after_dollar[4..])
        } else {
            (false, after_dollar)
        };
        let nlen = ident_src
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .count();
        if nlen > 0 {
            let name_low = ident_src[..nlen].to_ascii_lowercase();
            let after_name = ident_src[nlen..].trim_start_matches([' ', '\t']);
            if let Some(after_eq) = after_name.strip_prefix('=') {
                if !after_eq.starts_with('=') {
                    let rhs = after_eq.trim();
                    if has_unquoted_shell_meta(rhs) {
                        if !is_env {
                            vars.remove(&name_low);
                        }
                        return false;
                    }
                    let Some((tok, kind, tail)) = parse_ps_token_at(rhs) else {
                        if !is_env {
                            vars.remove(&name_low);
                        }
                        return false;
                    };
                    if !tail.trim().is_empty() {
                        if !is_env {
                            vars.remove(&name_low);
                        }
                        return false;
                    }
                    if is_env {
                        return is_safe_ps_preamble_env_var(&name_low);
                    }
                    if matches!(
                        name_low.as_str(),
                        "erroractionpreference"
                            | "progresspreference"
                            | "warningpreference"
                            | "verbosepreference"
                            | "informationpreference"
                            | "psnativecommanduseerroractionpreference"
                    ) {
                        return true;
                    }
                    if let Some(expanded) = expand_ps_path_token(&tok, kind, vars) {
                        vars.insert(name_low, expanded);
                        return true;
                    }
                    vars.remove(&name_low);
                    return false;
                }
            }
        }
    }
    if let Some((word, PsQuoteKind::Bare, _)) = parse_ps_token_at(s) {
        if is_readonly_ps_preamble_cmd(&word) && !has_unquoted_shell_meta(s) {
            return true;
        }
    }
    false
}

fn parse_nav_stmt(stmt: &str, vars: &HashMap<String, String>) -> Option<String> {
    let s = strip_leading_null_pipe(stmt).trim();
    let (cmd_word, PsQuoteKind::Bare, mut rest) = parse_ps_token_at(s)? else {
        return None;
    };
    let is_nav = matches!(
        cmd_word.to_ascii_lowercase().as_str(),
        "cd" | "chdir" | "set-location" | "sl" | "push-location" | "pushd"
    );
    if !is_nav || !rest.starts_with([' ', '\t']) {
        return None;
    }
    if let Some((flag, PsQuoteKind::Bare, after_flag)) = parse_ps_token_at(rest) {
        let fl = flag.to_ascii_lowercase();
        if (cmd_word.eq_ignore_ascii_case("cd") && fl == "/d")
            || fl == "-literalpath"
            || fl == "-path"
        {
            rest = after_flag;
        }
    }
    let (tok, kind, tail) = parse_ps_token_at(rest)?;
    if !tail.trim().is_empty() {
        return None;
    }
    expand_ps_path_token(&tok, kind, vars)
}

enum GitStmtKind {
    NotGit,
    WithDashC(Option<String>),
    ReadOnlyNoDashC,
    MutatingNoDashC,
}

fn is_readonly_git_subcommand(sub: &str, rest: &str) -> bool {
    let sub_low = sub.to_ascii_lowercase();
    if !matches!(
        sub_low.as_str(),
        "status"
            | "diff"
            | "log"
            | "show"
            | "grep"
            | "rev-parse"
            | "ls-files"
            | "ls-tree"
            | "cat-file"
            | "describe"
            | "rev-list"
            | "merge-base"
            | "for-each-ref"
            | "name-rev"
            | "check-ignore"
            | "shortlog"
            | "blame"
    ) {
        return false;
    }
    if has_unquoted_shell_meta(rest) {
        return false;
    }
    let mut tail = rest;
    while let Some((tok, _, next)) = parse_ps_token_at(tail) {
        if tok == "--output" || tok.starts_with("--output=") {
            return false;
        }
        tail = next;
    }
    true
}

fn parse_git_dash_c_stmt(stmt: &str, vars: &HashMap<String, String>) -> GitStmtKind {
    let mut s = strip_leading_null_pipe(stmt).trim();
    if let Some(after_amp) = s.strip_prefix('&') {
        let next = after_amp.trim_start_matches([' ', '\t']);
        if !next.starts_with('&') {
            s = next;
        }
    }
    let Some((cmd_tok, _, mut rest)) = parse_ps_token_at(s) else {
        return GitStmtKind::NotGit;
    };
    let base = cmd_tok
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(&cmd_tok)
        .to_ascii_lowercase();
    if base != "git" && base != "git.exe" {
        return GitStmtKind::NotGit;
    }
    while let Some((tok, kind, after)) = parse_ps_token_at(rest) {
        if kind == PsQuoteKind::Bare && matches!(tok.as_str(), "--no-optional-locks" | "--no-pager" | "-P") {
            rest = after;
            continue;
        }
        if kind == PsQuoteKind::Bare && tok == "-C" {
            let Some((dir_tok, dir_kind, _)) = parse_ps_token_at(after) else {
                return GitStmtKind::WithDashC(None);
            };
            return GitStmtKind::WithDashC(expand_ps_path_token(&dir_tok, dir_kind, vars));
        }
        if kind == PsQuoteKind::Bare && is_readonly_git_subcommand(&tok, after) {
            return GitStmtKind::ReadOnlyNoDashC;
        }
        break;
    }
    GitStmtKind::MutatingNoDashC
}

pub fn extract_cd_prefix_or_git_c(cmd: &str) -> (Option<String>, Option<String>) {
    // INVARIANT: Scan past pure PowerShell preamble statements (`$ErrorActionPreference`, `$env:`, literal `$var = "..."`, literal `Write-Output`) before leading directory navigation or first non-readonly `git` / `git -C`; stop at any potentially mutating statement so a trailing `cd`/`git -C` can never mask an earlier mutation's working directory.
    let mut vars: HashMap<String, String> = HashMap::new();
    let mut cd_dir: Option<String> = None;
    let mut git_c_dir: Option<String> = None;
    let mut saw_non_preamble = false;
    let mut saw_git = false;

    for stmt in split_ps_top_level_statements(cmd) {
        if !saw_non_preamble {
            if let Some(dir) = parse_nav_stmt(stmt, &vars) {
                cd_dir = Some(dir);
                saw_non_preamble = true;
                continue;
            }
            if parse_ps_preamble_stmt(stmt, &mut vars) {
                continue;
            }
            saw_non_preamble = true;
        } else if parse_ps_preamble_stmt(stmt, &mut vars) {
            continue;
        }
        if !saw_git {
            match parse_git_dash_c_stmt(stmt, &vars) {
                GitStmtKind::ReadOnlyNoDashC => {}
                GitStmtKind::WithDashC(gc_opt) => {
                    saw_git = true;
                    git_c_dir = gc_opt;
                }
                GitStmtKind::MutatingNoDashC | GitStmtKind::NotGit => {
                    saw_git = true;
                }
            }
        }
        if cd_dir.is_some() && saw_git {
            break;
        }
    }
    (cd_dir, git_c_dir)
}

fn is_executable_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path) {
            return (meta.permissions().mode() & 0o111) != 0;
        }
        return false;
    }
    #[cfg(not(unix))]
    {
        true
    }
}

pub fn which_in_path(name: &str) -> Option<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.contains('/') || trimmed.contains('\\') {
        let p = Path::new(trimmed);
        return if is_executable_file(p) {
            Some(p.to_string_lossy().into_owned())
        } else {
            None
        };
    }
    let path_var = env::var_os("PATH")?;
    let has_ext = Path::new(trimmed).extension().is_some();

    #[cfg(windows)]
    let exts: Vec<String> = if has_ext {
        Vec::new()
    } else {
        env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string())
            .split(';')
            .map(|e| e.trim().to_string())
            .filter(|e| !e.is_empty())
            .collect()
    };

    for dir in env::split_paths(&path_var) {
        if has_ext {
            let cand = dir.join(trimmed);
            if is_executable_file(&cand) {
                return Some(cand.to_string_lossy().into_owned());
            }
        } else {
            #[cfg(windows)]
            {
                for ext in &exts {
                    let cand = dir.join(format!("{}{}", trimmed, ext));
                    if is_executable_file(&cand) {
                        return Some(cand.to_string_lossy().into_owned());
                    }
                }
            }
            let cand = dir.join(trimmed);
            if is_executable_file(&cand) {
                return Some(cand.to_string_lossy().into_owned());
            }
        }
    }
    None
}

pub fn resolve_command_cwd(cmd: &str, default_cwd: &str, fallback_dir: &str) -> String {
    let unwrapped = unwrap_tokenade_command(cmd);
    let (cd_dir, git_c_dir) = extract_cd_prefix_or_git_c(&unwrapped);
    for raw_opt in [cd_dir, git_c_dir] {
        if let Some(raw_dir) = raw_opt {
            let trimmed = raw_dir.trim();
            if trimmed.is_empty() {
                continue;
            }
            let p = Path::new(trimmed);
            let candidate = if p.is_absolute() {
                p.to_path_buf()
            } else if !default_cwd.is_empty() {
                Path::new(default_cwd).join(trimmed)
            } else {
                continue;
            };
            if candidate.is_dir() {
                return resolve_abs_path(&candidate).to_string_lossy().into_owned();
            }
        }
    }
    if !fallback_dir.is_empty() && Path::new(fallback_dir).is_dir() {
        if default_cwd.is_empty() {
            return resolve_abs_path(Path::new(fallback_dir))
                .to_string_lossy()
                .into_owned();
        }
        let f_def = fold_path(default_cwd);
        let f_fb = fold_path(fallback_dir);
        if (f_def == f_fb || f_def.starts_with(&(f_fb + "/")))
            && Path::new(fallback_dir).join(".git").exists()
        {
            return default_cwd.to_string();
        }
        if git_toplevel(default_cwd, false).is_none() {
            return resolve_abs_path(Path::new(fallback_dir))
                .to_string_lossy()
                .into_owned();
        }
    }
    default_cwd.to_string()
}

pub fn run_git_raw(
    cwd: &str,
    args: &[&str],
    timeout_sec: f64,
    stdin_bytes: Option<&[u8]>,
    extra_env: &[(&str, &str)],
) -> (i32, Vec<u8>, String) {
    let eff_to = timeout_sec.max(0.25);
    let timeout_ms = (eff_to * 1000.0).round() as u64;
    let mut full_args = Vec::with_capacity(args.len() + 1);
    full_args.push("--no-optional-locks".to_string());
    for a in args {
        full_args.push((*a).to_string());
    }
    let mut env_pairs = Vec::with_capacity(2 + extra_env.len());
    env_pairs.push(("GIT_TERMINAL_PROMPT", "0"));
    env_pairs.push(("GIT_OPTIONAL_LOCKS", "0"));
    env_pairs.extend_from_slice(extra_env);
    let cwd_opt = if cwd.trim().is_empty() {
        None
    } else {
        Some(Path::new(cwd))
    };
    match run_command_with_job("git", &full_args, cwd_opt, &env_pairs, stdin_bytes, Some(timeout_ms)) {
        Ok(res) => {
            if res.timed_out {
                (124, Vec::new(), format!("git_timeout_after_{}s", eff_to))
            } else {
                let err_s = res.stderr_str();
                (res.code, res.stdout, err_s)
            }
        }
        Err(e) => (127, Vec::new(), e),
    }
}

pub fn run_git_env(
    cwd: &str,
    args: &[&str],
    timeout_sec: f64,
    extra_env: &[(&str, &str)],
) -> (i32, String, String) {
    let (rc, out, err) = run_git_raw(cwd, args, timeout_sec, None, extra_env);
    (rc, String::from_utf8_lossy(&out).into_owned(), err)
}

pub fn collect_masked_index_paths(
    git_root: &str,
    timeout_sec: f64,
    extra_env: &[(&str, &str)],
) -> Result<(Vec<String>, Vec<String>), ()> {
    // INVARIANT: Partition `CE_VALID` (`--assume-unchanged`, lowercase `ls-files -v` tag) and non-sparse `CE_SKIP_WORKTREE` (`--skip-worktree`, `S`/`s` tag) separately because `git update-index` returns early after `--no-assume-unchanged` if both flags are combined in one invocation.
    let (rc, out, _) = run_git_raw(git_root, &["ls-files", "-v", "-z"], timeout_sec, None, extra_env);
    if rc != 0 {
        return Err(());
    }
    let root_path = Path::new(git_root);
    let mut sparse_enabled: Option<bool> = None;
    let mut assume_paths: Vec<String> = Vec::new();
    let mut skip_paths: Vec<String> = Vec::new();
    for entry in out.split(|&b| b == 0).filter(|s| !s.is_empty()) {
        if entry.len() <= 2 || entry[1] != b' ' {
            return Err(());
        }
        let tag = entry[0];
        if !tag.is_ascii_lowercase() && tag != b'S' {
            continue;
        }
        let rel = std::str::from_utf8(&entry[2..]).map_err(|_| ())?;
        if tag.is_ascii_lowercase() {
            assume_paths.push(rel.to_string());
        }
        if tag == b'S' || tag == b's' {
            if tag == b'S'
                && sparse_enabled != Some(false)
                && root_path.join(rel).symlink_metadata().is_err()
            {
                let is_sparse = *sparse_enabled.get_or_insert_with(|| {
                    let (cfg_rc, cfg_out, _) = run_git_env(
                        git_root,
                        &["config", "--bool", "core.sparseCheckout"],
                        2.0,
                        extra_env,
                    );
                    cfg_rc == 0 && cfg_out.trim().eq_ignore_ascii_case("true")
                });
                if is_sparse {
                    continue;
                }
            }
            skip_paths.push(rel.to_string());
        }
    }
    Ok((assume_paths, skip_paths))
}

pub fn run_git(cwd: &str, args: &[&str], timeout_sec: f64) -> (i32, String, String) {
    run_git_env(cwd, args, timeout_sec, &[])
}

pub fn is_unapproved_home_git_root(cwd: &str, git_root: &str) -> bool {
    if git_root.trim().is_empty() {
        return false;
    }
    let home_fold = fold_path(&home_dir().to_string_lossy());
    if home_fold.is_empty() || fold_path(git_root) != home_fold {
        return false;
    }
    if env::var("CARBON_ALLOW_HOME_GIT_ROOT").ok().as_deref() == Some("1")
        && !cwd.trim().is_empty()
        && fold_path(cwd) == home_fold
    {
        return false;
    }
    true
}

pub fn git_toplevel(cwd: &str, include_home_root: bool) -> Option<String> {
    if cwd.trim().is_empty() || !Path::new(cwd).is_dir() {
        return None;
    }
    let (rc, out, _) = run_git(cwd, &["rev-parse", "--show-toplevel"], 3.0);
    if rc == 0 && !out.trim().is_empty() {
        let top = resolve_abs_path(Path::new(out.trim()))
            .to_string_lossy()
            .into_owned();
        // INVARIANT: Never climb from a non-git subdirectory (`~/.gemini/antigravity/scratch/...`, `%TEMP%`, etc.) into a stray `$HOME/.git`, which would scan the entire user profile.
        if !include_home_root && is_unapproved_home_git_root(cwd, &top) {
            return None;
        }
        return Some(top);
    }
    None
}

pub fn git_head_oid(git_root: &str) -> String {
    if git_root.trim().is_empty() || !Path::new(git_root).is_dir() {
        return String::new();
    }
    let (rc, out, _) = run_git(git_root, &["rev-parse", "--verify", "-q", "HEAD"], 3.0);
    if rc == 0 {
        out.trim().to_string()
    } else {
        String::new()
    }
}

struct TempDirGuard(PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn capture_worktree_tree_oid(git_root: &str, timeout_sec: f64) -> String {
    if git_root.trim().is_empty() || !Path::new(git_root).is_dir() {
        return String::new();
    }
    let (rc_idx, idx_path_out, _) = run_git(git_root, &["rev-parse", "--git-path", "index"], 3.0);
    let idx_rel = if rc_idx == 0 {
        idx_path_out.trim()
    } else {
        ""
    };
    let real_idx = if !idx_rel.is_empty() {
        let p = Path::new(idx_rel);
        if p.is_absolute() {
            Some(p.to_path_buf())
        } else {
            Some(Path::new(git_root).join(p))
        }
    } else {
        None
    };

    let Some(src_idx) = real_idx else {
        return String::new();
    };
    let tmp_base = env::temp_dir();
    let pid = std::process::id();
    let mut tmp_dir: Option<PathBuf> = None;
    for _ in 0..16 {
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let cand = tmp_base.join(format!("carbon-idx-{}-{}", pid, seq));
        if fs::create_dir(&cand).is_ok() {
            tmp_dir = Some(cand);
            break;
        }
    }
    let Some(dir_path) = tmp_dir else {
        return String::new();
    };
    let _guard = TempDirGuard(dir_path.clone());
    let tmp_index = dir_path.join("index");
    // INVARIANT: Abort snapshot capture if an existing Git index cannot be stat'd or copied so tracked gitignored files are never omitted.
    let mut copied_existing_index = false;
    match fs::metadata(&src_idx) {
        Ok(meta) => {
            if !meta.is_file() || fs::copy(&src_idx, &tmp_index).is_err() {
                return String::new();
            }
            copied_existing_index = true;
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(_) => return String::new(),
    }
    let tmp_index_str = tmp_index.to_string_lossy().into_owned();
    let extra_env = [("GIT_INDEX_FILE", tmp_index_str.as_str())];
    if copied_existing_index {
        let Ok((assume_paths, skip_paths)) =
            collect_masked_index_paths(git_root, timeout_sec, &extra_env)
        else {
            return String::new();
        };
        for (flag, list) in [
            ("--no-assume-unchanged", &assume_paths),
            ("--no-skip-worktree", &skip_paths),
        ] {
            if list.is_empty() {
                continue;
            }
            let mut stdin_buf: Vec<u8> = Vec::new();
            for p in list {
                stdin_buf.extend_from_slice(p.as_bytes());
                stdin_buf.push(0);
            }
            let (rc_unmask, _, _) = run_git_raw(
                git_root,
                &[
                    "-c",
                    "core.sparseCheckout=false",
                    "update-index",
                    flag,
                    "-z",
                    "--stdin",
                ],
                timeout_sec,
                Some(&stdin_buf),
                &extra_env,
            );
            if rc_unmask != 0 {
                return String::new();
            }
        }
    }
    let (rc1, _, _) = run_git_env(
        git_root,
        &["-c", "core.fsmonitor=false", "add", "-A"],
        timeout_sec,
        &extra_env,
    );
    if rc1 != 0 {
        return String::new();
    }
    let (rc2, tree_sha, _) = run_git_env(git_root, &["write-tree"], timeout_sec, &extra_env);
    if rc2 != 0 {
        return String::new();
    }
    tree_sha.trim().to_string()
}

pub fn capture_worktree_raw_digest(git_root: &str, timeout_sec: f64) -> String {
    // INVARIANT: Hash raw unfiltered on-disk bytes across all tracked and non-ignored files (`git ls-files -z`) so LF/CRLF changes outside `marker.paths` under `text eol=lf` or smudge/clean filters invalidate prior snapshots.
    if git_root.trim().is_empty() {
        return String::new();
    }
    let (rc, raw_out, _) = run_git_raw(
        git_root,
        &[
            "-c",
            "core.quotepath=false",
            "-c",
            "core.sparseCheckout=false",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
        timeout_sec,
        None,
        &[],
    );
    if rc != 0 {
        return String::new();
    }
    let mut rels: Vec<String> = raw_out
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    rels.sort();
    rels.dedup();
    let root = Path::new(git_root);
    let mut hasher = Sha256::new();
    for rel in &rels {
        hasher.update(rel.as_bytes());
        hasher.update(b"\0");
        let full = root.join(rel);
        match fs::symlink_metadata(&full) {
            Err(e) if e.kind() == ErrorKind::NotFound => {
                hasher.update(b"MISSING\0");
            }
            Err(_) => return String::new(),
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    hasher.update(b"SYMLINK\0");
                    if let Ok(tgt) = fs::read_link(&full) {
                        hasher.update(tgt.to_string_lossy().as_bytes());
                    }
                    hasher.update(b"\0");
                } else if meta.is_file() {
                    if meta.len() <= 32 * 1024 * 1024 {
                        let Ok(bytes) = fs::read(&full) else {
                            return String::new();
                        };
                        hasher.update(format!("FILE:{}\0", bytes.len()).as_bytes());
                        hasher.update(&bytes);
                    } else {
                        let mtime_ns = meta
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                            .map(|d| d.as_nanos())
                            .unwrap_or(0);
                        hasher.update(format!("LARGE:{}:{}\0", meta.len(), mtime_ns).as_bytes());
                    }
                } else {
                    hasher.update(b"OTHER\0");
                }
            }
        }
    }
    format!("{:x}", hasher.finalize())
}

pub fn mutation_stamp_path(session: &str) -> PathBuf {
    state_subdir(&["continuity", "stamps"]).join(format!("{}.stamp", safe_key(session, "default")))
}

pub fn bump_mutation_stamp(session: &str) -> i64 {
    if session.is_empty() || session == "unknown" {
        return 0;
    }
    let sp = mutation_stamp_path(session);
    let cur = read_mutation_stamp(session);
    let next = cur + 1;
    let _ = fs::write(&sp, format!("{}\n", next));
    next
}

pub fn read_mutation_stamp(session: &str) -> i64 {
    if session.is_empty() || session == "unknown" {
        return 0;
    }
    let sp = mutation_stamp_path(session);
    if !sp.is_file() {
        return 0;
    }
    fs::read_to_string(&sp)
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(0)
}

fn unquote_wrapped_inner(raw_inner: &str) -> String {
    let inner = raw_inner.trim();
    if inner.len() >= 2 && inner.starts_with('\'') && inner.ends_with('\'') {
        return inner[1..inner.len() - 1]
            .replace("''", "'")
            .trim()
            .to_string();
    }
    if inner.len() >= 2 && inner.starts_with('"') && inner.ends_with('"') {
        let replaced = inner[1..inner.len() - 1].replace("\"\"", "\"");
        let mut out = String::with_capacity(replaced.len());
        let mut chars = replaced.chars();
        while let Some(c) = chars.next() {
            if c == '`' {
                if let Some(next_c) = chars.next() {
                    out.push(next_c);
                } else {
                    out.push('`');
                }
            } else {
                out.push(c);
            }
        }
        return out.trim().to_string();
    }
    inner.to_string()
}

fn unwrap_tokenade_pass(s: &str) -> String {
    let re = tokenade_wrap_seg_re();
    let mut out = String::with_capacity(s.len());
    let mut pos: usize = 0;
    while pos < s.len() {
        let Some(caps) = re.captures_at(s, pos) else {
            break;
        };
        let Some(full) = caps.get(0) else {
            break;
        };
        let lead = caps.name("lead").map_or("", |m| m.as_str());
        let inner = caps.name("inner").map_or("", |m| m.as_str());
        let ws_tail_start = caps
            .name("ws_tail")
            .map_or_else(|| full.end(), |m| m.start());
        out.push_str(&s[pos..full.start()]);
        out.push_str(lead);
        out.push_str(&unquote_wrapped_inner(inner));
        if ws_tail_start <= pos {
            pos = full.end();
        } else {
            pos = ws_tail_start;
        }
    }
    if pos == 0 {
        return s.to_string();
    }
    out.push_str(&s[pos..]);
    out
}

pub fn unwrap_tokenade_command(cmd: &str) -> String {
    // INVARIANT: Unwrap Tokenade CLI wrappers so gate classification and destructive-command guards inspect the real payload.
    let mut s = leading_null_pipe_re()
        .replace(cmd.trim(), "")
        .into_owned();
    if !s.to_lowercase().contains("tokenade") {
        return s;
    }
    for _ in 0..3 {
        let nxt = unwrap_tokenade_pass(&s);
        if nxt == s {
            break;
        }
        s = leading_null_pipe_re()
            .replace(nxt.trim(), "")
            .into_owned();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_regexes_compile() {
        assert!(subagent_msg_re().is_match(
            "[Message] timestamp=2026-11-17T00:00:00Z sender=coord_1 priority=HIGH content=hi"
        ));
        assert!(swarm_board_wake_body_re().is_match("[swarm] new board message #133\n"));
        assert!(!swarm_board_wake_body_re().is_match("recorded on the board as #133"));
        assert!(swarm_wake_seq_re().is_match("recorded on the board as #42"));
        assert!(swarm_role_member_re().is_match("narrator-1"));
        assert!(swarm_role_member_re().is_match("Monitor"));
        assert!(bg_task_id_re().is_match("running as a background task with task id: task-abc"));
        assert!(safe_key_clean_re().is_match("a b/c"));
        assert!(safe_key_alnum_re().is_match("a-b"));
        assert!(compact_json_scalar_re().is_match("-42.5e1"));
        assert!(swarm_group_suffix_re().is_match("worker-2"));
        assert_eq!(
            extract_cd_prefix_or_git_c("Set-Location C:\\repo; git status"),
            (Some("C:\\repo".to_string()), None)
        );
        assert_eq!(
            extract_cd_prefix_or_git_c("git -C C:\\repo status"),
            (None, Some("C:\\repo".to_string()))
        );
        assert!(leading_null_pipe_re().is_match("$null | git status"));
        assert!(tokenade_wrap_seg_re().is_match("tokenade wrap 'git status'"));
    }

    #[test]
    fn test_decode_compact_step_args() {
        let mut steps = vec![json!({
            "step_index": 0,
            "tool_calls": [{
                "name": "run_command",
                "args": {
                    "CommandLine": "\"git status\"",
                    "WaitMsBeforeAsync": "5000",
                    "IsDaemon": "false",
                    "Extra": "{\"k\":[1,2]}"
                }
            }]
        })];
        decode_compact_step_args(&mut steps);
        let args = steps[0]["tool_calls"][0]["args"].as_object().unwrap();
        assert_eq!(args.get("CommandLine").unwrap(), &json!("git status"));
        assert_eq!(args.get("WaitMsBeforeAsync").unwrap(), &json!(5000));
        assert_eq!(args.get("IsDaemon").unwrap(), &json!(false));
        assert_eq!(args.get("Extra").unwrap(), &json!({"k": [1, 2]}));

        let mut already_decoded = vec![json!({
            "step_index": 0,
            "tool_calls": [{
                "name": "run_command",
                "args": {
                    "CommandLine": "\"git status\"",
                    "WaitMsBeforeAsync": 5000
                }
            }]
        })];
        let snapshot = already_decoded.clone();
        decode_compact_step_args(&mut already_decoded);
        assert_eq!(already_decoded, snapshot);
    }

    #[test]
    fn test_unwrap_tokenade_command() {
        assert_eq!(
            unwrap_tokenade_command("Set-Location C:\\repo; tokenade wrap 'git ''status'''"),
            "Set-Location C:\\repo;git 'status'"
        );
        assert_eq!(
            unwrap_tokenade_command(r#"$null | tokenade.exe exec-compact --shell pwsh "git ""diff"" `--stat""#),
            r#"git "diff" --stat"#
        );
        assert_eq!(
            unwrap_tokenade_command("tokenade wrap 'tokenade raw git status' | findstr M"),
            "git status | findstr M"
        );
        assert_eq!(
            unwrap_tokenade_command("echo tokenade wrap 'git status'"),
            "echo tokenade wrap 'git status'"
        );
        assert_eq!(
            unwrap_tokenade_command(
                "Set-Location 'C:\\repo'\r\n& 'C:/tools/tokenade.exe' wrap --shell powershell '$null | node scripts/validate.js'"
            ),
            "Set-Location 'C:\\repo'\r\n$null | node scripts/validate.js"
        );
    }

    #[test]
    fn test_is_unapproved_home_git_root() {
        let home = home_dir().to_string_lossy().into_owned();
        let sub = Path::new(&home)
            .join(".gemini")
            .join("antigravity")
            .join("scratch");
        let sub_str = sub.to_string_lossy().into_owned();
        assert!(is_unapproved_home_git_root(&sub_str, &home));
        assert!(!is_unapproved_home_git_root(&sub_str, ""));
        let other = Path::new(&home).join("projects").join("my-repo");
        assert!(!is_unapproved_home_git_root(
            &sub_str,
            &other.to_string_lossy()
        ));
    }

    #[test]
    fn test_mentions_and_normalize_path() {
        assert!(text_mentions_swarm_worker("@builder-rio check", "builder-rio"));
        assert!(text_mentions_swarm_worker("ping @builder now", "builder-1"));
        assert!(!text_mentions_swarm_worker("mail@builder-rio.com", "builder-rio"));
        assert!(!text_mentions_swarm_worker("@builder-rio-2", "builder-rio"));
        #[cfg(not(windows))]
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("//server/share/dir/"), "//server/share/dir");
        #[cfg(windows)]
        {
            assert_eq!(normalize_path("C:\\"), "c:/");
            assert_eq!(normalize_path("C:\\Users\\in\\"), "c:/Users/in");
        }
    }

    #[test]
    fn test_with_file_lock_timeout_and_broken_git_index_abort() {
        let base = env::temp_dir().join(format!("rio-lock-idx-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let lock_file = base.join("contended.lock");
        // INVARIANT: Rolling-upgrade `v1` (`HEAD`) file-existence lock (`<pid> <ts>`) blocks `v2` `with_file_lock`, AND `v2` `with_file_lock` creates `lock_path` so a concurrent `v1` `create_new(true)` gets `AlreadyExists`.
        fs::write(&lock_file, "99999 1795000000.0\n").unwrap();
        let acquired_vs_v1 = with_file_lock(&lock_file, 0.05, 300.0, |acq| acq);
        assert!(!acquired_vs_v1);
        let expired_v1_recovered = with_file_lock(&lock_file, 0.2, 0.0, |acq| {
            assert!(acq);
            let v1_try = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_file);
            assert!(v1_try.is_err());
            acq
        });
        assert!(expired_v1_recovered);
        assert!(!lock_file.exists());
        // INVARIANT: Crashed `v2` sentinel (`"v2 ..."`) is recovered immediately under `<lock_path>.k` even with large `stale_sec`, while a live `.k` holder blocks acquisition.
        fs::write(&lock_file, "v2 99999 1795000000.0\n").unwrap();
        assert!(with_file_lock(&lock_file, 0.2, 300.0, |acq| acq));
        let held_ext = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(kernel_companion_lock_path(&lock_file))
            .unwrap();
        held_ext.try_lock().unwrap();
        let acquired = with_file_lock(&lock_file, 0.05, 300.0, |acq| acq);
        assert!(!acquired);
        drop(held_ext);
        let recovered = with_file_lock(&lock_file, 0.2, 0.0, |acq| acq);
        assert!(recovered);
        let stamp_expired_v1 = |p: &Path| {
            fs::write(p, "11111 1000.0\n").unwrap();
            let old_ft = fs::FileTimes::new()
                .set_modified(std::time::SystemTime::now() - Duration::from_secs(120));
            File::options()
                .write(true)
                .open(p)
                .unwrap()
                .set_times(old_ft)
                .unwrap();
        };
        // INVARIANT: Deterministic lockstep pause test (Direction 1): `v1` checks `L_old` age (`> 30s`) and pauses right before `fs::remove_file`; while `v2` reclaims `L_old` and holds the critical section, `v1`'s resumed `fs::remove_file` MUST fail (`ERROR_SHARING_VIOLATION` on Windows, `EISDIR`/`EPERM` on Unix) and `v1`'s `create_new` MUST fail with `AlreadyExists`.
        let det_v1_pause = base.join("det-v1-paused-before-unlink.lock");
        stamp_expired_v1(&det_v1_pause);
        let v1_saw_stale = fs::metadata(&det_v1_pause)
            .unwrap()
            .modified()
            .unwrap()
            .elapsed()
            .unwrap()
            .as_secs_f64()
            > 30.0;
        assert!(v1_saw_stale);
        let det1_ok = with_file_lock(&det_v1_pause, 1.0, 30.0, |acq| {
            assert!(acq);
            assert!(fs::remove_file(&det_v1_pause).is_err());
            let v1_create = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&det_v1_pause);
            assert_eq!(v1_create.unwrap_err().kind(), ErrorKind::AlreadyExists);
            true
        });
        assert!(det1_ok);
        assert!(!det_v1_pause.exists());
        // INVARIANT: Deterministic lockstep pause test (Direction 2): `v1` replaces expired `L_old` with fresh `L_new` right before `v2` executes stale deletion; `L_new` MUST survive intact and block `v2`.
        let det_v2_pause = base.join("det-v2-paused-before-delete.lock");
        stamp_expired_v1(&det_v2_pause);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let h_old = OpenOptions::new()
                .read(true)
                .access_mode(0x8001_0000)
                .share_mode(7)
                .open(&det_v2_pause)
                .unwrap();
            fs::remove_file(&det_v2_pause).unwrap();
            let mut l_new = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&det_v2_pause)
                .unwrap();
            writeln!(l_new, "22222 {}", now_sec()).unwrap();
            drop(l_new);
            let _ = crate::win32_sqlite::delete_open_file_by_handle(&h_old);
            drop(h_old);
            assert!(det_v2_pause.is_file());
            assert!(fs::read_to_string(&det_v2_pause)
                .unwrap()
                .starts_with("22222 "));
            assert!(!with_file_lock(&det_v2_pause, 0.05, 300.0, |acq| acq));
            fs::remove_file(&det_v2_pause).unwrap();
        }
        stamp_expired_v1(&det_v2_pause);
        fs::remove_file(&det_v2_pause).unwrap();
        fs::write(&det_v2_pause, format!("33333 {}\n", now_sec())).unwrap();
        assert!(matches!(
            crate::win32_sqlite::try_reclaim_stale_legacy_lock(&det_v2_pause, 30.0),
            crate::win32_sqlite::LegacyLockReclaim::NotStale
        ));
        assert!(det_v2_pause.is_file());
        fs::remove_file(&det_v2_pause).unwrap();
        // INVARIANT: Deterministic Unix swap-slot tests: (a) `v1` replaces `L_old` with fresh `L_A` in the exact interval between `is_file_stale(lock_path)` and `exchange_fn`, proving rollback to `NotStale`; (b) `v2` crashes mid-swap after displacing fresh `L_A` into `<lock_path>.swap` while `lock_path` is a directory, proving the next `v2` rolls `L_A` back and returns `NotStale` instead of deleting the directory; (c) stale `L_old` is acquired cleanly (`AcquiredDir`) and crashed empty dir returns `ReclaimedRetry`.
        let unix_sim_lock = base.join("unix-swap-sim.lock");
        let sim_tmp = base.join("unix-swap-sim.tmp");
        let mock_exchange = |a: &Path, b: &Path| -> std::io::Result<()> {
            crate::win32_sqlite::simulated_exchange_paths(a, b, &sim_tmp)
        };
        stamp_expired_v1(&unix_sim_lock);
        assert!(matches!(
            crate::win32_sqlite::reclaim_unix_dir_lock_with_exchange(
                &unix_sim_lock,
                30.0,
                mock_exchange,
            ),
            crate::win32_sqlite::UnixDirReclaim::AcquiredDir
        ));
        assert!(unix_sim_lock.is_dir());
        assert!(matches!(
            crate::win32_sqlite::reclaim_unix_dir_lock_with_exchange(
                &unix_sim_lock,
                30.0,
                mock_exchange,
            ),
            crate::win32_sqlite::UnixDirReclaim::ReclaimedRetry
        ));
        assert!(!unix_sim_lock.exists());
        stamp_expired_v1(&unix_sim_lock);
        let mut injected_after_precheck = false;
        assert!(matches!(
            crate::win32_sqlite::reclaim_unix_dir_lock_with_exchange(
                &unix_sim_lock,
                30.0,
                |a, b| {
                    if !injected_after_precheck {
                        injected_after_precheck = true;
                        fs::remove_file(b)?;
                        fs::write(b, format!("44444 {}\n", now_sec()))?;
                    }
                    mock_exchange(a, b)
                },
            ),
            crate::win32_sqlite::UnixDirReclaim::NotStale
        ));
        assert!(unix_sim_lock.is_file());
        assert!(fs::read_to_string(&unix_sim_lock)
            .unwrap()
            .starts_with("44444 "));
        assert!(!crate::win32_sqlite::legacy_swap_path(&unix_sim_lock).exists());
        let sim_swap = crate::win32_sqlite::legacy_swap_path(&unix_sim_lock);
        fs::rename(&unix_sim_lock, &sim_swap).unwrap();
        fs::write(&unix_sim_lock, "v2-probe 999 1 1000.0\n").unwrap();
        assert!(matches!(
            crate::win32_sqlite::reclaim_unix_dir_lock_with_exchange(
                &unix_sim_lock,
                30.0,
                mock_exchange,
            ),
            crate::win32_sqlite::UnixDirReclaim::NotStale
        ));
        assert!(unix_sim_lock.is_file());
        assert!(fs::read_to_string(&unix_sim_lock)
            .unwrap()
            .starts_with("44444 "));
        assert!(!sim_swap.exists());
        fs::remove_file(&unix_sim_lock).unwrap();
        // INVARIANT: If `v1` finishes its critical section and calls `fs::remove_file(lock_path)` while its fresh lock `L_A` is in `<lock_path>.swap` during Phase-1 probe, `remove_file` succeeds on the regular probe file and `v2` deletes `L_A` (`ReclaimedRetry`) instead of restoring an orphaned lock.
        stamp_expired_v1(&unix_sim_lock);
        let mut release_during_probe_n = 0usize;
        assert!(matches!(
            crate::win32_sqlite::reclaim_unix_dir_lock_with_exchange(
                &unix_sim_lock,
                30.0,
                |a, b| {
                    release_during_probe_n += 1;
                    if release_during_probe_n == 1 {
                        fs::remove_file(b)?;
                        fs::write(b, format!("55555 {}\n", now_sec()))?;
                        mock_exchange(a, b)?;
                        fs::remove_file(b)?;
                        return Ok(());
                    }
                    mock_exchange(a, b)
                },
            ),
            crate::win32_sqlite::UnixDirReclaim::ReclaimedRetry
        ));
        assert!(!unix_sim_lock.exists());
        assert!(!sim_swap.exists());
        assert!(!crate::win32_sqlite::legacy_dir_stage_path(&unix_sim_lock).exists());
        // INVARIANT: Even if `v2` crashed during Phase 1 and dead `v1` (`999999999`) already exited after `fs::remove_file(lock_path)`, the next `v2` cleans `<lock_path>.swap` without restoring the dead lock.
        fs::write(&sim_swap, format!("999999999 {}\n", now_sec())).unwrap();
        assert!(matches!(
            crate::win32_sqlite::reclaim_unix_dir_lock_with_exchange(
                &unix_sim_lock,
                30.0,
                mock_exchange,
            ),
            crate::win32_sqlite::UnixDirReclaim::ReclaimedRetry
        ));
        assert!(!unix_sim_lock.exists());
        assert!(!sim_swap.exists());
        // INVARIANT: End-to-end `with_file_lock` test with FREE `lock_path` and an ACTIVE `v1` lock (`std::process::id()`) in `<lock_path>.swap`: `with_file_lock` reconciles `.swap` BEFORE `mkdir` / `create_legacy_lock_exclusive`, restores the active `v1` lock onto `lock_path`, and refuses concurrent entry (`acq == false`).
        let free_main_swap = crate::win32_sqlite::legacy_swap_path(&unix_sim_lock);
        fs::write(&free_main_swap, format!("{} {}\n", std::process::id(), now_sec())).unwrap();
        let entered_concurrently = with_file_lock(&unix_sim_lock, 0.08, 30.0, |acq| acq);
        assert!(!entered_concurrently);
        assert!(unix_sim_lock.is_file());
        assert!(!free_main_swap.exists());
        fs::remove_file(&unix_sim_lock).unwrap();
        // INVARIANT: If `v1` created `lock_path` via `O_EXCL` (0 bytes) and was displaced into `<lock_path>.swap` BEFORE writing its PID while `lock_path` became free, `with_file_lock` treats the empty fresh file as alive, restores its inode via `hard_link`, refuses concurrent entry, and preserves `v1`'s subsequent PID write through its open handle.
        let mut pending_v1_fh = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&free_main_swap)
            .unwrap();
        let entered_on_unwritten = with_file_lock(&unix_sim_lock, 0.08, 30.0, |acq| acq);
        assert!(!entered_on_unwritten);
        assert!(unix_sim_lock.is_file());
        assert!(!free_main_swap.exists());
        writeln!(pending_v1_fh, "{} {}", std::process::id(), now_sec()).unwrap();
        drop(pending_v1_fh);
        assert!(fs::read_to_string(&unix_sim_lock)
            .unwrap()
            .starts_with(&format!("{} ", std::process::id())));
        fs::remove_file(&unix_sim_lock).unwrap();
        // INVARIANT: If `lock_path` initially holds `v2-probe` when recovery starts (`restore_displaced_v1_lock` branch) and a delayed `v1` `unlink` removes `v2-probe` right before `exchange_fn` (`ErrorKind::NotFound`), `handle_missing_lock_with_slot` restores the live `v1` inode from `.swap` instead of deleting it and returns `NotStale`.
        let mut not_found_v1_fh = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&free_main_swap)
            .unwrap();
        fs::write(&unix_sim_lock, "v2-probe 999 7 0\n").unwrap();
        assert!(matches!(
            crate::win32_sqlite::reclaim_unix_dir_lock_with_exchange(
                &unix_sim_lock,
                30.0,
                |_a, b| {
                    let _ = fs::remove_file(b);
                    Err(std::io::Error::new(ErrorKind::NotFound, "delayed_unlink_during_exchange"))
                },
            ),
            crate::win32_sqlite::UnixDirReclaim::NotStale
        ));
        assert!(unix_sim_lock.is_file());
        assert!(!free_main_swap.exists());
        writeln!(not_found_v1_fh, "{} {}", std::process::id(), now_sec()).unwrap();
        drop(not_found_v1_fh);
        assert!(fs::read_to_string(&unix_sim_lock)
            .unwrap()
            .starts_with(&format!("{} ", std::process::id())));
        fs::remove_file(&unix_sim_lock).unwrap();
        // INVARIANT: Phase-2 crash recovery test: if `v2` crashes right after `exchange_fn(&dir_stage, lock_path)` when a paused `v1` had just replaced `probe` with fresh `L_B` (leaving `L_B` in `<lock_path>.dir` and a directory at `lock_path`), the next `v2` rolls `L_B` back to `lock_path`, removes `<lock_path>.dir`, and returns `NotStale` instead of deleting `lock_path`.
        let sim_dir_stage = crate::win32_sqlite::legacy_dir_stage_path(&unix_sim_lock);
        fs::write(&sim_dir_stage, format!("77777 {}\n", now_sec())).unwrap();
        fs::create_dir(&unix_sim_lock).unwrap();
        assert!(matches!(
            crate::win32_sqlite::reclaim_unix_dir_lock_with_exchange(
                &unix_sim_lock,
                30.0,
                mock_exchange,
            ),
            crate::win32_sqlite::UnixDirReclaim::NotStale
        ));
        assert!(unix_sim_lock.is_file());
        assert!(fs::read_to_string(&unix_sim_lock)
            .unwrap()
            .starts_with("77777 "));
        assert!(!sim_dir_stage.exists());
        fs::remove_file(&unix_sim_lock).unwrap();
        // INVARIANT: Phase-1 `.swap` crash recovery race test: if `v1_A` (`77770`) released `v2-probe` and `v1_B` (`88888`) acquired `lock_path` right before recovery's first `exchange_fn`, `restore_displaced_v1_lock` swaps `v1_B`'s active lock back onto `lock_path` instead of deleting `v1_B` or leaving `v1_A` in place.
        fs::write(&sim_swap, format!("77770 {}\n", now_sec())).unwrap();
        fs::write(&unix_sim_lock, "v2-probe 999 0 0\n").unwrap();
        let mut swap_rec_step = 0usize;
        assert!(matches!(
            crate::win32_sqlite::reclaim_unix_dir_lock_with_exchange(
                &unix_sim_lock,
                30.0,
                |a, b| {
                    swap_rec_step += 1;
                    if swap_rec_step == 1 {
                        fs::remove_file(b)?;
                        fs::write(b, format!("88888 {}\n", now_sec()))?;
                    }
                    mock_exchange(a, b)
                },
            ),
            crate::win32_sqlite::UnixDirReclaim::NotStale
        ));
        assert!(unix_sim_lock.is_file());
        assert!(fs::read_to_string(&unix_sim_lock)
            .unwrap()
            .starts_with("88888 "));
        assert!(!sim_swap.exists());
        assert!(!crate::win32_sqlite::legacy_undo_path(&unix_sim_lock).exists());
        fs::remove_file(&unix_sim_lock).unwrap();
        // INVARIANT: Double-crash `.swap` + `.undo` recovery test: if `v2` crashes right AFTER its first `exchange_fn` placed dead `v1_A` (`77771`) onto `lock_path` and moved active `v1_B` (`88889`) into `.swap` (before the undo swap can run), the next `v2` sees `undo_rank(v1_B) > undo_rank(v1_A)`, swaps `v1_B` back onto `lock_path`, and removes `v1_A` + `.undo`.
        let sim_undo = crate::win32_sqlite::legacy_undo_path(&unix_sim_lock);
        fs::write(&sim_swap, format!("77771 {}\n", now_sec())).unwrap();
        fs::write(&unix_sim_lock, "v2-probe 999 1 0\n").unwrap();
        let mut crash_mid_undo_step = 0usize;
        assert!(matches!(
            crate::win32_sqlite::reclaim_unix_dir_lock_with_exchange(
                &unix_sim_lock,
                30.0,
                |a, b| {
                    crash_mid_undo_step += 1;
                    if crash_mid_undo_step == 1 {
                        fs::remove_file(b)?;
                        fs::write(b, format!("88889 {}\n", now_sec()))?;
                        return mock_exchange(a, b);
                    }
                    Err(std::io::Error::new(ErrorKind::Interrupted, "simulated_sigkill_before_undo"))
                },
            ),
            crate::win32_sqlite::UnixDirReclaim::NotStale
        ));
        assert!(fs::read_to_string(&unix_sim_lock).unwrap().starts_with("77771 "));
        assert!(fs::read_to_string(&sim_swap).unwrap().starts_with("88889 "));
        assert!(sim_undo.is_file());
        assert!(matches!(
            crate::win32_sqlite::reclaim_unix_dir_lock_with_exchange(
                &unix_sim_lock,
                30.0,
                mock_exchange,
            ),
            crate::win32_sqlite::UnixDirReclaim::NotStale
        ));
        assert!(unix_sim_lock.is_file());
        assert!(fs::read_to_string(&unix_sim_lock)
            .unwrap()
            .starts_with("88889 "));
        assert!(!sim_swap.exists());
        assert!(!sim_undo.exists());
        fs::remove_file(&unix_sim_lock).unwrap();
        // INVARIANT: Exercise simultaneous `v1` (`HEAD`) stale-lock recovery + `v2` stale-lock recovery over an expired `L_old` lock protecting a shared JSON card across 12 rounds (1 `v1` thread + 3 `v2` threads), proving `max_concurrent == 1` and zero lost card updates.
        let mixed_lock = base.join("mixed-v1-v2-stale.lock");
        let shared_card = base.join("chips-card.json");
        write_json(&shared_card, &json!({"updates": 0})).unwrap();
        let mixed_active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mixed_max = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for _ in 0..12 {
            stamp_expired_v1(&mixed_lock);
            let round_bar = std::sync::Arc::new(std::sync::Barrier::new(4));
            let mut round_handles = Vec::new();
            {
                let ml = mixed_lock.clone();
                let sc = shared_card.clone();
                let rb = std::sync::Arc::clone(&round_bar);
                let act = std::sync::Arc::clone(&mixed_active);
                let mx = std::sync::Arc::clone(&mixed_max);
                round_handles.push(thread::spawn(move || {
                    rb.wait();
                    let dl = Instant::now() + Duration::from_secs(3);
                    let mut v1_acq = false;
                    while Instant::now() < dl {
                        match OpenOptions::new().write(true).create_new(true).open(&ml) {
                            Ok(mut fh) => {
                                let _ = writeln!(fh, "{} {}", std::process::id(), now_sec());
                                v1_acq = true;
                                break;
                            }
                            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                                if fs::metadata(&ml)
                                    .and_then(|m| m.modified())
                                    .ok()
                                    .and_then(|mt| mt.elapsed().ok())
                                    .is_some_and(|age| age.as_secs_f64() > 30.0)
                                {
                                    let _ = fs::remove_file(&ml);
                                    continue;
                                }
                                thread::sleep(Duration::from_millis(8));
                            }
                            Err(_) => thread::sleep(Duration::from_millis(8)),
                        }
                    }
                    assert!(v1_acq);
                    let cur = act.fetch_add(1, Ordering::SeqCst) + 1;
                    mx.fetch_max(cur, Ordering::SeqCst);
                    let prev_n = read_json(&sc)
                        .and_then(|v| v.get("updates").and_then(|x| x.as_i64()))
                        .unwrap_or(0);
                    thread::sleep(Duration::from_millis(4));
                    write_json(&sc, &json!({"updates": prev_n + 1})).unwrap();
                    act.fetch_sub(1, Ordering::SeqCst);
                    let _ = fs::remove_file(&ml);
                }));
            }
            for _ in 0..3 {
                let ml = mixed_lock.clone();
                let sc = shared_card.clone();
                let rb = std::sync::Arc::clone(&round_bar);
                let act = std::sync::Arc::clone(&mixed_active);
                let mx = std::sync::Arc::clone(&mixed_max);
                round_handles.push(thread::spawn(move || {
                    rb.wait();
                    with_file_lock(&ml, 3.0, 30.0, |acq| {
                        assert!(acq);
                        let cur = act.fetch_add(1, Ordering::SeqCst) + 1;
                        mx.fetch_max(cur, Ordering::SeqCst);
                        let prev_n = read_json(&sc)
                            .and_then(|v| v.get("updates").and_then(|x| x.as_i64()))
                            .unwrap_or(0);
                        thread::sleep(Duration::from_millis(4));
                        write_json(&sc, &json!({"updates": prev_n + 1})).unwrap();
                        act.fetch_sub(1, Ordering::SeqCst);
                    });
                }));
            }
            for rh in round_handles {
                rh.join().unwrap();
            }
        }
        assert_eq!(mixed_max.load(Ordering::SeqCst), 1);
        assert_eq!(
            read_json(&shared_card).unwrap()["updates"],
            json!(48)
        );
        let race_lock = base.join("race-8threads.lock");
        let bar = std::sync::Arc::new(std::sync::Barrier::new(8));
        let active_in_cs = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let max_in_cs = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let entered_total = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let rl = race_lock.clone();
            let b = std::sync::Arc::clone(&bar);
            let act = std::sync::Arc::clone(&active_in_cs);
            let mx = std::sync::Arc::clone(&max_in_cs);
            let tot = std::sync::Arc::clone(&entered_total);
            handles.push(thread::spawn(move || {
                b.wait();
                with_file_lock(&rl, 3.0, 0.0, |acq| {
                    assert!(acq);
                    let cur = act.fetch_add(1, Ordering::SeqCst) + 1;
                    mx.fetch_max(cur, Ordering::SeqCst);
                    tot.fetch_add(1, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(12));
                    act.fetch_sub(1, Ordering::SeqCst);
                });
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(entered_total.load(Ordering::SeqCst), 8);
        assert_eq!(max_in_cs.load(Ordering::SeqCst), 1);

        // INVARIANT: While `with_file_lock` is executing in `.lock_epoch = "v1"` mode (including before `O_EXCL` completes while waiting on an existing `v1` lock), `.v2_alive.lease` `LOCK_SH` stays held so `LOCK_EX` epoch clear cannot race `with_legacy_v1_file_lock`.
        let epoch_state = base.join("epoch-sync").join("state");
        fs::create_dir_all(epoch_state.join("chips")).unwrap();
        fs::write(lock_epoch_path(&epoch_state), "v1\n").unwrap();
        let contended_v1 = epoch_state.join("chips").join("sync.lock");
        fs::write(&contended_v1, format!("{} {}\n", std::process::id(), now_sec())).unwrap();
        let contended_v1_bg = contended_v1.clone();
        let entered_v1_wait = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let entered_v1_wait_bg = std::sync::Arc::clone(&entered_v1_wait);
        let bg_v1_caller = thread::spawn(move || {
            with_file_lock(&contended_v1_bg, 2.0, 30.0, |ok| {
                assert!(ok);
                entered_v1_wait_bg.store(true, Ordering::SeqCst);
            });
        });
        thread::sleep(Duration::from_millis(45));
        let ex_fh = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(v2_lease_path(&epoch_state))
            .unwrap();
        // INVARIANT: Even BEFORE `bg_v1_caller` acquires `contended_v1` (`O_EXCL` waiting on `AlreadyExists`), `bg_v1_caller` already holds `LOCK_SH` on `.v2_alive.lease`, blocking `LOCK_EX`.
        assert!(ex_fh.try_lock().is_err());
        fs::remove_file(&contended_v1).unwrap();
        bg_v1_caller.join().unwrap();
        assert!(entered_v1_wait.load(Ordering::SeqCst));
        assert!(ex_fh.try_lock().is_ok());
        let _ = ex_fh.unlock();

        let repo = base.join("repo");
        fs::create_dir_all(&repo).unwrap();
        let repo_s = repo.to_string_lossy().into_owned();
        let (rc, _, _) = run_git(&repo_s, &["init"], 5.0);
        if rc == 0 {
            let _ = run_git(&repo_s, &["config", "user.email", "t@example.com"], 5.0);
            let _ = run_git(&repo_s, &["config", "user.name", "Test"], 5.0);
            fs::write(repo.join("tracked.txt"), "v1\n").unwrap();
            let _ = run_git(&repo_s, &["add", "tracked.txt"], 5.0);
            let _ = run_git(&repo_s, &["commit", "-m", "init"], 5.0);
            let idx_file = repo.join(".git").join("index");
            let idx_bak = repo.join(".git").join("index.bak");
            fs::rename(&idx_file, &idx_bak).unwrap();
            // INVARIANT: Replacing `.git/index` with a directory causes copy/meta check to fail and abort snapshot capture.
            fs::create_dir_all(&idx_file).unwrap();
            assert_eq!(capture_worktree_tree_oid(&repo_s, 5.0), "");
            let _ = fs::remove_dir_all(&idx_file);
            let _ = fs::rename(&idx_bak, &idx_file);

            // INVARIANT: `capture_worktree_raw_digest` hashes unfiltered working-tree bytes so LF->CRLF changes masked by `text eol=lf` in `capture_worktree_tree_oid` still flip the raw digest.
            fs::write(repo.join(".gitattributes"), "*.txt text eol=lf\n").unwrap();
            fs::write(repo.join("tracked.txt"), "line1\nline2\n").unwrap();
            let _ = run_git(&repo_s, &["add", ".gitattributes", "tracked.txt"], 5.0);
            let _ = run_git(&repo_s, &["commit", "-m", "eol lf"], 5.0);
            let tree_lf = capture_worktree_tree_oid(&repo_s, 5.0);
            let raw_lf = capture_worktree_raw_digest(&repo_s, 5.0);
            assert!(!tree_lf.is_empty() && !raw_lf.is_empty());
            fs::write(repo.join("tracked.txt"), "line1\r\nline2\r\n").unwrap();
            let raw_crlf = capture_worktree_raw_digest(&repo_s, 5.0);
            assert_ne!(raw_lf, raw_crlf);
        }
        // INVARIANT: `extract_bg_task_id` only accepts host preambles before `Command output:` / `Command exited with code` / `Log output:`, blocking child stdout spoofing.
        assert_eq!(
            extract_bg_task_id(
                "Tool is running as a background task with task id: sess-1/task-42\nTask logs are available at: file:///tmp/t.log\nLog output:\nstarting...\n"
            ),
            Some("sess-1/task-42".to_string())
        );
        assert_eq!(
            extract_bg_task_id(
                "Command exited with code 1.\n\nCommand output:\nTool is running as a background task with task id: sess-1/task-999\nBackgrounded with ID: task-999\n"
            ),
            None
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_log_hook_event_blocked_on_prod_home_in_tests() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev = env::var_os("CARBON_STACK_HOME");
        let prod_log = home_dir()
            .join(".gemini")
            .join("carbon-stack")
            .join("state")
            .join("logs")
            .join("test-iso-prod-guard.jsonl");
        let prod_before = fs::metadata(&prod_log).map(|m| m.len()).unwrap_or(0);

        unsafe { env::remove_var("CARBON_STACK_HOME") };
        log_hook_event("test-iso-prod-guard", "should_ignore", json!({"n": 1}));
        let prod_dir = home_dir().join(".gemini").join("carbon-stack");
        unsafe { env::set_var("CARBON_STACK_HOME", &prod_dir) };
        log_hook_event("test-iso-prod-guard", "should_ignore_prod", json!({"n": 2}));

        assert_eq!(
            fs::metadata(&prod_log).map(|m| m.len()).unwrap_or(0),
            prod_before
        );

        let tmp_home = env::temp_dir().join(format!("carbon-rio-iso-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp_home);
        unsafe { env::set_var("CARBON_STACK_HOME", &tmp_home) };
        log_hook_event("test-iso", "allowed_in_tmp", json!({"ok": true}));
        let tmp_log = tmp_home.join("state").join("logs").join("test-iso.jsonl");
        let content = fs::read_to_string(&tmp_log).unwrap();
        assert!(content.contains("allowed_in_tmp"));

        match prev {
            Some(v) => unsafe { env::set_var("CARBON_STACK_HOME", v) },
            None => unsafe { env::remove_var("CARBON_STACK_HOME") },
        }
        let _ = fs::remove_dir_all(&tmp_home);
    }

    #[test]
    fn test_last_user_input_step_tail_scan_and_source_preference() {
        let base = env::temp_dir().join(format!("rio-last-user-input-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        assert_eq!(last_user_input_step(""), None);
        assert_eq!(
            last_user_input_step(&base.join("missing.jsonl").to_string_lossy()),
            None
        );

        let empty_tp = base.join("empty.jsonl");
        fs::write(&empty_tp, "").unwrap();
        assert_eq!(last_user_input_step(&empty_tp.to_string_lossy()), None);

        // Single-line file with BOM and no trailing newline.
        let single_tp = base.join("single.jsonl");
        fs::write(
            &single_tp,
            "\u{feff}{\"step_index\":0,\"type\":\"USER_INPUT\",\"content\":\"привет мир\"}",
        )
        .unwrap();
        assert_eq!(
            last_user_input_step(&single_tp.to_string_lossy()),
            Some((0, "привет мир".to_string()))
        );
        // Exercise tiny odd chunk sizes crossing multi-byte UTF-8 boundaries.
        assert_eq!(
            last_user_input_step_from_file(&single_tp, 7),
            Some((0, "привет мир".to_string()))
        );

        // Prefer USER_EXPLICIT over a later non-explicit USER_INPUT; ignore GENERIC mentioning USER_INPUT.
        let pref_tp = base.join("pref.jsonl");
        let pref_lines = [
            json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "content": "turn zero"}).to_string(),
            json!({"step_index": 5, "source": "USER_EXPLICIT", "type": "USER_INPUT", "content": "turn five"}).to_string(),
            json!({"step_index": 8, "source": "SYSTEM", "type": "USER_INPUT", "content": "synthetic"}).to_string(),
            json!({"step_index": 9, "source": "SYSTEM", "type": "GENERIC", "content": "mentions USER_INPUT in stdout"}).to_string(),
        ];
        fs::write(&pref_tp, pref_lines.join("\r\n") + "\r\n").unwrap();
        assert_eq!(
            last_user_input_step(&pref_tp.to_string_lossy()),
            Some((5, "turn five".to_string()))
        );
        assert_eq!(
            last_user_input_step_from_file(&pref_tp, 17),
            Some((5, "turn five".to_string()))
        );

        // Fallback when only non-explicit USER_INPUT exists.
        let fb_tp = base.join("fallback.jsonl");
        let fb_lines = [
            json!({"step_index": 2, "source": "SYSTEM", "type": "USER_INPUT", "content": "first"}).to_string(),
            json!({"step_index": 7, "source": "USER_QUEUED", "type": "USER_INPUT", "content": "latest fallback"}).to_string(),
        ];
        fs::write(&fb_tp, fb_lines.join("\n") + "\n").unwrap();
        assert_eq!(
            last_user_input_step(&fb_tp.to_string_lossy()),
            Some((7, "latest fallback".to_string()))
        );

        // Multi-chunk (>200 KiB, >500 trailing steps) transcript where USER_INPUT sits far behind EOF.
        let big_tp = base.join("big.jsonl");
        let mut big_body = String::new();
        big_body.push_str(
            &json!({"step_index": 3, "source": "USER_EXPLICIT", "type": "USER_INPUT", "content": "deep turn"})
                .to_string(),
        );
        big_body.push('\n');
        let pad = "x".repeat(420);
        for i in 4..540i64 {
            big_body.push_str(
                &json!({"step_index": i, "source": "MODEL", "type": "GENERIC", "content": pad.as_str()})
                    .to_string(),
            );
            big_body.push('\n');
        }
        assert!(big_body.len() > 200 * 1024);
        fs::write(&big_tp, &big_body).unwrap();
        assert_eq!(
            last_user_input_step(&big_tp.to_string_lossy()),
            Some((3, "deep turn".to_string()))
        );
        assert_eq!(strip_user_request_wrapper("plain prompt"), "plain prompt");
        assert_eq!(
            strip_user_request_wrapper("<USER_REQUEST>\nFix bug\n</USER_REQUEST>"),
            "Fix bug"
        );
        assert_eq!(
            strip_user_request_wrapper(
                "<CONTEXT_SUMMARY>old</CONTEXT_SUMMARY>\n<USER_REQUEST>\nReal task\n</USER_REQUEST>\n<ADDITIONAL_METADATA>\nlocal time\n</ADDITIONAL_METADATA>"
            ),
            "Real task"
        );

        // Append a new USER_INPUT near EOF and verify tail scan picks it up immediately.
        big_body.push_str(
            &json!({"step_index": 540, "source": "USER_EXPLICIT", "type": "USER_INPUT", "content": "tail turn"})
                .to_string(),
        );
        big_body.push('\n');
        fs::write(&big_tp, &big_body).unwrap();
        assert_eq!(
            last_user_input_step(&big_tp.to_string_lossy()),
            Some((540, "tail turn".to_string()))
        );

        // Sibling `transcript_full.jsonl` preference via `resolve_transcript_path`.
        let sib_dir = base.join("sib");
        fs::create_dir_all(&sib_dir).unwrap();
        let compact = sib_dir.join("transcript.jsonl");
        let full = sib_dir.join("transcript_full.jsonl");
        fs::write(
            &compact,
            "{\"step_index\":1,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"compact\"}\n",
        )
        .unwrap();
        fs::write(
            &full,
            "{\"step_index\":1,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"full untruncated\"}\n",
        )
        .unwrap();
        assert_eq!(
            last_user_input_step(&compact.to_string_lossy()),
            Some((1, "full untruncated".to_string()))
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_extract_cd_prefix_and_git_c_powershell_preamble_and_vars() {
        assert_eq!(
            extract_cd_prefix_or_git_c(
                r#"$ErrorActionPreference = 'Stop'; Push-Location "C:\repo\wt"; npm test"#
            ),
            (Some(r"C:\repo\wt".to_string()), None)
        );
        assert_eq!(
            extract_cd_prefix_or_git_c(
                r#"$ErrorActionPreference = 'Stop'; $env:QA_OUT = "C:\out"; Push-Location "C:\repo\wt\panel"; npx playwright test"#
            ),
            (Some(r"C:\repo\wt\panel".to_string()), None)
        );
        assert_eq!(
            extract_cd_prefix_or_git_c(
                r#"$wt = "C:\repo\wt"; git -C $wt grep -n foo"#
            ),
            (None, Some(r"C:\repo\wt".to_string()))
        );
        assert_eq!(
            extract_cd_prefix_or_git_c(
                r#"$ErrorActionPreference = 'Continue'; $wt = 'C:\repo\O''Connor\wt'; Write-Output "=== run ==="; Push-Location "$wt\panel"; npm test"#
            ),
            (Some(r"C:\repo\O'Connor\wt\panel".to_string()), None)
        );
        assert_eq!(
            extract_cd_prefix_or_git_c(r"git -C C:\repo status"),
            (None, Some(r"C:\repo".to_string()))
        );
        assert_eq!(
            extract_cd_prefix_or_git_c(r#"git reset --hard; Push-Location "C:\clean""#),
            (None, None)
        );
        assert_eq!(
            extract_cd_prefix_or_git_c(r"git reset --hard; git -C C:\clean status"),
            (None, None)
        );
        assert_eq!(
            extract_cd_prefix_or_git_c(r#"$wt = 'C:\repo\wt'; Push-Location '$wt'; npm test"#),
            (Some("$wt".to_string()), None)
        );
        assert_eq!(
            extract_cd_prefix_or_git_c(r#"$wt = $(whoami); Push-Location $wt; npm test"#),
            (None, None)
        );
        // R1 #1: parenthesized expression inside Write-Output can mutate parent repo and must stop preamble.
        assert_eq!(
            extract_cd_prefix_or_git_c(
                r#"Write-Output (New-Item -Path '.\src\generated.ts' -ItemType File); Push-Location '.\codex-worktrees\fix'; npm test"#
            ),
            (None, None)
        );
        // R1 #2: read-only git without -C must not mask a following mutating git -C, while redirected/mutating git still stops scan.
        assert_eq!(
            extract_cd_prefix_or_git_c(
                r#"git status; git -C .\codex-worktrees\fix apply C:\patches\fix.patch"#
            ),
            (None, Some(r".\codex-worktrees\fix".to_string()))
        );
        assert_eq!(
            extract_cd_prefix_or_git_c(r#"git status > out.txt; git -C .\codex-worktrees\fix status"#),
            (None, None)
        );
        // R2 #2: any non-preamble non-git statement after read-only git stops -C search so parent writes are not masked.
        assert_eq!(
            extract_cd_prefix_or_git_c(
                r#"git status; Set-Content .\src\settings.ts $content; git -C .\codex-worktrees\fix status"#
            ),
            (None, None)
        );
        // R3 #2: pure read-only inspection commands (e.g. Get-Location) without shell meta allow subsequent git -C / Push-Location.
        assert_eq!(
            extract_cd_prefix_or_git_c(
                r#"Get-Location; git -C .\codex-worktrees\fix apply C:\patches\fix.patch"#
            ),
            (None, Some(r".\codex-worktrees\fix".to_string()))
        );
        assert_eq!(
            extract_cd_prefix_or_git_c(
                r#"Get-Location > loc.txt; git -C .\codex-worktrees\fix apply C:\patches\fix.patch"#
            ),
            (None, None)
        );
        // Closure Pass 1 #1: built-in PowerShell/POSIX `pwd` (`Get-Location`) allows following `git -C` when free of shell meta, and stops on redirection.
        assert_eq!(
            extract_cd_prefix_or_git_c(
                r#"pwd; git -C .\codex-worktrees\fix apply C:\patches\fix.patch"#
            ),
            (None, Some(r".\codex-worktrees\fix".to_string()))
        );
        assert_eq!(
            extract_cd_prefix_or_git_c(
                r#"pwd > loc.txt; git -C .\codex-worktrees\fix apply C:\patches\fix.patch"#
            ),
            (None, None)
        );
        // R4 #2: external binaries (`rg --pre`, `whoami`), execution-sensitive `$env:` vars, and PowerShell here-strings must NEVER be treated as safe preamble.
        assert_eq!(
            extract_cd_prefix_or_git_c(
                r#"rg --pre evil.cmd pattern .; git -C .\codex-worktrees\fix status"#
            ),
            (None, None)
        );
        assert_eq!(
            extract_cd_prefix_or_git_c(r#"whoami; git -C .\codex-worktrees\fix status"#),
            (None, None)
        );
        assert_eq!(
            extract_cd_prefix_or_git_c(
                r#"$env:PATH = '.\evil'; git status; git -C .\codex-worktrees\fix status"#
            ),
            (None, None)
        );
        assert_eq!(
            extract_cd_prefix_or_git_c(
                "Write-Output @\"\n\"'$(New-Item evil)'\"\n\"@; Push-Location '.\\codex-worktrees\\fix'"
            ),
            (None, None)
        );
        // R1 #3: non-ASCII PowerShell variable names must never panic on UTF-8 slicing.
        assert_eq!(
            extract_cd_prefix_or_git_c(r#"$aПуть = 'C:\repo\worktree'; Push-Location $aПуть"#),
            (None, None)
        );
        assert_eq!(
            extract_cd_prefix_or_git_c(r#"$wt = 'C:\repo\папка'; Push-Location $wt"#),
            (Some(r"C:\repo\папка".to_string()), None)
        );
    }
}
