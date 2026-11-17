use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

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

fn subagent_msg_re() -> &'static Regex {
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
        Regex::new(r"(?i)running as a background task with task id:\s*(\S+)")
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

fn cd_leading_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)^\s*(?:cd(?:\s+/d)?|Set-Location|Push-Location)\s+["']?(?P<dir>[^"';&|\r\n]+)["']?"#,
        )
        .expect("cd_leading_re")
    })
}

fn git_dash_c_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\bgit(?:\.exe)?\s+-C\s+["']?(?P<dir>[^"';&|\r\n]+)["']?"#)
            .expect("git_dash_c_re")
    })
}

fn leading_null_pipe_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\A\s*\$null\s*\|\s*").expect("leading_null_pipe_re"))
}

fn tokenade_wrap_seg_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?P<lead>\A|[;\r\n|&])\s*(?:\$null\s*\|\s*)?(?:&\s*)?(?:'(?:''|[^'\r\n])*tokenade(?:\.cmd|\.exe)?'|"[^"`$\r\n]*tokenade(?:\.cmd|\.exe)?"|[^\s|;&"'`$()\r\n]*tokenade(?:\.cmd|\.exe)?)\s+(?:wrap|exec-compact|raw|bypass|noproxy|shellwrap)\b(?:\s+--shell\s+[A-Za-z0-9_.-]+)?\s+(?P<inner>'(?:''|[^'])*'|"(?:`[\s\S]|""|[^"`])*"|[^|;&"'\r\n]+?)(?P<ws_tail>\s*)(?:[;\r\n|&]|\z)"#,
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

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
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
            if cand.join("hooks").is_dir() || cand.is_dir() {
                return resolve_abs_path(&cand);
            }
        }
    }
    if let Ok(cwd) = env::current_dir() {
        for anc in cwd.ancestors() {
            let cand = anc.join("plugin");
            if cand.join("hooks").is_dir() {
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

pub fn write_json(path: &Path, data: &Value) -> Result<(), String> {
    let payload = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
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
            Err(e) => return Err(e.to_string()),
        }
    }
    let mut fh = tmp_file.ok_or_else(|| "failed to allocate temp file".to_string())?;
    let write_res = fh.write_all(payload.as_bytes()).and_then(|_| fh.flush());
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

struct LockGuard<'a> {
    path: &'a Path,
    acquired: bool,
}

impl Drop for LockGuard<'_> {
    fn drop(&mut self) {
        if self.acquired {
            let _ = fs::remove_file(self.path);
        }
    }
}

pub fn with_file_lock<T, F: FnOnce(bool) -> T>(
    lock_path: &Path,
    timeout_sec: f64,
    stale_sec: f64,
    f: F,
) -> T {
    if let Some(parent) = lock_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let _ = fs::create_dir_all(parent);
    }
    let deadline = Instant::now() + Duration::from_secs_f64(timeout_sec.max(0.0));
    let mut acquired = false;
    while Instant::now() < deadline {
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
                if let Ok(meta) = fs::metadata(lock_path) {
                    if let Ok(modified) = meta.modified() {
                        if let Ok(age) = modified.elapsed() {
                            if age.as_secs_f64() > stale_sec {
                                let _ = fs::remove_file(lock_path);
                                continue;
                            }
                        }
                    }
                }
                thread::sleep(Duration::from_millis(30));
            }
            Err(_) => break,
        }
    }
    let _guard = LockGuard {
        path: lock_path,
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
    let Some(Value::Object(doc)) = read_json(&path) else {
        return Map::new();
    };
    if let Some(Value::Object(members)) = doc.get("members") {
        return members.clone();
    }
    doc
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

fn json_truthy(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map_or(false, |x| x != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(m)) => !m.is_empty(),
        _ => false,
    }
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

pub fn is_swarm_worker_session(
    transcript_path: &str,
    steps: Option<&[Value]>,
    conversation_id: &str,
) -> bool {
    swarm_worker_model(transcript_path, steps, conversation_id).is_some()
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

pub fn extract_bg_task_id(text: &str) -> Option<String> {
    bg_task_id_re()
        .captures(text)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

pub fn extract_cd_prefix_or_git_c(cmd: &str) -> (Option<String>, Option<String>) {
    let cd_dir = cd_leading_re()
        .captures(cmd)
        .and_then(|c| c.name("dir"))
        .map(|m| m.as_str().trim().to_string())
        .filter(|s| !s.is_empty());
    let git_c_dir = git_dash_c_re()
        .captures(cmd)
        .and_then(|c| c.name("dir"))
        .map(|m| m.as_str().trim().to_string())
        .filter(|s| !s.is_empty());
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

fn run_git_env(
    cwd: &str,
    args: &[&str],
    timeout_sec: f64,
    extra_env: &[(&str, &str)],
) -> (i32, String, String) {
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
    match run_command_with_job("git", &full_args, cwd_opt, &env_pairs, None, Some(timeout_ms)) {
        Ok(res) => {
            if res.timed_out {
                (124, String::new(), format!("git_timeout_after_{}s", eff_to))
            } else {
                (res.code, res.stdout_str(), res.stderr_str())
            }
        }
        Err(e) => (127, String::new(), e),
    }
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
        // SAFETY: Never climb from a non-git subdirectory (`~/.gemini/antigravity/scratch/...`, `%TEMP%`, etc.) into a stray `$HOME/.git`, which would scan the entire user profile.
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
    // SAFETY: Abort snapshot capture if an existing Git index cannot be stat'd or copied so tracked gitignored files are never omitted.
    match fs::metadata(&src_idx) {
        Ok(meta) => {
            if !meta.is_file() || fs::copy(&src_idx, &tmp_index).is_err() {
                return String::new();
            }
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(_) => return String::new(),
    }
    let tmp_index_str = tmp_index.to_string_lossy().into_owned();
    let extra_env = [("GIT_INDEX_FILE", tmp_index_str.as_str())];
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
    // SAFETY: Unwrap Tokenade CLI wrappers so gate classification and destructive-command guards inspect the real payload.
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
        assert!(cd_leading_re().is_match("Set-Location C:\\repo; git status"));
        assert!(git_dash_c_re().is_match("git -C C:\\repo status"));
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
        fs::write(&lock_file, "held\n").unwrap();
        let acquired = with_file_lock(&lock_file, 0.05, 300.0, |acq| acq);
        assert!(!acquired);

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
        }
        let _ = fs::remove_dir_all(&base);
    }
}
