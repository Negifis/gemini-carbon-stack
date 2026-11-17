use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cwg_common;
use crate::rio;
use crate::win32_sqlite::{now_sec, run_command_with_job};

pub const BREAKER_TTL_SECONDS: i64 = 1800;
pub const DEFAULT_REVIEW_TIMEOUT_SEC: i64 = 600;
pub const DEFAULT_REVIEW_TIMEOUT_SECONDS: i64 = 600;
pub const DEFAULT_XHIGH_REVIEW_TIMEOUT_SECONDS: i64 = 900;
pub const TIMEOUT_STEP_SECONDS: i64 = 300;
pub const MAX_REVIEW_TIMEOUT_SECONDS: i64 = 1800;
pub const PACKET_TTL_SECONDS: f64 = 86400.0;
pub const MAX_DIFF_SNAPSHOT_CHARS: usize = 160_000;

pub const NATIVE_REVIEWERS: &[&str] = &["adversarial-reviewer", "adversarial-reviewer-xhigh"];
const XHIGH_NATIVE_REVIEWER: &str = "adversarial-reviewer-xhigh";
const JSONL_EVENT_PREFIXES: &[&str] = &["thread.", "turn.", "item."];
pub const REVIEW_VAL_FLAGS: &[&str] = &[
    "--cwd",
    "--summary",
    "--diff-file",
    "--review-id",
    "--session",
    "--model",
    "--resume",
    "--timeout",
    "--phase",
];
pub const REVIEW_BOOL_FLAGS: &[&str] = &["--new-session", "--xhigh", "--closure", "--pretty"];

static RID_SEQ: AtomicU64 = AtomicU64::new(1);

fn last_timeout_outage_map() -> &'static Mutex<HashMap<String, (String, String)>> {
    static MAP: OnceLock<Mutex<HashMap<String, (String, String)>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

fn last_rollout_turn_sid_map() -> &'static Mutex<HashMap<String, String>> {
    static MAP: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

fn set_last_timeout_outage(review_id: &str, kind: &str, sid: &str) {
    if let Ok(mut guard) = last_timeout_outage_map().lock() {
        guard.insert(review_id.to_string(), (kind.to_string(), sid.to_string()));
    }
}

fn pop_last_timeout_outage(review_id: &str) -> (String, String) {
    if let Ok(mut guard) = last_timeout_outage_map().lock() {
        if let Some(val) = guard.remove(review_id) {
            return val;
        }
    }
    ("thinking".to_string(), String::new())
}

fn set_last_rollout_turn_sid(review_id: &str, sid: &str) {
    if let Ok(mut guard) = last_rollout_turn_sid_map().lock() {
        guard.insert(review_id.to_string(), sid.to_string());
    }
}

fn pop_last_rollout_turn_sid(review_id: &str) -> String {
    if let Ok(mut guard) = last_rollout_turn_sid_map().lock() {
        return guard.remove(review_id).unwrap_or_default();
    }
    String::new()
}

fn outage_patterns() -> &'static [Regex] {
    static RE: OnceLock<Vec<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        [
            r"(?i)(?:hit|reached|exceeded)[^\n]{0,40}usage limit",
            r"(?i)usage limit[^\n]{0,30}(?:reached|exceeded|reset)",
            r"(?i)rate[ _-]limit[ _-]exceeded",
            r"(?i)exceeded[^\n]{0,30}rate limit",
            r"(?i)quota exceeded",
            r"(?i)insufficient_quota",
            r"(?i)model is at capacity",
            r"(?i)not logged in",
            r"(?i)authentication failed",
            r"(?i)401 unauthorized",
            r"(?i)429 too many requests",
            r"(?i)connection refused",
            r"(?i)timed out waiting for model",
            r"(?i)workspace routing discovery failed",
        ]
        .iter()
        .map(|p| Regex::new(p).expect("outage_pattern"))
        .collect()
    })
}

fn review_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"REVIEW_ID\s*:\s*([A-Za-z0-9_-]{6,64})").expect("review_id_re"))
}

fn aborted_rid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\A[A-Za-z0-9_-]{6,64}\z").expect("aborted_rid_re"))
}

fn cli_arg_error_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:^|\n)\s*(?:usage:\s|error:\s+(?:unexpected|unrecognized)\s+argument|[^\n]*:\s*error:\s*(?:unrecognized\s+arguments|argument\s+|the\s+following\s+arguments|invalid\s+int\s+value))",
        )
        .expect("cli_arg_error_re")
    })
}

fn null_pipe_prefix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\A\$null\s*\|\s*").expect("null_pipe_prefix_re"))
}

fn python_exe_base_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^python\d+(?:\.\d+)?$").expect("python_exe_base_re"))
}

fn sandbox_block_patterns() -> &'static [Regex] {
    static RE: OnceLock<Vec<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        [
            r"(?i)operation not permitted",
            r"(?i)permissionerror:\s*\[(?:errno|winerror)",
            r"(?i)winerror\s+10013",
            r"(?i)eacces:\s*permission denied",
            r"(?i)blocked by (?:sandbox|network policy|proxy)",
            r"(?i)carbon_stack_home is (?:read-only|not writable)",
        ]
        .iter()
        .map(|p| Regex::new(p).expect("sandbox_block_pattern"))
        .collect()
    })
}

fn network_timeout_patterns() -> &'static [Regex] {
    static RE: OnceLock<Vec<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        [
            r"(?i)connection\s+timed\s+out",
            r"(?i)connect\s+timeout",
            r"(?i)\betimedout\b",
            r"(?i)\beconnreset\b",
            r"(?i)\beconnrefused\b",
            r"(?i)\behostunreach\b",
            r"(?i)\benetunreach\b",
            r"(?i)\benotfound\b",
            r"(?i)\beai_again\b",
            r"(?i)getaddrinfo\b",
            r"(?i)temporary\s+failure\s+in\s+name\s+resolution",
            r"(?i)failed\s+to\s+lookup\s+address",
            r"(?i)tls\s+handshake\s+(?:timeout|eof|failed)",
            r"(?i)network\s+is\s+unreachable",
            r"(?i)error\s+sending\s+request\s+for\s+url",
            r"(?i)stream\s+disconnected\s+before\s+completion",
            r"(?i)timed\s+out\s+waiting\s+for\s+model",
        ]
        .iter()
        .map(|p| Regex::new(p).expect("network_timeout_pattern"))
        .collect()
    })
}

fn cli_diag_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)^\s*(?:(?:fatal|error|codex(?:\.exe|\.cmd)?|openai|api\s+error|stream\s+error)\s*:|\d{4}-\d{2}-\d{2}T\S+\s+(?:ERROR|FATAL)\b|caused\s+by\s*:|\d+\s*:\s*(?:error|reqwest|hyper|tls|dns|connect|io)|reqwest::error|permissionerror\s*:|oserror\s*:|traceback\b|thread\s+'[^']+'\s+panicked)",
        )
        .expect("cli_diag_line_re")
    })
}

fn stderr_tool_open_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)^(?:exec\s*$|.*\bin\s+\S.*\b(?:succeeded|exited)\b.*:\s*$|\s*(?:powershell(?:\.exe)?\b[^\n]*\b)?(?:Get-Content|Select-String|cat|type|rg(?:\.exe)?|git\s+(?:diff|show|grep|log))\b)",
        )
        .expect("stderr_tool_open_re")
    })
}

fn stderr_section_reset_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)^(?:thinking|codex|tokens\s+used)\s*$|^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}",
        )
        .expect("stderr_section_reset_re")
    })
}

fn safe_sid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9_-]{6,80}$").expect("safe_sid_re"))
}

fn codex_cli_wrapper_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\AREVIEW_ID:\s*[A-Za-z0-9_-]+[ \t]*\r?\n(?:(?:SESSION_ID|SESSION_MODE|ENGINE):[^\r\n]*\r?\n){0,3}--- CODEX REVIEW OUTPUT ---[ \t]*\r?\n",
        )
        .expect("codex_cli_wrapper_re")
    })
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

fn val_to_f64(v: Option<&Value>) -> f64 {
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

fn val_to_str(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn parse_ts_val(v: Option<&Value>) -> f64 {
    match v {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::String(s)) => rio::parse_iso_ts(s),
        _ => 0.0,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn random_hex_12() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = RID_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let seed = format!("{}:{}:{}", nanos, pid, seq);
    sha256_hex(seed.as_bytes())[..12].to_string()
}

fn abs_path_from_str(raw: &str) -> PathBuf {
    rio::resolve_abs_path(Path::new(raw))
}

fn unlink_quiet(path: &Path) {
    if path.exists() {
        let _ = fs::remove_file(path);
    }
}

fn file_mtime_sec(path: &Path) -> f64 {
    fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn strip_task_envelope_tail(blob: &str) -> String {
    // INVARIANT: Strip trailing `<SYSTEM_MESSAGE>` / `Log: file:///...` lines via O(1) rsplit_once with zero regex backtracking.
    let mut text = blob.trim().to_string();
    if text.is_empty() {
        return String::new();
    }
    let (head, last, has_sep) = match text.rsplit_once('\n') {
        Some((h, l)) => (h, l, true),
        None => ("", text.as_str(), false),
    };
    if last.trim().eq_ignore_ascii_case("</system_message>") {
        text = if has_sep {
            head.trim().to_string()
        } else {
            String::new()
        };
    }
    if !text.is_empty() {
        let (head2, last2, has_sep2) = match text.rsplit_once('\n') {
            Some((h, l)) => (h, l, true),
            None => ("", text.as_str(), false),
        };
        let tail_low = last2.trim().to_lowercase();
        if tail_low.starts_with("log:") && tail_low[4..].trim_start().starts_with("file:///") {
            text = if has_sep2 {
                head2.trim().to_string()
            } else {
                String::new()
            };
        }
    }
    text
}

fn fallback_reviewer(xhigh: bool) -> &'static str {
    if xhigh {
        XHIGH_NATIVE_REVIEWER
    } else {
        "adversarial-reviewer"
    }
}

pub fn next_timeout_after(timeout_sec: i64) -> i64 {
    MAX_REVIEW_TIMEOUT_SECONDS
        .min((timeout_sec + TIMEOUT_STEP_SECONDS).max(DEFAULT_XHIGH_REVIEW_TIMEOUT_SECONDS))
}

pub fn required_review_timeout(xhigh: bool, saved_next_sec: i64) -> i64 {
    let base = if xhigh {
        DEFAULT_XHIGH_REVIEW_TIMEOUT_SECONDS
    } else {
        DEFAULT_REVIEW_TIMEOUT_SECONDS
    };
    MAX_REVIEW_TIMEOUT_SECONDS.min(base.max(saved_next_sec.max(0)))
}

fn breaker_path() -> PathBuf {
    cwg_common::gate_dir().join("codex_lane.json")
}

fn packets_dir() -> PathBuf {
    let p = cwg_common::gate_dir().join("packets");
    let _ = fs::create_dir_all(&p);
    p
}

fn threads_dir() -> PathBuf {
    let p = cwg_common::gate_dir().join("threads");
    let _ = fs::create_dir_all(&p);
    p
}

fn codex_sessions_dir() -> PathBuf {
    if let Ok(ov) = env::var("CARBON_CODEX_SESSIONS_DIR") {
        let trimmed = ov.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    rio::home_dir().join(".codex").join("sessions")
}

fn which_in_path(name: &str) -> Option<String> {
    rio::which_in_path(name)
}

pub fn find_codex_binary() -> Option<String> {
    if let Ok(ov) = env::var("CARBON_CODEX_BIN") {
        let trimmed = ov.trim();
        if !trimmed.is_empty() {
            if Path::new(trimmed).is_file() {
                return Some(trimmed.to_string());
            }
            return which_in_path(trimmed);
        }
    }
    for name in ["codex.cmd", "codex.exe", "codex"] {
        if let Some(found) = which_in_path(name) {
            return Some(found);
        }
    }
    #[cfg(windows)]
    {
        if let Ok(appdata) = env::var("APPDATA") {
            let trimmed = appdata.trim();
            if !trimmed.is_empty() {
                let npm_dir = Path::new(trimmed).join("npm");
                for name in ["codex.cmd", "codex.exe", "codex"] {
                    let cand = npm_dir.join(name);
                    if cand.is_file() {
                        return Some(cand.to_string_lossy().into_owned());
                    }
                }
            }
        }
    }
    None
}

pub fn breaker_status() -> Value {
    let Some(Value::Object(data)) = rio::read_json(&breaker_path()) else {
        return json!({ "tripped": false });
    };
    let until = val_to_f64(data.get("tripped_until"));
    let now = now_sec();
    if until > now {
        let raw_reason = val_to_str(data.get("reason"));
        let reason = if raw_reason.is_empty() {
            "codex_outage".to_string()
        } else {
            raw_reason
        };
        let tripped_at = data.get("tripped_at").cloned().unwrap_or(Value::Null);
        return json!({
            "tripped": true,
            "reason": reason,
            "remaining_seconds": (until - now) as i64,
            "tripped_at": tripped_at,
        });
    }
    json!({ "tripped": false })
}

pub fn trip_breaker(reason: &str, ttl: i64) {
    let now = now_sec();
    let r_trunc: String = reason.chars().take(300).collect();
    let r_log: String = reason.chars().take(200).collect();
    let _ = rio::write_json(
        &breaker_path(),
        &json!({
            "tripped": true,
            "reason": r_trunc,
            "tripped_at": now,
            "tripped_until": now + (ttl as f64),
        }),
    );
    rio::log_hook_event(
        "gate-events",
        "codex_breaker_tripped",
        json!({
            "reason": r_log,
            "ttl": ttl,
        }),
    );
}

pub fn reset_breaker() {
    let bp = breaker_path();
    if bp.exists() && fs::remove_file(&bp).is_err() {
        let _ = rio::write_json(&bp, &json!({ "tripped": false }));
    }
}

fn infer_single_open_session(cwd: &str) -> String {
    let root_or_cwd = rio::git_toplevel(cwd, false).unwrap_or_else(|| cwd.to_string());
    let target_root = rio::fold_path(&root_or_cwd);
    if target_root.is_empty() {
        return String::new();
    }
    let root_prefix = format!("{}/", target_root.trim_end_matches('/'));
    let markers_dir = rio::state_dir().join("gate").join("markers");
    let Ok(entries) = fs::read_dir(&markers_dir) else {
        return String::new();
    };
    let mut matched: Vec<String> = Vec::new();
    for ent in entries.flatten() {
        let p = ent.path();
        if p.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Some(Value::Object(mdata)) = rio::read_json(&p) else {
            continue;
        };
        if json_truthy(mdata.get("closed")) {
            continue;
        }
        let sess = val_to_str(mdata.get("session"));
        if sess.is_empty() {
            continue;
        }
        let mroot_raw = {
            let gr = val_to_str(mdata.get("git_root"));
            if gr.is_empty() {
                val_to_str(mdata.get("cwd"))
            } else {
                gr
            }
        };
        let mroot = rio::fold_path(&mroot_raw);
        let mut path_match = mroot == target_root;
        if !path_match {
            if let Some(Value::Array(raw_paths)) = mdata.get("paths") {
                for touched in raw_paths {
                    let ftouched = rio::fold_path(&val_to_str(Some(touched)));
                    if ftouched == target_root || ftouched.starts_with(&root_prefix) {
                        path_match = true;
                        break;
                    }
                }
            }
        }
        if path_match && !matched.contains(&sess) {
            matched.push(sess);
        }
    }
    if matched.len() == 1 {
        matched.into_iter().next().unwrap_or_default()
    } else {
        String::new()
    }
}

fn candidate_first_ts(session: &str) -> f64 {
    if session.is_empty() {
        return 0.0;
    }
    let Some(Value::Object(mdata)) = rio::read_json(&cwg_common::marker_path(session)) else {
        return 0.0;
    };
    if json_truthy(mdata.get("closed")) {
        return 0.0;
    }
    val_to_f64(mdata.get("first_ts"))
}

fn thread_state_path(session: &str, git_root: &str) -> PathBuf {
    let sess_part = if session.is_empty() {
        "nosession"
    } else {
        session
    };
    let raw_key = format!("{}|{}", sess_part, rio::fold_path(git_root));
    let digest = sha256_hex(raw_key.as_bytes());
    threads_dir().join(format!("{}.json", &digest[..20]))
}

pub fn active_thread_state(
    session: &str,
    git_root: &str,
    candidate_first_ts_opt: Option<f64>,
) -> Option<Map<String, Value>> {
    let Some(Value::Object(saved)) = rio::read_json(&thread_state_path(session, git_root)) else {
        return None;
    };
    let cand_ts = candidate_first_ts_opt.unwrap_or_else(|| candidate_first_ts(session));
    let saved_cand_ts = val_to_f64(saved.get("candidate_first_ts"));
    // INVARIANT: Bind thread continuity & timeout escalation strictly to the active candidate (`1h` TTL when no marker is open).
    let matched = if cand_ts > 0.0 {
        (saved_cand_ts - cand_ts).abs() < 1.0
    } else {
        saved_cand_ts <= 0.0 && (now_sec() - val_to_f64(saved.get("updated_ts"))) < 3600.0
    };
    if matched {
        Some(saved)
    } else {
        None
    }
}

fn clear_pending_timeout_resume(session: &str, git_root: &str) {
    let tpath = thread_state_path(session, git_root);
    let Some(Value::Object(mut saved)) = rio::read_json(&tpath) else {
        return;
    };
    if !json_truthy(saved.get("pending_timeout_resume")) {
        return;
    }
    if json_truthy(saved.get("session_id")) {
        saved.insert("pending_timeout_resume".to_string(), Value::Bool(false));
        saved.remove("next_timeout_seconds");
        saved.insert("updated_ts".to_string(), json!(now_sec()));
        let _ = rio::write_json(&tpath, &Value::Object(saved));
    } else {
        unlink_quiet(&tpath);
    }
}

fn packet_path(review_id: &str) -> PathBuf {
    packets_dir().join(format!("{}.json", rio::safe_key(review_id, "default")))
}

pub fn record_packet(
    review_id: &str,
    prompt_text: &str,
    cwd: &str,
    effort: &str,
    phase: &str,
    session: &str,
) -> Value {
    let now = now_sec();
    let eff_session = if session.is_empty() {
        infer_single_open_session(cwd)
    } else {
        session.to_string()
    };
    let digest = sha256_hex(prompt_text.as_bytes())[..24].to_string();
    let pkt = json!({
        "review_id": review_id,
        "prompt_sha256": digest,
        "cwd": rio::normalize_path(cwd),
        "effort": effort.to_lowercase(),
        "phase": phase,
        "session": eff_session,
        "created_ts": now,
    });
    let _ = rio::write_json(&packet_path(review_id), &pkt);
    sweep_expired_gate_files();
    pkt
}

fn unlink_packet(review_id: &str) {
    if review_id.is_empty() {
        return;
    }
    unlink_quiet(&packet_path(review_id));
}

fn sweep_expired_gate_files() {
    let cutoff = now_sec() - PACKET_TTL_SECONDS;
    for base_dir in [packets_dir(), threads_dir()] {
        let Ok(entries) = fs::read_dir(&base_dir) else {
            continue;
        };
        for ent in entries.flatten() {
            let p = ent.path();
            if p.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let mt = file_mtime_sec(&p);
            if mt > 0.0 && mt < cutoff {
                let _ = fs::remove_file(&p);
            }
        }
    }
}

fn fold_ps_line_continuations(cmd_str: &str) -> String {
    // INVARIANT: Fold only PowerShell backtick line-continuations (`` ` `` + optional horizontal space + newline) outside quotes; bare newlines and arbitrary backticks remain untouched and rejected as multi-statement / escape hazards.
    if !cmd_str.contains('`') || (!cmd_str.contains('\n') && !cmd_str.contains('\r')) {
        return cmd_str.to_string();
    }
    let bytes = cmd_str.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(n);
    let mut quote: Option<u8> = None;
    let mut i = 0usize;
    while i < n {
        let ch = bytes[i];
        if let Some(q) = quote {
            if ch == q {
                out.push(q as char);
                if i + 1 < n && bytes[i + 1] == q {
                    out.push(q as char);
                    i += 2;
                    continue;
                }
                quote = None;
                i += 1;
                continue;
            }
            let step = cmd_str[i..].chars().next().map_or(1, char::len_utf8);
            out.push_str(&cmd_str[i..i + step]);
            i += step;
            continue;
        }
        if ch == b'\'' || ch == b'"' {
            quote = Some(ch);
            out.push(ch as char);
            i += 1;
            continue;
        }
        if ch == b'`' {
            let mut k = i + 1;
            while k < n && (bytes[k] == b' ' || bytes[k] == b'\t') {
                k += 1;
            }
            if k < n && bytes[k] == b'\r' && k + 1 < n && bytes[k + 1] == b'\n' {
                out.push(' ');
                i = k + 2;
                continue;
            }
            if k < n && bytes[k] == b'\n' {
                out.push(' ');
                i = k + 1;
                continue;
            }
        }
        let step = cmd_str[i..].chars().next().map_or(1, char::len_utf8);
        out.push_str(&cmd_str[i..i + step]);
        i += step;
    }
    out
}

fn validate_codex_lane_subcmd_tokens(subcmd: &str, rem: &[String]) -> bool {
    if subcmd == "check" {
        return rem.iter().all(|t| t == "--pretty" || t == "--json");
    }
    if subcmd != "review" {
        return false;
    }
    let mut j = 0usize;
    while j < rem.len() {
        let tok = &rem[j];
        if REVIEW_BOOL_FLAGS.iter().any(|&f| f == tok) {
            j += 1;
            continue;
        }
        let (opt, has_sep, inline_val) = match tok.split_once('=') {
            Some((o, v)) => (o, true, v),
            None => (tok.as_str(), false, ""),
        };
        if REVIEW_VAL_FLAGS.iter().any(|&f| f == opt) {
            let (val, step) = if has_sep {
                (inline_val, 1)
            } else if j + 1 < rem.len() {
                (rem[j + 1].as_str(), 2)
            } else {
                return false;
            };
            if opt == "--timeout" && (val.is_empty() || !val.chars().all(|c| c.is_ascii_digit())) {
                return false;
            }
            j += step;
            continue;
        }
        return false;
    }
    true
}

fn is_direct_codex_invocation(cmd_str: &str) -> bool {
    let folded = fold_ps_line_continuations(cmd_str.trim());
    let mut s = folded.trim();
    if s.is_empty()
        || s.contains('\r')
        || s.contains('\n')
        || s.contains('`')
        || !s.to_lowercase().contains("codex")
    {
        return false;
    }
    if let Some(m) = null_pipe_prefix_re().find(s) {
        s = s[m.end()..].trim();
    }
    let mut had_call_op = false;
    if s.starts_with('&') && s[1..].chars().next().map_or(false, char::is_whitespace) {
        had_call_op = true;
        s = s[1..].trim();
    }
    if s.is_empty() {
        return false;
    }
    // INVARIANT: In PowerShell, a quoted leading token without `&` is a string expression or parser error, never execution.
    if (s.starts_with('\'') || s.starts_with('"')) && !had_call_op {
        return false;
    }

    let bytes = s.as_bytes();
    let n = bytes.len();
    let mut tokens: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_tok = false;
    let mut quote: Option<u8> = None;
    let mut i = 0usize;
    while i < n {
        let ch = bytes[i];
        if let Some(q) = quote {
            if ch == q {
                // INVARIANT: In PowerShell, doubled quote (`''` or `""`) is an escaped quote literal; `\` is never an escape char.
                if i + 1 < n && bytes[i + 1] == q {
                    cur.push(q as char);
                    i += 2;
                    continue;
                }
                quote = None;
                i += 1;
                continue;
            }
            if q == b'"' && ch == b'$' {
                return false;
            }
            let step = s[i..].chars().next().map_or(1, char::len_utf8);
            cur.push_str(&s[i..i + step]);
            i += step;
            continue;
        }
        if ch == b'\'' || ch == b'"' {
            quote = Some(ch);
            in_tok = true;
            i += 1;
            continue;
        }
        let c = s[i..].chars().next().unwrap_or('\0');
        if c.is_whitespace() {
            if in_tok {
                tokens.push(std::mem::take(&mut cur));
                in_tok = false;
            }
            i += c.len_utf8();
            continue;
        }
        if matches!(ch, b';' | b'|' | b'&' | b'<' | b'>' | b'(' | b')' | b'$' | b'#') {
            return false;
        }
        cur.push(c);
        in_tok = true;
        i += c.len_utf8();
    }
    if quote.is_some() {
        return false;
    }
    if in_tok {
        tokens.push(cur);
    }
    if tokens.len() < 2 {
        return false;
    }

    let tok0_norm = tokens[0].replace('\\', "/").to_lowercase();
    let mut exe_base = tok0_norm.rsplit('/').next().unwrap_or("").to_string();
    if exe_base.ends_with(".exe") || exe_base.ends_with(".cmd") {
        exe_base.truncate(exe_base.len() - 4);
    }

    if exe_base == "codex" {
        return tokens[1].eq_ignore_ascii_case("exec");
    }

    if exe_base == "carbon-stack" {
        if tokens.len() < 3 {
            return false;
        }
        let mod_name = tokens[1].to_lowercase();
        if mod_name != "codex-lane" && mod_name != "codex_lane" {
            return false;
        }
        let subcmd = tokens[2].to_lowercase();
        return validate_codex_lane_subcmd_tokens(&subcmd, &tokens[3..]);
    }

    if exe_base == "python" || exe_base == "python3" || python_exe_base_re().is_match(&exe_base) {
        let mut idx = 1usize;
        while idx < tokens.len() && tokens[idx].starts_with('-') {
            let flag = &tokens[idx];
            if flag.starts_with("-c") || flag.starts_with("-m") {
                return false;
            }
            idx += if flag == "-X" { 2 } else { 1 };
        }
        if idx + 1 >= tokens.len() {
            return false;
        }
        let script_norm = tokens[idx].replace('\\', "/").to_lowercase();
        let script_base = script_norm.rsplit('/').next().unwrap_or("");
        if script_base != "codex_lane.py" {
            return false;
        }
        let subcmd = tokens[idx + 1].to_lowercase();
        return validate_codex_lane_subcmd_tokens(&subcmd, &tokens[idx + 2..]);
    }

    false
}

fn detect_sandbox_restriction(output_text: &str) -> Option<String> {
    if output_text.is_empty() {
        return None;
    }
    for pat in sandbox_block_patterns() {
        if let Some(m) = pat.find(output_text) {
            return Some(m.as_str().to_string());
        }
    }
    None
}

fn detect_network_timeout_from_output(output_text: &str) -> Option<String> {
    if output_text.is_empty() || cli_arg_error_re().is_match(output_text) {
        return None;
    }
    for pat in network_timeout_patterns() {
        if let Some(m) = pat.find(output_text) {
            return Some(m.as_str().to_string());
        }
    }
    None
}

fn detect_outage_from_output(output_text: &str, exit_code: i32) -> Option<String> {
    if output_text.is_empty() && exit_code == 0 {
        return None;
    }
    if cli_arg_error_re().is_match(output_text) {
        return None;
    }
    if exit_code == 0 && cwg_common::extract_review_decision(output_text) != (None, None) {
        return None;
    }
    for pat in outage_patterns() {
        if let Some(m) = pat.find(output_text) {
            return Some(m.as_str().to_string());
        }
    }
    None
}

fn extract_cli_error_lines(text: &str, excluded_blobs: &[String]) -> String {
    if text.is_empty() {
        return String::new();
    }
    let mut excluded_lines: HashSet<&str> = HashSet::new();
    for blob in excluded_blobs {
        if !blob.is_empty() {
            for ln in blob.lines() {
                let s = ln.trim();
                if !s.is_empty() {
                    excluded_lines.insert(s);
                }
            }
        }
    }
    let mut matched: Vec<String> = Vec::new();
    let mut in_tool_block = false;
    for raw_ln in text.lines() {
        let s_ln = raw_ln.trim();
        if s_ln.is_empty() {
            continue;
        }
        if in_tool_block && stderr_section_reset_re().is_match(s_ln) {
            in_tool_block = false;
        }
        if stderr_tool_open_re().is_match(raw_ln) {
            in_tool_block = true;
            continue;
        }
        if in_tool_block || excluded_lines.contains(s_ln) {
            continue;
        }
        if cli_diag_line_re().is_match(raw_ln) {
            matched.push(s_ln.to_string());
        }
    }
    matched.join("\n")
}

struct ParsedJsonStream {
    saw_jsonl: bool,
    thread_id: String,
    agent_text: String,
    cli_errors: Vec<String>,
    tool_outputs: Vec<String>,
}

fn parse_codex_json_stream(raw_stdout: &str) -> ParsedJsonStream {
    // INVARIANT: Parse `codex exec --json` JSONL stream so CLI/API `error` and `turn.failed` events are structurally separated from `command_execution` tool outputs (`Get-Content`/`rg` reading repository files).
    let mut saw_jsonl = false;
    let mut thread_id = String::new();
    let mut agent_messages: Vec<String> = Vec::new();
    let mut cli_errors: Vec<String> = Vec::new();
    let mut tool_outputs: Vec<String> = Vec::new();

    if raw_stdout.is_empty() || !raw_stdout.contains('{') {
        return ParsedJsonStream {
            saw_jsonl: false,
            thread_id,
            agent_text: String::new(),
            cli_errors,
            tool_outputs,
        };
    }

    for ln in raw_stdout.lines() {
        let s = ln.trim();
        if !(s.starts_with('{') && s.ends_with('}')) {
            continue;
        }
        let Ok(Value::Object(rec)) = serde_json::from_str::<Value>(s) else {
            continue;
        };
        let etype = val_to_str(rec.get("type"));
        if etype != "error" && !JSONL_EVENT_PREFIXES.iter().any(|p| etype.starts_with(p)) {
            continue;
        }
        saw_jsonl = true;
        if etype == "thread.started" {
            let tid = val_to_str(rec.get("thread_id")).trim().to_string();
            if !tid.is_empty() {
                thread_id = tid;
            }
        } else if etype == "error" {
            let emsg = val_to_str(rec.get("message")).trim().to_string();
            if !emsg.is_empty() {
                cli_errors.push(emsg);
            }
        } else if etype == "turn.failed" {
            let emsg = match rec.get("error") {
                Some(Value::Object(eobj)) => val_to_str(eobj.get("message")),
                Some(other) => val_to_str(Some(other)),
                None => val_to_str(rec.get("message")),
            }
            .trim()
            .to_string();
            if !emsg.is_empty() {
                cli_errors.push(emsg);
            }
        } else if etype == "item.completed" {
            if let Some(Value::Object(item)) = rec.get("item") {
                let itype = val_to_str(item.get("type"));
                if itype == "agent_message" {
                    let txt = val_to_str(item.get("text")).trim().to_string();
                    if !txt.is_empty() {
                        agent_messages.push(txt);
                    }
                } else if itype == "error" {
                    let emsg = val_to_str(item.get("message")).trim().to_string();
                    if !emsg.is_empty() {
                        cli_errors.push(emsg);
                    }
                } else if matches!(itype.as_str(), "command_execution" | "mcp_tool_call" | "tool_call") {
                    for k in ["aggregated_output", "output", "result"] {
                        if let Some(Value::String(v)) = item.get(k) {
                            if !v.trim().is_empty() {
                                tool_outputs.push(v.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    ParsedJsonStream {
        saw_jsonl,
        thread_id,
        agent_text: agent_messages.join("\n\n"),
        cli_errors,
        tool_outputs,
    }
}

fn extract_cli_json_payload(cleaned_text: &str) -> Option<Map<String, Value>> {
    if cleaned_text.is_empty() {
        return None;
    }
    let after_hdr = cleaned_text
        .rsplit_once("Command output:")
        .map(|(_, r)| r.trim())
        .unwrap_or("");
    let last_line = cleaned_text
        .rsplit_once('\n')
        .map(|(_, r)| r.trim())
        .unwrap_or_else(|| cleaned_text.trim());
    let mut seen: HashSet<&str> = HashSet::new();
    for cand in [cleaned_text, after_hdr, last_line] {
        if cand.is_empty() || !seen.insert(cand) {
            continue;
        }
        if cand.starts_with('{') && cand.ends_with('}') {
            if let Ok(Value::Object(jobj)) = serde_json::from_str::<Value>(cand) {
                return Some(jobj);
            }
        }
    }
    None
}

pub fn inspect_codex_cmd_result(cmd_str: &str, status: &str, output: &str) -> (bool, Option<String>) {
    if !is_direct_codex_invocation(cmd_str) {
        return (false, None);
    }
    let cleaned = strip_task_envelope_tail(output);
    if cleaned.is_empty()
        || cli_arg_error_re().is_match(&cleaned)
        || codex_cli_wrapper_re().is_match(&cleaned)
        || cleaned.contains(cwg_common::CODEX_REVIEW_OUTPUT_BANNER)
        || cwg_common::extract_review_decision(&cleaned) != (None, None)
    {
        return (false, None);
    }
    let low_cmd = cmd_str.to_lowercase();
    let is_lane = low_cmd.contains("codex_lane.py")
        || low_cmd.contains("codex-lane")
        || low_cmd.contains("codex_lane");
    let jobj_opt = extract_cli_json_payload(&cleaned);
    let mut aborted_rid: Option<String> = None;
    if let Some(ref jobj) = jobj_opt {
        if is_lane
            && status == "ERROR"
            && jobj.get("ok").and_then(|v| v.as_bool()) == Some(false)
        {
            let cand_rid = val_to_str(jobj.get("review_id")).trim().to_string();
            if aborted_rid_re().is_match(&cand_rid) {
                aborted_rid = Some(cand_rid);
            }
        }
        if jobj.get("available").and_then(|v| v.as_bool()) == Some(false)
            && jobj.get("lane").and_then(|v| v.as_str()) == Some("native-fallback")
        {
            return (true, aborted_rid);
        }
        let err_s = val_to_str(jobj.get("error"));
        // INVARIANT: A wall-clock thinking timeout (`timeout_after_*s` without `network_outage`) aborts the round (`round_consumed=False`) but is NEVER a Codex outage — the caller must resume the same Codex session rather than escalating to internal Opus/Carbon.
        let is_thinking_timeout = json_truthy(jobj.get("retry_in_same_lane"))
            || (json_truthy(jobj.get("timed_out")) && !json_truthy(jobj.get("network_outage")))
            || (err_s.starts_with("timeout_after_") && !json_truthy(jobj.get("network_outage")));
        let fallback_s = val_to_str(jobj.get("fallback"));
        if jobj.get("ok").and_then(|v| v.as_bool()) == Some(false)
            && !is_thinking_timeout
            && NATIVE_REVIEWERS.iter().any(|&nr| nr == fallback_s)
        {
            return (true, aborted_rid);
        }
    }
    if is_lane {
        return (false, aborted_rid);
    }
    let exit_c = if status == "ERROR" { 1 } else { 0 };
    let diag_err = extract_cli_error_lines(&cleaned, &[]);
    let diag_direct = if !diag_err.is_empty() {
        diag_err.as_str()
    } else if cleaned.len() <= 2048 {
        cleaned.as_str()
    } else {
        ""
    };
    let outage = detect_outage_from_output(diag_direct, exit_c).is_some()
        || (exit_c != 0 && detect_network_timeout_from_output(diag_direct).is_some());
    (outage, None)
}

pub fn is_verified_codex_cmd_outage(cmd_str: &str, status: &str, output: &str) -> bool {
    inspect_codex_cmd_result(cmd_str, status, output).0
}

pub fn record_from_command(command_text: &str, output_text: &str, exit_code: i32) {
    let status = if exit_code != 0 { "ERROR" } else { "DONE" };
    if !is_verified_codex_cmd_outage(command_text, status, output_text) {
        return;
    }
    let cleaned = strip_task_envelope_tail(output_text);
    if let Some(jobj) = extract_cli_json_payload(&cleaned) {
        let err_s = val_to_str(jobj.get("error"));
        // SAFETY: Local review timeouts, transient socket errors, and sandbox blocks must never trip the global 30-minute circuit breaker via PostToolUse.
        if json_truthy(jobj.get("sandbox_blocked"))
            || json_truthy(jobj.get("network_outage"))
            || err_s.starts_with("timeout_after_")
        {
            return;
        }
    }
    if let Some(reason) = detect_outage_from_output(&cleaned, exit_code) {
        trip_breaker(&format!("CLI reported: {}", reason), BREAKER_TTL_SECONDS);
    }
}

pub fn check_health() -> Value {
    let b = breaker_status();
    if json_truthy(b.get("tripped")) {
        let reason = val_to_str(b.get("reason"));
        let rem = b
            .get("remaining_seconds")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        return json!({
            "available": false,
            "lane": "native-fallback",
            "reason": format!("circuit_breaker_open ({}, {}s left)", reason, rem),
        });
    }
    let Some(binary) = find_codex_binary() else {
        return json!({
            "available": false,
            "lane": "native-fallback",
            "reason": "codex_binary_not_found",
        });
    };
    let args = vec!["login".to_string(), "status".to_string()];
    match run_command_with_job(&binary, &args, None, &[], None, Some(6000)) {
        Ok(res) if res.timed_out => {
            trip_breaker("health_probe_failed:TimeoutExpired", 600);
            json!({
                "available": false,
                "lane": "native-fallback",
                "reason": "health_probe_exception:TimeoutExpired",
            })
        }
        Ok(res) => {
            let combined = format!("{}\n{}", res.stdout_str(), res.stderr_str())
                .trim()
                .to_string();
            if res.code != 0 || !combined.to_lowercase().contains("logged in") {
                trip_breaker("codex_not_authenticated", 600);
                return json!({
                    "available": false,
                    "lane": "native-fallback",
                    "reason": format!("codex_not_logged_in: {}", combined),
                });
            }
            let auth = combined
                .lines()
                .next()
                .filter(|s| !s.is_empty())
                .unwrap_or("authenticated");
            json!({
                "available": true,
                "lane": "codex",
                "binary": binary,
                "auth": auth,
            })
        }
        Err(_) => {
            trip_breaker("health_probe_failed:OSError", 600);
            json!({
                "available": false,
                "lane": "native-fallback",
                "reason": "health_probe_exception:OSError",
            })
        }
    }
}

fn is_subagent_rollout_meta(payload: &Map<String, Value>) -> bool {
    if json_truthy(payload.get("parent_thread_id")) {
        return true;
    }
    if let Some(Value::Object(src)) = payload.get("source") {
        if src.contains_key("subagent") {
            return true;
        }
    }
    let tsrc = val_to_str(payload.get("thread_source"))
        .trim()
        .to_lowercase();
    if !tsrc.is_empty() && !matches!(tsrc.as_str(), "user" | "cli" | "exec") {
        return true;
    }
    false
}

fn read_rollout_session_meta(rollout_file: &Path) -> Map<String, Value> {
    let Ok(raw) = fs::read_to_string(rollout_file) else {
        return Map::new();
    };
    for raw_line in raw.lines().take(8) {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(Value::Object(rec)) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if rec.get("type").and_then(|v| v.as_str()) == Some("session_meta") {
            if let Some(Value::Object(payload)) = rec.get("payload") {
                return payload.clone();
            }
            return Map::new();
        }
    }
    Map::new()
}

fn rollout_message_text(blocks: Option<&Value>) -> String {
    match blocks {
        Some(Value::Array(arr)) => {
            let mut parts: Vec<&str> = Vec::new();
            for blk in arr {
                if let Some(txt) = blk
                    .as_object()
                    .and_then(|m| m.get("text"))
                    .and_then(|v| v.as_str())
                {
                    parts.push(txt);
                }
            }
            parts.join("\n").trim().to_string()
        }
        Some(Value::String(s)) => s.trim().to_string(),
        _ => String::new(),
    }
}

fn extract_review_ids(text: &str) -> Vec<String> {
    review_id_re()
        .captures_iter(text)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

fn rollout_user_review_ids(rtype: &str, payload: &Map<String, Value>) -> Vec<String> {
    let ptype = payload.get("type").and_then(|v| v.as_str()).unwrap_or("");
    if rtype == "event_msg" && ptype == "user_message" {
        let umsg = val_to_str(payload.get("message"));
        let trimmed = umsg.trim();
        if !trimmed.is_empty() {
            return extract_review_ids(trimmed);
        }
    } else if rtype == "response_item"
        && ptype == "message"
        && payload.get("role").and_then(|v| v.as_str()) == Some("user")
    {
        let txt = rollout_message_text(payload.get("content"));
        if !txt.is_empty() {
            return extract_review_ids(&txt);
        }
    }
    Vec::new()
}

struct RolloutTurn {
    review_ids: Vec<String>,
    started_ts: f64,
    completed_ts: f64,
    effort: String,
    model: String,
    assistant_messages: Vec<(f64, String)>,
    closed: bool,
}

struct RolloutMetaExtracted {
    path: String,
    session_id: String,
    is_subagent: bool,
    effort: String,
    model: String,
    started_ts: f64,
    completed_ts: f64,
    turns: Vec<RolloutTurn>,
}

fn extract_rollout_texts_and_meta(rollout_file: &Path) -> Option<RolloutMetaExtracted> {
    let records = rio::read_jsonl(rollout_file, None);
    if records.is_empty() {
        return None;
    }
    let file_mtime = file_mtime_sec(rollout_file);
    let mut turns: Vec<RolloutTurn> = Vec::new();
    let mut current_idx: Option<usize> = None;
    let mut cur_effort = String::new();
    let mut cur_model = String::new();
    let mut session_id = String::new();
    let mut is_subagent = false;
    let mut started_ts = 0.0f64;
    let mut completed_ts = 0.0f64;
    let mut last_msg_ts = 0.0f64;

    for rec in &records {
        let rec_ts = parse_ts_val(rec.get("timestamp"));
        let rtype = rec.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let empty_map = Map::new();
        let payload = rec
            .get("payload")
            .and_then(|v| v.as_object())
            .unwrap_or(&empty_map);
        let ptype = payload.get("type").and_then(|v| v.as_str()).unwrap_or("");

        if rtype == "session_meta" {
            let sid_cand = {
                let id_s = val_to_str(payload.get("id"));
                if !id_s.is_empty() {
                    id_s
                } else {
                    val_to_str(payload.get("session_id"))
                }
            };
            if !sid_cand.is_empty() {
                session_id = sid_cand;
            }
            if is_subagent_rollout_meta(payload) {
                is_subagent = true;
            }
            if started_ts == 0.0 {
                started_ts = if rec_ts > 0.0 {
                    rec_ts
                } else {
                    parse_ts_val(payload.get("timestamp"))
                };
            }
        } else if rtype == "turn_context" {
            let eff_s = val_to_str(payload.get("effort")).to_lowercase();
            if !eff_s.is_empty() {
                cur_effort = eff_s;
            }
            let mdl_s = val_to_str(payload.get("model"));
            if !mdl_s.is_empty() {
                cur_model = mdl_s;
            }
            if let Some(idx) = current_idx {
                let t = &mut turns[idx];
                if !t.closed && t.assistant_messages.is_empty() {
                    if !cur_effort.is_empty() {
                        t.effort = cur_effort.clone();
                    }
                    if !cur_model.is_empty() {
                        t.model = cur_model.clone();
                    }
                }
            }
        } else if rtype == "event_msg" && ptype == "task_started" {
            if let Some(idx) = current_idx {
                turns[idx].closed = true;
            }
        } else if (rtype == "event_msg" && ptype == "user_message")
            || (rtype == "response_item"
                && ptype == "message"
                && payload.get("role").and_then(|v| v.as_str()) == Some("user"))
        {
            let m_ids = rollout_user_review_ids(rtype, payload);
            let same_open_turn = current_idx.map_or(false, |idx| {
                let t = &turns[idx];
                !t.closed && t.review_ids == m_ids && t.assistant_messages.is_empty()
            });
            if !m_ids.is_empty() && !same_open_turn {
                if let Some(idx) = current_idx {
                    turns[idx].closed = true;
                }
                turns.push(RolloutTurn {
                    review_ids: m_ids,
                    started_ts: if rec_ts > 0.0 { rec_ts } else { started_ts },
                    completed_ts: 0.0,
                    effort: cur_effort.clone(),
                    model: cur_model.clone(),
                    assistant_messages: Vec::new(),
                    closed: false,
                });
                current_idx = Some(turns.len() - 1);
            }
        } else if rtype == "response_item"
            && ptype == "message"
            && payload.get("role").and_then(|v| v.as_str()) == Some("assistant")
        {
            let joined = rollout_message_text(payload.get("content"));
            if !joined.is_empty() {
                let msg_ts = if rec_ts > 0.0 { rec_ts } else { file_mtime };
                last_msg_ts = msg_ts;
                if let Some(idx) = current_idx {
                    let t = &mut turns[idx];
                    if !t.closed {
                        t.assistant_messages.push((msg_ts, joined));
                    }
                }
            }
        } else if rtype == "event_msg" && ptype == "task_complete" {
            let ts_done = if rec_ts > 0.0 {
                rec_ts
            } else {
                let ca = parse_ts_val(payload.get("completed_at"));
                if ca > 0.0 {
                    ca
                } else {
                    file_mtime
                }
            };
            completed_ts = ts_done;
            last_msg_ts = ts_done;
            if let Some(Value::String(last_msg)) = payload.get("last_agent_message") {
                let trimmed = last_msg.trim();
                if !trimmed.is_empty() {
                    if let Some(idx) = current_idx {
                        let t = &mut turns[idx];
                        if !t.closed {
                            t.assistant_messages.push((ts_done, trimmed.to_string()));
                        }
                    }
                }
            }
            if let Some(idx) = current_idx {
                turns[idx].completed_ts = ts_done;
                turns[idx].closed = true;
            }
        }
    }

    if started_ts == 0.0 {
        started_ts = file_mtime;
    }
    let eff_completed = if completed_ts > 0.0 {
        completed_ts
    } else if last_msg_ts > 0.0 {
        last_msg_ts
    } else {
        started_ts
    };

    Some(RolloutMetaExtracted {
        path: rollout_file.to_string_lossy().into_owned(),
        session_id,
        is_subagent,
        effort: cur_effort,
        model: cur_model,
        started_ts,
        completed_ts: eff_completed,
        turns,
    })
}

fn collect_jsonl_files_rec(
    dir: &Path,
    prefix: Option<&str>,
    substr: Option<&str>,
    depth: usize,
    out: &mut Vec<PathBuf>,
) {
    if depth == 0 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for ent in entries.flatten() {
        let p = ent.path();
        let Ok(ft) = ent.file_type() else {
            continue;
        };
        if ft.is_dir() {
            collect_jsonl_files_rec(&p, prefix, substr, depth - 1, out);
        } else if ft.is_file() {
            let Some(fname) = p.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if !fname.ends_with(".jsonl") {
                continue;
            }
            if let Some(pre) = prefix {
                if !fname.starts_with(pre) {
                    continue;
                }
            }
            if let Some(sub) = substr {
                if !fname.contains(sub) {
                    continue;
                }
            }
            out.push(p);
        }
    }
}

fn recent_rollout_files(since_ts: f64, limit: usize, newest_first: bool) -> Vec<PathBuf> {
    let root = codex_sessions_dir();
    if !root.is_dir() {
        return Vec::new();
    }
    let min_mtime = (since_ts - 5.0).max(0.0);
    let mut files = Vec::new();
    collect_jsonl_files_rec(&root, Some("rollout-"), None, 8, &mut files);
    let mut candidates: Vec<(f64, PathBuf)> = Vec::new();
    for rf in files {
        let mt = file_mtime_sec(&rf);
        if mt >= min_mtime {
            candidates.push((mt, rf));
        }
    }
    if newest_first {
        candidates.sort_by(|a, b| b.0.total_cmp(&a.0));
        candidates.truncate(limit);
    } else {
        candidates.sort_by(|a, b| a.0.total_cmp(&b.0));
        if candidates.len() > limit {
            let drain_n = candidates.len() - limit;
            candidates.drain(..drain_n);
        }
    }
    candidates.into_iter().map(|(_, rf)| rf).collect()
}

pub fn scan_verified_codex_reviews(since_ts: f64, session: &str, git_root: &str) -> Vec<Value> {
    let fold_target_root = if git_root.is_empty() {
        String::new()
    } else {
        rio::fold_path(git_root)
    };
    let mut cwd_root_cache: HashMap<String, String> = HashMap::new();
    let mut known_packets: HashMap<String, Map<String, Value>> = HashMap::new();

    if let Ok(entries) = fs::read_dir(packets_dir()) {
        for ent in entries.flatten() {
            let pf = ent.path();
            if pf.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Some(Value::Object(pdata)) = rio::read_json(&pf) else {
                continue;
            };
            let rid = val_to_str(pdata.get("review_id"));
            if rid.is_empty() {
                continue;
            }
            if val_to_f64(pdata.get("created_ts")) < since_ts - 2.0 {
                continue;
            }
            let pkt_sess = val_to_str(pdata.get("session"));
            if !session.is_empty() && pkt_sess != session {
                continue;
            }
            let pkt_cwd = val_to_str(pdata.get("cwd"));
            if !fold_target_root.is_empty() && !pkt_cwd.is_empty() {
                let pkt_root = if let Some(cached) = cwd_root_cache.get(&pkt_cwd) {
                    cached.clone()
                } else {
                    let top = rio::git_toplevel(&pkt_cwd, false).unwrap_or_else(|| pkt_cwd.clone());
                    let folded = rio::fold_path(&top);
                    cwd_root_cache.insert(pkt_cwd.clone(), folded.clone());
                    folded
                };
                if !pkt_root.is_empty() && pkt_root != fold_target_root {
                    continue;
                }
            }
            known_packets.insert(rid, pdata);
        }
    }

    if known_packets.is_empty() {
        return Vec::new();
    }

    let mut by_review_id: HashMap<String, Value> = HashMap::new();
    for rf in recent_rollout_files(since_ts, 40, false) {
        // INVARIANT: Subagent/guardian rollouts are never eligible sources of gate review verdicts.
        if is_subagent_rollout_meta(&read_rollout_session_meta(&rf)) {
            continue;
        }
        let Some(parsed) = extract_rollout_texts_and_meta(&rf) else {
            continue;
        };
        if parsed.is_subagent {
            continue;
        }
        for turn in &parsed.turns {
            let Some(bound_packet) = turn
                .review_ids
                .iter()
                .find_map(|rid| known_packets.get(rid))
            else {
                continue;
            };

            let mut verdict: Option<String> = None;
            let mut kind: Option<String> = None;
            let mut verdict_ts = if turn.completed_ts > 0.0 {
                turn.completed_ts
            } else {
                parsed.completed_ts
            };
            for (msg_ts, msg) in turn.assistant_messages.iter().rev() {
                let (dec_kind, dec_verdict) = cwg_common::extract_review_decision(msg);
                if let (Some(dk), Some(dv)) = (dec_kind, dec_verdict) {
                    kind = Some(dk);
                    verdict = Some(dv);
                    if *msg_ts > 0.0 {
                        verdict_ts = *msg_ts;
                    }
                    break;
                }
            }

            if let (Some(v), Some(k)) = (verdict, kind) {
                let pkt_ts = {
                    let cts = val_to_f64(bound_packet.get("created_ts"));
                    if cts > 0.0 {
                        cts
                    } else if turn.started_ts > 0.0 {
                        turn.started_ts
                    } else {
                        parsed.started_ts
                    }
                };
                let eff = if !turn.effort.is_empty() {
                    turn.effort.clone()
                } else if !parsed.effort.is_empty() {
                    parsed.effort.clone()
                } else {
                    let pkt_eff = val_to_str(bound_packet.get("effort"));
                    if pkt_eff.is_empty() {
                        "high".to_string()
                    } else {
                        pkt_eff
                    }
                };
                let mdl = if !turn.model.is_empty() {
                    turn.model.clone()
                } else {
                    parsed.model.clone()
                };
                let eff_verdict_ts = pkt_ts.max(if verdict_ts > 0.0 { verdict_ts } else { pkt_ts });
                let rid_key = val_to_str(bound_packet.get("review_id"));
                let rec = json!({
                    "engine": "codex",
                    "review_id": rid_key,
                    "session_id": parsed.session_id,
                    "kind": k,
                    "verdict": v,
                    "launch_ts": pkt_ts,
                    "verdict_ts": eff_verdict_ts,
                    "xhigh": eff == "xhigh",
                    "model": mdl,
                    "effort": eff,
                    "rollout_path": parsed.path,
                });
                let replace = match by_review_id.get(&rid_key) {
                    None => true,
                    Some(prev) => eff_verdict_ts >= val_to_f64(prev.get("verdict_ts")),
                };
                if replace {
                    by_review_id.insert(rid_key, rec);
                }
            }
        }
    }

    let mut results: Vec<Value> = by_review_id.into_values().collect();
    results.sort_by(|a, b| {
        let la = val_to_f64(a.get("launch_ts"));
        let lb = val_to_f64(b.get("launch_ts"));
        la.total_cmp(&lb).then_with(|| {
            let va = val_to_f64(a.get("verdict_ts"));
            let vb = val_to_f64(b.get("verdict_ts"));
            va.total_cmp(&vb)
        })
    });
    results
}

fn check_rollout_meta_match(
    rf: &Path,
    clean_sid: &str,
    checked: &mut HashSet<PathBuf>,
    meta_cache: &mut HashMap<PathBuf, Map<String, Value>>,
) -> Option<Map<String, Value>> {
    let pb = rf.to_path_buf();
    checked.insert(pb.clone());
    let meta = if let Some(cached) = meta_cache.get(&pb) {
        cached.clone()
    } else {
        let loaded = read_rollout_session_meta(rf);
        meta_cache.insert(pb, loaded.clone());
        loaded
    };
    let id_val = val_to_str(meta.get("id"));
    let meta_id = if !id_val.is_empty() {
        id_val
    } else if !is_subagent_rollout_meta(&meta) {
        val_to_str(meta.get("session_id"))
    } else {
        String::new()
    };
    if meta_id == clean_sid {
        Some(meta)
    } else {
        None
    }
}

fn find_rollout_meta_by_sid(
    sid: &str,
    recent_files: &[PathBuf],
    meta_cache: &mut HashMap<PathBuf, Map<String, Value>>,
) -> Map<String, Value> {
    let clean_sid = sid.trim();
    if clean_sid.is_empty() {
        return Map::new();
    }
    let mut name_hits: Vec<&PathBuf> = Vec::new();
    let mut rest_recent: Vec<&PathBuf> = Vec::new();
    for rf in recent_files {
        let fname = rf.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if fname.contains(clean_sid) {
            name_hits.push(rf);
        } else {
            rest_recent.push(rf);
        }
    }
    let mut checked: HashSet<PathBuf> = HashSet::new();

    for rf in name_hits.into_iter().chain(rest_recent) {
        if let Some(hit) = check_rollout_meta_match(rf, clean_sid, &mut checked, meta_cache) {
            return hit;
        }
    }

    let root = codex_sessions_dir();
    if safe_sid_re().is_match(clean_sid) && root.is_dir() {
        let mut sid_files = Vec::new();
        collect_jsonl_files_rec(&root, None, Some(clean_sid), 8, &mut sid_files);
        for rf in sid_files {
            if checked.contains(&rf) {
                continue;
            }
            if let Some(hit) = check_rollout_meta_match(&rf, clean_sid, &mut checked, meta_cache) {
                return hit;
            }
        }
    }
    Map::new()
}

fn unwrap_primary_session_id(sid: &str, since_ts: f64) -> String {
    // INVARIANT: Codex 0.159+ spawns guardian/subagent rollouts sharing the user prompt; always unwrap to parent thread.
    let mut cur = sid.trim().to_string();
    if cur.is_empty() {
        return String::new();
    }
    let recent_files = recent_rollout_files((since_ts - 60.0).max(0.0), 40, true);
    let mut meta_cache: HashMap<PathBuf, Map<String, Value>> = HashMap::new();
    let mut seen: HashSet<String> = HashSet::new();
    for _ in 0..4 {
        if cur.is_empty() || !seen.insert(cur.clone()) {
            return String::new();
        }
        let meta = find_rollout_meta_by_sid(&cur, &recent_files, &mut meta_cache);
        if meta.is_empty() || !is_subagent_rollout_meta(&meta) {
            return cur;
        }
        cur = val_to_str(meta.get("parent_thread_id")).trim().to_string();
    }
    String::new()
}

fn resolve_resume_session(
    git_root: &str,
    session: &str,
    candidate_first_ts: f64,
    explicit_resume: &str,
    force_new: bool,
) -> String {
    if force_new {
        return String::new();
    }
    let exp = explicit_resume.trim();
    if !exp.is_empty() {
        return unwrap_primary_session_id(exp, candidate_first_ts);
    }
    if let Some(saved) = active_thread_state(session, git_root, Some(candidate_first_ts)) {
        let raw_sid = val_to_str(saved.get("session_id"));
        if !raw_sid.is_empty() {
            let unwrapped = unwrap_primary_session_id(&raw_sid, candidate_first_ts);
            if !unwrapped.is_empty() {
                return unwrapped;
            }
        }
    }
    if !session.is_empty() && candidate_first_ts > 0.0 {
        let prior = scan_verified_codex_reviews(candidate_first_ts, session, git_root);
        for prev in prior.iter().rev() {
            let raw_sid = val_to_str(prev.get("session_id")).trim().to_string();
            if !raw_sid.is_empty() {
                let sid = unwrap_primary_session_id(&raw_sid, candidate_first_ts);
                if !sid.is_empty() {
                    return sid;
                }
            }
        }
    }
    String::new()
}

fn find_session_id_for_review(review_id: &str, since_ts: f64) -> String {
    if review_id.is_empty() {
        return String::new();
    }
    for rf in recent_rollout_files(since_ts, 30, true) {
        // INVARIANT: Never bind candidate review continuity to Codex internal subagent/guardian rollouts.
        if is_subagent_rollout_meta(&read_rollout_session_meta(&rf)) {
            continue;
        }
        let Some(parsed) = extract_rollout_texts_and_meta(&rf) else {
            continue;
        };
        if parsed.session_id.is_empty() || parsed.is_subagent {
            continue;
        }
        for turn in &parsed.turns {
            if turn.review_ids.iter().any(|r| r == review_id) {
                return parsed.session_id;
            }
        }
    }
    String::new()
}

fn find_rollout_turn_state(review_id: &str, since_ts: f64) -> (bool, String, Vec<String>) {
    if review_id.is_empty() {
        return (false, String::new(), Vec::new());
    }
    for rf in recent_rollout_files(since_ts, 30, true) {
        let meta = read_rollout_session_meta(&rf);
        if is_subagent_rollout_meta(&meta) {
            continue;
        }
        let records = rio::read_jsonl(&rf, None);
        if records.is_empty() {
            continue;
        }
        let mut has_rid = false;
        let mut in_target_turn = false;
        let mut err_msgs: Vec<String> = Vec::new();
        let mut tool_outputs: Vec<String> = Vec::new();

        for rec in &records {
            let rec_ts = parse_ts_val(rec.get("timestamp"));
            let rtype = rec.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let empty_map = Map::new();
            let payload = rec
                .get("payload")
                .and_then(|v| v.as_object())
                .unwrap_or(&empty_map);
            let ptype = payload.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let m_ids = rollout_user_review_ids(rtype, payload);
            if !m_ids.is_empty() {
                if m_ids.iter().any(|r| r == review_id) {
                    if !in_target_turn {
                        err_msgs.clear();
                        tool_outputs.clear();
                    }
                    has_rid = true;
                    in_target_turn = true;
                } else {
                    in_target_turn = false;
                }
            } else if rtype == "event_msg" && ptype == "task_complete" {
                in_target_turn = false;
            } else if in_target_turn && (rec_ts <= 0.0 || rec_ts >= since_ts - 2.0) {
                if rtype == "error" {
                    let msg = {
                        let m = val_to_str(payload.get("message"));
                        if m.is_empty() {
                            val_to_str(rec.get("message"))
                        } else {
                            m
                        }
                    }
                    .trim()
                    .to_string();
                    if !msg.is_empty() {
                        err_msgs.push(msg);
                    }
                } else if rtype == "event_msg" && (ptype == "error" || ptype == "stream_error") {
                    let msg = {
                        let m = val_to_str(payload.get("message"));
                        if m.is_empty() {
                            val_to_str(payload.get("error"))
                        } else {
                            m
                        }
                    }
                    .trim()
                    .to_string();
                    if !msg.is_empty() {
                        err_msgs.push(msg);
                    }
                } else if rtype == "response_item"
                    && (ptype == "function_call_output" || ptype == "custom_tool_call_output")
                {
                    if let Some(Value::String(tout)) = payload.get("output") {
                        if !tout.trim().is_empty() {
                            tool_outputs.push(tout.clone());
                        }
                    }
                } else if rtype == "event_msg" && ptype == "exec_command_end" {
                    for k in ["stdout", "stderr", "formatted_output", "aggregated_output"] {
                        if let Some(Value::String(tout)) = payload.get(k) {
                            if !tout.trim().is_empty() {
                                tool_outputs.push(tout.clone());
                            }
                        }
                    }
                }
            }
        }
        if has_rid {
            let sid = val_to_str(meta.get("id")).trim().to_string();
            if !sid.is_empty() {
                set_last_rollout_turn_sid(review_id, &sid);
            }
            return (true, err_msgs.join("\n"), tool_outputs);
        }
    }
    (false, String::new(), Vec::new())
}

fn extract_cli_diagnostic_text(
    stdout_text: &str,
    stderr_text: &str,
    review_id: &str,
    since_ts: f64,
    is_timeout: bool,
    parsed_json: Option<&ParsedJsonStream>,
) -> String {
    // INVARIANT: Combine structured `--json` CLI error events (`error`/`turn.failed`), current-turn rollout error events, and non-tool CLI stderr lines while strictly excluding `command_execution`/`function_call_output` file contents.
    let owned_js;
    let jstream = match parsed_json {
        Some(p) => p,
        None => {
            owned_js = parse_codex_json_stream(stdout_text);
            &owned_js
        }
    };
    let (found_rollout, rollout_err, rollout_tools) = find_rollout_turn_state(review_id, since_ts);
    let mut excluded_tools = jstream.tool_outputs.clone();
    excluded_tools.extend(rollout_tools);

    let mut parts: Vec<String> = Vec::new();
    for jerr in &jstream.cli_errors {
        if !jerr.is_empty() {
            parts.push(jerr.clone());
        }
    }
    if !rollout_err.is_empty() {
        parts.push(rollout_err);
    }
    let stderr_diag = extract_cli_error_lines(stderr_text, &excluded_tools);
    if !stderr_diag.is_empty() {
        parts.push(stderr_diag);
    }
    if jstream.saw_jsonl || is_timeout || found_rollout {
        return parts.join("\n");
    }
    let stdout_diag = extract_cli_error_lines(stdout_text, &excluded_tools);
    if !stdout_diag.is_empty() {
        parts.push(stdout_diag);
    }
    let combined = format!("{}\n{}", stdout_text, stderr_text)
        .trim()
        .to_string();
    if parts.is_empty() && combined.len() <= 2048 {
        return combined;
    }
    parts.join("\n")
}

fn read_diff_file(path: &str) -> String {
    let Ok(raw) = fs::read(path) else {
        return String::new();
    };
    let text = if raw.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = raw[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else if raw.starts_with(&[0xFE, 0xFF]) {
        let units: Vec<u16> = raw[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else if raw.starts_with(&[0xEF, 0xBB, 0xBF]) {
        String::from_utf8_lossy(&raw[3..]).into_owned()
    } else {
        String::from_utf8_lossy(&raw).into_owned()
    };
    text.replace('\0', "")
}

fn build_codex_exec_args(
    cwd: &str,
    effort: &str,
    model: &str,
    resume_session_id: &str,
) -> Vec<String> {
    let mut common_opts = vec![
        "--json".to_string(),
        "--skip-git-repo-check".to_string(),
        "-c".to_string(),
        "mcp_servers={}".to_string(),
        "-c".to_string(),
        "sandbox_mode=\"read-only\"".to_string(),
        "-c".to_string(),
        format!("model_reasoning_effort=\"{}\"", effort),
        "--disable".to_string(),
        "codex_hooks".to_string(),
    ];
    if !model.is_empty() {
        common_opts.push("-m".to_string());
        common_opts.push(model.to_string());
    }
    let mut args = vec!["exec".to_string()];
    if !resume_session_id.is_empty() {
        // INVARIANT: `codex exec resume` rejects `-s` and `-C`; rely on `-c sandbox_mode="read-only"`, `cwd=cwd`, and `--all`.
        args.push("resume".to_string());
        args.push("--all".to_string());
        args.extend(common_opts);
        args.push(resume_session_id.to_string());
        args.push("-".to_string());
    } else {
        args.push("-s".to_string());
        args.push("read-only".to_string());
        args.push("-C".to_string());
        args.push(cwd.to_string());
        args.extend(common_opts);
        args.push("-".to_string());
    }
    args
}

fn build_adversarial_prompt(
    review_id: &str,
    scope_summary: &str,
    diff_text: &str,
    phase: &str,
    is_resume: bool,
    is_timeout_resume: bool,
) -> String {
    let verdict_rule = if phase == "closure" {
        "Respond in plain text/markdown (not JSON) and conclude with an exact standalone line:\n\
CLOSURE_VALIDATION: READY\n\
or\n\
CLOSURE_VALIDATION: BLOCKED\n\
Choose BLOCKED only if concrete correctness, security, data-loss, or contract regressions remain."
    } else {
        "Respond in plain text/markdown (not JSON) and conclude with an exact standalone line:\n\
VERDICT: APPROVED\n\
or\n\
VERDICT: REVISE\n\
or (round 3 only when fundamental design trade-offs remain)\n\
VERDICT: ESCALATE\n\
Approve when no real correctness, security, concurrency, edge-case, or contract defects exist. \
Do not invent nitpicks to justify REVISE."
    };

    let round_mode = if is_timeout_resume {
        "ROUND_MODE: timeout_continuation (same review thread — your previous review turn hit the wall-clock timeout \
before emitting a final verdict; continue from the repository context already inspected in this thread \
without starting over, and conclude with your findings and exact standalone verdict line).\n"
    } else if is_resume {
        "ROUND_MODE: continuation (same review thread — verify whether prior findings are resolved, \
check remediation delta for regressions, and do not invent nitpicks on unchanged code).\n"
    } else {
        ""
    };

    let diff_snapshot: String = match diff_text.char_indices().nth(MAX_DIFF_SNAPSHOT_CHARS) {
        Some((idx, _)) => diff_text[..idx].to_string(),
        None => diff_text.to_string(),
    };

    format!(
        "REVIEW_ID: {}\n\
ROLE: Independent Adversarial Code Reviewer (Read-Only).\n\
{}\
RULES:\n\
1. Do NOT modify any files. Inspect repository files directly if needed for context.\n\
2. Verify invariants, failure paths, security boundaries, concurrency, and test coverage.\n\
3. Separate confirmed defects ([HIGH]/[MEDIUM]) from non-blocking observations.\n\
4. {}\n\n\
CANDIDATE SUMMARY:\n{}\n\n\
GIT DIFF SNAPSHOT:\n{}\n",
        review_id, round_mode, verdict_rule, scope_summary, diff_snapshot
    )
}

struct CodexExecResult {
    rc: i32,
    stdout: String,
    stderr: String,
    has_verdict: bool,
    outage: Option<String>,
    network_outage: Option<String>,
    sandbox_blocked: Option<String>,
    thread_id: String,
}

fn is_permission_spawn_err(err: &str) -> bool {
    let low = err.to_lowercase();
    low.contains("permission denied")
        || low.contains("access is denied")
        || low.contains("os error 5")
        || low.contains("os error 13")
}

fn exec_codex_once(
    binary: &str,
    args: &[String],
    prompt: &str,
    cwd: &str,
    timeout: f64,
    review_id: &str,
    xhigh: bool,
) -> Option<CodexExecResult> {
    let t_start = now_sec();
    let timeout_ms = ((timeout.max(0.1)) * 1000.0).round() as u64;
    let res = match run_command_with_job(
        binary,
        args,
        Some(Path::new(cwd)),
        &[],
        Some(prompt.as_bytes()),
        Some(timeout_ms),
    ) {
        Ok(r) => r,
        Err(exc) => {
            if is_permission_spawn_err(&exc) {
                let msg = format!("PermissionError: [Errno 13] {}", exc);
                return Some(CodexExecResult {
                    rc: 2,
                    stdout: String::new(),
                    stderr: msg.clone(),
                    has_verdict: false,
                    outage: None,
                    network_outage: None,
                    sandbox_blocked: Some(msg),
                    thread_id: String::new(),
                });
            }
            set_last_timeout_outage(review_id, "error", "");
            rio::print_cli_json(
                &json!({
                    "ok": false,
                    "review_id": review_id,
                    "error": exc,
                }),
                false,
            );
            return None;
        }
    };

    if res.timed_out {
        let partial_stdout_txt = res.stdout_str();
        let partial_stderr_txt = res.stderr_str();
        let jstream_to = parse_codex_json_stream(&partial_stdout_txt);
        let diag_timeout = extract_cli_diagnostic_text(
            &partial_stdout_txt,
            &partial_stderr_txt,
            review_id,
            t_start - 1.0,
            true,
            Some(&jstream_to),
        );
        let provider_outage = detect_outage_from_output(&diag_timeout, 1);
        let net_outage = provider_outage
            .clone()
            .or_else(|| detect_network_timeout_from_output(&diag_timeout));
        let sb_err = if net_outage.is_some() {
            None
        } else {
            detect_sandbox_restriction(&diag_timeout)
        };
        if let Some(sb) = sb_err {
            set_last_timeout_outage(review_id, "sandbox", "");
            rio::print_cli_json(
                &json!({
                    "ok": false,
                    "review_id": review_id,
                    "sandbox_blocked": true,
                    "round_consumed": false,
                    "error": format!("sandbox_restricted ({}); re-run codex_lane.py review with BypassSandbox=true", sb),
                }),
                false,
            );
            return None;
        }
        if let Some(net_reason) = net_outage {
            // SAFETY: Only genuine internet/API/quota failures during a timeout authorize fallback; local thinking timeouts never do.
            set_last_timeout_outage(review_id, "network", "");
            if let Some(po) = provider_outage {
                trip_breaker(&po, BREAKER_TTL_SECONDS);
            }
            rio::log_hook_event(
                "gate-events",
                "codex_review_network_timeout",
                json!({
                    "review_id": review_id,
                    "timeout": timeout as i64,
                    "reason": net_reason,
                }),
            );
            rio::print_cli_json(
                &json!({
                    "ok": false,
                    "review_id": review_id,
                    "network_outage": true,
                    "outage_reason": net_reason,
                    "round_consumed": false,
                    "fallback": fallback_reviewer(xhigh),
                    "error": format!("timeout_after_{}s", timeout as i64),
                }),
                false,
            );
            return None;
        }

        rio::log_hook_event(
            "gate-events",
            "codex_review_timeout",
            json!({
                "review_id": review_id,
                "timeout": timeout as i64,
            }),
        );
        let recommended_timeout = next_timeout_after(timeout as i64);
        let cached_rollout_sid = pop_last_rollout_turn_sid(review_id);
        let mut timeout_sid = if !jstream_to.thread_id.is_empty() {
            unwrap_primary_session_id(&jstream_to.thread_id, t_start - 1.0)
        } else {
            String::new()
        };
        if timeout_sid.is_empty() && !cached_rollout_sid.is_empty() {
            timeout_sid = unwrap_primary_session_id(&cached_rollout_sid, t_start - 1.0);
        }
        if timeout_sid.is_empty() {
            timeout_sid = find_session_id_for_review(review_id, t_start - 1.0);
        }
        set_last_timeout_outage(review_id, "thinking", &timeout_sid);
        let mut payload_to = Map::new();
        payload_to.insert("ok".to_string(), Value::Bool(false));
        payload_to.insert("review_id".to_string(), Value::String(review_id.to_string()));
        payload_to.insert("timed_out".to_string(), Value::Bool(true));
        payload_to.insert("retry_in_same_lane".to_string(), Value::Bool(true));
        payload_to.insert("round_consumed".to_string(), Value::Bool(false));
        payload_to.insert("recommended_timeout".to_string(), json!(recommended_timeout));
        payload_to.insert(
            "error".to_string(),
            Value::String(format!("timeout_after_{}s", timeout as i64)),
        );
        payload_to.insert(
            "hint".to_string(),
            Value::String(format!(
                "Codex did not finish within {}s (thinking timeout, NOT an outage; review round NOT consumed). Re-run codex_lane.py review without --timeout to continue the same Codex session with {}s timeout; escalating to internal review on a thinking timeout is forbidden.",
                timeout as i64, recommended_timeout
            )),
        );
        if !timeout_sid.is_empty() {
            payload_to.insert("session_id".to_string(), Value::String(timeout_sid));
        }
        rio::print_cli_json(&Value::Object(payload_to), false);
        return None;
    }

    let raw_stdout_text = res.stdout_str();
    let stderr_text = res.stderr_str();
    let jstream_exit = parse_codex_json_stream(&raw_stdout_text);
    let stream_tid = jstream_exit.thread_id.clone();
    let stdout_text = if jstream_exit.saw_jsonl {
        jstream_exit.agent_text.clone()
    } else {
        raw_stdout_text.clone()
    };
    let has_structured_verdict = cwg_common::extract_review_decision(&stdout_text) != (None, None);
    if res.code == 0 && has_structured_verdict {
        return Some(CodexExecResult {
            rc: 0,
            stdout: stdout_text,
            stderr: stderr_text,
            has_verdict: true,
            outage: None,
            network_outage: None,
            sandbox_blocked: None,
            thread_id: stream_tid,
        });
    }

    let diag_exit = extract_cli_diagnostic_text(
        &raw_stdout_text,
        &stderr_text,
        review_id,
        t_start - 1.0,
        false,
        Some(&jstream_exit),
    );
    let eff_stderr = if jstream_exit.saw_jsonl {
        let joined: Vec<&str> = jstream_exit
            .cli_errors
            .iter()
            .map(String::as_str)
            .filter(|s| !s.is_empty())
            .collect();
        if joined.is_empty() {
            stderr_text
        } else {
            joined.join("\n")
        }
    } else {
        stderr_text
    };
    let outage = detect_outage_from_output(&diag_exit, res.code);
    let net_err = if outage.is_none() && res.code != 0 {
        detect_network_timeout_from_output(&diag_exit)
    } else {
        None
    };
    let sb_exit = if outage.is_none() && net_err.is_none() && res.code != 0 {
        detect_sandbox_restriction(&diag_exit)
    } else {
        None
    };
    Some(CodexExecResult {
        rc: res.code,
        stdout: stdout_text,
        stderr: eff_stderr,
        has_verdict: has_structured_verdict,
        outage,
        network_outage: net_err,
        sandbox_blocked: sb_exit,
        thread_id: stream_tid,
    })
}

struct PacketCleanupGuard {
    review_id: String,
    committed: bool,
}

impl Drop for PacketCleanupGuard {
    fn drop(&mut self) {
        if !self.committed {
            unlink_packet(&self.review_id);
        }
    }
}

struct ReviewArgs {
    cwd: String,
    summary: String,
    diff_file: String,
    review_id: String,
    session: String,
    model: String,
    resume: String,
    new_session: bool,
    xhigh: bool,
    closure: bool,
    phase: String,
    timeout: Option<i64>,
    pretty: bool,
}

fn cmd_review(args: &ReviewArgs) -> i32 {
    if !args.review_id.is_empty() && packet_path(&args.review_id).exists() {
        rio::print_cli_json(
            &json!({
                "ok": false,
                "error": format!("duplicate_review_id:{}", args.review_id),
            }),
            args.pretty,
        );
        return 2;
    }

    let health = check_health();
    if !json_truthy(health.get("available")) {
        rio::print_cli_json(&health, args.pretty);
        return 2;
    }
    let binary = val_to_str(health.get("binary"));

    let cwd_raw = if args.cwd.trim().is_empty() {
        env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .to_string_lossy()
            .into_owned()
    } else {
        args.cwd.clone()
    };
    let cwd = abs_path_from_str(&cwd_raw).to_string_lossy().into_owned();
    let git_root = rio::git_toplevel(&cwd, false).unwrap_or_else(|| cwd.clone());
    let effort = if args.xhigh { "xhigh" } else { "high" };
    let phase = if args.closure || args.phase == "closure" {
        "closure"
    } else {
        "ordinary"
    };
    let review_id = if args.review_id.is_empty() {
        format!("cwg-{}", random_hex_12())
    } else {
        args.review_id.clone()
    };
    let eff_session = if args.session.is_empty() {
        infer_single_open_session(&cwd)
    } else {
        args.session.clone()
    };
    let cand_first_ts = candidate_first_ts(&eff_session);
    let resume_sid = resolve_resume_session(
        &git_root,
        &eff_session,
        cand_first_ts,
        &args.resume,
        args.new_session,
    );

    let diff_text = if !args.diff_file.is_empty() && Path::new(&args.diff_file).is_file() {
        read_diff_file(&args.diff_file)
    } else {
        let (rc_git, out, _) = rio::run_git(&cwd, &["diff", "HEAD"], 10.0);
        if rc_git == 0 && !out.trim().is_empty() {
            out
        } else {
            let (_, out2, _) = rio::run_git(&cwd, &["status", "--short"], 5.0);
            out2
        }
    };

    let scope_summary = if args.summary.is_empty() {
        "Review current repository candidate changes.".to_string()
    } else {
        args.summary.clone()
    };

    let saved_thread = if args.new_session {
        None
    } else {
        active_thread_state(&eff_session, &git_root, Some(cand_first_ts))
    };
    let is_timeout_continuation = saved_thread
        .as_ref()
        .map_or(false, |st| json_truthy(st.get("pending_timeout_resume")));
    let saved_next_timeout: i64 = if is_timeout_continuation {
        saved_thread
            .as_ref()
            .map(|st| val_to_f64(st.get("next_timeout_seconds")) as i64)
            .unwrap_or(0)
    } else {
        0
    };

    let min_required_timeout = required_review_timeout(args.xhigh, saved_next_timeout);
    let has_codex_override = env::var("CARBON_CODEX_BIN")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    if let Some(custom_to) = args.timeout {
        if !has_codex_override {
            // INVARIANT: Reject upfront or shrunk custom `--timeout` in live runs; standard defaults are 600s (HIGH) and 900s (XHIGH).
            if !is_timeout_continuation {
                rio::print_cli_json(
                    &json!({
                        "ok": false,
                        "invalid_timeout": true,
                        "error": format!(
                            "Upfront custom --timeout is forbidden; omit --timeout so codex_lane.py uses the standard {}s (HIGH) / {}s (--xhigh) timeout.",
                            DEFAULT_REVIEW_TIMEOUT_SECONDS, DEFAULT_XHIGH_REVIEW_TIMEOUT_SECONDS
                        ),
                    }),
                    args.pretty,
                );
                return 2;
            }
            if custom_to < min_required_timeout {
                rio::print_cli_json(
                    &json!({
                        "ok": false,
                        "invalid_timeout": true,
                        "error": format!(
                            "Custom --timeout {}s is below required continuation timeout ({}s); omit --timeout to continue automatically with increased timeout.",
                            custom_to, min_required_timeout
                        ),
                    }),
                    args.pretty,
                );
                return 2;
            }
        }
    }

    let eff_timeout = args.timeout.unwrap_or(min_required_timeout) as f64;
    let attempts: Vec<String> = if !resume_sid.is_empty() {
        vec![resume_sid.clone(), String::new()]
    } else {
        vec![String::new()]
    };

    let mut final_exec_res: Option<CodexExecResult> = None;
    let mut launch_wall_ts = 0.0f64;
    let mut used_resume_sid = String::new();
    let mut active_review_id = review_id.clone();

    for (attempt_idx, cur_resume_sid) in attempts.iter().enumerate() {
        active_review_id = if attempt_idx == 0 || !args.review_id.is_empty() {
            review_id.clone()
        } else {
            format!("cwg-{}", random_hex_12())
        };
        let prompt = build_adversarial_prompt(
            &active_review_id,
            &scope_summary,
            &diff_text,
            phase,
            !cur_resume_sid.is_empty(),
            !cur_resume_sid.is_empty() && is_timeout_continuation,
        );
        record_packet(
            &active_review_id,
            &prompt,
            &cwd,
            effort,
            phase,
            &eff_session,
        );
        if !packet_path(&active_review_id).is_file() {
            // SAFETY: Inside Standard Sandbox (`BypassSandbox=false`), `CARBON_STACK_HOME` is read-only; fail fast without hanging on blocked network sockets, without tripping the global breaker, and without granting fallback.
            rio::print_cli_json(
                &json!({
                    "ok": false,
                    "sandbox_blocked": true,
                    "error": "CARBON_STACK_HOME is not writable in sandbox; re-run codex_lane.py review with BypassSandbox=true",
                }),
                args.pretty,
            );
            return 2;
        }

        let mut pkt_guard = PacketCleanupGuard {
            review_id: active_review_id.clone(),
            committed: false,
        };
        launch_wall_ts = now_sec();
        let cmd_args = build_codex_exec_args(&cwd, effort, &args.model, cur_resume_sid);
        let exec_opt = exec_codex_once(
            &binary,
            &cmd_args,
            &prompt,
            &cwd,
            eff_timeout,
            &active_review_id,
            args.xhigh,
        );
        let Some(exec_res) = exec_opt else {
            let (timeout_kind, stream_sid) = pop_last_timeout_outage(&active_review_id);
            if timeout_kind == "thinking" {
                // INVARIANT: Persist timed-out Codex thread + elevated timeout so retry resumes the same lane without losing a round.
                let mut timeout_sid = stream_sid;
                if timeout_sid.is_empty() {
                    timeout_sid =
                        find_session_id_for_review(&active_review_id, launch_wall_ts - 1.0);
                }
                if timeout_sid.is_empty() && !cur_resume_sid.is_empty() {
                    timeout_sid = unwrap_primary_session_id(cur_resume_sid, cand_first_ts);
                }
                if timeout_sid.is_empty() {
                    if let Some(ref st) = saved_thread {
                        timeout_sid = val_to_str(st.get("session_id"));
                    }
                }
                let next_to = next_timeout_after(eff_timeout as i64);
                let _ = rio::write_json(
                    &thread_state_path(&eff_session, &git_root),
                    &json!({
                        "session_id": timeout_sid,
                        "last_review_id": active_review_id,
                        "session": eff_session,
                        "git_root": rio::normalize_path(&git_root),
                        "candidate_first_ts": cand_first_ts,
                        "pending_timeout_resume": true,
                        "last_timeout_seconds": eff_timeout as i64,
                        "next_timeout_seconds": next_to,
                        "updated_ts": now_sec(),
                    }),
                );
            } else if timeout_kind == "network" {
                clear_pending_timeout_resume(&eff_session, &git_root);
            }
            return 3;
        };

        used_resume_sid = cur_resume_sid.clone();
        let _ = pop_last_rollout_turn_sid(&active_review_id);

        // SAFETY: Fall back once to a fresh primary session if resuming an invalid or verdict-less thread (never on sandbox block).
        if attempt_idx == 0
            && !cur_resume_sid.is_empty()
            && !exec_res.has_verdict
            && exec_res.outage.is_none()
            && exec_res.network_outage.is_none()
            && exec_res.sandbox_blocked.is_none()
        {
            unlink_quiet(&thread_state_path(&eff_session, &git_root));
            continue;
        }
        if exec_res.outage.is_none() && exec_res.network_outage.is_none() && exec_res.rc == 0 {
            pkt_guard.committed = true;
        }
        final_exec_res = Some(exec_res);
        break;
    }

    let Some(exec_res) = final_exec_res else {
        return 2;
    };

    if exec_res.outage.is_some() || exec_res.network_outage.is_some() || exec_res.rc != 0 {
        if let Some(ref sb) = exec_res.sandbox_blocked {
            rio::print_cli_json(
                &json!({
                    "ok": false,
                    "review_id": active_review_id,
                    "exit_code": exec_res.rc,
                    "sandbox_blocked": true,
                    "error": format!("sandbox_restricted ({}); re-run codex_lane.py review with BypassSandbox=true", sb),
                }),
                args.pretty,
            );
            return 2;
        }
        let eff_outage = exec_res
            .outage
            .as_deref()
            .or(exec_res.network_outage.as_deref())
            .unwrap_or("");
        if let Some(ref o) = exec_res.outage {
            trip_breaker(o, BREAKER_TTL_SECONDS);
        }
        if !eff_outage.is_empty() {
            clear_pending_timeout_resume(&eff_session, &git_root);
        }
        let err_detail = {
            let se = exec_res.stderr.trim();
            if !se.is_empty() {
                se
            } else {
                exec_res.stdout.trim()
            }
        };
        let err_msg = if !eff_outage.is_empty() && !err_detail.is_empty() && !err_detail.contains(eff_outage) {
            format!("{}: {}", eff_outage, err_detail)
        } else if !eff_outage.is_empty() {
            eff_outage.trim().to_string()
        } else {
            err_detail.trim().to_string()
        };
        let mut err_obj = Map::new();
        err_obj.insert("ok".to_string(), Value::Bool(false));
        err_obj.insert("review_id".to_string(), Value::String(active_review_id));
        err_obj.insert("exit_code".to_string(), json!(exec_res.rc));
        err_obj.insert("error".to_string(), Value::String(err_msg));
        if let Some(ref net_o) = exec_res.network_outage {
            err_obj.insert("network_outage".to_string(), Value::Bool(true));
            err_obj.insert("outage_reason".to_string(), Value::String(net_o.clone()));
        }
        if !eff_outage.is_empty() {
            err_obj.insert(
                "fallback".to_string(),
                Value::String(fallback_reviewer(args.xhigh).to_string()),
            );
        }
        rio::print_cli_json(&Value::Object(err_obj), args.pretty);
        return 2;
    }

    let mut actual_sid = if !exec_res.thread_id.is_empty() {
        unwrap_primary_session_id(&exec_res.thread_id, cand_first_ts)
    } else {
        String::new()
    };
    if actual_sid.is_empty() {
        actual_sid = find_session_id_for_review(&active_review_id, launch_wall_ts);
    }
    if actual_sid.is_empty() && !used_resume_sid.is_empty() {
        actual_sid = unwrap_primary_session_id(&used_resume_sid, cand_first_ts);
    }

    if exec_res.has_verdict {
        if !actual_sid.is_empty() {
            let _ = rio::write_json(
                &thread_state_path(&eff_session, &git_root),
                &json!({
                    "session_id": actual_sid,
                    "last_review_id": active_review_id,
                    "session": eff_session,
                    "git_root": rio::normalize_path(&git_root),
                    "candidate_first_ts": cand_first_ts,
                    "updated_ts": now_sec(),
                }),
            );
        } else if is_timeout_continuation {
            unlink_quiet(&thread_state_path(&eff_session, &git_root));
        }
    }

    let session_mode = if !used_resume_sid.is_empty() {
        "resumed"
    } else {
        "new"
    };
    let output_block = format!(
        "REVIEW_ID: {}\nSESSION_ID: {}\nSESSION_MODE: {}\nENGINE: codex ({})\n{}\n{}\n",
        active_review_id,
        actual_sid,
        session_mode,
        effort,
        cwg_common::CODEX_REVIEW_OUTPUT_BANNER,
        exec_res.stdout.trim()
    );
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(output_block.as_bytes());
    let _ = out.flush();
    0
}

fn parse_flag_value(args: &[String], idx: &mut usize, flag: &str) -> Result<Option<String>, String> {
    let tok = &args[*idx];
    if tok == flag {
        if *idx + 1 >= args.len() {
            return Err(format!("error: argument {}: expected one argument", flag));
        }
        let val = args[*idx + 1].clone();
        *idx += 2;
        return Ok(Some(val));
    }
    if let Some(rest) = tok.strip_prefix(&format!("{}=", flag)) {
        *idx += 1;
        return Ok(Some(rest.to_string()));
    }
    Ok(None)
}

fn count_active_threads() -> usize {
    let Ok(entries) = fs::read_dir(threads_dir()) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
        .count()
}

pub fn run_cli(args: &[String]) -> i32 {
    if args.is_empty() {
        let _ = writeln!(
            std::io::stderr(),
            "usage: codex_lane <check|status|reset|breaker|scan|review> [args...]"
        );
        return 2;
    }
    let sub = args[0].as_str();
    let rest = &args[1..];
    match sub {
        "check" => {
            let mut pretty = false;
            for tok in rest {
                if tok == "--pretty" {
                    pretty = true;
                } else if tok == "--json" {
                    pretty = false;
                } else {
                    let _ = writeln!(std::io::stderr(), "error: unrecognized arguments: {}", tok);
                    return 2;
                }
            }
            let res = check_health();
            rio::print_cli_json(&res, pretty);
            if json_truthy(res.get("available")) {
                0
            } else {
                1
            }
        }
        "status" => {
            let mut pretty = false;
            for tok in rest {
                if tok == "--pretty" {
                    pretty = true;
                } else {
                    let _ = writeln!(std::io::stderr(), "error: unrecognized arguments: {}", tok);
                    return 2;
                }
            }
            sweep_expired_gate_files();
            let st_obj = json!({
                "breaker": breaker_status(),
                "binary": find_codex_binary(),
                "sessions_dir_exists": codex_sessions_dir().is_dir(),
                "active_threads": count_active_threads(),
            });
            rio::print_cli_json(&st_obj, pretty);
            0
        }
        "reset" => {
            if !rest.is_empty() {
                let _ = writeln!(
                    std::io::stderr(),
                    "error: unrecognized arguments: {}",
                    rest.join(" ")
                );
                return 2;
            }
            reset_breaker();
            rio::print_cli_json(&json!({ "reset": true }), false);
            0
        }
        "breaker" => {
            let mut do_reset = false;
            let mut pretty = false;
            for tok in rest {
                if tok == "--reset" {
                    do_reset = true;
                } else if tok == "--pretty" {
                    pretty = true;
                } else {
                    let _ = writeln!(std::io::stderr(), "error: unrecognized arguments: {}", tok);
                    return 2;
                }
            }
            if do_reset {
                reset_breaker();
                rio::print_cli_json(&json!({ "reset": true }), pretty);
            } else {
                rio::print_cli_json(&breaker_status(), pretty);
            }
            0
        }
        "scan" => {
            let mut since_ts = 0.0f64;
            let mut session = String::new();
            let mut cwd = String::new();
            let mut git_root = String::new();
            let mut pretty = false;
            let mut i = 0usize;
            while i < rest.len() {
                match parse_flag_value(rest, &mut i, "--since") {
                    Ok(Some(v)) => {
                        let Ok(ts) = v.trim().parse::<f64>() else {
                            let _ = writeln!(
                                std::io::stderr(),
                                "error: argument --since: invalid float value: '{}'",
                                v
                            );
                            return 2;
                        };
                        since_ts = ts;
                        continue;
                    }
                    Err(e) => {
                        let _ = writeln!(std::io::stderr(), "{}", e);
                        return 2;
                    }
                    Ok(None) => {}
                }
                match parse_flag_value(rest, &mut i, "--session") {
                    Ok(Some(v)) => {
                        session = v;
                        continue;
                    }
                    Err(e) => {
                        let _ = writeln!(std::io::stderr(), "{}", e);
                        return 2;
                    }
                    Ok(None) => {}
                }
                match parse_flag_value(rest, &mut i, "--cwd") {
                    Ok(Some(v)) => {
                        cwd = v;
                        continue;
                    }
                    Err(e) => {
                        let _ = writeln!(std::io::stderr(), "{}", e);
                        return 2;
                    }
                    Ok(None) => {}
                }
                match parse_flag_value(rest, &mut i, "--git-root") {
                    Ok(Some(v)) => {
                        git_root = v;
                        continue;
                    }
                    Err(e) => {
                        let _ = writeln!(std::io::stderr(), "{}", e);
                        return 2;
                    }
                    Ok(None) => {}
                }
                if rest[i] == "--pretty" {
                    pretty = true;
                    i += 1;
                    continue;
                }
                let _ = writeln!(
                    std::io::stderr(),
                    "error: unrecognized arguments: {}",
                    rest[i]
                );
                return 2;
            }
            if git_root.is_empty() && !cwd.is_empty() {
                git_root = rio::git_toplevel(&cwd, false).unwrap_or(cwd);
            }
            let reviews = scan_verified_codex_reviews(since_ts, &session, &git_root);
            rio::print_cli_json(&Value::Array(reviews), pretty);
            0
        }
        "review" => {
            let mut rargs = ReviewArgs {
                cwd: String::new(),
                summary: String::new(),
                diff_file: String::new(),
                review_id: String::new(),
                session: String::new(),
                model: String::new(),
                resume: String::new(),
                new_session: false,
                xhigh: false,
                closure: false,
                phase: String::new(),
                timeout: None,
                pretty: false,
            };
            let mut i = 0usize;
            while i < rest.len() {
                let tok = &rest[i];
                if tok == "--new-session" {
                    rargs.new_session = true;
                    i += 1;
                    continue;
                }
                if tok == "--xhigh" {
                    rargs.xhigh = true;
                    i += 1;
                    continue;
                }
                if tok == "--closure" {
                    rargs.closure = true;
                    i += 1;
                    continue;
                }
                if tok == "--pretty" {
                    rargs.pretty = true;
                    i += 1;
                    continue;
                }

                let mut str_flags = [
                    ("--cwd", &mut rargs.cwd),
                    ("--summary", &mut rargs.summary),
                    ("--diff-file", &mut rargs.diff_file),
                    ("--review-id", &mut rargs.review_id),
                    ("--session", &mut rargs.session),
                    ("--model", &mut rargs.model),
                    ("--resume", &mut rargs.resume),
                ];
                let mut matched_str = false;
                for (flag, slot) in str_flags.iter_mut() {
                    if *flag == tok.as_str() || tok.starts_with(&format!("{}=", flag)) {
                        match parse_flag_value(rest, &mut i, flag) {
                            Ok(Some(v)) => {
                                **slot = v;
                                matched_str = true;
                                break;
                            }
                            Ok(None) => {}
                            Err(e) => {
                                let _ = writeln!(std::io::stderr(), "{}", e);
                                return 2;
                            }
                        }
                    }
                }
                if matched_str {
                    continue;
                }

                match parse_flag_value(rest, &mut i, "--phase") {
                    Ok(Some(v)) => {
                        if v != "ordinary" && v != "closure" {
                            let _ = writeln!(
                                std::io::stderr(),
                                "error: argument --phase: invalid choice: '{}' (choose from 'ordinary', 'closure')",
                                v
                            );
                            return 2;
                        }
                        rargs.phase = v;
                        continue;
                    }
                    Err(e) => {
                        let _ = writeln!(std::io::stderr(), "{}", e);
                        return 2;
                    }
                    Ok(None) => {}
                }

                match parse_flag_value(rest, &mut i, "--timeout") {
                    Ok(Some(v)) => {
                        let Ok(parsed_to) = v.trim().parse::<i64>() else {
                            let _ = writeln!(
                                std::io::stderr(),
                                "error: argument --timeout: invalid int value: '{}'",
                                v
                            );
                            return 2;
                        };
                        rargs.timeout = Some(parsed_to);
                        continue;
                    }
                    Err(e) => {
                        let _ = writeln!(std::io::stderr(), "{}", e);
                        return 2;
                    }
                    Ok(None) => {}
                }

                let _ = writeln!(std::io::stderr(), "error: unrecognized arguments: {}", tok);
                return 2;
            }
            cmd_review(&rargs)
        }
        other => {
            let _ = writeln!(
                std::io::stderr(),
                "usage: codex_lane <check|status|reset|breaker|scan|review> (invalid choice: '{}')",
                other
            );
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EnvVarGuard {
        saved: Vec<(&'static str, Option<String>)>,
    }

    impl EnvVarGuard {
        fn set(vars: &[(&'static str, Option<&str>)]) -> Self {
            let mut saved = Vec::with_capacity(vars.len());
            for &(k, v) in vars {
                saved.push((k, env::var(k).ok()));
                match v {
                    Some(val) => env::set_var(k, val),
                    None => env::remove_var(k),
                }
            }
            Self { saved }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            for (k, prev) in self.saved.iter().rev() {
                match prev {
                    Some(v) => env::set_var(k, v),
                    None => env::remove_var(k),
                }
            }
        }
    }

    struct TempTestDir(PathBuf);

    impl TempTestDir {
        fn new(tag: &str) -> Self {
            let p = env::temp_dir().join(format!("carbon-codex-test-{}-{}", tag, random_hex_12()));
            fs::create_dir_all(&p).expect("create temp dir");
            Self(p)
        }
    }

    impl Drop for TempTestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn test_all_regexes_compile() {
        let _ = outage_patterns();
        let _ = review_id_re();
        let _ = aborted_rid_re();
        let _ = cli_arg_error_re();
        let _ = null_pipe_prefix_re();
        let _ = python_exe_base_re();
        let _ = sandbox_block_patterns();
        let _ = network_timeout_patterns();
        let _ = cli_diag_line_re();
        let _ = stderr_tool_open_re();
        let _ = stderr_section_reset_re();
        let _ = safe_sid_re();
        let _ = codex_cli_wrapper_re();

        assert!(review_id_re().is_match("REVIEW_ID: cwg-abc123def456"));
        assert!(aborted_rid_re().is_match("cwg-abc123def456"));
        assert!(!aborted_rid_re().is_match("bad rid!"));
        assert!(cli_arg_error_re().is_match("usage: codex_lane\nerror: unrecognized arguments: --foo"));
        assert!(detect_outage_from_output("429 Too Many Requests", 1).is_some());
        assert!(detect_network_timeout_from_output("TLS handshake timeout").is_some());
        assert!(detect_sandbox_restriction("Operation not permitted").is_some());
    }

    #[test]
    fn test_find_codex_binary_and_breaker() {
        let _lock = crate::win32_sqlite::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempTestDir::new("breaker");
        let stack_home = tmp.0.join("stack");
        let fake_bin = tmp.0.join("codex.cmd");
        fs::write(&fake_bin, "@echo off\r\n").expect("write fake bin");

        let _env = EnvVarGuard::set(&[
            ("CARBON_STACK_HOME", Some(&stack_home.to_string_lossy())),
            ("CARBON_CODEX_BIN", Some(&fake_bin.to_string_lossy())),
        ]);

        assert_eq!(
            find_codex_binary().as_deref(),
            Some(fake_bin.to_string_lossy().as_ref())
        );

        let missing_bin = tmp.0.join("no-such-codex.cmd");
        env::set_var("CARBON_CODEX_BIN", &missing_bin);
        assert_eq!(find_codex_binary(), None);

        reset_breaker();
        assert_eq!(breaker_status()["tripped"], Value::Bool(false));
        trip_breaker("quota exceeded", 600);
        let st = breaker_status();
        assert_eq!(st["tripped"], Value::Bool(true));
        assert_eq!(st["reason"], Value::String("quota exceeded".to_string()));
        reset_breaker();
        assert_eq!(breaker_status()["tripped"], Value::Bool(false));
    }

    #[test]
    fn test_inspect_codex_cmd_result_variants() {
        let cmd_lane = r#"$null | python -X utf8 "C:\hooks\codex_lane.py" review --cwd C:\repo"#;
        let thinking_out = json!({
            "ok": false,
            "review_id": "cwg-think01",
            "timed_out": true,
            "retry_in_same_lane": true,
            "round_consumed": false,
            "error": "timeout_after_600s"
        })
        .to_string();
        let (outage_to, aborted_to) = inspect_codex_cmd_result(cmd_lane, "ERROR", &thinking_out);
        assert!(!outage_to);
        assert_eq!(aborted_to.as_deref(), Some("cwg-think01"));

        let fallback_out = json!({
            "ok": false,
            "review_id": "cwg-outage01",
            "fallback": "adversarial-reviewer",
            "error": "quota exceeded"
        })
        .to_string();
        assert!(is_verified_codex_cmd_outage(cmd_lane, "ERROR", &fallback_out));

        let cmd_direct = r#"codex exec -s read-only -C C:\repo -"#;
        assert!(is_verified_codex_cmd_outage(
            cmd_direct,
            "ERROR",
            "ERROR: 401 unauthorized"
        ));
        assert!(!is_verified_codex_cmd_outage(
            cmd_direct,
            "DONE",
            "REVIEW_ID: cwg-ok1234\n--- CODEX REVIEW OUTPUT ---\nVERDICT: APPROVED\n"
        ));
    }

    #[test]
    fn test_scan_verified_codex_reviews_excludes_guardian_subagent() {
        let _lock = crate::win32_sqlite::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempTestDir::new("rollout");
        let stack_home = tmp.0.join("stack");
        let sessions_dir = tmp.0.join("sessions");
        let repo_dir = tmp.0.join("repo");
        fs::create_dir_all(&sessions_dir).unwrap();
        fs::create_dir_all(&repo_dir).unwrap();

        let _env = EnvVarGuard::set(&[
            ("CARBON_STACK_HOME", Some(&stack_home.to_string_lossy())),
            ("CARBON_CODEX_SESSIONS_DIR", Some(&sessions_dir.to_string_lossy())),
        ]);

        let now = now_sec();
        let rid = "cwg-guardtest01";
        let repo_str = repo_dir.to_string_lossy().into_owned();
        record_packet(
            rid,
            &format!("REVIEW_ID: {}\nCheck auth", rid),
            &repo_str,
            "xhigh",
            "ordinary",
            "sess-cli-01",
        );

        let primary_sid = "sess-primary-0001";
        let guard_sid = "sess-guardian-0002";
        let rf_primary = sessions_dir.join(format!("rollout-2026-{}.jsonl", primary_sid));
        let rf_guard = sessions_dir.join(format!("rollout-2026-{}.jsonl", guard_sid));

        let primary_lines = [
            json!({
                "type": "session_meta",
                "timestamp": "2026-11-17T10:00:00Z",
                "payload": {"id": primary_sid, "session_id": primary_sid, "source": "exec", "thread_source": "user"}
            }),
            json!({
                "type": "turn_context",
                "timestamp": "2026-11-17T10:00:01Z",
                "payload": {"model": "gpt-6.1-sol", "effort": "xhigh"}
            }),
            json!({
                "type": "response_item",
                "timestamp": "2026-11-17T10:00:02Z",
                "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": format!("REVIEW_ID: {}", rid)}]}
            }),
            json!({
                "type": "event_msg",
                "timestamp": "2026-11-17T10:00:10Z",
                "payload": {"type": "task_complete", "last_agent_message": "No issues found.\nVERDICT: APPROVED"}
            }),
        ];
        fs::write(
            &rf_primary,
            primary_lines
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join("\n")
                + "\n",
        )
        .unwrap();

        let guard_lines = [
            json!({
                "type": "session_meta",
                "timestamp": "2026-11-17T10:00:11Z",
                "payload": {
                    "id": guard_sid,
                    "session_id": primary_sid,
                    "parent_thread_id": primary_sid,
                    "source": {"subagent": {"other": "guardian"}},
                    "thread_source": "guardian_review"
                }
            }),
            json!({
                "type": "response_item",
                "timestamp": "2026-11-17T10:00:12Z",
                "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": format!("REVIEW_ID: {}", rid)}]}
            }),
            json!({
                "type": "event_msg",
                "timestamp": "2026-11-17T10:00:15Z",
                "payload": {"type": "task_complete", "last_agent_message": "{\"outcome\":\"allow\"}\nVERDICT: REVISE"}
            }),
        ];
        fs::write(
            &rf_guard,
            guard_lines
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join("\n")
                + "\n",
        )
        .unwrap();

        assert_eq!(
            unwrap_primary_session_id(guard_sid, now - 60.0),
            primary_sid
        );

        let scanned = scan_verified_codex_reviews(now - 60.0, "sess-cli-01", &repo_str);
        assert_eq!(scanned.len(), 1);
        assert_eq!(scanned[0]["review_id"], rid);
        assert_eq!(scanned[0]["session_id"], primary_sid);
        assert_eq!(scanned[0]["kind"], "ordinary");
        assert_eq!(scanned[0]["verdict"], "APPROVED");
        assert_eq!(scanned[0]["xhigh"], true);
    }

    #[test]
    fn test_run_cli_mock_cmd_and_verdictless_fallback() {
        let _lock = crate::win32_sqlite::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempTestDir::new("cli-mock");
        let stack_home = tmp.0.join("stack");
        let sessions_dir = tmp.0.join("sessions");
        let repo_dir = tmp.0.join("repo");
        let inv_log = tmp.0.join("invocations.log");
        fs::create_dir_all(&sessions_dir).unwrap();
        fs::create_dir_all(&repo_dir).unwrap();

        #[cfg(windows)]
        let mock_bin = {
            let py_path = tmp.0.join("mock_codex.py");
            let py_body = r#"import datetime, json, os, pathlib, re, sys, uuid
argv = sys.argv[1:]
prompt = sys.stdin.read() if not sys.stdin.isatty() else ""
if len(argv) >= 2 and argv[0] == "login" and argv[1] == "status":
    print("Logged in using ChatGPT")
    sys.exit(0)
with open(os.environ["MOCK_CODEX_LOG"], "a", encoding="utf-8") as lf:
    lf.write(" ".join(argv) + "\n")
sess_root = pathlib.Path(os.environ["CARBON_CODEX_SESSIONS_DIR"])
sess_root.mkdir(parents=True, exist_ok=True)
if len(argv) >= 2 and argv[0] == "exec" and argv[1] == "resume" and "sess-compacted-allow" in argv:
    print('{"outcome":"allow"}')
    sys.exit(0)
m = re.search(r"REVIEW_ID:\s*([A-Za-z0-9_-]+)", prompt)
rid = m.group(1) if m else "cwg-unknown0"
sid = "sess-live-" + uuid.uuid4().hex[:8]
iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
rows = [
    {"type": "session_meta", "timestamp": iso, "payload": {"id": sid, "session_id": sid, "source": "exec", "thread_source": "user"}},
    {"type": "turn_context", "timestamp": iso, "payload": {"model": "gpt-6.1-sol", "effort": "high"}},
    {"type": "response_item", "timestamp": iso, "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: " + rid}]}},
    {"type": "event_msg", "timestamp": iso, "payload": {"type": "task_complete", "last_agent_message": "CLOSURE_VALIDATION: READY"}},
]
(sess_root / f"rollout-primary-{sid}.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
print("CLOSURE_VALIDATION: READY")
"#;
            fs::write(&py_path, py_body).unwrap();
            let cmd_path = tmp.0.join("codex.cmd");
            fs::write(
                &cmd_path,
                "@echo off\r\npython -X utf8 \"%~dp0mock_codex.py\" %*\r\n",
            )
            .unwrap();
            cmd_path
        };

        #[cfg(not(windows))]
        let mock_bin = {
            use std::os::unix::fs::PermissionsExt;
            let sh_path = tmp.0.join("codex");
            let sh_body = r#"#!/bin/sh
prompt="$(cat)"
if [ "$1" = "login" ] && [ "$2" = "status" ]; then
  echo "Logged in using ChatGPT"
  exit 0
fi
echo "$*" >> "$MOCK_CODEX_LOG"
case " $* " in
  *" sess-compacted-allow "*)
    echo '{"outcome":"allow"}'
    exit 0
    ;;
esac
echo "CLOSURE_VALIDATION: READY"
exit 0
"#;
            fs::write(&sh_path, sh_body).unwrap();
            let mut perms = fs::metadata(&sh_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&sh_path, perms).unwrap();
            sh_path
        };

        let _env = EnvVarGuard::set(&[
            ("CARBON_STACK_HOME", Some(&stack_home.to_string_lossy())),
            ("CARBON_CODEX_SESSIONS_DIR", Some(&sessions_dir.to_string_lossy())),
            ("CARBON_CODEX_BIN", Some(&mock_bin.to_string_lossy())),
            ("MOCK_CODEX_LOG", Some(&inv_log.to_string_lossy())),
        ]);

        reset_breaker();
        assert_eq!(run_cli(&["check".to_string()]), 0);
        assert_eq!(run_cli(&["breaker".to_string()]), 0);

        let cli_sess = "cli-mock-sess-01";
        let repo_str = repo_dir.to_string_lossy().into_owned();
        let _ = rio::write_json(
            &cwg_common::marker_path(cli_sess),
            &json!({
                "session": cli_sess,
                "first_ts": now_sec(),
                "cwd": rio::normalize_path(&repo_str),
                "git_root": rio::normalize_path(&repo_str),
                "paths": [],
                "closed": false,
            }),
        );
        let diff_p = tmp.0.join("cand.diff");
        fs::write(&diff_p, "diff --git a/a.txt b/a.txt\n+ok\n").unwrap();

        let rc1 = run_cli(&[
            "review".to_string(),
            "--cwd".to_string(),
            repo_str.clone(),
            "--session".to_string(),
            cli_sess.to_string(),
            "--diff-file".to_string(),
            diff_p.to_string_lossy().into_owned(),
            "--closure".to_string(),
            "--summary".to_string(),
            "Initial closure review".to_string(),
        ]);
        assert_eq!(rc1, 0);

        let rc2 = run_cli(&[
            "review".to_string(),
            "--cwd".to_string(),
            repo_str.clone(),
            "--session".to_string(),
            cli_sess.to_string(),
            "--diff-file".to_string(),
            diff_p.to_string_lossy().into_owned(),
            "--closure".to_string(),
            "--resume".to_string(),
            "sess-compacted-allow".to_string(),
            "--summary".to_string(),
            "Fallback after verdictless resume".to_string(),
        ]);
        assert_eq!(rc2, 0);

        let logged = fs::read_to_string(&inv_log).unwrap_or_default();
        let log_lines: Vec<&str> = logged.lines().collect();
        assert!(log_lines.len() >= 3);
        assert!(log_lines[log_lines.len() - 2].contains("exec resume"));
        assert!(log_lines[log_lines.len() - 2].contains("sess-compacted-allow"));
        assert!(!log_lines[log_lines.len() - 1].contains("resume"));

        assert_eq!(
            run_cli(&[
                "scan".to_string(),
                "--session".to_string(),
                cli_sess.to_string(),
                "--cwd".to_string(),
                repo_str,
            ]),
            0
        );
    }
}
