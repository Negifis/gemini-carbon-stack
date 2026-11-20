use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cwg_common::{self, codex_cli_wrapper_re};
use crate::rio::{self, json_truthy, sha256_hex, val_to_f64, val_to_str};
use crate::win32_sqlite::{now_sec, run_command_with_job};

pub const BREAKER_TTL_SECONDS: i64 = 1800;
pub const DEFAULT_REVIEW_TIMEOUT_SECONDS: i64 = 600;
pub const DEFAULT_XHIGH_REVIEW_TIMEOUT_SECONDS: i64 = 900;
pub const TIMEOUT_STEP_SECONDS: i64 = 300;
pub const MAX_REVIEW_TIMEOUT_SECONDS: i64 = 1800;
pub const PACKET_TTL_SECONDS: f64 = 86400.0;
pub const MAX_DIFF_SNAPSHOT_CHARS: usize = 160_000;

pub const NATIVE_REVIEWERS: &[&str] = &["adversarial-reviewer", "adversarial-reviewer-xhigh"];
pub const XHIGH_NATIVE_REVIEWER: &str = "adversarial-reviewer-xhigh";
const JSONL_EVENT_PREFIXES: &[&str] = &["thread.", "turn.", "item."];
pub const REVIEW_VAL_FLAGS: &[&str] = &[
    "--cwd",
    "--cwd-hex",
    "--summary",
    "--summary-hex",
    "--diff-file",
    "--diff-file-hex",
    "--review-id",
    "--session",
    "--session-hex",
    "--model",
    "--model-hex",
    "--resume",
    "--resume-hex",
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

fn defer_timeout_print_map() -> &'static Mutex<HashMap<String, bool>> {
    static MAP: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

fn set_defer_timeout_print(review_id: &str, defer: bool) {
    if let Ok(mut guard) = defer_timeout_print_map().lock() {
        if defer {
            guard.insert(review_id.to_string(), true);
        } else {
            guard.remove(review_id);
        }
    }
}

fn take_defer_timeout_print(review_id: &str) -> bool {
    if let Ok(mut guard) = defer_timeout_print_map().lock() {
        return guard.remove(review_id).unwrap_or(false);
    }
    false
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

pub(crate) fn review_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"REVIEW_ID\s*:\s*([A-Za-z0-9_-]{6,64})").expect("review_id_re"))
}

fn packet_nonce_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"PACKET_NONCE\s*:\s*([A-Fa-f0-9]{12,64})").expect("packet_nonce_re")
    })
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

fn parse_ts_val(v: Option<&Value>) -> f64 {
    match v {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::String(s)) => rio::parse_iso_ts(s),
        _ => 0.0,
    }
}

fn random_hex_12() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = RID_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let seed = format!("{}:{}:{}", nanos, pid, seq);
    rio::sha256_hex(seed.as_bytes())[..12].to_string()
}

fn abs_path_from_str(raw: &str) -> PathBuf {
    rio::resolve_abs_path(Path::new(raw))
}

fn unlink_quiet(path: &Path) {
    if path.exists() {
        let _ = fs::remove_file(path);
    }
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

pub fn resolve_review_model(explicit_model: &str, xhigh: bool) -> String {
    let m = explicit_model.trim();
    if !m.is_empty() {
        return m.to_string();
    }
    if xhigh {
        cwg_common::CODEX_ASTRA_MODEL.to_string()
    } else {
        cwg_common::CODEX_SOL_MODEL.to_string()
    }
}

pub fn canonical_lane_effort(effort: &str) -> String {
    let e = effort.trim().to_ascii_lowercase();
    if cwg_common::is_codex_xhigh_effort(&e) {
        "xhigh".to_string()
    } else if matches!(e.as_str(), "" | "high" | "medium" | "low") {
        "high".to_string()
    } else {
        e
    }
}

pub fn review_lane_key(model: &str, effort: &str) -> String {
    format!(
        "{}|{}",
        model.trim().to_ascii_lowercase(),
        canonical_lane_effort(effort)
    )
}

fn is_bare_safe_cli_arg(val: &str) -> bool {
    val.chars().next().map_or(false, |c| c.is_ascii_alphabetic())
        && val
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | '\\' | ':'))
}

fn needs_hex_transport(val: &str) -> bool {
    // SAFETY: Windows PowerShell 5.1 (`Legacy` native argument passing) strips unescaped `"` and lets a trailing `\` in whitespace-quoted args escape the closing quote, while `is_direct_codex_invocation` rejects raw `\r`/`\n`/backticks; transport such values as UTF-8 hex so PS 5.1 and PS 7 deliver identical `argv`.
    val.chars()
        .any(|ch| matches!(ch, '"' | '\r' | '\n' | '`' | '\0'))
        || (val.ends_with('\\') && !is_bare_safe_cli_arg(val))
}

pub fn encode_utf8_hex(val: &str) -> String {
    hex::encode(val.as_bytes())
}

pub fn decode_utf8_hex(hex_str: &str) -> Result<String, String> {
    let bytes = hex::decode(hex_str).map_err(|e| e.to_string())?;
    if bytes.contains(&0) {
        return Err("nul byte in hex".to_string());
    }
    String::from_utf8(bytes).map_err(|_| "invalid utf-8".to_string())
}

pub fn quote_cli_arg(val: &str) -> String {
    // SAFETY: Single-quote non-trivial PowerShell tokens (doubling all PowerShell single-quote variants) so `;`, `$`, whitespace, and numeric literals pass through as a single literal argument without expansion.
    if is_bare_safe_cli_arg(val) {
        return val.to_string();
    }
    let mut out = String::with_capacity(val.len() + 4);
    out.push('\'');
    for ch in val.chars() {
        if matches!(ch, '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}') {
            out.push(ch);
        }
        out.push(ch);
    }
    out.push('\'');
    out
}

fn push_cli_flag_val(cmd: &mut String, flag: &str, val: &str) {
    cmd.push(' ');
    if needs_hex_transport(val) {
        cmd.push_str(flag);
        cmd.push_str("-hex '");
        cmd.push_str(&encode_utf8_hex(val));
        cmd.push('\'');
        return;
    }
    cmd.push_str(flag);
    if val.starts_with('-') {
        cmd.push('=');
    } else {
        cmd.push(' ');
    }
    cmd.push_str(&quote_cli_arg(val));
}

pub struct RetryCmdSpec<'a> {
    pub model: &'a str,
    pub xhigh: bool,
    pub closure: bool,
    pub session: &'a str,
    pub cwd: &'a str,
    pub diff_file: &'a str,
    pub summary: &'a str,
    pub pretty: bool,
}

pub fn format_review_retry_cmd_with_spec(spec: &RetryCmdSpec<'_>) -> String {
    let mut cmd = String::from("carbon-stack codex-lane review");
    if spec.xhigh {
        cmd.push_str(" --xhigh");
    }
    if spec.closure {
        cmd.push_str(" --closure");
    }
    let m = spec.model.trim();
    let default_mdl = resolve_review_model("", spec.xhigh);
    if !m.is_empty() && !m.eq_ignore_ascii_case(&default_mdl) {
        push_cli_flag_val(&mut cmd, "--model", m);
    }
    if !spec.session.is_empty() {
        push_cli_flag_val(&mut cmd, "--session", spec.session);
    }
    if !spec.cwd.is_empty() {
        push_cli_flag_val(&mut cmd, "--cwd", spec.cwd);
    }
    if !spec.diff_file.is_empty() {
        push_cli_flag_val(&mut cmd, "--diff-file", spec.diff_file);
    }
    if !spec.summary.is_empty() {
        push_cli_flag_val(&mut cmd, "--summary", spec.summary);
    }
    if spec.pretty {
        cmd.push_str(" --pretty");
    }
    cmd
}

pub fn format_review_retry_cmd_phase(model: &str, xhigh: bool, closure: bool) -> String {
    format_review_retry_cmd_with_spec(&RetryCmdSpec {
        model,
        xhigh,
        closure,
        session: "",
        cwd: "",
        diff_file: "",
        summary: "",
        pretty: false,
    })
}

pub fn format_review_retry_cmd(model: &str, xhigh: bool) -> String {
    format_review_retry_cmd_phase(model, xhigh, false)
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

fn breaker_lock_path() -> PathBuf {
    cwg_common::gate_dir().join("codex_lane.lock")
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

pub fn breaker_history_slice(v: &Value) -> &[Value] {
    v.get("history")
        .and_then(|h| h.as_array())
        .map(|a| a.as_slice())
        .unwrap_or(&[])
}

pub fn breaker_status() -> Value {
    let Some(data) = rio::read_json(&breaker_path()).filter(|v| v.is_object()) else {
        return json!({ "tripped": false, "history": [] });
    };
    let history = breaker_history_slice(&data).to_vec();
    let until = val_to_f64(data.get("tripped_until"));
    let now = now_sec();
    if json_truthy(data.get("tripped")) && until > now {
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
            "tripped_until": until,
            "history": history,
        });
    }
    json!({ "tripped": false, "history": history })
}

fn clamp_until_ts(h_until: f64, h_at: f64, clamp_at: f64) -> f64 {
    if h_until <= 0.0 || h_until > clamp_at {
        clamp_at.max(h_at)
    } else {
        h_until.max(h_at)
    }
}

fn clamp_breaker_history_for_probe(
    raw_history: &[Value],
    max_tripped_at: f64,
    recovery_ts: f64,
) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::with_capacity(raw_history.len());
    for item in raw_history {
        let Some(obj) = item.as_object() else {
            continue;
        };
        let h_at = val_to_f64(obj.get("tripped_at"));
        if h_at <= 0.0 {
            continue;
        }
        let h_until = val_to_f64(obj.get("until_ts"));
        let eff_until = if h_at <= max_tripped_at {
            clamp_until_ts(h_until, h_at, recovery_ts)
        } else if h_until > 0.0 {
            h_until.max(h_at)
        } else {
            0.0
        };
        let mut next_obj = obj.clone();
        next_obj.insert("until_ts".to_string(), json!(eff_until));
        out.push(Value::Object(next_obj));
    }
    out
}

fn trip_breaker_locked(reason: &str, ttl: i64, explicit_now: Option<f64>) {
    // SAFETY: Serialize `codex_lane.json` Read-Modify-Write under `codex_lane.lock` so concurrent trips and recoveries never lose outage windows or regress monotonic `tripped_at`/`tripped_until`.
    let bp = breaker_path();
    let r_trunc: String = reason.chars().take(300).collect();
    let r_log: String = reason.chars().take(200).collect();
    let wrote = rio::with_file_lock(&breaker_lock_path(), 5.0, 30.0, |locked| {
        if !locked {
            return false;
        }
        let now = explicit_now.unwrap_or_else(now_sec);
        let until_ts = now + (ttl.max(1) as f64);
        let existing = rio::read_json(&bp).filter(|v| v.is_object());
        let raw_history = existing.as_ref().map(breaker_history_slice).unwrap_or(&[]);
        let mut history: Vec<Value> = raw_history
            .iter()
            .filter(|item| item.is_object() && val_to_f64(item.get("tripped_at")) > 0.0)
            .cloned()
            .collect();
        let was_tripped = existing
            .as_ref()
            .map_or(false, |d| json_truthy(d.get("tripped")));
        let prev_at = existing
            .as_ref()
            .map_or(0.0, |d| val_to_f64(d.get("tripped_at")));
        let prev_until = existing
            .as_ref()
            .map_or(0.0, |d| val_to_f64(d.get("tripped_until")));
        if raw_history.is_empty() && prev_at > 0.0 && (was_tripped || prev_until > prev_at) {
            history.push(json!({
                "tripped_at": prev_at,
                "until_ts": prev_until.max(prev_at),
            }));
        }
        history.push(json!({
            "tripped_at": now,
            "until_ts": until_ts,
        }));
        history.sort_by(|a, b| {
            val_to_f64(a.get("tripped_at")).total_cmp(&val_to_f64(b.get("tripped_at")))
        });
        if history.len() > 32 {
            let drain_n = history.len() - 32;
            history.drain(0..drain_n);
        }
        let prev_active = was_tripped && prev_until > now;
        let (eff_at, eff_reason) = if prev_active && prev_at > now {
            let pr = existing
                .as_ref()
                .map(|d| val_to_str(d.get("reason")))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| r_trunc.clone());
            (prev_at, pr)
        } else {
            (now, r_trunc.clone())
        };
        let eff_until = if prev_active {
            prev_until.max(until_ts)
        } else {
            until_ts
        };
        rio::write_json(
            &bp,
            &json!({
                "tripped": true,
                "reason": eff_reason,
                "tripped_at": eff_at,
                "tripped_until": eff_until,
                "history": history,
            }),
        )
        .is_ok()
    });
    if wrote {
        rio::log_hook_event(
            "gate-events",
            "codex_breaker_tripped",
            json!({
                "reason": r_log,
                "ttl": ttl,
            }),
        );
    }
}

pub fn trip_breaker_at(reason: &str, ttl: i64, now: f64) {
    trip_breaker_locked(reason, ttl, Some(now));
}

pub fn trip_breaker(reason: &str, ttl: i64) {
    trip_breaker_locked(reason, ttl, None);
}

fn reset_breaker_locked(probe_bounds: Option<(f64, f64)>) {
    // SAFETY: Serialize under `codex_lane.lock` and clamp only outage windows whose `tripped_at <= max_tripped_at` so a slow or concurrent probe started before a newer outage cannot clear that newer outage or resurrect a closed breaker.
    let bp = breaker_path();
    if !bp.exists() {
        return;
    }
    let _ = rio::with_file_lock(&breaker_lock_path(), 5.0, 30.0, |locked| {
        if !locked {
            return false;
        }
        let (max_tripped_at, eff_rec_ts) = match probe_bounds {
            Some((m_at, r_ts)) => (m_at, r_ts.max(m_at)),
            None => {
                let now = now_sec();
                (now, now)
            }
        };
        let Some(mut doc) = rio::read_json(&bp).filter(|v| v.is_object()) else {
            if bp.exists() {
                let _ = fs::remove_file(&bp);
            }
            return false;
        };
        let was_tripped = json_truthy(doc.get("tripped"));
        let prev_at = val_to_f64(doc.get("tripped_at"));
        let prev_until = val_to_f64(doc.get("tripped_until"));
        let raw_history = breaker_history_slice(&doc);
        let mut history =
            clamp_breaker_history_for_probe(raw_history, max_tripped_at, eff_rec_ts);
        if prev_at > 0.0
            && (was_tripped || prev_until > prev_at)
            && !history
                .iter()
                .any(|w| (val_to_f64(w.get("tripped_at")) - prev_at).abs() < 1e-6)
        {
            let eff_prev_until = if prev_at <= max_tripped_at {
                clamp_until_ts(prev_until, prev_at, eff_rec_ts)
            } else {
                prev_until.max(prev_at)
            };
            history.push(json!({
                "tripped_at": prev_at,
                "until_ts": eff_prev_until,
            }));
        }
        if was_tripped {
            // SAFETY: Recompute `newer_at` and `newer_until` strictly from surviving unclosed windows (`h_at > max_tripped_at && h_until > eff_rec_ts`), never carrying forward an older closed window's longer TTL.
            let mut newer_at = 0.0f64;
            let mut newer_until = 0.0f64;
            for item in &history {
                let h_at = val_to_f64(item.get("tripped_at"));
                let h_until = val_to_f64(item.get("until_ts"));
                if h_at > max_tripped_at && h_until > eff_rec_ts {
                    newer_at = newer_at.max(h_at);
                    newer_until = newer_until.max(h_until);
                }
            }
            if newer_at > 0.0 && newer_until > 0.0 {
                if let Some(data) = doc.as_object_mut() {
                    data.insert("tripped".to_string(), Value::Bool(true));
                    data.insert("tripped_at".to_string(), json!(newer_at));
                    data.insert("tripped_until".to_string(), json!(newer_until));
                    data.insert("history".to_string(), Value::Array(history));
                }
                return rio::write_json(&bp, &doc).is_ok();
            }
        } else if prev_until == 0.0 && history.as_slice() == raw_history {
            return true;
        }
        if let Some(data) = doc.as_object_mut() {
            data.insert("tripped".to_string(), Value::Bool(false));
            data.insert("tripped_until".to_string(), json!(0.0));
            data.insert("history".to_string(), Value::Array(history));
        }
        rio::write_json(&bp, &doc).is_ok()
    });
}

pub fn reset_breaker_for_probe(max_tripped_at: f64, recovery_ts: f64) {
    if max_tripped_at > 0.0 {
        reset_breaker_locked(Some((max_tripped_at, recovery_ts.max(max_tripped_at))));
    }
}

pub fn reset_breaker_at(now: f64) {
    reset_breaker_locked(Some((now, now)));
}

pub fn reset_breaker() {
    reset_breaker_locked(None);
}

#[cfg(test)]
pub fn wipe_breaker_for_test() {
    let bp = breaker_path();
    let _ = rio::with_file_lock(&breaker_lock_path(), 5.0, 30.0, |locked| {
        if locked && bp.exists() {
            let _ = fs::remove_file(&bp);
        }
        locked
    });
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
    let mut seen_stems: HashSet<String> = HashSet::new();
    let mut matched: Vec<String> = Vec::new();
    for ent in entries.flatten() {
        let fname = ent.file_name().to_string_lossy().into_owned();
        let stem = if let Some(s) = fname.strip_suffix(".json") {
            s
        } else if let Some(s) = fname.strip_suffix(".pending.d") {
            s
        } else {
            continue;
        };
        if stem.is_empty() || !seen_stems.insert(stem.to_string()) {
            continue;
        }
        let Some(Value::Object(mdata)) = cwg_common::read_marker_with_pending(stem) else {
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

pub fn candidate_first_ts(session: &str) -> f64 {
    if session.is_empty() {
        return 0.0;
    }
    let Some(Value::Object(mdata)) = cwg_common::read_marker_with_pending(session) else {
        return 0.0;
    };
    if json_truthy(mdata.get("closed")) {
        return 0.0;
    }
    val_to_f64(mdata.get("first_ts"))
}

fn session_root_digest(session: &str, git_root: &str) -> String {
    let sess_part = if session.is_empty() {
        "nosession"
    } else {
        session
    };
    let raw_key = format!("{}|{}", sess_part, rio::fold_path(git_root));
    sha256_hex(raw_key.as_bytes())[..20].to_string()
}

fn thread_state_path(session: &str, git_root: &str) -> PathBuf {
    threads_dir().join(format!("{}.json", session_root_digest(session, git_root)))
}

fn is_default_high_lane(model: &str, effort: &str) -> bool {
    let m = model.trim();
    let e = effort.trim();
    (m.is_empty() || m.eq_ignore_ascii_case(cwg_common::CODEX_SOL_MODEL))
        && (e.is_empty() || e.eq_ignore_ascii_case("high"))
}

fn thread_state_path_for_lane(
    session: &str,
    git_root: &str,
    model: &str,
    effort: &str,
) -> PathBuf {
    if is_default_high_lane(model, effort) {
        return thread_state_path(session, git_root);
    }
    let root_dig = session_root_digest(session, git_root);
    let lane_dig = &sha256_hex(review_lane_key(model, effort).as_bytes())[..12];
    threads_dir().join(format!("{}-{}.json", root_dig, lane_dig))
}

fn thread_entry_matches_candidate(entry: &Map<String, Value>, cand_ts: f64, now: f64) -> bool {
    let saved_cand_ts = val_to_f64(entry.get("candidate_first_ts"));
    // INVARIANT: Bind thread continuity & timeout escalation strictly to the active candidate (`1h` TTL when no marker is open).
    if cand_ts > 0.0 {
        (saved_cand_ts - cand_ts).abs() < 1.0
    } else {
        saved_cand_ts <= 0.0 && (now - val_to_f64(entry.get("updated_ts"))) < 3600.0
    }
}

fn is_legacy_untyped_thread(saved: &Map<String, Value>) -> bool {
    !saved.contains_key("model") && !saved.contains_key("effort") && !saved.contains_key("xhigh")
}

fn thread_lock_path(session: &str, git_root: &str) -> PathBuf {
    threads_dir().join(format!("{}.lock", session_root_digest(session, git_root)))
}

fn find_rollout_lane_for_session(sid: &str, last_rid: &str, since_ts: f64) -> Option<(String, String)> {
    let clean_sid = sid.trim();
    let clean_rid = last_rid.trim();
    if clean_sid.is_empty() {
        return None;
    }
    let recent = recent_rollout_files((since_ts - 60.0).max(0.0), 40, true);
    let mut ordered: Vec<&PathBuf> = recent
        .iter()
        .filter(|rf| {
            rf.file_name()
                .and_then(|n| n.to_str())
                .map_or(false, |n| n.contains(clean_sid))
        })
        .collect();
    for rf in &recent {
        if !ordered.contains(&rf) {
            ordered.push(rf);
        }
    }
    for rf in ordered {
        if is_subagent_rollout_meta(&read_rollout_session_meta(rf)) {
            continue;
        }
        let Some(parsed) = extract_rollout_texts_and_meta(rf) else {
            continue;
        };
        if parsed.session_id != clean_sid || parsed.is_subagent {
            continue;
        }
        if !clean_rid.is_empty() {
            // INVARIANT: Match strictly the turn carrying `last_review_id` so an XHIGH turn that timed out before emitting `turn_context` never inherits an earlier HIGH turn's metadata.
            for turn in parsed.turns.iter().rev() {
                if turn.review_ids.iter().any(|r| r == clean_rid) {
                    if !turn.model.trim().is_empty() || !turn.effort.trim().is_empty() {
                        return Some((turn.model.trim().to_string(), turn.effort.trim().to_string()));
                    }
                    return None;
                }
            }
            return None;
        }
        let Some(last_turn) = parsed.turns.last() else {
            return None;
        };
        if last_turn.model.trim().is_empty() && last_turn.effort.trim().is_empty() {
            return None;
        }
        let last_key = review_lane_key(&last_turn.model, &last_turn.effort);
        let all_same = parsed.turns.iter().all(|t| {
            !t.model.trim().is_empty()
                && !t.effort.trim().is_empty()
                && review_lane_key(&t.model, &t.effort) == last_key
        });
        if all_same {
            return Some((
                last_turn.model.trim().to_string(),
                last_turn.effort.trim().to_string(),
            ));
        }
        return None;
    }
    None
}

enum LegacyThreadResolution {
    None,
    Typed(Map<String, Value>),
    UnknownPending(Map<String, Value>),
}

fn classify_legacy_default_from_raw(
    mut saved: Map<String, Value>,
    session: &str,
    git_root: &str,
    cand_ts: f64,
) -> LegacyThreadResolution {
    // INVARIANT: Pure read-only classification of pre-upgrade untyped records (zero disk writes/deletes during reads, preventing write-failure data loss and concurrent TOCTOU clobbers).
    if !is_legacy_untyped_thread(&saved) {
        return LegacyThreadResolution::None;
    }
    if !thread_entry_matches_candidate(&saved, cand_ts, now_sec()) {
        return LegacyThreadResolution::None;
    }
    let sid = val_to_str(saved.get("session_id")).trim().to_string();
    let last_rid = val_to_str(saved.get("last_review_id")).trim().to_string();
    let last_to = val_to_f64(saved.get("last_timeout_seconds")) as i64;
    let pending = json_truthy(saved.get("pending_timeout_resume"));

    let pkt_eff = if !last_rid.is_empty() {
        rio::read_json(&packet_path(&last_rid))
            .and_then(|v| {
                v.get("effort")
                    .and_then(|e| e.as_str())
                    .map(|s| s.trim().to_ascii_lowercase())
            })
            .unwrap_or_default()
    } else {
        String::new()
    };

    let (m_trim, e_low) = match find_rollout_lane_for_session(&sid, &last_rid, cand_ts) {
        Some((r_mdl, r_eff)) => (r_mdl.trim().to_string(), r_eff.trim().to_ascii_lowercase()),
        None => (String::new(), String::new()),
    };
    // INVARIANT: Resolve effort tier strictly from `turn_context.effort`, `packet.effort`, or timeout/candidate bounds — never assume XHIGH from an Astra model name alone, because `--model gpt-6.2-astra` is valid at HIGH (600s).
    let eff_hint = if !e_low.is_empty() {
        e_low.as_str()
    } else {
        pkt_eff.as_str()
    };
    let tier: Option<&str> = if !eff_hint.is_empty() {
        if cwg_common::is_codex_xhigh_effort(eff_hint) {
            Some("xhigh")
        } else {
            Some("high")
        }
    } else if pending && last_to > 0 && last_to < DEFAULT_XHIGH_REVIEW_TIMEOUT_SECONDS {
        Some("high")
    } else if pending && last_to >= DEFAULT_XHIGH_REVIEW_TIMEOUT_SECONDS && !session.is_empty() {
        let is_xhigh_cand = cwg_common::read_marker_with_pending(session)
            .filter(|m| !json_truthy(m.get("closed")))
            .map(|m| {
                let cctx = cwg_common::resolve_candidate_context(&m, false);
                val_to_str(cctx.get("floor")) == "XHIGH"
            })
            .unwrap_or(false);
        if is_xhigh_cand {
            Some("xhigh")
        } else {
            None
        }
    } else {
        None
    };

    let inferred: Option<(String, String, bool, bool)> = match tier {
        Some("xhigh") => {
            let is_astra = cwg_common::is_codex_astra_model(&m_trim);
            let verified_astra_turn = is_astra && !eff_hint.is_empty();
            let tgt_m = if is_astra {
                m_trim.clone()
            } else {
                cwg_common::CODEX_ASTRA_MODEL.to_string()
            };
            // INVARIANT: Normalize `max`/`ultra` to `"xhigh"` so `codex_lane.py review --xhigh` matches and clears the migrated lane.
            Some((tgt_m, "xhigh".to_string(), true, verified_astra_turn))
        }
        Some("high") => {
            let is_legacy_sol = m_trim.is_empty()
                || m_trim.eq_ignore_ascii_case("gpt-6.1-sol")
                || m_trim.eq_ignore_ascii_case("gpt-6-sol");
            let is_legacy_astra = m_trim.to_ascii_lowercase().contains("astra")
                && !cwg_common::is_codex_astra_model(&m_trim);
            let tgt_m = if is_legacy_sol {
                cwg_common::CODEX_SOL_MODEL.to_string()
            } else if is_legacy_astra {
                cwg_common::CODEX_ASTRA_MODEL.to_string()
            } else {
                m_trim.clone()
            };
            Some((tgt_m, "high".to_string(), false, !is_legacy_astra))
        }
        _ => None,
    };

    if let Some((tgt_m, tgt_e, tgt_xh, keep_sid)) = inferred {
        if !keep_sid {
            saved.insert("session_id".to_string(), Value::String(String::new()));
        }
        saved.insert("model".to_string(), Value::String(tgt_m));
        saved.insert("effort".to_string(), Value::String(tgt_e));
        saved.insert("xhigh".to_string(), Value::Bool(tgt_xh));
        saved
            .entry("session".to_string())
            .or_insert_with(|| Value::String(session.to_string()));
        saved
            .entry("git_root".to_string())
            .or_insert_with(|| Value::String(rio::normalize_path(git_root)));
        return LegacyThreadResolution::Typed(saved);
    }

    if !pending {
        return LegacyThreadResolution::None;
    }

    saved.insert("session_id".to_string(), Value::String(String::new()));
    saved.insert("legacy_unknown_tier".to_string(), Value::Bool(true));
    LegacyThreadResolution::UnknownPending(saved)
}

fn classify_legacy_default_thread_state(
    session: &str,
    git_root: &str,
    cand_ts: f64,
) -> LegacyThreadResolution {
    let default_p = thread_state_path(session, git_root);
    let Some(Value::Object(saved)) = rio::read_json(&default_p) else {
        return LegacyThreadResolution::None;
    };
    classify_legacy_default_from_raw(saved, session, git_root, cand_ts)
}

fn match_typed_lane_map(
    saved: Map<String, Value>,
    cand_ts: f64,
    req_mdl: &str,
    req_eff: &str,
) -> Option<Map<String, Value>> {
    if is_legacy_untyped_thread(&saved) || !thread_entry_matches_candidate(&saved, cand_ts, now_sec()) {
        return None;
    }
    let is_xh = json_truthy(saved.get("xhigh"));
    let saved_mdl = {
        let s = val_to_str(saved.get("model"));
        if s.trim().is_empty() {
            if is_xh {
                cwg_common::CODEX_ASTRA_MODEL.to_string()
            } else {
                cwg_common::CODEX_SOL_MODEL.to_string()
            }
        } else {
            s
        }
    };
    let saved_eff = {
        let s = val_to_str(saved.get("effort"));
        if s.trim().is_empty() {
            if is_xh {
                "xhigh".to_string()
            } else {
                "high".to_string()
            }
        } else {
            s
        }
    };
    if review_lane_key(&saved_mdl, &saved_eff) == review_lane_key(req_mdl, req_eff) {
        Some(saved)
    } else {
        None
    }
}

fn session_last_research_reset_ts(session: &str) -> f64 {
    if session.is_empty() {
        return 0.0;
    }
    cwg_common::read_marker_with_pending(session)
        .filter(|m| !json_truthy(m.get("closed")))
        .map(|m| cwg_common::last_research_reset_ts(&m))
        .unwrap_or(0.0)
}

pub fn active_thread_state_for_lane(
    session: &str,
    git_root: &str,
    candidate_first_ts_opt: Option<f64>,
    model: &str,
    effort: &str,
) -> Option<Map<String, Value>> {
    let cand_ts = candidate_first_ts_opt.unwrap_or_else(|| candidate_first_ts(session));
    let rr_ts = session_last_research_reset_ts(session);
    let req_mdl = if model.trim().is_empty() {
        cwg_common::CODEX_SOL_MODEL
    } else {
        model.trim()
    };
    let req_eff = if effort.trim().is_empty() {
        "high"
    } else {
        effort.trim()
    };
    let default_p = thread_state_path(session, git_root);
    let tpath = thread_state_path_for_lane(session, git_root, req_mdl, req_eff);
    let raw_def = rio::read_json(&default_p).and_then(|v| match v {
        Value::Object(m) => Some(m),
        _ => None,
    });
    let (legacy_def, typed_def) = match raw_def {
        Some(m) if is_legacy_untyped_thread(&m) => (Some(m), None),
        Some(m) => (None, Some(m)),
        None => (None, None),
    };
    let typed_hit = if tpath == default_p {
        typed_def.and_then(|m| match_typed_lane_map(m, cand_ts, req_mdl, req_eff))
    } else {
        rio::read_json(&tpath).and_then(|v| match v {
            Value::Object(m) => match_typed_lane_map(m, cand_ts, req_mdl, req_eff),
            _ => None,
        })
    }
    .filter(|m| rr_ts <= 0.0 || val_to_f64(m.get("updated_ts")) >= rr_ts);
    let Some(def_map) = legacy_def else {
        return typed_hit;
    };
    if rr_ts > 0.0 && val_to_f64(def_map.get("updated_ts")) < rr_ts {
        return typed_hit;
    }
    match classify_legacy_default_from_raw(def_map, session, git_root, cand_ts) {
        LegacyThreadResolution::Typed(leg) => {
            let leg_key = review_lane_key(&val_to_str(leg.get("model")), &val_to_str(leg.get("effort")));
            if leg_key == review_lane_key(req_mdl, req_eff) {
                if let Some(ref th) = typed_hit {
                    if val_to_f64(th.get("updated_ts")) >= val_to_f64(leg.get("updated_ts")) {
                        return typed_hit;
                    }
                }
                return Some(leg);
            }
            typed_hit
        }
        LegacyThreadResolution::UnknownPending(unk) => typed_hit.or(Some(unk)),
        LegacyThreadResolution::None => typed_hit,
    }
}

pub fn active_thread_state(
    session: &str,
    git_root: &str,
    candidate_first_ts_opt: Option<f64>,
) -> Option<Map<String, Value>> {
    let cand_ts = candidate_first_ts_opt.unwrap_or_else(|| candidate_first_ts(session));
    let rr_ts = session_last_research_reset_ts(session);
    let now = now_sec();
    let fold_root = rio::fold_path(git_root);
    let root_dig = session_root_digest(session, git_root);
    let default_name = format!("{}.json", root_dig);
    let lane_prefix = format!("{}-", root_dig);
    let mut matched: Vec<Map<String, Value>> = Vec::new();
    let mut legacy_raw: Option<Map<String, Value>> = None;
    if let Ok(entries) = fs::read_dir(threads_dir()) {
        for ent_res in entries.flatten() {
            let fname_os = ent_res.file_name();
            let Some(fname) = fname_os.to_str() else {
                continue;
            };
            let is_default = fname == default_name;
            // INVARIANT: Filter by `<session_root_digest>` filename prefix before JSON parsing so `PreToolUse` stays O(lanes of active session) instead of scanning stale files of unrelated sessions/repos.
            if !is_default && !(fname.starts_with(&lane_prefix) && fname.ends_with(".json")) {
                continue;
            }
            let Some(Value::Object(saved)) = rio::read_json(&ent_res.path()) else {
                continue;
            };
            if rr_ts > 0.0 && val_to_f64(saved.get("updated_ts")) < rr_ts {
                continue;
            }
            if is_default && is_legacy_untyped_thread(&saved) {
                legacy_raw = Some(saved);
                continue;
            }
            if !is_default {
                if val_to_str(saved.get("session")) != session {
                    continue;
                }
                if rio::fold_path(&val_to_str(saved.get("git_root"))) != fold_root {
                    continue;
                }
            }
            if thread_entry_matches_candidate(&saved, cand_ts, now) {
                matched.push(saved);
            }
        }
    }
    if let Some(def_map) = legacy_raw {
        match classify_legacy_default_from_raw(def_map, session, git_root, cand_ts) {
            LegacyThreadResolution::Typed(leg) => {
                let leg_key = review_lane_key(&val_to_str(leg.get("model")), &val_to_str(leg.get("effort")));
                let superseded = matched.iter().any(|m| {
                    review_lane_key(&val_to_str(m.get("model")), &val_to_str(m.get("effort"))) == leg_key
                        && val_to_f64(m.get("updated_ts")) >= val_to_f64(leg.get("updated_ts"))
                });
                if !superseded {
                    matched.push(leg);
                }
            }
            LegacyThreadResolution::UnknownPending(unk) => {
                let superseded = matched
                    .iter()
                    .any(|m| val_to_f64(m.get("updated_ts")) >= val_to_f64(unk.get("updated_ts")));
                if !superseded {
                    matched.push(unk);
                }
            }
            LegacyThreadResolution::None => {}
        }
    }
    let mut best_pending: Option<Map<String, Value>> = None;
    let mut best_any: Option<Map<String, Value>> = None;
    for saved in matched {
        let ts = val_to_f64(saved.get("updated_ts"));
        if json_truthy(saved.get("pending_timeout_resume")) {
            if best_pending
                .as_ref()
                .map_or(true, |b| ts >= val_to_f64(b.get("updated_ts")))
            {
                best_pending = Some(saved.clone());
            }
        }
        if best_any
            .as_ref()
            .map_or(true, |b| ts >= val_to_f64(b.get("updated_ts")))
        {
            best_any = Some(saved);
        }
    }
    best_pending.or(best_any)
}

fn preserve_or_retire_legacy_on_mutation(
    session: &str,
    git_root: &str,
    cand_ts: f64,
    mutating_lane_key: &str,
    about_to_overwrite_default: bool,
) -> bool {
    let default_p = thread_state_path(session, git_root);
    let Some(Value::Object(raw_def)) = rio::read_json(&default_p) else {
        return true;
    };
    if !is_legacy_untyped_thread(&raw_def) {
        return true;
    }
    match classify_legacy_default_from_raw(raw_def, session, git_root, cand_ts) {
        LegacyThreadResolution::None | LegacyThreadResolution::UnknownPending(_) => {
            if !about_to_overwrite_default {
                unlink_quiet(&default_p);
            }
            true
        }
        LegacyThreadResolution::Typed(leg) => {
            let leg_m = val_to_str(leg.get("model"));
            let leg_e = val_to_str(leg.get("effort"));
            let leg_key = review_lane_key(&leg_m, &leg_e);
            if leg_key == mutating_lane_key {
                if !about_to_overwrite_default {
                    unlink_quiet(&default_p);
                }
                return true;
            }
            if about_to_overwrite_default {
                let dest_p = thread_state_path_for_lane(session, git_root, &leg_m, &leg_e);
                let has_newer = rio::read_json(&dest_p)
                    .and_then(|v| v.as_object().cloned())
                    .map_or(false, |d| {
                        !is_legacy_untyped_thread(&d)
                            && thread_entry_matches_candidate(&d, cand_ts, now_sec())
                            && val_to_f64(d.get("updated_ts")) >= val_to_f64(leg.get("updated_ts"))
                    });
                if !has_newer && rio::write_json(&dest_p, &Value::Object(leg)).is_err() {
                    // SAFETY: Abort overwriting `default_p` if evacuating a non-default legacy record to `dest_p` fails.
                    return false;
                }
            }
            true
        }
    }
}

fn save_lane_thread_state(
    session: &str,
    git_root: &str,
    cand_first_ts: f64,
    model: &str,
    effort: &str,
    mut entry: Value,
) -> bool {
    let norm_eff = canonical_lane_effort(effort);
    if let Some(obj) = entry.as_object_mut() {
        obj.entry("session".to_string())
            .or_insert_with(|| Value::String(session.to_string()));
        obj.entry("git_root".to_string())
            .or_insert_with(|| Value::String(rio::normalize_path(git_root)));
        obj.entry("candidate_first_ts".to_string())
            .or_insert_with(|| json!(cand_first_ts));
        obj.entry("model".to_string())
            .or_insert_with(|| Value::String(model.to_string()));
        obj.insert("effort".to_string(), Value::String(norm_eff.clone()));
    }
    let lkey = review_lane_key(model, &norm_eff);
    let tpath = thread_state_path_for_lane(session, git_root, model, &norm_eff);
    let default_p = thread_state_path(session, git_root);
    let new_ts = val_to_f64(entry.get("updated_ts"));
    let mut persisted = false;
    rio::with_file_lock(&thread_lock_path(session, git_root), 5.0, 30.0, |locked| {
        // SAFETY: Fail closed without mutating thread state if the per-session lock could not be acquired.
        if !locked {
            return;
        }
        let has_newer = rio::read_json(&tpath)
            .and_then(|v| v.as_object().cloned())
            .map_or(false, |d| {
                !is_legacy_untyped_thread(&d)
                    && thread_entry_matches_candidate(&d, cand_first_ts, now_sec())
                    && val_to_f64(d.get("updated_ts")) > new_ts
            });
        if has_newer {
            return;
        }
        if tpath == default_p {
            if !preserve_or_retire_legacy_on_mutation(session, git_root, cand_first_ts, &lkey, true) {
                return;
            }
            persisted = rio::write_json(&tpath, &entry).is_ok();
        } else if rio::write_json(&tpath, &entry).is_ok() {
            let _ = preserve_or_retire_legacy_on_mutation(session, git_root, cand_first_ts, &lkey, false);
            persisted = true;
        }
    });
    persisted
}

fn remove_lane_thread_state(
    session: &str,
    git_root: &str,
    cand_first_ts: f64,
    model: &str,
    effort: &str,
) {
    let norm_eff = canonical_lane_effort(effort);
    let lkey = review_lane_key(model, &norm_eff);
    let tpath = thread_state_path_for_lane(session, git_root, model, &norm_eff);
    let default_p = thread_state_path(session, git_root);
    rio::with_file_lock(&thread_lock_path(session, git_root), 5.0, 30.0, |locked| {
        if !locked {
            return;
        }
        if tpath == default_p {
            if !preserve_or_retire_legacy_on_mutation(session, git_root, cand_first_ts, &lkey, true) {
                return;
            }
            unlink_quiet(&tpath);
        } else {
            unlink_quiet(&tpath);
            let _ = preserve_or_retire_legacy_on_mutation(session, git_root, cand_first_ts, &lkey, false);
        }
    });
}

fn clear_pending_timeout_resume(
    session: &str,
    git_root: &str,
    cand_first_ts: f64,
    model: &str,
    effort: &str,
) {
    let norm_eff = canonical_lane_effort(effort);
    let lkey = review_lane_key(model, &norm_eff);
    let tpath = thread_state_path_for_lane(session, git_root, model, &norm_eff);
    let default_p = thread_state_path(session, git_root);
    rio::with_file_lock(&thread_lock_path(session, git_root), 5.0, 30.0, |locked| {
        if !locked {
            return;
        }
        let mut base = rio::read_json(&tpath).and_then(|v| v.as_object().cloned()).filter(|d| !is_legacy_untyped_thread(d));
        if base.is_none() {
            if let LegacyThreadResolution::Typed(leg) =
                classify_legacy_default_thread_state(session, git_root, cand_first_ts)
            {
                if review_lane_key(&val_to_str(leg.get("model")), &val_to_str(leg.get("effort"))) == lkey {
                    base = Some(leg);
                }
            }
        }
        let Some(mut saved) = base else {
            let _ = preserve_or_retire_legacy_on_mutation(session, git_root, cand_first_ts, &lkey, false);
            return;
        };
        if !json_truthy(saved.get("pending_timeout_resume")) {
            return;
        }
        if json_truthy(saved.get("session_id")) {
            saved.insert("pending_timeout_resume".to_string(), Value::Bool(false));
            saved.remove("next_timeout_seconds");
            saved.insert("updated_ts".to_string(), json!(now_sec()));
            if tpath == default_p {
                if !preserve_or_retire_legacy_on_mutation(session, git_root, cand_first_ts, &lkey, true) {
                    return;
                }
                let _ = rio::write_json(&tpath, &Value::Object(saved));
            } else if rio::write_json(&tpath, &Value::Object(saved)).is_ok() {
                let _ = preserve_or_retire_legacy_on_mutation(session, git_root, cand_first_ts, &lkey, false);
            }
        } else {
            if tpath == default_p && !preserve_or_retire_legacy_on_mutation(session, git_root, cand_first_ts, &lkey, true) {
                return;
            }
            unlink_quiet(&tpath);
            if tpath != default_p {
                let _ = preserve_or_retire_legacy_on_mutation(session, git_root, cand_first_ts, &lkey, false);
            }
        }
    });
}

fn packet_path(review_id: &str) -> PathBuf {
    packets_dir().join(format!("{}.json", rio::safe_key(review_id, "default")))
}

pub fn has_recorded_packet(review_id: &str) -> bool {
    !review_id.is_empty() && packet_path(review_id).exists()
}

fn build_packet_doc(
    review_id: &str,
    prompt_text: &str,
    cwd: &str,
    effort: &str,
    phase: &str,
    session: &str,
    committed: bool,
) -> Value {
    let now = now_sec();
    let eff_session = if session.is_empty() {
        infer_single_open_session(cwd)
    } else {
        session.to_string()
    };
    let digest = sha256_hex(prompt_text.as_bytes())[..24].to_string();
    let pkt_nonce = packet_nonce_re()
        .captures(prompt_text)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_lowercase())
        .unwrap_or_default();
    json!({
        "review_id": review_id,
        "packet_nonce": pkt_nonce,
        "prompt_sha256": digest,
        "cwd": rio::normalize_path(cwd),
        "effort": effort.to_lowercase(),
        "phase": phase,
        "session": eff_session,
        "created_ts": now,
        "committed": committed,
    })
}

pub fn record_packet(
    review_id: &str,
    prompt_text: &str,
    cwd: &str,
    effort: &str,
    phase: &str,
    session: &str,
) -> Value {
    let pkt = build_packet_doc(review_id, prompt_text, cwd, effort, phase, session, true);
    let _ = rio::write_json(&packet_path(review_id), &pkt);
    sweep_expired_gate_files();
    pkt
}

pub fn record_packet_if_absent(
    review_id: &str,
    prompt_text: &str,
    cwd: &str,
    effort: &str,
    phase: &str,
    session: &str,
) -> bool {
    // SAFETY: Atomically create `packets/<review_id>.json` with `create_new(true)` so `PostToolUse` direct-`codex` fallback can never overwrite an in-flight or committed `codex-lane review` packet.
    if review_id.is_empty() {
        return false;
    }
    sweep_expired_gate_files();
    let pdir = packets_dir();
    if fs::create_dir_all(&pdir).is_err() {
        return false;
    }
    let pkt = build_packet_doc(review_id, prompt_text, cwd, effort, phase, session, true);
    let Ok(encoded) = serde_json::to_vec_pretty(&pkt) else {
        return false;
    };
    let Ok(mut fh) = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(packet_path(review_id))
    else {
        return false;
    };
    if fh.write_all(&encoded).and_then(|()| fh.flush()).is_err() {
        let _ = fs::remove_file(packet_path(review_id));
        return false;
    }
    true
}

enum PacketReserveError {
    Duplicate,
    Io(String),
}

fn reserve_packet_exclusive(
    review_id: &str,
    prompt_text: &str,
    cwd: &str,
    effort: &str,
    phase: &str,
    session: &str,
) -> Result<Value, PacketReserveError> {
    // SAFETY: Reserve `packets/<review_id>.json` atomically via OS `create_new(true)` (`CREATE_NEW` / `O_CREAT|O_EXCL`) so concurrent duplicate `--review-id` invocations never overwrite or clobber an existing packet.
    sweep_expired_gate_files();
    let pdir = packets_dir();
    fs::create_dir_all(&pdir).map_err(|e| PacketReserveError::Io(e.to_string()))?;
    let pkt = build_packet_doc(review_id, prompt_text, cwd, effort, phase, session, false);
    let encoded = serde_json::to_vec_pretty(&pkt)
        .map_err(|e| PacketReserveError::Io(e.to_string()))?;
    let mut fh = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(packet_path(review_id))
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                PacketReserveError::Duplicate
            } else {
                PacketReserveError::Io(e.to_string())
            }
        })?;
    fh.write_all(&encoded)
        .and_then(|()| fh.flush())
        .map_err(|e| {
            let _ = fs::remove_file(packet_path(review_id));
            PacketReserveError::Io(e.to_string())
        })?;
    Ok(pkt)
}

fn commit_packet_owned(review_id: &str, owner_nonce: &str) -> bool {
    if review_id.is_empty() || owner_nonce.is_empty() {
        return false;
    }
    let p = packet_path(review_id);
    rio::with_file_lock(&breaker_lock_path(), 3.0, 15.0, |locked| {
        if !locked {
            return false;
        }
        let Some(mut doc) = rio::read_json(&p) else {
            return false;
        };
        if !val_to_str(doc.get("packet_nonce")).eq_ignore_ascii_case(owner_nonce) {
            return false;
        }
        if let Some(obj) = doc.as_object_mut() {
            obj.insert("committed".to_string(), Value::Bool(true));
        }
        rio::write_json(&p, &doc).is_ok()
    })
}

fn unlink_packet_if_owned(review_id: &str, owner_nonce: &str) {
    if review_id.is_empty() || owner_nonce.is_empty() {
        return;
    }
    let p = packet_path(review_id);
    rio::with_file_lock(&breaker_lock_path(), 3.0, 15.0, |locked| {
        if !locked {
            return;
        }
        if let Some(doc) = rio::read_json(&p) {
            if val_to_str(doc.get("packet_nonce")).eq_ignore_ascii_case(owner_nonce) {
                unlink_quiet(&p);
            }
        }
    });
}

fn sweep_expired_gate_files() {
    let cutoff = now_sec() - PACKET_TTL_SECONDS;
    let mut open_session_cache: HashMap<String, bool> = HashMap::new();
    for base_dir in [packets_dir(), threads_dir()] {
        let Ok(entries) = fs::read_dir(&base_dir) else {
            continue;
        };
        for ent in entries.flatten() {
            let p = ent.path();
            if p.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let mt = rio::file_mtime_sec(&p).unwrap_or(0.0);
            if mt > 0.0 && mt < cutoff {
                // SAFETY: Retain committed packets and thread state for any session whose candidate marker is still open so multi-day candidates never lose review history or 2-BLOCKED accounting.
                if let Some(doc) = rio::read_json(&p) {
                    if doc.get("committed").and_then(|v| v.as_bool()) != Some(false) {
                        let sess = val_to_str(doc.get("session")).trim().to_string();
                        if !sess.is_empty() {
                            let is_open = *open_session_cache.entry(sess.clone()).or_insert_with(|| {
                                let skey = rio::safe_key(&sess, "default");
                                cwg_common::read_marker_with_pending(&skey)
                                    .map_or(false, |m| m.is_object() && !json_truthy(m.get("closed")))
                            });
                            if is_open {
                                continue;
                            }
                        }
                    }
                }
                let _ = fs::remove_file(&p);
            }
        }
    }
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
    let folded = crate::cwg_mark::fold_ps_line_continuations(cmd_str.trim());
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
    let Ok(f) = fs::File::open(rollout_file) else {
        return Map::new();
    };
    let reader = BufReader::new(f);
    for line_res in reader.lines().take(8) {
        let Ok(raw_line) = line_res else {
            break;
        };
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

fn extract_packet_nonces(text: &str) -> Vec<String> {
    packet_nonce_re()
        .captures_iter(text)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_lowercase()))
        .collect()
}

fn rollout_user_prompt_text(rtype: &str, payload: &Map<String, Value>) -> Option<String> {
    let ptype = payload.get("type").and_then(|v| v.as_str()).unwrap_or("");
    if rtype == "event_msg" && ptype == "user_message" {
        let umsg = val_to_str(payload.get("message"));
        let trimmed = umsg.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    } else if rtype == "response_item"
        && ptype == "message"
        && payload.get("role").and_then(|v| v.as_str()) == Some("user")
    {
        let txt = rollout_message_text(payload.get("content"));
        if !txt.is_empty() {
            return Some(txt);
        }
    }
    None
}

fn rollout_user_review_ids(rtype: &str, payload: &Map<String, Value>) -> Vec<String> {
    rollout_user_prompt_text(rtype, payload).map_or_else(Vec::new, |t| extract_review_ids(&t))
}

struct RolloutTurn {
    review_ids: Vec<String>,
    packet_nonces: Vec<String>,
    started_ts: f64,
    completed_ts: f64,
    effort: String,
    model: String,
    assistant_messages: Vec<(f64, String)>,
    closed: bool,
}

struct RolloutMetaExtracted {
    path: String,
    file_mtime: f64,
    session_id: String,
    is_subagent: bool,
    started_ts: f64,
    completed_ts: f64,
    turns: Vec<RolloutTurn>,
}

fn extract_rollout_texts_and_meta(rollout_file: &Path) -> Option<RolloutMetaExtracted> {
    let records = rio::read_jsonl(rollout_file, None);
    if records.is_empty() {
        return None;
    }
    let file_mtime = rio::file_mtime_sec(rollout_file).unwrap_or(0.0);
    let mut turns: Vec<RolloutTurn> = Vec::new();
    let mut current_idx: Option<usize> = None;
    let mut pending_effort = String::new();
    let mut pending_model = String::new();
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
            // INVARIANT: Bind `(model, effort)` strictly to the turn that emitted this `turn_context`; never carry missing fields across turns.
            let tc_eff = val_to_str(payload.get("effort")).trim().to_lowercase();
            let tc_mdl = val_to_str(payload.get("model")).trim().to_string();
            let applied_to_open_turn = match current_idx {
                Some(idx) => {
                    let t = &mut turns[idx];
                    if !t.closed && t.assistant_messages.is_empty() {
                        t.effort = tc_eff.clone();
                        t.model = tc_mdl.clone();
                        true
                    } else {
                        false
                    }
                }
                None => false,
            };
            if applied_to_open_turn {
                pending_effort.clear();
                pending_model.clear();
            } else {
                pending_effort = tc_eff;
                pending_model = tc_mdl;
            }
        } else if rtype == "event_msg" && ptype == "task_started" {
            if let Some(idx) = current_idx {
                turns[idx].closed = true;
            }
            pending_effort.clear();
            pending_model.clear();
        } else if (rtype == "event_msg" && ptype == "user_message")
            || (rtype == "response_item"
                && ptype == "message"
                && payload.get("role").and_then(|v| v.as_str()) == Some("user"))
        {
            let (m_ids, m_nonces) = match rollout_user_prompt_text(rtype, payload) {
                Some(txt) => (extract_review_ids(&txt), extract_packet_nonces(&txt)),
                None => (Vec::new(), Vec::new()),
            };
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
                    packet_nonces: m_nonces,
                    started_ts: if rec_ts > 0.0 { rec_ts } else { started_ts },
                    completed_ts: 0.0,
                    effort: std::mem::take(&mut pending_effort),
                    model: std::mem::take(&mut pending_model),
                    assistant_messages: Vec::new(),
                    closed: false,
                });
                current_idx = Some(turns.len() - 1);
            } else if same_open_turn {
                if let Some(idx) = current_idx {
                    for nc in m_nonces {
                        if !turns[idx].packet_nonces.contains(&nc) {
                            turns[idx].packet_nonces.push(nc);
                        }
                    }
                }
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
            pending_effort.clear();
            pending_model.clear();
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
        file_mtime,
        session_id,
        is_subagent,
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

fn collect_recent_rollout_files_rec(
    dir: &Path,
    min_mtime: f64,
    depth: usize,
    out: &mut Vec<(f64, PathBuf)>,
) {
    if depth == 0 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for ent in entries.flatten() {
        let Ok(ft) = ent.file_type() else {
            continue;
        };
        let p = ent.path();
        if ft.is_dir() {
            collect_recent_rollout_files_rec(&p, min_mtime, depth - 1, out);
        } else if ft.is_file() {
            let fname = ent.file_name();
            let Some(fname_s) = fname.to_str() else {
                continue;
            };
            if !fname_s.starts_with("rollout-") || !fname_s.ends_with(".jsonl") {
                continue;
            }
            let mt = ent
                .metadata()
                .ok()
                .and_then(|m| rio::meta_mtime_sec(&m))
                .unwrap_or(0.0);
            if mt >= min_mtime {
                out.push((mt, p));
            }
        }
    }
}

fn recent_rollout_files(since_ts: f64, limit: usize, newest_first: bool) -> Vec<PathBuf> {
    let root = codex_sessions_dir();
    if !root.is_dir() {
        return Vec::new();
    }
    let min_mtime = (since_ts - 5.0).max(0.0);
    let mut candidates: Vec<(f64, PathBuf)> = Vec::new();
    collect_recent_rollout_files_rec(&root, min_mtime, 8, &mut candidates);
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
    let min_pkt_mtime = (since_ts - 86_400.0).max(0.0);

    if let Ok(entries) = fs::read_dir(packets_dir()) {
        for ent in entries.flatten() {
            let pf = ent.path();
            if pf.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if min_pkt_mtime > 0.0 {
                let pkt_mt = ent
                    .metadata()
                    .ok()
                    .and_then(|m| rio::meta_mtime_sec(&m))
                    .unwrap_or(0.0);
                if pkt_mt > 0.0 && pkt_mt < min_pkt_mtime {
                    continue;
                }
            }
            let Some(Value::Object(pdata)) = rio::read_json(&pf) else {
                continue;
            };
            if pdata.get("committed").and_then(|v| v.as_bool()) == Some(false) {
                continue;
            }
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

    const PRIMARY_ROLLOUT_SCAN_WINDOW: usize = 40;
    let mut by_review_id: HashMap<String, (f64, Value)> = HashMap::new();
    let scan_rollout_file = |rf: &Path, out_map: &mut HashMap<String, (f64, Value)>| {
        // INVARIANT: Subagent/guardian rollouts are never eligible sources of gate review verdicts (`parsed.is_subagent` inspects `session_meta`).
        let Some(parsed) = extract_rollout_texts_and_meta(rf) else {
            return;
        };
        if parsed.is_subagent {
            return;
        }
        for turn in &parsed.turns {
            let Some(bound_packet) = turn
                .review_ids
                .iter()
                .find_map(|rid| known_packets.get(rid))
            else {
                continue;
            };
            // SAFETY: Bind rollout turns to the exact packet attempt via `packet_nonce` (when recorded) and reject rollout files predating `created_ts` so an older review's verdict can never bind to a newer packet.
            let pkt_nonce = val_to_str(bound_packet.get("packet_nonce"))
                .trim()
                .to_lowercase();
            if !pkt_nonce.is_empty()
                && !turn
                    .packet_nonces
                    .iter()
                    .any(|n| n.eq_ignore_ascii_case(&pkt_nonce))
            {
                continue;
            }
            let pkt_cts = val_to_f64(bound_packet.get("created_ts"));
            if pkt_cts > 0.0 && parsed.file_mtime > 0.0 && parsed.file_mtime < pkt_cts - 2.0 {
                continue;
            }

            let pkt_phase = val_to_str(bound_packet.get("phase"))
                .trim()
                .to_lowercase();
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
                    // SAFETY: Reject rollout verdicts whose phase (`ordinary` vs `closure`) diverges from the recorded packet `phase`.
                    if !pkt_phase.is_empty() && dk != pkt_phase {
                        continue;
                    }
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
                let turn_eff = turn.effort.trim();
                let turn_mdl = turn.model.trim();
                let eff = if !turn_eff.is_empty() {
                    turn_eff.to_string()
                } else {
                    let pkt_eff = val_to_str(bound_packet.get("effort"));
                    if pkt_eff.is_empty() {
                        "high".to_string()
                    } else {
                        pkt_eff
                    }
                };
                let raw_rank_ts = if verdict_ts > 0.0 { verdict_ts } else { turn.started_ts.max(parsed.started_ts) };
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
                    "xhigh": cwg_common::is_codex_xhigh_turn(turn_mdl, turn_eff),
                    "model": turn_mdl,
                    "effort": eff,
                    "rollout_path": parsed.path,
                });
                // SAFETY: Candidates are scanned newest-mtime-first; replace an existing match only when `raw_rank_ts` is strictly newer (or same rollout turn later in the same file).
                let replace = match out_map.get(&rid_key) {
                    None => true,
                    Some((prev_raw_ts, prev_rec)) => {
                        if raw_rank_ts > 0.0 && *prev_raw_ts > 0.0 {
                            raw_rank_ts > *prev_raw_ts
                                || ((raw_rank_ts - *prev_raw_ts).abs() <= 1e-6
                                    && val_to_str(prev_rec.get("rollout_path")) == parsed.path)
                        } else {
                            val_to_str(prev_rec.get("rollout_path")) == parsed.path
                        }
                    }
                };
                if replace {
                    out_map.insert(rid_key, (raw_rank_ts, rec));
                }
            }
        }
    };

    // SAFETY: Sort rollout candidates newest-mtime-first so `[..first_n]` always inspects the 40 freshest rollouts before considering older displaced files.
    const FALLBACK_ROLLOUT_SCAN_CAP: usize = 160;
    let all_candidates = recent_rollout_files(since_ts, FALLBACK_ROLLOUT_SCAN_CAP, true);
    let first_n = all_candidates.len().min(PRIMARY_ROLLOUT_SCAN_WINDOW);
    for rf in &all_candidates[..first_n] {
        scan_rollout_file(rf, &mut by_review_id);
    }
    if all_candidates.len() > first_n && by_review_id.len() < known_packets.len() {
        for rf in &all_candidates[first_n..] {
            // INVARIANT: Prefilter older/sibling rollout files by raw byte substring match against still-unresolved `review_id`s before JSONL parsing so in-flight or timed-out packets never trigger full-file JSON deserialization across unrelated Codex sessions.
            let raw_has_missing_rid = fs::read(rf).map_or(false, |bytes| {
                known_packets.keys().any(|rid| {
                    !by_review_id.contains_key(rid)
                        && bytes
                            .windows(rid.len())
                            .any(|w| w == rid.as_bytes())
                })
            });
            if raw_has_missing_rid {
                scan_rollout_file(rf, &mut by_review_id);
                if by_review_id.len() >= known_packets.len() {
                    break;
                }
            }
        }
    }

    let mut results: Vec<Value> = by_review_id.into_values().map(|(_, rec)| rec).collect();
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

fn extract_subagent_parent_id(payload: &Map<String, Value>) -> String {
    let direct = val_to_str(payload.get("parent_thread_id")).trim().to_string();
    if !direct.is_empty() {
        return direct;
    }
    if let Some(Value::Object(src)) = payload.get("source") {
        if let Some(Value::Object(sub)) = src.get("subagent") {
            let nested = val_to_str(sub.get("parent_thread_id")).trim().to_string();
            if !nested.is_empty() {
                return nested;
            }
            if let Some(Value::Object(tspawn)) = sub.get("thread_spawn") {
                let spawn_parent = val_to_str(tspawn.get("parent_thread_id")).trim().to_string();
                if !spawn_parent.is_empty() {
                    return spawn_parent;
                }
            }
        }
    }
    String::new()
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
        cur = extract_subagent_parent_id(&meta);
    }
    String::new()
}

pub fn rollout_session_origin_ts(session_id: &str, rollout_path: &str, since_hint_ts: f64) -> f64 {
    let probe_file = |p: &Path| -> f64 {
        let Ok(f) = fs::File::open(p) else {
            return 0.0;
        };
        let reader = BufReader::new(f);
        for line_res in reader.lines().take(12) {
            let Ok(line) = line_res else {
                break;
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
                let ts = v
                    .get("timestamp")
                    .and_then(|x| x.as_str())
                    .map(rio::parse_iso_ts)
                    .unwrap_or(0.0);
                if ts > 0.0 {
                    return ts;
                }
            }
        }
        0.0
    };

    if !rollout_path.trim().is_empty() {
        let p = Path::new(rollout_path.trim());
        if p.is_file() {
            let ts = probe_file(p);
            if ts > 0.0 {
                return ts;
            }
        }
    }
    let clean_sid = session_id.trim();
    if clean_sid.is_empty() {
        return 0.0;
    }
    let mut checked: HashSet<PathBuf> = HashSet::new();
    for rf in recent_rollout_files((since_hint_ts - 86400.0).max(0.0), 80, true) {
        checked.insert(rf.clone());
        let meta = read_rollout_session_meta(&rf);
        let mid = val_to_str(meta.get("id").or_else(|| meta.get("session_id")));
        if mid.trim() == clean_sid {
            let ts = probe_file(&rf);
            if ts > 0.0 {
                return ts;
            }
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
            let meta = read_rollout_session_meta(&rf);
            let mid = val_to_str(meta.get("id").or_else(|| meta.get("session_id")));
            if mid.trim() == clean_sid {
                let ts = probe_file(&rf);
                if ts > 0.0 {
                    return ts;
                }
            }
        }
    }
    0.0
}

pub fn is_post_reset_codex_session_proven(
    session_id: &str,
    rollout_path: &str,
    cutoff_ts: f64,
    since_hint_ts: f64,
) -> bool {
    if cutoff_ts <= 0.0 {
        return true;
    }
    // SAFETY: Fail closed after `research-reset` unless the unwrapped primary Codex session has a verified rollout origin strictly at/after `cutoff_ts`.
    let clean_raw = session_id.trim();
    let mut seed_sid = clean_raw.to_string();
    if !rollout_path.trim().is_empty() {
        let rp = Path::new(rollout_path.trim());
        if rp.is_file() {
            let rp_meta = read_rollout_session_meta(rp);
            if is_subagent_rollout_meta(&rp_meta) {
                let parent_sid = extract_subagent_parent_id(&rp_meta);
                if parent_sid.is_empty() {
                    return false;
                }
                seed_sid = parent_sid;
            }
        }
    }
    if seed_sid.is_empty() {
        return false;
    }
    let unwrapped = unwrap_primary_session_id(&seed_sid, 0.0);
    if unwrapped.is_empty() {
        return false;
    }
    let eff_rpath = if !clean_raw.is_empty() && unwrapped == clean_raw {
        rollout_path
    } else {
        ""
    };
    let origin = rollout_session_origin_ts(&unwrapped, eff_rpath, since_hint_ts);
    origin > 0.0 && origin >= cutoff_ts - 0.001
}

#[derive(Clone, Debug, Default)]
pub struct ClosureCycleSummary {
    pub blocked_count: usize,
    pub last_blocked_ts: f64,
    pub blocked_ids: Vec<String>,
    pub effective_pass_count: usize,
    pub last_closure_ts: f64,
    pub has_fresh_ready: bool,
    pub counted_ordinary_rounds: usize,
    pub raw_ordinary_rounds: usize,
    pub ordinary_cap_reached: bool,
    pub has_round_cap_escalate: bool,
    pub escalate_verdict_ts: f64,
    pub has_post_escalate_research: bool,
    pub has_fresh_ordinary_approved: bool,
    pub needs_simplify: bool,
    pub simplify_started_in_cycle: bool,
}

pub fn active_cycle_closure_summary_for_marker(
    marker: &Value,
    session: &str,
    git_root: &str,
    transcript_path: &str,
) -> ClosureCycleSummary {
    crate::cwg_stop::evaluate_closure_cycle_for_marker(
        marker,
        session,
        git_root,
        transcript_path,
        "",
    )
}

pub fn active_cycle_closure_summary_with_risk(
    session: &str,
    git_root: &str,
    transcript_path: &str,
    min_risk_override: &str,
) -> ClosureCycleSummary {
    if session.trim().is_empty() {
        return ClosureCycleSummary::default();
    }
    let skey = rio::safe_key(session, "default");
    let raw_marker = rio::read_json(&cwg_common::marker_path(&skey));
    let (merged_opt, _) = cwg_common::apply_pending_marker_deltas(&skey, raw_marker.as_ref());
    let Some(marker) = merged_opt else {
        return ClosureCycleSummary::default();
    };
    let summary = crate::cwg_stop::evaluate_closure_cycle_for_marker(
        &marker,
        session,
        git_root,
        transcript_path,
        min_risk_override,
    );
    if summary.blocked_count >= cwg_common::MAX_CLOSURE_PASSES_PER_CYCLE {
        cwg_common::latch_marker_closure_halt_for_marker(
            session,
            &marker,
            summary.blocked_count,
            summary.last_blocked_ts,
            &summary.blocked_ids,
        );
    }
    summary
}

pub fn active_cycle_closure_summary(
    session: &str,
    git_root: &str,
    transcript_path: &str,
) -> ClosureCycleSummary {
    active_cycle_closure_summary_with_risk(session, git_root, transcript_path, "")
}

pub fn active_cycle_closure_blocks_for_marker(
    marker: &Value,
    session: &str,
    git_root: &str,
    transcript_path: &str,
) -> (usize, f64, Vec<String>) {
    let s = active_cycle_closure_summary_for_marker(marker, session, git_root, transcript_path);
    (s.blocked_count, s.last_blocked_ts, s.blocked_ids)
}

pub fn active_cycle_closure_blocks(
    session: &str,
    git_root: &str,
    transcript_path: &str,
) -> (usize, f64, Vec<String>) {
    let s = active_cycle_closure_summary(session, git_root, transcript_path);
    (s.blocked_count, s.last_blocked_ts, s.blocked_ids)
}

#[derive(Copy, Clone)]
struct ResumeSessionQuery<'a> {
    git_root: &'a str,
    session: &'a str,
    candidate_first_ts: f64,
    explicit_resume: &'a str,
    force_new: bool,
    model: &'a str,
    effort: &'a str,
}

fn resolve_resume_session_with_saved(
    query: ResumeSessionQuery<'_>,
    preloaded_saved: Option<Option<&Map<String, Value>>>,
) -> String {
    let ResumeSessionQuery {
        git_root,
        session,
        candidate_first_ts,
        explicit_resume,
        force_new,
        model,
        effort,
    } = query;
    if force_new {
        return String::new();
    }
    let rr_ts = if !session.is_empty() {
        cwg_common::read_marker_with_pending(session)
            .map(|m| cwg_common::last_research_reset_ts(&m))
            .unwrap_or(0.0)
    } else {
        0.0
    };
    let min_since_ts = candidate_first_ts.max(rr_ts);
    let exp = explicit_resume.trim();
    if !exp.is_empty() {
        let unwrapped = unwrap_primary_session_id(exp, min_since_ts);
        if unwrapped.is_empty() {
            return String::new();
        }
        if rr_ts > 0.0
            && !is_post_reset_codex_session_proven(&unwrapped, "", rr_ts, candidate_first_ts)
        {
            return String::new();
        }
        return unwrapped;
    }
    let owned_saved = if preloaded_saved.is_none() {
        active_thread_state_for_lane(session, git_root, Some(candidate_first_ts), model, effort)
    } else {
        None
    };
    let saved_ref = match preloaded_saved {
        Some(s) => s,
        None => owned_saved.as_ref(),
    };
    if let Some(saved) = saved_ref {
        if rr_ts <= 0.0 || val_to_f64(saved.get("updated_ts")) >= rr_ts {
            let raw_sid = val_to_str(saved.get("session_id"));
            if !raw_sid.is_empty() {
                let unwrapped = unwrap_primary_session_id(&raw_sid, min_since_ts);
                if !unwrapped.is_empty()
                    && is_post_reset_codex_session_proven(&unwrapped, "", rr_ts, candidate_first_ts)
                {
                    return unwrapped;
                }
            }
        }
    }
    let target_key = review_lane_key(model, effort);
    if !session.is_empty() && min_since_ts > 0.0 {
        let prior = scan_verified_codex_reviews(min_since_ts, session, git_root);
        for prev in prior.iter().rev() {
            let prev_mdl = val_to_str(prev.get("model"));
            let prev_eff = val_to_str(prev.get("effort"));
            if review_lane_key(&prev_mdl, &prev_eff) != target_key {
                continue;
            }
            let raw_sid = val_to_str(prev.get("session_id")).trim().to_string();
            let rpath = val_to_str(prev.get("rollout_path"));
            if !is_post_reset_codex_session_proven(&raw_sid, &rpath, rr_ts, candidate_first_ts) {
                continue;
            }
            if !raw_sid.is_empty() {
                let sid = unwrap_primary_session_id(&raw_sid, min_since_ts);
                if !sid.is_empty()
                    && is_post_reset_codex_session_proven(&sid, "", rr_ts, candidate_first_ts)
                {
                    return sid;
                }
            }
        }
    }
    String::new()
}

#[cfg(test)]
fn resolve_resume_session(
    git_root: &str,
    session: &str,
    candidate_first_ts: f64,
    explicit_resume: &str,
    force_new: bool,
    model: &str,
    effort: &str,
) -> String {
    resolve_resume_session_with_saved(
        ResumeSessionQuery {
            git_root,
            session,
            candidate_first_ts,
            explicit_resume,
            force_new,
            model,
            effort,
        },
        None,
    )
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

struct PromptBuildSpec<'a> {
    review_id: &'a str,
    packet_nonce: &'a str,
    scope_summary: &'a str,
    diff_text: &'a str,
    interdiff_text: &'a str,
    prior_ledger: &'a str,
    phase: &'a str,
    round_num: usize,
    is_resume: bool,
    is_timeout_resume: bool,
}

fn build_adversarial_prompt(spec: PromptBuildSpec<'_>) -> String {
    let max_ord = crate::cwg_stop::MAX_REVIEW_ROUNDS;
    let max_cls = cwg_common::MAX_CLOSURE_PASSES_PER_CYCLE;
    let round_header = if spec.phase == "closure" {
        format!(
            "MODE: CLOSURE_VALIDATION (Pass {}/{}{})\n",
            spec.round_num.clamp(1, max_cls),
            max_cls,
            if spec.round_num >= max_cls {
                " — FINAL PASS"
            } else {
                ""
            }
        )
    } else {
        format!(
            "MODE: ORDINARY_REVIEW (Round {}/{}{})\n",
            spec.round_num.clamp(1, max_ord),
            max_ord,
            if spec.round_num >= max_ord {
                " — FINAL ORDINARY ROUND: emit VERDICT: ESCALATE if any CRITICAL/HIGH blocker remains"
            } else {
                ""
            }
        )
    };

    let verdict_rule = if spec.phase == "closure" {
        "Check ONLY the frozen open blocker ledger, recovery interdiff, affected interfaces, and direct regressions — NEVER re-audit the whole scope.\n\
Respond in plain text/markdown (not JSON) and conclude with an exact standalone last line (no trailing prose, no code fences):\n\
CLOSURE_VALIDATION: READY\n\
or\n\
CLOSURE_VALIDATION: BLOCKED\n\
READY means every prior CRITICAL/HIGH blocker is resolved or not applicable with evidence and no direct recovery regression blocks release. BLOCKED must name the remaining CRITICAL/HIGH blocker with a concrete trigger."
            .to_string()
    } else if spec.round_num >= max_ord {
        format!(
            "Respond in plain text/markdown (not JSON) and conclude with an exact standalone last line (no trailing prose, no code fences):\n\
VERDICT: APPROVED\n\
or (because this is Round {0}/{0} and ordinary budget is spent if CRITICAL/HIGH blockers remain)\n\
VERDICT: ESCALATE\n\
Never emit REVISE in Round {0}.",
            max_ord
        )
    } else {
        "Respond in plain text/markdown (not JSON) and conclude with an exact standalone last line (no trailing prose, no code fences):\n\
VERDICT: APPROVED\n\
or\n\
VERDICT: REVISE"
            .to_string()
    };

    let is_delta_scope = !spec.is_timeout_resume && (spec.phase == "closure" || spec.is_resume || spec.round_num > 1);
    let round_mode = if spec.is_timeout_resume {
        "ROUND_MODE: timeout_continuation (same review thread — your previous review turn hit the wall-clock timeout before emitting a final verdict; continue from the context already inspected without starting over, and conclude with your findings and exact standalone verdict line).\n"
    } else if is_delta_scope {
        "ROUND_MODE: delta_interdiff (re-review is strictly scoped to the remediation interdiff and prior blockers, NOT the whole change again:\n\
- Give each prior blocker disposition: RESOLVED, NOT RESOLVED (with concrete evidence), or REGRESSED. Judge whether the failure scenario is removed, even if implemented differently from your wording.\n\
- Inspect the changes since your last round plus their direct blast radius (callers, callees, contracts).\n\
- SETTLED-SCOPE FREEZE: Everything examined in earlier rounds that this interdiff does NOT touch is SETTLED. Do NOT re-read settled code and do NOT raise new findings on untouched code, except a brand-new CRITICAL with explicit justification why it was invisible in Round 1.)\n"
    } else {
        "ROUND_MODE: round_1_full_candidate (report every qualifying CRITICAL/HIGH finding in Round 1; never hold findings back for later rounds).\n"
    };

    let ledger_section = if is_delta_scope && !spec.prior_ledger.trim().is_empty() {
        let trimmed_ledger: String = match spec.prior_ledger.char_indices().nth(12_000) {
            Some((idx, _)) => spec.prior_ledger[..idx].to_string(),
            None => spec.prior_ledger.to_string(),
        };
        format!("\nPRIOR ROUND FINDING LEDGER:\n{}\n", trimmed_ledger.trim())
    } else {
        String::new()
    };

    let primary_diff = if is_delta_scope && !spec.interdiff_text.trim().is_empty() {
        let snap: String = match spec.interdiff_text.char_indices().nth(MAX_DIFF_SNAPSHOT_CHARS) {
            Some((idx, _)) => spec.interdiff_text[..idx].to_string(),
            None => spec.interdiff_text.to_string(),
        };
        format!("REMEDIATION INTERDIFF SINCE PREVIOUS ROUND:\n{}", snap)
    } else {
        let snap: String = match spec.diff_text.char_indices().nth(MAX_DIFF_SNAPSHOT_CHARS) {
            Some((idx, _)) => spec.diff_text[..idx].to_string(),
            None => spec.diff_text.to_string(),
        };
        format!("GIT DIFF SNAPSHOT:\n{}", snap)
    };

    format!(
        "REVIEW_ID: {}\n\
PACKET_NONCE: {}\n\
ROLE: Senior Read-Only Adversarial Code Reviewer.\n\
{}{}\
OPERATING STANCE & SEVERITY CALIBRATION (BLOCKING_THRESHOLD = HIGH):\n\
1. Read-only authorized review: NEVER edit, write, or delete files, and NEVER end with a question. Make reasonable assumptions, state them, and finish with the standalone verdict line.\n\
2. Adversarial search is the method; deciding whether anything blocks release is the job. A clean, evidence-backed APPROVED is a successful review, not a failed attack.\n\
3. Severity definitions:\n\
   - CRITICAL: data loss, security bypass, auth breach, schema corruption.\n\
   - HIGH: a concrete reachable path to a production failure, cascading breakage, or broken rollback, with a named concrete trigger.\n\
   - MEDIUM: a real edge case, observability gap, or race under load that does not break normal operation.\n\
   - LOW / INFO: correctness-adjacent polish or hypothetical concern without a concrete trigger.\n\
4. ONLY CRITICAL, HIGH, and explicit acceptance-criterion violations block. MEDIUM, LOW, and INFO are non-blocking notes inside an APPROVED verdict. A finding without a concrete trigger is LOW/INFO or nothing at all — do NOT manufacture severity to justify REVISE/BLOCKED. Pre-existing out-of-scope defects carry no severity and never affect the verdict.\n\
5. Pre-verdict self-check: if no open CRITICAL or HIGH remains and nothing required is missing, emit APPROVED / READY immediately rather than looking for one more reason to hold.\n\
6. {}\n\n\
CANDIDATE SUMMARY:\n{}\n{}\n\
{}\n",
        spec.review_id,
        spec.packet_nonce,
        round_header,
        round_mode,
        verdict_rule,
        spec.scope_summary,
        ledger_section,
        primary_diff
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

fn build_thinking_timeout_payload(
    review_id: &str,
    timeout_sec: i64,
    recommended_timeout: i64,
    retry_cmd: &str,
    timeout_sid: &str,
    state_persisted: bool,
) -> Value {
    let mut payload_to = Map::new();
    payload_to.insert("ok".to_string(), Value::Bool(false));
    payload_to.insert("review_id".to_string(), Value::String(review_id.to_string()));
    payload_to.insert("timed_out".to_string(), Value::Bool(true));
    payload_to.insert("state_persisted".to_string(), Value::Bool(state_persisted));
    payload_to.insert(
        "session_continuation_saved".to_string(),
        Value::Bool(state_persisted && !timeout_sid.is_empty()),
    );
    payload_to.insert("retry_in_same_lane".to_string(), Value::Bool(true));
    payload_to.insert("round_consumed".to_string(), Value::Bool(false));
    payload_to.insert("recommended_timeout".to_string(), json!(recommended_timeout));
    payload_to.insert(
        "error".to_string(),
        Value::String(format!("timeout_after_{}s", timeout_sec)),
    );
    let effective_retry_cmd = if !state_persisted && !timeout_sid.is_empty() {
        let mut s = retry_cmd.to_string();
        push_cli_flag_val(&mut s, "--resume", timeout_sid);
        s
    } else {
        retry_cmd.to_string()
    };
    payload_to.insert(
        "retry_command".to_string(),
        Value::String(effective_retry_cmd.clone()),
    );
    if !state_persisted {
        payload_to.insert(
            "persistence_error".to_string(),
            Value::String("thread_state_not_saved".to_string()),
        );
    }
    let hint = if state_persisted {
        if !timeout_sid.is_empty() {
            format!(
                "Codex did not finish within {}s (thinking timeout, NOT an outage; review round NOT consumed). Re-run {} without --timeout to continue the same Codex session with {}s timeout; escalating to internal review on a thinking timeout is forbidden.",
                timeout_sec, effective_retry_cmd, recommended_timeout
            )
        } else {
            format!(
                "Codex did not finish within {}s (thinking timeout, NOT an outage; review round NOT consumed). Re-run {} without --timeout to retry in the same Codex lane with {}s escalated timeout; escalating to internal review on a thinking timeout is forbidden.",
                timeout_sec, effective_retry_cmd, recommended_timeout
            )
        }
    } else if !timeout_sid.is_empty() {
        format!(
            "Codex did not finish within {}s (thinking timeout, NOT an outage; review round NOT consumed), and timeout continuation state could NOT be saved (`state_persisted=false`). Re-run {} without --timeout (uses {}s timeout because escalated state was not persisted); escalating to internal review on a thinking timeout is forbidden.",
            timeout_sec, effective_retry_cmd, recommended_timeout
        )
    } else {
        format!(
            "Codex did not finish within {}s (thinking timeout, NOT an outage; review round NOT consumed), and timeout continuation state could NOT be saved (`state_persisted=false`). Re-run {} without --timeout (opens a new session in the same Codex lane with {}s timeout); escalating to internal review on a thinking timeout is forbidden.",
            timeout_sec, effective_retry_cmd, recommended_timeout
        )
    };
    payload_to.insert("hint".to_string(), Value::String(hint));
    if !timeout_sid.is_empty() {
        payload_to.insert("session_id".to_string(), Value::String(timeout_sid.to_string()));
    }
    Value::Object(payload_to)
}

struct CodexExecSpec<'a> {
    binary: &'a str,
    args: &'a [String],
    prompt: &'a str,
    cwd: &'a str,
    timeout: f64,
    review_id: &'a str,
    expected_phase: &'a str,
    xhigh: bool,
}

fn exec_codex_once(spec: CodexExecSpec<'_>) -> Option<CodexExecResult> {
    let CodexExecSpec {
        binary,
        args,
        prompt,
        cwd,
        timeout,
        review_id,
        expected_phase,
        xhigh,
    } = spec;
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
                    "error": format!("sandbox_restricted ({}); re-run `carbon-stack codex-lane review` with BypassSandbox=true", sb),
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
        if take_defer_timeout_print(review_id) {
            return None;
        }
        let mut arg_model = String::new();
        for (idx, a) in args.iter().enumerate() {
            if a == "-m" && idx + 1 < args.len() {
                arg_model = args[idx + 1].clone();
                break;
            }
        }
        let payload_to = build_thinking_timeout_payload(
            review_id,
            timeout as i64,
            recommended_timeout,
            &format_review_retry_cmd(&arg_model, xhigh),
            &timeout_sid,
            true,
        );
        rio::print_cli_json(&payload_to, false);
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
    let has_structured_verdict = matches!(
        cwg_common::extract_review_decision(&stdout_text),
        (Some(ref dk), Some(_)) if expected_phase.is_empty() || dk == expected_phase
    );
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

fn purge_session_lane_threads_unlocked(session: &str, git_root: &str) {
    let root_dig = session_root_digest(session, git_root);
    let default_name = format!("{}.json", root_dig);
    let lane_prefix = format!("{}-", root_dig);
    if let Ok(entries) = fs::read_dir(threads_dir()) {
        for ent in entries.flatten() {
            let fname_os = ent.file_name();
            let Some(fname) = fname_os.to_str() else {
                continue;
            };
            if fname == default_name || (fname.starts_with(&lane_prefix) && fname.ends_with(".json"))
            {
                unlink_quiet(&ent.path());
            }
        }
    }
}

struct ResearchResetArgs {
    cwd: String,
    session: String,
    decision: String,
    findings: String,
    transcript: String,
    pretty: bool,
}

fn cmd_research_reset(args: &ResearchResetArgs) -> i32 {
    // INVARIANT: Allow at most `MAX_REDESIGN_RESETS = 1` finite architectural `REDESIGN` reset per candidate after Round 4 `ESCALATE` + verified post-`ESCALATE` research (clearing saved Codex threads, round counters, and simplify latches so the redesigned architecture starts in fresh reviewer/simplify sessions), while keeping `REMEDIATE` in the current Codex session (`max 2` `--closure` passes) and terminating finitely via `[gate] draft-blocked` when exhausted.
    let dec = args.decision.trim().to_ascii_lowercase();
    if !cwg_common::REDESIGN_RESET_DECISIONS.contains(&dec.as_str()) {
        rio::print_cli_json(
            &json!({
                "ok": false,
                "error": "invalid_decision",
                "hint": "Only architectural REDESIGN resets rounds and reviewer sessions (--decision redesign|refactor, max 1 per candidate). Targeted REMEDIATE stays in the current Codex session via `carbon-stack codex-lane review --closure` (max 2 passes).",
            }),
            args.pretty,
        );
        return 2;
    }
    let clean_findings = args.findings.trim();
    if clean_findings.chars().count() < 15 {
        rio::print_cli_json(
            &json!({
                "ok": false,
                "error": "insufficient_findings",
                "hint": "Provide a concrete --findings summary (>= 15 chars) of the researched documentation/best practices and architectural REDESIGN decision.",
            }),
            args.pretty,
        );
        return 2;
    }
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
    let eff_session = if args.session.trim().is_empty() {
        infer_single_open_session(&cwd)
    } else {
        args.session.trim().to_string()
    };
    if eff_session.is_empty() {
        rio::print_cli_json(
            &json!({
                "ok": false,
                "error": "missing_session",
                "hint": "Pass --session <conversation-id> explicitly.",
            }),
            args.pretty,
        );
        return 2;
    }
    let _flight_lock = match try_acquire_review_flight_lock(&eff_session, &git_root) {
        FlightLockResult::Acquired(fh) => fh,
        FlightLockResult::Busy => {
            rio::print_cli_json(
                &json!({
                    "ok": false,
                    "review_in_progress": true,
                    "error": "concurrent_review_in_flight",
                    "hint": "Wait for the running `carbon-stack codex-lane review` to finish before running `redesign-reset`.",
                }),
                args.pretty,
            );
            return 2;
        }
        FlightLockResult::Io(detail) => {
            rio::print_cli_json(
                &json!({
                    "ok": false,
                    "sandbox_blocked": true,
                    "detail": detail,
                    "error": "CARBON_STACK_HOME is not writable in sandbox; re-run `carbon-stack codex-lane redesign-reset` with BypassSandbox=true",
                }),
                args.pretty,
            );
            return 2;
        }
    };
    let skey = rio::safe_key(&eff_session, "default");
    let mpath = cwg_common::marker_path(&skey);
    let raw_marker = rio::read_json(&mpath);
    let (merged_m_opt, _) = cwg_common::apply_pending_marker_deltas(&skey, raw_marker.as_ref());
    let Some(marker) = merged_m_opt else {
        rio::print_cli_json(
            &json!({
                "ok": false,
                "error": "no_open_candidate",
                "session": eff_session,
            }),
            args.pretty,
        );
        return 2;
    };
    if !marker.is_object() || json_truthy(marker.get("closed")) {
        rio::print_cli_json(
            &json!({
                "ok": false,
                "error": "no_open_candidate",
                "session": eff_session,
            }),
            args.pretty,
        );
        return 2;
    }
    let pre_lock_rr_ts = cwg_common::last_research_reset_ts(&marker);
    let pre_lock_rr_seq = cwg_common::last_research_reset_board_seq(&marker);
    let used_redesigns = cwg_common::redesign_reset_count(&marker);
    let tp_buf = if !args.transcript.trim().is_empty() {
        PathBuf::from(args.transcript.trim())
    } else {
        rio::member_transcript_path(&rio::resolve_brain_root(""), &eff_session)
    };
    let tp_str = tp_buf.to_string_lossy().into_owned();
    let cls_summary = active_cycle_closure_summary(&eff_session, &git_root, &tp_str);
    let closure_exhausted = cls_summary.effective_pass_count
        >= cwg_common::MAX_CLOSURE_PASSES_PER_CYCLE
        || cls_summary.blocked_count >= cwg_common::MAX_CLOSURE_PASSES_PER_CYCLE
        || cwg_common::active_marker_closure_halt(&marker).is_some();
    if used_redesigns >= cwg_common::MAX_REDESIGN_RESETS {
        rio::print_cli_json(
            &json!({
                "ok": false,
                "error": "redesign_reset_limit_reached",
                "redesign_resets_used": used_redesigns,
                "max_redesign_resets": cwg_common::MAX_REDESIGN_RESETS,
                "terminal_draft_blocked": closure_exhausted,
                "hint": format!(
                    "Current candidate already consumed MAX_REDESIGN_RESETS={0}/{0}. Complete via `--closure` (max {1} passes) or terminate finitely with `[gate] draft-blocked: <exact blocker and handoff>`.",
                    cwg_common::MAX_REDESIGN_RESETS,
                    cwg_common::MAX_CLOSURE_PASSES_PER_CYCLE,
                ),
            }),
            args.pretty,
        );
        return 2;
    }
    if cls_summary.has_fresh_ordinary_approved || cls_summary.has_fresh_ready {
        rio::print_cli_json(
            &json!({
                "ok": false,
                "error": "already_terminal_approved_or_ready",
                "hint": "Current candidate already has a fresh APPROVED/READY verdict; close the gate instead of resetting.",
            }),
            args.pretty,
        );
        return 2;
    }
    if closure_exhausted {
        rio::print_cli_json(
            &json!({
                "ok": false,
                "error": "closure_budget_exhausted",
                "terminal_draft_blocked": true,
                "blocked_closure_passes": cls_summary.blocked_count,
                "effective_closure_passes": cls_summary.effective_pass_count,
                "hint": format!(
                    "All {0}/{0} closure passes were already consumed or halted by 2x BLOCKED; finish finitely with `[gate] draft-blocked: <exact blocker and handoff>`.",
                    cwg_common::MAX_CLOSURE_PASSES_PER_CYCLE,
                ),
            }),
            args.pretty,
        );
        return 2;
    }
    if !cls_summary.has_round_cap_escalate || cls_summary.escalate_verdict_ts <= 0.0 {
        rio::print_cli_json(
            &json!({
                "ok": false,
                "error": "redesign_requires_escalate",
                "counted_ordinary_rounds": cls_summary.counted_ordinary_rounds,
                "hint": format!(
                    "`redesign-reset` is allowed only after Round {0} ESCALATE + focused research when choosing architectural REDESIGN (max {1} per candidate).",
                    crate::cwg_stop::MAX_REVIEW_ROUNDS,
                    cwg_common::MAX_REDESIGN_RESETS,
                ),
            }),
            args.pretty,
        );
        return 2;
    }
    let halt_floor_ts = cls_summary
        .escalate_verdict_ts
        .max(cls_summary.last_blocked_ts);
    let steps = rio::read_transcript_steps(&tp_str, 4000);
    let research_tools = cwg_common::find_research_evidence_since(&steps, halt_floor_ts, None);
    if research_tools.is_empty() {
        rio::print_cli_json(
            &json!({
                "ok": false,
                "error": "missing_post_escalate_research",
                "escalate_verdict_ts": halt_floor_ts,
                "hint": "Execute focused external/docs research AFTER Round 4 ESCALATE (`search_web`, `context7`, `exa`, `fetch`, `tokenade search|web`, or `research` subagent) before running `redesign-reset`.",
            }),
            args.pretty,
        );
        return 2;
    }
    let brain_root = rio::swarm_brain_and_cid(&tp_str, &eff_session)
        .0
        .unwrap_or_else(|| rio::resolve_brain_root(""));
    let alive_workers = cwg_common::active_simplify_or_review_workers(&brain_root, &eff_session);
    if !alive_workers.is_empty() {
        rio::print_cli_json(
            &json!({
                "ok": false,
                "error": "active_swarm_workers_present",
                "workers": alive_workers,
                "hint": "Kill all waiting/active simplify and review swarm workers via swarm(action='kill', ...) before `redesign-reset` so the redesigned cycle starts in fresh sessions.",
            }),
            args.pretty,
        );
        return 2;
    }

    let pre_members = rio::load_swarm_members(&brain_root, &eff_session);
    let mut pre_cids: Vec<String> = pre_members
        .values()
        .filter_map(|m| m.get("conversation_id").or_else(|| m.get("conversationId")))
        .map(|v| val_to_str(Some(v)).trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    pre_cids.sort();
    pre_cids.dedup();
    let board_head_live = cwg_common::swarm_board_head_seq(&eff_session, &git_root, &tp_str, None);
    let now = now_sec().max(halt_floor_ts + 0.002);

    // SAFETY: Lock `marker_lock_path` and `thread_lock_path`, re-verify `MAX_REDESIGN_RESETS` and `ESCALATE` invariants under lock, persist `research_resets` BEFORE purging lane threads, and clear stale simplify latches so the redesigned candidate gets one fresh cycle.
    let commit_res: Result<(i64, Value), &'static str> =
        rio::with_file_lock(&cwg_common::marker_lock_path(&skey), 5.0, 30.0, |m_locked| {
            if !m_locked {
                return Err("marker_lock_failed");
            }
            let raw_fresh = rio::read_json(&mpath);
            let (fresh_opt, consumed_ids) =
                cwg_common::apply_pending_marker_deltas(&skey, raw_fresh.as_ref());
            let Some(mut fresh_marker) = fresh_opt else {
                return Err("no_open_candidate");
            };
            if !fresh_marker.is_object() || json_truthy(fresh_marker.get("closed")) {
                return Err("no_open_candidate");
            }
            if cwg_common::redesign_reset_count(&fresh_marker) >= cwg_common::MAX_REDESIGN_RESETS {
                return Err("redesign_reset_limit_reached");
            }
            if cwg_common::last_research_reset_ts(&fresh_marker) != pre_lock_rr_ts
                || cwg_common::last_research_reset_board_seq(&fresh_marker) != pre_lock_rr_seq
            {
                return Err("redesign_requires_escalate");
            }
            if cwg_common::active_marker_closure_halt(&fresh_marker).is_some() {
                return Err("closure_budget_exhausted");
            }
            let (live_halt_ts, live_blocked_ids, eff_res_tools) = if fresh_marker == marker {
                (
                    halt_floor_ts,
                    cls_summary.blocked_ids.clone(),
                    research_tools.clone(),
                )
            } else {
                let live_sum = active_cycle_closure_summary_for_marker(
                    &fresh_marker,
                    &eff_session,
                    &git_root,
                    &tp_str,
                );
                if live_sum.has_fresh_ordinary_approved || live_sum.has_fresh_ready {
                    return Err("already_terminal_approved_or_ready");
                }
                if live_sum.effective_pass_count >= cwg_common::MAX_CLOSURE_PASSES_PER_CYCLE
                    || live_sum.blocked_count >= cwg_common::MAX_CLOSURE_PASSES_PER_CYCLE
                {
                    return Err("closure_budget_exhausted");
                }
                if !live_sum.has_round_cap_escalate || live_sum.escalate_verdict_ts <= 0.0 {
                    return Err("redesign_requires_escalate");
                }
                let h_ts = live_sum.escalate_verdict_ts.max(live_sum.last_blocked_ts);
                let mut r_tools = research_tools.clone();
                if h_ts > halt_floor_ts {
                    let fresh_steps = rio::read_transcript_steps(&tp_str, 4000);
                    r_tools = cwg_common::find_research_evidence_since(&fresh_steps, h_ts, None);
                    if r_tools.is_empty() {
                        return Err("missing_post_escalate_research");
                    }
                }
                (h_ts, live_sum.blocked_ids, r_tools)
            };
            if !cwg_common::active_simplify_or_review_workers(&brain_root, &eff_session).is_empty()
            {
                return Err("active_swarm_workers_present");
            }
            let eff_now = now.max(live_halt_ts + 0.002);
            let board_head_seq = fresh_marker
                .get("round_start_msg_id")
                .and_then(|v| v.as_i64())
                .unwrap_or(0)
                .max(board_head_live);
            let reset_entry = json!({
                "reset_ts": eff_now,
                "last_blocked_ts": live_halt_ts,
                "blocked_review_ids": live_blocked_ids,
                "decision": dec,
                "findings": clean_findings,
                "research_tools": eff_res_tools,
                "board_head_seq": board_head_seq,
                "pre_reset_worker_cids": pre_cids,
            });
            if let Some(mobj) = fresh_marker.as_object_mut() {
                let arr_val = mobj
                    .entry("research_resets".to_string())
                    .or_insert_with(|| Value::Array(Vec::new()));
                if !arr_val.is_array() {
                    *arr_val = Value::Array(Vec::new());
                }
                if let Some(arr) = arr_val.as_array_mut() {
                    arr.push(reset_entry.clone());
                }
                mobj.insert("round_start_msg_id".to_string(), json!(board_head_seq));
                mobj.remove("closure_halt");
                mobj.remove("cycle_declared_risk");
                mobj.remove("simplify_fast_path_latched");
                mobj.remove("simplify_verified_latched");
            }
            rio::with_file_lock(&thread_lock_path(&eff_session, &git_root), 5.0, 30.0, |t_locked| {
                if !t_locked {
                    return Err("thread_purge_lock_failed");
                }
                if rio::read_json(&mpath) != raw_fresh {
                    return Err("concurrent_marker_mutation");
                }
                if rio::write_json(&mpath, &fresh_marker).is_err() {
                    return Err("marker_write_failed");
                }
                if !consumed_ids.is_empty() {
                    cwg_common::ack_pending_marker_deltas(&skey, &consumed_ids);
                }
                purge_session_lane_threads_unlocked(&eff_session, &git_root);
                unlink_quiet(&cwg_common::swarm_rounds_path(&skey));
                Ok((board_head_seq, reset_entry))
            })
        });

    let (board_head_seq, reset_entry) = match commit_res {
        Ok(pair) => pair,
        Err(err_code) => {
            rio::print_cli_json(
                &json!({
                    "ok": false,
                    "error": err_code,
                    "session": eff_session,
                }),
                args.pretty,
            );
            return 2;
        }
    };

    rio::log_hook_event("gate-events", "redesign_cycle_reset", reset_entry.clone());
    rio::print_cli_json(
        &json!({
            "ok": true,
            "session": eff_session,
            "decision": dec,
            "redesign_resets_used": used_redesigns + 1,
            "max_redesign_resets": cwg_common::MAX_REDESIGN_RESETS,
            "research_tools": reset_entry.get("research_tools").cloned().unwrap_or_else(|| json!(research_tools)),
            "reset_ts": reset_entry.get("reset_ts").cloned().unwrap_or_else(|| json!(now)),
            "board_head_seq": board_head_seq,
            "round_counters_reset": true,
            "fresh_sessions_enforced": true,
        }),
        args.pretty,
    );
    0
}

struct PacketCleanupGuard {
    review_id: String,
    owner_nonce: String,
    committed: bool,
}

impl Drop for PacketCleanupGuard {
    fn drop(&mut self) {
        if !self.committed {
            unlink_packet_if_owned(&self.review_id, &self.owner_nonce);
        }
    }
}

enum FlightLockResult {
    Acquired(fs::File),
    Busy,
    Io(String),
}

fn try_acquire_review_flight_lock(session: &str, git_root: &str) -> FlightLockResult {
    // SAFETY: Serialize in-flight `codex-lane review` runs per `(session, git_root)` via kernel `LockFileEx`/`flock` (`File::try_lock`) so parallel launches cannot bypass pre-launch `--closure` pass limits and crashes release the lock automatically.
    let tdir = threads_dir();
    if let Err(e) = fs::create_dir_all(&tdir) {
        return FlightLockResult::Io(e.to_string());
    }
    let key_sess = if session.trim().is_empty() {
        "default"
    } else {
        session.trim()
    };
    let lock_path = tdir.join(format!("{}.flight.lock", session_root_digest(key_sess, git_root)));
    let fh = match fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
    {
        Ok(f) => f,
        Err(e) => return FlightLockResult::Io(e.to_string()),
    };
    match fh.try_lock() {
        Ok(()) => FlightLockResult::Acquired(fh),
        Err(std::fs::TryLockError::WouldBlock) => FlightLockResult::Busy,
        Err(std::fs::TryLockError::Error(e)) => FlightLockResult::Io(e.to_string()),
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
    if !args.review_id.is_empty() {
        if !aborted_rid_re().is_match(&args.review_id) {
            rio::print_cli_json(
                &json!({
                    "ok": false,
                    "error": "invalid_review_id",
                    "review_id": args.review_id,
                    "hint": "Custom --review-id must match ^[A-Za-z0-9_-]{6,64}$; omit --review-id so carbon-stack generates one automatically.",
                }),
                args.pretty,
            );
            return 2;
        }
        if has_recorded_packet(&args.review_id) {
            rio::print_cli_json(
                &json!({
                    "ok": false,
                    "error": format!("duplicate_review_id:{}", args.review_id),
                }),
                args.pretty,
            );
            return 2;
        }
    }

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
    let eff_model = resolve_review_model(&args.model, args.xhigh);
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
    let _flight_lock = match try_acquire_review_flight_lock(&eff_session, &git_root) {
        FlightLockResult::Acquired(fh) => fh,
        FlightLockResult::Busy => {
            rio::print_cli_json(
                &json!({
                    "ok": false,
                    "review_in_progress": true,
                    "round_consumed": false,
                    "error": "concurrent_review_in_flight",
                    "hint": "Another `carbon-stack codex-lane review` is already running for this session and repository; wait for it to finish instead of running parallel reviews.",
                }),
                args.pretty,
            );
            return 2;
        }
        FlightLockResult::Io(detail) => {
            rio::print_cli_json(
                &json!({
                    "ok": false,
                    "sandbox_blocked": true,
                    "detail": detail,
                    "error": "CARBON_STACK_HOME is not writable in sandbox; re-run `carbon-stack codex-lane review` with BypassSandbox=true",
                }),
                args.pretty,
            );
            return 2;
        }
    };
    if !eff_session.is_empty() {
        let skey_fold = rio::safe_key(&eff_session, "default");
        let mfile_fold = cwg_common::marker_path(&skey_fold);
        if mfile_fold.is_file() || cwg_common::has_pending_marker_deltas(&skey_fold) {
            // SAFETY: Fold pending journaled edits AND persist external editor `catch_up_unmeasured_changes` BEFORE pre-launch cycle summary and `launch_ts`, failing closed (`rc == 2`) if marker lock or write fails so a later `Stop` never stamps an edit after `launch_ts`.
            let sync_res: Result<(), &'static str> =
                rio::with_file_lock(&cwg_common::marker_lock_path(&skey_fold), 5.0, 30.0, |locked| {
                    if !locked {
                        return Err("marker_lock_failed");
                    }
                    let raw_m = rio::read_json(&mfile_fold);
                    let (merged_opt, cids) =
                        cwg_common::apply_pending_marker_deltas(&skey_fold, raw_m.as_ref());
                    if let Some(merged) = merged_opt {
                        if merged.is_object() && !json_truthy(merged.get("closed")) {
                            let caught = crate::cwg_stop::catch_up_unmeasured_changes(&merged);
                            if !cids.is_empty() || Some(&caught) != raw_m.as_ref() {
                                if rio::write_json(&mfile_fold, &caught).is_err() {
                                    return Err("marker_sync_write_failed");
                                }
                                if !cids.is_empty() {
                                    cwg_common::ack_pending_marker_deltas(&skey_fold, &cids);
                                }
                            }
                        }
                    }
                    Ok(())
                });
            if let Err(sync_err) = sync_res {
                rio::print_cli_json(
                    &json!({
                        "ok": false,
                        "round_consumed": false,
                        "error": sync_err,
                        "hint": "Failed to synchronize candidate marker fingerprint before review; retry `carbon-stack codex-lane review` once marker lock/storage is available.",
                    }),
                    args.pretty,
                );
                return 2;
            }
        }
    }
    let req_risk_override = if args.xhigh { "XHIGH" } else { "" };
    // SAFETY: Latch `XHIGH` BEFORE `check_health()` so breaker-open / missing-binary / auth-failure fallbacks preserve escalated cycle risk in `Stop`.
    if args.xhigh
        && !eff_session.is_empty()
        && candidate_first_ts(&eff_session) > 0.0
        && !cwg_common::latch_marker_declared_risk(&eff_session, None, None, "XHIGH")
    {
        rio::print_cli_json(
            &json!({
                "ok": false,
                "round_consumed": false,
                "error": "marker_risk_latch_failed",
                "hint": "Failed to persist cycle XHIGH risk under marker lock; retry `carbon-stack codex-lane review --xhigh`.",
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

    let cls_summary =
        active_cycle_closure_summary_with_risk(&eff_session, &git_root, "", req_risk_override);
    let blocked_cls_n = cls_summary.blocked_count;
    let blocked_cls_ids = cls_summary.blocked_ids;
    let cand_first_ts = candidate_first_ts(&eff_session);
    if phase == "ordinary" && !eff_session.is_empty() {
        if let Some(m_fp) = cwg_common::read_marker_with_pending(&eff_session)
            .filter(|m| !json_truthy(m.get("closed")))
        {
            if crate::cwg_stop::has_completed_candidate_simplify(&eff_session, &m_fp, "")
                && cwg_common::is_simplify_fast_path_eligible(&m_fp, None, None, &git_root)
            {
                let _ = cwg_common::latch_marker_fast_path_simplify(&eff_session, now_sec());
            }
        }
    }
    if blocked_cls_n >= cwg_common::MAX_CLOSURE_PASSES_PER_CYCLE {
        // INVARIANT: Hard-stop review continuation after 2 `CLOSURE_VALIDATION: BLOCKED` passes (`Nothing wraps it in another loop`) and finish finitely via `[gate] draft-blocked`.
        rio::print_cli_json(
            &json!({
                "ok": false,
                "terminal_draft_blocked": true,
                "blocked_closure_passes": blocked_cls_n,
                "blocked_review_ids": blocked_cls_ids,
                "error": "max_closure_blocks_reached",
                "hint": format!(
                    "After {}/{} CLOSURE_VALIDATION: BLOCKED passes, the closure budget is exhausted. Do NOT restart review or simplify: preserve completed work and finish finitely with `[gate] draft-blocked: <exact blocker and handoff>`.",
                    blocked_cls_n,
                    cwg_common::MAX_CLOSURE_PASSES_PER_CYCLE,
                ),
            }),
            args.pretty,
        );
        return 2;
    }
    if cls_summary.effective_pass_count >= cwg_common::MAX_CLOSURE_PASSES_PER_CYCLE
        && (phase == "closure" || !cls_summary.has_fresh_ready)
    {
        rio::print_cli_json(
            &json!({
                "ok": false,
                "terminal_draft_blocked": !cls_summary.has_fresh_ready,
                "already_closure_ready": cls_summary.has_fresh_ready,
                "round_consumed": false,
                "effective_closure_passes": cls_summary.effective_pass_count,
                "error": "max_closure_passes_reached",
                "hint": if cls_summary.has_fresh_ready {
                    "Current candidate already completed 2/2 closure passes ending in CLOSURE_VALIDATION: READY; close the gate instead of launching a 3rd --closure pass.".to_string()
                } else {
                    format!(
                        "Current candidate already consumed MAX_CLOSURE_PASSES={0}/{0} closure passes; finish finitely with `[gate] draft-blocked: <exact blocker and handoff>`.",
                        cwg_common::MAX_CLOSURE_PASSES_PER_CYCLE,
                    )
                },
            }),
            args.pretty,
        );
        return 2;
    }
    if cls_summary.has_fresh_ordinary_approved {
        rio::print_cli_json(
            &json!({
                "ok": false,
                "round_consumed": false,
                "already_approved": true,
                "error": "already_ordinary_approved",
                "hint": "Current candidate already has a fresh valid `VERDICT: APPROVED`: close the gate immediately with `[gate] verified: ...` (never run post-approval simplify or `--closure`).",
            }),
            args.pretty,
        );
        return 2;
    }
    if phase == "ordinary" {
        if cls_summary.ordinary_cap_reached {
            let terminal_no_escalate = !cls_summary.has_round_cap_escalate;
            let ord_cap_hint = if cls_summary.has_round_cap_escalate {
                let can_redesign = cwg_common::read_marker_with_pending(&eff_session)
                    .map(|m| cwg_common::redesign_reset_count(&m) < cwg_common::MAX_REDESIGN_RESETS)
                    .unwrap_or(false);
                if can_redesign {
                    format!(
                        "All {0}/{0} ordinary review rounds have been used (ending in ESCALATE): perform one focused research pass, then either (a) REMEDIATE in the same Codex session via `carbon-stack codex-lane review --closure` (max {1} passes), or (b) for an architectural REDESIGN (max {2} per candidate) kill swarm workers and run `carbon-stack codex-lane redesign-reset --cwd <repo> --session <sid> --findings \"<summary>\"` to reset rounds and start fresh simplify + review sessions.",
                        crate::cwg_stop::MAX_REVIEW_ROUNDS,
                        cwg_common::MAX_CLOSURE_PASSES_PER_CYCLE,
                        cwg_common::MAX_REDESIGN_RESETS,
                    )
                } else {
                    format!(
                        "All {0}/{0} ordinary review rounds have been used (ending in ESCALATE; {2}/{2} REDESIGN reset already used): perform one focused research pass, run tests, and run `carbon-stack codex-lane review --closure` (max {1} passes), or finish finitely with `[gate] draft-blocked`.",
                        crate::cwg_stop::MAX_REVIEW_ROUNDS,
                        cwg_common::MAX_CLOSURE_PASSES_PER_CYCLE,
                        cwg_common::MAX_REDESIGN_RESETS,
                    )
                }
            } else {
                format!(
                    "All {0}/{0} ordinary review rounds have been exhausted without `ESCALATE` (`--closure` is unavailable): finish finitely with `[gate] draft-blocked: <exact blocker and handoff>`.",
                    crate::cwg_stop::MAX_REVIEW_ROUNDS,
                )
            };
            rio::print_cli_json(
                &json!({
                    "ok": false,
                    "round_consumed": false,
                    "terminal_draft_blocked": terminal_no_escalate,
                    "counted_ordinary_rounds": cls_summary.counted_ordinary_rounds,
                    "raw_ordinary_rounds": cls_summary.raw_ordinary_rounds,
                    "error": "max_ordinary_rounds_reached",
                    "hint": ord_cap_hint,
                }),
                args.pretty,
            );
            return 2;
        }
        if blocked_cls_n >= 1 {
            rio::print_cli_json(
                &json!({
                    "ok": false,
                    "round_consumed": false,
                    "blocked_closure_passes": blocked_cls_n,
                    "error": "closure_phase_active",
                    "hint": "Candidate is already in `--closure` after Pass 1/2 BLOCKED: apply one bounded REMEDIATE/REDESIGN + tests and run `carbon-stack codex-lane review --closure` (Pass 2/2), or finish with `[gate] draft-blocked`.",
                }),
                args.pretty,
            );
            return 2;
        }
    }
    if phase == "closure" && !eff_session.is_empty() {
        let brain_root = rio::resolve_brain_root("");
        let alive_workers = cwg_common::active_simplify_or_review_workers(&brain_root, &eff_session);
        if !alive_workers.is_empty() {
            rio::print_cli_json(
                &json!({
                    "ok": false,
                    "round_consumed": false,
                    "error": "active_swarm_workers_present",
                    "workers": alive_workers,
                    "hint": "Kill all waiting/active simplify and review swarm workers via swarm(action='kill', ...) BEFORE launching `carbon-stack codex-lane review --closure`.",
                }),
                args.pretty,
            );
            return 2;
        }
        let has_open_persistent_cand = cwg_common::read_marker_with_pending(&eff_session)
            .map(|m| cwg_common::candidate_class(&m) == cwg_common::WORK_PERSISTENT)
            .unwrap_or(false);
        if has_open_persistent_cand {
            if !cls_summary.has_round_cap_escalate {
                rio::print_cli_json(
                    &json!({
                        "ok": false,
                        "round_consumed": false,
                        "counted_ordinary_rounds": cls_summary.counted_ordinary_rounds,
                        "error": "closure_requires_escalate",
                        "hint": format!(
                            "`--closure` is reserved for autonomous closure AFTER Round {0} ESCALATE; run ordinary `carbon-stack codex-lane review` (rounds 1..{0}, ending in ESCALATE) first, or close finitely with `[gate] draft-blocked` if all {0} rounds returned REVISE.",
                            crate::cwg_stop::MAX_REVIEW_ROUNDS
                        ),
                    }),
                    args.pretty,
                );
                return 2;
            }
            if !cls_summary.has_post_escalate_research {
                rio::print_cli_json(
                    &json!({
                        "ok": false,
                        "round_consumed": false,
                        "escalate_verdict_ts": cls_summary.escalate_verdict_ts,
                        "error": "missing_post_escalate_research",
                        "hint": "Perform one focused external/docs research pass (`search_web`, `context7`, `exa`, `fetch`, `tokenade search|web`, or `research` subagent) AFTER Round 4 ESCALATE before launching `carbon-stack codex-lane review --closure`.",
                    }),
                    args.pretty,
                );
                return 2;
            }
        }
    }
    let last_rr_ts = if !eff_session.is_empty() {
        cwg_common::read_marker_with_pending(&eff_session)
            .map(|m| cwg_common::last_research_reset_ts(&m))
            .unwrap_or(0.0)
    } else {
        0.0
    };
    if !args.resume.trim().is_empty()
        && last_rr_ts > 0.0
        && !is_post_reset_codex_session_proven(args.resume.trim(), "", last_rr_ts, cand_first_ts)
    {
        rio::print_cli_json(
            &json!({
                "ok": false,
                "error": "pre_research_reset_session_forbidden",
                "hint": "Resuming a pre-research-reset or unverified Codex session after research-reset is forbidden; omit --resume so the new cycle starts in a fresh review session.",
            }),
            args.pretty,
        );
        return 2;
    }
    let saved_thread = if args.new_session {
        None
    } else {
        active_thread_state_for_lane(
            &eff_session,
            &git_root,
            Some(cand_first_ts),
            &eff_model,
            effort,
        )
    };
    let mut resume_sid = resolve_resume_session_with_saved(
        ResumeSessionQuery {
            git_root: &git_root,
            session: &eff_session,
            candidate_first_ts: cand_first_ts,
            explicit_resume: &args.resume,
            force_new: args.new_session,
            model: &eff_model,
            effort,
        },
        Some(saved_thread.as_ref()),
    );
    if !resume_sid.is_empty()
        && last_rr_ts > 0.0
        && !is_post_reset_codex_session_proven(&resume_sid, "", last_rr_ts, cand_first_ts)
    {
        if !args.resume.trim().is_empty() {
            rio::print_cli_json(
                &json!({
                    "ok": false,
                    "error": "pre_research_reset_session_forbidden",
                    "hint": "Resuming a pre-research-reset or unverified Codex session after research-reset is forbidden; omit --resume so the new cycle starts in a fresh review session.",
                }),
                args.pretty,
            );
            return 2;
        }
        resume_sid.clear();
    }

    let curr_worktree_tree = if args.diff_file.is_empty()
        && !git_root.is_empty()
        && rio::git_toplevel(&git_root, false).is_some()
    {
        rio::capture_worktree_tree_oid(&git_root, 10.0)
    } else {
        String::new()
    };

    let diff_text = if !args.diff_file.is_empty() && Path::new(&args.diff_file).is_file() {
        read_diff_file(&args.diff_file)
    } else {
        let tree_diff = if cwg_common::is_git_oid(&curr_worktree_tree) {
            let (rc_td, out_td, _) =
                rio::run_git(&cwd, &["diff", "HEAD", &curr_worktree_tree], 10.0);
            if rc_td == 0 && !out_td.trim().is_empty() {
                Some(out_td)
            } else {
                None
            }
        } else {
            None
        };
        if let Some(td) = tree_diff {
            td
        } else {
            let (rc_git, out, _) = rio::run_git(&cwd, &["diff", "HEAD"], 10.0);
            if rc_git == 0 && !out.trim().is_empty() {
                out
            } else {
                let (_, out2, _) = rio::run_git(&cwd, &["status", "--short"], 5.0);
                out2
            }
        }
    };

    let prior_ledger = saved_thread
        .as_ref()
        .map(|st| val_to_str(st.get("last_review_output")))
        .unwrap_or_default();
    let prev_reviewed_tree = saved_thread
        .as_ref()
        .map(|st| val_to_str(st.get("last_reviewed_tree_oid")))
        .unwrap_or_default();
    // INVARIANT: Diff `prev_reviewed_tree` against `curr_worktree_tree` (`git add -A` temp-index snapshot) so remediation rounds that modify a tracked file AND add a new untracked file include both in `interdiff_text` under `Settled-Scope Freeze`.
    let interdiff_text = if args.diff_file.is_empty()
        && !prev_reviewed_tree.is_empty()
        && cwg_common::is_git_oid(&prev_reviewed_tree)
    {
        let (rc_id, id_out, _) = if cwg_common::is_git_oid(&curr_worktree_tree) {
            rio::run_git(&cwd, &["diff", &prev_reviewed_tree, &curr_worktree_tree], 10.0)
        } else {
            rio::run_git(&cwd, &["diff", &prev_reviewed_tree], 10.0)
        };
        if rc_id == 0 && !id_out.trim().is_empty() {
            id_out
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    let round_num = if phase == "closure" {
        cls_summary.effective_pass_count + 1
    } else {
        cls_summary.counted_ordinary_rounds + 1
    };

    let scope_summary = if args.summary.is_empty() {
        "Review current repository candidate changes.".to_string()
    } else {
        args.summary.clone()
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
                            "Upfront custom --timeout is forbidden; omit --timeout so `carbon-stack codex-lane review` uses the standard {}s (HIGH) / {}s (--xhigh) timeout.",
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
    let mut packet_committed = false;
    let mut launch_wall_ts = 0.0f64;
    let mut verdict_wall_ts = 0.0f64;
    let mut used_resume_sid = String::new();
    let mut active_review_id = review_id.clone();

    for (attempt_idx, cur_resume_sid) in attempts.iter().enumerate() {
        active_review_id = if attempt_idx == 0 || !args.review_id.is_empty() {
            review_id.clone()
        } else {
            format!("cwg-{}", random_hex_12())
        };
        let packet_nonce = random_hex_12();
        let prompt = build_adversarial_prompt(PromptBuildSpec {
            review_id: &active_review_id,
            packet_nonce: &packet_nonce,
            scope_summary: &scope_summary,
            diff_text: &diff_text,
            interdiff_text: &interdiff_text,
            prior_ledger: &prior_ledger,
            phase,
            round_num,
            is_resume: !cur_resume_sid.is_empty(),
            is_timeout_resume: !cur_resume_sid.is_empty() && is_timeout_continuation,
        });
        match reserve_packet_exclusive(
            &active_review_id,
            &prompt,
            &cwd,
            effort,
            phase,
            &eff_session,
        ) {
            Ok(_) => {}
            Err(PacketReserveError::Duplicate) => {
                rio::print_cli_json(
                    &json!({
                        "ok": false,
                        "error": format!("duplicate_review_id:{}", active_review_id),
                    }),
                    args.pretty,
                );
                return 2;
            }
            Err(PacketReserveError::Io(detail)) => {
                // SAFETY: Inside Standard Sandbox (`BypassSandbox=false`), `CARBON_STACK_HOME` is read-only; fail fast without hanging on blocked network sockets, without tripping the global breaker, and without granting fallback.
                rio::print_cli_json(
                    &json!({
                        "ok": false,
                        "sandbox_blocked": true,
                        "detail": detail,
                        "error": "CARBON_STACK_HOME is not writable in sandbox; re-run `carbon-stack codex-lane review` with BypassSandbox=true",
                    }),
                    args.pretty,
                );
                return 2;
            }
        }

        let mut pkt_guard = PacketCleanupGuard {
            review_id: active_review_id.clone(),
            owner_nonce: packet_nonce.clone(),
            committed: false,
        };
        launch_wall_ts = now_sec();
        let cmd_args = build_codex_exec_args(&cwd, effort, &eff_model, cur_resume_sid);
        set_defer_timeout_print(&active_review_id, true);
        let exec_opt = exec_codex_once(CodexExecSpec {
            binary: &binary,
            args: &cmd_args,
            prompt: &prompt,
            cwd: &cwd,
            timeout: eff_timeout,
            review_id: &active_review_id,
            expected_phase: phase,
            xhigh: args.xhigh,
        });
        set_defer_timeout_print(&active_review_id, false);
        verdict_wall_ts = now_sec();
        let Some(exec_res) = exec_opt else {
            let (timeout_kind, stream_sid) = pop_last_timeout_outage(&active_review_id);
            if timeout_kind == "thinking" {
                // INVARIANT: Persist timed-out Codex thread + elevated timeout before emitting CLI JSON so `state_persisted` and `recommended_timeout` reflect whether saving actually succeeded.
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
                let persisted = save_lane_thread_state(
                    &eff_session,
                    &git_root,
                    cand_first_ts,
                    &eff_model,
                    effort,
                    json!({
                        "session_id": timeout_sid,
                        "last_review_id": active_review_id,
                        "session": eff_session,
                        "git_root": rio::normalize_path(&git_root),
                        "candidate_first_ts": cand_first_ts,
                        "model": eff_model,
                        "effort": effort,
                        "phase": phase,
                        "xhigh": args.xhigh,
                        "pending_timeout_resume": true,
                        "last_timeout_seconds": eff_timeout as i64,
                        "next_timeout_seconds": next_to,
                        "updated_ts": now_sec(),
                    }),
                );
                let effective_rec_to = if persisted {
                    next_to
                } else {
                    let existing_next = active_thread_state_for_lane(
                        &eff_session,
                        &git_root,
                        Some(cand_first_ts),
                        &eff_model,
                        effort,
                    )
                    .filter(|st| json_truthy(st.get("pending_timeout_resume")))
                    .map(|st| val_to_f64(st.get("next_timeout_seconds")) as i64)
                    .unwrap_or(0);
                    required_review_timeout(args.xhigh, existing_next)
                };
                let retry_base_cmd = format_review_retry_cmd_with_spec(&RetryCmdSpec {
                    model: &eff_model,
                    xhigh: args.xhigh,
                    closure: phase == "closure",
                    session: &eff_session,
                    cwd: &args.cwd,
                    diff_file: &args.diff_file,
                    summary: &args.summary,
                    pretty: args.pretty,
                });
                let payload_to = build_thinking_timeout_payload(
                    &active_review_id,
                    eff_timeout as i64,
                    effective_rec_to,
                    &retry_base_cmd,
                    &timeout_sid,
                    persisted,
                );
                rio::print_cli_json(&payload_to, args.pretty);
            } else if timeout_kind == "network" {
                clear_pending_timeout_resume(
                    &eff_session,
                    &git_root,
                    cand_first_ts,
                    &eff_model,
                    effort,
                );
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
            remove_lane_thread_state(
                &eff_session,
                &git_root,
                cand_first_ts,
                &eff_model,
                effort,
            );
            continue;
        }
        // SAFETY: Commit the packet only when Codex exited 0 without outage AND emitted a recognized standalone verdict line matching `phase`; if disk commit fails, fail closed with non-zero exit code below.
        if exec_res.has_verdict
            && exec_res.outage.is_none()
            && exec_res.network_outage.is_none()
            && exec_res.rc == 0
            && commit_packet_owned(&active_review_id, &packet_nonce)
        {
            pkt_guard.committed = true;
            packet_committed = true;
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
                    "error": format!("sandbox_restricted ({}); re-run `carbon-stack codex-lane review` with BypassSandbox=true", sb),
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
            clear_pending_timeout_resume(
                &eff_session,
                &git_root,
                cand_first_ts,
                &eff_model,
                effort,
            );
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

    if !exec_res.has_verdict {
        rio::print_cli_json(
            &json!({
                "ok": false,
                "review_id": active_review_id,
                "exit_code": exec_res.rc,
                "error": "missing_review_verdict",
                "hint": "Codex exited 0 without emitting a recognized standalone review verdict line; re-run `carbon-stack codex-lane review`.",
            }),
            args.pretty,
        );
        return 2;
    }
    if !packet_committed {
        rio::print_cli_json(
            &json!({
                "ok": false,
                "review_id": active_review_id,
                "round_consumed": false,
                "error": "packet_commit_failed",
                "hint": "Failed to persist committed review packet on disk; re-run `carbon-stack codex-lane review`.",
            }),
            args.pretty,
        );
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
        reset_breaker_for_probe(launch_wall_ts, verdict_wall_ts);
        if !actual_sid.is_empty() {
            // INVARIANT: Persist the exact pre-review `curr_worktree_tree` snapshot that built the reviewed packet (never a post-verdict re-capture, and empty when `--diff-file` bypassed the live worktree) so files created while the reviewer was running remain in the next round's `interdiff`.
            let reviewed_tree_oid = if cwg_common::is_git_oid(&curr_worktree_tree) {
                curr_worktree_tree.clone()
            } else {
                String::new()
            };
            save_lane_thread_state(
                &eff_session,
                &git_root,
                cand_first_ts,
                &eff_model,
                effort,
                json!({
                    "session_id": actual_sid,
                    "last_review_id": active_review_id,
                    "session": eff_session,
                    "git_root": rio::normalize_path(&git_root),
                    "candidate_first_ts": cand_first_ts,
                    "model": eff_model,
                    "effort": effort,
                    "xhigh": args.xhigh,
                    "last_reviewed_tree_oid": reviewed_tree_oid,
                    "last_review_output": rio::truncate_chars(exec_res.stdout.trim(), 12_000),
                    "updated_ts": now_sec(),
                }),
            );
        } else if is_timeout_continuation {
            remove_lane_thread_state(
                &eff_session,
                &git_root,
                cand_first_ts,
                &eff_model,
                effort,
            );
        }
        if phase == "closure" && !eff_session.is_empty() {
            let _ = active_cycle_closure_blocks(&eff_session, &git_root, "");
        }
    }

    let session_mode = if !used_resume_sid.is_empty() {
        "resumed"
    } else {
        "new"
    };
    let output_block = format!(
        "REVIEW_ID: {}\nSESSION_ID: {}\nSESSION_MODE: {}\nENGINE: codex ({}, {})\n{}\n{}\n",
        active_review_id,
        actual_sid,
        session_mode,
        eff_model,
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

fn parse_str_flag_table(
    rest: &[String],
    idx: &mut usize,
    tok: &str,
    table: &mut [(&str, &mut String)],
) -> Result<bool, String> {
    for (flag, slot) in table.iter_mut() {
        if *flag == tok || tok.starts_with(&format!("{}=", flag)) {
            if let Some(v) = parse_flag_value(rest, idx, flag)? {
                **slot = v;
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn parse_hex_flag_table(
    rest: &[String],
    idx: &mut usize,
    tok: &str,
    table: &mut [(&str, &mut String)],
) -> Result<bool, String> {
    for (flag, slot) in table.iter_mut() {
        if *flag == tok || tok.starts_with(&format!("{}=", flag)) {
            if let Some(v) = parse_flag_value(rest, idx, flag)? {
                let decoded = decode_utf8_hex(&v)
                    .map_err(|err_msg| format!("error: argument {}: invalid utf-8 hex ({})", flag, err_msg))?;
                **slot = decoded;
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub fn run_cli(args: &[String]) -> i32 {
    if args.is_empty() {
        let _ = writeln!(
            std::io::stderr(),
            "usage: codex_lane <check|status|reset|breaker|scan|review|redesign-reset|research-reset> [args...]"
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
                match parse_str_flag_table(rest, &mut i, tok, &mut str_flags) {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(e) => {
                        let _ = writeln!(std::io::stderr(), "{}", e);
                        return 2;
                    }
                }

                let mut hex_flags = [
                    ("--cwd-hex", &mut rargs.cwd),
                    ("--summary-hex", &mut rargs.summary),
                    ("--diff-file-hex", &mut rargs.diff_file),
                    ("--session-hex", &mut rargs.session),
                    ("--model-hex", &mut rargs.model),
                    ("--resume-hex", &mut rargs.resume),
                ];
                match parse_hex_flag_table(rest, &mut i, tok, &mut hex_flags) {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(e) => {
                        let _ = writeln!(std::io::stderr(), "{}", e);
                        return 2;
                    }
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
        "redesign-reset" | "research-reset" => {
            let mut rr = ResearchResetArgs {
                cwd: String::new(),
                session: String::new(),
                decision: if sub == "redesign-reset" {
                    "redesign".to_string()
                } else {
                    String::new()
                },
                findings: String::new(),
                transcript: String::new(),
                pretty: false,
            };
            let mut i = 0usize;
            while i < rest.len() {
                let tok = &rest[i];
                if tok == "--pretty" {
                    rr.pretty = true;
                    i += 1;
                    continue;
                }
                let mut str_flags = [
                    ("--cwd", &mut rr.cwd),
                    ("--session", &mut rr.session),
                    ("--decision", &mut rr.decision),
                    ("--findings", &mut rr.findings),
                    ("--transcript", &mut rr.transcript),
                ];
                match parse_str_flag_table(rest, &mut i, tok, &mut str_flags) {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(e) => {
                        let _ = writeln!(std::io::stderr(), "{}", e);
                        return 2;
                    }
                }
                let mut hex_flags = [
                    ("--cwd-hex", &mut rr.cwd),
                    ("--session-hex", &mut rr.session),
                    ("--findings-hex", &mut rr.findings),
                    ("--transcript-hex", &mut rr.transcript),
                ];
                match parse_hex_flag_table(rest, &mut i, tok, &mut hex_flags) {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(e) => {
                        let _ = writeln!(std::io::stderr(), "{}", e);
                        return 2;
                    }
                }
                let _ = writeln!(std::io::stderr(), "error: unrecognized arguments: {}", tok);
                return 2;
            }
            cmd_research_reset(&rr)
        }
        other => {
            let _ = writeln!(
                std::io::stderr(),
                "usage: codex_lane <check|status|reset|breaker|scan|review|redesign-reset|research-reset> (invalid choice: '{}')",
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

        // SAFETY: A probe started before a newer outage clamps only older windows and never closes the newer outage or resurrects an already-closed breaker.
        wipe_breaker_for_test();
        let base_now = now_sec();
        trip_breaker_at("older_outage", 900, base_now - 100.0);
        trip_breaker_at("newer_quota", 600, base_now - 20.0);
        reset_breaker_for_probe(base_now - 50.0, base_now - 30.0);
        let st_concurrent = breaker_status();
        assert_eq!(st_concurrent["tripped"], Value::Bool(true));
        assert_eq!(st_concurrent["reason"], Value::String("newer_quota".to_string()));
        assert!(
            (val_to_f64(st_concurrent.get("tripped_until")) - (base_now + 580.0)).abs() < 1e-6,
            "expected tripped_until to drop to newer window end, got: {:?}",
            st_concurrent.get("tripped_until")
        );
        let hist_concurrent = breaker_history_slice(&st_concurrent);
        assert_eq!(hist_concurrent.len(), 2);
        assert!(
            (val_to_f64(hist_concurrent[0].get("until_ts")) - (base_now - 30.0)).abs() < 1e-6
        );
        assert!(
            (val_to_f64(hist_concurrent[1].get("until_ts")) - (base_now + 580.0)).abs() < 1e-6
        );

        reset_breaker_at(base_now - 10.0);
        assert_eq!(breaker_status()["tripped"], Value::Bool(false));
        reset_breaker_for_probe(base_now - 50.0, base_now - 5.0);
        assert_eq!(breaker_status()["tripped"], Value::Bool(false));

        // SAFETY: Concurrent multi-threaded `trip_breaker_at` + `reset_breaker_for_probe` serialized via `codex_lane.lock` loses zero outage windows.
        wipe_breaker_for_test();
        std::thread::scope(|s| {
            for i in 0..8 {
                s.spawn(move || {
                    let t_at = base_now - 200.0 + (i as f64) * 10.0;
                    trip_breaker_at(&format!("parallel_{}", i), 600, t_at);
                    if i % 2 == 1 {
                        reset_breaker_for_probe(t_at - 5.0, t_at - 1.0);
                    }
                });
            }
        });
        let st_parallel = breaker_status();
        assert_eq!(breaker_history_slice(&st_parallel).len(), 8);
        wipe_breaker_for_test();
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
                "payload": {"model": "gpt-6.2-astra", "effort": "xhigh"}
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

        // SAFETY: When >40 rollouts exist and an older rollout carries a stale READY for the same `review_id`, scanning the 40 newest rollouts first selects the latest `BLOCKED` verdict rather than stopping early on the 40 oldest files.
        let rid_reuse = "cwg-reuse45newest";
        record_packet(
            rid_reuse,
            &format!("REVIEW_ID: {}\nClosure check", rid_reuse),
            &repo_str,
            "high",
            "closure",
            "sess-cli-01",
        );
        let stale_rf = sessions_dir.join("rollout-0000-stale.jsonl");
        let stale_lines = [
            json!({"type": "session_meta", "timestamp": "2026-11-17T10:01:00Z", "payload": {"id": "sess-old-ready", "session_id": "sess-old-ready", "source": "exec", "thread_source": "user"}}),
            json!({"type": "turn_context", "timestamp": "2026-11-17T10:01:01Z", "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": "2026-11-17T10:01:02Z", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": format!("REVIEW_ID: {}", rid_reuse)}]}}),
            json!({"type": "event_msg", "timestamp": "2026-11-17T10:01:05Z", "payload": {"type": "task_complete", "last_agent_message": "CLOSURE_VALIDATION: READY"}}),
        ];
        fs::write(
            &stale_rf,
            stale_lines.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        for idx in 0..42 {
            let noise_sid = format!("sess-noise-{:02}", idx);
            let noise_rf = sessions_dir.join(format!("rollout-01{:02}-{}.jsonl", idx, noise_sid));
            let noise_lines = [
                json!({"type": "session_meta", "timestamp": "2026-11-17T10:02:00Z", "payload": {"id": noise_sid, "session_id": noise_sid, "source": "exec", "thread_source": "user"}}),
                json!({"type": "event_msg", "timestamp": "2026-11-17T10:02:01Z", "payload": {"type": "task_complete", "last_agent_message": "CLOSURE_VALIDATION: READY"}}),
            ];
            fs::write(
                &noise_rf,
                noise_lines.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
            )
            .unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
        let fresh_rf = sessions_dir.join("rollout-9999-fresh-blocked.jsonl");
        let fresh_lines = [
            json!({"type": "session_meta", "timestamp": "2026-11-17T10:05:00Z", "payload": {"id": "sess-fresh-blk", "session_id": "sess-fresh-blk", "source": "exec", "thread_source": "user"}}),
            json!({"type": "turn_context", "timestamp": "2026-11-17T10:05:01Z", "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": "2026-11-17T10:05:02Z", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": format!("REVIEW_ID: {}", rid_reuse)}]}}),
            json!({"type": "event_msg", "timestamp": "2026-11-17T10:05:10Z", "payload": {"type": "task_complete", "last_agent_message": "CLOSURE_VALIDATION: BLOCKED"}}),
        ];
        fs::write(
            &fresh_rf,
            fresh_lines.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();

        let scanned_45 = scan_verified_codex_reviews(now - 60.0, "sess-cli-01", &repo_str);
        let reuse_hit = scanned_45
            .iter()
            .find(|r| r.get("review_id").and_then(|v| v.as_str()) == Some(rid_reuse))
            .expect("expected rid_reuse verdict");
        assert_eq!(reuse_hit["verdict"], "BLOCKED");
        assert_eq!(reuse_hit["session_id"], "sess-fresh-blk");
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
if "FORCE_VERDICTLESS_MOCK" in prompt:
    print("Completed inspection without standalone verdict")
    sys.exit(0)
if "FORCE_WRONG_PHASE_CLOSURE" in prompt:
    print("CLOSURE_VALIDATION: BLOCKED")
    sys.exit(0)
m = re.search(r"REVIEW_ID:\s*([A-Za-z0-9_-]+)", prompt)
rid = m.group(1) if m else "cwg-unknown0"
sid = "sess-live-" + uuid.uuid4().hex[:8]
iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
verdict_line = "VERDICT: APPROVED" if "FORCE_ORDINARY_APPROVED_MOCK" in prompt else "CLOSURE_VALIDATION: READY"
rows = [
    {"type": "session_meta", "timestamp": iso, "payload": {"id": sid, "session_id": sid, "source": "exec", "thread_source": "user"}},
    {"type": "turn_context", "timestamp": iso, "payload": {"model": "gpt-6.2-sol", "effort": "high"}},
    {"type": "response_item", "timestamp": iso, "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": prompt}]}},
    {"type": "event_msg", "timestamp": iso, "payload": {"type": "task_complete", "last_agent_message": verdict_line}},
]
(sess_root / f"rollout-primary-{sid}.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
print(verdict_line)
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
case "$prompt" in
  *FORCE_VERDICTLESS_MOCK*)
    echo "Completed inspection without standalone verdict"
    exit 0
    ;;
  *FORCE_WRONG_PHASE_CLOSURE*)
    echo "CLOSURE_VALIDATION: BLOCKED"
    exit 0
    ;;
  *FORCE_ORDINARY_APPROVED_MOCK*)
    echo "VERDICT: APPROVED"
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
                repo_str.clone(),
            ]),
            0
        );
        assert!(log_lines.iter().all(|l| l.contains("-m gpt-6.2-sol")));

        // SAFETY: Verdict-less `rc == 0` runs fail closed (`rc == 2`) without committing packets, duplicate `--review-id` is rejected without clobbering prior packets, and `scan_verified_codex_reviews` rejects stale rollouts by `packet_nonce` and `mtime`.
        let rc_vless = run_cli(&[
            "review".to_string(),
            "--cwd".to_string(),
            repo_str.clone(),
            "--session".to_string(),
            "cli-mock-sess-vless".to_string(),
            "--review-id".to_string(),
            "cwg-verdictless01".to_string(),
            "--new-session".to_string(),
            "--diff-file".to_string(),
            diff_p.to_string_lossy().into_owned(),
            "--closure".to_string(),
            "--summary".to_string(),
            "FORCE_VERDICTLESS_MOCK".to_string(),
        ]);
        assert_eq!(rc_vless, 2);
        assert!(!has_recorded_packet("cwg-verdictless01"));

        let dup_sess = "cli-mock-sess-dup";
        let rc_dup_ok = run_cli(&[
            "review".to_string(),
            "--cwd".to_string(),
            repo_str.clone(),
            "--session".to_string(),
            dup_sess.to_string(),
            "--review-id".to_string(),
            "cwg-dupcheck01".to_string(),
            "--new-session".to_string(),
            "--diff-file".to_string(),
            diff_p.to_string_lossy().into_owned(),
            "--closure".to_string(),
            "--summary".to_string(),
            "Valid explicit review_id".to_string(),
        ]);
        assert_eq!(rc_dup_ok, 0);
        let orig_pkt = rio::read_json(&packet_path("cwg-dupcheck01")).unwrap();
        let rc_dup_re = run_cli(&[
            "review".to_string(),
            "--cwd".to_string(),
            repo_str.clone(),
            "--session".to_string(),
            dup_sess.to_string(),
            "--review-id".to_string(),
            "cwg-dupcheck01".to_string(),
            "--new-session".to_string(),
            "--diff-file".to_string(),
            diff_p.to_string_lossy().into_owned(),
            "--closure".to_string(),
            "--summary".to_string(),
            "FORCE_VERDICTLESS_MOCK".to_string(),
        ]);
        assert_eq!(rc_dup_re, 2);
        assert_eq!(rio::read_json(&packet_path("cwg-dupcheck01")).unwrap(), orig_pkt);

        let stale_nonce_rf = sessions_dir.join("rollout-stale-nonce.jsonl");
        let stale_nonce_rows = [
            json!({"type": "session_meta", "timestamp": "2026-11-18T10:00:00Z", "payload": {"id": "sess-stale-nc", "session_id": "sess-stale-nc", "source": "exec", "thread_source": "user"}}),
            json!({"type": "turn_context", "timestamp": "2026-11-18T10:00:01Z", "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": "2026-11-18T10:00:02Z", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-nonce-mismatch01\nPACKET_NONCE: 111111111111"}]}}),
            json!({"type": "event_msg", "timestamp": "2026-11-18T10:00:03Z", "payload": {"type": "task_complete", "last_agent_message": "CLOSURE_VALIDATION: READY"}}),
        ];
        fs::write(
            &stale_nonce_rf,
            stale_nonce_rows.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        record_packet(
            "cwg-nonce-mismatch01",
            "REVIEW_ID: cwg-nonce-mismatch01\nPACKET_NONCE: 222222222222",
            &repo_str,
            "high",
            "closure",
            cli_sess,
        );
        let stale_mt_rf = sessions_dir.join("rollout-stale-mtime.jsonl");
        let stale_mt_rows = [
            json!({"type": "session_meta", "timestamp": "2026-11-18T10:00:00Z", "payload": {"id": "sess-stale-mt", "session_id": "sess-stale-mt", "source": "exec", "thread_source": "user"}}),
            json!({"type": "turn_context", "timestamp": "2026-11-18T10:00:01Z", "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": "2026-11-18T10:00:02Z", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-mtime-guard01"}]}}),
            json!({"type": "event_msg", "timestamp": "2026-11-18T10:00:03Z", "payload": {"type": "task_complete", "last_agent_message": "CLOSURE_VALIDATION: READY"}}),
        ];
        fs::write(
            &stale_mt_rf,
            stale_mt_rows.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        let old_ft = fs::FileTimes::new()
            .set_modified(SystemTime::now() - std::time::Duration::from_secs(30));
        fs::File::options()
            .write(true)
            .open(&stale_mt_rf)
            .unwrap()
            .set_times(old_ft)
            .unwrap();
        record_packet(
            "cwg-mtime-guard01",
            "REVIEW_ID: cwg-mtime-guard01",
            &repo_str,
            "high",
            "closure",
            cli_sess,
        );
        let scanned_guards = scan_verified_codex_reviews(now_sec() - 60.0, cli_sess, &repo_str);
        assert!(scanned_guards.iter().all(|r| r["review_id"] != "cwg-nonce-mismatch01"));
        assert!(scanned_guards.iter().all(|r| r["review_id"] != "cwg-mtime-guard01"));

        // SAFETY: Reject cross-phase verdicts (`CLOSURE_VALIDATION` in an ordinary review) in both CLI execution and rollout scanning.
        let rc_wrong_phase = run_cli(&[
            "review".to_string(),
            "--cwd".to_string(),
            repo_str.clone(),
            "--session".to_string(),
            cli_sess.to_string(),
            "--review-id".to_string(),
            "cwg-wrongphase01".to_string(),
            "--new-session".to_string(),
            "--diff-file".to_string(),
            diff_p.to_string_lossy().into_owned(),
            "--summary".to_string(),
            "FORCE_WRONG_PHASE_CLOSURE".to_string(),
        ]);
        assert_eq!(rc_wrong_phase, 2);
        assert!(!has_recorded_packet("cwg-wrongphase01"));

        let wrong_phase_rf = sessions_dir.join("rollout-wrong-phase.jsonl");
        let wrong_phase_rows = [
            json!({"type": "session_meta", "timestamp": "2026-11-18T10:05:00Z", "payload": {"id": "sess-wrong-ph", "session_id": "sess-wrong-ph", "source": "exec", "thread_source": "user"}}),
            json!({"type": "turn_context", "timestamp": "2026-11-18T10:05:01Z", "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": "2026-11-18T10:05:02Z", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-ord-spoof-cls01"}]}}),
            json!({"type": "event_msg", "timestamp": "2026-11-18T10:05:03Z", "payload": {"type": "task_complete", "last_agent_message": "CLOSURE_VALIDATION: BLOCKED"}}),
        ];
        record_packet(
            "cwg-ord-spoof-cls01",
            "REVIEW_ID: cwg-ord-spoof-cls01",
            &repo_str,
            "high",
            "ordinary",
            cli_sess,
        );
        fs::write(
            &wrong_phase_rf,
            wrong_phase_rows.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        let scanned_phase = scan_verified_codex_reviews(now_sec() - 60.0, cli_sess, &repo_str);
        assert!(scanned_phase.iter().all(|r| r["review_id"] != "cwg-ord-spoof-cls01"));

        // SAFETY: Parallel `reserve_packet_exclusive` + `record_packet_if_absent` calls on the same `review_id` admit strictly 1 creator and never overwrite or delete the winner's packet.
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let mut handles = Vec::new();
        for tidx in 0..8usize {
            let b = std::sync::Arc::clone(&barrier);
            let rdir = repo_str.clone();
            handles.push(std::thread::spawn(move || {
                let nonce = format!("{:012x}", tidx + 1);
                let pr = format!("REVIEW_ID: cwg-race-dup01\nPACKET_NONCE: {}", nonce);
                b.wait();
                if tidx < 4 {
                    match reserve_packet_exclusive(
                        "cwg-race-dup01",
                        &pr,
                        &rdir,
                        "high",
                        "closure",
                        "cli-mock-sess-01",
                    ) {
                        Ok(_) => {
                            let mut g = PacketCleanupGuard {
                                review_id: "cwg-race-dup01".to_string(),
                                owner_nonce: nonce.clone(),
                                committed: false,
                            };
                            assert!(!commit_packet_owned("cwg-race-dup01", "ffffffffffff"));
                            assert!(commit_packet_owned("cwg-race-dup01", &nonce));
                            g.committed = true;
                            true
                        }
                        Err(PacketReserveError::Duplicate) => {
                            let _loser_guard = PacketCleanupGuard {
                                review_id: "cwg-race-dup01".to_string(),
                                owner_nonce: nonce,
                                committed: false,
                            };
                            false
                        }
                        Err(PacketReserveError::Io(e)) => panic!("unexpected io err: {}", e),
                    }
                } else {
                    record_packet_if_absent(
                        "cwg-race-dup01",
                        &pr,
                        &rdir,
                        "high",
                        "ordinary",
                        "cli-mock-sess-01",
                    )
                }
            }));
        }
        let wins: usize = handles.into_iter().map(|h| usize::from(h.join().unwrap())).sum();
        assert_eq!(wins, 1);
        assert!(has_recorded_packet("cwg-race-dup01"));
        assert!(!record_packet_if_absent(
            "cwg-race-dup01",
            "REVIEW_ID: cwg-race-dup01\nPACKET_NONCE: 999999999999",
            &repo_str,
            "high",
            "ordinary",
            "cli-mock-sess-01",
        ));
        assert_eq!(
            rio::read_json(&packet_path("cwg-race-dup01"))
                .unwrap()
                .get("committed")
                .and_then(|v| v.as_bool()),
            Some(true)
        );

        let fl1 = match try_acquire_review_flight_lock(cli_sess, &repo_str) {
            FlightLockResult::Acquired(f) => f,
            _ => panic!("expected first flight lock to succeed"),
        };
        assert!(matches!(
            try_acquire_review_flight_lock(cli_sess, &repo_str),
            FlightLockResult::Busy
        ));
        drop(fl1);
        assert!(matches!(
            try_acquire_review_flight_lock(cli_sess, &repo_str),
            FlightLockResult::Acquired(_)
        ));

        // SAFETY: Valid `APPROVED -> simplify #1 -> BLOCKED -> simplify #2 -> READY` yields `effective_pass_count == 2, has_fresh_ready == true`, while pre-simplify `BLOCKED` and declared-`XHIGH` wrong-tier `READY` both yield `has_fresh_ready == false` and unlock `research-reset` cleanly.
        let brain_dir = tmp.0.join("brain");
        let _benv = EnvVarGuard::set(&[("ANTIGRAVITY_BRAIN_ROOT", Some(&brain_dir.to_string_lossy()))]);
        let sess_cap = "sess-cls-cap-2";
        let sw_dir = brain_dir.join(sess_cap).join(".system_generated").join("swarm");
        fs::create_dir_all(&sw_dir).unwrap();
        let sim_members = json!({
            "members": {
                "sim-r": {"model": "claude-sonnet-5-5-high", "state": "killed", "killed": true},
                "sim-q": {"model": "claude-sonnet-5-5-high", "state": "killed", "killed": true},
                "sim-e": {"model": "claude-sonnet-5-5-high", "state": "killed", "killed": true}
            }
        });
        rio::write_json(&sw_dir.join("members.json"), &sim_members).unwrap();
        let base_t = now_sec() - 30.0;
        let t_sim1 = crate::win32_sqlite::format_iso_utc(base_t + 2.5);
        let t_sim2 = crate::win32_sqlite::format_iso_utc(base_t + 8.0);
        let two_sim_board_rows = [
            json!({"seq": 1, "agent": "coordinator", "time": t_sim1, "text": "@sim-r @sim-q @sim-e initial simplify"}),
            json!({"seq": 2, "agent": "sim-r", "time": t_sim1, "text": "SIMPLIFY_LENS: REUSE\nSIMPLIFY_VERDICT: CLEAN"}),
            json!({"seq": 3, "agent": "sim-q", "time": t_sim1, "text": "SIMPLIFY_LENS: QUALITY\nSIMPLIFY_VERDICT: CLEAN"}),
            json!({"seq": 4, "agent": "sim-e", "time": t_sim1, "text": "SIMPLIFY_LENS: EFFICIENCY\nSIMPLIFY_VERDICT: CLEAN"}),
            json!({"seq": 5, "agent": "coordinator", "time": t_sim2, "text": "@sim-r @sim-q @sim-e post-blocked simplify"}),
            json!({"seq": 6, "agent": "sim-r", "time": t_sim2, "text": "SIMPLIFY_LENS: REUSE\nSIMPLIFY_VERDICT: CLEAN"}),
            json!({"seq": 7, "agent": "sim-q", "time": t_sim2, "text": "SIMPLIFY_LENS: QUALITY\nSIMPLIFY_VERDICT: CLEAN"}),
            json!({"seq": 8, "agent": "sim-e", "time": t_sim2, "text": "SIMPLIFY_LENS: EFFICIENCY\nSIMPLIFY_VERDICT: CLEAN"}),
        ];
        fs::write(
            sw_dir.join("board.jsonl"),
            two_sim_board_rows.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        let cap_auth = repo_dir.join("auth.rs");
        fs::write(&cap_auth, "pub fn check() {}\n").unwrap();
        let cap_auth_norm = rio::normalize_path(&cap_auth.to_string_lossy());
        let cap_fp = cwg_common::content_fingerprint(
            std::slice::from_ref(&cap_auth_norm),
            cwg_common::MAX_FINGERPRINT_FILE_BYTES,
        );
        rio::write_json(
            &cwg_common::marker_path(sess_cap),
            &json!({
                "session": sess_cap,
                "first_ts": base_t,
                "cwd": rio::normalize_path(&repo_str),
                "git_root": rio::normalize_path(&repo_str),
                "paths": [cap_auth_norm],
                "content_marks": [{"ts": base_t, "fp": cap_fp, "unknown": false}],
                "closed": false,
            }),
        )
        .unwrap();
        for (rid_c, ph_c, cts_c) in [
            ("cwg-cap-o0", "ordinary", base_t + 1.0),
            ("cwg-cap-b1", "closure", base_t + 4.0),
            ("cwg-cap-r2", "closure", base_t + 10.0),
        ] {
            record_packet(rid_c, &format!("REVIEW_ID: {}", rid_c), &repo_str, "high", ph_c, sess_cap);
            let p_c = packet_path(rid_c);
            let mut doc_c = rio::read_json(&p_c).unwrap();
            doc_c["created_ts"] = json!(cts_c);
            rio::write_json(&p_c, &doc_c).unwrap();
        }
        let cap_rf = sessions_dir.join("rollout-cap-2passes.jsonl");
        let cap_rows = [
            json!({"type": "session_meta", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 1.0), "payload": {"id": "sess-cap-2p", "session_id": "sess-cap-2p", "source": "exec", "thread_source": "user"}}),
            json!({"type": "turn_context", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 1.1), "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 1.2), "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-cap-o0"}]}}),
            json!({"type": "event_msg", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 2.0), "payload": {"type": "task_complete", "last_agent_message": "VERDICT: APPROVED"}}),
            json!({"type": "turn_context", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 4.1), "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 4.2), "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-cap-b1"}]}}),
            json!({"type": "event_msg", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 5.0), "payload": {"type": "task_complete", "last_agent_message": "CLOSURE_VALIDATION: BLOCKED"}}),
            json!({"type": "turn_context", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 10.1), "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 10.2), "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-cap-r2"}]}}),
            json!({"type": "event_msg", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 11.0), "payload": {"type": "task_complete", "last_agent_message": "CLOSURE_VALIDATION: READY"}}),
        ];
        fs::write(
            &cap_rf,
            cap_rows.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        let sum_cap = active_cycle_closure_summary(sess_cap, &repo_str, "");
        assert_eq!(sum_cap.blocked_count, 1);
        assert_eq!(sum_cap.effective_pass_count, 2);
        assert!(sum_cap.has_fresh_ready);
        let rc_3rd_cls = run_cli(&[
            "review".to_string(),
            "--cwd".to_string(),
            repo_str.clone(),
            "--session".to_string(),
            sess_cap.to_string(),
            "--closure".to_string(),
            "--diff-file".to_string(),
            diff_p.to_string_lossy().into_owned(),
            "--summary".to_string(),
            "Redundant 3rd closure attempt".to_string(),
        ]);
        assert_eq!(rc_3rd_cls, 2);
        let (sg_3rd_dec, _) = crate::safety_guards::guard_shell_command_with_session(
            &format!("carbon-stack codex-lane review --closure --cwd '{}' --session {}", repo_str, sess_cap),
            &repo_str,
            sess_cap,
        );
        assert_eq!(sg_3rd_dec, "deny");

        // SAFETY: Sub-case A (`APPROVED -> pre-simplify BLOCKED -> simplify -> READY`) has `has_fresh_ready == false` (matching `Stop`) and is accepted by `research-reset`.
        let sess_early_blk = "sess-early-blk-nosim";
        let sw_early = brain_dir.join(sess_early_blk).join(".system_generated").join("swarm");
        fs::create_dir_all(&sw_early).unwrap();
        rio::write_json(&sw_early.join("members.json"), &sim_members).unwrap();
        let one_sim_board_rows = [
            json!({"seq": 1, "agent": "coordinator", "time": t_sim2, "text": "@sim-r @sim-q @sim-e audit only after blocked pass 1"}),
            json!({"seq": 2, "agent": "sim-r", "time": t_sim2, "text": "SIMPLIFY_LENS: REUSE\nSIMPLIFY_VERDICT: CLEAN"}),
            json!({"seq": 3, "agent": "sim-q", "time": t_sim2, "text": "SIMPLIFY_LENS: QUALITY\nSIMPLIFY_VERDICT: CLEAN"}),
            json!({"seq": 4, "agent": "sim-e", "time": t_sim2, "text": "SIMPLIFY_LENS: EFFICIENCY\nSIMPLIFY_VERDICT: CLEAN"}),
        ];
        fs::write(
            sw_early.join("board.jsonl"),
            one_sim_board_rows.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        rio::write_json(
            &cwg_common::marker_path(sess_early_blk),
            &json!({
                "session": sess_early_blk,
                "first_ts": base_t,
                "cwd": rio::normalize_path(&repo_str),
                "git_root": rio::normalize_path(&repo_str),
                "paths": [cap_auth_norm],
                "content_marks": [{"ts": base_t, "fp": cap_fp, "unknown": false}],
                "closed": false,
            }),
        )
        .unwrap();
        for (rid_e, ph_e, cts_e) in [
            ("cwg-eb-o0", "ordinary", base_t + 1.0),
            ("cwg-eb-b1", "closure", base_t + 3.0),
            ("cwg-eb-r2", "closure", base_t + 10.0),
        ] {
            record_packet(rid_e, &format!("REVIEW_ID: {}", rid_e), &repo_str, "high", ph_e, sess_early_blk);
            let p_e = packet_path(rid_e);
            let mut doc_e = rio::read_json(&p_e).unwrap();
            doc_e["created_ts"] = json!(cts_e);
            rio::write_json(&p_e, &doc_e).unwrap();
        }
        let eb_rf = sessions_dir.join("rollout-eb-2passes.jsonl");
        let eb_rows = [
            json!({"type": "session_meta", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 1.0), "payload": {"id": "sess-eb-2p", "session_id": "sess-eb-2p", "source": "exec", "thread_source": "user"}}),
            json!({"type": "turn_context", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 1.1), "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 1.2), "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-eb-o0"}]}}),
            json!({"type": "event_msg", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 2.0), "payload": {"type": "task_complete", "last_agent_message": "VERDICT: ESCALATE"}}),
            json!({"type": "turn_context", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 3.1), "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 3.2), "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-eb-b1"}]}}),
            json!({"type": "event_msg", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 4.0), "payload": {"type": "task_complete", "last_agent_message": "CLOSURE_VALIDATION: BLOCKED"}}),
            json!({"type": "turn_context", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 10.1), "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 10.2), "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-eb-r2"}]}}),
            json!({"type": "event_msg", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 11.0), "payload": {"type": "task_complete", "last_agent_message": "CLOSURE_VALIDATION: READY"}}),
        ];
        fs::write(
            &eb_rf,
            eb_rows.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        let sum_eb = active_cycle_closure_summary(sess_early_blk, &repo_str, "");
        assert_eq!(sum_eb.blocked_count, 1);
        assert_eq!(sum_eb.effective_pass_count, 2);
        assert!(!sum_eb.has_fresh_ready);
        // SAFETY: Editing a durable file after the rejected `READY` must NOT trigger automatic cycle turnover or clear the 2/2 closure counter without `research-reset`.
        fs::write(&cap_auth, "pub fn check() -> bool { false }\n").unwrap();
        let cap_fp_edited = cwg_common::content_fingerprint(
            std::slice::from_ref(&cap_auth_norm),
            cwg_common::MAX_FINGERPRINT_FILE_BYTES,
        );
        rio::write_json(
            &cwg_common::marker_path(sess_early_blk),
            &json!({
                "session": sess_early_blk,
                "first_ts": base_t,
                "last_durable_ts": base_t + 12.0,
                "cwd": rio::normalize_path(&repo_str),
                "git_root": rio::normalize_path(&repo_str),
                "paths": [cap_auth_norm],
                "content_marks": [
                    {"ts": base_t, "fp": cap_fp, "unknown": false},
                    {"ts": base_t + 12.0, "fp": cap_fp_edited, "unknown": false}
                ],
                "closed": false,
            }),
        )
        .unwrap();
        let sum_eb_post_edit = active_cycle_closure_summary(sess_early_blk, &repo_str, "");
        assert_eq!(sum_eb_post_edit.blocked_count, 1);
        assert_eq!(sum_eb_post_edit.effective_pass_count, 2);
        assert!(!sum_eb_post_edit.has_fresh_ready);
        assert_eq!(
            run_cli(&[
                "review".to_string(),
                "--cwd".to_string(),
                repo_str.clone(),
                "--session".to_string(),
                sess_early_blk.to_string(),
                "--closure".to_string(),
                "--diff-file".to_string(),
                diff_p.to_string_lossy().into_owned(),
                "--summary".to_string(),
                "3rd closure after post-rejected-READY edit must stay blocked".to_string(),
            ]),
            2
        );
        fs::write(&cap_auth, "pub fn check() {}\n").unwrap();
        let tp_eb = tmp.0.join("transcript-eb.jsonl");
        let eb_res_steps = [
            json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": crate::win32_sqlite::format_iso_utc(base_t + 15.0), "tool_calls": [{"name": "search_web", "args": {"query": "sandwich gate order"}}]}),
            json!({"step_index": 2, "source": "SYSTEM", "type": "GENERIC", "status": "DONE", "created_at": crate::win32_sqlite::format_iso_utc(base_t + 16.0), "content": "ok"}),
        ];
        fs::write(
            &tp_eb,
            eb_res_steps.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        assert_eq!(
            run_cli(&[
                "research-reset".to_string(),
                "--cwd".to_string(),
                repo_str.clone(),
                "--session".to_string(),
                sess_early_blk.to_string(),
                "--decision".to_string(),
                "refine".to_string(),
                "--findings".to_string(),
                "Resetting cycle after premature pre-simplify BLOCKED pass.".to_string(),
                "--transcript".to_string(),
                tp_eb.to_string_lossy().into_owned(),
            ]),
            2
        );

        // SAFETY: Sub-case B (`HIGH` path floor escalated via `--xhigh` or `XHIGH -> HIGH` receipt transition in same cycle after Sol `READY`) blocks `Stop` (`verified: HIGH` & `pr-ready: HIGH`), keeps `has_fresh_ready == false`, and unlocks `research-reset`.
        let sess_decl_xh = "sess-decl-xhigh-on-high";
        let sw_dxh = brain_dir.join(sess_decl_xh).join(".system_generated").join("swarm");
        let log_dxh = brain_dir.join(sess_decl_xh).join(".system_generated").join("logs");
        fs::create_dir_all(&sw_dxh).unwrap();
        fs::create_dir_all(&log_dxh).unwrap();
        rio::write_json(&sw_dxh.join("members.json"), &sim_members).unwrap();
        fs::write(
            sw_dxh.join("board.jsonl"),
            two_sim_board_rows.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        rio::write_json(
            &cwg_common::marker_path(sess_decl_xh),
            &json!({
                "session": sess_decl_xh,
                "first_ts": base_t,
                "last_durable_ts": base_t,
                "cwd": rio::normalize_path(&repo_str),
                "git_root": rio::normalize_path(&repo_str),
                "paths": [cap_auth_norm],
                "content_marks": [{"ts": base_t, "fp": cap_fp, "unknown": false}],
                "closed": false,
            }),
        )
        .unwrap();
        let chk_dxh = cwg_common::checks_ledger_path(sess_decl_xh);
        if let Some(parent) = chk_dxh.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(
            &chk_dxh,
            json!({"kind": "check", "passed": true, "ts": base_t + 6.0, "start_ts": base_t + 6.0}).to_string() + "\n",
        )
        .unwrap();
        for (rid_d, eff_d, ph_d, cts_d) in [
            ("cwg-dxh-o0", "xhigh", "ordinary", base_t + 1.0),
            ("cwg-dxh-b1", "xhigh", "closure", base_t + 4.0),
            ("cwg-dxh-r2", "high", "closure", base_t + 10.0),
        ] {
            record_packet(rid_d, &format!("REVIEW_ID: {}", rid_d), &repo_str, eff_d, ph_d, sess_decl_xh);
            let p_d = packet_path(rid_d);
            let mut doc_d = rio::read_json(&p_d).unwrap();
            doc_d["created_ts"] = json!(cts_d);
            rio::write_json(&p_d, &doc_d).unwrap();
        }
        let dxh_rf = sessions_dir.join("rollout-dxh-wrongtier.jsonl");
        let dxh_rows = [
            json!({"type": "session_meta", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 1.0), "payload": {"id": "sess-dxh-wt", "session_id": "sess-dxh-wt", "source": "exec", "thread_source": "user"}}),
            json!({"type": "turn_context", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 1.1), "payload": {"model": "gpt-6.2-astra", "effort": "xhigh"}}),
            json!({"type": "response_item", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 1.2), "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-dxh-o0"}]}}),
            json!({"type": "event_msg", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 2.0), "payload": {"type": "task_complete", "last_agent_message": "VERDICT: APPROVED"}}),
            json!({"type": "turn_context", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 4.1), "payload": {"model": "gpt-6.2-astra", "effort": "xhigh"}}),
            json!({"type": "response_item", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 4.2), "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-dxh-b1"}]}}),
            json!({"type": "event_msg", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 5.0), "payload": {"type": "task_complete", "last_agent_message": "CLOSURE_VALIDATION: BLOCKED"}}),
            json!({"type": "turn_context", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 10.1), "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 10.2), "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-dxh-r2"}]}}),
            json!({"type": "event_msg", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 11.0), "payload": {"type": "task_complete", "last_agent_message": "CLOSURE_VALIDATION: READY"}}),
        ];
        fs::write(
            &dxh_rf,
            dxh_rows.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        let tp_dxh = log_dxh.join("transcript.jsonl");
        fs::write(&tp_dxh, "").unwrap();
        // SAFETY: First verify `--xhigh` latched inside `marker.json` (`cycle_declared_risk` at `reset_epoch == 0`) blocks `[gate] verified: HIGH` and `[gate] pr-ready: HIGH` in `decide_stop`.
        assert!(cwg_common::latch_marker_declared_risk(
            sess_decl_xh,
            None,
            None,
            "XHIGH",
        ));
        let stop_from_flag = crate::cwg_stop::decide_stop(&json!({
            "conversationId": sess_decl_xh,
            "cwd": repo_str,
            "transcriptPath": tp_dxh.to_string_lossy(),
            "lastAssistantMessage": "Done.\n[gate] verified: HIGH; downgrade attempt after --xhigh",
            "fullyIdle": true,
        }));
        assert!(
            stop_from_flag
                .as_deref()
                .is_some_and(|m| m.contains("below active cycle escalated risk")),
            "unexpected decide_stop result: {:?}",
            stop_from_flag
        );
        let stop_pr_from_flag = crate::cwg_stop::decide_stop(&json!({
            "conversationId": sess_decl_xh,
            "cwd": repo_str,
            "transcriptPath": tp_dxh.to_string_lossy(),
            "lastAssistantMessage": "Done.\n[gate] pr-ready: HIGH; downgrade attempt after --xhigh",
            "fullyIdle": true,
        }));
        assert!(stop_pr_from_flag.is_some());
        if let Some(mut m_clr) = rio::read_json(&cwg_common::marker_path(sess_decl_xh)) {
            if let Some(obj) = m_clr.as_object_mut() {
                obj.remove("cycle_declared_risk");
            }
            rio::write_json(&cwg_common::marker_path(sess_decl_xh), &m_clr).unwrap();
        }
        // SAFETY: Next verify `XHIGH -> HIGH` receipt transition in transcript also blocks `decide_stop` and preserves `XHIGH` monotonically inside `marker.json` + CLI.
        let dxh_steps = [
            json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": crate::win32_sqlite::format_iso_utc(base_t + 12.0), "content": "Done.\n[gate] verified: XHIGH; auth hardened"}),
            json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": crate::win32_sqlite::format_iso_utc(base_t + 13.0), "content": "Retrying lower.\n[gate] verified: HIGH; auth hardened"}),
            json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": crate::win32_sqlite::format_iso_utc(base_t + 15.0), "tool_calls": [{"name": "search_web", "args": {"query": "declared xhigh recovery"}}]}),
            json!({"step_index": 4, "source": "SYSTEM", "type": "GENERIC", "status": "DONE", "created_at": crate::win32_sqlite::format_iso_utc(base_t + 16.0), "content": "ok"}),
        ];
        fs::write(
            &tp_dxh,
            dxh_steps.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        let stop_tx_downgrade = crate::cwg_stop::decide_stop(&json!({
            "conversationId": sess_decl_xh,
            "cwd": repo_str,
            "transcriptPath": tp_dxh.to_string_lossy(),
            "lastAssistantMessage": "Retrying lower.\n[gate] verified: HIGH; auth hardened",
            "fullyIdle": true,
        }));
        assert!(
            stop_tx_downgrade
                .as_deref()
                .is_some_and(|m| m.contains("below active cycle escalated risk")),
            "unexpected decide_stop result on XHIGH->HIGH receipt transition: {:?}",
            stop_tx_downgrade
        );
        let m_before_rr = rio::read_json(&cwg_common::marker_path(sess_decl_xh)).unwrap();
        assert_eq!(cwg_common::active_marker_declared_risk(&m_before_rr), "XHIGH");
        let sum_dxh = active_cycle_closure_summary(sess_decl_xh, &repo_str, "");
        assert_eq!(sum_dxh.blocked_count, 1);
        assert_eq!(sum_dxh.effective_pass_count, 2);
        assert!(!sum_dxh.has_fresh_ready);
        // SAFETY: While `review_flight_lock` is held, `research-reset` fails closed (`2`) without mutating `marker.json`; once released, `research-reset` and concurrent new-cycle `--xhigh` latching serialize cleanly on `marker_lock_path` + `reset_epoch`.
        {
            let fl_rr = match try_acquire_review_flight_lock(sess_decl_xh, &repo_str) {
                FlightLockResult::Acquired(fh) => fh,
                _ => panic!("expected flight lock to be free"),
            };
            assert_eq!(
                run_cli(&[
                    "research-reset".to_string(),
                    "--cwd".to_string(),
                    repo_str.clone(),
                    "--session".to_string(),
                    sess_decl_xh.to_string(),
                    "--decision".to_string(),
                    "refine".to_string(),
                    "--findings".to_string(),
                    "Must reject while review is in flight.".to_string(),
                    "--transcript".to_string(),
                    tp_dxh.to_string_lossy().into_owned(),
                ]),
                2
            );
            drop(fl_rr);
        }
        let bar_rr = std::sync::Arc::new(std::sync::Barrier::new(2));
        let repo_t = repo_str.clone();
        let tp_dxh_t = tp_dxh.to_string_lossy().into_owned();
        let bar_rr_c = std::sync::Arc::clone(&bar_rr);
        let rr_handle = std::thread::spawn(move || {
            bar_rr_c.wait();
            run_cli(&[
                "research-reset".to_string(),
                "--cwd".to_string(),
                repo_t,
                "--session".to_string(),
                sess_decl_xh.to_string(),
                "--decision".to_string(),
                "refine".to_string(),
                "--findings".to_string(),
                "Resetting cycle after declared XHIGH receipt rejected Sol READY.".to_string(),
                "--transcript".to_string(),
                tp_dxh_t,
            ])
        });
        bar_rr.wait();
        let rc_rr_done = rr_handle.join().unwrap();
        assert_eq!(rc_rr_done, 2);
        let mut m_after_rr = rio::read_json(&cwg_common::marker_path(sess_decl_xh)).unwrap();
        assert_eq!(cwg_common::research_reset_epoch(&m_after_rr), 0);
        assert_eq!(cwg_common::active_marker_declared_risk(&m_after_rr), "XHIGH");
        m_after_rr["research_resets"] = json!([{
            "decision": "refine",
            "findings": "Legacy pre-migration reset fixture for epoch fencing test.",
            "last_blocked_ts": base_t + 5.0,
            "reset_ts": base_t + 16.5,
            "board_head_seq": 4,
            "research_tools": ["search_web"]
        }]);
        rio::write_json(&cwg_common::marker_path(sess_decl_xh), &m_after_rr).unwrap();
        assert_eq!(cwg_common::research_reset_epoch(&m_after_rr), 1);
        assert_eq!(cwg_common::active_marker_declared_risk(&m_after_rr), "");
        // INVARIANT: Stale epoch `0` latch cannot pollute epoch `1`, while new-cycle `--xhigh` (`None` epoch -> live epoch `1`) persists `XHIGH` on epoch `1` and blocks `[gate] verified: HIGH` in `Stop`.
        assert!(!cwg_common::latch_marker_declared_risk(
            sess_decl_xh,
            Some(base_t),
            Some(0),
            "XHIGH",
        ));
        assert!(cwg_common::latch_marker_declared_risk(
            sess_decl_xh,
            None,
            None,
            "XHIGH",
        ));
        let m_new_cycle_xh = rio::read_json(&cwg_common::marker_path(sess_decl_xh)).unwrap();
        assert_eq!(cwg_common::active_marker_declared_risk(&m_new_cycle_xh), "XHIGH");
        let stop_new_cycle_downgrade = crate::cwg_stop::decide_stop(&json!({
            "conversationId": sess_decl_xh,
            "cwd": repo_str,
            "transcriptPath": tp_dxh.to_string_lossy(),
            "lastAssistantMessage": "New cycle attempt.\n[gate] verified: HIGH; must stay XHIGH in new cycle",
            "fullyIdle": true,
        }));
        assert!(
            stop_new_cycle_downgrade
                .as_deref()
                .is_some_and(|m| m.contains("below active cycle escalated risk")),
            "expected new cycle XHIGH to block HIGH receipt: {:?}",
            stop_new_cycle_downgrade
        );

        // SAFETY: Invoking `review --xhigh` via CLI when `check_health()` returns `available: false` (e.g. open breaker) STILL latches `cycle_declared_risk == "XHIGH"` so an already-valid `HIGH` (`Sol`) `READY` on `sess_cap` cannot close as `HIGH`.
        rio::write_json(
            &breaker_path(),
            &json!({"until_ts": now_sec() + 600.0, "reason": "test_breaker_open"}),
        )
        .unwrap();
        let rc_xh_breaker = run_cli(&[
            "review".to_string(),
            "--xhigh".to_string(),
            "--cwd".to_string(),
            repo_str.clone(),
            "--session".to_string(),
            sess_cap.to_string(),
            "--diff-file".to_string(),
            diff_p.to_string_lossy().into_owned(),
            "--summary".to_string(),
            "XHIGH attempt while breaker open".to_string(),
        ]);
        let _ = fs::remove_file(breaker_path());
        assert_eq!(rc_xh_breaker, 2);
        let m_cap_xh = rio::read_json(&cwg_common::marker_path(sess_cap)).unwrap();
        assert_eq!(cwg_common::active_marker_declared_risk(&m_cap_xh), "XHIGH");
        let chk_cap = cwg_common::checks_ledger_path(sess_cap);
        if let Some(parent) = chk_cap.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(
            &chk_cap,
            json!({"kind": "check", "passed": true, "ts": base_t + 6.0, "start_ts": base_t + 6.0}).to_string() + "\n",
        )
        .unwrap();
        let tp_cap = tmp.0.join("tp-cap.jsonl");
        fs::write(&tp_cap, "").unwrap();
        let stop_cap_high = crate::cwg_stop::decide_stop(&json!({
            "conversationId": sess_cap,
            "cwd": repo_str,
            "transcriptPath": tp_cap.to_string_lossy(),
            "lastAssistantMessage": "Done.\n[gate] verified: HIGH; must be blocked after review --xhigh fallback",
            "fullyIdle": true,
        }));
        assert!(
            stop_cap_high
                .as_deref()
                .is_some_and(|m| m.contains("below active cycle escalated risk")),
            "expected breaker-fallback review --xhigh to block HIGH closure: {:?}",
            stop_cap_high
        );

        // SAFETY: Pre-launch ordinary review round cap rejects a 5th ordinary `codex-lane review` after `MAX_REVIEW_ROUNDS` (4) `REVISE` rounds (`rc == 2`, `max_ordinary_rounds_reached`).
        let sess_ord3 = "sess-ord-cap-4";
        rio::write_json(
            &cwg_common::marker_path(sess_ord3),
            &json!({
                "session": sess_ord3,
                "first_ts": base_t,
                "last_durable_ts": base_t,
                "cwd": rio::normalize_path(&repo_str),
                "git_root": rio::normalize_path(&repo_str),
                "paths": [cap_auth_norm],
                "content_marks": [{"ts": base_t, "fp": cap_fp, "unknown": false}],
                "closed": false,
            }),
        )
        .unwrap();
        for (idx_o, rid_o) in ["cwg-ord4-r1", "cwg-ord4-r2", "cwg-ord4-r3", "cwg-ord4-r4"].iter().enumerate() {
            record_packet(rid_o, &format!("REVIEW_ID: {}", rid_o), &repo_str, "high", "ordinary", sess_ord3);
            let p_o = packet_path(rid_o);
            let mut doc_o = rio::read_json(&p_o).unwrap();
            doc_o["created_ts"] = json!(base_t + 1.0 + (idx_o as f64) * 2.0);
            rio::write_json(&p_o, &doc_o).unwrap();
        }
        let ord3_rf = sessions_dir.join("rollout-ord4-cap.jsonl");
        let ord3_rows = [
            json!({"type": "session_meta", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 1.0), "payload": {"id": "sess-ord4-sid", "session_id": "sess-ord4-sid", "source": "exec", "thread_source": "user"}}),
            json!({"type": "turn_context", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 1.1), "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 1.2), "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-ord4-r1"}]}}),
            json!({"type": "event_msg", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 2.0), "payload": {"type": "task_complete", "last_agent_message": "VERDICT: REVISE"}}),
            json!({"type": "turn_context", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 3.1), "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 3.2), "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-ord4-r2"}]}}),
            json!({"type": "event_msg", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 4.0), "payload": {"type": "task_complete", "last_agent_message": "VERDICT: REVISE"}}),
            json!({"type": "turn_context", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 5.1), "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 5.2), "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-ord4-r3"}]}}),
            json!({"type": "event_msg", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 6.0), "payload": {"type": "task_complete", "last_agent_message": "VERDICT: REVISE"}}),
            json!({"type": "turn_context", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 7.1), "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 7.2), "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-ord4-r4"}]}}),
            json!({"type": "event_msg", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 8.0), "payload": {"type": "task_complete", "last_agent_message": "VERDICT: ESCALATE"}}),
        ];
        fs::write(
            &ord3_rf,
            ord3_rows.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        let inv_before_4th = fs::read_to_string(&inv_log).unwrap_or_default().lines().count();
        let rc_4th_ord = run_cli(&[
            "review".to_string(),
            "--cwd".to_string(),
            repo_str.clone(),
            "--session".to_string(),
            sess_ord3.to_string(),
            "--diff-file".to_string(),
            diff_p.to_string_lossy().into_owned(),
            "--summary".to_string(),
            "5th ordinary round must be rejected pre-launch".to_string(),
        ]);
        assert_eq!(rc_4th_ord, 2);
        let inv_after_4th = fs::read_to_string(&inv_log).unwrap_or_default().lines().count();
        assert_eq!(inv_after_4th, inv_before_4th);
        // INVARIANT: Completing `simplify` after `MAX_REVIEW_ROUNDS` (4) ordinary rounds MUST NOT un-count those 4 rounds: `cmd_review` still rejects a 5th ordinary round (`rc == 2`), and `validate_candidate_closure` rejects closing on an over-cap 5th ordinary `APPROVED`.
        let ord3_brain = rio::resolve_brain_root("");
        let ord3_tp = ord3_brain
            .join(sess_ord3)
            .join(".system_generated")
            .join("logs")
            .join("transcript.jsonl");
        let ord3_board = ord3_brain
            .join(sess_ord3)
            .join(".system_generated")
            .join("swarm")
            .join("board.jsonl");
        let ord3_members = ord3_brain
            .join(sess_ord3)
            .join(".system_generated")
            .join("swarm")
            .join("members.json");
        fs::create_dir_all(ord3_tp.parent().unwrap()).unwrap();
        fs::create_dir_all(ord3_board.parent().unwrap()).unwrap();
        fs::write(&ord3_tp, "").unwrap();
        fs::write(
            &ord3_members,
            json!([
                {"name": "simp-r", "model": cwg_common::SONNET_HIGH_MODEL, "state": "killed", "killed": true},
                {"name": "simp-q", "model": cwg_common::SONNET_HIGH_MODEL, "state": "killed", "killed": true},
                {"name": "simp-e", "model": cwg_common::SONNET_HIGH_MODEL, "state": "killed", "killed": true}
            ])
            .to_string(),
        )
        .unwrap();
        let sim_t_str = crate::win32_sqlite::format_iso_utc(base_t + 8.2);
        let sim_end_str = crate::win32_sqlite::format_iso_utc(base_t + 8.6);
        let ord3_board_lines = [
            json!({"seq": 1, "agent": "coordinator", "time": sim_t_str, "text": "@simp-r @simp-q @simp-e simplify"}),
            json!({"seq": 2, "agent": "simp-r", "time": sim_end_str, "text": format!("@coordinator\nDIFF_HASH: {}\nSIMPLIFY_LENS: REUSE\nSIMPLIFY_VERDICT: CLEAN", cap_fp)}),
            json!({"seq": 3, "agent": "simp-q", "time": sim_end_str, "text": format!("@coordinator\nDIFF_HASH: {}\nSIMPLIFY_LENS: QUALITY\nSIMPLIFY_VERDICT: CLEAN", cap_fp)}),
            json!({"seq": 4, "agent": "simp-e", "time": sim_end_str, "text": format!("@coordinator\nDIFF_HASH: {}\nSIMPLIFY_LENS: EFFICIENCY\nSIMPLIFY_VERDICT: CLEAN", cap_fp)}),
        ];
        fs::write(
            &ord3_board,
            ord3_board_lines.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        let mut m_ord3 = rio::read_json(&cwg_common::marker_path(sess_ord3)).unwrap();
        m_ord3["current_diff_hash"] = json!(cap_fp);
        rio::write_json(&cwg_common::marker_path(sess_ord3), &m_ord3).unwrap();
        assert_eq!(
            run_cli(&[
                "review".to_string(),
                "--cwd".to_string(),
                repo_str.clone(),
                "--session".to_string(),
                sess_ord3.to_string(),
                "--diff-file".to_string(),
                diff_p.to_string_lossy().into_owned(),
                "--summary".to_string(),
                "4th ordinary round AFTER simplify must STILL be rejected".to_string(),
            ]),
            2
        );
        assert_eq!(
            fs::read_to_string(&inv_log).unwrap_or_default().lines().count(),
            inv_before_4th
        );
        let ord3_tp_str = ord3_tp.to_string_lossy().into_owned();
        let sw_ord3 = crate::cwg_stop::scan_swarm_activity_with_reset(crate::cwg_stop::SwarmScanInput {
            steps: &[],
            transcript_path: Some(&ord3_tp_str),
            first_ts: base_t,
            round_start_msg_id: 0,
            current_diff_hash: &cap_fp,
            cwd: &repo_str,
            research_reset_ts: 0.0,
            research_reset_seq: 0,
            marker: Some(&m_ord3),
        });
        let mut revs_4th_app = scan_verified_codex_reviews(
            base_t,
            sess_ord3,
            &rio::normalize_path(&repo_str),
        );
        revs_4th_app.push(json!({
            "review_id": "cwg-ord3-r4-app",
            "engine": "codex",
            "kind": "ordinary",
            "verdict": "APPROVED",
            "launch_ts": base_t + 9.0,
            "verdict_ts": base_t + 9.5,
            "xhigh": false,
        }));
        let chk_ord3 = crate::cwg_stop::ChecksEvidence {
            checks_count: 1,
            passed_count: 1,
            failed_count: 0,
            latest_pass_ts: base_t + 0.5,
            latest_fail_ts: 0.0,
        };
        let sub_ord3 = crate::cwg_stop::SubagentEvidence::default();
        let rcp_high = cwg_common::parse_terminal_receipt("[gate] verified: HIGH; ok").unwrap();
        let (ok_4th_app, why_4th_app) = crate::cwg_stop::validate_candidate_closure(
            crate::cwg_stop::CandidateClosureInput {
                receipt: Some(&rcp_high),
                marker_in: &m_ord3,
                checks_ev: &chk_ord3,
                sub_ev: &sub_ord3,
                swarm_ev: &sw_ord3,
                codex_reviews: &revs_4th_app,
                ctx: None,
                steps: None,
                transcript_path: None,
            },
        );
        assert!(!ok_4th_app);
        assert!(
            why_4th_app.contains("exceeded MAX_REVIEW_ROUNDS"),
            "expected 4th ordinary APPROVED after simplify to fail round cap, got: {}",
            why_4th_app
        );

        // INVARIANT: Under the finite gate, premature `--closure` before Round 4 `ESCALATE` is rejected (`closure_requires_escalate`), `--closure` after Round 4 `ESCALATE` rejects unkilled `waiting` simplify workers (`active_swarm_workers_present`), and killing them unlocks `--closure`.
        let sess_sw_guard = "sess-finite-cli-guards";
        rio::write_json(
            &cwg_common::marker_path(sess_sw_guard),
            &json!({
                "session": sess_sw_guard,
                "first_ts": base_t,
                "last_durable_ts": base_t,
                "cwd": rio::normalize_path(&repo_str),
                "git_root": rio::normalize_path(&repo_str),
                "paths": [cap_auth_norm.clone()],
                "content_marks": [
                    {"ts": base_t, "fp": cap_fp.clone(), "unknown": false}
                ],
                "current_diff_hash": cap_fp.clone(),
                "closed": false,
            }),
        )
        .unwrap();
        let swg_dir = ord3_brain.join(sess_sw_guard).join(".system_generated").join("swarm");
        let swg_logs = ord3_brain.join(sess_sw_guard).join(".system_generated").join("logs");
        fs::create_dir_all(&swg_dir).unwrap();
        fs::create_dir_all(&swg_logs).unwrap();
        fs::write(swg_logs.join("transcript.jsonl"), "").unwrap();
        fs::write(
            swg_dir.join("members.json"),
            json!([
                {"name": "simp-r", "model": cwg_common::SONNET_HIGH_MODEL, "state": "killed", "killed": true},
                {"name": "simp-q", "model": cwg_common::SONNET_HIGH_MODEL, "state": "killed", "killed": true},
                {"name": "simp-e", "model": cwg_common::SONNET_HIGH_MODEL, "state": "killed", "killed": true}
            ])
            .to_string(),
        )
        .unwrap();
        fs::write(
            swg_dir.join("board.jsonl"),
            ord3_board_lines.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        let inv_before_swg = fs::read_to_string(&inv_log).unwrap_or_default().lines().count();
        assert_eq!(
            run_cli(&[
                "review".to_string(),
                "--closure".to_string(),
                "--cwd".to_string(),
                repo_str.clone(),
                "--session".to_string(),
                sess_sw_guard.to_string(),
                "--diff-file".to_string(),
                diff_p.to_string_lossy().into_owned(),
                "--summary".to_string(),
                "Premature --closure before Round 4 ESCALATE must fail".to_string(),
            ]),
            2
        );
        for (idx_g, rid_g) in ["cwg-swg-r1", "cwg-swg-r2", "cwg-swg-r3", "cwg-swg-r4"].iter().enumerate() {
            record_packet(rid_g, &format!("REVIEW_ID: {}", rid_g), &repo_str, "high", "ordinary", sess_sw_guard);
            let p_swg = packet_path(rid_g);
            let mut doc_swg = rio::read_json(&p_swg).unwrap();
            doc_swg["created_ts"] = json!(base_t + 1.0 + (idx_g as f64) * 1.5);
            rio::write_json(&p_swg, &doc_swg).unwrap();
        }
        let swg_rf = sessions_dir.join("rollout-swg-r4.jsonl");
        let swg_rows = [
            json!({"type": "session_meta", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 1.0), "payload": {"id": "sess-swg-sid", "session_id": "sess-swg-sid", "source": "exec", "thread_source": "user"}}),
            json!({"type": "turn_context", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 1.1), "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 1.2), "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-swg-r1"}]}}),
            json!({"type": "event_msg", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 1.4), "payload": {"type": "task_complete", "last_agent_message": "VERDICT: REVISE"}}),
            json!({"type": "turn_context", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 2.6), "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 2.7), "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-swg-r2"}]}}),
            json!({"type": "event_msg", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 2.9), "payload": {"type": "task_complete", "last_agent_message": "VERDICT: REVISE"}}),
            json!({"type": "turn_context", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 4.1), "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 4.2), "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-swg-r3"}]}}),
            json!({"type": "event_msg", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 4.4), "payload": {"type": "task_complete", "last_agent_message": "VERDICT: REVISE"}}),
            json!({"type": "turn_context", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 5.6), "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 5.7), "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-swg-r4"}]}}),
            json!({"type": "event_msg", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 5.9), "payload": {"type": "task_complete", "last_agent_message": "VERDICT: ESCALATE"}}),
        ];
        fs::write(
            &swg_rf,
            swg_rows.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        fs::write(
            swg_dir.join("members.json"),
            json!([
                {"name": "simp-r", "model": cwg_common::SONNET_HIGH_MODEL, "state": "waiting", "killed": false},
                {"name": "simp-q", "model": cwg_common::SONNET_HIGH_MODEL, "state": "killed", "killed": true},
                {"name": "simp-e", "model": cwg_common::SONNET_HIGH_MODEL, "state": "killed", "killed": true}
            ])
            .to_string(),
        )
        .unwrap();
        assert_eq!(
            run_cli(&[
                "review".to_string(),
                "--closure".to_string(),
                "--cwd".to_string(),
                repo_str.clone(),
                "--session".to_string(),
                sess_sw_guard.to_string(),
                "--diff-file".to_string(),
                diff_p.to_string_lossy().into_owned(),
                "--summary".to_string(),
                "Waiting simplify worker must block --closure".to_string(),
            ]),
            2
        );
        assert_eq!(
            fs::read_to_string(&inv_log).unwrap_or_default().lines().count(),
            inv_before_swg
        );
        fs::write(
            swg_dir.join("members.json"),
            json!([
                {"name": "simp-r", "model": cwg_common::SONNET_HIGH_MODEL, "state": "killed", "killed": true},
                {"name": "simp-q", "model": cwg_common::SONNET_HIGH_MODEL, "state": "killed", "killed": true},
                {"name": "simp-e", "model": cwg_common::SONNET_HIGH_MODEL, "state": "killed", "killed": true}
            ])
            .to_string(),
        )
        .unwrap();
        assert_eq!(
            run_cli(&[
                "review".to_string(),
                "--closure".to_string(),
                "--cwd".to_string(),
                repo_str.clone(),
                "--session".to_string(),
                sess_sw_guard.to_string(),
                "--diff-file".to_string(),
                diff_p.to_string_lossy().into_owned(),
                "--summary".to_string(),
                "Round 4 ESCALATE without post-escalation research must fail".to_string(),
            ]),
            2
        );
        let swg_res_steps = [
            json!({
                "step_index": 1,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "status": "DONE",
                "created_at": crate::win32_sqlite::format_iso_utc(base_t + 7.5),
                "tool_calls": [{"name": "search_web", "args": {"query": "escalation remediation docs"}}]
            }),
            json!({
                "step_index": 2,
                "source": "SYSTEM",
                "type": "GENERIC",
                "status": "DONE",
                "created_at": crate::win32_sqlite::format_iso_utc(base_t + 8.5),
                "content": "ok"
            }),
        ];
        fs::write(
            swg_logs.join("transcript.jsonl"),
            swg_res_steps.iter().map(Value::to_string).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        assert_eq!(
            run_cli(&[
                "review".to_string(),
                "--closure".to_string(),
                "--cwd".to_string(),
                repo_str.clone(),
                "--session".to_string(),
                sess_sw_guard.to_string(),
                "--diff-file".to_string(),
                diff_p.to_string_lossy().into_owned(),
                "--summary".to_string(),
                "All simplify workers killed + verified post-ESCALATE research unlocks --closure".to_string(),
            ]),
            0
        );

        // SAFETY: Fresh `VERDICT: APPROVED` blocks redundant ordinary review (`already_ordinary_approved`), whereas an external editor file modification (no `PostToolUse` delta) is caught via `catch_up_unmeasured_changes` and unlocks a fresh primary review.
        let sess_ext = "sess-ext-edit-after-app";
        rio::write_json(
            &cwg_common::marker_path(sess_ext),
            &json!({
                "session": sess_ext,
                "first_ts": base_t,
                "last_durable_ts": base_t,
                "cwd": rio::normalize_path(&repo_str),
                "git_root": rio::normalize_path(&repo_str),
                "paths": [cap_auth_norm],
                "content_marks": [{"ts": base_t, "fp": cap_fp, "unknown": false}],
                "closed": false,
            }),
        )
        .unwrap();
        record_packet("cwg-ext-app01", "REVIEW_ID: cwg-ext-app01", &repo_str, "high", "ordinary", sess_ext);
        let p_ext = packet_path("cwg-ext-app01");
        let mut doc_ext = rio::read_json(&p_ext).unwrap();
        doc_ext["created_ts"] = json!(base_t + 1.0);
        rio::write_json(&p_ext, &doc_ext).unwrap();
        let ext_rf = sessions_dir.join("rollout-ext-app.jsonl");
        let ext_rows = [
            json!({"type": "session_meta", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 1.0), "payload": {"id": "sess-ext-sid", "session_id": "sess-ext-sid", "source": "exec", "thread_source": "user"}}),
            json!({"type": "turn_context", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 1.1), "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 1.2), "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-ext-app01"}]}}),
            json!({"type": "event_msg", "timestamp": crate::win32_sqlite::format_iso_utc(base_t + 2.0), "payload": {"type": "task_complete", "last_agent_message": "VERDICT: APPROVED"}}),
        ];
        fs::write(
            &ext_rf,
            ext_rows.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        assert_eq!(
            run_cli(&[
                "review".to_string(),
                "--cwd".to_string(),
                repo_str.clone(),
                "--session".to_string(),
                sess_ext.to_string(),
                "--diff-file".to_string(),
                diff_p.to_string_lossy().into_owned(),
                "--summary".to_string(),
                "Redundant ordinary review on unchanged bytes must fail".to_string(),
            ]),
            2
        );
        fs::write(&cap_auth, "pub fn check_external_editor_edit() {}\n").unwrap();
        // SAFETY: If `marker.json` cannot be overwritten to persist the external-editor fingerprint, `cmd_review` fails closed (`rc == 2`, `marker_sync_write_failed`) BEFORE invoking Codex.
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let hold_ro = fs::OpenOptions::new()
                .read(true)
                .share_mode(1)
                .open(cwg_common::marker_path(sess_ext))
                .unwrap();
            let inv_before_sync_fail =
                fs::read_to_string(&inv_log).unwrap_or_default().lines().count();
            assert_eq!(
                run_cli(&[
                    "review".to_string(),
                    "--new-session".to_string(),
                    "--cwd".to_string(),
                    repo_str.clone(),
                    "--session".to_string(),
                    sess_ext.to_string(),
                    "--diff-file".to_string(),
                    diff_p.to_string_lossy().into_owned(),
                    "--summary".to_string(),
                    "FORCE_ORDINARY_APPROVED_MOCK".to_string(),
                ]),
                2
            );
            assert_eq!(
                fs::read_to_string(&inv_log).unwrap_or_default().lines().count(),
                inv_before_sync_fail
            );
            drop(hold_ro);
        }
        assert_eq!(
            run_cli(&[
                "review".to_string(),
                "--new-session".to_string(),
                "--cwd".to_string(),
                repo_str.clone(),
                "--session".to_string(),
                sess_ext.to_string(),
                "--diff-file".to_string(),
                diff_p.to_string_lossy().into_owned(),
                "--summary".to_string(),
                "FORCE_ORDINARY_APPROVED_MOCK".to_string(),
            ]),
            0
        );
        fs::write(&cap_auth, "pub fn check() {}\n").unwrap();
    }

    #[test]
    fn test_astra_vs_sol_model_routing_and_xhigh_rollout_verification() {
        let _lock = crate::win32_sqlite::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(resolve_review_model("", false), "gpt-6.2-sol");
        assert_eq!(resolve_review_model("", true), "gpt-6.2-astra");
        assert_eq!(resolve_review_model("custom-model", true), "custom-model");

        assert!(cwg_common::is_codex_xhigh_turn("gpt-6.2-astra", "xhigh"));
        assert!(cwg_common::is_codex_xhigh_turn("gpt-6.2-astra", "ultra"));
        assert!(cwg_common::is_codex_xhigh_turn("gpt-6.2-astra-2026-11", "max"));
        assert!(!cwg_common::is_codex_xhigh_turn("gpt-6.2-sol", "xhigh"));
        assert!(!cwg_common::is_codex_xhigh_turn("gpt-6-astra", "xhigh"));
        assert!(!cwg_common::is_codex_xhigh_turn("gpt-6.2-astra", "high"));
        assert!(!cwg_common::is_codex_xhigh_turn("", "xhigh"));

        let tmp = TempTestDir::new("astra-vs-sol");
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
        let repo_str = repo_dir.to_string_lossy().into_owned();
        let sess = "sess-astra-sol-01";
        let rid_sol = "cwg-solxhigh001";
        let rid_astra = "cwg-astraxhigh1";
        record_packet(rid_sol, &format!("REVIEW_ID: {}", rid_sol), &repo_str, "xhigh", "ordinary", sess);
        record_packet(rid_astra, &format!("REVIEW_ID: {}", rid_astra), &repo_str, "xhigh", "ordinary", sess);

        let write_rollout = |sid: &str, model: &str, effort: &str, rid: &str, ts_s: &str| {
            let lines = [
                json!({"type": "session_meta", "timestamp": ts_s, "payload": {"id": sid, "session_id": sid, "source": "exec", "thread_source": "user"}}),
                json!({"type": "turn_context", "timestamp": ts_s, "payload": {"model": model, "effort": effort}}),
                json!({"type": "response_item", "timestamp": ts_s, "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": format!("REVIEW_ID: {}", rid)}]}}),
                json!({"type": "event_msg", "timestamp": ts_s, "payload": {"type": "task_complete", "last_agent_message": "VERDICT: APPROVED"}}),
            ];
            fs::write(
                sessions_dir.join(format!("rollout-{}.jsonl", sid)),
                lines.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
            )
            .unwrap();
        };
        write_rollout("sid-sol-001", "gpt-6.2-sol", "xhigh", rid_sol, "2026-11-18T08:00:01Z");
        write_rollout("sid-astra-001", "gpt-6.2-astra", "xhigh", rid_astra, "2026-11-18T08:00:05Z");

        let scanned = scan_verified_codex_reviews(now - 60.0, sess, &repo_str);
        assert_eq!(scanned.len(), 2);
        let sol_rec = scanned.iter().find(|r| r["review_id"] == rid_sol).unwrap();
        let astra_rec = scanned.iter().find(|r| r["review_id"] == rid_astra).unwrap();
        assert_eq!(sol_rec["xhigh"], false);
        assert_eq!(astra_rec["xhigh"], true);

        let _ = rio::write_json(
            &thread_state_path(sess, &repo_str),
            &json!({
                "session_id": "sid-sol-001",
                "session": sess,
                "git_root": rio::normalize_path(&repo_str),
                "candidate_first_ts": now - 10.0,
                "model": "gpt-6.2-sol",
                "effort": "high",
                "xhigh": false,
                "updated_ts": now,
            }),
        );
        assert_eq!(
            resolve_resume_session(
                &repo_str,
                sess,
                now - 10.0,
                "",
                false,
                "gpt-6.2-sol",
                "high"
            ),
            "sid-sol-001"
        );
        assert_eq!(
            resolve_resume_session(
                &repo_str,
                sess,
                now - 10.0,
                "",
                false,
                "gpt-6.2-astra",
                "xhigh"
            ),
            "sid-astra-001"
        );

        let cand_ts = now - 10.0;
        save_lane_thread_state(
            sess,
            &repo_str,
            cand_ts,
            "gpt-6.2-astra",
            "xhigh",
            json!({
                "session_id": "sid-astra-timeout",
                "candidate_first_ts": cand_ts,
                "model": "gpt-6.2-astra",
                "effort": "xhigh",
                "xhigh": true,
                "pending_timeout_resume": true,
                "next_timeout_seconds": 1200,
                "updated_ts": now,
            }),
        );
        save_lane_thread_state(
            sess,
            &repo_str,
            cand_ts,
            "gpt-6.2-sol",
            "high",
            json!({
                "session_id": "sid-sol-approved",
                "candidate_first_ts": cand_ts,
                "model": "gpt-6.2-sol",
                "effort": "high",
                "xhigh": false,
                "updated_ts": now + 1.0,
            }),
        );
        save_lane_thread_state(
            sess,
            &repo_str,
            cand_ts,
            "gpt-6.2-astra",
            "high",
            json!({
                "session_id": "sid-astra-high",
                "candidate_first_ts": cand_ts,
                "model": "gpt-6.2-astra",
                "effort": "high",
                "xhigh": false,
                "pending_timeout_resume": true,
                "next_timeout_seconds": 900,
                "updated_ts": now + 2.0,
            }),
        );

        let xh_st = active_thread_state_for_lane(sess, &repo_str, Some(cand_ts), "gpt-6.2-astra", "xhigh").unwrap();
        assert_eq!(val_to_str(xh_st.get("session_id")), "sid-astra-timeout");
        assert_eq!(val_to_f64(xh_st.get("next_timeout_seconds")) as i64, 1200);
        assert_eq!(
            resolve_resume_session(&repo_str, sess, cand_ts, "", false, "gpt-6.2-astra", "xhigh"),
            "sid-astra-timeout"
        );
        assert_eq!(
            resolve_resume_session(&repo_str, sess, cand_ts, "", false, "gpt-6.2-astra", "high"),
            "sid-astra-high"
        );

        let rid_no_mdl = "cwg-nomdlbefore";
        let rid_bleed_mid = "cwg-astramid001";
        let rid_no_tc = "cwg-notcafter01";
        record_packet(rid_no_mdl, &format!("REVIEW_ID: {}", rid_no_mdl), &repo_str, "xhigh", "ordinary", sess);
        record_packet(rid_bleed_mid, &format!("REVIEW_ID: {}", rid_bleed_mid), &repo_str, "xhigh", "ordinary", sess);
        record_packet(rid_no_tc, &format!("REVIEW_ID: {}", rid_no_tc), &repo_str, "xhigh", "ordinary", sess);
        let multi_lines = [
            json!({"type": "session_meta", "timestamp": "2026-11-18T08:01:00Z", "payload": {"id": "sid-bleed-01", "session_id": "sid-bleed-01", "source": "exec", "thread_source": "user"}}),
            json!({"type": "turn_context", "timestamp": "2026-11-18T08:01:01Z", "payload": {"effort": "xhigh"}}),
            json!({"type": "response_item", "timestamp": "2026-11-18T08:01:02Z", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": format!("REVIEW_ID: {}", rid_no_mdl)}]}}),
            json!({"type": "event_msg", "timestamp": "2026-11-18T08:01:03Z", "payload": {"type": "task_complete", "last_agent_message": "VERDICT: APPROVED"}}),
            json!({"type": "event_msg", "timestamp": "2026-11-18T08:01:04Z", "payload": {"type": "task_started"}}),
            json!({"type": "turn_context", "timestamp": "2026-11-18T08:01:05Z", "payload": {"model": "gpt-6.2-astra", "effort": "xhigh"}}),
            json!({"type": "response_item", "timestamp": "2026-11-18T08:01:06Z", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": format!("REVIEW_ID: {}", rid_bleed_mid)}]}}),
            json!({"type": "event_msg", "timestamp": "2026-11-18T08:01:07Z", "payload": {"type": "task_complete", "last_agent_message": "VERDICT: REVISE"}}),
            json!({"type": "event_msg", "timestamp": "2026-11-18T08:01:08Z", "payload": {"type": "task_started"}}),
            json!({"type": "response_item", "timestamp": "2026-11-18T08:01:09Z", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": format!("REVIEW_ID: {}", rid_no_tc)}]}}),
            json!({"type": "event_msg", "timestamp": "2026-11-18T08:01:10Z", "payload": {"type": "task_complete", "last_agent_message": "VERDICT: APPROVED"}}),
        ];
        fs::write(
            sessions_dir.join("rollout-sid-bleed-01.jsonl"),
            multi_lines.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        let scanned2 = scan_verified_codex_reviews(now - 60.0, sess, &repo_str);
        let r_before = scanned2.iter().find(|r| r["review_id"] == rid_no_mdl).unwrap();
        let r_mid = scanned2.iter().find(|r| r["review_id"] == rid_bleed_mid).unwrap();
        let r_after = scanned2.iter().find(|r| r["review_id"] == rid_no_tc).unwrap();
        assert_eq!(r_before["xhigh"], false);
        assert_eq!(r_mid["xhigh"], true);
        assert_eq!(r_after["xhigh"], false);

        assert_eq!(format_review_retry_cmd("gpt-6.2-sol", false), "carbon-stack codex-lane review");
        assert_eq!(format_review_retry_cmd("gpt-6.2-astra", true), "carbon-stack codex-lane review --xhigh");
        assert_eq!(
            format_review_retry_cmd("gpt-6.2-astra", false),
            "carbon-stack codex-lane review --model gpt-6.2-astra"
        );
        assert_eq!(
            format_review_retry_cmd("custom-m", true),
            "carbon-stack codex-lane review --xhigh --model custom-m"
        );

        let sess_leg_kn = "sess-legacy-known-xh";
        let _ = rio::write_json(
            &thread_state_path(sess_leg_kn, &repo_str),
            &json!({
                "session_id": "sid-astra-001",
                "session": sess_leg_kn,
                "git_root": rio::normalize_path(&repo_str),
                "candidate_first_ts": cand_ts,
                "pending_timeout_resume": true,
                "last_timeout_seconds": 900,
                "next_timeout_seconds": 1200,
                "updated_ts": now,
            }),
        );
        assert!(active_thread_state_for_lane(sess_leg_kn, &repo_str, Some(cand_ts), "gpt-6.2-sol", "high").is_none());
        let mig_xh = active_thread_state_for_lane(sess_leg_kn, &repo_str, Some(cand_ts), "gpt-6.2-astra", "xhigh").unwrap();
        assert_eq!(val_to_str(mig_xh.get("session_id")), "sid-astra-001");
        assert_eq!(val_to_f64(mig_xh.get("next_timeout_seconds")) as i64, 1200);

        let sess_leg_unk = "sess-legacy-unk-xh";
        let _ = rio::write_json(
            &thread_state_path(sess_leg_unk, &repo_str),
            &json!({
                "session_id": "sid-unknown-old",
                "session": sess_leg_unk,
                "git_root": rio::normalize_path(&repo_str),
                "candidate_first_ts": cand_ts,
                "pending_timeout_resume": true,
                "last_timeout_seconds": 900,
                "next_timeout_seconds": 1200,
                "updated_ts": now,
            }),
        );
        assert_eq!(
            resolve_resume_session(&repo_str, sess_leg_unk, cand_ts, "", false, "gpt-6.2-sol", "high"),
            ""
        );
        let unk_for_xh = active_thread_state_for_lane(sess_leg_unk, &repo_str, Some(cand_ts), "gpt-6.2-astra", "xhigh").unwrap();
        assert_eq!(val_to_str(unk_for_xh.get("session_id")), "");
        assert_eq!(val_to_f64(unk_for_xh.get("next_timeout_seconds")) as i64, 1200);
        save_lane_thread_state(
            sess_leg_unk,
            &repo_str,
            cand_ts,
            "gpt-6.2-astra",
            "xhigh",
            json!({
                "session_id": "sid-new-astra-ok",
                "candidate_first_ts": cand_ts,
                "xhigh": true,
                "updated_ts": now + 5.0,
            }),
        );
        let post_xh_any = active_thread_state(sess_leg_unk, &repo_str, Some(cand_ts)).unwrap();
        assert!(!json_truthy(post_xh_any.get("pending_timeout_resume")));

        let sess_notc_xh = "sess-legacy-notc-xh";
        let notc_lines = [
            json!({"type": "session_meta", "timestamp": "2026-11-18T08:02:00Z", "payload": {"id": "sid-mixed-hi-xh", "session_id": "sid-mixed-hi-xh", "source": "exec", "thread_source": "user"}}),
            json!({"type": "turn_context", "timestamp": "2026-11-18T08:02:01Z", "payload": {"model": "gpt-6.1-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": "2026-11-18T08:02:02Z", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-oldhi0001"}]}}),
            json!({"type": "event_msg", "timestamp": "2026-11-18T08:02:03Z", "payload": {"type": "task_complete", "last_agent_message": "VERDICT: REVISE"}}),
            json!({"type": "event_msg", "timestamp": "2026-11-18T08:02:04Z", "payload": {"type": "task_started"}}),
            json!({"type": "response_item", "timestamp": "2026-11-18T08:02:05Z", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-newxhnotc"}]}}),
        ];
        fs::write(
            sessions_dir.join("rollout-sid-mixed-hi-xh.jsonl"),
            notc_lines.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        let _ = rio::write_json(
            &thread_state_path(sess_notc_xh, &repo_str),
            &json!({
                "session_id": "sid-mixed-hi-xh",
                "last_review_id": "cwg-newxhnotc",
                "session": sess_notc_xh,
                "git_root": rio::normalize_path(&repo_str),
                "candidate_first_ts": cand_ts,
                "pending_timeout_resume": true,
                "last_timeout_seconds": 900,
                "next_timeout_seconds": 1200,
                "updated_ts": now,
            }),
        );
        assert_eq!(
            resolve_resume_session(&repo_str, sess_notc_xh, cand_ts, "", false, "gpt-6.2-sol", "high"),
            ""
        );
        let xh_notc_st = active_thread_state_for_lane(sess_notc_xh, &repo_str, Some(cand_ts), "gpt-6.2-astra", "xhigh").unwrap();
        assert_eq!(val_to_f64(xh_notc_st.get("next_timeout_seconds")) as i64, 1200);

        write_rollout("sid-astra-max", "gpt-6.2-astra", "max", "cwg-astramax01", "2026-11-18T08:03:00Z");
        let sess_max = "sess-legacy-max";
        let _ = rio::write_json(
            &thread_state_path(sess_max, &repo_str),
            &json!({
                "session_id": "sid-astra-max",
                "last_review_id": "cwg-astramax01",
                "session": sess_max,
                "git_root": rio::normalize_path(&repo_str),
                "candidate_first_ts": cand_ts,
                "pending_timeout_resume": true,
                "last_timeout_seconds": 900,
                "next_timeout_seconds": 1200,
                "updated_ts": now,
            }),
        );
        let max_migrated = active_thread_state_for_lane(sess_max, &repo_str, Some(cand_ts), "gpt-6.2-astra", "xhigh").unwrap();
        assert_eq!(val_to_str(max_migrated.get("session_id")), "sid-astra-max");
        save_lane_thread_state(
            sess_max,
            &repo_str,
            cand_ts,
            "gpt-6.2-astra",
            "xhigh",
            json!({
                "session_id": "sid-astra-max",
                "candidate_first_ts": cand_ts,
                "xhigh": true,
                "updated_ts": now + 10.0,
            }),
        );
        let post_max = active_thread_state(sess_max, &repo_str, Some(cand_ts)).unwrap();
        assert!(!json_truthy(post_max.get("pending_timeout_resume")));

        let sess_noeff = "sess-legacy-partial-tc";
        let noeff_lines = [
            json!({"type": "session_meta", "timestamp": "2026-11-18T08:04:00Z", "payload": {"id": "sid-partial-noeff", "session_id": "sid-partial-noeff", "source": "exec", "thread_source": "user"}}),
            json!({"type": "turn_context", "timestamp": "2026-11-18T08:04:01Z", "payload": {"model": "gpt-6.1-sol"}}),
            json!({"type": "response_item", "timestamp": "2026-11-18T08:04:02Z", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-partialxh"}]}}),
        ];
        fs::write(
            sessions_dir.join("rollout-sid-partial-noeff.jsonl"),
            noeff_lines.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        let _ = record_packet("cwg-partialxh", "prompt", &repo_str, "xhigh", "ordinary", sess_noeff);
        let _ = rio::write_json(
            &thread_state_path(sess_noeff, &repo_str),
            &json!({
                "session_id": "sid-partial-noeff",
                "last_review_id": "cwg-partialxh",
                "session": sess_noeff,
                "git_root": rio::normalize_path(&repo_str),
                "candidate_first_ts": cand_ts,
                "pending_timeout_resume": true,
                "last_timeout_seconds": 900,
                "next_timeout_seconds": 1200,
                "updated_ts": now,
            }),
        );
        assert!(active_thread_state_for_lane(sess_noeff, &repo_str, Some(cand_ts), "gpt-6.2-sol", "high").is_none());
        let noeff_xh = active_thread_state_for_lane(sess_noeff, &repo_str, Some(cand_ts), "gpt-6.2-astra", "xhigh").unwrap();
        assert_eq!(val_to_str(noeff_xh.get("session_id")), "");
        assert_eq!(val_to_f64(noeff_xh.get("next_timeout_seconds")) as i64, 1200);

        let sess_ast_hi600 = "sess-legacy-astra-hi600";
        let ast600_lines = [
            json!({"type": "session_meta", "timestamp": "2026-11-18T08:05:00Z", "payload": {"id": "sid-astra-hi-600", "session_id": "sid-astra-hi-600", "source": "exec", "thread_source": "user"}}),
            json!({"type": "turn_context", "timestamp": "2026-11-18T08:05:01Z", "payload": {"model": "gpt-6.2-astra"}}),
            json!({"type": "response_item", "timestamp": "2026-11-18T08:05:02Z", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-astrahi600"}]}}),
        ];
        fs::write(
            sessions_dir.join("rollout-sid-astra-hi-600.jsonl"),
            ast600_lines.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        let _ = rio::write_json(
            &thread_state_path(sess_ast_hi600, &repo_str),
            &json!({
                "session_id": "sid-astra-hi-600",
                "last_review_id": "cwg-astrahi600",
                "session": sess_ast_hi600,
                "git_root": rio::normalize_path(&repo_str),
                "candidate_first_ts": cand_ts,
                "pending_timeout_resume": true,
                "last_timeout_seconds": 600,
                "next_timeout_seconds": 900,
                "updated_ts": now,
            }),
        );
        assert!(active_thread_state_for_lane(sess_ast_hi600, &repo_str, Some(cand_ts), "gpt-6.2-astra", "xhigh").is_none());
        let ast_hi_st = active_thread_state_for_lane(sess_ast_hi600, &repo_str, Some(cand_ts), "gpt-6.2-astra", "high").unwrap();
        assert_eq!(val_to_str(ast_hi_st.get("session_id")), "sid-astra-hi-600");
        assert_eq!(val_to_f64(ast_hi_st.get("next_timeout_seconds")) as i64, 900);

        let unpersisted_base = format_review_retry_cmd_with_spec(&RetryCmdSpec {
            model: "gpt-6.2-astra",
            xhigh: true,
            closure: true,
            session: "sess-explicit-01",
            cwd: "",
            diff_file: "",
            summary: "",
            pretty: false,
        });
        let unpersisted_p = build_thinking_timeout_payload(
            "cwg-unpersisted01",
            900,
            900,
            &unpersisted_base,
            "sid-unpersisted",
            false,
        );
        assert_eq!(unpersisted_p.get("state_persisted"), Some(&Value::Bool(false)));
        assert_eq!(unpersisted_p.get("session_continuation_saved"), Some(&Value::Bool(false)));
        assert_eq!(unpersisted_p.get("recommended_timeout"), Some(&json!(900)));
        assert_eq!(
            val_to_str(unpersisted_p.get("retry_command")),
            "carbon-stack codex-lane review --xhigh --closure --session sess-explicit-01 --resume sid-unpersisted"
        );
        let raw_sum = "keep \"double\" & 'single' quotes";
        let ps_tricky = format_review_retry_cmd_with_spec(&RetryCmdSpec {
            model: "gpt-6.2-astra",
            xhigh: true,
            closure: true,
            session: "sess-1",
            cwd: r"C:\work\release;archive",
            diff_file: r"C:\work\$release notes",
            summary: raw_sum,
            pretty: false,
        });
        assert_eq!(
            ps_tricky,
            format!(
                "carbon-stack codex-lane review --xhigh --closure --session sess-1 --cwd 'C:\\work\\release;archive' --diff-file 'C:\\work\\$release notes' --summary-hex '{}'",
                encode_utf8_hex(raw_sum)
            )
        );
        assert_eq!(decode_utf8_hex(&encode_utf8_hex(raw_sum)).unwrap(), raw_sum);

        // INVARIANT: 2-block closure halt, `research-reset`, and fresh-session enforcement hold in Rust.
        let sess_rr = "sess-rr-rust";
        let mpath_rr = cwg_common::marker_path(sess_rr);
        let _ = rio::write_json(
            &mpath_rr,
            &json!({
                "session": sess_rr,
                "class": cwg_common::WORK_PERSISTENT,
                "first_ts": cand_ts,
                "last_durable_ts": cand_ts,
                "git_root": rio::normalize_path(&repo_str),
                "cwd": rio::normalize_path(&repo_str),
                "paths": [rio::normalize_path(&Path::new(&repo_str).join("auth.rs").to_string_lossy())],
                "content_marks": [{"ts": cand_ts, "fp": "1122334455667788", "unknown": false}],
                "closed": false,
            }),
        );
        for (idx, (rid, ph)) in [("cwg-rr-o1", "ordinary"), ("cwg-rr-b1", "closure"), ("cwg-rr-b2", "closure")]
            .into_iter()
            .enumerate()
        {
            record_packet(rid, &format!("REVIEW_ID: {}", rid), &repo_str, "high", ph, sess_rr);
            let p_path = packet_path(rid);
            if let Some(mut pd) = rio::read_json(&p_path) {
                pd["created_ts"] = json!(cand_ts + (idx as f64) + 1.0);
                let _ = rio::write_json(&p_path, &pd);
            }
        }
        let rr_old_sid = "sid-rr-old-01";
        let rr_rollout = sessions_dir.join("rollout-sid-rr-old-01.jsonl");
        let rr_lines = [
            json!({"type": "session_meta", "timestamp": "2026-11-18T08:05:00Z", "payload": {"id": rr_old_sid, "session_id": rr_old_sid, "source": "exec", "thread_source": "user"}}),
            json!({"type": "turn_context", "timestamp": "2026-11-18T08:05:01Z", "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": "2026-11-18T08:05:02Z", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-rr-o1"}]}}),
            json!({"type": "event_msg", "timestamp": "2026-11-18T08:05:03Z", "payload": {"type": "task_complete", "last_agent_message": "VERDICT: APPROVED"}}),
            json!({"type": "turn_context", "timestamp": "2026-11-18T08:05:04Z", "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": "2026-11-18T08:05:05Z", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-rr-b1"}]}}),
            json!({"type": "event_msg", "timestamp": "2026-11-18T08:05:06Z", "payload": {"type": "task_complete", "last_agent_message": "CLOSURE_VALIDATION: BLOCKED"}}),
            json!({"type": "turn_context", "timestamp": "2026-11-18T08:05:07Z", "payload": {"model": "gpt-6.2-sol", "effort": "high"}}),
            json!({"type": "response_item", "timestamp": "2026-11-18T08:05:08Z", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "REVIEW_ID: cwg-rr-b2"}]}}),
            json!({"type": "event_msg", "timestamp": "2026-11-18T08:05:09Z", "payload": {"type": "task_complete", "last_agent_message": "CLOSURE_VALIDATION: BLOCKED"}}),
        ];
        fs::write(
            &rr_rollout,
            rr_lines.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        let (blk_cnt, _last_blk_ts, blk_ids) = active_cycle_closure_blocks(sess_rr, &repo_str, "");
        assert_eq!(blk_cnt, 2);
        assert_eq!(blk_ids, vec!["cwg-rr-b1".to_string(), "cwg-rr-b2".to_string()]);

        let (sg_dec, sg_rsn) = crate::safety_guards::guard_shell_command_with_session(
            &format!("carbon-stack codex-lane review --cwd '{}' --session {}", repo_str, sess_rr),
            &repo_str,
            sess_rr,
        );
        assert_eq!(sg_dec, "deny");
        let sg_msg = sg_rsn.unwrap_or_default();
        assert!(sg_msg.contains("[Finite Gate Policy]") && sg_msg.contains("draft-blocked"));

        // INVARIANT: Under the finite gate, `redesign-reset` / `research-reset` rejects `--decision refine` (`rc == 2`) and rejects reset after 2/2 closure exhaustion (`rc == 2`), preserving saved threads and terminating in `[gate] draft-blocked`.
        let tp_rr = Path::new(&repo_str).join("rr-transcript.jsonl");
        let research_steps = [
            json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2099-01-01T00:00:01Z", "tool_calls": [{"name": "search_web", "args": {"query": "gate verification docs"}}]}),
            json!({"step_index": 2, "source": "SYSTEM", "type": "GENERIC", "status": "DONE", "created_at": "2099-01-01T00:00:02Z", "content": "ok"}),
        ];
        fs::write(
            &tp_rr,
            research_steps.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        save_lane_thread_state(
            sess_rr,
            &repo_str,
            cand_ts,
            "gpt-6.2-sol",
            "high",
            json!({
                "session_id": "sid-finite-kept",
                "candidate_first_ts": cand_ts,
                "model": "gpt-6.2-sol",
                "effort": "high",
                "xhigh": false,
                "updated_ts": now + 100.0,
            }),
        );
        assert_eq!(
            run_cli(&[
                "research-reset".to_string(),
                "--cwd".to_string(),
                repo_str.clone(),
                "--session".to_string(),
                sess_rr.to_string(),
                "--decision".to_string(),
                "refine".to_string(),
                "--findings-hex".to_string(),
                encode_utf8_hex("Verified \"official\" docs & refined closure state machine."),
                "--transcript".to_string(),
                tp_rr.to_string_lossy().into_owned(),
            ]),
            2
        );
        assert_eq!(
            run_cli(&[
                "redesign-reset".to_string(),
                "--cwd".to_string(),
                repo_str.clone(),
                "--session".to_string(),
                sess_rr.to_string(),
                "--findings-hex".to_string(),
                encode_utf8_hex("Attempted redesign after 2/2 BLOCKED closure exhaustion."),
                "--transcript".to_string(),
                tp_rr.to_string_lossy().into_owned(),
            ]),
            2
        );
        let kept_saved = active_thread_state(sess_rr, &repo_str, Some(cand_ts)).unwrap();
        assert_eq!(val_to_str(kept_saved.get("session_id")), "sid-finite-kept");
        let unchanged_marker = rio::read_json(&mpath_rr).unwrap();
        assert!(unchanged_marker.get("research_resets").is_none());

        // INVARIANT: After Round 4 `ESCALATE` + verified post-`ESCALATE` research (before 2/2 closure exhaustion), `redesign-reset` succeeds at most ONCE (`MAX_REDESIGN_RESETS = 1`), purging saved threads + simplify latches so the redesigned candidate runs in fresh sessions, and rejects any 2nd reset attempt (`rc == 2`).
        let sess_red = "sess-redesign-once";
        let mpath_red = cwg_common::marker_path(sess_red);
        let cand_ts_red = now - 120.0;
        rio::write_json(
            &mpath_red,
            &json!({
                "session": sess_red,
                "class": cwg_common::WORK_PERSISTENT,
                "closed": false,
                "first_ts": cand_ts_red,
                "last_durable_ts": cand_ts_red,
                "last_ts": cand_ts_red,
                "edits": 1,
                "cwd": rio::normalize_path(&repo_str),
                "git_root": rio::normalize_path(&repo_str),
                "paths": [rio::normalize_path(&Path::new(&repo_str).join("rust/src/a.rs").to_string_lossy())],
                "content_marks": [{"ts": cand_ts_red, "fp": "1122334455667788", "unknown": false}],
                "declared_risk": "HIGH",
                "round_start_msg_id": 5,
                "simplify_verified_latched": {
                    "candidate_first_ts": cand_ts_red,
                    "reset_epoch": 0,
                    "verified_ts": cand_ts_red + 1.0,
                    "verified_hashes": ["h-old"],
                },
            }),
        )
        .unwrap();
        let esc_rid = "cwg-redesign-r4-esc";
        let esc_sid = "sid-redesign-old";
        let esc_roll = sessions_dir.join("rollout-redesign-esc.jsonl");
        let base_esc_ts = cand_ts_red + 5.0;
        let mut esc_lines: Vec<String> = vec![json!({
            "type": "session_meta",
            "timestamp": crate::win32_sqlite::format_iso_utc(base_esc_ts),
            "payload": {"id": esc_sid, "session_id": esc_sid, "source": "exec", "thread_source": "user"}
        })
        .to_string()];
        for r_idx in 1..=4usize {
            let rid_i = if r_idx == 4 {
                esc_rid.to_string()
            } else {
                format!("cwg-redesign-r{}", r_idx)
            };
            let v_str = if r_idx == 4 { "ESCALATE" } else { "REVISE" };
            let ts_i = base_esc_ts + (r_idx as f64) * 5.0;
            record_packet(
                &rid_i,
                &format!("REVIEW_ID: {}", rid_i),
                &repo_str,
                "high",
                "ordinary",
                sess_red,
            );
            let p_path = packet_path(&rid_i);
            if let Some(mut pd) = rio::read_json(&p_path) {
                pd["created_ts"] = json!(ts_i);
                let _ = rio::write_json(&p_path, &pd);
            }
            esc_lines.push(
                json!({
                    "type": "turn_context",
                    "timestamp": crate::win32_sqlite::format_iso_utc(ts_i + 1.0),
                    "payload": {"model": "gpt-6.2-sol", "effort": "high"}
                })
                .to_string(),
            );
            esc_lines.push(
                json!({
                    "type": "response_item",
                    "timestamp": crate::win32_sqlite::format_iso_utc(ts_i + 2.0),
                    "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": format!("REVIEW_ID: {}", rid_i)}]}
                })
                .to_string(),
            );
            esc_lines.push(
                json!({
                    "type": "event_msg",
                    "timestamp": crate::win32_sqlite::format_iso_utc(ts_i + 3.0),
                    "payload": {"type": "task_complete", "last_agent_message": format!("VERDICT: {}", v_str)}
                })
                .to_string(),
            );
        }
        fs::write(&esc_roll, esc_lines.join("\n") + "\n").unwrap();
        save_lane_thread_state(
            sess_red,
            &repo_str,
            cand_ts_red,
            "gpt-6.2-sol",
            "high",
            json!({
                "session_id": esc_sid,
                "candidate_first_ts": cand_ts_red,
                "model": "gpt-6.2-sol",
                "effort": "high",
                "xhigh": false,
                "updated_ts": base_esc_ts + 24.0,
            }),
        );
        let tp_red = Path::new(&repo_str).join("redesign-transcript.jsonl");
        let red_steps = [
            json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": crate::win32_sqlite::format_iso_utc(base_esc_ts + 30.0), "tool_calls": [{"name": "search_web", "args": {"query": "redesign architecture docs"}}]}),
            json!({"step_index": 2, "source": "SYSTEM", "type": "GENERIC", "status": "DONE", "created_at": crate::win32_sqlite::format_iso_utc(base_esc_ts + 31.0), "content": "ok"}),
        ];
        fs::write(
            &tp_red,
            red_steps.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        // INVARIANT: A latched `closure_halt` (2x `BLOCKED`) blocks `redesign-reset` even when live closure rollout records were evicted while the 4 ordinary rounds + `ESCALATE` remain visible.
        let mut halted_red_marker = rio::read_json(&mpath_red).unwrap();
        halted_red_marker["closure_halt"] = json!({
            "candidate_first_ts": cand_ts_red,
            "blocked_count": 2,
            "last_blocked_ts": base_esc_ts + 25.0,
            "blocked_review_ids": ["cwg-evicted-b1", "cwg-evicted-b2"],
        });
        rio::write_json(&mpath_red, &halted_red_marker).unwrap();
        assert_eq!(
            run_cli(&[
                "redesign-reset".to_string(),
                "--cwd".to_string(),
                repo_str.clone(),
                "--session".to_string(),
                sess_red.to_string(),
                "--findings-hex".to_string(),
                encode_utf8_hex("Attempted redesign while latched 2x BLOCKED closure_halt is active."),
                "--transcript".to_string(),
                tp_red.to_string_lossy().into_owned(),
            ]),
            2
        );
        let still_halted = rio::read_json(&mpath_red).unwrap();
        assert!(still_halted.get("closure_halt").is_some());
        halted_red_marker.as_object_mut().unwrap().remove("closure_halt");
        rio::write_json(&mpath_red, &halted_red_marker).unwrap();

        assert_eq!(
            run_cli(&[
                "redesign-reset".to_string(),
                "--cwd".to_string(),
                repo_str.clone(),
                "--session".to_string(),
                sess_red.to_string(),
                "--findings-hex".to_string(),
                encode_utf8_hex("Architectural redesign replacing retrospective digest reconstruction with forward latch."),
                "--transcript".to_string(),
                tp_red.to_string_lossy().into_owned(),
            ]),
            0
        );
        assert!(active_thread_state(sess_red, &repo_str, Some(cand_ts_red)).is_none());
        let marker_after_red = rio::read_json(&mpath_red).unwrap();
        assert_eq!(cwg_common::redesign_reset_count(&marker_after_red), 1);
        assert!(marker_after_red.get("simplify_verified_latched").is_none());
        assert_eq!(
            run_cli(&[
                "redesign-reset".to_string(),
                "--cwd".to_string(),
                repo_str.clone(),
                "--session".to_string(),
                sess_red.to_string(),
                "--findings-hex".to_string(),
                encode_utf8_hex("Second redesign attempt must fail closed under MAX_REDESIGN_RESETS=1."),
                "--transcript".to_string(),
                tp_red.to_string_lossy().into_owned(),
            ]),
            2
        );

        // INVARIANT: Legacy markers that already contain historical `research_resets` still enforce `is_post_reset_codex_session_proven` against pre-reset subagent rollouts, while `build_adversarial_prompt` enforces `BLOCKING_THRESHOLD = HIGH`, interdiff, finding ledger, and Settled-Scope Freeze on Round 2+.
        let rr_cutoff = rio::parse_iso_ts("2099-01-01T00:10:00Z");
        assert!(!is_post_reset_codex_session_proven(
            "sid-nonexistent-missing",
            "",
            rr_cutoff,
            cand_ts
        ));
        let child_of_old = sessions_dir.join("rollout-sid-child-of-old.jsonl");
        fs::write(
            &child_of_old,
            json!({
                "type": "session_meta",
                "timestamp": "2099-01-01T00:05:00Z",
                "payload": {
                    "id": "sid-child-of-old",
                    "session_id": "sid-child-of-old",
                    "source": {"subagent": {"thread_spawn": {"parent_thread_id": rr_old_sid}}},
                    "thread_source": "subagent"
                }
            })
            .to_string()
                + "\n",
        )
        .unwrap();
        assert!(!is_post_reset_codex_session_proven(
            "sid-child-of-old",
            &child_of_old.to_string_lossy(),
            rr_cutoff,
            cand_ts
        ));

        let p_r1 = build_adversarial_prompt(PromptBuildSpec {
            review_id: "cwg-r1",
            packet_nonce: "111122223333",
            scope_summary: "Harden auth gate",
            diff_text: "diff --git a/src/auth.rs b/src/auth.rs\n+check();\n",
            interdiff_text: "",
            prior_ledger: "",
            phase: "ordinary",
            round_num: 1,
            is_resume: false,
            is_timeout_resume: false,
        });
        assert!(p_r1.contains("BLOCKING_THRESHOLD = HIGH"));
        assert!(p_r1.contains("MODE: ORDINARY_REVIEW (Round 1/4)"));
        assert!(!p_r1.contains("SETTLED-SCOPE FREEZE"));

        let p_r2 = build_adversarial_prompt(PromptBuildSpec {
            review_id: "cwg-r2",
            packet_nonce: "444455556666",
            scope_summary: "Harden auth gate",
            diff_text: "diff --git a/src/auth.rs b/src/auth.rs\n+check_strict();\n",
            interdiff_text: "diff --git a/src/auth.rs b/src/auth.rs\n-check();\n+check_strict();\n",
            prior_ledger: "- [HIGH] src/auth.rs:10 missing strict check\nVERDICT: REVISE",
            phase: "ordinary",
            round_num: 2,
            is_resume: true,
            is_timeout_resume: false,
        });
        assert!(p_r2.contains("MODE: ORDINARY_REVIEW (Round 2/4)"));
        assert!(p_r2.contains("SETTLED-SCOPE FREEZE"));
        assert!(p_r2.contains("PRIOR ROUND FINDING LEDGER"));
        assert!(p_r2.contains("REMEDIATION INTERDIFF SINCE PREVIOUS ROUND"));

        // INVARIANT: `git diff <prev_tree> <curr_tree>` via `capture_worktree_tree_oid` includes both modified tracked files and brand-new untracked files in remediation interdiffs.
        let tmp = TempTestDir::new("codex-interdiff-untracked");
        let repo = tmp.0.join("repo");
        fs::create_dir_all(&repo).unwrap();
        let repo_s = repo.to_string_lossy().into_owned();
        if rio::run_git(&repo_s, &["init"], 5.0).0 == 0 {
            let _ = rio::run_git(&repo_s, &["config", "user.email", "t@e.st"], 5.0);
            let _ = rio::run_git(&repo_s, &["config", "user.name", "T"], 5.0);
            fs::write(repo.join("tracked.rs"), "pub fn v() -> i32 { 1 }\n").unwrap();
            let _ = rio::run_git(&repo_s, &["add", "tracked.rs"], 5.0);
            let _ = rio::run_git(&repo_s, &["commit", "-m", "init"], 5.0);
            fs::write(repo.join("tracked.rs"), "pub fn v() -> i32 { 2 }\n").unwrap();
            let prev_tree = rio::capture_worktree_tree_oid(&repo_s, 5.0);
            assert!(cwg_common::is_git_oid(&prev_tree));
            fs::write(repo.join("tracked.rs"), "pub fn v() -> i32 { 3 }\n").unwrap();
            fs::write(repo.join("new_untracked.rs"), "pub fn helper() -> bool { true }\n").unwrap();
            let curr_tree = rio::capture_worktree_tree_oid(&repo_s, 5.0);
            assert!(cwg_common::is_git_oid(&curr_tree));
            let (rc_id, id_out, _) = rio::run_git(&repo_s, &["diff", &prev_tree, &curr_tree], 5.0);
            assert_eq!(rc_id, 0);
            assert!(id_out.contains("tracked.rs") && id_out.contains("pub fn v() -> i32 { 3 }"));
            assert!(id_out.contains("new_untracked.rs") && id_out.contains("pub fn helper()"));
        }
    }
}
