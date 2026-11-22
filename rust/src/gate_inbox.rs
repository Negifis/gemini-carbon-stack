use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use crate::cwg_common;
use crate::rio::{self, json_truthy, truncate_chars, val_to_f64, val_to_str};
use crate::win32_sqlite::{now_sec, SqlParam, SqliteConn, SQLITE_OPEN_READONLY};

static REPORT_SEQ: AtomicU64 = AtomicU64::new(1);

fn bus_snapshot_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\Asnapshot-[0-9a-f]{12}-\d{12}-[0-9a-f]{8}\.db\z").expect("bus_snapshot_re")
    })
}

fn bus_resolved_prefix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\A\s*\[(?:[A-Z0-9_\s]+_RESOLVED|[A-Z0-9_]+\s+RESOLVED|RESOLVED)\b")
            .expect("bus_resolved_prefix_re")
    })
}

fn bus_non_anomaly_prefix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\A\s*\[(?:[A-Z0-9_]+_DONE|[A-Z0-9_]+_STARTED|[A-Z0-9_]+_QUEUE|LOCK_ACQUIRED|LOCK_RELEASED|COORDINATION|INFO|HANDOFF|HANDOFF_ACK|ACK)\b",
        )
        .expect("bus_non_anomaly_prefix_re")
    })
}

fn bus_explicit_anomaly_tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\[([A-Z0-9_]*(?:GATE_ANOMALY|ANOMALY|DEADLOCK|REPORT|BUG)[A-Z0-9_]*)(?:\s+[^\]]*)?\]",
        )
        .expect("bus_explicit_anomaly_tag_re")
    })
}

fn has_explicit_anomaly_tag(body: &str) -> bool {
    bus_explicit_anomaly_tag_re().captures_iter(body).any(|cap| {
        let head_ok = cap
            .get(1)
            .is_some_and(|m| !m.as_str().to_ascii_uppercase().ends_with("_RESOLVED"));
        let full_ok = cap.get(0).is_some_and(|m| {
            let inner = m.as_str().trim_end_matches(']').trim().to_ascii_uppercase();
            !inner.ends_with("_RESOLVED") && !inner.ends_with(" RESOLVED")
        });
        head_ok && full_ok
    })
}

fn bus_report_keyword_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\bGATE_ANOMALY\b|\banom-[0-9a-f]{6,}\b|\bdeadlock\b|\bcwg_stop\b|\bcodex_lane\b|\bsafety_guards\b|аномал",
        )
        .expect("bus_report_keyword_re")
    })
}

pub fn is_valid_anomaly_bus_body(body: &str) -> bool {
    // INVARIANT: Share one canonical anomaly-body predicate across `unhandled_bus_reports` and `cwg_stop` transcript verification so coordination/resolved status messages (`[NEON_DONE]`, `[REPORT_DONE]`, `[REPORT_RESOLVED]`, etc.) never count as handler notifications while dropped by the inbox.
    let trimmed = body.trim();
    if trimmed.is_empty() || bus_resolved_prefix_re().is_match(trimmed) {
        return false;
    }
    if let Some(m) = bus_non_anomaly_prefix_re().find(trimmed) {
        let rest_start = trimmed[m.end()..]
            .find(']')
            .map(|idx| m.end() + idx + 1)
            .unwrap_or(m.end());
        return has_explicit_anomaly_tag(&trimmed[rest_start..]);
    }
    has_explicit_anomaly_tag(trimmed) || bus_report_keyword_re().is_match(trimmed)
}

fn anom_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\banom-[0-9a-f]{6,}\b").expect("anom_id_re"))
}

fn eprintln_str(msg: &str) {
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(msg.as_bytes());
    let _ = err.flush();
}

pub fn inbox_dir() -> PathBuf {
    let dir = cwg_common::gate_dir().join("inbox");
    let _ = fs::create_dir_all(&dir);
    dir
}

pub fn report_path(report_id: &str) -> Option<PathBuf> {
    let safe_id = rio::safe_key(report_id, "");
    if safe_id.is_empty() {
        None
    } else {
        Some(inbox_dir().join(format!("{}.json", safe_id)))
    }
}

fn load_report(report_id: &str) -> (Option<PathBuf>, Option<Map<String, Value>>) {
    let Some(p) = report_path(report_id) else {
        return (None, None);
    };
    let rec = match rio::read_json(&p) {
        Some(Value::Object(m)) => Some(m),
        _ => None,
    };
    (Some(p), rec)
}

pub fn handler_config_path() -> PathBuf {
    cwg_common::gate_dir().join("anomaly_handler.json")
}

pub fn get_handler_config() -> Value {
    match rio::read_json(&handler_config_path()) {
        Some(Value::Object(m)) => Value::Object(m),
        _ => Value::Object(Map::new()),
    }
}

pub fn get_handler_session_from_cfg(cfg: Option<&Value>) -> String {
    let owned;
    let source = match cfg {
        Some(c) => c,
        None => {
            owned = get_handler_config();
            &owned
        }
    };
    let raw = val_to_str(source.get("handler_session")).trim().to_string();
    if raw.is_empty() {
        String::new()
    } else {
        rio::safe_key(&raw, "")
    }
}

pub fn get_handler_session() -> String {
    get_handler_session_from_cfg(None)
}

pub fn set_handler_config(session: &str, stack_repo: &str, clear: bool) -> Value {
    let cfg_path = handler_config_path();
    if clear {
        if cfg_path.exists() {
            if fs::remove_file(&cfg_path).is_err() && rio::write_json(&cfg_path, &json!({})).is_err()
            {
                return json!({
                    "ok": false,
                    "error": format!("failed to clear {}", cfg_path.display()),
                });
            }
        }
        return json!({
            "ok": true,
            "handler_session": "",
            "cleared": true,
        });
    }

    let clean_sess = rio::safe_key(session, "");
    if clean_sess.is_empty() || clean_sess == "unknown" {
        return json!({
            "ok": false,
            "error": "valid --session conversation ID is required",
        });
    }

    let norm_repo = if stack_repo.trim().is_empty() {
        String::new()
    } else {
        rio::normalize_path(stack_repo)
    };
    let installed_plugin = rio::normalize_path(&rio::plugin_root().to_string_lossy());
    let updated_ts = now_sec();
    let cfg = json!({
        "handler_session": clean_sess,
        "stack_repo": norm_repo,
        "installed_plugin": installed_plugin,
        "updated_ts": updated_ts,
    });
    if let Err(e) = rio::write_json(&cfg_path, &cfg) {
        return json!({
            "ok": false,
            "error": format!("failed to persist handler config to {}: {}", cfg_path.display(), e),
        });
    }
    rio::log_hook_event(
        "gate-events",
        "anomaly_handler_set",
        json!({ "handler_session": clean_sess }),
    );
    json!({
        "ok": true,
        "handler_session": clean_sess,
        "stack_repo": norm_repo,
        "installed_plugin": installed_plugin,
        "updated_ts": updated_ts,
    })
}

fn load_reports(include_resolved: bool) -> Vec<Value> {
    let mut items: Vec<Value> = Vec::new();
    let Ok(entries) = fs::read_dir(inbox_dir()) else {
        return items;
    };
    for ent in entries.flatten() {
        let p = ent.path();
        if p.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        if let Some(Value::Object(m)) = rio::read_json(&p) {
            if include_resolved || !json_truthy(m.get("resolved")) {
                items.push(Value::Object(m));
            }
        }
    }
    items.sort_by(|a, b| {
        let ta = val_to_f64(a.get("created_ts"));
        let tb = val_to_f64(b.get("created_ts"));
        let ord = ta.total_cmp(&tb);
        if ord != std::cmp::Ordering::Equal {
            ord
        } else {
            val_to_str(a.get("id")).cmp(&val_to_str(b.get("id")))
        }
    });
    items
}

pub fn unresolved_reports() -> Vec<Value> {
    load_reports(false)
}

pub fn unresolved_summary_text(limit: usize, handler_session: Option<&str>) -> String {
    let items = unresolved_reports();
    if items.is_empty() {
        return String::new();
    }
    let start = items.len().saturating_sub(limit);
    let shown = &items[start..];
    let parts: Vec<String> = shown
        .iter()
        .map(|r| {
            let rid = val_to_str(r.get("id"));
            let blk = val_to_str(r.get("block"));
            format!("{} ({})", rid, truncate_chars(&blk, 60))
        })
        .collect();
    let hsess = match handler_session {
        Some(s) => s.to_string(),
        None => get_handler_session(),
    };
    let suffix = if hsess.is_empty() {
        String::new()
    } else {
        format!(" -> handler: conversation://{}", hsess)
    };
    format!(
        "[Gate Inbox] {} unresolved anomaly report(s): {}{}",
        items.len(),
        parts.join(", "),
        suffix
    )
}

pub fn unresolved_summary(handler_session: &str) -> Value {
    let hsess = if handler_session.trim().is_empty() {
        get_handler_session()
    } else {
        rio::safe_key(handler_session, "")
    };
    let items = unresolved_reports();
    let bus_items = if hsess.is_empty() {
        Vec::new()
    } else {
        unhandled_bus_reports(&hsess)
    };
    let summary = unresolved_summary_text(5, Some(&hsess));
    json!({
        "count": items.len() + bus_items.len(),
        "inbox_count": items.len(),
        "bus_count": bus_items.len(),
        "handler_session": if hsess.is_empty() { Value::Null } else { Value::String(hsess) },
        "summary": summary,
        "reports": items,
        "bus_reports": bus_items,
    })
}

fn readonly_chat_bus_db_path() -> Option<PathBuf> {
    let bus_dir = rio::stack_home().join("state").join("chat-bus");
    if !bus_dir.is_dir() {
        return None;
    }
    if let Some(Value::Object(ptr)) = rio::read_json(&bus_dir.join("snapshot_current.json")) {
        let snap_name = val_to_str(ptr.get("file")).trim().to_string();
        if bus_snapshot_re().is_match(&snap_name) {
            let snap_path = bus_dir.join(&snap_name);
            if snap_path.is_file() {
                return Some(snap_path);
            }
        }
    }
    let main_db = bus_dir.join("bus.db");
    if main_db.is_file() {
        Some(main_db)
    } else {
        None
    }
}

pub fn unhandled_bus_reports_limited(handler_session: Option<&str>, limit: usize) -> Vec<Value> {
    if limit == 0 {
        return Vec::new();
    }
    let hsess = match handler_session {
        Some(s) => rio::safe_key(s, ""),
        None => get_handler_session(),
    };
    if hsess.is_empty() {
        return Vec::new();
    }
    let Some(db_path) = readonly_chat_bus_db_path() else {
        return Vec::new();
    };
    let Ok(conn) = SqliteConn::open(&db_path, SQLITE_OPEN_READONLY) else {
        return Vec::new();
    };
    let sql = "SELECT msg_id, thread_id, from_id, from_title, body, status, created_ts \
               FROM messages WHERE to_id = ? AND status IN ('unread', 'delivered') AND acked_ts <= 0 \
               ORDER BY created_ts DESC, msg_id DESC";
    let Ok(rows) = conn.query(sql, &[SqlParam::Text(hsess)]) else {
        return Vec::new();
    };

    let mut resolved_cache: HashMap<String, bool> = HashMap::new();
    let mut newest_first: Vec<Value> = Vec::new();

    for row in rows {
        if row.len() < 7 {
            continue;
        }
        let body_s = row[4].as_str().trim().to_string();
        if !is_valid_anomaly_bus_body(&body_s) {
            continue;
        }
        let anom_ids: Vec<String> = anom_id_re()
            .find_iter(&body_s)
            .map(|m| m.as_str().to_lowercase())
            .collect();
        if !anom_ids.is_empty() {
            for aid in &anom_ids {
                if !resolved_cache.contains_key(aid) {
                    let is_res = load_report(aid)
                        .1
                        .map_or(false, |m| json_truthy(m.get("resolved")));
                    resolved_cache.insert(aid.clone(), is_res);
                }
            }
            if anom_ids
                .iter()
                .all(|aid| resolved_cache.get(aid).copied().unwrap_or(false))
            {
                continue;
            }
        }
        newest_first.push(json!({
            "msg_id": row[0].as_str(),
            "thread_id": row[1].as_str(),
            "from_id": row[2].as_str(),
            "from_title": row[3].as_str(),
            "body": body_s,
            "status": row[5].as_str(),
            "created_ts": row[6].as_f64(),
        }));
        if newest_first.len() >= limit {
            break;
        }
    }

    newest_first.reverse();
    newest_first
}

pub fn unhandled_bus_reports(handler_session: &str) -> Vec<Value> {
    unhandled_bus_reports_limited(Some(handler_session), 10)
}

pub fn format_handler_digest(limit: usize, cfg: Option<&Value>) -> String {
    let owned_cfg;
    let eff_cfg = match cfg {
        Some(c) => c,
        None => {
            owned_cfg = get_handler_config();
            &owned_cfg
        }
    };
    let hsess = get_handler_session_from_cfg(Some(eff_cfg));
    let items = unresolved_reports();
    let bus_items = if hsess.is_empty() {
        Vec::new()
    } else {
        unhandled_bus_reports_limited(Some(&hsess), limit)
    };
    if items.is_empty() && bus_items.is_empty() {
        return String::new();
    }
    let repo_hint_raw = val_to_str(eff_cfg.get("stack_repo"));
    let repo_hint = if repo_hint_raw.is_empty() {
        rio::normalize_path(&rio::plugin_root().to_string_lossy())
    } else {
        repo_hint_raw
    };
    let cs_bin = rio::normalize_path(&rio::carbon_stack_bin_path().to_string_lossy());
    let total_cnt = items.len() + bus_items.len();
    let mut lines = vec![
        format!(
            "[Gate Anomaly Handler — {} unresolved report(s)/bus message(s) awaiting root-cause fix]",
            total_cnt
        ),
        format!("Stack repo: {}", repo_hint),
    ];
    let start = items.len().saturating_sub(limit);
    for rec in &items[start..] {
        let rid = val_to_str(rec.get("id"));
        let sess = val_to_str(rec.get("session"));
        let blk_full = val_to_str(rec.get("block"));
        let blk = truncate_chars(&blk_full, 140);
        let facts_full = val_to_str(rec.get("facts"));
        let facts = truncate_chars(&facts_full, 180);
        let tp = val_to_str(rec.get("transcript"));
        let tp_part = if tp.is_empty() {
            String::new()
        } else {
            format!(" | transcript={}", tp)
        };
        lines.push(format!(
            "- {} (from session={}): block=\"{}\" | facts=\"{}\"{}",
            rid, sess, blk, facts, tp_part
        ));
    }
    for bmsg in &bus_items {
        let body = val_to_str(bmsg.get("body"));
        let collapsed: String = body.split_whitespace().collect::<Vec<&str>>().join(" ");
        let one_line = truncate_chars(&collapsed, 240);
        let msg_id = val_to_str(bmsg.get("msg_id"));
        let from_id = val_to_str(bmsg.get("from_id"));
        let from_title_full = val_to_str(bmsg.get("from_title"));
        let from_title = truncate_chars(&from_title_full, 60);
        lines.push(format!(
            "- [chat-bus {}] (from session={} \"{}\"): {}",
            msg_id, from_id, from_title, one_line
        ));
    }
    let hsess_label = if hsess.is_empty() {
        "<handler>"
    } else {
        hsess.as_str()
    };
    lines.push(format!(
        "Action: inspect `& \"{}\" gate-inbox show --id <id>` (or chat-bus message), fix root cause + add Rust test in `{}`, build release `carbon-stack.exe` + run `carbon-stack install --force`, then mark `& \"{}\" gate-inbox resolve --id <id> --note \"...\"` (and reply via `chat_bus_cli.py reply --from-chat {} --message-id <msg_id> --message \"...\"` for chat-bus reports).",
        cs_bin, repo_hint, cs_bin, hsess_label
    ));
    lines.join("\n")
}

fn discover_session_transcript(session: &str) -> String {
    if session.is_empty() || session == "unknown" {
        return String::new();
    }
    let mem_tp = rio::member_transcript_path(&rio::resolve_brain_root(""), session);
    match rio::resolve_transcript_path(&mem_tp.to_string_lossy()) {
        Some(tp) => rio::normalize_path(&tp.to_string_lossy()),
        None => String::new(),
    }
}

fn capture_session_forensics(session: &str) -> Value {
    let mut out = Map::new();
    if let Some(Value::Object(mdata)) = cwg_common::read_marker_with_pending(session) {
        let paths: Vec<Value> = mdata
            .get("paths")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().take(25).cloned().collect())
            .unwrap_or_default();
        out.insert(
            "marker".to_string(),
            json!({
                "cwd": val_to_str(mdata.get("cwd")),
                "git_root": val_to_str(mdata.get("git_root")),
                "paths": paths,
                "first_ts": mdata.get("first_ts").cloned().unwrap_or(Value::Null),
                "last_durable_ts": mdata.get("last_durable_ts").cloned().unwrap_or(Value::Null),
                "edits": mdata.get("edits").cloned().unwrap_or(Value::Null),
                "operational": json_truthy(mdata.get("operational")),
            }),
        );
    }
    let checks = rio::read_jsonl(&cwg_common::checks_ledger_path(session), Some(50));
    out.insert("checks_count".to_string(), json!(checks.len()));
    Value::Object(out)
}

fn mutate_report<F>(report_id: &str, mutator: F) -> (Option<Map<String, Value>>, &'static str)
where
    F: FnOnce(&mut Map<String, Value>) -> bool,
{
    let Some(p) = report_path(report_id) else {
        return (None, "not_found");
    };
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("report");
    let lock_path = p
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(".{}.lock", stem));
    // SAFETY: Serialize concurrent report updates (`resolve_report`) to prevent lost fields.
    rio::with_file_lock(&lock_path, 3.0, 30.0, |acquired| {
        if !acquired {
            return (None, "lock_timeout");
        }
        let Some(Value::Object(mut rec)) = rio::read_json(&p) else {
            return (None, "not_found");
        };
        if mutator(&mut rec) && rio::write_json(&p, &Value::Object(rec.clone())).is_err() {
            return (None, "write_failed");
        }
        (Some(rec), "ok")
    })
}

pub fn verify_anomaly_report(
    report_id: &str,
    session: &str,
    expected_nonce: Option<&str>,
) -> (bool, String) {
    let (p_opt, rec_opt) = load_report(report_id);
    if p_opt.is_none() {
        return (false, "invalid anomaly report id".to_string());
    }
    let Some(rec) = rec_opt else {
        return (
            false,
            format!("anomaly report '{}' does not exist in gate inbox", report_id),
        );
    };
    let rec_sess = val_to_str(rec.get("session"));
    if !rec_sess.is_empty() && rio::safe_key(&rec_sess, "default") != session {
        return (
            false,
            format!("anomaly report '{}' belongs to a different session", report_id),
        );
    }
    if let Some(exp) = expected_nonce {
        if !exp.is_empty() && val_to_str(rec.get("nonce")) != exp {
            return (
                false,
                format!(
                    "anomaly report '{}' nonce does not match the latest gate block nonce",
                    report_id
                ),
            );
        }
    }
    if val_to_str(rec.get("facts")).trim().is_empty() {
        return (
            false,
            format!(
                "anomaly report '{}' lacks verified transcript facts",
                report_id
            ),
        );
    }
    (true, val_to_str(rec.get("id")))
}

fn generate_report_id() -> String {
    let seq = REPORT_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}:{:?}", std::process::id(), now_sec(), seq).as_bytes());
    let hex_str = hex::encode(hasher.finalize());
    format!("anom-{}", &hex_str[..8])
}

pub fn file_report(
    session_arg: &str,
    nonce: &str,
    block: &str,
    facts: &str,
    did: &str,
    transcript_arg: &str,
) -> (i32, Option<Value>, Option<String>) {
    let session = rio::safe_key(session_arg, "unknown");
    let st = match rio::read_json(&cwg_common::enforcement_state_path(&session)) {
        Some(Value::Object(m)) => m,
        _ => Map::new(),
    };
    let active_nonce = val_to_str(st.get("block_nonce"));
    if !active_nonce.is_empty() && nonce != active_nonce {
        return (
            2,
            None,
            Some(format!(
                "Nonce mismatch: expected active block nonce '{}', got '{}'. An anomaly report may only be filed after at least 1 Stop block on the current candidate.\n",
                active_nonce, nonce
            )),
        );
    }
    if active_nonce.is_empty() {
        return (
            2,
            None,
            Some("Cannot file anomaly report before the gate has issued a block nonce.\n".to_string()),
        );
    }

    let report_id = generate_report_id();
    let transcript = if !transcript_arg.trim().is_empty() {
        transcript_arg.trim().to_string()
    } else {
        discover_session_transcript(&session)
    };
    let handler_sess = get_handler_session();
    let blk_trim = block.trim();
    let facts_trim = facts.trim();
    let did_trim = did.trim();
    let notified_self = if handler_sess.is_empty() {
        false
    } else {
        handler_sess == session
    };

    let record = json!({
        "id": report_id,
        "created_ts": now_sec(),
        "session": session,
        "nonce": nonce,
        "block": blk_trim,
        "facts": facts_trim,
        "did": did_trim,
        "transcript": transcript,
        "forensics": capture_session_forensics(&session),
        "handler_session": handler_sess,
        "notified_handler": notified_self,
        "resolved": false,
    });

    let Some(rpath) = report_path(&report_id) else {
        return (
            1,
            None,
            Some("Failed to resolve gate inbox report path.\n".to_string()),
        );
    };
    // SAFETY: Fail closed when `write_json` fails instead of emitting a phantom report_id.
    if let Err(e) = rio::write_json(&rpath, &record) {
        return (
            1,
            None,
            Some(format!(
                "Failed to persist anomaly report to {} ({}); CARBON_STACK_HOME is read-only or not writable in this environment.\n",
                rpath.display(),
                e
            )),
        );
    }
    rio::log_hook_event(
        "gate-events",
        "anomaly_filed",
        json!({
            "session": session,
            "report_id": report_id,
            "handler_session": handler_sess,
        }),
    );

    let mut resp = Map::new();
    resp.insert("ok".to_string(), Value::Bool(true));
    resp.insert("report_id".to_string(), Value::String(report_id.clone()));
    if !handler_sess.is_empty() && handler_sess != session {
        let msg_payload = format!(
            "[GATE_ANOMALY {}] session={}; block={}; facts={}; did={}",
            report_id,
            session,
            truncate_chars(blk_trim, 160),
            truncate_chars(facts_trim, 220),
            truncate_chars(did_trim, 160)
        );
        let bus_cli = rio::chat_bus_cli_path();
        resp.insert("handler_session".to_string(), Value::String(handler_sess.clone()));
        resp.insert(
            "handler_uri".to_string(),
            Value::String(format!("conversation://{}", handler_sess)),
        );
        resp.insert("notify_required".to_string(), Value::Bool(true));
        resp.insert(
            "send_message_payload".to_string(),
            Value::String(msg_payload.clone()),
        );
        resp.insert(
            "chat_bus_cli_hint".to_string(),
            Value::String(format!(
                "python -X utf8 \"{}\" send --from-chat \"{}\" --to \"{}\" --message \"{}\"",
                bus_cli.display(),
                session,
                handler_sess,
                msg_payload
            )),
        );
    }
    (0, Some(Value::Object(resp)), None)
}

pub fn list_reports(include_resolved: bool) -> Value {
    let rows = load_reports(include_resolved);
    let hsess = get_handler_session();
    json!({
        "count": rows.len(),
        "handler_session": if hsess.is_empty() { Value::Null } else { Value::String(hsess) },
        "reports": rows,
    })
}

pub fn show_report(report_id: &str) -> Option<Value> {
    load_report(report_id).1.map(Value::Object)
}

pub fn resolve_report(report_id: &str, note: &str, by: &str) -> (i32, Option<Value>, Option<String>) {
    let resolved_by = if !by.trim().is_empty() {
        rio::safe_key(by, "")
    } else {
        get_handler_session()
    };
    let eff_note = if note.is_empty() { "resolved" } else { note };
    let (rec_opt, status) = mutate_report(report_id, |rec| {
        rec.insert("resolved".to_string(), Value::Bool(true));
        rec.insert("resolved_ts".to_string(), json!(now_sec()));
        rec.insert(
            "resolved_by".to_string(),
            Value::String(resolved_by.clone()),
        );
        rec.insert(
            "resolution_note".to_string(),
            Value::String(eff_note.to_string()),
        );
        true
    });
    let Some(rec) = rec_opt else {
        let msg = if status == "not_found" {
            format!("Report not found: {}\n", report_id)
        } else {
            format!("Failed to update report ({}): {}\n", status, report_id)
        };
        return (1, None, Some(msg));
    };
    let rid = val_to_str(rec.get("id"));
    let rby = val_to_str(rec.get("resolved_by"));
    rio::log_hook_event(
        "gate-events",
        "anomaly_resolved",
        json!({
            "report_id": rid,
            "resolved_by": rby,
        }),
    );
    (
        0,
        Some(json!({
            "ok": true,
            "id": rid,
            "resolved_by": rby,
        })),
        None,
    )
}

fn parse_flag_value<'a>(args: &'a [String], idx: &mut usize, flag: &str) -> Option<&'a str> {
    let cur = &args[*idx];
    if cur == flag {
        if *idx + 1 < args.len() {
            *idx += 1;
            return Some(args[*idx].as_str());
        }
        return None;
    }
    if let Some(rest) = cur.strip_prefix(&format!("{}=", flag)) {
        return Some(rest);
    }
    None
}

pub fn run_cli(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln_str("gate_inbox: missing subcommand (report|list|show|resolve|set-handler|handler)\n");
        return 2;
    }
    let cmd = args[0].as_str();
    let rest = &args[1..];
    match cmd {
        "report" => {
            let mut session = String::new();
            let mut nonce = String::new();
            let mut block = String::new();
            let mut facts = String::new();
            let mut did = String::new();
            let mut transcript = String::new();
            let mut has_session = false;
            let mut has_nonce = false;
            let mut has_block = false;
            let mut has_facts = false;
            let mut has_did = false;

            let mut i = 0;
            while i < rest.len() {
                if let Some(v) = parse_flag_value(rest, &mut i, "--session") {
                    session = v.to_string();
                    has_session = true;
                } else if let Some(v) = parse_flag_value(rest, &mut i, "--nonce") {
                    nonce = v.to_string();
                    has_nonce = true;
                } else if let Some(v) = parse_flag_value(rest, &mut i, "--block") {
                    block = v.to_string();
                    has_block = true;
                } else if let Some(v) = parse_flag_value(rest, &mut i, "--facts") {
                    facts = v.to_string();
                    has_facts = true;
                } else if let Some(v) = parse_flag_value(rest, &mut i, "--did") {
                    did = v.to_string();
                    has_did = true;
                } else if let Some(v) = parse_flag_value(rest, &mut i, "--transcript") {
                    transcript = v.to_string();
                } else {
                    eprintln_str(&format!("gate_inbox report: unrecognized argument '{}'\n", rest[i]));
                    return 2;
                }
                i += 1;
            }
            if !has_session || !has_nonce || !has_block || !has_facts || !has_did {
                eprintln_str(
                    "gate_inbox report: --session, --nonce, --block, --facts, and --did are required\n",
                );
                return 2;
            }
            let (rc, out, err) = file_report(&session, &nonce, &block, &facts, &did, &transcript);
            if let Some(e) = err {
                eprintln_str(&e);
            }
            if let Some(v) = out {
                rio::print_cli_json(&v, false);
            }
            rc
        }
        "list" => {
            let mut all = false;
            for arg in rest {
                if arg == "--all" {
                    all = true;
                } else {
                    eprintln_str(&format!("gate_inbox list: unrecognized argument '{}'\n", arg));
                    return 2;
                }
            }
            rio::print_cli_json(&list_reports(all), true);
            0
        }
        "show" => {
            let mut id = String::new();
            let mut has_id = false;
            let mut i = 0;
            while i < rest.len() {
                if let Some(v) = parse_flag_value(rest, &mut i, "--id") {
                    id = v.to_string();
                    has_id = true;
                } else {
                    eprintln_str(&format!("gate_inbox show: unrecognized argument '{}'\n", rest[i]));
                    return 2;
                }
                i += 1;
            }
            if !has_id {
                eprintln_str("gate_inbox show: --id is required\n");
                return 2;
            }
            match show_report(&id) {
                Some(rec) => {
                    rio::print_cli_json(&rec, true);
                    0
                }
                None => {
                    eprintln_str(&format!("Report not found: {}\n", id));
                    1
                }
            }
        }
        "resolve" => {
            let mut id = String::new();
            let mut note = String::new();
            let mut by = String::new();
            let mut has_id = false;
            let mut i = 0;
            while i < rest.len() {
                if let Some(v) = parse_flag_value(rest, &mut i, "--id") {
                    id = v.to_string();
                    has_id = true;
                } else if let Some(v) = parse_flag_value(rest, &mut i, "--note") {
                    note = v.to_string();
                } else if let Some(v) = parse_flag_value(rest, &mut i, "--by") {
                    by = v.to_string();
                } else {
                    eprintln_str(&format!("gate_inbox resolve: unrecognized argument '{}'\n", rest[i]));
                    return 2;
                }
                i += 1;
            }
            if !has_id {
                eprintln_str("gate_inbox resolve: --id is required\n");
                return 2;
            }
            let (rc, out, err) = resolve_report(&id, &note, &by);
            if let Some(e) = err {
                eprintln_str(&e);
            }
            if let Some(v) = out {
                rio::print_cli_json(&v, false);
            }
            rc
        }
        "set-handler" => {
            let mut session = String::new();
            let mut repo = String::new();
            let mut clear = false;
            let mut i = 0;
            while i < rest.len() {
                if rest[i] == "--clear" {
                    clear = true;
                } else if let Some(v) = parse_flag_value(rest, &mut i, "--session") {
                    session = v.to_string();
                } else if let Some(v) = parse_flag_value(rest, &mut i, "--repo") {
                    repo = v.to_string();
                } else {
                    eprintln_str(&format!("gate_inbox set-handler: unrecognized argument '{}'\n", rest[i]));
                    return 2;
                }
                i += 1;
            }
            let res = set_handler_config(&session, &repo, clear);
            let ok = json_truthy(res.get("ok"));
            rio::print_cli_json(&res, false);
            if ok { 0 } else { 2 }
        }
        "handler" => {
            if !rest.is_empty() {
                eprintln_str(&format!("gate_inbox handler: unrecognized argument '{}'\n", rest[0]));
                return 2;
            }
            let mut out = match get_handler_config() {
                Value::Object(m) => m,
                _ => Map::new(),
            };
            let configured = !val_to_str(out.get("handler_session")).is_empty();
            out.insert("configured".to_string(), Value::Bool(configured));
            rio::print_cli_json(&Value::Object(out), true);
            0
        }
        other => {
            eprintln_str(&format!("gate_inbox: unknown subcommand '{}'\n", other));
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::win32_sqlite::SQLITE_OPEN_CREATE;
    use crate::win32_sqlite::SQLITE_OPEN_READWRITE;

    #[test]
    fn test_all_regexes_compile() {
        assert!(bus_snapshot_re().is_match("snapshot-0123456789ab-202611170000-deadbeef.db"));
        assert!(!bus_snapshot_re().is_match("bus.db"));
        assert!(bus_non_anomaly_prefix_re().is_match("  [TASK_DONE] ok"));
        assert!(bus_non_anomaly_prefix_re().is_match("[LOCK_RELEASED] done"));
        assert!(bus_non_anomaly_prefix_re().is_match("[COORDINATION] note"));
        assert!(bus_non_anomaly_prefix_re().is_match("[HANDOFF_ACK] ok"));
        assert!(bus_resolved_prefix_re().is_match("[ANOMALY_RESOLVED] fixed"));
        assert!(bus_resolved_prefix_re().is_match("[REPORT_RESOLVED] fixed"));
        assert!(has_explicit_anomaly_tag("[HANDOFF] [GATE_ANOMALY anom-1234abcd] fail"));
        assert!(!has_explicit_anomaly_tag("[HANDOFF] [ANOMALY_RESOLVED] anom-1234abcd"));
        assert!(is_valid_anomaly_bus_body("[GATE_ANOMALY anom-1234abcd] fail"));
        assert!(is_valid_anomaly_bus_body("deadlock in worker"));
        assert!(is_valid_anomaly_bus_body("Обнаружена аномалия"));
        assert!(!is_valid_anomaly_bus_body("[REPORT_RESOLVED] anom-1234abcd"));
        assert!(!is_valid_anomaly_bus_body("[NEON_DONE] anom-1234abcd"));
        assert!(anom_id_re().is_match("see anom-deadbeef for details"));
    }

    #[test]
    fn test_unhandled_bus_reports_filters_status_prefixes_and_resolved() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp_dir = std::env::temp_dir().join(format!("gate-inbox-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(tmp_dir.join("state").join("chat-bus")).unwrap();
        let prev = std::env::var_os("CARBON_STACK_HOME");
        std::env::set_var("CARBON_STACK_HOME", &tmp_dir);

        let handler_id = "handler-test-01";
        let set_res = set_handler_config(handler_id, "", false);
        assert_eq!(set_res["ok"], json!(true));

        let db_path = tmp_dir.join("state").join("chat-bus").join("bus.db");
        {
            let conn = SqliteConn::open(&db_path, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE).unwrap();
            conn.exec_batch(
                "CREATE TABLE messages (\
                    msg_id TEXT PRIMARY KEY, thread_id TEXT, from_id TEXT, from_title TEXT, \
                    to_id TEXT, body TEXT, status TEXT, acked_ts REAL, created_ts REAL\
                 );",
            )
            .unwrap();

            let rows = [
                ("m-done", "t1", "w1", "W1", handler_id, "[TASK_DONE] anom-aaaaaa11 done", "delivered", 0.0, 10.0),
                ("m-ndone", "t1", "w1", "W1", handler_id, "[NEON_DONE] pushed main; you can land anom-693fb707", "delivered", 0.0, 10.5),
                ("m-nstart", "t1", "w1", "W1", handler_id, "[NEON_STARTED] starting after anom-693fb707", "delivered", 0.0, 10.6),
                ("m-info", "t1", "w1", "W1", handler_id, "[INFO / READY] gate ready anom-693fb707", "delivered", 0.0, 10.7),
                ("m-lock", "t1", "w1", "W1", handler_id, "[LOCK_RELEASED] bug cleared", "delivered", 0.0, 11.0),
                ("m-coord", "t1", "w1", "W1", handler_id, "[COORDINATION] deadlock check", "delivered", 0.0, 12.0),
                ("m-hack", "t1", "w1", "W1", handler_id, "[HANDOFF_ACK] cwg_stop ok", "delivered", 0.0, 13.0),
                ("m-ares", "t1", "w1", "W1", handler_id, "[ANOMALY_RESOLVED] anom-bbbbbb22", "delivered", 0.0, 14.0),
                ("m-rres", "t1", "w1", "W1", handler_id, "[REPORT_RESOLVED] anom-bbbbbb22", "delivered", 0.0, 14.2),
                ("m-bres", "t1", "w1", "W1", handler_id, "[BUG_RESOLVED] anom-bbbbbb22", "delivered", 0.0, 14.3),
                ("m-hares", "t1", "w1", "W1", handler_id, "[HANDOFF] [ANOMALY_RESOLVED] anom-bbbbbb22", "delivered", 0.0, 14.5),
                ("m-hrres", "t1", "w1", "W1", handler_id, "[HANDOFF] [REPORT_RESOLVED] anom-bbbbbb22", "delivered", 0.0, 14.7),
                ("m-acked", "t1", "w1", "W1", handler_id, "[GATE_ANOMALY anom-cccccc33] acked", "delivered", 50.0, 15.0),
                ("m-real", "t2", "w2", "Cross-Chat", handler_id, "[ANOMALY REPORT] cwg_stop blocked unexpectedly", "unread", 0.0, 16.0),
                ("m-handoff-anom", "t3", "w3", "Peer", handler_id, "[HANDOFF] [GATE_ANOMALY anom-1234abcd] cwg_stop blocked unexpectedly", "unread", 0.0, 17.0),
                ("m-handoff-rep", "t4", "w4", "Peer2", handler_id, "[HANDOFF] [REPORT anom-5678efab] cwg_stop blocked unexpectedly", "unread", 0.0, 18.0),
            ];
            for (mid, tid, fid, ft, to, body, st, ack, ts) in rows {
                conn.execute(
                    "INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    &[
                        SqlParam::Text(mid.to_string()),
                        SqlParam::Text(tid.to_string()),
                        SqlParam::Text(fid.to_string()),
                        SqlParam::Text(ft.to_string()),
                        SqlParam::Text(to.to_string()),
                        SqlParam::Text(body.to_string()),
                        SqlParam::Text(st.to_string()),
                        SqlParam::Float(ack),
                        SqlParam::Float(ts),
                    ],
                )
                .unwrap();
            }
        }

        let got = unhandled_bus_reports(handler_id);
        assert_eq!(got.len(), 3);
        assert_eq!(got[0]["msg_id"], json!("m-real"));
        assert_eq!(got[1]["msg_id"], json!("m-handoff-anom"));
        assert_eq!(got[2]["msg_id"], json!("m-handoff-rep"));
        let digest = format_handler_digest(10, None);
        assert!(digest.contains("m-real"));
        assert!(digest.contains("m-handoff-anom"));
        assert!(digest.contains("m-handoff-rep"));
        let summary = unresolved_summary(handler_id);
        assert_eq!(summary["bus_count"], json!(3));

        match prev {
            Some(v) => std::env::set_var("CARBON_STACK_HOME", v),
            None => std::env::remove_var("CARBON_STACK_HOME"),
        }
        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_resolve_report_fails_closed_on_lock_timeout() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp_dir = std::env::temp_dir().join(format!("gate-inbox-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp_dir);
        let prev = std::env::var_os("CARBON_STACK_HOME");
        std::env::set_var("CARBON_STACK_HOME", &tmp_dir);

        let inbox = inbox_dir();
        let rid = "anom-deadbeef";
        let rpath = inbox.join(format!("{}.json", rid));
        rio::write_json(
            &rpath,
            &json!({"id": rid, "resolved": false, "session": "s1", "facts": "verified"}),
        )
        .unwrap();
        let lock_file = inbox.join(format!(".{}.lock", rid));
        fs::write(&lock_file, "contended\n").unwrap();

        let (code, val, err) = resolve_report(rid, "note", "handler");
        assert_eq!(code, 1);
        assert!(val.is_none());
        assert!(err.unwrap_or_default().contains("lock_timeout"));
        let after = rio::read_json(&rpath).unwrap();
        assert_eq!(after["resolved"], json!(false));

        match prev {
            Some(v) => std::env::set_var("CARBON_STACK_HOME", v),
            None => std::env::remove_var("CARBON_STACK_HOME"),
        }
        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_is_valid_anomaly_bus_body_strips_status_tags() {
        // INVARIANT: Leading non-anomaly bracket tags (`[REPORT_DONE]`, `[NEON_DONE]`) must not misclassify routine bus traffic as anomaly reports unless followed by `[GATE_ANOMALY ...]` or `anom-<hex>`.
        assert!(!is_valid_anomaly_bus_body("[REPORT_DONE] routine handoff note"));
        assert!(!is_valid_anomaly_bus_body("[NEON_DONE] completed build"));
        assert!(is_valid_anomaly_bus_body(
            "[REPORT_DONE] [GATE_ANOMALY anom-123456] session=s1; block=test"
        ));
        assert!(is_valid_anomaly_bus_body(
            "Escalating anom-abcdef01 from worker chat"
        ));
    }
}
