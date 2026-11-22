use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use crate::codex_lane;
use crate::cwg_common;
use crate::cwg_mark;
use crate::gate_inbox;
use crate::rio::{self, json_truthy, subagent_msg_re, truncate_chars, val_to_f64, val_to_i64, val_to_str};
use crate::codex_lane::{NATIVE_REVIEWERS, XHIGH_NATIVE_REVIEWER};
use crate::cwg_mark::{EDIT_TOOLS, SHELL_TOOLS};
use crate::win32_sqlite::now_sec;

pub const MAX_BLOCKS_PER_CANDIDATE: i64 = 3;
pub const MAX_BACKGROUND_WAITS: i64 = 8;
pub const MAX_TOTAL_BACKGROUND_WAITS: i64 = 16;
pub const MAX_REVIEW_ROUNDS: usize = cwg_common::MAX_ORDINARY_REVIEW_ROUNDS;
pub const LEGACY_MAX_REVIEW_ROUNDS: usize = 3;
pub const MAX_RAW_ORDINARY_ROUNDS: usize = MAX_REVIEW_ROUNDS * 2;
pub const MAX_CLOSURE_PASSES: usize = cwg_common::MAX_CLOSURE_PASSES_PER_CYCLE;
pub const MAX_WORKER_POST_REMINDERS: i64 = 2;
const CLOSURE_PHASE_FLAG: &str = "--phase closure";
use crate::cwg_common::TS_EPS;

static NONCE_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
enum WorkerModelEvent {
    ConfirmedAdd { ts: f64, ord: usize, model: String },
    ConfirmedSwitch {
        req_ts: f64,
        done_ts: f64,
        done_ub: f64,
        ord: usize,
        model: String,
    },
    UnconfirmedSwitch { req_ts: f64, ord: usize },
}

// INVARIANT: Across warm worker `action="model"` switches, resolve each raw timestamp against confirmed intervals; fail closed on missing timestamps, in-flight or overlapping switches, unconfirmed switches, or same-second collisions, and recover after a subsequent confirmed switch.
#[derive(Debug, Clone, Copy, Default)]
struct ParsedTs {
    ts: f64,
    coarse: bool,
}

fn parse_iso_ts_meta(raw: &str) -> ParsedTs {
    let ts = rio::parse_iso_ts(raw);
    if ts <= 0.0 {
        return ParsedTs::default();
    }
    ParsedTs {
        ts,
        coarse: cwg_common::iso_ts_is_coarse(raw),
    }
}

fn switch_ts_any(
    model_events: &[WorkerModelEvent],
    include_done_ub: bool,
    pred: impl Fn(f64) -> bool,
) -> bool {
    model_events.iter().any(|e| match e {
        WorkerModelEvent::ConfirmedSwitch {
            req_ts,
            done_ts,
            done_ub,
            ..
        } => {
            (*req_ts > 0.0 && pred(*req_ts))
                || (*done_ts > 0.0 && pred(*done_ts))
                || (include_done_ub && *done_ub > 0.0 && pred(*done_ub))
        }
        WorkerModelEvent::UnconfirmedSwitch { req_ts, .. } => *req_ts > 0.0 && pred(*req_ts),
        WorkerModelEvent::ConfirmedAdd { .. } => false,
    })
}

fn launch_ts_or_start(win_ts: f64, start_ts: f64, first_ts: f64) -> f64 {
    if win_ts > 0.0 {
        win_ts
    } else if start_ts > 0.0 {
        start_ts
    } else {
        first_ts
    }
}

fn resolve_window_model(
    model_events: &[WorkerModelEvent],
    cur_model: &str,
    has_any_switch: bool,
    raw_ts: f64,
    coarse_ts: bool,
) -> String {
    if !has_any_switch {
        return cur_model.to_string();
    }
    if raw_ts <= 0.0 {
        return String::new();
    }
    if coarse_ts
        && switch_ts_any(model_events, false, |t| {
            t >= raw_ts - TS_EPS && t < raw_ts + 1.0 - TS_EPS
        })
    {
        return String::new();
    }
    let inflight_at_ts = model_events.iter().any(|e| match e {
        WorkerModelEvent::ConfirmedSwitch { req_ts, done_ub, .. } => {
            *req_ts <= raw_ts + TS_EPS && (*done_ub <= 0.0 || raw_ts < *done_ub - TS_EPS)
        }
        _ => false,
    });
    if inflight_at_ts {
        return String::new();
    }
    let mut best: Option<(f64, f64, u8, usize, String)> = None;
    for e in model_events {
        match e {
            WorkerModelEvent::UnconfirmedSwitch { .. } => {}
            WorkerModelEvent::ConfirmedAdd { ts, ord, model } => {
                if *ts <= raw_ts + TS_EPS {
                    let cand = (*ts, *ts, 0u8, *ord, model.clone());
                    if best.as_ref().map_or(true, |b| {
                        cand.0 > b.0 + TS_EPS
                            || ((cand.0 - b.0).abs() <= TS_EPS && (cand.2, cand.3) > (b.2, b.3))
                    }) {
                        best = Some(cand);
                    }
                }
            }
            WorkerModelEvent::ConfirmedSwitch {
                req_ts,
                done_ts,
                done_ub,
                ord,
                model,
            } => {
                // INVARIANT: Gate admissibility on conservative `done_ub` (failing closed across
                // coarse whole-second `DONE` intervals), while ranking completed switches by
                // `(done_ts, req_ts, ord)` so an earlier coarse switch never outranks a strictly
                // later exact switch once both have finished.
                if *done_ub > 0.0 && *done_ub <= raw_ts + TS_EPS {
                    let cand = (*done_ts, *req_ts, 1u8, *ord, model.clone());
                    if best.as_ref().map_or(true, |b| {
                        cand.0 > b.0 + TS_EPS
                            || ((cand.0 - b.0).abs() <= TS_EPS
                                && (cand.1 > b.1 + TS_EPS
                                    || ((cand.1 - b.1).abs() <= TS_EPS
                                        && (cand.2, cand.3) > (b.2, b.3))))
                    }) {
                        best = Some(cand);
                    }
                }
            }
        }
    }
    let Some((win_end, win_start, win_kind, win_ord, win_mdl)) = best else {
        return String::new();
    };
    if win_mdl.is_empty() {
        return String::new();
    }
    // INVARIANT: Recovery from any `UnconfirmedSwitch` (including an untimestamped one with
    // `u_ts == 0.0`) requires a strictly later transcript event (`win_ord > u_ord`) that is a
    // confirmed timestamped switch whose interval does not precede `u_ts`.
    let has_unrecovered_unconf = model_events.iter().any(|e| match e {
        WorkerModelEvent::UnconfirmedSwitch {
            req_ts: u_ts,
            ord: u_ord,
        } if *u_ts <= raw_ts + TS_EPS => {
            !(win_kind == 1
                && win_ord > *u_ord
                && win_end >= *u_ts - TS_EPS
                && win_start >= *u_ts - TS_EPS)
        }
        _ => false,
    });
    if has_unrecovered_unconf {
        return String::new();
    }
    // INVARIANT: Any other already-completed switch (`done_ub <= raw_ts`) that appeared strictly
    // later in transcript order (`ord > win_ord`) or started strictly after `win_start` renders
    // the winning model epoch ambiguous (including when a later coarse switch has `done_ts <= win_end`).
    let ambiguous_overlap = model_events.iter().any(|e| match e {
        WorkerModelEvent::ConfirmedSwitch {
            req_ts,
            done_ub,
            ord,
            ..
        } if *ord != win_ord => {
            *done_ub > 0.0
                && *done_ub <= raw_ts + TS_EPS
                && (*ord > win_ord || *req_ts > win_start + TS_EPS)
        }
        _ => false,
    });
    if ambiguous_overlap {
        return String::new();
    }
    win_mdl
}

fn parse_quota_pct(quotas: &Map<String, Value>, model: &str) -> Option<f64> {
    let qv = quotas.get(model)?.get("quota_remaining")?;
    if let Some(n) = qv.as_f64() {
        return n.is_finite().then_some(n);
    }
    let s = qv.as_str()?.trim();
    let num = s.strip_suffix('%').unwrap_or(s).trim();
    num.parse::<f64>().ok().filter(|n| n.is_finite())
}

fn quota_exhausted(quotas: &Map<String, Value>, model: &str) -> bool {
    parse_quota_pct(quotas, model).is_some_and(|pct| pct <= 0.0)
}

fn quota_positive(quotas: &Map<String, Value>, model: &str) -> bool {
    parse_quota_pct(quotas, model).is_some_and(|pct| pct > 0.0)
}

fn max_into(slot: &mut f64, val: f64) {
    *slot = (*slot).max(val);
}

fn board_ts_upper_bound(bts: f64, coarse: bool) -> f64 {
    if bts <= 0.0 {
        0.0
    } else if coarse {
        bts.floor() + 1.0
    } else {
        bts + TS_EPS
    }
}

fn reset_sticky_issue_state(state: &mut Map<String, Value>) {
    for prefix in ["sonnet", "neon", "hydrogen", "opus"] {
        state.insert(format!("{}_issue_verified", prefix), Value::Bool(false));
        state.insert(format!("{}_issue_ts", prefix), json!(0.0));
    }
    for prefix in ["sonnet", "neon", "hydrogen"] {
        state.insert(format!("{}_last_issue_ts", prefix), json!(0.0));
        state.insert(format!("{}_healthy_ts", prefix), json!(0.0));
    }
}

pub(crate) fn subagent_uri_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?s)"conversationId"\s*:\s*"(?P<cid>[A-Za-z0-9._-]{4,80})"(?:.*?"logAbsoluteUri"\s*:\s*"(?P<uri>file:///[^"]+)")?"#,
        )
        .expect("subagent_uri_re")
    })
}

fn sys_msg_close_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\s*</SYSTEM_MESSAGE>\s*\z").expect("sys_msg_close_re"))
}

fn system_swarm_err_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)\[Message\]\s+timestamp=(?P<ts>\S+)\s+sender=system\b[^\n]*Swarm Worker \((?P<name>[A-Za-z0-9._-]+)\)[^\n]*with id "(?P<cid>[A-Za-z0-9._-]+)" encountered an error[^\n]*?:\s*(?P<err>.+)"#,
        )
        .expect("system_swarm_err_re")
    })
}

fn model_failure_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:RESOURCE_EXHAUSTED|(?:out\s+of|insufficient|no)\s+quota|quota[^\n]{0,30}(?:exceeded|exhausted|reached|depleted|0%)|rate[ _-]limit|429\b|503\b|502\b|model[^\n]{0,40}(?:unavailable|at\s+capacity|not\s+found|not\s+supported|invalid|unknown)|(?:unknown|invalid|unsupported)\s+model|overloaded|not\s+eligible|internal\s+server\s+error|deadline[ _-]exceeded|timed?\s*out)",
        )
        .expect("model_failure_re")
    })
}

fn trailing_digits_suffix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"-\d+\z").expect("trailing_digits_suffix_re"))
}

fn sanitize_ps_arg_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"[`'"$\\\r\n]+"#).expect("sanitize_ps_arg_re"))
}

fn risk_order(risk: &str) -> i32 {
    match risk.to_uppercase().as_str() {
        "LOW" => 0,
        "STANDARD" => 1,
        "HIGH" => 2,
        "XHIGH" => 3,
        _ => -1,
    }
}

fn generate_nonce_hex12() -> String {
    let seq = NONCE_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}:{}", std::process::id(), now_sec(), seq).as_bytes());
    hex::encode(hasher.finalize())[..12].to_string()
}

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push(((h << 4) | l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn clean_lexical_path(p: &Path) -> PathBuf {
    rio::resolve_abs_path(p)
}

pub fn uri_to_path(uri: &str) -> String {
    let Some(rest) = uri.strip_prefix("file:///") else {
        return uri.to_string();
    };
    let parsed = percent_decode(rest);
    #[cfg(windows)]
    {
        let bytes = parsed.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' {
            return clean_lexical_path(Path::new(&parsed.replace('/', "\\")))
                .to_string_lossy()
                .into_owned();
        }
        clean_lexical_path(Path::new(&format!("\\{}", parsed.replace('/', "\\"))))
            .to_string_lossy()
            .into_owned()
    }
    #[cfg(not(windows))]
    {
        clean_lexical_path(Path::new(&format!("/{}", parsed)))
            .to_string_lossy()
            .into_owned()
    }
}

pub fn catch_up_unmeasured_changes(marker: &Value) -> Value {
    catch_up_unmeasured_changes_at(marker, None)
}

pub fn catch_up_unmeasured_changes_at(marker: &Value, at_ts: Option<f64>) -> Value {
    let dpaths = cwg_common::durable_paths_from_val(marker.get("paths"));
    if dpaths.is_empty() {
        return marker.clone();
    }
    let now_fp = cwg_common::content_fingerprint(&dpaths, cwg_common::MAX_FINGERPRINT_FILE_BYTES);
    let now_fp_opt = if now_fp.is_empty() {
        None
    } else {
        Some(now_fp.as_str())
    };
    let mut marks: Vec<Value> = marker
        .get("content_marks")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let last_fp_opt = cwg_common::last_mark_fp(marker);

    if now_fp_opt != last_fp_opt {
        let raw_now = at_ts.unwrap_or_else(now_sec);
        let prev_dur = val_to_f64(marker.get("last_durable_ts"));
        let prev_last = val_to_f64(marker.get("last_ts"));
        let prev_first = val_to_f64(marker.get("first_ts"));
        let max_mark_ts = marks
            .iter()
            .map(|m| val_to_f64(m.get("ts")))
            .fold(0.0_f64, f64::max);
        let now = raw_now
            .max(prev_dur)
            .max(prev_last)
            .max(prev_first)
            .max(max_mark_ts);
        let fp_str = now_fp;
        let fp_val = if fp_str.is_empty() {
            Value::Null
        } else {
            Value::String(fp_str.clone())
        };
        marks.push(json!({
            "ts": now,
            "fp": fp_val,
            "cause": "stop_catchup_unmeasured_edit",
        }));
        let mut updated = marker.clone();
        cwg_common::trim_content_marks(&mut updated, marks);
        if let Some(obj) = updated.as_object_mut() {
            obj.insert("last_durable_ts".to_string(), json!(now));
            obj.insert("last_ts".to_string(), json!(now));
            obj.insert("current_diff_hash".to_string(), Value::String(fp_str));
        }
        return updated;
    }
    if !marks.is_empty() && val_to_str(marker.get("current_diff_hash")) != now_fp {
        let mut updated = marker.clone();
        if let Some(obj) = updated.as_object_mut() {
            obj.insert("current_diff_hash".to_string(), Value::String(now_fp));
        }
        return updated;
    }
    marker.clone()
}

fn kept_commit_blocker(root: &str, start: &str, since_ts: f64) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"^(?:commit(?: \((?:amend|initial|merge)\))?|cherry-pick|revert|am|rebase(?: -i)? \((?:pick|continue|reword|squash|fixup|edit)\)|(?:merge|pull)\b[^:]*: Merge made)").expect("made_here_commit_re"));
    let (rc, out, _) = rio::run_git(root, &["reflog", "show", "--date=unix", "--format=%H %gd %gs", "HEAD"], 3.0);
    if rc != 0 { return None; }
    let since_sec = since_ts.floor() as i64;
    let mut made = Vec::new();
    for line in out.lines() {
        let mut sp = line.splitn(3, ' ');
        let (Some(c), Some(sel), Some(subj)) = (sp.next(), sp.next(), sp.next()) else { continue; };
        let ok_t = sel.split_once("@{").and_then(|(_, r)| r.strip_suffix('}')).and_then(|d| d.parse::<i64>().ok()).is_some_and(|t| t + 1 >= since_sec);
        if ok_t && c != start && re.is_match(subj) && !made.contains(&c) { made.push(c); }
    }
    if made.len() > 50 { return Some("more than 50 commits were made since the candidate opened to check where they went".into()); }
    if made.is_empty() { return None; }
    let mut ra = vec!["rev-list"]; ra.extend_from_slice(&made); ra.extend(["--not", start]);
    let (rc_rl, rl, _) = rio::run_git(root, &ra, 3.0);
    if rc_rl != 0 { return None; }
    let fresh: HashSet<&str> = rl.split_whitespace().collect();
    let has_c: Vec<String> = made.into_iter().filter(|c| fresh.contains(c)).map(|c| format!("--contains={}", c)).collect();
    if has_c.is_empty() { return None; }
    let mut fa = vec!["for-each-ref", "--format=%(refname)"];
    fa.extend(has_c.iter().map(String::as_str)); fa.extend(["refs/heads/", "refs/remotes/"]);
    let (rc_f, refs, _) = rio::run_git(root, &fa, 3.0);
    if rc_f != 0 { return Some("git for-each-ref failed while verifying undone commits".into()); }
    let names: Vec<&str> = refs.split_whitespace().filter(|n| !n.is_empty()).collect();
    if let Some(loc) = names.iter().find(|n| !n.starts_with("refs/remotes/")) { return Some(format!("a commit made while the candidate was open is still on {}", loc)); }
    names.first().map(|&r0| format!("a commit made while the candidate was open was pushed ({})", names.iter().copied().find(|n| !n.ends_with("/HEAD")).unwrap_or(r0)))
}

pub fn candidate_restored_to_clean_head(marker: &Value) -> (bool, String) {
    let dpaths = cwg_common::durable_paths_from_val(marker.get("paths"));
    if dpaths.is_empty() {
        return (true, String::new());
    }
    let git_root = val_to_str(marker.get("git_root"));
    if git_root.is_empty() || !Path::new(&git_root).is_dir() {
        return (
            false,
            "outside git repository, durable edits cannot be proven restored".to_string(),
        );
    }
    let mut args: Vec<&str> = Vec::with_capacity(3 + dpaths.len());
    args.push("status");
    args.push("--porcelain=v1");
    args.push("--");
    for p in &dpaths {
        args.push(p.as_str());
    }
    let (rc, out, _) = rio::run_git(&git_root, &args, 4.0);
    if rc != 0 {
        return (
            false,
            "git status failed while checking restoration".to_string(),
        );
    }
    if !out.trim().is_empty() {
        let dirty_names: Vec<String> = dpaths
            .iter()
            .take(3)
            .map(|p| {
                p.rsplit(['/', '\\'])
                    .next()
                    .unwrap_or(p.as_str())
                    .to_string()
            })
            .collect();
        return (
            false,
            format!(
                "durable candidate files remain modified in working tree ({})",
                dirty_names.join(", ")
            ),
        );
    }
    let oh = val_to_str(marker.get("opening_head"));
    if !oh.is_empty() {
        let ch = rio::git_head_oid(&git_root);
        if ch.is_empty() || ch != oh { return (false, "HEAD moved away from opening commit; candidate commits remain active".into()); }
        if let Some(why) = kept_commit_blocker(&git_root, &oh, val_to_f64(marker.get("first_ts"))) { return (false, why); }
    }
    (true, String::new())
}

#[derive(Debug, Clone, Default)]
pub struct ChecksEvidence {
    pub checks_count: usize,
    pub passed_count: usize,
    pub failed_count: usize,
    pub latest_pass_ts: f64,
    pub latest_fail_ts: f64,
    pub saw_uncertain_pass: bool,
}

impl ChecksEvidence {
    fn record_outcome(&mut self, passed: bool, ts: f64) {
        self.checks_count += 1;
        if passed {
            self.passed_count += 1;
            if ts > self.latest_pass_ts {
                self.latest_pass_ts = ts;
            }
        } else {
            self.failed_count += 1;
            if ts > self.latest_fail_ts {
                self.latest_fail_ts = ts;
            }
        }
    }
}

fn host_bg_task_sys_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?s)\A\s*(?:The following is a <SYSTEM_MESSAGE>[^\r\n]*\r?\n\s*)*(?:<SYSTEM_MESSAGE>\s*\r?\n\s*)?\[Message\]\s+timestamp=(?P<ts>\S+)\s+sender=(?P<sender>\S+)(?:\s+priority=\S+)?\s+content=Task id "(?P<tid>[^"]+)"\s+(?P<kind>finished with result:|was canceled)"#,
        )
        .expect("host_bg_task_sys_re")
    })
}

fn parse_host_bg_task_sys_msg(sys_txt: &str, fallback_ts: f64) -> Option<(String, bool, f64)> {
    // INVARIANT: Anchor background task completion parsing to the single host `[Message]` header at `\A` and require `sender == tid` so task `Command output:` cannot spoof another pending task's completion.
    let caps = host_bg_task_sys_re().captures(sys_txt)?;
    let whole = caps.get(0)?;
    let sender = caps.name("sender")?.as_str();
    let tid = caps.name("tid")?.as_str();
    if sender != tid {
        return None;
    }
    let parsed_ts = rio::parse_iso_ts(caps.name("ts")?.as_str());
    let eff_ts = if parsed_ts > 0.0 {
        parsed_ts
    } else {
        fallback_ts
    };
    if caps.name("kind")?.as_str() == "was canceled" {
        return Some((tid.to_string(), false, eff_ts));
    }
    let after = &sys_txt[whole.end()..];
    let end_sys = after.find("</SYSTEM_MESSAGE>").unwrap_or(after.len());
    let task_slice = &after[..end_sys];
    let passed = cwg_common::parse_host_command_exit_code(task_slice) == Some(0);
    Some((tid.to_string(), passed, eff_ts))
}

fn pass_credit_ts(start_ts: f64, fallback_ts: f64, first_ts: f64) -> Option<f64> {
    if start_ts > 0.0 {
        (start_ts >= first_ts - 1.0).then_some(start_ts)
    } else {
        (fallback_ts >= first_ts - 1.0).then_some(0.0)
    }
}

fn resolve_ledger_start_ts(
    rec: &Value,
    s_idx: Option<i64>,
    step_start_ts: &HashMap<i64, f64>,
) -> f64 {
    let rec_start = val_to_f64(rec.get("start_ts"));
    if rec_start > 0.0 {
        rec_start
    } else {
        s_idx
            .and_then(|si| step_start_ts.get(&si).copied())
            .unwrap_or(0.0)
    }
}

fn handle_bg_check_sys_step(
    st: &Value,
    first_ts: f64,
    pending_bg_checks: &mut HashMap<String, (String, f64, bool)>,
    completed_bg_checks: &mut Vec<(bool, f64)>,
    saw_bg_uncertain_pass: &mut bool,
    max_prior_ts: &mut f64,
) {
    let sys_pt = parse_iso_ts_meta(st.get("created_at").and_then(Value::as_str).unwrap_or(""));
    if !pending_bg_checks.is_empty() {
        let sys_txt = st.get("content").and_then(Value::as_str).unwrap_or("");
        if let Some((tid, passed, msg_ts)) = parse_host_bg_task_sys_msg(sys_txt, sys_pt.ts) {
            if let Some((pol, start_ts, _)) = pending_bg_checks.remove(&tid) {
                let done_ts = if msg_ts > 0.0 { msg_ts } else { start_ts };
                if done_ts > *max_prior_ts {
                    *max_prior_ts = done_ts;
                }
                if !passed {
                    if done_ts > 0.0 && done_ts >= first_ts - 1.0 {
                        completed_bg_checks.push((false, done_ts));
                    }
                } else if pol == "VALIDATION" {
                    if let Some(credit_ts) = pass_credit_ts(start_ts, done_ts, first_ts) {
                        completed_bg_checks.push((true, credit_ts));
                    }
                } else if pol == "UNCERTAIN"
                    && pass_credit_ts(start_ts, done_ts, first_ts).is_some()
                {
                    *saw_bg_uncertain_pass = true;
                }
            }
        }
    }
    if !sys_pt.coarse && sys_pt.ts > *max_prior_ts {
        *max_prior_ts = sys_pt.ts;
    }
}

pub fn read_checks_evidence_with_steps(
    session: &str,
    first_ts: f64,
    steps: &[Value],
) -> ChecksEvidence {
    read_checks_evidence_with_steps_in_cwd(session, first_ts, steps, "")
}

pub fn read_checks_evidence_with_steps_in_cwd(
    session: &str,
    first_ts: f64,
    steps: &[Value],
    candidate_cwd: &str,
) -> ChecksEvidence {
    // INVARIANT: Reconcile `checks_ledger` with transcript `run_command` outcomes so (1) premature `PostToolUse` entries on backgrounded tasks are replaced by the `\A`-anchored `SYSTEM_MESSAGE` completion, and (2) passing checks only credit verified pre-spawn `start_ts` (never completion `ts`), failing closed (`0.0`) when launch time is unknown or predates `last_durable_ts`.
    let path = cwg_common::checks_ledger_path(session);
    let ledger_recs = rio::read_jsonl_with_rotated(&path, Some(2000));
    struct LedgerRunMeta {
        cmd_sha: String,
        cmd_trunc: String,
        start_ts: f64,
        end_ts: f64,
        cwd: String,
        is_skipped: bool,
    }
    let mut ledger_ts_by_step: HashMap<i64, f64> = HashMap::new();
    let mut ledger_cwd_by_step: HashMap<i64, String> = HashMap::new();
    let mut ledger_cwd_by_call_id: HashMap<String, String> = HashMap::new();
    let mut suppressed_skipped_call_ids: HashSet<String> = HashSet::new();
    let mut ledger_runs: Vec<LedgerRunMeta> = Vec::new();
    let mut suppressed_bg_step_idxs: HashSet<i64> = HashSet::new();
    let mut suppressed_skipped_step_idxs: HashSet<i64> = HashSet::new();
    let mut suppressed_pass_step_idxs: HashSet<i64> = HashSet::new();
    let mut step_start_ts: HashMap<i64, f64> = HashMap::new();
    let mut sync_checks: Vec<(Option<i64>, bool, f64)> = Vec::new();
    let mut saw_sync_uncertain_pass = false;
    let mut pending_bg_checks: HashMap<String, (String, f64, bool)> = HashMap::new();
    let mut completed_bg_checks: Vec<(bool, f64)> = Vec::new();
    let mut saw_bg_uncertain_pass = false;

    for rec in &ledger_recs {
        let rcwd = val_to_str(rec.get("cwd"));
        let rcmd = val_to_str(rec.get("cmd"));
        let rcmd_sha = val_to_str(rec.get("cmd_sha")).trim().to_string();
        let rcall_id = val_to_str(rec.get("call_id")).trim().to_string();
        let r_start_ts = val_to_f64(rec.get("start_ts"));
        let r_end_ts = val_to_f64(rec.get("ts"));
        let rkind = rec.get("kind").and_then(Value::as_str);
        if let Some(si) = rec.get("step_idx").and_then(Value::as_i64) {
            if !rcwd.is_empty() {
                ledger_cwd_by_step.insert(si, rcwd.clone());
            }
        }
        if !rcall_id.is_empty() && !rcwd.is_empty() {
            ledger_cwd_by_call_id.insert(rcall_id.clone(), rcwd.clone());
        }
        let is_skipped = rkind == Some(cwg_mark::CHECK_KIND_SKIPPED);
        if !rcmd_sha.is_empty() || !rcmd.is_empty() {
            let canon_trunc = if !rcmd.is_empty() {
                let canon = cwg_mark::canonical_shell_snap_cmd(&rio::unwrap_tokenade_command(&rcmd));
                rio::truncate_chars(&canon, 240).to_string()
            } else {
                String::new()
            };
            ledger_runs.push(LedgerRunMeta {
                cmd_sha: rcmd_sha,
                cmd_trunc: canon_trunc,
                start_ts: r_start_ts,
                end_ts: r_end_ts,
                cwd: rcwd.clone(),
                is_skipped,
            });
        }
        match rkind {
            Some(cwg_mark::CHECK_KIND_CHECK | cwg_mark::CHECK_KIND_UNCERTAIN) => {
                if let Some(si) = rec.get("step_idx").and_then(Value::as_i64) {
                    let ts = r_end_ts;
                    if ts > 0.0 {
                        let prev = ledger_ts_by_step.entry(si).or_insert(0.0);
                        if ts > *prev {
                            *prev = ts;
                        }
                    }
                }
            }
            Some(cwg_mark::CHECK_KIND_SKIPPED) => {
                if let Some(si) = rec.get("step_idx").and_then(Value::as_i64) {
                    suppressed_skipped_step_idxs.insert(si);
                }
                if !rcall_id.is_empty() {
                    suppressed_skipped_call_ids.insert(rcall_id);
                }
            }
            Some(cwg_mark::CHECK_KIND_BG_LAUNCH) => {
                if let Some(si) = rec.get("step_idx").and_then(Value::as_i64) {
                    suppressed_bg_step_idxs.insert(si);
                }
                let tid = val_to_str(rec.get("task_id"));
                let pol = val_to_str(rec.get("policy"));
                let sts = r_start_ts;
                if !tid.is_empty() && !pol.is_empty() {
                    pending_bg_checks.insert(tid, (pol, sts.max(0.0), sts > 0.0));
                }
            }
            _ => {}
        }
    }

    let mut max_prior_ts: f64 = 0.0;

    for (idx, st) in steps.iter().enumerate() {
        let ssource = st.get("source").and_then(Value::as_str).unwrap_or("");
        if ssource == "SYSTEM" {
            handle_bg_check_sys_step(
                st,
                first_ts,
                &mut pending_bg_checks,
                &mut completed_bg_checks,
                &mut saw_bg_uncertain_pass,
                &mut max_prior_ts,
            );
            continue;
        }
        if ssource != "MODEL" || st.get("type").and_then(Value::as_str) != Some("PLANNER_RESPONSE")
        {
            continue;
        }
        let call_pt = parse_iso_ts_meta(st.get("created_at").and_then(Value::as_str).unwrap_or(""));
        let mut call_ts = call_pt.ts;
        if call_pt.coarse && call_ts > 0.0 && max_prior_ts >= call_ts && max_prior_ts < call_ts + 1.0
        {
            call_ts = (max_prior_ts + TS_EPS).min(call_pt.ts + 0.999_999);
        }
        let Some(tcs) = st.get("tool_calls").and_then(Value::as_array) else {
            continue;
        };
        if !tcs
            .iter()
            .any(|tc| tc.get("name").and_then(Value::as_str) == Some("run_command"))
        {
            continue;
        }
        let p_step_idx = st.get("step_index").and_then(Value::as_i64);
        let mut gen_end = idx + 1;
        while gen_end < steps.len()
            && steps[gen_end].get("type").and_then(Value::as_str) == Some("GENERIC")
        {
            gen_end += 1;
        }
        let gen_count = gen_end - (idx + 1);
        for (pos, tc) in tcs.iter().enumerate() {
            if pos >= gen_count || tc.get("name").and_then(Value::as_str) != Some("run_command") {
                continue;
            }
            let Some(cmd_val) = tc.get("args").and_then(|a| a.get("CommandLine")) else {
                continue;
            };
            let cmd_owned: String;
            let cmd_str: &str = match cmd_val.as_str() {
                Some(s) => s,
                None => {
                    cmd_owned = val_to_str(Some(cmd_val));
                    &cmd_owned
                }
            };
            if cmd_str.trim().is_empty() {
                continue;
            }
            let g_st = &steps[idx + 1 + pos];
            let g_status = g_st.get("status").and_then(Value::as_str).unwrap_or("");
            let g_content = g_st.get("content").and_then(Value::as_str).unwrap_or("");
            let g_step_idx = g_st.get("step_index").and_then(Value::as_i64);
            let g_pt =
                parse_iso_ts_meta(g_st.get("created_at").and_then(Value::as_str).unwrap_or(""));
            let core_cmd = rio::unwrap_tokenade_command(cmd_str);
            let canon_core_cmd = cwg_mark::canonical_shell_snap_cmd(&core_cmd);
            let canon_cmd_sha = cwg_mark::canonical_cmd_sha(&canon_core_cmd);
            let canon_cmd_trunc = rio::truncate_chars(&canon_core_cmd, 240);
            let tc_call_id = tc
                .get("id")
                .or_else(|| tc.get("callId"))
                .or_else(|| tc.get("toolCallId"))
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("");
            let next_planner_ts = steps[gen_end..]
                .iter()
                .find(|s| {
                    s.get("type").and_then(Value::as_str) == Some("PLANNER_RESPONSE")
                })
                .and_then(|s| s.get("created_at").and_then(Value::as_str))
                .map(rio::parse_iso_ts)
                .unwrap_or(0.0);
            let ledger_run_matches = |r: &LedgerRunMeta| -> bool {
                let cmd_ok = if !r.cmd_sha.is_empty() {
                    r.cmd_sha == canon_cmd_sha
                } else {
                    !r.cmd_trunc.is_empty() && r.cmd_trunc == canon_cmd_trunc
                };
                if !cmd_ok {
                    return false;
                }
                if r.start_ts > 0.0 && call_ts > 0.0 && (r.start_ts - call_ts).abs() <= 5.0 {
                    return true;
                }
                if r.end_ts > 0.0 && g_pt.ts > 0.0 && (r.end_ts - g_pt.ts).abs() <= 5.0 {
                    return true;
                }
                if call_ts > 0.0
                    && g_pt.ts > 0.0
                    && r.end_ts > 0.0
                    && r.end_ts >= call_ts - 2.0
                    && r.end_ts <= g_pt.ts + 5.0
                {
                    return true;
                }
                if r.start_ts <= 0.0
                    && g_pt.ts <= 0.0
                    && call_ts > 0.0
                    && r.end_ts > 0.0
                    && r.end_ts >= call_ts - 2.0
                    && (next_planner_ts <= 0.0 || r.end_ts <= next_planner_ts + 2.0)
                {
                    return true;
                }
                call_ts <= 0.0 && g_pt.ts <= 0.0
            };
            // INVARIANT: Bind each run_command's script classification strictly to that run's recorded `PostToolUse` `cwd` and `CHECK_KIND_SKIPPED` status via `call_id`, `step_idx`, or full `cmd_sha` + execution-interval `[start_ts, end_ts]` matching so long (>240-char) or slow (>5s) commands never fall through to a different package's `package.json`.
            let ledger_step_cwd = (!tc_call_id.is_empty())
                .then(|| ledger_cwd_by_call_id.get(tc_call_id))
                .flatten()
                .or_else(|| g_step_idx.and_then(|si| ledger_cwd_by_step.get(&si)))
                .or_else(|| {
                    (tcs.len() == 1)
                        .then(|| p_step_idx.and_then(|si| ledger_cwd_by_step.get(&si)))
                        .flatten()
                })
                .or_else(|| {
                    ledger_runs
                        .iter()
                        .rev()
                        .find(|r| !r.cwd.is_empty() && ledger_run_matches(r))
                        .map(|r| &r.cwd)
                })
                .map(String::as_str);
            let arg_cwd = tc
                .get("args")
                .and_then(|a| a.get("Cwd").or_else(|| a.get("cwd")))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let is_extended_pkg = cwg_mark::has_extended_pkg_script_segment(&core_cmd);
            let step_cwd_opt = ledger_step_cwd
                .or(arg_cwd)
                .or_else(|| {
                    // INVARIANT: Extended package scripts (`npm.cmd run validate`, `pnpm run schema:verify`, etc.) always require a verified per-run `cwd` (from `checks_ledger` or explicit tool-call `Cwd`), even when the ledger is empty, so an unrecorded/evicted `if-present=true` root run can never be miscredited against another package's `package.json`.
                    if is_extended_pkg {
                        None
                    } else {
                        (!candidate_cwd.trim().is_empty()).then_some(candidate_cwd)
                    }
                });
            let post_skipped = (!tc_call_id.is_empty()
                && suppressed_skipped_call_ids.contains(tc_call_id))
                || g_step_idx.is_some_and(|si| suppressed_skipped_step_idxs.contains(&si))
                || (tcs.len() == 1
                    && p_step_idx.is_some_and(|si| suppressed_skipped_step_idxs.contains(&si)))
                || ledger_runs
                    .iter()
                    .any(|r| r.is_skipped && ledger_run_matches(r));
            let (pol, has_val) = if post_skipped {
                ("UNCERTAIN", false)
            } else {
                cwg_mark::classify_gate_check_with_val(&core_cmd, step_cwd_opt)
            };
            let g_err = g_st
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            let g_blob_owned: String;
            let g_blob: &str = if g_err.is_empty() || g_content.contains(g_err) {
                g_content
            } else if g_content.is_empty() {
                g_err
            } else {
                g_blob_owned = format!("{}\n{}", g_content, g_err);
                g_blob_owned.trim()
            };
            let start_ts = call_ts;
            if let Some(bg_tid) = rio::extract_bg_task_id(g_blob) {
                if let Some(si) = p_step_idx {
                    suppressed_bg_step_idxs.insert(si);
                }
                if let Some(si) = g_step_idx {
                    suppressed_bg_step_idxs.insert(si);
                }
                if has_val && !pending_bg_checks.get(&bg_tid).is_some_and(|e| e.2) {
                    pending_bg_checks.insert(bg_tid, (pol.to_string(), start_ts, false));
                }
                continue;
            }
            if start_ts > 0.0 {
                if let Some(si) = g_step_idx {
                    step_start_ts.insert(si, start_ts);
                }
                if tcs.len() == 1 {
                    if let Some(si) = p_step_idx {
                        step_start_ts.insert(si, start_ts);
                    }
                }
            }
            if let Some(lts) = g_step_idx.and_then(|si| ledger_ts_by_step.get(&si).copied()) {
                if lts > max_prior_ts {
                    max_prior_ts = lts;
                }
            } else if !g_pt.coarse && g_pt.ts > max_prior_ts {
                max_prior_ts = g_pt.ts;
            }
            if !has_val {
                continue;
            }
            let exit_opt = cwg_common::parse_host_command_exit_code(g_blob);
            let cmd_failed = g_status == "ERROR" || matches!(exit_opt, Some(c) if c != 0);
            if cmd_failed {
                if let Some(si) = g_step_idx {
                    suppressed_pass_step_idxs.insert(si);
                }
                let done_ts = call_ts.max(g_pt.ts);
                if done_ts > 0.0 && done_ts >= first_ts - 1.0 {
                    sync_checks.push((g_step_idx, false, done_ts));
                }
            } else if pol == "VALIDATION" {
                if let Some(credit_ts) = pass_credit_ts(start_ts, g_pt.ts, first_ts) {
                    sync_checks.push((g_step_idx, true, credit_ts));
                }
            } else if pol == "UNCERTAIN"
                && exit_opt == Some(0)
                && pass_credit_ts(start_ts, g_pt.ts, first_ts).is_some()
            {
                saw_sync_uncertain_pass = true;
            }
        }
    }

    let mut ev = ChecksEvidence::default();
    let mut seen_sync_step_idxs: HashSet<i64> = HashSet::new();
    for rec in ledger_recs {
        let kind = rec.get("kind").and_then(Value::as_str);
        if !matches!(
            kind,
            Some(cwg_mark::CHECK_KIND_CHECK | cwg_mark::CHECK_KIND_UNCERTAIN)
        ) {
            continue;
        }
        let ts = val_to_f64(rec.get("ts"));
        let s_idx = rec.get("step_idx").and_then(Value::as_i64);
        if s_idx.is_some_and(|si| suppressed_bg_step_idxs.contains(&si)) {
            continue;
        }
        let passed = json_truthy(rec.get("passed"));
        if passed && s_idx.is_some_and(|si| suppressed_pass_step_idxs.contains(&si)) {
            continue;
        }
        if kind == Some(cwg_mark::CHECK_KIND_CHECK) {
            if let Some(si) = s_idx {
                seen_sync_step_idxs.insert(si);
            }
            if passed {
                let resolved_start = resolve_ledger_start_ts(&rec, s_idx, &step_start_ts);
                if let Some(credit_ts) = pass_credit_ts(resolved_start, ts, first_ts) {
                    ev.record_outcome(true, credit_ts);
                }
            } else if ts >= first_ts - 1.0 {
                ev.record_outcome(false, ts);
            }
        } else if passed {
            let resolved_start = resolve_ledger_start_ts(&rec, s_idx, &step_start_ts);
            if pass_credit_ts(resolved_start, ts, first_ts).is_some() {
                ev.saw_uncertain_pass = true;
            }
        }
    }
    for (g_step_idx, passed, credit_ts) in sync_checks {
        if g_step_idx.is_some_and(|si| seen_sync_step_idxs.contains(&si)) {
            continue;
        }
        ev.record_outcome(passed, credit_ts);
    }
    for (passed, credit_ts) in completed_bg_checks {
        ev.record_outcome(passed, credit_ts);
    }
    ev.saw_uncertain_pass |= saw_sync_uncertain_pass || saw_bg_uncertain_pass;
    ev
}

fn extract_generic_step_result(g_st: &Value) -> (String, String, ParsedTs) {
    let mut g_txt = val_to_str(g_st.get("content"));
    let g_err = val_to_str(g_st.get("error")).trim().to_string();
    if !g_err.is_empty() && !g_txt.contains(&g_err) {
        if g_txt.is_empty() {
            g_txt = g_err;
        } else {
            g_txt = format!("{}\n{}", g_txt, g_err).trim().to_string();
        }
    }
    let g_status = val_to_str(g_st.get("status"));
    let g_pt = g_st
        .get("created_at")
        .and_then(|v| v.as_str())
        .map(parse_iso_ts_meta)
        .unwrap_or_default();
    (g_status, g_txt, g_pt)
}

fn step_has_truncated_content(step: &Value) -> bool {
    step.get("truncated_fields")
        .and_then(|v| v.as_array())
        .map_or(false, |arr| arr.iter().any(|x| x.as_str() == Some("content")))
}

fn collect_generic_results(steps: &[Value], planner_idx: usize) -> Vec<(String, String, ParsedTs)> {
    let mut g_cur = planner_idx + 1;
    let mut out = Vec::new();
    while g_cur < steps.len() {
        let g_st = &steps[g_cur];
        if g_st.get("type").and_then(|v| v.as_str()) != Some("GENERIC") {
            break;
        }
        out.push(extract_generic_step_result(g_st));
        g_cur += 1;
    }
    out
}

fn extract_json_dict(blob: &str) -> Option<Map<String, Value>> {
    let pos = blob.find('{')?;
    match serde_json::from_str::<Value>(&blob[pos..]) {
        Ok(Value::Object(map)) => Some(map),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TimedChunk {
    pub(crate) ts: f64,
    pub(crate) text: String,
    kind: &'static str,
    is_signoff: bool,
}

pub(crate) fn extract_subagent_timed_chunks(
    subagent_transcript_path: Option<&str>,
    parent_cid: &str,
) -> (Vec<TimedChunk>, f64, bool) {
    let Some(tp) = subagent_transcript_path else {
        return (Vec::new(), 0.0, false);
    };
    if tp.is_empty() {
        return (Vec::new(), 0.0, false);
    }
    let steps = rio::read_transcript_steps(tp, 500);
    if steps.is_empty() {
        return (Vec::new(), 0.0, false);
    }
    let mut chunks = Vec::new();
    let mut last_ts = 0.0f64;
    let mut finished = false;
    let mut just_sent_to_parent = false;

    for (idx, st) in steps.iter().enumerate() {
        let ts = st
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(rio::parse_iso_ts)
            .unwrap_or(0.0);
        if ts > 0.0 {
            last_ts = last_ts.max(ts);
        }
        let stype = val_to_str(st.get("type"));
        if stype == "GENERIC" {
            continue;
        }
        if st.get("source").and_then(|v| v.as_str()) != Some("MODEL") || stype != "PLANNER_RESPONSE"
        {
            just_sent_to_parent = false;
            continue;
        }
        let tcs = st
            .get("tool_calls")
            .and_then(|v| v.as_array())
            .map(|a| a.as_slice())
            .unwrap_or(&[]);
        if !tcs.is_empty() {
            let gen_steps = collect_generic_results(&steps, idx);
            let mut sent_any = false;
            let mut only_parent_sends = true;
            for (pos, tc) in tcs.iter().enumerate() {
                let Some(tc_obj) = tc.as_object() else {
                    only_parent_sends = false;
                    continue;
                };
                if tc_obj.get("name").and_then(|v| v.as_str()) != Some("send_message") {
                    only_parent_sends = false;
                    continue;
                }
                let (g_status, g_ts) = if pos < gen_steps.len() {
                    (gen_steps[pos].0.as_str(), gen_steps[pos].2.ts)
                } else {
                    ("", 0.0)
                };
                if g_status == "ERROR" {
                    only_parent_sends = false;
                    continue;
                }
                let targs = tc_obj.get("args").and_then(|v| v.as_object());
                let recip = targs
                    .and_then(|m| m.get("Recipient"))
                    .map(|v| val_to_str(Some(v)).trim().to_string())
                    .unwrap_or_default();
                if !parent_cid.is_empty() && !recip.is_empty() && recip != parent_cid {
                    only_parent_sends = false;
                    continue;
                }
                let msg = targs
                    .and_then(|m| m.get("Message"))
                    .map(|v| val_to_str(Some(v)).trim().to_string())
                    .unwrap_or_default();
                if !msg.is_empty() {
                    let eff_send_ts = if g_ts > 0.0 { ts.max(g_ts) } else { ts };
                    chunks.push(TimedChunk {
                        ts: eff_send_ts,
                        text: msg,
                        kind: "send",
                        is_signoff: false,
                    });
                    finished = true;
                    sent_any = true;
                }
            }
            just_sent_to_parent = sent_any && only_parent_sends;
        } else {
            let content = val_to_str(st.get("content")).trim().to_string();
            if !content.is_empty() {
                chunks.push(TimedChunk {
                    ts,
                    text: content,
                    kind: "final",
                    is_signoff: just_sent_to_parent,
                });
                finished = true;
            }
            just_sent_to_parent = false;
        }
    }
    (chunks, last_ts, finished)
}

fn merge_subagent_chunks(
    sub_chunks: &[TimedChunk],
    delivered: &[(f64, String)],
) -> Vec<TimedChunk> {
    let mut merged: Vec<(f64, usize, String, &'static str, bool)> = Vec::new();
    let mut matched_sub: HashSet<usize> = HashSet::new();
    let mut sub_cursor = 0usize;

    for (d_idx, (dts, dbody)) in delivered.iter().enumerate() {
        let mut matched_idx: Option<usize> = None;
        for (s_idx, chunk) in sub_chunks.iter().enumerate().skip(sub_cursor) {
            if chunk.kind == "send"
                && &chunk.text == dbody
                && (chunk.ts == 0.0 || *dts == 0.0 || (chunk.ts - *dts).abs() < 300.0)
            {
                matched_idx = Some(s_idx);
                sub_cursor = s_idx + 1;
                break;
            }
        }
        if let Some(m_idx) = matched_idx {
            matched_sub.insert(m_idx);
            let ch = &sub_chunks[m_idx];
            let eff_ts = if *dts > 0.0 { *dts } else { ch.ts };
            merged.push((eff_ts, m_idx * 2, ch.text.clone(), ch.kind, ch.is_signoff));
        } else {
            merged.push((
                *dts,
                sub_chunks.len() * 2 + d_idx,
                dbody.clone(),
                "send",
                false,
            ));
        }
    }

    for (s_idx, ch) in sub_chunks.iter().enumerate() {
        if !matched_sub.contains(&s_idx) {
            merged.push((ch.ts, s_idx * 2 + 1, ch.text.clone(), ch.kind, ch.is_signoff));
        }
    }

    // INVARIANT: Propagate monotonic floor across missing (`0.0`) timestamps so causal step order is never inverted.
    merged.sort_by_key(|item| item.1);
    let mut floor_ts = 0.0f64;
    let mut normalized: Vec<(f64, usize, String, &'static str, bool)> =
        Vec::with_capacity(merged.len());
    for (ts_val, seq_val, body_val, kind_val, sign_val) in merged {
        let eff = if ts_val > 0.0 { ts_val } else { floor_ts };
        if eff > floor_ts {
            floor_ts = eff;
        }
        normalized.push((eff, seq_val, body_val, kind_val, sign_val));
    }
    normalized.sort_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    normalized
        .into_iter()
        .map(|(ts, _, text, kind, is_signoff)| TimedChunk {
            ts,
            text,
            kind,
            is_signoff,
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
struct TranscriptOut {
    pt: ParsedTs,
    text: String,
    is_board_post: bool,
}

#[derive(Debug, Clone, Default)]
struct MemberTranscriptSummary {
    outputs: Vec<TranscriptOut>,
    has_error: bool,
    error_ts: f64,
    error_timestamps: Vec<ParsedTs>,
    parked_or_done: bool,
    parked_ts: f64,
    start_ts: f64,
}

fn member_transcript_summary(member_tp: Option<&Path>, first_ts: f64) -> MemberTranscriptSummary {
    let Some(tp) = member_tp else {
        return MemberTranscriptSummary::default();
    };
    if !tp.is_file() {
        return MemberTranscriptSummary::default();
    }
    let m_steps = rio::read_transcript_steps(&tp.to_string_lossy(), 600);
    if m_steps.is_empty() {
        return MemberTranscriptSummary::default();
    }
    let mut outputs = Vec::new();
    let mut has_error = false;
    let mut error_ts = 0.0f64;
    let mut error_timestamps = Vec::new();
    let start_ts = m_steps[0]
        .get("created_at")
        .and_then(|v| v.as_str())
        .map(rio::parse_iso_ts)
        .unwrap_or(0.0);

    for (st_idx, st) in m_steps.iter().enumerate() {
        let pt = st
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(parse_iso_ts_meta)
            .unwrap_or_default();
        let ts = pt.ts;
        let ssource = val_to_str(st.get("source"));
        let stype = val_to_str(st.get("type"));
        let sstatus = val_to_str(st.get("status"));
        let scontent = val_to_str(st.get("content"));

        let in_window = ts == 0.0 || ts >= first_ts - 2.0;

        // SAFETY: Only model/turn failures count (never GENERIC tool-call errors or SYSTEM brief text).
        if in_window
            && (stype == "ERROR_MESSAGE"
                || (ssource == "MODEL" && stype != "GENERIC" && sstatus == "ERROR"))
        {
            has_error = true;
            if ts > 0.0 {
                error_timestamps.push(pt);
                max_into(&mut error_ts, ts);
            }
        }

        if ssource == "MODEL" && stype == "PLANNER_RESPONSE" {
            let tcs = st
                .get("tool_calls")
                .and_then(|v| v.as_array())
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let mut tool_results: Vec<&Value> = Vec::new();
            if !tcs.is_empty() {
                for nxt in &m_steps[st_idx + 1..] {
                    let ntype = val_to_str(nxt.get("type"));
                    if ntype == "PLANNER_RESPONSE" || ntype == "USER_INPUT" {
                        break;
                    }
                    if val_to_str(nxt.get("source")) != "SYSTEM" {
                        tool_results.push(nxt);
                    }
                }
            }
            for (tc_pos, tc) in tcs.iter().enumerate() {
                let Some(tc_obj) = tc.as_object() else {
                    continue;
                };
                let tname = tc_obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
                if tname == "post_message" || tname == "send_message" {
                    let targs = tc_obj.get("args").and_then(|v| v.as_object());
                    let txt = targs
                        .and_then(|m| m.get("text").or_else(|| m.get("Message")))
                        .map(|v| val_to_str(Some(v)).trim().to_string())
                        .unwrap_or_default();
                    if !txt.is_empty() && in_window {
                        let post_failed = sstatus == "ERROR"
                            || tool_results.get(tc_pos).is_some_and(|res| {
                                let rstatus = val_to_str(res.get("status"));
                                let rcontent = val_to_str(res.get("content")).to_lowercase();
                                !rcontent.contains("\"status\":\"posted\"")
                                    && !rcontent.contains("\"status\": \"posted\"")
                                    && (rstatus == "ERROR"
                                        || rcontent.contains("encountered error")
                                        || rcontent.contains("tool call denied")
                                        || rcontent.contains("\"error\""))
                            });
                        outputs.push(TranscriptOut {
                            pt,
                            text: txt,
                            is_board_post: tname == "post_message" && !post_failed,
                        });
                    }
                }
            }
            if !scontent.trim().is_empty() && tcs.is_empty() && in_window {
                outputs.push(TranscriptOut {
                    pt,
                    text: scontent.trim().to_string(),
                    is_board_post: false,
                });
            }
        }
    }

    let Some(last_st) = m_steps.last() else {
        return MemberTranscriptSummary::default();
    };
    let last_source = val_to_str(last_st.get("source"));
    let last_type = val_to_str(last_st.get("type"));
    let last_status = val_to_str(last_st.get("status"));
    let last_content_low = val_to_str(last_st.get("content")).to_lowercase();
    let last_tcs_empty = last_st
        .get("tool_calls")
        .and_then(|v| v.as_array())
        .is_none_or(|a| a.is_empty());
    let prev_called_wait = m_steps.len() >= 2
        && m_steps[m_steps.len() - 2]
            .get("tool_calls")
            .and_then(|v| v.as_array())
            .is_some_and(|a| {
                a.iter()
                    .any(|tc| tc.get("name").and_then(|n| n.as_str()) == Some("swarm_wait"))
            });

    let mut parked_or_done = false;
    if last_source == "MODEL" && last_type == "PLANNER_RESPONSE" && last_tcs_empty {
        parked_or_done = true;
    } else if last_type == "GENERIC"
        && last_status == "DONE"
        && (last_content_low.contains("waiting for a message")
            || last_content_low.contains("swarm_wait")
            || prev_called_wait)
    {
        parked_or_done = true;
    } else if has_error {
        parked_or_done = true;
    }

    let parked_ts = if parked_or_done {
        let lts = last_st
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(rio::parse_iso_ts)
            .unwrap_or(0.0);
        if lts > 0.0 {
            lts
        } else {
            error_ts
        }
    } else {
        0.0
    };

    MemberTranscriptSummary {
        outputs,
        has_error,
        error_ts,
        error_timestamps,
        parked_or_done,
        parked_ts,
        start_ts,
    }
}

fn chat_bus_wait_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(?:\bchat-bus(?:\.exe)?|\bchat_bus_cli\.py)["']?\s+wait\b"#)
            .expect("chat_bus_wait_re")
    })
}

fn is_passive_listener_cmd(cmd_str: &str) -> bool {
    chat_bus_wait_re().is_match(cmd_str)
        && cwg_mark::classify_shell_command(cmd_str) == "BOOKKEEPING"
}

#[derive(Debug, Clone, Default)]
pub struct SwarmEvidence {
    pub reviews: Vec<Value>,
    pub review_failures: Vec<f64>,
    pub in_flight_workers: Vec<String>,
    pub idle_unkilled_workers: Vec<String>,
    pub pending_bg_tasks: Vec<String>,
    pub passive_bg_tasks: Vec<String>,
    pub opus_issue_verified: bool,
    pub opus_issue_ts: f64,
    pub sonnet_issue_verified: bool,
    pub sonnet_issue_ts: f64,
    pub sonnet_last_issue_ts: f64,
    pub sonnet_healthy_ts: f64,
    pub neon_issue_verified: bool,
    pub neon_issue_ts: f64,
    pub neon_last_issue_ts: f64,
    pub neon_healthy_ts: f64,
    pub hydrogen_issue_verified: bool,
    pub hydrogen_issue_ts: f64,
    pub hydrogen_last_issue_ts: f64,
    pub hydrogen_healthy_ts: f64,
    pub codex_cmd_failed: bool,
    pub codex_issue_ts: f64,
    pub codex_issue_step: isize,
    pub codex_timeout_seen: bool,
    pub aborted_codex_reviews: HashMap<String, f64>,
    pub board_head: usize,
    pub stalled_workers: Vec<Value>,
    pub worker_activity_count: Option<usize>,
    pub compact_steps: Vec<Value>,
}

pub fn scan_swarm_activity(
    steps: &[Value],
    transcript_path: Option<&str>,
    first_ts: f64,
    round_start_msg_id: i64,
    current_diff_hash: &str,
    cwd: &str,
) -> SwarmEvidence {
    scan_swarm_activity_with_reset(SwarmScanInput {
        steps,
        transcript_path,
        first_ts,
        round_start_msg_id,
        current_diff_hash,
        cwd,
        research_reset_ts: 0.0,
        research_reset_seq: 0,
        marker: None,
    })
}

fn record_system_swarm_errors(
    txt: &str,
    sys_pt: ParsedTs,
    first_ts: f64,
    host_worker_errors: &mut HashMap<(String, String), Vec<ParsedTs>>,
) {
    if sys_pt.ts > 0.0 && sys_pt.ts < first_ts - 2.0 {
        return;
    }
    for sm in system_swarm_err_re().captures_iter(txt) {
        let err_txt = sm.name("err").map_or("", |m| m.as_str());
        if !model_failure_re().is_match(err_txt) {
            continue;
        }
        let msg_pt = sm
            .name("ts")
            .map(|m| parse_iso_ts_meta(m.as_str()))
            .unwrap_or_default();
        // INVARIANT: Picking the smaller of `msg_pt` and `sys_pt` preserves pre-switch origin timestamps against delayed delivery of host SYSTEM notifications.
        let eff_pt = if msg_pt.ts > 0.0 && sys_pt.ts > 0.0 {
            if msg_pt.ts < sys_pt.ts {
                msg_pt
            } else if sys_pt.ts < msg_pt.ts {
                sys_pt
            } else {
                ParsedTs {
                    ts: msg_pt.ts,
                    coarse: msg_pt.coarse && sys_pt.coarse,
                }
            }
        } else if msg_pt.ts > 0.0 {
            msg_pt
        } else if sys_pt.ts > 0.0 {
            sys_pt
        } else {
            ParsedTs::default()
        };
        if eff_pt.ts > 0.0 && eff_pt.ts < first_ts - 2.0 {
            continue;
        }
        let key = (
            sm.name("name").map_or("", |m| m.as_str()).to_string(),
            sm.name("cid").map_or("", |m| m.as_str()).to_string(),
        );
        host_worker_errors.entry(key).or_default().push(eff_pt);
    }
}

const MODELS_LEAD_IN_MAX_SEC: f64 = 600.0;

fn is_swarm_models_call(tc: &Value) -> bool {
    tc.get("name").and_then(|v| v.as_str()) == Some("swarm")
        && tc
            .get("args")
            .and_then(|v| v.as_object())
            .and_then(|m| m.get("action"))
            .and_then(|v| v.as_str())
            .is_some_and(|s| s.trim().eq_ignore_ascii_case("models"))
}

fn is_models_lead_in_ts(call_ts: f64, first_ts: f64, models_floor_ts: f64) -> bool {
    call_ts > 0.0
        && call_ts < first_ts - 2.0
        && models_floor_ts > 0.0
        && call_ts >= models_floor_ts
}

fn is_modern_review_cap_marker(marker: &Value) -> bool {
    marker
        .get("gate_max_review_rounds")
        .and_then(|v| v.as_u64())
        .is_some_and(|n| n >= MAX_REVIEW_ROUNDS as u64)
}

fn swarm_call_needs_full_content(tc: &Value) -> bool {
    let Some(args) = tc.get("args").and_then(|v| v.as_object()) else {
        return false;
    };
    let act = args
        .get("action")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("");
    matches!(act, "models" | "add" | "model")
        || args
            .get("model")
            .and_then(|v| v.as_str())
            .is_some_and(|m| !m.trim().is_empty())
}

fn recover_compact_swarm_steps(
    tp: &str,
    tail_idx: i64,
    first_ts: f64,
    models_floor_ts: f64,
    ev: &mut SwarmEvidence,
    host_worker_errors: &mut HashMap<(String, String), Vec<ParsedTs>>,
    mut on_swarm_res: impl FnMut(&mut SwarmEvidence, &Value, &str, &str, ParsedTs, f64, Option<usize>, bool),
) -> Vec<Value> {
    let compact_steps = rio::read_compact_transcript_steps(tp, 16000);
    // INVARIANT: Compact `transcript.jsonl` truncates `content` around ~4 KiB, chopping off the trailing `"quotas"` block of `swarm(action="models", all=true)`. Scan compact steps once, collect contiguous truncated swarm result `step_index`es, hydrate them in one streaming pass over `transcript_full.jsonl`, and dispatch cleanly.
    let mut matched_calls: Vec<(usize, usize, Option<usize>, f64)> = Vec::new();
    let mut wanted_full_indices: HashSet<i64> = HashSet::new();
    for (p_idx, p_st) in compact_steps.iter().enumerate() {
        let Some(s_idx) = p_st.get("step_index").and_then(|v| v.as_i64()) else {
            continue;
        };
        if s_idx <= 0 || s_idx >= tail_idx {
            continue;
        }
        let p_source = p_st.get("source").and_then(|v| v.as_str()).unwrap_or("");
        if p_source == "SYSTEM" {
            let sys_pt = p_st
                .get("created_at")
                .and_then(|v| v.as_str())
                .map(parse_iso_ts_meta)
                .unwrap_or_default();
            if sys_pt.ts == 0.0 || sys_pt.ts >= first_ts - 2.0 {
                let txt = val_to_str(p_st.get("content"));
                record_system_swarm_errors(&txt, sys_pt, first_ts, host_worker_errors);
            }
            continue;
        }
        if p_source != "MODEL"
            || p_st.get("type").and_then(|v| v.as_str()) != Some("PLANNER_RESPONSE")
        {
            continue;
        }
        let Some(p_tcs) = p_st.get("tool_calls").and_then(|v| v.as_array()) else {
            continue;
        };
        if !p_tcs
            .iter()
            .any(|tc| tc.get("name").and_then(|v| v.as_str()) == Some("swarm"))
        {
            continue;
        }
        let p_call_ts = p_st
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(rio::parse_iso_ts)
            .unwrap_or(0.0);
        let is_models_lead_in = is_models_lead_in_ts(p_call_ts, first_ts, models_floor_ts);
        if p_call_ts > 0.0 && p_call_ts < first_ts - 2.0 && !is_models_lead_in {
            continue;
        }
        let mut gen_len = 0usize;
        while compact_steps
            .get(p_idx + 1 + gen_len)
            .and_then(|s| s.get("type"))
            .and_then(|v| v.as_str())
            == Some("GENERIC")
        {
            gen_len += 1;
        }
        for (p_pos, p_tc) in p_tcs.iter().enumerate() {
            if p_tc.get("name").and_then(|v| v.as_str()) != Some("swarm") {
                continue;
            }
            if is_models_lead_in && !is_swarm_models_call(p_tc) {
                continue;
            }
            let g_pos = (p_pos < gen_len).then_some(p_idx + 1 + p_pos);
            if let Some(gi) = g_pos {
                let g_st = &compact_steps[gi];
                if step_has_truncated_content(g_st) && swarm_call_needs_full_content(p_tc) {
                    if let Some(g_idx) = g_st.get("step_index").and_then(|v| v.as_i64()) {
                        wanted_full_indices.insert(g_idx);
                    }
                }
            }
            matched_calls.push((p_idx, p_pos, g_pos, p_call_ts));
        }
    }
    let full_by_idx = if wanted_full_indices.is_empty() {
        HashMap::new()
    } else {
        rio::read_full_transcript_steps_by_indices(tp, &wanted_full_indices)
    };
    for (p_idx, p_pos, g_pos, p_call_ts) in matched_calls {
        let p_tc = &compact_steps[p_idx]["tool_calls"][p_pos];
        let ((g_status, blob, g_pt), content_complete) = if let Some(gi) = g_pos {
            let compact_g_st = &compact_steps[gi];
            let has_compact_trunc = step_has_truncated_content(compact_g_st);
            let hydrated = has_compact_trunc
                .then(|| compact_g_st.get("step_index").and_then(|v| v.as_i64()))
                .flatten()
                .and_then(|g_idx| full_by_idx.get(&g_idx));
            if let Some(full_st) = hydrated {
                (
                    extract_generic_step_result(full_st),
                    !step_has_truncated_content(full_st),
                )
            } else {
                (
                    extract_generic_step_result(compact_g_st),
                    !has_compact_trunc,
                )
            }
        } else {
            ((String::new(), String::new(), ParsedTs::default()), true)
        };
        on_swarm_res(
            ev,
            p_tc,
            g_status.as_str(),
            blob.as_str(),
            g_pt,
            p_call_ts,
            None,
            content_complete,
        );
    }
    compact_steps
}

pub struct SwarmScanInput<'a> {
    pub steps: &'a [Value],
    pub transcript_path: Option<&'a str>,
    pub first_ts: f64,
    pub round_start_msg_id: i64,
    pub current_diff_hash: &'a str,
    pub cwd: &'a str,
    pub research_reset_ts: f64,
    pub research_reset_seq: i64,
    pub marker: Option<&'a Value>,
}

pub fn scan_swarm_activity_with_reset(input: SwarmScanInput<'_>) -> SwarmEvidence {
    let SwarmScanInput {
        steps,
        transcript_path,
        first_ts,
        round_start_msg_id,
        current_diff_hash: _,
        cwd,
        research_reset_ts,
        research_reset_seq,
        marker,
    } = input;
    let mut ev = SwarmEvidence {
        codex_issue_step: -1,
        ..SwarmEvidence::default()
    };
    let mut worker_last_activity: HashMap<String, f64> = HashMap::new();
    let mut requested_models: HashMap<String, HashSet<String>> = HashMap::new();
    let mut worker_model_events: HashMap<String, Vec<WorkerModelEvent>> = HashMap::new();
    let mut opus_requested_ts: HashMap<String, Vec<f64>> = HashMap::new();
    let mut model_switches: HashMap<String, Vec<(f64, String, Option<usize>)>> = HashMap::new();
    let mut coord_call_events: Vec<(ParsedTs, String, usize)> = Vec::new();
    let mut host_worker_errors: HashMap<(String, String), Vec<ParsedTs>> = HashMap::new();
    let mut worker_add_step: HashMap<String, usize> = HashMap::new();
    let mut pending_codex_tasks: HashMap<String, (String, f64)> = HashMap::new();
    let mut pending_bg_tasks: BTreeSet<String> = BTreeSet::new();
    let mut passive_bg_tasks: BTreeSet<String> = BTreeSet::new();

    let mark_issue_ts = |verified: &mut bool,
                         issue_ts: &mut f64,
                         last_issue_ts: Option<&mut f64>,
                         min_ts: f64,
                         max_ts: f64| {
        *verified = true;
        let eff_min = if min_ts > 0.0 { min_ts } else { now_sec() };
        if *issue_ts <= 0.0 || eff_min < *issue_ts {
            *issue_ts = eff_min;
        }
        if let Some(last_ts) = last_issue_ts {
            if max_ts > *last_ts {
                *last_ts = max_ts;
            }
        }
    };

    let mark_codex_issue = |ev: &mut SwarmEvidence, ts_val: f64, step_idx_val: isize| {
        if !ev.codex_cmd_failed {
            ev.codex_cmd_failed = true;
            ev.codex_issue_ts = if ts_val > 0.0 { ts_val } else { 0.0 };
            ev.codex_issue_step = step_idx_val;
            return;
        }
        if ts_val > 0.0 && (ev.codex_issue_ts <= 0.0 || ts_val < ev.codex_issue_ts) {
            ev.codex_issue_ts = ts_val;
            ev.codex_issue_step = step_idx_val;
        } else if ts_val == ev.codex_issue_ts
            && step_idx_val >= 0
            && (ev.codex_issue_step < 0 || step_idx_val < ev.codex_issue_step)
        {
            ev.codex_issue_step = step_idx_val;
        }
    };

    let record_model_failure = |ev: &mut SwarmEvidence,
                                models: &HashSet<String>,
                                _worker_name: &str,
                                min_ts: f64,
                                max_ts: f64| {
        if models
            .iter()
            .any(|m| m.contains(cwg_common::OPUS_HIGH_MODEL))
        {
            mark_issue_ts(
                &mut ev.opus_issue_verified,
                &mut ev.opus_issue_ts,
                None,
                min_ts,
                max_ts,
            );
            ev.review_failures
                .push(if min_ts > 0.0 { min_ts } else { now_sec() });
        }
        for (model_id, verified, issue_ts, last_ts) in [
            (
                cwg_common::SONNET_HIGH_MODEL,
                &mut ev.sonnet_issue_verified,
                &mut ev.sonnet_issue_ts,
                &mut ev.sonnet_last_issue_ts,
            ),
            (
                cwg_common::NEON_XHIGH_MODEL,
                &mut ev.neon_issue_verified,
                &mut ev.neon_issue_ts,
                &mut ev.neon_last_issue_ts,
            ),
            (
                cwg_common::HYDROGEN_XHIGH_MODEL,
                &mut ev.hydrogen_issue_verified,
                &mut ev.hydrogen_issue_ts,
                &mut ev.hydrogen_last_issue_ts,
            ),
        ] {
            if models.iter().any(|m| m.contains(model_id)) {
                mark_issue_ts(verified, issue_ts, Some(last_ts), min_ts, max_ts);
            }
        }
    };

    let mut model_event_ord: usize = 0;
    let mut inspect_swarm_tool_result = |ev: &mut SwarmEvidence,
                                         tc: &Value,
                                         g_status: &str,
                                         blob: &str,
                                         g_pt: ParsedTs,
                                         call_ts: f64,
                                         step_pos: Option<usize>,
                                         allow_missing_avail: bool| {
        let g_ts = g_pt.ts;
        let args = tc.get("args").and_then(|v| v.as_object());
        let action = args
            .and_then(|m| m.get("action"))
            .map(|v| val_to_str(Some(v)).trim().to_lowercase())
            .unwrap_or_default();
        let wname = args
            .and_then(|m| m.get("name"))
            .map(|v| val_to_str(Some(v)).trim().to_string())
            .unwrap_or_default();
        let req_model = args
            .and_then(|m| m.get("model"))
            .map(|v| val_to_str(Some(v)).trim().to_lowercase())
            .unwrap_or_default();
        let mdata = extract_json_dict(blob);
        let md_err = mdata
            .as_ref()
            .and_then(|m| m.get("error"))
            .map(|v| val_to_str(Some(v)))
            .unwrap_or_default();
        let err_detail = format!("{}\n{}", md_err, blob).trim().to_string();
        let json_err = mdata
            .as_ref()
            .map_or(false, |m| json_truthy(m.get("error")));
        let blob_low = blob.to_lowercase();
        let is_err = g_status == "ERROR"
            || json_err
            || (mdata.is_none() && (blob_low.contains("error") || blob_low.contains("failed")));
        let is_confirmed_ok = !is_err && g_status == "DONE";
        let res_ts = if g_ts > 0.0 {
            call_ts.max(g_ts)
        } else {
            call_ts
        };

        if !wname.is_empty() && !req_model.is_empty() {
            requested_models
                .entry(wname.clone())
                .or_default()
                .insert(req_model.clone());
            if req_model == cwg_common::OPUS_HIGH_MODEL {
                opus_requested_ts
                    .entry(wname.clone())
                    .or_default()
                    .push(if call_ts > 0.0 { call_ts } else { now_sec() });
            }
        }
        let eff_model = if !req_model.is_empty() {
            req_model.clone()
        } else {
            mdata
                .as_ref()
                .and_then(|m| m.get("model"))
                .map(|v| val_to_str(Some(v)).trim().to_lowercase())
                .unwrap_or_default()
        };
        if action == "add" && is_confirmed_ok && !wname.is_empty() && !eff_model.is_empty() {
            model_event_ord += 1;
            let add_ts = if call_ts > 0.0 { call_ts } else { res_ts };
            worker_model_events
                .entry(wname.clone())
                .or_default()
                .push(WorkerModelEvent::ConfirmedAdd {
                    ts: add_ts,
                    ord: model_event_ord,
                    model: eff_model.clone(),
                });
        }
        if action == "model" && !is_err && !wname.is_empty() {
            model_event_ord += 1;
            // INVARIANT: Never collapse an unknown switch start (`call_ts <= 0.0`) to `g_ts`,
            // never collapse an unknown completion (`g_ts <= 0.0`, e.g. `DONE` without `created_at`)
            // to `call_ts`, and preserve whole-second `g_pt.coarse` completion upper bound
            // (`g_ts.floor() + 1.0`) so sub-second verdicts inside a coarse `DONE` second stay
            // fail-closed. Transcript ordinal `model_event_ord` prevents earlier switches from
            // recovering a later untimestamped `UnconfirmedSwitch`.
            if is_confirmed_ok && g_ts > 0.0 {
                let req_ts = call_ts;
                let done_ts = call_ts.max(g_ts);
                let done_ub = if g_pt.coarse {
                    call_ts.max(g_ts.floor() + 1.0)
                } else {
                    done_ts
                };
                if req_ts > 0.0 && done_ub > req_ts + TS_EPS {
                    model_switches.entry(wname.clone()).or_default().push((
                        req_ts,
                        "[model-switch-req]".to_string(),
                        step_pos,
                    ));
                }
                model_switches.entry(wname.clone()).or_default().push((
                    done_ub,
                    format!("[model-switch:{}]", eff_model),
                    step_pos,
                ));
                worker_model_events
                    .entry(wname.clone())
                    .or_default()
                    .push(WorkerModelEvent::ConfirmedSwitch {
                        req_ts,
                        done_ts,
                        done_ub,
                        ord: model_event_ord,
                        model: eff_model.clone(),
                    });
            } else {
                let unconf_ts = if call_ts > 0.0 { call_ts } else { 0.0 };
                if call_ts > 0.0 {
                    model_switches.entry(wname.clone()).or_default().push((
                        call_ts,
                        "[model-switch-req]".to_string(),
                        step_pos,
                    ));
                }
                worker_model_events
                    .entry(wname.clone())
                    .or_default()
                    .push(WorkerModelEvent::UnconfirmedSwitch {
                        req_ts: unconf_ts,
                        ord: model_event_ord,
                    });
            }
        }

        if action == "models" && is_confirmed_ok {
            if let Some(ref md) = mdata {
                let avail: HashSet<String> = md
                    .get("models")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                let quotas_opt = md.get("quotas").and_then(|v| v.as_object());
                for (mdl, flag, ts_ref, last_ts_ref, healthy_ts_ref) in [
                    (
                        cwg_common::OPUS_HIGH_MODEL,
                        &mut ev.opus_issue_verified,
                        &mut ev.opus_issue_ts,
                        None,
                        None,
                    ),
                    (
                        cwg_common::SONNET_HIGH_MODEL,
                        &mut ev.sonnet_issue_verified,
                        &mut ev.sonnet_issue_ts,
                        Some(&mut ev.sonnet_last_issue_ts),
                        Some(&mut ev.sonnet_healthy_ts),
                    ),
                    (
                        cwg_common::NEON_XHIGH_MODEL,
                        &mut ev.neon_issue_verified,
                        &mut ev.neon_issue_ts,
                        Some(&mut ev.neon_last_issue_ts),
                        Some(&mut ev.neon_healthy_ts),
                    ),
                    (
                        cwg_common::HYDROGEN_XHIGH_MODEL,
                        &mut ev.hydrogen_issue_verified,
                        &mut ev.hydrogen_issue_ts,
                        Some(&mut ev.hydrogen_last_issue_ts),
                        Some(&mut ev.hydrogen_healthy_ts),
                    ),
                ] {
                    let missing = !avail.is_empty() && allow_missing_avail && !avail.contains(mdl);
                    let exhausted = quotas_opt.is_some_and(|q| quota_exhausted(q, mdl));
                    if missing || exhausted {
                        mark_issue_ts(flag, ts_ref, last_ts_ref, res_ts, res_ts);
                    } else {
                        // INVARIANT: Presence in `models` alone does not prove positive quota (0%-quota models stay listed); require confirmed `DONE` status, positive `res_ts`, and explicit positive quota in `quotas` before clearing exhaustion.
                        let listed_ok = avail.is_empty() || avail.contains(mdl);
                        let healthy =
                            listed_ok && quotas_opt.is_some_and(|q| quota_positive(q, mdl));
                        if healthy && res_ts > 0.0 {
                            if let Some(h_ts) = healthy_ts_ref {
                                *h_ts = (*h_ts).max(res_ts);
                            }
                        }
                    }
                }
            }
        }

        // INVARIANT: Only model/quota/availability failures count (never duplicate worker names or bad args).
        if is_err && !req_model.is_empty() && model_failure_re().is_match(&err_detail) {
            let mut single = HashSet::new();
            single.insert(req_model);
            record_model_failure(ev, &single, &wname, res_ts, res_ts);
        }
    };

    let fallback_cid = marker.map(|m| val_to_str(m.get("session"))).unwrap_or_default();
    let (brain_root_opt, conv_cid) =
        rio::swarm_brain_and_cid(transcript_path.unwrap_or(""), &fallback_cid);
    let prior_closed_ts = if first_ts > 0.0 && research_reset_ts <= 0.0 && !conv_cid.is_empty() {
        cwg_common::enforcement_state_closed_ts(&conv_cid)
    } else {
        0.0
    };
    // INVARIANT: Allow a bounded pre-marker `swarm(action="models")` quota check strictly after any prior closed candidate (when no `research_reset` is active) so checking model availability before `swarm-cache prepare` / first edit still proves fallback causality.
    let models_floor_ts = if first_ts > 0.0 && research_reset_ts <= 0.0 {
        (first_ts - MODELS_LEAD_IN_MAX_SEC).max(prior_closed_ts + TS_EPS)
    } else {
        0.0
    };

    if let Some(tp) = transcript_path {
        if !tp.is_empty() && rio::has_prefix_slice_gap(steps) {
            let tail_first = if steps.len() > 1
                && steps[0].get("step_index").and_then(|v| v.as_i64()) == Some(0)
            {
                steps.get(1)
            } else {
                steps.first()
            };
            let tail_idx = tail_first
                .and_then(|s| s.get("step_index"))
                .and_then(|v| v.as_i64());
            let tail_ts = tail_first
                .and_then(|s| s.get("created_at"))
                .and_then(|v| v.as_str())
                .map(rio::parse_iso_ts)
                .unwrap_or(0.0);
            let compact_check_floor = if models_floor_ts > 0.0 {
                models_floor_ts.min(first_ts - 2.0)
            } else {
                first_ts - 2.0
            };
            if let Some(t_idx) =
                tail_idx.filter(|&i| i > 1 && (tail_ts == 0.0 || tail_ts > compact_check_floor))
            {
                // SAFETY: Recover early candidate swarm model/quota signals evicted from `transcript_full.jsonl` tail window via compact `transcript.jsonl` without shifting `steps` indices.
                ev.compact_steps = recover_compact_swarm_steps(
                    tp,
                    t_idx,
                    first_ts,
                    models_floor_ts,
                    &mut ev,
                    &mut host_worker_errors,
                    &mut inspect_swarm_tool_result,
                );
            }
        }
    }

    for (idx, st) in steps.iter().enumerate() {
        let ssource = val_to_str(st.get("source"));
        if ssource == "SYSTEM" {
            let sys_pt = st
                .get("created_at")
                .and_then(|v| v.as_str())
                .map(parse_iso_ts_meta)
                .unwrap_or_default();
            let sys_ts = sys_pt.ts;
            let sys_txt = val_to_str(st.get("content"));
            if (!pending_bg_tasks.is_empty() || !passive_bg_tasks.is_empty())
                && sys_txt.contains("Task id \"")
            {
                let done_tids: Vec<String> = pending_bg_tasks
                    .iter()
                    .chain(passive_bg_tasks.iter())
                    .filter(|tid| {
                        sys_txt.contains(&format!("Task id \"{}\" finished", tid))
                            || sys_txt.contains(&format!("Task id \"{}\" was canceled", tid))
                    })
                    .cloned()
                    .collect();
                for tid in done_tids {
                    pending_bg_tasks.remove(&tid);
                    passive_bg_tasks.remove(&tid);
                }
            }
            if sys_ts == 0.0 || sys_ts >= first_ts - 2.0 {
                record_system_swarm_errors(&sys_txt, sys_pt, first_ts, &mut host_worker_errors);
                let matched_codex: Vec<String> = pending_codex_tasks
                    .keys()
                    .filter(|tid| {
                        sys_txt.contains(&format!("Task id \"{}\" finished with result:", tid))
                    })
                    .cloned()
                    .collect();
                for tid in matched_codex {
                    if let Some((bg_cmd, bg_call_ts)) = pending_codex_tasks.remove(&tid) {
                        let bg_status = if sys_txt
                            .to_lowercase()
                            .contains("command exited with code 0")
                        {
                            "DONE"
                        } else {
                            "ERROR"
                        };
                        let (is_outage, aborted_rid) =
                            codex_lane::inspect_codex_cmd_result(&bg_cmd, bg_status, &sys_txt);
                        if is_outage {
                            mark_codex_issue(&mut ev, sys_ts, idx as isize);
                        } else if aborted_rid.is_some() && sys_txt.contains("timeout_after_") {
                            ev.codex_timeout_seen = true;
                        }
                        if let Some(rid) = aborted_rid {
                            ev.aborted_codex_reviews.entry(rid).or_insert(bg_call_ts);
                        }
                    }
                }
            }
            continue;
        }
        if ssource != "MODEL" || st.get("type").and_then(|v| v.as_str()) != Some("PLANNER_RESPONSE")
        {
            continue;
        }
        let call_pt = st
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(parse_iso_ts_meta)
            .unwrap_or_default();
        let call_ts = call_pt.ts;
        let is_models_lead_in = is_models_lead_in_ts(call_ts, first_ts, models_floor_ts);
        if call_ts > 0.0 && call_ts < first_ts - 2.0 && !is_models_lead_in {
            continue;
        }
        let all_tcs = st
            .get("tool_calls")
            .and_then(|v| v.as_array())
            .map(|a| a.as_slice())
            .unwrap_or(&[]);
        if call_ts > 0.0 && !is_models_lead_in {
            for tc in all_tcs {
                let Some(tc_obj) = tc.as_object() else {
                    continue;
                };
                let tname = tc_obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let targs = tc_obj.get("args").and_then(|v| v.as_object());
                if tname == "post_message" {
                    let txt = targs
                        .and_then(|m| m.get("text"))
                        .map(|v| val_to_str(Some(v)).trim().to_lowercase())
                        .unwrap_or_default();
                    let hint = truncate_chars(&txt, 64).to_string();
                    coord_call_events.push((call_pt, hint, idx));
                } else if tname == "swarm"
                    && targs
                        .and_then(|m| m.get("action"))
                        .map(|v| val_to_str(Some(v)).trim().to_lowercase())
                        .as_deref()
                        == Some("add")
                {
                    let base_n = targs
                        .and_then(|m| m.get("name"))
                        .map(|v| val_to_str(Some(v)).trim().to_string())
                        .unwrap_or_default();
                    let tasks_len = targs
                        .and_then(|m| m.get("tasks"))
                        .and_then(|v| v.as_array())
                        .map_or(0, |a| a.len());
                    let n_cnt = targs
                        .and_then(|m| m.get("n"))
                        .map(|v| val_to_i64(Some(v)).max(0) as usize)
                        .unwrap_or(1);
                    let copies = 1usize.max(tasks_len).max(n_cnt);
                    for copy_idx in 0..copies {
                        let w_full = if copies > 1 && !base_n.is_empty() {
                            format!("{}-{}", base_n, copy_idx + 1)
                        } else {
                            base_n.clone()
                        };
                        if !w_full.is_empty() {
                            worker_add_step.insert(w_full.clone(), idx);
                        }
                        let hint = if w_full.is_empty() {
                            String::new()
                        } else {
                            format!("@{}", w_full).to_lowercase()
                        };
                        coord_call_events.push((call_pt, hint, idx));
                    }
                }
            }
        }
        let has_swarm_tc = all_tcs.iter().any(|tc| {
            if is_models_lead_in {
                is_swarm_models_call(tc)
            } else {
                tc.get("name").and_then(|v| v.as_str()) == Some("swarm")
            }
        });
        let has_run_cmd_tc = !is_models_lead_in
            && all_tcs
                .iter()
                .any(|tc| tc.get("name").and_then(|v| v.as_str()) == Some("run_command"));
        if !has_swarm_tc && !has_run_cmd_tc {
            continue;
        }

        let generic_steps = collect_generic_results(steps, idx);
        for (pos, tc) in all_tcs.iter().enumerate() {
            let Some(tc_obj) = tc.as_object() else {
                continue;
            };
            let (g_status, blob, g_pt) = if pos < generic_steps.len() {
                (
                    generic_steps[pos].0.as_str(),
                    generic_steps[pos].1.as_str(),
                    generic_steps[pos].2,
                )
            } else {
                ("", "", ParsedTs::default())
            };
            let g_ts = g_pt.ts;
            let tname = tc_obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if tname == "run_command" {
                if is_models_lead_in {
                    continue;
                }
                let targs = tc_obj.get("args").and_then(|v| v.as_object());
                let cmd_str = targs
                    .and_then(|m| m.get("CommandLine"))
                    .map(|v| val_to_str(Some(v)))
                    .unwrap_or_default();
                let bgm_any = rio::extract_bg_task_id(blob);
                if let Some(ref bg_tid) = bgm_any {
                    let is_daemon = targs.map_or(false, |m| json_truthy(m.get("IsDaemon")));
                    if is_daemon || is_passive_listener_cmd(&cmd_str) {
                        passive_bg_tasks.insert(bg_tid.clone());
                    } else {
                        pending_bg_tasks.insert(bg_tid.clone());
                    }
                }
                if cmd_str.to_lowercase().contains("codex") {
                    let res_ts = if g_ts > 0.0 {
                        call_ts.max(g_ts)
                    } else {
                        call_ts
                    };
                    let (is_outage, aborted_rid) =
                        codex_lane::inspect_codex_cmd_result(&cmd_str, g_status, blob);
                    // INVARIANT: Bind Codex unavailability to the result step (`g_ts`/`idx + 1 + pos`), never the request step.
                    if is_outage {
                        mark_codex_issue(&mut ev, res_ts, (idx + 1 + pos) as isize);
                    } else if aborted_rid.is_some() && blob.contains("timeout_after_") {
                        ev.codex_timeout_seen = true;
                    }
                    if let Some(ref rid) = aborted_rid {
                        ev.aborted_codex_reviews.entry(rid.clone()).or_insert(call_ts);
                    }
                    if let Some(bg_tid) = bgm_any {
                        if aborted_rid.is_none() {
                            pending_codex_tasks.insert(bg_tid, (cmd_str, call_ts));
                        }
                    }
                }
                continue;
            }
            if tname != "swarm" || (is_models_lead_in && !is_swarm_models_call(tc)) {
                continue;
            }
            inspect_swarm_tool_result(&mut ev, tc, g_status, blob, g_pt, call_ts, Some(idx), true);
        }
    }

    ev.pending_bg_tasks = pending_bg_tasks.into_iter().collect();
    ev.passive_bg_tasks = passive_bg_tasks.into_iter().collect();

    let Some(brain_root) = brain_root_opt else {
        return ev;
    };
    if conv_cid.is_empty() {
        return ev;
    }
    let conv_dir = brain_root.join(&conv_cid);
    let members_map = rio::load_swarm_members(&brain_root, &conv_cid);
    if members_map.is_empty() {
        return ev;
    }

    let raw_board = cwg_common::read_swarm_board_tail(&brain_root, &conv_cid);
    ev.board_head = raw_board.len();
    coord_call_events.sort_by(|a, b| a.0.ts.total_cmp(&b.0.ts));
    let mut c_cursor = 0usize;
    struct BoardEntry {
        poster: String,
        text: String,
        raw_ts: f64,
        coarse_ts: bool,
        ord_ts: f64,
        pub_ts: f64,
        pub_coarse: bool,
        pub_ord_ub: f64,
        step_idx: Option<usize>,
        seq: i64,
    }
    let mut running_board_ts = 0.0f64;
    let mut running_pub_lb = 0.0f64;
    let mut running_pub_ub = 0.0f64;
    let mut parsed_board: Vec<BoardEntry> = Vec::with_capacity(raw_board.len());

    for (bp_idx, bp) in raw_board.iter().enumerate() {
        let poster = val_to_str(bp.get("agent"));
        let btext = val_to_str(bp.get("text")).trim().to_string();
        let bseq = cwg_common::extract_msg_seq(bp, (bp_idx + 1) as i64);
        let raw_pt = bp
            .get("time")
            .and_then(|v| v.as_str())
            .map(parse_iso_ts_meta)
            .unwrap_or_default();
        let raw_bts = raw_pt.ts;
        let pub_ts = raw_pt.ts;
        let pub_coarse = raw_pt.coarse;
        let pub_ord_ub = cwg_common::advance_monotonic_board_ub(
            pub_ts,
            pub_coarse,
            &mut running_pub_lb,
            &mut running_pub_ub,
        );
        let mut raw_ts = raw_bts;
        let mut coarse_ts = raw_pt.coarse;
        let mut bstep_idx: Option<usize> = None;
        if poster == "coordinator" && raw_bts > 0.0 {
            let low_btext = btext.to_lowercase();
            let mut probe = c_cursor;
            while probe < coord_call_events.len() && coord_call_events[probe].0.ts < raw_bts - 0.1 {
                probe += 1;
            }
            for cand_i in probe..coord_call_events.len() {
                let (evt_pt, ref evt_hint, evt_step) = coord_call_events[cand_i];
                if evt_pt.ts - raw_bts >= 1.5 {
                    break;
                }
                if evt_hint.is_empty() || low_btext.contains(evt_hint) {
                    raw_ts = evt_pt.ts;
                    coarse_ts = evt_pt.coarse;
                    bstep_idx = Some(evt_step);
                    c_cursor = cand_i + 1;
                    break;
                }
            }
        }
        let mut ord_ts = raw_ts;
        if ord_ts > 0.0 && running_board_ts > 0.0 && ord_ts < running_board_ts {
            // INVARIANT: `board.jsonl` is strictly append-only; clamp monotonic `ord_ts` without overwriting whole-second `raw_ts` used for switch-collision checks.
            ord_ts = running_board_ts;
        }
        if ord_ts > running_board_ts {
            running_board_ts = ord_ts;
        }
        parsed_board.push(BoardEntry {
            poster,
            text: btext,
            raw_ts,
            coarse_ts,
            ord_ts,
            pub_ts,
            pub_coarse,
            pub_ord_ub,
            step_idx: bstep_idx,
            seq: bseq,
        });
    }

    let has_reset = research_reset_ts > 0.0 || research_reset_seq > 0;
    let eff_research_reset_seq: i64 = if has_reset {
        cwg_common::compute_effective_reset_board_seq(
            parsed_board
                .iter()
                .map(|e| (e.seq, e.pub_ts, e.pub_coarse)),
            research_reset_seq,
            research_reset_ts,
        )
    } else {
        0
    };

    let known_workers: Vec<&str> = rio::swarm_worker_names(&members_map);

    for (mname, minfo) in &members_map {
        if !minfo.is_object() || rio::is_swarm_role_member(mname, Some(minfo)) {
            continue;
        }
        let cur_model = minfo
            .get("model")
            .map(|v| val_to_str(Some(v)).trim().to_lowercase())
            .unwrap_or_default();
        let mcid = minfo
            .get("conversation_id")
            .map(|v| val_to_str(Some(v)).trim().to_string())
            .unwrap_or_default();
        let killed = rio::is_swarm_member_killed(Some(minfo));
        let group_prefix = if trailing_digits_suffix_re().is_match(mname) {
            mname.rsplit_once('-').map(|(p, _)| p).unwrap_or("")
        } else {
            ""
        };

        let is_pre_reset_worker = has_reset
            && cwg_common::is_worker_spawned_before_reset(
                mname,
                Some(minfo),
                &raw_board,
                research_reset_ts,
                research_reset_seq,
                marker,
                if brain_root.as_os_str().is_empty() {
                    None
                } else {
                    Some(brain_root.as_path())
                },
            );

        let mut coord_posts: Vec<(f64, bool, String, Option<usize>, i64, f64)> = Vec::new();
        let mut broadcast_posts: Vec<(f64, bool, String, Option<usize>, i64, f64)> = Vec::new();
        let mut worker_board_posts: Vec<(f64, bool, f64, String, i64)> = Vec::new();
        let mut last_board_ts = 0.0f64;

        for entry in &parsed_board {
            if entry.text.is_empty() {
                continue;
            }
            // INVARIANT: Post-research-reset workers reusing a standard roster name must never inherit pre-reset board posts from a killed Cycle-1 worker.
            if has_reset
                && !is_pre_reset_worker
                && cwg_common::is_board_row_before_reset(
                    entry.seq,
                    entry.pub_ord_ub,
                    eff_research_reset_seq,
                    research_reset_ts,
                )
            {
                continue;
            }
            if entry.ord_ts > last_board_ts {
                last_board_ts = entry.ord_ts;
            }
            let entry_pub_ub = cwg_common::coarse_ts_upper_bound(entry.pub_ts, entry.pub_coarse);
            if entry.poster == "coordinator" {
                if rio::text_mentions_swarm_worker(&entry.text, mname) {
                    let scoped =
                        cwg_common::extract_worker_scoped_brief(&entry.text, mname, &known_workers);
                    coord_posts.push((
                        entry.ord_ts,
                        entry.coarse_ts,
                        scoped,
                        entry.step_idx,
                        entry.seq,
                        entry_pub_ub,
                    ));
                } else if rio::text_contains_mention(&entry.text, "all") {
                    let scoped =
                        cwg_common::extract_worker_scoped_brief(&entry.text, mname, &known_workers);
                    broadcast_posts.push((
                        entry.ord_ts,
                        entry.coarse_ts,
                        scoped,
                        entry.step_idx,
                        entry.seq,
                        entry_pub_ub,
                    ));
                }
            } else if entry.poster == *mname {
                // INVARIANT: Only posts authored by `mname` itself count as worker output (never coordinator prompts).
                // Preserve original whole-second/missing `entry.raw_ts` and `entry.coarse_ts` for model switch attribution alongside monotonic
                // `board_ord_ts` so append-order clamps never mask whole-second switch collisions.
                if entry.raw_ts == 0.0 || entry.ord_ts >= first_ts - 2.0 {
                    let board_ord_ts = if entry.ord_ts > 0.0 {
                        entry.ord_ts
                    } else {
                        last_board_ts
                    };
                    worker_board_posts.push((
                        entry.raw_ts,
                        entry.coarse_ts,
                        board_ord_ts,
                        entry.text.clone(),
                        entry.seq,
                    ));
                }
            }
        }

        let m_tp = if !mcid.is_empty() {
            Some(rio::member_transcript_path(&brain_root, &mcid))
        } else {
            None
        };
        let tsum = member_transcript_summary(m_tp.as_deref(), first_ts);

        let mut prior_reqs: HashSet<String> =
            requested_models.get(mname).cloned().unwrap_or_default();
        if !group_prefix.is_empty() {
            if let Some(g_reqs) = requested_models.get(group_prefix) {
                prior_reqs.extend(g_reqs.iter().cloned());
            }
        }

        let reset_min_ts = if has_reset && !is_pre_reset_worker && research_reset_ts > 0.0 {
            research_reset_ts
        } else {
            0.0
        };
        let keys = [
            Some(mname.as_str()),
            (!group_prefix.is_empty()).then_some(group_prefix),
        ];
        let mut model_events: Vec<WorkerModelEvent> = Vec::new();
        let mut worker_opus_req_ts: Option<f64> = None;
        for key in keys.into_iter().flatten() {
            if let Some(entries) = worker_model_events.get(key) {
                for ev_item in entries {
                    let keep = match ev_item {
                        WorkerModelEvent::ConfirmedAdd { ts, .. } => {
                            reset_min_ts <= 0.0 || *ts <= 0.0 || *ts > reset_min_ts
                        }
                        WorkerModelEvent::ConfirmedSwitch { req_ts, done_ub, .. } => {
                            reset_min_ts <= 0.0
                                || (*req_ts <= 0.0 && *done_ub <= 0.0)
                                || (*done_ub).max(*req_ts) > reset_min_ts
                        }
                        WorkerModelEvent::UnconfirmedSwitch { req_ts, .. } => {
                            reset_min_ts <= 0.0 || *req_ts <= 0.0 || *req_ts > reset_min_ts
                        }
                    };
                    if keep {
                        model_events.push(ev_item.clone());
                    }
                }
            }
            if let Some(entries) = opus_requested_ts.get(key) {
                for &ots in entries {
                    if (reset_min_ts <= 0.0 || ots <= 0.0 || ots > reset_min_ts)
                        && ots > 0.0
                        && worker_opus_req_ts.map_or(true, |cur| ots < cur)
                    {
                        worker_opus_req_ts = Some(ots);
                    }
                }
            }
        }
        let event_sort_key = |ev_item: &WorkerModelEvent| -> (f64, f64, u8, usize) {
            match ev_item {
                WorkerModelEvent::ConfirmedAdd { ts, ord, .. } => (*ts, *ts, 0, *ord),
                WorkerModelEvent::UnconfirmedSwitch { req_ts, ord } => (*req_ts, *req_ts, 1, *ord),
                WorkerModelEvent::ConfirmedSwitch {
                    req_ts,
                    done_ts,
                    ord,
                    ..
                } => (*req_ts, *done_ts, 2, *ord),
            }
        };
        model_events.sort_by(|a, b| {
            let ka = event_sort_key(a);
            let kb = event_sort_key(b);
            ka.0.total_cmp(&kb.0)
                .then_with(|| ka.1.total_cmp(&kb.1))
                .then_with(|| ka.2.cmp(&kb.2))
                .then_with(|| ka.3.cmp(&kb.3))
        });
        let has_any_switch = model_events.iter().any(|e| {
            matches!(
                e,
                WorkerModelEvent::ConfirmedSwitch { .. } | WorkerModelEvent::UnconfirmedSwitch { .. }
            )
        });
        let first_switch_req_ts = model_events
            .iter()
            .filter_map(|e| match e {
                WorkerModelEvent::ConfirmedSwitch {
                    req_ts, done_ts, ..
                } => {
                    if *req_ts > 0.0 {
                        Some(*req_ts)
                    } else if *done_ts > 0.0 {
                        Some(*done_ts)
                    } else {
                        None
                    }
                }
                WorkerModelEvent::UnconfirmedSwitch { req_ts, .. } if *req_ts > 0.0 => Some(*req_ts),
                _ => None,
            })
            .reduce(f64::min);

        let host_errs: &[ParsedTs] = if !mcid.is_empty() {
            host_worker_errors
                .get(&(mname.clone(), mcid.clone()))
                .map(Vec::as_slice)
                .unwrap_or(&[])
        } else {
            &[]
        };
        let host_err_ts = host_errs.iter().map(|p| p.ts).reduce(f64::max).unwrap_or(0.0);
        if tsum.has_error || !host_errs.is_empty() {
            // INVARIANT: Attribute each transcript error timestamp to its model epoch BEFORE slot
            // grouping so an ambiguous whole-second collision neither drops a trustworthy sibling
            // error nor pollutes `*_last_issue_ts` with an unverified boundary timestamp.
            // Async host `SYSTEM_MESSAGE` notices carry no attempt ID or model name: fence them
            // strictly to the initial pre-switch epoch (`< first_switch_req_ts` and attributed by
            // `resolve_window_model`), drop post-switch notices fail-closed, and fold the earliest
            // pre-switch host notice (`max_ts = 0.0`) only when the transcript has no attributed
            // error in that initial epoch.
            let mut attempt_errors: Vec<(Option<String>, f64, f64)> =
                if !tsum.error_timestamps.is_empty() {
                    let mut turn_bounds: Vec<f64> = Vec::new();
                    let mut push_pos = |ts: f64| {
                        if ts > 0.0 {
                            turn_bounds.push(ts);
                        }
                    };
                    push_pos(tsum.start_ts);
                    for p in &coord_posts {
                        push_pos(p.0);
                    }
                    for p in &broadcast_posts {
                        push_pos(p.0);
                    }
                    for p in &worker_board_posts {
                        push_pos(p.0);
                    }
                    for p in &tsum.outputs {
                        push_pos(p.pt.ts);
                    }
                    for mev in &model_events {
                        match mev {
                            WorkerModelEvent::ConfirmedAdd { ts, .. } => push_pos(*ts),
                            WorkerModelEvent::ConfirmedSwitch {
                                req_ts,
                                done_ts,
                                done_ub,
                                ..
                            } => {
                                push_pos(*req_ts);
                                push_pos(*done_ts);
                                push_pos(*done_ub);
                            }
                            WorkerModelEvent::UnconfirmedSwitch { req_ts, .. } => push_pos(*req_ts),
                        }
                    }
                    turn_bounds.sort_by(|a, b| a.total_cmp(b));
                    turn_bounds.dedup_by(|a, b| (*a - *b).abs() <= TS_EPS);

                    let mut slot_errs: BTreeMap<(usize, String), (f64, f64)> = BTreeMap::new();
                    for &err_pt in &tsum.error_timestamps {
                        let err_ts = err_pt.ts;
                        if err_ts <= 0.0 {
                            continue;
                        }
                        let mdl_key = if has_any_switch {
                            let resolved = resolve_window_model(
                                &model_events,
                                &cur_model,
                                true,
                                err_ts,
                                err_pt.coarse,
                            );
                            if resolved.is_empty() {
                                continue;
                            }
                            resolved
                        } else {
                            String::new()
                        };
                        let slot = turn_bounds.partition_point(|&b| b <= err_ts + TS_EPS);
                        slot_errs
                            .entry((slot, mdl_key))
                            .and_modify(|(lo, hi)| {
                                *lo = lo.min(err_ts);
                                *hi = hi.max(err_ts);
                            })
                            .or_insert((err_ts, err_ts));
                    }
                    slot_errs
                        .into_iter()
                        .map(|((_, mdl), (lo, hi))| {
                            (if mdl.is_empty() { None } else { Some(mdl) }, lo, hi)
                        })
                        .collect()
                } else {
                    Vec::new()
                };
            let has_initial_epoch_tsum = if !has_any_switch {
                !attempt_errors.is_empty()
            } else {
                attempt_errors
                    .iter()
                    .any(|(_, lo, _)| first_switch_req_ts.is_some_and(|fs| *lo < fs - TS_EPS))
            };
            if !has_initial_epoch_tsum {
                if !has_any_switch {
                    if let Some(h_lo) = host_errs
                        .iter()
                        .map(|p| p.ts)
                        .filter(|&h_ts| h_ts > 0.0)
                        .reduce(f64::min)
                    {
                        attempt_errors.push((None, h_lo, 0.0));
                    }
                } else if let Some((h_lo, h_mdl)) = host_errs
                    .iter()
                    .copied()
                    .filter(|h_pt| {
                        h_pt.ts > 0.0 && first_switch_req_ts.is_some_and(|fs| h_pt.ts < fs - TS_EPS)
                    })
                    .filter_map(|h_pt| {
                        let mdl = resolve_window_model(
                            &model_events,
                            &cur_model,
                            true,
                            h_pt.ts,
                            h_pt.coarse,
                        );
                        if mdl.is_empty() {
                            None
                        } else {
                            Some((h_pt.ts, mdl))
                        }
                    })
                    .min_by(|a, b| a.0.total_cmp(&b.0))
                {
                    attempt_errors.push((Some(h_mdl), h_lo, 0.0));
                }
            }
            let fallback_model_candidates = || -> HashSet<String> {
                let mut cand = HashSet::new();
                if !cur_model.is_empty() {
                    cand.insert(cur_model.clone());
                } else {
                    cand.extend(prior_reqs.iter().cloned());
                }
                cand
            };
            let mut any_attributed = false;
            for (resolved_model, min_ts, max_ts) in attempt_errors {
                if let Some(err_model) = resolved_model {
                    let mut single = HashSet::new();
                    single.insert(err_model);
                    record_model_failure(&mut ev, &single, mname, min_ts, max_ts);
                    any_attributed = true;
                } else {
                    let cand = fallback_model_candidates();
                    if !cand.is_empty() {
                        record_model_failure(&mut ev, &cand, mname, min_ts, max_ts);
                        any_attributed = true;
                    }
                }
            }
            if !any_attributed && !has_any_switch {
                let cand = fallback_model_candidates();
                if !cand.is_empty() {
                    let fb_ts = tsum.error_ts.max(host_err_ts);
                    record_model_failure(&mut ev, &cand, mname, fb_ts, tsum.error_ts);
                }
            }
        }

        struct CombinedOutput {
            raw_ts: f64,
            coarse_ts: bool,
            attr_ts: f64,
            attr_coarse: bool,
            delayed_flush: bool,
            order_ts: f64,
            emit_idx: usize,
            text: String,
            bseq: i64,
            causal_seq: i64,
            is_revoker: bool,
            tidx: Option<usize>,
        }
        let classify_verdict_polarity = |text: &str| -> Option<bool> {
            let rev_dec = cwg_common::extract_review_decision(text);
            let has_rev = rev_dec.0.is_some() && rev_dec.1.is_some();
            let rev_pos = matches!(rev_dec.1.as_deref(), Some("APPROVED" | "READY"));
            // INVARIANT: Never classify any message containing a positive verdict (`APPROVED`, `READY`)
            // as a fail-closed revoker, so mixed text can never warp a positive verdict across a window.
            if has_rev && rev_pos {
                Some(true)
            } else if has_rev {
                Some(false)
            } else {
                None
            }
        };
        let crosses_switch = |a: f64, b: f64| -> bool {
            has_any_switch && {
                let (lo, hi) = (a.min(b), a.max(b));
                switch_ts_any(&model_events, true, |t| t > lo + TS_EPS && t <= hi + TS_EPS)
            }
        };
        let mut tsum_ord_ts: Vec<f64> = Vec::with_capacity(tsum.outputs.len());
        let mut cur_t_ord = tsum.start_ts;
        for out_item in &tsum.outputs {
            max_into(&mut cur_t_ord, out_item.pt.ts);
            tsum_ord_ts.push(cur_t_ord);
        }
        let contains_ascii_ci = |hay: &str, needle: &[u8]| -> bool {
            hay.as_bytes()
                .windows(needle.len())
                .any(|w| w.eq_ignore_ascii_case(needle))
        };
        let has_rev_header_kw = |s: &str| {
            contains_ascii_ci(s, b"verdict") || contains_ascii_ci(s, b"closure")
        };
        let has_rev_revoker_kw = |s: &str| {
            contains_ascii_ci(s, b"revise")
                || contains_ascii_ci(s, b"blocked")
                || contains_ascii_ci(s, b"escalate")
        };
        let might_cross_rev_revoker_with_hdr = |h: &str, t: &str, h_has_hdr: bool| -> bool {
            let mut t_has_rev: Option<bool> = None;
            if h_has_hdr {
                let tr = has_rev_revoker_kw(t);
                if tr {
                    return true;
                }
                t_has_rev = Some(tr);
            }
            let t_end = t.trim_end();
            if !(t_end.ends_with('}') || t_end.ends_with("```")) {
                return false;
            }
            if !(h.contains('{') || h.contains("```")) {
                return false;
            }
            if h.contains("\\u") || t.contains("\\u") {
                return true;
            }
            (h_has_hdr || has_rev_header_kw(t))
                && (*t_has_rev.get_or_insert_with(|| has_rev_revoker_kw(t))
                    || has_rev_revoker_kw(h))
        };
        let might_cross_rev_revoker =
            |h: &str, t: &str| might_cross_rev_revoker_with_hdr(h, t, has_rev_header_kw(h));
        let mut split_revoker_t: Vec<bool> = vec![false; tsum.outputs.len()];
        let mut polarity_cache: Vec<Option<Option<bool>>> = vec![None; tsum.outputs.len()];
        for i in 0..tsum.outputs.len().saturating_sub(1) {
            let head = tsum.outputs[i].text.as_str();
            let tail = tsum.outputs[i + 1].text.as_str();
            let head_has_rev_hdr = has_rev_header_kw(head);
            let pair_may_cross_rev =
                might_cross_rev_revoker_with_hdr(head, tail, head_has_rev_hdr);
            if !pair_may_cross_rev {
                continue;
            }
            let cur_pol = *polarity_cache[i]
                .get_or_insert_with(|| classify_verdict_polarity(head));
            let nxt_pol = *polarity_cache[i + 1]
                .get_or_insert_with(|| classify_verdict_polarity(tail));
            if nxt_pol == Some(true) {
                continue;
            }
            let can_cross_rev = pair_may_cross_rev && nxt_pol.is_none();
            if !can_cross_rev {
                continue;
            }
            let crosses_rev_revoker =
                cwg_common::extract_split_review_revoker(head, tail).0.is_some();
            if crosses_rev_revoker {
                if cur_pol.is_none() {
                    split_revoker_t[i] = true;
                }
                split_revoker_t[i + 1] = true;
            }
        }
        let mut t_cursor = 0usize;
        let mut t_emit_cursor = 0usize;
        let mut matched_t: HashSet<usize> = HashSet::new();
        let mut combined_outputs: Vec<CombinedOutput> = Vec::new();
        let mut running_board_ord_ts = 0.0f64;
        let mut running_t_ord_ts = tsum.start_ts;
        let mut running_t_seq = 0i64;
        let mut unmatched_pre_round_boards: Vec<(f64, f64, f64, f64, &str)> = Vec::new();
        let push_unmatched_t =
            |ti: usize,
             combined: &mut Vec<CombinedOutput>,
             running_t_ord: &mut f64,
             causal_seq: i64| {
                let u_item = &tsum.outputs[ti];
                let clamped_ord = tsum_ord_ts[ti].max(*running_t_ord);
                let is_revoker = (causal_seq > 0
                    || (u_item.pt.ts > 0.0 && clamped_ord > u_item.pt.ts))
                    && (split_revoker_t[ti]
                        || classify_verdict_polarity(&u_item.text) == Some(false));
                // INVARIANT: Never warp a timestamped non-revoker unmatched transcript entry forward via `running_t_ord`;
                // un-timestamped entries and fail-closed revokers inherit the preceding merged lower bound so a later
                // coarse `ACTIONABLE_FIXES` / `REVISE` never sorts ahead of the `CLEAN` / `APPROVED` it followed.
                let u_ord = if u_item.pt.ts > 0.0 && !is_revoker {
                    tsum_ord_ts[ti]
                } else {
                    clamped_ord
                };
                max_into(running_t_ord, u_ord);
                let emit_idx = combined.len();
                combined.push(CombinedOutput {
                    raw_ts: u_item.pt.ts,
                    coarse_ts: u_item.pt.coarse,
                    attr_ts: u_item.pt.ts,
                    attr_coarse: u_item.pt.coarse,
                    delayed_flush: false,
                    order_ts: u_ord,
                    emit_idx,
                    text: u_item.text.clone(),
                    bseq: 0,
                    causal_seq,
                    is_revoker,
                    tidx: Some(ti),
                });
            };
        for (b_idx, (bts, bcoarse, board_ord_ts, btxt, bseq)) in worker_board_posts.iter().enumerate()
        {
            let mut eff_ots = *bts;
            let mut eff_coarse = *bcoarse;
            let mut attr_ts = *bts;
            let mut attr_coarse = *bcoarse;
            let next_worker_ub = worker_board_posts[b_idx + 1..]
                .iter()
                .find(|p| p.0 > 0.0)
                .map(|p| board_ts_upper_bound(p.0, p.1))
                .unwrap_or(f64::INFINITY);
            let next_coord_ub = if *bseq > 0 {
                coord_posts
                    .iter()
                    .chain(broadcast_posts.iter())
                    .filter(|c| c.4 > *bseq && c.0 > 0.0)
                    .map(|c| board_ts_upper_bound(c.0, c.1))
                    .reduce(f64::min)
                    .unwrap_or(f64::INFINITY)
            } else {
                f64::INFINITY
            };
            let prev_coord_bts = if *bseq > 0 {
                coord_posts
                    .iter()
                    .chain(broadcast_posts.iter())
                    .filter(|c| c.4 < *bseq && c.0 > 0.0)
                    .map(|c| c.0)
                    .reduce(f64::max)
                    .unwrap_or(0.0)
            } else {
                0.0
            };
            let next_bound = next_worker_ub.min(next_coord_ub);
            let mut cand_tidx: Option<usize> = None;
            let mut cand_count: u8 = 0;
            let mut delayed_tidx: Option<usize> = None;
            let mut delayed_count: u8 = 0;
            let bts_ub = board_ts_upper_bound(*bts, *bcoarse);
            for (tidx, item) in tsum.outputs.iter().enumerate().skip(t_cursor) {
                // INVARIANT: Only non-failed `post_message` transcript tool calls produce `board.jsonl` entries;
                // prefer a unique 1-to-1 in-round match (`after_prev_coord`), and fall back to a unique delayed
                // board flush (`ots < bts_ub`) even across an intervening coordinator post so provenance (`attr_ts`)
                // is preserved while round/window membership still respects formation time. Refuse forward-crossing
                // merges (`ots > bts`) across a switch boundary (`4h1`/`4j`).
                if !item.is_board_post || item.text != *btxt {
                    continue;
                }
                let ots = item.pt.ts;
                let is_cand = if *bts == 0.0 && ots == 0.0 {
                    true
                } else if *bts <= 0.0
                    || ots <= 0.0
                    || (ots - *bts).abs() >= 5.0
                    || ots >= next_bound
                    || (ots > *bts + TS_EPS && crosses_switch(*bts, ots))
                {
                    continue;
                } else {
                    prev_coord_bts <= 0.0
                        || if item.pt.coarse {
                            board_ts_upper_bound(ots, true) > prev_coord_bts + TS_EPS
                        } else {
                            ots >= prev_coord_bts - TS_EPS
                        }
                };
                if is_cand {
                    if cand_count == 0 {
                        cand_tidx = Some(tidx);
                    }
                    cand_count = cand_count.saturating_add(1);
                    if cand_count >= 2 {
                        break;
                    }
                } else if cand_count == 0 && ots < bts_ub {
                    if delayed_count == 0 {
                        delayed_tidx = Some(tidx);
                    }
                    delayed_count = delayed_count.saturating_add(1);
                }
            }
            let mut matched_idx: Option<usize> = None;
            let mut delayed_flush = false;
            let resolved_tidx = if cand_count == 1 {
                cand_tidx
            } else if cand_count == 0 && delayed_count == 1 {
                delayed_tidx
            } else {
                None
            };
            if let Some(tidx) = resolved_tidx {
                let opt = tsum.outputs[tidx].pt;
                let ots = opt.ts;
                if ots > eff_ots || (ots == eff_ots && eff_coarse && !opt.coarse) {
                    eff_ots = ots;
                    eff_coarse = opt.coarse;
                }
                if ots > 0.0
                    && (ots < attr_ts - TS_EPS
                        || (attr_coarse
                            && !opt.coarse
                            && ots < attr_ts.floor() + 1.0 - TS_EPS))
                {
                    attr_ts = ots;
                    attr_coarse = opt.coarse;
                }
                // INVARIANT: A board publication at coarse second `[bts, bts+1)` or strictly after
                // `attr_ts` (`pub_ub > attr_ts`) cannot prove formation occurred after an intervening
                // same-second assignment/round boundary (`formed_before` checks true uncertainty bounds).
                let pub_ub =
                    cwg_common::coarse_ts_upper_bound(*bts, *bcoarse).max(*board_ord_ts);
                delayed_flush = attr_ts > 0.0 && attr_ts < pub_ub - TS_EPS;
                matched_t.insert(tidx);
                matched_idx = Some(tidx);
                t_cursor = tidx + 1;
            } else if cand_count > 1 || (cand_count == 0 && delayed_count > 1) {
                // INVARIANT: Multiple unmatched `post_message` calls with identical text make this
                // board row's formation epoch ambiguous; clear `attr_ts` so switch attribution fails
                // closed while each individual transcript call is still evaluated on its own.
                attr_ts = 0.0;
                attr_coarse = false;
            }
            let mut matched_t_ord = 0.0f64;
            if let Some(m_tidx) = matched_idx {
                // INVARIANT: Emit preceding unmatched transcript entries strictly before the merged entry
                // so transcript-only earlier verdicts (e.g. timestamped APPROVED) can never sort after a
                // merged later un-timestamped verdict (e.g. REVISE).
                while t_emit_cursor < m_tidx {
                    if !matched_t.contains(&t_emit_cursor) {
                        push_unmatched_t(
                            t_emit_cursor,
                            &mut combined_outputs,
                            &mut running_t_ord_ts,
                            running_t_seq,
                        );
                    }
                    t_emit_cursor += 1;
                }
                if t_emit_cursor == m_tidx {
                    t_emit_cursor = m_tidx + 1;
                }
                matched_t_ord = tsum_ord_ts[m_tidx].max(running_t_ord_ts);
            } else if round_start_msg_id > 0 && *bseq > 0 && *bseq <= round_start_msg_id {
                let next_any_ub = parsed_board
                    .iter()
                    .filter(|e| e.seq > *bseq && e.raw_ts > 0.0)
                    .map(|e| board_ts_upper_bound(e.raw_ts, e.coarse_ts))
                    .reduce(f64::min)
                    .unwrap_or(f64::INFINITY);
                unmatched_pre_round_boards.push((
                    *bts,
                    *board_ord_ts,
                    prev_coord_bts,
                    next_bound.min(next_any_ub),
                    btxt.as_str(),
                ));
            }
            let item_ord_ts = (if eff_ots > 0.0 {
                eff_ots.max(*board_ord_ts)
            } else {
                *board_ord_ts
            })
            .max(matched_t_ord)
            .max(running_board_ord_ts);
            running_board_ord_ts = item_ord_ts;
            if matched_idx.is_some() {
                // INVARIANT: Advance `running_t_ord_ts` and Lamport `running_t_seq` on every verified
                // unique `post_message` merge so subsequent un-timestamped transcript entries preserve causal order.
                max_into(&mut running_t_ord_ts, item_ord_ts);
                running_t_seq = running_t_seq.max(*bseq);
            }
            let emit_idx = combined_outputs.len();
            combined_outputs.push(CombinedOutput {
                raw_ts: eff_ots,
                coarse_ts: eff_coarse,
                attr_ts,
                attr_coarse,
                delayed_flush,
                order_ts: item_ord_ts,
                emit_idx,
                text: btxt.clone(),
                bseq: *bseq,
                causal_seq: *bseq,
                is_revoker: *bseq == 0
                    && eff_ots > 0.0
                    && item_ord_ts > eff_ots
                    && classify_verdict_polarity(btxt) == Some(false),
                tidx: matched_idx,
            });
        }
        for tidx in t_emit_cursor..tsum.outputs.len() {
            if !matched_t.contains(&tidx) {
                push_unmatched_t(
                    tidx,
                    &mut combined_outputs,
                    &mut running_t_ord_ts,
                    running_t_seq,
                );
            }
        }
        let mut pre_round_declined_t: HashSet<usize> = HashSet::new();
        if round_start_msg_id > 0 && !unmatched_pre_round_boards.is_empty() {
            let mut pre_cursor = 0usize;
            for (bts, b_ord, prev_c, upper_b, btxt) in &unmatched_pre_round_boards {
                for tidx in pre_cursor..tsum.outputs.len() {
                    if matched_t.contains(&tidx) || pre_round_declined_t.contains(&tidx) {
                        continue;
                    }
                    let t_item = &tsum.outputs[tidx];
                    let ots = t_item.pt.ts;
                    if !t_item.is_board_post || t_item.text != *btxt {
                        continue;
                    }
                    let twin_ts_ok = if *bts > 0.0 && ots > 0.0 {
                        (ots - *bts).abs() < 5.0
                            && ots < *upper_b
                            && (*prev_c <= 0.0 || ots >= *prev_c - 1.0)
                    } else if *bts == 0.0 && ots > 0.0 {
                        ots < *upper_b
                            && (*b_ord <= 0.0 || ots >= *b_ord - 1.0)
                            && (*prev_c <= 0.0 || ots >= *prev_c - 1.0)
                    } else {
                        *bts == 0.0 && ots == 0.0
                    };
                    if twin_ts_ok {
                        pre_round_declined_t.insert(tidx);
                        pre_cursor = tidx + 1;
                        break;
                    }
                }
            }
        }
        combined_outputs.sort_by(|a, b| {
            a.order_ts
                .total_cmp(&b.order_ts)
                .then_with(|| a.emit_idx.cmp(&b.emit_idx))
        });

        let latest_assign_ts = coord_posts
            .last()
            .map(|p| p.0)
            .unwrap_or(tsum.start_ts);
        let latest_assign_seq = coord_posts.last().map(|p| p.4).unwrap_or(0);
        let latest_reply_seq = worker_board_posts.iter().map(|p| p.4).max().unwrap_or(0);
        let meta_brief = val_to_str(minfo.get("brief"));
        let mut brief_parts: Vec<&str> = Vec::with_capacity(
            coord_posts.len() + broadcast_posts.len() + usize::from(!meta_brief.trim().is_empty()),
        );
        if !meta_brief.trim().is_empty() {
            brief_parts.push(meta_brief.as_str());
        }
        for p in &coord_posts {
            if !p.2.is_empty() {
                brief_parts.push(p.2.as_str());
            }
        }
        for p in &broadcast_posts {
            if !p.2.is_empty() {
                brief_parts.push(p.2.as_str());
            }
        }
        let latest_brief = brief_parts.join("\n");
        let has_reply_since_assign = if latest_assign_seq > 0 && !worker_board_posts.is_empty() {
            latest_reply_seq > latest_assign_seq
        } else {
            combined_outputs.last().map_or(false, |last_out| {
                latest_assign_ts == 0.0
                    || last_out.raw_ts == 0.0
                    || last_out.raw_ts >= latest_assign_ts - 1.0
            })
        };

        let mut max_act = latest_assign_ts.max(tsum.start_ts).max(tsum.parked_ts);
        for out in &combined_outputs {
            if out.raw_ts > max_act {
                max_act = out.raw_ts;
            }
        }
        worker_last_activity.insert(mname.clone(), max_act);

        let eff_park_ts = tsum.parked_ts.max(host_err_ts);
        let parked_after_assign = (tsum.parked_or_done || host_err_ts > 0.0)
            && (latest_assign_ts == 0.0
                || eff_park_ts == 0.0
                || eff_park_ts >= latest_assign_ts - 0.5);

        if !killed
            && latest_assign_ts >= first_ts - 2.0
            && !has_reply_since_assign
            && !parked_after_assign
        {
            ev.in_flight_workers.push(format!("swarm:{}", mname));
            continue;
        }
        if !killed {
            ev.idle_unkilled_workers.push(mname.clone());
        }
        if is_pre_reset_worker
            && cwg_common::is_simplify_or_review_swarm_worker_with_brief(
                mname,
                Some(minfo),
                &latest_brief,
            )
        {
            continue;
        }
        if combined_outputs.is_empty() {
            continue;
        }

        struct ReviewWindow {
            ts: f64,
            coarse_ts: bool,
            pub_ub: f64,
            text: String,
            step_idx: Option<usize>,
            seq: i64,
        }
        impl ReviewWindow {
            fn bare(ts: f64) -> Self {
                Self {
                    ts,
                    coarse_ts: false,
                    pub_ub: 0.0,
                    text: String::new(),
                    step_idx: None,
                    seq: 0,
                }
            }
        }
        let mut windows: Vec<ReviewWindow> = Vec::new();
        for (ts, coarse, txt, st_i, seq, pub_ub) in &coord_posts {
            windows.push(ReviewWindow {
                ts: *ts,
                coarse_ts: *coarse,
                pub_ub: *pub_ub,
                text: txt.clone(),
                step_idx: *st_i,
                seq: *seq,
            });
        }
        for (ts, coarse, txt, st_i, seq, pub_ub) in &broadcast_posts {
            windows.push(ReviewWindow {
                ts: *ts,
                coarse_ts: *coarse,
                pub_ub: *pub_ub,
                text: txt.clone(),
                step_idx: *st_i,
                seq: *seq,
            });
        }
        if let Some(switches) = model_switches.get(mname) {
            for item in switches {
                if has_reset
                    && !is_pre_reset_worker
                    && research_reset_ts > 0.0
                    && item.0 > 0.0
                    && item.0 <= research_reset_ts
                {
                    continue;
                }
                windows.push(ReviewWindow {
                    ts: item.0,
                    coarse_ts: false,
                    pub_ub: 0.0,
                    text: item.1.clone(),
                    step_idx: item.2,
                    seq: 0,
                });
            }
        }
        windows.sort_by(|a, b| a.ts.total_cmp(&b.ts).then_with(|| a.seq.cmp(&b.seq)));
        if windows.is_empty() {
            windows.push(ReviewWindow::bare(launch_ts_or_start(0.0, tsum.start_ts, first_ts)));
        }

        let out_window_ts = |out: &CombinedOutput| -> f64 {
            // INVARIANT: Keep positive/non-revoker unsequenced timestamped transcript entries at exact `raw_ts`
            // so they never warp forward across a window, while preserving monotonic `order_ts` for fail-closed
            // revokers so a late coarse `ACTIONABLE_FIXES` / `REVISE` after a sub-second step never drops before its round.
            if out.bseq == 0 && out.raw_ts > 0.0 && !out.is_revoker {
                out.raw_ts
            } else {
                out.order_ts
            }
        };
        let win_ts_ub = |w: &ReviewWindow| -> f64 {
            cwg_common::coarse_ts_upper_bound(w.ts, w.coarse_ts).max(w.pub_ub)
        };
        let is_before_win_pub_ub = |w: &ReviewWindow, out: &CombinedOutput| -> bool {
            // INVARIANT: Only fail-closed revokers may bypass window publication-bound ambiguity via
            // Lamport `causal_seq`; unsequenced transcript outputs (`bseq == 0`) formed before
            // `win_ts_ub(w)` (either coarse window seconds or coordinator call-before-publish lag)
            // require explicit post-window proof before entering `w`.
            let revoker_proven_after =
                out.is_revoker && w.seq > 0 && out.causal_seq > w.seq;
            let w_ub = win_ts_ub(w);
            !w.text.starts_with("[model-switch")
                && out.bseq == 0
                && !revoker_proven_after
                && w_ub > 0.0
                && out_window_ts(out) < w_ub - TS_EPS
        };
        let coarse_board_tol = |w: &ReviewWindow, out: &CombinedOutput| -> f64 {
            let causal_coarse = !w.text.starts_with("[model-switch")
                && out.coarse_ts
                && w.seq > 0
                && (out.bseq > w.seq || (out.is_revoker && out.causal_seq > w.seq));
            if causal_coarse { 0.999 } else { TS_EPS }
        };

        // INVARIANT: Under coarse timestamp uncertainty `[earliest, latest)`, proving a positive
        // verdict formed at or after an assignment/round `[bound_lb, bound_ub)` requires
        // `attr_ts >= bound_ub - TS_EPS` (earliest formation >= latest bound), whereas proving a
        // fail-closed revoker preceded `[bound_lb, bound_ub)` requires its latest formation bound
        // to precede `bound_lb` (`board_ts_upper_bound(attr_ts, true) <= bound_lb + TS_EPS` when
        // coarse, or `attr_ts < bound_lb - TS_EPS` when exact).
        let formed_before = |delayed_flush: bool,
                             attr_ts: f64,
                             attr_coarse: bool,
                             bound_lb: f64,
                             bound_ub: f64,
                             fail_closed_revoker: bool|
         -> bool {
            delayed_flush
                && attr_ts > 0.0
                && if fail_closed_revoker {
                    bound_lb > 0.0
                        && if attr_coarse {
                            board_ts_upper_bound(attr_ts, true) <= bound_lb + TS_EPS
                        } else {
                            attr_ts < bound_lb - TS_EPS
                        }
                } else {
                    bound_ub > 0.0 && attr_ts < bound_ub - TS_EPS
                }
        };
        let is_out_revoker = |out: &CombinedOutput| -> bool {
            out.is_revoker
                || out.tidx.is_some_and(|ti| split_revoker_t[ti])
                || classify_verdict_polarity(&out.text) == Some(false)
        };
        // INVARIANT: Do not time-warp outputs strictly before `windows[0]` (by timestamp, board `seq`,
        // or delayed-flush formation time) or unsequenced transcript outputs before the first window's
        // publication upper bound `win_ts_ub(first_w)` into a later assignment window.
        if let Some(first_w) = windows.first() {
            if first_w.ts > 0.0 || first_w.seq > 0 {
                let first_w_ub = win_ts_ub(first_w);
                let has_before_first_win = combined_outputs.iter().any(|out| {
                    let before_seq = out.bseq > 0 && first_w.seq > 0 && out.bseq < first_w.seq;
                    let tol = coarse_board_tol(first_w, out);
                    before_seq
                        || is_before_win_pub_ub(first_w, out)
                        || (first_w.ts > 0.0 && out_window_ts(out) + tol < first_w.ts)
                        || ((first_w.seq > 0 || !first_w.text.is_empty())
                            && !first_w.text.starts_with("[model-switch")
                            && formed_before(
                                out.delayed_flush,
                                out.attr_ts,
                                out.attr_coarse,
                                first_w.ts,
                                first_w_ub,
                                out.delayed_flush
                                    && (out.attr_coarse || first_w.coarse_ts)
                                    && is_out_revoker(out),
                            ))
                });
                if has_before_first_win {
                    let w0 = if tsum.start_ts > 0.0
                        && (first_w.ts <= 0.0 || tsum.start_ts < first_w.ts)
                    {
                        tsum.start_ts
                    } else {
                        0.0
                    };
                    windows.insert(0, ReviewWindow::bare(w0));
                }
            }
        }

        struct BucketedOut {
            raw_ts: f64,
            order_ts: f64,
            attr_ts: f64,
            attr_coarse: bool,
            text: String,
        }
        let mut bucketed_outputs: HashMap<usize, Vec<BucketedOut>> = HashMap::new();
        for out in &combined_outputs {
            let mut out_revoker_cached: Option<bool> = None;
            let mut out_is_revoker = || -> bool {
                *out_revoker_cached.get_or_insert_with(|| is_out_revoker(out))
            };
            // INVARIANT: A coarse whole-second formation timestamp colliding with a switch in `[attr_ts, attr_ts + 1.0)` is
            // un-attributable to any single model epoch (`resolve_window_model == ""`); skip bucketing non-revokers
            // so they neither emit a positive verdict nor clobber an adjacent millisecond-attributed window, while
            // keeping fail-closed revokers (`ACTIONABLE_FIXES` / `REVISE` and `split_revoker_t` halves) eligible.
            if has_any_switch
                && out.attr_coarse
                && out.attr_ts > 0.0
                && resolve_window_model(&model_events, &cur_model, true, out.attr_ts, true)
                    .is_empty()
                && !out_is_revoker()
            {
                continue;
            }
            let mut w_idx = 0usize;
            let eff_out_ts = out_window_ts(out);
            // INVARIANT: Bucket by `out_window_ts` (monotonic `order_ts`, or exact `raw_ts` for unsequenced non-revoker
            // timestamped transcript entries) while keeping explicit `coarse_ts` precision; 0.999s tolerance applies only
            // when `out.bseq > w.seq` (or fail-closed revoker `out.causal_seq > w.seq`), unsequenced non-revoker
            // transcript outputs (`bseq == 0`) formed before `win_ts_ub(w)` fail closed, and delayed board flushes
            // never enter a coordinator window that began strictly after formation (`attr_ts`).
            for (cand_idx, w) in windows.iter().enumerate() {
                if out.bseq > 0 && w.seq > 0 && out.bseq < w.seq {
                    continue;
                }
                if cand_idx > 0
                    && !w.text.starts_with("[model-switch")
                    && formed_before(
                        out.delayed_flush,
                        out.attr_ts,
                        out.attr_coarse,
                        w.ts,
                        win_ts_ub(w),
                        out.delayed_flush
                            && (out.attr_coarse || w.coarse_ts)
                            && out_is_revoker(),
                    )
                {
                    continue;
                }
                if cand_idx > 0 && is_before_win_pub_ub(w, out) {
                    continue;
                }
                let tol = coarse_board_tol(w, out);
                if w.ts == 0.0 || w.ts <= eff_out_ts + tol {
                    w_idx = cand_idx;
                }
            }
            bucketed_outputs
                .entry(w_idx)
                .or_default()
                .push(BucketedOut {
                    raw_ts: out.raw_ts,
                    order_ts: out.order_ts,
                    attr_ts: out.attr_ts,
                    attr_coarse: out.attr_coarse,
                    text: out.text.clone(),
                });
        }

        let mut w_step_idx = worker_add_step.get(mname).copied();
        if w_step_idx.is_none() && !group_prefix.is_empty() {
            w_step_idx = worker_add_step.get(group_prefix).copied();
        }

        let mut win_keys: Vec<usize> = bucketed_outputs.keys().copied().collect();
        win_keys.sort();
        let advance_brief_flag = |flag: &mut Option<bool>,
                                      cursor: &mut usize,
                                      up_to: usize,
                                      pred: &dyn Fn(&str) -> bool|
         -> bool {
            let cur = flag.get_or_insert_with(|| pred(&meta_brief));
            while !*cur && *cursor <= up_to {
                let wb = windows[*cursor].text.as_str();
                if !wb.is_empty() && !wb.starts_with("[model-switch") && pred(wb) {
                    *cur = true;
                }
                *cursor += 1;
            }
            *cur
        };
        let mut brief_hint_cursor = 0usize;
        let mut brief_has_review_hint: Option<bool> = None;
        let mut brief_xhigh_cursor = 0usize;
        let mut brief_is_xhigh: Option<bool> = None;
        let mname_is_xhigh = mname.to_ascii_lowercase().contains("xhigh");
        for w_idx in win_keys {
            let win_ts = windows[w_idx].ts;
            let win_step_idx = windows[w_idx].step_idx;
            let win_outs = &bucketed_outputs[&w_idx];
            let mut r_kind: Option<String> = None;
            let mut r_verdict: Option<String> = None;
            let mut r_ts = 0.0f64;
            let mut r_ord_ts = 0.0f64;
            let mut r_attr_ts = 0.0f64;
            let mut r_attr_coarse = false;
            for idx in (0..win_outs.len()).rev() {
                let bo = &win_outs[idx];
                let (mut k, mut v) = cwg_common::extract_review_decision(&bo.text);
                if (k.is_none() || v.is_none())
                    && idx > 0
                    && might_cross_rev_revoker(win_outs[idx - 1].text.as_str(), bo.text.as_str())
                {
                    (k, v) = cwg_common::extract_split_review_revoker(
                        win_outs[idx - 1].text.as_str(),
                        bo.text.as_str(),
                    );
                }
                if k.is_some() && v.is_some() {
                    r_kind = k;
                    r_verdict = v;
                    r_ts = bo.raw_ts;
                    r_ord_ts = bo.order_ts;
                    r_attr_ts = bo.attr_ts;
                    r_attr_coarse = bo.attr_coarse;
                    break;
                }
            }
            let (Some(rk), Some(rv)) = (r_kind, r_verdict) else {
                continue;
            };
            let max_win_ots = win_outs
                .iter()
                .map(|x| x.raw_ts.max(x.order_ts))
                .reduce(f64::max)
                .unwrap_or(0.0);
            // INVARIANT: Attribute review model strictly by the verdict message's formation timestamp (`r_attr_ts`)
            // and explicit precision (`r_attr_coarse`) so a delayed post-switch board flush never promotes an in-flight
            // verdict; un-timestamped verdicts (`r_attr_ts == 0.0`) fail closed under `resolve_window_model` after switches,
            // while `eff_verdict_ts` preserves the proven `r_ts` / `r_ord_ts` lower bound.
            let raw_verdict_ts = r_attr_ts;
            let eff_launch_ts = launch_ts_or_start(win_ts, tsum.start_ts, first_ts);
            let eff_end_ts = eff_launch_ts.max(max_win_ots);
            let eff_step_idx = win_step_idx.or(w_step_idx);
            let verdict_lb = r_ts.max(r_ord_ts);
            let eff_verdict_ts = eff_launch_ts.max(if verdict_lb > 0.0 { verdict_lb } else { eff_end_ts });

            let win_model = resolve_window_model(
                &model_events,
                &cur_model,
                has_any_switch,
                raw_verdict_ts,
                r_attr_coarse,
            );
            let win_escalated_from_opus = win_model != cwg_common::OPUS_HIGH_MODEL
                && (worker_opus_req_ts.is_some_and(|ots| {
                    (eff_launch_ts <= 0.0 || ots <= eff_launch_ts + 1.0)
                        && (raw_verdict_ts <= 0.0 || ots <= raw_verdict_ts + 1.0)
                }) || (!has_any_switch
                    && prior_reqs.contains(cwg_common::OPUS_HIGH_MODEL)));
            if win_model != cwg_common::OPUS_HIGH_MODEL
                && win_model != cwg_common::CARBON_HIGH_MODEL
                && !(win_model == cwg_common::NEON_XHIGH_MODEL
                    && (win_escalated_from_opus
                        || advance_brief_flag(
                            &mut brief_has_review_hint,
                            &mut brief_hint_cursor,
                            w_idx,
                            &|b| cwg_common::is_review_worker_hint(mname, b),
                        )))
            {
                continue;
            }
            let win_eng = if win_model == cwg_common::OPUS_HIGH_MODEL {
                cwg_common::REVIEW_ENGINE_INTERNAL_OPUS
            } else if win_model == cwg_common::NEON_XHIGH_MODEL {
                cwg_common::REVIEW_ENGINE_INTERNAL_NEON
            } else {
                cwg_common::REVIEW_ENGINE_INTERNAL_CARBON
            };
            // INVARIANT: `internal-neon` (`gemini-4-neon-xhigh`) is capped at `HIGH` escalation (`xhigh=false`); `XHIGH` escalation stays on Opus/Carbon.
            // Derive review tier strictly from briefs active at or before `w_idx` so later `@all`/follow-up prompts never retroactively promote an earlier verdict to `XHIGH`.
            let is_xhigh = win_model != cwg_common::NEON_XHIGH_MODEL
                && (mname_is_xhigh
                    || advance_brief_flag(
                        &mut brief_is_xhigh,
                        &mut brief_xhigh_cursor,
                        w_idx,
                        &cwg_common::is_review_tier_xhigh,
                    )
                    || win_outs
                        .iter()
                        .any(|x| cwg_common::is_review_tier_xhigh(&x.text)));

            ev.reviews.push(json!({
                "engine": win_eng,
                "reviewer": mname,
                "cid": mcid,
                "kind": rk,
                "verdict": rv,
                "launch_ts": eff_launch_ts,
                "verdict_ts": eff_verdict_ts,
                "xhigh": is_xhigh,
                "model": win_model,
                "escalated_from_opus": win_escalated_from_opus,
                "step_idx": eff_step_idx,
            }));
        }
    }

    if !ev.in_flight_workers.is_empty() {
        let eff_cwd = if !cwd.is_empty() {
            cwd.to_string()
        } else {
            conv_dir.to_string_lossy().into_owned()
        };
        ev.stalled_workers = cwg_common::detect_stalled_workers(cwg_common::StallDetectInput {
            members: &members_map,
            board_messages: &raw_board,
            cwd: &eff_cwd,
            brain_root: Some(&brain_root),
            worker_last_activity: &worker_last_activity,
            in_flight_names: &ev.in_flight_workers,
            now_ts: None,
            timeout_sec: None,
        });
    }
    ev.worker_activity_count = Some(
        parsed_board
            .iter()
            .filter(|e| !e.text.is_empty() && !e.poster.is_empty() && e.poster != "coordinator")
            .count(),
    );
    ev
}

#[derive(Debug, Clone, Default)]
pub struct SubagentEvidence {
    pub reviews: Vec<Value>,
    pub review_failures: Vec<f64>,
    pub in_flight_subagents: Vec<String>,
}

pub fn scan_native_subagents(
    steps: &[Value],
    transcript_path: Option<&str>,
    first_ts: f64,
) -> SubagentEvidence {
    let mut ev = SubagentEvidence::default();
    let mut brain_root: Option<PathBuf> = None;
    let mut parent_cid = String::new();
    if let Some(tp) = transcript_path {
        if !tp.is_empty() {
            let abs_tp = clean_lexical_path(Path::new(tp));
            let resolved = fs::canonicalize(&abs_tp).unwrap_or(abs_tp);
            if resolved.ancestors().nth(2).and_then(|p| p.file_name()).and_then(|s| s.to_str())
                == Some(".system_generated")
            {
                if let (Some(cid_s), Some(br)) = (
                    resolved
                        .ancestors()
                        .nth(3)
                        .and_then(|p| p.file_name())
                        .and_then(|s| s.to_str()),
                    resolved.ancestors().nth(4),
                ) {
                    parent_cid = cid_s.to_string();
                    brain_root = Some(br.to_path_buf());
                }
            }
        }
    }

    let mut delivered_by_sender: HashMap<String, Vec<(f64, String)>> = HashMap::new();
    for st in steps {
        if st.get("source").and_then(|v| v.as_str()) == Some("SYSTEM")
            && st.get("type").and_then(|v| v.as_str()) == Some("SYSTEM_MESSAGE")
        {
            let content = val_to_str(st.get("content"));
            if let Some(caps) = subagent_msg_re().captures(&content) {
                let sender = caps.name("sender").map_or("", |m| m.as_str()).to_string();
                let ts_str = caps.name("ts").map_or("", |m| m.as_str());
                let parsed_ts = rio::parse_iso_ts(ts_str);
                let msg_ts = if parsed_ts > 0.0 {
                    parsed_ts
                } else {
                    st.get("created_at")
                        .and_then(|v| v.as_str())
                        .map(rio::parse_iso_ts)
                        .unwrap_or(0.0)
                };
                let raw_body = caps.name("body").map_or("", |m| m.as_str());
                let body = sys_msg_close_re()
                    .replace(raw_body, "")
                    .trim()
                    .to_string();
                delivered_by_sender
                    .entry(sender)
                    .or_default()
                    .push((msg_ts, body));
            }
        }
    }

    for (idx, st) in steps.iter().enumerate() {
        if st.get("source").and_then(|v| v.as_str()) != Some("MODEL")
            || st.get("type").and_then(|v| v.as_str()) != Some("PLANNER_RESPONSE")
        {
            continue;
        }
        let call_ts = st
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(rio::parse_iso_ts)
            .unwrap_or(0.0);
        if call_ts > 0.0 && call_ts < first_ts - 2.0 {
            continue;
        }
        let tcs = st
            .get("tool_calls")
            .and_then(|v| v.as_array())
            .map(|a| a.as_slice())
            .unwrap_or(&[]);
        if !tcs
            .iter()
            .any(|tc| tc.get("name").and_then(|v| v.as_str()) == Some("invoke_subagent"))
        {
            continue;
        }

        let generic_steps = collect_generic_results(steps, idx);
        for (pos, tc) in tcs.iter().enumerate() {
            let Some(tc_obj) = tc.as_object() else {
                continue;
            };
            if tc_obj.get("name").and_then(|v| v.as_str()) != Some("invoke_subagent") {
                continue;
            }
            let args = tc_obj.get("args").and_then(|v| v.as_object());
            let tname = args
                .and_then(|m| m.get("TypeName"))
                .map(|v| val_to_str(Some(v)).trim().to_string())
                .unwrap_or_default();
            let base_tname = tname.rsplit(':').next().unwrap_or("");
            let model_arg = args
                .and_then(|m| m.get("Model"))
                .map(|v| val_to_str(Some(v)).trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "inherit".to_string());

            let (g_status, blob) = if pos < generic_steps.len() {
                (generic_steps[pos].0.as_str(), generic_steps[pos].1.as_str())
            } else {
                ("", "")
            };
            let Some(sm) = subagent_uri_re().captures(blob) else {
                let blob_low = blob.to_lowercase();
                if (g_status == "ERROR"
                    || blob_low.contains("error")
                    || blob_low.contains("failed"))
                    && NATIVE_REVIEWERS.contains(&base_tname)
                {
                    ev.review_failures
                        .push(if call_ts > 0.0 { call_ts } else { now_sec() });
                }
                continue;
            };

            let cid = sm.name("cid").map_or("", |m| m.as_str());
            let mut sub_tp = sm
                .name("uri")
                .map(|m| uri_to_path(m.as_str()))
                .unwrap_or_default();
            if sub_tp.is_empty() {
                if let Some(ref br) = brain_root {
                    let cand = rio::member_transcript_path(br, cid);
                    if cand.exists() {
                        sub_tp = cand.to_string_lossy().into_owned();
                    }
                }
            }

            let sub_tp_opt = if sub_tp.is_empty() {
                None
            } else {
                Some(sub_tp.as_str())
            };
            let (sub_chunks, sub_last_ts, mut sub_done) =
                extract_subagent_timed_chunks(sub_tp_opt, &parent_cid);
            let delivered = delivered_by_sender
                .get(cid)
                .map(|v| v.as_slice())
                .unwrap_or(&[]);
            if !delivered.is_empty() {
                sub_done = true;
            }
            if !sub_done {
                let short_cid: String = cid.chars().take(8).collect();
                ev.in_flight_subagents
                    .push(format!("{}:{}", tname, short_cid));
                continue;
            }

            // INVARIANT: Bind each simplify/review verdict strictly to the timestamp of the message chunk that produced it; coalesce only an immediate post-`send_message` sign-off repeating the identical decision.
            let merged_chunks = merge_subagent_chunks(&sub_chunks, delivered);
            let last_chunk_ts = merged_chunks.iter().map(|c| c.ts).reduce(f64::max).unwrap_or(0.0);
            let fallback_end_ts = if last_chunk_ts > 0.0 {
                last_chunk_ts
            } else {
                sub_last_ts
            };
            let eff_launch_ts = if call_ts > 0.0 {
                call_ts
            } else if fallback_end_ts > 0.0 {
                fallback_end_ts
            } else {
                now_sec()
            };

            if NATIVE_REVIEWERS.contains(&base_tname) {
                let mut r_kind: Option<String> = None;
                let mut r_verdict: Option<String> = None;
                let mut r_ts = 0.0f64;
                let mut prev_send_dec: (Option<String>, Option<String>) = (None, None);

                for ch in &merged_chunks {
                    let dec = cwg_common::extract_review_decision(&ch.text);
                    if dec.0.is_some() && dec.1.is_some() {
                        if !(ch.kind == "final" && ch.is_signoff && dec == prev_send_dec) {
                            r_kind = dec.0.clone();
                            r_verdict = dec.1.clone();
                            r_ts = ch.ts;
                        }
                        prev_send_dec = if ch.kind == "send" { dec } else { (None, None) };
                    } else {
                        prev_send_dec = (None, None);
                    }
                }

                if let (Some(rk), Some(rv)) = (r_kind, r_verdict) {
                    let end_cand = if r_ts > 0.0 {
                        r_ts
                    } else if fallback_end_ts > 0.0 {
                        fallback_end_ts
                    } else {
                        eff_launch_ts
                    };
                    let eff_verdict_ts = eff_launch_ts.max(end_cand);
                    ev.reviews.push(json!({
                        "engine": "native",
                        "reviewer": base_tname,
                        "cid": cid,
                        "kind": rk,
                        "verdict": rv,
                        "launch_ts": eff_launch_ts,
                        "verdict_ts": eff_verdict_ts,
                        "xhigh": base_tname == XHIGH_NATIVE_REVIEWER,
                        "model": model_arg,
                        "step_idx": idx,
                    }));
                } else {
                    let fail_cand = if fallback_end_ts > 0.0 {
                        fallback_end_ts
                    } else {
                        eff_launch_ts
                    };
                    ev.review_failures.push(eff_launch_ts.max(fail_cand));
                }
            }
        }
    }
    ev
}

fn mark_fp(m: &Map<String, Value>) -> Option<&str> {
    m.get("fp").and_then(|v| v.as_str()).filter(|s| !s.is_empty())
}

fn is_review_fresh_marks(launch_ts: f64, marks: &[&Map<String, Value>]) -> bool {
    if marks.is_empty() {
        return true;
    }
    // INVARIANT: A mark with a concrete SHA-256 `fp` is cryptographically measured; only `fp is None` is unmeasured.
    let mut covered_fps: HashSet<&str> = HashSet::new();
    for m in marks {
        let mts = val_to_f64(m.get("ts"));
        if let Some(fp) = mark_fp(m) {
            if mts <= launch_ts {
                covered_fps.insert(fp);
            }
        } else if json_truthy(m.get("unknown")) && mts > launch_ts {
            return false;
        }
    }
    let Some(cur_fp) = mark_fp(marks[marks.len() - 1]) else {
        return false;
    };
    covered_fps.contains(cur_fp)
}

fn is_review_fresh_ts(launch_ts: f64, marker: &Value) -> bool {
    let marks: Vec<&Map<String, Value>> = marker
        .get("content_marks")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_object()).collect())
        .unwrap_or_default();
    is_review_fresh_marks(launch_ts, &marks)
}

pub fn is_review_fresh(review: &Value, marker: &Value) -> bool {
    is_review_fresh_ts(val_to_f64(review.get("launch_ts")), marker)
}

fn closure_ready_tail_ok(
    effective_risk: &str,
    ord_list: &[Value],
    cls_rev: &Value,
    allow_approved: bool,
) -> bool {
    if ord_list.is_empty() || val_to_str(cls_rev.get("verdict")) != "READY" {
        return false;
    }
    if !allow_approved && ord_list.len() != MAX_REVIEW_ROUNDS {
        return false;
    }
    if effective_risk == "XHIGH"
        && (!json_truthy(cls_rev.get("xhigh"))
            || val_to_str(cls_rev.get("engine")) == cwg_common::REVIEW_ENGINE_INTERNAL_NEON
            || ord_list
                .iter()
                .any(|r| val_to_str(r.get("engine")) == cwg_common::REVIEW_ENGINE_INTERNAL_NEON))
    {
        return false;
    }
    let Some(last_ord) = ord_list.last() else {
        return false;
    };
    let lv = val_to_str(last_ord.get("verdict"));
    if allow_approved {
        if lv != "APPROVED" || (effective_risk == "XHIGH" && !json_truthy(last_ord.get("xhigh"))) {
            return false;
        }
    } else if lv == "ESCALATE" {
        if ord_list.len() < MAX_REVIEW_ROUNDS {
            return false;
        }
    } else {
        return false;
    }
    let last_ord_vts = val_to_f64(last_ord.get("launch_ts"))
        .max(val_to_f64(last_ord.get("verdict_ts")));
    val_to_f64(cls_rev.get("launch_ts")) >= last_ord_vts
}

fn legacy_three_round_closure_cutoff(
    marker: &Value,
    effective_risk: &str,
    ord_list: &[Value],
    effective_closure: &[Value],
) -> Option<f64> {
    // INVARIANT: Only pre-upgrade markers (missing `gate_max_review_rounds` or `< MAX_REVIEW_ROUNDS`) may enter the legacy 3-round/Sandwich closure branch; post-upgrade candidates (`gate_max_review_rounds >= MAX_REVIEW_ROUNDS`) strictly require Round 4 `ESCALATE` + research regardless of reviewer engine.
    if is_modern_review_cap_marker(marker) {
        return None;
    }
    if effective_closure.is_empty() {
        return None;
    }
    let last_ord = ord_list.last()?;
    let lv = val_to_str(last_ord.get("verdict"));
    let legacy_ord_tail_ok = match lv.as_str() {
        "REVISE" | "ESCALATE" => ord_list.len() == LEGACY_MAX_REVIEW_ROUNDS,
        "APPROVED" => {
            (1..=MAX_REVIEW_ROUNDS).contains(&ord_list.len())
                && (effective_risk != "XHIGH" || json_truthy(last_ord.get("xhigh")))
        }
        _ => false,
    };
    if !legacy_ord_tail_ok {
        return None;
    }
    let last_ord_vts = val_to_f64(last_ord.get("launch_ts"))
        .max(val_to_f64(last_ord.get("verdict_ts")));
    let first_cls = &effective_closure[0];
    // INVARIANT: For Round-3 `REVISE`/`ESCALATE`, require verified `codex` Pass 1 (blocked by both `c146cc0` and post-upgrade `codex-lane`) so open `c146cc0` markers cannot spoof legacy entry via fallback reviewers; for legacy post-`APPROVED` Sandwich closures (where `last_ord` is already a valid terminal `APPROVED`), allow any eligible engine in `effective_closure`.
    if (lv != "APPROVED" && val_to_str(first_cls.get("engine")) != "codex")
        || val_to_f64(first_cls.get("launch_ts")) < last_ord_vts
    {
        return None;
    }
    if effective_risk == "XHIGH"
        && (!json_truthy(first_cls.get("xhigh"))
            || ord_list
                .iter()
                .any(|r| val_to_str(r.get("engine")) == cwg_common::REVIEW_ENGINE_INTERNAL_NEON))
    {
        return None;
    }
    Some(last_ord_vts)
}

fn legacy_closure_ready_tail_ok(
    marker: &Value,
    effective_risk: &str,
    ord_list: &[Value],
    effective_closure: &[Value],
    cls_rev: &Value,
) -> bool {
    if val_to_str(cls_rev.get("verdict")) != "READY" {
        return false;
    }
    let Some(last_ord_vts) =
        legacy_three_round_closure_cutoff(marker, effective_risk, ord_list, effective_closure)
    else {
        return false;
    };
    if effective_risk == "XHIGH"
        && (!json_truthy(cls_rev.get("xhigh"))
            || val_to_str(cls_rev.get("engine")) == cwg_common::REVIEW_ENGINE_INTERNAL_NEON)
    {
        return false;
    }
    val_to_f64(cls_rev.get("launch_ts")) >= last_ord_vts
}

fn steps_have_index_gap(step_list: &[Value]) -> bool {
    if step_list.len() < 2 {
        return false;
    }
    let s0 = step_list[0].get("step_index").and_then(|v| v.as_i64());
    let s1 = step_list[1].get("step_index").and_then(|v| v.as_i64());
    matches!((s0, s1), (Some(i0), Some(i1)) if i1 > i0 + 1)
}

fn steps_need_compact_fallback(step_list: &[Value]) -> bool {
    step_list.is_empty() || rio::has_prefix_slice_gap(step_list)
}

#[derive(Debug, Clone)]
struct TranscriptEditEvidence {
    covered_from_ts: f64,
    edit_spans: Vec<(f64, f64)>,
    proven_change_ts: Vec<f64>,
}

fn extract_transcript_edit_evidence(steps: &[Value], marker: &Value) -> TranscriptEditEvidence {
    if steps.is_empty() {
        return TranscriptEditEvidence {
            covered_from_ts: f64::INFINITY,
            edit_spans: Vec::new(),
            proven_change_ts: Vec::new(),
        };
    }
    let has_gap = steps_have_index_gap(steps);
    let iter_steps = if has_gap { &steps[1..] } else { steps };
    let mut covered_from_ts = f64::INFINITY;
    for st in iter_steps {
        let ts0 = st
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(rio::parse_iso_ts)
            .unwrap_or(0.0);
        if ts0 > 0.0 {
            covered_from_ts = ts0;
            break;
        }
    }

    let cwd = val_to_str(marker.get("cwd"));
    let shell_durable = marker
        .get("shell_durable_edit")
        .map_or(true, |v| json_truthy(Some(v)));
    let folded_dpaths: HashSet<String> = cwg_common::durable_paths_from_val(marker.get("paths"))
        .into_iter()
        .map(|p| rio::fold_path(&p))
        .collect();
    let mut edit_spans: Vec<(f64, f64)> = Vec::new();
    let mut proven_change_ts: Vec<f64> = Vec::new();
    let mut pending_mut_tasks: HashMap<String, f64> = HashMap::new();
    let is_mut_tool = |name: &str| EDIT_TOOLS.contains(&name) || SHELL_TOOLS.contains(&name);

    for (idx, st) in iter_steps.iter().enumerate() {
        let ssource = val_to_str(st.get("source"));
        if ssource == "SYSTEM" {
            let sys_ts = st
                .get("created_at")
                .and_then(|v| v.as_str())
                .map(rio::parse_iso_ts)
                .unwrap_or(0.0);
            let sys_txt = val_to_str(st.get("content"));
            let done_tids: Vec<String> = pending_mut_tasks
                .keys()
                .filter(|tid| sys_txt.contains(&format!("Task id \"{}\" finished with result:", tid)))
                .cloned()
                .collect();
            for tid in done_tids {
                if let Some(start_ts) = pending_mut_tasks.remove(&tid) {
                    let end_ts = if sys_ts > 0.0 {
                        start_ts.max(sys_ts)
                    } else {
                        start_ts
                    };
                    edit_spans.push((start_ts, end_ts));
                }
            }
            continue;
        }
        if ssource != "MODEL" || st.get("type").and_then(|v| v.as_str()) != Some("PLANNER_RESPONSE")
        {
            continue;
        }
        let call_ts = st
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(rio::parse_iso_ts)
            .unwrap_or(0.0);
        if call_ts <= 0.0 {
            continue;
        }
        let tcs = st
            .get("tool_calls")
            .and_then(|v| v.as_array())
            .map(|a| a.as_slice())
            .unwrap_or(&[]);
        if !tcs.iter().any(|tc| {
            tc.get("name")
                .and_then(|v| v.as_str())
                .map_or(false, is_mut_tool)
        }) {
            continue;
        }

        let gen_steps = collect_generic_results(iter_steps, idx);
        for (pos, tc) in tcs.iter().enumerate() {
            let Some(tc_obj) = tc.as_object() else {
                continue;
            };
            let tname = tc_obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if !is_mut_tool(tname) {
                continue;
            }
            let (g_status, g_blob, g_ts) = if pos < gen_steps.len() {
                (
                    gen_steps[pos].0.as_str(),
                    gen_steps[pos].1.as_str(),
                    gen_steps[pos].2.ts,
                )
            } else {
                ("", "", 0.0)
            };
            let end_ts = if g_ts > 0.0 {
                call_ts.max(g_ts)
            } else {
                call_ts
            };
            let targs = tc_obj.get("args").and_then(|v| v.as_object());
            if EDIT_TOOLS.contains(&tname) {
                if g_status == "ERROR"
                    || targs.map_or(false, |m| json_truthy(m.get("ArtifactMetadata")))
                {
                    continue;
                }
                let tpath = targs
                    .and_then(|m| m.get("Path"))
                    .map(|v| val_to_str(Some(v)))
                    .unwrap_or_default();
                if tpath.is_empty() || cwg_common::is_scratch_or_ephemeral(&tpath, "", &[], &cwd) {
                    continue;
                }
                edit_spans.push((call_ts, end_ts));
                let target_s = targs
                    .and_then(|m| m.get("Target"))
                    .map(|v| val_to_str(Some(v)))
                    .unwrap_or_default();
                let repl_s = targs
                    .and_then(|m| m.get("Replacement"))
                    .map(|v| val_to_str(Some(v)))
                    .unwrap_or_default();
                if tname == "edit_file"
                    && g_status == "DONE"
                    && folded_dpaths.contains(&rio::fold_path(&tpath))
                    && target_s != repl_s
                {
                    proven_change_ts.push(end_ts);
                }
            } else {
                if !shell_durable {
                    continue;
                }
                let cmd_s = targs
                    .and_then(|m| m.get("CommandLine"))
                    .map(|v| val_to_str(Some(v)))
                    .unwrap_or_default();
                let pol = cwg_mark::classify_shell_command(&cmd_s);
                if matches!(pol, "READ_ONLY" | "BOOKKEEPING" | "VALIDATION") {
                    continue;
                }
                if pol == "MUTATING"
                    && cwg_mark::is_ephemeral_only_shell_mutation(&cmd_s, "", &[], &cwd)
                {
                    continue;
                }
                if let Some(bg_tid) = rio::extract_bg_task_id(g_blob) {
                    pending_mut_tasks.insert(bg_tid, call_ts);
                } else {
                    edit_spans.push((call_ts, end_ts));
                }
            }
        }
    }

    for start_ts in pending_mut_tasks.into_values() {
        edit_spans.push((start_ts, f64::INFINITY));
    }
    proven_change_ts.sort_by(|a, b| a.total_cmp(b));
    TranscriptEditEvidence {
        covered_from_ts,
        edit_spans,
        proven_change_ts,
    }
}

struct ClosureEvalCtx<'a> {
    marker: &'a Value,
    steps: Option<&'a [Value]>,
    transcript_path: Option<&'a str>,
    effective_risk: &'a str,
    candidate_marks: &'a [&'a Map<String, Value>],
    oldest_mark_ts: f64,
    first_ts_val: f64,
    marks_truncated: bool,
    tx_edits_cache: Option<TranscriptEditEvidence>,
    swarm_ev: &'a SwarmEvidence,
    codex_bin_missing_cache: Option<bool>,
    breaker_info_cache: Option<Value>,
    inv_ts_cache: HashMap<(u64, u64), Option<f64>>,
}

impl<'a> ClosureEvalCtx<'a> {
    fn get_tx_edits(&mut self) -> TranscriptEditEvidence {
        if let Some(ref cached) = self.tx_edits_cache {
            return cached.clone();
        }
        let given_steps = self.steps.unwrap_or(&[]);
        let compact_buf: Vec<Value>;
        let tx_steps: &[Value] = if steps_need_compact_fallback(given_steps) {
            if !self.swarm_ev.compact_steps.is_empty() {
                &self.swarm_ev.compact_steps
            } else if let Some(tp) = self.transcript_path.filter(|s| !s.is_empty()) {
                // INVARIANT: When `transcript_full.jsonl` exceeds the tail-read window, recover full step-0..N edit spans from compact `transcript.jsonl` before failing closed on `covered_from_ts`.
                compact_buf = rio::read_compact_transcript_steps(tp, 16000);
                if !compact_buf.is_empty() {
                    &compact_buf
                } else {
                    given_steps
                }
            } else {
                given_steps
            }
        } else {
            given_steps
        };
        let computed = extract_transcript_edit_evidence(tx_steps, self.marker);
        self.tx_edits_cache = Some(computed.clone());
        computed
    }

    fn partition_cycle_closure_with_policy(
        &mut self,
        ord_list: &[Value],
        cls_slice: &[Value],
        reject_only_proven_absent_research: bool,
    ) -> (Vec<Value>, bool) {
        // INVARIANT: Under the finite `claude-code-stack` gate, modern markers (`gate_max_review_rounds >= 4`) only count closure passes after Round `MAX_REVIEW_ROUNDS` `ESCALATE`, while legacy markers without `gate_max_review_rounds` require legacy `APPROVED`, Round-`LEGACY_MAX_REVIEW_ROUNDS` / `ESCALATE` + verified `codex` Pass 1 before any fallback pass can enter closure; premature closure passes never consume slots, block Round 4, or unlock premature `draft-blocked`.
        if cls_slice.is_empty() {
            return (Vec::new(), false);
        }
        let is_modern_marker = is_modern_review_cap_marker(self.marker);
        let mut kept: Vec<Value> = Vec::with_capacity(cls_slice.len());
        let mut last_kept = false;
        for (idx, cls) in cls_slice.iter().enumerate() {
            let cls_lts = val_to_f64(cls.get("launch_ts"));
            let mut counted_before = 0usize;
            let mut last_ord: Option<&Value> = None;
            let mut has_neon_before = false;
            for r in ord_list {
                if val_to_f64(r.get("launch_ts")).max(val_to_f64(r.get("verdict_ts"))) > cls_lts {
                    continue;
                }
                if !self.counts_toward_round_cap(r) {
                    continue;
                }
                counted_before += 1;
                last_ord = Some(r);
                if val_to_str(r.get("engine")) == cwg_common::REVIEW_ENGINE_INTERNAL_NEON {
                    has_neon_before = true;
                }
            }
            let last_v = last_ord
                .map(|r| val_to_str(r.get("verdict")))
                .unwrap_or_default();
            let last_tier_ok = last_ord.is_some_and(|r| {
                self.effective_risk != "XHIGH" || (json_truthy(r.get("xhigh")) && !has_neon_before)
            });
            let research_ok = last_ord.is_some_and(|ord| {
                let st = self.post_escalate_research_status(std::slice::from_ref(ord), cls);
                if reject_only_proven_absent_research {
                    st != cwg_common::ResearchWindowStatus::ProvenAbsent
                } else {
                    st == cwg_common::ResearchWindowStatus::Verified
                }
            });
            let modern_escalate_ok =
                counted_before == MAX_REVIEW_ROUNDS && last_v == "ESCALATE" && last_tier_ok && research_ok;
            let legacy_approved_tail_ok = !is_modern_marker
                && (1..=MAX_REVIEW_ROUNDS).contains(&counted_before)
                && last_v == "APPROVED"
                && last_tier_ok;
            let legacy_codex_cap_ok = !is_modern_marker
                && (!kept.is_empty()
                    || (val_to_str(cls.get("engine")) == "codex"
                        && (counted_before == LEGACY_MAX_REVIEW_ROUNDS || last_v == "ESCALATE")));
            let ok = modern_escalate_ok || legacy_approved_tail_ok || legacy_codex_cap_ok;
            if ok {
                kept.push(cls.clone());
            }
            if idx + 1 == cls_slice.len() {
                last_kept = ok;
            }
        }
        (kept, last_kept)
    }

    fn partition_cycle_closure(
        &mut self,
        ord_list: &[Value],
        cls_slice: &[Value],
    ) -> (Vec<Value>, Option<Value>, &'static str) {
        let (kept, _) = self.partition_cycle_closure_with_policy(ord_list, cls_slice, false);
        (kept, None, "")
    }

    fn codex_bin_missing(&mut self) -> bool {
        if let Some(cached) = self.codex_bin_missing_cache {
            return cached;
        }
        let missing = codex_lane::find_codex_binary().is_none();
        self.codex_bin_missing_cache = Some(missing);
        missing
    }

    fn breaker_info(&mut self) -> Value {
        if let Some(ref cached) = self.breaker_info_cache {
            return cached.clone();
        }
        let info = codex_lane::breaker_status();
        self.breaker_info_cache = Some(info.clone());
        info
    }

    fn has_codex_issue(&mut self) -> bool {
        self.swarm_ev.codex_cmd_failed
            || json_truthy(self.breaker_info().get("tripped"))
            || self.codex_bin_missing()
    }

    fn engine_priority_error(&mut self, rev_item: &Value) -> String {
        engine_priority_error_for_swarm(
            rev_item,
            self.swarm_ev,
            self.effective_risk,
            &mut self.codex_bin_missing_cache,
            &mut self.breaker_info_cache,
        )
    }

    fn is_acceptable_engine(&mut self, rev_item: &Value) -> bool {
        is_acceptable_review_engine(
            rev_item,
            self.swarm_ev,
            self.effective_risk,
            &mut self.codex_bin_missing_cache,
            &mut self.breaker_info_cache,
        )
    }

    fn invalidated_at_ts(&mut self, rev_item: &Value) -> Option<f64> {
        let app_lts = val_to_f64(rev_item.get("launch_ts"));
        let app_vts = app_lts.max(val_to_f64(rev_item.get("verdict_ts")));
        let cache_key = (app_lts.to_bits(), app_vts.to_bits());
        if let Some(&cached) = self.inv_ts_cache.get(&cache_key) {
            return cached;
        }
        let res = self.compute_invalidated_at_ts(rev_item, app_lts, app_vts);
        self.inv_ts_cache.insert(cache_key, res);
        res
    }

    fn compute_invalidated_at_ts(
        &mut self,
        rev_item: &Value,
        app_lts: f64,
        app_vts: f64,
    ) -> Option<f64> {
        if self.candidate_marks.is_empty() || is_review_fresh(rev_item, self.marker) {
            return None;
        }
        // INVARIANT: Approval/READY must still be fresh at `verdict_ts`; mid-review edits (`launch_ts < ts <= verdict_ts`) mean the verdict arrived already stale and cannot reset `MAX_REVIEW_ROUNDS`.
        let marks_by_verdict: Vec<&Map<String, Value>> = self
            .candidate_marks
            .iter()
            .copied()
            .filter(|m| val_to_f64(m.get("ts")) <= app_vts)
            .collect();
        if !marks_by_verdict.is_empty() {
            let last_by_v = marks_by_verdict[marks_by_verdict.len() - 1];
            if mark_fp(last_by_v).is_some() {
                if !is_review_fresh_marks(app_lts, &marks_by_verdict) {
                    return None;
                }
            } else if json_truthy(last_by_v.get("unknown"))
                || marks_by_verdict
                    .iter()
                    .any(|m| val_to_f64(m.get("ts")) > app_lts)
            {
                // INVARIANT: Historical `fp: null` marks (superseded by later marks) were valid at `app_vts` only when non-unknown and zero marks occurred in `(app_lts, app_vts]`.
                return None;
            }
            let covered_fps: HashSet<&str> = marks_by_verdict
                .iter()
                .filter(|m| val_to_f64(m.get("ts")) <= app_lts)
                .filter_map(|m| mark_fp(m))
                .collect();
            for m in self.candidate_marks {
                let mts = val_to_f64(m.get("ts"));
                if mts <= app_vts {
                    continue;
                }
                if mark_fp(m).map_or(true, |s| !covered_fps.contains(s)) {
                    return Some(mts);
                }
            }
            return None;
        }
        if !self.marks_truncated || app_lts < self.first_ts_val - 2.0 || app_vts >= self.oldest_mark_ts {
            return None;
        }
        let tx_ev = self.get_tx_edits();
        if tx_ev.covered_from_ts > app_lts + 1.0 {
            return None;
        }
        for (sts, ets) in &tx_ev.edit_spans {
            if *sts <= app_vts && (*ets > app_lts || *sts == app_lts) {
                return None;
            }
        }
        let post_edits: Vec<f64> = tx_ev
            .proven_change_ts
            .iter()
            .copied()
            .filter(|&t| app_vts < t && t < self.oldest_mark_ts)
            .collect();
        let distinct_tail_fps: HashSet<String> = self
            .candidate_marks
            .iter()
            .filter_map(|m| {
                m.get("fp")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
            })
            .collect();
        let any_unknown = self
            .candidate_marks
            .iter()
            .any(|m| json_truthy(m.get("unknown")));
        if post_edits.is_empty() && distinct_tail_fps.len() < 2 && !any_unknown {
            return None;
        }
        let min_ts = post_edits
            .into_iter()
            .fold(self.oldest_mark_ts, |acc, t| acc.min(t));
        Some(min_ts)
    }

    fn is_valid_cycle_approval(&mut self, rev_item: &Value) -> bool {
        if val_to_str(rev_item.get("verdict")) != "APPROVED" {
            return false;
        }
        !(self.effective_risk == "XHIGH" && !json_truthy(rev_item.get("xhigh")))
    }

    fn has_prior_terminal_approval(&mut self, ord_list: &[Value]) -> bool {
        if ord_list.len() < 2 {
            return false;
        }
        for prev_r in &ord_list[..ord_list.len() - 1] {
            if self.is_valid_cycle_approval(prev_r)
                && (self.invalidated_at_ts(prev_r).is_some() || is_review_fresh(prev_r, self.marker))
            {
                return true;
            }
        }
        false
    }

    fn post_escalate_research_status(
        &self,
        ord_list: &[Value],
        cls_rev: &Value,
    ) -> cwg_common::ResearchWindowStatus {
        let Some(last_ord) = ord_list.last() else {
            return cwg_common::ResearchWindowStatus::Incomplete;
        };
        if val_to_str(last_ord.get("verdict")) != "ESCALATE" {
            return cwg_common::ResearchWindowStatus::Incomplete;
        }
        let esc_vts =
            val_to_f64(last_ord.get("launch_ts")).max(val_to_f64(last_ord.get("verdict_ts")));
        let cls_lts = val_to_f64(cls_rev.get("launch_ts"));
        let sess = val_to_str(self.marker.get("session"));
        let resolved_tp = resolve_session_transcript_path(
            &sess,
            self.transcript_path.unwrap_or(""),
        );
        let tp_opt = if resolved_tp.is_empty() {
            self.transcript_path
        } else {
            Some(resolved_tp.as_str())
        };
        cwg_common::research_status_between(self.steps, tp_opt, esc_vts, cls_lts)
    }

    fn has_post_escalate_research(&self, ord_list: &[Value], cls_rev: &Value) -> bool {
        self.post_escalate_research_status(ord_list, cls_rev)
            == cwg_common::ResearchWindowStatus::Verified
    }

    fn is_valid_cycle_closure_ready_at_risk(
        &mut self,
        risk: &str,
        ord_list: &[Value],
        effective_closure: &[Value],
        cls_rev: &Value,
    ) -> bool {
        let normal_tail = closure_ready_tail_ok(risk, ord_list, cls_rev, false);
        let legacy_tail = !normal_tail
            && legacy_closure_ready_tail_ok(
                self.marker,
                risk,
                ord_list,
                effective_closure,
                cls_rev,
            );
        if !normal_tail && !legacy_tail {
            return false;
        }
        !self.has_prior_terminal_approval(ord_list)
            && (legacy_tail || self.has_post_escalate_research(ord_list, cls_rev))
    }

    fn is_valid_cycle_closure_ready(
        &mut self,
        ord_list: &[Value],
        effective_closure: &[Value],
        cls_rev: &Value,
    ) -> bool {
        self.is_valid_cycle_closure_ready_at_risk(
            self.effective_risk,
            ord_list,
            effective_closure,
            cls_rev,
        )
    }

    fn counts_toward_round_cap(&mut self, _rev_item: &Value) -> bool {
        true
    }
}

fn closure_blocked_halt_msg(blocked_count: usize) -> String {
    format!(
        "closure validation reached {}/{} `BLOCKED` verdicts (terminal closure cap); do NOT restart review or simplify — finish finitely with `[gate] draft-blocked: <exact blocker and handoff>`",
        blocked_count, MAX_CLOSURE_PASSES
    )
}

fn reconciled_latched_closure_halt(
    marker: &Value,
    cycle_cutoff_ts: f64,
    upper_ts: Option<f64>,
    raw_closure: &[Value],
    effective_closure: &[Value],
) -> Option<(usize, f64, Vec<String>)> {
    // INVARIANT: Never reconcile away a post-upgrade `halt_schema_version >= 2` latch (even if Round-4 Codex rollouts are later evicted while fallback `BLOCKED`s stay visible on the board). Reconcile ONLY legacy pre-schema-2 `c146cc0` latches when the exact latched `BLOCKED` passes are still visible in `raw_closure` and were filtered out as premature by `partition_cycle_closure`.
    let (h_cnt, h_ts, h_ids) = cwg_common::active_marker_closure_halt(marker)?;
    if h_ts <= cycle_cutoff_ts || upper_ts.is_some_and(|u| h_ts > u) {
        return None;
    }
    if cwg_common::marker_closure_halt_schema_version(marker)
        >= cwg_common::CLOSURE_HALT_SCHEMA_VERSION
        || effective_closure.len() >= raw_closure.len()
    {
        return Some((h_cnt, h_ts, h_ids));
    }
    let raw_blk: Vec<&Value> = raw_closure
        .iter()
        .filter(|r| val_to_str(r.get("verdict")) == "BLOCKED")
        .collect();
    if !raw_blk.is_empty() {
        let eff_blk: Vec<&Value> = effective_closure
            .iter()
            .filter(|r| val_to_str(r.get("verdict")) == "BLOCKED")
            .collect();
        let raw_blk_ids: HashSet<String> = raw_blk
            .iter()
            .map(|r| val_to_str(r.get("review_id")))
            .filter(|id| !id.is_empty())
            .collect();
        let all_ids_seen = h_ids.iter().all(|id| raw_blk_ids.contains(id));
        if h_ids.len() >= h_cnt {
            let eff_blk_ids: HashSet<String> = eff_blk
                .iter()
                .map(|r| val_to_str(r.get("review_id")))
                .filter(|id| !id.is_empty())
                .collect();
            let surviving_ids = h_ids.iter().filter(|id| eff_blk_ids.contains(*id)).count();
            if all_ids_seen && surviving_ids < MAX_CLOSURE_PASSES {
                return None;
            }
        } else {
            let filtered_blk: Vec<&Value> = raw_blk
                .iter()
                .copied()
                .filter(|r| !eff_blk.iter().any(|e| *e == *r))
                .collect();
            let matches_halt_ts = filtered_blk.iter().any(|r| {
                let ts = val_to_f64(r.get("launch_ts")).max(val_to_f64(r.get("verdict_ts")));
                (ts - h_ts).abs() <= TS_EPS
            });
            if all_ids_seen
                && filtered_blk.len() >= h_cnt
                && matches_halt_ts
                && eff_blk.len() < MAX_CLOSURE_PASSES
            {
                return None;
            }
        }
    }
    Some((h_cnt, h_ts, h_ids))
}

fn reconciled_latched_closure_halt_for_eval(
    eval: &mut ClosureEvalCtx<'_>,
    ord_list: &[Value],
    cycle_cutoff_ts: f64,
    upper_ts: Option<f64>,
    raw_closure: &[Value],
    effective_closure: &[Value],
) -> Option<(usize, f64, Vec<String>)> {
    // SAFETY: Reconcile legacy pre-v2 halts when visible `raw_closure` passes are either out-of-phase OR proven pre-research by a complete, gap-free transcript (`ProvenAbsent`), while preserving them when historical transcript coverage is `Incomplete`/evicted.
    let marker = eval.marker;
    if cwg_common::active_marker_closure_halt(marker).is_none() {
        return None;
    }
    if cwg_common::marker_closure_halt_schema_version(marker)
        >= cwg_common::CLOSURE_HALT_SCHEMA_VERSION
        || effective_closure.len() >= raw_closure.len()
    {
        return reconciled_latched_closure_halt(
            marker,
            cycle_cutoff_ts,
            upper_ts,
            raw_closure,
            effective_closure,
        );
    }
    let (reconcile_cls, _) =
        eval.partition_cycle_closure_with_policy(ord_list, raw_closure, true);
    reconciled_latched_closure_halt(marker, cycle_cutoff_ts, upper_ts, raw_closure, &reconcile_cls)
}

pub struct CandidateClosureInput<'a> {
    pub receipt: Option<&'a Value>,
    pub marker_in: &'a Value,
    pub checks_ev: &'a ChecksEvidence,
    pub sub_ev: &'a SubagentEvidence,
    pub swarm_ev: &'a SwarmEvidence,
    pub codex_reviews: &'a [Value],
    pub ctx: Option<&'a mut Value>,
    pub steps: Option<&'a [Value]>,
    pub transcript_path: Option<&'a str>,
}

fn is_standalone_non_repo_doc_candidate(
    marker: &Value,
    dpaths: &[String],
    policy: Option<&Value>,
) -> bool {
    // INVARIANT: Only exempt standalone non-repo pure-doc `HIGH` edits (e.g. global `~/.gemini/*.md` rules/agents with no git repo, project manifest, or test harness) from requiring a runtime test runner; measured shell edits (`Set-Content`) to those exact standalone docs are allowed, while any repo file, symlink into a repo, code/config/JSON/YAML file, or unmeasured/opaque shell mutation stays fail-closed.
    if dpaths.is_empty()
        || json_truthy(marker.get("operational"))
        || json_truthy(marker.get("unmeasured_shell_edit"))
    {
        return false;
    }
    if marker
        .get("content_marks")
        .and_then(|v| v.as_array())
        .is_some_and(|marks| marks.iter().any(|m| json_truthy(m.get("unknown"))))
    {
        return false;
    }
    if policy
        .and_then(|p| p.get("require_tests_on_high"))
        .is_some_and(|v| json_truthy(Some(v)))
    {
        return false;
    }
    for p in dpaths {
        if p == cwg_common::SHELL_MUTATION_SENTINEL {
            return false;
        }
        let p_obj = Path::new(p);
        if !p_obj.is_absolute() {
            return false;
        }
        let ext = p_obj
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .unwrap_or_default();
        if !matches!(ext.as_str(), "md" | "mdx" | "txt" | "rst" | "adoc") {
            return false;
        }
    }
    const HARNESS_FILES: &[&str] = &[
        "Cargo.toml",
        "package.json",
        "pyproject.toml",
        "pytest.ini",
        "setup.py",
        "setup.cfg",
        "go.mod",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "pubspec.yaml",
        "Makefile",
        "justfile",
        "CMakeLists.txt",
        "composer.json",
        "Gemfile",
        "mix.exs",
    ];
    let mut clean_dirs: HashSet<PathBuf> = HashSet::new();
    let mut walk_ancestors_clean = |start: &Path| -> bool {
        let mut cur: Option<&Path> = Some(start);
        let mut hit_cached = false;
        for _ in 0..32 {
            let Some(dir) = cur else {
                break;
            };
            if clean_dirs.contains(dir) {
                hit_cached = true;
                break;
            }
            if dir.join(".git").exists()
                || dir.join(".agents").join("carbon-gate.json").is_file()
                || dir.join("tests").is_dir()
                || dir.join("test").is_dir()
                || HARNESS_FILES.iter().any(|f| dir.join(f).is_file())
            {
                return false;
            }
            cur = dir.parent();
        }
        // SAFETY: Fail closed if directory depth exceeds 32 ancestors without reaching filesystem root or a verified cached ancestor.
        if !hit_cached && cur.is_some() {
            return false;
        }
        let mut mark = Some(start);
        while let Some(dir) = mark {
            if !clean_dirs.insert(dir.to_path_buf()) {
                break;
            }
            mark = dir.parent();
        }
        true
    };
    for p in dpaths {
        let p_obj = Path::new(p);
        let Some(parent) = p_obj.parent() else {
            return false;
        };
        if !parent.is_dir() {
            return false;
        }
        let resolved_parent = fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
        if !walk_ancestors_clean(&resolved_parent) {
            return false;
        }
        if let Ok(canon_file) = fs::canonicalize(p_obj) {
            if let Some(target_parent) = canon_file.parent() {
                if target_parent != resolved_parent && !walk_ancestors_clean(target_parent) {
                    return false;
                }
            }
        }
    }
    true
}


pub fn validate_candidate_closure(input: CandidateClosureInput<'_>) -> (bool, String) {
    validate_candidate_closure_inner(input, None)
}

fn validate_candidate_closure_inner(
    input: CandidateClosureInput<'_>,
    mut cycle_probe: Option<&mut codex_lane::ClosureCycleSummary>,
) -> (bool, String) {
    let CandidateClosureInput {
        receipt,
        marker_in,
        checks_ev,
        sub_ev,
        swarm_ev,
        codex_reviews,
        ctx,
        steps,
        transcript_path,
    } = input;
    let probing = cycle_probe.is_some();
    let mut probe_early_reject = false;
    let sess_for_pend = val_to_str(marker_in.get("session"));
    let (merged_opt, pend_ids_in_val) =
        cwg_common::apply_pending_marker_deltas(&sess_for_pend, Some(marker_in));
    let had_pend_in_val = !pend_ids_in_val.is_empty();
    let marker_owned: Value;
    let marker: &Value = if had_pend_in_val {
        if let Some(m_val) = merged_opt {
            marker_owned = m_val;
            &marker_owned
        } else {
            marker_in
        }
    } else {
        marker_in
    };
    let wclass = cwg_common::candidate_class(marker);
    let owned_ctx: Value;
    let cctx: &Value = match ctx {
        Some(ref c) if !had_pend_in_val => c,
        _ => {
            owned_ctx = cwg_common::resolve_candidate_context(marker, true);
            &owned_ctx
        }
    };
    let cwd = val_to_str(cctx.get("cwd"));
    let git_root = val_to_str(cctx.get("git_root"));
    let dpaths: Vec<String> = cctx
        .get("dpaths")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(|x| val_to_str(Some(x))).collect())
        .unwrap_or_default();
    let policy_owned: Option<Value> = cctx.get("policy").cloned();
    let policy = policy_owned.as_ref();
    let floor = val_to_str(cctx.get("floor"));
    let ctx_require_tests = cctx.get("require_tests").and_then(|v| v.as_bool());
    let ctx_needs_review = json_truthy(cctx.get("needs_review"));

    if wclass == cwg_common::WORK_OPERATIONAL {
        return (true, "operational".to_string());
    }

    let Some(rcp) = receipt else {
        return (
            false,
            format!(
                "missing terminal `[gate] verified: {}; <candidate and checks>` receipt on last line",
                floor
            ),
        );
    };

    let rkind = val_to_str(rcp.get("kind"));
    if rkind == "misplaced" {
        return (
            false,
            "`[gate]` receipt must be the very last non-empty line of the final message"
                .to_string(),
        );
    }
    if rkind == "malformed" {
        return (
            false,
            format!(
                "malformed `[gate]` receipt; expected `[gate] {}`",
                val_to_str(rcp.get("expected"))
            ),
        );
    }

    if wclass == cwg_common::WORK_PERSISTENT {
        if rkind == "operational" {
            return (
                false,
                "PERSISTENT candidate modified durable files and cannot close as `operational`"
                    .to_string(),
            );
        }
        if rkind == "no-change" {
            let (restored, why) = candidate_restored_to_clean_head(marker);
            if !restored {
                return (false, format!("`no-change` rejected: {}", why));
            }
            return (true, "no-change".to_string());
        }
    }

    let rr_ts = cwg_common::last_research_reset_ts(marker);
    if (rkind == "verified" || rkind == "pr-ready")
        && !dpaths.is_empty()
        && cwg_common::last_mark_fp(marker).is_none()
    {
        if probing {
            probe_early_reject = true;
        } else {
            return (
                false,
                format!(
                    "`{}` rejected: candidate contains an unmeasured or >32 MB file whose full SHA-256 fingerprint could not be verified within read budget",
                    rkind
                ),
            );
        }
    }

    // INVARIANT: Evaluate PERSISTENT closure (`verified`, `pr-ready`, `draft-blocked`) against both candidate path risk floor and active-cycle escalated risk (`--xhigh` or cycle receipt).
    let first_ts_for_risk = val_to_f64(marker.get("first_ts"));
    let rr_ts_for_risk = cwg_common::last_research_reset_ts(marker);
    let mut cycle_risk_inputs = vec![floor.clone()];
    let marker_dr = cwg_common::active_marker_declared_risk(marker);
    if !marker_dr.is_empty() {
        cycle_risk_inputs.push(marker_dr);
    }
    if let Some(tx_steps) = steps {
        let tx_dr = max_cycle_declared_receipt_risk(tx_steps, first_ts_for_risk, rr_ts_for_risk);
        if !tx_dr.is_empty() {
            cycle_risk_inputs.push(tx_dr);
        }
    }
    let cycle_min_risk = cwg_common::max_risk(&cycle_risk_inputs);
    let explicit_rcp_risk = rcp
        .get("risk")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_uppercase())
        .unwrap_or_default();
    let declared_risk = if explicit_rcp_risk.is_empty() {
        cycle_min_risk.clone()
    } else {
        explicit_rcp_risk
    };
    if !probing && rkind == "verified" && risk_order(&declared_risk) < risk_order(&floor) {
        return (
            false,
            format!(
                "declared risk `{}` is below candidate path risk floor `{}`",
                declared_risk, floor
            ),
        );
    }
    if !probing && rkind == "verified" && risk_order(&declared_risk) < risk_order(&cycle_min_risk) {
        return (
            false,
            format!(
                "declared risk `{}` is below active cycle escalated risk `{}` (set by `--xhigh` or an earlier receipt in this cycle)",
                declared_risk, cycle_min_risk
            ),
        );
    }
    let effective_risk = cwg_common::max_risk(&[cycle_min_risk, declared_risk]);

    // INVARIANT: Deterministic check verification rejects failed validation runs and requires a post-edit check pass when applicable.
    if (rkind == "verified" || rkind == "pr-ready")
        && checks_ev.latest_fail_ts > checks_ev.latest_pass_ts
    {
        return (
            false,
            "latest validation/test command failed with no subsequent passing verification run"
                .to_string(),
        );
    }

    let require_checks = if effective_risk == floor {
        if let Some(rt) = ctx_require_tests {
            rt
        } else {
            cwg_common::requires_tests(&effective_risk, &cwd, &dpaths, policy, &git_root)
        }
    } else {
        cwg_common::requires_tests(&effective_risk, &cwd, &dpaths, policy, &git_root)
    };

    if require_checks && (rkind == "verified" || rkind == "pr-ready") {
        let last_durable = {
            let ld = val_to_f64(marker.get("last_durable_ts"));
            if ld > 0.0 {
                ld
            } else {
                val_to_f64(marker.get("first_ts"))
            }
        };
        let checks_missing = checks_ev.checks_count == 0;
        let checks_stale =
            !checks_missing && (checks_ev.passed_count == 0 || checks_ev.latest_pass_ts + TS_EPS < last_durable);
        if (checks_missing || checks_stale)
            && !(effective_risk == "HIGH"
                && is_standalone_non_repo_doc_candidate(marker, &dpaths, policy))
        {
            if checks_missing {
                if checks_ev.saw_uncertain_pass {
                    return (
                        false,
                        format!(
                            "{} candidate has zero standalone verification/test commands recorded in runtime (chained/non-standalone check run(s) were ignored because ';', '||', trailing segments, or pipes can mask exit codes); re-run verification as a standalone command (single runner, no '; cmd' or trailing pipes)",
                            effective_risk
                        ),
                    );
                }
                return (
                    false,
                    format!(
                        "{} candidate has zero executed verification/test commands recorded in runtime",
                        effective_risk
                    ),
                );
            }
            return (
                false,
                "last passing test/verification command ran BEFORE the latest file edit; re-verify current bytes with a standalone test command (no trailing '; cmd' or pipes)"
                    .to_string(),
            );
        }
    }

    let candidate_marks: Vec<&Map<String, Value>> = marker
        .get("content_marks")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_object()).collect())
        .unwrap_or_default();
    let oldest_mark_ts = candidate_marks
        .iter()
        .map(|m| val_to_f64(m.get("ts")))
        .reduce(f64::min)
        .unwrap_or(f64::INFINITY);
    let first_ts_val = val_to_f64(marker.get("first_ts"));
    let marks_truncated = !candidate_marks.is_empty()
        && (val_to_f64(marker.get("marks_evicted_through_ts")) > 0.0
            || (first_ts_val > 0.0
                && oldest_mark_ts > first_ts_val + 1.0
                && val_to_i64(marker.get("edits")) as usize > candidate_marks.len()));

    let mut eval = ClosureEvalCtx {
        marker,
        steps,
        transcript_path,
        effective_risk: &effective_risk,
        candidate_marks: &candidate_marks,
        oldest_mark_ts,
        first_ts_val,
        marks_truncated,
        tx_edits_cache: None,
        swarm_ev,
        codex_bin_missing_cache: None,
        breaker_info_cache: None,
        inv_ts_cache: HashMap::new(),
    };

    let aborted_codex_map = &swarm_ev.aborted_codex_reviews;
    let is_aborted_codex_review = |rev_item: &Value| -> bool {
        let rid = val_to_str(rev_item.get("review_id"));
        if rid.is_empty() {
            return false;
        }
        let Some(&ab_call_ts) = aborted_codex_map.get(&rid) else {
            return false;
        };
        let rev_lts = val_to_f64(rev_item.get("launch_ts"));
        ab_call_ts <= 0.0 || rev_lts >= ab_call_ts - 5.0
    };

    let is_post_reset_rev = |rev_item: &Value| -> bool {
        if rr_ts <= 0.0 {
            return true;
        }
        let lts = val_to_f64(rev_item.get("launch_ts"));
        let vts = val_to_f64(rev_item.get("verdict_ts"));
        !((vts > 0.0 && vts <= rr_ts) || (lts > 0.0 && lts < rr_ts))
    };

    let mut pre_reset_resumed_reviews: Vec<Value> = Vec::new();
    let mut all_reviews: Vec<Value> = Vec::new();
    for r in sub_ev.reviews.iter().chain(swarm_ev.reviews.iter()) {
        if is_post_reset_rev(r) {
            all_reviews.push(r.clone());
        }
    }
    for r in codex_reviews {
        if is_aborted_codex_review(r) || !is_post_reset_rev(r) {
            continue;
        }
        if rr_ts > 0.0 {
            let sid = val_to_str(r.get("session_id"));
            let rpath = val_to_str(r.get("rollout_path"));
            if !codex_lane::is_post_reset_codex_session_proven(&sid, &rpath, rr_ts, first_ts_val) {
                pre_reset_resumed_reviews.push(r.clone());
                continue;
            }
        }
        all_reviews.push(r.clone());
    }
    all_reviews.sort_by(|a, b| val_to_f64(a.get("verdict_ts")).total_cmp(&val_to_f64(b.get("verdict_ts"))));

    let all_ordinary_reviews: Vec<Value> = all_reviews
        .iter()
        .filter(|r| r.get("kind").and_then(|v| v.as_str()) == Some("ordinary"))
        .cloned()
        .collect();
    let all_closure_reviews: Vec<Value> = all_reviews
        .iter()
        .filter(|r| r.get("kind").and_then(|v| v.as_str()) == Some("closure"))
        .cloned()
        .collect();

    // INVARIANT: Disqualified engine runs (e.g. internal review while Codex is available) must never inflate `MAX_REVIEW_ROUNDS`/`MAX_CLOSURE_PASSES` when eligible Codex rounds run.
    let mut raw_ordinary_reviews: Vec<Value> = Vec::new();
    let mut ineligible_ordinary_reviews: Vec<Value> = Vec::new();
    for r in &all_ordinary_reviews {
        if eval.is_acceptable_engine(r) {
            raw_ordinary_reviews.push(r.clone());
        } else {
            ineligible_ordinary_reviews.push(r.clone());
        }
    }
    let mut raw_closure_reviews: Vec<Value> = Vec::new();
    let mut ineligible_closure_reviews: Vec<&Value> = Vec::new();
    for r in &all_closure_reviews {
        if eval.is_acceptable_engine(r) {
            raw_closure_reviews.push(r.clone());
        } else {
            ineligible_closure_reviews.push(r);
        }
    }

    // INVARIANT: A valid terminal APPROVED or round-3 READY invalidated by post-verdict durable edits starts a fresh cycle once post-edit review runs, without laundering over-limit cycles, BLOCKED passes, or mid-review edits.
    let mut raw_eligible_reviews: Vec<Value> = raw_ordinary_reviews.clone();
    raw_eligible_reviews.extend(raw_closure_reviews.iter().cloned());
    raw_eligible_reviews.sort_by(|a, b| {
        val_to_f64(a.get("verdict_ts"))
            .total_cmp(&val_to_f64(b.get("verdict_ts")))
            .then_with(|| val_to_f64(a.get("launch_ts")).total_cmp(&val_to_f64(b.get("launch_ts"))))
    });

    let mut cycle_cutoff_ts = if rr_ts > 0.0 { rr_ts } else { 0.0 };
    let mut cycle_raw_ordinary: Vec<Value> = Vec::new();
    let mut cycle_counted_ordinary_n = 0usize;
    let mut cycle_raw_closure: Vec<Value> = Vec::new();
    let mut pending_reset_ts: Option<f64> = None;
    let mut pending_reset_kind = String::new();

    let within_cycle_ordinary_caps = |counted_n: usize, raw_ord: &[Value]| -> bool {
        counted_n <= MAX_REVIEW_ROUNDS && raw_ord.len() <= MAX_RAW_ORDINARY_ROUNDS
    };

    for rev in &raw_eligible_reviews {
        let rev_lts = val_to_f64(rev.get("launch_ts"));
        if let Some(p_ts) = pending_reset_ts {
            if rev_lts >= p_ts {
                cycle_cutoff_ts = p_ts;
                cycle_raw_ordinary.clear();
                cycle_counted_ordinary_n = 0;
                cycle_raw_closure.clear();
                pending_reset_kind.clear();
            }
        }
        if rev.get("kind").and_then(|v| v.as_str()) == Some("ordinary") {
            cycle_raw_ordinary.push(rev.clone());
            if eval.counts_toward_round_cap(rev) {
                cycle_counted_ordinary_n += 1;
            }
            let has_effective_closure_so_far = !cycle_raw_closure.is_empty()
                && !eval
                    .partition_cycle_closure(&cycle_raw_ordinary, &cycle_raw_closure)
                    .0
                    .is_empty();
            // INVARIANT: Any valid terminal `VERDICT: APPROVED` inside `MAX_REVIEW_ROUNDS` invalidated by a later durable edit retires its sequence so subsequent delta rounds start a fresh budget of at most 3 (`claude-code-stack` §6).
            if !has_effective_closure_so_far
                && within_cycle_ordinary_caps(cycle_counted_ordinary_n, &cycle_raw_ordinary)
                && !eval.has_prior_terminal_approval(&cycle_raw_ordinary)
                && eval.is_valid_cycle_approval(rev)
            {
                pending_reset_ts = eval.invalidated_at_ts(rev);
                pending_reset_kind = if pending_reset_ts.is_some() {
                    "APPROVED".to_string()
                } else {
                    String::new()
                };
            } else {
                pending_reset_ts = None;
                pending_reset_kind.clear();
            }
        } else {
            cycle_raw_closure.push(rev.clone());
            let (eff_cls_so_far, rev_is_effective) = eval
                .partition_cycle_closure_with_policy(&cycle_raw_ordinary, &cycle_raw_closure, false);
            if !rev_is_effective {
                // INVARIANT: A premature/filtered closure pass (even if its verdict lands after Round-4 `APPROVED`) is not an effective closure event and must not clear an already-scheduled post-`APPROVED` cycle reset.
                continue;
            }
            let rev_vts = val_to_f64(rev.get("verdict_ts")).max(rev_lts);
            let live_blk_so_far = eff_cls_so_far
                .iter()
                .filter(|r| val_to_str(r.get("verdict")) == "BLOCKED")
                .count();
            let latched_blk_so_far = reconciled_latched_closure_halt_for_eval(
                &mut eval,
                &cycle_raw_ordinary,
                cycle_cutoff_ts,
                Some(rev_vts),
                &cycle_raw_closure,
                &eff_cls_so_far,
            )
            .map(|(cnt, _, _)| cnt)
            .unwrap_or(0);
            let blk_so_far = live_blk_so_far.max(latched_blk_so_far);
            if within_cycle_ordinary_caps(cycle_counted_ordinary_n, &cycle_raw_ordinary)
                && eff_cls_so_far.len() <= MAX_CLOSURE_PASSES
                && blk_so_far < MAX_CLOSURE_PASSES
                && (eval.is_valid_cycle_closure_ready(&cycle_raw_ordinary, &eff_cls_so_far, rev)
                    || closure_ready_tail_ok(&effective_risk, &cycle_raw_ordinary, rev, true))
            {
                pending_reset_ts = eval.invalidated_at_ts(rev);
                pending_reset_kind = if pending_reset_ts.is_some() {
                    "READY".to_string()
                } else {
                    String::new()
                };
            } else {
                pending_reset_ts = None;
                pending_reset_kind.clear();
            }
        }
    }

    if let Some(p_ts) = pending_reset_ts {
        if ineligible_ordinary_reviews
            .iter()
            .any(|r| val_to_f64(r.get("launch_ts")) >= p_ts)
        {
            cycle_cutoff_ts = p_ts;
            cycle_raw_ordinary.clear();
            cycle_counted_ordinary_n = 0;
            cycle_raw_closure.clear();
            pending_reset_kind.clear();
        }
    }

    let cycle_ineligible_ordinary: Vec<Value> = if cycle_cutoff_ts > 0.0 {
        ineligible_ordinary_reviews
            .iter()
            .filter(|r| val_to_f64(r.get("launch_ts")) >= cycle_cutoff_ts)
            .cloned()
            .collect()
    } else {
        ineligible_ordinary_reviews.clone()
    };

    let cycle_ineligible_closure: Vec<&Value> = if cycle_cutoff_ts > 0.0 {
        ineligible_closure_reviews
            .iter()
            .copied()
            .filter(|r| val_to_f64(r.get("launch_ts")) >= cycle_cutoff_ts)
            .collect()
    } else {
        ineligible_closure_reviews.clone()
    };

    let ordinary_reviews: Vec<Value> = cycle_raw_ordinary.clone();
    let closure_reviews: Vec<Value> = cycle_raw_closure.clone();

    if !within_cycle_ordinary_caps(cycle_counted_ordinary_n, &cycle_raw_ordinary) {
        if probing {
            probe_early_reject = true;
        } else {
            return (
                false,
                format!(
                    "ordinary adversarial review exceeded MAX_REVIEW_ROUNDS={}",
                    MAX_REVIEW_ROUNDS
                ),
            );
        }
    }

    let needs_review = if effective_risk == floor {
        ctx_needs_review
    } else {
        ctx_needs_review || cwg_common::requires_review(&effective_risk, policy)
    };

    let eff_cycle_ordinary: &[Value] = if !ordinary_reviews.is_empty() {
        &ordinary_reviews
    } else if cycle_counted_ordinary_n >= MAX_REVIEW_ROUNDS {
        &cycle_raw_ordinary
    } else {
        &ordinary_reviews
    };
    let (effective_cycle_closure, unreplaced_premature_cls, _) =
        eval.partition_cycle_closure(eff_cycle_ordinary, &cycle_raw_closure);
    let latest_eff_cls_rev: Option<&Value> = effective_cycle_closure.last();
    let latest_eff_cls_verdict = latest_eff_cls_rev
        .map(|r| val_to_str(r.get("verdict")))
        .unwrap_or_default();

    let live_blocked_closure_count = effective_cycle_closure
        .iter()
        .filter(|r| val_to_str(r.get("verdict")) == "BLOCKED")
        .count();
    let reconciled_halt = reconciled_latched_closure_halt_for_eval(
        &mut eval,
        eff_cycle_ordinary,
        cycle_cutoff_ts,
        None,
        &cycle_raw_closure,
        &effective_cycle_closure,
    );
    let latched_blocked_count = reconciled_halt.as_ref().map(|(cnt, _, _)| *cnt).unwrap_or(0);
    let blocked_closure_count = live_blocked_closure_count.max(latched_blocked_count);
    if (rkind == "verified" || rkind == "pr-ready") && latched_blocked_count >= MAX_CLOSURE_PASSES {
        if probing {
            probe_early_reject = true;
        } else {
            return (false, closure_blocked_halt_msg(latched_blocked_count));
        }
    }

    let mut norm_ordinary: Vec<(&Value, String)> = Vec::with_capacity(ordinary_reviews.len());
    for (idx, rev) in ordinary_reviews.iter().enumerate() {
        let mut v = val_to_str(rev.get("verdict"));
        if v == "ESCALATE" && (idx + 1) < MAX_REVIEW_ROUNDS {
            v = "REVISE".to_string();
        }
        norm_ordinary.push((rev, v));
    }

    if norm_ordinary.len() >= 2 {
        for (earlier_rev, earlier_v) in &norm_ordinary[..norm_ordinary.len() - 1] {
            if earlier_v == "APPROVED"
                && is_review_fresh(earlier_rev, marker)
                && (effective_risk != "XHIGH" || json_truthy(earlier_rev.get("xhigh")))
            {
                if probing {
                    probe_early_reject = true;
                } else {
                    return (
                        false,
                        "review rounds continued unnecessarily after a current terminal APPROVED"
                            .to_string(),
                    );
                }
            }
        }
    }

    let (latest_ord_rev, latest_ord_verdict) = norm_ordinary
        .last()
        .map(|(r, v)| (Some(*r), v.as_str()))
        .unwrap_or((None, ""));
    let latest_cls_rev = closure_reviews.last();
    let latest_cls_verdict = latest_cls_rev
        .map(|r| val_to_str(r.get("verdict")))
        .unwrap_or_default();

    let opus_issue = swarm_ev.opus_issue_verified;
    let total_review_failures_len = sub_ev.review_failures.len() + swarm_ev.review_failures.len();
    let review_unavailable = total_review_failures_len >= 2
        || (total_review_failures_len >= 1 && opus_issue && eval.has_codex_issue());

    // INVARIANT: Hard-cap closure validation passes at `MAX_CLOSURE_PASSES` (2); exceeding the cap rejects vouching receipts while allowing terminal `draft-blocked`.
    if pending_reset_kind != "READY"
        && rkind != "draft-blocked"
        && effective_cycle_closure.len() > MAX_CLOSURE_PASSES
    {
        if probing {
            probe_early_reject = true;
        } else {
            return (
                false,
                format!(
                    "closure validation exceeded MAX_CLOSURE_PASSES={}; finish finitely with `[gate] draft-blocked: <exact blocker and handoff>`",
                    MAX_CLOSURE_PASSES
                ),
            );
        }
    }

    let legacy_three_round_closure = legacy_three_round_closure_cutoff(
        marker,
        &effective_risk,
        eff_cycle_ordinary,
        &effective_cycle_closure,
    )
    .is_some()
        && !eval.has_prior_terminal_approval(eff_cycle_ordinary);
    let closure_ready_rev: Option<&Value> = if unreplaced_premature_cls.is_none()
        && effective_cycle_closure.len() <= MAX_CLOSURE_PASSES
        && blocked_closure_count < MAX_CLOSURE_PASSES
    {
        latest_eff_cls_rev.filter(|&cls_rev| {
            is_review_fresh(cls_rev, marker)
                && (eval.is_valid_cycle_closure_ready(
                    eff_cycle_ordinary,
                    &effective_cycle_closure,
                    cls_rev,
                ) || closure_ready_tail_ok(&effective_risk, &cycle_raw_ordinary, cls_rev, true))
        })
    } else {
        None
    };

    let is_fresh_tier_approved = |r: &Value, v: &str| -> bool {
        if v != "APPROVED"
            || !is_review_fresh(r, marker)
            || (effective_risk == "XHIGH" && !json_truthy(r.get("xhigh")))
        {
            return false;
        }
        let ord_vts = val_to_f64(r.get("launch_ts")).max(val_to_f64(r.get("verdict_ts")));
        !effective_cycle_closure
            .iter()
            .any(|c| val_to_f64(c.get("launch_ts")) > ord_vts + TS_EPS)
    };
    let has_fresh_valid_app = norm_ordinary.iter().any(|(r, v)| is_fresh_tier_approved(r, v))
        || (effective_cycle_closure.is_empty()
            && cycle_raw_ordinary
                .last()
                .is_some_and(|r| is_fresh_tier_approved(r, &val_to_str(r.get("verdict")))));

    if probing && pending_reset_ts.is_some_and(|p_ts| now_sec() >= p_ts) {
        if let Some(probe) = cycle_probe {
            *probe = codex_lane::ClosureCycleSummary::default();
        }
        return (false, String::new());
    }
    if let Some(ref mut probe) = cycle_probe {
        let mut blk_ids: Vec<String> = Vec::new();
        let mut last_blk_ts = 0.0f64;
        let mut last_cls_ts = 0.0f64;
        for cr in &effective_cycle_closure {
            let lts = val_to_f64(cr.get("launch_ts"));
            let vts = lts.max(val_to_f64(cr.get("verdict_ts")));
            last_cls_ts = last_cls_ts.max(vts);
            if val_to_str(cr.get("verdict")) == "BLOCKED" {
                blk_ids.push(val_to_str(cr.get("review_id")));
                last_blk_ts = last_blk_ts.max(vts);
            }
        }
        let live_blk_cnt = blk_ids.len();
        let mut blk_cnt = live_blk_cnt;
        if live_blk_cnt < MAX_CLOSURE_PASSES {
            if let Some((h_cnt, h_ts, h_ids)) = reconciled_halt.clone() {
                if blk_cnt < h_cnt {
                    blk_cnt = h_cnt;
                    last_blk_ts = h_ts.max(last_blk_ts);
                    if !h_ids.is_empty() {
                        blk_ids = h_ids;
                    }
                }
            }
        }
        probe.live_blocked_count = live_blk_cnt;
        probe.blocked_count = blk_cnt;
        probe.last_blocked_ts = last_blk_ts;
        probe.blocked_ids = blk_ids;
        probe.effective_pass_count = effective_cycle_closure.len();
        probe.last_closure_ts = last_cls_ts;
        probe.counted_ordinary_rounds = cycle_counted_ordinary_n;
        probe.raw_ordinary_rounds = cycle_raw_ordinary.len();
        probe.legacy_three_round_closure_active = legacy_three_round_closure;
        let hyp_ord_ts = now_sec().max(last_cls_ts + 0.001);
        let hyp_ord = json!({
            "kind": "ordinary",
            "verdict": "REVISE",
            "launch_ts": hyp_ord_ts,
            "verdict_ts": hyp_ord_ts + 0.001,
            "engine": "codex",
            "xhigh": effective_risk == "XHIGH",
        });
        let next_counted_ord =
            cycle_counted_ordinary_n + usize::from(eval.counts_toward_round_cap(&hyp_ord));
        let next_raw_ord = cycle_raw_ordinary.len() + 1;
        probe.ordinary_cap_reached =
            next_counted_ord > MAX_REVIEW_ROUNDS || next_raw_ord > MAX_RAW_ORDINARY_ROUNDS;
        let round_cap_esc_opt = (eff_cycle_ordinary.len() >= MAX_REVIEW_ROUNDS)
            .then(|| eff_cycle_ordinary.last())
            .flatten()
            .filter(|r| {
                val_to_str(r.get("verdict")) == "ESCALATE"
                    && (effective_risk != "XHIGH" || json_truthy(r.get("xhigh")))
            });
        if let Some(esc_rev) = round_cap_esc_opt {
            let esc_vts =
                val_to_f64(esc_rev.get("launch_ts")).max(val_to_f64(esc_rev.get("verdict_ts")));
            probe.has_round_cap_escalate = true;
            probe.escalate_verdict_ts = esc_vts;
            let res_until_ts = effective_cycle_closure
                .first()
                .map(|c| val_to_f64(c.get("launch_ts")))
                .unwrap_or_else(|| now_sec() + 5.0);
            probe.has_post_escalate_research = eval
                .has_post_escalate_research(
                    eff_cycle_ordinary,
                    &json!({ "launch_ts": res_until_ts }),
                );
        }
        // INVARIANT: Report `has_fresh_ordinary_approved` as `true` only when `simplify` is satisfied and no subsequent closure pass superseded `APPROVED`, avoiding deadlock on legacy `APPROVED -> closure BLOCKED` cycles.
        probe.has_fresh_ordinary_approved = !probe_early_reject && has_fresh_valid_app;
    }

    let is_closing_kind = rkind == "verified" || rkind == "pr-ready";
    let eff_cls_len = effective_cycle_closure.len();
    let append_exhausted_reset_hint = !probing
        && is_closing_kind
        && closure_ready_rev.is_none()
        && pending_reset_kind != "READY"
        && eff_cls_len >= MAX_CLOSURE_PASSES
        && blocked_closure_count < MAX_CLOSURE_PASSES;

    let (tail_ok, mut tail_msg) = (|| -> (bool, String) {
        if !probing && is_closing_kind {
            let marker_sess = val_to_str(marker.get("session"));
            if !marker_sess.is_empty() {
                let tp_hint = transcript_path.unwrap_or("");
                let brain_root = rio::swarm_brain_and_cid(tp_hint, &marker_sess)
                    .0
                    .unwrap_or_else(|| rio::resolve_brain_root(""));
                let alive_workers =
                    cwg_common::active_review_workers(&brain_root, &marker_sess);
                if !alive_workers.is_empty() {
                    return (
                        false,
                        format!(
                            "waiting/active review swarm workers ({}) must be killed via `swarm(action=\"kill\", ...)` before closing the gate",
                            alive_workers.join(", ")
                        ),
                    );
                }
            }
        }
        if is_closing_kind && blocked_closure_count >= MAX_CLOSURE_PASSES {
            return (false, closure_blocked_halt_msg(blocked_closure_count));
        }

    if is_closing_kind
        && raw_ordinary_reviews.is_empty()
        && raw_closure_reviews.is_empty()
        && !pre_reset_resumed_reviews.is_empty()
    {
        return (
            false,
            "post-research-reset review resumed a pre-reset Codex session; start a brand-new review session without `--resume`"
                .to_string(),
        );
    }

    let closing_inelig_err =
        |ctx_eval: &mut ClosureEvalCtx, min_launch_ts: Option<f64>, check_after_cls: bool|
         -> Option<String> {
            let rev = cycle_ineligible_closure.last().copied().filter(|r| {
                min_launch_ts.map_or(true, |mt| val_to_f64(r.get("launch_ts")) >= mt)
                    && (!check_after_cls
                        || !latest_eff_cls_rev.map_or(false, |lr| {
                            val_to_f64(lr.get("launch_ts")) > val_to_f64(r.get("launch_ts"))
                        }))
            })?;
            let err = ctx_eval.engine_priority_error(rev);
            (!err.is_empty()).then_some(err)
        };

    if rkind == "verified" {
        if closure_ready_rev.is_some() {
            return (true, "verified".to_string());
        }
        if effective_cycle_closure.len() == 1
            && val_to_str(effective_cycle_closure[0].get("verdict")) == "BLOCKED"
        {
            let first_blk = &effective_cycle_closure[0];
            let first_blk_ts = val_to_f64(first_blk.get("launch_ts"))
                .max(val_to_f64(first_blk.get("verdict_ts")));
            if let Some(err) = closing_inelig_err(&mut eval, Some(first_blk_ts), false) {
                return (false, err);
            }
            if is_review_fresh(&effective_cycle_closure[0], marker) {
                return (
                    false,
                    format!(
                        "closure validation pass 1/{} returned `BLOCKED`; apply one bounded REMEDIATE/REDESIGN + tests and run final `{}` pass 2/{}, or finish finitely with `[gate] draft-blocked: <blocker>`",
                        MAX_CLOSURE_PASSES, CLOSURE_PHASE_FLAG, MAX_CLOSURE_PASSES
                    ),
                );
            }
            return (
                false,
                format!(
                    "closure validation pass 1/{} returned `BLOCKED`; run final `{}` pass 2/{} for `CLOSURE_VALIDATION: READY` or finish with `[gate] draft-blocked: <blocker>`",
                    MAX_CLOSURE_PASSES, CLOSURE_PHASE_FLAG, MAX_CLOSURE_PASSES
                ),
            );
        }
        if effective_risk == "XHIGH" {
            if let Some(cls_rev) = latest_eff_cls_rev.filter(|&r| {
                is_review_fresh(r, marker)
                    && (eval.is_valid_cycle_closure_ready_at_risk(
                        "HIGH",
                        eff_cycle_ordinary,
                        &effective_cycle_closure,
                        r,
                    ) || closure_ready_tail_ok("HIGH", &cycle_raw_ordinary, r, true))
            }) {
                if !json_truthy(cls_rev.get("xhigh")) {
                    return (
                        false,
                        format!(
                            "XHIGH candidate's `CLOSURE_VALIDATION: READY` verdict came from standard tier (`{}`), not XHIGH (`codex --xhigh --closure` on `{}` or internal `{}` with `REVIEW_TIER: XHIGH`)",
                            val_to_str(cls_rev.get("engine")),
                            cwg_common::CODEX_ASTRA_MODEL,
                            cwg_common::OPUS_HIGH_MODEL
                        ),
                    );
                }
                if let Some(last_ord) = cycle_raw_ordinary.last().filter(|r| {
                    val_to_str(r.get("verdict")) == "APPROVED" && !json_truthy(r.get("xhigh"))
                }) {
                    return (
                        false,
                        format!(
                            "XHIGH candidate's `APPROVED` verdict came from standard tier (`{}`), not XHIGH (`codex --xhigh` on `{}` or internal `{}` with `REVIEW_TIER: XHIGH`)",
                            val_to_str(last_ord.get("engine")),
                            cwg_common::CODEX_ASTRA_MODEL,
                            cwg_common::OPUS_HIGH_MODEL
                        ),
                    );
                }
            }
        }
        if pending_reset_kind == "READY" {
            return (
                false,
                format!(
                    "{} candidate's `CLOSURE_VALIDATION: READY` verdict is stale: durable candidate content changed after review",
                    effective_risk
                ),
            );
        }
        let cap_exhausted_verdict: Option<String> = if ordinary_reviews.len() == MAX_REVIEW_ROUNDS
            && (latest_ord_verdict == "REVISE" || latest_ord_verdict == "ESCALATE")
        {
            Some(latest_ord_verdict.to_string())
        } else if ordinary_reviews.is_empty() && cycle_counted_ordinary_n == MAX_REVIEW_ROUNDS {
            cycle_raw_ordinary
                .last()
                .map(|r| val_to_str(r.get("verdict")))
                .filter(|v| v == "REVISE" || v == "ESCALATE")
        } else {
            None
        };
        if let Some(ref cap_v) = cap_exhausted_verdict {
            if latest_eff_cls_verdict == "BLOCKED"
                && latest_eff_cls_rev.map_or(false, |r| is_review_fresh(r, marker))
            {
                return (
                    false,
                    format!(
                        "invoked adversarial review ended in `{}` and closure validation returned `BLOCKED`, not `READY`",
                        cap_v
                    ),
                );
            }
            if cap_v != "ESCALATE" && latest_cls_verdict == "READY" {
                return (
                    false,
                    format!(
                        "round-{} ordinary review ended in `{}`, not `ESCALATE`; `--closure` requires round-{} `ESCALATE` + verified post-escalation research (finish finitely with `[gate] draft-blocked`)",
                        MAX_REVIEW_ROUNDS, cap_v, MAX_REVIEW_ROUNDS
                    ),
                );
            }
            if latest_cls_verdict == "READY" {
                if let Some(cls_r) = cycle_raw_closure.last() {
                    if !eval.has_post_escalate_research(eff_cycle_ordinary, cls_r) {
                        return (
                            false,
                            "closure validation `READY` lacks verified post-ESCALATE documentation/web research in transcript before `--closure`"
                                .to_string(),
                        );
                    }
                }
            } else if let Some(err) = closing_inelig_err(&mut eval, None, true) {
                return (false, err);
            }
            return (
                false,
                format!(
                    "invoked adversarial review ended in `{}`, not `APPROVED` (all {} ordinary rounds used; perform one focused research pass and run `{}` for `CLOSURE_VALIDATION: READY`, or finish with `[gate] draft-blocked`)",
                    cap_v, MAX_REVIEW_ROUNDS, CLOSURE_PHASE_FLAG
                ),
            );
        }
        if latest_eff_cls_verdict == "BLOCKED" {
            return (
                false,
                "closure validation returned `BLOCKED`, not `READY`; resolve blocking findings before closing"
                    .to_string(),
            );
        }
        if !latest_ord_verdict.is_empty() && latest_ord_verdict != "APPROVED" {
            return (
                false,
                format!(
                    "invoked adversarial review ended in `{}`, not `APPROVED`",
                    latest_ord_verdict
                ),
            );
        }
        if !needs_review && ordinary_reviews.is_empty() {
            if let Some(last_any) = all_ordinary_reviews.last() {
                let last_any_v = val_to_str(last_any.get("verdict"));
                if !last_any_v.is_empty() && last_any_v != "APPROVED" {
                    return (
                        false,
                        format!(
                            "invoked adversarial review ended in `{}`, not `APPROVED`",
                            last_any_v
                        ),
                    );
                }
                let prio_err = eval.engine_priority_error(last_any);
                if !prio_err.is_empty() {
                    return (false, prio_err);
                }
            }
        }
        if needs_review {
            let Some(ord_rev) = latest_ord_rev.filter(|_| latest_ord_verdict == "APPROVED") else {
                if let Some(last_pi) = cycle_ineligible_closure
                    .last()
                    .copied()
                    .or_else(|| cycle_ineligible_ordinary.last())
                {
                    let prio_err = eval.engine_priority_error(last_pi);
                    if !prio_err.is_empty() {
                        return (false, prio_err);
                    }
                }
                if let Some(last_raw) = raw_ordinary_reviews.last() {
                    if val_to_str(last_raw.get("verdict")) == "APPROVED"
                        && !is_review_fresh(last_raw, marker)
                    {
                        return (
                            false,
                            format!(
                                "{} candidate's `APPROVED` verdict is stale: durable candidate content changed after review",
                                effective_risk
                            ),
                        );
                    }
                }
                let esc_chain = cwg_common::review_escalation_chain(&effective_risk);
                return (
                    false,
                    format!(
                        "{} candidate lacks an independent `VERDICT: APPROVED` from Codex lane (`carbon-stack codex-lane review`, or internal {} only on verified outage)",
                        effective_risk,
                        esc_chain
                    ),
                );
            };
            if !is_review_fresh(ord_rev, marker) {
                return (
                    false,
                    format!(
                        "{} candidate's `APPROVED` verdict is stale: durable candidate content changed after review",
                        effective_risk
                    ),
                );
            }
            let eng = val_to_str(ord_rev.get("engine"));
            if effective_risk == "XHIGH" && !json_truthy(ord_rev.get("xhigh")) {
                return (
                    false,
                    format!(
                        "XHIGH candidate's `APPROVED` verdict came from standard tier (`{}`), not XHIGH (`codex --xhigh` on `{}` or internal `{}` with `REVIEW_TIER: XHIGH`)",
                        eng,
                        cwg_common::CODEX_ASTRA_MODEL,
                        cwg_common::OPUS_HIGH_MODEL
                    ),
                );
            }
            // INVARIANT: Under the finite `claude-code-stack` gate, a fresh `VERDICT: APPROVED` after candidate-bound `simplify` immediately closes `verified` without post-approval `--closure`.
            let ord_vts = val_to_f64(ord_rev.get("launch_ts")).max(val_to_f64(ord_rev.get("verdict_ts")));
            if effective_cycle_closure
                .iter()
                .any(|c| val_to_f64(c.get("launch_ts")) > ord_vts + TS_EPS)
            {
                return (
                    false,
                    "review activity continued after terminal `VERDICT: APPROVED`".to_string(),
                );
            }
        }
        return (true, "verified".to_string());
    }

    if rkind == "pr-ready" {
        if closure_ready_rev.is_some() {
            return (true, "pr-ready".to_string());
        }
        let pr_cap_met = ordinary_reviews.len() == MAX_REVIEW_ROUNDS
            || (ordinary_reviews.is_empty() && cycle_counted_ordinary_n == MAX_REVIEW_ROUNDS);
        if pr_cap_met {
            if let Some(err) = closing_inelig_err(&mut eval, None, true) {
                return (false, err);
            }
        }
        let eff_latest_ord_verdict = eff_cycle_ordinary
            .last()
            .map(|r| val_to_str(r.get("verdict")))
            .unwrap_or_default();
        if !legacy_three_round_closure {
            if eff_cycle_ordinary.len() < MAX_REVIEW_ROUNDS || eff_latest_ord_verdict != "ESCALATE" {
                return (
                    false,
                    format!(
                        "`pr-ready` requires round-{} `ESCALATE` + verified post-escalation research followed by fresh `CLOSURE_VALIDATION: READY`",
                        MAX_REVIEW_ROUNDS
                    ),
                );
            }
            if cycle_raw_closure.last().is_some_and(|cls_r| {
                val_to_str(cls_r.get("verdict")) == "READY"
                    && !eval.has_post_escalate_research(eff_cycle_ordinary, cls_r)
            }) {
                return (
                    false,
                    "`pr-ready` lacks verified post-ESCALATE documentation/web research in transcript before `--closure`"
                        .to_string(),
                );
            }
        }
        return (
            false,
            "`pr-ready` lacks fresh `CLOSURE_VALIDATION: READY` from an eligible review engine"
                .to_string(),
        );
    }

    if rkind == "draft-blocked" {
        if closure_ready_rev.is_some() {
            return (
                false,
                "`draft-blocked` conflicts with current `CLOSURE_VALIDATION: READY`; close with `pr-ready` or `verified`"
                    .to_string(),
            );
        }
        if has_fresh_valid_app {
            return (
                false,
                "`draft-blocked` conflicts with current fresh `VERDICT: APPROVED`; close with `verified`"
                    .to_string(),
            );
        }
        // INVARIANT: Match CLI guidance when all ordinary review rounds are exhausted without `ESCALATE` (e.g. 4x `REVISE` where `--closure` is forbidden): allow finite terminal `[gate] draft-blocked`.
        let hyp_ord_ts = now_sec();
        let hyp_ord = json!({
            "kind": "ordinary",
            "verdict": "REVISE",
            "launch_ts": hyp_ord_ts,
            "verdict_ts": hyp_ord_ts + 0.001,
            "engine": "codex",
            "xhigh": effective_risk == "XHIGH",
        });
        let ord_cap_exhausted = (cycle_counted_ordinary_n
            + usize::from(eval.counts_toward_round_cap(&hyp_ord))
            > MAX_REVIEW_ROUNDS)
            || (cycle_raw_ordinary.len() + 1 > MAX_RAW_ORDINARY_ROUNDS);
        let has_round_cap_esc = (eff_cycle_ordinary.len() >= MAX_REVIEW_ROUNDS)
            .then(|| eff_cycle_ordinary.last())
            .flatten()
            .is_some_and(|r| {
                val_to_str(r.get("verdict")) == "ESCALATE"
                    && (effective_risk != "XHIGH" || json_truthy(r.get("xhigh")))
            });
        if ord_cap_exhausted && !has_round_cap_esc {
            return (true, "draft-blocked".to_string());
        }
        let after_escalate = ordinary_reviews.len() >= MAX_REVIEW_ROUNDS
            || cycle_counted_ordinary_n >= MAX_REVIEW_ROUNDS
            || blocked_closure_count >= MAX_CLOSURE_PASSES
            || legacy_three_round_closure;
        // INVARIANT: When all `MAX_CLOSURE_PASSES` slots are consumed without a fresh valid `READY` (e.g. a mid-review edit made Pass 2 `READY` arrive already stale, so CLI/hooks forbid Pass 3 and `redesign-reset`), allow finite terminal `draft-blocked`.
        let closure_budget_exhausted_no_ready = effective_cycle_closure.len() >= MAX_CLOSURE_PASSES
            && closure_ready_rev.is_none()
            && pending_reset_kind != "READY";
        if after_escalate
            && ((latest_eff_cls_verdict == "BLOCKED"
                && latest_eff_cls_rev.map_or(false, |r| is_review_fresh(r, marker)))
                || blocked_closure_count >= MAX_CLOSURE_PASSES
                || closure_budget_exhausted_no_ready)
        {
            return (true, "draft-blocked".to_string());
        }
        if review_unavailable {
            return (true, "draft-blocked".to_string());
        }
        return (
            false,
            format!(
                "`draft-blocked` requires `CLOSURE_VALIDATION: BLOCKED` after round-{} ESCALATE (or {}/{} closure blocks, or {}/{} REVISE rounds without ESCALATE), or exhausted review lanes",
                MAX_REVIEW_ROUNDS, MAX_CLOSURE_PASSES, MAX_CLOSURE_PASSES, MAX_REVIEW_ROUNDS, MAX_REVIEW_ROUNDS
            ),
        );
    }

    (false, format!("unsupported receipt kind `{}`", rkind))
    })();

    if let Some(probe) = cycle_probe {
        probe.has_fresh_ready = !probe_early_reject && closure_ready_rev.is_some();
        return (probe.has_fresh_ready, String::new());
    }
    if !tail_ok && append_exhausted_reset_hint && !tail_msg.contains("draft-blocked") {
        tail_msg = format!(
            "{} (all {}/{} closure passes in this cycle are consumed; finish finitely with `[gate] draft-blocked: <exact blocker and handoff>`)",
            tail_msg, eff_cls_len, MAX_CLOSURE_PASSES
        );
    }
    (tail_ok, tail_msg)
}

fn merge_sticky_issue_entry(
    state: &mut Map<String, Value>,
    flag_key: &str,
    ts_key: &str,
    verified: &mut bool,
    issue_ts: &mut f64,
) {
    if !*verified && !json_truthy(state.get(flag_key)) {
        return;
    }
    state.insert(flag_key.to_string(), Value::Bool(true));
    *verified = true;
    let obs_ts = *issue_ts;
    let prev_ts = val_to_f64(state.get(ts_key));
    let eff_ts = if obs_ts > 0.0 && prev_ts > 0.0 {
        obs_ts.min(prev_ts)
    } else if obs_ts > 0.0 {
        obs_ts
    } else {
        prev_ts
    };
    state.insert(ts_key.to_string(), json!(eff_ts));
    *issue_ts = eff_ts;
}

fn merge_sticky_max_ts(state: &mut Map<String, Value>, key: &str, ts: &mut f64) {
    let eff = (*ts).max(val_to_f64(state.get(key)));
    if eff > 0.0 {
        state.insert(key.to_string(), json!(eff));
        *ts = eff;
    }
}

pub fn merge_sticky_outage_state(state: &mut Map<String, Value>, swarm_ev: &mut SwarmEvidence) {
    // INVARIANT: Propagate earliest confirmed candidate outage flags/timestamps bidirectionally between `state` and `swarm_ev` so in-window activity never erases earlier evicted outages.
    merge_sticky_issue_entry(
        state,
        "sonnet_issue_verified",
        "sonnet_issue_ts",
        &mut swarm_ev.sonnet_issue_verified,
        &mut swarm_ev.sonnet_issue_ts,
    );
    merge_sticky_issue_entry(
        state,
        "neon_issue_verified",
        "neon_issue_ts",
        &mut swarm_ev.neon_issue_verified,
        &mut swarm_ev.neon_issue_ts,
    );
    merge_sticky_issue_entry(
        state,
        "hydrogen_issue_verified",
        "hydrogen_issue_ts",
        &mut swarm_ev.hydrogen_issue_verified,
        &mut swarm_ev.hydrogen_issue_ts,
    );
    merge_sticky_issue_entry(
        state,
        "opus_issue_verified",
        "opus_issue_ts",
        &mut swarm_ev.opus_issue_verified,
        &mut swarm_ev.opus_issue_ts,
    );
    merge_sticky_max_ts(state, "sonnet_last_issue_ts", &mut swarm_ev.sonnet_last_issue_ts);
    merge_sticky_max_ts(state, "sonnet_healthy_ts", &mut swarm_ev.sonnet_healthy_ts);
    merge_sticky_max_ts(state, "neon_last_issue_ts", &mut swarm_ev.neon_last_issue_ts);
    merge_sticky_max_ts(state, "neon_healthy_ts", &mut swarm_ev.neon_healthy_ts);
    merge_sticky_max_ts(state, "hydrogen_last_issue_ts", &mut swarm_ev.hydrogen_last_issue_ts);
    merge_sticky_max_ts(state, "hydrogen_healthy_ts", &mut swarm_ev.hydrogen_healthy_ts);
}





fn engine_priority_error_for_swarm(
    rev_item: &Value,
    swarm_ev: &SwarmEvidence,
    effective_risk: &str,
    codex_bin_missing_cache: &mut Option<bool>,
    breaker_info_cache: &mut Option<Value>,
) -> String {
    let inv_eng = val_to_str(rev_item.get("engine"));
    // INVARIANT: `internal-neon` (`gemini-4-neon-xhigh`) is capped at `HIGH` escalation and excluded from `XHIGH` before round/closure counting.
    if inv_eng == cwg_common::REVIEW_ENGINE_INTERNAL_NEON && effective_risk == "XHIGH" {
        return format!(
            "XHIGH candidate cannot use `{}` (`internal-neon` is capped at `HIGH`); run `carbon-stack codex-lane review --xhigh` on `{}` or escalate to `{}` -> `{}` with `REVIEW_TIER: XHIGH`",
            cwg_common::NEON_XHIGH_MODEL,
            cwg_common::CODEX_ASTRA_MODEL,
            cwg_common::OPUS_HIGH_MODEL,
            cwg_common::CARBON_HIGH_MODEL
        );
    }
    // INVARIANT: Internal escalation is valid ONLY when launched strictly after Codex unavailability was confirmed.
    let codex_missing = *codex_bin_missing_cache
        .get_or_insert_with(|| codex_lane::find_codex_binary().is_none());
    let breaker_val: &Value = breaker_info_cache.get_or_insert_with(codex_lane::breaker_status);
    let hist_slice = codex_lane::breaker_history_slice(breaker_val);
    let has_codex_issue = swarm_ev.codex_cmd_failed
        || json_truthy(breaker_val.get("tripped"))
        || !hist_slice.is_empty()
        || codex_missing;

    let launch_ts = val_to_f64(rev_item.get("launch_ts"));
    let was_codex_unavailable = if codex_missing {
        true
    } else {
        let rev_step = rev_item.get("step_idx").and_then(|v| v.as_i64());
        let same_or_earlier_step = rev_step.map_or(false, |rs| {
            swarm_ev.codex_issue_step >= 0 && (rs as isize) <= swarm_ev.codex_issue_step
        });
        let cmd_failed_ok = swarm_ev.codex_cmd_failed
            && !same_or_earlier_step
            && (swarm_ev.codex_issue_ts <= 0.0
                || (launch_ts > 0.0 && launch_ts >= swarm_ev.codex_issue_ts));
        let breaker_ok = json_truthy(breaker_val.get("tripped")) && {
            let b_ts = val_to_f64(breaker_val.get("tripped_at"));
            b_ts <= 0.0
                || (launch_ts > 0.0
                    && (launch_ts > b_ts || (launch_ts == b_ts && !same_or_earlier_step)))
        };
        let hist_ok = hist_slice.iter().any(|w| {
            let w_at = val_to_f64(w.get("tripped_at"));
            let w_until = val_to_f64(w.get("until_ts"));
            w_at > 0.0
                && launch_ts > 0.0
                && (launch_ts > w_at || (launch_ts == w_at && !same_or_earlier_step))
                && (w_until <= 0.0 || launch_ts <= w_until)
        });
        cmd_failed_ok || breaker_ok || hist_ok
    };

    // INVARIANT: Escalation from Opus to Neon/Carbon/native is valid ONLY when launched at or after
    // the verified Opus outage (`opus_issue_ts`); `escalated_from_opus` records an earlier Opus request
    // on the same worker and must never let a post-hoc Opus failure retroactively legalize an earlier review.
    let escalated_tier_ok = swarm_ev.opus_issue_verified
        && (swarm_ev.opus_issue_ts <= 0.0
            || (launch_ts > 0.0 && launch_ts >= swarm_ev.opus_issue_ts - TS_EPS));

    if (inv_eng == cwg_common::REVIEW_ENGINE_INTERNAL_NEON
        || inv_eng == cwg_common::REVIEW_ENGINE_INTERNAL_CARBON
        || inv_eng == "native")
        && !escalated_tier_ok
    {
        let fallback_default = if inv_eng == cwg_common::REVIEW_ENGINE_INTERNAL_NEON {
            cwg_common::NEON_XHIGH_MODEL
        } else {
            cwg_common::CARBON_HIGH_MODEL
        };
        let m_label = rev_item
            .get("model")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(fallback_default);
        if swarm_ev.opus_issue_verified {
            return format!(
                "internal review ran on `{}` before the verified `{}` error/quota/availability failure; run a fresh review after the verified `{}` outage",
                m_label,
                cwg_common::OPUS_HIGH_MODEL,
                cwg_common::OPUS_HIGH_MODEL
            );
        }
        return format!(
            "internal review ran on `{}` without a verified `{}` error/quota/availability failure; run internal review on `{}` first",
            m_label,
            cwg_common::OPUS_HIGH_MODEL,
            cwg_common::OPUS_HIGH_MODEL
        );
    }
    if (inv_eng == cwg_common::REVIEW_ENGINE_INTERNAL_OPUS
        || inv_eng == cwg_common::REVIEW_ENGINE_INTERNAL_NEON
        || inv_eng == cwg_common::REVIEW_ENGINE_INTERNAL_CARBON
        || inv_eng == "native")
        && !was_codex_unavailable
    {
        if has_codex_issue {
            return "internal review ran before primary Codex lane (`carbon-stack codex-lane`) became unavailable; run a fresh review after the verified Codex outage".to_string();
        }
        if swarm_ev.codex_timeout_seen {
            return "internal review ran after a Codex thinking timeout while primary Codex lane (`carbon-stack codex-lane`) remained available; a thinking timeout is NOT an outage and does NOT consume a review round — re-run `carbon-stack codex-lane review` without `--timeout` to continue in the same Codex session with an increased timeout".to_string();
        }
        return "internal review ran while primary Codex lane (`carbon-stack codex-lane`) is available; run `carbon-stack codex-lane review` first and escalate to internal review ONLY when Codex is unavailable".to_string();
    }
    String::new()
}

fn is_acceptable_review_engine(
    rev_item: &Value,
    swarm_ev: &SwarmEvidence,
    effective_risk: &str,
    codex_bin_missing_cache: &mut Option<bool>,
    breaker_info_cache: &mut Option<Value>,
) -> bool {
    let eng_name = val_to_str(rev_item.get("engine"));
    matches!(
        eng_name.as_str(),
        "codex"
            | cwg_common::REVIEW_ENGINE_INTERNAL_OPUS
            | cwg_common::REVIEW_ENGINE_INTERNAL_NEON
            | cwg_common::REVIEW_ENGINE_INTERNAL_CARBON
            | "native"
    ) && engine_priority_error_for_swarm(
        rev_item,
        swarm_ev,
        effective_risk,
        codex_bin_missing_cache,
        breaker_info_cache,
    )
    .is_empty()
}

fn resolve_session_transcript_path(session: &str, transcript_path: &str) -> String {
    let trimmed = transcript_path.trim();
    if !trimmed.is_empty() {
        return trimmed.to_string();
    }
    let sess = session.trim();
    if sess.is_empty() {
        return String::new();
    }
    let broot = rio::resolve_brain_root("");
    let base_tp = rio::member_transcript_path(&broot, sess);
    let full_tp = base_tp.with_file_name("transcript_full.jsonl");
    if full_tp.is_file() {
        return full_tp.to_string_lossy().into_owned();
    }
    base_tp.to_string_lossy().into_owned()
}

fn max_cycle_declared_receipt_risk(steps: &[Value], min_ts: f64, rr_ts: f64) -> String {
    let mut found: Vec<String> = Vec::new();
    for step in steps.iter().rev() {
        let source = step.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let stype = step.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if source != "MODEL" || stype != "PLANNER_RESPONSE" {
            continue;
        }
        let sts = step
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(rio::parse_iso_ts)
            .unwrap_or(0.0);
        if rr_ts > 0.0 && sts <= rr_ts {
            if sts > 0.0 {
                break;
            }
            continue;
        }
        if sts > 0.0 && sts < min_ts - 1.0 {
            break;
        }
        let content = step.get("content").and_then(|v| v.as_str()).unwrap_or("");
        if let Some(rcp) = cwg_common::parse_terminal_receipt(content) {
            let rk = val_to_str(rcp.get("kind"));
            if rk == "verified" || rk == "pr-ready" {
                let r = val_to_str(rcp.get("risk")).to_uppercase();
                if cwg_common::is_valid_risk(&r) {
                    found.push(r);
                }
            }
        }
    }
    if found.is_empty() {
        String::new()
    } else {
        cwg_common::max_risk(&found)
    }
}

pub fn evaluate_closure_cycle_for_marker(
    marker: &Value,
    session: &str,
    git_root: &str,
    transcript_path: &str,
    min_risk_override: &str,
) -> codex_lane::ClosureCycleSummary {
    // INVARIANT: Evaluate CLI closure pass limits, `has_fresh_ready`, and `research-reset` eligibility through `validate_candidate_closure_inner` so CLI and `Stop` share a single cycle state machine.
    if session.trim().is_empty() || !marker.is_object() || json_truthy(marker.get("closed")) {
        return codex_lane::ClosureCycleSummary::default();
    }
    let mut marker_with_sess: Value;
    let base_marker: &Value = if val_to_str(marker.get("session")).is_empty() {
        marker_with_sess = marker.clone();
        if let Some(obj) = marker_with_sess.as_object_mut() {
            obj.insert("session".to_string(), Value::String(session.to_string()));
        }
        &marker_with_sess
    } else {
        marker
    };
    let caught_marker = catch_up_unmeasured_changes(base_marker);
    let eff_marker: &Value = &caught_marker;
    let first_ts_val = val_to_f64(eff_marker.get("first_ts"));
    let rr_ts = cwg_common::last_research_reset_ts(eff_marker);
    let rr_seq = cwg_common::last_research_reset_board_seq(eff_marker);
    let eff_first_ts = first_ts_val.max(rr_ts);
    if eff_first_ts <= 0.0 {
        return codex_lane::ClosureCycleSummary::default();
    }
    let eff_round_start = val_to_i64(eff_marker.get("round_start_msg_id")).max(rr_seq);
    let eff_tp = resolve_session_transcript_path(session, transcript_path);
    let tp_opt = if eff_tp.is_empty() {
        None
    } else {
        Some(eff_tp.as_str())
    };
    let steps = if !eff_tp.is_empty() {
        rio::read_transcript_steps(&eff_tp, 4000)
    } else {
        Vec::new()
    };
    let sub_ev = scan_native_subagents(&steps, tp_opt, eff_first_ts);
    let eff_cwd = if !git_root.is_empty() {
        git_root.to_string()
    } else {
        let gr = val_to_str(eff_marker.get("git_root"));
        if !gr.is_empty() {
            gr
        } else {
            val_to_str(eff_marker.get("cwd"))
        }
    };
    let cur_dh = val_to_str(eff_marker.get("current_diff_hash"));
    let mut swarm_ev = scan_swarm_activity_with_reset(SwarmScanInput {
        steps: &steps,
        transcript_path: tp_opt,
        first_ts: eff_first_ts,
        round_start_msg_id: eff_round_start,
        current_diff_hash: &cur_dh,
        cwd: &eff_cwd,
        research_reset_ts: rr_ts,
        research_reset_seq: rr_seq,
        marker: Some(eff_marker),
    });
    if let Some(Value::Object(mut st)) = rio::read_json(&cwg_common::enforcement_state_path(session))
    {
        if (val_to_f64(st.get("candidate_first_ts")) - first_ts_val).abs() < TS_EPS {
            merge_sticky_outage_state(&mut st, &mut swarm_ev);
        }
    }
    let mut cctx = cwg_common::resolve_candidate_context(eff_marker, false);
    let override_up = min_risk_override.trim().to_uppercase();
    let rcp_risk = if cwg_common::is_valid_risk(&override_up) {
        override_up
    } else {
        String::new()
    };

    let codex_reviews = codex_lane::scan_verified_codex_reviews(eff_first_ts, session, git_root);
    let synthetic_checks = ChecksEvidence {
        checks_count: 1,
        passed_count: 1,
        failed_count: 0,
        latest_pass_ts: f64::MAX / 2.0,
        latest_fail_ts: 0.0,
        ..Default::default()
    };
    let synthetic_rcp = json!({
        "kind": "verified",
        "risk": rcp_risk,
    });
    let mut summary = codex_lane::ClosureCycleSummary::default();
    let _ = validate_candidate_closure_inner(
        CandidateClosureInput {
            receipt: Some(&synthetic_rcp),
            marker_in: eff_marker,
            checks_ev: &synthetic_checks,
            sub_ev: &sub_ev,
            swarm_ev: &swarm_ev,
            codex_reviews: &codex_reviews,
            ctx: Some(&mut cctx),
            steps: Some(&steps),
            transcript_path: tp_opt,
        },
        Some(&mut summary),
    );
    summary
}

type PathStatMap = BTreeMap<String, Option<(u64, u128)>>;

fn snapshot_path_stats(marker: &Value) -> PathStatMap {
    let mut out = BTreeMap::new();
    for p in cwg_common::durable_paths_from_val(marker.get("paths")) {
        let stat = fs::metadata(Path::new(&p))
            .ok()
            .map(|m| (m.len(), rio::meta_mtime_ns(&m)));
        out.insert(rio::fold_path(&p), stat);
    }
    out
}

fn marker_matches_validated(
    live_merged: Option<&Value>,
    expected: &Value,
    expected_stats: Option<&PathStatMap>,
    allow_unhashed: bool,
) -> bool {
    // SAFETY: Re-verify under `marker_lock_path` that neither `marker.json`, cycle-reset metadata, nor live candidate file bytes mutated while `decide_stop` ran unlocked validation; unhashed (>32 MB) files fail closed on `verified`/`pr-ready` closure and require unchanged `(len, mtime_ns)` on `no-change`/`draft-blocked`/exhaustion/anomaly retirement.
    let Some(live) = live_merged else {
        return false;
    };
    if json_truthy(live.get("closed")) {
        return false;
    }
    let live_paths = cwg_common::durable_paths_from_val(live.get("paths"));
    let exp_paths = cwg_common::durable_paths_from_val(expected.get("paths"));
    if val_to_i64(live.get("edits")) != val_to_i64(expected.get("edits"))
        || json_truthy(live.get("operational")) != json_truthy(expected.get("operational"))
        || live_paths != exp_paths
        || (val_to_f64(live.get("last_durable_ts")) - val_to_f64(expected.get("last_durable_ts"))).abs() > TS_EPS
        || val_to_f64(live.get("last_ts")) > val_to_f64(expected.get("last_ts")) + TS_EPS
        || live.get("research_resets") != expected.get("research_resets")
        || live.get("closure_halt") != expected.get("closure_halt")
        || live.get("cycle_declared_risk") != expected.get("cycle_declared_risk")
        || val_to_i64(live.get("round_start_msg_id")) != val_to_i64(expected.get("round_start_msg_id"))
        || val_to_i64(live.get("round_id")) != val_to_i64(expected.get("round_id"))
    {
        return false;
    }
    let exp_fp = cwg_common::last_mark_fp(expected);
    if cwg_common::last_mark_fp(live) != exp_fp {
        return false;
    }
    if !live_paths.is_empty() {
        let disk_fp = cwg_common::content_fingerprint(&live_paths, cwg_common::MAX_FINGERPRINT_FILE_BYTES);
        if disk_fp.is_empty() {
            if !allow_unhashed || exp_fp.is_some() {
                return false;
            }
            let Some(exp_st) = expected_stats else {
                return false;
            };
            if &snapshot_path_stats(live) != exp_st {
                return false;
            }
        } else if Some(disk_fp.as_str()) != exp_fp.as_deref() {
            return false;
        }
    }
    true
}

struct RetireCandidateInput<'a> {
    session: &'a str,
    marker_file: &'a Path,
    state_file: &'a Path,
    state: &'a mut Map<String, Value>,
    receipt_summary: &'a str,
    expected_marker: Option<&'a Value>,
    expected_stats: Option<&'a PathStatMap>,
    consumed_pending_ids: &'a [String],
    allow_unhashed: bool,
}

fn retire_candidate_checked(input: RetireCandidateInput<'_>) -> bool {
    let RetireCandidateInput {
        session,
        marker_file,
        state_file,
        state,
        receipt_summary,
        expected_marker,
        expected_stats,
        consumed_pending_ids,
        allow_unhashed,
    } = input;
    let retired = rio::with_file_lock(&cwg_common::marker_lock_path(session), 5.0, 30.0, |locked| {
        if !locked {
            return false;
        }
        if cwg_common::has_unconsumed_pending_deltas(session, consumed_pending_ids) {
            return false;
        }
        let live_raw = rio::read_json(marker_file);
        if let Some(exp) = expected_marker {
            let (live_merged, _) =
                cwg_common::apply_pending_marker_deltas(session, live_raw.as_ref());
            if !marker_matches_validated(live_merged.as_ref(), exp, expected_stats, allow_unhashed) {
                return false;
            }
            if (receipt_summary == "no-change" || receipt_summary == "undo-clean")
                && cwg_common::last_mark_fp(exp).is_none()
                && !live_merged
                    .as_ref()
                    .map_or(false, |lm| candidate_restored_to_clean_head(lm).0)
            {
                return false;
            }
        }
        if marker_file.exists() && fs::remove_file(marker_file).is_err() {
            let mut cur = match live_raw {
                Some(Value::Object(m)) => m,
                _ => return false,
            };
            cur.insert("closed".to_string(), Value::Bool(true));
            if rio::write_json(marker_file, &Value::Object(cur)).is_err() {
                return false;
            }
        }
        cwg_common::ack_pending_marker_deltas(session, consumed_pending_ids);
        true
    });
    if !retired {
        return false;
    }
    state.insert("blocks".to_string(), json!(0));
    state.insert("waits".to_string(), json!(0));
    state.insert("total_waits".to_string(), json!(0));
    state.insert("notify_reminders".to_string(), json!(0));
    let closed_ts = now_sec();
    state.insert("closed_ts".to_string(), json!(closed_ts));
    state.insert(
        "last_receipt".to_string(),
        Value::String(receipt_summary.to_string()),
    );
    state.insert("block_nonce".to_string(), Value::String(String::new()));
    state.insert("candidate_first_ts".to_string(), json!(0.0));
    reset_sticky_issue_state(state);
    let _ = rio::write_json(state_file, &Value::Object(state.clone()));
    cwg_common::clear_claim(session);
    cwg_common::clear_swarm_rounds(session);
    true
}

fn evaluate_swarm_worker_stop(
    payload: &Value,
    session: &str,
    transcript_path: Option<&str>,
) -> Option<String> {
    // SAFETY: Block active swarm workers from ending a turn with plain assistant text and zero `post_message` after a board assignment.
    let tp = transcript_path.filter(|s| !s.is_empty())?;
    let head_steps = rio::read_transcript_head(tp, 8);
    let winfo = rio::resolve_swarm_worker_assignment(tp, Some(&head_steps), session)?;
    let board_path_str = val_to_str(winfo.get("board_path"));
    if board_path_str.is_empty() {
        return None;
    }
    let raw_board = rio::read_jsonl(Path::new(&board_path_str), Some(400));
    if raw_board.is_empty() {
        return None;
    }

    let wname = val_to_str(winfo.get("worker_name"));
    let added_by = val_to_str(winfo.get("added_by"));
    let (last_assign_seq, last_reply_seq) =
        rio::latest_board_assign_and_reply_seq(&raw_board, &wname, &added_by);
    if last_assign_seq <= 0 || last_reply_seq >= last_assign_seq {
        return None;
    }

    let w_steps = rio::read_transcript_steps(tp, 400);
    let turn = rio::inspect_worker_turn_after_wake(&w_steps, last_assign_seq);
    if val_to_i64(turn.get("max_wake_seq")) > 0 && !json_truthy(turn.get("woke_for_assign")) {
        return None;
    }
    if json_truthy(turn.get("has_error"))
        || json_truthy(turn.get("called_post"))
        || json_truthy(turn.get("pending_bg"))
    {
        return None;
    }
    if payload.get("fullyIdle").and_then(|v| v.as_bool()) == Some(false)
        && turn
            .get("last_model_tcs")
            .and_then(|v| v.as_array())
            .map_or(false, |arr| {
                arr.iter()
                    .any(|tc| tc.get("name").and_then(|n| n.as_str()) == Some("invoke_subagent"))
            })
    {
        return None;
    }

    let wsfile = cwg_common::enforcement_state_path(session);
    let mut wstate = match rio::read_json(&wsfile) {
        Some(Value::Object(m)) => m,
        _ => Map::new(),
    };
    let rem_count = if val_to_i64(wstate.get("worker_post_assign_seq")) == last_assign_seq {
        val_to_i64(wstate.get("worker_post_reminders"))
    } else {
        0
    };
    if rem_count >= MAX_WORKER_POST_REMINDERS {
        return None;
    }
    wstate.insert("worker_post_assign_seq".to_string(), json!(last_assign_seq));
    wstate.insert("worker_post_reminders".to_string(), json!(rem_count + 1));
    let _ = rio::write_json(&wsfile, &Value::Object(wstate));
    rio::log_hook_event(
        "gate-events",
        "worker_unposted_stop_block",
        json!({
            "session": session,
            "worker": wname,
            "coordinator": val_to_str(winfo.get("coordinator")),
            "assign_seq": last_assign_seq,
            "reminder": rem_count + 1,
        }),
    );
    Some(format!(
        "[Swarm Worker Stop Guard] Получено задание на доске (#{} для @{}), но ход завершается без вызова `post_message`. Обычный текст ответа не попадает на доску роя и приводит к вечному зависанию координатора в `swarm_wait`.\nВызовите `post_message(text=\"@coordinator ...\")` с вашим результатом перед завершением хода.",
        last_assign_seq, wname
    ))
}

pub fn format_block_message(
    reason: &str,
    block_num: i64,
    marker: &Value,
    session: &str,
    nonce: &str,
    ctx: Option<&Value>,
) -> String {
    let owned_ctx;
    let cctx = match ctx {
        Some(c) => c,
        None => {
            owned_ctx = cwg_common::resolve_candidate_context(marker, true);
            &owned_ctx
        }
    };
    let policy = cctx.get("policy");
    let floor = val_to_str(cctx.get("floor"));
    let cwd = val_to_str(cctx.get("cwd"));
    let git_root = val_to_str(cctx.get("git_root"));
    let dpaths: Vec<String> = cctx
        .get("dpaths")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(|x| val_to_str(Some(x))).collect())
        .unwrap_or_default();
    let has_tests = match cctx.get("require_tests").and_then(|v| v.as_bool()) {
        Some(rt) => rt,
        None => cwg_common::requires_tests(&floor, &cwd, &dpaths, policy, &git_root),
    };
    let cs_bin = rio::normalize_path(&rio::carbon_stack_bin_path().to_string_lossy());

    let guidance = if reason.contains("terminal closure cap") || reason.contains("draft-blocked") {
        let reqs = cwg_common::receipt_requirements_summary(&floor, policy, has_tests);
        format!(
            "Кандидат `PERSISTENT` (риск `{}`). Обязательные условия: {}.\n- Конечный потолок гейта (`3` раунда ревью + `2/2` прохода `--closure` с `BLOCKED`) исчерпан: новые циклы ревью запрещены.\n- Сохраните текущее состояние, опишите точный оставшийся блокер и завершите ответ терминальной квитанцией `[gate] draft-blocked: <точный блокер и handoff>`.",
            floor, reqs
        )
    } else {
        let reqs = cwg_common::receipt_requirements_summary(&floor, policy, has_tests);
        let xhigh_hint = if floor == "XHIGH" {
            " с `REVIEW_TIER: XHIGH`"
        } else {
            ""
        };
        let review_hint = if json_truthy(cctx.get("needs_review")) {
            let has_cls = reason.contains(CLOSURE_PHASE_FLAG) || reason.contains("--closure");
            let phase_flag = if has_cls {
                format!("{} ", CLOSURE_PHASE_FLAG)
            } else {
                String::new()
            };
            let xhigh_flag = if floor == "XHIGH" { "--xhigh " } else { "" };
            let cls_mode_note = if has_cls {
                " в режиме `CLOSURE_VALIDATION: READY|BLOCKED`"
            } else {
                ""
            };
            let kill_note = if has_cls {
                " (перед `--closure` пакетно завершите `waiting` воркеров через `swarm(action=\"kill\", ...)`)"
            } else {
                ""
            };
            let esc_hint = if floor == "XHIGH" {
                format!("`{}`", cwg_common::CARBON_HIGH_MODEL)
            } else {
                format!(
                    "`{}` / `{}`",
                    cwg_common::NEON_XHIGH_MODEL,
                    cwg_common::CARBON_HIGH_MODEL
                )
            };
            format!(
                "- Для независимого ревью сначала проверьте `& \"{}\" codex-lane check`; если доступно — запустите `& \"{}\" codex-lane review --session \"{}\" {}{}--summary \"...\"`{} (при недоступности Codex запустите внутреннее ревью{} на `{}`{} через `swarm`, с эскалацией на {} при ошибке/квоте Opus).\n",
                cs_bin,
                cs_bin,
                session,
                phase_flag,
                xhigh_flag,
                kill_note,
                cls_mode_note,
                cwg_common::OPUS_HIGH_MODEL,
                xhigh_hint,
                esc_hint
            )
        } else {
            String::new()
        };
        format!(
            "Кандидат `PERSISTENT` (риск `{}`). Обязательные условия: {}.\n{}- Завершите финальный ответ строкой `[gate] verified: {}; <кандидат и решающие проверки>`.",
            floor, reqs, review_hint, floor
        )
    };

    // SAFETY: Strip PowerShell metacharacters from CLI/tool hint arguments so copy-pasted `carbon-stack gate-inbox report --block "..."` commands never suffer PS escape corruption.
    let cleaned_reason = sanitize_ps_arg_re().replace_all(reason, "");
    let safe_reason_owned = cleaned_reason.trim();
    let safe_reason = if safe_reason_owned.is_empty() {
        "gate_block"
    } else {
        safe_reason_owned
    };
    let handler_sess = gate_inbox::get_handler_session();
    let bus_cli = rio::chat_bus_cli_path();
    let escape_tail = if !handler_sess.is_empty() && handler_sess != session {
        format!(
            "отправьте уведомление дежурному чату аномалий через `chat-bus` (`python -X utf8 \"{}\" send --from-chat \"{}\" --to \"{}\" --message \"[GATE_ANOMALY <id>] session={}; block={}; facts=...\"` с `BypassSandbox=true`; внутри того же проекта также допустим `send_message(Recipient=\"{}\", ...)`) и закройте ответ строкой `[gate] anomaly-reported: <id>; <факт>` (ссылка для отчёта: `[Чат аномалий](conversation://{})`).",
            bus_cli.to_string_lossy(),
            session,
            handler_sess,
            session,
            truncate_chars(safe_reason, 80),
            handler_sess,
            handler_sess
        )
    } else {
        "и закройте ответ строкой `[gate] anomaly-reported: <id>; <факт>`.".to_string()
    };

    format!(
        "[Code Work Gate] Остановка заблокирована ({}/{} для неизменённого кандидата): {}.\n{}\nЕсли блокировка противоречит проверяемым фактам транскрипта, не уходите в цикл: зафиксируйте отчёт (с `BypassSandbox=true`) `& \"{}\" gate-inbox report --session \"{}\" --nonce \"{}\" --block \"{}\" --facts \"<факты>\" --did \"<выполненные проверки>\"`, {}",
        block_num,
        MAX_BLOCKS_PER_CANDIDATE,
        reason,
        guidance,
        cs_bin,
        session,
        nonce,
        truncate_chars(safe_reason, 120),
        escape_tail
    )
}

#[cfg(test)]
static TEST_MID_DECIDE_STOP_HOOK: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>> =
    std::sync::Mutex::new(None);

pub fn decide_stop(payload: &Value) -> Option<String> {
    let term_reason = val_to_str(payload.get("terminationReason"));
    if rio::NON_ENFORCEABLE_STOP_REASONS.contains(&term_reason.as_str())
        || json_truthy(payload.get("error"))
    {
        return None;
    }

    // INVARIANT: Fast exit on NO_CHANGE sessions before touching multi-thousand-line transcript files.
    let session = rio::session_key(payload);
    let transcript_path = payload
        .get("transcriptPath")
        .or_else(|| payload.get("transcript_path"))
        .and_then(|v| v.as_str());
    if let Some(worker_msg) = evaluate_swarm_worker_stop(payload, &session, transcript_path) {
        return Some(worker_msg);
    }

    let mfile = cwg_common::marker_path(&session);
    if !mfile.is_file() && !cwg_common::has_pending_marker_deltas(&session) {
        return None;
    }
    let tp_str = transcript_path.unwrap_or("");
    let steps = rio::read_transcript_steps(tp_str, 4000);
    if rio::is_subagent_session(tp_str, Some(&steps)) {
        return None;
    }

    let (marker_opt, stop_consumed_ids, start_stats): (Option<Value>, Vec<String>, PathStatMap) =
        rio::with_file_lock(&cwg_common::marker_lock_path(&session), 5.0, 30.0, |locked| {
            let raw_marker = rio::read_json(&mfile);
            let (merged_opt, consumed_ids) =
                cwg_common::apply_pending_marker_deltas(&session, raw_marker.as_ref());
            let Some(merged) = merged_opt else {
                return (None, Vec::new(), BTreeMap::new());
            };
            if !merged.is_object() || json_truthy(merged.get("closed")) {
                return (None, Vec::new(), BTreeMap::new());
            }
            let caught = catch_up_unmeasured_changes(&merged);
            let stats = snapshot_path_stats(&caught);
            if locked && (!consumed_ids.is_empty() || Some(&caught) != raw_marker.as_ref()) {
                if rio::write_json(&mfile, &caught).is_ok() && !consumed_ids.is_empty() {
                    cwg_common::ack_pending_marker_deltas(&session, &consumed_ids);
                }
            }
            (Some(caught), consumed_ids, stats)
        });
    let mut marker = marker_opt?;
    if val_to_str(marker.get("session")).is_empty() {
        if let Some(obj) = marker.as_object_mut() {
            obj.insert("session".to_string(), Value::String(session.clone()));
        }
    }
    #[cfg(test)]
    if let Some(cb) = TEST_MID_DECIDE_STOP_HOOK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
    {
        cb();
    }

    if cwg_common::candidate_class(&marker) == cwg_common::WORK_NO_CHANGE {
        return None;
    }

    let sfile = cwg_common::enforcement_state_path(&session);
    let mut state = match rio::read_json(&sfile) {
        Some(Value::Object(m)) => m,
        _ => Map::new(),
    };

    let ckey = cwg_common::candidate_key(&marker);
    let cur_reset_epoch = cwg_common::research_reset_epoch(&marker) as i64;
    if val_to_str(state.get("candidate_key")) != ckey
        || val_to_i64(state.get("reset_epoch")) != cur_reset_epoch
    {
        state.insert("candidate_key".to_string(), Value::String(ckey));
        state.insert("reset_epoch".to_string(), json!(cur_reset_epoch));
        state.insert("blocks".to_string(), json!(0));
        state.insert("waits".to_string(), json!(0));
        state.insert("total_waits".to_string(), json!(0));
        state.insert("notify_reminders".to_string(), json!(0));
        state.insert("block_nonce".to_string(), Value::String(String::new()));
    }

    let first_ts = val_to_f64(marker.get("first_ts"));
    if (val_to_f64(state.get("candidate_first_ts")) - first_ts).abs() >= TS_EPS {
        state.insert("candidate_first_ts".to_string(), json!(first_ts));
        reset_sticky_issue_state(&mut state);
    }

    let mut try_auto_retire = |kind: &str| {
        let ok = retire_candidate_checked(RetireCandidateInput { session: &session, marker_file: &mfile, state_file: &sfile, state: &mut state, receipt_summary: kind, expected_marker: Some(&marker), expected_stats: Some(&start_stats), consumed_pending_ids: &stop_consumed_ids, allow_unhashed: true });
        if ok { rio::log_hook_event("gate-events", "close", json!({"session": session, "receipt": kind})); }
        ok
    };
    let cls = cwg_common::candidate_class(&marker);
    if cls == cwg_common::WORK_OPERATIONAL && try_auto_retire("operational") { return None; }
    let dm = val_to_str(payload.get("lastAssistantMessage"));
    let assistant_msg = if dm.is_empty() { rio::last_assistant_message(&steps) } else { dm };
    let receipt = cwg_common::parse_terminal_receipt(&assistant_msg);
    let rkind = receipt.as_ref().and_then(|r| r.get("kind")).and_then(|v| v.as_str()).unwrap_or("");
    if cls == cwg_common::WORK_PERSISTENT && !val_to_str(marker.get("opening_head")).is_empty() && (receipt.is_none() || rkind == "no-change") && candidate_restored_to_clean_head(&marker).0 && try_auto_retire("undo-clean") { return None; }
    let receipt_declared_risk = receipt
        .as_ref()
        .filter(|r| {
            let rk = val_to_str(r.get("kind"));
            rk == "verified" || rk == "pr-ready"
        })
        .map(|r| val_to_str(r.get("risk")).to_uppercase())
        .filter(|r| cwg_common::is_valid_risk(r))
        .unwrap_or_default();
    let tx_decl_risk = max_cycle_declared_receipt_risk(
        &steps,
        first_ts,
        cwg_common::last_research_reset_ts(&marker),
    );
    let cycle_receipt_risk = match (receipt_declared_risk.is_empty(), tx_decl_risk.is_empty()) {
        (true, true) => String::new(),
        (false, true) => receipt_declared_risk,
        (true, false) => tx_decl_risk,
        (false, false) => cwg_common::max_risk(&[receipt_declared_risk, tx_decl_risk]),
    };
    let mut cctx: Value;
    let mut reason: String;
    let mut concurrent_mutation = false;

    if let Some(rcp_ref) = receipt
        .as_ref()
        .filter(|r| r.get("kind").and_then(|v| v.as_str()) == Some("anomaly-reported"))
    {
        let rid = val_to_str(rcp_ref.get("report_id"));
        let active_nonce = val_to_str(state.get("block_nonce"));
        let expected_nonce = if active_nonce.is_empty() {
            None
        } else {
            Some(active_nonce.as_str())
        };
        let (ok_anom, anom_note) =
            gate_inbox::verify_anomaly_report(&rid, &session, expected_nonce);
        if ok_anom {
            let anom_summary = format!("anomaly-reported:{}", anom_note);
            if retire_candidate_checked(RetireCandidateInput {
                session: &session,
                marker_file: &mfile,
                state_file: &sfile,
                state: &mut state,
                receipt_summary: &anom_summary,
                expected_marker: Some(&marker),
                expected_stats: Some(&start_stats),
                consumed_pending_ids: &stop_consumed_ids,
                allow_unhashed: true,
            }) {
                rio::log_hook_event(
                    "gate-events",
                    "close",
                    json!({
                        "session": session,
                        "receipt": "anomaly-reported",
                        "report": anom_note,
                    }),
                );
                return None;
            }
            concurrent_mutation = true;
            reason = "Обнаружены новые параллельные правки или занятая блокировка маркера во время закрытия гейта; повторите финальную проверку на актуальном содержимом файлов.".to_string();
            cctx = cwg_common::resolve_candidate_context(&marker, true);
        } else {
            reason = anom_note;
            cctx = cwg_common::resolve_candidate_context(&marker, true);
        }
    } else {
        let rr_ts = cwg_common::last_research_reset_ts(&marker);
        let rr_seq = cwg_common::last_research_reset_board_seq(&marker);
        let eff_first_ts = first_ts.max(rr_ts);
        let eff_round_start_msg_id = val_to_i64(marker.get("round_start_msg_id")).max(rr_seq);
        let check_base_cwd = {
            let pc = rio::effective_cwd(payload);
            if !pc.is_empty() {
                pc
            } else {
                let gr = val_to_str(marker.get("git_root"));
                if !gr.is_empty() {
                    gr
                } else {
                    val_to_str(marker.get("cwd"))
                }
            }
        };
        let checks_ev =
            read_checks_evidence_with_steps_in_cwd(&session, first_ts, &steps, &check_base_cwd);
        let sub_ev = scan_native_subagents(&steps, transcript_path, eff_first_ts);
        let eff_cwd = {
            let gr = val_to_str(marker.get("git_root"));
            if !gr.is_empty() {
                gr
            } else {
                let mc = val_to_str(marker.get("cwd"));
                if !mc.is_empty() {
                    mc
                } else {
                    rio::effective_cwd(payload)
                }
            }
        };
        let cur_dh = val_to_str(marker.get("current_diff_hash"));
        let mut swarm_ev = scan_swarm_activity_with_reset(SwarmScanInput {
            steps: &steps,
            transcript_path,
            first_ts: eff_first_ts,
            round_start_msg_id: eff_round_start_msg_id,
            current_diff_hash: &cur_dh,
            cwd: &eff_cwd,
            research_reset_ts: rr_ts,
            research_reset_seq: rr_seq,
            marker: Some(&marker),
        });
        merge_sticky_outage_state(&mut state, &mut swarm_ev);
        let codex_revs = codex_lane::scan_verified_codex_reviews(
            eff_first_ts,
            &session,
            &val_to_str(marker.get("git_root")),
        );
        cctx = cwg_common::resolve_candidate_context(&marker, true);
        let (valid, val_reason) = validate_candidate_closure(CandidateClosureInput {
            receipt: receipt.as_ref(),
            marker_in: &marker,
            checks_ev: &checks_ev,
            sub_ev: &sub_ev,
            swarm_ev: &swarm_ev,
            codex_reviews: &codex_revs,
            ctx: Some(&mut cctx),
            steps: Some(&steps),
            transcript_path,
        });
        if valid {
            let rkind = receipt
                .as_ref()
                .and_then(|r| r.get("kind"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("verified");
            if retire_candidate_checked(RetireCandidateInput {
                session: &session,
                marker_file: &mfile,
                state_file: &sfile,
                state: &mut state,
                receipt_summary: rkind,
                expected_marker: Some(&marker),
                expected_stats: Some(&start_stats),
                consumed_pending_ids: &stop_consumed_ids,
                allow_unhashed: rkind != "verified" && rkind != "pr-ready",
            }) {
                rio::log_hook_event(
                    "gate-events",
                    "close",
                    json!({
                        "session": session,
                        "receipt": rkind,
                        "floor": val_to_str(cctx.get("floor")),
                    }),
                );
                return None;
            }
            concurrent_mutation = true;
            reason = "Обнаружены новые параллельные правки или занятая блокировка маркера во время закрытия гейта; повторите финальную проверку на актуальном содержимом файлов.".to_string();
        } else if !swarm_ev.stalled_workers.is_empty() {
            let stalled_desc: Vec<String> = swarm_ev
                .stalled_workers
                .iter()
                .map(|sw| {
                    format!(
                        "{} ({}s >= {}s)",
                        val_to_str(sw.get("worker")),
                        val_to_str(sw.get("idle_sec")),
                        val_to_str(sw.get("timeout_sec"))
                    )
                })
                .collect();
            reason = format!(
                "[Swarm Stall Watchdog] Зависли in-flight воркеры без новых сообщений в `board.jsonl` и активности в `.swarm/`: {}. Перезапустите или перепинайте зависшего воркера вместо ожидания.",
                stalled_desc.join(", ")
            );
        } else {
            reason = val_reason;
            let fully_idle = payload
                .get("fullyIdle")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let mut in_flight: Vec<String> = Vec::new();
            in_flight.extend(sub_ev.in_flight_subagents.iter().cloned());
            in_flight.extend(swarm_ev.in_flight_workers.iter().cloned());
            for t in &swarm_ev.pending_bg_tasks {
                in_flight.push(format!("bg:{}", t));
            }
            // SAFETY: Unkilled `waiting` swarm workers and standing passive listeners (`IsDaemon=true`, `chat-bus wait`) keep host `fullyIdle=False`; require real `in_flight` work when either is present.
            let effective_not_idle = !fully_idle
                && swarm_ev.idle_unkilled_workers.is_empty()
                && swarm_ev.passive_bg_tasks.is_empty();
            let progress_sig = format!(
                "{}:{}",
                swarm_ev.worker_activity_count.unwrap_or(0),
                sub_ev.reviews.len()
            );
            let waits = if val_to_str(state.get("last_wait_progress")) != progress_sig {
                0
            } else {
                val_to_i64(state.get("waits"))
            };
            let total_waits = val_to_i64(state.get("total_waits"));
            if (effective_not_idle || !in_flight.is_empty())
                && waits < MAX_BACKGROUND_WAITS
                && total_waits < MAX_TOTAL_BACKGROUND_WAITS
            {
                state.insert("waits".to_string(), json!(waits + 1));
                state.insert("total_waits".to_string(), json!(total_waits + 1));
                state.insert("last_wait_progress".to_string(), Value::String(progress_sig));
                let _ = rio::write_json(&sfile, &Value::Object(state));
                rio::log_hook_event(
                    "gate-events",
                    "background_wait",
                    json!({
                        "session": session,
                        "waits": waits + 1,
                        "total_waits": total_waits + 1,
                        "fully_idle": fully_idle,
                        "in_flight": in_flight,
                    }),
                );
                return None;
            }
        }
    }

    if !concurrent_mutation && !cycle_receipt_risk.is_empty() {
        cwg_common::latch_marker_declared_risk_for_marker(
            &session,
            &mut marker,
            &cycle_receipt_risk,
        );
    }

    let cls_summary = codex_lane::active_cycle_closure_summary_for_marker(
        &marker,
        &session,
        &val_to_str(cctx.get("git_root")),
        &tp_str,
    );
    // SAFETY: Promote to v2 latched closure halt ONLY from live-confirmed `BLOCKED` passes in this cycle (never re-latch a pre-existing legacy v0 halt as v2 when live passes are missing/evicted).
    if !concurrent_mutation && cls_summary.live_blocked_count >= MAX_CLOSURE_PASSES {
        cwg_common::latch_marker_closure_halt_for_marker(
            &session,
            &marker,
            cls_summary.live_blocked_count,
            cls_summary.last_blocked_ts,
            &cls_summary.blocked_ids,
        );
    }

    let blocks = val_to_i64(state.get("blocks"));
    // INVARIANT: Enforce `MAX_BLOCKS_PER_CANDIDATE` (3) unconditionally on an unchanged candidate (`claude-code-stack` finite Stop cap) so no state can trap a session in an infinite Stop loop.
    if !concurrent_mutation && blocks >= MAX_BLOCKS_PER_CANDIDATE {
        let exh_summary = format!("exhausted:{}", truncate_chars(&reason, 100));
        if retire_candidate_checked(RetireCandidateInput {
            session: &session,
            marker_file: &mfile,
            state_file: &sfile,
            state: &mut state,
            receipt_summary: &exh_summary,
            expected_marker: Some(&marker),
            expected_stats: Some(&start_stats),
            consumed_pending_ids: &stop_consumed_ids,
            allow_unhashed: true,
        }) {
            rio::log_hook_event(
                "gate-events",
                "exhausted",
                json!({
                    "session": session,
                    "reason": reason,
                }),
            );
            return None;
        }
        // SAFETY: Concurrent edit or lock contention raced with retry exhaustion; refuse to wipe the newer unvalidated candidate and block instead.
        concurrent_mutation = true;
        reason = "Обнаружены новые параллельные правки или занятая блокировка маркера во время закрытия гейта; повторите финальную проверку на актуальном содержимом файлов.".to_string();
    }

    let next_blocks = if concurrent_mutation { 1 } else { blocks + 1 };
    let nonce = generate_nonce_hex12();
    state.insert("blocks".to_string(), json!(next_blocks));
    state.insert(
        "last_block_reason".to_string(),
        Value::String(reason.clone()),
    );
    state.insert("last_block_ts".to_string(), json!(now_sec()));
    state.insert("block_nonce".to_string(), Value::String(nonce.clone()));
    let _ = rio::write_json(&sfile, &Value::Object(state));
    rio::log_hook_event(
        "gate-events",
        "block",
        json!({
            "session": session,
            "block": next_blocks,
            "reason": reason,
            "floor": val_to_str(cctx.get("floor")),
        }),
    );
    Some(format_block_message(
        &reason,
        blocks + 1,
        &marker,
        &session,
        &nonce,
        Some(&cctx),
    ))
}

pub fn run_cli(args: &[String]) -> i32 {
    let _event = rio::parse_event_arg(args, "Stop");
    let payload = match rio::read_hook_stdin() {
        Ok(val) => val,
        Err(err) => {
            rio::log_hook_event(
                "hook-errors",
                "stdin_error",
                json!({
                    "hook": "cwg_stop",
                    "error": err,
                }),
            );
            rio::emit_stop_allow();
            return 0;
        }
    };
    match decide_stop(&payload) {
        Some(reason) => rio::emit_stop_continue(&reason),
        None => rio::emit_stop_allow(),
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::win32_sqlite::TEST_ENV_LOCK;
    use std::env;

    struct TempEnvDir {
        path: PathBuf,
        prev_home: Option<String>,
        prev_brain: Option<String>,
        prev_codex_bin: Option<String>,
    }

    impl TempEnvDir {
        fn new(name: &str) -> Self {
            let p = env::temp_dir().join(format!(
                "cwg-stop-test-{}-{}-{}",
                name,
                std::process::id(),
                NONCE_SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::create_dir_all(&p);
            let fake_codex = p.join("fake_codex.cmd");
            let _ = fs::write(&fake_codex, "@echo off\r\n");
            let prev_home = env::var("CARBON_STACK_HOME").ok();
            let prev_brain = env::var("ANTIGRAVITY_BRAIN_ROOT").ok();
            let prev_codex_bin = env::var("CARBON_CODEX_BIN").ok();
            env::set_var("CARBON_STACK_HOME", p.join("stack"));
            env::set_var("ANTIGRAVITY_BRAIN_ROOT", p.join("brain"));
            env::set_var("CARBON_CODEX_BIN", &fake_codex);
            Self {
                path: p,
                prev_home,
                prev_brain,
                prev_codex_bin,
            }
        }
    }

    impl Drop for TempEnvDir {
        fn drop(&mut self) {
            if let Some(ref v) = self.prev_home {
                env::set_var("CARBON_STACK_HOME", v);
            } else {
                env::remove_var("CARBON_STACK_HOME");
            }
            if let Some(ref v) = self.prev_brain {
                env::set_var("ANTIGRAVITY_BRAIN_ROOT", v);
            } else {
                env::remove_var("ANTIGRAVITY_BRAIN_ROOT");
            }
            if let Some(ref v) = self.prev_codex_bin {
                env::set_var("CARBON_CODEX_BIN", v);
            } else {
                env::remove_var("CARBON_CODEX_BIN");
            }
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn test_all_regexes_compile() {
        assert!(subagent_uri_re().is_match(
            r#"{"conversationId": "abc12345", "logAbsoluteUri": "file:///C:/logs/transcript.jsonl"}"#
        ));
        assert!(subagent_msg_re().is_match(
            "[Message] timestamp=2026-11-17T00:00:00Z sender=coord_1 priority=HIGH content=hello"
        ));
        assert!(sys_msg_close_re().is_match("hello\n</SYSTEM_MESSAGE>\n"));
        assert!(system_swarm_err_re().is_match(
            r#"[Message] timestamp=2026-11-17T00:00:00Z sender=system content=Swarm Worker (simp-reuse) with id "cid-123" encountered an error: out of quota"#
        ));
        assert!(model_failure_re().is_match("Error: out of quota"));
        assert!(model_failure_re().is_match("insufficient quota"));
        assert!(model_failure_re().is_match("quota depleted"));
        assert!(model_failure_re().is_match("RESOURCE_EXHAUSTED: 429"));
        assert!(trailing_digits_suffix_re().is_match("worker-12"));
        assert!(sanitize_ps_arg_re().is_match("`\"$\r\n"));
        assert!(chat_bus_wait_re().is_match("chat-bus.exe wait --chat s1"));
    }

    #[test]
    fn test_merge_sticky_outage_state() {
        let mut state = Map::new();
        state.insert("opus_issue_verified".to_string(), Value::Bool(true));
        state.insert("opus_issue_ts".to_string(), json!(100.0));

        let mut swarm_ev = SwarmEvidence {
            sonnet_issue_verified: true,
            opus_issue_verified: true,
            opus_issue_ts: 250.0,
            ..SwarmEvidence::default()
        };

        merge_sticky_outage_state(&mut state, &mut swarm_ev);
        assert_eq!(state.get("sonnet_issue_verified"), Some(&Value::Bool(true)));
        assert!(swarm_ev.sonnet_issue_verified);
        assert_eq!(state.get("opus_issue_verified"), Some(&Value::Bool(true)));
        assert!(swarm_ev.opus_issue_verified);
        assert_eq!(val_to_f64(state.get("opus_issue_ts")), 100.0);
        assert_eq!(swarm_ev.opus_issue_ts, 100.0);

        let mut state2 = Map::new();
        let mut swarm_ev2 = SwarmEvidence {
            opus_issue_verified: true,
            opus_issue_ts: 420.0,
            ..SwarmEvidence::default()
        };
        merge_sticky_outage_state(&mut state2, &mut swarm_ev2);
        assert_eq!(val_to_f64(state2.get("opus_issue_ts")), 420.0);
        assert_eq!(swarm_ev2.opus_issue_ts, 420.0);
    }

    #[test]
    fn test_scan_swarm_activity_out_of_quota_and_tail_recovery() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempEnvDir::new("quota");
        let conv_id = "conv-quota-1";
        let logs_dir = tmp.path.join("brain").join(conv_id).join(".system_generated").join("logs");
        fs::create_dir_all(&logs_dir).unwrap();
        let compact_tp = logs_dir.join("transcript.jsonl");
        let full_tp = logs_dir.join("transcript_full.jsonl");

        // INVARIANT: Evicted step 1 in compact transcript reports Sonnet out-of-quota error.
        let compact_lines = [
            json!({
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "created_at": "2026-11-17T10:00:00Z"
            }),
            json!({
                "step_index": 1,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2026-11-17T10:00:10Z",
                "tool_calls": [{
                    "name": "swarm",
                    "args": {
                        "action": "\"add\"",
                        "name": "\"simp-reuse\"",
                        "model": "\"claude-sonnet-5-5-high\""
                    }
                }]
            }),
            json!({
                "step_index": 2,
                "source": "GENERIC",
                "type": "GENERIC",
                "status": "ERROR",
                "created_at": "2026-11-17T10:00:11Z",
                "content": "",
                "error": "out of quota for claude-sonnet-5-5-high"
            }),
        ];
        let compact_body: String = compact_lines
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        fs::write(&compact_tp, compact_body).unwrap();
        fs::write(&full_tp, "").unwrap();

        // INVARIANT: Tail slice starts at step_index 5 (missing steps 1..4) and also records Opus SYSTEM error.
        let tail_steps = vec![
            json!({
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "created_at": "2026-11-17T10:00:00Z"
            }),
            json!({
                "step_index": 5,
                "source": "SYSTEM",
                "type": "SYSTEM_MESSAGE",
                "created_at": "2026-11-17T10:01:00Z",
                "content": "[Message] timestamp=2026-11-17T10:01:00Z sender=system content=Swarm Worker (reviewer-opus) with id \"wcid-1\" encountered an error: insufficient quota"
            }),
        ];

        // INVARIANT: Create members.json so worker error resolves against Opus model.
        let swarm_dir = rio::swarm_dir(&tmp.path.join("brain"), conv_id);
        fs::create_dir_all(&swarm_dir).unwrap();
        fs::write(
            swarm_dir.join("members.json"),
            serde_json::to_string(&json!({
                "members": {
                    "reviewer-opus": {
                        "conversation_id": "wcid-1",
                        "model": cwg_common::OPUS_HIGH_MODEL
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let first_ts = rio::parse_iso_ts("2026-11-17T09:59:55Z");
        let ev = scan_swarm_activity(
            &tail_steps,
            Some(&full_tp.to_string_lossy()),
            first_ts,
            0,
            "",
            "",
        );
        assert!(ev.sonnet_issue_verified);
        assert!(ev.opus_issue_verified);
        assert!(ev.opus_issue_ts > 0.0);
        assert_eq!(ev.review_failures.len(), 1);
    }

    #[test]
    fn test_validate_candidate_closure_high_flow() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempEnvDir::new("closure");
        let auth_file = tmp.path.join("src").join("auth.rs");
        fs::create_dir_all(auth_file.parent().unwrap()).unwrap();
        fs::write(&auth_file, "pub fn ok() -> bool { true }\n").unwrap();
        let fp = cwg_common::content_fingerprint(&[auth_file.to_string_lossy().into_owned()], 4_000_000);

        let marker = json!({
            "cwd": tmp.path.to_string_lossy(),
            "paths": [auth_file.to_string_lossy()],
            "first_ts": 100.0,
            "last_durable_ts": 110.0,
            "content_marks": [
                { "ts": 110.0, "fp": fp }
            ]
        });
        let checks_ev = ChecksEvidence {
            checks_count: 1,
            passed_count: 1,
            failed_count: 0,
            latest_pass_ts: 115.0,
            latest_fail_ts: 0.0,
            ..Default::default()
        };
        let sub_ev = SubagentEvidence::default();

        // INVARIANT: Missing independent review must reject HIGH closure.
        let swarm_empty = SwarmEvidence::default();
        let receipt_ok = cwg_common::parse_terminal_receipt("[gate] verified: HIGH; all checks passed").unwrap();
        let (ok0, reason0) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt_ok),
            marker_in: &marker,
            checks_ev: &checks_ev,
            sub_ev: &sub_ev,
            swarm_ev: &swarm_empty,
            codex_reviews: &[],
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(!ok0);
        assert!(
            reason0.contains("VERDICT: APPROVED"),
            "got: {}",
            reason0
        );

        // INVARIANT: Under the finite `claude-code-stack` gate on `HIGH`, a single fresh `ordinary` `VERDICT: APPROVED` IMMEDIATELY closes `verified` without `--closure` or simplify, whereas extra post-`APPROVED` review rounds are rejected.
        let single_ord_approved = vec![json!({
            "engine": "codex",
            "kind": "ordinary",
            "verdict": "APPROVED",
            "launch_ts": 118.0,
            "verdict_ts": 120.0,
            "xhigh": false,
        })];
        let (ok1, res1) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt_ok),
            marker_in: &marker,
            checks_ev: &checks_ev,
            sub_ev: &sub_ev,
            swarm_ev: &swarm_empty,
            codex_reviews: &single_ord_approved,
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(ok1, "expected immediate finite closure on APPROVED, got: {}", res1);
        assert_eq!(res1, "verified");

        let extra_post_approved = vec![
            json!({
                "engine": "codex",
                "kind": "ordinary",
                "verdict": "APPROVED",
                "launch_ts": 118.0,
                "verdict_ts": 120.0,
                "xhigh": false,
            }),
            json!({
                "engine": "codex",
                "kind": "ordinary",
                "verdict": "APPROVED",
                "launch_ts": 130.0,
                "verdict_ts": 135.0,
                "xhigh": false,
            }),
        ];
        let (ok_dup_app, res_dup_app) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt_ok),
            marker_in: &marker,
            checks_ev: &checks_ev,
            sub_ev: &sub_ev,
            swarm_ev: &swarm_empty,
            codex_reviews: &extra_post_approved,
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(!ok_dup_app, "redundant review after APPROVED must be rejected");
        assert!(
            res_dup_app.contains("unnecessarily") || res_dup_app.contains("after terminal"),
            "got: {}",
            res_dup_app
        );

        let marker_post_sim_edit = json!({
            "cwd": tmp.path.to_string_lossy(),
            "paths": [auth_file.to_string_lossy()],
            "first_ts": 100.0,
            "last_durable_ts": 122.0,
            "content_marks": [
                { "ts": 110.0, "fp": "stale_pre_simplify_fp" },
                { "ts": 122.0, "fp": fp }
            ]
        });
        let checks_post_sim_edit = ChecksEvidence {
            checks_count: 2,
            passed_count: 2,
            failed_count: 0,
            latest_pass_ts: 123.0,
            latest_fail_ts: 0.0,
            ..Default::default()
        };
        let revise_then_approved = vec![
            json!({
                "engine": "codex",
                "kind": "ordinary",
                "verdict": "REVISE",
                "launch_ts": 118.0,
                "verdict_ts": 120.0,
                "xhigh": false,
            }),
            json!({
                "engine": "codex",
                "kind": "ordinary",
                "verdict": "APPROVED",
                "launch_ts": 125.0,
                "verdict_ts": 128.0,
                "xhigh": false,
            }),
        ];
        let (ok1_edit, res1_edit) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt_ok),
            marker_in: &marker_post_sim_edit,
            checks_ev: &checks_post_sim_edit,
            sub_ev: &sub_ev,
            swarm_ev: &swarm_empty,
            codex_reviews: &revise_then_approved,
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(
            ok1_edit,
            "expected post-REVISE edit + tests + Round-2 APPROVED to close without re-running simplify, got: {}",
            res1_edit
        );
        let (ok1_stale_app, res1_stale_app) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt_ok),
            marker_in: &marker_post_sim_edit,
            checks_ev: &checks_post_sim_edit,
            sub_ev: &sub_ev,
            swarm_ev: &swarm_empty,
            codex_reviews: &single_ord_approved,
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(!ok1_stale_app, "stale pre-edit APPROVED must still be rejected");
        assert!(res1_stale_app.contains("stale"), "got: {}", res1_stale_app);

        // INVARIANT: Codex thinking timeout followed by internal Opus must be rejected.
        let mut swarm_timeout = swarm_empty.clone();
        swarm_timeout.codex_timeout_seen = true;
        swarm_timeout.reviews.push(json!({
            "engine": "internal-opus",
            "kind": "ordinary",
            "verdict": "APPROVED",
            "launch_ts": 130.0,
            "verdict_ts": 135.0,
            "xhigh": false,
        }));
        let (ok2, reason2) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt_ok),
            marker_in: &marker,
            checks_ev: &checks_ev,
            sub_ev: &sub_ev,
            swarm_ev: &swarm_timeout,
            codex_reviews: &[],
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(!ok2);
        assert!(reason2.contains("thinking timeout is NOT an outage"));

        // INVARIANT: Standing `chat-bus.exe wait` background listener is passive (`passive_bg_tasks`) and never creates an infinite `edit_span`.
        let wait_steps = vec![
            json!({
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "1970-01-01T00:01:45Z",
                "tool_calls": [{
                    "name": "run_command",
                    "args": {
                        "CommandLine": r"$null | C:\Users\in\.gemini\config\plugins\chat-bus\bin\chat-bus.exe wait --chat sess-1"
                    }
                }]
            }),
            json!({
                "source": "GENERIC",
                "type": "GENERIC",
                "status": "DONE",
                "created_at": "1970-01-01T00:01:46Z",
                "content": "Tool is running as a background task with task id: sess-1/task-99"
            }),
        ];
        let tx_ev = extract_transcript_edit_evidence(&wait_steps, &marker);
        assert!(tx_ev.edit_spans.is_empty());
        let sw_wait = scan_swarm_activity(&wait_steps, None, 100.0, 0, "", "");
        assert!(sw_wait.pending_bg_tasks.is_empty());
        assert_eq!(sw_wait.passive_bg_tasks, vec!["sess-1/task-99".to_string()]);
    }

    #[test]
    fn test_sandwich_closure_premature_recovery_two_block_halt_and_post_reset_workers() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempEnvDir::new("sandwich-stop");
        let ws = tmp.path.join("ws");
        let brain = tmp.path.join("brain");
        fs::create_dir_all(&ws).unwrap();
        fs::create_dir_all(&brain).unwrap();

        let auth_rs = ws.join("auth_guard.rs");
        fs::write(&auth_rs, "pub fn ok() -> bool { true }\n").unwrap();
        let t0 = 1000.0_f64;
        let sess = "sess-sandwich-rust";
        let marker = json!({
            "session": sess,
            "class": cwg_common::WORK_PERSISTENT,
            "first_ts": t0,
            "last_durable_ts": t0,
            "cwd": rio::normalize_path(&ws.to_string_lossy()),
            "git_root": "",
            "paths": [rio::normalize_path(&auth_rs.to_string_lossy())],
            "changed_lines": 1,
            "shell_durable_edit": false,
            "content_marks": [{"ts": t0, "fp": "aa11bb22cc33dd44", "unknown": false}],
            "closed": false,
        });
        let receipt = json!({"kind": "verified", "risk": "HIGH"});
        let checks_ev = ChecksEvidence {
            checks_count: 1,
            passed_count: 1,
            failed_count: 0,
            latest_pass_ts: t0 + 0.2,
            latest_fail_ts: 0.0,
            ..Default::default()
        };
        let sub_ev = SubagentEvidence::default();

        let sw_pass1 = SwarmEvidence::default();

        let ord_e1 = json!({"review_id": "cwg-o1", "engine": "codex", "kind": "ordinary", "verdict": "REVISE", "launch_ts": t0 + 0.1, "verdict_ts": t0 + 0.2, "xhigh": false});
        let ord_e2 = json!({"review_id": "cwg-o2", "engine": "codex", "kind": "ordinary", "verdict": "REVISE", "launch_ts": t0 + 0.3, "verdict_ts": t0 + 0.4, "xhigh": false});
        let ord_e3 = json!({"review_id": "cwg-o3", "engine": "codex", "kind": "ordinary", "verdict": "REVISE", "launch_ts": t0 + 0.5, "verdict_ts": t0 + 0.6, "xhigh": false});
        let ord_e4 = json!({"review_id": "cwg-o4", "engine": "codex", "kind": "ordinary", "verdict": "ESCALATE", "launch_ts": t0 + 0.7, "verdict_ts": t0 + 0.8, "xhigh": false});
        let cls_b1 = json!({"review_id": "cwg-b1", "engine": "codex", "kind": "closure", "verdict": "BLOCKED", "launch_ts": t0 + 1.5, "verdict_ts": t0 + 1.7, "xhigh": false});
        let cls_pass2_rdy = json!({"review_id": "cwg-r-p2", "engine": "codex", "kind": "closure", "verdict": "READY", "launch_ts": t0 + 2.0, "verdict_ts": t0 + 2.2, "xhigh": false});

        // INVARIANT: Under the finite gate, `--closure` requires Round-4 `ESCALATE` (4x `REVISE` is rejected) AND verified post-`ESCALATE` research in transcript before `--closure`, after which Pass 2 `CLOSURE_VALIDATION: READY` closes directly WITHOUT requiring an inter-pass `simplify` loop.
        let ord_e4_revise = json!({"review_id": "cwg-o4-rev", "engine": "codex", "kind": "ordinary", "verdict": "REVISE", "launch_ts": t0 + 0.7, "verdict_ts": t0 + 0.8, "xhigh": false});
        let esc_res_steps = vec![
            json!({
                "step_index": 1,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "status": "DONE",
                "created_at": crate::win32_sqlite::format_iso_utc(t0 + 1.3),
                "tool_calls": [{"name": "search_web", "args": {"query": "finite gate escalation remediation"}}]
            }),
            json!({
                "step_index": 2,
                "source": "SYSTEM",
                "type": "GENERIC",
                "status": "DONE",
                "created_at": crate::win32_sqlite::format_iso_utc(t0 + 1.35),
                "content": "ok"
            }),
        ];
        let rec_revs_4revise = [
            ord_e1.clone(),
            ord_e2.clone(),
            ord_e3.clone(),
            ord_e4_revise,
            cls_b1.clone(),
            cls_pass2_rdy.clone(),
        ];
        let (ok_4rev, why_4rev) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt),
            marker_in: &marker,
            checks_ev: &checks_ev,
            sub_ev: &sub_ev,
            swarm_ev: &sw_pass1,
            codex_reviews: &rec_revs_4revise,
            ctx: None,
            steps: Some(&esc_res_steps),
            transcript_path: None,
        });
        assert!(!ok_4rev, "4x REVISE without Round-4 ESCALATE must reject closure READY: {}", why_4rev);

        let rec_revs = [
            ord_e1.clone(),
            ord_e2.clone(),
            ord_e3.clone(),
            ord_e4.clone(),
            cls_b1.clone(),
            cls_pass2_rdy,
        ];
        let (ok_no_res, why_no_res) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt),
            marker_in: &marker,
            checks_ev: &checks_ev,
            sub_ev: &sub_ev,
            swarm_ev: &sw_pass1,
            codex_reviews: &rec_revs,
            ctx: None,
            steps: Some(&[]),
            transcript_path: None,
        });
        assert!(!ok_no_res, "Round-4 ESCALATE without post-escalation research must reject closure READY: {}", why_no_res);
        assert!(why_no_res.contains("post-ESCALATE"), "got: {}", why_no_res);

        let (ok_rec, why_rec) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt),
            marker_in: &marker,
            checks_ev: &checks_ev,
            sub_ev: &sub_ev,
            swarm_ev: &sw_pass1,
            codex_reviews: &rec_revs,
            ctx: None,
            steps: Some(&esc_res_steps),
            transcript_path: None,
        });
        assert!(ok_rec, "expected Pass 2 READY with post-ESCALATE research to close cleanly without inter-pass simplify, got: {}", why_rec);

        // INVARIANT: 2 `BLOCKED` closure verdicts strictly halt `verified` with terminal `[gate] draft-blocked` guidance, allow `[gate] draft-blocked` closure, and reject any forged 3rd `READY` pass (`MAX_CLOSURE_PASSES=2`).
        let cls_b2 = json!({"review_id": "cwg-b2", "engine": "codex", "kind": "closure", "verdict": "BLOCKED", "launch_ts": t0 + 3.5, "verdict_ts": t0 + 3.7, "xhigh": false});
        let blk2_revs = [
            ord_e1.clone(),
            ord_e2.clone(),
            ord_e3.clone(),
            ord_e4.clone(),
            cls_b1.clone(),
            cls_b2.clone(),
        ];
        let (ok_2blk, why_2blk) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt),
            marker_in: &marker,
            checks_ev: &checks_ev,
            sub_ev: &sub_ev,
            swarm_ev: &sw_pass1,
            codex_reviews: &blk2_revs,
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(!ok_2blk);
        assert!(
            why_2blk.contains("2/2 `BLOCKED`") && why_2blk.contains("draft-blocked"),
            "got: {}",
            why_2blk
        );

        let draft_receipt = cwg_common::parse_terminal_receipt(
            "[gate] draft-blocked: unresolved architectural tradeoff after 2/2 closure passes",
        )
        .unwrap();
        let (ok_draft, why_draft) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&draft_receipt),
            marker_in: &marker,
            checks_ev: &checks_ev,
            sub_ev: &sub_ev,
            swarm_ev: &sw_pass1,
            codex_reviews: &blk2_revs,
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(ok_draft, "expected terminal draft-blocked to pass after 2/2 BLOCKED, got: {}", why_draft);
        assert_eq!(why_draft, "draft-blocked");

        let cls_forged3 = json!({"review_id": "cwg-r3", "engine": "codex", "kind": "closure", "verdict": "READY", "launch_ts": t0 + 4.5, "verdict_ts": t0 + 4.7, "xhigh": false});
        let forged3_revs = [ord_e1, ord_e2, ord_e3, ord_e4, cls_b1, cls_b2, cls_forged3];
        let (ok_3rd, why_3rd) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt),
            marker_in: &marker,
            checks_ev: &checks_ev,
            sub_ev: &sub_ev,
            swarm_ev: &sw_pass1,
            codex_reviews: &forged3_revs,
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(!ok_3rd);
        assert!(why_3rd.contains("MAX_CLOSURE_PASSES=2"), "got: {}", why_3rd);

        // INVARIANT: Post-research-reset worker reusing standard name `adversarial-reviewer` with new `conversation_id` is counted without inheriting Cycle-1 board messages.
        let sdir = brain.join(sess).join(".system_generated").join("swarm");
        let ldir = brain.join(sess).join(".system_generated").join("logs");
        fs::create_dir_all(&sdir).unwrap();
        fs::create_dir_all(&ldir).unwrap();
        let tp_fake = ldir.join("transcript.jsonl");
        fs::write(&tp_fake, "").unwrap();
        let rr_marker = json!({
            "session": sess,
            "research_resets": [{
                "reset_ts": 2000.0,
                "last_blocked_ts": 1990.0,
                "board_head_seq": 5,
                "pre_reset_worker_cids": ["cid-old-cycle1"],
                "decision": "refactor",
                "findings": "docs",
                "research_tools": ["search_web"]
            }]
        });
        fs::write(
            sdir.join("members.json"),
            json!({
                "members": {
                    "adversarial-reviewer": {
                        "conversation_id": "cid-new-cycle2",
                        "model": cwg_common::OPUS_HIGH_MODEL,
                        "role": "worker",
                        "killed": true,
                        "created_at": "1970-01-01T00:33:25Z"
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
        let board_rows = [
            json!({"seq": 1, "agent": "coordinator", "time": "1970-01-01T00:20:00Z", "text": "@adversarial-reviewer old cycle"}),
            json!({"seq": 6, "agent": "coordinator", "time": "1970-01-01T00:33:26Z", "text": "@adversarial-reviewer review h2"}),
            json!({"seq": 7, "agent": "adversarial-reviewer", "time": "1970-01-01T00:33:30Z", "text": "VERDICT: APPROVED"}),
        ];
        fs::write(
            sdir.join("board.jsonl"),
            board_rows.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        let tp_fake_str = tp_fake.to_string_lossy().into_owned();
        let ws_str = ws.to_string_lossy().into_owned();
        let scanned_new = scan_swarm_activity_with_reset(SwarmScanInput {
            steps: &[],
            transcript_path: Some(&tp_fake_str),
            first_ts: 2000.0,
            round_start_msg_id: 5,
            current_diff_hash: "h2",
            cwd: &ws_str,
            research_reset_ts: 2000.0,
            research_reset_seq: 5,
            marker: Some(&rr_marker),
        });
        assert_eq!(scanned_new.reviews.len(), 1);
        assert!(val_to_f64(scanned_new.reviews[0].get("launch_ts")) > 2000.0);

        // SAFETY: `retire_candidate_checked` refuses to close/delete `marker.json` if a concurrent `PostToolUse` persisted a newer edit into `marker.json` after Stop's initial snapshot.
        let sess_conc = "sess-retire-toctou";
        let mfile_conc = cwg_common::marker_path(sess_conc);
        let sfile_conc = cwg_common::enforcement_state_path(sess_conc);
        let mut st_conc = Map::new();
        let auth_norm = rio::normalize_path(&auth_rs.to_string_lossy());
        let auth_fp = cwg_common::content_fingerprint(
            std::slice::from_ref(&auth_norm),
            cwg_common::MAX_FINGERPRINT_FILE_BYTES,
        );
        let snap_v1 = json!({
            "session": sess_conc,
            "first_ts": 100.0,
            "last_ts": 100.0,
            "last_durable_ts": 100.0,
            "edits": 1,
            "operational": false,
            "paths": [auth_norm],
            "content_marks": [{"ts": 100.0, "fp": auth_fp}],
            "closed": false,
        });
        let persisted_v2 = json!({
            "session": sess_conc,
            "first_ts": 100.0,
            "last_ts": 105.0,
            "last_durable_ts": 105.0,
            "edits": 2,
            "operational": false,
            "paths": [auth_norm],
            "content_marks": [{"ts": 105.0, "fp": auth_fp}],
            "closed": false,
        });
        rio::write_json(&mfile_conc, &persisted_v2).unwrap();
        assert!(!retire_candidate_checked(RetireCandidateInput {
            session: sess_conc,
            marker_file: &mfile_conc,
            state_file: &sfile_conc,
            state: &mut st_conc,
            receipt_summary: "verified",
            expected_marker: Some(&snap_v1),
            expected_stats: None,
            consumed_pending_ids: &[],
            allow_unhashed: false,
        }));
        assert!(mfile_conc.is_file());
        assert!(retire_candidate_checked(RetireCandidateInput {
            session: sess_conc,
            marker_file: &mfile_conc,
            state_file: &sfile_conc,
            state: &mut st_conc,
            receipt_summary: "verified",
            expected_marker: Some(&persisted_v2),
            expected_stats: None,
            consumed_pending_ids: &[],
            allow_unhashed: false,
        }));
        assert!(!mfile_conc.exists());

        // SAFETY: `decide_stop` at `blocks == MAX_BLOCKS_PER_CANDIDATE` never force-retires an unvalidated concurrent file mutation on either the `valid` or `invalid` path.
        let sess_exh = "sess-decide-stop-exhaust-race";
        let notes_md = ws.join("notes.md");
        fs::write(&notes_md, "# v1\n").unwrap();
        let notes_norm = rio::normalize_path(&notes_md.to_string_lossy());
        let notes_fp_v1 = cwg_common::content_fingerprint(
            std::slice::from_ref(&notes_norm),
            cwg_common::MAX_FINGERPRINT_FILE_BYTES,
        );
        let exh_marker = json!({
            "session": sess_exh,
            "first_ts": 200.0,
            "last_ts": 200.0,
            "last_durable_ts": 200.0,
            "edits": 1,
            "operational": false,
            "paths": [notes_norm],
            "content_marks": [{"ts": 200.0, "fp": notes_fp_v1}],
            "closed": false,
        });
        let mfile_exh = cwg_common::marker_path(sess_exh);
        let sfile_exh = cwg_common::enforcement_state_path(sess_exh);
        rio::write_json(&mfile_exh, &exh_marker).unwrap();
        rio::write_json(
            &sfile_exh,
            &json!({
                "candidate_key": cwg_common::candidate_key(&exh_marker),
                "candidate_first_ts": 200.0,
                "blocks": MAX_BLOCKS_PER_CANDIDATE,
            }),
        )
        .unwrap();
        let notes_for_hook1 = notes_md.clone();
        *TEST_MID_DECIDE_STOP_HOOK.lock().unwrap() = Some(Box::new(move || {
            fs::write(&notes_for_hook1, "# v2 concurrent edit\n").unwrap();
        }));

        let blk_valid_race = decide_stop(&json!({
            "conversationId": sess_exh,
            "lastAssistantMessage": "[gate] verified: LOW; checked v1",
        }));
        assert!(blk_valid_race.is_some());
        assert!(mfile_exh.is_file());
        assert_eq!(
            rio::read_json(&sfile_exh)
                .and_then(|v| v.get("blocks").and_then(|b| b.as_i64())),
            Some(1)
        );

        fs::write(&notes_md, "# v1\n").unwrap();
        rio::write_json(&mfile_exh, &exh_marker).unwrap();
        rio::write_json(
            &sfile_exh,
            &json!({
                "candidate_key": cwg_common::candidate_key(&exh_marker),
                "candidate_first_ts": 200.0,
                "blocks": MAX_BLOCKS_PER_CANDIDATE,
            }),
        )
        .unwrap();
        let notes_for_hook2 = notes_md.clone();
        *TEST_MID_DECIDE_STOP_HOOK.lock().unwrap() = Some(Box::new(move || {
            fs::write(&notes_for_hook2, "# v3 concurrent edit during exhaustion\n").unwrap();
        }));
        let blk_invalid_race = decide_stop(&json!({
            "conversationId": sess_exh,
            "lastAssistantMessage": "missing receipt",
        }));
        assert!(blk_invalid_race.is_some());
        assert!(mfile_exh.is_file());
        assert_eq!(
            rio::read_json(&sfile_exh)
                .and_then(|v| v.get("blocks").and_then(|b| b.as_i64())),
            Some(1)
        );

        // SAFETY: Concurrent `research-reset` (`research_resets` + `round_start_msg_id` updated without file edits) also prevents `decide_stop` exhaustion from deleting the marker.
        fs::write(&notes_md, "# v1\n").unwrap();
        rio::write_json(&mfile_exh, &exh_marker).unwrap();
        rio::write_json(
            &sfile_exh,
            &json!({
                "candidate_key": cwg_common::candidate_key(&exh_marker),
                "candidate_first_ts": 200.0,
                "blocks": MAX_BLOCKS_PER_CANDIDATE,
            }),
        )
        .unwrap();
        let mfile_for_rr = mfile_exh.clone();
        *TEST_MID_DECIDE_STOP_HOOK.lock().unwrap() = Some(Box::new(move || {
            let mut m = rio::read_json(&mfile_for_rr).unwrap();
            m["research_resets"] = json!([{"reset_ts": 205.0, "board_head_seq": 12, "decision": "refine"}]);
            m["round_start_msg_id"] = json!(12);
            rio::write_json(&mfile_for_rr, &m).unwrap();
        }));
        let blk_rr_race = decide_stop(&json!({
            "conversationId": sess_exh,
            "lastAssistantMessage": "missing receipt",
        }));
        assert!(blk_rr_race.is_some());
        assert!(mfile_exh.is_file());
        assert_eq!(
            rio::read_json(&mfile_exh)
                .and_then(|v| v.get("round_start_msg_id").and_then(|x| x.as_i64())),
            Some(12)
        );

        // SAFETY: Files exceeding `MAX_FINGERPRINT_FILE_BYTES` (32 MB) yield `""` (`fp: null`) so `is_review_fresh` and `verified` closure fail closed (even on middle-byte edits with preserved size/mtime), while `decide_stop` retry exhaustion retires finitely when `(len, mtime_ns)` did not mutate mid-Stop.
        let big_bin = ws.join("oversized.md");
        {
            let mut bf = fs::File::create(&big_bin).unwrap();
            std::io::Write::write_all(&mut bf, b"# oversized v1\n").unwrap();
            bf.set_len(cwg_common::MAX_FINGERPRINT_FILE_BYTES + 4096).unwrap();
        }
        let big_norm = rio::normalize_path(&big_bin.to_string_lossy());
        let big_fp_v1 = cwg_common::content_fingerprint(
            std::slice::from_ref(&big_norm),
            cwg_common::MAX_FINGERPRINT_FILE_BYTES,
        );
        assert!(big_fp_v1.is_empty());
        let sess_big = "sess-oversized-fp";
        let mfile_big = cwg_common::marker_path(sess_big);
        let sfile_big = cwg_common::enforcement_state_path(sess_big);
        let big_marker = json!({
            "session": sess_big,
            "first_ts": 300.0,
            "last_ts": 300.0,
            "last_durable_ts": 300.0,
            "edits": 1,
            "operational": false,
            "paths": [big_norm],
            "content_marks": [{"ts": 300.0, "fp": Value::Null}],
            "closed": false,
        });
        assert!(!is_review_fresh(&json!({"launch_ts": 305.0}), &big_marker));
        let big_stats = snapshot_path_stats(&big_marker);
        assert!(!marker_matches_validated(Some(&big_marker), &big_marker, Some(&big_stats), false));
        assert!(marker_matches_validated(Some(&big_marker), &big_marker, Some(&big_stats), true));
        rio::write_json(&mfile_big, &big_marker).unwrap();
        for expected_blk in 1..=MAX_BLOCKS_PER_CANDIDATE {
            let blk_msg = decide_stop(&json!({
                "conversationId": sess_big,
                "lastAssistantMessage": "[gate] verified: LOW; checked oversized",
            }));
            assert!(
                blk_msg.as_deref().map_or(false, |m| m.contains(">32 MB")),
                "expected >32 MB validation rejection, got: {:?}",
                blk_msg
            );
            assert_eq!(
                rio::read_json(&sfile_big).and_then(|v| v.get("blocks").and_then(|b| b.as_i64())),
                Some(expected_blk)
            );
        }
        assert!(mfile_big.is_file());
        let big_for_hook = big_bin.clone();
        *TEST_MID_DECIDE_STOP_HOOK.lock().unwrap() = Some(Box::new(move || {
            let bf = fs::OpenOptions::new().write(true).open(&big_for_hook).unwrap();
            bf.set_len(cwg_common::MAX_FINGERPRINT_FILE_BYTES + 8192).unwrap();
        }));
        assert!(decide_stop(&json!({
            "conversationId": sess_big,
            "lastAssistantMessage": "[gate] verified: LOW; checked oversized",
        }))
        .is_some());
        assert_eq!(
            rio::read_json(&sfile_big).and_then(|v| v.get("blocks").and_then(|b| b.as_i64())),
            Some(1)
        );
        assert!(mfile_big.is_file());
        for expected_blk in 2..=MAX_BLOCKS_PER_CANDIDATE {
            assert!(decide_stop(&json!({
                "conversationId": sess_big,
                "lastAssistantMessage": "[gate] verified: LOW; checked oversized",
            }))
            .is_some());
            assert_eq!(
                rio::read_json(&sfile_big).and_then(|v| v.get("blocks").and_then(|b| b.as_i64())),
                Some(expected_blk)
            );
        }
        assert!(decide_stop(&json!({
            "conversationId": sess_big,
            "lastAssistantMessage": "[gate] verified: LOW; checked oversized",
        }))
        .is_none());
        assert!(!mfile_big.exists());
        let _ = fs::remove_file(&big_bin);

        // SAFETY: A tracked >32 MB file restored to clean `HEAD` closes immediately on the first `[gate] no-change: ...` Stop call.
        let git_big_dir = tmp.path.join("git_big_nc");
        fs::create_dir_all(&git_big_dir).unwrap();
        assert!(std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(&git_big_dir)
            .status()
            .unwrap()
            .success());
        assert!(std::process::Command::new("git")
            .args(["config", "user.email", "test@example.com"])
            .current_dir(&git_big_dir)
            .status()
            .unwrap()
            .success());
        assert!(std::process::Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(&git_big_dir)
            .status()
            .unwrap()
            .success());
        let tracked_big = git_big_dir.join("tracked_oversized.bin");
        {
            let tf = fs::File::create(&tracked_big).unwrap();
            tf.set_len(cwg_common::MAX_FINGERPRINT_FILE_BYTES + 4096).unwrap();
        }
        assert!(std::process::Command::new("git")
            .args(["add", "tracked_oversized.bin"])
            .current_dir(&git_big_dir)
            .status()
            .unwrap()
            .success());
        assert!(std::process::Command::new("git")
            .args(["commit", "-q", "-m", "add oversized"])
            .current_dir(&git_big_dir)
            .status()
            .unwrap()
            .success());
        let sess_big_nc = "sess-oversized-no-change";
        let mfile_big_nc = cwg_common::marker_path(sess_big_nc);
        let git_big_norm = rio::normalize_path(&git_big_dir.to_string_lossy());
        let tracked_big_norm = rio::normalize_path(&tracked_big.to_string_lossy());
        rio::write_json(
            &mfile_big_nc,
            &json!({
                "session": sess_big_nc,
                "first_ts": 310.0,
                "last_ts": 310.0,
                "last_durable_ts": 310.0,
                "edits": 2,
                "operational": false,
                "cwd": git_big_norm,
                "git_root": git_big_norm,
                "paths": [tracked_big_norm],
                "content_marks": [{"ts": 310.0, "fp": Value::Null}],
                "closed": false,
            }),
        )
        .unwrap();
        assert!(decide_stop(&json!({
            "conversationId": sess_big_nc,
            "lastAssistantMessage": "[gate] no-change: reverted oversized file to clean HEAD",
        }))
        .is_none());
        assert!(!mfile_big_nc.exists());
        let _ = fs::remove_dir_all(&git_big_dir);

        // SAFETY: With empty `transcript_path` (CLI mode), `active_cycle_closure_blocks_for_marker` resolves `<brain_root>/<session>`, rejects scouts, and clamps overlapping `breaker.json` outage windows on `reset_breaker_at`.
        let sess_board_cli = "sess-board-cli-parity";
        let swarm_cli_dir = tmp
            .path
            .join("brain")
            .join(sess_board_cli)
            .join(".system_generated")
            .join("swarm");
        let logs_cli_dir = tmp
            .path
            .join("brain")
            .join(sess_board_cli)
            .join(".system_generated")
            .join("logs");
        fs::create_dir_all(&swarm_cli_dir).unwrap();
        fs::create_dir_all(&logs_cli_dir).unwrap();
        let esc_cli_ts = rio::parse_iso_ts("2026-11-18 10:00:55");
        let iso_cli = |ts: f64| crate::win32_sqlite::format_iso_utc(ts);
        fs::write(
            logs_cli_dir.join("transcript.jsonl"),
            [
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": iso_cli(esc_cli_ts - 60.0), "content": "fix"}).to_string(),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": iso_cli(esc_cli_ts + 5.0), "tool_calls": [{"name": "search_web", "args": {"query": "docs"}}]}).to_string(),
                json!({"step_index": 2, "source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": iso_cli(esc_cli_ts + 6.0), "content": "official docs result"}).to_string(),
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();
        rio::write_json(
            &swarm_cli_dir.join("members.json"),
            &json!({
                "members": {
                    "scout-1": {"model": "gemini-4-hydrogen-medium", "state": "killed", "killed": true},
                    "rev-opus": {"model": "claude-opus-5-5-high", "state": "killed", "killed": true},
                }
            }),
        )
        .unwrap();
        let board_cli_lines = [
            json!({"seq": 1, "agent": "coordinator", "time": "2026-11-18 10:00:05", "text": "@scout-1 inspect"}),
            json!({"seq": 2, "agent": "scout-1", "time": "2026-11-18 10:00:10", "text": "CLOSURE_VALIDATION: BLOCKED"}),
            json!({"seq": 3, "agent": "coordinator", "time": "2026-11-18 10:00:12", "text": "@scout-1 inspect again"}),
            json!({"seq": 4, "agent": "scout-1", "time": "2026-11-18 10:00:15", "text": "CLOSURE_VALIDATION: BLOCKED"}),
            json!({"seq": 5, "agent": "coordinator", "time": "2026-11-18 10:00:20", "text": "@rev-opus round 1"}),
            json!({"seq": 6, "agent": "rev-opus", "time": "2026-11-18 10:00:25", "text": "VERDICT: REVISE"}),
            json!({"seq": 7, "agent": "coordinator", "time": "2026-11-18 10:00:30", "text": "@rev-opus round 2"}),
            json!({"seq": 8, "agent": "rev-opus", "time": "2026-11-18 10:00:35", "text": "VERDICT: REVISE"}),
            json!({"seq": 9, "agent": "coordinator", "time": "2026-11-18 10:00:40", "text": "@rev-opus round 3"}),
            json!({"seq": 10, "agent": "rev-opus", "time": "2026-11-18 10:00:45", "text": "VERDICT: REVISE"}),
            json!({"seq": 11, "agent": "coordinator", "time": "2026-11-18 10:00:50", "text": "@rev-opus round 4"}),
            json!({"seq": 12, "agent": "rev-opus", "time": "2026-11-18 10:00:55", "text": "VERDICT: ESCALATE"}),
            json!({"seq": 13, "agent": "coordinator", "time": "2026-11-18 10:01:10", "text": "@rev-opus closure pass 1"}),
            json!({"seq": 14, "agent": "rev-opus", "time": "2026-11-18 10:01:20", "text": "CLOSURE_VALIDATION: BLOCKED"}),
            json!({"seq": 15, "agent": "coordinator", "time": "2026-11-18 10:02:10", "text": "@rev-opus closure pass 2"}),
            json!({"seq": 16, "agent": "rev-opus", "time": "2026-11-18 10:02:20", "text": "CLOSURE_VALIDATION: BLOCKED"}),
            json!({"seq": 17, "agent": "coordinator", "time": "2026-11-18 10:05:10", "text": "@rev-opus post-recovery unauthorized pass"}),
            json!({"seq": 18, "agent": "rev-opus", "time": "2026-11-18 10:05:20", "text": "CLOSURE_VALIDATION: BLOCKED"}),
        ];
        fs::write(
            swarm_cli_dir.join("board.jsonl"),
            board_cli_lines.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        let cli_marker = json!({
            "session": sess_board_cli,
            "first_ts": 100.0,
            "last_ts": 100.0,
            "last_durable_ts": 100.0,
            "edits": 1,
            "cwd": ws.to_string_lossy(),
            "git_root": ws.to_string_lossy(),
            "paths": [notes_norm],
            "content_marks": [{"ts": 100.0, "fp": notes_fp_v1}],
            "closed": false,
        });
        codex_lane::wipe_breaker_for_test();
        let (cnt_codex_up, _, _) = codex_lane::active_cycle_closure_blocks_for_marker(
            &cli_marker,
            sess_board_cli,
            &ws.to_string_lossy(),
            "",
        );
        assert_eq!(cnt_codex_up, 0);

        let rev1_launch_ts = rio::parse_iso_ts("2026-11-18 10:01:10");
        let rev2_launch_ts = rio::parse_iso_ts("2026-11-18 10:02:10");
        let post_rec_first_ts = rio::parse_iso_ts("2026-11-18 10:04:00");
        // SAFETY: Exercise overlapping legacy windows `[rev1 - 60, rev1 + 900]` and `[rev1 - 10, rev2 + 60]` followed by recovery at `rev2 + 5`.
        rio::write_json(
            &cwg_common::gate_dir().join("codex_lane.json"),
            &json!({
                "tripped": true,
                "reason": "overlapping_outage",
                "tripped_at": rev1_launch_ts - 10.0,
                "tripped_until": rev2_launch_ts + 60.0,
                "history": [
                    {"tripped_at": rev1_launch_ts - 60.0, "until_ts": rev1_launch_ts + 900.0},
                    {"tripped_at": rev1_launch_ts - 10.0, "until_ts": rev2_launch_ts + 60.0},
                ],
            }),
        )
        .unwrap();
        codex_lane::reset_breaker_at(rev2_launch_ts + 5.0);
        assert_eq!(
            codex_lane::breaker_status().get("tripped").and_then(|v| v.as_bool()),
            Some(false)
        );
        let (cnt_during_outage, _, _) = codex_lane::active_cycle_closure_blocks_for_marker(
            &cli_marker,
            sess_board_cli,
            &ws.to_string_lossy(),
            "",
        );
        assert_eq!(cnt_during_outage, 2);

        // SAFETY: Durable `closure_halt` latched on `marker.json` preserves the 2-BLOCKED hard stop even after rollout/packet/board eviction until `research_resets` advances past `last_blocked_ts`.
        let mfile_cli = cwg_common::marker_path(sess_board_cli);
        rio::write_json(&mfile_cli, &cli_marker).unwrap();
        let (latched_n, latched_ts, latched_ids) =
            codex_lane::active_cycle_closure_blocks(sess_board_cli, &ws.to_string_lossy(), "");
        assert_eq!(latched_n, 2);
        assert!(latched_ts > 0.0);
        let _ = fs::remove_file(swarm_cli_dir.join("board.jsonl"));
        codex_lane::wipe_breaker_for_test();
        let (cnt_after_eviction, _, _) =
            codex_lane::active_cycle_closure_blocks(sess_board_cli, &ws.to_string_lossy(), "");
        assert_eq!(cnt_after_eviction, 2);
        let halted_marker = rio::read_json(&mfile_cli).unwrap();
        let rcp_evict = json!({"kind": "verified", "risk": "HIGH"});
        let chk_evict = ChecksEvidence {
            checks_count: 1,
            passed_count: 1,
            failed_count: 0,
            latest_pass_ts: 105.0,
            latest_fail_ts: 0.0,
            ..Default::default()
        };
        let sub_evict = SubagentEvidence::default();
        let sw_evict = SwarmEvidence::default();
        let (ok_evicted_stop, why_evicted_stop) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&rcp_evict),
            marker_in: &halted_marker,
            checks_ev: &chk_evict,
            sub_ev: &sub_evict,
            swarm_ev: &sw_evict,
            codex_reviews: &[],
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(!ok_evicted_stop);
        assert!(
            why_evicted_stop.contains("2/2 `BLOCKED` verdicts"),
            "expected 2/2 BLOCKED halt after eviction, got: {}",
            why_evicted_stop
        );
        // INVARIANT: Under the finite Stop cap (`MAX_BLOCKS_PER_CANDIDATE`), an unchanged candidate at `blocks >= MAX_BLOCKS_PER_CANDIDATE` retires finitely (`None`) instead of trapping the session in an infinite Stop loop, and `latch_marker_closure_halt` rejects cross-candidate turnover (`first_ts` mismatch).
        let sfile_cli = cwg_common::enforcement_state_path(sess_board_cli);
        rio::write_json(
            &sfile_cli,
            &json!({
                "candidate_key": cwg_common::candidate_key(&halted_marker),
                "candidate_first_ts": 100.0,
                "blocks": MAX_BLOCKS_PER_CANDIDATE + 1,
            }),
        )
        .unwrap();
        let blk_halted_exhaust = decide_stop(&json!({
            "conversationId": sess_board_cli,
            "lastAssistantMessage": "[gate] verified: HIGH; attempted exhaustion bypass",
        }));
        assert!(
            blk_halted_exhaust.is_none(),
            "expected decide_stop to release unchanged candidate finitely at MAX_BLOCKS_PER_CANDIDATE, got: {:?}",
            blk_halted_exhaust
        );
        let _ = fs::remove_file(&sfile_cli);

        let newer_candidate = json!({
            "session": sess_board_cli,
            "first_ts": 250.0,
            "last_ts": 250.0,
            "last_durable_ts": 250.0,
            "edits": 1,
            "cwd": ws.to_string_lossy(),
            "git_root": ws.to_string_lossy(),
            "paths": [notes_norm],
            "content_marks": [{"ts": 250.0, "fp": notes_fp_v1}],
            "closed": false,
        });
        rio::write_json(&mfile_cli, &newer_candidate).unwrap();
        cwg_common::latch_marker_closure_halt(cwg_common::ClosureHaltLatch {
            session: sess_board_cli,
            expected_first_ts: 100.0,
            expected_rr_ts: 0.0,
            expected_round_start_msg_id: 0,
            blocked_count: 2,
            last_blocked_ts: latched_ts,
            blocked_ids: &latched_ids,
            cycle_base_ts: 100.0,
        });
        let after_stale_latch = rio::read_json(&mfile_cli).unwrap();
        assert!(after_stale_latch.get("closure_halt").is_none());

        let mut cleared_marker = halted_marker.clone();
        cleared_marker["research_resets"] = json!([{
            "reset_ts": latched_ts + 1.0,
            "last_blocked_ts": latched_ts,
            "blocked_review_ids": latched_ids,
            "decision": "refine",
            "findings": "verified durable halt clear",
            "research_tools": ["search_web"],
            "board_head_seq": 8,
        }]);
        assert!(cwg_common::active_marker_closure_halt(&cleared_marker).is_none());
        let _ = fs::remove_file(&mfile_cli);
        fs::write(
            swarm_cli_dir.join("board.jsonl"),
            board_cli_lines.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        rio::write_json(
            &cwg_common::gate_dir().join("codex_lane.json"),
            &json!({
                "tripped": false,
                "tripped_at": rev1_launch_ts - 10.0,
                "tripped_until": 0.0,
                "history": [
                    {"tripped_at": rev1_launch_ts - 60.0, "until_ts": rev2_launch_ts + 5.0},
                    {"tripped_at": rev1_launch_ts - 10.0, "until_ts": rev2_launch_ts + 5.0},
                ],
            }),
        )
        .unwrap();

        let mut post_rec_marker = cli_marker.clone();
        post_rec_marker["first_ts"] = json!(post_rec_first_ts);
        post_rec_marker["last_ts"] = json!(post_rec_first_ts);
        post_rec_marker["last_durable_ts"] = json!(post_rec_first_ts);
        post_rec_marker["round_start_msg_id"] = json!(8);
        let (cnt_post_recovery, _, _) = codex_lane::active_cycle_closure_blocks_for_marker(
            &post_rec_marker,
            sess_board_cli,
            &ws.to_string_lossy(),
            "",
        );
        codex_lane::wipe_breaker_for_test();
        assert_eq!(cnt_post_recovery, 0);

        fs::write(&notes_md, "# v1\n").unwrap();
        rio::write_json(&mfile_exh, &exh_marker).unwrap();
        rio::write_json(
            &sfile_exh,
            &json!({
                "candidate_key": cwg_common::candidate_key(&exh_marker),
                "candidate_first_ts": 200.0,
                "blocks": MAX_BLOCKS_PER_CANDIDATE,
            }),
        )
        .unwrap();
        let allow_unchanged_exhaust = decide_stop(&json!({
            "conversationId": sess_exh,
            "lastAssistantMessage": "missing receipt",
        }));
        assert!(allow_unchanged_exhaust.is_none());
        assert!(!mfile_exh.exists());

        // SAFETY: If `marker.json` cannot be deleted or overwritten (`FILE_SHARE_READ`-only handle on Windows), `retire_candidate_checked` fails closed without acking pending deltas or clearing state.
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let sess_locked = "sess-retire-write-locked";
            let mfile_locked = cwg_common::marker_path(sess_locked);
            let sfile_locked = cwg_common::enforcement_state_path(sess_locked);
            let locked_marker = json!({
                "session": sess_locked,
                "first_ts": 400.0,
                "last_ts": 400.0,
                "last_durable_ts": 400.0,
                "edits": 1,
                "operational": false,
                "paths": [notes_norm],
                "content_marks": [{"ts": 400.0, "fp": notes_fp_v1}],
                "closed": false,
            });
            rio::write_json(&mfile_locked, &locked_marker).unwrap();
            let pend_dir = cwg_common::marker_pending_dir(sess_locked);
            fs::create_dir_all(&pend_dir).unwrap();
            let pend_file = pend_dir.join("0001.json");
            rio::write_json(&pend_file, &json!({"ts": 400.0, "edits": 0, "paths": []})).unwrap();
            let stats_locked = snapshot_path_stats(&locked_marker);
            let mut st_locked = Map::new();
            st_locked.insert("blocks".to_string(), json!(2));
            let hold_read_only = fs::OpenOptions::new()
                .read(true)
                .share_mode(1)
                .open(&mfile_locked)
                .unwrap();
            let pend_ids_locked = ["0001.json".to_string()];
            let retired_while_locked = retire_candidate_checked(RetireCandidateInput {
                session: sess_locked,
                marker_file: &mfile_locked,
                state_file: &sfile_locked,
                state: &mut st_locked,
                receipt_summary: "verified",
                expected_marker: Some(&locked_marker),
                expected_stats: Some(&stats_locked),
                consumed_pending_ids: &pend_ids_locked,
                allow_unhashed: false,
            });
            assert!(!retired_while_locked);
            assert!(pend_file.is_file());
            assert_eq!(st_locked.get("blocks").and_then(|v| v.as_i64()), Some(2));
            drop(hold_read_only);
            let _ = fs::remove_file(&pend_file);
            let _ = fs::remove_file(&mfile_locked);
        }
    }

    fn write_jsonl_lines(path: &Path, items: &[Value]) {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).unwrap();
        }
        let body = if items.is_empty() {
            String::new()
        } else {
            items
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join("\n")
                + "\n"
        };
        fs::write(path, body).unwrap();
    }

    fn setup_neon_session_env(
        brain: &Path,
        sess: &str,
        coord_initial: &str,
        members: Value,
        board: &[Value],
        member_logs: &[(&str, &[Value])],
    ) -> PathBuf {
        let tp = brain
            .join(sess)
            .join(".system_generated")
            .join("logs")
            .join("transcript_full.jsonl");
        let sd = brain.join(sess).join(".system_generated").join("swarm");
        fs::create_dir_all(tp.parent().unwrap()).unwrap();
        fs::create_dir_all(&sd).unwrap();
        fs::write(&tp, coord_initial).unwrap();
        rio::write_json(&sd.join("members.json"), &members).unwrap();
        write_jsonl_lines(&sd.join("board.jsonl"), board);
        for (cid, m_steps) in member_logs {
            write_jsonl_lines(&rio::member_transcript_path(brain, cid), m_steps);
        }
        tp
    }

    #[test]
    fn test_object_tool_response_tokenade_anon_snap_and_chained_check_guidance() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!(
            "cwg-obj-resp-chained-{}-{}",
            std::process::id(),
            (now_sec() * 1000.0) as u64
        ));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let shome = tmp.join("stack_home");
        fs::create_dir_all(&shome).unwrap();
        let prev_home = std::env::var_os("CARBON_STACK_HOME");
        std::env::set_var("CARBON_STACK_HOME", &shome);

        let tokenade_bin = "C:/Users/in/AppData/Roaming/npm/node_modules/@tokenade/cli/node_modules/@tokenade/cli-win32-x64/tokenade.exe";
        let raw_val_cmd = "$null | node scripts/ux/validate-system.js";
        let wrapped_val_cmd = format!(
            "& '{}' wrap --shell powershell '{}'",
            tokenade_bin, raw_val_cmd
        );

        let sess_tok = "sess-obj-tokenade-anon";
        let pre_tok = json!({
            "conversationId": sess_tok,
            "cwd": tmp.to_string_lossy(),
            "workspacePaths": [tmp.to_string_lossy()],
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": raw_val_cmd}
            }
        });
        cwg_mark::record_pre_tool_use(&pre_tok);
        let t_after_pre = now_sec();
        std::thread::sleep(std::time::Duration::from_millis(15));
        let post_tok = json!({
            "conversationId": sess_tok,
            "cwd": tmp.to_string_lossy(),
            "workspacePaths": [tmp.to_string_lossy()],
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": wrapped_val_cmd}
            },
            "toolResponse": {"output": "Command exited with code 0.\n\nCommand output:\nvalidate-system: OK\n"}
        });
        cwg_mark::record_post_tool_use(&post_tok).unwrap();
        let ev_tok = read_checks_evidence_with_steps(sess_tok, 0.0, &[]);
        assert_eq!((ev_tok.checks_count, ev_tok.passed_count, ev_tok.failed_count), (1, 1, 0));
        assert!(
            ev_tok.latest_pass_ts > 0.0 && ev_tok.latest_pass_ts <= t_after_pre,
            "tokenade-wrapped PostToolUse must hit raw PreToolUse anon snapshot start_ts: {:?}",
            ev_tok
        );

        let sess_cd_tok = "sess-obj-tokenade-cd-indent";
        let raw_cd_cmd = format!(
            "Set-Location '{}'\r\n   $null | node scripts/validate.js  ",
            tmp.to_string_lossy()
        );
        let wrapped_cd_cmd = format!(
            "Set-Location '{}'\r\n& '{}' wrap --shell powershell '$null | node scripts/validate.js'",
            tmp.to_string_lossy(),
            tokenade_bin
        );
        let pre_cd_tok = json!({
            "conversationId": sess_cd_tok,
            "cwd": tmp.to_string_lossy(),
            "workspacePaths": [tmp.to_string_lossy()],
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": raw_cd_cmd}
            }
        });
        cwg_mark::record_pre_tool_use(&pre_cd_tok);
        let t_cd_after_pre = now_sec();
        std::thread::sleep(std::time::Duration::from_millis(15));
        let post_cd_tok = json!({
            "conversationId": sess_cd_tok,
            "cwd": tmp.to_string_lossy(),
            "workspacePaths": [tmp.to_string_lossy()],
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": wrapped_cd_cmd}
            },
            "toolResponse": {"output": "Command exited with code 0.\n\nCommand output:\nvalidate: OK\n"}
        });
        cwg_mark::record_post_tool_use(&post_cd_tok).unwrap();
        let ev_cd_tok = read_checks_evidence_with_steps(sess_cd_tok, 0.0, &[]);
        assert_eq!((ev_cd_tok.checks_count, ev_cd_tok.passed_count), (1, 1));
        assert!(
            ev_cd_tok.latest_pass_ts > 0.0 && ev_cd_tok.latest_pass_ts <= t_cd_after_pre,
            "Set-Location + indented tokenade-wrapped PostToolUse must hit raw PreToolUse anon snapshot start_ts: {:?}",
            ev_cd_tok
        );

        let pkg_dir = tmp.join("pkg_with_scripts");
        let pkg_missing_dir = tmp.join("pkg_missing_scripts");
        fs::create_dir_all(&pkg_dir).unwrap();
        fs::create_dir_all(&pkg_missing_dir).unwrap();
        fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"demo","scripts":{"ux:validate":"node scripts/ux/validate-system.js","schema:verify":"node scripts/verify.mjs"}}"#,
        )
        .unwrap();
        fs::write(pkg_dir.join(".npmrc"), "if-present=true\n").unwrap();
        fs::write(
            pkg_missing_dir.join("package.json"),
            r#"{"name":"missing","scripts":{"test":"node test.js"}}"#,
        )
        .unwrap();
        fs::write(pkg_missing_dir.join(".npmrc"), "if-present=true\n").unwrap();

        let sess_pkg_ok = "sess-pkg-validate-defined";
        let pre_pkg_ok = json!({
            "conversationId": sess_pkg_ok,
            "cwd": pkg_dir.to_string_lossy(),
            "workspacePaths": [pkg_dir.to_string_lossy()],
            "stepIndex": 14,
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": "$null | npm run ux:validate"}
            }
        });
        cwg_mark::record_pre_tool_use(&pre_pkg_ok);
        let t_pkg_pre = now_sec();
        let mut post_pkg_ok = pre_pkg_ok.clone();
        post_pkg_ok["toolResponse"] = json!({"output": "Command exited with code 0.\n\nCommand output:\nvalidate-system: OK\n"});
        cwg_mark::record_post_tool_use(&post_pkg_ok).unwrap();
        let ev_pkg_ok = read_checks_evidence_with_steps_in_cwd(
            sess_pkg_ok,
            0.0,
            &[],
            &pkg_dir.to_string_lossy(),
        );
        assert_eq!((ev_pkg_ok.checks_count, ev_pkg_ok.passed_count), (1, 1));
        assert!(
            ev_pkg_ok.latest_pass_ts > 0.0 && ev_pkg_ok.latest_pass_ts <= t_pkg_pre,
            "defined package.json validate script must be credited with pre-spawn start_ts: {:?}",
            ev_pkg_ok
        );

        let sess_pkg_tx = "sess-pkg-pnpm-transcript";
        let pnpm_steps = vec![
            json!({
                "step_index": 30,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2026-11-21T12:00:00Z",
                "tool_calls": [{
                    "name": "run_command",
                    "args": {
                        "CommandLine": "$null | pnpm run schema:verify",
                        "Cwd": pkg_dir.to_string_lossy()
                    }
                }]
            }),
            json!({
                "step_index": 31,
                "source": "SYSTEM",
                "type": "GENERIC",
                "status": "DONE",
                "created_at": "2026-11-21T12:00:02Z",
                "content": "Command exited with code 0.\n"
            }),
        ];
        let ev_pnpm_ok = read_checks_evidence_with_steps_in_cwd(
            sess_pkg_tx,
            1795262000.0,
            &pnpm_steps,
            &pkg_dir.to_string_lossy(),
        );
        assert_eq!(
            (ev_pnpm_ok.checks_count, ev_pnpm_ok.passed_count),
            (1, 1),
            "defined pnpm schema:verify with verified run Cwd in transcript must be credited: {:?}",
            ev_pnpm_ok
        );
        let pnpm_missing_steps = vec![
            json!({
                "step_index": 30,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2026-11-21T12:00:00Z",
                "tool_calls": [{
                    "name": "run_command",
                    "args": {
                        "CommandLine": "$null | pnpm run schema:verify",
                        "Cwd": pkg_missing_dir.to_string_lossy()
                    }
                }]
            }),
            json!({
                "step_index": 31,
                "source": "SYSTEM",
                "type": "GENERIC",
                "status": "DONE",
                "created_at": "2026-11-21T12:00:02Z",
                "content": "Command exited with code 0.\n"
            }),
        ];
        let ev_pnpm_missing = read_checks_evidence_with_steps_in_cwd(
            sess_pkg_tx,
            1795262000.0,
            &pnpm_missing_steps,
            &pkg_missing_dir.to_string_lossy(),
        );
        assert_eq!(
            (ev_pnpm_missing.checks_count, ev_pnpm_missing.passed_count, ev_pnpm_missing.saw_uncertain_pass),
            (0, 0, false),
            "missing pnpm schema:verify under if-present=true must not be credited: {:?}",
            ev_pnpm_missing
        );

        let sess_ifp = "sess-npm-if-present";
        let pkg_mono_ws = tmp.join("pkg_mono_ws");
        let pkg_mono_quoted = tmp.join("pkg_mono_ws_quoted");
        let pkg_git_c_sub = pkg_missing_dir.join("sub_with_validate");
        fs::create_dir_all(pkg_mono_ws.join("packages").join("child")).unwrap();
        fs::create_dir_all(pkg_mono_quoted.join("packages").join("child")).unwrap();
        fs::create_dir_all(&pkg_git_c_sub).unwrap();
        for (ws_root, npmrc_body) in [
            (&pkg_mono_ws, "workspaces=true\nif-present=true\n"),
            (&pkg_mono_quoted, "\"workspaces\"=true\nif-present=true\n"),
        ] {
            fs::write(
                ws_root.join("package.json"),
                r#"{"name":"mono","workspaces":["packages/*"],"scripts":{"validate":"node v.js"}}"#,
            )
            .unwrap();
            fs::write(ws_root.join(".npmrc"), npmrc_body).unwrap();
            fs::write(
                ws_root.join("packages").join("child").join("package.json"),
                r#"{"name":"child","scripts":{"test":"node t.js"}}"#,
            )
            .unwrap();
        }
        fs::write(
            pkg_git_c_sub.join("package.json"),
            r#"{"name":"sub","scripts":{"validate":"node sub.js"}}"#,
        )
        .unwrap();
        for (sidx, cwd_p, cmd) in [
            (15, &pkg_dir, "$null | npm run ux:validate --if-present"),
            (16, &pkg_missing_dir, "$null | npm run validate"),
            (17, &pkg_dir, "$null | npm run test --if-present"),
            (18, &pkg_dir, "$null | npm run ux:validate --ws"),
            (19, &pkg_mono_ws, "$null | npm run validate"),
            (20, &pkg_missing_dir, "git -C 'sub_with_validate' status; $null | npm run validate"),
            (21, &pkg_mono_quoted, "$null | npm run validate"),
            (22, &pkg_missing_dir, "cd /d sub_with_validate; $null | npm run validate"),
        ] {
            let post_ifp = json!({
                "conversationId": sess_ifp,
                "cwd": cwd_p.to_string_lossy(),
                "workspacePaths": [cwd_p.to_string_lossy()],
                "stepIndex": sidx,
                "toolCall": {
                    "name": "run_command",
                    "args": {"CommandLine": cmd}
                },
                "toolResponse": {"output": "Command exited with code 0.\n"}
            });
            cwg_mark::record_post_tool_use(&post_ifp).unwrap();
        }
        let git_c_steps = vec![
            json!({
                "step_index": 35,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2026-11-21T12:05:00Z",
                "tool_calls": [{
                    "name": "run_command",
                    "args": {"CommandLine": "git -C 'sub_with_validate' status; $null | npm run validate"}
                }]
            }),
            json!({
                "step_index": 36,
                "source": "SYSTEM",
                "type": "GENERIC",
                "status": "DONE",
                "created_at": "2026-11-21T12:05:02Z",
                "content": "Command exited with code 0.\n"
            }),
            json!({
                "step_index": 37,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2026-11-21T12:05:05Z",
                "tool_calls": [{
                    "name": "run_command",
                    "args": {"CommandLine": "cd /d sub_with_validate; $null | npm run validate"}
                }]
            }),
            json!({
                "step_index": 38,
                "source": "SYSTEM",
                "type": "GENERIC",
                "status": "DONE",
                "created_at": "2026-11-21T12:05:07Z",
                "content": "Command exited with code 0.\n"
            }),
        ];
        let ev_ifp = read_checks_evidence_with_steps_in_cwd(
            sess_ifp,
            0.0,
            &git_c_steps,
            &pkg_missing_dir.to_string_lossy(),
        );
        assert_eq!(
            (ev_ifp.checks_count, ev_ifp.passed_count, ev_ifp.saw_uncertain_pass),
            (0, 0, false),
            "missing npm run validate, --ws, .npmrc workspaces=true, git -C target, or --if-present must not count as passing or uncertain checks: {:?}",
            ev_ifp
        );

        let pkg_dir_sub_missing = pkg_dir.join("sub_no_script");
        fs::create_dir_all(&pkg_dir_sub_missing).unwrap();
        fs::write(
            pkg_dir_sub_missing.join("package.json"),
            r#"{"name":"sub-no","scripts":{"test":"node t.js"}}"#,
        )
        .unwrap();
        let sess_git_c_ok = "sess-git-c-root-ok";
        let git_c_ok_steps = vec![
            json!({
                "step_index": 40,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2026-11-21T12:06:00Z",
                "tool_calls": [{
                    "name": "run_command",
                    "args": {
                        "CommandLine": "git -C 'sub_no_script' status; $null | npm run ux:validate",
                        "Cwd": pkg_dir.to_string_lossy()
                    }
                }]
            }),
            json!({
                "step_index": 41,
                "source": "SYSTEM",
                "type": "GENERIC",
                "status": "DONE",
                "created_at": "2026-11-21T12:06:02Z",
                "content": "Command exited with code 0.\n"
            }),
        ];
        let ev_git_c_ok = read_checks_evidence_with_steps_in_cwd(
            sess_git_c_ok,
            1795262000.0,
            &git_c_ok_steps,
            &pkg_dir.to_string_lossy(),
        );
        assert_eq!(
            (ev_git_c_ok.checks_count, ev_git_c_ok.passed_count),
            (1, 1),
            "git -C subdir must not hide executing root package.json script: {:?}",
            ev_git_c_ok
        );

        let sess_fail_obj = "sess-obj-nonzero-spoof";
        let post_fail_obj = json!({
            "conversationId": sess_fail_obj,
            "cwd": tmp.to_string_lossy(),
            "workspacePaths": [tmp.to_string_lossy()],
            "stepIndex": 12,
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": raw_val_cmd}
            },
            "toolResponse": {"output": "Command exited with code 1.\n\nCommand output:\nCommand exited with code 0.\n"}
        });
        cwg_mark::record_post_tool_use(&post_fail_obj).unwrap();
        let ev_fail_obj = read_checks_evidence_with_steps(sess_fail_obj, 0.0, &[]);
        assert_eq!((ev_fail_obj.checks_count, ev_fail_obj.passed_count, ev_fail_obj.failed_count), (1, 0, 1));

        let sess_bg_obj = "sess-obj-bg-launch";
        let pre_bg_obj = json!({
            "conversationId": sess_bg_obj,
            "cwd": tmp.to_string_lossy(),
            "workspacePaths": [tmp.to_string_lossy()],
            "stepIndex": 20,
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": raw_val_cmd}
            }
        });
        cwg_mark::record_pre_tool_use(&pre_bg_obj);
        let t_bg_pre = now_sec();
        let mut post_bg_obj = pre_bg_obj.clone();
        post_bg_obj["toolResponse"] = json!({
            "output": "Tool is running as a background task with task id: sess-obj-bg-launch/task-20\n"
        });
        cwg_mark::record_post_tool_use(&post_bg_obj).unwrap();
        let ev_bg_pending = read_checks_evidence_with_steps(sess_bg_obj, 0.0, &[]);
        assert_eq!(ev_bg_pending.checks_count, 0, "pending bg_launch must not count before completion");
        let bg_done_steps = vec![json!({
            "source": "SYSTEM",
            "type": "SYSTEM_MESSAGE",
            "created_at": "2026-11-21T11:16:31Z",
            "content": "<SYSTEM_MESSAGE>\n[Message] timestamp=2026-11-21T11:16:31Z sender=sess-obj-bg-launch/task-20 priority=MESSAGE_PRIORITY_HIGH content=Task id \"sess-obj-bg-launch/task-20\" finished with result:\nCommand exited with code 0.\n\nCommand output:\nvalidate-system: OK\n</SYSTEM_MESSAGE>"
        })];
        let ev_bg_done = read_checks_evidence_with_steps(sess_bg_obj, 0.0, &bg_done_steps);
        assert_eq!((ev_bg_done.checks_count, ev_bg_done.passed_count), (1, 1));
        assert!(
            ev_bg_done.latest_pass_ts > 0.0 && ev_bg_done.latest_pass_ts <= t_bg_pre,
            "completed object bg_launch must preserve pre-spawn start_ts: {:?}",
            ev_bg_done
        );

        let sess_chained = "sess-anom-48e3ee7b-chained";
        let chained_cmd = "$null | node scripts/ux/validate-system.js ; $null | node scripts/ci/test-mr-routing.js";
        let wrapped_chained = format!(
            "& '{}' wrap --shell powershell '{}'",
            tokenade_bin, chained_cmd
        );
        let post_raw_stdout_only = json!({
            "conversationId": sess_chained,
            "cwd": tmp.to_string_lossy(),
            "workspacePaths": [tmp.to_string_lossy()],
            "stepIndex": 5510,
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": wrapped_chained}
            },
            "toolResponse": {"stdout": "Command exited with code 0.\n"}
        });
        cwg_mark::record_post_tool_use(&post_raw_stdout_only).unwrap();
        let ev_raw_stdout = read_checks_evidence_with_steps(sess_chained, 0.0, &[]);
        assert!(
            !ev_raw_stdout.saw_uncertain_pass,
            "raw stdout field must not spoof host exit header"
        );

        let post_chained_bg = json!({
            "conversationId": sess_chained,
            "cwd": tmp.to_string_lossy(),
            "workspacePaths": [tmp.to_string_lossy()],
            "stepIndex": 5503,
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": wrapped_chained}
            },
            "toolResponse": {"output": "Tool is running as a background task with task id: sess-anom-48e3ee7b-chained/task-5503\n"}
        });
        cwg_mark::record_post_tool_use(&post_chained_bg).unwrap();
        let post_chained_sync = json!({
            "conversationId": sess_chained,
            "cwd": tmp.to_string_lossy(),
            "workspacePaths": [tmp.to_string_lossy()],
            "stepIndex": 5515,
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": wrapped_chained}
            },
            "toolResponse": {"output": "Command exited with code 0.\n\nCommand output:\nvalidate-system: OK\n"}
        });
        cwg_mark::record_post_tool_use(&post_chained_sync).unwrap();
        let chained_steps = vec![
            json!({
                "source": "SYSTEM",
                "type": "SYSTEM_MESSAGE",
                "created_at": "2026-11-21T11:16:31Z",
                "content": "<SYSTEM_MESSAGE>\n[Message] timestamp=2026-11-21T11:16:31Z sender=sess-anom-48e3ee7b-chained/task-5503 priority=MESSAGE_PRIORITY_HIGH content=Task id \"sess-anom-48e3ee7b-chained/task-5503\" finished with result:\nCommand exited with code 0.\n\nCommand output:\nvalidate-system: OK\n</SYSTEM_MESSAGE>"
            }),
            json!({
                "step_index": 5514,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2026-11-21T11:18:07Z",
                "tool_calls": [{
                    "name": "run_command",
                    "args": {"CommandLine": chained_cmd}
                }]
            }),
            json!({
                "step_index": 5515,
                "source": "SYSTEM",
                "type": "GENERIC",
                "status": "DONE",
                "created_at": "2026-11-21T11:18:11Z",
                "content": "Command exited with code 0.\n\nCommand output:\nvalidate-system: OK\n"
            }),
        ];
        let ev_chained = read_checks_evidence_with_steps(sess_chained, 1795258412.0, &chained_steps);
        assert_eq!(
            (ev_chained.checks_count, ev_chained.passed_count, ev_chained.saw_uncertain_pass),
            (0, 0, true),
            "chained `;` checks must remain uncounted as standalone checks while flagging ignored runs: {:?}",
            ev_chained
        );

        let sess_anon_unc = "sess-anom-48e3ee7b-anon-unc";
        let post_anon_unc = json!({
            "conversationId": sess_anon_unc,
            "cwd": tmp.to_string_lossy(),
            "workspacePaths": [tmp.to_string_lossy()],
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": wrapped_chained}
            },
            "toolResponse": {"output": "   \n", "text": "Command exited with code 0.\n\nCommand output:\nvalidate-system: OK\n"}
        });
        cwg_mark::record_post_tool_use(&post_anon_unc).unwrap();
        let ev_anon_now = read_checks_evidence_with_steps(sess_anon_unc, 0.0, &[]);
        assert_eq!(
            (ev_anon_now.checks_count, ev_anon_now.saw_uncertain_pass),
            (0, true),
            "whitespace-only output must fall back to text host envelope: {:?}",
            ev_anon_now
        );
        let ev_anon_stale = read_checks_evidence_with_steps(sess_anon_unc, now_sec() + 60.0, &[]);
        assert!(
            !ev_anon_stale.saw_uncertain_pass,
            "pre-candidate uncertain run must not trigger ignored-check hint for a newer candidate"
        );

        let ws_chained = tmp.join("ws_chained");
        let rules_dir = ws_chained.join(".claude").join("rules");
        fs::create_dir_all(&rules_dir).unwrap();
        fs::write(ws_chained.join("package.json"), r#"{"name":"ws-chained"}"#).unwrap();
        let rule_file = rules_dir.join("out-of-scope-issues.md");
        fs::write(&rule_file, "# rule\n").unwrap();
        let rule_path = rule_file.to_string_lossy().into_owned();
        let rule_fp = cwg_common::content_fingerprint(std::slice::from_ref(&rule_path), 4_000_000);
        let marker_chained = json!({
            "session": sess_chained,
            "cwd": ws_chained.to_string_lossy(),
            "git_root": "",
            "paths": [rule_path],
            "first_ts": 1795258412.0,
            "last_durable_ts": 1795259764.0,
            "content_marks": [{"ts": 1795259764.0, "fp": rule_fp}],
            "edits": 1,
            "closed": false,
        });
        let rcp_high = cwg_common::parse_terminal_receipt("[gate] verified: HIGH; ok").unwrap();
        let (ok_chained, why_chained) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&rcp_high),
            marker_in: &marker_chained,
            checks_ev: &ev_chained,
            sub_ev: &SubagentEvidence::default(),
            swarm_ev: &SwarmEvidence::default(),
            codex_reviews: &[],
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(!ok_chained);
        assert!(
            why_chained.contains("zero standalone verification/test commands")
                && why_chained.contains("chained/non-standalone check run(s) were ignored")
                && why_chained.contains("standalone command"),
            "expected actionable chained-command block reason, got: {}",
            why_chained
        );

        match prev_home {
            Some(v) => std::env::set_var("CARBON_STACK_HOME", v),
            None => std::env::remove_var("CARBON_STACK_HOME"),
        }
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_anom_232ff9d9_draft_blocked_closure_cap_and_anom_65718cd1_standalone_docs() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!(
            "cwg-anom-232-657-{}-{}",
            std::process::id(),
            (now_sec() * 1000.0) as u64
        ));
        let _ = fs::remove_dir_all(&tmp);
        let shome = tmp.join("stack_home");
        let prev_home = std::env::var_os("CARBON_STACK_HOME");
        std::env::set_var("CARBON_STACK_HOME", &shome);

        let repo_dir = tmp.join("repo_232");
        fs::create_dir_all(repo_dir.join(".git")).unwrap();
        let src_file = repo_dir.join("rust").join("src").join("cwg_mark.rs");
        fs::create_dir_all(src_file.parent().unwrap()).unwrap();
        fs::write(&src_file, "// test\n").unwrap();
        let src_path = src_file.to_string_lossy().into_owned();
        let src_fp = cwg_common::content_fingerprint(std::slice::from_ref(&src_path), 4_000_000);
        let m_232 = json!({
            "session": "sess-anom-232",
            "cwd": repo_dir.to_string_lossy(),
            "git_root": repo_dir.to_string_lossy(),
            "paths": [src_path],
            "first_ts": 100.0,
            "last_durable_ts": 110.0,
            "content_marks": [{"ts": 110.0, "fp": src_fp}],
            "gate_max_review_rounds": 4,
            "edits": 1,
            "closed": false,
            "closure_halt": {
                "blocked_count": 2,
                "blocked_review_ids": ["cwg-b1", "cwg-b2"],
                "candidate_first_ts": 100.0,
                "cycle_base_ts": 100.0,
                "halt_schema_version": 2,
                "last_blocked_ts": 160.0
            }
        });
        let checks_ok = ChecksEvidence {
            checks_count: 1,
            passed_count: 1,
            latest_pass_ts: 120.0,
            ..Default::default()
        };
        let sw_unver = SwarmEvidence::default();
        let rev_list = vec![
            json!({"id":"r1","kind":"ordinary","verdict":"REVISE","engine":"codex","launch_ts":125.0,"verdict_ts":126.0}),
            json!({"id":"r2","kind":"ordinary","verdict":"REVISE","engine":"codex","launch_ts":130.0,"verdict_ts":131.0}),
            json!({"id":"r3","kind":"ordinary","verdict":"REVISE","engine":"codex","launch_ts":135.0,"verdict_ts":136.0}),
            json!({"id":"r4","kind":"ordinary","verdict":"ESCALATE","engine":"codex","launch_ts":140.0,"verdict_ts":141.0}),
            json!({"id":"cwg-b1","kind":"closure","verdict":"BLOCKED","engine":"codex","launch_ts":150.0,"verdict_ts":151.0}),
            json!({"id":"cwg-b2","kind":"closure","verdict":"BLOCKED","engine":"codex","launch_ts":159.0,"verdict_ts":160.0}),
        ];
        let rcp_draft = cwg_common::parse_terminal_receipt("[gate] draft-blocked: 2/2 blocked").unwrap();
        let (ok_draft, why_draft) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&rcp_draft),
            marker_in: &m_232,
            checks_ev: &checks_ok,
            sub_ev: &SubagentEvidence::default(),
            swarm_ev: &sw_unver,
            codex_reviews: &rev_list,
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(ok_draft, "2/2 blocked closure draft-blocked must succeed: {}", why_draft);

        let rcp_ver = cwg_common::parse_terminal_receipt("[gate] verified: HIGH; ok").unwrap();

        let global_cfg_dir = tmp.join("fake_home").join(".gemini").join("config").join("rules");
        fs::create_dir_all(&global_cfg_dir).unwrap();
        let md_file = global_cfg_dir.join("uiux-design.md");
        fs::write(&md_file, "# uiux\n").unwrap();
        let md_path = md_file.to_string_lossy().into_owned();
        let md_fp = cwg_common::content_fingerprint(std::slice::from_ref(&md_path), 4_000_000);
        let m_doc = json!({
            "session": "sess-anom-657",
            "cwd": repo_dir.to_string_lossy(),
            "git_root": repo_dir.to_string_lossy(),
            "paths": [md_path],
            "first_ts": 200.0,
            "last_durable_ts": 210.0,
            "content_marks": [{"ts": 210.0, "fp": md_fp}],
            "gate_max_review_rounds": 4,
            "edits": 1,
            "closed": false,
            "shell_durable_edit": false,
        });
        let sw_clean = SwarmEvidence::default();
        let rev_approved = vec![json!({
            "id": "cwg-app-657",
            "kind": "ordinary",
            "verdict": "APPROVED",
            "engine": "codex",
            "launch_ts": 220.0,
            "verdict_ts": 222.0,
            "reviewed_tree_oid": ""
        })];
        let (ok_doc, why_doc) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&rcp_ver),
            marker_in: &m_doc,
            checks_ev: &ChecksEvidence::default(),
            sub_ev: &SubagentEvidence::default(),
            swarm_ev: &sw_clean,
            codex_reviews: &rev_approved,
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(ok_doc, "standalone non-repo HIGH markdown config must not require nonexistent test runner: {}", why_doc);

        let failed_checks = ChecksEvidence {
            checks_count: 1,
            passed_count: 0,
            latest_fail_ts: 212.0,
            ..Default::default()
        };
        let (ok_doc_fail, _) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&rcp_ver),
            marker_in: &m_doc,
            checks_ev: &failed_checks,
            sub_ev: &SubagentEvidence::default(),
            swarm_ev: &sw_clean,
            codex_reviews: &rev_approved,
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(!ok_doc_fail, "failing check must still block standalone non-repo doc candidate");

        let json_cfg = global_cfg_dir.parent().unwrap().join("mcp_config.json");
        fs::write(&json_cfg, "{}\n").unwrap();
        let json_path = json_cfg.to_string_lossy().into_owned();
        let mix_paths = vec![md_path.clone(), json_path];
        let mix_fp = cwg_common::content_fingerprint(&mix_paths, 4_000_000);
        let mut m_mix = m_doc.clone();
        m_mix["paths"] = json!(mix_paths);
        m_mix["content_marks"] = json!([{"ts": 210.0, "fp": mix_fp}]);
        let (ok_mix, why_mix) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&rcp_ver),
            marker_in: &m_mix,
            checks_ev: &ChecksEvidence::default(),
            sub_ev: &SubagentEvidence::default(),
            swarm_ev: &sw_clean,
            codex_reviews: &rev_approved,
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(
            !ok_mix && why_mix.contains("zero executed verification/test commands"),
            "non-doc config file paired with markdown must still require checks: ({}, {})",
            ok_mix,
            why_mix
        );

        let rcp_xhigh = cwg_common::parse_terminal_receipt("[gate] verified: XHIGH; ok").unwrap();
        let (ok_xhigh, why_xhigh) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&rcp_xhigh),
            marker_in: &m_doc,
            checks_ev: &ChecksEvidence::default(),
            sub_ev: &SubagentEvidence::default(),
            swarm_ev: &sw_clean,
            codex_reviews: &rev_approved,
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(
            !ok_xhigh && why_xhigh.contains("zero executed verification/test commands"),
            "XHIGH must never bypass test requirement: ({}, {})",
            ok_xhigh,
            why_xhigh
        );

        match prev_home {
            Some(v) => std::env::set_var("CARBON_STACK_HOME", v),
            None => std::env::remove_var("CARBON_STACK_HOME"),
        }
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_outside_marker_crlf_simplify_rejection_and_four_revise_draft_blocked() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!(
            "cwg-r3-crlf-4rev-{}-{}",
            std::process::id(),
            (now_sec() * 1000.0) as u64
        ));
        let _ = fs::remove_dir_all(&tmp);
        let shome = tmp.join("stack_home");
        let brain = tmp.join("brain");
        let repo = tmp.join("repo");
        fs::create_dir_all(&repo).unwrap();
        let prev_home = std::env::var_os("CARBON_STACK_HOME");
        std::env::set_var("CARBON_STACK_HOME", &shome);

        let run_git = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .args(args)
                .current_dir(&repo)
                .output()
                .unwrap();
            assert!(out.status.success(), "git {:?} failed", args);
        };
        run_git(&["init"]);
        run_git(&["config", "user.email", "t@example.com"]);
        run_git(&["config", "user.name", "Tester"]);
        run_git(&["config", "core.autocrlf", "false"]);
        fs::write(repo.join(".gitattributes"), "*.sh text eol=lf\n").unwrap();
        let script_file = repo.join("deploy.sh");
        fs::write(&script_file, "#!/bin/sh\necho ok\n").unwrap();
        let src_dir = repo.join("rust").join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let crlf_helper = src_dir.join("helper_crlf.rs");
        fs::write(&crlf_helper, "pub fn h() -> i32 { 1 }\r\n").unwrap();
        let src_file = src_dir.join("auth.rs");
        fs::write(&src_file, "pub fn v() -> i32 { 1 }\n").unwrap();
        run_git(&[
            "add",
            ".gitattributes",
            "deploy.sh",
            "rust/src/auth.rs",
            "rust/src/helper_crlf.rs",
        ]);
        run_git(&["commit", "-m", "init"]);
        fs::write(&crlf_helper, "pub fn h() -> i32 { 1 }\r\n").unwrap();

        fs::write(&src_file, "pub fn v() -> i32 { 2 }\n").unwrap();
        let src_norm = rio::normalize_path(&src_file.to_string_lossy());
        let fp_r1 = cwg_common::content_fingerprint(
            std::slice::from_ref(&src_norm),
            cwg_common::MAX_FINGERPRINT_FILE_BYTES,
        );
        let sess = "sess-r3-crlf-outside";
        let t_first = rio::parse_iso_ts("2026-11-20T10:00:00Z");
        let t_edit1 = rio::parse_iso_ts("2026-11-20T10:01:00Z");
        let repo_str = repo.to_string_lossy().into_owned();
        let mpath = cwg_common::marker_path(sess);
        let marker_r1 = json!({
            "session": sess,
            "closed": false,
            "first_ts": t_first,
            "last_durable_ts": t_edit1,
            "last_ts": t_edit1,
            "edits": 1,
            "cwd": rio::normalize_path(&repo_str),
            "git_root": rio::normalize_path(&repo_str),
            "paths": [src_norm.clone()],
            "declared_risk": "HIGH",
            "diff_metrics": {"files_count": 1, "total_lines": 4},
            "round_id": 1,
            "round_start_msg_id": 1,
            "current_diff_hash": fp_r1,
            "content_marks": [{"ts": t_edit1, "fp": fp_r1, "cause": "edit_file"}],
        });
        rio::write_json(&mpath, &marker_r1).unwrap();
        let tp = setup_neon_session_env(
            &brain,
            sess,
            "",
            json!({"members": {}}),
            &[],
            &[],
        );
        let tp_str = tp.to_string_lossy().into_owned();
        let script_norm = rio::normalize_path(&script_file.to_string_lossy());
        let helper_norm = rio::normalize_path(&crlf_helper.to_string_lossy());
        let paths_r2 =
            cwg_common::durable_paths(&[src_norm.clone(), script_norm.clone(), helper_norm.clone()]);
        let fp_r2 =
            cwg_common::content_fingerprint(&paths_r2, cwg_common::MAX_FINGERPRINT_FILE_BYTES);
        let t_edit2 = rio::parse_iso_ts("2026-11-20T10:09:00Z");
        let mut marker_r2 = marker_r1.clone();
        marker_r2["paths"] = json!(paths_r2);
        marker_r2["last_durable_ts"] = json!(t_edit2);
        marker_r2["last_ts"] = json!(t_edit2);
        marker_r2["current_diff_hash"] = json!(fp_r2);
        marker_r2["content_marks"] = json!([{"ts": t_edit2, "fp": fp_r2, "cause": "edit_file"}]);
        rio::write_json(&mpath, &marker_r2).unwrap();

        let checks_ok = ChecksEvidence {
            checks_count: 1,
            passed_count: 1,
            latest_pass_ts: t_edit2 + 10.0,
            ..Default::default()
        };
        let sub_empty = SubagentEvidence::default();
        let sw_ev = scan_swarm_activity_with_reset(SwarmScanInput {
            steps: &[],
            transcript_path: Some(&tp_str),
            first_ts: t_first,
            round_start_msg_id: 1,
            current_diff_hash: &fp_r2,
            cwd: &repo_str,
            research_reset_ts: 0.0,
            research_reset_seq: 0,
            marker: Some(&marker_r2),
        });
        let four_revise: Vec<Value> = (1..=4)
            .map(|i| {
                let lts = t_edit2 + 20.0 + (i as f64) * 5.0;
                json!({
                    "review_id": format!("cwg-4rev-{}", i),
                    "kind": "ordinary",
                    "verdict": "REVISE",
                    "engine": "codex",
                    "xhigh": false,
                    "launch_ts": lts,
                    "verdict_ts": lts + 1.0,
                })
            })
            .collect();
        let rcp_verified = cwg_common::parse_terminal_receipt("[gate] verified: HIGH; candidate").unwrap();
        let (ok_ver, _) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&rcp_verified),
            marker_in: &marker_r2,
            checks_ev: &checks_ok,
            sub_ev: &sub_empty,
            swarm_ev: &sw_ev,
            codex_reviews: &four_revise,
            ctx: None,
            steps: None,
            transcript_path: Some(&tp_str),
        });
        assert!(!ok_ver, "4x REVISE must reject verified receipt");

        let rcp_draft = cwg_common::parse_terminal_receipt(
            "[gate] draft-blocked: 4/4 ordinary rounds returned REVISE without ESCALATE",
        )
        .unwrap();
        let (ok_draft, kind_draft) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&rcp_draft),
            marker_in: &marker_r2,
            checks_ev: &checks_ok,
            sub_ev: &sub_empty,
            swarm_ev: &sw_ev,
            codex_reviews: &four_revise,
            ctx: None,
            steps: None,
            transcript_path: Some(&tp_str),
        });
        assert!(
            ok_draft && kind_draft == "draft-blocked",
            "4x REVISE without ESCALATE must accept terminal draft-blocked: ({}, {})",
            ok_draft,
            kind_draft
        );

        // INVARIANT (Codex Round-1 #6 & #7): Premature/pre-research closure passes are excluded from `effective_cycle_closure`, so they neither block a post-APPROVED cycle reset (#6) nor consume closure budget / pin `res_until_ts` before verified post-ESCALATE research (#7).
        {
            let iso = |ts: f64| crate::win32_sqlite::format_iso_utc(ts);
            let mut m_r6 = marker_r2.clone();
            m_r6["first_ts"] = json!(1000.0);
            m_r6["last_ts"] = json!(1050.0);
            m_r6["last_durable_ts"] = json!(1050.0);
            m_r6["gate_max_review_rounds"] = json!(cwg_common::MAX_ORDINARY_REVIEW_ROUNDS);
            m_r6["content_marks"] = json!([
                {"ts": 1000.0, "fp": "fp-v1", "unknown": false},
                {"ts": 1050.0, "fp": "fp-v2", "unknown": false},
            ]);
            m_r6["current_diff_hash"] = json!("fp-v2");
            let sw_r6 = SwarmEvidence::default();
            let r6_reviews = vec![
                json!({"review_id": "r6-1", "kind": "ordinary", "verdict": "REVISE", "engine": "codex", "xhigh": false, "launch_ts": 1010.0, "verdict_ts": 1012.0}),
                json!({"review_id": "r6-prem-cls", "kind": "closure", "verdict": "BLOCKED", "engine": "codex", "xhigh": false, "launch_ts": 1015.0, "verdict_ts": 1016.0}),
                json!({"review_id": "r6-2", "kind": "ordinary", "verdict": "REVISE", "engine": "codex", "xhigh": false, "launch_ts": 1020.0, "verdict_ts": 1022.0}),
                json!({"review_id": "r6-3", "kind": "ordinary", "verdict": "REVISE", "engine": "codex", "xhigh": false, "launch_ts": 1030.0, "verdict_ts": 1032.0}),
                json!({"review_id": "r6-4", "kind": "ordinary", "verdict": "APPROVED", "engine": "codex", "xhigh": false, "launch_ts": 1040.0, "verdict_ts": 1042.0}),
                json!({"review_id": "r6-post-edit-1", "kind": "ordinary", "verdict": "APPROVED", "engine": "codex", "xhigh": false, "launch_ts": 1060.0, "verdict_ts": 1062.0}),
            ];
            let chk_r6 = ChecksEvidence {
                checks_count: 1,
                passed_count: 1,
                latest_pass_ts: 1055.0,
                ..Default::default()
            };
            let (ok_r6, why_r6) = validate_candidate_closure(CandidateClosureInput {
                receipt: Some(&rcp_verified),
                marker_in: &m_r6,
                checks_ev: &chk_r6,
                sub_ev: &sub_empty,
                swarm_ev: &sw_r6,
                codex_reviews: &r6_reviews,
                ctx: None,
                steps: None,
                transcript_path: None,
            });
            assert!(
                ok_r6,
                "filtered premature closure pass must not block post-APPROVED cycle reset, got: {}",
                why_r6
            );
            // #6 (late verdict): premature closure pass launched BEFORE Round-4 APPROVED (1015.0) whose BLOCKED verdict arrives AFTER Round-4 APPROVED (1045.0) must still preserve pending_reset_ts for the post-edit round.
            let mut r6_late_reviews = r6_reviews.clone();
            r6_late_reviews[1]["verdict_ts"] = json!(1045.0);
            let (ok_r6_late, why_r6_late) = validate_candidate_closure(CandidateClosureInput {
                receipt: Some(&rcp_verified),
                marker_in: &m_r6,
                checks_ev: &chk_r6,
                sub_ev: &sub_empty,
                swarm_ev: &sw_r6,
                codex_reviews: &r6_late_reviews,
                ctx: None,
                steps: None,
                transcript_path: None,
            });
            assert!(
                ok_r6_late,
                "late BLOCKED verdict from premature closure pass must not clear post-APPROVED pending_reset_ts, got: {}",
                why_r6_late
            );

            // #7: Round 4 ESCALATE -> pre-research BLOCKED (excluded!) -> verified docs research -> post-research READY -> pr-ready accepted.
            let mut m_r7 = m_r6.clone();
            m_r7["last_ts"] = json!(1000.0);
            m_r7["last_durable_ts"] = json!(1000.0);
            m_r7["content_marks"] = json!([{"ts": 1000.0, "fp": "fp-v1", "unknown": false}]);
            m_r7["current_diff_hash"] = json!("fp-v1");
            let r7_steps = vec![
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": iso(995.0), "content": "fix"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": iso(1060.0), "tool_calls": [{"name": "search_web", "args": {"query": "rust docs"}}]}),
                json!({"step_index": 2, "source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": iso(1061.0), "content": "results"}),
            ];
            let r7_before_post_cls = vec![
                json!({"review_id": "r7-1", "kind": "ordinary", "verdict": "REVISE", "engine": "codex", "xhigh": false, "launch_ts": 1010.0, "verdict_ts": 1012.0}),
                json!({"review_id": "r7-2", "kind": "ordinary", "verdict": "REVISE", "engine": "codex", "xhigh": false, "launch_ts": 1020.0, "verdict_ts": 1022.0}),
                json!({"review_id": "r7-3", "kind": "ordinary", "verdict": "REVISE", "engine": "codex", "xhigh": false, "launch_ts": 1030.0, "verdict_ts": 1032.0}),
                json!({"review_id": "r7-4", "kind": "ordinary", "verdict": "ESCALATE", "engine": "codex", "xhigh": false, "launch_ts": 1040.0, "verdict_ts": 1042.0}),
                json!({"review_id": "r7-pre-res-blk", "kind": "closure", "verdict": "BLOCKED", "engine": "codex", "xhigh": false, "launch_ts": 1050.0, "verdict_ts": 1052.0}),
            ];
            let mut probe_r7 = crate::codex_lane::ClosureCycleSummary::default();
            let _ = validate_candidate_closure_inner(
                CandidateClosureInput {
                    receipt: Some(&rcp_verified),
                    marker_in: &m_r7,
                    checks_ev: &chk_r6,
                    sub_ev: &sub_empty,
                    swarm_ev: &sw_r6,
                    codex_reviews: &r7_before_post_cls,
                    ctx: None,
                    steps: Some(&r7_steps),
                    transcript_path: None,
                },
                Some(&mut probe_r7),
            );
            assert!(probe_r7.has_round_cap_escalate, "probe must observe round-4 ESCALATE");
            assert_eq!(probe_r7.effective_pass_count, 0, "pre-research closure must not consume budget");
            assert_eq!(probe_r7.blocked_count, 0, "pre-research BLOCKED must not count toward halt");
            assert!(
                probe_r7.has_post_escalate_research,
                "pre-research closure must not pin res_until_ts before actual research"
            );
            let mut r7_with_ready = r7_before_post_cls.clone();
            r7_with_ready.push(json!({"review_id": "r7-post-res-ready", "kind": "closure", "verdict": "READY", "engine": "codex", "xhigh": false, "launch_ts": 1070.0, "verdict_ts": 1072.0}));
            let rcp_pr = cwg_common::parse_terminal_receipt("[gate] pr-ready: HIGH; fixed").unwrap();
            let (ok_r7, why_r7) = validate_candidate_closure(CandidateClosureInput {
                receipt: Some(&rcp_pr),
                marker_in: &m_r7,
                checks_ev: &chk_r6,
                sub_ev: &sub_empty,
                swarm_ev: &sw_r6,
                codex_reviews: &r7_with_ready,
                ctx: None,
                steps: Some(&r7_steps),
                transcript_path: None,
            });
            assert!(
                ok_r7,
                "post-research closure READY must succeed despite earlier pre-research BLOCKED, got: {}",
                why_r7
            );

            // INVARIANT (Codex Round-2 #8 & Round-3): Legacy v0 `closure_halt` reconciliation distinguishes:
            // (a) incomplete/evicted transcript history (`Incomplete`) -> PRESERVES the legacy v0 halt (prevents reopening closure after evicted research);
            // (b) complete, gap-free transcript proving both `BLOCKED` passes ran BEFORE first research (`ProvenAbsent`) -> RECONCILES (clears) the bogus pre-research halt so post-research `--closure` can run.
            let mut m_r8 = m_r7.clone();
            m_r8["session"] = json!("sess-r8-evicted-no-disk-tx");
            m_r8["closure_halt"] = json!({
                "candidate_first_ts": 1000.0,
                "research_reset_ts": 0.0,
                "round_start_msg_id": 0,
                "blocked_count": 2,
                "last_blocked_ts": 1056.0,
                "blocked_review_ids": ["r8-blk-1", "r8-blk-2"],
            });
            let r8_reviews = vec![
                json!({"review_id": "r8-1", "kind": "ordinary", "verdict": "REVISE", "engine": "codex", "xhigh": false, "launch_ts": 1010.0, "verdict_ts": 1012.0}),
                json!({"review_id": "r8-2", "kind": "ordinary", "verdict": "REVISE", "engine": "codex", "xhigh": false, "launch_ts": 1020.0, "verdict_ts": 1022.0}),
                json!({"review_id": "r8-3", "kind": "ordinary", "verdict": "REVISE", "engine": "codex", "xhigh": false, "launch_ts": 1030.0, "verdict_ts": 1032.0}),
                json!({"review_id": "r8-4", "kind": "ordinary", "verdict": "ESCALATE", "engine": "codex", "xhigh": false, "launch_ts": 1040.0, "verdict_ts": 1042.0}),
                json!({"review_id": "r8-blk-1", "kind": "closure", "verdict": "BLOCKED", "engine": "codex", "xhigh": false, "launch_ts": 1050.0, "verdict_ts": 1052.0}),
                json!({"review_id": "r8-blk-2", "kind": "closure", "verdict": "BLOCKED", "engine": "codex", "xhigh": false, "launch_ts": 1054.0, "verdict_ts": 1056.0}),
            ];
            // (a) Evicted/incomplete transcript (`step_index` gap + earliest after ESCALATE, no transcript_path): legacy v0 halt MUST be preserved.
            let r8_evicted_steps = vec![
                json!({"step_index": 50, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": iso(1060.0), "tool_calls": [{"name": "search_web", "args": {"query": "later docs"}}]}),
                json!({"step_index": 51, "source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": iso(1061.0), "content": "results"}),
            ];
            let mut probe_r8_inc = crate::codex_lane::ClosureCycleSummary::default();
            let _ = validate_candidate_closure_inner(
                CandidateClosureInput {
                    receipt: Some(&rcp_verified),
                    marker_in: &m_r8,
                    checks_ev: &chk_r6,
                    sub_ev: &sub_empty,
                    swarm_ev: &sw_r6,
                    codex_reviews: &r8_reviews,
                    ctx: None,
                    steps: Some(&r8_evicted_steps),
                    transcript_path: None,
                },
                Some(&mut probe_r8_inc),
            );
            assert_eq!(
                probe_r8_inc.blocked_count, 2,
                "evicted/incomplete transcript history must preserve a phase-eligible legacy v0 closure_halt"
            );
            assert_eq!(probe_r8_inc.live_blocked_count, 0);
            let (ok_r8_inc, why_r8_inc) = validate_candidate_closure(CandidateClosureInput {
                receipt: Some(&rcp_verified),
                marker_in: &m_r8,
                checks_ev: &chk_r6,
                sub_ev: &sub_empty,
                swarm_ev: &sw_r6,
                codex_reviews: &r8_reviews,
                ctx: None,
                steps: Some(&r8_evicted_steps),
                transcript_path: None,
            });
            assert!(
                !ok_r8_inc && why_r8_inc.contains("2/2"),
                "preserved legacy v0 closure_halt under evicted history must block verified closure, got: ({}, {})",
                ok_r8_inc,
                why_r8_inc
            );

            // (b) Complete, gap-free transcript on disk proving both BLOCKED passes preceded the first research (at 1060.0): legacy v0 halt MUST reconcile away so post-research closure is admitted.
            let r8_logs_dir = brain
                .join("sess-r8-full")
                .join(".system_generated")
                .join("logs");
            fs::create_dir_all(&r8_logs_dir).unwrap();
            let tp_r8_full = r8_logs_dir.join("transcript_full.jsonl");
            fs::write(
                &tp_r8_full,
                r7_steps
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n",
            )
            .unwrap();
            let tp_r8_str = tp_r8_full.to_string_lossy().into_owned();
            let mut probe_r8_full = crate::codex_lane::ClosureCycleSummary::default();
            let _ = validate_candidate_closure_inner(
                CandidateClosureInput {
                    receipt: Some(&rcp_verified),
                    marker_in: &m_r8,
                    checks_ev: &chk_r6,
                    sub_ev: &sub_empty,
                    swarm_ev: &sw_r6,
                    codex_reviews: &r8_reviews,
                    ctx: None,
                    steps: None,
                    transcript_path: Some(&tp_r8_str),
                },
                Some(&mut probe_r8_full),
            );
            assert_eq!(
                probe_r8_full.blocked_count, 0,
                "complete gap-free transcript proving both BLOCKED passes preceded first research must clear legacy v0 closure_halt"
            );
            assert!(
                probe_r8_full.has_post_escalate_research,
                "post-ESCALATE research at 1060.0 must unlock the first legitimate closure pass"
            );

            // (c) Codex Round-4 #1: `truncated_fields: ["content"]` on an unrelated command 30s AFTER the checked closure launches (`1086.0 > 1055.0`) MUST NOT taint `ProvenAbsent` (neither in-memory nor in compact transcript file).
            let mut r8_post_trunc_steps = r7_steps.clone();
            r8_post_trunc_steps.push(json!({
                "step_index": 3,
                "source": "GENERIC",
                "type": "GENERIC",
                "status": "DONE",
                "created_at": iso(1086.0),
                "content": "later long output",
                "truncated_fields": ["content"]
            }));
            let r8_compact_dir = brain
                .join("sess-r8-post-trunc")
                .join(".system_generated")
                .join("logs");
            fs::create_dir_all(&r8_compact_dir).unwrap();
            let tp_r8_compact = r8_compact_dir.join("transcript.jsonl");
            fs::write(
                &tp_r8_compact,
                r8_post_trunc_steps
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n",
            )
            .unwrap();
            let tp_r8_compact_str = tp_r8_compact.to_string_lossy().into_owned();
            for (mem_steps, disk_tp, label) in [
                (Some(r8_post_trunc_steps.as_slice()), None, "in-memory"),
                (None, Some(tp_r8_compact_str.as_str()), "compact-file"),
            ] {
                let mut probe_trunc = crate::codex_lane::ClosureCycleSummary::default();
                let _ = validate_candidate_closure_inner(
                    CandidateClosureInput {
                        receipt: Some(&rcp_verified),
                        marker_in: &m_r8,
                        checks_ev: &chk_r6,
                        sub_ev: &sub_empty,
                        swarm_ev: &sw_r6,
                        codex_reviews: &r8_reviews,
                        ctx: None,
                        steps: mem_steps,
                        transcript_path: disk_tp,
                    },
                    Some(&mut probe_trunc),
                );
                assert_eq!(
                    probe_trunc.blocked_count, 0,
                    "out-of-window truncation at +30s ({}) must not prevent reconciling pre-research legacy v0 halt",
                    label
                );
                assert!(probe_trunc.has_post_escalate_research);
            }

            // (d) Codex Round-4 #2: Internal `step_index` gap (`0, 1, 4, 5` with `2, 3` missing in the middle) MUST be classified `Incomplete` (NOT `ProvenAbsent`) both in-memory and from disk, preserving valid legacy v0 halt; out-of-order adjacent writes (`0, 1, 3, 2` with no missing indices) remain `ProvenAbsent`.
            let r8_mid_gap_steps = vec![
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": iso(995.0), "content": "fix"}),
                json!({"step_index": 1, "source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": iso(1040.0), "content": "before"}),
                json!({"step_index": 4, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": iso(1060.0), "tool_calls": [{"name": "search_web", "args": {"query": "later docs"}}]}),
                json!({"step_index": 5, "source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": iso(1061.0), "content": "results"}),
            ];
            let r8_gap_dir = brain
                .join("sess-r8-mid-gap")
                .join(".system_generated")
                .join("logs");
            fs::create_dir_all(&r8_gap_dir).unwrap();
            let tp_r8_gap = r8_gap_dir.join("transcript_full.jsonl");
            fs::write(
                &tp_r8_gap,
                r8_mid_gap_steps
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n",
            )
            .unwrap();
            let tp_r8_gap_str = tp_r8_gap.to_string_lossy().into_owned();
            for (mem_steps, disk_tp, label) in [
                (Some(r8_mid_gap_steps.as_slice()), None, "in-memory"),
                (None, Some(tp_r8_gap_str.as_str()), "disk-file"),
            ] {
                let mut probe_gap = crate::codex_lane::ClosureCycleSummary::default();
                let _ = validate_candidate_closure_inner(
                    CandidateClosureInput {
                        receipt: Some(&rcp_verified),
                        marker_in: &m_r8,
                        checks_ev: &chk_r6,
                        sub_ev: &sub_empty,
                        swarm_ev: &sw_r6,
                        codex_reviews: &r8_reviews,
                        ctx: None,
                        steps: mem_steps,
                        transcript_path: disk_tp,
                    },
                    Some(&mut probe_gap),
                );
                assert_eq!(
                    probe_gap.blocked_count, 2,
                    "internal step_index gap 0,1,4,5 ({}) must preserve legacy v0 closure_halt",
                    label
                );
            }
            // (e) Codex Closure Pass 1 regression: Out-of-order `0, 1, 3, 2` inside the window (where `GENERIC` result step `3` precedes `PLANNER_RESPONSE` `search_web` step `2` in `(1042.0, 1050.0]`) MUST fail closed to `Incomplete` (NEVER `ProvenAbsent`) both in-memory and from disk, preserving valid legacy v0 `closure_halt`.
            let r8_ooo_research = vec![
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": iso(995.0), "content": "fix"}),
                json!({"step_index": 1, "source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": iso(1040.0), "content": "before"}),
                json!({"step_index": 3, "source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": iso(1046.0), "content": "official docs result"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": iso(1045.0), "tool_calls": [{"name": "search_web", "args": {"query": "rust docs"}}]}),
                json!({"step_index": 4, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": iso(1060.0), "tool_calls": [{"name": "search_web", "args": {"query": "later docs"}}]}),
                json!({"step_index": 5, "source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": iso(1061.0), "content": "later results"}),
            ];
            let r8_ooo_dir = brain
                .join("sess-r8-ooo")
                .join(".system_generated")
                .join("logs");
            fs::create_dir_all(&r8_ooo_dir).unwrap();
            let tp_r8_ooo = r8_ooo_dir.join("transcript_full.jsonl");
            fs::write(
                &tp_r8_ooo,
                r8_ooo_research
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n",
            )
            .unwrap();
            let tp_r8_ooo_str = tp_r8_ooo.to_string_lossy().into_owned();
            assert_eq!(
                cwg_common::research_status_between(Some(&r8_ooo_research), None, 1042.0, 1050.0),
                cwg_common::ResearchWindowStatus::Incomplete
            );
            assert_eq!(
                cwg_common::research_status_between(None, Some(&tp_r8_ooo_str), 1042.0, 1050.0),
                cwg_common::ResearchWindowStatus::Incomplete
            );
            for (mem_steps, disk_tp, label) in [
                (Some(r8_ooo_research.as_slice()), None, "in-memory"),
                (None, Some(tp_r8_ooo_str.as_str()), "disk-file"),
            ] {
                let mut probe_ooo = crate::codex_lane::ClosureCycleSummary::default();
                let _ = validate_candidate_closure_inner(
                    CandidateClosureInput {
                        receipt: Some(&rcp_verified),
                        marker_in: &m_r8,
                        checks_ev: &chk_r6,
                        sub_ev: &sub_empty,
                        swarm_ev: &sw_r6,
                        codex_reviews: &r8_reviews,
                        ctx: None,
                        steps: mem_steps,
                        transcript_path: disk_tp,
                    },
                    Some(&mut probe_ooo),
                );
                assert_eq!(
                    probe_ooo.blocked_count, 2,
                    "out-of-order 0,1,3,2 research pair ({}) must return Incomplete and preserve legacy v0 closure_halt",
                    label
                );
            }
        }

        match prev_home {
            Some(v) => std::env::set_var("CARBON_STACK_HOME", v),
            None => std::env::remove_var("CARBON_STACK_HOME"),
        }
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_anom_82fa8544_uncovered_full_prepare_and_truncated_models_recovery() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!(
            "cwg-anom-82fa8544-{}-{}",
            std::process::id(),
            (now_sec() * 1000.0) as u64
        ));
        let _ = fs::remove_dir_all(&tmp);
        let shome = tmp.join("stack_home");
        let brain = tmp.join("brain");
        let repo = tmp.join("repo");
        fs::create_dir_all(repo.join("rust/src")).unwrap();
        let prev_home = std::env::var("CARBON_STACK_HOME").ok();
        std::env::set_var("CARBON_STACK_HOME", &shome);

        let repo_str = rio::normalize_path(&repo.to_string_lossy());
        let run_git = |args: &[&str]| {
            let (rc, out, err) = rio::run_git(&repo_str, args, 10.0);
            assert_eq!(rc, 0, "git {:?} failed: {} {}", args, out, err);
        };
        run_git(&["init"]);
        run_git(&["config", "user.email", "t@example.com"]);
        run_git(&["config", "user.name", "Test"]);
        let src_file = repo.join("rust/src/auth.rs");
        fs::write(&src_file, "pub fn v() -> i32 { 1 }\n").unwrap();
        run_git(&["add", "."]);
        run_git(&["commit", "-m", "init"]);

        // Mutate tracked HIGH file + an external file outside git_root so full-repo prepare fails uncovered.
        fs::write(&src_file, "pub fn v() -> i32 { 2 }\n").unwrap();
        let outside_file = tmp.join("outside_notes.rs");
        fs::write(&outside_file, "pub fn ext() {}\n").unwrap();
        let src_norm = rio::normalize_path(&src_file.to_string_lossy());
        let out_norm = rio::normalize_path(&outside_file.to_string_lossy());

        let sess = "sess-anom-82fa8544";
        let skey = rio::safe_key(sess, "default");
        let mpath = cwg_common::marker_path(&skey);
        let t_first = rio::parse_iso_ts("2026-11-21T04:00:00Z");
        let t_prep = rio::parse_iso_ts("2026-11-21T04:01:00Z");
        let t_models = rio::parse_iso_ts("2026-11-21T04:02:00Z");
        let t_sim_start = rio::parse_iso_ts("2026-11-21T04:03:00Z");
        let t_edit_post = rio::parse_iso_ts("2026-11-21T04:05:00Z");
        let iso = |ts: f64| crate::win32_sqlite::format_iso_utc(ts);

        let m_init = json!({
            "session": sess,
            "git_root": repo_str,
            "cwd": repo_str,
            "first_ts": t_first,
            "last_ts": t_first + 5.0,
            "last_durable_ts": t_first + 5.0,
            "round_start_msg_id": 0,
            "edits": 2,
            "risk": "HIGH",
            "paths": [src_norm.clone(), out_norm.clone()],
            "current_diff_hash": "",
            "content_marks": [
                {"ts": t_first + 2.0, "fp": "aaaa111122223333", "cause": "edit_file"},
                {"ts": t_first + 5.0, "fp": Value::Null, "cause": "stop_catchup_unmeasured_edit"}
            ],
            "gate_max_review_rounds": cwg_common::MAX_ORDINARY_REVIEW_ROUNDS,
        });
        rio::write_json(&mpath, &m_init).unwrap();

        // 1) Fresh full-repo `swarm-cache prepare` (paths: &[]) fails uncovered WITHOUT poisoning marker/rounds.json, and explicitly reports `direct_read_allowed: true`.
        let prep_fail = crate::swarm_cache::prepare_round(crate::swarm_cache::PrepareRoundInput {
            session: sess,
            cwd: &repo_str,
            brain_root: &brain,
            label: "simplify",
            ttl_seconds: 270,
            paths: &[],
            reset: false,
            now_ts: Some(t_prep),
        });
        assert_eq!(prep_fail["ok"], json!(false));
        assert_eq!(prep_fail["candidate_diff_covered"], json!(false));
        assert_eq!(prep_fail["direct_read_allowed"], json!(true));
        assert_eq!(prep_fail["error"], json!("partial_or_uncovered_candidate_diff"));
        let m_after_prep = rio::read_json(&mpath).unwrap();
        assert!(
            !cwg_common::marker_has_prepare_cycle(Some(&m_after_prep)),
            "fresh full-repo uncovered prepare must not stamp swarm_prepare_cycle_ts"
        );
        assert!(
            !cwg_common::swarm_rounds_path(&skey).exists(),
            "fresh full-repo uncovered prepare must not poison swarm_rounds/<session>.json"
        );
        let (req_after, _) = cwg_common::swarm_prepare_hash_policy(sess, Some(&m_after_prep), "");
        assert!(
            !req_after,
            "fresh full-repo uncovered prepare must keep require_explicit_hash_match=false for direct file reading"
        );

        // 2) Truncated compact transcript.jsonl (`swarm(action="models", all=true)` quotas chopped off) hydrated from sibling transcript_full.jsonl.
        let compact_models_step = json!({
            "step_index": 5,
            "source": "MODEL",
            "type": "GENERIC",
            "status": "DONE",
            "created_at": iso(t_models + 1.0),
            "content": "{\"models\":[\"claude-sonnet-5-5-high\",\"gemini-4-neon-xhigh\"]...TRUNCATED",
            "truncated_fields": ["content"]
        });
        let full_models_step = json!({
            "step_index": 5,
            "source": "MODEL",
            "type": "GENERIC",
            "status": "DONE",
            "created_at": iso(t_models + 1.0),
            "content": "{\"models\":[\"claude-sonnet-5-5-high\",\"gemini-4-neon-xhigh\"],\"quotas\":{\"claude-sonnet-5-5-high\":{\"quota_remaining\":\"0%\"},\"gemini-4-neon-xhigh\":{\"quota_remaining\":\"90%\"}}}"
        });
        let models_call_step = json!({
            "step_index": 4,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": iso(t_models),
            "tool_calls": [{"name": "swarm", "args": {"action": "models", "all": true}}]
        });
        let compact_tx = format!("{}\n{}\n", models_call_step, compact_models_step);
        let full_tx = format!("{}\n{}\n", models_call_step, full_models_step);

        let tp_full = setup_neon_session_env(
            &brain,
            sess,
            &full_tx,
            json!({
                "members": {
                    "simplify-reuse": {"role": "worker", "conversation_id": "cid-82f-r", "model": cwg_common::NEON_XHIGH_MODEL, "killed": true},
                    "simplify-quality": {"role": "worker", "conversation_id": "cid-82f-q", "model": cwg_common::NEON_XHIGH_MODEL, "killed": true},
                    "simplify-efficiency": {"role": "worker", "conversation_id": "cid-82f-e", "model": cwg_common::NEON_XHIGH_MODEL, "killed": true},
                }
            }),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": iso(t_sim_start), "text": "@simplify-reuse direct review"}),
                json!({"seq": 2, "agent": "coordinator", "time": iso(t_sim_start + 1.0), "text": "@simplify-quality direct review"}),
                json!({"seq": 3, "agent": "coordinator", "time": iso(t_sim_start + 2.0), "text": "@simplify-efficiency direct review"}),
                json!({"seq": 4, "agent": "simplify-reuse", "time": iso(t_sim_start + 20.0), "text": "@coordinator\nSIMPLIFY_LENS: REUSE\nSIMPLIFY_VERDICT: ACTIONABLE_FIXES"}),
                json!({"seq": 5, "agent": "simplify-quality", "time": iso(t_sim_start + 25.0), "text": "@coordinator\nSIMPLIFY_LENS: QUALITY\nSIMPLIFY_VERDICT: ACTIONABLE_FIXES"}),
                json!({"seq": 6, "agent": "simplify-efficiency", "time": iso(t_sim_start + 30.0), "text": "@coordinator\nSIMPLIFY_LENS: EFFICIENCY\nSIMPLIFY_VERDICT: ACTIONABLE_FIXES"}),
            ],
            &[
                ("cid-82f-r", &[json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": iso(t_sim_start)})]),
                ("cid-82f-q", &[json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": iso(t_sim_start + 1.0)})]),
                ("cid-82f-e", &[json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": iso(t_sim_start + 2.0)})]),
            ],
        );
        fs::write(tp_full.with_file_name("transcript.jsonl"), &compact_tx).unwrap();
        let tp_full_str = tp_full.to_string_lossy().into_owned();

        // 3) Post-simplify durable edit (still unmeasured `fp: null`) + 4 ordinary rounds (ESCALATE) + research + 2/2 closure BLOCKED -> `[gate] draft-blocked` accepted!
        let mut m_post = m_after_prep.clone();
        m_post["last_ts"] = json!(t_edit_post);
        m_post["last_durable_ts"] = json!(t_edit_post);
        m_post["content_marks"]
            .as_array_mut()
            .unwrap()
            .push(json!({"ts": t_edit_post, "fp": Value::Null, "cause": "edit_file"}));
        rio::write_json(&mpath, &m_post).unwrap();

        // Simulate >4000-step eviction so `recover_compact_swarm_steps` must hydrate step 5 from `transcript_full.jsonl`.
        let tail_steps = vec![
            json!({"step_index": 5000, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": iso(t_edit_post + 45.0), "tool_calls": [{"name": "search_web", "args": {"query": "wechat runtime"}}]}),
            json!({"step_index": 5001, "source": "MODEL", "type": "GENERIC", "status": "DONE", "created_at": iso(t_edit_post + 46.0), "content": "docs"}),
        ];
        let sw_ev = scan_swarm_activity_with_reset(SwarmScanInput {
            steps: &tail_steps,
            transcript_path: Some(&tp_full_str),
            first_ts: t_first,
            round_start_msg_id: 0,
            current_diff_hash: "",
            cwd: &repo_str,
            research_reset_ts: 0.0,
            research_reset_seq: 0,
            marker: Some(&m_post),
        });
        assert!(
            sw_ev.sonnet_issue_verified,
            "truncated compact models(all=true) must hydrate quotas from transcript_full.jsonl"
        );

        let reviews = vec![
            json!({"review_id": "cwg-82f-1", "kind": "ordinary", "verdict": "REVISE", "engine": "codex", "xhigh": false, "launch_ts": t_edit_post + 10.0, "verdict_ts": t_edit_post + 11.0}),
            json!({"review_id": "cwg-82f-2", "kind": "ordinary", "verdict": "REVISE", "engine": "codex", "xhigh": false, "launch_ts": t_edit_post + 20.0, "verdict_ts": t_edit_post + 21.0}),
            json!({"review_id": "cwg-82f-3", "kind": "ordinary", "verdict": "REVISE", "engine": "codex", "xhigh": false, "launch_ts": t_edit_post + 30.0, "verdict_ts": t_edit_post + 31.0}),
            json!({"review_id": "cwg-82f-4", "kind": "ordinary", "verdict": "ESCALATE", "engine": "codex", "xhigh": false, "launch_ts": t_edit_post + 40.0, "verdict_ts": t_edit_post + 41.0}),
            json!({"review_id": "cwg-82f-c1", "kind": "closure", "verdict": "BLOCKED", "engine": "codex", "xhigh": false, "launch_ts": t_edit_post + 50.0, "verdict_ts": t_edit_post + 51.0}),
            json!({"review_id": "cwg-82f-c2", "kind": "closure", "verdict": "BLOCKED", "engine": "codex", "xhigh": false, "launch_ts": t_edit_post + 60.0, "verdict_ts": t_edit_post + 61.0}),
        ];
        let chk_ok = ChecksEvidence {
            checks_count: 1,
            passed_count: 1,
            latest_pass_ts: t_edit_post + 5.0,
            ..Default::default()
        };
        let rcp_draft = cwg_common::parse_terminal_receipt(
            "[gate] draft-blocked: 2/2 closure passes blocked after 4 ordinary rounds",
        )
        .unwrap();
        let (ok_draft, why_draft) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&rcp_draft),
            marker_in: &m_post,
            checks_ev: &chk_ok,
            sub_ev: &SubagentEvidence::default(),
            swarm_ev: &sw_ev,
            codex_reviews: &reviews,
            ctx: None,
            steps: Some(&tail_steps),
            transcript_path: Some(&tp_full_str),
        });
        assert!(
            ok_draft && why_draft == "draft-blocked",
            "anom-82fa8544 flow must accept terminal [gate] draft-blocked: ({}, {})",
            ok_draft,
            why_draft
        );

        // 5) Security counter-check (Codex #2): fresh full-repo covered `prepare` hitting a `swarm_rounds` write failure must NOT leave `swarm_prepare_cycle_ts` stamped on marker.
        let sess_rw = "sess-anom-82f-rounds-lock";
        let skey_rw = rio::safe_key(sess_rw, "default");
        let mpath_rw = cwg_common::marker_path(&skey_rw);
        let rpath_rw = cwg_common::swarm_rounds_path(&skey_rw);
        let fp_src = cwg_common::content_fingerprint(
            &[src_norm.clone()],
            cwg_common::MAX_FINGERPRINT_FILE_BYTES,
        );
        rio::write_json(
            &mpath_rw,
            &json!({
                "session": sess_rw,
                "git_root": repo_str,
                "cwd": repo_str,
                "first_ts": t_first,
                "last_ts": t_first + 5.0,
                "last_durable_ts": t_first + 5.0,
                "edits": 1,
                "risk": "HIGH",
                "paths": [src_norm.clone()],
                "current_diff_hash": fp_src,
                "content_marks": [{"ts": t_first + 5.0, "fp": fp_src, "cause": "edit_file"}],
            }),
        )
        .unwrap();
        rio::write_json(
            &rpath_rw,
            &json!({"session": sess_rw, "marker_first_ts": 1.0, "lanes": {}}),
        )
        .unwrap();
        let prep_rw = {
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                let pinned = fs::OpenOptions::new()
                    .read(true)
                    .share_mode(0x0000_0001)
                    .open(&rpath_rw)
                    .unwrap();
                let res = crate::swarm_cache::prepare_round(crate::swarm_cache::PrepareRoundInput {
                    session: sess_rw,
                    cwd: &repo_str,
                    brain_root: &brain,
                    label: "simplify",
                    ttl_seconds: 270,
                    paths: &[],
                    reset: false,
                    now_ts: Some(t_prep),
                });
                drop(pinned);
                res
            }
            #[cfg(unix)]
            {
                fs::remove_file(&rpath_rw).unwrap();
                fs::create_dir_all(&rpath_rw).unwrap();
                let res = crate::swarm_cache::prepare_round(crate::swarm_cache::PrepareRoundInput {
                    session: sess_rw,
                    cwd: &repo_str,
                    brain_root: &brain,
                    label: "simplify",
                    ttl_seconds: 270,
                    paths: &[],
                    reset: false,
                    now_ts: Some(t_prep),
                });
                let _ = fs::remove_dir_all(&rpath_rw);
                res
            }
        };
        assert_eq!(prep_rw["ok"], json!(false));
        assert!(
            !cwg_common::marker_has_prepare_cycle(rio::read_json(&mpath_rw).as_ref()),
            "failed rounds.json commit on fresh full-repo prepare must not leave swarm_prepare_cycle_ts stamped on marker"
        );
        let _ = fs::remove_file(&rpath_rw);

        // 6) Contract counter-checks (Codex #3 & #4): partial `--paths` prepare returns `direct_read_allowed: false`; under active `prepare`, fresh `ACTIONABLE_FIXES` without `DIFF_HASH` revokes earlier `CLEAN` without crediting lenses.
        let sess_af = "sess-anom-82f-unhashed-af";
        let skey_af = rio::safe_key(sess_af, "default");
        let mpath_af = cwg_common::marker_path(&skey_af);
        rio::write_json(
            &mpath_af,
            &json!({
                "session": sess_af,
                "git_root": repo_str,
                "cwd": repo_str,
                "first_ts": t_first,
                "last_ts": t_first + 5.0,
                "last_durable_ts": t_first + 5.0,
                "edits": 1,
                "risk": "HIGH",
                "paths": [src_norm.clone()],
                "current_diff_hash": fp_src,
                "content_marks": [{"ts": t_first + 5.0, "fp": fp_src, "cause": "edit_file"}],
            }),
        )
        .unwrap();
        let prep_af_ok = crate::swarm_cache::prepare_round(crate::swarm_cache::PrepareRoundInput {
            session: sess_af,
            cwd: &repo_str,
            brain_root: &brain,
            label: "simplify",
            ttl_seconds: 270,
            paths: &[],
            reset: false,
            now_ts: Some(t_prep),
        });
        assert_eq!(prep_af_ok["ok"], json!(true));
        let prep_af_partial =
            crate::swarm_cache::prepare_round(crate::swarm_cache::PrepareRoundInput {
                session: sess_af,
                cwd: &repo_str,
                brain_root: &brain,
                label: "simplify",
                ttl_seconds: 270,
                paths: &["rust/src/auth.rs".to_string()],
                reset: false,
                now_ts: Some(t_prep + 5.0),
            });
        assert_eq!(prep_af_partial["ok"], json!(false));
        assert_eq!(prep_af_partial["direct_read_allowed"], json!(false));
        fs::write(&src_file, "pub fn v() -> i32 { 2 }\n").unwrap();

        // 8) Codex R2/R3/R4 #2: marker persistence failure on fresh full-repo `prepare` must fail before touching `rounds.json` (`DELETE | GENERIC_WRITE` on Windows for both 0x1 and 0x3, non-root `0o444` on Unix), and even an orphaned `require_marker_cycle_ts` rounds.json left by a dual-lock rollback failure must stay inactive until `marker` commits.
        let sess_mp = "sess-anom-82f-marker-lock";
        let skey_mp = rio::safe_key(sess_mp, "default");
        let mpath_mp = cwg_common::marker_path(&skey_mp);
        let rpath_mp = cwg_common::swarm_rounds_path(&skey_mp);
        rio::write_json(
            &mpath_mp,
            &json!({
                "session": sess_mp,
                "git_root": repo_str,
                "cwd": repo_str,
                "first_ts": t_first,
                "last_ts": t_first + 5.0,
                "last_durable_ts": t_first + 5.0,
                "edits": 1,
                "risk": "HIGH",
                "paths": [src_norm.clone()],
                "current_diff_hash": fp_src,
                "content_marks": [{"ts": t_first + 5.0, "fp": fp_src, "cause": "edit_file"}],
            }),
        )
        .unwrap();
        assert!(!rpath_mp.exists());
        #[cfg(windows)]
        let share_modes: &[u32] = &[0x0000_0001, 0x0000_0003];
        #[cfg(unix)]
        let share_modes: &[u32] = &[0];
        for &mode_val in share_modes {
            let prep_mp_opt: Option<Value> = {
                #[cfg(windows)]
                {
                    use std::os::windows::fs::OpenOptionsExt;
                    let pinned = fs::OpenOptions::new()
                        .read(true)
                        .share_mode(mode_val)
                        .open(&mpath_mp)
                        .unwrap();
                    let res =
                        crate::swarm_cache::prepare_round(crate::swarm_cache::PrepareRoundInput {
                            session: sess_mp,
                            cwd: &repo_str,
                            brain_root: &brain,
                            label: "simplify",
                            ttl_seconds: 270,
                            paths: &[],
                            reset: false,
                            now_ts: Some(t_prep),
                        });
                    drop(pinned);
                    Some(res)
                }
                #[cfg(unix)]
                {
                    let _ = mode_val;
                    use std::os::unix::fs::PermissionsExt;
                    let mut perms = fs::metadata(&mpath_mp).unwrap().permissions();
                    let orig_mode = perms.mode();
                    perms.set_mode(0o444);
                    fs::set_permissions(&mpath_mp, perms).unwrap();
                    // WORKAROUND: Skip `0o444` DAC write-denial check under root / `CAP_DAC_OVERRIDE` where open(O_WRONLY) succeeds regardless of file mode.
                    let dac_enforced = fs::OpenOptions::new().write(true).open(&mpath_mp).is_err();
                    let res = if dac_enforced {
                        Some(crate::swarm_cache::prepare_round(
                            crate::swarm_cache::PrepareRoundInput {
                                session: sess_mp,
                                cwd: &repo_str,
                                brain_root: &brain,
                                label: "simplify",
                                ttl_seconds: 270,
                                paths: &[],
                                reset: false,
                                now_ts: Some(t_prep),
                            },
                        ))
                    } else {
                        None
                    };
                    let mut restore = fs::metadata(&mpath_mp).unwrap().permissions();
                    restore.set_mode(orig_mode);
                    let _ = fs::set_permissions(&mpath_mp, restore);
                    res
                }
            };
            if let Some(prep_mp) = prep_mp_opt {
                assert_eq!(prep_mp["ok"], json!(false));
                assert_eq!(prep_mp["direct_read_allowed"], json!(true));
                assert!(
                    val_to_str(prep_mp.get("error")).starts_with("marker_persist_failed:"),
                    "marker write failure (mode={}) must surface marker_persist_failed: {:?}",
                    mode_val,
                    prep_mp
                );
                assert!(
                    !rpath_mp.exists(),
                    "marker_persist_failed (mode={}) on fresh full-repo prepare must leave no rounds.json on disk",
                    mode_val
                );
                assert!(
                    !cwg_common::swarm_prepare_hash_policy(
                        sess_mp,
                        rio::read_json(&mpath_mp).as_ref(),
                        &fp_src
                    )
                    .0,
                    "failed fresh prepare (mode={}) must keep require_explicit_hash_match=false",
                    mode_val
                );
            }
        }
        // Cross-platform (including root/CAP_DAC_OVERRIDE) 2-phase commit proof: an orphaned `rounds.json` carrying `require_marker_cycle_ts` without a committed `marker.swarm_prepare_cycle_ts` must neither require `DIFF_HASH`, expose its `tree_oid`, nor reject `fp_src` after a `HEAD` shift (`git commit --allow-empty`).
        let live_tree_mp = rio::capture_worktree_tree_oid(&repo_str, 10.0);
        let live_head_mp = rio::git_head_oid(&repo_str);
        rio::write_json(
            &rpath_mp,
            &json!({
                "session": sess_mp,
                "marker_first_ts": t_first,
                "require_marker_cycle_ts": t_first,
                "seen_heads": { rio::fold_path(&repo_str): [live_head_mp] },
                "lanes": {
                    format!("{}|simplify", rio::fold_path(&repo_str)): [{
                        "round": 1,
                        "head_oid": live_head_mp,
                        "tree_oid": live_tree_mp,
                        "diff_hash": fp_src,
                        "unfiltered_tree_match": true,
                        "paths": []
                    }]
                }
            }),
        )
        .unwrap();
        let m_mp_disk = rio::read_json(&mpath_mp);
        let (req_uncom, acc_uncom) =
            cwg_common::swarm_prepare_hash_policy(sess_mp, m_mp_disk.as_ref(), &fp_src);
        assert!(
            !req_uncom && acc_uncom == vec![fp_src.clone()],
            "uncommitted require_marker_cycle_ts rounds.json must neither require DIFF_HASH nor expose tree_oid {}: ({}, {:?})",
            live_tree_mp,
            req_uncom,
            acc_uncom
        );
        run_git(&["commit", "--allow-empty", "-m", "shift head without changing candidate"]);
        let (req_uncom_head, acc_uncom_head) =
            cwg_common::swarm_prepare_hash_policy(sess_mp, m_mp_disk.as_ref(), &fp_src);
        assert!(
            !req_uncom_head && acc_uncom_head == vec![fp_src.clone()],
            "uncommitted require_marker_cycle_ts rounds.json must not trigger require_head_bound or reject direct-read fp after HEAD shift: ({}, {:?})",
            req_uncom_head,
            acc_uncom_head
        );
        let _ = fs::remove_file(&rpath_mp);

        // 9) Codex R2 #3: pre-existing `marker_first_ts: 0` rounds.json on disk must yield `direct_read_allowed: false` matching gate policy.
        let sess_pm = "sess-anom-82f-premarker-rounds";
        let skey_pm = rio::safe_key(sess_pm, "default");
        let mpath_pm = cwg_common::marker_path(&skey_pm);
        let rpath_pm = cwg_common::swarm_rounds_path(&skey_pm);
        rio::write_json(
            &mpath_pm,
            &json!({
                "session": sess_pm,
                "git_root": repo_str,
                "cwd": repo_str,
                "first_ts": t_first,
                "last_ts": t_first + 5.0,
                "last_durable_ts": t_first + 5.0,
                "edits": 2,
                "risk": "HIGH",
                "paths": [src_norm.clone(), out_norm.clone()],
                "current_diff_hash": "",
                "content_marks": [{"ts": t_first + 5.0, "fp": Value::Null, "cause": "edit_file"}],
            }),
        )
        .unwrap();
        rio::write_json(
            &rpath_pm,
            &json!({
                "session": sess_pm,
                "marker_first_ts": 0.0,
                "lanes": {
                    format!("{}|simplify", rio::fold_path(&repo_str)): [{
                        "round": 1,
                        "tree_oid": "1111111111111111111111111111111111111111",
                        "paths": []
                    }]
                }
            }),
        )
        .unwrap();
        let prep_pm = crate::swarm_cache::prepare_round(crate::swarm_cache::PrepareRoundInput {
            session: sess_pm,
            cwd: &repo_str,
            brain_root: &brain,
            label: "simplify",
            ttl_seconds: 270,
            paths: &[],
            reset: false,
            now_ts: Some(t_prep),
        });
        assert_eq!(prep_pm["ok"], json!(false));
        assert_eq!(
            prep_pm["direct_read_allowed"],
            json!(false),
            "pre-existing marker_first_ts=0 rounds.json requires DIFF_HASH in gate and must report direct_read_allowed=false"
        );
        assert!(
            cwg_common::swarm_prepare_hash_policy(sess_pm, rio::read_json(&mpath_pm).as_ref(), "").0,
            "gate policy must match direct_read_allowed=false"
        );

        match prev_home {
            Some(v) => std::env::set_var("CARBON_STACK_HOME", v),
            None => std::env::remove_var("CARBON_STACK_HOME"),
        }
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_round1_four_anomalies_edge_cases() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempEnvDir::new("r1-anomalies");

        // anom-65718cd1: measured shell edit (`shell_durable_edit: true`, no unknown/unmeasured) on standalone non-repo doc is exempt; unmeasured stays fail-closed.
        let doc_dir = tmp.path.join("standalone_docs");
        fs::create_dir_all(&doc_dir).unwrap();
        let doc_file = doc_dir.join("GEMINI.md");
        fs::write(&doc_file, "# Rule\n").unwrap();
        let doc_s = doc_file.to_string_lossy().into_owned();
        let measured_shell_marker = json!({
            "shell_durable_edit": true,
            "unmeasured_shell_edit": false,
            "operational": false,
            "content_marks": [{"ts": 100.0, "fp": "abc123", "cause": "run_command:Set-Content"}],
        });
        assert!(is_standalone_non_repo_doc_candidate(
            &measured_shell_marker,
            std::slice::from_ref(&doc_s),
            None
        ));
        let unmeasured_shell_marker = json!({
            "shell_durable_edit": true,
            "unmeasured_shell_edit": true,
            "operational": false,
            "content_marks": [{"ts": 100.0, "fp": null, "unknown": true, "cause": "run_command"}],
        });
        assert!(!is_standalone_non_repo_doc_candidate(
            &unmeasured_shell_marker,
            std::slice::from_ref(&doc_s),
            None
        ));

        // anom-48e3ee7b: unified parser handles `npm.cmd run validate`, and `CHECK_KIND_SKIPPED` suppresses long (>240-char) AND slow (>5s) root-skipped runs without `step_idx` via `cmd_sha` + `[start_ts, ts]` matching.
        assert!(cwg_mark::has_extended_pkg_script_segment("npm.cmd run validate"));
        assert!(cwg_mark::has_extended_pkg_script_segment("pnpm.cmd verify:all"));
        assert!(cwg_mark::has_extended_pkg_script_segment("bun.exe run 'validate'"));
        let root = tmp.path.join("mono");
        let subpkg = root.join("subpkg");
        fs::create_dir_all(&subpkg).unwrap();
        fs::write(root.join("package.json"), r#"{"name":"root","scripts":{}}"#).unwrap();
        fs::write(
            subpkg.join("package.json"),
            r#"{"name":"sub","scripts":{"validate":"node check.js"}}"#,
        )
        .unwrap();
        let sess_chk = "sess-anom-48e3-cwd";
        let ledger = cwg_common::checks_ledger_path(sess_chk);
        let long_cmd = format!(
            "npm.cmd run validate -- --filter={} --strict",
            "a".repeat(260)
        );
        let long_canon = cwg_mark::canonical_shell_snap_cmd(&long_cmd);
        let long_sha = cwg_mark::canonical_cmd_sha(&long_canon);
        let short_canon = cwg_mark::canonical_shell_snap_cmd("npm.cmd run validate");
        let short_sha = cwg_mark::canonical_cmd_sha(&short_canon);
        rio::append_jsonl(
            &ledger,
            &json!({
                "kind": cwg_mark::CHECK_KIND_SKIPPED,
                "cmd": rio::truncate_chars(&long_canon, 240),
                "cmd_sha": long_sha,
                "cwd": rio::normalize_path(&root.to_string_lossy()),
                "start_ts": 1008.0,
                "ts": 1010.0,
                "step_idx": Value::Null,
            }),
            65536,
        )
        .unwrap();
        rio::append_jsonl(
            &ledger,
            &json!({
                "kind": cwg_mark::CHECK_KIND_SKIPPED,
                "cmd": short_canon,
                "cmd_sha": short_sha,
                "cwd": rio::normalize_path(&root.to_string_lossy()),
                "start_ts": 1020.0,
                "ts": 1035.0,
                "step_idx": Value::Null,
            }),
            65536,
        )
        .unwrap();
        let steps_chk = vec![
            json!({
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "step_index": 10,
                "created_at": "1970-01-01T00:16:48Z",
                "tool_calls": [{"name": "run_command", "args": {"CommandLine": long_cmd}}]
            }),
            json!({
                "type": "GENERIC",
                "step_index": 11,
                "status": "DONE",
                "created_at": "1970-01-01T00:16:50Z",
                "content": "Command exited with code 0"
            }),
            json!({
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "step_index": 12,
                "created_at": "1970-01-01T00:17:00Z",
                "tool_calls": [{"name": "run_command", "args": {"CommandLine": "npm.cmd run validate"}}]
            }),
            json!({
                "type": "GENERIC",
                "step_index": 13,
                "status": "DONE",
                "created_at": "1970-01-01T00:17:15Z",
                "content": "Command exited with code 0"
            }),
        ];
        let chk_ev = read_checks_evidence_with_steps_in_cwd(
            sess_chk,
            1000.0,
            &steps_chk,
            &subpkg.to_string_lossy(),
        );
        assert_eq!(
            chk_ev.latest_pass_ts, 0.0,
            "long (>240 char) and slow (>5s) root skipped npm.cmd runs must NOT be credited against subpkg"
        );

        // #9: Rotated `checks_ledger.jsonl.1` must still suppress root skipped runs, and an evicted extended pkg script run with an active ledger must NOT fall back to `candidate_cwd` (`subpkg`).
        let sess_rot = "sess-anom-48e3-rotated";
        let ledger_rot = cwg_common::checks_ledger_path(sess_rot);
        let rot_file = ledger_rot.with_file_name(format!(
            "{}.1",
            ledger_rot.file_name().unwrap().to_string_lossy()
        ));
        rio::append_jsonl(
            &rot_file,
            &json!({
                "kind": cwg_mark::CHECK_KIND_SKIPPED,
                "cmd": short_canon,
                "cmd_sha": short_sha,
                "cwd": rio::normalize_path(&root.to_string_lossy()),
                "start_ts": 1020.0,
                "ts": 1035.0,
                "step_idx": Value::Null,
            }),
            65536,
        )
        .unwrap();
        rio::append_jsonl(
            &ledger_rot,
            &json!({
                "kind": cwg_mark::CHECK_KIND_SKIPPED,
                "cmd": "npm.cmd run lint:unrelated",
                "cmd_sha": "unrelated-sha",
                "cwd": rio::normalize_path(&root.to_string_lossy()),
                "start_ts": 1040.0,
                "ts": 1041.0,
                "step_idx": 99,
            }),
            65536,
        )
        .unwrap();
        let chk_rot = read_checks_evidence_with_steps_in_cwd(
            sess_rot,
            1000.0,
            &steps_chk,
            &subpkg.to_string_lossy(),
        );
        assert_eq!(
            chk_rot.latest_pass_ts, 0.0,
            "rotated checks_ledger.jsonl.1 skipped record AND evicted extended pkg script run must NOT be miscredited against subpkg: {:?}",
            chk_rot
        );

        // #9 (cont.): Even when the session has an EMPTY checks_ledger (e.g. first skipped run was not persisted), an extended pkg script without verified run `Cwd` must NOT fall back to `candidate_cwd` (`subpkg`).
        let chk_empty_ledger = read_checks_evidence_with_steps_in_cwd(
            "sess-anom-48e3-empty-ledger",
            1000.0,
            &steps_chk,
            &subpkg.to_string_lossy(),
        );
        assert_eq!(
            chk_empty_ledger.latest_pass_ts, 0.0,
            "empty-ledger extended pkg script without verified per-run Cwd must fail closed instead of falling back to candidate_cwd: {:?}",
            chk_empty_ledger
        );

        let rcp_db = cwg_common::parse_terminal_receipt("[gate] draft-blocked: HIGH; 2 closure passes BLOCKED");
        let rcp_ver = cwg_common::parse_terminal_receipt("[gate] verified: HIGH; cargo test");
        let marker_db = json!({
            "session": "sess-anom-232f-db",
            "first_ts": 1000.0,
            "last_durable_ts": 1005.0,
            "edits": 3,
            "changed_lines": 120,
            "paths": ["rust/src/a.rs", "rust/src/b.rs", "rust/src/c.rs"],
            "current_diff_hash": "fp-232f",
            "content_marks": [{"ts": 1005.0, "fp": "fp-232f", "cause": "edit_file"}],
        });
        let sw_comb = SwarmEvidence::default();
        let checks_ok = ChecksEvidence {
            latest_pass_ts: 1008.0,
            checks_count: 1,
            passed_count: 1,
            ..Default::default()
        };
        let sub_empty = SubagentEvidence::default();
        let codex_two_blocked = vec![
            json!({"engine":"codex","kind":"ordinary","verdict":"REVISE","launch_ts":1020.0,"verdict_ts":1025.0,"diff_hash":"fp-232f","fresh":true}),
            json!({"engine":"codex","kind":"ordinary","verdict":"REVISE","launch_ts":1030.0,"verdict_ts":1035.0,"diff_hash":"fp-232f","fresh":true}),
            json!({"engine":"codex","kind":"ordinary","verdict":"REVISE","launch_ts":1040.0,"verdict_ts":1045.0,"diff_hash":"fp-232f","fresh":true}),
            json!({"engine":"codex","kind":"ordinary","verdict":"ESCALATE","launch_ts":1050.0,"verdict_ts":1055.0,"diff_hash":"fp-232f","fresh":true}),
            json!({"engine":"codex","kind":"closure","verdict":"BLOCKED","launch_ts":1070.0,"verdict_ts":1075.0,"diff_hash":"fp-232f","fresh":true}),
            json!({"engine":"codex","kind":"closure","verdict":"BLOCKED","launch_ts":1080.0,"verdict_ts":1085.0,"diff_hash":"fp-232f","fresh":true}),
        ];
        let research_step = vec![json!({
            "type": "PLANNER_RESPONSE",
            "source": "MODEL",
            "created_at": "1970-01-01T00:17:40Z",
            "tool_calls": [{"name": "search_web", "args": {"query": "rust gate"}}]
        })];
        let mut ctx_db = json!({
            "cwd": tmp.path.to_string_lossy(),
            "git_root": Value::Null,
            "dpaths": ["rust/src/a.rs", "rust/src/b.rs", "rust/src/c.rs"],
            "design_paths": [],
            "policy": cwg_common::default_gate_policy(),
            "floor": "HIGH",
            "require_tests": true,
            "needs_review": true,
        });
        let (ok_db, msg_db) = validate_candidate_closure(CandidateClosureInput {
            receipt: rcp_db.as_ref(),
            marker_in: &marker_db,
            checks_ev: &checks_ok,
            sub_ev: &sub_empty,
            swarm_ev: &sw_comb,
            codex_reviews: &codex_two_blocked,
            ctx: Some(&mut ctx_db),
            steps: Some(&research_step),
            transcript_path: None,
        });
        assert!(ok_db, "terminal draft-blocked after 2 BLOCKED passes must succeed: {}", msg_db);

        let mut ctx_ver = ctx_db.clone();
        let (ok_ver, msg_ver) = validate_candidate_closure(CandidateClosureInput {
            receipt: rcp_ver.as_ref(),
            marker_in: &marker_db,
            checks_ev: &checks_ok,
            sub_ev: &sub_empty,
            swarm_ev: &sw_comb,
            codex_reviews: &codex_two_blocked[..4],
            ctx: Some(&mut ctx_ver),
            steps: Some(&research_step),
            transcript_path: None,
        });
        assert!(!ok_ver, "{}", msg_ver);
    }

    #[test]
    fn test_stage2_operational_auto_retires_without_receipt() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempEnvDir::new("stage2-op");
        let sess = "sess-stage2-op";
        let mpath = cwg_common::marker_path(sess);
        let spath = cwg_common::enforcement_state_path(sess);
        let tp = tmp.path.join("tx.jsonl");
        fs::write(
            &tp,
            "{\"step_index\":0,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"run build\"}\n",
        )
        .unwrap();
        rio::write_json(
            &mpath,
            &json!({
                "session": sess,
                "class": cwg_common::WORK_OPERATIONAL,
                "operational": true,
                "closed": false,
                "first_ts": 1000.0,
                "last_ts": 1001.0,
                "edits": 1,
                "paths": [],
                "cwd": rio::normalize_path(&tmp.path.to_string_lossy()),
            }),
        )
        .unwrap();
        let res = decide_stop(&json!({
            "conversationId": sess,
            "transcriptPath": tp.to_string_lossy(),
            "lastAssistantMessage": "Ran operational check without any gate receipt.",
        }));
        assert_eq!(res, None);
        assert!(!mpath.exists(), "WORK_OPERATIONAL marker must retire automatically");
        let st = rio::read_json(&spath).unwrap();
        assert_eq!(st.get("last_receipt"), Some(&json!("operational")));
    }

    #[test]
    fn test_stage2_high_closes_verified_without_simplify_or_design_gate() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempEnvDir::new("stage2-high-ui");
        let ui_file = tmp.path.join("src").join("App.tsx");
        fs::create_dir_all(ui_file.parent().unwrap()).unwrap();
        fs::write(&ui_file, "export function App() { return null; }\n").unwrap();
        let ui_norm = rio::normalize_path(&ui_file.to_string_lossy());
        let fp = cwg_common::content_fingerprint(std::slice::from_ref(&ui_norm), 4_000_000);
        let marker = json!({
            "session": "sess-stage2-high-ui",
            "class": cwg_common::WORK_PERSISTENT,
            "first_ts": 100.0,
            "last_durable_ts": 110.0,
            "cwd": rio::normalize_path(&tmp.path.to_string_lossy()),
            "paths": [ui_norm],
            "content_marks": [{"ts": 110.0, "fp": fp}],
            "declared_risk": "HIGH",
            "closed": false,
        });
        let checks_ev = ChecksEvidence {
            checks_count: 1,
            passed_count: 1,
            latest_pass_ts: 115.0,
            ..Default::default()
        };
        let codex_reviews = vec![json!({
            "engine": "codex",
            "kind": "ordinary",
            "verdict": "APPROVED",
            "launch_ts": 118.0,
            "verdict_ts": 120.0,
            "xhigh": false,
        })];
        let receipt =
            cwg_common::parse_terminal_receipt("[gate] verified: HIGH; App.tsx updated and checks passed")
                .unwrap();
        let (ok, res) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt),
            marker_in: &marker,
            checks_ev: &checks_ev,
            sub_ev: &SubagentEvidence::default(),
            swarm_ev: &SwarmEvidence::default(),
            codex_reviews: &codex_reviews,
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(ok, "HIGH visual candidate must close without simplify or Design Gate: {}", res);
        assert_eq!(res, "verified");

        let mut m_simp = marker.clone();
        let sess_simp = "sess-stage2-waiting-simplify";
        m_simp["session"] = json!(sess_simp);
        let brain_simp = tmp.path.join("brain");
        let tp_simp = setup_neon_session_env(
            &brain_simp,
            sess_simp,
            "",
            json!({
                "members": {
                    "simplify-reviewer": {
                        "role": "worker",
                        "conversation_id": "cid-simp-wait",
                        "model": cwg_common::SONNET_HIGH_MODEL,
                        "killed": false
                    },
                    "helper-1": {
                        "role": "worker",
                        "conversation_id": "cid-simp-helper",
                        "model": cwg_common::SONNET_HIGH_MODEL,
                        "killed": false
                    }
                }
            }),
            &[
                json!({"seq": 1, "agent": "simplify-reviewer", "time": "2026-11-22T10:00:00Z", "text": "SIMPLIFY_LENS: ALL\nSIMPLIFY_VERDICT: CLEAN"}),
                json!({"seq": 2, "agent": "helper-1", "time": "2026-11-22T10:00:05Z", "text": "SIMPLIFY_VERDICT: ACTIONABLE_FIXES"}),
            ],
            &[],
        );
        let tp_simp_str = tp_simp.to_string_lossy().into_owned();
        assert!(cwg_common::active_review_workers(&brain_simp, sess_simp).is_empty());
        let (ok_simp, res_simp) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt),
            marker_in: &m_simp,
            checks_ev: &checks_ev,
            sub_ev: &SubagentEvidence::default(),
            swarm_ev: &SwarmEvidence::default(),
            codex_reviews: &codex_reviews,
            ctx: None,
            steps: None,
            transcript_path: Some(&tp_simp_str),
        });
        assert!(ok_simp, "waiting simplify worker must not block APPROVED Stop: {}", res_simp);
        assert_eq!(res_simp, "verified");

        let sess_rev = "sess-stage2-waiting-reviewer";
        let mut m_rev = marker.clone();
        m_rev["session"] = json!(sess_rev);
        let tp_rev = setup_neon_session_env(
            &brain_simp,
            sess_rev,
            "",
            json!({
                "members": {
                    "adversarial-reviewer": {
                        "role": "worker",
                        "conversation_id": "cid-rev-wait",
                        "model": cwg_common::OPUS_HIGH_MODEL,
                        "killed": false
                    }
                }
            }),
            &[],
            &[],
        );
        let tp_rev_str = tp_rev.to_string_lossy().into_owned();
        assert_eq!(
            cwg_common::active_review_workers(&brain_simp, sess_rev),
            vec!["adversarial-reviewer".to_string()]
        );
        let (ok_rev, res_rev) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt),
            marker_in: &m_rev,
            checks_ev: &checks_ev,
            sub_ev: &SubagentEvidence::default(),
            swarm_ev: &SwarmEvidence::default(),
            codex_reviews: &codex_reviews,
            ctx: None,
            steps: None,
            transcript_path: Some(&tp_rev_str),
        });
        assert!(!ok_rev);
        assert!(res_rev.contains("review swarm workers"), "{}", res_rev);
    }

    #[test]
    fn test_stage2_clean_undo_auto_retires_and_kept_commit_blocks() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempEnvDir::new("stage2-undo");
        let repo = tmp.path.join("repo");
        let src_dir = repo.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let lib_rs = src_dir.join("lib.rs");
        fs::write(&lib_rs, "pub fn n() -> i32 { 1 }\n").unwrap();
        let repo_str = repo.to_string_lossy().into_owned();
        let run_git = |args: &[&str]| {
            let (rc, _out, err) = rio::run_git(&repo_str, args, 10.0);
            assert_eq!(rc, 0, "git {:?} failed: {}", args, err);
        };
        run_git(&["init"]);
        run_git(&["config", "user.email", "t@example.com"]);
        run_git(&["config", "user.name", "Tester"]);
        run_git(&["add", "."]);
        run_git(&["commit", "-m", "init"]);
        let opening_head = rio::git_head_oid(&repo_str);
        assert!(!opening_head.is_empty());

        let tp = tmp.path.join("tx-undo.jsonl");
        fs::write(
            &tp,
            "{\"step_index\":0,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"edit\"}\n",
        )
        .unwrap();
        let lib_norm = rio::normalize_path(&lib_rs.to_string_lossy());
        let repo_norm = rio::normalize_path(&repo_str);

        // Case A: revert file to opening_head -> clean working tree & same HEAD -> auto-retires as undo-clean without receipt.
        let sess_undo = "sess-stage2-undo-clean";
        let mpath_undo = cwg_common::marker_path(sess_undo);
        let spath_undo = cwg_common::enforcement_state_path(sess_undo);
        fs::write(&lib_rs, "pub fn n() -> i32 { 2 }\n").unwrap();
        rio::write_json(
            &mpath_undo,
            &json!({
                "session": sess_undo,
                "class": cwg_common::WORK_PERSISTENT,
                "operational": false,
                "closed": false,
                "first_ts": 100.0,
                "last_ts": 110.0,
                "last_durable_ts": 110.0,
                "edits": 1,
                "cwd": repo_norm,
                "git_root": repo_norm,
                "opening_head": opening_head,
                "paths": [lib_norm],
            }),
        )
        .unwrap();
        run_git(&["checkout", "--", "src/lib.rs"]);
        let res_undo = decide_stop(&json!({
            "conversationId": sess_undo,
            "transcriptPath": tp.to_string_lossy(),
            "lastAssistantMessage": "Reverted my temporary edit.",
        }));
        assert_eq!(res_undo, None);
        assert!(!mpath_undo.exists(), "clean undo to opening_head must retire marker");
        let st_undo = rio::read_json(&spath_undo).unwrap();
        assert_eq!(st_undo.get("last_receipt"), Some(&json!("undo-clean")));

        // Case B: commit edit ahead of opening_head -> HEAD moved -> must NOT auto-retire and must block Stop without receipt.
        let sess_commit = "sess-stage2-kept-commit";
        let mpath_commit = cwg_common::marker_path(sess_commit);
        fs::write(&lib_rs, "pub fn n() -> i32 { 3 }\n").unwrap();
        let fp_commit = cwg_common::content_fingerprint(std::slice::from_ref(&lib_norm), 4_000_000);
        let marker_commit = json!({
            "session": sess_commit,
            "class": cwg_common::WORK_PERSISTENT,
            "operational": false,
            "closed": false,
            "first_ts": 200.0,
            "last_ts": 210.0,
            "last_durable_ts": 210.0,
            "edits": 1,
            "cwd": repo_norm,
            "git_root": repo_norm,
            "opening_head": opening_head,
            "paths": [lib_norm],
            "current_diff_hash": fp_commit,
            "content_marks": [{"ts": 210.0, "fp": fp_commit}],
        });
        rio::write_json(&mpath_commit, &marker_commit).unwrap();
        run_git(&["add", "."]);
        run_git(&["commit", "-m", "kept durable change"]);
        let (restored, why_restored) = candidate_restored_to_clean_head(&marker_commit);
        assert!(!restored, "committed change ahead of opening_head must reject clean restoration");
        assert!(why_restored.contains("HEAD"), "got: {}", why_restored);
        let res_commit = decide_stop(&json!({
            "conversationId": sess_commit,
            "transcriptPath": tp.to_string_lossy(),
            "lastAssistantMessage": "Committed change without closing receipt.",
        }));
        assert!(res_commit.is_some(), "kept commit ahead of opening_head must block Stop without receipt");
        assert!(mpath_commit.exists());

        // Case C: First shell command modifies and commits in a single invocation -> opening_head MUST reflect pre-command HEAD (H0, not post-commit H1) so Stop blocks without receipt instead of retiring as `undo-clean`.
        let sess_shell_commit = "sess-stage2-shell-first-commit";
        let pre_cmd = "python -c edit_and_commit";
        let pre_payload = json!({
            "conversationId": sess_shell_commit,
            "cwd": repo_str,
            "workspacePaths": [repo_str],
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": pre_cmd}
            }
        });
        cwg_mark::record_pre_tool_use(&pre_payload);
        let h0 = rio::git_head_oid(&repo_str);
        fs::write(&lib_rs, "pub fn n() -> i32 { 4 }\n").unwrap();
        run_git(&["add", "src/lib.rs"]);
        run_git(&["commit", "-m", "first command commit"]);
        let h1 = rio::git_head_oid(&repo_str);
        assert_ne!(h0, h1);
        let mut post_payload = pre_payload.clone();
        post_payload["toolResponse"] = json!({"output": "Command exited with code 0.\n"});
        cwg_mark::record_post_tool_use(&post_payload).unwrap();
        let m_shell = cwg_common::read_marker_with_pending(sess_shell_commit).unwrap();
        assert_eq!(val_to_str(m_shell.get("opening_head")), h0);
        let res_shell_stop = decide_stop(&json!({
            "conversationId": sess_shell_commit,
            "transcriptPath": tp.to_string_lossy(),
            "lastAssistantMessage": "Applied and committed change without closing receipt.",
        }));
        assert!(
            res_shell_stop.is_some(),
            "first shell command commit must block Stop without receipt"
        );
    }
}
