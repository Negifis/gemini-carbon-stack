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
pub const MAX_REVIEW_ROUNDS: usize = 3;
// SAFETY: Bound uncounted pre-simplify `REVISE`/`ESCALATE` rounds so broken loops cannot run unboundedly.
pub const MAX_RAW_ORDINARY_ROUNDS: usize = MAX_REVIEW_ROUNDS * 2;
pub const MAX_CLOSURE_PASSES: usize = cwg_common::MAX_CLOSURE_PASSES_PER_CYCLE;
pub const MAX_WORKER_POST_REMINDERS: i64 = 2;
const CLOSURE_PHASE_FLAG: &str = "--phase closure";
use crate::cwg_common::TS_EPS;

const PRE_SIMPLIFY_REVIEW_ERR: &str = "adversarial review ran simultaneously with or before simplify lenses; complete all simplify lenses BEFORE launching adversarial review (or run `--closure` / `--phase closure` once simplify finishes)";

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

fn tier_currently_unavailable(
    issue_verified: bool,
    last_issue_ts: f64,
    healthy_ts: f64,
) -> bool {
    if !issue_verified {
        return false;
    }
    if healthy_ts <= 0.0 {
        return true;
    }
    // INVARIANT: Once a confirmed healthy/positive-quota check is observed (`healthy_ts > 0`), only a failure with a verified timestamp strictly newer than `healthy_ts` can re-open current exhaustion for `draft-blocked`; un-timestamped failures (`last_issue_ts == 0.0`) fail closed and never cancel confirmed recovery.
    last_issue_ts > healthy_ts + TS_EPS
}

fn is_simplify_tier_causal(
    tier: &str,
    launch_ts: f64,
    sonnet_issue: bool,
    sonnet_issue_ts: f64,
    neon_issue: bool,
    neon_issue_ts: f64,
) -> bool {
    let fb_causal =
        sonnet_issue && (sonnet_issue_ts <= 0.0 || launch_ts >= sonnet_issue_ts - TS_EPS);
    let sec_causal =
        fb_causal && neon_issue && (neon_issue_ts <= 0.0 || launch_ts >= neon_issue_ts - TS_EPS);
    tier == cwg_common::SIMPLIFY_TIER_SONNET
        || (fb_causal && tier == cwg_common::SIMPLIFY_TIER_FALLBACK)
        || (sec_causal && tier == cwg_common::SIMPLIFY_TIER_SECONDARY_FALLBACK)
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

fn record_lens_window(
    lenses: &mut HashMap<String, f64>,
    ends: &mut HashMap<String, f64>,
    lens: &str,
    launch_ts: f64,
    end_ts: f64,
) {
    max_into(lenses.entry(lens.to_string()).or_insert(0.0), launch_ts);
    max_into(ends.entry(lens.to_string()).or_insert(0.0), end_ts);
}

fn record_combined_window(
    combined_ts: &mut f64,
    combined_end_ts: &mut f64,
    launch_ts: f64,
    end_ts: f64,
) {
    max_into(combined_ts, launch_ts);
    max_into(combined_end_ts, end_ts);
}

fn merge_tier_maps_after(maps: &[&HashMap<String, f64>], min_ts: f64) -> HashMap<String, f64> {
    let mut out = HashMap::new();
    for src in maps {
        for (k, &v) in *src {
            if min_ts > 0.0 && v < min_ts {
                continue;
            }
            max_into(out.entry(k.clone()).or_insert(0.0), v);
        }
    }
    out
}

fn merge_tier_maps(maps: &[&HashMap<String, f64>]) -> HashMap<String, f64> {
    merge_tier_maps_after(maps, 0.0)
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

fn subagent_uri_re() -> &'static Regex {
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

fn simplify_combined_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\A(?:simplify(?:-reviewer)?|simp-all(?:-[0-9a-f]{2,4})?)(?:-r\d+)?\z")
            .expect("simplify_combined_name_re")
    })
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

fn lens_word_re(lens: &str) -> Option<&'static Regex> {
    static RE_REUSE: OnceLock<Regex> = OnceLock::new();
    static RE_QUALITY: OnceLock<Regex> = OnceLock::new();
    static RE_EFFICIENCY: OnceLock<Regex> = OnceLock::new();
    match lens {
        "reuse" => Some(RE_REUSE.get_or_init(|| Regex::new(r"(?i)\breuse\b").expect("reuse"))),
        "quality" => {
            Some(RE_QUALITY.get_or_init(|| Regex::new(r"(?i)\bquality\b").expect("quality")))
        }
        "efficiency" => Some(
            RE_EFFICIENCY.get_or_init(|| Regex::new(r"(?i)\befficiency\b").expect("efficiency")),
        ),
        _ => None,
    }
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
        let now = now_sec();
        let fp_val = if now_fp.is_empty() {
            Value::Null
        } else {
            Value::String(now_fp)
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
        }
        return updated;
    }
    marker.clone()
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
    (true, String::new())
}

#[derive(Debug, Clone, Default)]
pub struct ChecksEvidence {
    pub checks_count: usize,
    pub passed_count: usize,
    pub failed_count: usize,
    pub latest_pass_ts: f64,
    pub latest_fail_ts: f64,
}

pub fn read_checks_evidence(session: &str, first_ts: f64) -> ChecksEvidence {
    let path = cwg_common::checks_ledger_path(session);
    let mut ev = ChecksEvidence::default();
    for rec in rio::read_jsonl(&path, Some(200)) {
        let ts = val_to_f64(rec.get("ts"));
        if rec.get("kind").and_then(|v| v.as_str()) == Some("check") && ts >= first_ts - 1.0 {
            ev.checks_count += 1;
            if json_truthy(rec.get("passed")) {
                ev.passed_count += 1;
                if ts > ev.latest_pass_ts {
                    ev.latest_pass_ts = ts;
                }
            } else {
                ev.failed_count += 1;
                if ts > ev.latest_fail_ts {
                    ev.latest_fail_ts = ts;
                }
            }
        }
    }
    ev
}

fn collect_generic_results(steps: &[Value], planner_idx: usize) -> Vec<(String, String, ParsedTs)> {
    let mut g_cur = planner_idx + 1;
    let mut out = Vec::new();
    while g_cur < steps.len() {
        let g_st = &steps[g_cur];
        if g_st.get("type").and_then(|v| v.as_str()) != Some("GENERIC") {
            break;
        }
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
        out.push((g_status, g_txt, g_pt));
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
struct TimedChunk {
    ts: f64,
    text: String,
    kind: &'static str,
    is_signoff: bool,
}

fn extract_subagent_timed_chunks(
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

fn classify_simplify_worker(
    name: &str,
    brief_or_role: &str,
    output_text: &str,
) -> (&'static str, Option<String>) {
    let parsed = cwg_common::parse_simplify_verdict(output_text, None);
    let has_verdict = !val_to_str(parsed.get("verdict")).is_empty();
    if json_truthy(parsed.get("has_explicit_all")) {
        return if has_verdict {
            ("combined", None)
        } else {
            ("other", None)
        };
    }

    let explicit: Vec<String> = parsed
        .get("explicit_lenses")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    if explicit.len() == 1 {
        return ("lens", Some(explicit[0].clone()));
    }
    if explicit.len() > 1 {
        return if has_verdict {
            ("combined", None)
        } else {
            ("other", None)
        };
    }

    let name_lens = cwg_common::simplify_lens_from_worker_name(name);
    if !name_lens.is_empty() {
        return ("lens", Some(name_lens));
    }

    if simplify_combined_name_re().is_match(name.trim()) {
        return if has_verdict {
            ("combined", None)
        } else {
            ("other", None)
        };
    }

    if cwg_common::is_simplify_worker_name(name)
        || brief_or_role.to_lowercase().contains("simplify")
    {
        let low_brief = brief_or_role.to_lowercase();
        let matched: Vec<&str> = cwg_common::SIMPLIFY_LENSES
            .iter()
            .copied()
            .filter(|&lens| lens_word_re(lens).map_or(false, |re| re.is_match(&low_brief)))
            .collect();
        if matched.len() == 1 {
            return ("lens", Some(matched[0].to_string()));
        }
    }

    ("other", None)
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
pub struct SimplifyHistoryItem {
    pub kind: String,
    pub lens: Option<String>,
    pub tier: String,
    pub launch_ts: f64,
    pub end_ts: f64,
    pub seq: i64,
    pub causal_seq: i64,
    pub worker_ord: usize,
    pub win_ord: usize,
    pub clean: bool,
    pub has_explicit_all: bool,
}

impl SimplifyHistoryItem {
    fn compute_chronological_order(items: &[&Self]) -> (Vec<usize>, Vec<f64>, Vec<bool>) {
        let n = items.len();
        let mut end_ts: Vec<f64> = items.iter().map(|it| it.end_ts).collect();
        let mut eff_clean: Vec<bool> = items.iter().map(|it| it.clean).collect();
        if n <= 1 {
            return ((0..n).collect(), end_ts, eff_clean);
        }
        // INVARIANT: `board.jsonl` is strictly append-only; clamp monotonic `end_ts` across
        // real board-sequenced items (`seq > 0`) in ascending `seq` order so a coarse later board post
        // (`10:00:02Z`, `seq=3`) never precedes an earlier millisecond-merged board post (`10:00:02.200Z`,
        // `seq=2`), without letting unsequenced (`seq == 0`) timestamps warp later `seq > 0` items.
        let mut seq_indices: Vec<usize> = (0..n).filter(|&i| items[i].seq > 0).collect();
        seq_indices.sort_by_key(|&i| items[i].seq);
        let mut running_ts = 0.0f64;
        for &idx in &seq_indices {
            if running_ts > 0.0 && end_ts[idx] < running_ts {
                end_ts[idx] = running_ts;
            }
            if end_ts[idx] > running_ts {
                running_ts = end_ts[idx];
            }
        }

        // INVARIANT: Model causal happens-before relations as per-(kind, lens) DAGs and emit a
        // deterministic linear extension via priority-queue Kahn topological sort (|E| = O(n)):
        //   1. Global append-only board order within lane: `u.seq < v.seq` (for `seq > 0`).
        //   2. Per-worker sequential window order within lane: `u.worker_ord == v.worker_ord > 0 && u.win_ord < v.win_ord`.
        //   3. Lamport causal lower bound within lane: `u.seq > 0 && v.seq == 0 && u.seq <= v.causal_seq`.
        // Partition each timestamp into Stratum 0 (`clean` nodes and ancestors of a same-lane `clean`
        // at `<= end_ts`) before Stratum 1 (terminal `!clean` revokers), so every concurrent revoker
        // always pops after any concurrent `clean` even behind multi-step ancestor chains.
        fn connect_group_pair(adj: &mut [Vec<usize>], prev: &[usize], cur: &[usize]) {
            for &u in prev {
                for &v in cur {
                    if u != v {
                        adj[u].push(v);
                    }
                }
            }
        }
        fn peel_zero_deg(
            deg: &mut [usize],
            neighbors: &[Vec<usize>],
            peeled: &mut [bool],
            q: &mut Vec<usize>,
        ) {
            while let Some(u) = q.pop() {
                for &v in &neighbors[u] {
                    if !peeled[v] {
                        deg[v] = deg[v].saturating_sub(1);
                        if deg[v] == 0 {
                            peeled[v] = true;
                            q.push(v);
                        }
                    }
                }
            }
        }

        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut lane_map: std::collections::BTreeMap<(&str, Option<&str>), Vec<usize>> =
            std::collections::BTreeMap::new();
        for (i, it) in items.iter().enumerate() {
            lane_map
                .entry((it.kind.as_str(), it.lens.as_deref()))
                .or_default()
                .push(i);
        }
        for lane in lane_map.values() {
            let mut lane_seq: Vec<usize> = lane
                .iter()
                .copied()
                .filter(|&i| items[i].seq > 0)
                .collect();
            lane_seq.sort_by_key(|&i| items[i].seq);
            let seq_groups: Vec<(i64, &[usize])> = lane_seq
                .chunk_by(|&a, &b| items[a].seq == items[b].seq)
                .map(|g| (items[g[0]].seq, g))
                .collect();
            for pair in seq_groups.windows(2) {
                connect_group_pair(&mut adj, pair[0].1, pair[1].1);
            }
            if !seq_groups.is_empty() {
                for &v in lane {
                    let it = items[v];
                    if it.seq == 0 && it.causal_seq > 0 {
                        let pos = seq_groups.partition_point(|&(s, _)| s <= it.causal_seq);
                        if pos > 0 {
                            connect_group_pair(&mut adj, seq_groups[pos - 1].1, &[v]);
                        }
                    }
                }
            }

            let mut worker_indices: Vec<usize> = lane
                .iter()
                .copied()
                .filter(|&i| items[i].worker_ord > 0)
                .collect();
            worker_indices.sort_by_key(|&i| (items[i].worker_ord, items[i].win_ord, i));
            for w_slice in
                worker_indices.chunk_by(|&a, &b| items[a].worker_ord == items[b].worker_ord)
            {
                let mut prev_win: Option<&[usize]> = None;
                for win_group in w_slice.chunk_by(|&a, &b| items[a].win_ord == items[b].win_ord) {
                    if let Some(prev) = prev_win {
                        connect_group_pair(&mut adj, prev, win_group);
                    }
                    prev_win = Some(win_group);
                }
            }
        }

        let mut rev_adj: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut in_deg: Vec<usize> = vec![0; n];
        for u in 0..n {
            if adj[u].len() > 1 {
                adj[u].sort_unstable();
                adj[u].dedup();
            }
            for &v in &adj[u] {
                rev_adj[v].push(u);
                in_deg[v] += 1;
            }
        }

        // SAFETY: Detect and eliminate all causal cycles BEFORE computing `min_clean_ts` or running
        // Kahn's priority queue:
        //   1. Forward-peel acyclic prefixes (`in_deg == 0`).
        //   2. Reverse-peel acyclic downstream tails (`out_deg == 0` among remaining nodes).
        //   3. Every un-peeled node belongs to the cyclic core: poison `eff_clean = false` and strip
        //      intra-core edges while keeping prefix->core and core->tail edges. The resulting
        //      graph is guaranteed acyclic so downstream tails (e.g. R2 `CLEAN`) unlock at their
        //      real timestamp and compete fairly against concurrent revokers at the same `end_ts`.
        let mut fwd_in = in_deg.clone();
        let mut acyclic = vec![false; n];
        let mut peel_q: Vec<usize> = Vec::new();
        for (i, &deg) in fwd_in.iter().enumerate() {
            if deg == 0 {
                acyclic[i] = true;
                peel_q.push(i);
            }
        }
        peel_zero_deg(&mut fwd_in, &adj, &mut acyclic, &mut peel_q);
        if acyclic.iter().any(|&ok| !ok) {
            let mut out_deg = vec![0usize; n];
            for i in 0..n {
                if !acyclic[i] {
                    out_deg[i] = adj[i].iter().filter(|&&nxt| !acyclic[nxt]).count();
                }
            }
            let mut peeled = acyclic;
            for (i, &deg) in out_deg.iter().enumerate() {
                if !peeled[i] && deg == 0 {
                    peeled[i] = true;
                    peel_q.push(i);
                }
            }
            peel_zero_deg(&mut out_deg, &rev_adj, &mut peeled, &mut peel_q);
            for u in 0..n {
                if !peeled[u] {
                    eff_clean[u] = false;
                    adj[u].retain(|&v| peeled[v]);
                }
            }
            for v in 0..n {
                if !peeled[v] {
                    rev_adj[v].retain(|&u| peeled[u]);
                }
            }
            in_deg.fill(0);
            for edges in &adj {
                for &v in edges {
                    in_deg[v] += 1;
                }
            }
        }

        // INVARIANT: Compute minimum reachable same-lane `clean` timestamp via reverse DFS from
        // `clean` nodes sorted by ascending `end_ts` (each node visited at most once, O(n)).
        let mut min_clean_ts = vec![f64::INFINITY; n];
        let mut clean_nodes: Vec<usize> = (0..n).filter(|&i| eff_clean[i]).collect();
        clean_nodes.sort_by(|&a, &b| end_ts[a].total_cmp(&end_ts[b]));
        let mut stack: Vec<usize> = Vec::new();
        for c in clean_nodes {
            let cts = end_ts[c];
            if min_clean_ts[c] <= cts {
                continue;
            }
            min_clean_ts[c] = cts;
            stack.push(c);
            while let Some(cur) = stack.pop() {
                for &prev in &rev_adj[cur] {
                    if min_clean_ts[prev] > cts {
                        min_clean_ts[prev] = cts;
                        stack.push(prev);
                    }
                }
            }
        }

        #[derive(Clone, Copy)]
        struct KahnKey {
            eff_ts: f64,
            terminal_revoker: bool,
            is_non_clean: bool,
            seq: i64,
            launch_ts: f64,
            idx: usize,
        }
        impl PartialEq for KahnKey {
            fn eq(&self, other: &Self) -> bool {
                self.cmp(other) == std::cmp::Ordering::Equal
            }
        }
        impl Eq for KahnKey {}
        impl PartialOrd for KahnKey {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }
        impl Ord for KahnKey {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.eff_ts
                    .total_cmp(&other.eff_ts)
                    .then_with(|| self.terminal_revoker.cmp(&other.terminal_revoker))
                    .then_with(|| self.is_non_clean.cmp(&other.is_non_clean))
                    .then_with(|| self.seq.cmp(&other.seq))
                    .then_with(|| self.launch_ts.total_cmp(&other.launch_ts))
                    .then_with(|| self.idx.cmp(&other.idx))
            }
        }
        let make_key = |idx: usize| -> KahnKey {
            let it = items[idx];
            let ets = end_ts[idx];
            let clean = eff_clean[idx];
            let mct = min_clean_ts[idx];
            KahnKey {
                eff_ts: ets.min(mct),
                terminal_revoker: !clean && mct > ets + TS_EPS,
                is_non_clean: !clean,
                seq: it.seq,
                launch_ts: it.launch_ts,
                idx,
            }
        };

        let mut pq: std::collections::BinaryHeap<std::cmp::Reverse<KahnKey>> =
            std::collections::BinaryHeap::with_capacity(n);
        for (idx, &deg) in in_deg.iter().enumerate() {
            if deg == 0 {
                pq.push(std::cmp::Reverse(make_key(idx)));
            }
        }
        let mut order: Vec<usize> = Vec::with_capacity(n);
        while let Some(std::cmp::Reverse(k)) = pq.pop() {
            order.push(k.idx);
            for &nxt in &adj[k.idx] {
                if in_deg[nxt] > 0 {
                    in_deg[nxt] -= 1;
                    if in_deg[nxt] == 0 {
                        pq.push(std::cmp::Reverse(make_key(nxt)));
                    }
                }
            }
        }
        debug_assert_eq!(order.len(), n);
        (order, end_ts, eff_clean)
    }

    fn sort_chronologically(items: &mut [Self]) {
        if items.len() <= 1 {
            return;
        }
        let (order, end_ts, eff_clean) = {
            let refs: Vec<&Self> = items.iter().collect();
            Self::compute_chronological_order(&refs)
        };
        for (i, it) in items.iter_mut().enumerate() {
            it.end_ts = end_ts[i];
            it.clean = eff_clean[i];
        }
        let mut slots: Vec<Option<Self>> =
            items.iter_mut().map(|x| Some(std::mem::take(x))).collect();
        for (dst, idx) in items.iter_mut().zip(order) {
            if let Some(it) = slots[idx].take() {
                *dst = it;
            }
        }
    }

    fn replay_completion<'a>(
        items: &[&'a Self],
        max_end_ts: Option<f64>,
    ) -> Option<(HashMap<&'a str, f64>, Option<f64>)> {
        if let Some(limit) = max_end_ts {
            if items.iter().any(|sr| sr.launch_ts.max(sr.end_ts) > limit) {
                return None;
            }
        }
        let (order, _, eff_clean) = Self::compute_chronological_order(items);
        let mut done_lenses: HashMap<&'a str, f64> = HashMap::new();
        let mut done_combined_lts: Option<f64> = None;
        for idx in order {
            let sr = items[idx];
            if !eff_clean[idx] {
                if sr.kind == "lens" {
                    if let Some(sl) = sr.lens.as_deref() {
                        done_lenses.remove(sl);
                    }
                } else {
                    done_combined_lts = None;
                }
            } else if sr.kind == "lens" {
                if let Some(sl) = sr.lens.as_deref() {
                    done_lenses.insert(sl, sr.launch_ts);
                }
            } else if sr.has_explicit_all {
                done_combined_lts = Some(sr.launch_ts);
            }
        }
        Some((done_lenses, done_combined_lts))
    }
}

#[derive(Debug, Clone, Default)]
pub struct SwarmEvidence {
    pub sonnet_lenses: HashMap<String, f64>,
    pub fallback_lenses: HashMap<String, f64>,
    pub secondary_fallback_lenses: HashMap<String, f64>,
    pub sonnet_lenses_end: HashMap<String, f64>,
    pub fallback_lenses_end: HashMap<String, f64>,
    pub secondary_fallback_lenses_end: HashMap<String, f64>,
    pub sonnet_combined_ts: f64,
    pub fallback_combined_ts: f64,
    pub secondary_fallback_combined_ts: f64,
    pub sonnet_combined_end_ts: f64,
    pub fallback_combined_end_ts: f64,
    pub secondary_fallback_combined_end_ts: f64,
    pub simplify_launch_steps: HashSet<usize>,
    pub simplify_history: Vec<SimplifyHistoryItem>,
    pub simplify_current_history: Option<Vec<SimplifyHistoryItem>>,
    pub simplify_failures: i64,
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
    pub multi_lens_spoof: bool,
    pub multi_lens_spoof_ts: f64,
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

fn recover_compact_swarm_steps(
    tp: &str,
    tail_idx: i64,
    first_ts: f64,
    ev: &mut SwarmEvidence,
    host_worker_errors: &mut HashMap<(String, String), Vec<ParsedTs>>,
    mut on_swarm_res: impl FnMut(&mut SwarmEvidence, &Value, &str, &str, ParsedTs, f64, Option<usize>, bool),
) -> Vec<Value> {
    let compact_steps = rio::read_compact_transcript_steps(tp, 16000);
    for (p_idx, p_st) in compact_steps.iter().enumerate() {
        let Some(s_idx) = p_st.get("step_index").and_then(|v| v.as_i64()) else {
            continue;
        };
        if s_idx <= 0 || s_idx >= tail_idx {
            continue;
        }
        let p_source = val_to_str(p_st.get("source"));
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
        let p_call_ts = p_st
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(rio::parse_iso_ts)
            .unwrap_or(0.0);
        if p_call_ts > 0.0 && p_call_ts < first_ts - 2.0 {
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
        let p_gen = collect_generic_results(&compact_steps, p_idx);
        for (p_pos, p_tc) in p_tcs.iter().enumerate() {
            if p_tc.get("name").and_then(|v| v.as_str()) != Some("swarm") {
                continue;
            }
            let (g_status, blob, g_pt) = p_gen
                .get(p_pos)
                .map(|(st, b, pt)| (st.as_str(), b.as_str(), *pt))
                .unwrap_or(("", "", ParsedTs::default()));
            let has_content_trunc = compact_steps
                .get(p_idx + 1 + p_pos)
                .and_then(|s| s.get("truncated_fields"))
                .and_then(|v| v.as_array())
                .map_or(false, |arr| arr.iter().any(|x| x.as_str() == Some("content")));
            on_swarm_res(ev, p_tc, g_status, blob, g_pt, p_call_ts, None, !has_content_trunc);
        }
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
        current_diff_hash,
        cwd,
        research_reset_ts,
        research_reset_seq,
        marker,
    } = input;
    let mut ev = SwarmEvidence {
        codex_issue_step: -1,
        ..SwarmEvidence::default()
    };
    let mut simplify_events: Vec<SimplifyHistoryItem> = Vec::new();
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
                                worker_name: &str,
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
        let mut simplify_failed = false;
        let is_simp_worker = cwg_common::is_simplify_worker_name(worker_name);
        for (model_id, always_simplify, verified, issue_ts, last_ts) in [
            (
                cwg_common::SONNET_HIGH_MODEL,
                true,
                &mut ev.sonnet_issue_verified,
                &mut ev.sonnet_issue_ts,
                &mut ev.sonnet_last_issue_ts,
            ),
            (
                cwg_common::NEON_XHIGH_MODEL,
                false,
                &mut ev.neon_issue_verified,
                &mut ev.neon_issue_ts,
                &mut ev.neon_last_issue_ts,
            ),
            (
                cwg_common::HYDROGEN_XHIGH_MODEL,
                false,
                &mut ev.hydrogen_issue_verified,
                &mut ev.hydrogen_issue_ts,
                &mut ev.hydrogen_last_issue_ts,
            ),
        ] {
            if models.iter().any(|m| m.contains(model_id)) {
                mark_issue_ts(verified, issue_ts, Some(last_ts), min_ts, max_ts);
                if always_simplify || is_simp_worker {
                    simplify_failed = true;
                }
            }
        }
        if simplify_failed {
            ev.simplify_failures += 1;
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
            if let Some(t_idx) = tail_idx.filter(|&i| i > 1 && (tail_ts == 0.0 || tail_ts > first_ts - 2.0)) {
                // SAFETY: Recover early candidate swarm model/quota signals evicted from `transcript_full.jsonl` tail window via compact `transcript.jsonl` without shifting `steps` indices.
                ev.compact_steps = recover_compact_swarm_steps(
                    tp,
                    t_idx,
                    first_ts,
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
        if call_ts > 0.0 && call_ts < first_ts - 2.0 {
            continue;
        }
        let all_tcs = st
            .get("tool_calls")
            .and_then(|v| v.as_array())
            .map(|a| a.as_slice())
            .unwrap_or(&[]);
        if call_ts > 0.0 {
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
        let has_swarm_tc = all_tcs
            .iter()
            .any(|tc| tc.get("name").and_then(|v| v.as_str()) == Some("swarm"));
        let has_run_cmd_tc = all_tcs
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
            if tname != "swarm" {
                continue;
            }
            inspect_swarm_tool_result(&mut ev, tc, g_status, blob, g_pt, call_ts, Some(idx), true);
        }
    }

    ev.pending_bg_tasks = pending_bg_tasks.into_iter().collect();
    ev.passive_bg_tasks = passive_bg_tasks.into_iter().collect();

    let fallback_cid = marker.map(|m| val_to_str(m.get("session"))).unwrap_or_default();
    let (brain_root_opt, conv_cid) =
        rio::swarm_brain_and_cid(transcript_path.unwrap_or(""), &fallback_cid);
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

    let round_start_ts_lb: f64 = if round_start_msg_id > 0 {
        parsed_board
            .iter()
            .filter(|e| e.seq > 0 && e.seq <= round_start_msg_id && (e.ord_ts > 0.0 || e.pub_ts > 0.0))
            .map(|e| e.ord_ts.max(e.pub_ts))
            .reduce(f64::max)
            .unwrap_or(0.0)
    } else {
        0.0
    };
    let round_start_ts_ub: f64 = if round_start_msg_id > 0 {
        // INVARIANT: `board.jsonl` is append-only in `seq` order; compute upper bounds strictly
        // from board publication timestamps (`pub_ts`/`pub_coarse`) rather than earlier coordinator
        // `post_message` call timestamps so an exact publication tightens earlier coarse rows
        // without shifting the round boundary backward to call time.
        let mut pre: Vec<(i64, f64, bool)> = parsed_board
            .iter()
            .filter(|e| e.seq > 0 && e.seq <= round_start_msg_id && e.pub_ts > 0.0)
            .map(|e| (e.seq, e.pub_ts, e.pub_coarse))
            .collect();
        pre.sort_by_key(|&(seq, _, _)| seq);
        let mut prev_lb = 0.0f64;
        let mut rs_ub = 0.0f64;
        for (_, pub_ts, pub_coarse) in pre {
            cwg_common::advance_monotonic_ub(
                pub_ts,
                pub_coarse,
                board_ts_upper_bound(pub_ts, pub_coarse),
                &mut prev_lb,
                &mut rs_ub,
            );
        }
        rs_ub
    } else {
        0.0
    };

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

    for (member_idx, (mname, minfo)) in members_map.iter().enumerate() {
        if !minfo.is_object() || rio::is_swarm_role_member(mname, Some(minfo)) {
            continue;
        }
        let worker_ord = member_idx + 1;
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
            let parsed = cwg_common::parse_simplify_verdict(text, None);
            let has_simp = !val_to_str(parsed.get("verdict")).is_empty();
            let simp_clean = json_truthy(parsed.get("clean"));
            let rev_dec = cwg_common::extract_review_decision(text);
            let has_rev = rev_dec.0.is_some() && rev_dec.1.is_some();
            let rev_pos = matches!(rev_dec.1.as_deref(), Some("APPROVED" | "READY"));
            // INVARIANT: Never classify any message containing a positive verdict (`CLEAN`, `APPROVED`, `READY`)
            // as a fail-closed revoker, so mixed text can never warp a positive verdict across a window.
            if (has_simp && simp_clean) || (has_rev && rev_pos) {
                Some(true)
            } else if has_simp || has_rev {
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
        // INVARIANT: Detect fail-closed revokers split across two adjacent transcript messages
        // (including when `head` already holds a prior verdict plus a trailing `SIMPLIFY_VERDICT:`
        // or `VERDICT:`/`CLOSURE_VALIDATION:` header). Never mark a positive-verdict-bearing
        // message itself as `split_revoker_t`.
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
            let tail_has_simp_revoker = head_has_rev_hdr
                && (contains_ascii_ci(tail, b"actionable_fixes")
                    || contains_ascii_ci(tail, b"findings_reported"));
            let pair_may_cross_rev =
                might_cross_rev_revoker_with_hdr(head, tail, head_has_rev_hdr);
            if !tail_has_simp_revoker && !pair_may_cross_rev {
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
            if !tail_has_simp_revoker && !can_cross_rev {
                continue;
            }
            let need_simp_spans = tail_has_simp_revoker
                || (can_cross_rev
                    && (contains_ascii_ci(tail, b"clean")
                        || (cur_pol == Some(true) && contains_ascii_ci(head, b"clean"))));
            let simp_spans = if need_simp_spans {
                let pair_txt = format!("{}\n\n{}", head, tail);
                cwg_common::find_simplify_verdict_spans(&pair_txt)
            } else {
                Vec::new()
            };
            let boundary_end = head.len() + 2;
            let crosses_simp_revoker = tail_has_simp_revoker
                && simp_spans
                    .iter()
                    .any(|&(ms, me, is_clean)| ms < head.len() && me > boundary_end && !is_clean);
            let crosses_rev_revoker = !crosses_simp_revoker
                && can_cross_rev
                && !simp_spans.last().is_some_and(|&(_, _, is_clean)| is_clean)
                && cwg_common::extract_split_review_revoker(head, tail).0.is_some();
            if crosses_simp_revoker || crosses_rev_revoker {
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
            delayed_flush: bool,
            text: String,
            bseq: i64,
            causal_seq: i64,
            pre_round_stale: bool,
            is_split_revoker: bool,
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
                    delayed_flush: out.delayed_flush,
                    text: out.text.clone(),
                    bseq: out.bseq,
                    causal_seq: out.causal_seq,
                    pre_round_stale: out
                        .tidx
                        .is_some_and(|ti| pre_round_declined_t.contains(&ti)),
                    is_split_revoker: out.tidx.is_some_and(|ti| split_revoker_t[ti]),
                });
        }

        let joined_worker_text = combined_outputs
            .iter()
            .map(|x| x.text.as_str())
            .collect::<Vec<&str>>()
            .join("\n\n");
        let (skind, slens) = classify_simplify_worker(mname, &latest_brief, &joined_worker_text);
        let mut w_step_idx = worker_add_step.get(mname).copied();
        if w_step_idx.is_none() && !group_prefix.is_empty() {
            w_step_idx = worker_add_step.get(group_prefix).copied();
        }
        if (skind == "lens" && slens.is_some()) || skind == "combined" {
            // INVARIANT: Simplify fallback distinguishes Neon XHigh (`fallback`) from secondary Hydrogen XHigh (`secondary-fallback`), never Carbon.
            let classify_simplify_tier = |mdl: &str| -> &'static str {
                if mdl == cwg_common::SONNET_HIGH_MODEL {
                    cwg_common::SIMPLIFY_TIER_SONNET
                } else if mdl == cwg_common::NEON_XHIGH_MODEL {
                    cwg_common::SIMPLIFY_TIER_FALLBACK
                } else if mdl == cwg_common::HYDROGEN_XHIGH_MODEL {
                    cwg_common::SIMPLIFY_TIER_SECONDARY_FALLBACK
                } else {
                    ""
                }
            };
            struct WinOut<'a> {
                raw_ts: f64,
                order_ts: f64,
                attr_ts: f64,
                attr_coarse: bool,
                delayed_flush: bool,
                text: &'a str,
                bseq: i64,
                causal_seq: i64,
                has_verdict: bool,
                is_clean: bool,
                pre_round_stale: bool,
                is_split_revoker: bool,
            }
            #[derive(Clone, Copy, PartialEq, Eq)]
            enum MsgFreshness {
                Stale,
                RevokerExc,
                Fresh,
            }
            let round_start_eff_ub = if round_start_ts_ub > round_start_ts_lb + 2.0 * TS_EPS {
                round_start_ts_ub
            } else {
                round_start_ts_lb
            };
            let msg_freshness = |item: &WinOut<'_>, seen_clean: bool| -> MsgFreshness {
                if round_start_msg_id <= 0 {
                    return MsgFreshness::Fresh;
                }
                if item.bseq > 0 && item.bseq <= round_start_msg_id {
                    return MsgFreshness::Stale;
                }
                if item.bseq > round_start_msg_id
                    && formed_before(
                        item.delayed_flush,
                        item.attr_ts,
                        item.attr_coarse,
                        round_start_ts_lb,
                        round_start_eff_ub,
                        !item.is_clean && (item.has_verdict || item.is_split_revoker),
                    )
                {
                    return MsgFreshness::Stale;
                }
                if item.bseq == 0 {
                    let base_stale = item.raw_ts <= 0.0
                        || (round_start_ts_ub > 0.0 && item.raw_ts < round_start_ts_ub);
                    let non_clean_revoker = (item.has_verdict || item.is_split_revoker)
                        && !item.is_clean
                        && (seen_clean
                            || item.causal_seq > round_start_msg_id
                            || (round_start_ts_lb > 0.0
                                && item.raw_ts.max(item.order_ts)
                                    >= round_start_ts_lb - TS_EPS));
                    if item.pre_round_stale || (!non_clean_revoker && base_stale) {
                        return MsgFreshness::Stale;
                    }
                    if base_stale && non_clean_revoker {
                        return MsgFreshness::RevokerExc;
                    }
                }
                MsgFreshness::Fresh
            };
            let build_item = |src_out: &WinOut<'_>,
                              win_ts: f64,
                              win_ord: usize,
                              win_tier: &str,
                              clean: bool,
                              lens_flags: (bool, bool)|
             -> (SimplifyHistoryItem, bool) {
                let eff_lts = launch_ts_or_start(win_ts, tsum.start_ts, first_ts);
                let eff_ets = eff_lts.max(src_out.raw_ts.max(src_out.order_ts));
                let (has_explicit_all, multi_lens_spoof) = lens_flags;
                let spoof = multi_lens_spoof
                    || (skind == "combined"
                        && !has_explicit_all
                        && !simplify_combined_name_re().is_match(mname.trim()));
                (
                    SimplifyHistoryItem {
                        kind: skind.to_string(),
                        lens: if skind == "lens" { slens.clone() } else { None },
                        tier: win_tier.to_string(),
                        launch_ts: eff_lts,
                        end_ts: eff_ets,
                        seq: src_out.bseq,
                        causal_seq: src_out.bseq.max(src_out.causal_seq),
                        worker_ord,
                        win_ord,
                        clean,
                        has_explicit_all,
                    },
                    spoof,
                )
            };

            let cur_simp_tier = classify_simplify_tier(&cur_model);
            let worker_has_simplify_model = !cur_simp_tier.is_empty()
                || (has_any_switch
                    && model_events.iter().any(|e| match e {
                        WorkerModelEvent::ConfirmedAdd { model, .. }
                        | WorkerModelEvent::ConfirmedSwitch { model, .. } => {
                            !classify_simplify_tier(model).is_empty()
                        }
                        WorkerModelEvent::UnconfirmedSwitch { .. } => false,
                    }));
            if !worker_has_simplify_model {
                continue;
            }
            let mut recorded_simplify_step = false;
            let mut seen_fresh_clean = false;
            let mut win_keys: Vec<usize> = bucketed_outputs.keys().copied().collect();
            win_keys.sort();
            for w_idx in win_keys {
                let win_ts = windows[w_idx].ts;
                let win_outs = &bucketed_outputs[&w_idx];
                let win_annotated: Vec<WinOut<'_>> = win_outs
                    .iter()
                    .map(|bo| {
                        let p = cwg_common::parse_simplify_verdict(&bo.text, None);
                        WinOut {
                            raw_ts: bo.raw_ts,
                            order_ts: bo.order_ts,
                            attr_ts: bo.attr_ts,
                            attr_coarse: bo.attr_coarse,
                            delayed_flush: bo.delayed_flush,
                            text: bo.text.as_str(),
                            bseq: bo.bseq,
                            causal_seq: bo.causal_seq,
                            has_verdict: !val_to_str(p.get("verdict")).is_empty(),
                            is_clean: json_truthy(p.get("clean")),
                            pre_round_stale: bo.pre_round_stale,
                            is_split_revoker: bo.is_split_revoker,
                        }
                    })
                    .collect();
                let k = win_annotated.len();
                if k == 0 {
                    continue;
                }
                let total_len: usize = win_annotated.iter().map(|x| x.text.len()).sum::<usize>()
                    + k.saturating_sub(1) * 2;
                let mut all_joined = String::with_capacity(total_len);
                let mut ends: Vec<usize> = Vec::with_capacity(k);
                for (i, x) in win_annotated.iter().enumerate() {
                    if i > 0 {
                        all_joined.push_str("\n\n");
                    }
                    all_joined.push_str(x.text);
                    ends.push(all_joined.len());
                }
                let (all_spans, all_explicit_all, all_multi_spoof) =
                    cwg_common::parse_simplify_window_spans(&all_joined);
                if all_spans.is_empty() {
                    continue;
                }
                let all_lens_flags = (all_explicit_all, all_multi_spoof);
                let mut msg_in_any_span = vec![false; k];
                let span_bounds: Vec<(usize, usize, bool)> = all_spans
                    .iter()
                    .map(|&(ms, me, is_clean)| {
                        let start_msg = ends.partition_point(|&e| e <= ms).min(k - 1);
                        let end_msg = ends.partition_point(|&e| e < me).min(k - 1);
                        for flag in &mut msg_in_any_span[start_msg..=end_msg] {
                            *flag = true;
                        }
                        (start_msg, end_msg, is_clean)
                    })
                    .collect();
                // INVARIANT: Distinguish definitively disallowed non-simplify models (e.g. Carbon/Opus ->
                // `SpanTier::Disallowed`, ignored completely) from ambiguous/in-flight switch intervals
                // (`SpanTier::Ambiguous`, failing closed by rejecting `CLEAN` while preserving
                // `ACTIONABLE_FIXES` revokers with empty tier) and valid simplify epochs (`SpanTier::Allowed`).
                #[derive(Clone, Copy, PartialEq, Eq)]
                enum SpanTier {
                    Allowed(&'static str),
                    Ambiguous,
                    Disallowed,
                }
                let span_tiers: Vec<SpanTier> = if has_any_switch {
                    span_bounds
                        .iter()
                        .map(|&(start_msg, end_msg, _)| {
                            let mut agreed_tier: &'static str = "";
                            let mut has_ambiguous = false;
                            for item in &win_annotated[start_msg..=end_msg] {
                                let mdl = resolve_window_model(
                                    &model_events,
                                    &cur_model,
                                    true,
                                    item.attr_ts,
                                    item.attr_coarse,
                                );
                                if mdl.is_empty() {
                                    has_ambiguous = true;
                                    continue;
                                }
                                let tier = classify_simplify_tier(&mdl);
                                if tier.is_empty() {
                                    return SpanTier::Disallowed;
                                }
                                if agreed_tier.is_empty() {
                                    agreed_tier = tier;
                                } else if agreed_tier != tier {
                                    has_ambiguous = true;
                                }
                            }
                            if has_ambiguous || agreed_tier.is_empty() {
                                SpanTier::Ambiguous
                            } else {
                                SpanTier::Allowed(agreed_tier)
                            }
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                let span_tier_at = |s_idx: usize| -> SpanTier {
                    if has_any_switch {
                        span_tiers[s_idx]
                    } else {
                        SpanTier::Allowed(cur_simp_tier)
                    }
                };
                let mut hist_span: Option<(usize, bool, &'static str)> = None;
                for (s_idx, &(_, end_msg, is_clean)) in span_bounds.iter().enumerate() {
                    match span_tier_at(s_idx) {
                        SpanTier::Allowed(tier) => {
                            hist_span = Some((end_msg, is_clean, tier));
                        }
                        SpanTier::Ambiguous if !is_clean => {
                            // INVARIANT: Preserve fail-closed revokers (`ACTIONABLE_FIXES` /
                            // `FINDINGS_REPORTED`) with an empty tier (`""`) only when the model
                            // epoch is ambiguous/in-flight — never for definitively non-simplify models.
                            hist_span = Some((end_msg, false, ""));
                        }
                        SpanTier::Ambiguous | SpanTier::Disallowed => {}
                    }
                }
                let Some((hist_end_msg, hist_clean, hist_tier)) = hist_span else {
                    continue;
                };
                if !recorded_simplify_step {
                    recorded_simplify_step = true;
                    if let Some(ws) = w_step_idx {
                        ev.simplify_launch_steps.insert(ws);
                    }
                }
                // INVARIANT: Record every completed attributed window in `simplify_history` (unfiltered by
                // current `round_start_msg_id` / `current_diff_hash`) attributed to its completing span message.
                let (hist_ev, hist_spoof) = build_item(
                    &win_annotated[hist_end_msg],
                    win_ts,
                    w_idx,
                    hist_tier,
                    hist_clean,
                    all_lens_flags,
                );
                ev.simplify_history.push(hist_ev.clone());

                // INVARIANT: Evaluate round freshness and `current_diff_hash` directly on each original
                // verdict span `(start_msg..=end_msg)` plus its adjacent fresh non-verdict messages
                // without deleting intermediate messages and re-gluing non-adjacent fragments (`4t3`/`4t4`).
                // Positive `CLEAN` requires every message in `start_msg..=end_msg` to be strictly
                // `MsgFreshness::Fresh` and every explicit `DIFF_HASH` across both the verdict and its
                // adjacent fresh non-verdict messages to match `current_diff_hash` (fail-closed under
                // conflicting hashes), while revokers are skipped only when every explicit hash mismatches.
                let msg_hash_flags: Vec<(bool, bool)> = if current_diff_hash.is_empty() {
                    Vec::new()
                } else {
                    win_annotated
                        .iter()
                        .map(|item| cwg_common::check_diff_hashes(item.text, current_diff_hash))
                        .collect()
                };
                let mut msg_is_fresh = vec![false; k];
                let mut all_msgs_fresh_and_hash_ok = true;
                for (idx, item) in win_annotated.iter().enumerate() {
                    let is_fresh = msg_freshness(item, false) == MsgFreshness::Fresh;
                    msg_is_fresh[idx] = is_fresh;
                    let no_mismatch = current_diff_hash.is_empty() || !msg_hash_flags[idx].1;
                    if !(is_fresh && no_mismatch) {
                        all_msgs_fresh_and_hash_ok = false;
                    }
                }
                let mut last_fresh_span: Option<(usize, bool, &'static str)> = None;
                for (s_idx, &(start_msg, end_msg, is_clean)) in span_bounds.iter().enumerate() {
                    let span_fresh_ok = if is_clean {
                        (start_msg..=end_msg).all(|i| msg_is_fresh[i])
                    } else {
                        msg_is_fresh[end_msg]
                            || msg_freshness(&win_annotated[end_msg], seen_fresh_clean)
                                != MsgFreshness::Stale
                    };
                    if !span_fresh_ok {
                        continue;
                    }
                    if !current_diff_hash.is_empty() {
                        let prev_end = span_bounds[..s_idx]
                            .iter()
                            .rev()
                            .find(|s| s.1 < start_msg)
                            .map_or(0, |s| s.1 + 1);
                        let next_start = span_bounds[s_idx + 1..]
                            .iter()
                            .find(|s| s.0 > end_msg)
                            .map_or(k, |s| s.0);
                        let (mut any_match, mut any_mismatch) = (false, false);
                        for j in prev_end..next_start {
                            if (start_msg..=end_msg).contains(&j)
                                || (!msg_in_any_span[j] && msg_is_fresh[j])
                            {
                                any_match |= msg_hash_flags[j].0;
                                any_mismatch |= msg_hash_flags[j].1;
                            }
                        }
                        let hash_rejected = if is_clean {
                            any_mismatch
                        } else {
                            any_mismatch && !any_match
                        };
                        if hash_rejected {
                            continue;
                        }
                    }
                    match span_tier_at(s_idx) {
                        SpanTier::Allowed(tier) => {
                            if is_clean {
                                seen_fresh_clean = true;
                            }
                            last_fresh_span = Some((end_msg, is_clean, tier));
                        }
                        SpanTier::Ambiguous if !is_clean => {
                            last_fresh_span = Some((end_msg, false, ""));
                        }
                        SpanTier::Ambiguous | SpanTier::Disallowed => {}
                    }
                }
                let fresh_pair = last_fresh_span.map(|(end_msg, clean, fresh_tier)| {
                    if all_msgs_fresh_and_hash_ok && last_fresh_span == hist_span {
                        (hist_ev, hist_spoof)
                    } else {
                        let mut fresh_lens_text = String::new();
                        let mut prev_idx: Option<usize> = None;
                        for (idx, item) in win_annotated.iter().enumerate() {
                            let hash_ok = current_diff_hash.is_empty()
                                || !msg_hash_flags[idx].1
                                || (!clean && msg_hash_flags[idx].0);
                            let eligible = hash_ok
                                && (msg_is_fresh[idx]
                                    || (!clean
                                        && msg_freshness(item, seen_fresh_clean)
                                            != MsgFreshness::Stale));
                            if !eligible {
                                continue;
                            }
                            if let Some(pi) = prev_idx {
                                fresh_lens_text.push_str(if idx == pi + 1 {
                                    "\n\n"
                                } else {
                                    "\n\n---\n\n"
                                });
                            }
                            fresh_lens_text.push_str(item.text);
                            prev_idx = Some(idx);
                        }
                        let lens_flags = cwg_common::parse_simplify_lens_flags(&fresh_lens_text);
                        build_item(
                            &win_annotated[end_msg],
                            win_ts,
                            w_idx,
                            fresh_tier,
                            clean,
                            lens_flags,
                        )
                    }
                });
                if let Some((sev, spoof)) = fresh_pair {
                    if spoof {
                        ev.multi_lens_spoof = true;
                        if sev.end_ts > ev.multi_lens_spoof_ts {
                            ev.multi_lens_spoof_ts = sev.end_ts;
                        }
                    }
                    simplify_events.push(sev);
                }
            }
            continue;
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

    // INVARIANT: Replay simplify events in chronological order across all workers so a stale CLEAN in another member entry can never survive or overwrite a later ACTIONABLE_FIXES verdict.
    SimplifyHistoryItem::sort_chronologically(&mut simplify_events);
    SimplifyHistoryItem::sort_chronologically(&mut ev.simplify_history);
    for sev in &simplify_events {
        if !sev.clean {
            if sev.kind == "lens" {
                if let Some(ref sl) = sev.lens {
                    ev.sonnet_lenses.remove(sl);
                    ev.sonnet_lenses_end.remove(sl);
                    ev.fallback_lenses.remove(sl);
                    ev.fallback_lenses_end.remove(sl);
                    ev.secondary_fallback_lenses.remove(sl);
                    ev.secondary_fallback_lenses_end.remove(sl);
                }
            } else {
                ev.sonnet_combined_ts = 0.0;
                ev.sonnet_combined_end_ts = 0.0;
                ev.fallback_combined_ts = 0.0;
                ev.fallback_combined_end_ts = 0.0;
                ev.secondary_fallback_combined_ts = 0.0;
                ev.secondary_fallback_combined_end_ts = 0.0;
            }
            continue;
        }
        let (lenses_map, ends_map, comb_ts_ref, comb_end_ref) =
            if sev.tier == cwg_common::SIMPLIFY_TIER_SONNET {
                (
                    &mut ev.sonnet_lenses,
                    &mut ev.sonnet_lenses_end,
                    &mut ev.sonnet_combined_ts,
                    &mut ev.sonnet_combined_end_ts,
                )
            } else if sev.tier == cwg_common::SIMPLIFY_TIER_SECONDARY_FALLBACK {
                (
                    &mut ev.secondary_fallback_lenses,
                    &mut ev.secondary_fallback_lenses_end,
                    &mut ev.secondary_fallback_combined_ts,
                    &mut ev.secondary_fallback_combined_end_ts,
                )
            } else {
                (
                    &mut ev.fallback_lenses,
                    &mut ev.fallback_lenses_end,
                    &mut ev.fallback_combined_ts,
                    &mut ev.fallback_combined_end_ts,
                )
            };
        if sev.kind == "lens" {
            if let Some(ref sl) = sev.lens {
                record_lens_window(lenses_map, ends_map, sl, sev.launch_ts, sev.end_ts);
            }
        } else {
            record_combined_window(comb_ts_ref, comb_end_ref, sev.launch_ts, sev.end_ts);
        }
    }
    ev.simplify_current_history = Some(simplify_events);

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
    pub fallback_lenses: HashMap<String, f64>,
    pub secondary_fallback_lenses: HashMap<String, f64>,
    pub fallback_lenses_end: HashMap<String, f64>,
    pub secondary_fallback_lenses_end: HashMap<String, f64>,
    pub fallback_combined_ts: f64,
    pub secondary_fallback_combined_ts: f64,
    pub fallback_combined_end_ts: f64,
    pub secondary_fallback_combined_end_ts: f64,
    pub simplify_launch_steps: HashSet<usize>,
    pub simplify_history: Vec<SimplifyHistoryItem>,
    pub neon_simplify_failures: i64,
    pub neon_simplify_failure_ts: f64,
    pub hydrogen_simplify_failures: i64,
    pub hydrogen_simplify_failure_ts: f64,
    pub reviews: Vec<Value>,
    pub review_failures: Vec<f64>,
    pub in_flight_subagents: Vec<String>,
}

impl SubagentEvidence {
    fn record_fallback_simplify(
        &mut self,
        is_secondary: bool,
        kind: &str,
        lens: Option<&str>,
        launch_ts: f64,
        end_ts: f64,
    ) {
        let tier = if is_secondary {
            cwg_common::SIMPLIFY_TIER_SECONDARY_FALLBACK
        } else {
            cwg_common::SIMPLIFY_TIER_FALLBACK
        };
        let (lens_val, has_explicit_all) = match (kind, lens) {
            ("lens", Some(sl)) => {
                if is_secondary {
                    record_lens_window(
                        &mut self.secondary_fallback_lenses,
                        &mut self.secondary_fallback_lenses_end,
                        sl,
                        launch_ts,
                        end_ts,
                    );
                } else {
                    record_lens_window(
                        &mut self.fallback_lenses,
                        &mut self.fallback_lenses_end,
                        sl,
                        launch_ts,
                        end_ts,
                    );
                }
                (Some(sl.to_string()), false)
            }
            ("combined", _) => {
                if is_secondary {
                    record_combined_window(
                        &mut self.secondary_fallback_combined_ts,
                        &mut self.secondary_fallback_combined_end_ts,
                        launch_ts,
                        end_ts,
                    );
                } else {
                    record_combined_window(
                        &mut self.fallback_combined_ts,
                        &mut self.fallback_combined_end_ts,
                        launch_ts,
                        end_ts,
                    );
                }
                (None, true)
            }
            _ => return,
        };
        self.simplify_history.push(SimplifyHistoryItem {
            kind: kind.to_string(),
            lens: lens_val,
            tier: tier.to_string(),
            launch_ts,
            end_ts,
            seq: 0,
            clean: true,
            has_explicit_all,
            ..Default::default()
        });
    }
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

    let first_idx = steps
        .first()
        .and_then(|s| s.get("step_index"))
        .and_then(|v| v.as_i64());
    let tp_is_file = transcript_path.map_or(false, |tp| !tp.is_empty() && Path::new(tp).is_file());
    let head_slice: Option<&[Value]> = if !steps.is_empty()
        && (matches!(first_idx, None | Some(0)) || !tp_is_file)
    {
        Some(&steps[..steps.len().min(5)])
    } else {
        None
    };
    let caller_worker_model =
        rio::swarm_worker_model(transcript_path.unwrap_or(""), head_slice, &parent_cid);

    let record_sub_simplify_fail = |ev: &mut SubagentEvidence, secondary: bool, ts: f64| {
        if secondary {
            ev.hydrogen_simplify_failures += 1;
            ev.hydrogen_simplify_failure_ts = ev.hydrogen_simplify_failure_ts.max(ts);
        } else {
            ev.neon_simplify_failures += 1;
            ev.neon_simplify_failure_ts = ev.neon_simplify_failure_ts.max(ts);
        }
    };

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
            let role_str = args
                .and_then(|m| m.get("Role"))
                .map(|v| val_to_str(Some(v)).trim().to_string())
                .unwrap_or_default();
            let prompt_str = args
                .and_then(|m| m.get("Prompt"))
                .map(|v| val_to_str(Some(v)).trim().to_string())
                .unwrap_or_default();
            let is_simplify_subagent = cwg_common::is_simplify_subagent_call(base_tname, &role_str);
            let model_arg = args
                .and_then(|m| m.get("Model"))
                .map(|v| val_to_str(Some(v)).trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "inherit".to_string());
            // INVARIANT: Credit `invoke_subagent` simplify runs only when inherited inside a verified Neon/Hydrogen XHigh swarm fallback worker.
            let is_secondary_fallback =
                caller_worker_model.as_deref() == Some(cwg_common::HYDROGEN_XHIGH_MODEL);
            let has_simplify_fallback_provenance = is_simplify_subagent
                && caller_worker_model
                    .as_deref()
                    .map_or(false, |m| cwg_common::SIMPLIFY_FALLBACK_MODELS.contains(&m))
                && matches!(model_arg.to_lowercase().as_str(), "" | "inherit");

            let (g_status, blob) = if pos < generic_steps.len() {
                (generic_steps[pos].0.as_str(), generic_steps[pos].1.as_str())
            } else {
                ("", "")
            };
            let Some(sm) = subagent_uri_re().captures(blob) else {
                let blob_low = blob.to_lowercase();
                if g_status == "ERROR"
                    || blob_low.contains("error")
                    || blob_low.contains("failed")
                {
                    if has_simplify_fallback_provenance {
                        let fail_ts = if pos < generic_steps.len() && generic_steps[pos].2.ts > 0.0 {
                            call_ts.max(generic_steps[pos].2.ts)
                        } else if call_ts > 0.0 {
                            call_ts
                        } else {
                            0.0
                        };
                        record_sub_simplify_fail(&mut ev, is_secondary_fallback, fail_ts);
                    } else if NATIVE_REVIEWERS.contains(&base_tname) {
                        ev.review_failures
                            .push(if call_ts > 0.0 { call_ts } else { now_sec() });
                    }
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
            let sub_text = merged_chunks
                .iter()
                .map(|c| c.text.as_str())
                .collect::<Vec<&str>>()
                .join("\n\n")
                .trim()
                .to_string();
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

            if is_simplify_subagent {
                let brief_ctx = format!("{}\n{}", role_str, prompt_str);
                let mut chosen_skind: &str = "other";
                let mut chosen_slens: Option<String> = None;
                let mut chosen_sts = 0.0f64;
                let mut has_simplify_verdict = false;
                let mut prev_send_sdec: Option<(String, Option<String>, String)> = None;

                for ch in &merged_chunks {
                    let parsed_c = cwg_common::parse_simplify_verdict(&ch.text, None);
                    let s_verdict = val_to_str(parsed_c.get("verdict"));
                    if !s_verdict.is_empty() {
                        let (mut sk, mut sl) =
                            classify_simplify_worker(base_tname, &brief_ctx, &ch.text);
                        if sk == "other" {
                            (sk, sl) =
                                classify_simplify_worker(base_tname, &brief_ctx, &sub_text);
                        }
                        let sdec = (sk.to_string(), sl.clone(), s_verdict);
                        if !(ch.kind == "final"
                            && ch.is_signoff
                            && prev_send_sdec.as_ref() == Some(&sdec))
                        {
                            has_simplify_verdict = true;
                            chosen_skind = sk;
                            chosen_slens = sl;
                            chosen_sts = ch.ts;
                        }
                        prev_send_sdec = if ch.kind == "send" { Some(sdec) } else { None };
                    } else {
                        prev_send_sdec = None;
                    }
                }

                if has_simplify_verdict {
                    let end_cand = if chosen_sts > 0.0 {
                        chosen_sts
                    } else if fallback_end_ts > 0.0 {
                        fallback_end_ts
                    } else {
                        eff_launch_ts
                    };
                    let eff_end_ts = eff_launch_ts.max(end_cand);
                    ev.simplify_launch_steps.insert(idx);
                    if has_simplify_fallback_provenance {
                        ev.record_fallback_simplify(
                            is_secondary_fallback,
                            chosen_skind,
                            chosen_slens.as_deref(),
                            eff_launch_ts,
                            eff_end_ts,
                        );
                    }
                } else if sub_text.is_empty() && has_simplify_fallback_provenance {
                    record_sub_simplify_fail(
                        &mut ev,
                        is_secondary_fallback,
                        fallback_end_ts.max(call_ts),
                    );
                }
            } else if NATIVE_REVIEWERS.contains(&base_tname) {
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
    if allow_approved && lv == "APPROVED" {
        if effective_risk == "XHIGH" && !json_truthy(last_ord.get("xhigh")) {
            return false;
        }
    } else if lv == "REVISE" || lv == "ESCALATE" {
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
    needs_simplify: bool,
    allow_combined: bool,
    multi_lens_spoof: bool,
    sonnet_issue: bool,
    sonnet_issue_ts: f64,
    neon_issue: bool,
    neon_issue_ts: f64,
    effective_risk: &'a str,
    required_lenses: &'a HashSet<String>,
    active_simplify_windows: &'a [(f64, f64)],
    max_simplify_launch_ts: f64,
    max_simplify_end_ts: f64,
    all_simplify_steps: &'a HashSet<usize>,
    all_simplify_history: &'a [SimplifyHistoryItem],
    current_simplify_history: &'a [SimplifyHistoryItem],
    candidate_marks: &'a [&'a Map<String, Value>],
    oldest_mark_ts: f64,
    first_ts_val: f64,
    marks_truncated: bool,
    tx_edits_cache: Option<TranscriptEditEvidence>,
    swarm_ev: &'a SwarmEvidence,
    codex_bin_missing_cache: Option<bool>,
    breaker_info_cache: Option<Value>,
    sim_ver_cache: HashMap<(u64, i64), bool>,
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

    fn is_after_simplify(&self, rev_item: &Value) -> bool {
        if !(self.needs_simplify && !self.active_simplify_windows.is_empty()) {
            return true;
        }
        let rev_launch_ts = val_to_f64(rev_item.get("launch_ts"));
        if let Some(rev_step_idx) = rev_item
            .get("step_idx")
            .and_then(|v| v.as_i64())
            .filter(|&x| x >= 0)
        {
            if self.all_simplify_steps.contains(&(rev_step_idx as usize)) {
                return false;
            }
        }
        if self.max_simplify_launch_ts > 0.0 && rev_launch_ts <= self.max_simplify_launch_ts {
            return false;
        }
        if self.max_simplify_end_ts > 0.0 && rev_launch_ts < self.max_simplify_end_ts {
            return false;
        }
        true
    }

    fn version_edit_bounds(&mut self, rev_launch_ts: f64) -> Option<(f64, f64)> {
        let marks_before: Vec<&Map<String, Value>> = self
            .candidate_marks
            .iter()
            .copied()
            .filter(|m| val_to_f64(m.get("ts")) <= rev_launch_ts)
            .collect();
        if !marks_before.is_empty() {
            let last_mark = marks_before[marks_before.len() - 1];
            if let Some(fp_s) = mark_fp(last_mark) {
                let r_edit = marks_before
                    .iter()
                    .filter(|m| mark_fp(m) == Some(fp_s))
                    .map(|m| val_to_f64(m.get("ts")))
                    .reduce(f64::min)
                    .unwrap_or(0.0);
                let n_edit = self
                    .candidate_marks
                    .iter()
                    .filter(|m| val_to_f64(m.get("ts")) > rev_launch_ts && mark_fp(m) != Some(fp_s))
                    .map(|m| val_to_f64(m.get("ts")))
                    .reduce(f64::min)
                    .unwrap_or(f64::INFINITY);
                return Some((r_edit, n_edit));
            }
            // INVARIANT: Two `fp: null` marks are never proven equal; isolate the exact mark timestamp and treat any subsequent mark as a new version.
            let r_edit = val_to_f64(last_mark.get("ts"));
            let n_edit = self
                .candidate_marks
                .iter()
                .map(|m| val_to_f64(m.get("ts")))
                .filter(|&mts| mts > rev_launch_ts)
                .reduce(f64::min)
                .unwrap_or(f64::INFINITY);
            return Some((r_edit, n_edit));
        }
        if self.marks_truncated {
            let tx_ev = self.get_tx_edits();
            let mut r_edit = self.first_ts_val;
            for (sts, ets) in &tx_ev.edit_spans {
                if *sts <= rev_launch_ts && *ets > r_edit {
                    r_edit = *ets;
                }
            }
            if tx_ev.covered_from_ts > r_edit + 1.0 {
                return None;
            }
            let mut n_edit = f64::INFINITY;
            for (sts, _) in &tx_ev.edit_spans {
                if *sts > rev_launch_ts && *sts < n_edit {
                    n_edit = *sts;
                }
            }
            for m in self.candidate_marks {
                let mts = val_to_f64(m.get("ts"));
                if mts > rev_launch_ts && mts < n_edit {
                    n_edit = mts;
                }
            }
            return Some((r_edit, n_edit));
        }
        let n_edit = self
            .candidate_marks
            .iter()
            .map(|m| val_to_f64(m.get("ts")))
            .filter(|&mts| mts > rev_launch_ts)
            .reduce(f64::min)
            .unwrap_or(f64::INFINITY);
        Some((self.first_ts_val, n_edit))
    }

    fn is_allowed_simplify_tier(&self, tier: &str, launch_ts: f64) -> bool {
        is_simplify_tier_causal(
            tier,
            launch_ts,
            self.sonnet_issue,
            self.sonnet_issue_ts,
            self.neon_issue,
            self.neon_issue_ts,
        )
    }

    fn is_eligible_simplify_item(&self, sr: &SimplifyHistoryItem) -> bool {
        // INVARIANT: Positive `CLEAN` items require an allowed causal simplify tier, while an
        // un-attributable switch-boundary revoker (`!sr.clean && sr.tier.is_empty()`) stays
        // eligible so it can revoke any earlier `CLEAN` across workers.
        (!sr.clean && sr.tier.is_empty()) || self.is_allowed_simplify_tier(&sr.tier, sr.launch_ts)
    }

    fn has_completed_simplify_for_version(&mut self, rev_item: &Value) -> bool {
        if !self.needs_simplify {
            return true;
        }
        if !self.active_simplify_windows.is_empty() && self.is_after_simplify(rev_item) {
            return true;
        }
        let rev_launch_ts = val_to_f64(rev_item.get("launch_ts"));
        let rev_step_key = rev_item
            .get("step_idx")
            .and_then(|v| v.as_i64())
            .unwrap_or(-1);
        let cache_key = (rev_launch_ts.to_bits(), rev_step_key);
        if let Some(&cached) = self.sim_ver_cache.get(&cache_key) {
            return cached;
        }
        if rev_step_key >= 0 && self.all_simplify_steps.contains(&(rev_step_key as usize)) {
            self.sim_ver_cache.insert(cache_key, false);
            return false;
        }

        let Some((rev_edit_ts, next_edit_ts)) = self.version_edit_bounds(rev_launch_ts) else {
            self.sim_ver_cache.insert(cache_key, false);
            return false;
        };

        let hist_src = if next_edit_ts.is_infinite() {
            self.current_simplify_history
        } else {
            self.all_simplify_history
        };
        let mut eligible: Vec<&SimplifyHistoryItem> = Vec::new();
        for sr in hist_src {
            if !self.is_eligible_simplify_item(sr)
                || sr.launch_ts < rev_edit_ts - TS_EPS
                || sr.launch_ts >= next_edit_ts
            {
                continue;
            }
            let s_lts = sr.launch_ts;
            let s_ets = s_lts.max(sr.end_ts);
            if s_lts <= rev_launch_ts && rev_launch_ts < s_ets {
                self.sim_ver_cache.insert(cache_key, false);
                return false;
            }
            if s_lts < rev_launch_ts {
                eligible.push(sr);
            }
        }
        // INVARIANT: Sort AFTER span and tier filtering so excluded future `CLEAN` windows
        // cannot promote an in-span `ACTIONABLE_FIXES` to Stratum 0.
        let res = !eligible.is_empty() && self.simplify_items_satisfied(&eligible, None);
        self.sim_ver_cache.insert(cache_key, res);
        res
    }

    fn simplify_items_satisfied(
        &self,
        items: &[&SimplifyHistoryItem],
        max_end_ts: Option<f64>,
    ) -> bool {
        let Some((done_lenses, done_combined_lts)) =
            SimplifyHistoryItem::replay_completion(items, max_end_ts)
        else {
            return false;
        };
        (self.allow_combined && !self.multi_lens_spoof && done_combined_lts.is_some())
            || self
                .required_lenses
                .iter()
                .all(|req| done_lenses.contains_key(req.as_str()))
    }

    fn is_round_after_its_simplify(&mut self, rev_item: &Value) -> bool {
        if self.is_after_simplify(rev_item) {
            return true;
        }
        self.has_completed_simplify_for_version(rev_item)
    }

    fn has_simplify_between(&self, after_ts: f64, before_ts: f64) -> bool {
        if !self.needs_simplify {
            return true;
        }
        if before_ts <= after_ts {
            return false;
        }
        if self.all_simplify_history.is_empty() {
            return !self.active_simplify_windows.is_empty()
                && self
                    .active_simplify_windows
                    .iter()
                    .all(|&(w_lts, w_ets)| {
                        w_lts >= after_ts - TS_EPS && w_lts < before_ts && w_lts.max(w_ets) <= before_ts
                    });
        }
        let last_dur = val_to_f64(self.marker.get("last_durable_ts"));
        let hist_src = if last_dur > 0.0 && after_ts >= last_dur - TS_EPS {
            self.current_simplify_history
        } else {
            self.all_simplify_history
        };
        let mut span_items: Vec<&SimplifyHistoryItem> = Vec::new();
        for sr in hist_src {
            if !self.is_eligible_simplify_item(sr)
                || sr.launch_ts < after_ts - TS_EPS
                || sr.launch_ts >= before_ts
            {
                continue;
            }
            if sr.launch_ts.max(sr.end_ts) > before_ts {
                return false;
            }
            span_items.push(sr);
        }
        // INVARIANT: Sort AFTER span and tier filtering so excluded future `CLEAN` windows
        // (`launch_ts >= before_ts`) cannot promote an in-span `ACTIONABLE_FIXES` to Stratum 0.
        !span_items.is_empty() && self.simplify_items_satisfied(&span_items, Some(before_ts))
    }

    fn partition_cycle_closure(&mut self, cls_slice: &[Value]) -> (Vec<Value>, Option<Value>, &'static str) {
        // INVARIANT: Every `BLOCKED` verdict permanently consumes a closure slot; a premature `READY` without required simplify is rejected while latest, and superseded (not double-counted) once a fresh simplify + replacement `--closure` pass runs.
        if !self.needs_simplify {
            return (cls_slice.to_vec(), None, "");
        }
        let mut effective: Vec<Value> = Vec::new();
        let mut unreplaced_premature: Option<Value> = None;
        let mut unreplaced_kind = "";
        let mut min_next_sim_after_ts = 0.0_f64;
        for rev in cls_slice {
            let verdict = val_to_str(rev.get("verdict"));
            let rev_lts = val_to_f64(rev.get("launch_ts"));
            let rev_vts = rev_lts.max(val_to_f64(rev.get("verdict_ts")));
            if verdict == "BLOCKED" || effective.len() >= MAX_CLOSURE_PASSES {
                effective.push(rev.clone());
                unreplaced_premature = None;
                unreplaced_kind = "";
                min_next_sim_after_ts = min_next_sim_after_ts.max(rev_vts);
                continue;
            }
            let has_ver_sim = self.is_round_after_its_simplify(rev);
            let after_prev_gate = if min_next_sim_after_ts > 0.0 {
                self.has_simplify_between(min_next_sim_after_ts, rev_lts)
            } else {
                true
            };
            if has_ver_sim && after_prev_gate {
                effective.push(rev.clone());
                unreplaced_premature = None;
                unreplaced_kind = "";
            } else {
                unreplaced_premature = Some(rev.clone());
                unreplaced_kind = if effective.is_empty() {
                    "initial"
                } else {
                    "inter_pass"
                };
            }
            min_next_sim_after_ts = min_next_sim_after_ts.max(rev_vts);
        }
        (effective, unreplaced_premature, unreplaced_kind)
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
        if self.effective_risk == "XHIGH" && !json_truthy(rev_item.get("xhigh")) {
            return false;
        }
        self.has_completed_simplify_for_version(rev_item)
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

    fn is_valid_cycle_closure_ready_at_risk(
        &mut self,
        risk: &str,
        ord_list: &[Value],
        cls_rev: &Value,
    ) -> bool {
        if !closure_ready_tail_ok(risk, ord_list, cls_rev, false) {
            return false;
        }
        if self.has_prior_terminal_approval(ord_list) {
            return false;
        }
        if !self.has_completed_simplify_for_version(cls_rev) {
            return false;
        }
        ord_list
            .iter()
            .all(|r| self.has_completed_simplify_for_version(r))
    }

    fn is_valid_cycle_closure_ready(&mut self, ord_list: &[Value], cls_rev: &Value) -> bool {
        self.is_valid_cycle_closure_ready_at_risk(self.effective_risk, ord_list, cls_rev)
    }

    fn min_simplify_launch_for_version(&mut self, rev_item: &Value) -> f64 {
        if !self.active_simplify_windows.is_empty() && self.is_after_simplify(rev_item) {
            return self
                .active_simplify_windows
                .iter()
                .map(|w| w.0)
                .reduce(f64::min)
                .unwrap_or(0.0);
        }
        let rev_launch_ts = val_to_f64(rev_item.get("launch_ts"));
        let Some((rev_edit_ts, next_edit_ts)) = self.version_edit_bounds(rev_launch_ts) else {
            return 0.0;
        };
        self.all_simplify_history
            .iter()
            .filter(|sr| {
                self.is_eligible_simplify_item(sr)
                    && sr.launch_ts >= rev_edit_ts - TS_EPS
                    && sr.launch_ts < next_edit_ts
                    && sr.launch_ts < rev_launch_ts
            })
            .map(|sr| sr.launch_ts)
            .reduce(f64::min)
            .unwrap_or(0.0)
    }

    fn is_valid_swarm_v2_cycle_closure_ready(
        &mut self,
        ord_list: &[Value],
        pre_simplify_only: bool,
        cls_rev: &Value,
    ) -> bool {
        // INVARIANT: Swarm 2.0 `ORDINARY -> SIMPLIFY -> CLOSURE READY` resets the cycle on post-READY edits without laundering over-limit or mixed post-simplify cycles.
        if !(self.needs_simplify
            && pre_simplify_only
            && closure_ready_tail_ok(self.effective_risk, ord_list, cls_rev, true)
            && self.has_completed_simplify_for_version(cls_rev))
        {
            return false;
        }
        let min_sim_ts = self.min_simplify_launch_for_version(cls_rev);
        min_sim_ts > 0.0
            && !ord_list
                .iter()
                .any(|r| val_to_f64(r.get("launch_ts")) >= min_sim_ts)
    }

    fn was_invalidated_by_simplify_findings(&mut self, rev_item: &Value) -> bool {
        if self.invalidated_at_ts(rev_item).is_none() {
            return false;
        }
        let rev_lts = val_to_f64(rev_item.get("launch_ts"));
        let rev_vts = rev_lts.max(val_to_f64(rev_item.get("verdict_ts")));
        let Some((_, next_edit_ts)) = self.version_edit_bounds(rev_lts) else {
            return false;
        };
        next_edit_ts.is_finite()
            && self.all_simplify_history.iter().any(|sr| {
                let sr_ets = sr.launch_ts.max(sr.end_ts);
                !sr.clean
                    && self.is_allowed_simplify_tier(&sr.tier, sr.launch_ts)
                    && sr.launch_ts >= rev_vts - TS_EPS
                    && sr_ets <= next_edit_ts
            })
    }

    fn counts_toward_round_cap(&mut self, rev_item: &Value) -> bool {
        // INVARIANT: Every `REVISE` / `ESCALATE` ordinary round consumes 1 of the cycle's `MAX_REVIEW_ROUNDS` (3) even after `simplify` runs; only a pre-simplify `APPROVED` invalidated by `simplify` findings is exempt.
        if val_to_str(rev_item.get("verdict")) == "APPROVED"
            && self.needs_simplify
            && (!self.active_simplify_windows.is_empty() || !self.all_simplify_history.is_empty())
        {
            return !self.was_invalidated_by_simplify_findings(rev_item);
        }
        true
    }
}

fn closure_blocked_halt_msg(blocked_count: usize) -> String {
    format!(
        "closure validation reached {}/{} `BLOCKED` verdicts; continuing in the current cycle is forbidden — enter Research Mode (study relevant documentation/best practices via plugins/internet, choose `refactor` or `refine`, kill waiting swarm workers, and run `carbon-stack codex-lane research-reset`) to start fresh simplify and review sessions",
        blocked_count, MAX_CLOSURE_PASSES
    )
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
    let mut ctx_opt = ctx;
    let cctx: &Value = match ctx_opt {
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
    let ctx_needs_simplify = json_truthy(cctx.get("needs_simplify"));
    let ctx_needs_review = json_truthy(cctx.get("needs_review"));

    let Some(rcp) = receipt else {
        if wclass == cwg_common::WORK_OPERATIONAL {
            return (
                false,
                "missing terminal `[gate] operational: <pre-check>; <verified effect>` receipt on last line"
                    .to_string(),
            );
        }
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

    if wclass == cwg_common::WORK_OPERATIONAL {
        if rkind == "operational" || rkind == "no-change" {
            return (true, rkind);
        }
        if rkind != "verified" {
            return (
                false,
                format!("OPERATIONAL candidate cannot close with `{}`", rkind),
            );
        }
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

    let (mut rr_ts, _rr_board_seq, rr_err) = cwg_common::verified_research_reset_state(marker, steps);
    if let Some(err_msg) = rr_err {
        if probing && steps.map_or(true, <[Value]>::is_empty) {
            rr_ts = cwg_common::last_research_reset_ts(marker);
        } else if rkind == "verified" || rkind == "pr-ready" {
            if probing {
                probe_early_reject = true;
                rr_ts = cwg_common::last_research_reset_ts(marker);
            } else {
                return (false, err_msg);
            }
        }
    }
    if rkind == "verified" || rkind == "pr-ready" {
        if let Some((h_cnt, _, _)) = cwg_common::active_marker_closure_halt(marker) {
            if probing {
                probe_early_reject = true;
            } else {
                return (false, closure_blocked_halt_msg(h_cnt));
            }
        }
    }
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
        if checks_ev.checks_count == 0 {
            return (
                false,
                format!(
                    "{} candidate has zero executed verification/test commands recorded in runtime",
                    effective_risk
                ),
            );
        }
        if checks_ev.passed_count == 0 || checks_ev.latest_pass_ts < last_durable - 1.0 {
            return (
                false,
                "last passing test/verification command ran BEFORE the latest file edit; re-verify current bytes with a standalone test command (no trailing '; cmd' or pipes)"
                    .to_string(),
            );
        }
    }

    // INVARIANT: Proportionate simplify verification enforces 3 lenses on HIGH/XHIGH (or Fast-Path ALL) and opt-in on STANDARD.
    let needs_simplify = if effective_risk == floor {
        ctx_needs_simplify
    } else {
        ctx_needs_simplify || cwg_common::requires_simplify(&effective_risk, policy)
    };
    let required_lenses: HashSet<String> = cwg_common::SIMPLIFY_LENSES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let raw_sonnet_map = merge_tier_maps_after(&[&swarm_ev.sonnet_lenses], rr_ts);
    let raw_fallback_map =
        merge_tier_maps_after(&[&swarm_ev.fallback_lenses, &sub_ev.fallback_lenses], rr_ts);
    let raw_secondary_fallback_map = merge_tier_maps_after(
        &[
            &swarm_ev.secondary_fallback_lenses,
            &sub_ev.secondary_fallback_lenses,
        ],
        rr_ts,
    );

    let sonnet_lenses: HashSet<String> = raw_sonnet_map
        .iter()
        .filter(|(_, &lts)| is_review_fresh_ts(lts, marker))
        .map(|(k, _)| k.clone())
        .collect();
    let fallback_lenses: HashSet<String> = raw_fallback_map
        .iter()
        .filter(|(_, &lts)| is_review_fresh_ts(lts, marker))
        .map(|(k, _)| k.clone())
        .collect();
    let secondary_fallback_lenses: HashSet<String> = raw_secondary_fallback_map
        .iter()
        .filter(|(_, &lts)| is_review_fresh_ts(lts, marker))
        .map(|(k, _)| k.clone())
        .collect();

    let sonnet_issue = swarm_ev.sonnet_issue_verified;
    let neon_issue = swarm_ev.neon_issue_verified;
    let sonnet_issue_ts = swarm_ev.sonnet_issue_ts;
    let neon_issue_ts = swarm_ev.neon_issue_ts;
    let secondary_fallback_ok = sonnet_issue && neon_issue;
    let is_fallback_causal = |lts: f64| -> bool {
        is_simplify_tier_causal(
            cwg_common::SIMPLIFY_TIER_FALLBACK,
            lts,
            sonnet_issue,
            sonnet_issue_ts,
            neon_issue,
            neon_issue_ts,
        )
    };
    let is_secondary_fallback_causal = |lts: f64| -> bool {
        is_simplify_tier_causal(
            cwg_common::SIMPLIFY_TIER_SECONDARY_FALLBACK,
            lts,
            sonnet_issue,
            sonnet_issue_ts,
            neon_issue,
            neon_issue_ts,
        )
    };
    let causal_fallback_lenses: HashSet<String> = raw_fallback_map
        .iter()
        .filter(|(k, &lts)| fallback_lenses.contains(*k) && is_fallback_causal(lts))
        .map(|(k, _)| k.clone())
        .collect();
    let causal_secondary_fallback_lenses: HashSet<String> = raw_secondary_fallback_map
        .iter()
        .filter(|(k, &lts)| {
            secondary_fallback_lenses.contains(*k) && is_secondary_fallback_causal(lts)
        })
        .map(|(k, _)| k.clone())
        .collect();
    let simplify_failures = swarm_ev.simplify_failures
        + sub_ev.neon_simplify_failures
        + sub_ev.hydrogen_simplify_failures;
    let sonnet_curr_unavail = tier_currently_unavailable(
        sonnet_issue,
        swarm_ev.sonnet_last_issue_ts,
        swarm_ev.sonnet_healthy_ts,
    );
    let neon_curr_unavail = tier_currently_unavailable(
        neon_issue || sub_ev.neon_simplify_failures > 0,
        swarm_ev
            .neon_last_issue_ts
            .max(sub_ev.neon_simplify_failure_ts),
        swarm_ev.neon_healthy_ts,
    );
    let hydrogen_curr_unavail = tier_currently_unavailable(
        swarm_ev.hydrogen_issue_verified || sub_ev.hydrogen_simplify_failures > 0,
        swarm_ev
            .hydrogen_last_issue_ts
            .max(sub_ev.hydrogen_simplify_failure_ts),
        swarm_ev.hydrogen_healthy_ts,
    );
    let simplify_exhausted =
        sonnet_curr_unavail && neon_curr_unavail && hydrogen_curr_unavail;

    let mut effective_lenses: HashSet<String> = sonnet_lenses.clone();
    effective_lenses.extend(causal_fallback_lenses.iter().cloned());
    effective_lenses.extend(causal_secondary_fallback_lenses.iter().cloned());
    let mut raw_effective_lenses: HashSet<String> = raw_sonnet_map.keys().cloned().collect();
    raw_effective_lenses.extend(
        raw_fallback_map
            .iter()
            .filter(|(_, &lts)| is_fallback_causal(lts))
            .map(|(k, _)| k.clone()),
    );
    raw_effective_lenses.extend(
        raw_secondary_fallback_map
            .iter()
            .filter(|(_, &lts)| is_secondary_fallback_causal(lts))
            .map(|(k, _)| k.clone()),
    );
    let mut stale_simplify_lenses: Vec<String> = raw_effective_lenses
        .intersection(&required_lenses)
        .filter(|k| !effective_lenses.contains(*k))
        .cloned()
        .collect();
    stale_simplify_lenses.sort();
    let mut missing_lenses: Vec<String> = required_lenses
        .difference(&effective_lenses)
        .cloned()
        .collect();
    missing_lenses.sort();

    let raw_sonnet_combined = if rr_ts > 0.0 && swarm_ev.sonnet_combined_ts < rr_ts {
        0.0
    } else {
        swarm_ev.sonnet_combined_ts
    };
    let raw_fallback_combined_unfiltered = swarm_ev
        .fallback_combined_ts
        .max(sub_ev.fallback_combined_ts);
    let raw_fallback_combined = if rr_ts > 0.0 && raw_fallback_combined_unfiltered < rr_ts {
        0.0
    } else {
        raw_fallback_combined_unfiltered
    };
    let raw_secondary_fallback_combined_unfiltered = swarm_ev
        .secondary_fallback_combined_ts
        .max(sub_ev.secondary_fallback_combined_ts);
    let raw_secondary_fallback_combined =
        if rr_ts > 0.0 && raw_secondary_fallback_combined_unfiltered < rr_ts {
            0.0
        } else {
            raw_secondary_fallback_combined_unfiltered
        };
    let sonnet_combined_fresh =
        raw_sonnet_combined > 0.0 && is_review_fresh_ts(raw_sonnet_combined, marker);
    let fallback_combined_fresh =
        raw_fallback_combined > 0.0 && is_review_fresh_ts(raw_fallback_combined, marker);
    let secondary_fallback_combined_fresh = raw_secondary_fallback_combined > 0.0
        && is_review_fresh_ts(raw_secondary_fallback_combined, marker);
    let fb_comb_causal = raw_fallback_combined > 0.0 && is_fallback_causal(raw_fallback_combined);
    let sec_comb_causal = raw_secondary_fallback_combined > 0.0
        && is_secondary_fallback_causal(raw_secondary_fallback_combined);
    let combined_fresh = sonnet_combined_fresh
        || (fb_comb_causal && fallback_combined_fresh)
        || (sec_comb_causal && secondary_fallback_combined_fresh);
    let combined_stale = (raw_sonnet_combined > 0.0 && !sonnet_combined_fresh)
        || (fb_comb_causal && raw_fallback_combined > 0.0 && !fallback_combined_fresh)
        || (sec_comb_causal
            && raw_secondary_fallback_combined > 0.0
            && !secondary_fallback_combined_fresh);

    let multi_lens_spoof = swarm_ev.multi_lens_spoof;
    let swarm_ev_for_fp = json!({ "multi_lens_spoof": multi_lens_spoof });
    let fp_repo_root = if !cwd.is_empty() {
        cwd.clone()
    } else {
        val_to_str(marker.get("git_root"))
    };
    let fast_path = cwg_common::is_simplify_fast_path_eligible(
        marker,
        Some(&swarm_ev_for_fp),
        None,
        &fp_repo_root,
    );
    if let Some(ref mut c_val) = ctx_opt {
        if let Some(obj) = c_val.as_object_mut() {
            obj.insert("fast_path".to_string(), Value::Bool(fast_path));
        }
    }
    let allow_combined = (effective_risk == "STANDARD") || fast_path;
    let simplify_satisfied =
        missing_lenses.is_empty() || (allow_combined && combined_fresh && !multi_lens_spoof);
    let mut unstarted_simplify_reason = String::new();

    if needs_simplify && !simplify_satisfied && !(rkind == "draft-blocked" && simplify_exhausted) {
        if effective_risk != "STANDARD"
            && (multi_lens_spoof
                || (!fast_path
                    && (sonnet_combined_fresh
                        || fallback_combined_fresh
                        || secondary_fallback_combined_fresh)))
        {
            if probing {
                probe_early_reject = true;
            } else {
                return (
                    false,
                    format!(
                        "{} candidate cannot collapse simplify into a single combined lane; run all 3 separate `{}` lenses (`reuse`, `quality`, `efficiency`); missing: {}",
                        effective_risk,
                        cwg_common::SONNET_HIGH_MODEL,
                        missing_lenses.join(", ")
                    ),
                );
            }
        }
        let mut all_combined_union: HashSet<String> =
            sonnet_lenses.union(&fallback_lenses).cloned().collect();
        all_combined_union.extend(secondary_fallback_lenses.iter().cloned());
        let has_uncausal_sonnet_bypass = (!sonnet_issue && !fallback_lenses.is_empty())
            || raw_fallback_map
                .iter()
                .any(|(k, &lts)| fallback_lenses.contains(k) && !is_fallback_causal(lts))
            || (!fb_comb_causal && fallback_combined_fresh)
            || (!sonnet_issue
                && (!secondary_fallback_lenses.is_empty() || secondary_fallback_combined_fresh));
        if has_uncausal_sonnet_bypass
            && ((allow_combined && (fallback_combined_fresh || secondary_fallback_combined_fresh))
                || all_combined_union.is_superset(&required_lenses))
        {
            let target = if allow_combined {
                "`simplify-reviewer`"
            } else {
                "all 3 lenses (`reuse`, `quality`, `efficiency`)"
            };
            if probing {
                probe_early_reject = true;
            } else {
                return (
                    false,
                    format!(
                        "simplify ran on fallback model without prior verified `{}` error/quota issue; run {} on `{}` via `swarm`",
                        cwg_common::SONNET_HIGH_MODEL,
                        target,
                        cwg_common::SONNET_HIGH_MODEL
                    ),
                );
            }
        }
        let has_uncausal_secondary_fallback = raw_secondary_fallback_map
            .iter()
            .any(|(k, &lts)| {
                secondary_fallback_lenses.contains(k) && !is_secondary_fallback_causal(lts)
            })
            || (!sec_comb_causal && secondary_fallback_combined_fresh);
        if has_uncausal_secondary_fallback
            && ((allow_combined && secondary_fallback_combined_fresh)
                || (!secondary_fallback_lenses.is_empty()
                    && all_combined_union.is_superset(&required_lenses)))
        {
            let target = if allow_combined {
                "`simplify-reviewer`"
            } else {
                "all 3 lenses (`reuse`, `quality`, `efficiency`)"
            };
            if probing {
                probe_early_reject = true;
            } else {
                return (
                    false,
                    format!(
                        "simplify ran on secondary fallback `{}` without prior verified `{}` error/quota issue; run {} on `{}` via `swarm` first",
                        cwg_common::HYDROGEN_XHIGH_MODEL,
                        cwg_common::NEON_XHIGH_MODEL,
                        target,
                        cwg_common::NEON_XHIGH_MODEL
                    ),
                );
            }
        }
        if !stale_simplify_lenses.is_empty() || (allow_combined && combined_stale) {
            let stale_label =
                if allow_combined && combined_stale && stale_simplify_lenses.is_empty() {
                    "combined simplify".to_string()
                } else {
                    format!("simplify lenses ({})", stale_simplify_lenses.join(", "))
                };
            let reverify_model = if secondary_fallback_ok {
                cwg_common::HYDROGEN_XHIGH_MODEL
            } else if sonnet_issue {
                cwg_common::SIMPLIFY_FALLBACK_MODEL
            } else {
                cwg_common::SONNET_HIGH_MODEL
            };
            unstarted_simplify_reason = format!(
                "{} stale because durable files changed after simplify; re-verify on `{}`",
                stale_label, reverify_model
            );
        } else if effective_risk == "STANDARD" {
            unstarted_simplify_reason = format!(
                "STANDARD candidate requires 1 combined `simplify-reviewer` lane (`SIMPLIFY_LENS: ALL`) or all 3 lenses on `{}` (fallback `{}` on Sonnet outage) via `swarm`",
                cwg_common::SONNET_HIGH_MODEL,
                cwg_common::SIMPLIFY_FALLBACK_MODEL
            );
        } else if fast_path {
            unstarted_simplify_reason = format!(
                "{} candidate qualifies for Swarm 2.0 Fast-Path (<=2 files, <=30 changed lines): run 1 `simplify-reviewer` lane (`SIMPLIFY_LENS: ALL`) or 3 separate lenses on `{}` (fallback `{}` on Sonnet outage) via `swarm`; missing: {}",
                effective_risk,
                cwg_common::SONNET_HIGH_MODEL,
                cwg_common::SIMPLIFY_FALLBACK_MODEL,
                missing_lenses.join(", ")
            );
        } else {
            unstarted_simplify_reason = format!(
                "{} candidate requires all 3 separate `{}` simplify lenses (fallback `{}` via `swarm` on Sonnet outage: `reuse`, `quality`, `efficiency`); missing: {}",
                effective_risk,
                cwg_common::SONNET_HIGH_MODEL,
                cwg_common::SIMPLIFY_FALLBACK_MODEL,
                missing_lenses.join(", ")
            );
        }
    }

    // INVARIANT: Compute simplify completion windows before review checks so all closure paths enforce `simplify -> final/closure review`.
    let raw_sonnet_end_map = &swarm_ev.sonnet_lenses_end;
    let raw_fallback_end_map =
        merge_tier_maps(&[&swarm_ev.fallback_lenses_end, &sub_ev.fallback_lenses_end]);
    let raw_secondary_fallback_end_map = merge_tier_maps(&[
        &swarm_ev.secondary_fallback_lenses_end,
        &sub_ev.secondary_fallback_lenses_end,
    ]);

    let mut active_simplify_windows: Vec<(f64, f64)> = Vec::new();
    if needs_simplify {
        if allow_combined && combined_fresh && !multi_lens_spoof && !missing_lenses.is_empty() {
            let best_comb = [
                (
                    sonnet_combined_fresh,
                    raw_sonnet_combined,
                    swarm_ev.sonnet_combined_end_ts,
                ),
                (
                    fb_comb_causal && fallback_combined_fresh,
                    raw_fallback_combined,
                    swarm_ev
                        .fallback_combined_end_ts
                        .max(sub_ev.fallback_combined_end_ts),
                ),
                (
                    sec_comb_causal && secondary_fallback_combined_fresh,
                    raw_secondary_fallback_combined,
                    swarm_ev
                        .secondary_fallback_combined_end_ts
                        .max(sub_ev.secondary_fallback_combined_end_ts),
                ),
            ]
            .into_iter()
            .filter(|(ok, _, _)| *ok)
            .fold(None::<(f64, f64)>, |best, (_, lts, ets)| {
                if best.map_or(true, |b| lts >= b.0) {
                    Some((lts, ets))
                } else {
                    best
                }
            });
            if let Some((c_lts, c_end)) = best_comb {
                active_simplify_windows.push((c_lts, c_lts.max(c_end)));
            }
        } else {
            let lens_tiers: [(&HashSet<String>, &HashMap<String, f64>, &HashMap<String, f64>); 3] = [
                (&sonnet_lenses, &raw_sonnet_map, raw_sonnet_end_map),
                (
                    &causal_fallback_lenses,
                    &raw_fallback_map,
                    &raw_fallback_end_map,
                ),
                (
                    &causal_secondary_fallback_lenses,
                    &raw_secondary_fallback_map,
                    &raw_secondary_fallback_end_map,
                ),
            ];
            for k in &required_lenses {
                let best =
                    lens_tiers
                        .into_iter()
                        .fold(None::<(f64, f64)>, |best, (set, lmap, emap)| {
                            if !set.contains(k) {
                                return best;
                            }
                            let lts = lmap.get(k).copied().unwrap_or(0.0);
                            let ets = emap.get(k).copied().unwrap_or(0.0);
                            if best.map_or(true, |b| lts >= b.0) {
                                Some((lts, ets))
                            } else {
                                best
                            }
                        });
                if let Some((lts, ets)) = best {
                    active_simplify_windows.push((lts, lts.max(ets)));
                }
            }
        }
    }

    let max_simplify_launch_ts = active_simplify_windows
        .iter()
        .map(|w| w.0)
        .reduce(f64::max)
        .unwrap_or(0.0);
    let max_simplify_end_ts = active_simplify_windows
        .iter()
        .map(|w| w.1)
        .reduce(f64::max)
        .unwrap_or(0.0);
    let mut all_simplify_steps: HashSet<usize> = swarm_ev.simplify_launch_steps.clone();
    all_simplify_steps.extend(sub_ev.simplify_launch_steps.iter().copied());
    let mut all_simplify_history: Vec<SimplifyHistoryItem> = swarm_ev
        .simplify_history
        .iter()
        .chain(sub_ev.simplify_history.iter())
        .filter(|sr| rr_ts <= 0.0 || sr.launch_ts >= rr_ts)
        .cloned()
        .collect();
    SimplifyHistoryItem::sort_chronologically(&mut all_simplify_history);
    let current_simplify_history: Vec<SimplifyHistoryItem> = swarm_ev
        .simplify_current_history
        .as_deref()
        .unwrap_or(&swarm_ev.simplify_history)
        .iter()
        .chain(sub_ev.simplify_history.iter())
        .filter(|sr| rr_ts <= 0.0 || sr.launch_ts >= rr_ts)
        .cloned()
        .collect();

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
        needs_simplify,
        allow_combined,
        multi_lens_spoof,
        sonnet_issue,
        sonnet_issue_ts,
        neon_issue,
        neon_issue_ts,
        effective_risk: &effective_risk,
        required_lenses: &required_lenses,
        active_simplify_windows: &active_simplify_windows,
        max_simplify_launch_ts,
        max_simplify_end_ts,
        all_simplify_steps: &all_simplify_steps,
        all_simplify_history: &all_simplify_history,
        current_simplify_history: &current_simplify_history,
        candidate_marks: &candidate_marks,
        oldest_mark_ts,
        first_ts_val,
        marks_truncated,
        tx_edits_cache: None,
        swarm_ev,
        codex_bin_missing_cache: None,
        breaker_info_cache: None,
        sim_ver_cache: HashMap::new(),
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
            // INVARIANT: Under the Sandwich Gate (`needs_simplify == true`), an ordinary `VERDICT: APPROVED` is NOT a terminal gate-closing verdict (`--closure` `CLOSURE_VALIDATION: READY` is); post-approval edits made during `simplify` must preserve the cycle's primary review history rather than resetting `cycle_raw_ordinary`.
            if !needs_simplify
                && cycle_raw_closure.is_empty()
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
            let valid_so_far: Vec<Value> = cycle_raw_ordinary
                .iter()
                .filter(|r| eval.is_round_after_its_simplify(r))
                .cloned()
                .collect();
            let (eff_cls_so_far, unrep_so_far, _) =
                eval.partition_cycle_closure(&cycle_raw_closure);
            let post_sim_eff_cls_all_so_far = eff_cls_so_far
                .iter()
                .all(|r| eval.is_round_after_its_simplify(r));
            let rev_vts = val_to_f64(rev.get("verdict_ts")).max(rev_lts);
            let live_blk_so_far = eff_cls_so_far
                .iter()
                .filter(|r| val_to_str(r.get("verdict")) == "BLOCKED")
                .count();
            let latched_blk_so_far = cwg_common::active_marker_closure_halt(marker)
                .filter(|(_, h_ts, _)| *h_ts > cycle_cutoff_ts && *h_ts <= rev_vts)
                .map(|(cnt, _, _)| cnt)
                .unwrap_or(0);
            let blk_so_far = live_blk_so_far.max(latched_blk_so_far);
            let has_post_sim_inelig_so_far = ineligible_ordinary_reviews
                .iter()
                .filter(|r| {
                    let lts = val_to_f64(r.get("launch_ts"));
                    (cycle_cutoff_ts <= 0.0 || lts >= cycle_cutoff_ts) && lts <= rev_vts
                })
                .any(|r| eval.is_round_after_its_simplify(r));
            if within_cycle_ordinary_caps(cycle_counted_ordinary_n, &cycle_raw_ordinary)
                && unrep_so_far.is_none()
                && post_sim_eff_cls_all_so_far
                && eff_cls_so_far.len() <= MAX_CLOSURE_PASSES
                && blk_so_far < MAX_CLOSURE_PASSES
                && eval.is_round_after_its_simplify(rev)
                && (eval.is_valid_cycle_closure_ready(&valid_so_far, rev)
                    || (!has_post_sim_inelig_so_far
                        && eval.is_valid_swarm_v2_cycle_closure_ready(
                            &cycle_raw_ordinary,
                            valid_so_far.is_empty(),
                            rev,
                        )))
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

    let post_simplify_ordinary: Vec<Value> = cycle_raw_ordinary
        .iter()
        .filter(|r| eval.is_round_after_its_simplify(r))
        .cloned()
        .collect();
    let post_simplify_closure: Vec<Value> = cycle_raw_closure
        .iter()
        .filter(|r| eval.is_round_after_its_simplify(r))
        .cloned()
        .collect();
    let post_simplify_ineligible: Vec<Value> = cycle_ineligible_ordinary
        .iter()
        .filter(|r| eval.is_round_after_its_simplify(r))
        .cloned()
        .collect();
    let cycle_ineligible_closure: Vec<&Value> = if cycle_cutoff_ts > 0.0 {
        ineligible_closure_reviews
            .iter()
            .copied()
            .filter(|r| val_to_f64(r.get("launch_ts")) >= cycle_cutoff_ts)
            .collect()
    } else {
        ineligible_closure_reviews.clone()
    };
    let post_simplify_ineligible_closure: Vec<&Value> = cycle_ineligible_closure
        .iter()
        .copied()
        .filter(|r| eval.is_round_after_its_simplify(r))
        .collect();

    let fresh_pre_simplify_reviews_non_empty = cycle_raw_ordinary
        .iter()
        .chain(cycle_raw_closure.iter())
        .chain(cycle_ineligible_ordinary.iter())
        .any(|r| is_review_fresh(r, marker) && !eval.is_after_simplify(r));
    let had_pre_simplify_review = needs_simplify
        && !active_simplify_windows.is_empty()
        && (fresh_pre_simplify_reviews_non_empty
            || post_simplify_closure.len() < cycle_raw_closure.len());

    let ordinary_reviews: Vec<Value> = if needs_simplify && !active_simplify_windows.is_empty() {
        post_simplify_ordinary.clone()
    } else {
        cycle_raw_ordinary.clone()
    };
    let closure_reviews: Vec<Value> = if needs_simplify && !active_simplify_windows.is_empty() {
        post_simplify_closure.clone()
    } else {
        cycle_raw_closure.clone()
    };

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

    // INVARIANT: Stale simplify from an earlier round (including a stale Fast-Path combined lane before a 3rd file was edited) must never suppress Logic-First primary review checks when prior reviews exist or no simplify ever ran.
    let simplify_freshly_started = !effective_lenses.is_empty();
    let had_any_simplify = simplify_freshly_started
        || !stale_simplify_lenses.is_empty()
        || raw_sonnet_combined > 0.0
        || raw_fallback_combined > 0.0
        || raw_secondary_fallback_combined > 0.0;
    if !unstarted_simplify_reason.is_empty() && !(rkind == "draft-blocked" && simplify_exhausted) {
        if probing {
            probe_early_reject = true;
        } else {
            if needs_review && !simplify_freshly_started {
                if cycle_raw_ordinary.is_empty() && cycle_raw_closure.is_empty() {
                    if let Some(last_inelig) = cycle_ineligible_ordinary.last() {
                        let prio_err = eval.engine_priority_error(last_inelig);
                        if !prio_err.is_empty() {
                            return (false, prio_err);
                        }
                    }
                    if !had_any_simplify || cycle_cutoff_ts > 0.0 {
                        let esc_chain = cwg_common::review_escalation_chain(&effective_risk);
                        return (
                            false,
                            format!(
                                "{} candidate requires primary independent review first (`carbon-stack codex-lane review` -> {}) BEFORE simplify (`CARGO TEST -> REVIEW -> SIMPLIFY -> --closure`)",
                                effective_risk,
                                esc_chain
                            ),
                        );
                    }
                }
                if let Some(last_pre_rev) = cycle_raw_ordinary.last() {
                    let last_pre_v = val_to_str(last_pre_rev.get("verdict"));
                    if (last_pre_v == "REVISE" || last_pre_v == "ESCALATE")
                        && cycle_raw_ordinary.len() < MAX_REVIEW_ROUNDS
                    {
                        return (
                            false,
                            format!(
                                "invoked adversarial review ended in `{}`, not `APPROVED`; resolve findings with `carbon-stack codex-lane review` BEFORE running simplify",
                                last_pre_v
                            ),
                        );
                    }
                    if last_pre_v == "APPROVED" && !is_review_fresh(last_pre_rev, marker) {
                        return (
                            false,
                            format!(
                                "{} candidate's primary `APPROVED` verdict is stale: run primary `carbon-stack codex-lane review` BEFORE simplify",
                                effective_risk
                            ),
                        );
                    }
                    if effective_risk == "XHIGH"
                        && last_pre_v == "APPROVED"
                        && !json_truthy(last_pre_rev.get("xhigh"))
                    {
                        return (
                            false,
                            format!(
                                "XHIGH candidate's primary `APPROVED` verdict came from standard tier, not XHIGH; run XHIGH review (`carbon-stack codex-lane review --xhigh` on `{}`) BEFORE simplify",
                                cwg_common::CODEX_ASTRA_MODEL
                            ),
                        );
                    }
                }
            }
            return (false, unstarted_simplify_reason);
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

    let (effective_cycle_closure, unreplaced_premature_cls, unreplaced_premature_kind) =
        eval.partition_cycle_closure(&cycle_raw_closure);
    let post_simplify_eff_closure_all = effective_cycle_closure
        .iter()
        .all(|r| eval.is_round_after_its_simplify(r));
    let latest_eff_cls_rev: Option<&Value> = effective_cycle_closure.last();

    let is_swarm_v2_closure_ready =
        |risk: &str, ord_list: &[Value], cls_rev: &Value, after_sim: bool| -> bool {
            if !(needs_simplify && !active_simplify_windows.is_empty()) {
                return false;
            }
            if !post_simplify_eff_closure_all {
                return false;
            }
            if !after_sim || !is_review_fresh(cls_rev, marker) {
                return false;
            }
            if !closure_ready_tail_ok(risk, ord_list, cls_rev, true) {
                return false;
            }
            if !post_simplify_ordinary.is_empty() || !post_simplify_ineligible.is_empty() {
                return false;
            }
            let min_sim_ts = active_simplify_windows
                .iter()
                .map(|w| w.0)
                .reduce(f64::min)
                .unwrap_or(0.0);
            min_sim_ts > 0.0
                && !ord_list
                    .iter()
                    .any(|r| val_to_f64(r.get("launch_ts")) >= min_sim_ts)
        };

    let live_blocked_closure_count = effective_cycle_closure
        .iter()
        .filter(|r| val_to_str(r.get("verdict")) == "BLOCKED")
        .count();
    let latched_blocked_count = cwg_common::active_marker_closure_halt(marker)
        .filter(|(_, h_ts, _)| *h_ts > cycle_cutoff_ts)
        .map(|(cnt, _, _)| cnt)
        .unwrap_or(0);
    let blocked_closure_count = live_blocked_closure_count.max(latched_blocked_count);

    // INVARIANT: Hard-cap effective closure passes at `MAX_CLOSURE_PASSES` (2) per cycle; superseded premature pre-simplify READY passes do not deadlock recovery once simplify + replacement `--closure` runs.
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
                    "closure validation exceeded MAX_CLOSURE_PASSES={}; enter Research Mode and run `carbon-stack codex-lane research-reset` to start a fresh cycle",
                    MAX_CLOSURE_PASSES
                ),
            );
        }
    }

    let closure_ready_rev: Option<&Value> = if unreplaced_premature_cls.is_none()
        && post_simplify_eff_closure_all
        && effective_cycle_closure.len() <= MAX_CLOSURE_PASSES
        && blocked_closure_count < MAX_CLOSURE_PASSES
    {
        latest_eff_cls_rev.filter(|&cls_rev| {
            let after_sim = eval.is_after_simplify(cls_rev);
            is_review_fresh(cls_rev, marker)
                && after_sim
                && (eval.is_valid_cycle_closure_ready(&ordinary_reviews, cls_rev)
                    || is_swarm_v2_closure_ready(&effective_risk, &cycle_raw_ordinary, cls_rev, after_sim))
        })
    } else {
        None
    };

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
        let mut blk_cnt = blk_ids.len();
        if let Some((h_cnt, h_ts, h_ids)) = cwg_common::active_marker_closure_halt(marker)
            .filter(|(_, h_ts, _)| *h_ts > cycle_cutoff_ts)
        {
            if blk_cnt < h_cnt {
                blk_cnt = h_cnt;
                last_blk_ts = h_ts.max(last_blk_ts);
                if !h_ids.is_empty() {
                    blk_ids = h_ids;
                }
            }
        }
        probe.blocked_count = blk_cnt;
        probe.last_blocked_ts = last_blk_ts;
        probe.blocked_ids = blk_ids;
        probe.effective_pass_count = effective_cycle_closure.len();
        probe.last_closure_ts = last_cls_ts;
        probe.counted_ordinary_rounds = cycle_counted_ordinary_n;
        probe.raw_ordinary_rounds = cycle_raw_ordinary.len();
        probe.needs_simplify = needs_simplify;
        let min_cycle_ts = cycle_cutoff_ts.max(first_ts_val);
        probe.simplify_started_in_cycle = had_any_simplify
            || swarm_ev
                .simplify_history
                .iter()
                .any(|it| it.launch_ts > min_cycle_ts);
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
        let is_fresh_tier_approved = |r: &Value, v: &str| -> bool {
            v == "APPROVED"
                && is_review_fresh(r, marker)
                && (effective_risk != "XHIGH" || json_truthy(r.get("xhigh")))
        };
        let has_post_sim_app = norm_ordinary
            .iter()
            .any(|(r, v)| is_fresh_tier_approved(r, v));
        let has_pre_sim_app = cycle_raw_closure.is_empty()
            && cycle_raw_ordinary
                .last()
                .is_some_and(|r| is_fresh_tier_approved(r, &val_to_str(r.get("verdict"))));
        probe.has_fresh_ordinary_approved = has_post_sim_app || has_pre_sim_app;
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
                    cwg_common::active_simplify_or_review_workers(&brain_root, &marker_sess);
                if !alive_workers.is_empty() {
                    return (
                        false,
                        format!(
                            "waiting/active simplify or review swarm workers ({}) must be killed via `swarm(action=\"kill\", ...)` before closing the gate",
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
        && closure_ready_rev.is_none()
        && unreplaced_premature_cls.is_some()
    {
        if unreplaced_premature_kind == "inter_pass" {
            return (
                false,
                format!(
                    "closure validation pass 2/{} ran without a fresh `simplify` pass after pass 1 `BLOCKED`; run `simplify` before final `{}`",
                    MAX_CLOSURE_PASSES, CLOSURE_PHASE_FLAG
                ),
            );
        }
        return (false, PRE_SIMPLIFY_REVIEW_ERR.to_string());
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
            let rev = post_simplify_ineligible_closure.last().copied().filter(|r| {
                min_launch_ts.map_or(true, |mt| val_to_f64(r.get("launch_ts")) >= mt)
                    && (!check_after_cls
                        || !latest_cls_rev.map_or(false, |lr| {
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
            if !post_simplify_eff_closure_all {
                return (false, PRE_SIMPLIFY_REVIEW_ERR.to_string());
            }
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
                        "closure validation pass 1/{} returned `BLOCKED`; fix the blocking issue, run tests, run `simplify` on the updated diff, and run final `{}` pass 2/{}",
                        MAX_CLOSURE_PASSES, CLOSURE_PHASE_FLAG, MAX_CLOSURE_PASSES
                    ),
                );
            }
            return (
                false,
                format!(
                    "closure validation pass 1/{} returned `BLOCKED`; run final `{}` pass 2/{} for `CLOSURE_VALIDATION: READY`",
                    MAX_CLOSURE_PASSES, CLOSURE_PHASE_FLAG, MAX_CLOSURE_PASSES
                ),
            );
        }
        if effective_risk == "XHIGH" {
            if let Some(cls_rev) = latest_eff_cls_rev.filter(|&r| {
                let after_sim = eval.is_after_simplify(r);
                is_review_fresh(r, marker)
                    && after_sim
                    && (eval.is_valid_cycle_closure_ready_at_risk("HIGH", &ordinary_reviews, r)
                        || is_swarm_v2_closure_ready("HIGH", &cycle_raw_ordinary, r, after_sim))
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
            if post_simplify_closure.len() < cycle_raw_closure.len() {
                return (false, PRE_SIMPLIFY_REVIEW_ERR.to_string());
            }
            if latest_cls_verdict == "BLOCKED"
                && latest_cls_rev.map_or(false, |r| is_review_fresh(r, marker))
            {
                return (
                    false,
                    format!(
                        "invoked adversarial review ended in `{}` and closure validation returned `BLOCKED`, not `READY`",
                        cap_v
                    ),
                );
            }
            if latest_cls_verdict != "READY" {
                if let Some(err) = closing_inelig_err(&mut eval, None, true) {
                    return (false, err);
                }
            }
            return (
                false,
                format!(
                    "invoked adversarial review ended in `{}`, not `APPROVED` (all {} ordinary rounds used; run `{}` for `CLOSURE_VALIDATION: READY`)",
                    cap_v, MAX_REVIEW_ROUNDS, CLOSURE_PHASE_FLAG
                ),
            );
        }
        if latest_cls_verdict == "BLOCKED" {
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
                if let Some(last_pi) = post_simplify_ineligible_closure
                    .last()
                    .copied()
                    .or_else(|| post_simplify_ineligible.last())
                {
                    let prio_err = eval.engine_priority_error(last_pi);
                    if !prio_err.is_empty() {
                        return (false, prio_err);
                    }
                }
                if had_pre_simplify_review {
                    return (false, PRE_SIMPLIFY_REVIEW_ERR.to_string());
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
            if !eval.is_after_simplify(ord_rev) {
                return (false, PRE_SIMPLIFY_REVIEW_ERR.to_string());
            }
            if needs_simplify {
                return (
                    false,
                    format!(
                        "{} candidate requires final `carbon-stack codex-lane review --closure` (`{}` / `CLOSURE_VALIDATION: READY`) after `simplify`; ordinary `VERDICT: APPROVED` cannot replace `--closure`",
                        effective_risk, CLOSURE_PHASE_FLAG
                    ),
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
        if pr_cap_met && post_simplify_closure.len() == cycle_raw_closure.len() {
            if let Some(err) = closing_inelig_err(&mut eval, None, true) {
                return (false, err);
            }
        }
        if had_pre_simplify_review
            && (ordinary_reviews.len() < MAX_REVIEW_ROUNDS
                || post_simplify_closure.len() < cycle_raw_closure.len())
        {
            return (false, PRE_SIMPLIFY_REVIEW_ERR.to_string());
        }
        if ordinary_reviews.len() < MAX_REVIEW_ROUNDS
            || (latest_ord_verdict != "ESCALATE" && latest_ord_verdict != "REVISE")
        {
            return (
                false,
                "`pr-ready` requires round-3 `ESCALATE`/`REVISE` followed by fresh `CLOSURE_VALIDATION: READY`"
                    .to_string(),
            );
        }
        return (
            false,
            "`pr-ready` lacks fresh `CLOSURE_VALIDATION: READY` from an eligible review engine"
                .to_string(),
        );
    }

    if rkind == "draft-blocked" {
        if latest_cls_verdict == "BLOCKED"
            && latest_cls_rev.map_or(false, |r| is_review_fresh(r, marker))
        {
            return (true, "draft-blocked".to_string());
        }
        if review_unavailable || (needs_simplify && simplify_exhausted) {
            return (true, "draft-blocked".to_string());
        }
        return (
            false,
            format!(
                "`draft-blocked` requires fresh `CLOSURE_VALIDATION: BLOCKED` after round-3 ESCALATE, or exhausted review/simplify lanes (observed simplify failures: {}, tiers unavailable: sonnet={}, neon={}, hydrogen={})",
                simplify_failures, sonnet_curr_unavail, neon_curr_unavail, hydrogen_curr_unavail
            ),
        );
    }

    (false, format!("unsupported receipt kind `{}`", rkind))
    })();

    if let Some(probe) = cycle_probe {
        probe.has_fresh_ready = !probe_early_reject && tail_ok;
        return (probe.has_fresh_ready, String::new());
    }
    if !tail_ok && append_exhausted_reset_hint && !tail_msg.contains("research-reset") {
        tail_msg = format!(
            "{} (all {}/{} closure passes in this cycle are consumed; enter Research Mode and run `carbon-stack codex-lane research-reset` to start a fresh cycle)",
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

pub fn has_simplify_in_span(
    session: &str,
    marker_in: &Value,
    transcript_path: &str,
    after_ts: f64,
    before_ts: f64,
    require_fresh: bool,
) -> bool {
    if after_ts <= 0.0 || !marker_in.is_object() || json_truthy(marker_in.get("closed")) {
        return true;
    }
    if before_ts <= after_ts {
        return false;
    }
    let (merged_opt, _) = cwg_common::apply_pending_marker_deltas(session, Some(marker_in));
    let Some(eff_marker) = merged_opt else {
        return true;
    };
    let cctx = cwg_common::resolve_candidate_context(&eff_marker, false);
    if !json_truthy(cctx.get("needs_simplify")) {
        return true;
    }
    let eff_tp = resolve_session_transcript_path(session, transcript_path);
    let steps = if !eff_tp.is_empty() {
        rio::read_transcript_steps(&eff_tp, 4000)
    } else {
        Vec::new()
    };
    let tp_opt = if eff_tp.is_empty() {
        None
    } else {
        Some(eff_tp.as_str())
    };
    let first_ts = val_to_f64(eff_marker.get("first_ts"));
    let rr_ts = cwg_common::last_research_reset_ts(&eff_marker);
    let rr_seq = cwg_common::last_research_reset_board_seq(&eff_marker);
    let eff_first_ts = first_ts.max(rr_ts);
    let eff_round_start = val_to_i64(eff_marker.get("round_start_msg_id")).max(rr_seq);
    let gr = val_to_str(eff_marker.get("git_root"));
    let eff_cwd = if !gr.is_empty() {
        gr
    } else {
        val_to_str(eff_marker.get("cwd"))
    };
    let sub_ev = scan_native_subagents(&steps, tp_opt, eff_first_ts);
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
        marker: Some(&eff_marker),
    });
    if let Some(Value::Object(mut st)) = rio::read_json(&cwg_common::enforcement_state_path(session))
    {
        merge_sticky_outage_state(&mut st, &mut swarm_ev);
    }
    let sonnet_issue = swarm_ev.sonnet_issue_verified;
    let neon_issue = swarm_ev.neon_issue_verified;
    let sonnet_issue_ts = swarm_ev.sonnet_issue_ts;
    let neon_issue_ts = swarm_ev.neon_issue_ts;
    let multi_spoof = swarm_ev.multi_lens_spoof;
    let swarm_ev_for_fp = json!({ "multi_lens_spoof": multi_spoof });
    let effective_risk = val_to_str(cctx.get("floor"));
    let fast_path = cwg_common::is_simplify_fast_path_eligible(
        &eff_marker,
        Some(&swarm_ev_for_fp),
        None,
        &eff_cwd,
    );
    let allow_combined = effective_risk == "STANDARD" || fast_path;

    let min_lts = rr_ts.max(after_ts - TS_EPS);
    // INVARIANT: Filter both span and tier causality BEFORE `replay_completion` so excluded
    // future or disallowed-tier `CLEAN` windows cannot lift an in-span `ACTIONABLE_FIXES` to Stratum 0.
    // When `require_fresh` is set (e.g. post-BLOCKED `--closure` Pass 2 admission), read ONLY
    // round- and `current_diff_hash`-validated `simplify_current_history` so rejected hashes cannot pass.
    let swarm_hist = if require_fresh {
        swarm_ev
            .simplify_current_history
            .as_deref()
            .unwrap_or(&swarm_ev.simplify_history)
    } else {
        &swarm_ev.simplify_history
    };
    let mut hist: Vec<&SimplifyHistoryItem> = Vec::new();
    for sr in swarm_hist.iter().chain(sub_ev.simplify_history.iter()) {
        let tier_ok = (!sr.clean && sr.tier.is_empty())
            || is_simplify_tier_causal(
                &sr.tier,
                sr.launch_ts,
                sonnet_issue,
                sonnet_issue_ts,
                neon_issue,
                neon_issue_ts,
            );
        if sr.launch_ts < min_lts || sr.launch_ts >= before_ts || !tier_ok {
            continue;
        }
        if sr.launch_ts.max(sr.end_ts) > before_ts {
            return false;
        }
        hist.push(sr);
    }
    if hist.is_empty() {
        return false;
    }
    let Some((done_lenses, done_combined_lts)) =
        SimplifyHistoryItem::replay_completion(&hist, Some(before_ts))
    else {
        return false;
    };

    let comb_ok = allow_combined
        && !multi_spoof
        && done_combined_lts.is_some_and(|lts| {
            lts > 0.0 && (!require_fresh || is_review_fresh_ts(lts, &eff_marker))
        });
    let lenses_ok = cwg_common::SIMPLIFY_LENSES.iter().all(|req| {
        done_lenses
            .get(*req)
            .copied()
            .is_some_and(|lts| !require_fresh || is_review_fresh_ts(lts, &eff_marker))
    });
    comb_ok || lenses_ok
}

pub fn has_completed_simplify_after(
    session: &str,
    marker_in: &Value,
    transcript_path: &str,
    after_ts: f64,
) -> bool {
    has_simplify_in_span(session, marker_in, transcript_path, after_ts, f64::INFINITY, true)
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
            if receipt_summary == "no-change"
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
    state.insert("closed_ts".to_string(), json!(now_sec()));
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

fn has_notified_anomaly_handler(
    steps: &[Value],
    handler_session: &str,
    first_ts: f64,
    report_id: &str,
    session: &str,
) -> bool {
    let target = rio::safe_key(handler_session, "");
    let rid_low = report_id.trim().to_lowercase();
    if target.is_empty() || rid_low.is_empty() {
        return true;
    }
    if !session.is_empty()
        && gate_inbox::bus_has_anomaly_notification(session, &target, first_ts, &rid_low)
    {
        return true;
    }
    let is_notify_tool = |name: &str| {
        matches!(
            name,
            "send_message"
                | "mcp_chat-bus_peers_chat_send"
                | "peers_chat_send"
                | "chat_send"
                | "call_mcp_tool"
                | "run_command"
        )
    };
    let target_low = target.to_lowercase();
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
        if !tcs.iter().any(|tc| {
            tc.get("name")
                .and_then(|v| v.as_str())
                .map_or(false, is_notify_tool)
        }) {
            continue;
        }
        let generic_steps = collect_generic_results(steps, idx);
        for (pos, tc) in tcs.iter().enumerate() {
            if pos >= generic_steps.len() {
                continue;
            }
            let Some(tc_obj) = tc.as_object() else {
                continue;
            };
            let tname = tc_obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if !is_notify_tool(tname) {
                continue;
            }
            let (ref g_status, ref g_blob, _) = generic_steps[pos];
            if g_status != "DONE" {
                continue;
            }
            if let Some(g_json) = extract_json_dict(g_blob) {
                if g_json.get("ok").and_then(|v| v.as_bool()) == Some(false)
                    || json_truthy(g_json.get("error"))
                {
                    continue;
                }
            }
            let Some(args) = tc_obj.get("args").and_then(|v| v.as_object()) else {
                continue;
            };
            if tname == "send_message" {
                let recip = rio::safe_key(&val_to_str(args.get("Recipient")), "");
                let msg = val_to_str(args.get("Message")).to_lowercase();
                if recip == target && msg.contains(&rid_low) {
                    return true;
                }
            } else if tname == "run_command" {
                let cmd_low = val_to_str(args.get("CommandLine")).to_lowercase();
                if cmd_low.contains("chat_bus_cli")
                    && cmd_low.contains("send")
                    && cmd_low.contains(&target_low)
                    && cmd_low.contains(&rid_low)
                {
                    return true;
                }
            } else {
                let eff_args = if tname == "call_mcp_tool" {
                    if val_to_str(args.get("ToolName")).trim() != "chat_send" {
                        continue;
                    }
                    match args.get("Arguments").and_then(|v| v.as_object()) {
                        Some(sub) => sub,
                        None => continue,
                    }
                } else {
                    args
                };
                let to_val = val_to_str(eff_args.get("to")).trim().to_lowercase();
                let msg = val_to_str(eff_args.get("message")).to_lowercase();
                if msg.contains(&rid_low)
                    && (to_val.contains(&target_low) || to_val.contains("anomaly"))
                {
                    return true;
                }
            }
        }
    }
    false
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
    let wclass = cwg_common::candidate_class(marker);
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

    let guidance = if wclass == cwg_common::WORK_OPERATIONAL {
        "Для OPERATIONAL-работы завершите ответ последней строкой:\n`[gate] operational: <предпроверка>; <подтверждённый эффект>`\nили `[gate] no-change: <причина>`, если изменений не произошло.".to_string()
    } else if reason.contains("research-reset") {
        let reqs = cwg_common::receipt_requirements_summary(&floor, policy, has_tests);
        format!(
            "Кандидат `PERSISTENT` (риск `{}`). Обязательные условия: {}.\n- Режим исследования после 2 блокировок `--closure`: изучите документацию и лучшие практики через плагины/интернет (`search_web`, `tokenade search/web`, `Context7`, `Developer Knowledge` / `Gemini Docs`, субагент `research`), определите сценарий (`refactor` или `refine`), завершите ожидающих swarm-воркеров через `swarm(action=\"kill\", ...)` и выполните `& \"{}\" codex-lane research-reset --session \"{}\" --decision <refactor|refine> --findings \"...\"`, чтобы обнулить раунды и начать новый цикл в чистых сессиях.\n- Завершите финальный ответ строкой `[gate] verified: {}; <кандидат и решающие проверки>`.",
            floor, reqs, cs_bin, session, floor
        )
    } else {
        let reqs = cwg_common::receipt_requirements_summary(&floor, policy, has_tests);
        let xhigh_hint = if floor == "XHIGH" {
            " с `REVIEW_TIER: XHIGH`"
        } else {
            ""
        };
        let is_fast_path = match cctx.get("fast_path").and_then(|v| v.as_bool()) {
            Some(fp) => fp,
            None => {
                let rr = {
                    let g = val_to_str(marker.get("git_root"));
                    if !g.is_empty() {
                        g
                    } else {
                        val_to_str(marker.get("cwd"))
                    }
                };
                cwg_common::is_simplify_fast_path_eligible(marker, None, None, &rr)
            }
        };
        let simplify_hint = if json_truthy(cctx.get("needs_simplify")) {
            if floor == "STANDARD" || is_fast_path {
                let fp_note = if floor == "STANDARD" {
                    "STANDARD по политике проекта"
                } else {
                    "Swarm 2.0 Fast-Path: <=2 файлов и <=30 строк"
                };
                format!(
                    "- Для simplify ({}) запустите 1 объединённый read-only воркер `simplify-reviewer` (`SIMPLIFY_LENS: ALL`) на `{}` через `swarm(action=\"add\", name=\"simplify-reviewer\", model=\"{}\")` (при сбое/0% квоты Sonnet — `model=\"{}\"`).\n",
                    fp_note,
                    cwg_common::SONNET_HIGH_MODEL,
                    cwg_common::SONNET_HIGH_MODEL,
                    cwg_common::SIMPLIFY_FALLBACK_MODEL
                )
            } else {
                format!(
                    "- Для simplify (`{}`) запустите строго 3 отдельные параллельные линзы (`reuse`, `quality`, `efficiency`) на `{}` через `swarm(action=\"add\", ..., model=\"{}\")` (при сбое/0% квоты Sonnet — `model=\"{}\"`, никогда не `{}`).\n",
                    floor,
                    cwg_common::SONNET_HIGH_MODEL,
                    cwg_common::SONNET_HIGH_MODEL,
                    cwg_common::SIMPLIFY_FALLBACK_MODEL,
                    cwg_common::CARBON_HIGH_MODEL
                )
            }
        } else {
            String::new()
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
            "Кандидат `PERSISTENT` (риск `{}`). Обязательные условия: {}.\n{}{}- Завершите финальный ответ строкой `[gate] verified: {}; <кандидат и решающие проверки>`.",
            floor, reqs, simplify_hint, review_hint, floor
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

    let assistant_msg = {
        let direct = val_to_str(payload.get("lastAssistantMessage"));
        if !direct.is_empty() {
            direct
        } else {
            rio::last_assistant_message(&steps)
        }
    };
    let receipt = cwg_common::parse_terminal_receipt(&assistant_msg);
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
            let handler_sess = gate_inbox::get_handler_session();
            if !handler_sess.is_empty() && handler_sess != session {
                if has_notified_anomaly_handler(
                    &steps,
                    &handler_sess,
                    first_ts,
                    &anom_note,
                    &session,
                ) {
                    gate_inbox::mark_handler_notified(&anom_note);
                } else {
                    let rem = val_to_i64(state.get("notify_reminders"));
                    if rem < 1 {
                        // SAFETY: Preserve `state["block_nonce"]` and cap reminder at 1 so the filed report stays valid and finite.
                        state.insert("notify_reminders".to_string(), json!(rem + 1));
                        let _ = rio::write_json(&sfile, &Value::Object(state));
                        rio::log_hook_event(
                            "gate-events",
                            "notify_handler_reminder",
                            json!({
                                "session": session,
                                "report": anom_note,
                                "handler_session": handler_sess,
                            }),
                        );
                        let bus_cli = rio::chat_bus_cli_path();
                        return Some(format!(
                            "[Code Work Gate] Отчёт об аномалии `{}` сохранён, но дежурный чат аномалий `{}` ещё не уведомлён.\nОтправьте уведомление через `chat-bus` (`python -X utf8 \"{}\" send --from-chat \"{}\" --to \"{}\" --message \"[GATE_ANOMALY {}] session={}; block=...; facts=...\"` с `BypassSandbox=true` — работает между разными проектами; внутри одного проекта допустим `send_message`) и повторите закрытие строкой `[gate] anomaly-reported: {}; <факт>` (`[Чат аномалий](conversation://{})`).",
                            anom_note,
                            handler_sess,
                            bus_cli.to_string_lossy(),
                            session,
                            handler_sess,
                            anom_note,
                            session,
                            anom_note,
                            handler_sess
                        ));
                    }
                }
            }
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
        let checks_ev = read_checks_evidence(&session, first_ts);
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
            let has_combined_any = swarm_ev.sonnet_combined_ts > 0.0
                || swarm_ev.fallback_combined_ts > 0.0
                || swarm_ev.secondary_fallback_combined_ts > 0.0
                || sub_ev.fallback_combined_ts > 0.0
                || sub_ev.secondary_fallback_combined_ts > 0.0;
            let progress_sig = format!(
                "{}:{}:{}:{}",
                swarm_ev.worker_activity_count.unwrap_or(0),
                sub_ev.reviews.len(),
                sub_ev.fallback_lenses.len() + sub_ev.secondary_fallback_lenses.len(),
                if has_combined_any { 1 } else { 0 }
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

    let (live_cls_blks, live_cls_ts, live_cls_ids) =
        codex_lane::active_cycle_closure_blocks_for_marker(
            &marker,
            &session,
            &val_to_str(cctx.get("git_root")),
            &tp_str,
        );
    let closure_halt_active = live_cls_blks >= MAX_CLOSURE_PASSES;
    if !concurrent_mutation && closure_halt_active {
        cwg_common::latch_marker_closure_halt_for_marker(
            &session,
            &marker,
            live_cls_blks,
            live_cls_ts,
            &live_cls_ids,
        );
    }

    let blocks = val_to_i64(state.get("blocks"));
    // SAFETY: Never allow `MAX_BLOCKS_PER_CANDIDATE` retry exhaustion to retire a candidate halted after 2 `CLOSURE_VALIDATION: BLOCKED` passes; require `research-reset` (or explicit `draft-blocked` / `no-change` / `anomaly-reported`).
    if !concurrent_mutation && !closure_halt_active && blocks >= MAX_BLOCKS_PER_CANDIDATE {
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
        assert!(simplify_combined_name_re().is_match("simplify-reviewer"));
        assert!(simplify_combined_name_re().is_match("simp-all-ab12-r2"));
        assert!(system_swarm_err_re().is_match(
            r#"[Message] timestamp=2026-11-17T00:00:00Z sender=system content=Swarm Worker (simp-reuse) with id "cid-123" encountered an error: out of quota"#
        ));
        assert!(model_failure_re().is_match("Error: out of quota"));
        assert!(model_failure_re().is_match("insufficient quota"));
        assert!(model_failure_re().is_match("quota depleted"));
        assert!(model_failure_re().is_match("RESOURCE_EXHAUSTED: 429"));
        assert!(lens_word_re("reuse").unwrap().is_match("check reuse"));
        assert!(lens_word_re("quality").unwrap().is_match("check quality"));
        assert!(lens_word_re("efficiency").unwrap().is_match("check efficiency"));
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
        assert_eq!(ev.simplify_failures, 1);
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
        };
        let sub_ev = SubagentEvidence::default();

        // INVARIANT: Missing simplify and review must reject closure.
        let mut swarm_empty = SwarmEvidence::default();
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
        assert!(reason0.contains("requires primary independent review first"));

        // INVARIANT: Under Sandwich Gate on `HIGH`, post-simplify `ordinary` `APPROVED` without `--closure` MUST be rejected, whereas primary `ordinary` `APPROVED` -> `simplify` -> `--closure` `READY` passes closure (including when `simplify` prompted a durable fix before `--closure`).
        swarm_empty.sonnet_combined_ts = 125.0;
        swarm_empty.sonnet_combined_end_ts = 128.0;
        swarm_empty.simplify_history.push(SimplifyHistoryItem {
            kind: "combined".to_string(),
            lens: None,
            tier: "sonnet".to_string(),
            launch_ts: 125.0,
            end_ts: 128.0,
            seq: 0,
            clean: true,
            has_explicit_all: true,
            ..Default::default()
        });
        let post_sim_ord_only = vec![
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
        let (ok_no_cls, res_no_cls) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt_ok),
            marker_in: &marker,
            checks_ev: &checks_ev,
            sub_ev: &sub_ev,
            swarm_ev: &swarm_empty,
            codex_reviews: &post_sim_ord_only,
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(!ok_no_cls, "post-simplify ordinary APPROVED must not bypass --closure");
        assert!(
            res_no_cls.contains("--closure") || res_no_cls.contains("unnecessarily"),
            "got: {}",
            res_no_cls
        );

        let codex_revs = vec![
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
                "kind": "closure",
                "verdict": "READY",
                "launch_ts": 130.0,
                "verdict_ts": 135.0,
                "xhigh": false,
            }),
        ];
        let (ok1, res1) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt_ok),
            marker_in: &marker,
            checks_ev: &checks_ev,
            sub_ev: &sub_ev,
            swarm_ev: &swarm_empty,
            codex_reviews: &codex_revs,
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(ok1, "expected closure pass, got: {}", res1);
        assert_eq!(res1, "verified");

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
        };
        let (ok1_edit, res1_edit) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt_ok),
            marker_in: &marker_post_sim_edit,
            checks_ev: &checks_post_sim_edit,
            sub_ev: &sub_ev,
            swarm_ev: &swarm_empty,
            codex_reviews: &codex_revs,
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(
            ok1_edit,
            "expected post-simplify edit + fresh simplify + --closure READY to pass, got: {}",
            res1_edit
        );
        let (ok1_bypass, res1_bypass) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt_ok),
            marker_in: &marker_post_sim_edit,
            checks_ev: &checks_post_sim_edit,
            sub_ev: &sub_ev,
            swarm_ev: &swarm_empty,
            codex_reviews: &post_sim_ord_only,
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(!ok1_bypass, "post-simplify edit must still require --closure, got: {}", res1_bypass);
        assert!(res1_bypass.contains("--closure"), "got: {}", res1_bypass);

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

        // INVARIANT: When HIGH has neither primary review nor simplify, report missing primary review BEFORE simplify; when simplify already ran and went stale, report stale simplify.
        let def_sw = SwarmEvidence::default();
        let (ok3a, reason3a) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt_ok),
            marker_in: &marker,
            checks_ev: &checks_ev,
            sub_ev: &sub_ev,
            swarm_ev: &def_sw,
            codex_reviews: &[],
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(!ok3a);
        assert!(
            reason3a.contains("BEFORE simplify"),
            "expected Logic-First primary review priority, got: {}",
            reason3a
        );

        let mut swarm_stale = SwarmEvidence::default();
        swarm_stale.sonnet_lenses.insert("reuse".to_string(), 105.0);
        swarm_stale.sonnet_lenses.insert("quality".to_string(), 105.0);
        swarm_stale.sonnet_lenses.insert("efficiency".to_string(), 105.0);
        let (ok3b, reason3b) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt_ok),
            marker_in: &marker,
            checks_ev: &checks_ev,
            sub_ev: &sub_ev,
            swarm_ev: &swarm_stale,
            codex_reviews: &[],
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(!ok3b);
        assert!(reason3b.contains("stale because durable files changed after simplify"));

        // INVARIANT: Exiting Fast-Path (2 -> 3 files) after stale APPROVED + combined simplify reports primary review BEFORE simplify.
        let f2 = tmp.path.join("src").join("auth2.rs");
        let f3 = tmp.path.join("src").join("auth3.rs");
        fs::write(&f2, "pub fn b() -> bool { true }\n").unwrap();
        fs::write(&f3, "pub fn c() -> bool { true }\n").unwrap();
        let paths3 = vec![
            auth_file.to_string_lossy().into_owned(),
            f2.to_string_lossy().into_owned(),
            f3.to_string_lossy().into_owned(),
        ];
        let fp3 = cwg_common::content_fingerprint(&paths3, cwg_common::MAX_FINGERPRINT_FILE_BYTES);
        let marker3 = json!({
            "cwd": tmp.path.to_string_lossy(),
            "paths": paths3,
            "first_ts": 100.0,
            "last_durable_ts": 110.0,
            "content_marks": [{ "ts": 110.0, "fp": fp3 }]
        });
        let mut sw_fp_exit = SwarmEvidence::default();
        sw_fp_exit.sonnet_combined_ts = 105.0;
        sw_fp_exit.sonnet_combined_end_ts = 106.0;
        let stale_approved = vec![json!({
            "engine": "codex",
            "kind": "ordinary",
            "verdict": "APPROVED",
            "launch_ts": 102.0,
            "verdict_ts": 104.0,
            "xhigh": false,
        })];
        let (ok3c, reason3c) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt_ok),
            marker_in: &marker3,
            checks_ev: &checks_ev,
            sub_ev: &sub_ev,
            swarm_ev: &sw_fp_exit,
            codex_reviews: &stale_approved,
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(!ok3c);
        assert!(
            reason3c.contains("BEFORE simplify"),
            "expected primary review BEFORE simplify after Fast-Path exit, got: {}",
            reason3c
        );

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
        };
        let sub_ev = SubagentEvidence::default();

        let sim1 = SimplifyHistoryItem {
            kind: "combined".to_string(),
            lens: None,
            tier: "sonnet".to_string(),
            launch_ts: t0 + 1.0,
            end_ts: t0 + 1.2,
            seq: 1,
            clean: true,
            has_explicit_all: true,
            ..Default::default()
        };
        let mut sw_pass1 = SwarmEvidence::default();
        sw_pass1.sonnet_combined_ts = t0 + 1.0;
        sw_pass1.sonnet_combined_end_ts = t0 + 1.2;
        sw_pass1.simplify_history = vec![sim1.clone()];

        let ord_app = json!({"review_id": "cwg-o1", "engine": "codex", "kind": "ordinary", "verdict": "APPROVED", "launch_ts": t0 + 0.4, "verdict_ts": t0 + 0.6, "xhigh": false});
        let cls_b1 = json!({"review_id": "cwg-b1", "engine": "codex", "kind": "closure", "verdict": "BLOCKED", "launch_ts": t0 + 1.5, "verdict_ts": t0 + 1.7, "xhigh": false});
        let cls_premature_rdy = json!({"review_id": "cwg-r-prem", "engine": "codex", "kind": "closure", "verdict": "READY", "launch_ts": t0 + 2.0, "verdict_ts": t0 + 2.2, "xhigh": false});

        // INVARIANT: Premature 2nd READY without simplify after BLOCKED #1 is rejected.
        let prem_revs = [ord_app.clone(), cls_b1.clone(), cls_premature_rdy.clone()];
        let (ok_prem, why_prem) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt),
            marker_in: &marker,
            checks_ev: &checks_ev,
            sub_ev: &sub_ev,
            swarm_ev: &sw_pass1,
            codex_reviews: &prem_revs,
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(!ok_prem);
        assert!(why_prem.contains("without a fresh `simplify` pass"), "got: {}", why_prem);

        // INVARIANT: Running simplify + replacement `--closure` READY supersedes the premature pass within MAX_CLOSURE_PASSES=2.
        let sim2 = SimplifyHistoryItem {
            kind: "combined".to_string(),
            lens: None,
            tier: "sonnet".to_string(),
            launch_ts: t0 + 3.0,
            end_ts: t0 + 3.2,
            seq: 2,
            clean: true,
            has_explicit_all: true,
            ..Default::default()
        };
        let mut sw_rec = SwarmEvidence::default();
        sw_rec.sonnet_combined_ts = t0 + 3.0;
        sw_rec.sonnet_combined_end_ts = t0 + 3.2;
        sw_rec.simplify_history = vec![sim1.clone(), sim2.clone()];
        let cls_rec_rdy = json!({"review_id": "cwg-r-rec", "engine": "codex", "kind": "closure", "verdict": "READY", "launch_ts": t0 + 3.5, "verdict_ts": t0 + 3.7, "xhigh": false});
        let rec_revs = [ord_app.clone(), cls_b1.clone(), cls_premature_rdy, cls_rec_rdy];
        let (ok_rec, why_rec) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt),
            marker_in: &marker,
            checks_ev: &checks_ev,
            sub_ev: &sub_ev,
            swarm_ev: &sw_rec,
            codex_reviews: &rec_revs,
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(ok_rec, "expected recovery to close cleanly, got: {}", why_rec);

        // INVARIANT: 2 BLOCKED closure verdicts strictly halt the cycle, and a 3rd READY pass cannot launder 2 BLOCKED passes.
        let cls_b2 = json!({"review_id": "cwg-b2", "engine": "codex", "kind": "closure", "verdict": "BLOCKED", "launch_ts": t0 + 3.5, "verdict_ts": t0 + 3.7, "xhigh": false});
        let blk2_revs = [ord_app.clone(), cls_b1.clone(), cls_b2.clone()];
        let (ok_2blk, why_2blk) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt),
            marker_in: &marker,
            checks_ev: &checks_ev,
            sub_ev: &sub_ev,
            swarm_ev: &sw_rec,
            codex_reviews: &blk2_revs,
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(!ok_2blk);
        assert!(why_2blk.contains("2/2 `BLOCKED`"), "got: {}", why_2blk);

        let cls_forged3 = json!({"review_id": "cwg-r3", "engine": "codex", "kind": "closure", "verdict": "READY", "launch_ts": t0 + 4.5, "verdict_ts": t0 + 4.7, "xhigh": false});
        let forged3_revs = [ord_app, cls_b1, cls_b2, cls_forged3];
        let (ok_3rd, why_3rd) = validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&receipt),
            marker_in: &marker,
            checks_ev: &checks_ev,
            sub_ev: &sub_ev,
            swarm_ev: &sw_rec,
            codex_reviews: &forged3_revs,
            ctx: None,
            steps: None,
            transcript_path: None,
        });
        assert!(!ok_3rd);
        assert!(why_3rd.contains("MAX_CLOSURE_PASSES=2"), "got: {}", why_3rd);

        // INVARIANT: Post-research-reset worker reusing standard name `simplify-reviewer` with new `conversation_id` is counted without inheriting Cycle-1 board messages.
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
                    "simplify-reviewer": {
                        "conversation_id": "cid-new-cycle2",
                        "model": cwg_common::SONNET_HIGH_MODEL,
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
            json!({"seq": 1, "agent": "coordinator", "time": "1970-01-01T00:20:00Z", "text": "@simplify-reviewer old cycle"}),
            json!({"seq": 6, "agent": "coordinator", "time": "1970-01-01T00:33:26Z", "text": "@simplify-reviewer SIMPLIFY_LENS: ALL\nDIFF_HASH: h2"}),
            json!({"seq": 7, "agent": "simplify-reviewer", "time": "1970-01-01T00:33:30Z", "text": "SIMPLIFY_LENS: ALL\nDIFF_HASH: h2\nSIMPLIFY_VERDICT: CLEAN"}),
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
        assert!(scanned_new.sonnet_combined_ts > 2000.0);

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
        fs::create_dir_all(&swarm_cli_dir).unwrap();
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
            json!({"seq": 5, "agent": "coordinator", "time": "2026-11-18 10:01:10", "text": "@rev-opus closure pass 1"}),
            json!({"seq": 6, "agent": "rev-opus", "time": "2026-11-18 10:01:20", "text": "CLOSURE_VALIDATION: BLOCKED"}),
            json!({"seq": 7, "agent": "coordinator", "time": "2026-11-18 10:02:10", "text": "@rev-opus closure pass 2"}),
            json!({"seq": 8, "agent": "rev-opus", "time": "2026-11-18 10:02:20", "text": "CLOSURE_VALIDATION: BLOCKED"}),
            json!({"seq": 9, "agent": "coordinator", "time": "2026-11-18 10:05:10", "text": "@rev-opus post-recovery unauthorized pass"}),
            json!({"seq": 10, "agent": "rev-opus", "time": "2026-11-18 10:05:20", "text": "CLOSURE_VALIDATION: BLOCKED"}),
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
        // SAFETY: `MAX_BLOCKS_PER_CANDIDATE` retry exhaustion in `decide_stop` must never retire a candidate halted after 2 `BLOCKED` passes without `research-reset`, and `latch_marker_closure_halt` must reject cross-candidate turnover (`first_ts` mismatch).
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
            blk_halted_exhaust
                .as_deref()
                .map_or(false, |m| m.contains("2/2 `BLOCKED` verdicts")),
            "expected decide_stop to stay halted past MAX_BLOCKS_PER_CANDIDATE, got: {:?}",
            blk_halted_exhaust
        );
        assert!(mfile_cli.is_file());
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

    fn make_three_file_fixture(
        ws: &Path,
        sess: &str,
        t0: f64,
    ) -> (Value, ChecksEvidence, SubagentEvidence) {
        fs::create_dir_all(ws.join("src")).unwrap();
        let files = ["a.rs", "b.rs", "c.rs"]
            .into_iter()
            .map(|name| {
                let p = ws.join("src").join(name);
                fs::write(&p, format!("pub fn {}() {{}}\n", &name[..1])).unwrap();
                p
            })
            .collect::<Vec<_>>();
        let path_strs: Vec<String> = files
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let fp3 = cwg_common::content_fingerprint(&path_strs, 4_000_000);
        let norm_paths: Vec<String> = path_strs.iter().map(|p| rio::normalize_path(p)).collect();
        let marker = json!({
            "session": sess,
            "class": cwg_common::WORK_PERSISTENT,
            "first_ts": t0,
            "last_durable_ts": t0 + 1.0,
            "cwd": rio::normalize_path(&ws.to_string_lossy()),
            "git_root": "",
            "paths": norm_paths,
            "changed_lines": 45,
            "content_marks": [{"ts": t0 + 1.0, "fp": fp3}],
            "closed": false,
        });
        let checks_ev = ChecksEvidence {
            checks_count: 1,
            passed_count: 1,
            failed_count: 0,
            latest_pass_ts: t0 + 2.0,
            latest_fail_ts: 0.0,
        };
        (marker, checks_ev, SubagentEvidence::default())
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_closure_default(
        rkind: &str,
        risk: &str,
        marker: &Value,
        checks_ev: &ChecksEvidence,
        sub_ev: &SubagentEvidence,
        swarm_ev: &SwarmEvidence,
        codex_reviews: &[Value],
        steps: Option<&[Value]>,
        tp: Option<&Path>,
    ) -> (bool, String) {
        let tp_str = tp.map(|p| p.to_string_lossy().into_owned());
        validate_candidate_closure(CandidateClosureInput {
            receipt: Some(&json!({"kind": rkind, "risk": risk})),
            marker_in: marker,
            checks_ev,
            sub_ev,
            swarm_ev,
            codex_reviews,
            ctx: None,
            steps,
            transcript_path: tp_str.as_deref(),
        })
    }

    #[test]
    fn test_neon_simplify_fallback_and_internal_high_review_escalation() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempEnvDir::new("neon-gate");
        let ws = tmp.path.join("ws");
        let brain = tmp.path.join("brain");
        let t0 = rio::parse_iso_ts("2026-11-19T10:00:00Z");
        let (marker3, checks_ev, sub_ev) = make_three_file_fixture(&ws, "sess-neon-gate", t0);

        let sess = "sess-neon-gate";
        let full_tp = setup_neon_session_env(
            &brain,
            sess,
            "{\"step_index\":0,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"created_at\":\"2026-11-19T10:00:00Z\"}\n",
            json!({
                "members": {
                    "internal-reviewer-xhigh": {"role": "worker", "model": cwg_common::NEON_XHIGH_MODEL, "killed": true},
                    "root-cause-debugger": {"role": "worker", "model": cwg_common::NEON_XHIGH_MODEL, "killed": true},
                    "simplify-reuse-r1": {"role": "worker", "model": cwg_common::NEON_XHIGH_MODEL, "killed": true},
                    "simplify-quality-r1": {"role": "worker", "model": cwg_common::NEON_XHIGH_MODEL, "killed": true},
                    "simplify-efficiency-r1": {"role": "worker", "model": cwg_common::HYDROGEN_XHIGH_MODEL, "killed": true},
                }
            }),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:05Z", "text": "@root-cause-debugger diagnose shutdown race"}),
                json!({"seq": 2, "agent": "root-cause-debugger", "time": "2026-11-19T10:00:08Z", "text": "Confirmed shutdown race. No verdict lines."}),
                json!({"seq": 3, "agent": "coordinator", "time": "2026-11-19T10:00:10Z", "text": "@internal-reviewer-xhigh verify candidate REVIEW_TIER: XHIGH"}),
                json!({"seq": 4, "agent": "internal-reviewer-xhigh", "time": "2026-11-19T10:00:15Z", "text": "REVIEW_TIER: XHIGH\nVERDICT: APPROVED"}),
                json!({"seq": 5, "agent": "coordinator", "time": "2026-11-19T10:00:20Z", "text": "@simplify-reuse-r1 @simplify-quality-r1 @simplify-efficiency-r1 check lenses"}),
                json!({"seq": 6, "agent": "simplify-reuse-r1", "time": "2026-11-19T10:00:25Z", "text": "SIMPLIFY_LENS: REUSE\nSIMPLIFY_VERDICT: CLEAN"}),
                json!({"seq": 7, "agent": "simplify-quality-r1", "time": "2026-11-19T10:00:26Z", "text": "SIMPLIFY_LENS: QUALITY\nSIMPLIFY_VERDICT: CLEAN"}),
                json!({"seq": 8, "agent": "simplify-efficiency-r1", "time": "2026-11-19T10:00:27Z", "text": "SIMPLIFY_LENS: EFFICIENCY\nSIMPLIFY_VERDICT: CLEAN"}),
                json!({"seq": 9, "agent": "coordinator", "time": "2026-11-19T10:00:30Z", "text": "@internal-reviewer-xhigh closure check REVIEW_TIER: XHIGH"}),
                json!({"seq": 10, "agent": "internal-reviewer-xhigh", "time": "2026-11-19T10:00:35Z", "text": "REVIEW_TIER: XHIGH\nCLOSURE_VALIDATION: READY"}),
            ],
            &[],
        );

        let steps = vec![
            json!({
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2026-11-19T10:00:02Z",
                "tool_calls": [{"name": "swarm", "args": {"action": "models", "all": true}}]
            }),
            json!({
                "source": "GENERIC",
                "type": "GENERIC",
                "status": "DONE",
                "created_at": "2026-11-19T10:00:03Z",
                "content": json!({
                    "models": [
                        cwg_common::OPUS_HIGH_MODEL,
                        cwg_common::SONNET_HIGH_MODEL,
                        cwg_common::NEON_XHIGH_MODEL,
                        cwg_common::HYDROGEN_XHIGH_MODEL
                    ],
                    "quotas": {
                        cwg_common::OPUS_HIGH_MODEL: {"quota_remaining": "0%"},
                        cwg_common::SONNET_HIGH_MODEL: {"quota_remaining": "0%"},
                        cwg_common::NEON_XHIGH_MODEL: {"quota_remaining": "0%"}
                    }
                }).to_string()
            }),
        ];

        let mut ev = scan_swarm_activity(
            &steps,
            Some(&full_tp.to_string_lossy()),
            t0,
            0,
            sess,
            &brain.to_string_lossy(),
        );
        assert!(ev.fallback_lenses.contains_key("reuse"));
        assert!(ev.fallback_lenses.contains_key("quality"));
        assert!(ev.secondary_fallback_lenses.contains_key("efficiency"));
        assert!(ev.neon_issue_verified);
        assert_eq!(ev.reviews.len(), 2);
        assert!(ev.reviews.iter().all(|r| {
            r["engine"] == cwg_common::REVIEW_ENGINE_INTERNAL_NEON
                && r["reviewer"] == "internal-reviewer-xhigh"
                && r["xhigh"] == false
        }));

        ev.codex_cmd_failed = true;
        ev.codex_issue_ts = t0 + 1.5;
        ev.codex_issue_step = -1;
        let (ok_high, why_high) = eval_closure_default(
            "verified",
            "HIGH",
            &marker3,
            &checks_ev,
            &sub_ev,
            &ev,
            &[],
            Some(&steps),
            Some(&full_tp),
        );
        assert!(ok_high, "expected internal-neon + Neon/Hydrogen simplify fallback to pass HIGH, got: {}", why_high);

        let (ok_xhigh, why_xhigh) = eval_closure_default(
            "verified",
            "XHIGH",
            &marker3,
            &checks_ev,
            &sub_ev,
            &ev,
            &[],
            Some(&steps),
            Some(&full_tp),
        );
        assert!(!ok_xhigh, "internal-neon must not satisfy XHIGH review");
        assert!(
            why_xhigh.contains("XHIGH") && why_xhigh.contains(cwg_common::NEON_XHIGH_MODEL),
            "expected XHIGH rejection naming {}, got: {}",
            cwg_common::NEON_XHIGH_MODEL,
            why_xhigh
        );

        let mut ev_healthy_opus = ev.clone();
        ev_healthy_opus.opus_issue_verified = false;
        let (ok_no_opus_err, why_no_opus_err) = eval_closure_default(
            "verified",
            "HIGH",
            &marker3,
            &checks_ev,
            &sub_ev,
            &ev_healthy_opus,
            &[],
            Some(&steps),
            Some(&full_tp),
        );
        assert!(!ok_no_opus_err);
        assert!(why_no_opus_err.contains(cwg_common::OPUS_HIGH_MODEL), "got: {}", why_no_opus_err);

        let mut ev_healthy_sonnet = ev.clone();
        ev_healthy_sonnet.sonnet_issue_verified = false;
        let (ok_no_sonnet_err, why_no_sonnet_err) = eval_closure_default(
            "verified",
            "HIGH",
            &marker3,
            &checks_ev,
            &sub_ev,
            &ev_healthy_sonnet,
            &[],
            Some(&steps),
            Some(&full_tp),
        );
        assert!(!ok_no_sonnet_err);
        assert!(why_no_sonnet_err.contains(cwg_common::SONNET_HIGH_MODEL), "got: {}", why_no_sonnet_err);

        let mut ev_healthy_neon = ev.clone();
        ev_healthy_neon.neon_issue_verified = false;
        let (ok_no_neon_err, why_no_neon_err) = eval_closure_default(
            "verified",
            "HIGH",
            &marker3,
            &checks_ev,
            &sub_ev,
            &ev_healthy_neon,
            &[],
            Some(&steps),
            Some(&full_tp),
        );
        assert!(!ok_no_neon_err);
        assert!(why_no_neon_err.contains(cwg_common::NEON_XHIGH_MODEL), "got: {}", why_no_neon_err);
    }

    #[test]
    fn test_neon_model_switch_attribution_xhigh_exclusion_and_cap_exhausted_closure_error() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempEnvDir::new("neon-switch");
        let brain = tmp.path.join("brain");
        let ws = tmp.path.join("repo");
        let t0 = rio::parse_iso_ts("2026-11-19T10:00:00Z");
        let (marker_xhigh, checks_ev, sub_ev) =
            make_three_file_fixture(&ws, "sess-neon-xhigh-excl", t0);

        let sess_sw = "sess-neon-switch";
        let tp_sw = setup_neon_session_env(
            &brain,
            sess_sw,
            "",
            json!({
                "members": {
                    "reviewer-n2c": {"role": "worker", "model": cwg_common::CARBON_HIGH_MODEL, "killed": true},
                    "rev-o2n": {"role": "worker", "model": cwg_common::NEON_XHIGH_MODEL, "killed": true},
                    "rev-unk2c": {"role": "worker", "model": cwg_common::CARBON_HIGH_MODEL, "killed": true},
                }
            }),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:03Z", "text": "@reviewer-n2c primary"}),
                json!({"seq": 2, "agent": "reviewer-n2c", "time": "2026-11-19T10:00:05Z", "text": "REVIEW_TIER: XHIGH\nVERDICT: APPROVED"}),
                json!({"seq": 3, "agent": "coordinator", "time": "2026-11-19T10:00:11Z", "text": "@reviewer-n2c closure"}),
                json!({"seq": 4, "agent": "reviewer-n2c", "time": "2026-11-19T10:00:15Z", "text": "REVIEW_TIER: XHIGH\nCLOSURE_VALIDATION: READY"}),
                json!({"seq": 5, "agent": "coordinator", "time": "2026-11-19T10:00:23Z", "text": "@rev-o2n primary"}),
                json!({"seq": 6, "agent": "rev-o2n", "time": "2026-11-19T10:00:25Z", "text": "REVIEW_TIER: XHIGH\nVERDICT: APPROVED"}),
                json!({"seq": 7, "agent": "coordinator", "time": "2026-11-19T10:00:43Z", "text": "@rev-unk2c primary"}),
                json!({"seq": 8, "agent": "rev-unk2c", "time": "2026-11-19T10:00:45Z", "text": "REVIEW_TIER: XHIGH\nVERDICT: APPROVED"}),
                json!({"seq": 9, "agent": "coordinator", "time": "2026-11-19T10:00:51Z", "text": "@rev-unk2c closure"}),
                json!({"seq": 10, "agent": "rev-unk2c", "time": "2026-11-19T10:00:55Z", "text": "REVIEW_TIER: XHIGH\nCLOSURE_VALIDATION: READY"}),
            ],
            &[],
        );
        let steps_sw = vec![
            json!({
                "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z",
                "tool_calls": [
                    {"name": "swarm", "args": {"action": "add", "name": "reviewer-n2c", "model": cwg_common::NEON_XHIGH_MODEL}},
                    {"name": "swarm", "args": {"action": "add", "name": "rev-o2n", "model": cwg_common::OPUS_HIGH_MODEL}},
                    {"name": "swarm", "args": {"action": "add", "name": "rev-unk2c"}}
                ]
            }),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03Z", "tool_calls": [{"name": "post_message", "args": {"text": "@reviewer-n2c primary"}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:03Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "reviewer-n2c", "model": cwg_common::CARBON_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:10Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:11Z", "tool_calls": [{"name": "post_message", "args": {"text": "@reviewer-n2c closure"}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:11Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:23Z", "tool_calls": [{"name": "post_message", "args": {"text": "@rev-o2n primary"}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:23Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:30Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "rev-o2n", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:30Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:43Z", "tool_calls": [{"name": "post_message", "args": {"text": "@rev-unk2c primary"}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:43Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:50Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "rev-unk2c", "model": cwg_common::CARBON_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:50Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:51Z", "tool_calls": [{"name": "post_message", "args": {"text": "@rev-unk2c closure"}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:51Z", "content": "{}"}),
        ];
        let ev_sw = scan_swarm_activity(
            &steps_sw,
            Some(&tp_sw.to_string_lossy()),
            t0,
            0,
            sess_sw,
            &brain.to_string_lossy(),
        );
        let n2c_ord = ev_sw.reviews.iter().find(|r| r["reviewer"] == "reviewer-n2c" && r["kind"] == "ordinary").unwrap();
        assert_eq!(n2c_ord["engine"], cwg_common::REVIEW_ENGINE_INTERNAL_NEON);
        assert_eq!(n2c_ord["model"], cwg_common::NEON_XHIGH_MODEL);
        assert_eq!(n2c_ord["xhigh"], false);
        let n2c_cls = ev_sw.reviews.iter().find(|r| r["reviewer"] == "reviewer-n2c" && r["kind"] == "closure").unwrap();
        assert_eq!(n2c_cls["engine"], cwg_common::REVIEW_ENGINE_INTERNAL_CARBON);
        assert_eq!(n2c_cls["model"], cwg_common::CARBON_HIGH_MODEL);
        assert_eq!(n2c_cls["xhigh"], true);

        let o2n_ord = ev_sw.reviews.iter().find(|r| r["reviewer"] == "rev-o2n" && r["kind"] == "ordinary").unwrap();
        assert_eq!(o2n_ord["engine"], cwg_common::REVIEW_ENGINE_INTERNAL_OPUS);
        assert_eq!(o2n_ord["model"], cwg_common::OPUS_HIGH_MODEL);
        assert_eq!(o2n_ord["xhigh"], true);

        let unk_revs: Vec<&Value> = ev_sw.reviews.iter().filter(|r| r["reviewer"] == "rev-unk2c").collect();
        assert_eq!(unk_revs.len(), 1);
        assert_eq!(unk_revs[0]["kind"], "closure");
        assert_eq!(unk_revs[0]["engine"], cwg_common::REVIEW_ENGINE_INTERNAL_CARBON);

        let mut base_sonnet_lenses = HashMap::new();
        let mut base_sonnet_lenses_end = HashMap::new();
        for l in cwg_common::SIMPLIFY_LENSES {
            base_sonnet_lenses.insert((*l).to_string(), t0 + 20.0);
            base_sonnet_lenses_end.insert((*l).to_string(), t0 + 22.0);
        }

        let mut ev_neon_rounds_xhigh = SwarmEvidence {
            sonnet_lenses: base_sonnet_lenses.clone(),
            sonnet_lenses_end: base_sonnet_lenses_end.clone(),
            opus_issue_verified: true,
            opus_issue_ts: t0 + 2.5,
            codex_cmd_failed: true,
            codex_issue_ts: t0 + 1.5,
            codex_issue_step: -1,
            ..SwarmEvidence::default()
        };
        for r_i in 0..3 {
            let lts = t0 + 5.0 + (r_i as f64) * 3.0;
            ev_neon_rounds_xhigh.reviews.push(json!({
                "engine": cwg_common::REVIEW_ENGINE_INTERNAL_NEON,
                "reviewer": "neon-rev", "kind": "ordinary",
                "verdict": "ESCALATE", "launch_ts": lts, "verdict_ts": lts + 1.0,
                "xhigh": false, "model": cwg_common::NEON_XHIGH_MODEL, "escalated_from_opus": true
            }));
        }
        ev_neon_rounds_xhigh.reviews.push(json!({
            "engine": cwg_common::REVIEW_ENGINE_INTERNAL_CARBON,
            "reviewer": "carbon-rev", "kind": "closure",
            "verdict": "READY", "launch_ts": t0 + 30.0, "verdict_ts": t0 + 32.0,
            "xhigh": true, "model": cwg_common::CARBON_HIGH_MODEL, "escalated_from_opus": true
        }));
        let (ok_neon_3, why_neon_3) = eval_closure_default(
            "verified",
            "XHIGH",
            &marker_xhigh,
            &checks_ev,
            &sub_ev,
            &ev_neon_rounds_xhigh,
            &[],
            None,
            None,
        );
        assert!(!ok_neon_3, "3 Neon ESCALATE rounds must not satisfy XHIGH round count");
        assert!(!why_neon_3.is_empty());

        let mut ev_neon_blocked_xhigh = SwarmEvidence {
            sonnet_lenses: base_sonnet_lenses.clone(),
            sonnet_lenses_end: base_sonnet_lenses_end.clone(),
            opus_issue_verified: true,
            opus_issue_ts: t0 + 2.5,
            codex_cmd_failed: true,
            codex_issue_ts: t0 + 1.5,
            codex_issue_step: -1,
            ..SwarmEvidence::default()
        };
        ev_neon_blocked_xhigh.reviews.push(json!({
            "engine": cwg_common::REVIEW_ENGINE_INTERNAL_CARBON,
            "reviewer": "carbon-rev", "kind": "ordinary",
            "verdict": "APPROVED", "launch_ts": t0 + 6.0, "verdict_ts": t0 + 8.0,
            "xhigh": true, "model": cwg_common::CARBON_HIGH_MODEL, "escalated_from_opus": true
        }));
        for b_i in 0..2 {
            let lts = t0 + 25.0 + (b_i as f64) * 3.0;
            ev_neon_blocked_xhigh.reviews.push(json!({
                "engine": cwg_common::REVIEW_ENGINE_INTERNAL_NEON,
                "reviewer": "neon-cls", "kind": "closure",
                "verdict": "BLOCKED", "launch_ts": lts, "verdict_ts": lts + 1.0,
                "xhigh": false, "model": cwg_common::NEON_XHIGH_MODEL, "escalated_from_opus": true
            }));
        }
        let (ok_neon_blk, why_neon_blk) = eval_closure_default(
            "verified",
            "XHIGH",
            &marker_xhigh,
            &checks_ev,
            &sub_ev,
            &ev_neon_blocked_xhigh,
            &[],
            None,
            None,
        );
        assert!(!ok_neon_blk);
        assert!(
            !why_neon_blk.contains("2/2") && !why_neon_blk.contains("research-reset"),
            "Neon BLOCKED must not consume XHIGH closure attempts, got: {}",
            why_neon_blk
        );

        let mut ev_cap_inelig = SwarmEvidence {
            sonnet_lenses: base_sonnet_lenses,
            sonnet_lenses_end: base_sonnet_lenses_end,
            opus_issue_verified: false,
            codex_cmd_failed: true,
            codex_issue_ts: t0 + 1.5,
            codex_issue_step: -1,
            ..SwarmEvidence::default()
        };
        for r_i in 0..3 {
            let lts = t0 + 5.0 + (r_i as f64) * 3.0;
            ev_cap_inelig.reviews.push(json!({
                "engine": cwg_common::REVIEW_ENGINE_INTERNAL_OPUS,
                "reviewer": "opus-rev", "kind": "ordinary",
                "verdict": "ESCALATE", "launch_ts": lts, "verdict_ts": lts + 1.0,
                "xhigh": false, "model": cwg_common::OPUS_HIGH_MODEL, "escalated_from_opus": false
            }));
        }
        ev_cap_inelig.reviews.push(json!({
            "engine": cwg_common::REVIEW_ENGINE_INTERNAL_NEON,
            "reviewer": "neon-cls", "kind": "closure",
            "verdict": "READY", "launch_ts": t0 + 30.0, "verdict_ts": t0 + 32.0,
            "xhigh": false, "model": cwg_common::NEON_XHIGH_MODEL, "escalated_from_opus": false
        }));
        let (ok_cap_err, why_cap_err) = eval_closure_default(
            "verified",
            "HIGH",
            &marker_xhigh,
            &checks_ev,
            &sub_ev,
            &ev_cap_inelig,
            &[],
            None,
            None,
        );
        assert!(!ok_cap_err);
        assert!(
            why_cap_err.contains(cwg_common::OPUS_HIGH_MODEL),
            "expected ineligible closure engine error mentioning Opus, got: {}",
            why_cap_err
        );
    }

    #[test]
    fn test_neon_switch_boundary_sonnet_error_isolation_and_post_blocked_closure_error() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempEnvDir::new("neon-boundary");
        let brain = tmp.path.join("brain");
        let ws = tmp.path.join("repo");
        let t0 = rio::parse_iso_ts("2026-11-19T10:00:00Z");
        let (marker_xhigh, checks_ev, sub_ev) =
            make_three_file_fixture(&ws, "sess-neon-boundary-val", t0);

        let sess_bnd = "sess-neon-boundary";
        let sub_cid = "worker-sub-cid";
        let sub_steps = [
            json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:20Z"}),
            json!({
                "step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:25.200Z",
                "tool_calls": [{"name": "post_message", "args": {"text": "REVIEW_TIER: XHIGH\nVERDICT: APPROVED"}}]
            }),
            json!({
                "step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:25.900Z",
                "tool_calls": [{"name": "post_message", "args": {"text": "REVIEW_TIER: XHIGH\nCLOSURE_VALIDATION: READY"}}]
            }),
        ];
        let tp_bnd = setup_neon_session_env(
            &brain,
            sess_bnd,
            "",
            json!({
                "members": {
                    "reviewer-unconf": {"role": "worker", "model": cwg_common::CARBON_HIGH_MODEL, "killed": true},
                    "reviewer-bnd": {"role": "worker", "model": cwg_common::CARBON_HIGH_MODEL, "killed": true},
                    "reviewer-sub": {"role": "worker", "conversation_id": sub_cid, "model": cwg_common::CARBON_HIGH_MODEL, "killed": true},
                }
            }),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:03Z", "text": "@reviewer-unconf primary"}),
                json!({"seq": 2, "agent": "coordinator", "time": "2026-11-19T10:00:03Z", "text": "@reviewer-bnd primary"}),
                json!({"seq": 3, "agent": "reviewer-unconf", "time": "2026-11-19T10:00:04Z", "text": "REVIEW_TIER: XHIGH\nVERDICT: APPROVED"}),
                json!({"seq": 4, "agent": "reviewer-bnd", "time": "2026-11-19T10:00:05Z", "text": "REVIEW_TIER: XHIGH\nVERDICT: APPROVED"}),
                json!({"seq": 5, "agent": "coordinator", "time": "2026-11-19T10:00:11Z", "text": "@reviewer-unconf closure"}),
                json!({"seq": 6, "agent": "reviewer-unconf", "time": "2026-11-19T10:00:15Z", "text": "REVIEW_TIER: XHIGH\nCLOSURE_VALIDATION: READY"}),
                json!({"seq": 7, "agent": "coordinator", "time": "2026-11-19T10:00:21Z", "text": "@reviewer-sub primary"}),
                json!({"seq": 8, "agent": "reviewer-sub", "time": "2026-11-19T10:00:25Z", "text": "REVIEW_TIER: XHIGH\nVERDICT: APPROVED"}),
                json!({"seq": 9, "agent": "reviewer-sub", "time": "2026-11-19T10:00:25Z", "text": "REVIEW_TIER: XHIGH\nCLOSURE_VALIDATION: READY"}),
            ],
            &[(sub_cid, &sub_steps)],
        );
        let steps_bnd = vec![
            json!({
                "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z",
                "tool_calls": [
                    {"name": "swarm", "args": {"action": "add", "name": "reviewer-unconf", "model": cwg_common::NEON_XHIGH_MODEL}},
                    {"name": "swarm", "args": {"action": "add", "name": "reviewer-bnd", "model": cwg_common::NEON_XHIGH_MODEL}},
                    {"name": "swarm", "args": {"action": "add", "name": "reviewer-sub", "model": cwg_common::NEON_XHIGH_MODEL}}
                ]
            }),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({
                "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03Z",
                "tool_calls": [
                    {"name": "post_message", "args": {"text": "@reviewer-unconf primary"}},
                    {"name": "post_message", "args": {"text": "@reviewer-bnd primary"}}
                ]
            }),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:03Z", "content": "{}"}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:03Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:05.700Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "reviewer-bnd", "model": cwg_common::CARBON_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:05.800Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "reviewer-unconf", "model": cwg_common::CARBON_HIGH_MODEL}}]}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:11Z", "tool_calls": [{"name": "post_message", "args": {"text": "@reviewer-unconf closure"}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:11Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:21Z", "tool_calls": [{"name": "post_message", "args": {"text": "@reviewer-sub primary"}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:21Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:25.700Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "reviewer-sub", "model": cwg_common::CARBON_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:25.800Z", "content": "{}"}),
        ];
        let ev_bnd = scan_swarm_activity(
            &steps_bnd,
            Some(&tp_bnd.to_string_lossy()),
            t0,
            0,
            sess_bnd,
            &brain.to_string_lossy(),
        );
        let unconf_revs: Vec<&Value> = ev_bnd.reviews.iter().filter(|r| r["reviewer"] == "reviewer-unconf").collect();
        assert_eq!(unconf_revs.len(), 1);
        assert_eq!(unconf_revs[0]["engine"], cwg_common::REVIEW_ENGINE_INTERNAL_NEON);
        assert!(ev_bnd.reviews.iter().all(|r| r["reviewer"] != "reviewer-bnd"), "same-second whole-second post near 05.800Z switch must fail closed");
        let sub_ord = ev_bnd.reviews.iter().find(|r| r["reviewer"] == "reviewer-sub" && r["kind"] == "ordinary").unwrap();
        assert_eq!(sub_ord["engine"], cwg_common::REVIEW_ENGINE_INTERNAL_NEON);
        assert_eq!(sub_ord["xhigh"], false);
        let sub_cls = ev_bnd.reviews.iter().find(|r| r["reviewer"] == "reviewer-sub" && r["kind"] == "closure").unwrap();
        assert_eq!(sub_cls["engine"], cwg_common::REVIEW_ENGINE_INTERNAL_CARBON);
        assert_eq!(sub_cls["xhigh"], true);

        let sess_err = "sess-sonnet-err-only";
        let simp_cid = "simp-err-cid";
        let simp_steps = [
            json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
            json!({"step_index": 1, "source": "SYSTEM", "type": "ERROR_MESSAGE", "created_at": "2026-11-19T10:00:05Z", "content": "quota exhausted"}),
            json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:15Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE\nSIMPLIFY_VERDICT: CLEAN"}}]}),
        ];
        let tp_err = setup_neon_session_env(
            &brain,
            sess_err,
            "",
            json!({"members": {"simplify-reuse": {"role": "worker", "conversation_id": simp_cid, "model": cwg_common::NEON_XHIGH_MODEL, "killed": true}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:03Z", "text": "@simplify-reuse check reuse"}),
                json!({"seq": 2, "agent": "simplify-reuse", "time": "2026-11-19T10:00:15Z", "text": "SIMPLIFY_LENS: REUSE\nSIMPLIFY_VERDICT: CLEAN"}),
            ],
            &[(simp_cid, &simp_steps)],
        );
        let steps_err = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-reuse", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "simplify-reuse", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:10Z", "content": "{}"}),
        ];
        let ev_err = scan_swarm_activity(
            &steps_err,
            Some(&tp_err.to_string_lossy()),
            t0,
            0,
            sess_err,
            &brain.to_string_lossy(),
        );
        assert!(ev_err.sonnet_issue_verified);
        assert!((ev_err.sonnet_issue_ts - (t0 + 5.0)).abs() < TS_EPS);
        assert!(!ev_err.neon_issue_verified, "error during Sonnet turn must not taint healthy Neon");
        assert!(ev_err.fallback_lenses.contains_key("reuse"));

        let mut fb_pre_neon = HashMap::new();
        let mut fb_pre_neon_end = HashMap::new();
        fb_pre_neon.insert("reuse".to_string(), t0 + 10.0);
        fb_pre_neon.insert("quality".to_string(), t0 + 10.0);
        fb_pre_neon_end.insert("reuse".to_string(), t0 + 12.0);
        fb_pre_neon_end.insert("quality".to_string(), t0 + 12.0);
        let mut sec_pre_neon = HashMap::new();
        let mut sec_pre_neon_end = HashMap::new();
        sec_pre_neon.insert("efficiency".to_string(), t0 + 10.0);
        sec_pre_neon_end.insert("efficiency".to_string(), t0 + 12.0);
        let mut ev_premature_h2 = SwarmEvidence {
            fallback_lenses: fb_pre_neon,
            fallback_lenses_end: fb_pre_neon_end,
            secondary_fallback_lenses: sec_pre_neon,
            secondary_fallback_lenses_end: sec_pre_neon_end,
            sonnet_issue_verified: true,
            sonnet_issue_ts: t0 + 3.0,
            neon_issue_verified: true,
            neon_issue_ts: t0 + 25.0,
            codex_cmd_failed: true,
            codex_issue_ts: t0 + 1.5,
            codex_issue_step: -1,
            ..SwarmEvidence::default()
        };
        ev_premature_h2.reviews.push(json!({
            "engine": cwg_common::REVIEW_ENGINE_INTERNAL_OPUS,
            "reviewer": "opus-rev", "kind": "ordinary",
            "verdict": "APPROVED", "launch_ts": t0 + 5.0, "verdict_ts": t0 + 6.0,
            "xhigh": true, "model": cwg_common::OPUS_HIGH_MODEL
        }));
        ev_premature_h2.reviews.push(json!({
            "engine": cwg_common::REVIEW_ENGINE_INTERNAL_OPUS,
            "reviewer": "opus-cls", "kind": "closure",
            "verdict": "READY", "launch_ts": t0 + 30.0, "verdict_ts": t0 + 31.0,
            "xhigh": true, "model": cwg_common::OPUS_HIGH_MODEL
        }));
        let (ok_pre_h2, why_pre_h2) = eval_closure_default(
            "verified",
            "HIGH",
            &marker_xhigh,
            &checks_ev,
            &sub_ev,
            &ev_premature_h2,
            &[],
            None,
            None,
        );
        assert!(!ok_pre_h2);
        assert!(why_pre_h2.contains(cwg_common::NEON_XHIGH_MODEL), "got: {}", why_pre_h2);

        let mut s_lenses = HashMap::new();
        let mut s_lenses_end = HashMap::new();
        let mut sim_hist = Vec::new();
        for l in cwg_common::SIMPLIFY_LENSES {
            s_lenses.insert((*l).to_string(), t0 + 30.0);
            s_lenses_end.insert((*l).to_string(), t0 + 32.0);
            sim_hist.push(SimplifyHistoryItem {
                kind: "lens".to_string(),
                lens: Some((*l).to_string()),
                tier: cwg_common::SIMPLIFY_TIER_SONNET.to_string(),
                launch_ts: t0 + 20.0,
                end_ts: t0 + 22.0,
                seq: 1,
                clean: true,
                has_explicit_all: false,
                ..Default::default()
            });
            sim_hist.push(SimplifyHistoryItem {
                kind: "lens".to_string(),
                lens: Some((*l).to_string()),
                tier: cwg_common::SIMPLIFY_TIER_SONNET.to_string(),
                launch_ts: t0 + 30.0,
                end_ts: t0 + 32.0,
                seq: 2,
                clean: true,
                has_explicit_all: false,
                ..Default::default()
            });
        }
        let mut ev_post_blk = SwarmEvidence {
            sonnet_lenses: s_lenses,
            sonnet_lenses_end: s_lenses_end,
            simplify_history: sim_hist,
            opus_issue_verified: false,
            codex_cmd_failed: true,
            codex_issue_ts: t0 + 1.5,
            codex_issue_step: -1,
            ..SwarmEvidence::default()
        };
        for r_i in 0..3 {
            let lts = t0 + 5.0 + (r_i as f64) * 3.0;
            ev_post_blk.reviews.push(json!({
                "engine": cwg_common::REVIEW_ENGINE_INTERNAL_OPUS,
                "reviewer": "opus-rev", "kind": "ordinary",
                "verdict": "ESCALATE", "launch_ts": lts, "verdict_ts": lts + 1.0,
                "xhigh": false, "model": cwg_common::OPUS_HIGH_MODEL
            }));
        }
        ev_post_blk.reviews.push(json!({
            "engine": cwg_common::REVIEW_ENGINE_INTERNAL_OPUS,
            "reviewer": "opus-cls", "kind": "closure",
            "verdict": "BLOCKED", "launch_ts": t0 + 25.0, "verdict_ts": t0 + 26.0,
            "xhigh": false, "model": cwg_common::OPUS_HIGH_MODEL
        }));
        ev_post_blk.reviews.push(json!({
            "engine": cwg_common::REVIEW_ENGINE_INTERNAL_NEON,
            "reviewer": "neon-cls", "kind": "closure",
            "verdict": "READY", "launch_ts": t0 + 35.0, "verdict_ts": t0 + 36.0,
            "xhigh": false, "model": cwg_common::NEON_XHIGH_MODEL
        }));
        let (ok_post_blk, why_post_blk) = eval_closure_default(
            "verified",
            "HIGH",
            &marker_xhigh,
            &checks_ev,
            &sub_ev,
            &ev_post_blk,
            &[],
            None,
            None,
        );
        assert!(!ok_post_blk);
        assert!(
            why_post_blk.contains(cwg_common::OPUS_HIGH_MODEL)
                && !why_post_blk.contains("pass 1/2 returned"),
            "expected Opus priority error on ineligible pass-2 closure after pass-1 BLOCKED, got: {}",
            why_post_blk
        );
    }

    #[test]
    fn test_neon_inflight_switch_recovery_models_res_ts_and_error_dedup() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempEnvDir::new("neon-inflight-dedup");
        let brain = tmp.path.join("brain");
        let ws = tmp.path.join("repo");
        let t0 = rio::parse_iso_ts("2026-11-19T10:00:00Z");
        let (marker_3, checks_ev, sub_ev) =
            make_three_file_fixture(&ws, "sess-neon-r4-val", t0);

        let sess_inf = "sess-neon-r4-inflight";
        let tp_inf = setup_neon_session_env(
            &brain,
            sess_inf,
            "",
            json!({"members": {"rev-inflight": {"role": "worker", "model": cwg_common::NEON_XHIGH_MODEL, "killed": true}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:03Z", "text": "@rev-inflight audit HIGH"}),
                json!({"seq": 2, "agent": "rev-inflight", "time": "2026-11-19T10:00:11Z", "text": "REVIEW_TIER: HIGH\nVERDICT: APPROVED"}),
            ],
            &[],
        );
        let steps_inf = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "rev-inflight", "model": cwg_common::CARBON_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "rev-inflight", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:12Z", "content": "{}"}),
        ];
        let ev_inf = scan_swarm_activity(
            &steps_inf,
            Some(&tp_inf.to_string_lossy()),
            t0,
            0,
            sess_inf,
            &brain.to_string_lossy(),
        );
        assert!(
            !ev_inf.reviews.iter().any(|r| r.get("model").and_then(|v| v.as_str()).is_some_and(|m| !m.is_empty())),
            "verdict during in-flight Carbon->Neon switch [10..12] must fail closed, got: {:?}",
            ev_inf.reviews
        );

        let sess_rec = "sess-neon-r4-recover";
        let tp_rec = setup_neon_session_env(
            &brain,
            sess_rec,
            "",
            json!({"members": {"rev-recover": {"role": "worker", "model": cwg_common::CARBON_HIGH_MODEL, "killed": true}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:03Z", "text": "@rev-recover round 1"}),
                json!({"seq": 2, "agent": "rev-recover", "time": "2026-11-19T10:00:15Z", "text": "REVIEW_TIER: XHIGH\nVERDICT: APPROVED"}),
                json!({"seq": 3, "agent": "coordinator", "time": "2026-11-19T10:00:21Z", "text": "@rev-recover round 2"}),
                json!({"seq": 4, "agent": "rev-recover", "time": "2026-11-19T10:00:25Z", "text": "REVIEW_TIER: XHIGH\nVERDICT: APPROVED"}),
            ],
            &[],
        );
        let steps_rec = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "rev-recover", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "rev-recover", "model": cwg_common::CARBON_HIGH_MODEL}}]}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:18Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "rev-recover", "model": cwg_common::CARBON_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:20Z", "content": "{}"}),
        ];
        let ev_rec = scan_swarm_activity(
            &steps_rec,
            Some(&tp_rec.to_string_lossy()),
            t0,
            0,
            sess_rec,
            &brain.to_string_lossy(),
        );
        let rec_valid: Vec<_> = ev_rec
            .reviews
            .iter()
            .filter(|r| r.get("model").and_then(|v| v.as_str()).is_some_and(|m| !m.is_empty()))
            .collect();
        assert_eq!(rec_valid.len(), 1, "only post-recovery verdict should count, got: {:?}", ev_rec.reviews);
        assert_eq!(rec_valid[0].get("model").and_then(|v| v.as_str()), Some(cwg_common::CARBON_HIGH_MODEL));
        assert!(rec_valid[0].get("verdict_ts").and_then(|v| v.as_f64()).unwrap_or(0.0) >= t0 + 25.0 - 1.0);

        let sess_mod = "sess-neon-r4-models";
        let tp_mod = setup_neon_session_env(&brain, sess_mod, "", json!({"members": {}}), &[], &[]);
        let models_payload = json!({
            "models": [
                cwg_common::OPUS_HIGH_MODEL,
                cwg_common::SONNET_HIGH_MODEL,
                cwg_common::NEON_XHIGH_MODEL,
                cwg_common::HYDROGEN_XHIGH_MODEL,
                cwg_common::CARBON_HIGH_MODEL
            ],
            "quotas": {
                cwg_common::SONNET_HIGH_MODEL: {"quota_remaining": "0%"},
                cwg_common::NEON_XHIGH_MODEL: {"quota_remaining": "0%"},
                cwg_common::HYDROGEN_XHIGH_MODEL: {"quota_remaining": "100%"}
            }
        });
        let steps_mod = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10Z", "tool_calls": [{"name": "swarm", "args": {"action": "models", "all": true}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:12Z", "content": models_payload.to_string()}),
        ];
        let ev_mod = scan_swarm_activity(
            &steps_mod,
            Some(&tp_mod.to_string_lossy()),
            t0,
            0,
            sess_mod,
            &brain.to_string_lossy(),
        );
        assert!(ev_mod.sonnet_issue_verified && ev_mod.neon_issue_verified);
        assert!((ev_mod.sonnet_issue_ts - (t0 + 12.0)).abs() < TS_EPS, "got: {}", ev_mod.sonnet_issue_ts - t0);
        assert!((ev_mod.neon_issue_ts - (t0 + 12.0)).abs() < TS_EPS, "got: {}", ev_mod.neon_issue_ts - t0);

        let build_sec_ev = |lts: f64, ets: f64| -> SwarmEvidence {
            let mut sec_l = HashMap::new();
            let mut sec_e = HashMap::new();
            let mut sim_h = Vec::new();
            for l in cwg_common::SIMPLIFY_LENSES {
                sec_l.insert((*l).to_string(), lts);
                sec_e.insert((*l).to_string(), ets);
                sim_h.push(SimplifyHistoryItem {
                    kind: "lens".to_string(),
                    lens: Some((*l).to_string()),
                    tier: cwg_common::SIMPLIFY_TIER_SECONDARY_FALLBACK.to_string(),
                    launch_ts: lts,
                    end_ts: ets,
                    seq: 1,
                    clean: true,
                    has_explicit_all: false,
                    ..Default::default()
                });
            }
            SwarmEvidence {
                sonnet_issue_verified: ev_mod.sonnet_issue_verified,
                sonnet_issue_ts: ev_mod.sonnet_issue_ts,
                neon_issue_verified: ev_mod.neon_issue_verified,
                neon_issue_ts: ev_mod.neon_issue_ts,
                secondary_fallback_lenses: sec_l,
                secondary_fallback_lenses_end: sec_e,
                simplify_history: sim_h,
                ..SwarmEvidence::default()
            }
        };
        let codex_ok = vec![
            json!({"review_id": "cwg-r4-o1", "engine": "codex", "kind": "ordinary", "verdict": "APPROVED", "launch_ts": t0 + 5.0, "verdict_ts": t0 + 5.5, "xhigh": false}),
            json!({"review_id": "cwg-r4-c1", "engine": "codex", "kind": "closure", "verdict": "READY", "launch_ts": t0 + 15.0, "verdict_ts": t0 + 15.5, "xhigh": false}),
        ];
        let (ok_pre_h, why_pre_h) = eval_closure_default(
            "verified",
            "HIGH",
            &marker_3,
            &checks_ev,
            &sub_ev,
            &build_sec_ev(t0 + 11.0, t0 + 11.5),
            &codex_ok,
            None,
            None,
        );
        assert!(!ok_pre_h, "Hydrogen launched at 11.0 before models DONE at 12.0 must fail");
        assert!(why_pre_h.contains(cwg_common::NEON_XHIGH_MODEL), "got: {}", why_pre_h);
        let (ok_post_h, why_post_h) = eval_closure_default(
            "verified",
            "HIGH",
            &marker_3,
            &checks_ev,
            &sub_ev,
            &build_sec_ev(t0 + 12.5, t0 + 13.0),
            &codex_ok,
            None,
            None,
        );
        assert!(ok_post_h, "Hydrogen launched at 12.5 after models DONE at 12.0 should pass, got: {}", why_post_h);

        let sess_dedup = "sess-neon-r4-dedup";
        let wcid_dedup = "cid-r4-dedup";
        let w_steps = [
            json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
            json!({"step_index": 1, "source": "SYSTEM", "type": "ERROR_MESSAGE", "created_at": "2026-11-19T10:00:05.100Z", "content": "insufficient quota"}),
        ];
        let tp_dedup = setup_neon_session_env(
            &brain,
            sess_dedup,
            "",
            json!({"members": {"simplify-reuse": {"role": "worker", "conversation_id": wcid_dedup, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}}}),
            &[json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:03Z", "text": "@simplify-reuse check reuse"})],
            &[(wcid_dedup, &w_steps)],
        );
        let steps_dedup = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-reuse", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "SYSTEM", "type": "SYSTEM_MESSAGE", "created_at": "2026-11-19T10:00:05.400Z", "content": "[Message] timestamp=2026-11-19T10:00:05.400Z sender=system content=Swarm Worker (simplify-reuse) with id \"cid-r4-dedup\" encountered an error: insufficient quota"}),
        ];
        let ev_dedup = scan_swarm_activity(
            &steps_dedup,
            Some(&tp_dedup.to_string_lossy()),
            t0,
            0,
            sess_dedup,
            &brain.to_string_lossy(),
        );
        assert!(ev_dedup.sonnet_issue_verified);
        assert_eq!(ev_dedup.simplify_failures, 1, "single failed Sonnet turn across transcript and host SYSTEM must count once");
        let (ok_draft, _) = eval_closure_default(
            "draft-blocked",
            "HIGH",
            &marker_3,
            &checks_ev,
            &sub_ev,
            &ev_dedup,
            &[],
            None,
            None,
        );
        assert!(!ok_draft, "single simplify failure must not allow draft-blocked exhaustion");
    }

    #[test]
    fn test_neon_delayed_host_error_after_switch_and_three_tier_simplify_exhaustion() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempEnvDir::new("neon-closure-blockers");
        let ws = tmp.path.join("ws");
        let brain = tmp.path.join("brain");
        let t0 = rio::parse_iso_ts("2026-11-19T10:00:00Z");
        let (marker_3, checks_ev, sub_ev) = make_three_file_fixture(&ws, "sess-neon-blk", t0);

        let codex_ok = vec![
            json!({"review_id": "cwg-blk-o1", "engine": "codex", "kind": "ordinary", "verdict": "APPROVED", "launch_ts": t0 + 5.0, "verdict_ts": t0 + 5.5, "xhigh": false}),
            json!({"review_id": "cwg-blk-c1", "engine": "codex", "kind": "closure", "verdict": "READY", "launch_ts": t0 + 18.0, "verdict_ts": t0 + 18.5, "xhigh": false}),
        ];
        let build_sec_ev = |sonnet_ok: bool, sonnet_ts: f64, neon_ok: bool, neon_ts: f64| -> SwarmEvidence {
            let mut sec_l = HashMap::new();
            let mut sec_e = HashMap::new();
            let mut sim_h = Vec::new();
            for l in cwg_common::SIMPLIFY_LENSES {
                sec_l.insert((*l).to_string(), t0 + 13.0);
                sec_e.insert((*l).to_string(), t0 + 13.5);
                sim_h.push(SimplifyHistoryItem {
                    kind: "lens".to_string(),
                    lens: Some((*l).to_string()),
                    tier: cwg_common::SIMPLIFY_TIER_SECONDARY_FALLBACK.to_string(),
                    launch_ts: t0 + 13.0,
                    end_ts: t0 + 13.5,
                    seq: 1,
                    clean: true,
                    has_explicit_all: false,
                    ..Default::default()
                });
            }
            SwarmEvidence {
                sonnet_issue_verified: sonnet_ok,
                sonnet_issue_ts: sonnet_ts,
                neon_issue_verified: neon_ok,
                neon_issue_ts: neon_ts,
                secondary_fallback_lenses: sec_l,
                secondary_fallback_lenses_end: sec_e,
                simplify_history: sim_h,
                ..SwarmEvidence::default()
            }
        };

        let sess_emb = "sess-delay-emb";
        let cid_emb = "cid-delay-emb";
        let w_steps_no_err = [
            json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
        ];
        let tp_emb = setup_neon_session_env(
            &brain,
            sess_emb,
            "",
            json!({"members": {"simplify-reuse": {"role": "worker", "conversation_id": cid_emb, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}}}),
            &[json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:03Z", "text": "@simplify-reuse check reuse"})],
            &[(cid_emb, &w_steps_no_err)],
        );
        let steps_emb = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-reuse", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "simplify-reuse", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:12Z", "content": "{}"}),
            json!({"source": "SYSTEM", "type": "SYSTEM_MESSAGE", "created_at": "2026-11-19T10:00:12.400Z", "content": "[Message] timestamp=2026-11-19T10:00:05.100Z sender=system content=Swarm Worker (simplify-reuse) with id \"cid-delay-emb\" encountered an error: insufficient quota"}),
        ];
        let ev_emb = scan_swarm_activity(
            &steps_emb,
            Some(&tp_emb.to_string_lossy()),
            t0,
            0,
            sess_emb,
            &brain.to_string_lossy(),
        );
        assert!(ev_emb.sonnet_issue_verified);
        assert!((ev_emb.sonnet_issue_ts - (t0 + 5.1)).abs() < TS_EPS);
        assert!(!ev_emb.neon_issue_verified, "embedded pre-switch timestamp must attribute to Sonnet only");
        assert_eq!(ev_emb.simplify_failures, 1);
        let (ok_sec_emb, why_sec_emb) = eval_closure_default(
            "verified",
            "HIGH",
            &marker_3,
            &checks_ev,
            &sub_ev,
            &build_sec_ev(
                ev_emb.sonnet_issue_verified,
                ev_emb.sonnet_issue_ts,
                ev_emb.neon_issue_verified,
                ev_emb.neon_issue_ts,
            ),
            &codex_ok,
            None,
            None,
        );
        assert!(!ok_sec_emb, "Hydrogen simplify must be rejected when Neon is untainted: {}", why_sec_emb);

        let sess_deliv = "sess-delay-deliv";
        let cid_deliv = "cid-delay-deliv";
        let w_steps_sonnet_err = [
            json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
            json!({"step_index": 1, "source": "SYSTEM", "type": "ERROR_MESSAGE", "created_at": "2026-11-19T10:00:05.100Z", "content": "insufficient quota"}),
        ];
        let tp_deliv = setup_neon_session_env(
            &brain,
            sess_deliv,
            "",
            json!({"members": {"simplify-reuse": {"role": "worker", "conversation_id": cid_deliv, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}}}),
            &[json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:03Z", "text": "@simplify-reuse check reuse"})],
            &[(cid_deliv, &w_steps_sonnet_err)],
        );
        let steps_deliv = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-reuse", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "simplify-reuse", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:12Z", "content": "{}"}),
            json!({"source": "SYSTEM", "type": "SYSTEM_MESSAGE", "created_at": "2026-11-19T10:00:12.400Z", "content": "[Message] timestamp=2026-11-19T10:00:12.400Z sender=system content=Swarm Worker (simplify-reuse) with id \"cid-delay-deliv\" encountered an error: insufficient quota"}),
        ];
        let ev_deliv = scan_swarm_activity(
            &steps_deliv,
            Some(&tp_deliv.to_string_lossy()),
            t0,
            0,
            sess_deliv,
            &brain.to_string_lossy(),
        );
        assert!(ev_deliv.sonnet_issue_verified);
        assert!((ev_deliv.sonnet_issue_ts - (t0 + 5.1)).abs() < TS_EPS);
        assert!(!ev_deliv.neon_issue_verified, "post-switch host SYSTEM delivery timestamp must fail closed");
        assert_eq!(ev_deliv.simplify_failures, 1);
        let (ok_sec_deliv, why_sec_deliv) = eval_closure_default(
            "verified",
            "HIGH",
            &marker_3,
            &checks_ev,
            &sub_ev,
            &build_sec_ev(
                ev_deliv.sonnet_issue_verified,
                ev_deliv.sonnet_issue_ts,
                ev_deliv.neon_issue_verified,
                ev_deliv.neon_issue_ts,
            ),
            &codex_ok,
            None,
            None,
        );
        assert!(!ok_sec_deliv, "Hydrogen simplify must be rejected on post-switch delayed host error: {}", why_sec_deliv);

        let sess_fc = "sess-delay-fc";
        let cid_fc = "cid-delay-fc";
        let tp_fc = setup_neon_session_env(
            &brain,
            sess_fc,
            "",
            json!({"members": {"simplify-reuse": {"role": "worker", "conversation_id": cid_fc, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}}}),
            &[json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:03Z", "text": "@simplify-reuse check reuse"})],
            &[(cid_fc, &w_steps_no_err)],
        );
        let mut steps_fc = steps_deliv.clone();
        steps_fc[4] = json!({"source": "SYSTEM", "type": "SYSTEM_MESSAGE", "created_at": "2026-11-19T10:00:12.400Z", "content": "[Message] timestamp=2026-11-19T10:00:12.400Z sender=system content=Swarm Worker (simplify-reuse) with id \"cid-delay-fc\" encountered an error: insufficient quota"});
        let ev_fc = scan_swarm_activity(
            &steps_fc,
            Some(&tp_fc.to_string_lossy()),
            t0,
            0,
            sess_fc,
            &brain.to_string_lossy(),
        );
        assert!(!ev_fc.sonnet_issue_verified && !ev_fc.neon_issue_verified);
        assert_eq!(ev_fc.simplify_failures, 0);

        let sess_ex = "sess-three-tier";
        let cid_ex_s = "cid-ex-sonnet";
        let cid_ex_n = "cid-ex-neon";
        let cid_ex_h = "cid-ex-hydrogen";
        let tp_two = setup_neon_session_env(
            &brain,
            sess_ex,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_ex_s, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-quality": {"role": "worker", "conversation_id": cid_ex_n, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false},
                "simplify-efficiency": {"role": "worker", "conversation_id": cid_ex_h, "model": cwg_common::HYDROGEN_XHIGH_MODEL, "killed": false}
            }}),
            &[json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:03Z", "text": "@simplify-reuse @simplify-quality check"})],
            &[
                (cid_ex_s, &[json!({"step_index": 1, "source": "SYSTEM", "type": "ERROR_MESSAGE", "created_at": "2026-11-19T10:00:04Z", "content": "insufficient quota"})]),
                (cid_ex_n, &[json!({"step_index": 1, "source": "SYSTEM", "type": "ERROR_MESSAGE", "created_at": "2026-11-19T10:00:08Z", "content": "insufficient quota"})]),
                (cid_ex_h, &[json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:10Z"})]),
            ],
        );
        let steps_two = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [
                {"name": "swarm", "args": {"action": "add", "name": "simplify-reuse", "model": cwg_common::SONNET_HIGH_MODEL}},
                {"name": "swarm", "args": {"action": "add", "name": "simplify-quality", "model": cwg_common::NEON_XHIGH_MODEL}}
            ]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
        ];
        let ev_two = scan_swarm_activity(
            &steps_two,
            Some(&tp_two.to_string_lossy()),
            t0,
            0,
            sess_ex,
            &brain.to_string_lossy(),
        );
        assert!(ev_two.sonnet_issue_verified && ev_two.neon_issue_verified && !ev_two.hydrogen_issue_verified);
        assert_eq!(ev_two.simplify_failures, 2);
        let (ok_two_draft, why_two_draft) = eval_closure_default(
            "draft-blocked",
            "HIGH",
            &marker_3,
            &checks_ev,
            &sub_ev,
            &ev_two,
            &codex_ok[..1],
            None,
            None,
        );
        assert!(
            !ok_two_draft,
            "Sonnet+Neon failures must NOT permit draft-blocked while Hydrogen is healthy; got: {}",
            why_two_draft
        );

        write_jsonl_lines(
            &rio::member_transcript_path(&brain, cid_ex_h),
            &[json!({"step_index": 1, "source": "SYSTEM", "type": "ERROR_MESSAGE", "created_at": "2026-11-19T10:00:12Z", "content": "insufficient quota"})],
        );
        let mut steps_three = steps_two;
        steps_three.push(json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-efficiency", "model": cwg_common::HYDROGEN_XHIGH_MODEL}}]}));
        steps_three.push(json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:10Z", "content": "{}"}));
        let ev_three = scan_swarm_activity(
            &steps_three,
            Some(&tp_two.to_string_lossy()),
            t0,
            0,
            sess_ex,
            &brain.to_string_lossy(),
        );
        assert!(ev_three.sonnet_issue_verified && ev_three.neon_issue_verified && ev_three.hydrogen_issue_verified);
        assert_eq!(ev_three.simplify_failures, 3);
        let (ok_three_draft, why_three_draft) = eval_closure_default(
            "draft-blocked",
            "HIGH",
            &marker_3,
            &checks_ev,
            &sub_ev,
            &ev_three,
            &[],
            None,
            None,
        );
        assert!(ok_three_draft, "all 3 simplify tiers failed should permit draft-blocked, got: {}", why_three_draft);

        let models_zero = json!({
            "models": [cwg_common::SONNET_HIGH_MODEL, cwg_common::NEON_XHIGH_MODEL, cwg_common::HYDROGEN_XHIGH_MODEL],
            "quotas": {
                cwg_common::SONNET_HIGH_MODEL: {"quota_remaining": "0%"},
                cwg_common::NEON_XHIGH_MODEL: {"quota_remaining": "0%"},
                cwg_common::HYDROGEN_XHIGH_MODEL: {"quota_remaining": "0%"}
            }
        });
        let steps_zero = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "models", "all": true}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:03Z", "content": models_zero.to_string()}),
        ];
        let mut ev_zero = scan_swarm_activity(&steps_zero, None, t0, 0, "", "");
        assert!(ev_zero.sonnet_issue_verified && ev_zero.neon_issue_verified && ev_zero.hydrogen_issue_verified);
        let (ok_zero_draft, why_zero_draft) = eval_closure_default(
            "draft-blocked",
            "HIGH",
            &marker_3,
            &checks_ev,
            &sub_ev,
            &ev_zero,
            &[],
            None,
            None,
        );
        assert!(ok_zero_draft, "0% quota across all 3 simplify tiers should permit draft-blocked, got: {}", why_zero_draft);

        let mut sticky = Map::new();
        merge_sticky_outage_state(&mut sticky, &mut ev_zero);
        assert_eq!(sticky.get("hydrogen_issue_verified"), Some(&Value::Bool(true)));
        assert!((val_to_f64(sticky.get("hydrogen_issue_ts")) - (t0 + 3.0)).abs() < TS_EPS);
        reset_sticky_issue_state(&mut sticky);
        assert_eq!(sticky.get("hydrogen_issue_verified"), Some(&Value::Bool(false)));
        assert_eq!(val_to_f64(sticky.get("hydrogen_issue_ts")), 0.0);
    }

    #[test]
    fn test_neon_simplify_quota_recovery_blocks_draft_blocked_and_post_recovery_failure_reallows() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempEnvDir::new("neon-liveness");
        let ws = tmp.path.join("ws");
        let brain = tmp.path.join("brain");
        let t0 = rio::parse_iso_ts("2026-11-19T10:00:00Z");
        let (marker_3, checks_ev, sub_ev) = make_three_file_fixture(&ws, "sess-neon-live", t0);

        let models_all_zero = json!({
            "models": [cwg_common::SONNET_HIGH_MODEL, cwg_common::NEON_XHIGH_MODEL, cwg_common::HYDROGEN_XHIGH_MODEL],
            "quotas": {
                cwg_common::SONNET_HIGH_MODEL: {"quota_remaining": "0%"},
                cwg_common::NEON_XHIGH_MODEL: {"quota_remaining": "0%"},
                cwg_common::HYDROGEN_XHIGH_MODEL: {"quota_remaining": "0%"}
            }
        });
        let models_hydrogen_rec = json!({
            "models": [cwg_common::SONNET_HIGH_MODEL, cwg_common::NEON_XHIGH_MODEL, cwg_common::HYDROGEN_XHIGH_MODEL],
            "quotas": {
                cwg_common::SONNET_HIGH_MODEL: {"quota_remaining": "0%"},
                cwg_common::NEON_XHIGH_MODEL: {"quota_remaining": "0%"},
                cwg_common::HYDROGEN_XHIGH_MODEL: {"quota_remaining": "50%"}
            }
        });

        let steps_0 = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "models", "all": true}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:03Z", "content": models_all_zero.to_string()}),
        ];
        let ev_0 = scan_swarm_activity(&steps_0, None, t0, 0, "", "");
        assert!(ev_0.sonnet_issue_verified && ev_0.neon_issue_verified && ev_0.hydrogen_issue_verified);
        let (ok_0, why_0) = eval_closure_default("draft-blocked", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_0, &[], None, None);
        assert!(ok_0, "all 3 at 0% should permit draft-blocked, got: {}", why_0);

        let mut steps_rec = steps_0.clone();
        steps_rec.push(json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:09Z", "tool_calls": [{"name": "swarm", "args": {"action": "models", "all": true}}]}));
        steps_rec.push(json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:10Z", "content": models_hydrogen_rec.to_string()}));
        let ev_rec = scan_swarm_activity(&steps_rec, None, t0, 0, "", "");
        assert!(ev_rec.sonnet_issue_verified && ev_rec.neon_issue_verified && ev_rec.hydrogen_issue_verified);
        assert!((ev_rec.hydrogen_healthy_ts - (t0 + 10.0)).abs() < TS_EPS);
        let (ok_rec_draft, why_rec_draft) = eval_closure_default("draft-blocked", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_rec, &[], None, None);
        assert!(!ok_rec_draft, "Hydrogen quota recovery at t0+10 must reject draft-blocked: {}", why_rec_draft);

        let mut sec_l = HashMap::new();
        let mut sec_e = HashMap::new();
        let mut sim_h = Vec::new();
        for l in cwg_common::SIMPLIFY_LENSES {
            sec_l.insert((*l).to_string(), t0 + 12.0);
            sec_e.insert((*l).to_string(), t0 + 12.5);
            sim_h.push(SimplifyHistoryItem {
                kind: "lens".to_string(),
                lens: Some((*l).to_string()),
                tier: cwg_common::SIMPLIFY_TIER_SECONDARY_FALLBACK.to_string(),
                launch_ts: t0 + 12.0,
                end_ts: t0 + 12.5,
                seq: 1,
                clean: true,
                has_explicit_all: false,
                ..Default::default()
            });
        }
        let mut ev_rec_sim = ev_rec.clone();
        ev_rec_sim.secondary_fallback_lenses = sec_l;
        ev_rec_sim.secondary_fallback_lenses_end = sec_e;
        ev_rec_sim.simplify_history = sim_h;
        let codex_ok = vec![
            json!({"review_id": "cwg-live-o1", "engine": "codex", "kind": "ordinary", "verdict": "APPROVED", "launch_ts": t0 + 5.0, "verdict_ts": t0 + 5.5, "xhigh": false}),
            json!({"review_id": "cwg-live-c1", "engine": "codex", "kind": "closure", "verdict": "READY", "launch_ts": t0 + 15.0, "verdict_ts": t0 + 15.5, "xhigh": false}),
        ];
        let (ok_ver, why_ver) = eval_closure_default("verified", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_rec_sim, &codex_ok, None, None);
        assert!(ok_ver, "Hydrogen simplify after recovery must stay causally valid, got: {}", why_ver);

        let sess_fail = "sess-live-postfail";
        let cid_h = "cid-live-h";
        let tp_fail = setup_neon_session_env(
            &brain,
            sess_fail,
            "",
            json!({"members": {"simplify-efficiency": {"role": "worker", "conversation_id": cid_h, "model": cwg_common::HYDROGEN_XHIGH_MODEL, "killed": false}}}),
            &[],
            &[(cid_h, &[json!({"step_index": 1, "source": "SYSTEM", "type": "ERROR_MESSAGE", "created_at": "2026-11-19T10:00:14Z", "content": "insufficient quota"})])],
        );
        let mut steps_postfail = steps_rec.clone();
        steps_postfail.push(json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:12Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-efficiency", "model": cwg_common::HYDROGEN_XHIGH_MODEL}}]}));
        steps_postfail.push(json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:12Z", "content": "{}"}));
        let ev_postfail = scan_swarm_activity(&steps_postfail, Some(&tp_fail.to_string_lossy()), t0, 0, sess_fail, &brain.to_string_lossy());
        assert!(ev_postfail.hydrogen_last_issue_ts >= t0 + 14.0 - TS_EPS);
        assert!(ev_postfail.hydrogen_last_issue_ts > ev_postfail.hydrogen_healthy_ts);
        let (ok_postfail, why_postfail) = eval_closure_default("draft-blocked", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_postfail, &[], None, None);
        assert!(ok_postfail, "post-recovery Hydrogen failure should re-allow draft-blocked, got: {}", why_postfail);

        let models_sonnet_rec = json!({
            "models": [cwg_common::SONNET_HIGH_MODEL, cwg_common::NEON_XHIGH_MODEL, cwg_common::HYDROGEN_XHIGH_MODEL],
            "quotas": {
                cwg_common::SONNET_HIGH_MODEL: {"quota_remaining": "20%"},
                cwg_common::NEON_XHIGH_MODEL: {"quota_remaining": "0%"},
                cwg_common::HYDROGEN_XHIGH_MODEL: {"quota_remaining": "0%"}
            }
        });
        let mut steps_s_rec = steps_0;
        steps_s_rec.push(json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:09Z", "tool_calls": [{"name": "swarm", "args": {"action": "models", "all": true}}]}));
        steps_s_rec.push(json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:10Z", "content": models_sonnet_rec.to_string()}));
        let ev_s_rec = scan_swarm_activity(&steps_s_rec, None, t0, 0, "", "");
        assert!((ev_s_rec.sonnet_healthy_ts - (t0 + 10.0)).abs() < TS_EPS);
        let (ok_s_rec, _) = eval_closure_default("draft-blocked", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_s_rec, &[], None, None);
        assert!(!ok_s_rec, "Sonnet quota recovery must reject draft-blocked");

        let mut sticky = Map::new();
        let mut ev_rec_mut = ev_rec.clone();
        merge_sticky_outage_state(&mut sticky, &mut ev_rec_mut);
        assert!((val_to_f64(sticky.get("hydrogen_last_issue_ts")) - (t0 + 3.0)).abs() < TS_EPS);
        assert!((val_to_f64(sticky.get("hydrogen_healthy_ts")) - (t0 + 10.0)).abs() < TS_EPS);
        let mut ev_empty_window = SwarmEvidence::default();
        merge_sticky_outage_state(&mut sticky, &mut ev_empty_window);
        let (ok_evicted_rec, _) = eval_closure_default("draft-blocked", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_empty_window, &[], None, None);
        assert!(!ok_evicted_rec, "sticky merge across eviction must preserve post-recovery rejection");
        reset_sticky_issue_state(&mut sticky);
        assert_eq!(val_to_f64(sticky.get("hydrogen_last_issue_ts")), 0.0);
        assert_eq!(val_to_f64(sticky.get("hydrogen_healthy_ts")), 0.0);
    }

    #[test]
    fn test_neon_untimestamped_error_unconfirmed_models_and_same_worker_repeat_failure() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempEnvDir::new("neon-r2-findings");
        let ws = tmp.path.join("ws");
        let brain = tmp.path.join("brain");
        let t0 = rio::parse_iso_ts("2026-11-19T10:00:00Z");
        let (marker_3, checks_ev, sub_ev) = make_three_file_fixture(&ws, "sess-neon-f123", t0);

        let models_all_zero = json!({
            "models": [cwg_common::SONNET_HIGH_MODEL, cwg_common::NEON_XHIGH_MODEL, cwg_common::HYDROGEN_XHIGH_MODEL],
            "quotas": {
                cwg_common::SONNET_HIGH_MODEL: {"quota_remaining": "0%"},
                cwg_common::NEON_XHIGH_MODEL: {"quota_remaining": "0%"},
                cwg_common::HYDROGEN_XHIGH_MODEL: {"quota_remaining": "0%"}
            }
        });
        let models_hydrogen_rec = json!({
            "models": [cwg_common::SONNET_HIGH_MODEL, cwg_common::NEON_XHIGH_MODEL, cwg_common::HYDROGEN_XHIGH_MODEL],
            "quotas": {
                cwg_common::SONNET_HIGH_MODEL: {"quota_remaining": "0%"},
                cwg_common::NEON_XHIGH_MODEL: {"quota_remaining": "0%"},
                cwg_common::HYDROGEN_XHIGH_MODEL: {"quota_remaining": "50%"}
            }
        });

        let sess_u1 = "sess-f1-worker";
        let cid_u1 = "cid-f1-h";
        let tp_u1 = setup_neon_session_env(
            &brain,
            sess_u1,
            "",
            json!({"members": {"simplify-efficiency": {"role": "worker", "conversation_id": cid_u1, "model": cwg_common::HYDROGEN_XHIGH_MODEL, "killed": false}}}),
            &[],
            &[(cid_u1, &[json!({"step_index": 1, "source": "SYSTEM", "type": "ERROR_MESSAGE", "content": "insufficient quota"})])],
        );
        let steps_u1_only = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:09Z", "tool_calls": [{"name": "swarm", "args": {"action": "models", "all": true}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:10Z", "content": models_hydrogen_rec.to_string()}),
        ];
        let ev_u1_only = scan_swarm_activity(&steps_u1_only, Some(&tp_u1.to_string_lossy()), t0, 0, sess_u1, &brain.to_string_lossy());
        assert!(ev_u1_only.hydrogen_issue_verified);
        assert_eq!(ev_u1_only.hydrogen_last_issue_ts, 0.0, "un-timestamped worker error must keep hydrogen_last_issue_ts=0.0");
        let (ok_u1_only, _) = eval_closure_default("draft-blocked", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_u1_only, &[], None, None);
        assert!(!ok_u1_only, "un-timestamped worker error must not cancel confirmed Hydrogen recovery");

        let steps_u1_both = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "models", "all": true}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:03Z", "content": models_all_zero.to_string()}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:09Z", "tool_calls": [{"name": "swarm", "args": {"action": "models", "all": true}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:10Z", "content": models_hydrogen_rec.to_string()}),
        ];
        let ev_u1_both = scan_swarm_activity(&steps_u1_both, Some(&tp_u1.to_string_lossy()), t0, 0, sess_u1, &brain.to_string_lossy());
        assert!(ev_u1_both.hydrogen_last_issue_ts <= t0 + 3.0 + TS_EPS);
        let (ok_u1_both, _) = eval_closure_default("draft-blocked", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_u1_both, &[], None, None);
        assert!(!ok_u1_both);

        let sess_u2 = "sess-f1-sys";
        let cid_u2 = "cid-f1-sys-h";
        let tp_u2 = setup_neon_session_env(
            &brain,
            sess_u2,
            "",
            json!({"members": {"simplify-efficiency": {"role": "worker", "conversation_id": cid_u2, "model": cwg_common::HYDROGEN_XHIGH_MODEL, "killed": false}}}),
            &[],
            &[(cid_u2, &[])],
        );
        let mut steps_u2 = steps_u1_only;
        steps_u2.push(json!({"source": "SYSTEM", "type": "SYSTEM_MESSAGE", "content": "[Message] timestamp=unknown sender=system content=Swarm Worker (simplify-efficiency) with id \"cid-f1-sys-h\" encountered an error: insufficient quota"}));
        let ev_u2 = scan_swarm_activity(&steps_u2, Some(&tp_u2.to_string_lossy()), t0, 0, sess_u2, &brain.to_string_lossy());
        assert!(ev_u2.hydrogen_issue_verified);
        assert_eq!(ev_u2.hydrogen_last_issue_ts, 0.0);
        let (ok_u2, _) = eval_closure_default("draft-blocked", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_u2, &[], None, None);
        assert!(!ok_u2, "un-timestamped host SYSTEM error must not cancel confirmed Hydrogen recovery");

        let steps_err_mod = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "models", "all": true}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "ERROR", "created_at": "2026-11-19T10:00:03Z", "content": json!({"error": "partial", "models": [cwg_common::CARBON_HIGH_MODEL]}).to_string()}),
        ];
        let ev_err_mod = scan_swarm_activity(&steps_err_mod, None, t0, 0, "", "");
        assert!(!ev_err_mod.sonnet_issue_verified && !ev_err_mod.neon_issue_verified && !ev_err_mod.hydrogen_issue_verified && !ev_err_mod.opus_issue_verified);
        let (ok_err_mod, _) = eval_closure_default("draft-blocked", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_err_mod, &[], None, None);
        assert!(!ok_err_mod);

        let models_no_quotas = json!({
            "models": [cwg_common::SONNET_HIGH_MODEL, cwg_common::NEON_XHIGH_MODEL, cwg_common::HYDROGEN_XHIGH_MODEL]
        });
        let steps_no_q = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "models", "all": true}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:03Z", "content": models_all_zero.to_string()}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:09Z", "tool_calls": [{"name": "swarm", "args": {"action": "models", "all": true}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:10Z", "content": models_no_quotas.to_string()}),
        ];
        let ev_no_q = scan_swarm_activity(&steps_no_q, None, t0, 0, "", "");
        assert_eq!(ev_no_q.hydrogen_healthy_ts, 0.0, "models list without quotas must not set healthy_ts");
        let (ok_no_q, why_no_q) = eval_closure_default("draft-blocked", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_no_q, &[], None, None);
        assert!(ok_no_q, "models list without quotas must not clear prior 0% exhaustion: {}", why_no_q);

        let sess_rep = "sess-f3-repeat";
        let cid_rep = "cid-f3-h";
        let tp_rep = setup_neon_session_env(
            &brain,
            sess_rep,
            "",
            json!({"members": {"simplify-efficiency": {"role": "worker", "conversation_id": cid_rep, "model": cwg_common::HYDROGEN_XHIGH_MODEL, "killed": false}}}),
            &[],
            &[(cid_rep, &[
                json!({"step_index": 1, "source": "SYSTEM", "type": "ERROR_MESSAGE", "created_at": "2026-11-19T10:00:04Z", "content": "insufficient quota"}),
                json!({"step_index": 2, "source": "SYSTEM", "type": "ERROR_MESSAGE", "created_at": "2026-11-19T10:00:14Z", "content": "insufficient quota"}),
            ])],
        );
        let steps_rep_inwin = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:09Z", "tool_calls": [{"name": "swarm", "args": {"action": "models", "all": true}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:10Z", "content": models_hydrogen_rec.to_string()}),
        ];
        let ev_rep_inwin = scan_swarm_activity(&steps_rep_inwin, Some(&tp_rep.to_string_lossy()), t0, 0, sess_rep, &brain.to_string_lossy());
        assert!((ev_rep_inwin.hydrogen_healthy_ts - (t0 + 10.0)).abs() < TS_EPS);
        assert!((ev_rep_inwin.hydrogen_last_issue_ts - (t0 + 14.0)).abs() < TS_EPS);
        let (ok_rep_inwin, why_rep_inwin) = eval_closure_default("draft-blocked", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_rep_inwin, &[], None, None);
        assert!(ok_rep_inwin, "repeat post-recovery failure at t0+14 must re-open exhaustion: {}", why_rep_inwin);

        let mut sticky_evict = Map::new();
        sticky_evict.insert("sonnet_issue_verified".to_string(), Value::Bool(true));
        sticky_evict.insert("neon_issue_verified".to_string(), Value::Bool(true));
        sticky_evict.insert("hydrogen_healthy_ts".to_string(), json!(t0 + 10.0));
        let mut ev_rep_evicted = scan_swarm_activity(&[], Some(&tp_rep.to_string_lossy()), t0, 0, sess_rep, &brain.to_string_lossy());
        assert!((ev_rep_evicted.hydrogen_last_issue_ts - (t0 + 14.0)).abs() < TS_EPS);
        merge_sticky_outage_state(&mut sticky_evict, &mut ev_rep_evicted);
        let (ok_rep_evicted, why_rep_evicted) = eval_closure_default("draft-blocked", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_rep_evicted, &[], None, None);
        assert!(ok_rep_evicted, "slot_errs max_ts must preserve t0+14 failure even after models recovery evicted: {}", why_rep_evicted);
    }

    #[test]
    fn test_neon_delayed_host_echo_across_models_recovery_does_not_cancel_recovery() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempEnvDir::new("neon-echo-rec");
        let ws = tmp.path.join("ws");
        let brain = tmp.path.join("brain");
        let t0 = rio::parse_iso_ts("2026-11-19T10:00:00Z");
        let (marker_3, checks_ev, sub_ev) = make_three_file_fixture(&ws, "sess-neon-echo", t0);

        let models_hydrogen_rec = json!({
            "models": [cwg_common::SONNET_HIGH_MODEL, cwg_common::NEON_XHIGH_MODEL, cwg_common::HYDROGEN_XHIGH_MODEL],
            "quotas": {
                cwg_common::SONNET_HIGH_MODEL: {"quota_remaining": "0%"},
                cwg_common::NEON_XHIGH_MODEL: {"quota_remaining": "0%"},
                cwg_common::HYDROGEN_XHIGH_MODEL: {"quota_remaining": "50%"}
            }
        });

        let sess_a = "sess-echo-a";
        let cid_a = "cid-echo-a";
        let tp_a = setup_neon_session_env(
            &brain,
            sess_a,
            "",
            json!({"members": {"simplify-efficiency": {"role": "worker", "conversation_id": cid_a, "model": cwg_common::HYDROGEN_XHIGH_MODEL, "killed": false}}}),
            &[],
            &[(cid_a, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "SYSTEM", "type": "ERROR_MESSAGE", "created_at": "2026-11-19T10:00:05.100Z", "content": "insufficient quota"}),
            ])],
        );
        let steps_a = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-efficiency", "model": cwg_common::HYDROGEN_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:05.150Z", "tool_calls": [{"name": "swarm", "args": {"action": "models", "all": true}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:05.200Z", "content": models_hydrogen_rec.to_string()}),
            json!({"source": "SYSTEM", "type": "SYSTEM_MESSAGE", "created_at": "2026-11-19T10:00:05.400Z", "content": "[Message] timestamp=2026-11-19T10:00:05.400Z sender=system content=Swarm Worker (simplify-efficiency) with id \"cid-echo-a\" encountered an error: insufficient quota"}),
        ];
        let ev_a = scan_swarm_activity(&steps_a, Some(&tp_a.to_string_lossy()), t0, 0, sess_a, &brain.to_string_lossy());
        assert!(ev_a.hydrogen_issue_verified);
        assert_eq!(ev_a.simplify_failures, 1);
        assert!((ev_a.hydrogen_last_issue_ts - (t0 + 5.1)).abs() < TS_EPS);
        assert!((ev_a.hydrogen_healthy_ts - (t0 + 5.2)).abs() < TS_EPS);
        let (ok_a, why_a) = eval_closure_default("draft-blocked", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_a, &[], None, None);
        assert!(!ok_a, "delayed host SYSTEM echo at t0+5.400 must NOT override t0+5.200 recovery: {}", why_a);

        let sess_b = "sess-echo-b";
        let cid_b = "cid-echo-b";
        let tp_b = setup_neon_session_env(
            &brain,
            sess_b,
            "",
            json!({"members": {"simplify-efficiency": {"role": "worker", "conversation_id": cid_b, "model": cwg_common::HYDROGEN_XHIGH_MODEL, "killed": false}}}),
            &[],
            &[(cid_b, &[])],
        );
        let mut steps_b = steps_a.clone();
        steps_b[4] = json!({"source": "SYSTEM", "type": "SYSTEM_MESSAGE", "created_at": "2026-11-19T10:00:05.400Z", "content": "[Message] timestamp=2026-11-19T10:00:05.400Z sender=system content=Swarm Worker (simplify-efficiency) with id \"cid-echo-b\" encountered an error: insufficient quota"});
        let ev_b = scan_swarm_activity(&steps_b, Some(&tp_b.to_string_lossy()), t0, 0, sess_b, &brain.to_string_lossy());
        assert!(ev_b.hydrogen_issue_verified);
        assert_eq!(ev_b.hydrogen_last_issue_ts, 0.0, "host-only echo must leave last_issue_ts=0.0");
        assert!(ev_b.hydrogen_last_issue_ts < ev_b.hydrogen_healthy_ts);
        let (ok_b, why_b) = eval_closure_default("draft-blocked", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_b, &[], None, None);
        assert!(!ok_b, "host-only delayed echo must not cancel confirmed recovery: {}", why_b);

        let sess_c1 = "sess-echo-c1";
        let cid_c1 = "cid-echo-c1";
        let tp_c1 = setup_neon_session_env(
            &brain,
            sess_c1,
            "",
            json!({"members": {"simplify-efficiency": {"role": "worker", "conversation_id": cid_c1, "model": cwg_common::HYDROGEN_XHIGH_MODEL, "killed": false}}}),
            &[json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:06Z", "text": "@all status"})],
            &[(cid_c1, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "SYSTEM", "type": "ERROR_MESSAGE", "created_at": "2026-11-19T10:00:05.100Z", "content": "insufficient quota"}),
            ])],
        );
        let mut steps_c1 = steps_a.clone();
        steps_c1[4] = json!({"source": "SYSTEM", "type": "SYSTEM_MESSAGE", "created_at": "2026-11-19T10:00:07Z", "content": "[Message] timestamp=2026-11-19T10:00:07Z sender=system content=Swarm Worker (simplify-efficiency) with id \"cid-echo-c1\" encountered an error: insufficient quota"});
        let ev_c1 = scan_swarm_activity(&steps_c1, Some(&tp_c1.to_string_lossy()), t0, 0, sess_c1, &brain.to_string_lossy());
        assert_eq!(ev_c1.simplify_failures, 1);
        assert!((ev_c1.hydrogen_last_issue_ts - (t0 + 5.1)).abs() < TS_EPS, "got: {}", ev_c1.hydrogen_last_issue_ts - t0);
        assert!(ev_c1.hydrogen_last_issue_ts < ev_c1.hydrogen_healthy_ts);
        let (ok_c1, why_c1) = eval_closure_default("draft-blocked", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_c1, &[], None, None);
        assert!(!ok_c1, "@all post + delayed host SYSTEM must not override recovery (with transcript error): {}", why_c1);

        let sess_c2 = "sess-echo-c2";
        let cid_c2 = "cid-echo-c2";
        let tp_c2 = setup_neon_session_env(
            &brain,
            sess_c2,
            "",
            json!({"members": {"simplify-efficiency": {"role": "worker", "conversation_id": cid_c2, "model": cwg_common::HYDROGEN_XHIGH_MODEL, "killed": false}}}),
            &[json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:06Z", "text": "@all status"})],
            &[(cid_c2, &[])],
        );
        let mut steps_c2 = steps_a.clone();
        steps_c2[4] = json!({"source": "SYSTEM", "type": "SYSTEM_MESSAGE", "created_at": "2026-11-19T10:00:07Z", "content": "[Message] timestamp=2026-11-19T10:00:07Z sender=system content=Swarm Worker (simplify-efficiency) with id \"cid-echo-c2\" encountered an error: insufficient quota"});
        let ev_c2 = scan_swarm_activity(&steps_c2, Some(&tp_c2.to_string_lossy()), t0, 0, sess_c2, &brain.to_string_lossy());
        assert_eq!(ev_c2.hydrogen_last_issue_ts, 0.0, "empty transcript + host-only post-@all SYSTEM must keep last_issue_ts=0.0");
        let (ok_c2, why_c2) = eval_closure_default("draft-blocked", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_c2, &[], None, None);
        assert!(!ok_c2, "@all post + delayed host SYSTEM must not override recovery (empty transcript): {}", why_c2);

        let sess_d = "sess-echo-d";
        let cid_d = "cid-echo-d";
        let tp_d = setup_neon_session_env(
            &brain,
            sess_d,
            "",
            json!({"members": {"simplify-efficiency": {"role": "worker", "conversation_id": cid_d, "model": cwg_common::HYDROGEN_XHIGH_MODEL, "killed": false}}}),
            &[json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:06Z", "text": "@simplify-efficiency retry lens"})],
            &[(cid_d, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "SYSTEM", "type": "ERROR_MESSAGE", "created_at": "2026-11-19T10:00:07Z", "content": "insufficient quota"}),
            ])],
        );
        let mut steps_d = steps_a;
        steps_d[4] = json!({"source": "SYSTEM", "type": "SYSTEM_MESSAGE", "created_at": "2026-11-19T10:00:07.200Z", "content": "[Message] timestamp=2026-11-19T10:00:07.200Z sender=system content=Swarm Worker (simplify-efficiency) with id \"cid-echo-d\" encountered an error: insufficient quota"});
        let ev_d = scan_swarm_activity(&steps_d, Some(&tp_d.to_string_lossy()), t0, 0, sess_d, &brain.to_string_lossy());
        assert!((ev_d.hydrogen_last_issue_ts - (t0 + 7.0)).abs() < TS_EPS, "got: {}", ev_d.hydrogen_last_issue_ts - t0);
        assert!(ev_d.hydrogen_last_issue_ts > ev_d.hydrogen_healthy_ts);
        let (ok_d, why_d) = eval_closure_default("draft-blocked", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_d, &[], None, None);
        assert!(ok_d, "genuine post-recovery failure with authoritative transcript ERROR_MESSAGE must re-open exhaustion: {}", why_d);

        let sess_e1 = "sess-echo-e1";
        let cid_e1 = "cid-echo-e1";
        let tp_e1 = setup_neon_session_env(
            &brain,
            sess_e1,
            "",
            json!({"members": {"reviewer-opus": {"role": "worker", "conversation_id": cid_e1, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}}}),
            &[json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:06Z", "text": "@all status"})],
            &[(cid_e1, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "SYSTEM", "type": "ERROR_MESSAGE", "created_at": "2026-11-19T10:00:05.100Z", "content": "insufficient quota"}),
            ])],
        );
        let steps_e1 = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "reviewer-opus", "model": cwg_common::OPUS_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "SYSTEM", "type": "SYSTEM_MESSAGE", "created_at": "2026-11-19T10:00:07Z", "content": "[Message] timestamp=2026-11-19T10:00:07Z sender=system content=Swarm Worker (reviewer-opus) with id \"cid-echo-e1\" encountered an error: insufficient quota"}),
        ];
        let mut ev_e1 = scan_swarm_activity(&steps_e1, Some(&tp_e1.to_string_lossy()), t0, 0, sess_e1, &brain.to_string_lossy());
        assert!(ev_e1.opus_issue_verified);
        assert_eq!(ev_e1.review_failures.len(), 1, "delayed @all host echo must not duplicate Opus review_failures");
        for l in cwg_common::SIMPLIFY_LENSES {
            ev_e1.sonnet_lenses.insert((*l).to_string(), t0 + 8.0);
            ev_e1.sonnet_lenses_end.insert((*l).to_string(), t0 + 8.5);
        }
        let (ok_e1, why_e1) = eval_closure_default("draft-blocked", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_e1, &[], None, None);
        assert!(!ok_e1, "single Opus failure + delayed @all host echo must not trigger review_unavailable: {}", why_e1);

        let sess_e2 = "sess-echo-e2";
        let cid_e2 = "cid-echo-e2";
        let tp_e2 = setup_neon_session_env(
            &brain,
            sess_e2,
            "",
            json!({"members": {"reviewer-opus": {"role": "worker", "conversation_id": cid_e2, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}}}),
            &[json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:06Z", "text": "@all status"})],
            &[(cid_e2, &[])],
        );
        let steps_e2 = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "reviewer-opus", "model": cwg_common::OPUS_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "SYSTEM", "type": "SYSTEM_MESSAGE", "created_at": "2026-11-19T10:00:05.100Z", "content": "[Message] timestamp=2026-11-19T10:00:05.100Z sender=system content=Swarm Worker (reviewer-opus) with id \"cid-echo-e2\" encountered an error: insufficient quota"}),
            json!({"source": "SYSTEM", "type": "SYSTEM_MESSAGE", "created_at": "2026-11-19T10:00:07Z", "content": "[Message] timestamp=2026-11-19T10:00:07Z sender=system content=Swarm Worker (reviewer-opus) with id \"cid-echo-e2\" encountered an error: insufficient quota"}),
        ];
        let mut ev_e2 = scan_swarm_activity(&steps_e2, Some(&tp_e2.to_string_lossy()), t0, 0, sess_e2, &brain.to_string_lossy());
        assert!(ev_e2.opus_issue_verified);
        assert_eq!(ev_e2.review_failures.len(), 1, "host-only Opus notices across @all must collapse to 1 attempt");
        for l in cwg_common::SIMPLIFY_LENSES {
            ev_e2.sonnet_lenses.insert((*l).to_string(), t0 + 8.0);
            ev_e2.sonnet_lenses_end.insert((*l).to_string(), t0 + 8.5);
        }
        let (ok_e2, why_e2) = eval_closure_default("draft-blocked", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_e2, &[], None, None);
        assert!(!ok_e2, "host-only Opus notices collapsed to 1 attempt must not trigger review_unavailable: {}", why_e2);

        let sess_f1 = "sess-echo-f1";
        let cid_f1 = "cid-echo-f1";
        let tp_f1 = setup_neon_session_env(
            &brain,
            sess_f1,
            "",
            json!({"members": {"simplify-efficiency": {"role": "worker", "conversation_id": cid_f1, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}}}),
            &[],
            &[(cid_f1, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "SYSTEM", "type": "ERROR_MESSAGE", "created_at": "2026-11-19T10:00:15Z", "content": "insufficient quota"}),
            ])],
        );
        let steps_f1 = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-efficiency", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "SYSTEM", "type": "SYSTEM_MESSAGE", "created_at": "2026-11-19T10:00:05.100Z", "content": "[Message] timestamp=2026-11-19T10:00:05.100Z sender=system content=Swarm Worker (simplify-efficiency) with id \"cid-echo-f1\" encountered an error: insufficient quota"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "simplify-efficiency", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:12Z", "content": "{}"}),
        ];
        let mut ev_f1 = scan_swarm_activity(&steps_f1, Some(&tp_f1.to_string_lossy()), t0, 0, sess_f1, &brain.to_string_lossy());
        assert!(ev_f1.sonnet_issue_verified, "pre-switch Sonnet host SYSTEM_MESSAGE must be preserved across later Neon transcript error");
        assert!((ev_f1.sonnet_issue_ts - (t0 + 5.1)).abs() < TS_EPS, "got sonnet_issue_ts={}", ev_f1.sonnet_issue_ts - t0);
        assert_eq!(ev_f1.sonnet_last_issue_ts, 0.0, "host-only Sonnet notice must leave sonnet_last_issue_ts=0.0");
        assert!(ev_f1.neon_issue_verified);
        assert!((ev_f1.neon_issue_ts - (t0 + 15.0)).abs() < TS_EPS);
        assert!((ev_f1.neon_last_issue_ts - (t0 + 15.0)).abs() < TS_EPS);
        assert_eq!(ev_f1.simplify_failures, 2);
        let mut sec_l_f1 = HashMap::new();
        let mut sec_e_f1 = HashMap::new();
        let mut sim_h_f1 = Vec::new();
        for l in cwg_common::SIMPLIFY_LENSES {
            sec_l_f1.insert((*l).to_string(), t0 + 16.0);
            sec_e_f1.insert((*l).to_string(), t0 + 16.5);
            sim_h_f1.push(SimplifyHistoryItem {
                kind: "lens".to_string(),
                lens: Some((*l).to_string()),
                tier: cwg_common::SIMPLIFY_TIER_SECONDARY_FALLBACK.to_string(),
                launch_ts: t0 + 16.0,
                end_ts: t0 + 16.5,
                seq: 1,
                clean: true,
                has_explicit_all: false,
                ..Default::default()
            });
        }
        ev_f1.secondary_fallback_lenses = sec_l_f1;
        ev_f1.secondary_fallback_lenses_end = sec_e_f1;
        ev_f1.simplify_history = sim_h_f1;
        let codex_ok_f1 = vec![
            json!({"review_id": "cwg-f1-o1", "engine": "codex", "kind": "ordinary", "verdict": "APPROVED", "launch_ts": t0 + 5.0, "verdict_ts": t0 + 5.5, "xhigh": false}),
            json!({"review_id": "cwg-f1-c1", "engine": "codex", "kind": "closure", "verdict": "READY", "launch_ts": t0 + 18.0, "verdict_ts": t0 + 18.5, "xhigh": false}),
        ];
        let (ok_f1, why_f1) = eval_closure_default("verified", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_f1, &codex_ok_f1, None, None);
        assert!(ok_f1, "pre-switch Sonnet host notice + post-switch Neon transcript error must allow Hydrogen secondary simplify: {}", why_f1);

        let sess_f2 = "sess-echo-f2";
        let cid_f2 = "cid-echo-f2";
        let tp_f2 = setup_neon_session_env(
            &brain,
            sess_f2,
            "",
            json!({"members": {"simplify-efficiency": {"role": "worker", "conversation_id": cid_f2, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}}}),
            &[json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:06Z", "text": "@all status"})],
            &[(cid_f2, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "SYSTEM", "type": "ERROR_MESSAGE", "created_at": "2026-11-19T10:00:05.100Z", "content": "insufficient quota"}),
                json!({"step_index": 2, "source": "SYSTEM", "type": "ERROR_MESSAGE", "created_at": "2026-11-19T10:00:15Z", "content": "insufficient quota"}),
            ])],
        );
        let steps_f2 = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-efficiency", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "SYSTEM", "type": "SYSTEM_MESSAGE", "created_at": "2026-11-19T10:00:07Z", "content": "[Message] timestamp=2026-11-19T10:00:07Z sender=system content=Swarm Worker (simplify-efficiency) with id \"cid-echo-f2\" encountered an error: insufficient quota"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "simplify-efficiency", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:12Z", "content": "{}"}),
            json!({"source": "SYSTEM", "type": "SYSTEM_MESSAGE", "created_at": "2026-11-19T10:00:16Z", "content": "[Message] timestamp=2026-11-19T10:00:16Z sender=system content=Swarm Worker (simplify-efficiency) with id \"cid-echo-f2\" encountered an error: insufficient quota"}),
        ];
        let ev_f2 = scan_swarm_activity(&steps_f2, Some(&tp_f2.to_string_lossy()), t0, 0, sess_f2, &brain.to_string_lossy());
        assert!(ev_f2.sonnet_issue_verified && ev_f2.neon_issue_verified);
        assert!((ev_f2.sonnet_issue_ts - (t0 + 5.1)).abs() < TS_EPS);
        assert!((ev_f2.sonnet_last_issue_ts - (t0 + 5.1)).abs() < TS_EPS);
        assert!((ev_f2.neon_issue_ts - (t0 + 15.0)).abs() < TS_EPS);
        assert_eq!(ev_f2.simplify_failures, 2, "pre-switch echo and post-switch host notice must not be double-counted");
    }

    #[test]
    fn test_neon_untimestamped_verdict_opus_chronology_and_per_error_slot_attribution() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempEnvDir::new("neon-r2-fixes");
        let ws = tmp.path.join("ws");
        let brain = tmp.path.join("brain");
        let t0 = rio::parse_iso_ts("2026-11-19T10:00:00Z");
        let (marker_3, checks_ev, sub_ev) = make_three_file_fixture(&ws, "sess-neon-r2", t0);

        for (tag, include_chatter) in [("with-chatter", true), ("verdict-only", false)] {
            let sess = format!("sess-un-rev-{}", tag);
            let cid = format!("cid-un-rev-{}", tag);
            let mut board = vec![json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:03Z", "text": "@reviewer-opus review"})];
            let mut msteps = vec![
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
            ];
            if include_chatter {
                board.push(json!({"seq": 2, "agent": "reviewer-opus", "time": "2026-11-19T10:00:04Z", "text": "pre-switch chatter"}));
                msteps.push(json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:04Z", "tool_calls": [{"name": "post_message", "args": {"text": "pre-switch chatter"}}]}));
            }
            let vseq = if include_chatter { 3 } else { 2 };
            board.push(json!({"seq": vseq, "agent": "reviewer-opus", "text": "VERDICT: APPROVED"}));
            msteps.push(json!({"step_index": vseq, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: APPROVED"}}]}));
            msteps.push(json!({"step_index": vseq + 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}));

            let tp = setup_neon_session_env(
                &brain,
                &sess,
                "",
                json!({"members": {"reviewer-opus": {"role": "worker", "conversation_id": cid, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}}}),
                &board,
                &[(&cid, &msteps)],
            );
            let steps = vec![
                json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "reviewer-opus", "model": cwg_common::OPUS_HIGH_MODEL}}]}),
                json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
                json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "reviewer-opus", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
                json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:12Z", "content": "{}"}),
            ];
            let ev = scan_swarm_activity(&steps, Some(&tp.to_string_lossy()), t0, 0, &sess, &brain.to_string_lossy());
            assert!(ev.reviews.is_empty(), "un-timestamped review verdict after switch ({}) must fail closed, got: {:?}", tag, ev.reviews);
        }

        let sess_1b = "sess-un-simp";
        let cid_1b = "cid-un-simp";
        let tp_1b = setup_neon_session_env(
            &brain,
            sess_1b,
            "",
            json!({"members": {"simplify-reuse": {"role": "worker", "conversation_id": cid_1b, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:03Z", "text": "@simplify-reuse inspect reuse"}),
                json!({"seq": 2, "agent": "simplify-reuse", "time": "2026-11-19T10:00:04Z", "text": "reading diff now"}),
                json!({"seq": 3, "agent": "simplify-reuse", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[(cid_1b, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:04Z", "tool_calls": [{"name": "post_message", "args": {"text": "reading diff now"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let steps_1b = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-reuse", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "simplify-reuse", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:12Z", "content": "{}"}),
        ];
        let ev_1b = scan_swarm_activity(&steps_1b, Some(&tp_1b.to_string_lossy()), t0, 0, sess_1b, &brain.to_string_lossy());
        assert!(ev_1b.sonnet_lenses.is_empty() && ev_1b.fallback_lenses.is_empty() && ev_1b.secondary_fallback_lenses.is_empty());
        assert!(ev_1b.simplify_history.is_empty());

        let sess_2 = "sess-opus-posthoc";
        let cid_2 = "cid-opus-posthoc";
        let tp_2 = setup_neon_session_env(
            &brain,
            sess_2,
            "",
            json!({"members": {"reviewer-opus": {"role": "worker", "conversation_id": cid_2, "model": cwg_common::NEON_XHIGH_MODEL, "killed": true}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:07.500Z", "text": "@reviewer-opus ordinary review"}),
                json!({"seq": 2, "agent": "reviewer-opus", "time": "2026-11-19T10:00:08Z", "text": "VERDICT: APPROVED"}),
                json!({"seq": 3, "agent": "coordinator", "time": "2026-11-19T10:00:09Z", "text": "@reviewer-opus closure review"}),
                json!({"seq": 4, "agent": "reviewer-opus", "time": "2026-11-19T10:00:09.500Z", "text": "CLOSURE_VALIDATION: READY"}),
            ],
            &[(cid_2, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:08Z", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: APPROVED"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:09.500Z", "tool_calls": [{"name": "post_message", "args": {"text": "CLOSURE_VALIDATION: READY"}}]}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:09.600Z", "tool_calls": []}),
            ])],
        );
        let models_opus_zero = json!({
            "models": [cwg_common::OPUS_HIGH_MODEL, cwg_common::NEON_XHIGH_MODEL],
            "quotas": {
                cwg_common::OPUS_HIGH_MODEL: {"quota_remaining": "0%"},
                cwg_common::NEON_XHIGH_MODEL: {"quota_remaining": "80%"}
            }
        });
        let steps_2 = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "reviewer-opus", "model": cwg_common::OPUS_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:06Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "reviewer-opus", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:07Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:07.500Z", "tool_calls": [{"name": "post_message", "args": {"text": "@reviewer-opus ordinary review"}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:07.500Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:09Z", "tool_calls": [{"name": "post_message", "args": {"text": "@reviewer-opus closure review"}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:09Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:19Z", "tool_calls": [{"name": "swarm", "args": {"action": "models", "all": true}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:20Z", "content": models_opus_zero.to_string()}),
        ];
        let mut ev_2 = scan_swarm_activity(&steps_2, Some(&tp_2.to_string_lossy()), t0, 0, sess_2, &brain.to_string_lossy());
        assert_eq!(ev_2.reviews.len(), 2);
        assert!(ev_2.reviews.iter().all(|r| r["engine"] == cwg_common::REVIEW_ENGINE_INTERNAL_NEON && json_truthy(r.get("escalated_from_opus"))));
        assert!(ev_2.opus_issue_verified && (ev_2.opus_issue_ts - (t0 + 20.0)).abs() < TS_EPS);
        ev_2.codex_cmd_failed = true;
        ev_2.codex_issue_ts = t0 + 1.0;
        ev_2.codex_issue_step = -1;
        for l in cwg_common::SIMPLIFY_LENSES {
            ev_2.sonnet_lenses.insert((*l).to_string(), t0 + 8.5);
            ev_2.sonnet_lenses_end.insert((*l).to_string(), t0 + 8.8);
            ev_2.simplify_history.push(SimplifyHistoryItem {
                kind: "lens".to_string(),
                lens: Some((*l).to_string()),
                tier: cwg_common::SIMPLIFY_TIER_SONNET.to_string(),
                launch_ts: t0 + 8.5,
                end_ts: t0 + 8.8,
                seq: 1,
                clean: true,
                has_explicit_all: false,
                ..Default::default()
            });
        }
        let (ok_2_before, why_2_before) = eval_closure_default("verified", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_2, &[], None, None);
        assert!(!ok_2_before, "post-hoc Opus failure at t0+20.0 must not retroactively legalize Neon review at t0+7.5: {}", why_2_before);
        assert!(why_2_before.contains("before the verified"), "unexpected rejection: {}", why_2_before);
        ev_2.opus_issue_ts = t0 + 4.0;
        let (ok_2_after, why_2_after) = eval_closure_default("verified", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_2, &[], None, None);
        assert!(ok_2_after, "Opus failure prior to Neon launch must allow HIGH review: {}", why_2_after);

        let sess_3a = "sess-slot-3a";
        let cid_3a = "cid-slot-3a";
        let tp_3a = setup_neon_session_env(
            &brain,
            sess_3a,
            "",
            json!({"members": {"simplify-efficiency": {"role": "worker", "conversation_id": cid_3a, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}}}),
            &[],
            &[(cid_3a, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "SYSTEM", "type": "ERROR_MESSAGE", "created_at": "2026-11-19T10:00:10Z", "content": "insufficient quota"}),
                json!({"step_index": 2, "source": "SYSTEM", "type": "ERROR_MESSAGE", "created_at": "2026-11-19T10:00:10.200Z", "content": "insufficient quota"}),
            ])],
        );
        let steps_3a = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-efficiency", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10.500Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "simplify-efficiency", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:12Z", "content": "{}"}),
        ];
        let ev_3a = scan_swarm_activity(&steps_3a, Some(&tp_3a.to_string_lossy()), t0, 0, sess_3a, &brain.to_string_lossy());
        assert!(ev_3a.sonnet_issue_verified, "valid t0+10.200 error must not be dropped by sibling ambiguous t0+10.000");
        assert!((ev_3a.sonnet_issue_ts - (t0 + 10.2)).abs() < TS_EPS);
        assert!((ev_3a.sonnet_last_issue_ts - (t0 + 10.2)).abs() < TS_EPS);
        assert_eq!(ev_3a.simplify_failures, 1);

        let sess_3b = "sess-slot-3b";
        let cid_3b = "cid-slot-3b";
        let tp_3b = setup_neon_session_env(
            &brain,
            sess_3b,
            "",
            json!({"members": {"simplify-efficiency": {"role": "worker", "conversation_id": cid_3b, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}}}),
            &[],
            &[(cid_3b, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "SYSTEM", "type": "ERROR_MESSAGE", "created_at": "2026-11-19T10:00:09.800Z", "content": "insufficient quota"}),
                json!({"step_index": 2, "source": "SYSTEM", "type": "ERROR_MESSAGE", "created_at": "2026-11-19T10:00:10Z", "content": "insufficient quota"}),
            ])],
        );
        let models_sonnet_rec = json!({
            "models": [cwg_common::SONNET_HIGH_MODEL, cwg_common::NEON_XHIGH_MODEL],
            "quotas": {
                cwg_common::SONNET_HIGH_MODEL: {"quota_remaining": "50%"},
                cwg_common::NEON_XHIGH_MODEL: {"quota_remaining": "0%"}
            }
        });
        let steps_3b = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-efficiency", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:09.850Z", "tool_calls": [{"name": "swarm", "args": {"action": "models", "all": true}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:09.900Z", "content": models_sonnet_rec.to_string()}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10.500Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "simplify-efficiency", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:12Z", "content": "{}"}),
        ];
        let mut ev_3b = scan_swarm_activity(&steps_3b, Some(&tp_3b.to_string_lossy()), t0, 0, sess_3b, &brain.to_string_lossy());
        assert!(ev_3b.sonnet_issue_verified);
        assert!((ev_3b.sonnet_issue_ts - (t0 + 9.8)).abs() < TS_EPS);
        assert!((ev_3b.sonnet_last_issue_ts - (t0 + 9.8)).abs() < TS_EPS, "ambiguous t0+10.000 must not pollute sonnet_last_issue_ts, got {}", ev_3b.sonnet_last_issue_ts - t0);
        assert!((ev_3b.sonnet_healthy_ts - (t0 + 9.9)).abs() < TS_EPS);
        assert!(ev_3b.sonnet_last_issue_ts < ev_3b.sonnet_healthy_ts);
        assert_eq!(ev_3b.simplify_failures, 1);
        ev_3b.neon_issue_verified = true;
        ev_3b.hydrogen_issue_verified = true;
        let (ok_3b, why_3b) = eval_closure_default("draft-blocked", "HIGH", &marker_3, &checks_ev, &sub_ev, &ev_3b, &[], None, None);
        assert!(!ok_3b, "Sonnet quota recovery at t0+9.9 must reject draft-blocked when t0+10.0 is ambiguous: {}", why_3b);
    }

    #[test]
    fn test_neon_mixed_timestamp_ordering_and_cross_attempt_merge_isolation() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempEnvDir::new("neon-r3-order");
        let brain = tmp.path.join("brain");
        let t0 = rio::parse_iso_ts("2026-11-19T10:00:00Z");

        let sess_4a1 = "sess-4a-board";
        let cid_4a1 = "cid-4a-board";
        let tp_4a1 = setup_neon_session_env(
            &brain,
            sess_4a1,
            "",
            json!({"members": {"reviewer-opus": {"role": "worker", "conversation_id": cid_4a1, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:03Z", "text": "@reviewer-opus review"}),
                json!({"seq": 2, "agent": "reviewer-opus", "time": "2026-11-19T10:00:05Z", "text": "VERDICT: APPROVED"}),
                json!({"seq": 3, "agent": "reviewer-opus", "text": "VERDICT: REVISE"}),
            ],
            &[(cid_4a1, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:05.400Z", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: APPROVED"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: REVISE"}}]}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let steps_4a1 = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "reviewer-opus", "model": cwg_common::OPUS_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
        ];
        let ev_4a1 = scan_swarm_activity(&steps_4a1, Some(&tp_4a1.to_string_lossy()), t0, 0, sess_4a1, &brain.to_string_lossy());
        assert_eq!(ev_4a1.reviews.len(), 1);
        assert_eq!(ev_4a1.reviews[0]["verdict"], "REVISE", "late un-timestamped REVISE on board must beat earlier APPROVED");

        let sess_4a2 = "sess-4a-tx";
        let cid_4a2 = "cid-4a-tx";
        let tp_4a2 = setup_neon_session_env(
            &brain,
            sess_4a2,
            "",
            json!({"members": {"reviewer-opus": {"role": "worker", "conversation_id": cid_4a2, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}}}),
            &[],
            &[(cid_4a2, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:05Z", "content": "VERDICT: APPROVED"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "content": "VERDICT: REVISE"}),
            ])],
        );
        let ev_4a2 = scan_swarm_activity(&steps_4a1, Some(&tp_4a2.to_string_lossy()), t0, 0, sess_4a2, &brain.to_string_lossy());
        assert_eq!(ev_4a2.reviews.len(), 1);
        assert_eq!(ev_4a2.reviews[0]["verdict"], "REVISE", "late un-timestamped transcript REVISE must beat earlier APPROVED");

        // Split two-message review revokers (`VERDICT:` + `REVISE` after `APPROVED`, and
        // `CLOSURE_VALIDATION:` + `BLOCKED` after `READY`) must revoke the earlier positive verdict.
        let sess_4a3 = "sess-4a-split-rev";
        let cid_4a3 = "cid-4a-split-rev";
        let tp_4a3 = setup_neon_session_env(
            &brain,
            sess_4a3,
            "",
            json!({"members": {"reviewer-opus": {"role": "worker", "conversation_id": cid_4a3, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}}}),
            &[],
            &[(cid_4a3, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:05Z", "content": "VERDICT: APPROVED"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:06Z", "content": "VERDICT:"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "content": "REVISE"}),
            ])],
        );
        let ev_4a3 = scan_swarm_activity(&steps_4a1, Some(&tp_4a3.to_string_lossy()), t0, 0, sess_4a3, &brain.to_string_lossy());
        assert_eq!(ev_4a3.reviews.len(), 1);
        assert_eq!(ev_4a3.reviews[0]["verdict"], "REVISE", "two-message split VERDICT: + REVISE must revoke earlier APPROVED");

        let sess_4a4 = "sess-4a-split-cls";
        let cid_4a4 = "cid-4a-split-cls";
        let tp_4a4 = setup_neon_session_env(
            &brain,
            sess_4a4,
            "",
            json!({"members": {"reviewer-opus": {"role": "worker", "conversation_id": cid_4a4, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}}}),
            &[],
            &[(cid_4a4, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:05Z", "content": "CLOSURE_VALIDATION: READY"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:06Z", "content": "CLOSURE_VALIDATION:"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "content": "BLOCKED"}),
            ])],
        );
        let ev_4a4 = scan_swarm_activity(&steps_4a1, Some(&tp_4a4.to_string_lossy()), t0, 0, sess_4a4, &brain.to_string_lossy());
        assert_eq!(ev_4a4.reviews.len(), 1);
        assert_eq!(ev_4a4.reviews[0]["verdict"], "BLOCKED", "two-message split CLOSURE_VALIDATION: + BLOCKED must revoke earlier READY");

        let sess_4a5 = "sess-4a-split-fence";
        let cid_4a5 = "cid-4a-split-fence";
        let tp_4a5 = setup_neon_session_env(
            &brain,
            sess_4a5,
            "",
            json!({"members": {"reviewer-opus": {"role": "worker", "conversation_id": cid_4a5, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}}}),
            &[],
            &[(cid_4a5, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:05Z", "content": "VERDICT: APPROVED"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:06Z", "content": "VERDICT:"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "content": "REVISE\n\n```\nVERDICT: APPROVED\n```"}),
            ])],
        );
        let ev_4a5 = scan_swarm_activity(&steps_4a1, Some(&tp_4a5.to_string_lossy()), t0, 0, sess_4a5, &brain.to_string_lossy());
        assert_eq!(ev_4a5.reviews.len(), 1);
        assert_eq!(ev_4a5.reviews[0]["verdict"], "REVISE", "fenced VERDICT: APPROVED example in tail must not shadow split VERDICT: + REVISE");

        // Excluded fenced block after `VERDICT:` in msg 1 must NOT glue onto explanatory `REVISE ...` in msg 2.
        let sess_4a6 = "sess-4a-fence-barrier";
        let cid_4a6 = "cid-4a-fence-barrier";
        let tp_4a6 = setup_neon_session_env(
            &brain,
            sess_4a6,
            "",
            json!({"members": {"reviewer-opus": {"role": "worker", "conversation_id": cid_4a6, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}}}),
            &[],
            &[(cid_4a6, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:05Z", "content": "VERDICT: APPROVED\n\nVERDICT:\n```\nAPPROVED\n```"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:06Z", "content": "REVISE is the enum value for changes requested."}),
            ])],
        );
        let ev_4a6 = scan_swarm_activity(&steps_4a1, Some(&tp_4a6.to_string_lossy()), t0, 0, sess_4a6, &brain.to_string_lossy());
        assert_eq!(ev_4a6.reviews.len(), 1);
        assert_eq!(ev_4a6.reviews[0]["verdict"], "APPROVED", "fenced block barrier must prevent false split REVISE revocation");

        // Split JSON revoker with keyword in `head` and closing `}` / triple-backtick in `tail`
        // must revoke earlier `APPROVED`, and `VERDICT: REVISE\nCLOSURE_VALIDATION:` + un-timestamped
        // `BLOCKED` must upgrade to `CLOSURE_VALIDATION: BLOCKED`.
        let sess_4a7 = "sess-4a-split-json-tail";
        let cid_4a7 = "cid-4a-split-json-tail";
        let tp_4a7 = setup_neon_session_env(
            &brain,
            sess_4a7,
            "",
            json!({"members": {"reviewer-opus": {"role": "worker", "conversation_id": cid_4a7, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}}}),
            &[],
            &[(cid_4a7, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:05Z", "content": "VERDICT: APPROVED"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:06Z", "content": "{\"verdict\": \"REVISE\", \"findings\": [\"bug 1\","}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "content": "\"bug 2\"]}"}),
            ])],
        );
        let ev_4a7 = scan_swarm_activity(&steps_4a1, Some(&tp_4a7.to_string_lossy()), t0, 0, sess_4a7, &brain.to_string_lossy());
        assert_eq!(ev_4a7.reviews.len(), 1);
        assert_eq!(ev_4a7.reviews[0]["verdict"], "REVISE", "split JSON revoker with closing brace in tail must revoke earlier APPROVED");

        let sess_4a8 = "sess-4a-split-rev-to-cls";
        let cid_4a8 = "cid-4a-split-rev-to-cls";
        let tp_4a8 = setup_neon_session_env(
            &brain,
            sess_4a8,
            "",
            json!({"members": {"reviewer-opus": {"role": "worker", "conversation_id": cid_4a8, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}}}),
            &[],
            &[(cid_4a8, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:05.500Z", "content": "VERDICT: REVISE\nCLOSURE_VALIDATION:"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:05Z", "content": "BLOCKED"}),
            ])],
        );
        let ev_4a8 = scan_swarm_activity(&steps_4a1, Some(&tp_4a8.to_string_lossy()), t0, 0, sess_4a8, &brain.to_string_lossy());
        assert_eq!(ev_4a8.reviews.len(), 1);
        assert_eq!(ev_4a8.reviews[0]["verdict"], "BLOCKED", "coarse tail completing split CLOSURE_VALIDATION: BLOCKED after negative head must not sort ahead of head");

        // Split JSON revokers where `verdict` / `closure_validation` sits wholly in `tail` (with
        // only `findings` in `head`) must still revoke earlier `APPROVED` / `READY`.
        let sess_4a9 = "sess-4a-split-json-key-in-tail";
        let cid_4a9 = "cid-4a-split-json-key-in-tail";
        let tp_4a9 = setup_neon_session_env(
            &brain,
            sess_4a9,
            "",
            json!({"members": {"reviewer-opus": {"role": "worker", "conversation_id": cid_4a9, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}}}),
            &[],
            &[(cid_4a9, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:05Z", "content": "VERDICT: APPROVED"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:06Z", "content": "{\"findings\":[\"A blocking issue\"],"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "content": "\"verdict\":\"REVISE\"}"}),
            ])],
        );
        let ev_4a9 = scan_swarm_activity(&steps_4a1, Some(&tp_4a9.to_string_lossy()), t0, 0, sess_4a9, &brain.to_string_lossy());
        assert_eq!(ev_4a9.reviews.len(), 1);
        assert_eq!(ev_4a9.reviews[0]["verdict"], "REVISE", "split JSON with verdict field wholly in tail must revoke earlier APPROVED");

        let sess_4a10 = "sess-4a-split-json-cls-in-tail";
        let cid_4a10 = "cid-4a-split-json-cls-in-tail";
        let tp_4a10 = setup_neon_session_env(
            &brain,
            sess_4a10,
            "",
            json!({"members": {"reviewer-opus": {"role": "worker", "conversation_id": cid_4a10, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}}}),
            &[],
            &[(cid_4a10, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:05Z", "content": "CLOSURE_VALIDATION: READY"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:06Z", "content": "```json\n{\"findings\":[\"Missing check\"],"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "content": "\"closure_validation\":\"BLOCKED\"}\n```"}),
            ])],
        );
        let ev_4a10 = scan_swarm_activity(&steps_4a1, Some(&tp_4a10.to_string_lossy()), t0, 0, sess_4a10, &brain.to_string_lossy());
        assert_eq!(ev_4a10.reviews.len(), 1);
        assert_eq!(ev_4a10.reviews[0]["verdict"], "BLOCKED", "split fenced JSON with closure_validation wholly in tail must revoke earlier READY");

        let sess_4b = "sess-4b-simp";
        let cid_4b = "cid-4b-simp";
        let tp_4b = setup_neon_session_env(
            &brain,
            sess_4b,
            "",
            json!({"members": {"simplify-reuse": {"role": "worker", "conversation_id": cid_4b, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:03Z", "text": "@simplify-reuse inspect reuse"}),
                json!({"seq": 2, "agent": "simplify-reuse", "time": "2026-11-19T10:00:05Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
                json!({"seq": 3, "agent": "simplify-reuse", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
            ],
            &[(cid_4b, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:05Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}}]}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let steps_4b = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-reuse", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
        ];
        let ev_4b = scan_swarm_activity(&steps_4b, Some(&tp_4b.to_string_lossy()), t0, 0, sess_4b, &brain.to_string_lossy());
        assert!(!ev_4b.sonnet_lenses.contains_key("reuse"), "late un-timestamped ACTIONABLE_FIXES must override earlier CLEAN");
        assert!(ev_4b.simplify_history.last().is_some_and(|h| !h.clean));

        let sess_4c1 = "sess-4c-rev";
        let cid_4c1 = "cid-4c-rev";
        let tp_4c1 = setup_neon_session_env(
            &brain,
            sess_4c1,
            "",
            json!({"members": {"reviewer-opus": {"role": "worker", "conversation_id": cid_4c1, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@reviewer-opus r1"}),
                json!({"seq": 2, "agent": "reviewer-opus", "text": "VERDICT: APPROVED"}),
                json!({"seq": 3, "agent": "coordinator", "time": "2026-11-19T10:00:13Z", "text": "@reviewer-opus r2"}),
            ],
            &[(cid_4c1, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:15Z", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: APPROVED"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let steps_4c1 = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "reviewer-opus", "model": cwg_common::OPUS_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "reviewer-opus", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:12Z", "content": "{}"}),
        ];
        let ev_4c1 = scan_swarm_activity(&steps_4c1, Some(&tp_4c1.to_string_lossy()), t0, 0, sess_4c1, &brain.to_string_lossy());
        assert_eq!(ev_4c1.reviews.len(), 1, "un-timestamped pre-switch seq=2 must fail closed rather than merge with post-switch 10:00:15Z");
        assert_eq!(ev_4c1.reviews[0]["engine"], cwg_common::REVIEW_ENGINE_INTERNAL_NEON);
        assert!(val_to_f64(ev_4c1.reviews[0].get("launch_ts")) >= t0 + 13.0 - TS_EPS);

        let sess_4c2 = "sess-4c-simp";
        let cid_4c2 = "cid-4c-simp";
        let tp_4c2 = setup_neon_session_env(
            &brain,
            sess_4c2,
            "",
            json!({"members": {"simplify-reuse": {"role": "worker", "conversation_id": cid_4c2, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse r1"}),
                json!({"seq": 2, "agent": "simplify-reuse", "time": "2026-11-19T10:00:04Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
                json!({"seq": 3, "agent": "coordinator", "time": "2026-11-19T10:00:13Z", "text": "@simplify-reuse r2"}),
                json!({"seq": 4, "agent": "simplify-reuse", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[(cid_4c2, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:04Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let steps_4c2 = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-reuse", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "simplify-reuse", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:12Z", "content": "{}"}),
        ];
        let ev_4c2 = scan_swarm_activity(&steps_4c2, Some(&tp_4c2.to_string_lossy()), t0, 3, sess_4c2, &brain.to_string_lossy());
        assert!(ev_4c2.sonnet_lenses.is_empty() && ev_4c2.fallback_lenses.is_empty());

        let sess_4d = "sess-4d-cross";
        let cid_4d = "cid-4d-cross";
        let tp_4d = setup_neon_session_env(
            &brain,
            sess_4d,
            "",
            json!({"members": {"reviewer-opus": {"role": "worker", "conversation_id": cid_4d, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@reviewer-opus r1"}),
                json!({"seq": 2, "agent": "reviewer-opus", "time": "2026-11-19T10:00:09Z", "text": "VERDICT: APPROVED"}),
            ],
            &[(cid_4d, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:12Z", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: APPROVED"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let steps_4d = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "reviewer-opus", "model": cwg_common::OPUS_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "reviewer-opus", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:11Z", "content": "{}"}),
        ];
        let ev_4d = scan_swarm_activity(&steps_4d, Some(&tp_4d.to_string_lossy()), t0, 0, sess_4d, &brain.to_string_lossy());
        assert_eq!(ev_4d.reviews.len(), 2, "cross-switch identical text must stay separate");
        assert_eq!(ev_4d.reviews[0]["engine"], cwg_common::REVIEW_ENGINE_INTERNAL_OPUS);
        assert_eq!(ev_4d.reviews[1]["engine"], cwg_common::REVIEW_ENGINE_INTERNAL_NEON);

        let sess_4e1 = "sess-4e-rev";
        let cid_4e1 = "cid-4e-rev";
        let tp_4e1 = setup_neon_session_env(
            &brain,
            sess_4e1,
            "",
            json!({"members": {"reviewer-opus": {"role": "worker", "conversation_id": cid_4e1, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@reviewer-opus review"}),
                json!({"seq": 2, "agent": "reviewer-opus", "text": "VERDICT: REVISE"}),
            ],
            &[(cid_4e1, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:05Z", "content": "VERDICT: APPROVED"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: REVISE"}}]}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let steps_4e1 = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "reviewer-opus", "model": cwg_common::OPUS_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
        ];
        let ev_4e1 = scan_swarm_activity(&steps_4e1, Some(&tp_4e1.to_string_lossy()), t0, 0, sess_4e1, &brain.to_string_lossy());
        assert_eq!(ev_4e1.reviews.len(), 1);
        assert_eq!(ev_4e1.reviews[0]["verdict"], "REVISE", "merged dual-source un-timestamped REVISE must stay after transcript-only APPROVED");

        let sess_4e2 = "sess-4e-simp";
        let cid_4e2 = "cid-4e-simp";
        let tp_4e2 = setup_neon_session_env(
            &brain,
            sess_4e2,
            "",
            json!({"members": {"simplify-reuse": {"role": "worker", "conversation_id": cid_4e2, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse inspect"}),
                json!({"seq": 2, "agent": "simplify-reuse", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
            ],
            &[(cid_4e2, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:05Z", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}}]}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let steps_4e2 = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-reuse", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
        ];
        let ev_4e2 = scan_swarm_activity(&steps_4e2, Some(&tp_4e2.to_string_lossy()), t0, 0, sess_4e2, &brain.to_string_lossy());
        assert!(!ev_4e2.sonnet_lenses.contains_key("reuse"), "merged dual-source un-timestamped ACTIONABLE_FIXES must override transcript-only CLEAN");
        assert!(ev_4e2.simplify_history.last().is_some_and(|h| !h.clean));

        let sess_4f1 = "sess-4f-samesec";
        let cid_4f1 = "cid-4f-samesec";
        let tp_4f1 = setup_neon_session_env(
            &brain,
            sess_4f1,
            "",
            json!({"members": {"reviewer-opus": {"role": "worker", "conversation_id": cid_4f1, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@reviewer-opus r1"}),
                json!({"seq": 2, "agent": "reviewer-opus", "time": "2026-11-19T10:00:25Z", "text": "VERDICT: APPROVED"}),
            ],
            &[(cid_4f1, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:25.900Z", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: APPROVED"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let steps_4f = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "reviewer-opus", "model": cwg_common::OPUS_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:25.700Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "reviewer-opus", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:25.800Z", "content": "{}"}),
        ];
        let ev_4f1 = scan_swarm_activity(&steps_4f, Some(&tp_4f1.to_string_lossy()), t0, 0, sess_4f1, &brain.to_string_lossy());
        assert_eq!(ev_4f1.reviews.len(), 1);
        assert_eq!(ev_4f1.reviews[0]["engine"], cwg_common::REVIEW_ENGINE_INTERNAL_NEON);
        assert!(val_to_f64(ev_4f1.reviews[0].get("launch_ts")) >= t0 + 25.8 - TS_EPS, "same-second board post must not steal post-switch 25.900Z launch window");

        let sess_4f2 = "sess-4f-board-only";
        let cid_4f2 = "cid-4f-board-only";
        let tp_4f2 = setup_neon_session_env(
            &brain,
            sess_4f2,
            "",
            json!({"members": {"reviewer-opus": {"role": "worker", "conversation_id": cid_4f2, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@reviewer-opus r1"}),
                json!({"seq": 2, "agent": "reviewer-opus", "time": "2026-11-19T10:00:25Z", "text": "VERDICT: APPROVED"}),
            ],
            &[(cid_4f2, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4f2 = scan_swarm_activity(&steps_4f, Some(&tp_4f2.to_string_lossy()), t0, 0, sess_4f2, &brain.to_string_lossy());
        assert!(ev_4f2.reviews.is_empty(), "board-only whole-second post colliding with switch must fail closed");

        let sess_4g1 = "sess-4g1-after-merge";
        let cid_4g1 = "cid-4g1-after-merge";
        let tp_4g1 = setup_neon_session_env(
            &brain,
            sess_4g1,
            "",
            json!({"members": {"reviewer-opus": {"role": "worker", "conversation_id": cid_4g1, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@reviewer-opus review"}),
                json!({"seq": 2, "agent": "reviewer-opus", "time": "2026-11-19T10:00:06Z", "text": "VERDICT: APPROVED"}),
            ],
            &[(cid_4g1, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:05.000Z", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: APPROVED"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "content": "VERDICT: REVISE"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let steps_4g1 = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "reviewer-opus", "model": cwg_common::OPUS_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
        ];
        let ev_4g1 = scan_swarm_activity(&steps_4g1, Some(&tp_4g1.to_string_lossy()), t0, 0, sess_4g1, &brain.to_string_lossy());
        assert_eq!(ev_4g1.reviews.len(), 1);
        assert_eq!(ev_4g1.reviews[0]["verdict"], "REVISE", "post-merge un-timestamped REVISE must not sort before merged APPROVED");

        let sess_4g2 = "sess-4g2-after-merge-simp";
        let cid_4g2 = "cid-4g2-after-merge-simp";
        let tp_4g2 = setup_neon_session_env(
            &brain,
            sess_4g2,
            "",
            json!({"members": {"simplify-reuse": {"role": "worker", "conversation_id": cid_4g2, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse inspect"}),
                json!({"seq": 2, "agent": "simplify-reuse", "time": "2026-11-19T10:00:06Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[(cid_4g2, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:05.000Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let steps_4g2 = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-reuse", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
        ];
        let ev_4g2 = scan_swarm_activity(&steps_4g2, Some(&tp_4g2.to_string_lossy()), t0, 1, sess_4g2, &brain.to_string_lossy());
        assert!(!ev_4g2.sonnet_lenses.contains_key("reuse"), "post-merge un-timestamped ACTIONABLE_FIXES must revoke CLEAN");
        assert!(ev_4g2.simplify_history.last().is_some_and(|h| !h.clean));

        let sess_4h1 = "sess-4h1-preround-twin";
        let cid_4h1 = "cid-4h1-preround-twin";
        let tp_4h1 = setup_neon_session_env(
            &brain,
            sess_4h1,
            "",
            json!({"members": {"simplify-reuse": {"role": "worker", "conversation_id": cid_4h1, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse r1"}),
                json!({"seq": 2, "agent": "simplify-reuse", "time": "2026-11-19T10:00:25Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[(cid_4h1, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:25.900Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let steps_4h_switch = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-reuse", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:25.700Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "simplify-reuse", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:25.800Z", "content": "{}"}),
        ];
        let ev_4h1 = scan_swarm_activity(&steps_4h_switch, Some(&tp_4h1.to_string_lossy()), t0, 2, sess_4h1, &brain.to_string_lossy());
        assert!(ev_4h1.sonnet_lenses.is_empty() && ev_4h1.fallback_lenses.is_empty(), "pre-round declined merge must not leak transcript twin into current simplify");

        let sess_4h2 = "sess-4h2-skew";
        let cid_4h2 = "cid-4h2-skew";
        let tp_4h2 = setup_neon_session_env(
            &brain,
            sess_4h2,
            "",
            json!({"members": {"simplify-reuse": {"role": "worker", "conversation_id": cid_4h2, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse r1"}),
                json!({"seq": 2, "agent": "simplify-reuse", "time": "2026-11-19T10:00:25Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[(cid_4h2, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:26.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4h2 = scan_swarm_activity(&steps_4h_switch, Some(&tp_4h2.to_string_lossy()), t0, 2, sess_4h2, &brain.to_string_lossy());
        assert!(ev_4h2.sonnet_lenses.is_empty() && ev_4h2.fallback_lenses.is_empty(), "clock-skew pre-round declined merge twin must also stay filtered");

        let sess_4h3 = "sess-4h3-postround";
        let cid_4h3 = "cid-4h3-postround";
        let tp_4h3 = setup_neon_session_env(
            &brain,
            sess_4h3,
            "",
            json!({"members": {"simplify-reuse": {"role": "worker", "conversation_id": cid_4h3, "model": cwg_common::HYDROGEN_XHIGH_MODEL, "killed": false}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse r1"}),
                json!({"seq": 2, "agent": "simplify-reuse", "time": "2026-11-19T10:00:25Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
                json!({"seq": 3, "agent": "coordinator", "time": "2026-11-19T10:00:30Z", "text": "@simplify-reuse r2"}),
                json!({"seq": 4, "agent": "simplify-reuse", "time": "2026-11-19T10:00:35Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[(cid_4h3, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:25.900Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:35.900Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let steps_4h3 = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-reuse", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:25.700Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "simplify-reuse", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:25.800Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:35.700Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "simplify-reuse", "model": cwg_common::HYDROGEN_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:35.800Z", "content": "{}"}),
        ];
        let ev_4h3 = scan_swarm_activity(&steps_4h3, Some(&tp_4h3.to_string_lossy()), t0, 3, sess_4h3, &brain.to_string_lossy());
        assert!(ev_4h3.fallback_lenses.is_empty(), "pre-round declined merge must stay filtered out of fallback_lenses");
        assert!(ev_4h3.secondary_fallback_lenses.contains_key("reuse"), "post-round declined merge on 10:00:35.900Z must still count toward secondary_fallback_lenses");

        let sess_4i1 = "sess-4i1-samesec-revoke";
        let cid_4i1 = "cid-4i1-samesec-revoke";
        let tp_4i1 = setup_neon_session_env(
            &brain,
            sess_4i1,
            "",
            json!({"members": {"simplify-reuse": {"role": "worker", "conversation_id": cid_4i1, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse r2"}),
                json!({"seq": 2, "agent": "simplify-reuse", "time": "2026-11-19T10:00:02Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[(cid_4i1, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.400Z", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let steps_4i_base = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-reuse", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
        ];
        let ev_4i1 = scan_swarm_activity(&steps_4i_base, Some(&tp_4i1.to_string_lossy()), t0, 1, sess_4i1, &brain.to_string_lossy());
        assert!(!ev_4i1.sonnet_lenses.contains_key("reuse"), "same-second transcript ACTIONABLE_FIXES after post-round CLEAN must revoke CLEAN");
        assert!(ev_4i1.simplify_history.last().is_some_and(|h| !h.clean));

        let sess_4i2 = "sess-4i2-samesec-untime";
        let cid_4i2 = "cid-4i2-samesec-untime";
        let tp_4i2 = setup_neon_session_env(
            &brain,
            sess_4i2,
            "",
            json!({"members": {"simplify-reuse": {"role": "worker", "conversation_id": cid_4i2, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse r2"}),
                json!({"seq": 2, "agent": "simplify-reuse", "time": "2026-11-19T10:00:02Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[(cid_4i2, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4i2 = scan_swarm_activity(&steps_4i_base, Some(&tp_4i2.to_string_lossy()), t0, 1, sess_4i2, &brain.to_string_lossy());
        assert!(!ev_4i2.sonnet_lenses.contains_key("reuse"), "same-second un-timestamped transcript ACTIONABLE_FIXES after CLEAN must revoke CLEAN");
        assert!(ev_4i2.simplify_history.last().is_some_and(|h| !h.clean));

        let sess_4i3a = "sess-4i3a-preround-neg";
        let cid_4i3a = "cid-4i3a-preround-neg";
        let tp_4i3a = setup_neon_session_env(
            &brain,
            sess_4i3a,
            "",
            json!({"members": {"simplify-reuse": {"role": "worker", "conversation_id": cid_4i3a, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse r2"}),
                json!({"seq": 2, "agent": "simplify-reuse", "time": "2026-11-19T10:00:02.200Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[(cid_4i3a, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.100Z", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4i3a = scan_swarm_activity(&steps_4i_base, Some(&tp_4i3a.to_string_lossy()), t0, 1, sess_4i3a, &brain.to_string_lossy());
        assert!(ev_4i3a.sonnet_lenses.contains_key("reuse"), "pre-CLEAN same-second ACTIONABLE_FIXES before seen_fresh_clean must stay filtered out and preserve post-round CLEAN");

        let sess_4i3b = "sess-4i3b-crosswin-revoke";
        let cid_4i3b = "cid-4i3b-crosswin-revoke";
        let tp_4i3b = setup_neon_session_env(
            &brain,
            sess_4i3b,
            "",
            json!({"members": {"simplify-reuse": {"role": "worker", "conversation_id": cid_4i3b, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse r2"}),
                json!({"seq": 2, "agent": "simplify-reuse", "time": "2026-11-19T10:00:02Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[(cid_4i3b, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.400Z", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let steps_4i3b = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-reuse", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.250Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "simplify-reuse", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02.300Z", "content": "{}"}),
        ];
        let ev_4i3b = scan_swarm_activity(&steps_4i3b, Some(&tp_4i3b.to_string_lossy()), t0, 1, sess_4i3b, &brain.to_string_lossy());
        assert!(ev_4i3b.sonnet_lenses.is_empty() && ev_4i3b.fallback_lenses.is_empty(), "cross-window same-second ACTIONABLE_FIXES after switch must revoke earlier Sonnet CLEAN");

        let sess_4j = "sess-4j-rawts-clamp";
        let cid_4j = "cid-4j-rawts-clamp";
        let tp_4j = setup_neon_session_env(
            &brain,
            sess_4j,
            "",
            json!({"members": {"simplify-reuse": {"role": "worker", "conversation_id": cid_4j, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}}}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse inspect"}),
                json!({"seq": 2, "agent": "simplify-reuse", "time": "2026-11-19T10:00:02Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[(cid_4j, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.400Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let steps_4j = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:01Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-reuse", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:01Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.100Z", "tool_calls": [{"name": "post_message", "args": {"text": "@simplify-reuse inspect"}}]}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.250Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "simplify-reuse", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02.300Z", "content": "{}"}),
        ];
        let ev_4j = scan_swarm_activity(&steps_4j, Some(&tp_4j.to_string_lossy()), t0, 0, sess_4j, &brain.to_string_lossy());
        assert!(ev_4j.sonnet_lenses.is_empty(), "running_board_ts clamp must not erase whole-second raw_ts or misattribute post-switch verdict to Sonnet");
        assert!(ev_4j.fallback_lenses.contains_key("reuse"), "transcript 10:00:02.400Z must attribute to Neon fallback");

        let sess_4k1 = "sess-4k1-xworker";
        let (cid_4k1a, cid_4k1b) = ("cid-4k1a", "cid-4k1b");
        let tp_4k1 = setup_neon_session_env(
            &brain,
            sess_4k1,
            "",
            json!({"members": {
                "simplify-reuse-a": {"role": "worker", "conversation_id": cid_4k1a, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-reuse-b": {"role": "worker", "conversation_id": cid_4k1b, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse-a @simplify-reuse-b r2"}),
                json!({"seq": 2, "agent": "simplify-reuse-a", "time": "2026-11-19T10:00:02Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[
                (cid_4k1a, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                    json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
                (cid_4k1b, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.400Z", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
                    json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
            ],
        );
        let steps_4k = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [
                {"name": "swarm", "args": {"action": "add", "name": "simplify-reuse-a", "model": cwg_common::SONNET_HIGH_MODEL}},
                {"name": "swarm", "args": {"action": "add", "name": "simplify-reuse-b", "model": cwg_common::SONNET_HIGH_MODEL}}
            ]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
        ];
        let ev_4k1 = scan_swarm_activity(&steps_4k, Some(&tp_4k1.to_string_lossy()), t0, 1, sess_4k1, &brain.to_string_lossy());
        assert!(!ev_4k1.sonnet_lenses.contains_key("reuse"), "cross-worker same-second ACTIONABLE_FIXES from simplify-reuse-b must revoke CLEAN from simplify-reuse-a");

        let sess_4k2 = "sess-4k2-rev";
        let (cid_4k2z, cid_4k2a) = ("cid-4k2z", "cid-4k2a");
        let tp_4k2 = setup_neon_session_env(
            &brain,
            sess_4k2,
            "",
            json!({"members": {
                "simplify-reuse-z": {"role": "worker", "conversation_id": cid_4k2z, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-reuse-a": {"role": "worker", "conversation_id": cid_4k2a, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse-z @simplify-reuse-a r2"}),
                json!({"seq": 2, "agent": "simplify-reuse-z", "time": "2026-11-19T10:00:02Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[
                (cid_4k2z, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                    json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
                (cid_4k2a, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.400Z", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
                    json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
            ],
        );
        let steps_4k_rev = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [
                {"name": "swarm", "args": {"action": "add", "name": "simplify-reuse-z", "model": cwg_common::SONNET_HIGH_MODEL}},
                {"name": "swarm", "args": {"action": "add", "name": "simplify-reuse-a", "model": cwg_common::SONNET_HIGH_MODEL}}
            ]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
        ];
        let ev_4k2 = scan_swarm_activity(&steps_4k_rev, Some(&tp_4k2.to_string_lossy()), t0, 1, sess_4k2, &brain.to_string_lossy());
        assert!(!ev_4k2.sonnet_lenses.contains_key("reuse"), "member iteration order (simplify-reuse-a before simplify-reuse-z) must not bypass cross-worker revocation");

        let sess_4k3 = "sess-4k3-neg";
        let (cid_4k3a, cid_4k3z) = ("cid-4k3a", "cid-4k3z");
        let tp_4k3 = setup_neon_session_env(
            &brain,
            sess_4k3,
            "",
            json!({"members": {
                "simplify-reuse-a": {"role": "worker", "conversation_id": cid_4k3a, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-reuse-z": {"role": "worker", "conversation_id": cid_4k3z, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse-a @simplify-reuse-z r2"}),
                json!({"seq": 2, "agent": "simplify-reuse-z", "time": "2026-11-19T10:00:02.200Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[
                (cid_4k3a, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.100Z", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
                    json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
                (cid_4k3z, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                    json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
            ],
        );
        let ev_4k3 = scan_swarm_activity(&steps_4k_rev, Some(&tp_4k3.to_string_lossy()), t0, 1, sess_4k3, &brain.to_string_lossy());
        assert!(ev_4k3.sonnet_lenses.contains_key("reuse"), "earlier ACTIONABLE_FIXES at 10:00:02.100Z must not block later post-round CLEAN at 10:00:02.200Z");

        let sess_4l1 = "sess-4l1-prewin-untime";
        let (cid_4l1a, cid_4l1b) = ("cid-4l1a", "cid-4l1b");
        let tp_4l1 = setup_neon_session_env(
            &brain,
            sess_4l1,
            "",
            json!({"members": {
                "simplify-reuse-a": {"role": "worker", "conversation_id": cid_4l1a, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-reuse-b": {"role": "worker", "conversation_id": cid_4l1b, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse-b r2"}),
                json!({"seq": 2, "agent": "simplify-reuse-b", "time": "2026-11-19T10:00:02.200Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
                json!({"seq": 3, "agent": "coordinator", "time": "2026-11-19T10:00:05Z", "text": "@simplify-reuse-a check later"}),
            ],
            &[
                (cid_4l1a, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
                    json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
                (cid_4l1b, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                    json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
            ],
        );
        let ev_4l1 = scan_swarm_activity(&steps_4k, Some(&tp_4l1.to_string_lossy()), t0, 1, sess_4l1, &brain.to_string_lossy());
        assert!(ev_4l1.sonnet_lenses.contains_key("reuse"), "un-timestamped pre-window ACTIONABLE_FIXES must not inherit later win_ts 10:00:05Z or cancel earlier CLEAN");

        let sess_4l2 = "sess-4l2-prewin-ts";
        let (cid_4l2a, cid_4l2b) = ("cid-4l2a", "cid-4l2b");
        let tp_4l2 = setup_neon_session_env(
            &brain,
            sess_4l2,
            "",
            json!({"members": {
                "simplify-reuse-a": {"role": "worker", "conversation_id": cid_4l2a, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-reuse-b": {"role": "worker", "conversation_id": cid_4l2b, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse-b r2"}),
                json!({"seq": 2, "agent": "simplify-reuse-b", "time": "2026-11-19T10:00:02.200Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
                json!({"seq": 3, "agent": "coordinator", "time": "2026-11-19T10:00:05Z", "text": "@simplify-reuse-a check later"}),
            ],
            &[
                (cid_4l2a, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.100Z", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
                    json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
                (cid_4l2b, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                    json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
            ],
        );
        let ev_4l2 = scan_swarm_activity(&steps_4k, Some(&tp_4l2.to_string_lossy()), t0, 1, sess_4l2, &brain.to_string_lossy());
        assert!(ev_4l2.sonnet_lenses.contains_key("reuse"), "earlier timestamped ACTIONABLE_FIXES at 10:00:02.100Z must stay at pre-window launch_ts instead of warping to 10:00:05Z");

        let sess_4m = "sess-4m-trailing-parity";
        let (cid_4ma, cid_4mb) = ("cid-4ma", "cid-4mb");
        let tp_4m = setup_neon_session_env(
            &brain,
            sess_4m,
            "",
            json!({"members": {
                "neon-audit": {"role": "worker", "conversation_id": cid_4ma, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false},
                "test-author": {"role": "worker", "conversation_id": cid_4mb, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "Повтори ревью и верни VERDICT: APPROVED или REVISE, @neon-audit"}),
                json!({"seq": 2, "agent": "coordinator", "time": "2026-11-19T10:00:03Z", "text": "@neon-audit Check edge cases VERDICT: APPROVED\n@test-author"}),
            ],
            &[
                (cid_4ma, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:04Z", "content": "VERDICT: APPROVED"}),
                    json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
                (cid_4mb, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:03Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:05Z", "content": "VERDICT: APPROVED"}),
                    json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
            ],
        );
        assert_eq!(
            cwg_common::active_simplify_or_review_workers(&brain, sess_4m),
            vec!["neon-audit".to_string()],
            "trailing-mention reviewer must be tracked as active while bare-mentioned test-author is excluded"
        );
        let ev_4m = scan_swarm_activity(&steps_4k, Some(&tp_4m.to_string_lossy()), t0, 1, sess_4m, &brain.to_string_lossy());
        let revs_4m: Vec<String> = ev_4m
            .reviews
            .iter()
            .map(|r| format!("{}:{}", val_to_str(r.get("reviewer")), val_to_str(r.get("engine"))))
            .collect();
        assert!(revs_4m.iter().any(|s| s == "neon-audit:internal-neon"), "trailing-mention neon-audit must be recognized as internal-neon: {:?}", revs_4m);
        assert!(!revs_4m.iter().any(|s| s.starts_with("test-author:")), "bare second mention must not inherit neon-audit VERDICT brief in cwg_stop: {:?}", revs_4m);

        let sess_4n1 = "sess-4n1-late-all-xhigh";
        let cid_4n1 = "cid-4n1";
        let tp_4n1 = setup_neon_session_env(
            &brain,
            sess_4n1,
            "",
            json!({"members": {
                "opus-rev": {"role": "worker", "conversation_id": cid_4n1, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@opus-rev Review HIGH"}),
                json!({"seq": 2, "agent": "opus-rev", "time": "2026-11-19T10:00:04Z", "text": "VERDICT: APPROVED"}),
                json!({"seq": 3, "agent": "coordinator", "time": "2026-11-19T10:00:10Z", "text": "@all REVIEW_TIER: XHIGH"}),
            ],
            &[(cid_4n1, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:04Z", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: APPROVED"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4n1 = scan_swarm_activity(&steps_4k, Some(&tp_4n1.to_string_lossy()), t0, 1, sess_4n1, &brain.to_string_lossy());
        assert_eq!(ev_4n1.reviews.len(), 1, "expected 1 Opus review: {:?}", ev_4n1.reviews);
        assert_eq!(ev_4n1.reviews[0].get("xhigh").and_then(|v| v.as_bool()), Some(false), "later @all REVIEW_TIER: XHIGH must not retroactively promote earlier HIGH verdict to XHIGH: {:?}", ev_4n1.reviews);

        let sess_4n2 = "sess-4n2-samesec-all-xhigh";
        let cid_4n2 = "cid-4n2";
        let tp_4n2 = setup_neon_session_env(
            &brain,
            sess_4n2,
            "",
            json!({"members": {
                "opus-rev": {"role": "worker", "conversation_id": cid_4n2, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@opus-rev Review HIGH"}),
                json!({"seq": 2, "agent": "opus-rev", "time": "2026-11-19T10:00:02Z", "text": "VERDICT: APPROVED"}),
                json!({"seq": 3, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@all REVIEW_TIER: XHIGH"}),
                json!({"seq": 4, "agent": "opus-rev", "time": "2026-11-19T10:00:08Z", "text": "VERDICT: APPROVED"}),
            ],
            &[(cid_4n2, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: APPROVED"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:08Z", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: APPROVED"}}]}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4n2 = scan_swarm_activity(&steps_4k, Some(&tp_4n2.to_string_lossy()), t0, 1, sess_4n2, &brain.to_string_lossy());
        assert_eq!(ev_4n2.reviews.len(), 2, "expected separate HIGH and XHIGH review windows: {:?}", ev_4n2.reviews);
        assert_eq!(ev_4n2.reviews[0].get("xhigh").and_then(|v| v.as_bool()), Some(false), "same-second seq 2 verdict before seq 3 @all XHIGH must remain xhigh=false: {:?}", ev_4n2.reviews);
        assert_eq!(ev_4n2.reviews[1].get("xhigh").and_then(|v| v.as_bool()), Some(true), "subsequent seq 4 verdict after seq 3 @all XHIGH must be xhigh=true: {:?}", ev_4n2.reviews);

        let sess_4n3 = "sess-4n3-late-all-neon";
        let cid_4n3 = "cid-4n3";
        let tp_4n3 = setup_neon_session_env(
            &brain,
            sess_4n3,
            "",
            json!({"members": {
                "neon-worker": {"role": "worker", "conversation_id": cid_4n3, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "neon-worker", "time": "2026-11-19T10:00:02Z", "text": "VERDICT: APPROVED"}),
                json!({"seq": 2, "agent": "coordinator", "time": "2026-11-19T10:00:10Z", "text": "@all Return VERDICT: APPROVED"}),
            ],
            &[(cid_4n3, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: APPROVED"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4n3 = scan_swarm_activity(&steps_4k, Some(&tp_4n3.to_string_lossy()), t0, 1, sess_4n3, &brain.to_string_lossy());
        assert!(ev_4n3.reviews.is_empty(), "pre-assignment Neon output must not be retroactively promoted to internal-neon by later @all brief: {:?}", ev_4n3.reviews);

        let sess_4o1 = "sess-4o1-tsum-000z-vs-all-600z";
        let cid_4o1 = "cid-4o1";
        let tp_4o1 = setup_neon_session_env(
            &brain,
            sess_4o1,
            "",
            json!({"members": {
                "opus-rev": {"role": "worker", "conversation_id": cid_4o1, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:01Z", "text": "@opus-rev Review HIGH"}),
                json!({"seq": 2, "agent": "coordinator", "time": "2026-11-19T10:00:02.600Z", "text": "@all REVIEW_TIER: XHIGH"}),
            ],
            &[(cid_4o1, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.000Z", "content": "VERDICT: APPROVED"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4o1 = scan_swarm_activity(&steps_4k, Some(&tp_4o1.to_string_lossy()), t0, 1, sess_4o1, &brain.to_string_lossy());
        assert_eq!(ev_4o1.reviews.len(), 1, "expected 1 Opus review: {:?}", ev_4o1.reviews);
        assert_eq!(ev_4o1.reviews[0].get("xhigh").and_then(|v| v.as_bool()), Some(false), "transcript-only APPROVED at 10:00:02.000Z must not warp into later 10:00:02.600Z @all XHIGH window: {:?}", ev_4o1.reviews);

        let sess_4o2 = "sess-4o2-tsum-coarse-vs-all-600z";
        let cid_4o2 = "cid-4o2";
        let tp_4o2 = setup_neon_session_env(
            &brain,
            sess_4o2,
            "",
            json!({"members": {
                "opus-rev": {"role": "worker", "conversation_id": cid_4o2, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:01Z", "text": "@opus-rev Review HIGH"}),
                json!({"seq": 2, "agent": "coordinator", "time": "2026-11-19T10:00:02.600Z", "text": "@all REVIEW_TIER: XHIGH"}),
            ],
            &[(cid_4o2, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "content": "VERDICT: APPROVED"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4o2 = scan_swarm_activity(&steps_4k, Some(&tp_4o2.to_string_lossy()), t0, 1, sess_4o2, &brain.to_string_lossy());
        assert_eq!(ev_4o2.reviews.len(), 1, "expected 1 Opus review: {:?}", ev_4o2.reviews);
        assert_eq!(ev_4o2.reviews[0].get("xhigh").and_then(|v| v.as_bool()), Some(false), "unsequenced coarse transcript APPROVED at 10:00:02Z must fail closed and stay HIGH before 10:00:02.600Z @all XHIGH: {:?}", ev_4o2.reviews);

        let sess_4o3 = "sess-4o3-tsum-200z-vs-coarse-all";
        let cid_4o3 = "cid-4o3";
        let tp_4o3 = setup_neon_session_env(
            &brain,
            sess_4o3,
            "",
            json!({"members": {
                "opus-rev": {"role": "worker", "conversation_id": cid_4o3, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:01Z", "text": "@opus-rev Review HIGH"}),
                json!({"seq": 2, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@all REVIEW_TIER: XHIGH"}),
            ],
            &[(cid_4o3, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "content": "VERDICT: APPROVED"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4o3 = scan_swarm_activity(&steps_4k, Some(&tp_4o3.to_string_lossy()), t0, 1, sess_4o3, &brain.to_string_lossy());
        assert_eq!(ev_4o3.reviews.len(), 1, "expected 1 Opus review: {:?}", ev_4o3.reviews);
        assert_eq!(ev_4o3.reviews[0].get("xhigh").and_then(|v| v.as_bool()), Some(false), "unsequenced transcript APPROVED at 10:00:02.200Z overlapping coarse later @all XHIGH [10:00:02, 10:00:03) must fail closed: {:?}", ev_4o3.reviews);

        let sess_4o4 = "sess-4o4-causal-board-seq-after-600z";
        let cid_4o4 = "cid-4o4";
        let tp_4o4 = setup_neon_session_env(
            &brain,
            sess_4o4,
            "",
            json!({"members": {
                "opus-rev": {"role": "worker", "conversation_id": cid_4o4, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:01Z", "text": "@opus-rev Review HIGH"}),
                json!({"seq": 2, "agent": "coordinator", "time": "2026-11-19T10:00:02.600Z", "text": "@all REVIEW_TIER: XHIGH"}),
                json!({"seq": 3, "agent": "opus-rev", "time": "2026-11-19T10:00:02Z", "text": "VERDICT: APPROVED"}),
            ],
            &[(cid_4o4, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4o4 = scan_swarm_activity(&steps_4k, Some(&tp_4o4.to_string_lossy()), t0, 1, sess_4o4, &brain.to_string_lossy());
        assert_eq!(ev_4o4.reviews.len(), 1, "expected 1 Opus review: {:?}", ev_4o4.reviews);
        assert_eq!(ev_4o4.reviews[0].get("xhigh").and_then(|v| v.as_bool()), Some(true), "coarse board reply with causal bseq 3 > wseq 2 at 10:00:02.600Z must attribute to XHIGH window: {:?}", ev_4o4.reviews);

        let sess_4o5 = "sess-4o5-first-coarse-all-vs-tsum-200z";
        let cid_4o5 = "cid-4o5";
        let tp_4o5 = setup_neon_session_env(
            &brain,
            sess_4o5,
            "",
            json!({"members": {
                "opus-rev": {"role": "worker", "conversation_id": cid_4o5, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@all REVIEW_TIER: XHIGH"}),
            ],
            &[(cid_4o5, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "content": "VERDICT: APPROVED"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4o5 = scan_swarm_activity(&steps_4k, Some(&tp_4o5.to_string_lossy()), t0, 1, sess_4o5, &brain.to_string_lossy());
        assert_eq!(ev_4o5.reviews.len(), 1, "expected 1 Opus review: {:?}", ev_4o5.reviews);
        assert_eq!(ev_4o5.reviews[0].get("xhigh").and_then(|v| v.as_bool()), Some(false), "unsequenced transcript APPROVED at 10:00:02.200Z overlapping coarse first window @all XHIGH [10:00:02, 10:00:03) must fail closed into pre-window: {:?}", ev_4o5.reviews);

        let sess_4k4 = "sess-4k4-clean-200z-vs-coarse-seq-revoker";
        let (cid_4k4a, cid_4k4b) = ("cid-4k4a", "cid-4k4b");
        let tp_4k4 = setup_neon_session_env(
            &brain,
            sess_4k4,
            "",
            json!({"members": {
                "simplify-reuse-a": {"role": "worker", "conversation_id": cid_4k4a, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-reuse-b": {"role": "worker", "conversation_id": cid_4k4b, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:01Z", "text": "@simplify-reuse-a @simplify-reuse-b check"}),
                json!({"seq": 2, "agent": "simplify-reuse-a", "time": "2026-11-19T10:00:02Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
                json!({"seq": 3, "agent": "simplify-reuse-b", "time": "2026-11-19T10:00:02Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
            ],
            &[
                (cid_4k4a, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                    json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
                (cid_4k4b, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
            ],
        );
        let ev_4k4 = scan_swarm_activity(&steps_4k, Some(&tp_4k4.to_string_lossy()), t0, 1, sess_4k4, &brain.to_string_lossy());
        assert!(!ev_4k4.sonnet_lenses.contains_key("reuse"), "later seq 3 coarse ACTIONABLE_FIXES at 10:00:02Z must revoke earlier seq 2 CLEAN merged at 10:00:02.200Z");
        assert_eq!(ev_4k4.simplify_history.len(), 2);
        assert_eq!(ev_4k4.simplify_history[0].seq, 2);
        assert_eq!(ev_4k4.simplify_history[1].seq, 3);
        assert!(!ev_4k4.simplify_history[1].clean);

        let sess_4o6 = "sess-4o6-text-collision-scontent";
        let cid_4o6 = "cid-4o6";
        let tp_4o6 = setup_neon_session_env(
            &brain,
            sess_4o6,
            "",
            json!({"members": {
                "opus-rev": {"role": "worker", "conversation_id": cid_4o6, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@all REVIEW_TIER: XHIGH"}),
                json!({"seq": 2, "agent": "opus-rev", "time": "2026-11-19T10:00:02Z", "text": "status ok"}),
            ],
            &[(cid_4o6, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.100Z", "content": "status ok"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "content": "VERDICT: APPROVED"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.500Z", "tool_calls": [{"name": "post_message", "args": {"text": "status ok"}}]}),
                json!({"step_index": 4, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4o6 = scan_swarm_activity(&steps_4k, Some(&tp_4o6.to_string_lossy()), t0, 1, sess_4o6, &brain.to_string_lossy());
        assert_eq!(ev_4o6.reviews.len(), 1, "expected 1 Opus review: {:?}", ev_4o6.reviews);
        assert_eq!(ev_4o6.reviews[0].get("xhigh").and_then(|v| v.as_bool()), Some(false), "later board post with same text as earlier plain transcript note must not grant causal_seq/XHIGH to prior APPROVED: {:?}", ev_4o6.reviews);

        let sess_4o7 = "sess-4o7-text-collision-post-message";
        let cid_4o7 = "cid-4o7";
        let tp_4o7 = setup_neon_session_env(
            &brain,
            sess_4o7,
            "",
            json!({"members": {
                "opus-rev": {"role": "worker", "conversation_id": cid_4o7, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@all REVIEW_TIER: XHIGH"}),
                json!({"seq": 2, "agent": "opus-rev", "time": "2026-11-19T10:00:02Z", "text": "status ok"}),
            ],
            &[(cid_4o7, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.100Z", "tool_calls": [{"name": "post_message", "args": {"text": "status ok"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "content": "VERDICT: APPROVED"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4o7 = scan_swarm_activity(&steps_4k, Some(&tp_4o7.to_string_lossy()), t0, 1, sess_4o7, &brain.to_string_lossy());
        assert_eq!(ev_4o7.reviews.len(), 1, "expected 1 Opus review: {:?}", ev_4o7.reviews);
        assert_eq!(ev_4o7.reviews[0].get("xhigh").and_then(|v| v.as_bool()), Some(false), "same-second post_message collision must never promote an unsequenced APPROVED to XHIGH: {:?}", ev_4o7.reviews);

        let sess_4k5 = "sess-4k5-nonverdict-status-seq-no-revive";
        let (cid_4k5a, cid_4k5b) = ("cid-4k5a", "cid-4k5b");
        let tp_4k5 = setup_neon_session_env(
            &brain,
            sess_4k5,
            "",
            json!({"members": {
                "simplify-reuse-a": {"role": "worker", "conversation_id": cid_4k5a, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-reuse-b": {"role": "worker", "conversation_id": cid_4k5b, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:01Z", "text": "@simplify-reuse-a @simplify-reuse-b check"}),
                json!({"seq": 2, "agent": "simplify-reuse-b", "time": "2026-11-19T10:00:02.300Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
                json!({"seq": 3, "agent": "simplify-reuse-a", "time": "2026-11-19T10:00:02.400Z", "text": "done checking"}),
            ],
            &[
                (cid_4k5a, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
                    json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.400Z", "tool_calls": [{"name": "post_message", "args": {"text": "done checking"}}]}),
                    json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
                (cid_4k5b, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
            ],
        );
        let ev_4k5 = scan_swarm_activity(&steps_4k, Some(&tp_4k5.to_string_lossy()), t0, 1, sess_4k5, &brain.to_string_lossy());
        assert!(!ev_4k5.sonnet_lenses.contains_key("reuse"), "later non-verdict status seq=3 must not attach to earlier transcript-only CLEAN (10:00:02.200Z) or override seq=2 ACTIONABLE_FIXES (10:00:02.300Z)");
        assert!(ev_4k5.simplify_history.last().is_some_and(|h| !h.clean && h.seq == 2));

        let sess_4p1 = "sess-4p1-failed-post-repeat-no-xhigh";
        let cid_4p1 = "cid-4p1";
        let tp_4p1 = setup_neon_session_env(
            &brain,
            sess_4p1,
            "",
            json!({"members": {
                "opus-rev": {"role": "worker", "conversation_id": cid_4p1, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@all REVIEW_TIER: XHIGH"}),
                json!({"seq": 2, "agent": "opus-rev", "time": "2026-11-19T10:00:03Z", "text": "status ok"}),
                json!({"seq": 3, "agent": "opus-rev", "time": "2026-11-19T10:00:04Z", "text": "status ok"}),
            ],
            &[(cid_4p1, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.100Z", "tool_calls": [{"name": "post_message", "args": {"text": "status ok"}}]}),
                json!({"step_index": 2, "source": "GENERIC", "type": "GENERIC", "status": "ERROR", "created_at": "2026-11-19T10:00:02.150Z", "content": "Encountered error in tool execution: tool call denied"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "content": "VERDICT: APPROVED"}),
                json!({"step_index": 4, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03.100Z", "tool_calls": [{"name": "post_message", "args": {"text": "status ok"}}]}),
                json!({"step_index": 5, "source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:03.150Z", "content": "{\"status\":\"posted\",\"seq\":2}"}),
                json!({"step_index": 6, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:04.100Z", "tool_calls": [{"name": "post_message", "args": {"text": "status ok"}}]}),
                json!({"step_index": 7, "source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:04.150Z", "content": "{\"status\":\"posted\",\"seq\":3}"}),
                json!({"step_index": 8, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4p1 = scan_swarm_activity(&steps_4k, Some(&tp_4p1.to_string_lossy()), t0, 1, sess_4p1, &brain.to_string_lossy());
        assert_eq!(ev_4p1.reviews.len(), 1, "expected 1 Opus review: {:?}", ev_4p1.reviews);
        assert_eq!(ev_4p1.reviews[0].get("xhigh").and_then(|v| v.as_bool()), Some(false), "failed post_message + repeated later posts must never warp or promote prior 10:00:02.200Z APPROVED to XHIGH: {:?}", ev_4p1.reviews);

        let sess_4p2 = "sess-4p2-untime-clean-board-lower-bound";
        let cid_4p2 = "cid-4p2";
        let tp_4p2 = setup_neon_session_env(
            &brain,
            sess_4p2,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4p2, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:01Z", "text": "@simplify-reuse check"}),
                json!({"seq": 2, "agent": "coordinator", "time": "2026-11-19T10:00:05Z", "text": "note after closure launch"}),
                json!({"seq": 3, "agent": "simplify-reuse", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[(cid_4p2, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4p2 = scan_swarm_activity(&steps_4k, Some(&tp_4p2.to_string_lossy()), t0, 1, sess_4p2, &brain.to_string_lossy());
        let t5 = rio::parse_iso_ts("2026-11-19T10:00:05Z");
        let reuse_end = ev_4p2.sonnet_lenses_end.get("reuse").copied().unwrap_or(0.0);
        assert!(reuse_end >= t5 - TS_EPS, "un-timestamped CLEAN posted after 10:00:05Z board entry must preserve proven order_ts lower bound >= 10:00:05Z, got {}", reuse_end);
        assert!(ev_4p2.simplify_history.last().is_some_and(|h| h.end_ts >= t5 - TS_EPS), "simplify_history end_ts must also preserve >= 10:00:05Z lower bound: {:?}", ev_4p2.simplify_history);

        let sess_4p3a = "sess-4p3a-coarse-revoker-after-clean-merged";
        let cid_4p3a = "cid-4p3a";
        let tp_4p3a = setup_neon_session_env(
            &brain,
            sess_4p3a,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4p3a, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02.100Z", "text": "@simplify-reuse check"}),
                json!({"seq": 2, "agent": "simplify-reuse", "time": "2026-11-19T10:00:02.200Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[(cid_4p3a, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                json!({"step_index": 2, "source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02.210Z", "content": "{\"status\":\"posted\",\"seq\":2}"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
                json!({"step_index": 4, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4p3a = scan_swarm_activity(&steps_4k, Some(&tp_4p3a.to_string_lossy()), t0, 1, "", &brain.to_string_lossy());
        assert!(!ev_4p3a.sonnet_lenses.contains_key("reuse"), "coarse 10:00:02Z ACTIONABLE_FIXES after 10:00:02.200Z CLEAN must not drop before 10:00:02.100Z round assignment: {:?}", ev_4p3a.sonnet_lenses);
        assert!(ev_4p3a.simplify_history.last().is_some_and(|h| !h.clean), "simplify_history must end with ACTIONABLE_FIXES: {:?}", ev_4p3a.simplify_history);

        let sess_4p3b = "sess-4p3b-coarse-revoker-after-transcript-clean";
        let cid_4p3b = "cid-4p3b";
        let tp_4p3b = setup_neon_session_env(
            &brain,
            sess_4p3b,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4p3b, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02.100Z", "text": "@simplify-reuse check"}),
            ],
            &[(cid_4p3b, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4p3b = scan_swarm_activity(&steps_4k, Some(&tp_4p3b.to_string_lossy()), t0, 1, "", &brain.to_string_lossy());
        assert!(!ev_4p3b.sonnet_lenses.contains_key("reuse"), "coarse 10:00:02Z ACTIONABLE_FIXES after transcript-only 10:00:02.200Z CLEAN must revoke CLEAN: {:?}", ev_4p3b.sonnet_lenses);

        let sess_4p4a = "sess-4p4a-coarse-revoker-after-coarse-tsum-merged-clean";
        let cid_4p4a = "cid-4p4a";
        let tp_4p4a = setup_neon_session_env(
            &brain,
            sess_4p4a,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4p4a, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02.100Z", "text": "@simplify-reuse check"}),
                json!({"seq": 2, "agent": "simplify-reuse", "time": "2026-11-19T10:00:02.200Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[(cid_4p4a, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                json!({"step_index": 2, "source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{\"status\":\"posted\",\"seq\":2}"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
                json!({"step_index": 4, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4p4a = scan_swarm_activity(&steps_4k, Some(&tp_4p4a.to_string_lossy()), t0, 1, "", &brain.to_string_lossy());
        assert!(!ev_4p4a.sonnet_lenses.contains_key("reuse"), "coarse ACTIONABLE_FIXES after merged seq=2 CLEAN must inherit order_ts/causal_seq and never sort ahead of CLEAN: {:?}", ev_4p4a.sonnet_lenses);

        let sess_4p4b = "sess-4p4b-pre-round-coarse-revoker-does-not-revoke-r2-clean";
        let cid_4p4b = "cid-4p4b";
        let tp_4p4b = setup_neon_session_env(
            &brain,
            sess_4p4b,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4p4b, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02.100Z", "text": "@simplify-reuse r2"}),
                json!({"seq": 2, "agent": "simplify-reuse", "time": "2026-11-19T10:00:02.200Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[(cid_4p4b, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                json!({"step_index": 3, "source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02.210Z", "content": "{\"status\":\"posted\",\"seq\":2}"}),
                json!({"step_index": 4, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4p4b = scan_swarm_activity(&steps_4k, Some(&tp_4p4b.to_string_lossy()), t0, 1, "", &brain.to_string_lossy());
        assert!(ev_4p4b.sonnet_lenses.contains_key("reuse"), "earlier R1 coarse 10:00:02Z ACTIONABLE_FIXES before R2 10:00:02.100Z assignment must not falsely revoke R2 CLEAN: {:?}", ev_4p4b.sonnet_lenses);

        let sess_4p4c = "sess-4p4c-coarse-revise-after-approved";
        let cid_4p4c = "cid-4p4c";
        let tp_4p4c = setup_neon_session_env(
            &brain,
            sess_4p4c,
            "",
            json!({"members": {
                "opus-rev": {"role": "worker", "conversation_id": cid_4p4c, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02.100Z", "text": "@opus-rev review"}),
            ],
            &[(cid_4p4c, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "content": "VERDICT: APPROVED"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "content": "VERDICT: REVISE"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4p4c = scan_swarm_activity(&steps_4k, Some(&tp_4p4c.to_string_lossy()), t0, 1, "", &brain.to_string_lossy());
        assert_eq!(ev_4p4c.reviews.len(), 1, "expected 1 Opus review window: {:?}", ev_4p4c.reviews);
        assert_eq!(ev_4p4c.reviews[0].get("verdict").and_then(|v| v.as_str()), Some("REVISE"), "coarse 10:00:02Z REVISE after 10:00:02.200Z APPROVED must stay in assignment window and override APPROVED: {:?}", ev_4p4c.reviews);

        let sess_4p5 = "sess-4p5-no-causal-seq-clamp-and-mixed-pos-verdict";
        let (cid_4p5a, cid_4p5b, cid_4p5r) = ("cid-4p5a", "cid-4p5b", "cid-4p5r");
        let tp_4p5 = setup_neon_session_env(
            &brain,
            sess_4p5,
            "",
            json!({"members": {
                "simplify-reuse-a": {"role": "worker", "conversation_id": cid_4p5a, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-reuse-b": {"role": "worker", "conversation_id": cid_4p5b, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "opus-rev": {"role": "worker", "conversation_id": cid_4p5r, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:01Z", "text": "@simplify-reuse-a @simplify-reuse-b check"}),
                json!({"seq": 2, "agent": "simplify-reuse-a", "time": "2026-11-19T10:00:01.500Z", "text": "status ok"}),
                json!({"seq": 3, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@all REVIEW_TIER: XHIGH"}),
                json!({"seq": 4, "agent": "simplify-reuse-b", "time": "2026-11-19T10:00:02Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
                json!({"seq": 5, "agent": "opus-rev", "time": "2026-11-19T10:00:02.100Z", "text": "started"}),
            ],
            &[
                (cid_4p5a, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:01.500Z", "tool_calls": [{"name": "post_message", "args": {"text": "status ok"}}]}),
                    json!({"step_index": 2, "source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:01.510Z", "content": "{\"status\":\"posted\",\"seq\":2}"}),
                    json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10Z", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
                    json!({"step_index": 4, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
                (cid_4p5b, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
                (cid_4p5r, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.100Z", "tool_calls": [{"name": "post_message", "args": {"text": "started"}}]}),
                    json!({"step_index": 2, "source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02.110Z", "content": "{\"status\":\"posted\",\"seq\":5}"}),
                    json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "content": "SIMPLIFY_VERDICT: ACTIONABLE_FIXES.\nVERDICT: APPROVED"}),
                    json!({"step_index": 4, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
            ],
        );
        let ev_4p5 = scan_swarm_activity(&steps_4k, Some(&tp_4p5.to_string_lossy()), t0, 1, "", &brain.to_string_lossy());
        let t5_4p5 = rio::parse_iso_ts("2026-11-19T10:00:05Z");
        assert!(!ev_4p5.sonnet_lenses.contains_key("reuse"), "unsequenced 10:00:10Z ACTIONABLE_FIXES (causal_seq=2) must sort after seq=4 10:00:02Z CLEAN and revoke it: {:?}", ev_4p5.simplify_history);
        assert!(ev_4p5.simplify_history.iter().any(|h| h.clean && h.seq == 4 && h.end_ts < t5_4p5), "seq=4 CLEAN end_ts must not warp up to 10:00:10Z via causal_seq=2: {:?}", ev_4p5.simplify_history);
        assert_eq!(ev_4p5.reviews.len(), 1, "expected 1 Opus review: {:?}", ev_4p5.reviews);
        assert_eq!(ev_4p5.reviews[0].get("xhigh").and_then(|v| v.as_bool()), Some(false), "mixed text containing VERDICT: APPROVED + SIMPLIFY_VERDICT: ACTIONABLE_FIXES must not bypass coarse @all XHIGH ambiguity: {:?}", ev_4p5.reviews);

        let sess_4q1 = "sess-4q1-two-window-same-ms-coarse-revoker";
        let cid_4q1 = "cid-4q1";
        let tp_4q1 = setup_neon_session_env(
            &brain,
            sess_4q1,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4q1, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:01Z", "text": "@simplify-reuse r1"}),
                json!({"seq": 2, "agent": "simplify-reuse", "time": "2026-11-19T10:00:02.200Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
                json!({"seq": 3, "agent": "coordinator", "time": "2026-11-19T10:00:02.200Z", "text": "@simplify-reuse r2"}),
            ],
            &[(cid_4q1, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                json!({"step_index": 2, "source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02.205Z", "content": "{\"status\":\"posted\",\"seq\":2}"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
                json!({"step_index": 4, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4q1 = scan_swarm_activity(&steps_4k, Some(&tp_4q1.to_string_lossy()), t0, 1, "", &brain.to_string_lossy());
        assert!(!ev_4q1.sonnet_lenses.contains_key("reuse"), "same-worker second-window coarse ACTIONABLE_FIXES (seq=0, causal_seq=2) at same ms as seq=2 CLEAN must sort after CLEAN and revoke it: {:?}", ev_4q1.simplify_history);
        assert_eq!(ev_4q1.simplify_history.len(), 2, "expected 2 windows in simplify_history: {:?}", ev_4q1.simplify_history);
        assert!(ev_4q1.simplify_history[0].clean && ev_4q1.simplify_history[0].seq == 2);
        assert!(!ev_4q1.simplify_history[1].clean && ev_4q1.simplify_history[1].seq == 0 && ev_4q1.simplify_history[1].causal_seq == 2);
        let mut rev_4q1 = vec![ev_4q1.simplify_history[1].clone(), ev_4q1.simplify_history[0].clone()];
        SimplifyHistoryItem::sort_chronologically(&mut rev_4q1);
        assert!(rev_4q1[0].clean && !rev_4q1[1].clean, "DAG sort must be input-order independent: {:?}", rev_4q1);

        let sess_4q2 = "sess-4q2-concurrent-cross-worker-same-ms-fail-closed";
        let (cid_4q2a, cid_4q2b) = ("cid-4q2a", "cid-4q2b");
        let tp_4q2 = setup_neon_session_env(
            &brain,
            sess_4q2,
            "",
            json!({"members": {
                "simplify-reuse-a": {"role": "worker", "conversation_id": cid_4q2a, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-reuse-b": {"role": "worker", "conversation_id": cid_4q2b, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:01Z", "text": "@simplify-reuse-a @simplify-reuse-b check"}),
                json!({"seq": 2, "agent": "simplify-reuse-a", "time": "2026-11-19T10:00:02.200Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[
                (cid_4q2a, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
                (cid_4q2b, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
                    json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
            ],
        );
        let ev_4q2 = scan_swarm_activity(&steps_4k, Some(&tp_4q2.to_string_lossy()), t0, 1, "", &brain.to_string_lossy());
        assert!(!ev_4q2.sonnet_lenses.contains_key("reuse"), "concurrent cross-worker seq=0 ACTIONABLE_FIXES at same ms as seq=2 CLEAN must fail closed: {:?}", ev_4q2.simplify_history);

        let sess_4q3 = "sess-4q3-later-seq-coarse-clean-beats-earlier-seq-revoker";
        let (cid_4q3a, cid_4q3b) = ("cid-4q3a", "cid-4q3b");
        let tp_4q3 = setup_neon_session_env(
            &brain,
            sess_4q3,
            "",
            json!({"members": {
                "simplify-reuse-a": {"role": "worker", "conversation_id": cid_4q3a, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-reuse-b": {"role": "worker", "conversation_id": cid_4q3b, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:01Z", "text": "@simplify-reuse-a @simplify-reuse-b check"}),
                json!({"seq": 2, "agent": "simplify-reuse-a", "time": "2026-11-19T10:00:02.200Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
                json!({"seq": 3, "agent": "simplify-reuse-b", "time": "2026-11-19T10:00:02Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[
                (cid_4q3a, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
                (cid_4q3b, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
            ],
        );
        let ev_4q3 = scan_swarm_activity(&steps_4k, Some(&tp_4q3.to_string_lossy()), t0, 1, "", &brain.to_string_lossy());
        assert!(ev_4q3.sonnet_lenses.contains_key("reuse"), "later board seq=3 coarse CLEAN must order after earlier seq=2 ACTIONABLE_FIXES via append-only board DAG edge: {:?}", ev_4q3.simplify_history);

        let mut cyc = vec![
            SimplifyHistoryItem { kind: "lens".to_string(), lens: Some("reuse".to_string()), tier: "sonnet".to_string(), launch_ts: 100.0, end_ts: 102.0, seq: 2, causal_seq: 2, worker_ord: 1, win_ord: 1, clean: true, has_explicit_all: false },
            SimplifyHistoryItem { kind: "lens".to_string(), lens: Some("reuse".to_string()), tier: "sonnet".to_string(), launch_ts: 100.0, end_ts: 101.0, seq: 3, causal_seq: 3, worker_ord: 1, win_ord: 0, clean: false, has_explicit_all: false },
        ];
        SimplifyHistoryItem::sort_chronologically(&mut cyc);
        assert_eq!(cyc.len(), 2, "cycle fallback must deterministically emit all items");
        assert!(cyc.iter().all(|it| !it.clean), "contradictory causal cycle must fail closed and never retain CLEAN: {:?}", cyc);

        let mut cyc_with_r2 = vec![
            SimplifyHistoryItem { kind: "lens".to_string(), lens: Some("reuse".to_string()), tier: "sonnet".to_string(), launch_ts: 100.0, end_ts: 102.0, seq: 2, causal_seq: 2, worker_ord: 1, win_ord: 1, clean: true, has_explicit_all: false },
            SimplifyHistoryItem { kind: "lens".to_string(), lens: Some("reuse".to_string()), tier: "sonnet".to_string(), launch_ts: 100.0, end_ts: 101.0, seq: 3, causal_seq: 3, worker_ord: 1, win_ord: 0, clean: false, has_explicit_all: false },
            SimplifyHistoryItem { kind: "lens".to_string(), lens: Some("reuse".to_string()), tier: "sonnet".to_string(), launch_ts: 108.0, end_ts: 110.0, seq: 5, causal_seq: 5, worker_ord: 2, win_ord: 0, clean: true, has_explicit_all: false },
        ];
        SimplifyHistoryItem::sort_chronologically(&mut cyc_with_r2);
        assert_eq!(cyc_with_r2.len(), 3);
        assert!(!cyc_with_r2[0].clean && !cyc_with_r2[1].clean && cyc_with_r2[2].clean && cyc_with_r2[2].seq == 5, "downstream acyclic seq=5 R2 CLEAN must survive while cyclic core fails closed: {:?}", cyc_with_r2);

        let sess_4r1 = "sess-4r1-same-window-trailing-revoker-no-seq-inherit";
        let (cid_4r1a, cid_4r1b) = ("cid-4r1a", "cid-4r1b");
        let tp_4r1 = setup_neon_session_env(
            &brain,
            sess_4r1,
            "",
            json!({"members": {
                "simplify-reuse-a": {"role": "worker", "conversation_id": cid_4r1a, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-reuse-b": {"role": "worker", "conversation_id": cid_4r1b, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:01Z", "text": "@simplify-reuse-a @simplify-reuse-b check"}),
                json!({"seq": 2, "agent": "simplify-reuse-a", "time": "2026-11-19T10:00:02.200Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
                json!({"seq": 3, "agent": "simplify-reuse-b", "time": "2026-11-19T10:00:02.200Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[
                (cid_4r1a, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                    json!({"step_index": 2, "source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02.205Z", "content": "{\"status\":\"posted\",\"seq\":2}"}),
                    json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
                    json!({"step_index": 4, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
                (cid_4r1b, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
            ],
        );
        let ev_4r1 = scan_swarm_activity(&steps_4k, Some(&tp_4r1.to_string_lossy()), t0, 1, "", &brain.to_string_lossy());
        assert!(!ev_4r1.sonnet_lenses.contains_key("reuse"), "same-window unsequenced ACTIONABLE_FIXES after seq=2 CLEAN must not inherit seq=2 or sort before sibling seq=3 CLEAN: {:?}", ev_4r1.simplify_history);

        let sess_4r2 = "sess-4r2-chained-seq2-seq3-vs-concurrent-seq0-revoker";
        let (cid_4r2a, cid_4r2b, cid_4r2c) = ("cid-4r2a", "cid-4r2b", "cid-4r2c");
        let tp_4r2 = setup_neon_session_env(
            &brain,
            sess_4r2,
            "",
            json!({"members": {
                "simplify-reuse-a": {"role": "worker", "conversation_id": cid_4r2a, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-reuse-b": {"role": "worker", "conversation_id": cid_4r2b, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-reuse-c": {"role": "worker", "conversation_id": cid_4r2c, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:01Z", "text": "@simplify-reuse-a @simplify-reuse-b @simplify-reuse-c check"}),
                json!({"seq": 2, "agent": "simplify-reuse-a", "time": "2026-11-19T10:00:02.200Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
                json!({"seq": 3, "agent": "simplify-reuse-b", "time": "2026-11-19T10:00:02.200Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[
                (cid_4r2a, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
                (cid_4r2b, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
                (cid_4r2c, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
                    json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
            ],
        );
        let ev_4r2 = scan_swarm_activity(&steps_4k, Some(&tp_4r2.to_string_lossy()), t0, 1, "", &brain.to_string_lossy());
        assert!(!ev_4r2.sonnet_lenses.contains_key("reuse"), "concurrent unsequenced ACTIONABLE_FIXES at same ms must sort after chained seq=2->seq=3 CLEAN (Stratum 0 before Stratum 1): {:?}", ev_4r2.simplify_history);

        let mut cyc_with_r2_concurrent = vec![
            SimplifyHistoryItem { kind: "lens".to_string(), lens: Some("reuse".to_string()), tier: "sonnet".to_string(), launch_ts: 100.0, end_ts: 102.0, seq: 2, causal_seq: 2, worker_ord: 1, win_ord: 1, clean: true, has_explicit_all: false },
            SimplifyHistoryItem { kind: "lens".to_string(), lens: Some("reuse".to_string()), tier: "sonnet".to_string(), launch_ts: 100.0, end_ts: 101.0, seq: 3, causal_seq: 3, worker_ord: 1, win_ord: 0, clean: false, has_explicit_all: false },
            SimplifyHistoryItem { kind: "lens".to_string(), lens: Some("reuse".to_string()), tier: "sonnet".to_string(), launch_ts: 108.0, end_ts: 110.0, seq: 5, causal_seq: 5, worker_ord: 2, win_ord: 0, clean: true, has_explicit_all: false },
            SimplifyHistoryItem { kind: "lens".to_string(), lens: Some("reuse".to_string()), tier: "sonnet".to_string(), launch_ts: 108.0, end_ts: 110.0, seq: 0, causal_seq: 0, worker_ord: 3, win_ord: 0, clean: false, has_explicit_all: false },
        ];
        SimplifyHistoryItem::sort_chronologically(&mut cyc_with_r2_concurrent);
        assert_eq!(cyc_with_r2_concurrent.len(), 4);
        assert!(cyc_with_r2_concurrent[2].clean && cyc_with_r2_concurrent[2].seq == 5 && !cyc_with_r2_concurrent[3].clean && cyc_with_r2_concurrent[3].seq == 0, "concurrent ACTIONABLE_FIXES at end_ts=110 must sort after cycle-recovered seq=5 CLEAN (pre-Kahn cycle elimination): {:?}", cyc_with_r2_concurrent);

        let sess_4s3 = "sess-4s3-split-message-revoker-no-seq-inherit";
        let (cid_4s3a, cid_4s3b) = ("cid-4s3a", "cid-4s3b");
        let tp_4s3 = setup_neon_session_env(
            &brain,
            sess_4s3,
            "",
            json!({"members": {
                "simplify-reuse-a": {"role": "worker", "conversation_id": cid_4s3a, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-reuse-b": {"role": "worker", "conversation_id": cid_4s3b, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:01Z", "text": "@simplify-reuse-a @simplify-reuse-b check"}),
                json!({"seq": 2, "agent": "simplify-reuse-a", "time": "2026-11-19T10:00:02.200Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
                json!({"seq": 3, "agent": "simplify-reuse-b", "time": "2026-11-19T10:00:02.200Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[
                (cid_4s3a, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                    json!({"step_index": 2, "source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02.205Z", "content": "{\"status\":\"posted\",\"seq\":2}"}),
                    json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "content": "SIMPLIFY_VERDICT:"}),
                    json!({"step_index": 4, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "content": "ACTIONABLE_FIXES"}),
                    json!({"step_index": 5, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
                (cid_4s3b, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
            ],
        );
        let ev_4s3 = scan_swarm_activity(&steps_4k, Some(&tp_4s3.to_string_lossy()), t0, 1, "", &brain.to_string_lossy());
        assert!(!ev_4s3.sonnet_lenses.contains_key("reuse"), "split-message ACTIONABLE_FIXES after seq=2 CLEAN must derive seq=0 from final split message and revoke sibling seq=3 CLEAN: {:?}", ev_4s3.simplify_history);

        let sess_4s3b = "sess-4s3b-combined-clean-and-split-header-followed-by-revoker";
        let (cid_4s3ba, cid_4s3bb) = ("cid-4s3ba", "cid-4s3bb");
        let tp_4s3b = setup_neon_session_env(
            &brain,
            sess_4s3b,
            "",
            json!({"members": {
                "simplify-reuse-a": {"role": "worker", "conversation_id": cid_4s3ba, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-reuse-b": {"role": "worker", "conversation_id": cid_4s3bb, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:01Z", "text": "@simplify-reuse-a @simplify-reuse-b check"}),
                json!({"seq": 2, "agent": "simplify-reuse-a", "time": "2026-11-19T10:00:02.200Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN\nSIMPLIFY_VERDICT:"}),
                json!({"seq": 3, "agent": "simplify-reuse-b", "time": "2026-11-19T10:00:02.200Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[
                (cid_4s3ba, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN\nSIMPLIFY_VERDICT:"}}]}),
                    json!({"step_index": 2, "source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02.205Z", "content": "{\"status\":\"posted\",\"seq\":2}"}),
                    json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "content": "ACTIONABLE_FIXES"}),
                    json!({"step_index": 4, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
                (cid_4s3bb, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
            ],
        );
        let ev_4s3b = scan_swarm_activity(&steps_4k, Some(&tp_4s3b.to_string_lossy()), t0, 1, "", &brain.to_string_lossy());
        assert!(!ev_4s3b.sonnet_lenses.contains_key("reuse"), "message containing CLEAN plus trailing SIMPLIFY_VERDICT: followed by ACTIONABLE_FIXES must attribute to ACTIONABLE_FIXES (seq=0) and revoke sibling seq=3 CLEAN: {:?}", ev_4s3b.simplify_history);

        // 4s1: verify has_simplify_between rejects excluded future CLEAN at launch_ts == before_ts.
        let mut hist_4s1 = vec![
            SimplifyHistoryItem { kind: "lens".to_string(), lens: Some("reuse".to_string()), tier: cwg_common::SIMPLIFY_TIER_SONNET.to_string(), launch_ts: 101.0, end_ts: 102.2, seq: 2, causal_seq: 2, worker_ord: 1, win_ord: 0, clean: false, has_explicit_all: false },
            SimplifyHistoryItem { kind: "lens".to_string(), lens: Some("reuse".to_string()), tier: cwg_common::SIMPLIFY_TIER_SONNET.to_string(), launch_ts: 101.0, end_ts: 102.2, seq: 3, causal_seq: 3, worker_ord: 2, win_ord: 0, clean: true, has_explicit_all: false },
            SimplifyHistoryItem { kind: "lens".to_string(), lens: Some("reuse".to_string()), tier: cwg_common::SIMPLIFY_TIER_SONNET.to_string(), launch_ts: 101.0, end_ts: 102.2, seq: 0, causal_seq: 0, worker_ord: 3, win_ord: 0, clean: false, has_explicit_all: false },
            SimplifyHistoryItem { kind: "lens".to_string(), lens: Some("reuse".to_string()), tier: cwg_common::SIMPLIFY_TIER_SONNET.to_string(), launch_ts: 102.2, end_ts: 102.2, seq: 0, causal_seq: 0, worker_ord: 3, win_ord: 1, clean: true, has_explicit_all: false },
            SimplifyHistoryItem { kind: "lens".to_string(), lens: Some("quality".to_string()), tier: cwg_common::SIMPLIFY_TIER_SONNET.to_string(), launch_ts: 101.0, end_ts: 102.2, seq: 4, causal_seq: 4, worker_ord: 4, win_ord: 0, clean: true, has_explicit_all: false },
            SimplifyHistoryItem { kind: "lens".to_string(), lens: Some("efficiency".to_string()), tier: cwg_common::SIMPLIFY_TIER_SONNET.to_string(), launch_ts: 101.0, end_ts: 102.2, seq: 5, causal_seq: 5, worker_ord: 5, win_ord: 0, clean: true, has_explicit_all: false },
        ];
        SimplifyHistoryItem::sort_chronologically(&mut hist_4s1);
        let marker_4s1 = json!({"first_ts": 100.0, "last_durable_ts": 100.0});
        let sw_4s1 = SwarmEvidence::default();
        let req_lenses_4s1: HashSet<String> = cwg_common::SIMPLIFY_LENSES.iter().map(|s| (*s).to_string()).collect();
        let empty_steps_4s1: HashSet<usize> = HashSet::new();
        let mut ctx_4s1 = ClosureEvalCtx {
            marker: &marker_4s1,
            steps: None,
            transcript_path: None,
            needs_simplify: true,
            allow_combined: false,
            multi_lens_spoof: false,
            sonnet_issue: false,
            sonnet_issue_ts: 0.0,
            neon_issue: false,
            neon_issue_ts: 0.0,
            effective_risk: "HIGH",
            required_lenses: &req_lenses_4s1,
            active_simplify_windows: &[],
            max_simplify_launch_ts: 102.2,
            max_simplify_end_ts: 102.2,
            all_simplify_steps: &empty_steps_4s1,
            all_simplify_history: &hist_4s1,
            current_simplify_history: &hist_4s1,
            candidate_marks: &[],
            oldest_mark_ts: 100.0,
            first_ts_val: 100.0,
            marks_truncated: false,
            tx_edits_cache: None,
            swarm_ev: &sw_4s1,
            codex_bin_missing_cache: None,
            breaker_info_cache: None,
            sim_ver_cache: HashMap::new(),
            inv_ts_cache: HashMap::new(),
        };
        assert!(!ctx_4s1.has_simplify_between(100.0, 102.2), "excluded future CLEAN at launch_ts == before_ts must not lift in-span ACTIONABLE_FIXES to Stratum 0 in closure has_simplify_between");
        assert!(!ctx_4s1.has_completed_simplify_for_version(&json!({"launch_ts": 102.2, "verdict_ts": 102.3, "verdict": "READY"})), "excluded future CLEAN at launch_ts == rev_launch_ts must not lift in-span ACTIONABLE_FIXES in has_completed_simplify_for_version");

        // 4t1: cycle core detection must be input-order independent (R2 CLEAN placed first).
        let mut cyc_r2_first = vec![
            SimplifyHistoryItem { kind: "lens".to_string(), lens: Some("reuse".to_string()), tier: "sonnet".to_string(), launch_ts: 108.0, end_ts: 110.0, seq: 5, causal_seq: 5, worker_ord: 2, win_ord: 0, clean: true, has_explicit_all: false },
            SimplifyHistoryItem { kind: "lens".to_string(), lens: Some("reuse".to_string()), tier: "sonnet".to_string(), launch_ts: 100.0, end_ts: 102.0, seq: 2, causal_seq: 2, worker_ord: 1, win_ord: 1, clean: true, has_explicit_all: false },
            SimplifyHistoryItem { kind: "lens".to_string(), lens: Some("reuse".to_string()), tier: "sonnet".to_string(), launch_ts: 100.0, end_ts: 101.0, seq: 3, causal_seq: 3, worker_ord: 1, win_ord: 0, clean: false, has_explicit_all: false },
            SimplifyHistoryItem { kind: "lens".to_string(), lens: Some("reuse".to_string()), tier: "sonnet".to_string(), launch_ts: 108.0, end_ts: 110.0, seq: 0, causal_seq: 0, worker_ord: 3, win_ord: 0, clean: false, has_explicit_all: false },
        ];
        SimplifyHistoryItem::sort_chronologically(&mut cyc_r2_first);
        assert_eq!(cyc_r2_first.len(), 4);
        assert!(!cyc_r2_first[0].clean && !cyc_r2_first[1].clean && cyc_r2_first[2].clean && cyc_r2_first[2].seq == 5 && !cyc_r2_first[3].clean && cyc_r2_first[3].seq == 0, "cycle detection must not depend on input order when R2 CLEAN precedes cycle nodes: {:?}", cyc_r2_first);

        // 4t2 & 4t3: stale split CLEAN + old-DIFF_HASH ACTIONABLE_FIXES must never forge a fresh CLEAN.
        let sess_4t2 = "sess-4t2-stale-split-clean-old-hash-revoker";
        let cid_4t2 = "cid-4t2";
        let tp_4t2 = setup_neon_session_env(
            &brain,
            sess_4t2,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4t2, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse r2 DIFF_HASH: new_hash"}),
            ],
            &[(cid_4t2, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.100Z", "content": "SIMPLIFY_VERDICT:"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.100Z", "content": "CLEAN"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES. DIFF_HASH: old_hash"}),
                json!({"step_index": 4, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t2 = scan_swarm_activity(&steps_4k, Some(&tp_4t2.to_string_lossy()), t0, 1, "new_hash", &brain.to_string_lossy());
        assert!(!ev_4t2.sonnet_lenses.contains_key("reuse"), "stale split SIMPLIFY_VERDICT:+CLEAN in coarse round-start second must not pass freshness filter when trailing old-hash ACTIONABLE_FIXES is filtered: {:?}", ev_4t2.sonnet_lenses);

        let sess_4t3 = "sess-4t3-revoker-exc-fragment-cannot-forge-clean";
        let cid_4t3 = "cid-4t3";
        let tp_4t3 = setup_neon_session_env(
            &brain,
            sess_4t3,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4t3, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse r2 DIFF_HASH: new_hash"}),
            ],
            &[(cid_4t3, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.100Z", "content": "SIMPLIFY_VERDICT:"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.150Z", "content": "ACTIONABLE_FIXES DIFF_HASH: old_hash"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03.100Z", "content": "CLEAN"}),
                json!({"step_index": 4, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t3 = scan_swarm_activity(&steps_4k, Some(&tp_4t3.to_string_lossy()), t0, 1, "new_hash", &brain.to_string_lossy());
        assert!(!ev_4t3.sonnet_lenses.contains_key("reuse"), "fragment admitted only via revoker exception must never combine with later CLEAN token after old-hash revoker is filtered: {:?}", ev_4t3.sonnet_lenses);

        // 4s3c: repeated ACTIONABLE_FIXES split across messages must attribute to final match offset (seq=0), not first ACTIONABLE_FIXES (seq=2).
        let sess_4s3c = "sess-4s3c-repeated-revoker-split-uses-last-match-offset";
        let (cid_4s3ca, cid_4s3cb) = ("cid-4s3ca", "cid-4s3cb");
        let tp_4s3c = setup_neon_session_env(
            &brain,
            sess_4s3c,
            "",
            json!({"members": {
                "simplify-reuse-a": {"role": "worker", "conversation_id": cid_4s3ca, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-reuse-b": {"role": "worker", "conversation_id": cid_4s3cb, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:01Z", "text": "@simplify-reuse-a @simplify-reuse-b check"}),
                json!({"seq": 2, "agent": "simplify-reuse-a", "time": "2026-11-19T10:00:02.200Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES\nSIMPLIFY_VERDICT:"}),
                json!({"seq": 3, "agent": "simplify-reuse-b", "time": "2026-11-19T10:00:02.200Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[
                (cid_4s3ca, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES\nSIMPLIFY_VERDICT:"}}]}),
                    json!({"step_index": 2, "source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02.205Z", "content": "{\"status\":\"posted\",\"seq\":2}"}),
                    json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02.200Z", "content": "ACTIONABLE_FIXES"}),
                    json!({"step_index": 4, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
                (cid_4s3cb, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
            ],
        );
        let ev_4s3c = scan_swarm_activity(&steps_4k, Some(&tp_4s3c.to_string_lossy()), t0, 1, "", &brain.to_string_lossy());
        assert!(!ev_4s3c.sonnet_lenses.contains_key("reuse"), "repeated ACTIONABLE_FIXES split after seq=2 must attribute seq=0 from final span and revoke sibling seq=3 CLEAN: {:?}", ev_4s3c.simplify_history);

        // 4t4: DIFF_HASH filtering after round_start_ts_ub must never glue non-adjacent fragments into a forged CLEAN.
        let sess_4t4 = "sess-4t4-post-boundary-diff-hash-no-forged-clean";
        let cid_4t4 = "cid-4t4";
        let tp_4t4 = setup_neon_session_env(
            &brain,
            sess_4t4,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4t4, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse r2 DIFF_HASH: new_hash"}),
            ],
            &[(cid_4t4, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03.100Z", "content": "SIMPLIFY_VERDICT:"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03.150Z", "content": "ACTIONABLE_FIXES DIFF_HASH: old_hash"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03.200Z", "content": "CLEAN"}),
                json!({"step_index": 4, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t4 = scan_swarm_activity(&steps_4k, Some(&tp_4t4.to_string_lossy()), t0, 1, "new_hash", &brain.to_string_lossy());
        assert!(!ev_4t4.sonnet_lenses.contains_key("reuse"), "post-boundary DIFF_HASH skip must preserve original verdict span boundaries and never glue SIMPLIFY_VERDICT: with bare CLEAN: {:?}", ev_4t4.sonnet_lenses);

        // 4t5: split CLEAN carrying old DIFF_HASH on head or adjacent non-verdict message must be rejected.
        let sess_4t5 = "sess-4t5-split-clean-old-hash-on-head";
        let cid_4t5 = "cid-4t5";
        let tp_4t5 = setup_neon_session_env(
            &brain,
            sess_4t5,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4t5, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse r2 DIFF_HASH: new_hash"}),
            ],
            &[(cid_4t5, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03.100Z", "content": "DIFF_HASH: old_hash\nSIMPLIFY_VERDICT:"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03.150Z", "content": "CLEAN"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t5 = scan_swarm_activity(&steps_4k, Some(&tp_4t5.to_string_lossy()), t0, 1, "new_hash", &brain.to_string_lossy());
        assert!(!ev_4t5.sonnet_lenses.contains_key("reuse"), "split CLEAN with old DIFF_HASH on first half must be rejected as a whole verdict: {:?}", ev_4t5.sonnet_lenses);

        // 4t6: stale bold verdict closing `**` must not bleed across `\n\n` into fresh Round 2 CLEAN span start in the same window.
        let sess_4t6 = "sess-4t6-stale-bold-no-bleed-into-fresh-clean";
        let cid_4t6 = "cid-4t6";
        let tp_4t6 = setup_neon_session_env(
            &brain,
            sess_4t6,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4t6, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:01Z", "text": "@simplify-reuse check"}),
                json!({"seq": 2, "agent": "simplify-reuse", "time": "2026-11-19T10:00:02.100Z", "text": "**SIMPLIFY_VERDICT: ACTIONABLE_FIXES**"}),
                json!({"seq": 3, "agent": "simplify-reuse", "time": "2026-11-19T10:00:02.200Z", "text": "**SIMPLIFY_VERDICT: CLEAN**. SIMPLIFY_LENS: REUSE. DIFF_HASH: new_hash"}),
            ],
            &[(cid_4t6, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t6 = scan_swarm_activity(&steps_4k, Some(&tp_4t6.to_string_lossy()), t0, 2, "new_hash", &brain.to_string_lossy());
        assert!(ev_4t6.sonnet_lenses.contains_key("reuse"), "stale bold verdict must not leak its closing ** into next message's fresh CLEAN span: {:?}", ev_4t6.simplify_history);

        // 4t7: adjacent old DIFF_HASH must reject ALL verdict spans inside a multi-verdict message (no CLEAN bypass).
        let sess_4t7 = "sess-4t7-multi-verdict-msg-adjacent-old-hash";
        let cid_4t7 = "cid-4t7";
        let tp_4t7 = setup_neon_session_env(
            &brain,
            sess_4t7,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4t7, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse r2 DIFF_HASH: new_hash"}),
            ],
            &[(cid_4t7, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03.100Z", "content": "SIMPLIFY_VERDICT: CLEAN\nSIMPLIFY_VERDICT: ACTIONABLE_FIXES"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03.150Z", "content": "DIFF_HASH: old_hash"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t7 = scan_swarm_activity(&steps_4k, Some(&tp_4t7.to_string_lossy()), t0, 1, "new_hash", &brain.to_string_lossy());
        assert!(!ev_4t7.sonnet_lenses.contains_key("reuse"), "adjacent DIFF_HASH: old_hash must apply to all verdict spans inside the preceding multi-verdict message: {:?}", ev_4t7.sonnet_lenses);

        // 4t5b: split CLEAN with conflicting DIFF_HASH values (old_hash in head, new_hash in tail) must fail closed.
        let sess_4t5b = "sess-4t5b-conflicting-split-clean-diff-hashes";
        let cid_4t5b = "cid-4t5b";
        let tp_4t5b = setup_neon_session_env(
            &brain,
            sess_4t5b,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4t5b, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse r2 DIFF_HASH: new_hash"}),
            ],
            &[(cid_4t5b, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03.100Z", "content": "DIFF_HASH: old_hash\nSIMPLIFY_VERDICT:"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03.150Z", "content": "CLEAN\nDIFF_HASH: new_hash"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t5b = scan_swarm_activity(&steps_4k, Some(&tp_4t5b.to_string_lossy()), t0, 1, "new_hash", &brain.to_string_lossy());
        assert!(!ev_4t5b.sonnet_lenses.contains_key("reuse"), "split CLEAN with conflicting old_hash in head and new_hash in tail must fail closed: {:?}", ev_4t5b.sonnet_lenses);

        // 4t5c: adjacent conflicting hashes around hashless CLEAN must fail closed.
        let sess_4t5c = "sess-4t5c-adjacent-conflicting-hashes-around-clean";
        let cid_4t5c = "cid-4t5c";
        let tp_4t5c = setup_neon_session_env(
            &brain,
            sess_4t5c,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4t5c, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse r2 DIFF_HASH: new_hash"}),
            ],
            &[(cid_4t5c, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03.100Z", "content": "DIFF_HASH: old_hash"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03.150Z", "content": "SIMPLIFY_VERDICT: CLEAN"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03.200Z", "content": "DIFF_HASH: new_hash"}),
                json!({"step_index": 4, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t5c = scan_swarm_activity(&steps_4k, Some(&tp_4t5c.to_string_lossy()), t0, 1, "new_hash", &brain.to_string_lossy());
        assert!(!ev_4t5c.sonnet_lenses.contains_key("reuse"), "hashless CLEAN flanked by conflicting old_hash and new_hash must fail closed: {:?}", ev_4t5c.sonnet_lenses);

        // 4t5d: split revoker with conflicting old_hash and new_hash must fail closed (remain active and revoke sibling CLEAN).
        let sess_4t5d = "sess-4t5d-conflicting-split-revoker-fails-closed";
        let (cid_4t5da, cid_4t5db) = ("cid-4t5da", "cid-4t5db");
        let tp_4t5d = setup_neon_session_env(
            &brain,
            sess_4t5d,
            "",
            json!({"members": {
                "simplify-reuse-a": {"role": "worker", "conversation_id": cid_4t5da, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-reuse-b": {"role": "worker", "conversation_id": cid_4t5db, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse-a @simplify-reuse-b r2 DIFF_HASH: new_hash"}),
                json!({"seq": 2, "agent": "simplify-reuse-b", "time": "2026-11-19T10:00:03.150Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}),
            ],
            &[
                (cid_4t5da, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03.100Z", "content": "DIFF_HASH: old_hash\nSIMPLIFY_VERDICT:"}),
                    json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03.150Z", "content": "ACTIONABLE_FIXES\nDIFF_HASH: new_hash"}),
                    json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
                (cid_4t5db, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
            ],
        );
        let ev_4t5d = scan_swarm_activity(&steps_4k, Some(&tp_4t5d.to_string_lossy()), t0, 1, "new_hash", &brain.to_string_lossy());
        assert!(!ev_4t5d.sonnet_lenses.contains_key("reuse"), "split revoker with conflicting old_hash and new_hash must fail closed and revoke sibling CLEAN: {:?}", ev_4t5d.sonnet_lenses);

        // 4t8a & 4t8b: adjacent fresh non-verdict messages must be folded even when verdict message carries its own DIFF_HASH.
        let sess_4t8a = "sess-4t8a-clean-new-hash-plus-adjacent-old-hash";
        let cid_4t8a = "cid-4t8a";
        let tp_4t8a = setup_neon_session_env(
            &brain,
            sess_4t8a,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4t8a, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse r2 DIFF_HASH: new_hash"}),
            ],
            &[(cid_4t8a, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03.100Z", "content": "SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03.150Z", "content": "DIFF_HASH: old_hash"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t8a = scan_swarm_activity(&steps_4k, Some(&tp_4t8a.to_string_lossy()), t0, 1, "new_hash", &brain.to_string_lossy());
        assert!(!ev_4t8a.sonnet_lenses.contains_key("reuse"), "CLEAN with new_hash followed by adjacent old_hash in same window must fail closed: {:?}", ev_4t8a.sonnet_lenses);

        let sess_4t8b = "sess-4t8b-revoker-old-hash-plus-adjacent-new-hash";
        let (cid_4t8ba, cid_4t8bb) = ("cid-4t8ba", "cid-4t8bb");
        let tp_4t8b = setup_neon_session_env(
            &brain,
            sess_4t8b,
            "",
            json!({"members": {
                "simplify-reuse-a": {"role": "worker", "conversation_id": cid_4t8ba, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-reuse-b": {"role": "worker", "conversation_id": cid_4t8bb, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse-a @simplify-reuse-b r2 DIFF_HASH: new_hash"}),
                json!({"seq": 2, "agent": "simplify-reuse-b", "time": "2026-11-19T10:00:03.150Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}),
            ],
            &[
                (cid_4t8ba, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03.150Z", "content": "SIMPLIFY_VERDICT: ACTIONABLE_FIXES. DIFF_HASH: old_hash"}),
                    json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03.200Z", "content": "DIFF_HASH: new_hash"}),
                    json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
                (cid_4t8bb, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
            ],
        );
        let ev_4t8b = scan_swarm_activity(&steps_4k, Some(&tp_4t8b.to_string_lossy()), t0, 1, "new_hash", &brain.to_string_lossy());
        assert!(!ev_4t8b.sonnet_lenses.contains_key("reuse"), "ACTIONABLE_FIXES with old_hash plus adjacent new_hash must stay active and revoke sibling CLEAN: {:?}", ev_4t8b.sonnet_lenses);

        // 4t9: has_completed_simplify_after must reject conflicting-hash CLEAN when admitting 2nd --closure pass.
        let sess_4t9_bad = "sess-4t9-closure-pass2-rejects-conflicting-hash-clean";
        let (cid_4t9r, cid_4t9q, cid_4t9e) = ("cid-4t9r", "cid-4t9q", "cid-4t9e");
        let tp_4t9_bad = setup_neon_session_env(
            &brain,
            sess_4t9_bad,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4t9r, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-quality": {"role": "worker", "conversation_id": cid_4t9q, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-efficiency": {"role": "worker", "conversation_id": cid_4t9e, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse @simplify-quality @simplify-efficiency r2 DIFF_HASH: new_hash"}),
                json!({"seq": 2, "agent": "simplify-quality", "time": "2026-11-19T10:00:03.200Z", "text": "SIMPLIFY_LENS: QUALITY. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}),
                json!({"seq": 3, "agent": "simplify-efficiency", "time": "2026-11-19T10:00:03.200Z", "text": "SIMPLIFY_LENS: EFFICIENCY. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}),
            ],
            &[
                (cid_4t9r, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03.100Z", "content": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}),
                    json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:03.150Z", "content": "DIFF_HASH: old_hash"}),
                    json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
                (cid_4t9q, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
                (cid_4t9e, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
            ],
        );
        let t_blk_4t9 = rio::parse_iso_ts("2026-11-19T10:00:01.500Z");
        let marker_4t9 = json!({
            "first_ts": t0,
            "last_durable_ts": t0,
            "edits": 1,
            "paths": ["rust/src/cwg_stop.rs"],
            "round_start_msg_id": 1,
            "current_diff_hash": "new_hash",
            "diff_metrics": {"files_count": 3, "total_lines": 50},
            "cwd": brain.to_string_lossy()
        });
        assert!(
            !has_completed_simplify_after(
                sess_4t9_bad,
                &marker_4t9,
                &tp_4t9_bad.to_string_lossy(),
                t_blk_4t9
            ),
            "conflicting-hash CLEAN must NOT unlock 2nd --closure pass via has_completed_simplify_after"
        );
        let sess_4t9_ok = "sess-4t9-closure-pass2-accepts-valid-hash-clean";
        let (cid_4t9r2, cid_4t9q2, cid_4t9e2) = ("cid-4t9r2", "cid-4t9q2", "cid-4t9e2");
        let tp_4t9_ok = setup_neon_session_env(
            &brain,
            sess_4t9_ok,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4t9r2, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-quality": {"role": "worker", "conversation_id": cid_4t9q2, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-efficiency": {"role": "worker", "conversation_id": cid_4t9e2, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse @simplify-quality @simplify-efficiency r2 DIFF_HASH: new_hash"}),
                json!({"seq": 2, "agent": "simplify-reuse", "time": "2026-11-19T10:00:03.200Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}),
                json!({"seq": 3, "agent": "simplify-quality", "time": "2026-11-19T10:00:03.200Z", "text": "SIMPLIFY_LENS: QUALITY. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}),
                json!({"seq": 4, "agent": "simplify-efficiency", "time": "2026-11-19T10:00:03.200Z", "text": "SIMPLIFY_LENS: EFFICIENCY. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}),
            ],
            &[
                (cid_4t9r2, &[json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"})]),
                (cid_4t9q2, &[json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"})]),
                (cid_4t9e2, &[json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"})]),
            ],
        );
        assert!(
            has_completed_simplify_after(
                sess_4t9_ok,
                &marker_4t9,
                &tp_4t9_ok.to_string_lossy(),
                t_blk_4t9
            ),
            "valid hash-matched 3-lens CLEAN after BLOCKED must unlock 2nd --closure pass"
        );

        // 4t10: swarm(action="model") DONE without created_at must NOT collapse switch interval or promote Neon verdict to Carbon XHIGH.
        let sess_4t10 = "sess-4t10-model-switch-done-without-timestamp-fails-closed";
        let cid_4t10 = "cid-4t10";
        let tp_4t10 = setup_neon_session_env(
            &brain,
            sess_4t10,
            "",
            json!({"members": {
                "reviewer-xhigh": {"role": "worker", "conversation_id": cid_4t10, "model": cwg_common::CARBON_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@reviewer-xhigh REVIEW_TIER: XHIGH check"}),
            ],
            &[(cid_4t10, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:05Z", "content": "VERDICT: APPROVED"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:11Z", "content": "VERDICT: APPROVED"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let steps_4t10 = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:01Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "reviewer-xhigh", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:01Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "reviewer-xhigh", "model": cwg_common::CARBON_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "content": "{}"}),
        ];
        let ev_4t10 = scan_swarm_activity(&steps_4t10, Some(&tp_4t10.to_string_lossy()), t0, 0, "", &brain.to_string_lossy());
        assert_eq!(
            ev_4t10.reviews.len(),
            1,
            "post-request verdict after untimestamped model-switch DONE must fail closed instead of promoting to Carbon XHIGH: {:?}",
            ev_4t10.reviews
        );
        assert_eq!(val_to_str(ev_4t10.reviews[0].get("engine")), cwg_common::REVIEW_ENGINE_INTERNAL_NEON);
        assert!(!json_truthy(ev_4t10.reviews[0].get("xhigh")));

        // 4t10b: untimestamped model switch (missing both request and DONE created_at) after an earlier Carbon switch must NOT be "recovered" by that earlier Carbon switch.
        let sess_4t10b = "sess-4t10b-untimestamped-switch-after-carbon-not-recovered-by-earlier-switch";
        let cid_4t10b = "cid-4t10b";
        let tp_4t10b = setup_neon_session_env(
            &brain,
            sess_4t10b,
            "",
            json!({"members": {
                "reviewer-xhigh": {"role": "worker", "conversation_id": cid_4t10b, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@reviewer-xhigh REVIEW_TIER: XHIGH check"}),
            ],
            &[(cid_4t10b, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10Z", "content": "VERDICT: APPROVED"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let steps_4t10b = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:01Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "reviewer-xhigh", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:01Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:05.000Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "reviewer-xhigh", "model": cwg_common::CARBON_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:05.100Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "reviewer-xhigh", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "content": "{}"}),
        ];
        let ev_4t10b = scan_swarm_activity(&steps_4t10b, Some(&tp_4t10b.to_string_lossy()), t0, 0, "", &brain.to_string_lossy());
        assert!(
            ev_4t10b.reviews.is_empty(),
            "earlier confirmed Carbon switch must NOT recover a later untimestamped switch to Neon: {:?}",
            ev_4t10b.reviews
        );

        // 4t10c: sub-second model-switch request with whole-second coarse DONE must fail closed inside [req_ts, done_ts.floor()+1.0) and succeed strictly after.
        let sess_4t10c = "sess-4t10c-coarse-done-switch-preserves-second-upper-bound";
        let cid_4t10c = "cid-4t10c";
        let tp_4t10c = setup_neon_session_env(
            &brain,
            sess_4t10c,
            "",
            json!({"members": {
                "reviewer-xhigh": {"role": "worker", "conversation_id": cid_4t10c, "model": cwg_common::CARBON_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@reviewer-xhigh REVIEW_TIER: XHIGH check"}),
            ],
            &[(cid_4t10c, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10.200Z", "content": "VERDICT: APPROVED"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:11.050Z", "content": "VERDICT: APPROVED"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let steps_4t10c = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:01Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "reviewer-xhigh", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:01Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10.100Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "reviewer-xhigh", "model": cwg_common::CARBON_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:10Z", "content": "{}"}),
        ];
        let ev_4t10c = scan_swarm_activity(&steps_4t10c, Some(&tp_4t10c.to_string_lossy()), t0, 0, "", &brain.to_string_lossy());
        assert_eq!(
            ev_4t10c.reviews.len(),
            1,
            "10:00:10.200Z verdict inside coarse DONE 10:00:10Z second must fail closed while 10:00:11.050Z succeeds as Carbon XHIGH: {:?}",
            ev_4t10c.reviews
        );
        assert_eq!(val_to_str(ev_4t10c.reviews[0].get("engine")), cwg_common::REVIEW_ENGINE_INTERNAL_CARBON);
        assert!(json_truthy(ev_4t10c.reviews[0].get("xhigh")));
        assert!((val_to_f64(ev_4t10c.reviews[0].get("verdict_ts")) - rio::parse_iso_ts("2026-11-19T10:00:11.050Z")).abs() < 0.01);

        // 4t10d: delayed board.jsonl flush after coarse DONE done_ub must merge with its in-flight post_message call and preserve formation time (failing closed, never promoting to Carbon XHIGH).
        let sess_4t10d = "sess-4t10d-delayed-board-flush-preserves-formation-timestamp";
        let cid_4t10d = "cid-4t10d";
        let tp_4t10d = setup_neon_session_env(
            &brain,
            sess_4t10d,
            "",
            json!({"members": {
                "reviewer-xhigh": {"role": "worker", "conversation_id": cid_4t10d, "model": cwg_common::CARBON_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@reviewer-xhigh REVIEW_TIER: XHIGH check"}),
                json!({"seq": 2, "agent": "reviewer-xhigh", "time": "2026-11-19T10:00:11.050Z", "text": "VERDICT: APPROVED"}),
            ],
            &[(cid_4t10d, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: APPROVED"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t10d = scan_swarm_activity(&steps_4t10c, Some(&tp_4t10d.to_string_lossy()), t0, 0, "", &brain.to_string_lossy());
        assert!(
            ev_4t10d.reviews.is_empty(),
            "in-flight 10:00:10.200Z post_message flushed to board at 10:00:11.050Z must NOT be promoted to Carbon XHIGH: {:?}",
            ev_4t10d.reviews
        );

        // 4t10e: sequential confirmed switches (Switch 1 coarse DONE 10Z with done_ub=11.0, Switch 2 exact 10.500Z->10.600Z) must attribute post-11.0 verdicts to Switch 2 without false ambiguous_overlap.
        let sess_4t10e = "sess-4t10e-coarse-done-then-exact-switch-ranks-by-done-ts";
        let cid_4t10e = "cid-4t10e";
        let tp_4t10e = setup_neon_session_env(
            &brain,
            sess_4t10e,
            "",
            json!({"members": {
                "reviewer-xhigh": {"role": "worker", "conversation_id": cid_4t10e, "model": cwg_common::CARBON_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@reviewer-xhigh REVIEW_TIER: XHIGH check"}),
            ],
            &[(cid_4t10e, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:11.050Z", "content": "VERDICT: APPROVED"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let steps_4t10e = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:01Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "reviewer-xhigh", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:01Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10.000Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "reviewer-xhigh", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:10Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10.500Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "reviewer-xhigh", "model": cwg_common::CARBON_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:10.600Z", "content": "{}"}),
        ];
        let ev_4t10e = scan_swarm_activity(&steps_4t10e, Some(&tp_4t10e.to_string_lossy()), t0, 0, "", &brain.to_string_lossy());
        assert_eq!(
            ev_4t10e.reviews.len(),
            1,
            "sequential Switch 1 (coarse 10Z) -> Switch 2 (exact 10.500Z->10.600Z) must attribute post-11.0 verdict to Carbon XHIGH: {:?}",
            ev_4t10e.reviews
        );
        assert_eq!(val_to_str(ev_4t10e.reviews[0].get("engine")), cwg_common::REVIEW_ENGINE_INTERNAL_CARBON);
        assert!(json_truthy(ev_4t10e.reviews[0].get("xhigh")));

        // 4t10f: earlier exact Carbon switch/add (10.500Z->10.600Z) followed by a strictly later same-second coarse Neon switch (req=10Z, DONE=10Z, done_ub=11.0) must fail closed at 11.050Z instead of promoting to Carbon XHIGH.
        let sess_4t10f = "sess-4t10f-later-same-second-coarse-switch-blocks-earlier-exact-carbon";
        let cid_4t10f = "cid-4t10f";
        let tp_4t10f = setup_neon_session_env(
            &brain,
            sess_4t10f,
            "",
            json!({"members": {
                "reviewer-xhigh": {"role": "worker", "conversation_id": cid_4t10f, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@reviewer-xhigh REVIEW_TIER: XHIGH check"}),
            ],
            &[(cid_4t10f, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:11.050Z", "content": "VERDICT: APPROVED"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let steps_4t10f = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:01Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "reviewer-xhigh", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:01Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10.500Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "reviewer-xhigh", "model": cwg_common::CARBON_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:10.600Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "reviewer-xhigh", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:10Z", "content": "{}"}),
        ];
        let ev_4t10f = scan_swarm_activity(&steps_4t10f, Some(&tp_4t10f.to_string_lossy()), t0, 0, "", &brain.to_string_lossy());
        assert!(
            ev_4t10f.reviews.is_empty(),
            "earlier exact Carbon switch must NOT outrank a strictly later same-second coarse Neon switch: {:?}",
            ev_4t10f.reviews
        );

        // 4t10g: post-switch ACTIONABLE_FIXES in a simplify window must NOT mask a delayed in-flight CLEAN board flush (attr_ts=10.200Z, order_ts=11.200Z) or cross-switch split verdict and promote it to Neon fallback.
        let sess_4t10g = "sess-4t10g-delayed-inflight-simplify-clean-not-promoted-by-sibling";
        let cid_4t10g = "cid-4t10g";
        let tp_4t10g = setup_neon_session_env(
            &brain,
            sess_4t10g,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4t10g, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse check"}),
                json!({"seq": 2, "agent": "simplify-reuse", "time": "2026-11-19T10:00:11.050Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES."}),
                json!({"seq": 3, "agent": "simplify-reuse", "time": "2026-11-19T10:00:11.200Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}),
            ],
            &[(cid_4t10g, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN."}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let steps_4t10g = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:01Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-reuse", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:01Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10.100Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "simplify-reuse", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:10Z", "content": "{}"}),
        ];
        let ev_4t10g = scan_swarm_activity(&steps_4t10g, Some(&tp_4t10g.to_string_lossy()), t0, 0, "", &brain.to_string_lossy());
        assert!(
            ev_4t10g.fallback_lenses.is_empty() && ev_4t10g.sonnet_lenses.is_empty(),
            "delayed in-flight CLEAN flush (10:00:10.200Z -> board 11.200Z) must NOT inherit post-switch ACTIONABLE_FIXES Neon tier: {:?}",
            ev_4t10g.fallback_lenses
        );
        assert!(
            ev_4t10g.simplify_history.last().is_some_and(|h| !h.clean),
            "simplify_history must keep ACTIONABLE_FIXES instead of un-attributable CLEAN: {:?}",
            ev_4t10g.simplify_history
        );
        let sess_4t10g_split = "sess-4t10g-cross-switch-split-simplify-verdict-fails-closed";
        let cid_4t10g_split = "cid-4t10g-split";
        let tp_4t10g_split = setup_neon_session_env(
            &brain,
            sess_4t10g_split,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4t10g_split, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse check"}),
                json!({"seq": 2, "agent": "simplify-reuse", "time": "2026-11-19T10:00:11.020Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT:"}),
            ],
            &[(cid_4t10g_split, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT:"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:11.050Z", "content": "CLEAN"}),
                json!({"step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t10g_split = scan_swarm_activity(&steps_4t10g, Some(&tp_4t10g_split.to_string_lossy()), t0, 0, "", &brain.to_string_lossy());
        assert!(
            ev_4t10g_split.fallback_lenses.is_empty() && ev_4t10g_split.sonnet_lenses.is_empty() && ev_4t10g_split.simplify_history.is_empty(),
            "split simplify verdict with in-flight first half must fail closed: {:?}",
            ev_4t10g_split.fallback_lenses
        );

        // 4t10h: intervening coordinator post between verdict formation (10:00:10.200Z) and board flush (10:00:11.050Z) must still merge delayed flush provenance and fail closed instead of promoting to Carbon XHIGH.
        let sess_4t10h = "sess-4t10h-intervening-coord-post-preserves-delayed-flush-provenance";
        let cid_4t10h = "cid-4t10h";
        let tp_4t10h = setup_neon_session_env(
            &brain,
            sess_4t10h,
            "",
            json!({"members": {
                "reviewer-xhigh": {"role": "worker", "conversation_id": cid_4t10h, "model": cwg_common::CARBON_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@reviewer-xhigh REVIEW_TIER: XHIGH check"}),
                json!({"seq": 2, "agent": "coordinator", "time": "2026-11-19T10:00:11.020Z", "text": "@reviewer-xhigh status?"}),
                json!({"seq": 3, "agent": "reviewer-xhigh", "time": "2026-11-19T10:00:11.050Z", "text": "VERDICT: APPROVED"}),
            ],
            &[(cid_4t10h, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: APPROVED"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t10h = scan_swarm_activity(&steps_4t10c, Some(&tp_4t10h.to_string_lossy()), t0, 0, "", &brain.to_string_lossy());
        assert!(
            ev_4t10h.reviews.is_empty(),
            "delayed flush across intervening coordinator post (10.200Z -> coord 11.020Z -> board 11.050Z) must NOT promote to Carbon XHIGH: {:?}",
            ev_4t10h.reviews
        );

        // 4t10h_xhigh: without a model switch, a delayed board flush formed before an intervening `@all REVIEW_TIER: XHIGH` must stay in its pre-XHIGH window (`xhigh=false`).
        let sess_4t10h_x = "sess-4t10h-delayed-flush-before-xhigh-brief-stays-high";
        let cid_4t10h_x = "cid-4t10h-x";
        let tp_4t10h_x = setup_neon_session_env(
            &brain,
            sess_4t10h_x,
            "",
            json!({"members": {
                "opus-rev": {"role": "worker", "conversation_id": cid_4t10h_x, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@opus-rev Review HIGH"}),
                json!({"seq": 2, "agent": "coordinator", "time": "2026-11-19T10:00:06.000Z", "text": "@all REVIEW_TIER: XHIGH"}),
                json!({"seq": 3, "agent": "opus-rev", "time": "2026-11-19T10:00:06.100Z", "text": "VERDICT: APPROVED"}),
            ],
            &[(cid_4t10h_x, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:05.000Z", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: APPROVED"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t10h_x = scan_swarm_activity(&steps_4k, Some(&tp_4t10h_x.to_string_lossy()), t0, 1, sess_4t10h_x, &brain.to_string_lossy());
        assert_eq!(ev_4t10h_x.reviews.len(), 1, "expected 1 Opus review: {:?}", ev_4t10h_x.reviews);
        assert_eq!(ev_4t10h_x.reviews[0].get("xhigh").and_then(|v| v.as_bool()), Some(false), "delayed flush formed before @all XHIGH must remain HIGH: {:?}", ev_4t10h_x.reviews);

        // 4t10h_coarse_first: same-second coarse board flush (06Z) formed at 06.200Z before first window @all XHIGH (06.500Z) must prepend a bare pre-window via has_before_first_win and remain HIGH.
        let sess_4t10h_cf = "sess-4t10h-coarse-first-win-delayed-flush-stays-high";
        let cid_4t10h_cf = "cid-4t10h-cf";
        let tp_4t10h_cf = setup_neon_session_env(
            &brain,
            sess_4t10h_cf,
            "",
            json!({"members": {
                "opus-rev": {"role": "worker", "conversation_id": cid_4t10h_cf, "model": cwg_common::OPUS_HIGH_MODEL, "brief": "Review HIGH", "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:06.500Z", "text": "@all REVIEW_TIER: XHIGH"}),
                json!({"seq": 2, "agent": "opus-rev", "time": "2026-11-19T10:00:06Z", "text": "VERDICT: APPROVED"}),
            ],
            &[(cid_4t10h_cf, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:06.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: APPROVED"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t10h_cf = scan_swarm_activity(&steps_4k, Some(&tp_4t10h_cf.to_string_lossy()), t0, 0, sess_4t10h_cf, &brain.to_string_lossy());
        assert_eq!(ev_4t10h_cf.reviews.len(), 1, "expected 1 Opus review: {:?}", ev_4t10h_cf.reviews);
        assert_eq!(ev_4t10h_cf.reviews[0].get("xhigh").and_then(|v| v.as_bool()), Some(false), "same-second coarse delayed flush formed before first window @all XHIGH must remain HIGH: {:?}", ev_4t10h_cf.reviews);

        // 4t10i: delayed in-flight ACTIONABLE_FIXES with current DIFF_HASH after a filtered old-hash CLEAN in a Sonnet->Neon worker must be preserved and revoke another worker's CLEAN across the current round (both scan_swarm_activity and has_completed_simplify_after).
        let sess_4t10i = "sess-4t10i-cross-worker-inflight-revoker-after-old-hash-clean";
        let (cid_4t10ia, cid_4t10ib, cid_4t10iq, cid_4t10ie) = ("cid-4t10ia", "cid-4t10ib", "cid-4t10iq", "cid-4t10ie");
        let steps_4t10i = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:01Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-reuse-a", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:01Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:01Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-reuse-b", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:01Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:01Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-quality", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:01Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:01Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-efficiency", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:01Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10.100Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "simplify-reuse-b", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:10Z", "content": "{}"}),
        ];
        let coord_4t10i = steps_4t10i
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let tp_4t10i = setup_neon_session_env(
            &brain,
            sess_4t10i,
            &coord_4t10i,
            json!({"members": {
                "simplify-reuse-a": {"role": "worker", "conversation_id": cid_4t10ia, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-reuse-b": {"role": "worker", "conversation_id": cid_4t10ib, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false},
                "simplify-quality": {"role": "worker", "conversation_id": cid_4t10iq, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-efficiency": {"role": "worker", "conversation_id": cid_4t10ie, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse-a @simplify-reuse-b @simplify-quality @simplify-efficiency r2 DIFF_HASH: new_hash"}),
                json!({"seq": 2, "agent": "simplify-reuse-a", "time": "2026-11-19T10:00:05.000Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}),
                json!({"seq": 3, "agent": "simplify-reuse-b", "time": "2026-11-19T10:00:11.050Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: old_hash"}),
                json!({"seq": 4, "agent": "simplify-reuse-b", "time": "2026-11-19T10:00:11.200Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES. DIFF_HASH: new_hash"}),
                json!({"seq": 5, "agent": "simplify-quality", "time": "2026-11-19T10:00:12.000Z", "text": "SIMPLIFY_LENS: QUALITY. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}),
                json!({"seq": 6, "agent": "simplify-efficiency", "time": "2026-11-19T10:00:12.000Z", "text": "SIMPLIFY_LENS: EFFICIENCY. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}),
            ],
            &[
                (cid_4t10ia, &[json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"})]),
                (cid_4t10ib, &[
                    json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"}),
                    json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES. DIFF_HASH: new_hash"}}]}),
                    json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
                ]),
                (cid_4t10iq, &[json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"})]),
                (cid_4t10ie, &[json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"})]),
            ],
        );
        let ev_4t10i = scan_swarm_activity(&steps_4t10i, Some(&tp_4t10i.to_string_lossy()), t0, 1, "new_hash", &brain.to_string_lossy());
        assert!(
            !ev_4t10i.sonnet_lenses.contains_key("reuse") && !ev_4t10i.fallback_lenses.contains_key("reuse"),
            "delayed in-flight ACTIONABLE_FIXES with new_hash after filtered old_hash CLEAN must revoke simplify-reuse-a CLEAN: sonnet={:?}, fallback={:?}",
            ev_4t10i.sonnet_lenses,
            ev_4t10i.fallback_lenses
        );
        assert!(
            ev_4t10i
                .simplify_history
                .iter()
                .any(|x| !x.clean && x.lens.as_deref() == Some("reuse") && x.seq == 4 && x.tier.is_empty()),
            "simplify_history must retain un-attributable revoker seq=4 with empty tier (never inheriting disallowed fallback): {:?}",
            ev_4t10i.simplify_history
        );
        assert!(
            ev_4t10i
                .simplify_current_history
                .as_ref()
                .is_some_and(|h| h.iter().any(|x| !x.clean && x.lens.as_deref() == Some("reuse") && x.seq == 4 && x.tier.is_empty())),
            "simplify_current_history must retain the cross-worker revoker seq=4: {:?}",
            ev_4t10i.simplify_current_history
        );
        assert!(
            !has_completed_simplify_after(
                sess_4t10i,
                &marker_4t9,
                &tp_4t10i.to_string_lossy(),
                t_blk_4t9
            ),
            "cross-worker in-flight ACTIONABLE_FIXES in current round history must block has_completed_simplify_after"
        );

        // 4t10k: coarse transcript post_message (10:00:06Z) flushed to board at 10:00:06.700Z after `@all REVIEW_TIER: XHIGH` at 10:00:06.500Z must fail closed (xhigh=false) because earliest formation bound 10:00:06.000Z < 10:00:06.500Z.
        let sess_4t10k = "sess-4t10k-coarse-transcript-formation-before-xhigh-stays-high";
        let cid_4t10k = "cid-4t10k";
        let tp_4t10k = setup_neon_session_env(
            &brain,
            sess_4t10k,
            "",
            json!({"members": {
                "opus-rev": {"role": "worker", "conversation_id": cid_4t10k, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@opus-rev Review HIGH"}),
                json!({"seq": 2, "agent": "coordinator", "time": "2026-11-19T10:00:06.500Z", "text": "@all REVIEW_TIER: XHIGH"}),
                json!({"seq": 3, "agent": "opus-rev", "time": "2026-11-19T10:00:06.700Z", "text": "VERDICT: APPROVED"}),
            ],
            &[(cid_4t10k, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:06Z", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: APPROVED"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t10k = scan_swarm_activity(&steps_4k, Some(&tp_4t10k.to_string_lossy()), t0, 1, sess_4t10k, &brain.to_string_lossy());
        assert_eq!(ev_4t10k.reviews.len(), 1, "expected 1 Opus review: {:?}", ev_4t10k.reviews);
        assert_eq!(
            ev_4t10k.reviews[0].get("xhigh").and_then(|v| v.as_bool()),
            Some(false),
            "coarse 10:00:06Z post_message flushed at 10:00:06.700Z after 10:00:06.500Z @all XHIGH must remain HIGH: {:?}",
            ev_4t10k.reviews
        );

        // 4t10l: ACTIONABLE_FIXES definitively emitted by a disallowed non-simplify model (Carbon) before a later switch to Neon must classify as SpanTier::Disallowed and NEVER revoke another simplify worker's valid CLEAN.
        let sess_4t10l = "sess-4t10l-carbon-actionable-fixes-before-neon-switch-does-not-revoke";
        let (cid_4t10la, cid_4t10lb, cid_4t10lq, cid_4t10le) = ("cid-4t10la", "cid-4t10lb", "cid-4t10lq", "cid-4t10le");
        let steps_4t10l = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:01Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-reuse-a", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:01Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:01Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-reuse-b", "model": cwg_common::CARBON_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:01Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:01Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-quality", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:01Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:01Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-efficiency", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:01Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:10.100Z", "tool_calls": [{"name": "swarm", "args": {"action": "model", "name": "simplify-reuse-b", "model": cwg_common::NEON_XHIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:10.200Z", "content": "{}"}),
        ];
        let coord_4t10l = steps_4t10l
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let tp_4t10l = setup_neon_session_env(
            &brain,
            sess_4t10l,
            &coord_4t10l,
            json!({"members": {
                "simplify-reuse-a": {"role": "worker", "conversation_id": cid_4t10la, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-reuse-b": {"role": "worker", "conversation_id": cid_4t10lb, "model": cwg_common::NEON_XHIGH_MODEL, "killed": false},
                "simplify-quality": {"role": "worker", "conversation_id": cid_4t10lq, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false},
                "simplify-efficiency": {"role": "worker", "conversation_id": cid_4t10le, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@simplify-reuse-a @simplify-reuse-b @simplify-quality @simplify-efficiency r2 DIFF_HASH: new_hash"}),
                json!({"seq": 2, "agent": "simplify-reuse-a", "time": "2026-11-19T10:00:05.000Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}),
                json!({"seq": 3, "agent": "simplify-reuse-b", "time": "2026-11-19T10:00:06.000Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: ACTIONABLE_FIXES. DIFF_HASH: new_hash"}),
                json!({"seq": 4, "agent": "simplify-quality", "time": "2026-11-19T10:00:12.000Z", "text": "SIMPLIFY_LENS: QUALITY. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}),
                json!({"seq": 5, "agent": "simplify-efficiency", "time": "2026-11-19T10:00:12.000Z", "text": "SIMPLIFY_LENS: EFFICIENCY. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}),
            ],
            &[
                (cid_4t10la, &[json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"})]),
                (cid_4t10lb, &[json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"})]),
                (cid_4t10lq, &[json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"})]),
                (cid_4t10le, &[json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:02Z"})]),
            ],
        );
        let ev_4t10l = scan_swarm_activity(&steps_4t10l, Some(&tp_4t10l.to_string_lossy()), t0, 1, "new_hash", &brain.to_string_lossy());
        assert!(
            ev_4t10l.sonnet_lenses.contains_key("reuse"),
            "Carbon-epoch ACTIONABLE_FIXES (seq=3) before later Neon switch must NOT revoke simplify-reuse-a Sonnet CLEAN: {:?}",
            ev_4t10l.sonnet_lenses
        );
        assert!(
            has_completed_simplify_after(
                sess_4t10l,
                &marker_4t9,
                &tp_4t10l.to_string_lossy(),
                t_blk_4t9
            ),
            "disallowed Carbon-epoch ACTIONABLE_FIXES must NOT block valid 3-lens Sonnet CLEAN in has_completed_simplify_after"
        );

        // 4t10m: coarse `@all REVIEW_TIER: XHIGH` (10:00:06Z, ub=10:00:07.000Z) with delayed exact post_message formed at 10:00:06.200Z and published at 10:00:06.700Z must NOT promote APPROVED to XHIGH (or accept a delayed CLEAN after coarse round_start_msg_id).
        let sess_4t10m = "sess-4t10m-coarse-xhigh-window-rejects-delayed-same-second-flush";
        let cid_4t10m = "cid-4t10m";
        let tp_4t10m = setup_neon_session_env(
            &brain,
            sess_4t10m,
            "",
            json!({"members": {
                "opus-rev": {"role": "worker", "conversation_id": cid_4t10m, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@opus-rev Review HIGH"}),
                json!({"seq": 2, "agent": "coordinator", "time": "2026-11-19T10:00:06Z", "text": "@all REVIEW_TIER: XHIGH"}),
                json!({"seq": 3, "agent": "opus-rev", "time": "2026-11-19T10:00:06.700Z", "text": "VERDICT: APPROVED"}),
            ],
            &[(cid_4t10m, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:06.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: APPROVED"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t10m = scan_swarm_activity(&steps_4k, Some(&tp_4t10m.to_string_lossy()), t0, 1, sess_4t10m, &brain.to_string_lossy());
        assert_eq!(ev_4t10m.reviews.len(), 1, "expected 1 Opus review: {:?}", ev_4t10m.reviews);
        assert_eq!(
            ev_4t10m.reviews[0].get("xhigh").and_then(|v| v.as_bool()),
            Some(false),
            "delayed 10:00:06.200Z post_message flushed at 10:00:06.700Z after coarse 10:00:06Z @all XHIGH must remain HIGH: {:?}",
            ev_4t10m.reviews
        );

        let sess_4t10m_s = "sess-4t10m-coarse-round-start-rejects-delayed-same-second-clean";
        let cid_4t10m_s = "cid-4t10m-s";
        let tp_4t10m_s = setup_neon_session_env(
            &brain,
            sess_4t10m_s,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4t10m_s, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:06Z", "text": "@simplify-reuse r2 DIFF_HASH: new_hash"}),
                json!({"seq": 2, "agent": "simplify-reuse", "time": "2026-11-19T10:00:06.700Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}),
            ],
            &[(cid_4t10m_s, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:06.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t10m_s = scan_swarm_activity(&steps_4i_base, Some(&tp_4t10m_s.to_string_lossy()), t0, 1, "new_hash", &brain.to_string_lossy());
        assert!(
            ev_4t10m_s.sonnet_lenses.is_empty(),
            "delayed 10:00:06.200Z CLEAN flushed at 10:00:06.700Z after coarse 10:00:06Z round_start_msg_id must stay stale: {:?}",
            ev_4t10m_s.sonnet_lenses
        );

        // 4t10n: same-second coarse `@all REVIEW_TIER: XHIGH` (10:00:06Z), coarse `post_message` (10:00:06Z) or exact `10:00:06.200Z`, and coarse board publish (10:00:06Z) cannot prove formation occurred after assignment/round start; must fail closed for both XHIGH promotion and CLEAN freshness.
        let sess_4t10n = "sess-4t10n-all-coarse-same-second-xhigh-fails-closed";
        let cid_4t10n = "cid-4t10n";
        let tp_4t10n = setup_neon_session_env(
            &brain,
            sess_4t10n,
            "",
            json!({"members": {
                "opus-rev": {"role": "worker", "conversation_id": cid_4t10n, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@opus-rev Review HIGH"}),
                json!({"seq": 2, "agent": "coordinator", "time": "2026-11-19T10:00:06Z", "text": "@all REVIEW_TIER: XHIGH"}),
                json!({"seq": 3, "agent": "opus-rev", "time": "2026-11-19T10:00:06Z", "text": "VERDICT: APPROVED"}),
            ],
            &[(cid_4t10n, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:06Z", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: APPROVED"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t10n = scan_swarm_activity(&steps_4k, Some(&tp_4t10n.to_string_lossy()), t0, 1, sess_4t10n, &brain.to_string_lossy());
        assert_eq!(ev_4t10n.reviews.len(), 1, "expected 1 Opus review: {:?}", ev_4t10n.reviews);
        assert_eq!(
            ev_4t10n.reviews[0].get("xhigh").and_then(|v| v.as_bool()),
            Some(false),
            "same-second all-coarse 10:00:06Z @all XHIGH + post_message + board publish must remain HIGH: {:?}",
            ev_4t10n.reviews
        );

        let sess_4t10n_ex = "sess-4t10n-coarse-xhigh-exact-pm-coarse-board-fails-closed";
        let cid_4t10n_ex = "cid-4t10n-ex";
        let tp_4t10n_ex = setup_neon_session_env(
            &brain,
            sess_4t10n_ex,
            "",
            json!({"members": {
                "opus-rev": {"role": "worker", "conversation_id": cid_4t10n_ex, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@opus-rev Review HIGH"}),
                json!({"seq": 2, "agent": "coordinator", "time": "2026-11-19T10:00:06Z", "text": "@all REVIEW_TIER: XHIGH"}),
                json!({"seq": 3, "agent": "opus-rev", "time": "2026-11-19T10:00:06Z", "text": "VERDICT: APPROVED"}),
            ],
            &[(cid_4t10n_ex, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:06.200Z", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: APPROVED"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t10n_ex = scan_swarm_activity(&steps_4k, Some(&tp_4t10n_ex.to_string_lossy()), t0, 1, sess_4t10n_ex, &brain.to_string_lossy());
        assert_eq!(ev_4t10n_ex.reviews.len(), 1, "expected 1 Opus review: {:?}", ev_4t10n_ex.reviews);
        assert_eq!(
            ev_4t10n_ex.reviews[0].get("xhigh").and_then(|v| v.as_bool()),
            Some(false),
            "coarse 10:00:06Z @all XHIGH + exact 10:00:06.200Z post_message + coarse 10:00:06Z board publish must remain HIGH: {:?}",
            ev_4t10n_ex.reviews
        );

        let sess_4t10n_s = "sess-4t10n-all-coarse-same-second-clean-fails-closed";
        let cid_4t10n_s = "cid-4t10n-s";
        let tp_4t10n_s = setup_neon_session_env(
            &brain,
            sess_4t10n_s,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4t10n_s, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:06Z", "text": "@simplify-reuse r2 DIFF_HASH: new_hash"}),
                json!({"seq": 2, "agent": "simplify-reuse", "time": "2026-11-19T10:00:06Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}),
            ],
            &[(cid_4t10n_s, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:06Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t10n_s = scan_swarm_activity(&steps_4i_base, Some(&tp_4t10n_s.to_string_lossy()), t0, 1, "new_hash", &brain.to_string_lossy());
        assert!(
            ev_4t10n_s.sonnet_lenses.is_empty(),
            "same-second all-coarse 10:00:06Z round_start_msg_id + post_message + board CLEAN must stay stale: {:?}",
            ev_4t10n_s.sonnet_lenses
        );

        // 4t10o: earlier coarse seq=10 (10:00:06Z) followed by exact round_start_msg_id seq=11 (10:00:06.500Z) must tighten `round_start_ts_ub` to 10:00:06.500Z so a fresh CLEAN formed at 10:00:06.600Z and published at 10:00:06.700Z (seq=12) is accepted.
        let sess_4t10o = "sess-4t10o-exact-round-start-tightens-earlier-coarse-ub";
        let cid_4t10o = "cid-4t10o";
        let tp_4t10o = setup_neon_session_env(
            &brain,
            sess_4t10o,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4t10o, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 10, "agent": "coordinator", "time": "2026-11-19T10:00:06Z", "text": "@simplify-reuse prior round note"}),
                json!({"seq": 11, "agent": "coordinator", "time": "2026-11-19T10:00:06.500Z", "text": "@simplify-reuse r2 DIFF_HASH: new_hash"}),
                json!({"seq": 12, "agent": "simplify-reuse", "time": "2026-11-19T10:00:06.700Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}),
            ],
            &[(cid_4t10o, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:06.600Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t10o = scan_swarm_activity(&steps_4i_base, Some(&tp_4t10o.to_string_lossy()), t0, 11, "new_hash", &brain.to_string_lossy());
        assert!(
            ev_4t10o.sonnet_lenses.contains_key("reuse"),
            "exact seq=11 (10:00:06.500Z) must tighten earlier coarse seq=10 (10:00:06Z) so CLEAN formed 10:00:06.600Z / published 10:00:06.700Z is fresh: {:?}",
            ev_4t10o.sonnet_lenses
        );

        // 4t10p: coordinator `post_message` call timestamp (10:00:06.650Z) must NOT shift `round_start_ts_ub`
        // backward from the board publication time of `round_start_msg_id` seq=11 (10:00:06.700Z): a CLEAN formed
        // at 10:00:06.675Z (between call and publish) must stay stale, while a CLEAN formed at 10:00:06.750Z is fresh.
        let steps_4t10p = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "simplify-reuse", "model": cwg_common::SONNET_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:06.650Z", "tool_calls": [{"name": "post_message", "args": {"text": "@simplify-reuse r2 DIFF_HASH: new_hash"}}]}),
        ];
        let sess_4t10p_stale = "sess-4t10p-coord-call-does-not-narrow-pub-ub-stale";
        let cid_4t10p_s = "cid-4t10p-s";
        let tp_4t10p_s = setup_neon_session_env(
            &brain,
            sess_4t10p_stale,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4t10p_s, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 10, "agent": "coordinator", "time": "2026-11-19T10:00:06Z", "text": "@simplify-reuse prior round note"}),
                json!({"seq": 11, "agent": "coordinator", "time": "2026-11-19T10:00:06.700Z", "text": "@simplify-reuse r2 DIFF_HASH: new_hash"}),
                json!({"seq": 12, "agent": "simplify-reuse", "time": "2026-11-19T10:00:06.800Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}),
            ],
            &[(cid_4t10p_s, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:06.675Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t10p_s = scan_swarm_activity(&steps_4t10p, Some(&tp_4t10p_s.to_string_lossy()), t0, 11, "new_hash", &brain.to_string_lossy());
        assert!(
            ev_4t10p_s.sonnet_lenses.is_empty(),
            "CLEAN formed at 10:00:06.675Z before seq=11 board publish 10:00:06.700Z must stay stale even when coordinator called post_message at 10:00:06.650Z: {:?}",
            ev_4t10p_s.sonnet_lenses
        );

        let sess_4t10p_fresh = "sess-4t10p-coord-call-after-pub-ub-fresh";
        let cid_4t10p_f = "cid-4t10p-f";
        let tp_4t10p_f = setup_neon_session_env(
            &brain,
            sess_4t10p_fresh,
            "",
            json!({"members": {
                "simplify-reuse": {"role": "worker", "conversation_id": cid_4t10p_f, "model": cwg_common::SONNET_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 10, "agent": "coordinator", "time": "2026-11-19T10:00:06Z", "text": "@simplify-reuse prior round note"}),
                json!({"seq": 11, "agent": "coordinator", "time": "2026-11-19T10:00:06.700Z", "text": "@simplify-reuse r2 DIFF_HASH: new_hash"}),
                json!({"seq": 12, "agent": "simplify-reuse", "time": "2026-11-19T10:00:06.800Z", "text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}),
            ],
            &[(cid_4t10p_f, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:06.750Z", "tool_calls": [{"name": "post_message", "args": {"text": "SIMPLIFY_LENS: REUSE. SIMPLIFY_VERDICT: CLEAN. DIFF_HASH: new_hash"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t10p_f = scan_swarm_activity(&steps_4t10p, Some(&tp_4t10p_f.to_string_lossy()), t0, 11, "new_hash", &brain.to_string_lossy());
        assert!(
            ev_4t10p_f.sonnet_lenses.contains_key("reuse"),
            "CLEAN formed at 10:00:06.750Z after seq=11 board publish 10:00:06.700Z must be fresh: {:?}",
            ev_4t10p_f.sonnet_lenses
        );

        // 4t10p_xhigh: coordinator `post_message("@all REVIEW_TIER: XHIGH")` at 10:00:06.650Z published on board at 10:00:06.700Z must NOT promote worker APPROVED formed at 10:00:06.675Z to XHIGH.
        let steps_4t10p_x = vec![
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:02Z", "tool_calls": [{"name": "swarm", "args": {"action": "add", "name": "opus-rev", "model": cwg_common::OPUS_HIGH_MODEL}}]}),
            json!({"source": "GENERIC", "type": "GENERIC", "status": "DONE", "created_at": "2026-11-19T10:00:02Z", "content": "{}"}),
            json!({"source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:06.650Z", "tool_calls": [{"name": "post_message", "args": {"text": "@all REVIEW_TIER: XHIGH"}}]}),
        ];
        let sess_4t10p_x = "sess-4t10p-xhigh-coord-call-before-board-pub";
        let cid_4t10p_x = "cid-4t10p-x";
        let tp_4t10p_x = setup_neon_session_env(
            &brain,
            sess_4t10p_x,
            "",
            json!({"members": {
                "opus-rev": {"role": "worker", "conversation_id": cid_4t10p_x, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@opus-rev Review HIGH"}),
                json!({"seq": 2, "agent": "coordinator", "time": "2026-11-19T10:00:06.700Z", "text": "@all REVIEW_TIER: XHIGH"}),
                json!({"seq": 3, "agent": "opus-rev", "time": "2026-11-19T10:00:06.800Z", "text": "VERDICT: APPROVED"}),
            ],
            &[(cid_4t10p_x, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:06.675Z", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: APPROVED"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t10p_x = scan_swarm_activity(&steps_4t10p_x, Some(&tp_4t10p_x.to_string_lossy()), t0, 1, sess_4t10p_x, &brain.to_string_lossy());
        assert_eq!(ev_4t10p_x.reviews.len(), 1, "expected 1 Opus review: {:?}", ev_4t10p_x.reviews);
        assert_eq!(
            ev_4t10p_x.reviews[0].get("xhigh").and_then(|v| v.as_bool()),
            Some(false),
            "APPROVED formed at 10:00:06.675Z before @all XHIGH board publish 10:00:06.700Z must stay HIGH: {:?}",
            ev_4t10p_x.reviews
        );

        // 4t10p_xhigh_tsum_only: transcript-only Opus APPROVED (no matching worker board row) formed at
        // 10:00:06.675Z between coordinator `post_message` call (10:00:06.650Z) and board publish (10:00:06.700Z)
        // must stay HIGH, while transcript-only APPROVED at 10:00:06.750Z (after publish) promotes to XHIGH.
        let sess_4t10p_xt = "sess-4t10p-xhigh-transcript-only-before-board-pub";
        let cid_4t10p_xt = "cid-4t10p-xt";
        let tp_4t10p_xt = setup_neon_session_env(
            &brain,
            sess_4t10p_xt,
            "",
            json!({"members": {
                "opus-rev": {"role": "worker", "conversation_id": cid_4t10p_xt, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@opus-rev Review HIGH"}),
                json!({"seq": 2, "agent": "coordinator", "time": "2026-11-19T10:00:06.700Z", "text": "@all REVIEW_TIER: XHIGH"}),
            ],
            &[(cid_4t10p_xt, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:06.675Z", "content": "VERDICT: APPROVED"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t10p_xt = scan_swarm_activity(&steps_4t10p_x, Some(&tp_4t10p_xt.to_string_lossy()), t0, 1, sess_4t10p_xt, &brain.to_string_lossy());
        assert_eq!(ev_4t10p_xt.reviews.len(), 1, "expected 1 Opus review: {:?}", ev_4t10p_xt.reviews);
        assert_eq!(
            ev_4t10p_xt.reviews[0].get("xhigh").and_then(|v| v.as_bool()),
            Some(false),
            "transcript-only APPROVED at 10:00:06.675Z before @all XHIGH board publish 10:00:06.700Z must stay HIGH: {:?}",
            ev_4t10p_xt.reviews
        );

        let sess_4t10p_xta = "sess-4t10p-xhigh-transcript-only-after-board-pub";
        let cid_4t10p_xta = "cid-4t10p-xta";
        let tp_4t10p_xta = setup_neon_session_env(
            &brain,
            sess_4t10p_xta,
            "",
            json!({"members": {
                "opus-rev": {"role": "worker", "conversation_id": cid_4t10p_xta, "model": cwg_common::OPUS_HIGH_MODEL, "killed": false}
            }}),
            &[
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:02Z", "text": "@opus-rev Review HIGH"}),
                json!({"seq": 2, "agent": "coordinator", "time": "2026-11-19T10:00:06.700Z", "text": "@all REVIEW_TIER: XHIGH"}),
            ],
            &[(cid_4t10p_xta, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:01Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:06.750Z", "content": "VERDICT: APPROVED"}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let ev_4t10p_xta = scan_swarm_activity(&steps_4t10p_x, Some(&tp_4t10p_xta.to_string_lossy()), t0, 1, sess_4t10p_xta, &brain.to_string_lossy());
        assert_eq!(ev_4t10p_xta.reviews.len(), 1, "expected 1 Opus review: {:?}", ev_4t10p_xta.reviews);
        assert_eq!(
            ev_4t10p_xta.reviews[0].get("xhigh").and_then(|v| v.as_bool()),
            Some(true),
            "transcript-only APPROVED at 10:00:06.750Z after @all XHIGH board publish 10:00:06.700Z must enter XHIGH: {:?}",
            ev_4t10p_xta.reviews
        );

        // 4t10q: coarse pre-reset seq=6 (`10:00:06Z`) assigning `@neon-audit REVIEW_TIER: XHIGH` followed by exact
        // pre-reset seq=7 (`10:00:06.300Z <= reset_ts=10:00:06.500Z`) must advance the causal reset prefix to
        // `eff_research_reset_seq=7`, preventing a post-reset worker reusing `neon-audit` from inheriting seq=6.
        let rr_ts_4t10q = rio::parse_iso_ts("2026-11-19T10:00:06.500Z");
        let rr_marker_4t10q = json!({
            "session": "sess-4t10q-causal-reset-prefix",
            "research_resets": [{
                "reset_ts": rr_ts_4t10q,
                "board_head_seq": 5,
                "pre_reset_worker_cids": ["cid-old-neon-audit"]
            }]
        });
        let sess_4t10q = "sess-4t10q-causal-reset-prefix";
        let cid_4t10q = "cid-4t10q-post-builder";
        let tp_4t10q = setup_neon_session_env(
            &brain,
            sess_4t10q,
            "",
            json!({"members": {
                "neon-audit": {
                    "role": "worker",
                    "conversation_id": cid_4t10q,
                    "model": cwg_common::NEON_XHIGH_MODEL,
                    "created_at": "2026-11-19T10:00:06.600Z",
                    "killed": false
                }
            }}),
            &[
                json!({"seq": 6, "agent": "coordinator", "time": "2026-11-19T10:00:06Z", "text": "@neon-audit Adversarial review; return VERDICT: APPROVED or REVISE."}),
                json!({"seq": 7, "agent": "coordinator", "time": "2026-11-19T10:00:06.300Z", "text": "@other sync"}),
                json!({"seq": 8, "agent": "coordinator", "time": "2026-11-19T10:00:06Z", "text": "@neon-audit Implement parser module"}),
                json!({"seq": 9, "agent": "neon-audit", "time": "2026-11-19T10:00:08Z", "text": "VERDICT: APPROVED"}),
            ],
            &[(cid_4t10q, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:06.600Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:08Z", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: APPROVED"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let tp_4t10q_str = tp_4t10q.to_string_lossy().into_owned();
        let brain_str = brain.to_string_lossy().into_owned();
        let ev_4t10q = scan_swarm_activity_with_reset(SwarmScanInput {
            steps: &[],
            transcript_path: Some(&tp_4t10q_str),
            first_ts: t0,
            round_start_msg_id: 5,
            current_diff_hash: "",
            cwd: &brain_str,
            research_reset_ts: rr_ts_4t10q,
            research_reset_seq: 5,
            marker: Some(&rr_marker_4t10q),
        });
        assert!(
            ev_4t10q.reviews.is_empty(),
            "post-reset builder reusing neon-audit must NOT inherit coarse pre-reset seq=6 review brief tightened by seq=7 (10:00:06.300Z <= reset_ts): {:?}",
            ev_4t10q.reviews
        );

        // 4t10r: tail-truncated board (>400 rows without explicit `seq`/`msg_id`/`id`) must preserve full-board
        // ordinal seq so post-reset assignment (row 401) and verdict (row 402) after `board_head_seq=400` are NOT dropped.
        let sess_4t10r = "sess-4t10r-tail-401-no-seq-preserved";
        let cid_4t10r = "cid-4t10r-post-rev";
        let mut board_4t10r: Vec<Value> = Vec::with_capacity(402);
        for i in 1..=400 {
            board_4t10r.push(json!({
                "agent": "coordinator",
                "time": "2026-11-19T10:00:01Z",
                "text": format!("@other note {}", i)
            }));
        }
        board_4t10r.push(json!({
            "agent": "coordinator",
            "time": "2026-11-19T10:00:10.000Z",
            "text": "@neon-audit Adversarial review; return VERDICT: APPROVED or REVISE."
        }));
        board_4t10r.push(json!({
            "agent": "neon-audit",
            "time": "2026-11-19T10:00:12.000Z",
            "text": "VERDICT: APPROVED"
        }));
        let tp_4t10r = setup_neon_session_env(
            &brain,
            sess_4t10r,
            "",
            json!({"members": {
                "neon-audit": {
                    "role": "worker",
                    "conversation_id": cid_4t10r,
                    "model": cwg_common::NEON_XHIGH_MODEL,
                    "created_at": "2026-11-19T10:00:09.000Z",
                    "killed": false
                }
            }}),
            &board_4t10r,
            &[(cid_4t10r, &[
                json!({"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "created_at": "2026-11-19T10:00:09.000Z"}),
                json!({"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "created_at": "2026-11-19T10:00:12.000Z", "tool_calls": [{"name": "post_message", "args": {"text": "VERDICT: APPROVED"}}]}),
                json!({"step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE", "tool_calls": []}),
            ])],
        );
        let rr_marker_4t10r = json!({
            "session": sess_4t10r,
            "research_resets": [{
                "reset_ts": rr_ts_4t10q,
                "board_head_seq": 400,
                "pre_reset_worker_cids": ["cid-old-neon-audit"]
            }]
        });
        let tp_4t10r_str = tp_4t10r.to_string_lossy().into_owned();
        let ev_4t10r = scan_swarm_activity_with_reset(SwarmScanInput {
            steps: &[],
            transcript_path: Some(&tp_4t10r_str),
            first_ts: t0,
            round_start_msg_id: 400,
            current_diff_hash: "",
            cwd: &brain_str,
            research_reset_ts: rr_ts_4t10q,
            research_reset_seq: 400,
            marker: Some(&rr_marker_4t10r),
        });
        assert_eq!(
            ev_4t10r.reviews.len(),
            1,
            "post-reset assignment row 401 and APPROVED row 402 without explicit seq must survive 400-line tail truncation: {:?}",
            ev_4t10r.reviews
        );
        assert_eq!(
            ev_4t10r.reviews[0].get("verdict").and_then(|v| v.as_str()),
            Some("APPROVED")
        );
    }
}
