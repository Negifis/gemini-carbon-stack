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

const SIMPLIFY_FALLBACK_MODELS: &[&str] = &[cwg_common::HYDROGEN_XHIGH_MODEL];

const PRE_SIMPLIFY_REVIEW_ERR: &str = "adversarial review ran simultaneously with or before simplify lenses; complete all simplify lenses BEFORE launching adversarial review (or run `--closure` / `--phase closure` once simplify finishes)";

static NONCE_SEQ: AtomicU64 = AtomicU64::new(1);

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
            r#"(?i)\[Message\]\s+timestamp=\S+\s+sender=system\b[^\n]*Swarm Worker \((?P<name>[A-Za-z0-9._-]+)\)[^\n]*with id "(?P<cid>[A-Za-z0-9._-]+)" encountered an error[^\n]*?:\s*(?P<err>.+)"#,
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

fn collect_generic_results(steps: &[Value], planner_idx: usize) -> Vec<(String, String, f64)> {
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
        let g_ts = g_st
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(rio::parse_iso_ts)
            .unwrap_or(0.0);
        out.push((g_status, g_txt, g_ts));
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
                    (gen_steps[pos].0.as_str(), gen_steps[pos].2)
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
struct MemberTranscriptSummary {
    outputs: Vec<(f64, String)>,
    has_error: bool,
    error_ts: f64,
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
    let start_ts = m_steps[0]
        .get("created_at")
        .and_then(|v| v.as_str())
        .map(rio::parse_iso_ts)
        .unwrap_or(0.0);

    for st in &m_steps {
        let ts = st
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(rio::parse_iso_ts)
            .unwrap_or(0.0);
        let ssource = val_to_str(st.get("source"));
        let stype = val_to_str(st.get("type"));
        let sstatus = val_to_str(st.get("status"));
        let scontent = val_to_str(st.get("content"));

        // SAFETY: Only model/turn failures count (never GENERIC tool-call errors or SYSTEM brief text).
        if stype == "ERROR_MESSAGE"
            || (ssource == "MODEL" && stype != "GENERIC" && sstatus == "ERROR")
        {
            if ts == 0.0 || ts >= first_ts - 2.0 {
                has_error = true;
                let eff = if ts > 0.0 { ts } else { now_sec() };
                if eff > error_ts {
                    error_ts = eff;
                }
            }
        }

        if ssource == "MODEL" && stype == "PLANNER_RESPONSE" {
            let tcs = st
                .get("tool_calls")
                .and_then(|v| v.as_array())
                .map(|a| a.as_slice())
                .unwrap_or(&[]);
            for tc in tcs {
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
                    if !txt.is_empty() && (ts == 0.0 || ts >= first_ts - 2.0) {
                        outputs.push((if ts > 0.0 { ts } else { now_sec() }, txt));
                    }
                }
            }
            if !scontent.trim().is_empty() && tcs.is_empty() && (ts == 0.0 || ts >= first_ts - 2.0)
            {
                outputs.push((
                    if ts > 0.0 { ts } else { now_sec() },
                    scontent.trim().to_string(),
                ));
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
        .map_or(true, |a| a.is_empty());
    let prev_called_wait = m_steps.len() >= 2
        && m_steps[m_steps.len() - 2]
            .get("tool_calls")
            .and_then(|v| v.as_array())
            .map_or(false, |a| {
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

fn text_mentions_swarm_worker_exact(text: &str, wname: &str) -> bool {
    rio::text_mentions_swarm_worker(text, wname)
}

#[derive(Debug, Clone, Default)]
pub struct SimplifyHistoryItem {
    pub kind: String,
    pub lens: Option<String>,
    pub tier: String,
    pub launch_ts: f64,
    pub end_ts: f64,
    pub seq: i64,
    pub clean: bool,
    pub has_explicit_all: bool,
}

impl SimplifyHistoryItem {
    fn chrono_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.end_ts
            .total_cmp(&other.end_ts)
            .then_with(|| self.seq.cmp(&other.seq))
            .then_with(|| self.launch_ts.total_cmp(&other.launch_ts))
    }
}

#[derive(Debug, Clone, Default)]
pub struct SwarmEvidence {
    pub sonnet_lenses: HashMap<String, f64>,
    pub fallback_lenses: HashMap<String, f64>,
    pub sonnet_lenses_end: HashMap<String, f64>,
    pub fallback_lenses_end: HashMap<String, f64>,
    pub sonnet_combined_ts: f64,
    pub fallback_combined_ts: f64,
    pub sonnet_combined_end_ts: f64,
    pub fallback_combined_end_ts: f64,
    pub simplify_launch_steps: HashSet<usize>,
    pub simplify_history: Vec<SimplifyHistoryItem>,
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

fn record_compact_system_swarm_errors(
    step: &Value,
    first_ts: f64,
    host_worker_errors: &mut HashMap<(String, String), f64>,
) {
    let sys_ts = step
        .get("created_at")
        .and_then(|v| v.as_str())
        .map(rio::parse_iso_ts)
        .unwrap_or(0.0);
    if sys_ts > 0.0 && sys_ts < first_ts - 2.0 {
        return;
    }
    let txt = val_to_str(step.get("content"));
    let ts_val = if sys_ts > 0.0 { sys_ts } else { now_sec() };
    for sm in system_swarm_err_re().captures_iter(&txt) {
        let err_txt = sm.name("err").map_or("", |m| m.as_str());
        if !model_failure_re().is_match(err_txt) {
            continue;
        }
        let key = (
            sm.name("name").map_or("", |m| m.as_str()).to_string(),
            sm.name("cid").map_or("", |m| m.as_str()).to_string(),
        );
        let entry = host_worker_errors.entry(key).or_insert(0.0);
        if ts_val > *entry {
            *entry = ts_val;
        }
    }
}

fn recover_compact_swarm_steps(
    tp: &str,
    tail_idx: i64,
    first_ts: f64,
    ev: &mut SwarmEvidence,
    host_worker_errors: &mut HashMap<(String, String), f64>,
    mut on_swarm_res: impl FnMut(&mut SwarmEvidence, &Value, &str, &str, f64, Option<usize>, bool),
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
            record_compact_system_swarm_errors(p_st, first_ts, host_worker_errors);
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
            let (g_status, blob) = p_gen
                .get(p_pos)
                .map(|(st, b, _)| (st.as_str(), b.as_str()))
                .unwrap_or(("", ""));
            let has_content_trunc = compact_steps
                .get(p_idx + 1 + p_pos)
                .and_then(|s| s.get("truncated_fields"))
                .and_then(|v| v.as_array())
                .map_or(false, |arr| arr.iter().any(|x| x.as_str() == Some("content")));
            on_swarm_res(ev, p_tc, g_status, blob, p_call_ts, None, !has_content_trunc);
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
    let mut model_switches: HashMap<String, Vec<(f64, String, Option<usize>)>> = HashMap::new();
    let mut coord_call_events: Vec<(f64, String, usize)> = Vec::new();
    let mut host_worker_errors: HashMap<(String, String), f64> = HashMap::new();
    let mut worker_add_step: HashMap<String, usize> = HashMap::new();
    let mut pending_codex_tasks: HashMap<String, (String, f64)> = HashMap::new();
    let mut pending_bg_tasks: BTreeSet<String> = BTreeSet::new();
    let mut passive_bg_tasks: BTreeSet<String> = BTreeSet::new();

    let mark_opus_issue = |ev: &mut SwarmEvidence, ts_val: f64| {
        ev.opus_issue_verified = true;
        let eff = if ts_val > 0.0 { ts_val } else { now_sec() };
        if ev.opus_issue_ts <= 0.0 || eff < ev.opus_issue_ts {
            ev.opus_issue_ts = eff;
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

    let record_model_failure =
        |ev: &mut SwarmEvidence, models: &HashSet<String>, worker_name: &str, ts_val: f64| {
            if models
                .iter()
                .any(|m| m.contains(cwg_common::OPUS_HIGH_MODEL))
            {
                mark_opus_issue(ev, ts_val);
                ev.review_failures
                    .push(if ts_val > 0.0 { ts_val } else { now_sec() });
            }
            if models
                .iter()
                .any(|m| m.contains(cwg_common::SONNET_HIGH_MODEL))
            {
                ev.sonnet_issue_verified = true;
                ev.simplify_failures += 1;
            } else if models
                .iter()
                .any(|m| SIMPLIFY_FALLBACK_MODELS.contains(&m.as_str()))
                && cwg_common::is_simplify_worker_name(worker_name)
            {
                ev.simplify_failures += 1;
            }
        };

    let mut inspect_swarm_tool_result = |ev: &mut SwarmEvidence,
                                         tc: &Value,
                                         g_status: &str,
                                         blob: &str,
                                         call_ts: f64,
                                         step_pos: Option<usize>,
                                         allow_missing_avail: bool| {
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

        if !wname.is_empty() && !req_model.is_empty() {
            requested_models
                .entry(wname.clone())
                .or_default()
                .insert(req_model.clone());
        }
        if action == "model" && !wname.is_empty() && call_ts > 0.0 {
            model_switches.entry(wname.clone()).or_default().push((
                call_ts,
                format!("[model-switch:{}]", req_model),
                step_pos,
            ));
        }

        if action == "models" {
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
                if !avail.is_empty() && allow_missing_avail {
                    if !avail.contains(cwg_common::OPUS_HIGH_MODEL) {
                        mark_opus_issue(ev, call_ts);
                    }
                    if !avail.contains(cwg_common::SONNET_HIGH_MODEL) {
                        ev.sonnet_issue_verified = true;
                    }
                }
                if let Some(quotas) = md.get("quotas").and_then(|v| v.as_object()) {
                    let opus_q = quotas
                        .get(cwg_common::OPUS_HIGH_MODEL)
                        .and_then(|v| v.get("quota_remaining"))
                        .map(|v| val_to_str(Some(v)))
                        .unwrap_or_default();
                    if opus_q == "0%" || opus_q == "0" {
                        mark_opus_issue(ev, call_ts);
                    }
                    let sonnet_q = quotas
                        .get(cwg_common::SONNET_HIGH_MODEL)
                        .and_then(|v| v.get("quota_remaining"))
                        .map(|v| val_to_str(Some(v)))
                        .unwrap_or_default();
                    if sonnet_q == "0%" || sonnet_q == "0" {
                        ev.sonnet_issue_verified = true;
                    }
                }
            }
        }

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
        // INVARIANT: Only model/quota/availability failures count (never duplicate worker names or bad args).
        if is_err && !req_model.is_empty() && model_failure_re().is_match(&err_detail) {
            let mut single = HashSet::new();
            single.insert(req_model);
            record_model_failure(ev, &single, &wname, call_ts);
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
            let sys_ts = st
                .get("created_at")
                .and_then(|v| v.as_str())
                .map(rio::parse_iso_ts)
                .unwrap_or(0.0);
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
                for sm in system_swarm_err_re().captures_iter(&sys_txt) {
                    let err_txt = sm.name("err").map_or("", |m| m.as_str());
                    if model_failure_re().is_match(err_txt) {
                        let key = (
                            sm.name("name").map_or("", |m| m.as_str()).to_string(),
                            sm.name("cid").map_or("", |m| m.as_str()).to_string(),
                        );
                        let ts_val = if sys_ts > 0.0 { sys_ts } else { now_sec() };
                        let entry = host_worker_errors.entry(key).or_insert(0.0);
                        if ts_val > *entry {
                            *entry = ts_val;
                        }
                    }
                }
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
        let call_ts = st
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(rio::parse_iso_ts)
            .unwrap_or(0.0);
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
                    coord_call_events.push((call_ts, hint, idx));
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
                        coord_call_events.push((call_ts, hint, idx));
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
            let (g_status, blob, g_ts) = if pos < generic_steps.len() {
                (
                    generic_steps[pos].0.as_str(),
                    generic_steps[pos].1.as_str(),
                    generic_steps[pos].2,
                )
            } else {
                ("", "", 0.0)
            };
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
            inspect_swarm_tool_result(&mut ev, tc, g_status, blob, call_ts, Some(idx), true);
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
    let swarm_dir = rio::swarm_dir(&brain_root, &conv_cid);
    let members_map = rio::load_swarm_members(&brain_root, &conv_cid);
    if members_map.is_empty() {
        return ev;
    }

    let raw_board = rio::read_jsonl(&swarm_dir.join("board.jsonl"), Some(400));
    ev.board_head = raw_board.len();
    coord_call_events.sort_by(|a, b| a.0.total_cmp(&b.0));
    let mut c_cursor = 0usize;
    let mut running_board_ts = 0.0f64;
    let mut parsed_board: Vec<(String, String, f64, Option<usize>, i64)> =
        Vec::with_capacity(raw_board.len());

    for (bp_idx, bp) in raw_board.iter().enumerate() {
        let poster = val_to_str(bp.get("agent"));
        let btext = val_to_str(bp.get("text")).trim().to_string();
        let bseq = cwg_common::extract_msg_seq(bp, (bp_idx + 1) as i64);
        let raw_bts = bp
            .get("time")
            .and_then(|v| v.as_str())
            .map(rio::parse_iso_ts)
            .unwrap_or(0.0);
        let mut bts = raw_bts;
        let mut bstep_idx: Option<usize> = None;
        if poster == "coordinator" && raw_bts > 0.0 {
            let low_btext = btext.to_lowercase();
            let mut probe = c_cursor;
            while probe < coord_call_events.len() && coord_call_events[probe].0 < raw_bts - 0.1 {
                probe += 1;
            }
            for cand_i in probe..coord_call_events.len() {
                let (evt_ts, ref evt_hint, evt_step) = coord_call_events[cand_i];
                if evt_ts - raw_bts >= 1.5 {
                    break;
                }
                if evt_hint.is_empty() || low_btext.contains(evt_hint) {
                    bts = evt_ts;
                    bstep_idx = Some(evt_step);
                    c_cursor = cand_i + 1;
                    break;
                }
            }
        }
        if bts > 0.0 && running_board_ts > 0.0 && bts < running_board_ts {
            // INVARIANT: `board.jsonl` is strictly append-only; clamp whole-second floor truncation to preceding board timestamp.
            bts = running_board_ts;
        }
        if bts > running_board_ts {
            running_board_ts = bts;
        }
        parsed_board.push((poster, btext, bts, bstep_idx, bseq));
    }

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

        let has_reset = research_reset_ts > 0.0 || research_reset_seq > 0;
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

        let mut coord_posts: Vec<(f64, String, Option<usize>, i64)> = Vec::new();
        let mut broadcast_posts: Vec<(f64, String, Option<usize>)> = Vec::new();
        let mut worker_board_posts: Vec<(f64, String, i64)> = Vec::new();

        for (poster, btext, bts, bstep_idx, bseq) in &parsed_board {
            if btext.is_empty() {
                continue;
            }
            // INVARIANT: Post-research-reset workers reusing a standard roster name must never inherit pre-reset board posts from a killed Cycle-1 worker.
            if has_reset
                && !is_pre_reset_worker
                && ((research_reset_seq > 0 && *bseq > 0 && *bseq <= research_reset_seq)
                    || (research_reset_ts > 0.0 && *bts > 0.0 && *bts <= research_reset_ts))
            {
                continue;
            }
            if poster == "coordinator" {
                if text_mentions_swarm_worker_exact(btext, mname) {
                    coord_posts.push((*bts, btext.clone(), *bstep_idx, *bseq));
                } else if rio::text_contains_mention(btext, "all") {
                    broadcast_posts.push((*bts, btext.clone(), *bstep_idx));
                }
            } else if poster == mname {
                // INVARIANT: Only posts authored by `mname` itself count as worker output (never coordinator prompts).
                if *bts == 0.0 || *bts >= first_ts - 2.0 {
                    let eff_ts = if *bts > 0.0 { *bts } else { now_sec() };
                    worker_board_posts.push((eff_ts, btext.clone(), *bseq));
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

        let host_err_ts = if !mcid.is_empty() {
            host_worker_errors
                .get(&(mname.clone(), mcid.clone()))
                .copied()
                .unwrap_or(0.0)
        } else {
            0.0
        };
        if tsum.has_error || host_err_ts > 0.0 {
            let mut cand_models = prior_reqs.clone();
            if !cur_model.is_empty() {
                cand_models.insert(cur_model.clone());
            }
            record_model_failure(&mut ev, &cand_models, mname, tsum.error_ts.max(host_err_ts));
        }

        let mut t_cursor = 0usize;
        let mut matched_t: HashSet<usize> = HashSet::new();
        let mut combined_outputs: Vec<(f64, String, i64)> = Vec::new();
        for (b_idx, (bts, btxt, bseq)) in worker_board_posts.iter().enumerate() {
            let mut eff_ots = *bts;
            let next_bts = if b_idx + 1 < worker_board_posts.len() {
                worker_board_posts[b_idx + 1].0
            } else {
                f64::INFINITY
            };
            for tidx in t_cursor..tsum.outputs.len() {
                let (ots, ref otxt) = tsum.outputs[tidx];
                if otxt == btxt && (ots - *bts).abs() < 5.0 && ots < next_bts {
                    eff_ots = eff_ots.max(ots);
                    matched_t.insert(tidx);
                    t_cursor = tidx + 1;
                    break;
                }
            }
            combined_outputs.push((eff_ots, btxt.clone(), *bseq));
        }
        for (tidx, (ots, otxt)) in tsum.outputs.iter().enumerate() {
            if !matched_t.contains(&tidx) {
                combined_outputs.push((*ots, otxt.clone(), 0));
            }
        }
        combined_outputs.sort_by(|a, b| a.0.total_cmp(&b.0));

        let latest_assign_ts = coord_posts
            .last()
            .map(|p| p.0)
            .unwrap_or(tsum.start_ts);
        let latest_assign_seq = coord_posts.last().map(|p| p.3).unwrap_or(0);
        let latest_reply_seq = worker_board_posts.iter().map(|p| p.2).max().unwrap_or(0);
        let latest_brief = coord_posts
            .iter()
            .map(|p| p.1.as_str())
            .collect::<Vec<&str>>()
            .join("\n");
        let has_reply_since_assign = if latest_assign_seq > 0 && !worker_board_posts.is_empty() {
            latest_reply_seq > latest_assign_seq
        } else {
            combined_outputs.last().map_or(false, |last_out| {
                latest_assign_ts == 0.0 || last_out.0 >= latest_assign_ts - 1.0
            })
        };

        let mut max_act = latest_assign_ts.max(tsum.start_ts).max(tsum.parked_ts);
        for (ots, _, _) in &combined_outputs {
            if *ots > max_act {
                max_act = *ots;
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
        if is_pre_reset_worker && cwg_common::is_simplify_or_review_swarm_worker(mname, Some(minfo))
        {
            continue;
        }
        if combined_outputs.is_empty() {
            continue;
        }

        let mut windows: Vec<(f64, String, Option<usize>)> = Vec::new();
        for (ts, txt, st_i, _) in &coord_posts {
            windows.push((*ts, txt.clone(), *st_i));
        }
        for (ts, txt, st_i) in &broadcast_posts {
            windows.push((*ts, txt.clone(), *st_i));
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
                windows.push(item.clone());
            }
        }
        windows.sort_by(|a, b| a.0.total_cmp(&b.0));
        if windows.is_empty() {
            let w0 = if tsum.start_ts > 0.0 {
                tsum.start_ts
            } else {
                first_ts
            };
            windows.push((w0, String::new(), None));
        }

        let mut bucketed_outputs: HashMap<usize, Vec<(f64, String, i64)>> = HashMap::new();
        for (out_ts, out_txt, out_seq) in &combined_outputs {
            let mut w_idx = 0usize;
            // INVARIANT: Sub-second ISO transcript timestamps are strictly causal (`wts <= out_ts`); whole-second board fallbacks allow <1s floor slack.
            let tol = if (*out_ts % 1.0) != 0.0 { 1e-6 } else { 0.999 };
            for (cand_idx, (wts, _, _)) in windows.iter().enumerate() {
                if *wts == 0.0 || *wts <= *out_ts + tol {
                    w_idx = cand_idx;
                }
            }
            bucketed_outputs
                .entry(w_idx)
                .or_default()
                .push((*out_ts, out_txt.clone(), *out_seq));
        }

        let joined_worker_text = combined_outputs
            .iter()
            .map(|x| x.1.as_str())
            .collect::<Vec<&str>>()
            .join("\n\n");
        let (skind, slens) = classify_simplify_worker(mname, &latest_brief, &joined_worker_text);
        let mut w_step_idx = worker_add_step.get(mname).copied();
        if w_step_idx.is_none() && !group_prefix.is_empty() {
            w_step_idx = worker_add_step.get(group_prefix).copied();
        }
        if (skind == "lens" && slens.is_some()) || skind == "combined" {
            if let Some(ws) = w_step_idx {
                ev.simplify_launch_steps.insert(ws);
            }
            // INVARIANT: Simplify fallback runs strictly on Hydrogen XHigh via swarm (never Carbon), protecting main-agent quota.
            let tier = if cur_model == cwg_common::SONNET_HIGH_MODEL {
                "sonnet"
            } else if SIMPLIFY_FALLBACK_MODELS.contains(&cur_model.as_str()) {
                "fallback"
            } else {
                ""
            };
            if !tier.is_empty() {
                let eval_win_outs = |outs: &[&(f64, String, i64)],
                                     win_ts: f64|
                 -> Option<(SimplifyHistoryItem, bool)> {
                    if outs.is_empty() {
                        return None;
                    }
                    let joined = outs
                        .iter()
                        .map(|x| x.1.as_str())
                        .collect::<Vec<&str>>()
                        .join("\n\n");
                    let parsed = cwg_common::parse_simplify_verdict(
                        &joined,
                        Some(slens.as_deref().unwrap_or("")),
                    );
                    if val_to_str(parsed.get("verdict")).is_empty() {
                        return None;
                    }
                    let s_ts = outs
                        .iter()
                        .filter(|(_, otxt, _)| {
                            let p = cwg_common::parse_simplify_verdict(otxt, None);
                            !val_to_str(p.get("verdict")).is_empty()
                        })
                        .map(|(ots, _, _)| *ots)
                        .reduce(f64::max)
                        .unwrap_or_else(|| outs.last().map_or(0.0, |x| x.0));
                    let eff_lts = if win_ts > 0.0 {
                        win_ts
                    } else if tsum.start_ts > 0.0 {
                        tsum.start_ts
                    } else {
                        first_ts
                    };
                    let max_ots = outs.iter().map(|x| x.0).reduce(f64::max).unwrap_or(eff_lts);
                    let eff_ets = eff_lts.max(if s_ts > 0.0 { s_ts } else { max_ots });
                    let has_explicit_all = json_truthy(parsed.get("has_explicit_all"));
                    let spoof = json_truthy(parsed.get("multi_lens_spoof"))
                        || (skind == "combined"
                            && !has_explicit_all
                            && !simplify_combined_name_re().is_match(mname.trim()));
                    let max_seq = outs.iter().map(|x| x.2).max().unwrap_or(0);
                    Some((
                        SimplifyHistoryItem {
                            kind: skind.to_string(),
                            lens: if skind == "lens" { slens.clone() } else { None },
                            tier: tier.to_string(),
                            launch_ts: eff_lts,
                            end_ts: eff_ets,
                            seq: max_seq,
                            clean: json_truthy(parsed.get("clean")),
                            has_explicit_all,
                        },
                        spoof,
                    ))
                };

                let mut win_keys: Vec<usize> = bucketed_outputs.keys().copied().collect();
                win_keys.sort();
                for w_idx in win_keys {
                    let win_ts = windows[w_idx].0;
                    let win_outs = &bucketed_outputs[&w_idx];
                    let all_refs: Vec<&(f64, String, i64)> = win_outs.iter().collect();
                    // INVARIANT: Record every completed window in `simplify_history` (unfiltered by current `round_start_msg_id` / `current_diff_hash`) so prior candidate versions retain historical simplify evidence.
                    let hist_pair = eval_win_outs(&all_refs, win_ts);
                    if let Some((ref hist_ev, _)) = hist_pair {
                        ev.simplify_history.push(hist_ev.clone());
                    }
                    let mut fresh_refs: Vec<&(f64, String, i64)> =
                        Vec::with_capacity(win_outs.len());
                    for item in win_outs {
                        let (_, ref otxt, obseq) = *item;
                        if round_start_msg_id > 0 && obseq > 0 && obseq <= round_start_msg_id {
                            continue;
                        }
                        if !current_diff_hash.is_empty() {
                            let hm_hash = cwg_common::extract_diff_hash(otxt);
                            if !hm_hash.is_empty() && hm_hash != current_diff_hash {
                                continue;
                            }
                        }
                        fresh_refs.push(item);
                    }
                    let fresh_pair = if fresh_refs.len() == win_outs.len() {
                        hist_pair
                    } else {
                        eval_win_outs(&fresh_refs, win_ts)
                    };
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
            }
            continue;
        }

        if cur_model != cwg_common::OPUS_HIGH_MODEL && cur_model != cwg_common::CARBON_HIGH_MODEL {
            continue;
        }
        let eng = if cur_model == cwg_common::OPUS_HIGH_MODEL {
            "internal-opus"
        } else {
            "internal-carbon"
        };
        let escalated_from_opus = prior_reqs.contains(cwg_common::OPUS_HIGH_MODEL);
        let mut win_keys: Vec<usize> = bucketed_outputs.keys().copied().collect();
        win_keys.sort();
        for w_idx in win_keys {
            let (win_ts, ref win_brief, win_step_idx) = windows[w_idx];
            let win_outs = &bucketed_outputs[&w_idx];
            let eff_launch_ts = if win_ts > 0.0 {
                win_ts
            } else if tsum.start_ts > 0.0 {
                tsum.start_ts
            } else {
                first_ts
            };
            let max_win_ots = win_outs
                .iter()
                .map(|x| x.0)
                .reduce(f64::max)
                .unwrap_or(eff_launch_ts);
            let eff_end_ts = eff_launch_ts.max(max_win_ots);
            let eff_step_idx = win_step_idx.or(w_step_idx);
            let win_txt = win_outs
                .iter()
                .map(|x| x.1.as_str())
                .collect::<Vec<&str>>()
                .join("\n\n");
            let is_xhigh = mname.to_lowercase().contains("xhigh")
                || cwg_common::is_review_tier_xhigh(&latest_brief)
                || cwg_common::is_review_tier_xhigh(win_brief)
                || cwg_common::is_review_tier_xhigh(&win_txt);

            let mut r_kind: Option<String> = None;
            let mut r_verdict: Option<String> = None;
            let mut r_ts = 0.0f64;
            for (ots, otxt, _) in win_outs.iter().rev() {
                let (k, v) = cwg_common::extract_review_decision(otxt);
                if k.is_some() && v.is_some() {
                    r_kind = k;
                    r_verdict = v;
                    r_ts = *ots;
                    break;
                }
            }
            if let (Some(rk), Some(rv)) = (r_kind, r_verdict) {
                let eff_verdict_ts = eff_launch_ts.max(if r_ts > 0.0 { r_ts } else { eff_end_ts });
                ev.reviews.push(json!({
                    "engine": eng,
                    "reviewer": mname,
                    "cid": mcid,
                    "kind": rk,
                    "verdict": rv,
                    "launch_ts": eff_launch_ts,
                    "verdict_ts": eff_verdict_ts,
                    "xhigh": is_xhigh,
                    "model": cur_model,
                    "escalated_from_opus": escalated_from_opus,
                    "step_idx": eff_step_idx,
                }));
            }
        }
    }

    // INVARIANT: Replay simplify events in chronological order across all workers so a stale CLEAN in another member entry can never survive or overwrite a later ACTIONABLE_FIXES verdict.
    simplify_events.sort_by(SimplifyHistoryItem::chrono_cmp);
    ev.simplify_history.sort_by(SimplifyHistoryItem::chrono_cmp);
    for sev in simplify_events {
        if !sev.clean {
            if sev.kind == "lens" {
                if let Some(ref sl) = sev.lens {
                    ev.sonnet_lenses.remove(sl);
                    ev.sonnet_lenses_end.remove(sl);
                    ev.fallback_lenses.remove(sl);
                    ev.fallback_lenses_end.remove(sl);
                }
            } else {
                ev.sonnet_combined_ts = 0.0;
                ev.sonnet_combined_end_ts = 0.0;
                ev.fallback_combined_ts = 0.0;
                ev.fallback_combined_end_ts = 0.0;
            }
            continue;
        }
        if sev.kind == "lens" {
            if let Some(ref sl) = sev.lens {
                if sev.tier == "sonnet" {
                    let l_entry = ev.sonnet_lenses.entry(sl.clone()).or_insert(0.0);
                    *l_entry = (*l_entry).max(sev.launch_ts);
                    let e_entry = ev.sonnet_lenses_end.entry(sl.clone()).or_insert(0.0);
                    *e_entry = (*e_entry).max(sev.end_ts);
                } else {
                    let l_entry = ev.fallback_lenses.entry(sl.clone()).or_insert(0.0);
                    *l_entry = (*l_entry).max(sev.launch_ts);
                    let e_entry = ev.fallback_lenses_end.entry(sl.clone()).or_insert(0.0);
                    *e_entry = (*e_entry).max(sev.end_ts);
                }
            }
        } else if sev.tier == "sonnet" {
            ev.sonnet_combined_ts = ev.sonnet_combined_ts.max(sev.launch_ts);
            ev.sonnet_combined_end_ts = ev.sonnet_combined_end_ts.max(sev.end_ts);
        } else {
            ev.fallback_combined_ts = ev.fallback_combined_ts.max(sev.launch_ts);
            ev.fallback_combined_end_ts = ev.fallback_combined_end_ts.max(sev.end_ts);
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
            .filter(|(poster, btext, _, _, _)| {
                !btext.is_empty() && !poster.is_empty() && poster != "coordinator"
            })
            .count(),
    );
    ev
}

#[derive(Debug, Clone, Default)]
pub struct SubagentEvidence {
    pub fallback_lenses: HashMap<String, f64>,
    pub fallback_lenses_end: HashMap<String, f64>,
    pub fallback_combined_ts: f64,
    pub fallback_combined_end_ts: f64,
    pub simplify_launch_steps: HashSet<usize>,
    pub simplify_history: Vec<SimplifyHistoryItem>,
    pub simplify_failures: i64,
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
            // INVARIANT: Credit `invoke_subagent` simplify runs only when inherited inside a verified Hydrogen XHigh swarm worker.
            let has_simplify_fallback_provenance = is_simplify_subagent
                && caller_worker_model
                    .as_deref()
                    .map_or(false, |m| SIMPLIFY_FALLBACK_MODELS.contains(&m))
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
                        ev.simplify_failures += 1;
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
                        if chosen_skind == "lens" {
                            if let Some(ref sl) = chosen_slens {
                                let l_entry = ev.fallback_lenses.entry(sl.clone()).or_insert(0.0);
                                *l_entry = (*l_entry).max(eff_launch_ts);
                                let e_entry =
                                    ev.fallback_lenses_end.entry(sl.clone()).or_insert(0.0);
                                *e_entry = (*e_entry).max(eff_end_ts);
                                ev.simplify_history.push(SimplifyHistoryItem {
                                    kind: "lens".to_string(),
                                    lens: Some(sl.clone()),
                                    tier: "fallback".to_string(),
                                    launch_ts: eff_launch_ts,
                                    end_ts: eff_end_ts,
                                    seq: 0,
                                    clean: true,
                                    has_explicit_all: false,
                                });
                            }
                        } else if chosen_skind == "combined" {
                            ev.fallback_combined_ts = ev.fallback_combined_ts.max(eff_launch_ts);
                            ev.fallback_combined_end_ts = ev.fallback_combined_end_ts.max(eff_end_ts);
                            ev.simplify_history.push(SimplifyHistoryItem {
                                kind: "combined".to_string(),
                                lens: None,
                                tier: "fallback".to_string(),
                                launch_ts: eff_launch_ts,
                                end_ts: eff_end_ts,
                                seq: 0,
                                clean: true,
                                has_explicit_all: true,
                            });
                        }
                    }
                } else if sub_text.is_empty() && has_simplify_fallback_provenance {
                    ev.simplify_failures += 1;
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

pub fn is_review_fresh(review: &Value, marker: &Value) -> bool {
    let marks: Vec<&Map<String, Value>> = marker
        .get("content_marks")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_object()).collect())
        .unwrap_or_default();
    is_review_fresh_marks(val_to_f64(review.get("launch_ts")), &marks)
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
    if effective_risk == "XHIGH" && !json_truthy(cls_rev.get("xhigh")) {
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
                    gen_steps[pos].2,
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
    effective_risk: &'a str,
    required_lenses: &'a HashSet<String>,
    active_simplify_windows: &'a [(f64, f64)],
    max_simplify_launch_ts: f64,
    max_simplify_end_ts: f64,
    all_simplify_steps: &'a HashSet<usize>,
    all_simplify_history: &'a [SimplifyHistoryItem],
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

    fn is_allowed_simplify_tier(&self, tier: &str) -> bool {
        tier == "sonnet" || (self.sonnet_issue && tier == "fallback")
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

        let mut any_in_ver = false;
        let mut done_lenses: HashSet<String> = HashSet::new();
        let mut done_combined = false;
        for sr in self.all_simplify_history {
            if !self.is_allowed_simplify_tier(&sr.tier)
                || sr.launch_ts < rev_edit_ts - 1e-6
                || sr.launch_ts >= next_edit_ts
            {
                continue;
            }
            any_in_ver = true;
            let s_lts = sr.launch_ts;
            let s_ets = s_lts.max(sr.end_ts);
            if s_lts <= rev_launch_ts && rev_launch_ts < s_ets {
                self.sim_ver_cache.insert(cache_key, false);
                return false;
            }
            if s_lts < rev_launch_ts {
                if !sr.clean {
                    if sr.kind == "lens" {
                        if let Some(ref sl) = sr.lens {
                            done_lenses.remove(sl);
                        }
                    } else {
                        done_combined = false;
                    }
                } else if sr.kind == "lens" {
                    if let Some(ref sl) = sr.lens {
                        done_lenses.insert(sl.clone());
                    }
                } else if sr.has_explicit_all {
                    done_combined = true;
                }
            }
        }
        let res = any_in_ver
            && ((self.allow_combined && !self.multi_lens_spoof && done_combined)
                || done_lenses.is_superset(self.required_lenses));
        self.sim_ver_cache.insert(cache_key, res);
        res
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
                        w_lts >= after_ts - 1e-6 && w_lts < before_ts && w_lts.max(w_ets) <= before_ts
                    });
        }
        let mut any_in_span = false;
        let mut done_lenses: HashSet<String> = HashSet::new();
        let mut done_combined = false;
        for sr in self.all_simplify_history {
            if !self.is_allowed_simplify_tier(&sr.tier)
                || sr.launch_ts < after_ts - 1e-6
                || sr.launch_ts >= before_ts
            {
                continue;
            }
            let s_lts = sr.launch_ts;
            let s_ets = s_lts.max(sr.end_ts);
            if s_ets > before_ts {
                return false;
            }
            any_in_span = true;
            if !sr.clean {
                if sr.kind == "lens" {
                    if let Some(ref sl) = sr.lens {
                        done_lenses.remove(sl);
                    }
                } else {
                    done_combined = false;
                }
            } else if sr.kind == "lens" {
                if let Some(ref sl) = sr.lens {
                    done_lenses.insert(sl.clone());
                }
            } else if sr.has_explicit_all {
                done_combined = true;
            }
        }
        any_in_span
            && ((self.allow_combined && !self.multi_lens_spoof && done_combined)
                || done_lenses.is_superset(self.required_lenses))
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
            &mut self.codex_bin_missing_cache,
            &mut self.breaker_info_cache,
        )
    }

    fn is_acceptable_engine(&mut self, rev_item: &Value) -> bool {
        is_acceptable_review_engine(
            rev_item,
            self.swarm_ev,
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
                self.is_allowed_simplify_tier(&sr.tier)
                    && sr.launch_ts >= rev_edit_ts - 1e-6
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
                    && self.is_allowed_simplify_tier(&sr.tier)
                    && sr.launch_ts >= rev_vts - 1e-6
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
    let raw_sonnet_map: HashMap<String, f64> = swarm_ev
        .sonnet_lenses
        .iter()
        .filter(|(_, &lts)| rr_ts <= 0.0 || lts >= rr_ts)
        .map(|(k, &v)| (k.clone(), v))
        .collect();
    let mut raw_fallback_map: HashMap<String, f64> = HashMap::new();
    for src_map in [&swarm_ev.fallback_lenses, &sub_ev.fallback_lenses] {
        for (k, v) in src_map {
            if rr_ts > 0.0 && *v < rr_ts {
                continue;
            }
            let e = raw_fallback_map.entry(k.clone()).or_insert(0.0);
            if *v > *e {
                *e = *v;
            }
        }
    }

    let sonnet_lenses: HashSet<String> = raw_sonnet_map
        .iter()
        .filter(|(_, &lts)| is_review_fresh(&json!({ "launch_ts": lts }), marker))
        .map(|(k, _)| k.clone())
        .collect();
    let fallback_lenses: HashSet<String> = raw_fallback_map
        .iter()
        .filter(|(_, &lts)| is_review_fresh(&json!({ "launch_ts": lts }), marker))
        .map(|(k, _)| k.clone())
        .collect();

    let sonnet_issue = swarm_ev.sonnet_issue_verified;
    let simplify_failures = swarm_ev.simplify_failures + sub_ev.simplify_failures;
    let simplify_exhausted = simplify_failures >= 2;

    let effective_lenses: HashSet<String> = if sonnet_issue {
        sonnet_lenses.union(&fallback_lenses).cloned().collect()
    } else {
        sonnet_lenses.clone()
    };
    let raw_effective_lenses: HashSet<String> = if sonnet_issue {
        raw_sonnet_map
            .keys()
            .chain(raw_fallback_map.keys())
            .cloned()
            .collect()
    } else {
        raw_sonnet_map.keys().cloned().collect()
    };
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
    let sonnet_combined_fresh = raw_sonnet_combined > 0.0
        && is_review_fresh(&json!({ "launch_ts": raw_sonnet_combined }), marker);
    let fallback_combined_fresh = raw_fallback_combined > 0.0
        && is_review_fresh(&json!({ "launch_ts": raw_fallback_combined }), marker);
    let combined_fresh = sonnet_combined_fresh || (sonnet_issue && fallback_combined_fresh);
    let combined_stale = (raw_sonnet_combined > 0.0 && !sonnet_combined_fresh)
        || (sonnet_issue && raw_fallback_combined > 0.0 && !fallback_combined_fresh);

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
                || (!fast_path && (sonnet_combined_fresh || fallback_combined_fresh)))
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
        let all_combined_union: HashSet<String> =
            sonnet_lenses.union(&fallback_lenses).cloned().collect();
        if !sonnet_issue
            && ((allow_combined && fallback_combined_fresh)
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
                        "simplify ran on fallback model without verified `{}` error/quota issue; run {} on `{}` via `swarm`",
                        cwg_common::SONNET_HIGH_MODEL,
                        target,
                        cwg_common::SONNET_HIGH_MODEL
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
            let reverify_model = if sonnet_issue {
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
    let mut raw_fallback_end_map: HashMap<String, f64> = HashMap::new();
    for src_end_map in [&swarm_ev.fallback_lenses_end, &sub_ev.fallback_lenses_end] {
        for (k, v) in src_end_map {
            let e = raw_fallback_end_map.entry(k.clone()).or_insert(0.0);
            if *v > *e {
                *e = *v;
            }
        }
    }

    let mut active_simplify_windows: Vec<(f64, f64)> = Vec::new();
    if needs_simplify {
        if allow_combined && combined_fresh && !multi_lens_spoof && !missing_lenses.is_empty() {
            if sonnet_combined_fresh {
                let c_lts = raw_sonnet_combined;
                let c_ets = c_lts.max(swarm_ev.sonnet_combined_end_ts);
                active_simplify_windows.push((c_lts, c_ets));
            } else {
                let c_lts = raw_fallback_combined;
                let c_ets = c_lts
                    .max(swarm_ev.fallback_combined_end_ts)
                    .max(sub_ev.fallback_combined_end_ts);
                active_simplify_windows.push((c_lts, c_ets));
            }
        } else {
            for k in &required_lenses {
                let use_fallback = sonnet_issue
                    && fallback_lenses.contains(k)
                    && (!sonnet_lenses.contains(k)
                        || raw_fallback_map.get(k).copied().unwrap_or(0.0)
                            >= raw_sonnet_map.get(k).copied().unwrap_or(0.0));
                if use_fallback {
                    let lts = raw_fallback_map.get(k).copied().unwrap_or(0.0);
                    let ets = lts.max(raw_fallback_end_map.get(k).copied().unwrap_or(0.0));
                    active_simplify_windows.push((lts, ets));
                } else if sonnet_lenses.contains(k) {
                    let lts = raw_sonnet_map.get(k).copied().unwrap_or(0.0);
                    let ets = lts.max(raw_sonnet_end_map.get(k).copied().unwrap_or(0.0));
                    active_simplify_windows.push((lts, ets));
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
    all_simplify_history.sort_by(SimplifyHistoryItem::chrono_cmp);

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
        effective_risk: &effective_risk,
        required_lenses: &required_lenses,
        active_simplify_windows: &active_simplify_windows,
        max_simplify_launch_ts,
        max_simplify_end_ts,
        all_simplify_steps: &all_simplify_steps,
        all_simplify_history: &all_simplify_history,
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
    let raw_closure_reviews: Vec<Value> = all_closure_reviews
        .iter()
        .filter(|r| eval.is_acceptable_engine(r))
        .cloned()
        .collect();

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
        || raw_fallback_combined > 0.0;
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
                        return (
                            false,
                            format!(
                                "{} candidate requires primary independent review first (`carbon-stack codex-lane review` -> `{}` -> `{}`) BEFORE simplify (`CARGO TEST -> REVIEW -> SIMPLIFY -> --closure`)",
                                effective_risk,
                                cwg_common::OPUS_HIGH_MODEL,
                                cwg_common::CARBON_HIGH_MODEL
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
                if let Some(last_pi) = post_simplify_ineligible.last() {
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
                return (
                    false,
                    format!(
                        "{} candidate lacks an independent `VERDICT: APPROVED` from Codex lane (`carbon-stack codex-lane review`, or internal `{}` -> `{}` only on verified outage)",
                        effective_risk,
                        cwg_common::OPUS_HIGH_MODEL,
                        cwg_common::CARBON_HIGH_MODEL
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
        if review_unavailable || simplify_exhausted {
            return (true, "draft-blocked".to_string());
        }
        return (
            false,
            "`draft-blocked` requires fresh `CLOSURE_VALIDATION: BLOCKED` after round-3 ESCALATE, or exhausted review/simplify lanes"
                .to_string(),
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

pub fn merge_sticky_outage_state(state: &mut Map<String, Value>, swarm_ev: &mut SwarmEvidence) {
    // INVARIANT: Propagate the earliest confirmed candidate outage timestamp bidirectionally between `state` and `swarm_ev` so a later in-window Opus failure never overwrites an earlier evicted Opus outage.
    if swarm_ev.sonnet_issue_verified || json_truthy(state.get("sonnet_issue_verified")) {
        state.insert("sonnet_issue_verified".to_string(), Value::Bool(true));
        swarm_ev.sonnet_issue_verified = true;
    }
    if swarm_ev.opus_issue_verified || json_truthy(state.get("opus_issue_verified")) {
        state.insert("opus_issue_verified".to_string(), Value::Bool(true));
        swarm_ev.opus_issue_verified = true;
        let obs_opus_ts = swarm_ev.opus_issue_ts;
        let prev_opus_ts = val_to_f64(state.get("opus_issue_ts"));
        let eff_opus_ts = if obs_opus_ts > 0.0 && prev_opus_ts > 0.0 {
            obs_opus_ts.min(prev_opus_ts)
        } else if obs_opus_ts > 0.0 {
            obs_opus_ts
        } else {
            prev_opus_ts
        };
        state.insert("opus_issue_ts".to_string(), json!(eff_opus_ts));
        swarm_ev.opus_issue_ts = eff_opus_ts;
    }
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

    let min_lts = rr_ts.max(after_ts - 1e-6);
    let mut hist: Vec<SimplifyHistoryItem> = swarm_ev
        .simplify_history
        .into_iter()
        .chain(sub_ev.simplify_history.into_iter())
        .filter(|sr| sr.launch_ts >= min_lts && sr.launch_ts < before_ts)
        .collect();
    if hist.is_empty() {
        return false;
    }
    hist.sort_by(|a, b| {
        a.launch_ts
            .total_cmp(&b.launch_ts)
            .then_with(|| a.end_ts.total_cmp(&b.end_ts))
    });

    let mut done_lenses: HashMap<String, f64> = HashMap::new();
    let mut done_combined_lts = 0.0_f64;
    for sr in &hist {
        if !(sr.tier == "sonnet" || (sonnet_issue && sr.tier == "fallback")) {
            continue;
        }
        if sr.launch_ts.max(sr.end_ts) > before_ts {
            return false;
        }
        if !sr.clean {
            if sr.kind == "lens" {
                if let Some(ref sl) = sr.lens {
                    done_lenses.remove(sl);
                }
            } else {
                done_combined_lts = 0.0;
            }
        } else if sr.kind == "lens" {
            if let Some(ref sl) = sr.lens {
                done_lenses.insert(sl.clone(), sr.launch_ts);
            }
        } else if sr.has_explicit_all {
            done_combined_lts = sr.launch_ts;
        }
    }

    let comb_ok = allow_combined
        && !multi_spoof
        && done_combined_lts > 0.0
        && (!require_fresh
            || is_review_fresh(&json!({ "launch_ts": done_combined_lts }), &eff_marker));
    let lenses_ok = ["reuse", "quality", "efficiency"].iter().all(|req| {
        done_lenses.get(*req).copied().map_or(false, |lts| {
            !require_fresh || is_review_fresh(&json!({ "launch_ts": lts }), &eff_marker)
        })
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
    codex_bin_missing_cache: &mut Option<bool>,
    breaker_info_cache: &mut Option<Value>,
) -> String {
    // INVARIANT: Internal escalation is valid ONLY when launched strictly after Codex unavailability was confirmed.
    let codex_missing = *codex_bin_missing_cache
        .get_or_insert_with(|| codex_lane::find_codex_binary().is_none());
    let breaker_val: &Value = breaker_info_cache.get_or_insert_with(codex_lane::breaker_status);
    let hist_slice = codex_lane::breaker_history_slice(breaker_val);
    let has_codex_issue = swarm_ev.codex_cmd_failed
        || json_truthy(breaker_val.get("tripped"))
        || !hist_slice.is_empty()
        || codex_missing;

    let was_codex_unavailable = if codex_missing {
        true
    } else {
        let launch_ts = val_to_f64(rev_item.get("launch_ts"));
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

    let inv_eng = val_to_str(rev_item.get("engine"));
    let carbon_ok = swarm_ev.opus_issue_verified
        && (json_truthy(rev_item.get("escalated_from_opus"))
            || swarm_ev.opus_issue_ts <= 0.0
            || val_to_f64(rev_item.get("launch_ts")) >= swarm_ev.opus_issue_ts);

    if (inv_eng == "internal-carbon" || inv_eng == "native") && !carbon_ok {
        let m_label = rev_item
            .get("model")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(cwg_common::CARBON_HIGH_MODEL);
        return format!(
            "internal review ran on `{}` without a verified `{}` error/quota/availability failure; run internal review on `{}` first",
            m_label,
            cwg_common::OPUS_HIGH_MODEL,
            cwg_common::OPUS_HIGH_MODEL
        );
    }
    if (inv_eng == "internal-opus" || inv_eng == "internal-carbon" || inv_eng == "native")
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
    codex_bin_missing_cache: &mut Option<bool>,
    breaker_info_cache: &mut Option<Value>,
) -> bool {
    let eng_name = val_to_str(rev_item.get("engine"));
    matches!(
        eng_name.as_str(),
        "codex" | "internal-opus" | "internal-carbon" | "native"
    ) && engine_priority_error_for_swarm(
        rev_item,
        swarm_ev,
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
    if let Some(Value::Object(st)) = rio::read_json(&cwg_common::enforcement_state_path(session)) {
        if (val_to_f64(st.get("candidate_first_ts")) - first_ts_val).abs() < 1e-6 {
            if json_truthy(st.get("sonnet_issue_verified")) {
                swarm_ev.sonnet_issue_verified = true;
            }
            if json_truthy(st.get("opus_issue_verified")) {
                swarm_ev.opus_issue_verified = true;
                let pts = val_to_f64(st.get("opus_issue_ts"));
                if pts > 0.0 && (swarm_ev.opus_issue_ts <= 0.0 || pts < swarm_ev.opus_issue_ts) {
                    swarm_ev.opus_issue_ts = pts;
                }
            }
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
        || (val_to_f64(live.get("last_durable_ts")) - val_to_f64(expected.get("last_durable_ts"))).abs() > 1e-6
        || val_to_f64(live.get("last_ts")) > val_to_f64(expected.get("last_ts")) + 1e-6
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
    state.insert("sonnet_issue_verified".to_string(), Value::Bool(false));
    state.insert("opus_issue_verified".to_string(), Value::Bool(false));
    state.insert("opus_issue_ts".to_string(), json!(0.0));
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
            format!(
                "- Для независимого ревью сначала проверьте `& \"{}\" codex-lane check`; если доступно — запустите `& \"{}\" codex-lane review --session \"{}\" {}{}--summary \"...\"`{} (при недоступности Codex запустите внутреннее ревью{} на `{}`{} через `swarm`, с эскалацией на `{}` при ошибке/квоте Opus).\n",
                cs_bin,
                cs_bin,
                session,
                phase_flag,
                xhigh_flag,
                kill_note,
                cls_mode_note,
                cwg_common::OPUS_HIGH_MODEL,
                xhigh_hint,
                cwg_common::CARBON_HIGH_MODEL
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
    if (val_to_f64(state.get("candidate_first_ts")) - first_ts).abs() >= 1e-6 {
        state.insert("candidate_first_ts".to_string(), json!(first_ts));
        state.insert("sonnet_issue_verified".to_string(), Value::Bool(false));
        state.insert("opus_issue_verified".to_string(), Value::Bool(false));
        state.insert("opus_issue_ts".to_string(), json!(0.0));
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
                || sub_ev.fallback_combined_ts > 0.0;
            let progress_sig = format!(
                "{}:{}:{}:{}",
                swarm_ev.worker_activity_count.unwrap_or(0),
                sub_ev.reviews.len(),
                sub_ev.fallback_lenses.len(),
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
}
