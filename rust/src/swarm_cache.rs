use regex::Regex;
use serde_json::{json, Map, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::cwg_common;
use crate::rio::{self, val_to_f64, val_to_i64, val_to_str};
use crate::win32_sqlite::now_sec;

pub const MAX_SWARM_WORKER_NAME_LEN: usize = 24;
pub const MAX_ROUND_HISTORY: usize = 16;

fn round_suffix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)-r\d+\z").expect("round_suffix_re"))
}

fn eprintln_line(msg: &str) {
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(msg.as_bytes());
    let _ = err.write_all(b"\n");
    let _ = err.flush();
}

pub fn base_worker_name(worker_name: &str) -> String {
    round_suffix_re()
        .replace(worker_name.trim(), "")
        .into_owned()
}

pub fn rotated_worker_name(base_name: &str, round_num: i64) -> String {
    // INVARIANT: Native Antigravity `swarm(action="add")` rejects worker names > 24 chars; keep full `<lens>` intact via `simp-<lens>-<hash>-r<N>`.
    let suffix = format!("-r{}", round_num);
    let limit = MAX_SWARM_WORKER_NAME_LEN.saturating_sub(suffix.len()).max(1);
    let raw_base = if base_name.is_empty() {
        "worker"
    } else {
        base_name
    };
    let stripped = base_worker_name(raw_base);
    let trimmed = stripped.trim_end_matches('-');
    let mut stem = if trimmed.is_empty() {
        "w".to_string()
    } else {
        trimmed.to_string()
    };
    let mut low_stem = stem.to_lowercase();
    if low_stem.starts_with("simplify-efficie-") && stem.chars().count() == 21 {
        let tail: String = stem
            .chars()
            .skip(stem.chars().count().saturating_sub(4))
            .collect();
        stem = format!("simp-efficiency-{}", tail);
        low_stem = stem.to_lowercase();
    }
    if stem.chars().count() <= limit {
        return format!("{}{}", stem, suffix);
    }
    if limit <= 5 {
        let head: String = stem.chars().take(limit).collect();
        return format!("{}{}", head, suffix);
    }
    let full_hex = rio::sha256_hex(stem.as_bytes());
    let digest = &full_hex[..4];
    if cwg_common::is_simplify_worker_name(&low_stem) {
        let raw_tag = cwg_common::simplify_lens_from_worker_name(&low_stem);
        let tag = if raw_tag.is_empty() {
            "all"
        } else {
            raw_tag.as_str()
        };
        for dlen in [4usize, 3, 2] {
            let compact = format!("simp-{}-{}", tag, &digest[..dlen]);
            if compact.chars().count() <= limit {
                return format!("{}{}", compact, suffix);
            }
        }
    }
    let raw_prefix: String = stem.chars().take(limit - 5).collect();
    let trimmed_prefix = raw_prefix.trim_end_matches('-');
    let prefix = if trimmed_prefix.is_empty() {
        "w"
    } else {
        trimmed_prefix
    };
    format!("{}-{}{}", prefix, digest, suffix)
}

pub fn resolve_brain_root(brain_root_arg: &str) -> PathBuf {
    rio::resolve_brain_root(brain_root_arg)
}

fn matches_label(worker_name: &str, label: &str, model: &str, brief: &str) -> bool {
    let clean = label.trim().to_lowercase();
    if clean.is_empty() {
        return true;
    }
    let low = worker_name.trim().to_lowercase();
    let model_low = model.trim().to_lowercase();
    let is_simplify = cwg_common::is_simplify_worker_name(&low)
        || !cwg_common::simplify_lens_from_worker_name(&low).is_empty();
    if clean == "simplify" {
        if !is_simplify {
            return false;
        }
        return model_low.is_empty() || cwg_common::is_simplify_allowed_model(&model_low);
    }
    if clean == "review" {
        // INVARIANT: Align Warm Pool review-worker selection with the gate (`cwg_stop` /
        // `cwg_common`): allow only gate review models (`opus-high`, `carbon-high`, `neon-xhigh`,
        // or unset), and require role confirmation via name or assignment brief for multi-role
        // models (`carbon-high`, `neon-xhigh`) so Carbon builders never trigger `resume_in_place`
        // while brief-assigned Neon reviewers (e.g. `neon-audit`) are included.
        if is_simplify {
            return false;
        }
        if model_low == cwg_common::OPUS_HIGH_MODEL {
            return true;
        }
        if !model_low.is_empty()
            && model_low != cwg_common::CARBON_HIGH_MODEL
            && model_low != cwg_common::NEON_XHIGH_MODEL
        {
            return false;
        }
        return cwg_common::is_review_worker_hint(&low, brief);
    }
    low.contains(&clean)
}

fn summarize_diff_stat(diff_text: &str) -> String {
    if diff_text.is_empty() {
        return "0 files changed".to_string();
    }
    let mut files: usize = 0;
    let mut adds: usize = 0;
    let mut dels: usize = 0;
    for line in diff_text.lines() {
        if line.starts_with("diff --git ") {
            files += 1;
        } else if line.starts_with('+') && !line.starts_with("+++ ") {
            adds += 1;
        } else if line.starts_with('-') && !line.starts_with("--- ") {
            dels += 1;
        }
    }
    format!(
        "{} file(s) changed, {} insertion(s)(+), {} deletion(s)(-)",
        files, adds, dels
    )
}

fn inspect_worker_transcript(worker_tp: &Path) -> Value {
    let resolved = rio::resolve_transcript_path(&worker_tp.to_string_lossy())
        .unwrap_or_else(|| worker_tp.to_path_buf());
    let is_file = resolved.is_file();
    let t_bytes = if is_file {
        fs::metadata(&resolved).map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };
    let steps = if is_file {
        rio::read_jsonl(&resolved, Some(120))
    } else {
        Vec::new()
    };

    let mut last_model_ts: f64 = 0.0;
    let mut model_turns: i64 = 0;
    let mut last_input_tokens: i64 = 0;
    let mut last_cache_read_tokens: i64 = 0;
    let mut last_output_tokens: i64 = 0;

    for st in &steps {
        let Some(obj) = st.as_object() else {
            continue;
        };
        if obj.get("source").and_then(|v| v.as_str()) != Some("MODEL") {
            continue;
        }
        model_turns += 1;
        let ts = match obj.get("created_at") {
            Some(Value::String(s)) => rio::parse_iso_ts(s),
            Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
            _ => 0.0,
        };
        if ts > 0.0 && ts > last_model_ts {
            last_model_ts = ts;
        }
        if obj.contains_key("input_tokens") || obj.contains_key("cache_read_tokens") {
            last_input_tokens = val_to_i64(obj.get("input_tokens"));
            last_cache_read_tokens = val_to_i64(obj.get("cache_read_tokens"));
            last_output_tokens = val_to_i64(obj.get("output_tokens"));
        }
    }

    json!({
        "transcript_path": rio::normalize_path(&resolved.to_string_lossy()),
        "transcript_bytes": t_bytes,
        "last_model_ts": last_model_ts,
        "model_turns": model_turns,
        "last_input_tokens": last_input_tokens,
        "last_cache_read_tokens": last_cache_read_tokens,
        "last_context_tokens": last_input_tokens + last_cache_read_tokens,
        "last_output_tokens": last_output_tokens,
    })
}

pub fn inspect_swarm_workers(
    session: &str,
    brain_root: &Path,
    ttl_seconds: u64,
    label: &str,
    now_ts: Option<f64>,
    current_round: i64,
) -> Value {
    inspect_swarm_workers_inner(
        session,
        brain_root,
        ttl_seconds,
        label,
        now_ts,
        current_round,
        None,
    )
}

fn inspect_swarm_workers_with_marker(
    session: &str,
    brain_root: &Path,
    ttl_seconds: u64,
    label: &str,
    now_ts: Option<f64>,
    current_round: i64,
    marker: Option<&Value>,
) -> Value {
    inspect_swarm_workers_inner(
        session,
        brain_root,
        ttl_seconds,
        label,
        now_ts,
        current_round,
        Some(marker),
    )
}

fn inspect_swarm_workers_inner(
    session: &str,
    brain_root: &Path,
    ttl_seconds: u64,
    label: &str,
    now_ts: Option<f64>,
    current_round: i64,
    marker_override: Option<Option<&Value>>,
) -> Value {
    let now = now_ts.unwrap_or_else(now_sec);
    let members = rio::load_swarm_members(brain_root, session);
    let mut names: Vec<&String> = members.keys().collect();
    names.sort();

    let label_low = label.trim().to_lowercase();
    let is_gated_lane = label_low == "simplify" || label_low == "review";
    let loaded_marker = if marker_override.is_none() && is_gated_lane && !members.is_empty() {
        cwg_common::read_active_marker_with_pending(session)
    } else {
        None
    };
    let marker = match marker_override {
        Some(m) => m,
        None => loaded_marker.as_ref(),
    };
    let rr_ts = marker.map_or(0.0, cwg_common::last_research_reset_ts);
    let rr_seq = marker.map_or(0, cwg_common::last_research_reset_board_seq);
    let has_reset = rr_ts > 0.0 || rr_seq > 0;
    let known_workers = if label_low == "review" {
        rio::swarm_worker_names(&members)
    } else {
        Vec::new()
    };
    let mut raw_board_cache: Option<Vec<Value>> = None;
    let mut board_briefs_cache: Option<std::collections::HashMap<String, String>> = None;

    let mut active: Vec<Value> = Vec::new();
    let mut killed_count: usize = 0;

    for name in names {
        let Some(meta) = members.get(name) else {
            continue;
        };
        if !meta.is_object() || rio::is_swarm_role_member(name, Some(meta)) {
            continue;
        }
        let model = val_to_str(meta.get("model")).trim().to_lowercase();
        let meta_brief = val_to_str(meta.get("brief"));
        let direct_match = matches_label(name, &label_low, &model, &meta_brief);
        let can_match_via_board = !direct_match
            && label_low == "review"
            && (model.is_empty()
                || model == cwg_common::CARBON_HIGH_MODEL
                || model == cwg_common::NEON_XHIGH_MODEL);
        if !direct_match && !can_match_via_board {
            continue;
        }
        // INVARIANT: Align Warm Pool selection with `cwg_stop`'s `research-reset` cycle boundary:
        // ignore pre-reset simplify/review workers (fresh sessions enforced) and never inherit
        // pre-reset coordinator board briefs when a post-reset worker reuses the same roster name.
        if has_reset && is_gated_lane {
            let raw_board = raw_board_cache
                .get_or_insert_with(|| cwg_common::read_swarm_board_tail(brain_root, session));
            if cwg_common::is_worker_spawned_before_reset(
                name,
                Some(meta),
                raw_board,
                rr_ts,
                rr_seq,
                marker,
                Some(brain_root),
            ) {
                continue;
            }
        }
        let matched = if direct_match {
            true
        } else {
            let briefs = board_briefs_cache.get_or_insert_with(|| {
                let raw_board = raw_board_cache
                    .get_or_insert_with(|| cwg_common::read_swarm_board_tail(brain_root, session));
                cwg_common::collect_coordinator_board_briefs(
                    raw_board,
                    &known_workers,
                    &known_workers,
                    rr_seq,
                    rr_ts,
                )
            });
            briefs
                .get(name)
                .is_some_and(|b| matches_label(name, &label_low, &model, b))
        };
        if rio::is_swarm_member_killed(Some(meta)) {
            if matched {
                killed_count += 1;
            }
            continue;
        }
        if !matched {
            continue;
        }

        let cid = val_to_str(
            meta.get("conversation_id")
                .or_else(|| meta.get("conversationId")),
        )
        .trim()
        .to_string();

        let tinfo = if !cid.is_empty() {
            inspect_worker_transcript(&rio::member_transcript_path(brain_root, &cid))
        } else {
            json!({
                "transcript_path": "",
                "transcript_bytes": 0,
                "last_model_ts": 0.0,
                "model_turns": 0,
                "last_input_tokens": 0,
                "last_cache_read_tokens": 0,
                "last_context_tokens": 0,
                "last_output_tokens": 0,
            })
        };

        let last_ts = val_to_f64(tinfo.get("last_model_ts"));
        // INVARIANT: Anthropic 5-minute ephemeral prompt-cache expiry (`270s`) applies only to `claude-*` models; non-Claude Warm Pool workers (`gemini-4-hydrogen-*`) retain warm conversation context across rounds and resume via `@mention`.
        let uses_ephemeral_ttl = model.is_empty() || model.starts_with("claude-");
        let (cache_state, age_s, rem_s, rec_action) = if last_ts <= 0.0 {
            ("NEW", 0.0, ttl_seconds as f64, "wait_or_assign")
        } else {
            let age = ((now - last_ts).max(0.0) * 10.0).round() / 10.0;
            let rem = if uses_ephemeral_ttl {
                (((ttl_seconds as f64) - age).max(0.0) * 10.0).round() / 10.0
            } else {
                ttl_seconds as f64
            };
            if !uses_ephemeral_ttl || age <= ttl_seconds as f64 {
                ("WARM", age, rem, "resume_in_place")
            } else {
                ("EXPIRED", age, rem, "rotate_incremental")
            }
        };

        let mut entry = Map::new();
        entry.insert("name".to_string(), Value::String(name.clone()));
        entry.insert("base_name".to_string(), Value::String(base_worker_name(name)));
        entry.insert("conversation_id".to_string(), Value::String(cid));
        entry.insert("model".to_string(), Value::String(model));
        entry.insert("cache_state".to_string(), Value::String(cache_state.to_string()));
        entry.insert("age_seconds".to_string(), json!(age_s));
        entry.insert("remaining_ttl_seconds".to_string(), json!(rem_s));
        entry.insert(
            "recommended_action".to_string(),
            Value::String(rec_action.to_string()),
        );
        if let Value::Object(tmap) = tinfo {
            for (k, v) in tmap {
                entry.insert(k, v);
            }
        }
        active.push(Value::Object(entry));
    }

    let expired_workers: Vec<String> = active
        .iter()
        .filter(|w| w.get("cache_state").and_then(|v| v.as_str()) == Some("EXPIRED"))
        .filter_map(|w| w.get("name").and_then(|v| v.as_str()).map(|s| s.to_string()))
        .collect();
    let warm_workers: Vec<String> = active
        .iter()
        .filter(|w| w.get("cache_state").and_then(|v| v.as_str()) == Some("WARM"))
        .filter_map(|w| w.get("name").and_then(|v| v.as_str()).map(|s| s.to_string()))
        .collect();

    let overall = if active.is_empty() {
        if current_round == 1 {
            "initial_spawn"
        } else if current_round >= 2 || killed_count > 0 {
            "spawn_incremental"
        } else {
            "initial_spawn"
        }
    } else if !expired_workers.is_empty() {
        "rotate_incremental"
    } else if !warm_workers.is_empty() {
        "resume_in_place"
    } else {
        "wait_or_assign"
    };

    let eff_label = if label.is_empty() { "all" } else { label };
    json!({
        "session": session,
        "label": eff_label,
        "anthropic_ephemeral_ttl_seconds": cwg_common::ANTHROPIC_EPHEMERAL_TTL_SECONDS,
        "safe_ttl_seconds": ttl_seconds,
        "active_count": active.len(),
        "killed_count": killed_count,
        "overall_action": overall,
        "expired_workers": expired_workers,
        "warm_workers": warm_workers,
        "workers": active,
    })
}

fn git_diff_pair(
    git_root: &str,
    old_oid: &str,
    new_oid: &str,
    paths: &[String],
) -> Result<String, String> {
    let mut args: Vec<&str> = vec![
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--full-index",
        old_oid,
        new_oid,
    ];
    if !paths.is_empty() {
        args.push("--");
        for p in paths {
            args.push(p.as_str());
        }
    }
    let (rc, out, err) = rio::run_git(git_root, &args, 15.0);
    if rc != 0 {
        let detail = if !err.trim().is_empty() {
            err.trim().to_string()
        } else if !out.trim().is_empty() {
            out.trim().to_string()
        } else {
            format!("rc={}", rc)
        };
        return Err(format!("git_diff_failed:{}", detail));
    }
    Ok(out)
}

fn has_uncovered_binary_diff(
    git_root: &str,
    old_oid: &str,
    new_oid: &str,
    paths: &[String],
    diff_text: &str,
) -> bool {
    if !diff_text.contains("\nBinary files ") && !diff_text.starts_with("Binary files ") {
        return false;
    }
    let mut args: Vec<&str> = vec![
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--numstat",
        "-z",
        old_oid,
        new_oid,
    ];
    if !paths.is_empty() {
        args.push("--");
        for p in paths {
            args.push(p.as_str());
        }
    }
    let (rc, out, _) = rio::run_git(git_root, &args, 15.0);
    if rc != 0 {
        return true;
    }
    for rec in out.split('\0') {
        if rec.is_empty() {
            continue;
        }
        let mut parts = rec.splitn(3, '\t');
        let (Some(added), Some(deleted), Some(rel)) = (parts.next(), parts.next(), parts.next())
        else {
            return true;
        };
        if added == "-" && deleted == "-" && !cwg_common::is_known_binary_artifact_rel(rel) {
            return true;
        }
    }
    false
}

fn format_crlf_notes(notes: &[(String, String)]) -> String {
    if notes.is_empty() {
        return String::new();
    }
    let mut out = String::from("# Working-tree CRLF files (normalized to LF in Git tree):\n");
    for (rel, sha) in notes {
        out.push_str("#   ");
        out.push_str(rel);
        out.push_str(" (raw_sha256=");
        out.push_str(sha);
        out.push_str(")\n");
    }
    out
}

fn write_scratch_text(path: &Path, content: &str) -> Result<String, String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir_failed:{}", e))?;
    }
    fs::write(path, content.as_bytes()).map_err(|e| format!("write_failed:{}", e))?;
    Ok(rio::normalize_path(&path.to_string_lossy()))
}

struct SyncDiffResult {
    full_diff_path: String,
    incremental_diff_path: String,
    incremental_stat: String,
}

struct RoundSyncInput<'a> {
    git_root: &'a str,
    head_oid: &'a str,
    prev_head_oid: &'a str,
    cur_tree_oid: &'a str,
    prev_tree_oid: &'a str,
    cur_crlf_summary: &'a str,
    prev_crlf_summary: &'a str,
    rel_paths: &'a [String],
    scratch_dir: &'a Path,
    clean_label: &'a str,
    cur_round: i64,
    regen: bool,
    enforce_text_coverage: bool,
}

fn format_head_diff_body(header: &str, full_diff: &str, cur_crlf_summary: &str) -> String {
    let diff_body = if full_diff.is_empty() && cur_crlf_summary.is_empty() {
        "# No diff against HEAD.\n"
    } else {
        full_diff
    };
    let mut body =
        String::with_capacity(header.len() + diff_body.len() + cur_crlf_summary.len() + 2);
    body.push_str(header);
    body.push_str(diff_body);
    if !cur_crlf_summary.is_empty() {
        if !body.is_empty() && !body.ends_with('\n') {
            body.push('\n');
        }
        body.push_str(cur_crlf_summary);
    }
    body
}

fn diff_snapshot_tag(
    base_oid: &str,
    cur_tree_oid: &str,
    extra_meta: &str,
    rel_paths: &[String],
) -> String {
    let mut material =
        String::with_capacity(base_oid.len() + cur_tree_oid.len() + extra_meta.len() + 32);
    material.push_str(base_oid);
    material.push('\0');
    material.push_str(cur_tree_oid);
    material.push('\0');
    material.push_str(extra_meta);
    for p in rel_paths {
        material.push('\0');
        material.push_str(p);
    }
    rio::sha256_hex(material.as_bytes())
        .chars()
        .take(12)
        .collect()
}

fn sync_round_diffs(input: RoundSyncInput<'_>) -> Result<SyncDiffResult, String> {
    let RoundSyncInput {
        git_root,
        head_oid,
        prev_head_oid,
        cur_tree_oid,
        prev_tree_oid,
        cur_crlf_summary,
        prev_crlf_summary,
        rel_paths,
        scratch_dir,
        clean_label,
        cur_round,
        regen,
        enforce_text_coverage,
    } = input;
    let base_changed = cur_round >= 2 && (prev_head_oid.is_empty() || prev_head_oid != head_oid);
    let full_tag = diff_snapshot_tag(head_oid, cur_tree_oid, cur_crlf_summary, rel_paths);
    let full_file = scratch_dir.join(format!(
        "{}_r{}_{}_full.diff",
        clean_label, cur_round, full_tag
    ));
    let need_full = regen || !full_file.is_file();

    let inc_file = if cur_round >= 2 && (base_changed || !prev_tree_oid.is_empty()) {
        let (inc_base, inc_meta) = if base_changed {
            (
                head_oid,
                format!("BASE_SHIFT:{}\n{}", prev_head_oid, cur_crlf_summary),
            )
        } else {
            (
                prev_tree_oid,
                format!("{}\n---\n{}", prev_crlf_summary, cur_crlf_summary),
            )
        };
        let inc_tag = diff_snapshot_tag(inc_base, cur_tree_oid, &inc_meta, rel_paths);
        Some(scratch_dir.join(format!(
            "{}_r{}_{}_incremental.diff",
            clean_label, cur_round, inc_tag
        )))
    } else {
        None
    };
    let need_inc = inc_file
        .as_ref()
        .map_or(false, |f| regen || !f.is_file());
    let need_head_diff = need_full || (need_inc && base_changed);
    let full_diff = if need_head_diff {
        git_diff_pair(git_root, head_oid, cur_tree_oid, rel_paths)?
    } else {
        String::new()
    };
    let inc_diff = if need_inc && !base_changed && prev_tree_oid != cur_tree_oid {
        git_diff_pair(git_root, prev_tree_oid, cur_tree_oid, rel_paths)?
    } else {
        String::new()
    };

    if enforce_text_coverage {
        if need_head_diff
            && has_uncovered_binary_diff(git_root, head_oid, cur_tree_oid, rel_paths, &full_diff)
        {
            return Err("uncovered_binary_diff".to_string());
        }
        if need_inc
            && !base_changed
            && prev_tree_oid != cur_tree_oid
            && has_uncovered_binary_diff(git_root, prev_tree_oid, cur_tree_oid, rel_paths, &inc_diff)
        {
            return Err("uncovered_binary_diff".to_string());
        }
    }

    let full_diff_path = if need_full {
        if !full_diff.is_empty() && cur_crlf_summary.is_empty() {
            write_scratch_text(&full_file, &full_diff)?
        } else {
            let full_body = format_head_diff_body("", &full_diff, cur_crlf_summary);
            write_scratch_text(&full_file, &full_body)?
        }
    } else {
        rio::normalize_path(&full_file.to_string_lossy())
    };

    let Some(inc_path) = inc_file else {
        return Ok(SyncDiffResult {
            full_diff_path,
            incremental_diff_path: String::new(),
            incremental_stat: String::new(),
        });
    };

    // INVARIANT: When `HEAD` shifts between rounds (`base_changed`), tree-to-tree comparison misses newly exposed `HEAD..tree` hunks; emit the full candidate diff against the new `HEAD` in `incremental_diff_path` as well.
    if base_changed {
        let (inc_diff_path, stat) = if need_inc {
            let stat = summarize_diff_stat(&full_diff);
            let prev_h_short: String = if prev_head_oid.is_empty() {
                "unknown".to_string()
            } else {
                prev_head_oid.chars().take(12).collect()
            };
            let cur_h_short: String = head_oid.chars().take(12).collect();
            let header = format!(
                "# Base HEAD changed Round {} -> Round {} ({}..{}); full candidate diff against new HEAD\n",
                cur_round - 1,
                cur_round,
                prev_h_short,
                cur_h_short
            );
            let body = format_head_diff_body(&header, &full_diff, cur_crlf_summary);
            (write_scratch_text(&inc_path, &body)?, stat)
        } else {
            let raw = fs::read(&inc_path).unwrap_or_default();
            let cached = String::from_utf8_lossy(&raw);
            (
                rio::normalize_path(&inc_path.to_string_lossy()),
                summarize_diff_stat(&cached),
            )
        };
        let incremental_stat = if stat.is_empty() {
            "HEAD base changed; no diff against new HEAD".to_string()
        } else {
            format!("HEAD base changed; full diff: {}", stat)
        };
        return Ok(SyncDiffResult {
            full_diff_path,
            incremental_diff_path: inc_diff_path,
            incremental_stat,
        });
    }

    let eol_changed = prev_crlf_summary != cur_crlf_summary;
    let (inc_diff_path, raw_inc_empty, stat) = if need_inc {
        let raw_inc_empty = inc_diff.is_empty();
        let stat = summarize_diff_stat(&inc_diff);
        let prev_short: String = prev_tree_oid.chars().take(12).collect();
        let cur_short: String = cur_tree_oid.chars().take(12).collect();
        let header = format!(
            "# Incremental diff Round {} -> Round {}\n# Trees: {}..{}\n",
            cur_round - 1,
            cur_round,
            prev_short,
            cur_short
        );
        let mut body =
            String::with_capacity(header.len() + inc_diff.len() + cur_crlf_summary.len() + 64);
        body.push_str(&header);
        if raw_inc_empty && !eol_changed {
            body.push_str("# No textual changes since previous round.\n");
        } else {
            body.push_str(&inc_diff);
        }
        if eol_changed {
            if !body.ends_with('\n') {
                body.push('\n');
            }
            if cur_crlf_summary.is_empty() {
                body.push_str("# Working-tree CRLF files normalized to LF since previous round.\n");
            } else {
                body.push_str(cur_crlf_summary);
            }
        }
        (write_scratch_text(&inc_path, &body)?, raw_inc_empty, stat)
    } else {
        let raw = fs::read(&inc_path).unwrap_or_default();
        let cached = String::from_utf8_lossy(&raw);
        let stat = summarize_diff_stat(&cached);
        let raw_inc_empty = !cached.contains("\ndiff --git ");
        (
            rio::normalize_path(&inc_path.to_string_lossy()),
            raw_inc_empty,
            stat,
        )
    };

    let incremental_stat = if raw_inc_empty && eol_changed {
        "working-tree CRLF metadata changed".to_string()
    } else {
        stat
    };

    Ok(SyncDiffResult {
        full_diff_path,
        incremental_diff_path: inc_diff_path,
        incremental_stat,
    })
}

fn entry_paths(entry: &Value) -> Vec<String> {
    entry
        .get("paths")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

pub struct PrepareRoundInput<'a> {
    pub session: &'a str,
    pub cwd: &'a str,
    pub brain_root: &'a Path,
    pub label: &'a str,
    pub ttl_seconds: u64,
    pub paths: &'a [String],
    pub reset: bool,
    pub now_ts: Option<f64>,
}

fn is_active_same_repo_marker(marker: &Value, folded_git_root: &str) -> bool {
    cwg_common::is_active_marker(marker) && {
        let m_gr = val_to_str(marker.get("git_root"));
        !m_gr.is_empty() && rio::fold_path(&m_gr) == folded_git_root
    }
}

fn stamp_rounds_marker_ts(state: &mut Map<String, Value>, marker_first_ts: f64) {
    let eff_mts = if marker_first_ts != 0.0 {
        marker_first_ts
    } else {
        val_to_f64(state.get("marker_first_ts"))
    };
    state.insert("marker_first_ts".to_string(), json!(eff_mts));
}

fn ensure_object_mut<'a>(
    map: &'a mut Map<String, Value>,
    key: &str,
) -> &'a mut Map<String, Value> {
    let slot = map
        .entry(key.to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if !slot.is_object() {
        *slot = Value::Object(Map::new());
    }
    slot.as_object_mut().expect("object slot initialized")
}

// INVARIANT: Return `true` whenever capping `list` at 64 evicts an entry so bounded provenance windows fail closed by latching `snapshot_bound_required` for the remainder of the candidate cycle.
fn push_capped_64(list: &mut Vec<String>, item: String) -> bool {
    if item.is_empty() || list.iter().any(|s| s == &item) {
        return false;
    }
    list.push(item);
    if list.len() > 64 {
        list.drain(1..list.len() - 63);
        return true;
    }
    false
}

fn with_locked_marker<T, F>(skey: &str, mfile: &Path, f: F) -> Result<T, String>
where
    F: FnOnce(Option<Value>, Option<Value>, Vec<String>) -> Result<T, String>,
{
    rio::with_file_lock(&cwg_common::marker_lock_path(skey), 5.0, 30.0, |locked| {
        if !locked {
            return Err("marker_lock_timeout".to_string());
        }
        let raw_m = rio::read_json(mfile);
        if raw_m.is_none() && mfile.exists() {
            return Err("marker_read_failed".to_string());
        }
        let (merged_opt, consumed_ids) =
            cwg_common::apply_pending_marker_deltas(skey, raw_m.as_ref());
        f(raw_m, merged_opt, consumed_ids)
    })
}

fn marker_cycle_or_reset_mismatch(
    cur_m: &Value,
    expected_cycle_ts: f64,
    expected_rr_ts: f64,
) -> bool {
    cwg_common::cycle_ts_mismatch(cwg_common::marker_cycle_first_ts(cur_m), expected_cycle_ts)
        || (cwg_common::last_research_reset_ts(cur_m) - expected_rr_ts).abs() > cwg_common::TS_EPS
}

fn sync_marker_under_lock(
    skey: &str,
    mfile: &Path,
    folded_git_root: &str,
    now_ts: Option<f64>,
) -> Result<(Option<Value>, bool), String> {
    with_locked_marker(skey, mfile, |raw_m, merged_opt, consumed_ids| {
        let Some(merged) = merged_opt else {
            return Ok((None, false));
        };
        let mut caught = if is_active_same_repo_marker(&merged, folded_git_root)
            && (merged.get("content_marks").is_some()
                || val_to_str(merged.get("current_diff_hash")).is_empty())
        {
            let mark_now = now_ts.unwrap_or_else(now_sec);
            crate::cwg_stop::catch_up_unmeasured_changes_at(&merged, Some(mark_now))
        } else {
            merged
        };
        let had_prior_cycle_prepare = cwg_common::marker_has_prepare_cycle(Some(&caught));
        if cwg_common::is_active_marker(&caught) {
            let cycle_ts = cwg_common::marker_cycle_first_ts(&caught);
            let stamp_ts = if cycle_ts > 0.0 {
                cycle_ts
            } else {
                now_ts.unwrap_or_else(now_sec).max(1.0)
            };
            if let Some(obj) = caught.as_object_mut() {
                let prev_prep = val_to_f64(obj.get("swarm_prepare_cycle_ts"));
                if prev_prep <= 0.0 || cwg_common::cycle_ts_mismatch(prev_prep, stamp_ts) {
                    obj.insert("swarm_prepare_cycle_ts".to_string(), json!(stamp_ts));
                    obj.insert(
                        "swarm_prepare_repo_state".to_string(),
                        Value::Object(Map::new()),
                    );
                }
            }
        }
        if !consumed_ids.is_empty() || Some(&caught) != raw_m.as_ref() {
            if let Err(err) = rio::write_json(mfile, &caught) {
                return Err(format!("marker_persist_failed:{}", err));
            }
            if !consumed_ids.is_empty() {
                cwg_common::ack_pending_marker_deltas(skey, &consumed_ids);
            }
        }
        Ok((Some(caught), had_prior_cycle_prepare))
    })
}

#[derive(Clone, Copy)]
struct MarkerRepoPrepUpdate<'a> {
    skey: &'a str,
    mfile: &'a Path,
    folded_git_root: &'a str,
    expected_cycle_ts: f64,
    expected_research_reset_ts: f64,
    expected_last_durable_ts: f64,
    expected_dpaths: &'a [String],
    expected_diff_hash: &'a str,
    seen_heads: &'a [String],
    seen_fp_trees: &'a [String],
    snapshot_bound_required: bool,
}

fn commit_rounds_under_marker_lock(
    rfile: &Path,
    rounds_doc: Option<&Value>,
) -> Result<(), String> {
    match rounds_doc {
        Some(doc) => rio::write_json(rfile, doc)
            .map_err(|err| format!("swarm_rounds_write_failed:{}", err)),
        None if rfile.is_file() => Ok(()),
        None => Err("concurrent_worktree_mutation".to_string()),
    }
}

fn persist_marker_repo_prepare_state(
    upd: MarkerRepoPrepUpdate<'_>,
    strict_commit: bool,
    persist_write: bool,
    rounds_file: &Path,
    rounds_doc: Option<&Value>,
) -> Result<Option<Value>, String> {
    // INVARIANT: Re-verify marker identity, `research_resets` cursor, pending hook deltas, durable path list, and measured fingerprint under `marker_lock_path`, and commit `rounds.json` inside the same lock so concurrent `research-reset` or candidate turnover cannot race `prepare`.
    with_locked_marker(upd.skey, upd.mfile, |raw_m, merged_opt, consumed_ids| {
        let (mut next_m, ack_ids) = if strict_commit {
            if !consumed_ids.is_empty() {
                return Err("concurrent_worktree_mutation".to_string());
            }
            let Some(cur_m) = raw_m else {
                return Err("concurrent_worktree_mutation".to_string());
            };
            let live_dur = val_to_f64(cur_m.get("last_durable_ts"));
            if !is_active_same_repo_marker(&cur_m, upd.folded_git_root)
                || marker_cycle_or_reset_mismatch(
                    &cur_m,
                    upd.expected_cycle_ts,
                    upd.expected_research_reset_ts,
                )
                || (live_dur - upd.expected_last_durable_ts).abs() > cwg_common::TS_EPS
                || cwg_common::durable_paths_from_val(cur_m.get("paths")) != upd.expected_dpaths
                || val_to_str(cur_m.get("current_diff_hash")) != upd.expected_diff_hash
                || (!upd.expected_dpaths.is_empty()
                    && cwg_common::content_fingerprint(
                        upd.expected_dpaths,
                        cwg_common::MAX_FINGERPRINT_FILE_BYTES,
                    ) != upd.expected_diff_hash)
            {
                return Err("concurrent_worktree_mutation".to_string());
            }
            if !persist_write {
                commit_rounds_under_marker_lock(rounds_file, rounds_doc)?;
                return Ok(Some(cur_m));
            }
            (cur_m, Vec::new())
        } else {
            let Some(cur_m) = merged_opt else {
                return Err("concurrent_worktree_mutation".to_string());
            };
            if !cwg_common::is_active_marker(&cur_m)
                || marker_cycle_or_reset_mismatch(
                    &cur_m,
                    upd.expected_cycle_ts,
                    upd.expected_research_reset_ts,
                )
            {
                return Err("concurrent_worktree_mutation".to_string());
            }
            (cur_m, consumed_ids)
        };

        let Some(obj) = next_m.as_object_mut() else {
            return Err("concurrent_worktree_mutation".to_string());
        };
        let rs_map = ensure_object_mut(obj, "swarm_prepare_repo_state");
        let prev_count = rs_map
            .get(upd.folded_git_root)
            .and_then(|v| v.get("prepare_count"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        rs_map.insert(
            upd.folded_git_root.to_string(),
            json!({
                "prepare_count": prev_count.saturating_add(1),
                "seen_heads": upd.seen_heads,
                "seen_fp_trees": upd.seen_fp_trees,
                "snapshot_bound_required": upd.snapshot_bound_required,
            }),
        );
        if let Err(err) = rio::write_json(upd.mfile, &next_m) {
            return Err(format!("marker_persist_failed:{}", err));
        }
        if !ack_ids.is_empty() {
            cwg_common::ack_pending_marker_deltas(upd.skey, &ack_ids);
        }
        commit_rounds_under_marker_lock(rounds_file, rounds_doc)?;
        Ok(Some(next_m))
    })
}

struct RepoPrepareProvenance {
    seen_heads: Vec<String>,
    seen_fp_trees: Vec<String>,
    prior_other_head: bool,
    require_snapshot_bound: bool,
}

struct RepoPrepProvQuery<'a> {
    state: &'a Map<String, Value>,
    marker: Option<&'a Value>,
    folded_git_root: &'a str,
    head_oid: &'a str,
    cur_tree_oid: &'a str,
    same_repo_diff_hash: &'a str,
    had_prior_cycle_prepare: bool,
}

fn collect_repo_prepare_provenance(q: RepoPrepProvQuery<'_>) -> RepoPrepareProvenance {
    let RepoPrepProvQuery {
        state,
        marker,
        folded_git_root,
        head_oid,
        cur_tree_oid,
        same_repo_diff_hash,
        had_prior_cycle_prepare,
    } = q;
    let expected_repo_prefix = format!("{}|", folded_git_root);
    let marker_rps = cwg_common::active_cycle_repo_prepare_state(marker, folded_git_root);
    let marker_prep_count = marker_rps
        .and_then(|r| r.get("prepare_count"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let marker_upgraded_without_rps = had_prior_cycle_prepare && marker_rps.is_none();

    let mut seen_heads: Vec<String> = Vec::new();
    let mut seen_fp_trees: Vec<String> = Vec::new();
    let mut prior_other_head = false;
    let mut prior_snapshot_bound = marker_rps
        .and_then(|r| r.get("snapshot_bound_required"))
        .and_then(Value::as_bool)
        == Some(true)
        || state
            .get("snapshot_bound_required")
            .and_then(Value::as_object)
            .and_then(|sm| sm.get(folded_git_root))
            .and_then(Value::as_bool)
            == Some(true);

    if let Some(rps) = marker_rps {
        if let Some(arr) = rps.get("seen_heads").and_then(Value::as_array) {
            for sh in arr.iter().filter_map(Value::as_str).filter(|s| !s.is_empty()) {
                if sh != head_oid {
                    prior_other_head = true;
                }
                prior_snapshot_bound |= push_capped_64(&mut seen_heads, sh.to_string());
            }
        }
        if let Some(arr) = rps.get("seen_fp_trees").and_then(Value::as_array) {
            for ft in arr.iter().filter_map(Value::as_str).filter(|s| !s.is_empty()) {
                prior_snapshot_bound |= push_capped_64(&mut seen_fp_trees, ft.to_string());
            }
        }
    }

    let mut rounds_had_repo_provenance = false;
    if let Some(arr) = state
        .get("seen_heads")
        .and_then(Value::as_object)
        .and_then(|sm| sm.get(folded_git_root))
        .and_then(Value::as_array)
    {
        for sh in arr.iter().filter_map(Value::as_str).filter(|s| !s.is_empty()) {
            rounds_had_repo_provenance = true;
            if sh != head_oid {
                prior_other_head = true;
            }
            prior_snapshot_bound |= push_capped_64(&mut seen_heads, sh.to_string());
        }
    }

    if let Some(lanes_map) = state.get("lanes").and_then(Value::as_object) {
        for (k, v) in lanes_map {
            if !k.starts_with(&expected_repo_prefix) {
                continue;
            }
            let Some(arr) = v.as_array() else {
                continue;
            };
            if !arr.is_empty() {
                rounds_had_repo_provenance = true;
                if marker_upgraded_without_rps
                    && arr.first().is_some_and(|f| val_to_i64(f.get("round")) > 1)
                {
                    prior_snapshot_bound = true;
                }
            }
            for ent in arr {
                let eh = val_to_str(ent.get("head_oid"));
                if eh.is_empty() || eh != head_oid {
                    prior_other_head = true;
                }
                prior_snapshot_bound |= push_capped_64(&mut seen_heads, eh);
                if !val_to_str(ent.get("head_bound_diff_hash")).is_empty() {
                    prior_snapshot_bound = true;
                }
                let edh = val_to_str(ent.get("diff_hash"));
                let etr = val_to_str(ent.get("tree_oid"));
                if !edh.is_empty() && !etr.is_empty() {
                    prior_snapshot_bound |=
                        push_capped_64(&mut seen_fp_trees, format!("{}|{}", edh, etr));
                }
            }
        }
    }

    prior_snapshot_bound |= push_capped_64(&mut seen_heads, head_oid.to_string());
    let prior_other_tree_for_fp = !same_repo_diff_hash.is_empty()
        && seen_fp_trees.iter().any(|ft| {
            ft.split_once('|')
                .is_some_and(|(fp, tr)| fp == same_repo_diff_hash && tr != cur_tree_oid)
        });
    if !same_repo_diff_hash.is_empty() && !cur_tree_oid.is_empty() {
        prior_snapshot_bound |= push_capped_64(
            &mut seen_fp_trees,
            format!("{}|{}", same_repo_diff_hash, cur_tree_oid),
        );
    }
    let lost_rounds_provenance =
        (marker_prep_count > 0 || marker_upgraded_without_rps) && !rounds_had_repo_provenance;
    let require_snapshot_bound = prior_other_head
        || prior_other_tree_for_fp
        || prior_snapshot_bound
        || lost_rounds_provenance;

    RepoPrepareProvenance {
        seen_heads,
        seen_fp_trees,
        prior_other_head,
        require_snapshot_bound,
    }
}

struct UncoveredFailInput<'a> {
    skey: &'a str,
    mfile: &'a Path,
    rounds_file: &'a Path,
    marker_first_ts: f64,
    expected_rr_ts: f64,
    cur_tree_oid: &'a str,
    marker_upd: Option<MarkerRepoPrepUpdate<'a>>,
}

fn record_uncovered_and_fail(
    state: &mut Map<String, Value>,
    inp: UncoveredFailInput<'_>,
) -> Value {
    stamp_rounds_marker_ts(state, inp.marker_first_ts);
    state.insert("uncovered_prepare".to_string(), Value::Bool(true));
    let rounds_doc = Value::Object(state.clone());
    let commit_res = if let Some(upd) = inp.marker_upd {
        persist_marker_repo_prepare_state(
            upd,
            false,
            true,
            inp.rounds_file,
            Some(&rounds_doc),
        )
        .map(|_| ())
    } else {
        with_locked_marker(inp.skey, inp.mfile, |_, merged_opt, _| {
            let Some(cur_m) = merged_opt else {
                return Err("concurrent_worktree_mutation".to_string());
            };
            if !cwg_common::is_active_marker(&cur_m)
                || marker_cycle_or_reset_mismatch(
                    &cur_m,
                    inp.marker_first_ts,
                    inp.expected_rr_ts,
                )
            {
                return Err("concurrent_worktree_mutation".to_string());
            }
            commit_rounds_under_marker_lock(inp.rounds_file, Some(&rounds_doc))
        })
    };
    if let Err(err) = commit_res {
        if err.starts_with("swarm_rounds_write_failed:") {
            return json!({
                "ok": false,
                "candidate_diff_covered": false,
                "current_diff_hash": "",
                "current_tree_oid": inp.cur_tree_oid,
                "error": err,
            });
        }
        return json!({
            "ok": false,
            "error": err,
        });
    }
    json!({
        "ok": false,
        "candidate_diff_covered": false,
        "current_diff_hash": "",
        "current_tree_oid": inp.cur_tree_oid,
        "error": "partial_or_uncovered_candidate_diff",
    })
}

struct PrepareLockedCtx<'a> {
    input: &'a PrepareRoundInput<'a>,
    clean_label: &'a str,
    git_root: &'a str,
    folded_git_root: &'a str,
    rel_paths: &'a [String],
    skey: &'a str,
}

fn prepare_round_locked(ctx: PrepareLockedCtx<'_>) -> Value {
    let PrepareLockedCtx {
        input,
        clean_label,
        git_root,
        folded_git_root,
        rel_paths,
        skey,
    } = ctx;
    let mfile = cwg_common::marker_path(skey);

    let mut initial_had_cycle_prepare: Option<bool> = None;
    let mut snapshot_pair: Option<(Option<Value>, String, String, String, bool, Vec<String>)> =
        None;
    for _attempt in 0..2 {
        let (synced_marker, had_prior) =
            match sync_marker_under_lock(skey, &mfile, folded_git_root, input.now_ts) {
                Ok(pair) => pair,
                Err(err) => {
                    return json!({
                        "ok": false,
                        "error": err,
                    });
                }
            };
        initial_had_cycle_prepare.get_or_insert(had_prior);

        let same_repo_active = synced_marker
            .as_ref()
            .is_some_and(|m| is_active_same_repo_marker(m, folded_git_root));
        let dpaths = synced_marker
            .as_ref()
            .filter(|_| same_repo_active)
            .map(|m| cwg_common::durable_paths_from_val(m.get("paths")))
            .unwrap_or_default();
        let fp_before = synced_marker
            .as_ref()
            .filter(|_| same_repo_active)
            .map(|m| val_to_str(m.get("current_diff_hash")))
            .unwrap_or_default();

        let head_1 = rio::git_head_oid(git_root);
        let tree_1 = rio::capture_worktree_tree_oid(git_root, 15.0);
        if tree_1.is_empty() {
            return json!({
                "ok": false,
                "error": "capture_worktree_tree_oid_failed",
            });
        }
        let fp_after = if same_repo_active && !dpaths.is_empty() {
            cwg_common::content_fingerprint(&dpaths, cwg_common::MAX_FINGERPRINT_FILE_BYTES)
        } else {
            fp_before.clone()
        };
        if fp_before != fp_after {
            continue;
        }
        // INVARIANT: Bracket `fp_before == fp_after` with two `HEAD` + worktree tree captures so concurrent edits to non-marker files or refs during `prepare_round` retry or fail closed with `concurrent_worktree_mutation`.
        let tree_2 = rio::capture_worktree_tree_oid(git_root, 15.0);
        let head_2 = rio::git_head_oid(git_root);
        if head_1 == head_2 && tree_1 == tree_2 {
            snapshot_pair = Some((
                synced_marker,
                head_1,
                tree_1,
                fp_before,
                same_repo_active,
                dpaths,
            ));
            break;
        }
    }

    let Some((
        mut marker,
        raw_head,
        cur_tree_oid,
        same_repo_diff_hash,
        same_repo_active,
        dpaths_for_cov,
    )) = snapshot_pair
    else {
        return json!({
            "ok": false,
            "error": "concurrent_worktree_mutation",
        });
    };
    let had_prior_cycle_prepare = initial_had_cycle_prepare.unwrap_or(false) && same_repo_active;

    let head_oid = cwg_common::effective_head_oid_from_raw(&raw_head, cur_tree_oid.len());

    let now = input.now_ts.unwrap_or_else(now_sec);
    let has_any_active_marker = marker.as_ref().is_some_and(cwg_common::is_active_marker);
    let cov_crlf_notes = if same_repo_active
        && rel_paths.is_empty()
        && !same_repo_diff_hash.is_empty()
    {
        cwg_common::inspect_durable_paths_in_git_tree(git_root, &cur_tree_oid, &dpaths_for_cov)
    } else {
        None
    };
    let full_candidate_covered = cov_crlf_notes.is_some();
    let unfiltered_tree_match = cov_crlf_notes.as_ref().is_some_and(Vec::is_empty);
    let cur_crlf_summary = cov_crlf_notes
        .as_deref()
        .map(format_crlf_notes)
        .unwrap_or_default();
    let raw_wt_digest = rio::capture_worktree_raw_digest(git_root, 15.0);
    let marker_first_ts = marker.as_ref().map_or(0.0, cwg_common::marker_cycle_first_ts);

    let rounds_file = cwg_common::swarm_rounds_path(skey);
    let loaded_state = rio::read_json(&rounds_file);
    if loaded_state.is_none() && rounds_file.exists() {
        return json!({
            "ok": false,
            "error": "swarm_rounds_read_failed",
        });
    }
    let mut state: Map<String, Value> = match loaded_state {
        Some(Value::Object(map))
            if map.get("session").and_then(|v| v.as_str()) == Some(input.session) =>
        {
            let prev_mts = val_to_f64(map.get("marker_first_ts"));
            if marker_first_ts > 0.0
                && (prev_mts <= 0.0 || cwg_common::cycle_ts_mismatch(prev_mts, marker_first_ts))
            {
                let mut fresh = Map::new();
                fresh.insert(
                    "session".to_string(),
                    Value::String(input.session.to_string()),
                );
                fresh.insert("marker_first_ts".to_string(), json!(marker_first_ts));
                fresh.insert("lanes".to_string(), Value::Object(Map::new()));
                fresh
            } else {
                map
            }
        }
        _ => {
            let mut fresh = Map::new();
            fresh.insert(
                "session".to_string(),
                Value::String(input.session.to_string()),
            );
            fresh.insert("marker_first_ts".to_string(), json!(marker_first_ts));
            fresh.insert("lanes".to_string(), Value::Object(Map::new()));
            fresh
        }
    };

    let cov_fp_for_prov = if full_candidate_covered {
        same_repo_diff_hash.as_str()
    } else {
        ""
    };
    let prov = collect_repo_prepare_provenance(RepoPrepProvQuery {
        state: &state,
        marker: marker.as_ref(),
        folded_git_root,
        head_oid,
        cur_tree_oid: &cur_tree_oid,
        same_repo_diff_hash: cov_fp_for_prov,
        had_prior_cycle_prepare,
    });
    let marker_rr_ts = marker
        .as_ref()
        .map_or(0.0, cwg_common::last_research_reset_ts);
    let marker_last_durable_ts = marker
        .as_ref()
        .map_or(0.0, |m| val_to_f64(m.get("last_durable_ts")));
    let marker_upd = same_repo_active.then_some(MarkerRepoPrepUpdate {
        skey,
        mfile: &mfile,
        folded_git_root,
        expected_cycle_ts: marker_first_ts,
        expected_research_reset_ts: marker_rr_ts,
        expected_last_durable_ts: marker_last_durable_ts,
        expected_dpaths: &dpaths_for_cov,
        expected_diff_hash: &same_repo_diff_hash,
        seen_heads: &prov.seen_heads,
        seen_fp_trees: &prov.seen_fp_trees,
        snapshot_bound_required: prov.require_snapshot_bound,
    });

    let mut seen_heads_updated = false;
    {
        let seen_map = ensure_object_mut(&mut state, "seen_heads");
        let next_val = Value::Array(
            prov.seen_heads
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        );
        if seen_map.get(folded_git_root) != Some(&next_val) {
            seen_map.insert(folded_git_root.to_string(), next_val);
            seen_heads_updated = true;
        }
    }
    let mut snapshot_bound_updated = false;
    if prov.require_snapshot_bound {
        let sb_map = ensure_object_mut(&mut state, "snapshot_bound_required");
        if sb_map.get(folded_git_root).and_then(Value::as_bool) != Some(true) {
            sb_map.insert(folded_git_root.to_string(), Value::Bool(true));
            snapshot_bound_updated = true;
        }
    }

    if has_any_active_marker && !full_candidate_covered {
        return record_uncovered_and_fail(
            &mut state,
            UncoveredFailInput {
                skey,
                mfile: &mfile,
                rounds_file: &rounds_file,
                marker_first_ts,
                expected_rr_ts: marker_rr_ts,
                cur_tree_oid: &cur_tree_oid,
                marker_upd,
            },
        );
    }

    let recorded_lane_diff_hash = if full_candidate_covered {
        same_repo_diff_hash.clone()
    } else {
        String::new()
    };
    let recorded_head_bound_dh = if full_candidate_covered && prov.require_snapshot_bound {
        cwg_common::head_bound_diff_hash(&same_repo_diff_hash, head_oid, &cur_tree_oid)
    } else {
        String::new()
    };
    let current_diff_hash = if full_candidate_covered {
        if prov.require_snapshot_bound {
            recorded_head_bound_dh.clone()
        } else {
            same_repo_diff_hash.clone()
        }
    } else if rel_paths.is_empty() {
        if prov.require_snapshot_bound {
            cwg_common::head_bound_diff_hash("", head_oid, &cur_tree_oid)
        } else {
            cur_tree_oid.clone()
        }
    } else {
        String::new()
    };

    ensure_object_mut(&mut state, "lanes");
    let lane_key = format!("{}|{}", folded_git_root, clean_label);
    let mut history: Vec<Value> = if input.reset {
        Vec::new()
    } else {
        state
            .get("lanes")
            .and_then(|l| l.get(&lane_key))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
    };

    let changed_tree = history.is_empty()
        || history
            .last()
            .and_then(|h| h.get("tree_oid"))
            .and_then(|v| v.as_str())
            != Some(cur_tree_oid.as_str());
    let changed_head = history.last().map_or(false, |last| {
        let prev_h = val_to_str(last.get("head_oid"));
        prev_h.is_empty() || prev_h != head_oid
    });
    let changed_paths = history
        .last()
        .map_or(false, |last| entry_paths(last) != rel_paths);
    let changed_diff_hash = history.last().map_or(false, |last| {
        last.get("diff_hash").is_none()
            || val_to_str(last.get("diff_hash")) != recorded_lane_diff_hash
            || val_to_str(last.get("head_bound_diff_hash")) != recorded_head_bound_dh
            || last.get("unfiltered_tree_match").and_then(Value::as_bool)
                != Some(unfiltered_tree_match)
            || val_to_str(last.get("crlf_summary")) != cur_crlf_summary
            || val_to_str(last.get("raw_worktree_digest")) != raw_wt_digest
    });
    let had_prev_recorded_dh = history
        .last()
        .is_some_and(|last| !val_to_str(last.get("diff_hash")).is_empty());
    let advance_round = changed_tree
        || changed_head
        || (full_candidate_covered && had_prev_recorded_dh && changed_diff_hash && !changed_paths);

    if advance_round {
        let next_round = history
            .last()
            .map(|h| val_to_i64(h.get("round")) + 1)
            .unwrap_or(1);
        history.push(json!({
            "round": next_round,
            "head_oid": head_oid,
            "tree_oid": cur_tree_oid,
            "diff_hash": recorded_lane_diff_hash,
            "head_bound_diff_hash": recorded_head_bound_dh,
            "unfiltered_tree_match": unfiltered_tree_match,
            "crlf_summary": cur_crlf_summary,
            "raw_worktree_digest": raw_wt_digest,
            "paths": rel_paths,
            "ts": (now * 1000.0).round() / 1000.0,
        }));
        if history.len() > MAX_ROUND_HISTORY {
            let keep_from = history.len() - MAX_ROUND_HISTORY;
            history = history[keep_from..].to_vec();
        }
    } else if changed_paths || changed_diff_hash {
        if let Some(Value::Object(last_obj)) = history.last_mut() {
            last_obj.insert("head_oid".to_string(), Value::String(head_oid.to_string()));
            last_obj.insert("paths".to_string(), json!(rel_paths));
            last_obj.insert(
                "diff_hash".to_string(),
                Value::String(recorded_lane_diff_hash),
            );
            last_obj.insert(
                "head_bound_diff_hash".to_string(),
                Value::String(recorded_head_bound_dh),
            );
            last_obj.insert(
                "unfiltered_tree_match".to_string(),
                Value::Bool(unfiltered_tree_match),
            );
            last_obj.insert(
                "crlf_summary".to_string(),
                Value::String(cur_crlf_summary.clone()),
            );
            last_obj.insert(
                "raw_worktree_digest".to_string(),
                Value::String(raw_wt_digest.clone()),
            );
        }
    }

    let cur_round = history
        .last()
        .map(|h| val_to_i64(h.get("round")))
        .unwrap_or(1);
    let (prev_head_oid, prev_tree_oid, prev_crlf_summary) = if history.len() >= 2 {
        let prev = &history[history.len() - 2];
        (
            val_to_str(prev.get("head_oid")),
            val_to_str(prev.get("tree_oid")),
            val_to_str(prev.get("crlf_summary")),
        )
    } else {
        (String::new(), String::new(), String::new())
    };
    let head_changed_in_round = if cur_round >= 2 {
        prev_head_oid.is_empty() || prev_head_oid != head_oid
    } else {
        prov.prior_other_head
    };

    let proj_key = rio::project_key(git_root, &[], git_root, "");
    let scratch_dir = input
        .brain_root
        .join(input.session)
        .join("scratch")
        .join(proj_key);
    let diff_res = match sync_round_diffs(RoundSyncInput {
        git_root,
        head_oid,
        prev_head_oid: &prev_head_oid,
        cur_tree_oid: &cur_tree_oid,
        prev_tree_oid: &prev_tree_oid,
        cur_crlf_summary: &cur_crlf_summary,
        prev_crlf_summary: &prev_crlf_summary,
        rel_paths,
        scratch_dir: &scratch_dir,
        clean_label,
        cur_round,
        regen: advance_round || changed_paths || changed_diff_hash,
        enforce_text_coverage: full_candidate_covered,
    }) {
        Ok(res) => res,
        Err(err) if err == "uncovered_binary_diff" && has_any_active_marker => {
            return record_uncovered_and_fail(
                &mut state,
                UncoveredFailInput {
                    skey,
                    mfile: &mfile,
                    rounds_file: &rounds_file,
                    marker_first_ts,
                    expected_rr_ts: marker_rr_ts,
                    cur_tree_oid: &cur_tree_oid,
                    marker_upd,
                },
            );
        }
        Err(err) => {
            return json!({
                "ok": false,
                "error": err,
            });
        }
    };

    let state_mutated = advance_round
        || changed_paths
        || changed_diff_hash
        || seen_heads_updated
        || snapshot_bound_updated;
    let marker_rps_missing =
        cwg_common::active_cycle_repo_prepare_state(marker.as_ref(), folded_git_root).is_none();
    if rio::git_head_oid(git_root) != raw_head
        || rio::capture_worktree_tree_oid(git_root, 15.0) != cur_tree_oid
    {
        return json!({
            "ok": false,
            "error": "concurrent_worktree_mutation",
        });
    }
    let rounds_doc_opt = if state_mutated {
        ensure_object_mut(&mut state, "lanes").insert(lane_key, Value::Array(history));
        stamp_rounds_marker_ts(&mut state, marker_first_ts);
        Some(Value::Object(state))
    } else {
        None
    };
    if let Some(upd) = marker_upd {
        match persist_marker_repo_prepare_state(
            upd,
            true,
            state_mutated || marker_rps_missing,
            &rounds_file,
            rounds_doc_opt.as_ref(),
        ) {
            Ok(updated_m) => {
                marker = updated_m;
            }
            Err(err) => {
                return json!({
                    "ok": false,
                    "error": err,
                });
            }
        }
    } else if let Err(err) = with_locked_marker(skey, &mfile, |_, merged_opt, _| {
        if merged_opt.is_some_and(|m| cwg_common::is_active_marker(&m)) {
            return Err("concurrent_worktree_mutation".to_string());
        }
        commit_rounds_under_marker_lock(&rounds_file, rounds_doc_opt.as_ref())
    }) {
        return json!({
            "ok": false,
            "error": err,
        });
    }

    let active_marker = marker.as_ref().filter(|m| cwg_common::is_active_marker(m));
    let worker_status = inspect_swarm_workers_with_marker(
        input.session,
        input.brain_root,
        input.ttl_seconds,
        clean_label,
        Some(now),
        cur_round,
        active_marker,
    );

    let mut next_names = Map::new();
    if let Some(workers_arr) = worker_status.get("workers").and_then(|v| v.as_array()) {
        for w in workers_arr {
            if w.get("cache_state").and_then(|v| v.as_str()) == Some("EXPIRED") {
                let wname = val_to_str(w.get("name"));
                let bname = val_to_str(w.get("base_name"));
                if !wname.is_empty() {
                    next_names.insert(
                        wname,
                        Value::String(rotated_worker_name(&bname, cur_round)),
                    );
                }
            }
        }
    }

    let marker_doc = marker
        .filter(|v| v.is_object())
        .unwrap_or_else(|| json!({}));
    let eff_repo_root = if !git_root.is_empty() {
        git_root
    } else {
        input.cwd
    };
    let diff_metrics = cwg_common::compute_diff_metrics(&marker_doc, eff_repo_root, None);
    let fast_path_eligible =
        cwg_common::is_simplify_fast_path_eligible(&json!({}), None, Some(&diff_metrics), "");

    let overall_action = val_to_str(worker_status.get("overall_action"));
    json!({
        "ok": true,
        "session": input.session,
        "label": clean_label,
        "git_root": rio::normalize_path(git_root),
        "head_oid": head_oid,
        "head_changed": head_changed_in_round,
        "round": cur_round,
        "candidate_diff_covered": full_candidate_covered,
        "current_diff_hash": current_diff_hash,
        "current_tree_oid": cur_tree_oid,
        "previous_tree_oid": prev_tree_oid,
        "full_diff_path": diff_res.full_diff_path,
        "incremental_diff_path": diff_res.incremental_diff_path,
        "incremental_stat": diff_res.incremental_stat,
        "diff_metrics": diff_metrics,
        "fast_path_eligible": fast_path_eligible,
        "overall_action": overall_action,
        "next_worker_names": next_names,
        "worker_status": worker_status,
    })
}

pub fn prepare_round(input: PrepareRoundInput<'_>) -> Value {
    let raw_label = if input.label.is_empty() {
        "simplify"
    } else {
        input.label
    };
    let clean_label = rio::safe_key(raw_label, "simplify");

    let eff_cwd = if input.cwd.trim().is_empty() {
        "."
    } else {
        input.cwd
    };
    let Some(git_root) = rio::git_toplevel(eff_cwd, false) else {
        return json!({
            "ok": false,
            "error": format!("not_in_git_repo:{}", input.cwd),
        });
    };

    let mut rel_paths: Vec<String> = Vec::new();
    for raw_p in input.paths {
        if raw_p.trim().is_empty() {
            continue;
        }
        let (rel_opt, inside) = cwg_common::resolve_repo_rel_info(raw_p, &git_root);
        if inside {
            if let Some(rel) = rel_opt {
                rel_paths.push(rel);
                continue;
            }
        }
        rel_paths.push(raw_p.replace('\\', "/"));
    }

    let skey = rio::safe_key(input.session, "default");
    let folded_git_root = rio::fold_path(&git_root);

    // INVARIANT: Serialize per-session `prepare_round` execution on `swarm_rounds_lock_path`, sample `HEAD` + worktree tree stability and persist `swarm_prepare_cycle_ts` strictly under locks, refuse (`ok: false`, writing zero diff files) any partial `--paths`, `-diff`/binary-masked text edit, or uncovered candidate snapshot when an active CWG marker exists, and key diff filenames by snapshot digest.
    rio::with_file_lock(
        &cwg_common::swarm_rounds_lock_path(&skey),
        15.0,
        60.0,
        |rounds_locked| {
            if !rounds_locked {
                return json!({
                    "ok": false,
                    "error": "swarm_rounds_lock_timeout",
                });
            }
            prepare_round_locked(PrepareLockedCtx {
                input: &input,
                clean_label: &clean_label,
                git_root: &git_root,
                folded_git_root: &folded_git_root,
                rel_paths: &rel_paths,
                skey: &skey,
            })
        },
    )
}

fn take_flag_value(args: &[String], idx: &mut usize, flag_name: &str) -> Result<String, String> {
    let arg = &args[*idx];
    if let Some((_, val)) = arg.split_once('=') {
        return Ok(val.to_string());
    }
    if *idx + 1 >= args.len() {
        return Err(format!("argument {} expected one argument", flag_name));
    }
    *idx += 1;
    Ok(args[*idx].clone())
}

fn parse_status_args(args: &[String]) -> Result<(String, u64, String, String, bool), String> {
    let mut session = String::new();
    let mut ttl = cwg_common::SWARM_CACHE_SAFE_TTL_SECONDS;
    let mut label = String::new();
    let mut brain_root = String::new();
    let mut pretty = false;

    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--pretty" {
            pretty = true;
        } else if a == "--session" || a.starts_with("--session=") {
            session = take_flag_value(args, &mut i, "--session")?;
        } else if a == "--ttl" || a.starts_with("--ttl=") {
            let raw = take_flag_value(args, &mut i, "--ttl")?;
            ttl = raw
                .trim()
                .parse::<u64>()
                .map_err(|_| format!("invalid --ttl value: {}", raw))?;
        } else if a == "--label" || a.starts_with("--label=") {
            label = take_flag_value(args, &mut i, "--label")?;
        } else if a == "--brain-root" || a.starts_with("--brain-root=") {
            brain_root = take_flag_value(args, &mut i, "--brain-root")?;
        } else {
            return Err(format!("unrecognized arguments: {}", a));
        }
        i += 1;
    }
    if session.is_empty() {
        return Err("the following arguments are required: --session".to_string());
    }
    Ok((session, ttl, label, brain_root, pretty))
}

struct PrepareArgs {
    session: String,
    cwd: String,
    label: String,
    ttl: u64,
    brain_root: String,
    reset: bool,
    paths: Vec<String>,
    pretty: bool,
}

fn parse_prepare_args(args: &[String]) -> Result<PrepareArgs, String> {
    let mut out = PrepareArgs {
        session: String::new(),
        cwd: ".".to_string(),
        label: "simplify".to_string(),
        ttl: cwg_common::SWARM_CACHE_SAFE_TTL_SECONDS,
        brain_root: String::new(),
        reset: false,
        paths: Vec::new(),
        pretty: false,
    };

    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--pretty" {
            out.pretty = true;
        } else if a == "--reset" {
            out.reset = true;
        } else if a == "--session" || a.starts_with("--session=") {
            out.session = take_flag_value(args, &mut i, "--session")?;
        } else if a == "--cwd" || a.starts_with("--cwd=") {
            out.cwd = take_flag_value(args, &mut i, "--cwd")?;
        } else if a == "--label" || a.starts_with("--label=") {
            out.label = take_flag_value(args, &mut i, "--label")?;
        } else if a == "--ttl" || a.starts_with("--ttl=") {
            let raw = take_flag_value(args, &mut i, "--ttl")?;
            out.ttl = raw
                .trim()
                .parse::<u64>()
                .map_err(|_| format!("invalid --ttl value: {}", raw))?;
        } else if a == "--brain-root" || a.starts_with("--brain-root=") {
            out.brain_root = take_flag_value(args, &mut i, "--brain-root")?;
        } else if a == "--paths" {
            while i + 1 < args.len() && !args[i + 1].starts_with('-') {
                i += 1;
                out.paths.push(args[i].clone());
            }
        } else if let Some(val) = a.strip_prefix("--paths=") {
            if !val.is_empty() {
                out.paths.push(val.to_string());
            }
        } else {
            return Err(format!("unrecognized arguments: {}", a));
        }
        i += 1;
    }
    if out.session.is_empty() {
        return Err("the following arguments are required: --session".to_string());
    }
    Ok(out)
}

pub fn run_cli(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln_line("usage: swarm_cache <status|prepare> [options]");
        return 2;
    }
    match args[0].as_str() {
        "-h" | "--help" => {
            eprintln_line("usage: swarm_cache <status|prepare> [--session ID ...]");
            0
        }
        "status" => match parse_status_args(&args[1..]) {
            Ok((session, ttl, label, brain_root, pretty)) => {
                let broot = resolve_brain_root(&brain_root);
                let out = inspect_swarm_workers(&session, &broot, ttl, &label, None, 0);
                rio::print_cli_json(&out, pretty);
                0
            }
            Err(err) => {
                eprintln_line(&format!("swarm_cache status: {}", err));
                2
            }
        },
        "prepare" => match parse_prepare_args(&args[1..]) {
            Ok(pargs) => {
                let broot = resolve_brain_root(&pargs.brain_root);
                let out = prepare_round(PrepareRoundInput {
                    session: &pargs.session,
                    cwd: &pargs.cwd,
                    brain_root: &broot,
                    label: &pargs.label,
                    ttl_seconds: pargs.ttl,
                    paths: &pargs.paths,
                    reset: pargs.reset,
                    now_ts: None,
                });
                rio::print_cli_json(&out, pargs.pretty);
                if out.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                    0
                } else {
                    1
                }
            }
            Err(err) => {
                eprintln_line(&format!("swarm_cache prepare: {}", err));
                2
            }
        },
        other => {
            eprintln_line(&format!("swarm_cache: unknown subcommand '{}'", other));
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQ: AtomicU64 = AtomicU64::new(1);

    struct EnvGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, val: &Path) -> Self {
            let prev = env::var_os(key);
            env::set_var(key, val);
            Self { key, prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => env::set_var(self.key, v),
                None => env::remove_var(self.key),
            }
        }
    }

    fn make_temp_dir(prefix: &str) -> PathBuf {
        let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = env::temp_dir().join(format!("{}-{}-{}", prefix, std::process::id(), seq));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_regex_and_worker_name_rotation() {
        assert!(round_suffix_re().is_match("worker-r12"));
        assert!(!round_suffix_re().is_match("worker-r"));
        assert_eq!(base_worker_name("simp-reuse-abcd-r3"), "simp-reuse-abcd");

        let healed = rotated_worker_name("simplify-efficie-abcd", 2);
        assert!(healed.len() <= MAX_SWARM_WORKER_NAME_LEN);
        assert_eq!(healed, "simp-efficiency-abcd-r2");

        let long_simp = rotated_worker_name("simplify-efficiency-reviewer-extra-long", 12);
        assert!(long_simp.len() <= MAX_SWARM_WORKER_NAME_LEN);
        assert!(long_simp.starts_with("simp-efficiency-"));
        assert!(long_simp.ends_with("-r12"));

        let long_other = rotated_worker_name("very-long-adversarial-reviewer-worker-name", 4);
        assert!(long_other.len() <= MAX_SWARM_WORKER_NAME_LEN);
        assert!(long_other.ends_with("-r4"));
    }

    #[test]
    fn test_inspect_swarm_workers_ttl_and_tokens() {
        let brain = make_temp_dir("swarm-cache-inspect");
        let session = "sess-001";
        let worker_cid = "worker-cid-001";
        let warm_cid = "worker-cid-002";

        let swarm_meta_dir = brain.join(session).join(".system_generated").join("swarm");
        fs::create_dir_all(&swarm_meta_dir).unwrap();
        let members = json!({
            "members": {
                "coordinator": {"role": "coordinator", "conversation_id": session},
                "simp-reuse-r1": {"role": "worker", "model": cwg_common::SONNET_HIGH_MODEL, "conversation_id": worker_cid},
                "simp-quality-r1": {"role": "worker", "model": cwg_common::SONNET_HIGH_MODEL, "conversation_id": warm_cid},
                "simp-efficiency-r1": {"role": "worker", "model": cwg_common::SIMPLIFY_FALLBACK_MODEL, "conversation_id": worker_cid},
                "simplify-efficiency-r0": {"role": "worker", "model": cwg_common::SONNET_HIGH_MODEL, "killed": true}
            }
        });
        fs::write(
            swarm_meta_dir.join("members.json"),
            serde_json::to_string_pretty(&members).unwrap(),
        )
        .unwrap();

        let tp1_dir = brain.join(worker_cid).join(".system_generated").join("logs");
        fs::create_dir_all(&tp1_dir).unwrap();
        fs::write(
            tp1_dir.join("transcript.jsonl"),
            concat!(
                r#"{"source":"MODEL","created_at":"2026-11-17T10:00:00Z","input_tokens":120,"cache_read_tokens":880,"output_tokens":45}"#,
                "\n"
            ),
        )
        .unwrap();

        let tp2_dir = brain.join(warm_cid).join(".system_generated").join("logs");
        fs::create_dir_all(&tp2_dir).unwrap();
        fs::write(
            tp2_dir.join("transcript.jsonl"),
            concat!(
                r#"{"source":"MODEL","created_at":"2026-11-17T10:05:00Z","input_tokens":50,"cache_read_tokens":500,"output_tokens":20}"#,
                "\n"
            ),
        )
        .unwrap();

        let now = crate::win32_sqlite::parse_iso_ts("2026-11-17T10:06:00Z");
        let res = inspect_swarm_workers(
            session,
            &brain,
            cwg_common::SWARM_CACHE_SAFE_TTL_SECONDS,
            "simplify",
            Some(now),
            1,
        );
        assert_eq!(res["active_count"], json!(3));
        assert_eq!(res["killed_count"], json!(1));
        assert_eq!(res["overall_action"], json!("rotate_incremental"));
        assert_eq!(res["expired_workers"], json!(["simp-reuse-r1"]));
        assert_eq!(res["warm_workers"], json!(["simp-efficiency-r1", "simp-quality-r1"]));

        let workers = res["workers"].as_array().unwrap();
        let w_warm = workers
            .iter()
            .find(|w| w["name"] == "simp-quality-r1")
            .unwrap();
        assert_eq!(w_warm["last_input_tokens"], json!(50));
        assert_eq!(w_warm["last_cache_read_tokens"], json!(500));
        assert_eq!(w_warm["last_output_tokens"], json!(20));
        assert_eq!(w_warm["last_context_tokens"], json!(550));

        let _ = fs::remove_dir_all(&brain);
    }

    #[test]
    fn test_prepare_round_non_git_and_diff_generation() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp_home = make_temp_dir("swarm-cache-home");
        let _env = EnvGuard::set("CARBON_STACK_HOME", &tmp_home);

        let non_git = make_temp_dir("swarm-cache-nongit");
        let brain = make_temp_dir("swarm-cache-brain");
        let non_git_s = non_git.to_string_lossy().into_owned();
        let err_res = prepare_round(PrepareRoundInput {
            session: "sess-nongit",
            cwd: &non_git_s,
            brain_root: &brain,
            label: "simplify",
            ttl_seconds: 270,
            paths: &[],
            reset: false,
            now_ts: None,
        });
        assert_eq!(err_res["ok"], json!(false));
        assert!(err_res["error"]
            .as_str()
            .unwrap()
            .starts_with("not_in_git_repo:"));

        let repo = make_temp_dir("swarm-cache-repo");
        let repo_s = repo.to_string_lossy().into_owned();
        let (rc_init, _, _) = rio::run_git(&repo_s, &["init"], 5.0);
        if rc_init == 0 {
            let _ = rio::run_git(&repo_s, &["config", "user.email", "t@example.com"], 5.0);
            let _ = rio::run_git(&repo_s, &["config", "user.name", "Test"], 5.0);
            fs::write(repo.join("a.txt"), "one\n").unwrap();
            let _ = rio::run_git(&repo_s, &["add", "a.txt"], 5.0);
            let _ = rio::run_git(&repo_s, &["commit", "-m", "init"], 5.0);
            fs::write(repo.join("a.txt"), "one\ntwo\n").unwrap();

            let r1 = prepare_round(PrepareRoundInput {
                session: "sess-git",
                cwd: &repo_s,
                brain_root: &brain,
                label: "simplify",
                ttl_seconds: 270,
                paths: &[],
                reset: false,
                now_ts: Some(1000.0),
            });
            assert_eq!(r1["ok"], json!(true));
            assert_eq!(r1["round"], json!(1));
            assert_eq!(r1["fast_path_eligible"], json!(true));
            assert!(Path::new(r1["full_diff_path"].as_str().unwrap()).is_file());

            fs::write(repo.join("a.txt"), "one\ntwo\nthree\n").unwrap();
            let r2 = prepare_round(PrepareRoundInput {
                session: "sess-git",
                cwd: &repo_s,
                brain_root: &brain,
                label: "simplify",
                ttl_seconds: 270,
                paths: &[],
                reset: false,
                now_ts: Some(1005.0),
            });
            assert_eq!(r2["ok"], json!(true));
            assert_eq!(r2["round"], json!(2));
            assert!(Path::new(r2["incremental_diff_path"].as_str().unwrap()).is_file());
        }

        let _ = fs::remove_dir_all(&non_git);
        let _ = fs::remove_dir_all(&repo);
        let _ = fs::remove_dir_all(&brain);
        let _ = fs::remove_dir_all(&tmp_home);
    }

    #[test]
    fn test_matches_label_neon_routing() {
        assert!(matches_label(
            "simplify-reuse-r1",
            "simplify",
            cwg_common::NEON_XHIGH_MODEL,
            ""
        ));
        assert!(matches_label(
            "simplify-quality-r1",
            "simplify",
            cwg_common::HYDROGEN_XHIGH_MODEL,
            ""
        ));
        assert!(matches_label(
            "internal-reviewer",
            "review",
            cwg_common::NEON_XHIGH_MODEL,
            ""
        ));
        assert!(matches_label(
            "internal-reviewer-xhigh",
            "review",
            cwg_common::CARBON_HIGH_MODEL,
            ""
        ));
        assert!(matches_label(
            "neon-audit",
            "review",
            cwg_common::NEON_XHIGH_MODEL,
            "Audit diff and emit VERDICT: APPROVED or REVISE"
        ));
        assert!(!matches_label(
            "builder-carbon",
            "review",
            cwg_common::CARBON_HIGH_MODEL,
            "Implement feature module"
        ));
        assert!(!matches_label(
            "root-cause-debugger",
            "review",
            cwg_common::NEON_XHIGH_MODEL,
            "Diagnose flaky test"
        ));
        assert!(!matches_label(
            "repo-architect-scout",
            "review",
            cwg_common::NEON_XHIGH_MODEL,
            ""
        ));
    }

    #[test]
    fn test_inspect_workers_review_role_and_overall_action() {
        let brain = make_temp_dir("swarm-cache-review-role");
        let now = 1_795_120_000.0;

        let write_warm_worker = |cid: &str| {
            let log_dir = brain.join(cid).join(".system_generated").join("logs");
            fs::create_dir_all(&log_dir).unwrap();
            let step = json!({
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2026-11-19T20:26:00Z",
                "metadata": {"modelUsage": {"inputTokens": 40, "outputTokens": 10, "cacheReadTokens": 100}}
            });
            fs::write(
                log_dir.join("transcript_full.jsonl"),
                format!("{}\n", serde_json::to_string(&step).unwrap()),
            )
            .unwrap();
        };

        // Case 1: Active warm Carbon builder must NOT trigger `resume_in_place` for `--label review`.
        let sess_builder = "sess-carbon-builder-only";
        let sw_builder = rio::swarm_dir(&brain, sess_builder);
        fs::create_dir_all(&sw_builder).unwrap();
        write_warm_worker("cid-carbon-builder");
        fs::write(
            sw_builder.join("members.json"),
            serde_json::to_string(&json!({
                "members": {
                    "builder-carbon": {
                        "role": "worker",
                        "conversation_id": "cid-carbon-builder",
                        "model": cwg_common::CARBON_HIGH_MODEL,
                        "brief": "Implement parser module",
                        "killed": false
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let res_builder = inspect_swarm_workers(
            sess_builder,
            &brain,
            cwg_common::SWARM_CACHE_SAFE_TTL_SECONDS,
            "review",
            Some(now),
            1,
        );
        assert_eq!(res_builder["active_count"], json!(0));
        assert_eq!(res_builder["overall_action"], json!("initial_spawn"));

        // Case 2: Active warm Neon worker `neon-audit` assigned a review role via board.jsonl brief MUST trigger `resume_in_place`.
        let sess_neon_audit = "sess-neon-audit-brief-review";
        let sw_neon = rio::swarm_dir(&brain, sess_neon_audit);
        fs::create_dir_all(&sw_neon).unwrap();
        write_warm_worker("cid-neon-audit");
        fs::write(
            sw_neon.join("members.json"),
            serde_json::to_string(&json!({
                "members": {
                    "builder-carbon": {
                        "role": "worker",
                        "conversation_id": "cid-carbon-builder",
                        "model": cwg_common::CARBON_HIGH_MODEL,
                        "brief": "Implement parser module",
                        "killed": false
                    },
                    "neon-audit": {
                        "role": "worker",
                        "conversation_id": "cid-neon-audit",
                        "model": cwg_common::NEON_XHIGH_MODEL,
                        "killed": false
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            sw_neon.join("board.jsonl"),
            format!(
                "{}\n",
                serde_json::to_string(&json!({
                    "seq": 1,
                    "agent": "coordinator",
                    "time": "2026-11-19T20:25:00Z",
                    "text": "@neon-audit Adversarial audit of diff; report VERDICT: APPROVED or REVISE."
                }))
                .unwrap()
            ),
        )
        .unwrap();
        let res_neon = inspect_swarm_workers(
            sess_neon_audit,
            &brain,
            cwg_common::SWARM_CACHE_SAFE_TTL_SECONDS,
            "review",
            Some(now),
            1,
        );
        assert_eq!(res_neon["active_count"], json!(1));
        assert_eq!(res_neon["warm_workers"], json!(["neon-audit"]));
        assert_eq!(res_neon["overall_action"], json!("resume_in_place"));

        // Case 3: After `research-reset`, a new post-reset Neon builder reusing roster name `neon-audit`
        // must NOT inherit pre-reset reviewer board briefs (must stay `initial_spawn`, not `resume_in_place`).
        let rr_ts = rio::parse_iso_ts("2026-11-19T20:25:30Z");
        let rr_marker = json!({
            "closed": false,
            "research_resets": [{
                "reset_ts": rr_ts,
                "board_head_seq": 5,
                "pre_reset_worker_cids": ["cid-neon-audit-pre-reset"]
            }]
        });
        let sess_rr_reuse = "sess-neon-audit-post-reset-builder-reuse";
        let sw_rr = rio::swarm_dir(&brain, sess_rr_reuse);
        fs::create_dir_all(&sw_rr).unwrap();
        write_warm_worker("cid-neon-builder-post-reset");
        fs::write(
            sw_rr.join("members.json"),
            serde_json::to_string(&json!({
                "members": {
                    "neon-audit": {
                        "role": "worker",
                        "conversation_id": "cid-neon-builder-post-reset",
                        "model": cwg_common::NEON_XHIGH_MODEL,
                        "created_at": "2026-11-19T20:25:45Z",
                        "killed": false
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            sw_rr.join("board.jsonl"),
            [
                json!({
                    "seq": 1,
                    "agent": "coordinator",
                    "time": "2026-11-19T20:25:00Z",
                    "text": "@neon-audit Adversarial audit of diff; report VERDICT: APPROVED or REVISE."
                }),
                json!({
                    "seq": 6,
                    "agent": "coordinator",
                    "time": "2026-11-19T20:25:50Z",
                    "text": "@neon-audit Implement parser module in src/parser.rs."
                }),
            ]
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("\n")
                + "\n",
        )
        .unwrap();
        let res_rr_builder = inspect_swarm_workers_with_marker(
            sess_rr_reuse,
            &brain,
            cwg_common::SWARM_CACHE_SAFE_TTL_SECONDS,
            "review",
            Some(now),
            1,
            Some(&rr_marker),
        );
        assert_eq!(res_rr_builder["active_count"], json!(0));
        assert_eq!(res_rr_builder["overall_action"], json!("initial_spawn"));

        // Case 4: Pre-reset unkilled reviewer `neon-audit` (`cid` in `pre_reset_worker_cids`) must NOT
        // trigger Warm Pool `resume_in_place` after `research-reset`.
        let sess_rr_pre = "sess-neon-audit-pre-reset-stale";
        let sw_rr_pre = rio::swarm_dir(&brain, sess_rr_pre);
        fs::create_dir_all(&sw_rr_pre).unwrap();
        write_warm_worker("cid-neon-audit-pre-reset");
        fs::write(
            sw_rr_pre.join("members.json"),
            serde_json::to_string(&json!({
                "members": {
                    "neon-audit": {
                        "role": "worker",
                        "conversation_id": "cid-neon-audit-pre-reset",
                        "model": cwg_common::NEON_XHIGH_MODEL,
                        "killed": false
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            sw_rr_pre.join("board.jsonl"),
            format!(
                "{}\n",
                json!({
                    "seq": 1,
                    "agent": "coordinator",
                    "time": "2026-11-19T20:25:00Z",
                    "text": "@neon-audit Adversarial audit of diff; report VERDICT: APPROVED or REVISE."
                })
            ),
        )
        .unwrap();
        let res_rr_pre = inspect_swarm_workers_with_marker(
            sess_rr_pre,
            &brain,
            cwg_common::SWARM_CACHE_SAFE_TTL_SECONDS,
            "review",
            Some(now),
            1,
            Some(&rr_marker),
        );
        assert_eq!(res_rr_pre["active_count"], json!(0));
        assert_eq!(res_rr_pre["overall_action"], json!("initial_spawn"));

        // Case 5: Post-reset Neon reviewer `neon-audit` assigned AFTER `research-reset` MUST trigger `resume_in_place`.
        let sess_rr_post_rev = "sess-neon-audit-post-reset-reviewer";
        let sw_rr_post = rio::swarm_dir(&brain, sess_rr_post_rev);
        fs::create_dir_all(&sw_rr_post).unwrap();
        write_warm_worker("cid-neon-reviewer-post-reset");
        fs::write(
            sw_rr_post.join("members.json"),
            serde_json::to_string(&json!({
                "members": {
                    "neon-audit": {
                        "role": "worker",
                        "conversation_id": "cid-neon-reviewer-post-reset",
                        "model": cwg_common::NEON_XHIGH_MODEL,
                        "created_at": "2026-11-19T20:25:45Z",
                        "killed": false
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            sw_rr_post.join("board.jsonl"),
            format!(
                "{}\n",
                json!({
                    "seq": 6,
                    "agent": "coordinator",
                    "time": "2026-11-19T20:25:50Z",
                    "text": "@neon-audit Adversarial audit of diff; report VERDICT: APPROVED or REVISE."
                })
            ),
        )
        .unwrap();
        let res_rr_post = inspect_swarm_workers_with_marker(
            sess_rr_post_rev,
            &brain,
            cwg_common::SWARM_CACHE_SAFE_TTL_SECONDS,
            "review",
            Some(now),
            1,
            Some(&rr_marker),
        );
        assert_eq!(res_rr_post["active_count"], json!(1));
        assert_eq!(res_rr_post["warm_workers"], json!(["neon-audit"]));
        assert_eq!(res_rr_post["overall_action"], json!("resume_in_place"));

        // Case 6: Post-reset Neon reviewer assigned with `seq > board_head_seq` and a coarse same-second
        // board timestamp (`20:25:30Z` vs `reset_ts = 20:25:30.500Z`) MUST be preserved (`resume_in_place`),
        // matching `cwg_stop` when `board_head_seq` proves the row is post-reset.
        let rr_half_sec = rio::parse_iso_ts("2026-11-19T20:25:30.500Z");
        let rr_half_marker = json!({
            "closed": false,
            "research_resets": [{
                "reset_ts": rr_half_sec,
                "board_head_seq": 5,
                "pre_reset_worker_cids": ["cid-neon-audit-pre-reset"]
            }]
        });
        let sess_rr_samesec = "sess-neon-audit-post-reset-same-second-coarse";
        let sw_rr_ss = rio::swarm_dir(&brain, sess_rr_samesec);
        fs::create_dir_all(&sw_rr_ss).unwrap();
        write_warm_worker("cid-neon-reviewer-samesec");
        fs::write(
            sw_rr_ss.join("members.json"),
            serde_json::to_string(&json!({
                "members": {
                    "neon-audit": {
                        "role": "worker",
                        "conversation_id": "cid-neon-reviewer-samesec",
                        "model": cwg_common::NEON_XHIGH_MODEL,
                        "created_at": "2026-11-19T20:25:30.600Z",
                        "killed": false
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            sw_rr_ss.join("board.jsonl"),
            format!(
                "{}\n",
                json!({
                    "seq": 6,
                    "agent": "coordinator",
                    "time": "2026-11-19T20:25:30Z",
                    "text": "@neon-audit Adversarial audit of diff; report VERDICT: APPROVED or REVISE."
                })
            ),
        )
        .unwrap();
        let res_rr_ss = inspect_swarm_workers_with_marker(
            sess_rr_samesec,
            &brain,
            cwg_common::SWARM_CACHE_SAFE_TTL_SECONDS,
            "review",
            Some(now),
            1,
            Some(&rr_half_marker),
        );
        assert_eq!(res_rr_ss["active_count"], json!(1));
        assert_eq!(res_rr_ss["warm_workers"], json!(["neon-audit"]));
        assert_eq!(res_rr_ss["overall_action"], json!("resume_in_place"));

        // Case 7: Pre-reset row appended between `board_head_seq` snapshot (`seq=5`) and `reset_ts`
        // (`20:25:30.500Z`) has `seq=6 > rr_seq` but exact timestamp `20:25:30.200Z <= reset_ts`;
        // MUST be filtered out so a post-reset Neon builder reusing `neon-audit` stays `initial_spawn`,
        // while a subsequent post-reset coarse same-second row (`seq=7`, `20:25:30Z`) retains its
        // full upper bound (`20:25:31Z > 20:25:30.500Z`) and is preserved when assigning a reviewer.
        let sess_rr_gap_b = "sess-neon-audit-pre-reset-gap-builder";
        let sw_rr_gb = rio::swarm_dir(&brain, sess_rr_gap_b);
        fs::create_dir_all(&sw_rr_gb).unwrap();
        write_warm_worker("cid-neon-builder-gap");
        fs::write(
            sw_rr_gb.join("members.json"),
            serde_json::to_string(&json!({
                "members": {
                    "neon-audit": {
                        "role": "worker",
                        "conversation_id": "cid-neon-builder-gap",
                        "model": cwg_common::NEON_XHIGH_MODEL,
                        "created_at": "2026-11-19T20:25:30.600Z",
                        "killed": false
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            sw_rr_gb.join("board.jsonl"),
            [
                json!({
                    "seq": 6,
                    "agent": "coordinator",
                    "time": "2026-11-19T20:25:30.200Z",
                    "text": "@neon-audit Adversarial audit of diff; report VERDICT: APPROVED or REVISE."
                }),
                json!({
                    "seq": 7,
                    "agent": "coordinator",
                    "time": "2026-11-19T20:25:30Z",
                    "text": "@neon-audit Implement parser module in src/parser.rs."
                }),
            ]
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("\n")
                + "\n",
        )
        .unwrap();
        let res_rr_gb = inspect_swarm_workers_with_marker(
            sess_rr_gap_b,
            &brain,
            cwg_common::SWARM_CACHE_SAFE_TTL_SECONDS,
            "review",
            Some(now),
            1,
            Some(&rr_half_marker),
        );
        assert_eq!(res_rr_gb["active_count"], json!(0));
        assert_eq!(res_rr_gb["overall_action"], json!("initial_spawn"));

        let sess_rr_gap_r = "sess-neon-audit-pre-reset-gap-then-post-coarse-rev";
        let sw_rr_gr = rio::swarm_dir(&brain, sess_rr_gap_r);
        fs::create_dir_all(&sw_rr_gr).unwrap();
        write_warm_worker("cid-neon-rev-after-gap");
        fs::write(
            sw_rr_gr.join("members.json"),
            serde_json::to_string(&json!({
                "members": {
                    "neon-audit": {
                        "role": "worker",
                        "conversation_id": "cid-neon-rev-after-gap",
                        "model": cwg_common::NEON_XHIGH_MODEL,
                        "created_at": "2026-11-19T20:25:30.600Z",
                        "killed": false
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            sw_rr_gr.join("board.jsonl"),
            [
                json!({
                    "seq": 6,
                    "agent": "coordinator",
                    "time": "2026-11-19T20:25:30.200Z",
                    "text": "@neon-audit Implement old cycle builder."
                }),
                json!({
                    "seq": 7,
                    "agent": "coordinator",
                    "time": "2026-11-19T20:25:30Z",
                    "text": "@neon-audit Adversarial audit of diff; report VERDICT: APPROVED or REVISE."
                }),
            ]
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("\n")
                + "\n",
        )
        .unwrap();
        let res_rr_gr = inspect_swarm_workers_with_marker(
            sess_rr_gap_r,
            &brain,
            cwg_common::SWARM_CACHE_SAFE_TTL_SECONDS,
            "review",
            Some(now),
            1,
            Some(&rr_half_marker),
        );
        assert_eq!(res_rr_gr["active_count"], json!(1));
        assert_eq!(res_rr_gr["warm_workers"], json!(["neon-audit"]));
        assert_eq!(res_rr_gr["overall_action"], json!("resume_in_place"));

        // Case 8: Coarse pre-reset row `seq=6` (`20:25:30Z`, `@neon-audit VERDICT: APPROVED`) followed by
        // exact pre-reset row `seq=7` (`20:25:30.300Z <= reset_ts 20:25:30.500Z`) proves BOTH `seq=6` and
        // `seq=7` preceded reset via append-only causal prefix tightening; post-reset Neon builder reusing
        // `neon-audit` (`seq=8` coarse `20:25:30Z`) MUST stay `initial_spawn` (not `resume_in_place`),
        // while a post-reset reviewer assigned at `seq=8` (coarse `20:25:30Z`) IS still preserved.
        let sess_rr_cp_b = "sess-neon-audit-causal-prefix-builder";
        let sw_rr_cpb = rio::swarm_dir(&brain, sess_rr_cp_b);
        fs::create_dir_all(&sw_rr_cpb).unwrap();
        write_warm_worker("cid-neon-builder-cp");
        fs::write(
            sw_rr_cpb.join("members.json"),
            serde_json::to_string(&json!({
                "members": {
                    "neon-audit": {
                        "role": "worker",
                        "conversation_id": "cid-neon-builder-cp",
                        "model": cwg_common::NEON_XHIGH_MODEL,
                        "created_at": "2026-11-19T20:25:30.600Z",
                        "killed": false
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            sw_rr_cpb.join("board.jsonl"),
            [
                json!({
                    "seq": 6,
                    "agent": "coordinator",
                    "time": "2026-11-19T20:25:30Z",
                    "text": "@neon-audit Adversarial audit of diff; report VERDICT: APPROVED or REVISE."
                }),
                json!({
                    "seq": 7,
                    "agent": "coordinator",
                    "time": "2026-11-19T20:25:30.300Z",
                    "text": "@other-worker sync"
                }),
                json!({
                    "seq": 8,
                    "agent": "coordinator",
                    "time": "2026-11-19T20:25:30Z",
                    "text": "@neon-audit Implement parser module in src/parser.rs."
                }),
            ]
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("\n")
                + "\n",
        )
        .unwrap();
        let res_rr_cpb = inspect_swarm_workers_with_marker(
            sess_rr_cp_b,
            &brain,
            cwg_common::SWARM_CACHE_SAFE_TTL_SECONDS,
            "review",
            Some(now),
            1,
            Some(&rr_half_marker),
        );
        assert_eq!(res_rr_cpb["active_count"], json!(0));
        assert_eq!(res_rr_cpb["overall_action"], json!("initial_spawn"));

        let sess_rr_cp_r = "sess-neon-audit-causal-prefix-reviewer";
        let sw_rr_cpr = rio::swarm_dir(&brain, sess_rr_cp_r);
        fs::create_dir_all(&sw_rr_cpr).unwrap();
        write_warm_worker("cid-neon-reviewer-cp");
        fs::write(
            sw_rr_cpr.join("members.json"),
            serde_json::to_string(&json!({
                "members": {
                    "neon-audit": {
                        "role": "worker",
                        "conversation_id": "cid-neon-reviewer-cp",
                        "model": cwg_common::NEON_XHIGH_MODEL,
                        "created_at": "2026-11-19T20:25:30.600Z",
                        "killed": false
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            sw_rr_cpr.join("board.jsonl"),
            [
                json!({
                    "seq": 6,
                    "agent": "coordinator",
                    "time": "2026-11-19T20:25:30Z",
                    "text": "@neon-audit Implement old cycle builder."
                }),
                json!({
                    "seq": 7,
                    "agent": "coordinator",
                    "time": "2026-11-19T20:25:30.300Z",
                    "text": "@other-worker sync"
                }),
                json!({
                    "seq": 8,
                    "agent": "coordinator",
                    "time": "2026-11-19T20:25:30Z",
                    "text": "@neon-audit Adversarial audit of diff; report VERDICT: APPROVED or REVISE."
                }),
            ]
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("\n")
                + "\n",
        )
        .unwrap();
        let res_rr_cpr = inspect_swarm_workers_with_marker(
            sess_rr_cp_r,
            &brain,
            cwg_common::SWARM_CACHE_SAFE_TTL_SECONDS,
            "review",
            Some(now),
            1,
            Some(&rr_half_marker),
        );
        assert_eq!(res_rr_cpr["active_count"], json!(1));
        assert_eq!(res_rr_cpr["warm_workers"], json!(["neon-audit"]));
        assert_eq!(res_rr_cpr["overall_action"], json!("resume_in_place"));

        // Case 9: Tail truncation (>400 board rows without explicit `seq`/`msg_id`/`id`) must preserve
        // true full-board ordinal seq so row 401 after `board_head_seq=400` is NOT dropped into the old cycle.
        let sess_rr_tail = "sess-neon-audit-tail-401-no-seq";
        let sw_rr_tail = rio::swarm_dir(&brain, sess_rr_tail);
        fs::create_dir_all(&sw_rr_tail).unwrap();
        write_warm_worker("cid-neon-rev-tail401");
        fs::write(
            sw_rr_tail.join("members.json"),
            serde_json::to_string(&json!({
                "members": {
                    "neon-audit": {
                        "role": "worker",
                        "conversation_id": "cid-neon-rev-tail401",
                        "model": cwg_common::NEON_XHIGH_MODEL,
                        "created_at": "2026-11-19T20:25:35Z",
                        "killed": false
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let mut tail_lines: Vec<String> = Vec::with_capacity(401);
        for i in 1..=400 {
            tail_lines.push(
                json!({
                    "agent": "coordinator",
                    "time": "2026-11-19T20:20:00Z",
                    "text": format!("@other-worker note {}", i)
                })
                .to_string(),
            );
        }
        tail_lines.push(
            json!({
                "agent": "coordinator",
                "time": "2026-11-19T20:25:40.000Z",
                "text": "@neon-audit Adversarial audit of diff; report VERDICT: APPROVED or REVISE."
            })
            .to_string(),
        );
        fs::write(sw_rr_tail.join("board.jsonl"), tail_lines.join("\n") + "\n").unwrap();
        let rr_tail_marker = json!({
            "closed": false,
            "research_resets": [{
                "reset_ts": rr_half_sec,
                "board_head_seq": 400,
                "pre_reset_worker_cids": ["cid-neon-audit-pre-reset"]
            }]
        });
        let res_rr_tail = inspect_swarm_workers_with_marker(
            sess_rr_tail,
            &brain,
            cwg_common::SWARM_CACHE_SAFE_TTL_SECONDS,
            "review",
            Some(now),
            1,
            Some(&rr_tail_marker),
        );
        assert_eq!(res_rr_tail["active_count"], json!(1));
        assert_eq!(res_rr_tail["warm_workers"], json!(["neon-audit"]));
        assert_eq!(res_rr_tail["overall_action"], json!("resume_in_place"));

        // Case 10: Fractional Unix string timestamp `"1795119930.300"` (<= `reset_ts = 1795119930.500`)
        // must be classified as exact (not coarse) so it excludes itself and earlier coarse seq=6 from Warm Pool.
        let sess_rr_unix = "sess-neon-audit-unix-frac-reset";
        let sw_rr_unix = rio::swarm_dir(&brain, sess_rr_unix);
        fs::create_dir_all(&sw_rr_unix).unwrap();
        write_warm_worker("cid-neon-builder-unix");
        fs::write(
            sw_rr_unix.join("members.json"),
            serde_json::to_string(&json!({
                "members": {
                    "neon-audit": {
                        "role": "worker",
                        "conversation_id": "cid-neon-builder-unix",
                        "model": cwg_common::NEON_XHIGH_MODEL,
                        "created_at": "2026-11-19T20:25:30.600Z",
                        "killed": false
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let rr_sec_int = rr_half_sec.floor() as i64;
        fs::write(
            sw_rr_unix.join("board.jsonl"),
            [
                json!({
                    "seq": 6,
                    "agent": "coordinator",
                    "time": format!("{}", rr_sec_int),
                    "text": "@neon-audit Adversarial audit of diff; report VERDICT: APPROVED or REVISE."
                }),
                json!({
                    "seq": 7,
                    "agent": "coordinator",
                    "time": format!("{}.300", rr_sec_int),
                    "text": "@other-worker sync"
                }),
                json!({
                    "seq": 8,
                    "agent": "coordinator",
                    "time": format!("{}", rr_sec_int),
                    "text": "@neon-audit Implement parser module."
                }),
            ]
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("\n")
                + "\n",
        )
        .unwrap();
        let res_rr_unix = inspect_swarm_workers_with_marker(
            sess_rr_unix,
            &brain,
            cwg_common::SWARM_CACHE_SAFE_TTL_SECONDS,
            "review",
            Some(now),
            1,
            Some(&rr_half_marker),
        );
        assert_eq!(res_rr_unix["active_count"], json!(0));
        assert_eq!(res_rr_unix["overall_action"], json!("initial_spawn"));

        // Case 11: Non-object JSONL rows (`null`, `[1, 2]`) before the 400th object in an old cycle
        // must NOT inflate fallback ordinal `seq` in `read_swarm_board_tail` past `board_head_seq=400`.
        let sess_rr_nonobj = "sess-neon-audit-nonobj-jsonl-ordinal";
        let sw_rr_no = rio::swarm_dir(&brain, sess_rr_nonobj);
        fs::create_dir_all(&sw_rr_no).unwrap();
        write_warm_worker("cid-neon-builder-nonobj");
        fs::write(
            sw_rr_no.join("members.json"),
            serde_json::to_string(&json!({
                "members": {
                    "neon-audit": {
                        "role": "worker",
                        "conversation_id": "cid-neon-builder-nonobj",
                        "model": cwg_common::NEON_XHIGH_MODEL,
                        "created_at": "2026-11-19T20:25:30.600Z",
                        "killed": false
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let mut nonobj_lines: Vec<String> = Vec::with_capacity(403);
        nonobj_lines.push("null".to_string());
        nonobj_lines.push("[1, 2]".to_string());
        nonobj_lines.push("{\"text\":\"\\uD800\"}".to_string());
        for i in 1..=399 {
            nonobj_lines.push(
                json!({
                    "agent": "coordinator",
                    "time": "2026-11-19T20:20:00Z",
                    "text": format!("@other-worker note {}", i)
                })
                .to_string(),
            );
        }
        // 400th JSON object (same second as reset_ts 20:25:30.500Z, pre-reset under board_head_seq=400):
        nonobj_lines.push(
            json!({
                "agent": "coordinator",
                "time": "2026-11-19T20:25:30Z",
                "text": "@neon-audit Adversarial audit of diff; report VERDICT: APPROVED or REVISE."
            })
            .to_string(),
        );
        fs::write(sw_rr_no.join("board.jsonl"), nonobj_lines.join("\n") + "\n").unwrap();
        let res_rr_no = inspect_swarm_workers_with_marker(
            sess_rr_nonobj,
            &brain,
            cwg_common::SWARM_CACHE_SAFE_TTL_SECONDS,
            "review",
            Some(now),
            1,
            Some(&rr_tail_marker),
        );
        assert_eq!(res_rr_no["active_count"], json!(0));
        assert_eq!(res_rr_no["overall_action"], json!("initial_spawn"));

        let _ = fs::remove_dir_all(&brain);
    }

    #[test]
    fn test_strict_prepare_commit_rejects_mid_prepare_marker_and_delta_mutations() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp_home = env::temp_dir().join(format!("swarm-cache-strict-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp_home);
        fs::create_dir_all(&tmp_home).unwrap();
        let prev = env::var_os("CARBON_STACK_HOME");
        env::set_var("CARBON_STACK_HOME", &tmp_home);

        let repo_dir = tmp_home.join("repo");
        fs::create_dir_all(repo_dir.join("src")).unwrap();
        let fpath = repo_dir.join("src").join("lib.rs");
        fs::write(&fpath, "pub fn a() -> i32 { 1 }\n").unwrap();
        let fnorm = rio::normalize_path(&fpath.to_string_lossy());
        let fp1 = cwg_common::content_fingerprint(&[fnorm.clone()], cwg_common::MAX_FINGERPRINT_FILE_BYTES);
        let gr_norm = rio::normalize_path(&repo_dir.to_string_lossy());
        let folded_gr = rio::fold_path(&gr_norm);

        let skey = "sess_strict_commit";
        let mfile = cwg_common::marker_path(skey);
        let base_marker = json!({
            "session": skey,
            "first_ts": 1000.0,
            "last_durable_ts": 1005.0,
            "git_root": gr_norm,
            "paths": [fnorm.clone()],
            "current_diff_hash": fp1.clone()
        });
        rio::write_json(&mfile, &base_marker).unwrap();
        let seen_h = vec!["1111111111111111111111111111111111111111".to_string()];
        let seen_t = vec![format!("{}|2222222222222222222222222222222222222222", fp1)];
        let dpaths = vec![fnorm.clone()];
        let rfile = cwg_common::swarm_rounds_path(skey);
        let sample_rounds = json!({"session": skey, "marker_first_ts": 1000.0, "lanes": {}});
        let upd = MarkerRepoPrepUpdate {
            skey,
            mfile: &mfile,
            folded_git_root: &folded_gr,
            expected_cycle_ts: 1000.0,
            expected_research_reset_ts: 0.0,
            expected_last_durable_ts: 1005.0,
            expected_dpaths: &dpaths,
            expected_diff_hash: &fp1,
            seen_heads: &seen_h,
            seen_fp_trees: &seen_t,
            snapshot_bound_required: false,
        };
        assert!(persist_marker_repo_prepare_state(
            upd,
            true,
            true,
            &rfile,
            Some(&sample_rounds),
        )
        .is_ok());
        assert!(rfile.is_file());

        let _ = fs::remove_file(&rfile);
        assert_eq!(
            persist_marker_repo_prepare_state(upd, true, false, &rfile, None).unwrap_err(),
            "concurrent_worktree_mutation",
            "unlinked rounds.json during non-mutating prepare must fail closed"
        );

        let mut reset_marker = base_marker.clone();
        reset_marker
            .as_object_mut()
            .unwrap()
            .insert("research_resets".to_string(), json!([{"reset_ts": 990.0}]));
        rio::write_json(&mfile, &reset_marker).unwrap();
        assert_eq!(
            persist_marker_repo_prepare_state(upd, true, true, &rfile, Some(&sample_rounds))
                .unwrap_err(),
            "concurrent_worktree_mutation"
        );
        assert_eq!(
            persist_marker_repo_prepare_state(upd, false, true, &rfile, Some(&sample_rounds))
                .unwrap_err(),
            "concurrent_worktree_mutation"
        );
        assert!(
            !rfile.exists(),
            "aborted prepare after concurrent research-reset must not recreate rounds.json"
        );
        rio::write_json(&mfile, &base_marker).unwrap();

        let pdir = cwg_common::marker_pending_dir(skey);
        fs::create_dir_all(&pdir).unwrap();
        let delta_file = pdir.join("0001.json");
        rio::write_json(
            &delta_file,
            &json!({"ts": 1006.0, "durable": true, "paths": [fnorm], "measured_fp": "other_fp"}),
        )
        .unwrap();
        assert_eq!(
            persist_marker_repo_prepare_state(upd, true, false, &rfile, None).unwrap_err(),
            "concurrent_worktree_mutation"
        );
        assert!(
            delta_file.is_file(),
            "aborted strict commit must leave concurrent pending delta intact"
        );
        let _ = fs::remove_file(&delta_file);

        fs::write(&fpath, "pub fn a() -> i32 { 2 }\n").unwrap();
        assert_eq!(
            persist_marker_repo_prepare_state(upd, true, true, &rfile, Some(&sample_rounds))
                .unwrap_err(),
            "concurrent_worktree_mutation"
        );

        match prev {
            Some(v) => env::set_var("CARBON_STACK_HOME", v),
            None => env::remove_var("CARBON_STACK_HOME"),
        }
        let _ = fs::remove_dir_all(&tmp_home);
    }
}
