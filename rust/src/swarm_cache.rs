use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::cwg_common;
use crate::rio;
use crate::win32_sqlite::now_sec;

pub const EMPTY_TREE_OID: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
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

fn val_to_i64(v: Option<&Value>) -> i64 {
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

fn sha256_hex_str(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
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
    let full_hex = sha256_hex_str(&stem);
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

fn is_hydrogen_model(model_low: &str) -> bool {
    model_low == cwg_common::HYDROGEN_LOW_MODEL
        || model_low == cwg_common::HYDROGEN_MEDIUM_MODEL
        || model_low == cwg_common::HYDROGEN_HIGH_MODEL
        || model_low == cwg_common::HYDROGEN_XHIGH_MODEL
}

fn matches_label(worker_name: &str, label: &str, model: &str) -> bool {
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
        return model_low.is_empty()
            || model_low == cwg_common::SONNET_HIGH_MODEL
            || model_low == cwg_common::SIMPLIFY_FALLBACK_MODEL;
    }
    if clean == "review" {
        if !model_low.is_empty()
            && (is_hydrogen_model(&model_low) || cwg_common::is_flash_model(&model_low))
        {
            return false;
        }
        return !is_simplify
            && (model_low == cwg_common::OPUS_HIGH_MODEL
                || low.contains("review")
                || low.contains("adversarial")
                || low.contains("critic")
                || low.contains("verifier"));
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
    let now = now_ts.unwrap_or_else(now_sec);
    let members = rio::load_swarm_members(brain_root, session);
    let mut names: Vec<&String> = members.keys().collect();
    names.sort();

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
        if rio::is_swarm_member_killed(Some(meta)) {
            if matches_label(name, label, &model) {
                killed_count += 1;
            }
            continue;
        }
        if !matches_label(name, label, &model) {
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
    let mut args: Vec<&str> = vec!["diff", old_oid, new_oid];
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

fn sync_round_diffs(
    git_root: &str,
    head_oid: &str,
    cur_tree_oid: &str,
    prev_tree_oid: &str,
    rel_paths: &[String],
    scratch_dir: &Path,
    clean_label: &str,
    cur_round: i64,
    regen: bool,
) -> Result<SyncDiffResult, String> {
    let full_file = scratch_dir.join(format!("{}_r{}_full.diff", clean_label, cur_round));
    let need_full = regen || !full_file.is_file();
    let full_diff = if need_full {
        git_diff_pair(git_root, head_oid, cur_tree_oid, rel_paths)?
    } else {
        String::new()
    };

    let inc_file = if cur_round >= 2 && !prev_tree_oid.is_empty() {
        Some(scratch_dir.join(format!("{}_r{}_incremental.diff", clean_label, cur_round)))
    } else {
        None
    };
    let need_inc = inc_file
        .as_ref()
        .map_or(false, |f| regen || !f.is_file());
    let mut inc_diff = if need_inc {
        git_diff_pair(git_root, prev_tree_oid, cur_tree_oid, rel_paths)?
    } else {
        String::new()
    };

    let full_diff_path = if need_full {
        let body = if full_diff.is_empty() {
            "# No diff against HEAD.\n"
        } else {
            full_diff.as_str()
        };
        write_scratch_text(&full_file, body)?
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

    let inc_diff_path = if need_inc {
        let prev_short: String = prev_tree_oid.chars().take(12).collect();
        let cur_short: String = cur_tree_oid.chars().take(12).collect();
        let header = format!(
            "# Incremental diff Round {} -> Round {}\n# Trees: {}..{}\n",
            cur_round - 1,
            cur_round,
            prev_short,
            cur_short
        );
        let tail = if inc_diff.is_empty() {
            "# No textual changes since previous round.\n"
        } else {
            inc_diff.as_str()
        };
        write_scratch_text(&inc_path, &format!("{}{}", header, tail))?
    } else {
        let raw = fs::read(&inc_path).unwrap_or_default();
        inc_diff = String::from_utf8_lossy(&raw).into_owned();
        rio::normalize_path(&inc_path.to_string_lossy())
    };

    Ok(SyncDiffResult {
        full_diff_path,
        incremental_diff_path: inc_diff_path,
        incremental_stat: summarize_diff_stat(&inc_diff),
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

pub fn prepare_round(
    session: &str,
    cwd: &str,
    brain_root: &Path,
    label: &str,
    ttl_seconds: u64,
    paths: &[String],
    reset: bool,
    now_ts: Option<f64>,
) -> Value {
    let now = now_ts.unwrap_or_else(now_sec);
    let raw_label = if label.is_empty() { "simplify" } else { label };
    let clean_label = rio::safe_key(raw_label, "simplify");

    let eff_cwd = if cwd.trim().is_empty() { "." } else { cwd };
    let Some(git_root) = rio::git_toplevel(eff_cwd, false) else {
        return json!({
            "ok": false,
            "error": format!("not_in_git_repo:{}", cwd),
        });
    };

    let raw_head = rio::git_head_oid(&git_root);
    let head_oid = if raw_head.is_empty() {
        EMPTY_TREE_OID.to_string()
    } else {
        raw_head
    };
    let cur_tree_oid = rio::capture_worktree_tree_oid(&git_root, 15.0);
    if cur_tree_oid.is_empty() {
        return json!({
            "ok": false,
            "error": "capture_worktree_tree_oid_failed",
        });
    }

    let mut rel_paths: Vec<String> = Vec::new();
    for raw_p in paths {
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

    let skey = rio::safe_key(session, "default");
    let marker = rio::read_json(&cwg_common::marker_path(&skey));
    let marker_first_ts = val_to_f64(marker.as_ref().and_then(|m| m.get("first_ts")));

    let rounds_file = cwg_common::swarm_rounds_path(&skey);
    let loaded_state = rio::read_json(&rounds_file);
    let mut state: Map<String, Value> = match loaded_state {
        Some(Value::Object(map))
            if map.get("session").and_then(|v| v.as_str()) == Some(session) =>
        {
            let prev_mts = val_to_f64(map.get("marker_first_ts"));
            if marker_first_ts != 0.0 && (prev_mts - marker_first_ts).abs() > 1.0 {
                let mut fresh = Map::new();
                fresh.insert("session".to_string(), Value::String(session.to_string()));
                fresh.insert("marker_first_ts".to_string(), json!(marker_first_ts));
                fresh.insert("lanes".to_string(), Value::Object(Map::new()));
                fresh
            } else {
                map
            }
        }
        _ => {
            let mut fresh = Map::new();
            fresh.insert("session".to_string(), Value::String(session.to_string()));
            fresh.insert("marker_first_ts".to_string(), json!(marker_first_ts));
            fresh.insert("lanes".to_string(), Value::Object(Map::new()));
            fresh
        }
    };

    if !state.get("lanes").map_or(false, |v| v.is_object()) {
        state.insert("lanes".to_string(), Value::Object(Map::new()));
    }
    let lane_key = format!("{}|{}", rio::fold_path(&git_root), clean_label);
    let mut history: Vec<Value> = if reset {
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
    let changed_paths = history
        .last()
        .map_or(false, |last| entry_paths(last) != rel_paths);

    if changed_tree {
        let next_round = history
            .last()
            .map(|h| val_to_i64(h.get("round")) + 1)
            .unwrap_or(1);
        history.push(json!({
            "round": next_round,
            "tree_oid": cur_tree_oid,
            "paths": rel_paths,
            "ts": (now * 1000.0).round() / 1000.0,
        }));
        if history.len() > MAX_ROUND_HISTORY {
            let keep_from = history.len() - MAX_ROUND_HISTORY;
            history = history[keep_from..].to_vec();
        }
    } else if changed_paths {
        if let Some(Value::Object(last_obj)) = history.last_mut() {
            last_obj.insert("paths".to_string(), json!(rel_paths));
        }
    }

    let cur_round = history
        .last()
        .map(|h| val_to_i64(h.get("round")))
        .unwrap_or(1);
    let prev_tree_oid = if history.len() >= 2 {
        val_to_str(history[history.len() - 2].get("tree_oid"))
    } else {
        String::new()
    };

    let proj_key = rio::project_key(&git_root, &[], &git_root, "");
    let scratch_dir = brain_root.join(session).join("scratch").join(proj_key);
    let diff_res = match sync_round_diffs(
        &git_root,
        &head_oid,
        &cur_tree_oid,
        &prev_tree_oid,
        &rel_paths,
        &scratch_dir,
        &clean_label,
        cur_round,
        changed_tree || changed_paths,
    ) {
        Ok(res) => res,
        Err(err) => {
            return json!({
                "ok": false,
                "error": err,
            });
        }
    };

    if changed_tree || changed_paths {
        if let Some(Value::Object(lanes_map)) = state.get_mut("lanes") {
            lanes_map.insert(lane_key, Value::Array(history));
        }
        let eff_mts = if marker_first_ts != 0.0 {
            marker_first_ts
        } else {
            val_to_f64(state.get("marker_first_ts"))
        };
        state.insert("marker_first_ts".to_string(), json!(eff_mts));
        let _ = rio::write_json(&rounds_file, &Value::Object(state));
    }

    let worker_status = inspect_swarm_workers(
        session,
        brain_root,
        ttl_seconds,
        &clean_label,
        Some(now),
        cur_round,
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

    let marker_doc = rio::read_json(&cwg_common::marker_path(session))
        .filter(|v| v.is_object())
        .unwrap_or_else(|| json!({}));
    let eff_repo_root = if !git_root.is_empty() {
        git_root.as_str()
    } else {
        cwd
    };
    let diff_metrics = cwg_common::compute_diff_metrics(&marker_doc, eff_repo_root, None);
    let fast_path_eligible =
        cwg_common::is_simplify_fast_path_eligible(&json!({}), None, Some(&diff_metrics), "");

    let overall_action = val_to_str(worker_status.get("overall_action"));
    json!({
        "ok": true,
        "session": session,
        "label": clean_label,
        "git_root": rio::normalize_path(&git_root),
        "head_oid": head_oid,
        "round": cur_round,
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
                let out = prepare_round(
                    &pargs.session,
                    &pargs.cwd,
                    &broot,
                    &pargs.label,
                    pargs.ttl,
                    &pargs.paths,
                    pargs.reset,
                    None,
                );
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
        let err_res = prepare_round(
            "sess-nongit",
            &non_git.to_string_lossy(),
            &brain,
            "simplify",
            270,
            &[],
            false,
            None,
        );
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

            let r1 = prepare_round("sess-git", &repo_s, &brain, "simplify", 270, &[], false, Some(1000.0));
            assert_eq!(r1["ok"], json!(true));
            assert_eq!(r1["round"], json!(1));
            assert_eq!(r1["fast_path_eligible"], json!(true));
            assert!(Path::new(r1["full_diff_path"].as_str().unwrap()).is_file());

            fs::write(repo.join("a.txt"), "one\ntwo\nthree\n").unwrap();
            let r2 = prepare_round("sess-git", &repo_s, &brain, "simplify", 270, &[], false, Some(1005.0));
            assert_eq!(r2["ok"], json!(true));
            assert_eq!(r2["round"], json!(2));
            assert!(Path::new(r2["incremental_diff_path"].as_str().unwrap()).is_file());
        }

        let _ = fs::remove_dir_all(&non_git);
        let _ = fs::remove_dir_all(&repo);
        let _ = fs::remove_dir_all(&brain);
        let _ = fs::remove_dir_all(&tmp_home);
    }
}
