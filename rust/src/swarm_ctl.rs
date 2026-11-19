use serde_json::{json, Map, Value};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::cwg_common;
use crate::rio;
use crate::win32_sqlite::now_sec;
use crate::worktree_guard;

fn eprintln_line(msg: &str) {
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(msg.as_bytes());
    let _ = err.write_all(b"\n");
    let _ = err.flush();
}

fn truncate_chars(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
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

fn val_to_str(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn abs_clean_path(raw: &str) -> PathBuf {
    if raw.trim().is_empty() {
        rio::resolve_abs_path(Path::new("."))
    } else {
        rio::resolve_abs_path(Path::new(raw))
    }
}

fn repo_root(cwd: &str) -> String {
    let eff = abs_clean_path(cwd).to_string_lossy().into_owned();
    rio::git_toplevel(&eff, false).unwrap_or(eff)
}

fn dirty_durable_files(root: &str) -> Vec<String> {
    let mut files: BTreeSet<String> = BTreeSet::new();
    let (rc, out, _) = rio::run_git(
        root,
        &["-c", "core.quotepath=false", "status", "--porcelain=v1", "-uall"],
        10.0,
    );
    if rc == 0 && !out.is_empty() {
        for line in out.lines() {
            if line.len() < 4 {
                continue;
            }
            let mut raw_path = line[3..].trim();
            if let Some((_, rhs)) = raw_path.split_once(" -> ") {
                raw_path = rhs.trim();
            }
            raw_path = raw_path.trim_matches('"');
            let norm = cwg_common::normalize_glob_pattern(raw_path);
            if norm.is_empty() || cwg_common::is_scratch_or_ephemeral(&norm, "", &[], root) {
                continue;
            }
            files.insert(norm);
        }
    }
    files.into_iter().collect()
}

fn caller_worker_if_non_coordinator() -> String {
    // SAFETY: Detect non-coordinator swarm worker env vars for mutating CLI commands.
    for key in rio::WORKER_ENV_KEYS {
        let val = env::var(key).unwrap_or_default().trim().to_string();
        if !val.is_empty()
            && !rio::COORDINATOR_ROLE_NAMES.contains(&val.to_lowercase().as_str())
        {
            return val;
        }
    }
    String::new()
}

fn deny_if_worker_caller() -> Option<i32> {
    let caller = caller_worker_if_non_coordinator();
    if !caller.is_empty() {
        rio::print_cli_json(
            &json!({"ok": false, "error": "coordinator_only", "worker": caller}),
            false,
        );
        return Some(2);
    }
    None
}

pub fn cmd_ownership_set(worker_arg: &str, paths_arg: &str, cwd: &str) -> i32 {
    if let Some(code) = deny_if_worker_caller() {
        return code;
    }
    let root = repo_root(cwd);
    let worker = worker_arg.trim();
    if worker.is_empty() || worker.eq_ignore_ascii_case("coordinator") {
        rio::print_cli_json(
            &json!({"ok": false, "error": "invalid_worker", "worker": worker}),
            false,
        );
        return 2;
    }

    let mut seen_globs: HashSet<String> = HashSet::new();
    let mut globs: Vec<String> = Vec::new();
    for raw_g in paths_arg.split(',') {
        if raw_g.trim().is_empty() {
            continue;
        }
        let g = cwg_common::normalize_glob_pattern(raw_g);
        if !g.is_empty() && seen_globs.insert(g.clone()) {
            globs.push(g);
        }
    }
    if globs.is_empty() {
        rio::print_cli_json(&json!({"ok": false, "error": "empty_paths"}), false);
        return 2;
    }

    let manifest = cwg_common::load_ownership_manifest(&root);
    let mut candidate_map = match manifest {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    let mut workers_map = candidate_map
        .get("workers")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    workers_map.insert(
        worker.to_string(),
        json!({"paths": globs, "updated_at": now_sec()}),
    );
    candidate_map.insert("workers".to_string(), Value::Object(workers_map));
    let candidate = Value::Object(candidate_map);

    let overlaps = cwg_common::detect_ownership_overlaps(&candidate, &root);
    if !overlaps.is_empty() {
        rio::print_cli_json(
            &json!({
                "ok": false,
                "error": "ownership_overlap",
                "worker": worker,
                "conflicts": overlaps,
            }),
            false,
        );
        return 2;
    }

    match cwg_common::save_ownership_manifest(&root, &candidate) {
        Ok(manifest_path) => {
            rio::print_cli_json(
                &json!({
                    "ok": true,
                    "manifest": rio::normalize_path(&manifest_path.to_string_lossy()),
                    "worker": worker,
                    "paths": globs,
                }),
                false,
            );
            0
        }
        Err(_) => {
            let mpath = cwg_common::ownership_manifest_path(&root)
                .map(|p| rio::normalize_path(&p.to_string_lossy()))
                .unwrap_or_default();
            rio::print_cli_json(
                &json!({"ok": false, "error": "manifest_write_failed", "manifest": mpath}),
                false,
            );
            1
        }
    }
}

fn remove_manifest_if_exists(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

pub fn clear_ownership_at_path(root: &str, mpath: &Path, worker_arg: &str) -> i32 {
    let mpath_norm = rio::normalize_path(&mpath.to_string_lossy());
    let worker = worker_arg.trim();

    // SAFETY: Distinguish genuine `NotFound` from `PermissionDenied` / stat errors so inaccessible manifests never report false success.
    match fs::symlink_metadata(mpath) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            rio::print_cli_json(&json!({"ok": true, "cleared": true, "manifest": mpath_norm}), false);
            return 0;
        }
        Err(e) => {
            rio::print_cli_json(
                &json!({"ok": false, "error": "manifest_stat_failed", "detail": e.to_string(), "manifest": mpath_norm}),
                false,
            );
            return 1;
        }
    }
    if worker.is_empty() {
        if let Err(err) = remove_manifest_if_exists(mpath) {
            rio::print_cli_json(
                &json!({"ok": false, "error": "manifest_remove_failed", "detail": err, "manifest": mpath_norm}),
                false,
            );
            return 1;
        }
        rio::print_cli_json(&json!({"ok": true, "cleared": "all", "manifest": mpath_norm}), false);
        return 0;
    }

    let raw = match fs::read_to_string(mpath) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            rio::print_cli_json(&json!({"ok": true, "cleared": true, "manifest": mpath_norm}), false);
            return 0;
        }
        Err(e) => {
            rio::print_cli_json(
                &json!({"ok": false, "error": "manifest_read_failed", "detail": e.to_string(), "manifest": mpath_norm}),
                false,
            );
            return 1;
        }
    };
    let mut manifest = match serde_json::from_str::<Value>(&raw) {
        Ok(Value::Object(m)) => m,
        Ok(_) => {
            rio::print_cli_json(
                &json!({"ok": false, "error": "manifest_invalid_json", "detail": "root is not an object", "manifest": mpath_norm}),
                false,
            );
            return 1;
        }
        Err(e) => {
            rio::print_cli_json(
                &json!({"ok": false, "error": "manifest_invalid_json", "detail": e.to_string(), "manifest": mpath_norm}),
                false,
            );
            return 1;
        }
    };
    let mut workers = manifest
        .get("workers")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let removed = workers.remove(worker).is_some();
    if !workers.is_empty() {
        let remaining: Vec<String> = workers.keys().cloned().collect();
        manifest.insert("workers".to_string(), Value::Object(workers));
        if cwg_common::save_ownership_manifest(root, &Value::Object(manifest)).is_err() {
            rio::print_cli_json(
                &json!({"ok": false, "error": "manifest_write_failed", "manifest": mpath_norm}),
                false,
            );
            return 1;
        }
        rio::print_cli_json(
            &json!({"ok": true, "worker": worker, "removed": removed, "remaining": remaining}),
            false,
        );
    } else {
        if let Err(err) = remove_manifest_if_exists(mpath) {
            rio::print_cli_json(
                &json!({"ok": false, "error": "manifest_remove_failed", "detail": err, "manifest": mpath_norm}),
                false,
            );
            return 1;
        }
        rio::print_cli_json(
            &json!({"ok": true, "worker": worker, "removed": removed, "remaining": []}),
            false,
        );
    }
    0
}

pub fn cmd_ownership_clear(worker_arg: &str, cwd: &str) -> i32 {
    if let Some(code) = deny_if_worker_caller() {
        return code;
    }
    let root = repo_root(cwd);
    let mpath = cwg_common::ownership_manifest_path(&root)
        .unwrap_or_else(|| PathBuf::from(&root).join(".swarm").join("ownership.json"));
    clear_ownership_at_path(&root, &mpath, worker_arg)
}

fn worker_owned_paths(entry: Option<&Value>) -> Vec<String> {
    entry
        .and_then(|v| v.get("paths"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

pub fn cmd_ownership_verify(worker_arg: &str, cwd: &str, strict: bool) -> i32 {
    let root = repo_root(cwd);
    let manifest = cwg_common::load_ownership_manifest(&root);
    let overlaps = cwg_common::detect_ownership_overlaps(&manifest, &root);
    let dirty_files = dirty_durable_files(&root);
    let workers = manifest
        .get("workers")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let target_worker = worker_arg.trim();

    let mut violations: Vec<Value> = Vec::new();
    if !target_worker.is_empty()
        && !target_worker.eq_ignore_ascii_case("coordinator")
        && !workers.is_empty()
    {
        let owned = worker_owned_paths(workers.get(target_worker));
        for rel in &dirty_files {
            if !cwg_common::path_matches_any_glob(rel, &owned) {
                violations.push(json!({
                    "worker": target_worker,
                    "path": rel,
                    "owned_paths": owned,
                }));
            }
        }
    } else if !workers.is_empty() && strict {
        for rel in &dirty_files {
            let mut owners: Vec<String> = Vec::new();
            for (wname, meta) in &workers {
                if meta.is_object() {
                    let owned = worker_owned_paths(Some(meta));
                    if cwg_common::path_matches_any_glob(rel, &owned) {
                        owners.push(wname.clone());
                    }
                }
            }
            if owners.is_empty() || owners.len() > 1 {
                violations.push(json!({"path": rel, "owners": owners}));
            }
        }
    }

    let ok = overlaps.is_empty() && violations.is_empty();
    let worker_names: Vec<String> = workers.keys().cloned().collect();
    rio::print_cli_json(
        &json!({
            "ok": ok,
            "overlaps": overlaps,
            "violations": violations,
            "dirty_files": dirty_files,
            "workers": worker_names,
        }),
        false,
    );
    if ok {
        0
    } else {
        2
    }
}

fn worktrees_base(root: &str) -> PathBuf {
    Path::new(root).join(".swarm").join("worktrees")
}

fn list_git_worktrees(root: &str) -> Vec<Map<String, Value>> {
    let (rc, mut items, _) = worktree_guard::list_worktrees(root);
    if rc != 0 {
        return Vec::new();
    }
    for item in &mut items {
        if let Some(branch) = item
            .get("branch")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
        {
            if !branch.is_empty() {
                let clean = branch.replace("refs/heads/", "");
                item.insert("branch".to_string(), Value::String(clean));
            }
        }
    }
    items
}

pub fn cmd_worktree_create(worker_arg: &str, cwd: &str, branch_arg: &str, base_arg: &str) -> i32 {
    if let Some(code) = deny_if_worker_caller() {
        return code;
    }
    let root = repo_root(cwd);
    let safe_worker = rio::safe_key(worker_arg, "");
    if safe_worker.is_empty() {
        rio::print_cli_json(&json!({"ok": false, "error": "invalid_worker"}), false);
        return 2;
    }
    let base_dir = worktrees_base(&root);
    let _ = fs::create_dir_all(&base_dir);
    let wt_path = base_dir.join(&safe_worker);
    let wt_str = wt_path.to_string_lossy().into_owned();
    let wt_fold = rio::fold_path(&wt_str);
    let wt_norm = rio::normalize_path(&wt_str);
    let branch = if branch_arg.trim().is_empty() {
        format!("swarm/{}", safe_worker)
    } else {
        branch_arg.trim().to_string()
    };

    for existing in list_git_worktrees(&root) {
        let ex_path = val_to_str(existing.get("path"));
        if rio::fold_path(&ex_path) == wt_fold && wt_path.exists() {
            let ex_branch = existing
                .get("branch")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or(branch.as_str());
            rio::print_cli_json(
                &json!({
                    "ok": true,
                    "reused": true,
                    "worker": worker_arg,
                    "worktree": wt_norm,
                    "branch": ex_branch,
                }),
                false,
            );
            return 0;
        }
    }

    let ref_branch = format!("refs/heads/{}", branch);
    let (rc_b, _, _) = rio::run_git(&root, &["show-ref", "--verify", "--quiet", &ref_branch], 5.0);
    let (rc, out, err) = if rc_b == 0 {
        rio::run_git(&root, &["worktree", "add", &wt_str, &branch], 15.0)
    } else {
        let mut cmd_args: Vec<&str> = vec!["worktree", "add", "-b", &branch, &wt_str];
        if !base_arg.is_empty() {
            cmd_args.push(base_arg);
        }
        rio::run_git(&root, &cmd_args, 15.0)
    };
    if rc != 0 {
        let msg = if !err.trim().is_empty() {
            err.trim().to_string()
        } else if !out.trim().is_empty() {
            out.trim().to_string()
        } else {
            "git worktree add failed".to_string()
        };
        rio::print_cli_json(
            &json!({"ok": false, "error": msg, "worktree": wt_norm}),
            false,
        );
        return 1;
    }

    rio::print_cli_json(
        &json!({
            "ok": true,
            "reused": false,
            "worker": worker_arg,
            "worktree": wt_norm,
            "branch": branch,
        }),
        false,
    );
    0
}

pub fn cmd_worktree_status(cwd: &str) -> i32 {
    let root = repo_root(cwd);
    let base_fold = rio::fold_path(&worktrees_base(&root).to_string_lossy());
    let base_prefix = format!("{}/", base_fold);
    let mut swarm_wts: Vec<Value> = Vec::new();
    for wt in list_git_worktrees(&root) {
        let p = val_to_str(wt.get("path"));
        if !rio::fold_path(&p).starts_with(&base_prefix) {
            continue;
        }
        let exists = Path::new(&p).is_dir();
        let dirty = if exists {
            dirty_durable_files(&p)
        } else {
            Vec::new()
        };
        let worker_name = Path::new(&p)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        swarm_wts.push(json!({
            "worker": worker_name,
            "path": rio::normalize_path(&p),
            "branch": val_to_str(wt.get("branch")),
            "exists": exists,
            "dirty_count": dirty.len(),
            "dirty_files": dirty,
        }));
    }
    rio::print_cli_json(
        &json!({"ok": true, "worktrees": swarm_wts, "count": swarm_wts.len()}),
        false,
    );
    0
}

pub fn cmd_worktree_cleanup(worker_arg: &str, cwd: &str, delete_branch: bool) -> i32 {
    if let Some(code) = deny_if_worker_caller() {
        return code;
    }
    let root = repo_root(cwd);
    let base_dir = worktrees_base(&root);
    let base_fold = rio::fold_path(&base_dir.to_string_lossy());
    let base_prefix = format!("{}/", base_fold);

    let mut targets: Vec<PathBuf> = Vec::new();
    let safe_worker = rio::safe_key(worker_arg, "");
    if !safe_worker.is_empty() {
        targets.push(base_dir.join(safe_worker));
    } else {
        let mut seen_folds: HashSet<String> = HashSet::new();
        for wt in list_git_worktrees(&root) {
            let p_str = val_to_str(wt.get("path"));
            let fold = rio::fold_path(&p_str);
            if fold.starts_with(&base_prefix) {
                seen_folds.insert(fold);
                targets.push(PathBuf::from(p_str));
            }
        }
        if base_dir.is_dir() {
            if let Ok(rd) = fs::read_dir(&base_dir) {
                let mut children: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|x| x.path())).collect();
                children.sort();
                for child in children {
                    let fold = rio::fold_path(&child.to_string_lossy());
                    if !seen_folds.contains(&fold) {
                        targets.push(child);
                    }
                }
            }
        }
    }

    let mut results: Vec<Value> = Vec::new();
    let mut all_ok = true;
    for wt_path in targets {
        let wt_str = wt_path.to_string_lossy().into_owned();
        let res = worktree_guard::safe_remove_worktree(&wt_str, &root, true);
        let ok = res.get("ok").and_then(|v| v.as_bool()) == Some(true);
        if delete_branch && ok {
            let btail = wt_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            if !btail.is_empty() {
                let branch_name = format!("swarm/{}", btail);
                let _ = rio::run_git(&root, &["branch", "-D", &branch_name], 5.0);
            }
        }
        results.push(res);
        if !ok {
            all_ok = false;
        }
    }
    let _ = rio::run_git(&root, &["worktree", "prune"], 5.0);
    rio::print_cli_json(&json!({"ok": all_ok, "removed": results}), false);
    if all_ok {
        0
    } else {
        1
    }
}

fn load_summary_members(session: &str, root: &str) -> (Option<PathBuf>, Map<String, Value>) {
    let brain_root = rio::resolve_brain_root("");
    if !session.is_empty() {
        let members = rio::load_swarm_members(&brain_root, session);
        if !members.is_empty() {
            return (Some(brain_root), members);
        }
    }
    let local_path = Path::new(root).join(".swarm").join("members.json");
    if let Some(Value::Object(local_doc)) = rio::read_json(&local_path) {
        let src = match local_doc.get("members") {
            Some(Value::Object(m)) => m,
            _ => &local_doc,
        };
        let mut filtered = Map::new();
        for (k, v) in src {
            if v.is_object() {
                filtered.insert(k.clone(), v.clone());
            }
        }
        return (Some(brain_root), filtered);
    }
    (Some(brain_root), Map::new())
}

pub fn cmd_board_summary(since_arg: i64, session: &str, cwd: &str) -> i32 {
    let root = repo_root(cwd);
    let since = since_arg.max(0);
    let (bp_opt, messages) = cwg_common::load_swarm_board_messages(session, &root, "", None);
    let head_seq = messages
        .iter()
        .map(|m| val_to_i64(m.get("_seq")))
        .max()
        .unwrap_or(0);

    let mut recent: Vec<Value> = Vec::new();
    for m in &messages {
        let seq = val_to_i64(m.get("_seq"));
        if seq <= since {
            continue;
        }
        let agent = val_to_str(m.get("agent").or_else(|| m.get("worker")));
        let raw_text = val_to_str(m.get("text"));
        let collapsed = raw_text.split_whitespace().collect::<Vec<_>>().join(" ");
        let preview = truncate_chars(&collapsed, 120).to_string();
        let time = val_to_str(m.get("time").or_else(|| m.get("ts")));
        recent.push(json!({
            "seq": seq,
            "agent": agent,
            "preview": preview,
            "time": time,
        }));
    }

    let (brain_root, members) = load_summary_members(session, &root);
    let mut worker_summary = Map::new();
    for (name, meta) in &members {
        if rio::is_swarm_role_member(name, Some(meta)) {
            continue;
        }
        let last_post_seq = messages
            .iter()
            .filter(|m| val_to_str(m.get("agent")) == *name)
            .map(|m| val_to_i64(m.get("_seq")))
            .max()
            .unwrap_or(0);
        let state = if rio::is_swarm_member_killed(Some(meta)) {
            "killed".to_string()
        } else {
            let wm = val_to_str(meta.get("wake_mode"));
            if wm.is_empty() {
                "active".to_string()
            } else {
                wm
            }
        };
        let model = val_to_str(
            meta.get("applied_model")
                .filter(|v| !v.is_null() && !val_to_str(Some(v)).is_empty())
                .or_else(|| {
                    meta.get("desired_model")
                        .filter(|v| !v.is_null() && !val_to_str(Some(v)).is_empty())
                })
                .or_else(|| meta.get("model")),
        );
        worker_summary.insert(
            name.clone(),
            json!({
                "state": state,
                "model": model,
                "last_seq": last_post_seq,
            }),
        );
    }

    let empty_act = HashMap::new();
    let stalled = cwg_common::detect_stalled_workers(cwg_common::StallDetectInput {
        members: &members,
        board_messages: &messages,
        cwd: &root,
        brain_root: brain_root.as_deref(),
        worker_last_activity: &empty_act,
        in_flight_names: &[],
        now_ts: None,
        timeout_sec: None,
    });

    let art_dir = Path::new(&root).join(".swarm").join("artifacts");
    let mut artifacts: Vec<String> = Vec::new();
    if art_dir.is_dir() {
        if let Ok(rd) = fs::read_dir(&art_dir) {
            for ent in rd.flatten() {
                let p = ent.path();
                if p.is_file() {
                    if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                        artifacts.push(name.to_string());
                    }
                }
            }
        }
        artifacts.sort();
    }

    let bp_str = bp_opt
        .map(|p| rio::normalize_path(&p.to_string_lossy()))
        .unwrap_or_default();
    rio::print_cli_json(
        &json!({
            "ok": true,
            "board_path": bp_str,
            "head_seq": head_seq,
            "since": since,
            "total_messages": messages.len(),
            "recent_count": recent.len(),
            "recent_messages": recent,
            "workers": worker_summary,
            "stalled_workers": stalled,
            "artifacts": artifacts,
        }),
        false,
    );
    0
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

pub fn run_cli(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln_line("usage: swarm_ctl <ownership|worktree|board> <action> [options]");
        return 2;
    }
    match args[0].as_str() {
        "-h" | "--help" => {
            eprintln_line("usage: swarm_ctl <ownership|worktree|board> <action> [options]");
            0
        }
        "ownership" => {
            if args.len() < 2 {
                eprintln_line("swarm_ctl ownership: action required (set|clear|verify-git-diff)");
                return 2;
            }
            match args[1].as_str() {
                "set" => {
                    let mut worker = String::new();
                    let mut paths = String::new();
                    let mut cwd = String::new();
                    let mut i = 2usize;
                    while i < args.len() {
                        let a = args[i].as_str();
                        if a == "--worker" || a.starts_with("--worker=") {
                            match take_flag_value(args, &mut i, "--worker") {
                                Ok(v) => worker = v,
                                Err(e) => {
                                    eprintln_line(&format!("swarm_ctl ownership set: {}", e));
                                    return 2;
                                }
                            }
                        } else if a == "--paths" || a.starts_with("--paths=") {
                            match take_flag_value(args, &mut i, "--paths") {
                                Ok(v) => paths = v,
                                Err(e) => {
                                    eprintln_line(&format!("swarm_ctl ownership set: {}", e));
                                    return 2;
                                }
                            }
                        } else if a == "--cwd" || a.starts_with("--cwd=") {
                            match take_flag_value(args, &mut i, "--cwd") {
                                Ok(v) => cwd = v,
                                Err(e) => {
                                    eprintln_line(&format!("swarm_ctl ownership set: {}", e));
                                    return 2;
                                }
                            }
                        } else {
                            eprintln_line(&format!("swarm_ctl ownership set: unrecognized argument {}", a));
                            return 2;
                        }
                        i += 1;
                    }
                    if worker.is_empty() || paths.is_empty() {
                        eprintln_line("swarm_ctl ownership set: --worker and --paths are required");
                        return 2;
                    }
                    cmd_ownership_set(&worker, &paths, &cwd)
                }
                "clear" => {
                    let mut worker = String::new();
                    let mut cwd = String::new();
                    let mut i = 2usize;
                    while i < args.len() {
                        let a = args[i].as_str();
                        if a == "--worker" || a.starts_with("--worker=") {
                            match take_flag_value(args, &mut i, "--worker") {
                                Ok(v) => worker = v,
                                Err(e) => {
                                    eprintln_line(&format!("swarm_ctl ownership clear: {}", e));
                                    return 2;
                                }
                            }
                        } else if a == "--cwd" || a.starts_with("--cwd=") {
                            match take_flag_value(args, &mut i, "--cwd") {
                                Ok(v) => cwd = v,
                                Err(e) => {
                                    eprintln_line(&format!("swarm_ctl ownership clear: {}", e));
                                    return 2;
                                }
                            }
                        } else {
                            eprintln_line(&format!("swarm_ctl ownership clear: unrecognized argument {}", a));
                            return 2;
                        }
                        i += 1;
                    }
                    cmd_ownership_clear(&worker, &cwd)
                }
                "verify-git-diff" => {
                    let mut worker = String::new();
                    let mut cwd = String::new();
                    let mut strict = false;
                    let mut i = 2usize;
                    while i < args.len() {
                        let a = args[i].as_str();
                        if a == "--strict" {
                            strict = true;
                        } else if a == "--worker" || a.starts_with("--worker=") {
                            match take_flag_value(args, &mut i, "--worker") {
                                Ok(v) => worker = v,
                                Err(e) => {
                                    eprintln_line(&format!("swarm_ctl ownership verify-git-diff: {}", e));
                                    return 2;
                                }
                            }
                        } else if a == "--cwd" || a.starts_with("--cwd=") {
                            match take_flag_value(args, &mut i, "--cwd") {
                                Ok(v) => cwd = v,
                                Err(e) => {
                                    eprintln_line(&format!("swarm_ctl ownership verify-git-diff: {}", e));
                                    return 2;
                                }
                            }
                        } else {
                            eprintln_line(&format!(
                                "swarm_ctl ownership verify-git-diff: unrecognized argument {}",
                                a
                            ));
                            return 2;
                        }
                        i += 1;
                    }
                    cmd_ownership_verify(&worker, &cwd, strict)
                }
                other => {
                    eprintln_line(&format!("swarm_ctl ownership: unknown action '{}'", other));
                    2
                }
            }
        }
        "worktree" => {
            if args.len() < 2 {
                eprintln_line("swarm_ctl worktree: action required (create|status|cleanup)");
                return 2;
            }
            match args[1].as_str() {
                "create" => {
                    let mut worker = String::new();
                    let mut cwd = String::new();
                    let mut branch = String::new();
                    let mut base = String::new();
                    let mut i = 2usize;
                    while i < args.len() {
                        let a = args[i].as_str();
                        if a == "--worker" || a.starts_with("--worker=") {
                            match take_flag_value(args, &mut i, "--worker") {
                                Ok(v) => worker = v,
                                Err(e) => {
                                    eprintln_line(&format!("swarm_ctl worktree create: {}", e));
                                    return 2;
                                }
                            }
                        } else if a == "--cwd" || a.starts_with("--cwd=") {
                            match take_flag_value(args, &mut i, "--cwd") {
                                Ok(v) => cwd = v,
                                Err(e) => {
                                    eprintln_line(&format!("swarm_ctl worktree create: {}", e));
                                    return 2;
                                }
                            }
                        } else if a == "--branch" || a.starts_with("--branch=") {
                            match take_flag_value(args, &mut i, "--branch") {
                                Ok(v) => branch = v,
                                Err(e) => {
                                    eprintln_line(&format!("swarm_ctl worktree create: {}", e));
                                    return 2;
                                }
                            }
                        } else if a == "--base" || a.starts_with("--base=") {
                            match take_flag_value(args, &mut i, "--base") {
                                Ok(v) => base = v,
                                Err(e) => {
                                    eprintln_line(&format!("swarm_ctl worktree create: {}", e));
                                    return 2;
                                }
                            }
                        } else {
                            eprintln_line(&format!("swarm_ctl worktree create: unrecognized argument {}", a));
                            return 2;
                        }
                        i += 1;
                    }
                    if worker.is_empty() {
                        eprintln_line("swarm_ctl worktree create: --worker is required");
                        return 2;
                    }
                    cmd_worktree_create(&worker, &cwd, &branch, &base)
                }
                "status" => {
                    let mut cwd = String::new();
                    let mut i = 2usize;
                    while i < args.len() {
                        let a = args[i].as_str();
                        if a == "--cwd" || a.starts_with("--cwd=") {
                            match take_flag_value(args, &mut i, "--cwd") {
                                Ok(v) => cwd = v,
                                Err(e) => {
                                    eprintln_line(&format!("swarm_ctl worktree status: {}", e));
                                    return 2;
                                }
                            }
                        } else {
                            eprintln_line(&format!("swarm_ctl worktree status: unrecognized argument {}", a));
                            return 2;
                        }
                        i += 1;
                    }
                    cmd_worktree_status(&cwd)
                }
                "cleanup" => {
                    let mut worker = String::new();
                    let mut cwd = String::new();
                    let mut delete_branch = false;
                    let mut i = 2usize;
                    while i < args.len() {
                        let a = args[i].as_str();
                        if a == "--delete-branch" {
                            delete_branch = true;
                        } else if a == "--worker" || a.starts_with("--worker=") {
                            match take_flag_value(args, &mut i, "--worker") {
                                Ok(v) => worker = v,
                                Err(e) => {
                                    eprintln_line(&format!("swarm_ctl worktree cleanup: {}", e));
                                    return 2;
                                }
                            }
                        } else if a == "--cwd" || a.starts_with("--cwd=") {
                            match take_flag_value(args, &mut i, "--cwd") {
                                Ok(v) => cwd = v,
                                Err(e) => {
                                    eprintln_line(&format!("swarm_ctl worktree cleanup: {}", e));
                                    return 2;
                                }
                            }
                        } else {
                            eprintln_line(&format!("swarm_ctl worktree cleanup: unrecognized argument {}", a));
                            return 2;
                        }
                        i += 1;
                    }
                    cmd_worktree_cleanup(&worker, &cwd, delete_branch)
                }
                other => {
                    eprintln_line(&format!("swarm_ctl worktree: unknown action '{}'", other));
                    2
                }
            }
        }
        "board" => {
            if args.len() < 2 {
                eprintln_line("swarm_ctl board: action required (summary)");
                return 2;
            }
            match args[1].as_str() {
                "summary" => {
                    let mut since: i64 = 0;
                    let mut session = String::new();
                    let mut cwd = String::new();
                    let mut i = 2usize;
                    while i < args.len() {
                        let a = args[i].as_str();
                        if a == "--since" || a.starts_with("--since=") {
                            match take_flag_value(args, &mut i, "--since") {
                                Ok(raw) => match raw.trim().parse::<i64>() {
                                    Ok(n) => since = n,
                                    Err(_) => {
                                        eprintln_line(&format!(
                                            "swarm_ctl board summary: invalid --since value: {}",
                                            raw
                                        ));
                                        return 2;
                                    }
                                },
                                Err(e) => {
                                    eprintln_line(&format!("swarm_ctl board summary: {}", e));
                                    return 2;
                                }
                            }
                        } else if a == "--session" || a.starts_with("--session=") {
                            match take_flag_value(args, &mut i, "--session") {
                                Ok(v) => session = v,
                                Err(e) => {
                                    eprintln_line(&format!("swarm_ctl board summary: {}", e));
                                    return 2;
                                }
                            }
                        } else if a == "--cwd" || a.starts_with("--cwd=") {
                            match take_flag_value(args, &mut i, "--cwd") {
                                Ok(v) => cwd = v,
                                Err(e) => {
                                    eprintln_line(&format!("swarm_ctl board summary: {}", e));
                                    return 2;
                                }
                            }
                        } else {
                            eprintln_line(&format!("swarm_ctl board summary: unrecognized argument {}", a));
                            return 2;
                        }
                        i += 1;
                    }
                    cmd_board_summary(since, &session, &cwd)
                }
                other => {
                    eprintln_line(&format!("swarm_ctl board: unknown action '{}'", other));
                    2
                }
            }
        }
        other => {
            eprintln_line(&format!("swarm_ctl: unknown command '{}'", other));
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQ: AtomicU64 = AtomicU64::new(1);

    struct EnvRestore {
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl EnvRestore {
        fn clear_worker_keys() -> Self {
            let mut saved = Vec::new();
            for &k in rio::WORKER_ENV_KEYS {
                saved.push((k, env::var_os(k)));
                env::remove_var(k);
            }
            Self { saved }
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            for (k, v) in &self.saved {
                match v {
                    Some(val) => env::set_var(k, val),
                    None => env::remove_var(k),
                }
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
    fn test_worker_caller_guard_and_ownership_set_verify() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _env = EnvRestore::clear_worker_keys();

        let repo = make_temp_dir("swarm-ctl-own");
        let repo_s = repo.to_string_lossy().into_owned();
        let (rc_init, _, _) = rio::run_git(&repo_s, &["init"], 5.0);
        if rc_init == 0 {
            let _ = rio::run_git(&repo_s, &["config", "user.email", "t@example.com"], 5.0);
            let _ = rio::run_git(&repo_s, &["config", "user.name", "Test"], 5.0);
            fs::create_dir_all(repo.join("src")).unwrap();
            fs::create_dir_all(repo.join("tests")).unwrap();
            fs::write(repo.join("src").join("a.rs"), "fn a() {}\n").unwrap();
            fs::write(repo.join("tests").join("t.rs"), "fn t() {}\n").unwrap();
            let _ = rio::run_git(&repo_s, &["add", "."], 5.0);
            let _ = rio::run_git(&repo_s, &["commit", "-m", "init"], 5.0);

            env::set_var("SWARM_WORKER_NAME", "builder-1");
            assert_eq!(cmd_ownership_set("builder-1", "src/**", &repo_s), 2);
            env::remove_var("SWARM_WORKER_NAME");

            assert_eq!(cmd_ownership_set("builder-a", "src/**", &repo_s), 0);
            assert_eq!(cmd_ownership_set("builder-b", "src/*.rs", &repo_s), 2);
            assert_eq!(cmd_ownership_set("builder-b", "tests/**", &repo_s), 0);

            fs::write(repo.join("src").join("a.rs"), "fn a() { /* edit */ }\n").unwrap();
            assert_eq!(cmd_ownership_verify("builder-a", &repo_s, false), 0);
            assert_eq!(cmd_ownership_verify("builder-b", &repo_s, false), 2);
            assert_eq!(cmd_ownership_verify("", &repo_s, true), 0);

            assert_eq!(cmd_ownership_clear("builder-a", &repo_s), 0);
            assert_eq!(cmd_ownership_verify("", &repo_s, true), 2);
            assert_eq!(cmd_ownership_clear("", &repo_s), 0);
        }

        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn test_worktree_create_status_cleanup_and_board_summary() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _env = EnvRestore::clear_worker_keys();

        let repo = make_temp_dir("swarm-ctl-wt");
        let repo_s = repo.to_string_lossy().into_owned();
        let (rc_init, _, _) = rio::run_git(&repo_s, &["init"], 5.0);
        if rc_init == 0 {
            let _ = rio::run_git(&repo_s, &["config", "user.email", "t@example.com"], 5.0);
            let _ = rio::run_git(&repo_s, &["config", "user.name", "Test"], 5.0);
            fs::write(repo.join("README.md"), "hello\n").unwrap();
            let _ = rio::run_git(&repo_s, &["add", "README.md"], 5.0);
            let _ = rio::run_git(&repo_s, &["commit", "-m", "init"], 5.0);

            assert_eq!(cmd_worktree_create("worker-1", &repo_s, "", ""), 0);
            assert_eq!(cmd_worktree_status(&repo_s), 0);
            assert_eq!(cmd_worktree_cleanup("worker-1", &repo_s, true), 0);
            assert_eq!(cmd_board_summary(0, "", &repo_s), 0);

            // INVARIANT: `ownership clear` must return error (1) both when stat fails (`manifest_stat_failed`) and when unlink fails (`manifest_remove_failed`).
            let bad_mpath = repo.join(".swarm").join("ownership.json");
            let _ = fs::remove_file(&bad_mpath);
            fs::create_dir_all(&bad_mpath).unwrap();
            assert_eq!(cmd_ownership_clear("", &repo_s), 1);
            let _ = fs::remove_dir_all(&bad_mpath);
            let unstatable = repo.join(".swarm").join("bad\0manifest.json");
            assert_eq!(clear_ownership_at_path(&repo_s, &unstatable, ""), 1);
            assert_eq!(clear_ownership_at_path(&repo_s, &bad_mpath, ""), 0);
        }

        let _ = fs::remove_dir_all(&repo);
    }
}
