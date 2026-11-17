use serde_json::{json, Map, Value};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::rio;
use crate::win32_sqlite;

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

fn abs_clean_path(raw: &str) -> PathBuf {
    if raw.trim().is_empty() {
        rio::resolve_abs_path(Path::new("."))
    } else {
        rio::resolve_abs_path(Path::new(raw))
    }
}

pub fn is_directory_link(path: &Path) -> bool {
    win32_sqlite::is_link_or_junction(path)
}

pub fn unlink_directory_links(root_dir: &str) -> (Vec<String>, Vec<String>) {
    // SAFETY: Detach symlinks and NTFS junctions without recursing into target directories so `git worktree remove` never wipes shared targets like `node_modules`.
    let mut unlinked: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    if root_dir.trim().is_empty() || !Path::new(root_dir).is_dir() {
        return (unlinked, errors);
    }

    let mut stack: Vec<PathBuf> = vec![abs_clean_path(root_dir)];
    while let Some(current) = stack.pop() {
        let entries = match fs::read_dir(&current) {
            Ok(rd) => rd,
            Err(exc) => {
                errors.push(format!("scandir:{}:{}", current.to_string_lossy(), exc));
                continue;
            }
        };

        for entry_res in entries {
            let Ok(entry) = entry_res else {
                continue;
            };
            if entry.file_name().to_string_lossy() == ".git" {
                continue;
            }
            let full = entry.path();
            if is_directory_link(&full) {
                let unlink_res = if cfg!(windows) {
                    win32_sqlite::remove_junction_dir(&full).or_else(|e1| {
                        let is_file_symlink = fs::symlink_metadata(&full)
                            .map(|m| m.file_type().is_symlink() && !m.is_dir())
                            .unwrap_or(false);
                        if is_file_symlink {
                            fs::remove_file(&full).map_err(|e2| format!("{}; {}", e1, e2))
                        } else {
                            Err(e1)
                        }
                    })
                } else {
                    fs::remove_file(&full)
                        .map_err(|e| e.to_string())
                        .or_else(|_| win32_sqlite::remove_junction_dir(&full))
                };
                match unlink_res {
                    Ok(()) => unlinked.push(rio::normalize_path(&full.to_string_lossy())),
                    Err(exc) => errors.push(format!("unlink:{}:{}", full.to_string_lossy(), exc)),
                }
            } else if entry.file_type().map_or(false, |ft| ft.is_dir()) {
                stack.push(full);
            }
        }
    }

    (unlinked, errors)
}

pub fn snapshot_dirty_worktree(worktree_dir: &str, label: &str) -> Value {
    let wt = abs_clean_path(worktree_dir);
    let wt_str = wt.to_string_lossy().into_owned();
    let Some(top) = rio::git_toplevel(&wt_str, false) else {
        return json!({"ok": false, "error": "not_a_git_worktree"});
    };

    let (rc_st, status_out, _) = rio::run_git(&top, &["status", "--porcelain=v1"], 5.0);
    if rc_st != 0 {
        return json!({"ok": false, "error": "git_status_failed"});
    }
    if status_out.trim().is_empty() {
        return json!({"ok": true, "clean": true, "ref": "", "commit": ""});
    }

    let parent_sha = rio::git_head_oid(&top);
    let tree_sha = rio::capture_worktree_tree_oid(&top, 15.0);
    if tree_sha.is_empty() {
        return json!({"ok": false, "error": "capture_worktree_tree_oid_failed"});
    }

    let now = win32_sqlite::now_sec();
    let commit_msg = format!(
        "WIP snapshot ({}) at {}",
        label,
        win32_sqlite::format_iso_utc(now)
    );
    let mut commit_args: Vec<&str> = vec!["commit-tree", &tree_sha];
    if !parent_sha.is_empty() {
        commit_args.push("-p");
        commit_args.push(&parent_sha);
    }
    commit_args.push("-m");
    commit_args.push(&commit_msg);

    let (rc3, commit_out, err3) = rio::run_git(&top, &commit_args, 15.0);
    let commit_sha = commit_out.trim().to_string();
    if rc3 != 0 || commit_sha.is_empty() {
        return json!({
            "ok": false,
            "error": format!("git_commit_tree_failed:{}", truncate_chars(err3.trim(), 160)),
        });
    }

    let raw_lbl = rio::safe_key(label, "wip");
    let safe_lbl = truncate_chars(&raw_lbl, 32);
    let ref_name = format!("refs/wip/{}-{}", safe_lbl, now as i64);
    let (rc4, _, err4) = rio::run_git(&top, &["update-ref", &ref_name, &commit_sha], 5.0);
    if rc4 != 0 {
        return json!({
            "ok": false,
            "error": format!("git_update_ref_failed:{}", truncate_chars(err4.trim(), 160)),
        });
    }

    json!({
        "ok": true,
        "clean": false,
        "ref": ref_name,
        "commit": commit_sha,
        "worktree": rio::normalize_path(&top),
    })
}

pub fn safe_remove_worktree(worktree_dir: &str, repo_dir: &str, snapshot_dirty: bool) -> Value {
    let wt_path = abs_clean_path(worktree_dir);
    let wt = wt_path.to_string_lossy().into_owned();
    let wt_norm = rio::normalize_path(&wt);
    if !wt_path.exists() {
        return json!({"ok": true, "already_absent": true, "worktree": wt_norm});
    }

    let (rc_st, status_out, _) = rio::run_git(&wt, &["status", "--porcelain=v1"], 5.0);
    let is_dirty = rc_st == 0 && !status_out.trim().is_empty();

    let mut snap_info: Option<Value> = None;
    if is_dirty {
        if !snapshot_dirty {
            return json!({
                "ok": false,
                "error": "worktree_dirty_refused",
                "worktree": wt_norm,
            });
        }
        let lbl = wt_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("auto");
        let snap = snapshot_dirty_worktree(&wt, lbl);
        if snap.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            let err_s = snap.get("error").and_then(|v| v.as_str()).unwrap_or("");
            return json!({
                "ok": false,
                "error": format!("dirty_snapshot_failed:{}", err_s),
                "worktree": wt_norm,
            });
        }
        snap_info = Some(snap);
    }

    // SAFETY: Unlink directory links/junctions BEFORE `git worktree remove` touches the tree.
    let (unlinked, link_errors) = unlink_directory_links(&wt);
    if !link_errors.is_empty() {
        return json!({
            "ok": false,
            "error": "junction_unlink_failed",
            "details": link_errors,
            "worktree": wt_norm,
        });
    }

    let mut anchor = if !repo_dir.trim().is_empty() {
        abs_clean_path(repo_dir).to_string_lossy().into_owned()
    } else {
        wt_path
            .parent()
            .and_then(|p| rio::git_toplevel(&p.to_string_lossy(), false))
            .unwrap_or_default()
    };

    if anchor.is_empty() {
        let (rc_c, common_out, _) = rio::run_git(&wt, &["rev-parse", "--git-common-dir"], 3.0);
        let cpath = common_out.trim();
        if rc_c == 0 && !cpath.is_empty() {
            let cabs = if Path::new(cpath).is_absolute() {
                abs_clean_path(cpath)
            } else {
                abs_clean_path(&wt_path.join(cpath).to_string_lossy())
            };
            if cabs.file_name().and_then(|s| s.to_str()) == Some(".git") {
                if let Some(parent) = cabs.parent() {
                    anchor = parent.to_string_lossy().into_owned();
                }
            } else {
                anchor = cabs.to_string_lossy().into_owned();
            }
        }
    }

    if anchor.is_empty() || !Path::new(&anchor).is_dir() {
        return json!({"ok": false, "error": "cannot_resolve_parent_repo"});
    }

    let mut rm_args: Vec<&str> = vec!["worktree", "remove"];
    if is_dirty && snap_info.is_some() {
        rm_args.push("--force");
    }
    rm_args.push(&wt);

    let (rc_rm, _, err_rm) = rio::run_git(&anchor, &rm_args, 15.0);
    let snap_val = snap_info.unwrap_or(Value::Null);
    if rc_rm != 0 {
        return json!({
            "ok": false,
            "error": format!("git_worktree_remove_failed:{}", truncate_chars(err_rm.trim(), 200)),
            "snapshot": snap_val,
            "unlinked_links": unlinked,
        });
    }

    json!({
        "ok": true,
        "worktree": wt_norm,
        "unlinked_links": unlinked,
        "snapshot": snap_val,
    })
}

pub fn list_worktrees(root: &str) -> (i32, Vec<Map<String, Value>>, String) {
    let (rc, out, err) = rio::run_git(root, &["worktree", "list", "--porcelain"], 6.0);
    if rc != 0 {
        return (rc, Vec::new(), err);
    }
    let mut trees: Vec<Map<String, Value>> = Vec::new();
    let mut cur: Map<String, Value> = Map::new();
    for line in out.lines().chain(std::iter::once("")) {
        if line.trim().is_empty() {
            if cur
                .get("worktree")
                .and_then(|v| v.as_str())
                .map_or(false, |s| !s.is_empty())
            {
                trees.push(cur);
            }
            cur = Map::new();
            continue;
        }
        if let Some(rest) = line.strip_prefix("worktree ") {
            let norm = rio::normalize_path(rest.trim());
            cur.insert("worktree".to_string(), Value::String(norm.clone()));
            cur.insert("path".to_string(), Value::String(norm));
        } else if let Some(rest) = line.strip_prefix("HEAD ") {
            cur.insert("head".to_string(), Value::String(rest.trim().to_string()));
        } else if let Some(rest) = line.strip_prefix("branch ") {
            cur.insert("branch".to_string(), Value::String(rest.trim().to_string()));
        } else if line == "detached" {
            cur.insert("detached".to_string(), Value::Bool(true));
        } else if line == "bare" {
            cur.insert("bare".to_string(), Value::Bool(true));
        }
    }
    (0, trees, String::new())
}

pub fn audit_worktrees(cwd: &str) -> Value {
    let eff_cwd = if cwd.trim().is_empty() {
        env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| ".".to_string())
    } else {
        cwd.to_string()
    };
    let Some(root) = rio::git_toplevel(&eff_cwd, false) else {
        return json!({"ok": false, "error": "not_in_git_repo"});
    };

    let (rc, mut trees, err) = list_worktrees(&root);
    if rc != 0 {
        return json!({"ok": false, "error": err.trim()});
    }

    for item in &mut trees {
        let wt_path = item
            .get("worktree")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if Path::new(&wt_path).is_dir() {
            let (rc_s, st_out, _) = rio::run_git(&wt_path, &["status", "--porcelain=v1"], 4.0);
            let dirty_count = if rc_s == 0 {
                st_out
                    .lines()
                    .filter(|ln| !ln.trim().is_empty())
                    .count()
            } else {
                0
            };
            item.insert("dirty".to_string(), Value::Bool(dirty_count > 0));
            item.insert("dirty_count".to_string(), json!(dirty_count));
        } else {
            item.insert("missing_on_disk".to_string(), Value::Bool(true));
        }
    }

    let (rc_wip, wip_out, _) = rio::run_git(
        &root,
        &[
            "for-each-ref",
            "--format=%(refname:short) %(objectname:short)",
            "refs/wip/",
        ],
        4.0,
    );
    let wip_refs: Vec<String> = if rc_wip == 0 {
        wip_out
            .lines()
            .map(|ln| ln.trim().to_string())
            .filter(|ln| !ln.is_empty())
            .collect()
    } else {
        Vec::new()
    };

    let wt_vals: Vec<Value> = trees.into_iter().map(Value::Object).collect();
    json!({
        "ok": true,
        "repo_root": rio::normalize_path(&root),
        "worktree_count": wt_vals.len(),
        "worktrees": wt_vals,
        "wip_snapshots": wip_refs,
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

pub fn run_cli(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln_line("usage: worktree_guard <audit|snapshot|remove|unlink-links> [options]");
        return 2;
    }
    match args[0].as_str() {
        "-h" | "--help" => {
            eprintln_line("usage: worktree_guard <audit|snapshot|remove|unlink-links> [options]");
            0
        }
        "audit" => {
            let mut cwd = String::new();
            let mut i = 1usize;
            while i < args.len() {
                let a = args[i].as_str();
                if a == "--cwd" || a.starts_with("--cwd=") {
                    match take_flag_value(args, &mut i, "--cwd") {
                        Ok(v) => cwd = v,
                        Err(e) => {
                            eprintln_line(&format!("worktree_guard audit: {}", e));
                            return 2;
                        }
                    }
                } else {
                    eprintln_line(&format!("worktree_guard audit: unrecognized argument {}", a));
                    return 2;
                }
                i += 1;
            }
            let res = audit_worktrees(&cwd);
            rio::print_cli_json(&res, true);
            if res.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                0
            } else {
                1
            }
        }
        "snapshot" => {
            let mut worktree = String::new();
            let mut label = "manual".to_string();
            let mut i = 1usize;
            while i < args.len() {
                let a = args[i].as_str();
                if a == "--worktree" || a.starts_with("--worktree=") {
                    match take_flag_value(args, &mut i, "--worktree") {
                        Ok(v) => worktree = v,
                        Err(e) => {
                            eprintln_line(&format!("worktree_guard snapshot: {}", e));
                            return 2;
                        }
                    }
                } else if a == "--label" || a.starts_with("--label=") {
                    match take_flag_value(args, &mut i, "--label") {
                        Ok(v) => label = v,
                        Err(e) => {
                            eprintln_line(&format!("worktree_guard snapshot: {}", e));
                            return 2;
                        }
                    }
                } else {
                    eprintln_line(&format!("worktree_guard snapshot: unrecognized argument {}", a));
                    return 2;
                }
                i += 1;
            }
            let eff_wt = if worktree.trim().is_empty() {
                env::current_dir()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| ".".to_string())
            } else {
                worktree
            };
            let res = snapshot_dirty_worktree(&eff_wt, &label);
            rio::print_cli_json(&res, true);
            if res.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                0
            } else {
                1
            }
        }
        "remove" => {
            let mut worktree = String::new();
            let mut repo = String::new();
            let mut no_snapshot = false;
            let mut i = 1usize;
            while i < args.len() {
                let a = args[i].as_str();
                if a == "--no-snapshot" {
                    no_snapshot = true;
                } else if a == "--worktree" || a.starts_with("--worktree=") {
                    match take_flag_value(args, &mut i, "--worktree") {
                        Ok(v) => worktree = v,
                        Err(e) => {
                            eprintln_line(&format!("worktree_guard remove: {}", e));
                            return 2;
                        }
                    }
                } else if a == "--repo" || a.starts_with("--repo=") {
                    match take_flag_value(args, &mut i, "--repo") {
                        Ok(v) => repo = v,
                        Err(e) => {
                            eprintln_line(&format!("worktree_guard remove: {}", e));
                            return 2;
                        }
                    }
                } else {
                    eprintln_line(&format!("worktree_guard remove: unrecognized argument {}", a));
                    return 2;
                }
                i += 1;
            }
            if worktree.trim().is_empty() {
                eprintln_line("worktree_guard remove: --worktree is required");
                return 2;
            }
            let res = safe_remove_worktree(&worktree, &repo, !no_snapshot);
            rio::print_cli_json(&res, true);
            if res.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                0
            } else {
                1
            }
        }
        "unlink-links" => {
            let mut tree = String::new();
            let mut i = 1usize;
            while i < args.len() {
                let a = args[i].as_str();
                if a == "--tree" || a.starts_with("--tree=") {
                    match take_flag_value(args, &mut i, "--tree") {
                        Ok(v) => tree = v,
                        Err(e) => {
                            eprintln_line(&format!("worktree_guard unlink-links: {}", e));
                            return 2;
                        }
                    }
                } else {
                    eprintln_line(&format!("worktree_guard unlink-links: unrecognized argument {}", a));
                    return 2;
                }
                i += 1;
            }
            if tree.trim().is_empty() {
                eprintln_line("worktree_guard unlink-links: --tree is required");
                return 2;
            }
            let (unlinked, errs) = unlink_directory_links(&tree);
            let ok = errs.is_empty();
            rio::print_cli_json(
                &json!({"ok": ok, "unlinked": unlinked, "errors": errs}),
                true,
            );
            if ok {
                0
            } else {
                1
            }
        }
        other => {
            eprintln_line(&format!("worktree_guard: unknown subcommand '{}'", other));
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQ: AtomicU64 = AtomicU64::new(1);

    fn make_temp_dir(prefix: &str) -> PathBuf {
        let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = env::temp_dir().join(format!("{}-{}-{}", prefix, std::process::id(), seq));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_junction_detection_and_safe_unlink() {
        let base = make_temp_dir("wguard-junc");
        let target = base.join("shared_node_modules");
        let wt_tree = base.join("wt_copy");
        let nested_dir = wt_tree.join("packages").join("app");
        fs::create_dir_all(&target).unwrap();
        fs::create_dir_all(&nested_dir).unwrap();
        let sentinel = target.join("sentinel.txt");
        fs::write(&sentinel, "keep-me").unwrap();

        let link_path = nested_dir.join("node_modules");

        #[cfg(windows)]
        {
            let link_str = link_path.to_string_lossy().into_owned();
            let target_str = target.to_string_lossy().into_owned();
            let cmd_line = vec![
                "/C".to_string(),
                "mklink".to_string(),
                "/J".to_string(),
                link_str,
                target_str,
            ];
            let res = win32_sqlite::run_command_with_job("cmd", &cmd_line, None, &[], None, Some(5000))
                .unwrap();
            assert_eq!(res.code, 0);
        }

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&target, &link_path).unwrap();
        }

        assert!(!is_directory_link(&target));
        assert!(is_directory_link(&link_path));

        let (unlinked, errs) = unlink_directory_links(&wt_tree.to_string_lossy());
        assert!(errs.is_empty(), "unlink errors: {:?}", errs);
        assert_eq!(unlinked.len(), 1);
        assert!(!link_path.exists());
        assert!(sentinel.is_file());
        assert_eq!(fs::read_to_string(&sentinel).unwrap(), "keep-me");

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_snapshot_and_safe_remove_worktree() {
        let base = make_temp_dir("wguard-git");
        let repo = base.join("repo");
        let wt = base.join("wt-worker");
        fs::create_dir_all(&repo).unwrap();
        let repo_s = repo.to_string_lossy().into_owned();
        let wt_s = wt.to_string_lossy().into_owned();

        let (rc_init, _, _) = rio::run_git(&repo_s, &["init"], 5.0);
        if rc_init == 0 {
            let _ = rio::run_git(&repo_s, &["config", "user.email", "t@example.com"], 5.0);
            let _ = rio::run_git(&repo_s, &["config", "user.name", "Test"], 5.0);
            fs::write(repo.join("README.md"), "base\n").unwrap();
            let _ = rio::run_git(&repo_s, &["add", "README.md"], 5.0);
            let _ = rio::run_git(&repo_s, &["commit", "-m", "init"], 5.0);

            let (rc_add, _, _) =
                rio::run_git(&repo_s, &["worktree", "add", "-b", "swarm/w1", &wt_s], 5.0);
            assert_eq!(rc_add, 0);

            fs::write(wt.join("dirty.txt"), "wip\n").unwrap();
            let refused = safe_remove_worktree(&wt_s, &repo_s, false);
            assert_eq!(refused["ok"], json!(false));
            assert_eq!(refused["error"], json!("worktree_dirty_refused"));

            let removed = safe_remove_worktree(&wt_s, &repo_s, true);
            assert_eq!(removed["ok"], json!(true));
            assert!(!wt.exists());

            let audit = audit_worktrees(&repo_s);
            assert_eq!(audit["ok"], json!(true));
            assert!(!audit["wip_snapshots"].as_array().unwrap().is_empty());
        }

        let _ = fs::remove_dir_all(&base);
    }
}
