use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::rio;
use crate::win32_sqlite;

const SNAPSHOT_PROBE_TIMEOUT: f64 = 60.0;
static CONFLICT_IDX_SEQ: AtomicU64 = AtomicU64::new(1);

struct TempDirGuard(PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

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

fn git_out(p: &str, a: &[&str]) -> Result<String, String> {
    let (rc, o, e) = rio::run_git(p, a, SNAPSHOT_PROBE_TIMEOUT);
    if rc == 0 { Ok(o) } else { Err(if e.trim().is_empty() { format!("exit_{}", rc) } else { e.trim().into() }) }
}
fn pending_files(p: &str) -> Result<Vec<String>, String> { Ok(git_out(p, &["status", "--porcelain"])?.lines().filter(|l| !l.trim().is_empty()).map(str::to_string).collect()) }
fn commit_tree_obj(top: &str, tree: &str, parents: &[&str], msg: &str) -> Result<String, String> {
    let mut args: Vec<&str> = vec!["commit-tree", tree];
    for p in parents {
        if !p.trim().is_empty() {
            args.push("-p");
            args.push(p);
        }
    }
    args.push("-m");
    args.push(msg);
    let (rc, out, err) = rio::run_git(top, &args, 15.0);
    let oid = out.trim().to_string();
    if rc != 0 || oid.is_empty() {
        Err(if err.trim().is_empty() {
            "git commit-tree failed".into()
        } else {
            truncate_chars(err.trim(), 160).to_string()
        })
    } else {
        Ok(oid)
    }
}

fn capture_conflicted_index_trees(top: &str) -> Result<(String, String), String> {
    // SAFETY: Build `staged_tree` (verbatim stage-0 staged files) and `conflicts_tree` (pure `stage<N>/<path>` entries) in TWO separate temp index files so synthetic stage prefixes can never overwrite or collide with staged user paths.
    let (rc_ip, raw_ip, err_ip) = rio::run_git(top, &["rev-parse", "--git-path", "index"], 5.0);
    let ip_rel = raw_ip.trim();
    if rc_ip != 0 || ip_rel.is_empty() {
        return Err(format!("rev-parse --git-path index failed: {}", truncate_chars(err_ip.trim(), 120)));
    }
    let ip_p = Path::new(ip_rel);
    let src_idx = if ip_p.is_absolute() { ip_p.to_path_buf() } else { Path::new(top).join(ip_p) };
    if !src_idx.is_file() {
        return Err("conflicted index snapshot failed: real git index file missing".into());
    }
    let dir = env::temp_dir().join(format!(
        "cwg-cidx-{}-{}",
        std::process::id(),
        CONFLICT_IDX_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).map_err(|e| format!("temp index dir failed: {}", e))?;
    let _guard = TempDirGuard(dir.clone());
    let tmp_idx_staged = dir.join("index-staged");
    fs::copy(&src_idx, &tmp_idx_staged).map_err(|e| format!("copy git index failed: {}", e))?;
    let tmp_idx_staged_s = tmp_idx_staged.to_string_lossy().into_owned();
    let ge_staged = [("GIT_INDEX_FILE", tmp_idx_staged_s.as_str())];

    let (rc_u, out_u, err_u) = rio::run_git_raw(top, &["ls-files", "-u", "-z"], 10.0, None, &ge_staged);
    if rc_u != 0 || out_u.is_empty() {
        return Err(format!("ls-files -u -z failed: {}", truncate_chars(err_u.trim(), 120)));
    }
    let mut unmerged_paths = BTreeSet::<Vec<u8>>::new();
    let mut conflict_info_buf = Vec::<u8>::new();
    for rec in out_u.split(|&b| b == 0).filter(|s| !s.is_empty()) {
        let Some(tab) = rec.iter().position(|&b| b == b'\t') else {
            return Err("malformed ls-files -u record".into());
        };
        let meta = std::str::from_utf8(&rec[..tab])
            .map_err(|_| "non-ascii metadata in unmerged index".to_string())?;
        let mut parts = meta.split_whitespace();
        let (Some(mode), Some(oid), Some(stage)) = (parts.next(), parts.next(), parts.next()) else {
            return Err("malformed ls-files -u metadata".into());
        };
        let path_bytes = &rec[tab + 1..];
        unmerged_paths.insert(path_bytes.to_vec());
        conflict_info_buf.extend_from_slice(format!("{} {} 0\tstage{}/", mode, oid, stage).as_bytes());
        conflict_info_buf.extend_from_slice(path_bytes);
        conflict_info_buf.push(0);
    }
    let mut rm_buf = Vec::<u8>::new();
    for p in &unmerged_paths {
        rm_buf.extend_from_slice(p);
        rm_buf.push(0);
    }
    let (rc_rm, _, err_rm) = rio::run_git_raw(
        top,
        &["update-index", "-z", "--force-remove", "--stdin"],
        30.0,
        Some(&rm_buf),
        &ge_staged,
    );
    if rc_rm != 0 {
        return Err(format!("update-index remove unmerged failed: {}", truncate_chars(err_rm.trim(), 120)));
    }
    let (rc_wt_st, out_wt_st, err_wt_st) = rio::run_git_env(top, &["write-tree"], 30.0, &ge_staged);
    let staged_tree = out_wt_st.trim().to_string();
    if rc_wt_st != 0 || staged_tree.is_empty() {
        return Err(format!("staged write-tree failed: {}", truncate_chars(err_wt_st.trim(), 120)));
    }

    let tmp_idx_conflicts = dir.join("index-conflicts");
    let tmp_idx_conflicts_s = tmp_idx_conflicts.to_string_lossy().into_owned();
    let ge_conflicts = [("GIT_INDEX_FILE", tmp_idx_conflicts_s.as_str())];
    let (rc_up, _, err_up) = rio::run_git_raw(
        top,
        &["update-index", "-z", "--index-info"],
        30.0,
        Some(&conflict_info_buf),
        &ge_conflicts,
    );
    if rc_up != 0 {
        return Err(format!("update-index preserve conflict stages failed: {}", truncate_chars(err_up.trim(), 120)));
    }
    let (rc_wt_cf, out_wt_cf, err_wt_cf) = rio::run_git_env(top, &["write-tree"], 30.0, &ge_conflicts);
    let conflicts_tree = out_wt_cf.trim().to_string();
    if rc_wt_cf != 0 || conflicts_tree.is_empty() {
        return Err(format!("conflicts write-tree failed: {}", truncate_chars(err_wt_cf.trim(), 120)));
    }
    Ok((staged_tree, conflicts_tree))
}

fn capture_snapshot_commits(
    top: &str,
    head: Option<&str>,
    msg: &str,
) -> Result<(String, Option<String>, Option<String>), String> {
    // SAFETY: Capture staged index (and conflict stages in a disjoint tree when unmerged) BEFORE working-tree snapshot via isolated/read-only `git write-tree` so neither staged changes nor conflict stages can overwrite each other or be lost to `git add -A`.
    let head_parents: Vec<&str> = head.iter().copied().collect();
    let (rc_u, out_u, err_u) = rio::run_git(top, &["ls-files", "-u"], 10.0);
    if rc_u != 0 {
        return Err(format!("git ls-files failed: {}", truncate_chars(err_u.trim(), 120)));
    }
    let mut idx_tree = String::new();
    let mut idx_commit: Option<String> = None;
    let mut conflicts_commit: Option<String> = None;
    if out_u.trim().is_empty() {
        let (rc_wt, out_wt, err_wt) = rio::run_git(top, &["write-tree"], 30.0);
        if rc_wt == 0 {
            let candidate_idx_tree = out_wt.trim().to_string();
            let staged_differs = if let Some(h) = head {
                let ht_ref = format!("{}^{{tree}}", h);
                let (rc_ht, out_ht, _) = rio::run_git(top, &["rev-parse", "--verify", "-q", &ht_ref], 5.0);
                rc_ht == 0 && !candidate_idx_tree.is_empty() && candidate_idx_tree != out_ht.trim()
            } else {
                let (rc_ls, out_ls, _) = rio::run_git(top, &["ls-files", "--cached", "-z"], 10.0);
                rc_ls == 0 && !out_ls.is_empty() && !candidate_idx_tree.is_empty()
            };
            if staged_differs {
                idx_tree = candidate_idx_tree;
                let idx_msg = format!("staged index before {}", msg);
                idx_commit = Some(commit_tree_obj(top, &idx_tree, &head_parents, &idx_msg)?);
            }
        } else {
            return Err(format!(
                "git write-tree failed: {}",
                truncate_chars(err_wt.trim(), 120)
            ));
        }
    } else {
        let (staged_tree, conflicts_tree) = capture_conflicted_index_trees(top)?;
        idx_tree = staged_tree;
        let idx_msg = format!("staged index before {}", msg);
        let cf_msg = format!("conflict stages before {}", msg);
        idx_commit = Some(commit_tree_obj(top, &idx_tree, &head_parents, &idx_msg)?);
        conflicts_commit = Some(commit_tree_obj(top, &conflicts_tree, &head_parents, &cf_msg)?);
    }

    let wt_tree = rio::capture_worktree_tree_oid(top, SNAPSHOT_PROBE_TIMEOUT);
    if wt_tree.is_empty() {
        return Err("capture_worktree_tree_oid_failed".into());
    }
    if let (Some(ref sc), Some(ref cc)) = (&idx_commit, &conflicts_commit) {
        // SAFETY: Always create `wt_commit` with both `sc` and `cc` as parents so BOTH disjoint snapshots stay reachable from the snapshot branch/ref even if `wt_tree == idx_tree`.
        let wt_commit = commit_tree_obj(top, &wt_tree, &[sc.as_str(), cc.as_str()], msg)?;
        return Ok((wt_commit, idx_commit, conflicts_commit));
    }
    if let Some(ref ic) = idx_commit {
        if wt_tree == idx_tree {
            return Ok((ic.clone(), idx_commit, None));
        }
        let wt_commit = commit_tree_obj(top, &wt_tree, &[ic.as_str()], msg)?;
        return Ok((wt_commit, idx_commit, None));
    }
    let wt_commit = commit_tree_obj(top, &wt_tree, &head_parents, msg)?;
    Ok((wt_commit, None, None))
}

pub fn snapshot_for_removal(p: &str, name: Option<&str>, br: Option<&str>) -> Option<Value> {
    if p.trim().is_empty() || !Path::new(p).is_dir() || git_out(p, &["rev-parse", "--git-dir"]).is_err() { return None; }
    let err = |m: String| Some(json!({"error": m}));
    let Ok(pend) = pending_files(p) else { return err("git status did not answer, so a clean tree cannot be told from a busy one".into()); };
    let ne = |r: Result<String, String>| r.ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let cur = ne(git_out(p, &["rev-parse", "--abbrev-ref", "HEAD"])).filter(|s| s != "HEAD").or_else(|| br.map(str::trim).filter(|b| !b.is_empty()).map(str::to_string));
    let pcnt = |s: &str| { let t = s.trim(); (!t.is_empty() && t.bytes().all(|b| b.is_ascii_digit())).then(|| t.parse::<usize>().ok()).flatten() };
    let ahead_res = git_out(p, &["rev-list", "--count", "@{upstream}..HEAD"]).and_then(|u| pcnt(&u).ok_or(u)).or_else(|_| {
        git_out(p, &["for-each-ref", "--format=%(refname)", "refs/heads", "refs/remotes"]).and_then(|refs| {
            let own = cur.as_deref().map(str::trim).filter(|b| !b.is_empty()).map(|b| format!("refs/heads/{}", b));
            let mut a = vec!["rev-list", "--count", "HEAD", "--not"];
            a.extend(refs.lines().map(str::trim).filter(|r| !r.is_empty() && own.as_deref() != Some(*r)));
            git_out(p, &a).and_then(|o| pcnt(&o).ok_or(o))
        })
    });
    let ahead = match ahead_res { Ok(n) => n, Err(_) if pend.is_empty() => return err("git could not say whether this branch holds commits nothing else reaches".into()), Err(_) => 0 };
    if pend.is_empty() && ahead == 0 { return None; }
    let stamp = win32_sqlite::format_iso_utc(win32_sqlite::now_sec()).get(..10).map_or_else(|| "19700101".into(), |s| s.replace('-', ""));
    let bn = name.map(str::trim).filter(|s| !s.is_empty()).or_else(|| Path::new(p.trim_end_matches(['/', '\\'])).file_name().and_then(|s| s.to_str())).unwrap_or("worktree");
    let lr: String = bn.chars().map(|c| if c.is_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '-' }).collect();
    let lbl = truncate_chars(&lr, 60);
    let base = format!("wip/{}-{}", lbl, stamp);
    let Some(target) = (0..50).filter(|&i| i != 1).map(|i| if i == 0 { base.clone() } else { format!("{}-{}", base, i) }).find(|c| rio::run_git(p, &["rev-parse", "--verify", "--quiet", c], 5.0).0 != 0) else { return err(format!("no free wip/ branch name for {}", lbl)); };
    let head = ne(git_out(p, &["rev-parse", "HEAD"]));
    if head.is_none() && pend.is_empty() { return None; }
    let (mode, files, commit, staged_commit, conflicts_commit) = if pend.is_empty() {
        ("ref", 0, head.unwrap_or_default(), None, None)
    } else {
        let msg = format!("snapshot: unfinished work from worktree {}", lbl);
        let (wt_c, st_c, cf_c) = match capture_snapshot_commits(p, head.as_deref(), &msg) {
            Ok(triple) => triple,
            Err(m) => return err(m),
        };
        ("commit", pend.len(), wt_c, st_c, cf_c)
    };
    if rio::run_git(p, &["branch", &target, &commit], 10.0).0 != 0 { return err(format!("could not create branch {}", target)); }
    let mut out = json!({"branch": target, "mode": mode, "files": files, "ahead": ahead, "head": commit});
    if let Some(sc) = staged_commit {
        out["staged_commit"] = Value::String(sc);
    }
    if let Some(cc) = conflicts_commit {
        out["conflicts_commit"] = Value::String(cc);
    }
    Some(out)
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
    let head_opt = (!parent_sha.is_empty()).then_some(parent_sha.as_str());
    let now = win32_sqlite::now_sec();
    let commit_msg = format!(
        "WIP snapshot ({}) at {}",
        label,
        win32_sqlite::format_iso_utc(now)
    );
    let (commit_sha, staged_commit, conflicts_commit) = match capture_snapshot_commits(&top, head_opt, &commit_msg) {
        Ok(triple) => triple,
        Err(err_s) => {
            return json!({
                "ok": false,
                "error": format!("git_commit_tree_failed:{}", truncate_chars(&err_s, 160)),
            });
        }
    };

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

    let mut out = json!({
        "ok": true,
        "clean": false,
        "ref": ref_name,
        "commit": commit_sha,
        "worktree": rio::normalize_path(&top),
    });
    if let Some(sc) = staged_commit {
        out["staged_commit"] = Value::String(sc);
    }
    if let Some(cc) = conflicts_commit {
        out["conflicts_commit"] = Value::String(cc);
    }
    out
}

pub fn safe_remove_worktree(worktree_dir: &str, repo_dir: &str, snapshot_dirty: bool) -> Value {
    let wt_path = abs_clean_path(worktree_dir);
    let wt = wt_path.to_string_lossy().into_owned();
    let wt_norm = rio::normalize_path(&wt);
    if !wt_path.exists() {
        return json!({"ok": true, "already_absent": true, "worktree": wt_norm});
    }

    let pending = match pending_files(&wt) {
        Ok(v) => v,
        Err(err_s) => {
            return json!({
                "ok": false,
                "error": format!("git_status_failed:{}", truncate_chars(&err_s, 160)),
                "worktree": wt_norm,
            });
        }
    };
    let is_dirty = !pending.is_empty();

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
    } else if snapshot_dirty {
        if let Some(res) = snapshot_for_removal(&wt, None, None) {
            if let Some(err_s) = res.get("error").and_then(|v| v.as_str()) {
                return json!({
                    "ok": false,
                    "error": format!("clean_ahead_snapshot_failed:{}", err_s),
                    "worktree": wt_norm,
                });
            }
            snap_info = Some(res);
        }
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
            "refs/heads/wip/",
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
        eprintln_line(
            "usage: worktree_guard <audit|snapshot|remove|unlink-links> [options]",
        );
        return 2;
    }
    match args[0].as_str() {
        "-h" | "--help" => {
            eprintln_line(
                "usage: worktree_guard <audit|snapshot|remove|unlink-links> [options]",
            );
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

    #[test]
    fn test_snapshot_for_removal_dirty_clean_ahead_conflicted_and_fails_closed() {
        let base = make_temp_dir("wguard-snap");

        let repo = base.join("repo");
        let wt_dirty = base.join("wt-dirty");
        let wt_clean = base.join("wt-clean-ahead");
        fs::create_dir_all(&repo).unwrap();
        let repo_s = repo.to_string_lossy().into_owned();
        if rio::run_git(&repo_s, &["init"], 5.0).0 == 0 {
            let _ = rio::run_git(&repo_s, &["config", "user.email", "t@example.com"], 5.0);
            let _ = rio::run_git(&repo_s, &["config", "user.name", "Test"], 5.0);
            fs::write(repo.join("base.txt"), "base\n").unwrap();
            let _ = rio::run_git(&repo_s, &["add", "base.txt"], 5.0);
            let _ = rio::run_git(&repo_s, &["commit", "-m", "init"], 5.0);

            // 1. Dirty worktree -> mode: "commit" on wip/<label>-<YYYYMMDD>, real index untouched.
            let wt_dirty_s = wt_dirty.to_string_lossy().into_owned();
            assert_eq!(
                rio::run_git(
                    &repo_s,
                    &["worktree", "add", "-b", "feat/dirty", &wt_dirty_s],
                    5.0
                )
                .0,
                0
            );
            fs::write(wt_dirty.join("untracked.txt"), "rescue me\n").unwrap();
            let snap_dirty =
                snapshot_for_removal(&wt_dirty_s, Some("feat-dirty"), Some("feat/dirty"))
                    .expect("dirty worktree must produce a commit snapshot");
            assert_eq!(snap_dirty["mode"], json!("commit"));
            assert_eq!(snap_dirty["files"], json!(1));
            let dirty_br = snap_dirty["branch"].as_str().unwrap();
            assert!(dirty_br.starts_with("wip/feat-dirty-"), "{}", snap_dirty);
            let dirty_head = snap_dirty["head"].as_str().unwrap();
            assert_eq!(
                rio::run_git(&repo_s, &["show", &format!("{}:untracked.txt", dirty_head)], 5.0).1,
                "rescue me\n"
            );
            let (rc_b1, branches1, _) =
                rio::run_git(&repo_s, &["branch", "--list", "wip/feat-dirty-*"], 5.0);
            assert_eq!(rc_b1, 0);
            assert!(!branches1.trim().is_empty());
            // Real worktree index must remain untouched (untracked.txt not staged into real index).
            let (_, diff_cached, _) = rio::run_git(&wt_dirty_s, &["diff", "--cached", "--name-only"], 5.0);
            assert!(diff_cached.trim().is_empty());

            // 2. Clean worktree with unreachable local commit -> mode: "ref"
            let wt_clean_s = wt_clean.to_string_lossy().into_owned();
            assert_eq!(
                rio::run_git(
                    &repo_s,
                    &["worktree", "add", "-b", "feat/ahead", &wt_clean_s],
                    5.0
                )
                .0,
                0
            );
            let _ = rio::run_git(&wt_clean_s, &["config", "user.email", "t@example.com"], 5.0);
            let _ = rio::run_git(&wt_clean_s, &["config", "user.name", "Test"], 5.0);
            fs::write(wt_clean.join("committed.txt"), "ahead\n").unwrap();
            let _ = rio::run_git(&wt_clean_s, &["add", "committed.txt"], 5.0);
            let _ = rio::run_git(&wt_clean_s, &["commit", "-m", "ahead commit"], 5.0);
            let snap_clean =
                snapshot_for_removal(&wt_clean_s, Some("feat-ahead"), Some("feat/ahead"))
                    .expect("clean-ahead worktree must produce a ref snapshot");
            assert_eq!(snap_clean["mode"], json!("ref"));
            assert_eq!(snap_clean["files"], json!(0));
            assert!(snap_clean["ahead"].as_u64().unwrap_or(0) >= 1);
            let clean_br = snap_clean["branch"].as_str().unwrap();
            assert!(clean_br.starts_with("wip/feat-ahead-"), "{}", snap_clean);
            let (_, branches2, _) =
                rio::run_git(&repo_s, &["branch", "--list", "wip/feat-ahead-*"], 5.0);
            assert!(!branches2.trim().is_empty());

            // 2b. Staged index (V2) + worktree reverted to HEAD (V1) preserves BOTH V1 and V2 in both snapshot_for_removal and safe_remove_worktree!
            let wt_staged_hook = base.join("wt-staged-hook");
            let wt_staged_hook_s = wt_staged_hook.to_string_lossy().into_owned();
            assert_eq!(
                rio::run_git(&repo_s, &["worktree", "add", "-b", "feat/staged-hook", &wt_staged_hook_s], 5.0).0,
                0
            );
            fs::write(wt_staged_hook.join("base.txt"), "staged-v2\n").unwrap();
            assert_eq!(rio::run_git(&wt_staged_hook_s, &["add", "base.txt"], 5.0).0, 0);
            fs::write(wt_staged_hook.join("base.txt"), "base\n").unwrap();
            let snap_hook = snapshot_for_removal(&wt_staged_hook_s, Some("staged-hook"), Some("feat/staged-hook")).unwrap();
            let tip_hook = snap_hook["head"].as_str().unwrap().to_string();
            let st_hook = snap_hook["staged_commit"].as_str().unwrap().to_string();
            assert_ne!(tip_hook, st_hook);
            assert_eq!(rio::run_git(&repo_s, &["show", &format!("{}:base.txt", tip_hook)], 5.0).1, "base\n");
            assert_eq!(rio::run_git(&repo_s, &["show", &format!("{}:base.txt", st_hook)], 5.0).1, "staged-v2\n");

            let wt_staged_rm = base.join("wt-staged-rm");
            let wt_staged_rm_s = wt_staged_rm.to_string_lossy().into_owned();
            assert_eq!(
                rio::run_git(&repo_s, &["worktree", "add", "-b", "feat/staged-rm", &wt_staged_rm_s], 5.0).0,
                0
            );
            fs::write(wt_staged_rm.join("base.txt"), "staged-rm-v2\n").unwrap();
            assert_eq!(rio::run_git(&wt_staged_rm_s, &["add", "base.txt"], 5.0).0, 0);
            fs::write(wt_staged_rm.join("base.txt"), "base\n").unwrap();
            let rm_res = safe_remove_worktree(&wt_staged_rm_s, &repo_s, true);
            assert_eq!(rm_res["ok"], json!(true), "{}", rm_res);
            assert!(!wt_staged_rm.exists());
            let tip_rm = rm_res["snapshot"]["commit"].as_str().unwrap().to_string();
            let st_rm = rm_res["snapshot"]["staged_commit"].as_str().unwrap().to_string();
            assert_eq!(rio::run_git(&repo_s, &["show", &format!("{}:base.txt", tip_rm)], 5.0).1, "base\n");
            assert_eq!(rio::run_git(&repo_s, &["show", &format!("{}:base.txt", st_rm)], 5.0).1, "staged-rm-v2\n");

            // 2c. Clean detached-HEAD worktree with unreachable local commit is snapshotted before safe_remove_worktree deletes it.
            let wt_detached = base.join("wt-detached-ahead");
            let wt_detached_s = wt_detached.to_string_lossy().into_owned();
            assert_eq!(
                rio::run_git(&repo_s, &["worktree", "add", "--detach", &wt_detached_s, "HEAD"], 5.0).0,
                0
            );
            let _ = rio::run_git(&wt_detached_s, &["config", "user.email", "t@example.com"], 5.0);
            let _ = rio::run_git(&wt_detached_s, &["config", "user.name", "Test"], 5.0);
            fs::write(wt_detached.join("detached.txt"), "keep-commit\n").unwrap();
            assert_eq!(rio::run_git(&wt_detached_s, &["add", "detached.txt"], 5.0).0, 0);
            assert_eq!(rio::run_git(&wt_detached_s, &["commit", "-m", "detached ahead"], 5.0).0, 0);
            let detached_oid = rio::git_head_oid(&wt_detached_s);
            let rm_det = safe_remove_worktree(&wt_detached_s, &repo_s, true);
            assert_eq!(rm_det["ok"], json!(true), "{}", rm_det);
            assert!(!wt_detached.exists());
            assert_eq!(rm_det["snapshot"]["mode"], json!("ref"));
            assert_eq!(rm_det["snapshot"]["head"], json!(detached_oid));
            let snap_br = rm_det["snapshot"]["branch"].as_str().unwrap();
            assert_eq!(rio::run_git(&repo_s, &["show", &format!("{}:detached.txt", snap_br)], 5.0).1, "keep-commit\n");

            // 2d. Conflicted index (a.rs unmerged) + staged user files at b.rs, .cwg-unmerged/stage2/a.rs, and stage2/a.rs + reverted worktree preserves ALL staged, worktree, and conflict trees without collision!
            assert_eq!(rio::run_git(&repo_s, &["branch", "conflict-src"], 5.0).0, 0);
            fs::write(repo.join("a.rs"), "ours-conflict\n").unwrap();
            fs::write(repo.join("b.rs"), "base-b\n").unwrap();
            assert_eq!(rio::run_git(&repo_s, &["add", "a.rs", "b.rs"], 5.0).0, 0);
            assert_eq!(rio::run_git(&repo_s, &["commit", "-m", "main conflict side"], 5.0).0, 0);
            let conflict_target_oid = rio::git_head_oid(&repo_s);
            assert!(!conflict_target_oid.is_empty());

            let wt_conf = base.join("wt-conflict-staged");
            let wt_conf_s = wt_conf.to_string_lossy().into_owned();
            assert_eq!(
                rio::run_git(&repo_s, &["worktree", "add", &wt_conf_s, "conflict-src"], 5.0).0,
                0
            );
            let _ = rio::run_git(&wt_conf_s, &["config", "user.email", "t@example.com"], 5.0);
            let _ = rio::run_git(&wt_conf_s, &["config", "user.name", "Test"], 5.0);
            fs::write(wt_conf.join("a.rs"), "theirs-conflict\n").unwrap();
            fs::write(wt_conf.join("b.rs"), "base-b\n").unwrap();
            assert_eq!(rio::run_git(&wt_conf_s, &["add", "a.rs", "b.rs"], 5.0).0, 0);
            assert_eq!(rio::run_git(&wt_conf_s, &["commit", "-m", "branch conflict side"], 5.0).0, 0);
            let (rc_merge, _, _) = rio::run_git(&wt_conf_s, &["merge", &conflict_target_oid], 5.0);
            assert_ne!(rc_merge, 0, "expected real merge conflict");
            assert!(!rio::run_git(&wt_conf_s, &["ls-files", "-u"], 5.0).1.trim().is_empty());

            fs::create_dir_all(wt_conf.join(".cwg-unmerged").join("stage2")).unwrap();
            fs::create_dir_all(wt_conf.join("stage2")).unwrap();
            fs::write(wt_conf.join(".cwg-unmerged").join("stage2").join("a.rs"), "user-staged-cwg\n").unwrap();
            fs::write(wt_conf.join("stage2").join("a.rs"), "user-staged-s2\n").unwrap();
            fs::write(wt_conf.join("b.rs"), "staged-b-v2\n").unwrap();
            assert_eq!(
                rio::run_git(&wt_conf_s, &["add", "b.rs", ".cwg-unmerged/stage2/a.rs", "stage2/a.rs"], 5.0).0,
                0
            );
            fs::write(wt_conf.join(".cwg-unmerged").join("stage2").join("a.rs"), "user-wt-cwg\n").unwrap();
            fs::write(wt_conf.join("stage2").join("a.rs"), "user-wt-s2\n").unwrap();
            fs::write(wt_conf.join("b.rs"), "base-b\n").unwrap();

            let rm_conf = safe_remove_worktree(&wt_conf_s, &repo_s, true);
            assert_eq!(rm_conf["ok"], json!(true), "{}", rm_conf);
            assert!(!wt_conf.exists());
            let tip_c = rm_conf["snapshot"]["commit"].as_str().unwrap().to_string();
            let st_c = rm_conf["snapshot"]["staged_commit"].as_str().unwrap().to_string();
            let cf_c = rm_conf["snapshot"]["conflicts_commit"].as_str().unwrap().to_string();
            assert_eq!(rio::run_git(&repo_s, &["show", &format!("{}:b.rs", st_c)], 5.0).1, "staged-b-v2\n");
            assert_eq!(rio::run_git(&repo_s, &["show", &format!("{}:.cwg-unmerged/stage2/a.rs", st_c)], 5.0).1, "user-staged-cwg\n");
            assert_eq!(rio::run_git(&repo_s, &["show", &format!("{}:stage2/a.rs", st_c)], 5.0).1, "user-staged-s2\n");
            assert_eq!(rio::run_git(&repo_s, &["show", &format!("{}:b.rs", tip_c)], 5.0).1, "base-b\n");
            assert_eq!(rio::run_git(&repo_s, &["show", &format!("{}:.cwg-unmerged/stage2/a.rs", tip_c)], 5.0).1, "user-wt-cwg\n");
            assert_eq!(rio::run_git(&repo_s, &["show", &format!("{}:stage2/a.rs", tip_c)], 5.0).1, "user-wt-s2\n");
            assert_eq!(rio::run_git(&repo_s, &["show", &format!("{}:stage2/a.rs", cf_c)], 5.0).1, "theirs-conflict\n");
            assert_eq!(rio::run_git(&repo_s, &["show", &format!("{}:stage3/a.rs", cf_c)], 5.0).1, "ours-conflict\n");
            assert_eq!(rio::run_git(&repo_s, &["merge-base", "--is-ancestor", &st_c, &tip_c], 5.0).0, 0);
            assert_eq!(rio::run_git(&repo_s, &["merge-base", "--is-ancestor", &cf_c, &tip_c], 5.0).0, 0);
        }

        // 3. Non-repo path returns None from snapshot_for_removal and fails closed with git_status_failed in safe_remove_worktree.
        let not_repo = base.join("not-a-repo");
        fs::create_dir_all(&not_repo).unwrap();
        assert!(snapshot_for_removal(&not_repo.to_string_lossy(), None, None).is_none());
        let failed = safe_remove_worktree(&not_repo.to_string_lossy(), "", false);
        assert_eq!(failed["ok"], json!(false));
        assert!(failed["error"].as_str().unwrap().starts_with("git_status_failed:"));

        let _ = fs::remove_dir_all(&base);
    }
}
