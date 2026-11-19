use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
#[cfg(test)]
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::cwg_common;
use crate::rio;
use crate::stack_doctor;
use crate::win32_sqlite;

const PLUGIN_NAME: &str = "gemini-carbon-stack";
const RETIRED_BINS_DIR_NAME: &str = ".retired_bins";
const SKIP_NAMES: &[&str] = &["__pycache__", ".DS_Store", RETIRED_BINS_DIR_NAME];
const ROLLBACK_V2_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

fn sha256_file_full(path: &Path) -> Result<String, String> {
    match cwg_common::sha256_file_bounded(path, u64::MAX) {
        Ok(Some((_, hex))) => Ok(hex),
        Ok(None) => Err(format!("file exceeded bounds: {}", path.display())),
        Err(e) => Err(format!("{}: {}", path.display(), e)),
    }
}

fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn has_dot_components(path: &Path) -> bool {
    path.components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
}

fn tree_manifest_inner(
    root: &Path,
    strict: bool,
    compute_hash: bool,
) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    if !root.is_dir() {
        if strict {
            return Err(format!("Directory does not exist: {}", root.display()));
        }
        return Ok(out);
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = match fs::read_dir(&dir) {
            Ok(r) => r,
            Err(e) if strict => return Err(format!("{}: {}", dir.display(), e)),
            Err(_) => continue,
        };
        let mut subdirs = Vec::new();
        let mut files = Vec::new();
        for entry_res in rd {
            let entry = match entry_res {
                Ok(ent) => ent,
                Err(e) if strict => return Err(format!("{}: {}", dir.display(), e)),
                Err(_) => continue,
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            if SKIP_NAMES.contains(&name.as_str())
                || name.ends_with(".pyc")
                || name.ends_with(".pyo")
            {
                continue;
            }
            let p = entry.path();
            if win32_sqlite::is_link_or_junction(&p) {
                if strict {
                    return Err(format!("Symlink/junction inside snapshot: {}", p.display()));
                }
                continue;
            }
            if p.is_dir() {
                subdirs.push(p);
            } else if p.is_file() {
                files.push((name, p));
            } else if strict {
                return Err(format!("Unsupported non-regular entry: {}", p.display()));
            }
        }
        subdirs.sort();
        for sd in subdirs.into_iter().rev() {
            stack.push(sd);
        }
        files.sort_by(|a, b| a.0.cmp(&b.0));
        for (_, fpath) in files {
            let rel = fpath.strip_prefix(root).map_err(|e| e.to_string())?;
            let rel_posix = rel.to_string_lossy().replace('\\', "/");
            if !compute_hash {
                out.insert(rel_posix, String::new());
                continue;
            }
            match sha256_file_full(&fpath) {
                Ok(hash) => {
                    out.insert(rel_posix, hash);
                }
                Err(e) if strict => return Err(e),
                Err(_) => {}
            }
        }
    }
    Ok(out)
}

fn tree_rel_paths(root: &Path) -> BTreeSet<String> {
    tree_manifest_inner(root, false, false)
        .unwrap_or_default()
        .into_keys()
        .collect()
}

pub fn tree_manifest(root: &Path) -> BTreeMap<String, String> {
    tree_manifest_inner(root, false, true).unwrap_or_default()
}

pub fn tree_manifest_strict(root: &Path) -> Result<BTreeMap<String, String>, String> {
    tree_manifest_inner(root, true, true)
}

pub fn resolve_repo_root(explicit_repo: &str) -> PathBuf {
    if !explicit_repo.trim().is_empty() {
        return rio::resolve_abs_path(Path::new(explicit_repo.trim()));
    }
    let has_repo_layout = |dir: &Path| -> bool {
        dir.join("plugin").join("plugin.json").is_file()
            && dir.join("rules").join("uiux-design.md").is_file()
    };
    if let Ok(cwd) = env::current_dir() {
        for anc in cwd.ancestors() {
            if has_repo_layout(anc) {
                return rio::resolve_abs_path(anc);
            }
        }
    }
    if let Ok(exe) = env::current_exe() {
        for anc in exe.ancestors() {
            if has_repo_layout(anc) {
                return rio::resolve_abs_path(anc);
            }
        }
    }
    if let Some(manifest_dir) = option_env!("CARGO_MANIFEST_DIR") {
        if let Some(repo) = Path::new(manifest_dir).parent() {
            if has_repo_layout(repo) {
                return rio::resolve_abs_path(repo);
            }
        }
    }
    rio::resolve_abs_path(Path::new("."))
}

pub fn resolve_paths(config_dir_arg: &str, stack_home_arg: &str) -> (PathBuf, PathBuf) {
    let cfg = if !config_dir_arg.trim().is_empty() {
        rio::resolve_abs_path(Path::new(config_dir_arg.trim()))
    } else {
        rio::home_dir().join(".gemini").join("config")
    };
    let shome = if !stack_home_arg.trim().is_empty() {
        rio::resolve_abs_path(Path::new(stack_home_arg.trim()))
    } else if let Ok(env_sh) = env::var("CARBON_STACK_HOME") {
        if !env_sh.trim().is_empty() {
            rio::resolve_abs_path(Path::new(env_sh.trim()))
        } else {
            rio::home_dir().join(".gemini").join("carbon-stack")
        }
    } else {
        rio::home_dir().join(".gemini").join("carbon-stack")
    };
    (cfg, shome)
}

pub fn platform_hook_binary_rel(is_windows: bool) -> &'static str {
    if is_windows {
        "bin/carbon-stack.exe"
    } else {
        "bin/carbon-stack"
    }
}

pub fn normalize_hooks_json_for_os(txt: &str, is_windows: bool) -> String {
    if is_windows {
        txt.replace("bin/carbon-stack hook", "bin\\carbon-stack.exe hook")
    } else {
        txt.replace("bin\\\\carbon-stack.exe", "bin/carbon-stack")
            .replace("bin/carbon-stack.exe", "bin/carbon-stack")
    }
}

pub fn effective_source_manifest_strict(
    src_plugin_dir: &Path,
    is_windows: bool,
) -> Result<BTreeMap<String, String>, String> {
    let mut map = tree_manifest_strict(src_plugin_dir)?;
    if !is_windows {
        if map.contains_key("bin/carbon-stack") {
            map.remove("bin/carbon-stack.exe");
        }
        let hooks_file = src_plugin_dir.join("hooks.json");
        if map.contains_key("hooks.json") {
            let raw = fs::read_to_string(&hooks_file)
                .map_err(|e| format!("{}: {}", hooks_file.display(), e))?;
            let norm = normalize_hooks_json_for_os(&raw, false);
            map.insert("hooks.json".to_string(), rio::sha256_hex(norm.as_bytes()));
        }
    }
    Ok(map)
}

pub fn effective_source_manifest(src_plugin_dir: &Path, is_windows: bool) -> BTreeMap<String, String> {
    effective_source_manifest_strict(src_plugin_dir, is_windows).unwrap_or_default()
}

fn collect_links_under_tree(root: &Path, out: &mut Vec<PathBuf>) {
    if win32_sqlite::is_link_or_junction(root) {
        out.push(root.to_path_buf());
        return;
    }
    if !root.is_dir() {
        return;
    }
    let Ok(rd) = fs::read_dir(root) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if win32_sqlite::is_link_or_junction(&p) {
            out.push(p);
        } else if p.is_dir() {
            collect_links_under_tree(&p, out);
        }
    }
}

fn ensure_no_links_between(base: &Path, target: &Path) -> Result<(), String> {
    // INVARIANT: Reject `.` / `..` traversal components, equal-root targets, and any symlink/junction between `base` and `target`.
    if has_dot_components(base) || has_dot_components(target) {
        return Err(format!(
            "Refusing relative dot/parent traversal in path: {} -> {}",
            base.display(),
            target.display()
        ));
    }
    if win32_sqlite::is_link_or_junction(base) {
        return Err(format!(
            "Refusing to traverse symlink/junction root: {}",
            base.display()
        ));
    }
    let Ok(rel) = target.strip_prefix(base) else {
        return Err(format!(
            "Target {} escapes base {}",
            target.display(),
            base.display()
        ));
    };
    let mut cur = base.to_path_buf();
    let mut depth = 0usize;
    for comp in rel.components() {
        let Component::Normal(_) = comp else {
            return Err(format!(
                "Refusing non-normal path component under {}: {}",
                base.display(),
                target.display()
            ));
        };
        depth += 1;
        cur.push(comp);
        if win32_sqlite::is_link_or_junction(&cur) {
            return Err(format!(
                "Refusing to traverse nested symlink/junction component: {}",
                cur.display()
            ));
        }
    }
    if depth == 0 {
        return Err(format!(
            "Target {} must be a strict child path inside {}",
            target.display(),
            base.display()
        ));
    }
    Ok(())
}

fn validate_target_hierarchy(
    config_dir: &Path,
    p_target: &Path,
    r_target: &Path,
) -> Vec<String> {
    // INVARIANT: Verify `config_dir`, every intermediate parent (`plugins`, `rules`), `hooks.json`, and nested plugin entries contain zero symlinks/junctions and never escape `config_dir`.
    let mut errs = Vec::new();
    if let Err(e) = ensure_no_links_between(config_dir, p_target) {
        errs.push(e);
    }
    if let Err(e) = ensure_no_links_between(config_dir, r_target) {
        errs.push(e);
    }
    let h_target = config_dir.join("hooks.json");
    if let Err(e) = ensure_no_links_between(config_dir, &h_target) {
        errs.push(e);
    }
    let mut nested = Vec::new();
    if p_target.exists() || win32_sqlite::is_link_or_junction(p_target) {
        collect_links_under_tree(p_target, &mut nested);
    }
    for lnk in nested {
        errs.push(format!(
            "Refusing to traverse nested symlink/junction: {}",
            lnk.display()
        ));
    }
    errs
}

fn validate_target_entry_types(
    config_dir: &Path,
    p_target: &Path,
    r_target: &Path,
    src_plugin_dir: Option<&Path>,
    is_windows: bool,
) -> Vec<String> {
    // INVARIANT: Pre-validate destination entry types (`config_dir`, `plugins`, `p_target`, nested bundle paths, `rules`, `r_target`, `hooks.json`) BEFORE creating backups or mutating targets so malformed paths never delete regular files or leave partial updates.
    let mut errs = Vec::new();
    if let Ok(m) = fs::symlink_metadata(config_dir) {
        if !m.file_type().is_dir() {
            errs.push(format!(
                "Target config root is not a directory: {}",
                config_dir.display()
            ));
            return errs;
        }
    }
    let h_target = config_dir.join("hooks.json");
    if let Ok(m) = fs::symlink_metadata(&h_target) {
        if !m.file_type().is_file() {
            errs.push(format!(
                "Target global hooks.json path is not a regular file: {}",
                h_target.display()
            ));
        }
    }
    if let Some(p_parent) = p_target.parent() {
        if let Ok(m) = fs::symlink_metadata(p_parent) {
            if !m.file_type().is_dir() {
                errs.push(format!(
                    "Target plugins parent path is not a directory: {}",
                    p_parent.display()
                ));
            }
        }
    }
    if let Ok(m) = fs::symlink_metadata(p_target) {
        if !m.file_type().is_dir() {
            errs.push(format!(
                "Target plugin path is not a directory: {}",
                p_target.display()
            ));
        }
    }
    if let Some(r_parent) = r_target.parent() {
        if let Ok(m) = fs::symlink_metadata(r_parent) {
            if !m.file_type().is_dir() {
                errs.push(format!(
                    "Target rules parent path is not a directory: {}",
                    r_parent.display()
                ));
            }
        }
    }
    if let Ok(m) = fs::symlink_metadata(r_target) {
        if !m.file_type().is_file() {
            errs.push(format!(
                "Target rule path is not a regular file: {}",
                r_target.display()
            ));
        }
    }
    if let Some(src_dir) = src_plugin_dir {
        if p_target.is_dir() {
            for rel in effective_source_manifest(src_dir, is_windows).keys() {
                let dst_leaf = p_target.join(rel);
                if let Some(rel_parent) = Path::new(rel).parent() {
                    let mut cur = p_target.to_path_buf();
                    for comp in rel_parent.components() {
                        cur.push(comp);
                        if let Ok(m) = fs::symlink_metadata(&cur) {
                            if !m.file_type().is_dir() {
                                errs.push(format!(
                                    "Target plugin subdirectory path is not a directory: {}",
                                    cur.display()
                                ));
                                break;
                            }
                        }
                    }
                }
                if let Ok(m) = fs::symlink_metadata(&dst_leaf) {
                    if !m.file_type().is_file() {
                        errs.push(format!(
                            "Target plugin file path is not a regular file: {}",
                            dst_leaf.display()
                        ));
                    }
                }
            }
        }
    }
    errs
}

pub(crate) fn has_mz_header(path: &Path) -> bool {
    let Ok(mut f) = fs::File::open(path) else {
        return false;
    };
    let mut buf = [0u8; 2];
    f.read_exact(&mut buf).map(|()| &buf == b"MZ").unwrap_or(false)
}

pub(crate) fn run_agy_plugin_validate(
    agy_bin: &str,
    plugin_dir: &Path,
    timeout_ms: u64,
) -> (bool, String) {
    let args = vec![
        "plugin".to_string(),
        "validate".to_string(),
        plugin_dir.to_string_lossy().into_owned(),
    ];
    match win32_sqlite::run_command_with_job(agy_bin, &args, None, &[], None, Some(timeout_ms)) {
        Ok(res) if res.timed_out => (
            false,
            format!(
                "`agy plugin validate` timed out after {:.1}s",
                (timeout_ms as f64) / 1000.0
            ),
        ),
        Ok(res) => {
            let combined = format!("{}\n{}", res.stdout_str(), res.stderr_str())
                .trim()
                .to_string();
            (res.code == 0, combined)
        }
        Err(e) => (
            false,
            format!("failed to launch `agy plugin validate`: {}", e),
        ),
    }
}

pub fn preflight_check_for_os_mode(
    repo_root: &Path,
    config_dir: &Path,
    is_windows: bool,
    allow_unbuilt_hook_bin: bool,
) -> Value {
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    let source_plugin_dir = repo_root.join("plugin");
    let source_glob_rule = repo_root.join("rules").join("uiux-design.md");
    let hook_bin_rel = platform_hook_binary_rel(is_windows);
    let hook_bin_path = source_plugin_dir.join(hook_bin_rel);
    let mut bootstrap_build_required = false;
    let required = [
        source_plugin_dir.join("plugin.json"),
        source_plugin_dir.join("hooks.json"),
        source_plugin_dir.join("rules").join("AGENTS.md"),
        source_glob_rule.clone(),
    ];
    for req in &required {
        if !req.is_file() {
            errors.push(format!("Missing required source file: {}", req.display()));
        } else if req.extension().and_then(|s| s.to_str()) == Some("json") {
            match fs::read_to_string(req) {
                Ok(txt) => {
                    if let Err(e) = serde_json::from_str::<Value>(&txt) {
                        errors.push(format!("Invalid JSON in {}: {}", req.display(), e));
                    }
                }
                Err(e) => errors.push(format!("Cannot read {}: {}", req.display(), e)),
            }
        }
    }
    if !hook_bin_path.is_file()
        || fs::metadata(&hook_bin_path)
            .map(|m| m.len() == 0)
            .unwrap_or(true)
    {
        if allow_unbuilt_hook_bin && repo_root.join("rust").join("Cargo.toml").is_file() {
            bootstrap_build_required = true;
            warnings.push(format!(
                "Native hook binary {} is not built in source tree yet; install will build via `cargo build --release`.",
                hook_bin_path.display()
            ));
        } else {
            errors.push(format!(
                "Missing or empty required hook binary: {}",
                hook_bin_path.display()
            ));
        }
    } else if !is_windows && has_mz_header(&hook_bin_path) {
        errors.push(format!(
            "Hook binary {} is a Windows PE executable on a non-Windows target",
            hook_bin_path.display()
        ));
    }
    if is_windows == cfg!(windows) {
        if let Err(e) = win32_sqlite::probe_sqlite_runtime() {
            errors.push(format!("SQLite runtime unavailable: {}", e));
        }
    }

    let target_plugin_dir = config_dir.join("plugins").join(PLUGIN_NAME);
    let target_glob_rule = config_dir.join("rules").join("uiux-design.md");
    errors.extend(validate_target_hierarchy(
        config_dir,
        &target_plugin_dir,
        &target_glob_rule,
    ));
    errors.extend(validate_target_entry_types(
        config_dir,
        &target_plugin_dir,
        &target_glob_rule,
        Some(&source_plugin_dir),
        is_windows,
    ));
    let mut src_links = Vec::new();
    collect_links_under_tree(&source_plugin_dir, &mut src_links);
    for lnk in src_links {
        errors.push(format!(
            "Refusing to traverse nested symlink/junction: {}",
            lnk.display()
        ));
    }
    if let Err(e) = inspect_global_hooks_migration(config_dir, &target_plugin_dir, is_windows) {
        errors.push(e);
    }

    let user_cfg_json = config_dir.join("config.json");
    let agy_bin = rio::find_agy_cli();
    let mut agy_validation = json!({ "ran": false, "ok": true, "output": "" });
    if let Some(ref bin) = agy_bin {
        if errors.is_empty() {
            let (ok, combined) = run_agy_plugin_validate(bin, &source_plugin_dir, 12_000);
            agy_validation = json!({ "ran": true, "ok": ok, "output": combined });
            if !ok {
                errors.push(format!("`agy plugin validate` failed: {}", combined));
            }
        }
    } else {
        warnings.push("`agy` CLI binary not found on PATH; skipped `agy plugin validate`.".to_string());
    }

    json!({
        "ok": errors.is_empty(),
        "errors": errors,
        "warnings": warnings,
        "bootstrap_build_required": bootstrap_build_required,
        "config_dir": config_dir.to_string_lossy(),
        "user_config_json_untouched": user_cfg_json.exists(),
        "agy_cli": agy_bin,
        "agy_validation": agy_validation,
    })
}

#[cfg(test)]
pub fn preflight_check_for_os(repo_root: &Path, config_dir: &Path, is_windows: bool) -> Value {
    preflight_check_for_os_mode(repo_root, config_dir, is_windows, false)
}

fn is_windows_pe_path(p: &Path) -> bool {
    matches!(
        p.extension()
            .and_then(|s| s.to_str())
            .map(|s| s.to_ascii_lowercase())
            .as_deref(),
        Some("exe" | "dll")
    )
}

fn prepare_retired_slot(retired_dir: &Path, dst_file: &Path) -> Result<PathBuf, String> {
    // INVARIANT: Refuse symlinks/junctions on `retired_dir` (and its parent) BEFORE creating or sweeping `retired-*` entries so a planted `.retired_bins` junction can never delete files outside `state` or `config_dir`.
    if has_dot_components(retired_dir) || win32_sqlite::is_link_or_junction(retired_dir) {
        return Err(format!(
            "Refusing symlink/junction retired directory: {}",
            retired_dir.display()
        ));
    }
    if let Some(parent) = retired_dir.parent() {
        if win32_sqlite::is_link_or_junction(parent) {
            return Err(format!(
                "Refusing symlink/junction parent of retired directory: {}",
                parent.display()
            ));
        }
    }
    if let Ok(meta) = fs::symlink_metadata(retired_dir) {
        if !meta.file_type().is_dir() {
            return Err(format!(
                "Refusing non-directory retired path: {}",
                retired_dir.display()
            ));
        }
    } else {
        fs::create_dir_all(retired_dir).map_err(|e| e.to_string())?;
    }
    if win32_sqlite::is_link_or_junction(retired_dir) {
        return Err(format!(
            "Refusing symlink/junction retired directory after create: {}",
            retired_dir.display()
        ));
    }
    for rel in tree_rel_paths(retired_dir) {
        if rel.starts_with("retired-") && !rel.contains('/') {
            let ep = retired_dir.join(&rel);
            if !win32_sqlite::is_link_or_junction(&ep) {
                let _ = fs::remove_file(&ep);
            }
        }
    }
    static RETIRE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let seq = RETIRE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let fname = dst_file
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("bin.exe");
    Ok(retired_dir.join(format!("retired-{}-{}-{}-{}", std::process::id(), ms, seq, fname)))
}

fn retire_locked_windows_pe(dst_file: &Path, tmp: &Path) -> Result<bool, String> {
    // WORKAROUND: Windows NTFS forbids overwriting a mapped `.exe`/`.dll` in place, but permits renaming the live image within the same volume (`.retired_bins`).
    if !cfg!(windows) || !dst_file.exists() || !is_windows_pe_path(dst_file) {
        return Ok(false);
    }
    let Some(parent) = dst_file.parent() else {
        return Ok(false);
    };
    let retired_dir = parent.join(RETIRED_BINS_DIR_NAME);
    let retired = prepare_retired_slot(&retired_dir, dst_file)?;
    fs::rename(dst_file, &retired).map_err(|e| e.to_string())?;
    if let Err(e) = fs::rename(tmp, dst_file) {
        let _ = fs::rename(&retired, dst_file);
        return Err(e.to_string());
    }
    let _ = fs::remove_file(&retired);
    let _ = fs::remove_dir(&retired_dir);
    Ok(true)
}

fn remove_file_or_retire_pe(target_file: &Path, external_retired_dirs: &[&Path]) -> Result<(), String> {
    match fs::remove_file(target_file) {
        Ok(()) => Ok(()),
        Err(e) => {
            // WORKAROUND: When rolling back to a Python-only or pre-install snapshot on Windows while `bin/carbon-stack.exe` is mapped in memory, `DeleteFileW` fails; rename the mapped PE out of `p_target` into `state/.retired_bins` or same-volume `config_dir/.retired_bins` (both outside `p_target`) so `remove_dir_all(p_target)` succeeds even when `stack_home` and `config_dir` are on different volumes.
            if !cfg!(windows) || !is_windows_pe_path(target_file) || !target_file.exists() {
                return Err(e.to_string());
            }
            for ext_dir in external_retired_dirs {
                if let Ok(slot) = prepare_retired_slot(ext_dir, target_file) {
                    if fs::rename(target_file, &slot).is_ok() {
                        let _ = fs::remove_file(&slot);
                        return Ok(());
                    }
                }
            }
            if let Some(parent) = target_file.parent() {
                let fallback_dir = parent.join(RETIRED_BINS_DIR_NAME);
                if let Ok(slot) = prepare_retired_slot(&fallback_dir, target_file) {
                    if fs::rename(target_file, &slot).is_ok() {
                        let _ = fs::remove_file(&slot);
                        return Ok(());
                    }
                }
            }
            Err(e.to_string())
        }
    }
}

fn remove_tree_or_retire_pe(target_dir: &Path, external_retired_dirs: &[&Path]) -> std::io::Result<()> {
    match fs::remove_dir_all(target_dir) {
        Ok(()) => Ok(()),
        Err(e) if cfg!(windows) => {
            for rel in tree_rel_paths(target_dir) {
                let p = target_dir.join(&rel);
                if is_windows_pe_path(&p) {
                    let _ = remove_file_or_retire_pe(&p, external_retired_dirs);
                }
            }
            if !target_dir.exists() {
                return Ok(());
            }
            match fs::remove_dir_all(target_dir) {
                Ok(()) => Ok(()),
                Err(_) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

fn next_exclusive_tmp_path(dst_file: &Path) -> PathBuf {
    static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let fname = dst_file
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    dst_file.with_file_name(format!(".{}.agy-tmp-{}-{}-{}", fname, std::process::id(), nanos, seq))
}

fn atomic_copy_file(src_file: &Path, dst_file: &Path) -> Result<(), String> {
    if let Some(parent) = dst_file.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = next_exclusive_tmp_path(dst_file);
    let copy_res = (|| -> Result<(), String> {
        let mut src_fh = fs::File::open(src_file).map_err(|e| e.to_string())?;
        let src_perms = src_fh.metadata().map_err(|e| e.to_string())?.permissions();
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut tmp_fh = opts.open(&tmp).map_err(|e| e.to_string())?;
        std::io::copy(&mut src_fh, &mut tmp_fh).map_err(|e| e.to_string())?;
        drop(tmp_fh);
        drop(src_fh);
        // INVARIANT: Transfer exact `src_file` permissions onto `tmp` BEFORE `rename` so private user snapshots (e.g. `0600` rules under `umask 022`) never widen permissions on rollback.
        fs::set_permissions(&tmp, src_perms.clone()).map_err(|e| e.to_string())?;
        for attempt in 0..4 {
            match fs::rename(&tmp, dst_file) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if attempt == 3 {
                        if retire_locked_windows_pe(dst_file, &tmp)? {
                            return Ok(());
                        }
                        if win32_sqlite::is_link_or_junction(dst_file) {
                            return Err(format!("Refusing symlink/junction target: {}", dst_file.display()));
                        }
                        fs::copy(src_file, dst_file).map_err(|e2| format!("{}; {}", e, e2))?;
                        let _ = fs::set_permissions(dst_file, src_perms);
                        return Ok(());
                    }
                    thread::sleep(Duration::from_millis(50 * (attempt + 1)));
                }
            }
        }
        Ok(())
    })();
    if tmp.exists() {
        let _ = fs::remove_file(&tmp);
    }
    copy_res
}

fn atomic_write_bytes_with_default_perms(
    dst_file: &Path,
    bytes: &[u8],
    fallback_perms: Option<fs::Permissions>,
) -> Result<(), String> {
    // INVARIANT: Refuse symlink/junction targets, open `tmp` with private `0600` mode on Unix, and transfer `dst_file` permissions (or `fallback_perms` on creation) onto `tmp` BEFORE `rename` so migrating `<config_dir>/hooks.json` never widens private user permissions under `umask 022`.
    if win32_sqlite::is_link_or_junction(dst_file) {
        return Err(format!(
            "Refusing symlink/junction target: {}",
            dst_file.display()
        ));
    }
    let existing_perms = match fs::symlink_metadata(dst_file) {
        Ok(m) if m.file_type().is_file() => Some(m.permissions()),
        Ok(_) => {
            return Err(format!(
                "Refusing to overwrite non-regular file target: {}",
                dst_file.display()
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.to_string()),
    };
    let desired_perms = existing_perms.or(fallback_perms);
    if let Some(parent) = dst_file.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = next_exclusive_tmp_path(dst_file);
    let write_res = (|| -> Result<(), String> {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut tmp_fh = opts.open(&tmp).map_err(|e| e.to_string())?;
        tmp_fh.write_all(bytes).map_err(|e| e.to_string())?;
        drop(tmp_fh);
        #[cfg(unix)]
        if let Some(ref perms) = desired_perms {
            fs::set_permissions(&tmp, perms.clone()).map_err(|e| e.to_string())?;
        }
        for attempt in 0..4 {
            match fs::rename(&tmp, dst_file) {
                Ok(()) => {
                    #[cfg(not(unix))]
                    if let Some(perms) = desired_perms {
                        let _ = fs::set_permissions(dst_file, perms);
                    }
                    return Ok(());
                }
                Err(e) => {
                    if attempt == 3 {
                        if win32_sqlite::is_link_or_junction(dst_file) {
                            return Err(format!(
                                "Refusing symlink/junction target: {}",
                                dst_file.display()
                            ));
                        }
                        fs::write(dst_file, bytes).map_err(|e2| format!("{}; {}", e, e2))?;
                        if let Some(perms) = desired_perms {
                            fs::set_permissions(dst_file, perms).map_err(|e2| e2.to_string())?;
                        }
                        return Ok(());
                    }
                    thread::sleep(Duration::from_millis(50 * (attempt + 1)));
                }
            }
        }
        Ok(())
    })();
    if tmp.exists() {
        let _ = fs::remove_file(&tmp);
    }
    write_res
}

fn collect_dirs_postorder(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(root) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if !win32_sqlite::is_link_or_junction(&p) && p.is_dir() {
            collect_dirs_postorder(&p, out);
            out.push(p);
        }
    }
}

pub fn copy_clean_tree_for_os(src: &Path, dst: &Path, is_windows: bool) -> Result<(), String> {
    copy_clean_tree_with_retire(src, dst, is_windows, &[])
}

fn copy_clean_tree_additive(src: &Path, dst: &Path, is_windows: bool) -> Result<(), String> {
    // INVARIANT: Copy/update incoming files without deleting pre-existing files yet so legacy hook handlers (`hooks/tokenade_hook.py`) remain runnable on disk until `<config_dir>/hooks.json` is atomically switched to `bin/carbon-stack`.
    let mut existing_links = Vec::new();
    collect_links_under_tree(src, &mut existing_links);
    if dst.exists() || win32_sqlite::is_link_or_junction(dst) {
        collect_links_under_tree(dst, &mut existing_links);
    }
    if let Some(first_lnk) = existing_links.first() {
        return Err(format!(
            "Refusing to synchronize tree containing symlink/junction: {}",
            first_lnk.display()
        ));
    }

    if let Ok(meta) = fs::symlink_metadata(dst) {
        if !meta.file_type().is_dir() {
            return Err(format!(
                "Refusing to overwrite non-directory destination with tree: {}",
                dst.display()
            ));
        }
    }
    fs::create_dir_all(dst).map_err(|e| e.to_string())?;

    let src_map = effective_source_manifest_strict(src, is_windows)?;
    let dst_map = tree_manifest(dst);
    for (rel, src_hash) in &src_map {
        let dst_path = dst.join(rel);
        ensure_no_links_between(dst, &dst_path)?;
        if dst_map.get(rel) != Some(src_hash) {
            if !is_windows && rel == "hooks.json" {
                let src_file = src.join(rel);
                let raw = fs::read_to_string(&src_file).map_err(|e| e.to_string())?;
                let norm = normalize_hooks_json_for_os(&raw, false);
                let src_perms = fs::metadata(&src_file).ok().map(|m| m.permissions());
                atomic_write_bytes_with_default_perms(&dst_path, norm.as_bytes(), src_perms)?;
            } else {
                atomic_copy_file(&src.join(rel), &dst_path)?;
            }
        }
        #[cfg(unix)]
        if rel == "bin/carbon-stack" {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(&dst_path).map_err(|e| e.to_string())?;
            let cur_mode = meta.permissions().mode();
            let fixed_mode = ensure_owner_exec_mode_bits(cur_mode);
            if fixed_mode != cur_mode {
                let mut perms = meta.permissions();
                perms.set_mode(fixed_mode);
                fs::set_permissions(&dst_path, perms).map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}

fn prune_stale_subdirs(src: &Path, dst: &Path) {
    let mut subdirs = Vec::new();
    collect_dirs_postorder(dst, &mut subdirs);
    for cur in subdirs {
        let cname = cur
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if cname == RETIRED_BINS_DIR_NAME {
            let _ = fs::remove_dir(&cur);
            continue;
        }
        let Ok(rel_dir) = cur.strip_prefix(dst) else {
            continue;
        };
        if SKIP_NAMES.contains(&cname) || !src.join(rel_dir).is_dir() {
            let _ = fs::remove_dir_all(&cur);
        }
    }
}

fn compute_stale_rel_paths(
    src_tree: Option<&Path>,
    dst_tree: &Path,
    is_windows_manifest: bool,
    case_fold: bool,
) -> Result<Vec<String>, String> {
    let dst_rels = tree_rel_paths(dst_tree);
    let Some(src) = src_tree else {
        return Ok(dst_rels.into_iter().collect());
    };
    let src_map = effective_source_manifest_strict(src, is_windows_manifest)?;
    let src_keys: BTreeSet<String> = src_map
        .keys()
        .map(|k| {
            if case_fold {
                norm_instance_path(k, true)
            } else {
                k.clone()
            }
        })
        .collect();
    Ok(dst_rels
        .into_iter()
        .filter(|rel| {
            let key = if case_fold {
                norm_instance_path(rel, true)
            } else {
                rel.clone()
            };
            !src_keys.contains(&key)
        })
        .collect())
}

fn prune_stale_tree_entries(
    src: &Path,
    dst: &Path,
    is_windows: bool,
    external_retired_dirs: &[&Path],
) -> Result<(), String> {
    let case_fold = is_windows || cfg!(windows) || path_fs_is_case_insensitive(dst);
    let stale_rels = compute_stale_rel_paths(Some(src), dst, is_windows, case_fold)?;
    for rel in &stale_rels {
        let stale = dst.join(rel);
        ensure_no_links_between(dst, &stale)?;
        if stale.exists() {
            remove_file_or_retire_pe(&stale, external_retired_dirs)?;
        }
    }
    prune_stale_subdirs(src, dst);
    Ok(())
}

fn copy_clean_tree_with_retire(
    src: &Path,
    dst: &Path,
    is_windows: bool,
    external_retired_dirs: &[&Path],
) -> Result<(), String> {
    copy_clean_tree_additive(src, dst, is_windows)?;
    prune_stale_tree_entries(src, dst, is_windows, external_retired_dirs)
}

pub fn copy_clean_tree(src: &Path, dst: &Path) -> Result<(), String> {
    copy_clean_tree_for_os(src, dst, cfg!(windows))
}

fn utc_backup_stamp_and_iso() -> (String, String) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let micros = now.subsec_micros();
    let iso = win32_sqlite::format_iso_utc(secs as f64);
    let compact: String = iso
        .chars()
        .filter(|c: &char| c.is_ascii_digit())
        .take(14)
        .collect();
    let stamp = if compact.len() == 14 {
        format!("{}-{}-{:06}", &compact[..8], &compact[8..14], micros)
    } else {
        format!("{}-{:06}", secs, micros)
    };
    let truncated: String = stamp.chars().take(20).collect();
    (truncated, iso)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GlobalHookMigration {
    pub pointer: String,
    pub before: String,
    pub after: String,
    pub context_sha256: String,
    pub peer_set_sha256: String,
    pub has_ambiguous_peer: bool,
}

pub(crate) struct GlobalHooksPlan {
    pub rendered_json: String,
    pub migrations: Vec<GlobalHookMigration>,
}

pub fn create_backup(config_dir: &Path, stack_home: &Path) -> Result<Value, String> {
    let target_plugin_dir = config_dir.join("plugins").join(PLUGIN_NAME);
    let target_glob_rule = config_dir.join("rules").join("uiux-design.md");
    let link_errs = validate_target_hierarchy(config_dir, &target_plugin_dir, &target_glob_rule);
    if let Some(first_err) = link_errs.first() {
        return Err(first_err.clone());
    }
    let type_errs = validate_target_entry_types(
        config_dir,
        &target_plugin_dir,
        &target_glob_rule,
        None,
        cfg!(windows),
    );
    if let Some(first_err) = type_errs.first() {
        return Err(first_err.clone());
    }
    // INVARIANT: Enforce `validate_backups_root_strict` BEFORE creating snapshot directories or mutating the installed plugin so `--rollback` can always read any backup produced by `create_backup`.
    let backups_root = match validate_backups_root_strict(stack_home)? {
        Some(b) => b,
        None => {
            let b = stack_home.join("backups");
            fs::create_dir_all(&b).map_err(|e| e.to_string())?;
            validate_backups_root_strict(stack_home)?
                .ok_or_else(|| format!("Failed to initialize backups directory {}", b.display()))?
        }
    };
    let (stamp, iso) = utc_backup_stamp_and_iso();
    let mut backup_id = format!("install-{}", stamp);
    let mut bdir = backups_root.join(&backup_id);
    let mut suffix = 1usize;
    while bdir.exists() {
        backup_id = format!("install-{}-{}", stamp, suffix);
        bdir = backups_root.join(&backup_id);
        suffix += 1;
    }
    fs::create_dir_all(&bdir).map_err(|e| e.to_string())?;

    let target_global_hooks = config_dir.join("hooks.json");
    let plugin_existed = target_plugin_dir.is_dir();
    let rule_existed = target_glob_rule.is_file();

    let mut plugin_target = json!({
        "path": target_plugin_dir.to_string_lossy(),
        "existed": plugin_existed,
    });
    if plugin_existed {
        let p_backup = bdir.join("plugin_dir");
        copy_clean_tree_for_os(&target_plugin_dir, &p_backup, true)?;
        let src_hashes = tree_manifest_strict(&target_plugin_dir)?;
        let bak_hashes = tree_manifest_strict(&p_backup)?;
        if bak_hashes != src_hashes {
            return Err("Backup plugin snapshot verification failed".to_string());
        }
        if let Some(obj) = plugin_target.as_object_mut() {
            obj.insert("files_sha256".to_string(), json!(bak_hashes));
        }
    }

    let mut was_foreign = false;
    let mut rule_sha_opt: Option<String> = None;
    if rule_existed {
        let rules_bdir = bdir.join("rules");
        fs::create_dir_all(&rules_bdir).map_err(|e| e.to_string())?;
        let r_backup = rules_bdir.join("uiux-design.md");
        fs::copy(&target_glob_rule, &r_backup).map_err(|e| e.to_string())?;
        let src_sha = sha256_file_full(&target_glob_rule)?;
        let bak_sha = sha256_file_full(&r_backup)?;
        if bak_sha != src_sha {
            return Err("Backup rule snapshot verification failed".to_string());
        }
        rule_sha_opt = Some(bak_sha);
        if let Ok(txt) = fs::read_to_string(&target_glob_rule) {
            if !txt.contains("Frontend UI/UX & Live Browser Verification Rules") {
                was_foreign = true;
            }
        }
    }

    let mut rule_target = json!({
        "path": target_glob_rule.to_string_lossy(),
        "existed": rule_existed,
    });
    if let Some(obj) = rule_target.as_object_mut() {
        if let Some(r_sha) = rule_sha_opt {
            obj.insert("sha256".to_string(), Value::String(r_sha));
        }
        if was_foreign {
            obj.insert("was_foreign_user_file".to_string(), Value::Bool(true));
        }
    }

    // INVARIANT: Initialize `global_hooks.migrations` empty at backup creation time; surgical command-pointer undo records (`pointer`, `before`, `after`, `context_sha256`, `post_install_sha256`) are persisted via write-ahead undo logging immediately BEFORE `cas_update_hooks_file` replaces `<config_dir>/hooks.json`.
    let hooks_target = json!({
        "path": target_global_hooks.to_string_lossy(),
        "migrations": [],
    });

    let manifest = json!({
        "backup_id": backup_id,
        "created_utc": iso,
        "config_dir": config_dir.to_string_lossy(),
        "targets": {
            "plugin_dir": plugin_target,
            "glob_rule": rule_target,
            "global_hooks": hooks_target,
        },
    });
    rio::write_json(&bdir.join("manifest.json"), &manifest)?;
    Ok(manifest)
}

#[cfg(any(unix, test))]
pub(crate) fn mode_is_owner_executable(mode: u32) -> bool {
    (mode & 0o100) != 0
}

#[cfg(any(unix, test))]
pub(crate) fn ensure_owner_exec_mode_bits(mode: u32) -> u32 {
    // INVARIANT: Guarantee owner execute (`0o100`) and mirror existing group/other read bits (`0o044 >> 2`) to execute without widening access to groups/others that lack read permission (`0o650 -> 0o750`, `0o600 -> 0o700`, `0o644 -> 0o755`).
    mode | 0o100 | ((mode & 0o044) >> 2)
}

#[cfg(any(unix, test))]
pub(crate) fn posix_dac_mode_allows_exec(
    mode: u32,
    file_uid: u32,
    file_gid: u32,
    caller_euid: u32,
    caller_groups: &[u32],
) -> bool {
    // INVARIANT: Require owner execute (`0o100`) unconditionally so `0o650` is never treated as executable for its owner, and evaluate exact POSIX DAC class precedence (`owner` -> `group` -> `other`) when `caller_euid != file_uid`.
    if !mode_is_owner_executable(mode) {
        return false;
    }
    if caller_euid == 0 || caller_euid == file_uid {
        return true;
    }
    if caller_groups.contains(&file_gid) {
        return (mode & 0o010) != 0;
    }
    (mode & 0o001) != 0
}

#[cfg(unix)]
fn current_unix_euid_and_groups() -> (u32, Vec<u32>) {
    extern "C" {
        fn geteuid() -> u32;
        fn getegid() -> u32;
        fn getgroups(size: std::os::raw::c_int, list: *mut u32) -> std::os::raw::c_int;
    }
    // SAFETY: `geteuid()` and `getegid()` are thread-safe POSIX syscalls taking no pointer arguments.
    let (euid, egid) = unsafe { (geteuid(), getegid()) };
    let mut groups = vec![egid];
    // SAFETY: Passing `(0, null_mut())` queries the supplementary group count without writing memory.
    let count = unsafe { getgroups(0, std::ptr::null_mut()) };
    if count > 0 {
        let mut sup = vec![0u32; count as usize];
        // SAFETY: `sup` is allocated with `count` elements matching the capacity passed to `getgroups`.
        let got = unsafe { getgroups(count, sup.as_mut_ptr()) };
        if got > 0 {
            sup.truncate(got as usize);
            for g in sup {
                if !groups.contains(&g) {
                    groups.push(g);
                }
            }
        }
    }
    (euid, groups)
}

pub(crate) fn is_posix_executable_file(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let Ok(m) = fs::metadata(path) else {
            return false;
        };
        if !m.is_file() {
            return false;
        }
        let (euid, groups) = current_unix_euid_and_groups();
        posix_dac_mode_allows_exec(m.permissions().mode(), m.uid(), m.gid(), euid, &groups)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

fn has_executable_hook_mode_for_os(plugin_dir: &Path, is_windows: bool) -> bool {
    if is_windows {
        return true;
    }
    is_posix_executable_file(&plugin_dir.join("bin").join("carbon-stack"))
}

fn desired_tokenade_hook_command(target_plugin_dir: &Path, is_windows: bool) -> String {
    let raw_bin = target_plugin_dir
        .join(platform_hook_binary_rel(is_windows))
        .to_string_lossy()
        .into_owned();
    let bin_full = if is_windows {
        raw_bin.replace('/', "\\")
    } else {
        raw_bin.replace('\\', "/")
    };
    if bin_full.contains(' ') {
        format!("\"{}\" tokenade-hook --event PreToolUse", bin_full)
    } else {
        format!("{} tokenade-hook --event PreToolUse", bin_full)
    }
}

fn legacy_python_tokenade_hook_command(target_plugin_dir: &Path, is_windows: bool) -> String {
    let raw_py = target_plugin_dir
        .join("hooks")
        .join("tokenade_hook.py")
        .to_string_lossy()
        .into_owned();
    let py_full = if is_windows {
        raw_py.replace('/', "\\")
    } else {
        raw_py.replace('\\', "/")
    };
    if py_full.contains(' ') {
        format!("python \"{}\"", py_full)
    } else {
        format!("python {}", py_full)
    }
}

fn split_simple_hook_tokens(cmd: &str) -> Option<Vec<String>> {
    // INVARIANT: Tokenize simple single-command hook invocations while rejecting compound shell metacharacters (`;`, `&`, `|`, `>`, `<`, backticks, `$()`, newlines) or unclosed quotes so user shell pipelines are never clobbered.
    let trimmed = cmd.trim();
    if trimmed.is_empty()
        || trimmed.contains('\n')
        || trimmed.contains('\r')
        || trimmed.contains('\0')
        || trimmed.contains('`')
        || trimmed.contains("$(")
    {
        return None;
    }
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut has_token = false;
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = trimmed.chars().peekable();
    while let Some(ch) = chars.next() {
        if in_single {
            if ch == '\'' {
                in_single = false;
            } else {
                cur.push(ch);
            }
        } else if in_double {
            if ch == '"' {
                in_double = false;
            } else if ch == '\\' && chars.peek() == Some(&'"') {
                let _ = chars.next();
                cur.push('"');
            } else {
                cur.push(ch);
            }
        } else if ch.is_whitespace() {
            if has_token {
                out.push(std::mem::take(&mut cur));
                has_token = false;
            }
        } else if matches!(ch, ';' | '&' | '|' | '>' | '<') {
            return None;
        } else if ch == '\'' {
            in_single = true;
            has_token = true;
        } else if ch == '"' {
            in_double = true;
            has_token = true;
        } else {
            cur.push(ch);
            has_token = true;
        }
    }
    if in_single || in_double {
        return None;
    }
    if has_token {
        out.push(cur);
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

#[derive(Copy, Clone)]
pub(crate) struct HookInstanceScope<'a> {
    pub config_dir: &'a Path,
    pub target_plugin_dir: &'a Path,
    pub is_windows: bool,
}

#[cfg(unix)]
fn path_fs_is_case_insensitive(probe: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    for anc in probe.ancestors() {
        let Some(parent) = anc.parent() else {
            continue;
        };
        let Some(name) = anc.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let mut toggled = String::with_capacity(name.len());
        let mut flipped = false;
        for ch in name.chars() {
            if !flipped && ch.is_ascii_alphabetic() {
                toggled.push(if ch.is_ascii_lowercase() {
                    ch.to_ascii_uppercase()
                } else {
                    ch.to_ascii_lowercase()
                });
                flipped = true;
            } else {
                toggled.push(ch);
            }
        }
        if !flipped {
            continue;
        }
        let Ok(m1) = fs::symlink_metadata(anc) else {
            continue;
        };
        if m1.file_type().is_symlink() {
            continue;
        }
        return fs::symlink_metadata(parent.join(toggled)).is_ok_and(|m2| {
            !m2.file_type().is_symlink() && m1.dev() == m2.dev() && m1.ino() == m2.ino()
        });
    }
    false
}

#[cfg(not(unix))]
fn path_fs_is_case_insensitive(_probe: &Path) -> bool {
    true
}

fn scope_case_fold(scope: HookInstanceScope<'_>) -> bool {
    scope.is_windows
        || cfg!(windows)
        || path_fs_is_case_insensitive(scope.target_plugin_dir)
        || path_fs_is_case_insensitive(scope.config_dir)
}

fn norm_instance_path(tok: &str, is_windows: bool) -> String {
    let case_fold = is_windows || cfg!(windows);
    let mut out = String::with_capacity(tok.len());
    let mut prev_slash = false;
    for ch in tok.chars() {
        if ch == '\\' || ch == '/' {
            if !prev_slash {
                out.push('/');
            }
            prev_slash = true;
        } else if case_fold {
            for lc in ch.to_lowercase() {
                out.push(lc);
            }
            prev_slash = false;
        } else {
            out.push(ch);
            prev_slash = false;
        }
    }
    while out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    out
}

fn expand_home_in_cmd_path(raw_tok: &str) -> String {
    // INVARIANT: Use UTF-8 boundary-safe `str::get(..14)` (never raw `&str[..14]` indexing) so non-ASCII Cyrillic/UTF-8 paths like `/профиль/plugins/...` never panic.
    if matches!(raw_tok, "~" | "$HOME" | "${HOME}")
        || raw_tok.eq_ignore_ascii_case("%userprofile%")
    {
        return rio::home_dir().to_string_lossy().into_owned();
    }
    if let Some(rest) = raw_tok
        .strip_prefix("~/")
        .or_else(|| raw_tok.strip_prefix("~\\"))
        .or_else(|| raw_tok.strip_prefix("$HOME/"))
        .or_else(|| raw_tok.strip_prefix("${HOME}/"))
    {
        return format!("{}/{}", rio::home_dir().to_string_lossy(), rest);
    }
    if let (Some(head), Some(tail)) = (raw_tok.get(..14), raw_tok.get(14..)) {
        if head.eq_ignore_ascii_case("%userprofile%/")
            || head.eq_ignore_ascii_case("%userprofile%\\")
        {
            return format!("{}/{}", rio::home_dir().to_string_lossy(), tail);
        }
    }
    raw_tok.to_string()
}

fn matches_target_plugin_subpath(
    raw_tok: &str,
    scope: HookInstanceScope<'_>,
    rel_subpath: &str,
) -> bool {
    // INVARIANT: Bind command path matching strictly to `scope.target_plugin_dir` (expanding `~`/`$HOME`/`%USERPROFILE%` or resolving unanchored relative paths against `scope.config_dir`) so hooks referencing another profile's Carbon Stack installation are never redirected.
    let expanded = expand_home_in_cmd_path(raw_tok);
    let trimmed = expanded
        .strip_prefix("./")
        .or_else(|| expanded.strip_prefix(".\\"))
        .unwrap_or(&expanded);
    if trimmed.is_empty() || has_dot_components(Path::new(trimmed)) {
        return false;
    }
    let has_drive = trimmed.as_bytes().get(1) == Some(&b':')
        && trimmed.as_bytes()[0].is_ascii_alphabetic();
    let is_anchored = has_drive
        || trimmed.starts_with('/')
        || trimmed.starts_with('\\')
        || trimmed.starts_with('~')
        || trimmed.starts_with('$')
        || trimmed.starts_with('%');
    let candidate = if is_anchored {
        PathBuf::from(trimmed)
    } else {
        scope.config_dir.join(trimmed)
    };
    let expected = scope.target_plugin_dir.join(rel_subpath);
    norm_instance_path(&candidate.to_string_lossy(), scope.is_windows)
        == norm_instance_path(&expected.to_string_lossy(), scope.is_windows)
}

fn is_managed_native_carbon_tokenade_command(
    tokens: &[String],
    scope: HookInstanceScope<'_>,
) -> bool {
    if tokens.len() < 2 {
        return false;
    }
    let bin_ok = matches_target_plugin_subpath(&tokens[0], scope, "bin/carbon-stack")
        || matches_target_plugin_subpath(&tokens[0], scope, "bin/carbon-stack.exe");
    if !bin_ok {
        return false;
    }
    match &tokens[1..] {
        [sub] => sub == "tokenade-hook",
        [sub, flag_eq] => sub == "tokenade-hook" && flag_eq == "--event=PreToolUse",
        [sub, flag, ev] => sub == "tokenade-hook" && flag == "--event" && ev == "PreToolUse",
        _ => false,
    }
}

fn is_python_exec_span(ns: &str) -> bool {
    let base = ns.rsplit('/').next().unwrap_or(ns);
    matches!(
        base,
        "python" | "python3" | "python.exe" | "python3.exe" | "py" | "py.exe"
    ) || base
        .strip_prefix("python3.")
        .map(|r| r.strip_suffix(".exe").unwrap_or(r))
        .is_some_and(|r| !r.is_empty() && r.chars().all(|c| c.is_ascii_digit()))
}

fn is_managed_legacy_python_tokenade_command(
    tokens: &[String],
    scope: HookInstanceScope<'_>,
) -> bool {
    if tokens.is_empty() {
        return false;
    }
    let mut idx = 0usize;
    let first = norm_instance_path(&tokens[0], true);
    if is_python_exec_span(&first) {
        idx += 1;
        while idx < tokens.len() {
            let f = tokens[idx].as_str();
            if matches!(f, "-3" | "-u" | "-B" | "-E" | "-s" | "-S")
                || (f.starts_with("-X") && f.len() > 2)
            {
                idx += 1;
            } else if f == "-X" && idx + 1 < tokens.len() {
                idx += 2;
            } else {
                break;
            }
        }
    }
    if idx >= tokens.len() {
        return false;
    }
    if !matches_target_plugin_subpath(&tokens[idx], scope, "hooks/tokenade_hook.py") {
        return false;
    }
    match &tokens[idx + 1..] {
        [] => true,
        [flag_eq] => flag_eq == "--event=PreToolUse",
        [flag, ev] => flag == "--event" && ev == "PreToolUse",
        _ => false,
    }
}

pub(crate) fn is_managed_carbon_tokenade_command_in_scope(
    cmd: &str,
    scope: HookInstanceScope<'_>,
) -> bool {
    let Some(tokens) = split_simple_hook_tokens(cmd) else {
        return false;
    };
    is_managed_legacy_python_tokenade_command(&tokens, scope)
        || is_managed_native_carbon_tokenade_command(&tokens, scope)
}

fn escape_json_pointer_segment(seg: &str) -> String {
    seg.replace('~', "~0").replace('/', "~1")
}

fn unescape_json_pointer_segment(seg: &str) -> String {
    seg.replace("~1", "/").replace("~0", "~")
}

fn canonicalize_json_value(val: &Value) -> Value {
    match val {
        Value::Object(map) => {
            let sorted: BTreeMap<String, Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), canonicalize_json_value(v)))
                .collect();
            let mut out = serde_json::Map::new();
            for (k, v) in sorted {
                out.insert(k, v);
            }
            Value::Object(out)
        }
        Value::Array(items) => {
            Value::Array(items.iter().map(canonicalize_json_value).collect())
        }
        other => other.clone(),
    }
}

fn compute_hook_pointer_context_sha(root: &Value, pointer: &str) -> String {
    // INVARIANT: Hash array lengths and non-`command` sibling fields (`matcher`, `timeout`, `type`, `env`, etc.) along the hook rule/entry path below group depth so swapping or shifting array elements after installation is detected deterministically while unrelated top-level groups or sibling events do not trigger false conflicts.
    let Some(stripped) = pointer.strip_prefix('/') else {
        return String::new();
    };
    let mut cur = root;
    let mut steps = Vec::new();
    for (depth, raw_seg) in stripped.split('/').enumerate() {
        let key = unescape_json_pointer_segment(raw_seg);
        match cur {
            Value::Object(map) => {
                if depth >= 2 {
                    let mut sibs = serde_json::Map::new();
                    let sorted_keys: BTreeSet<&String> = map.keys().collect();
                    for k in sorted_keys {
                        if k != &key {
                            if let Some(v) = map.get(k) {
                                sibs.insert(k.clone(), canonicalize_json_value(v));
                            }
                        }
                    }
                    steps.push(json!({ "depth": depth, "siblings": sibs }));
                }
                let Some(next) = map.get(&key) else {
                    return String::new();
                };
                cur = next;
            }
            Value::Array(arr) => {
                let Ok(idx) = key.parse::<usize>() else {
                    return String::new();
                };
                steps.push(json!({ "depth": depth, "array_len": arr.len() }));
                let Some(next) = arr.get(idx) else {
                    return String::new();
                };
                cur = next;
            }
            _ => return String::new(),
        }
    }
    let encoded = serde_json::to_vec(&Value::Array(steps)).unwrap_or_default();
    rio::sha256_hex(&encoded)
}

fn collect_and_rewrite_managed_tokenade_commands(
    val: &mut Value,
    scope: HookInstanceScope<'_>,
    desired_cmd: &str,
    cur_pointer: &str,
    out: &mut Vec<GlobalHookMigration>,
) {
    match val {
        Value::Object(map) => {
            if let Some(Value::String(cmd)) = map.get_mut("command") {
                if is_managed_carbon_tokenade_command_in_scope(cmd, scope) && cmd != desired_cmd {
                    let before = cmd.clone();
                    *cmd = desired_cmd.to_string();
                    out.push(GlobalHookMigration {
                        pointer: format!("{}/command", cur_pointer),
                        before,
                        after: desired_cmd.to_string(),
                        context_sha256: String::new(),
                        peer_set_sha256: String::new(),
                        has_ambiguous_peer: false,
                    });
                }
            }
            for (k, child) in map.iter_mut() {
                if k == "command" && child.is_string() {
                    continue;
                }
                let next_ptr = format!("{}/{}", cur_pointer, escape_json_pointer_segment(k));
                collect_and_rewrite_managed_tokenade_commands(
                    child,
                    scope,
                    desired_cmd,
                    &next_ptr,
                    out,
                );
            }
        }
        Value::Array(items) => {
            for (idx, item) in items.iter_mut().enumerate() {
                let next_ptr = format!("{}/{}", cur_pointer, idx);
                collect_and_rewrite_managed_tokenade_commands(
                    item,
                    scope,
                    desired_cmd,
                    &next_ptr,
                    out,
                );
            }
        }
        _ => {}
    }
}

fn collect_all_command_pointers(val: &Value, cur_pointer: &str, out: &mut BTreeMap<String, String>) {
    match val {
        Value::Object(map) => {
            if let Some(Value::String(cmd)) = map.get("command") {
                out.insert(format!("{}/command", cur_pointer), cmd.clone());
            }
            for (k, child) in map {
                if k == "command" && child.is_string() {
                    continue;
                }
                let next_ptr = format!("{}/{}", cur_pointer, escape_json_pointer_segment(k));
                collect_all_command_pointers(child, &next_ptr, out);
            }
        }
        Value::Array(items) => {
            for (idx, item) in items.iter().enumerate() {
                let next_ptr = format!("{}/{}", cur_pointer, idx);
                collect_all_command_pointers(item, &next_ptr, out);
            }
        }
        _ => {}
    }
}

fn compute_hook_peer_set_sha(root: &Value, all_cmds: &BTreeMap<String, String>, after_cmd: &str) -> String {
    // INVARIANT: Hash the canonical sorted list of `(pointer, context_sha256)` across ALL groups in `hooks.json` that share `command == after_cmd` so cross-group swaps + destination attribute edits invalidate `peers_untouched` while unrelated hooks (`command != after_cmd`) do not.
    let mut peers = Vec::new();
    for (ptr, cmd) in all_cmds {
        if cmd == after_cmd {
            peers.push(json!({
                "pointer": ptr,
                "context_sha256": compute_hook_pointer_context_sha(root, ptr),
            }));
        }
    }
    let encoded = serde_json::to_vec(&Value::Array(peers)).unwrap_or_default();
    rio::sha256_hex(&encoded)
}

fn populate_migration_context_hashes(root: &Value, migrations: &mut [GlobalHookMigration]) {
    // INVARIANT: Record `context_sha256`, `peer_set_sha256`, and `has_ambiguous_peer` (true whenever another entry anywhere in post-install `hooks.json` shares `m.after` with a different pre-install origin, including pre-existing native hooks in other groups) so rollback never overwrites an unmigrated native hook.
    let mig_before_by_ptr: BTreeMap<String, String> = migrations
        .iter()
        .map(|m| (m.pointer.clone(), m.before.clone()))
        .collect();
    let mut all_cmds = BTreeMap::new();
    collect_all_command_pointers(root, "", &mut all_cmds);
    let mut peer_shas_by_after: BTreeMap<String, String> = BTreeMap::new();
    for m in migrations.iter_mut() {
        m.context_sha256 = compute_hook_pointer_context_sha(root, &m.pointer);
        let psha = peer_shas_by_after
            .entry(m.after.clone())
            .or_insert_with(|| compute_hook_peer_set_sha(root, &all_cmds, &m.after))
            .clone();
        m.peer_set_sha256 = psha;
        m.has_ambiguous_peer = all_cmds.iter().any(|(ptr, cmd)| {
            ptr != &m.pointer
                && cmd == &m.after
                && mig_before_by_ptr.get(ptr) != Some(&m.before)
        });
    }
}

fn split_norm_root_prefix(norm_slash_path: &str) -> (&str, &str) {
    let bytes = norm_slash_path.as_bytes();
    if bytes.get(1) == Some(&b':') && bytes[0].is_ascii_alphabetic() {
        if bytes.get(2) == Some(&b'/') {
            return (&norm_slash_path[..3], &norm_slash_path[3..]);
        }
        return (&norm_slash_path[..2], &norm_slash_path[2..]);
    }
    if let Some(after_root) = norm_slash_path.strip_prefix('/') {
        return ("/", after_root);
    }
    ("", norm_slash_path)
}

fn collapse_lexical_dot_segments(norm_slash_path: &str) -> String {
    let (prefix, rest) = split_norm_root_prefix(norm_slash_path);
    let is_rooted = prefix == "/" || prefix.ends_with(":/");
    let mut stack: Vec<&str> = Vec::new();
    for seg in rest.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            if stack.last().is_some_and(|last| *last != "..") {
                stack.pop();
            } else if !is_rooted {
                stack.push("..");
            }
        } else {
            stack.push(seg);
        }
    }
    let body = stack.join("/");
    if prefix.is_empty() {
        body
    } else if body.is_empty() {
        prefix.trim_end_matches('/').to_string()
    } else {
        format!("{}{}", prefix, body)
    }
}

fn shlex_split_statements(cmd: &str, is_windows: bool) -> Vec<Vec<String>> {
    let mut stmts: Vec<Vec<String>> = Vec::new();
    let mut cur_stmt: Vec<String> = Vec::new();
    let mut cur_word = String::new();
    let mut has_word = false;
    let flush_word = |w: &mut String, hw: &mut bool, st: &mut Vec<String>| {
        if *hw {
            let trimmed = w.trim();
            if !trimmed.is_empty() {
                st.push(trimmed.to_string());
            }
            w.clear();
            *hw = false;
        }
    };
    let flush_stmt = |st: &mut Vec<String>, out: &mut Vec<Vec<String>>| {
        if !st.is_empty() {
            out.push(std::mem::take(st));
        }
    };
    let mut chars = cmd.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\'' => {
                has_word = true;
                for qc in chars.by_ref() {
                    if qc == '\'' {
                        break;
                    }
                    cur_word.push(qc);
                }
            }
            '"' => {
                has_word = true;
                while let Some(qc) = chars.next() {
                    if qc == '"' {
                        break;
                    }
                    if qc == '\\' && chars.peek() == Some(&'"') {
                        let _ = chars.next();
                        cur_word.push('"');
                    } else {
                        cur_word.push(qc);
                    }
                }
            }
            '\\' if !is_windows && matches!(chars.peek(), Some(' ' | '\t' | '\'' | '"')) => {
                if let Some(esc) = chars.next() {
                    has_word = true;
                    cur_word.push(esc);
                }
            }
            '$' if !has_word && chars.peek() == Some(&'(') => {}
            '(' | ')' => {
                flush_word(&mut cur_word, &mut has_word, &mut cur_stmt);
                flush_stmt(&mut cur_stmt, &mut stmts);
                stmts.push(vec![ch.to_string()]);
            }
            ';' | '&' | '|' | '\n' | '`' => {
                flush_word(&mut cur_word, &mut has_word, &mut cur_stmt);
                flush_stmt(&mut cur_stmt, &mut stmts);
            }
            '>' | '<' => {
                flush_word(&mut cur_word, &mut has_word, &mut cur_stmt);
            }
            c if c.is_whitespace() => {
                flush_word(&mut cur_word, &mut has_word, &mut cur_stmt);
            }
            c => {
                has_word = true;
                cur_word.push(c);
            }
        }
    }
    flush_word(&mut cur_word, &mut has_word, &mut cur_stmt);
    flush_stmt(&mut cur_stmt, &mut stmts);
    stmts
}

fn is_anchored_norm_path(ns: &str) -> bool {
    ns.starts_with('/')
        || (ns.as_bytes().get(1) == Some(&b':') && ns.as_bytes()[0].is_ascii_alphabetic())
}

fn is_env_assignment_word(word: &str) -> bool {
    let Some((lhs, _)) = word.split_once('=') else {
        return false;
    };
    !lhs.is_empty()
        && !lhs.starts_with('-')
        && !lhs.contains(['/', '\\'])
        && lhs
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[derive(Copy, Clone)]
enum ScopedTargetKind {
    LegacyPy,
    NativeBin,
}

fn strip_ci_prefix<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then(|| &s[prefix.len()..])
}

fn resolve_raw_dir_against_cwd(
    raw_dir: &str,
    case_fold: bool,
    norm_cfg: &str,
    cur_cwd: Option<&str>,
) -> Option<String> {
    let expanded = expand_home_in_cmd_path(raw_dir.trim_matches(|c| c == '\'' || c == '"'));
    if expanded.starts_with('$') || expanded.starts_with('%') {
        return None;
    }
    let norm_dir = collapse_lexical_dot_segments(&norm_instance_path(&expanded, case_fold));
    if is_anchored_norm_path(&norm_dir) {
        return Some(norm_dir);
    }
    let base = cur_cwd.unwrap_or(norm_cfg);
    Some(collapse_lexical_dot_segments(&format!(
        "{}/{}",
        base.trim_end_matches('/'),
        norm_dir
    )))
}

fn extract_ps_stack_key(stmt: &[String], verb_idx: usize) -> Option<String> {
    let mut idx = verb_idx + 1;
    while idx < stmt.len() {
        let tok = stmt[idx].as_str();
        if tok == "--" {
            break;
        }
        if tok.eq_ignore_ascii_case("-stackname") {
            let raw_val = stmt.get(idx + 1)?;
            let trimmed = raw_val.trim_matches(|c| c == '\'' || c == '"');
            if trimmed.starts_with('$') || trimmed.starts_with('%') {
                return None;
            }
            return Some(trimmed.to_ascii_lowercase());
        }
        if let Some(colon_val) = strip_ci_prefix(tok, "-stackname:") {
            let trimmed = colon_val.trim_matches(|c| c == '\'' || c == '"');
            if trimmed.is_empty() {
                let next_val = stmt.get(idx + 1)?;
                let next_trim = next_val.trim_matches(|c| c == '\'' || c == '"');
                if next_trim.starts_with('$') || next_trim.starts_with('%') {
                    return None;
                }
                return Some(next_trim.to_ascii_lowercase());
            }
            if trimmed.starts_with('$') || trimmed.starts_with('%') {
                return None;
            }
            return Some(trimmed.to_ascii_lowercase());
        }
        idx += 1;
    }
    Some(String::new())
}

fn resolve_cd_target(
    stmt: &[String],
    verb_idx: usize,
    case_fold: bool,
    norm_cfg: &str,
    cur_cwd: Option<&str>,
    empty_is_home: bool,
) -> Option<String> {
    let mut arg_opt: Option<&str> = None;
    let mut idx = verb_idx + 1;
    while idx < stmt.len() {
        let tok = stmt[idx].as_str();
        if tok == "--" {
            arg_opt = stmt.get(idx + 1).map(String::as_str);
            break;
        }
        if tok.eq_ignore_ascii_case("-stackname") {
            idx += 2;
            continue;
        }
        if let Some(colon_val) = strip_ci_prefix(tok, "-stackname:") {
            idx += if colon_val.is_empty() { 2 } else { 1 };
            continue;
        }
        if let Some(colon_val) = strip_ci_prefix(tok, "-literalpath:")
            .or_else(|| strip_ci_prefix(tok, "-path:"))
            .or_else(|| strip_ci_prefix(tok, "-lp:"))
            .or_else(|| strip_ci_prefix(tok, "-p:"))
        {
            if !colon_val.is_empty() {
                arg_opt = Some(colon_val);
                break;
            }
            idx += 1;
            continue;
        }
        if tok.starts_with('-') || tok.eq_ignore_ascii_case("/d") {
            idx += 1;
            continue;
        }
        arg_opt = Some(tok);
        break;
    }
    let Some(raw_dir) = arg_opt else {
        if empty_is_home {
            return Some(collapse_lexical_dot_segments(&norm_instance_path(
                &rio::home_dir().to_string_lossy(),
                case_fold,
            )));
        }
        return cur_cwd.map(|s| s.to_string());
    };
    resolve_raw_dir_against_cwd(raw_dir, case_fold, norm_cfg, cur_cwd)
}

fn matches_scoped_rel_for_kind(rel: &str, kind: ScopedTargetKind) -> bool {
    match kind {
        ScopedTargetKind::LegacyPy => {
            (rel.starts_with("/hooks/") || rel.starts_with("/tools/")) && rel.ends_with(".py")
        }
        ScopedTargetKind::NativeBin => {
            matches!(rel, "/bin/carbon-stack" | "/bin/carbon-stack.exe")
        }
    }
}

fn matched_scoped_rel_for_token(
    raw_tok: &str,
    case_fold: bool,
    norm_plug: &str,
    cwd: Option<&str>,
    kind: ScopedTargetKind,
) -> Option<String> {
    let candidate_raw = match raw_tok.split_once('=') {
        Some((lhs, rhs))
            if !lhs.contains(['/', '\\'])
                && match kind {
                    ScopedTargetKind::LegacyPy => rhs.to_ascii_lowercase().ends_with(".py"),
                    ScopedTargetKind::NativeBin => {
                        rhs.to_ascii_lowercase().contains("carbon-stack")
                    }
                } =>
        {
            rhs.trim_matches(|c| c == '\'' || c == '"')
        }
        _ => raw_tok,
    };
    let cand_owned = collapse_lexical_dot_segments(&norm_instance_path(
        &expand_home_in_cmd_path(candidate_raw),
        case_fold,
    ));
    let cand = cand_owned.strip_suffix(',').unwrap_or(&cand_owned);
    let suffix_ok = match kind {
        ScopedTargetKind::LegacyPy => cand.ends_with(".py"),
        ScopedTargetKind::NativeBin => {
            cand == "carbon-stack"
                || cand == "carbon-stack.exe"
                || cand.ends_with("/carbon-stack")
                || cand.ends_with("/carbon-stack.exe")
        }
    };
    if !suffix_ok {
        return None;
    }
    if let Some(rel) = cand.strip_prefix(norm_plug) {
        if matches_scoped_rel_for_kind(rel, kind) {
            return Some(rel.trim_start_matches('/').to_string());
        }
    }
    if is_anchored_norm_path(cand) {
        return None;
    }
    if let Some(base) = cwd {
        let joined = collapse_lexical_dot_segments(&format!(
            "{}/{}",
            base.trim_end_matches('/'),
            cand
        ));
        if let Some(rel) = joined.strip_prefix(norm_plug) {
            if matches_scoped_rel_for_kind(rel, kind) {
                return Some(rel.trim_start_matches('/').to_string());
            }
        }
        return None;
    }
    let mut stripped = cand;
    while let Some(rest) = stripped
        .strip_prefix("../")
        .or_else(|| stripped.strip_prefix("./"))
    {
        stripped = rest;
    }
    let after_plug = stripped.strip_prefix("plugins/gemini-carbon-stack")?;
    matches_scoped_rel_for_kind(after_plug, kind)
        .then(|| after_plug.trim_start_matches('/').to_string())
}

struct ShellScanCtx<'a> {
    scope: HookInstanceScope<'a>,
    case_fold: bool,
    norm_cfg: &'a str,
    norm_plug: &'a str,
    kind: ScopedTargetKind,
}

fn scan_shell_command_collect_targets(
    cmd: &str,
    ctx: &ShellScanCtx<'_>,
    inherited_cwd: Option<&str>,
    depth: u8,
    out: &mut BTreeSet<String>,
) {
    let stmts = shlex_split_statements(cmd, ctx.scope.is_windows);
    let mut cur_cwd: Option<String> = inherited_cwd.map(|s| s.to_string());
    let mut subshell_stack: Vec<(Option<String>, BTreeMap<String, Vec<Option<String>>>)> =
        Vec::new();
    let mut dir_stacks: BTreeMap<String, Vec<Option<String>>> = BTreeMap::new();
    for stmt in &stmts {
        if stmt.len() == 1 {
            if stmt[0] == "(" {
                subshell_stack.push((cur_cwd.clone(), dir_stacks.clone()));
                continue;
            }
            if stmt[0] == ")" {
                if let Some((saved_cwd, saved_stacks)) = subshell_stack.pop() {
                    cur_cwd = saved_cwd;
                    dir_stacks = saved_stacks;
                }
                continue;
            }
        }
        let mut stmt_cwd: Option<String> = cur_cwd.clone();
        let mut used_env_wrapper = false;
        let mut verb_idx = 0usize;
        while verb_idx < stmt.len() {
            let w = stmt[verb_idx].as_str();
            let w_norm = norm_instance_path(w, true);
            let w_base = w_norm.rsplit('/').next().unwrap_or(&w_norm);
            if is_env_assignment_word(w) || matches!(w_base, "command" | "exec" | "nohup" | "&") {
                verb_idx += 1;
            } else if w_base == "env" {
                used_env_wrapper = true;
                verb_idx += 1;
                while verb_idx < stmt.len() {
                    let ef = stmt[verb_idx].as_str();
                    if is_env_assignment_word(ef) || matches!(ef, "-i" | "-0" | "-v") {
                        verb_idx += 1;
                    } else if ef == "-u" && verb_idx + 1 < stmt.len() {
                        verb_idx += 2;
                    } else if (ef == "-C" || ef == "--chdir") && verb_idx + 1 < stmt.len() {
                        stmt_cwd = resolve_raw_dir_against_cwd(
                            &stmt[verb_idx + 1],
                            ctx.case_fold,
                            ctx.norm_cfg,
                            stmt_cwd.as_deref(),
                        );
                        verb_idx += 2;
                    } else if let Some(dir_val) =
                        ef.strip_prefix("--chdir=").or_else(|| ef.strip_prefix("-C"))
                    {
                        if !dir_val.is_empty() && ef.starts_with('-') {
                            stmt_cwd = resolve_raw_dir_against_cwd(
                                dir_val,
                                ctx.case_fold,
                                ctx.norm_cfg,
                                stmt_cwd.as_deref(),
                            );
                            verb_idx += 1;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            } else {
                break;
            }
        }
        if !used_env_wrapper {
            if let Some(verb_tok) = stmt.get(verb_idx) {
                let verb_norm = norm_instance_path(verb_tok, true);
                let verb_base = verb_norm.rsplit('/').next().unwrap_or(&verb_norm);
                if matches!(verb_base, "cd" | "chdir") {
                    cur_cwd = resolve_cd_target(
                        stmt,
                        verb_idx,
                        ctx.case_fold,
                        ctx.norm_cfg,
                        cur_cwd.as_deref(),
                        !ctx.scope.is_windows && verb_base == "cd",
                    );
                    stmt_cwd = cur_cwd.clone();
                } else if matches!(verb_base, "set-location" | "sl") {
                    cur_cwd = resolve_cd_target(
                        stmt,
                        verb_idx,
                        ctx.case_fold,
                        ctx.norm_cfg,
                        cur_cwd.as_deref(),
                        false,
                    );
                    stmt_cwd = cur_cwd.clone();
                } else if verb_base == "pushd" {
                    dir_stacks
                        .entry(String::new())
                        .or_default()
                        .push(cur_cwd.clone());
                    cur_cwd = resolve_cd_target(
                        stmt,
                        verb_idx,
                        ctx.case_fold,
                        ctx.norm_cfg,
                        cur_cwd.as_deref(),
                        false,
                    );
                    stmt_cwd = cur_cwd.clone();
                } else if matches!(verb_base, "push-location" | "pul") {
                    if let Some(stack_key) = extract_ps_stack_key(stmt, verb_idx) {
                        dir_stacks.entry(stack_key).or_default().push(cur_cwd.clone());
                    }
                    cur_cwd = resolve_cd_target(
                        stmt,
                        verb_idx,
                        ctx.case_fold,
                        ctx.norm_cfg,
                        cur_cwd.as_deref(),
                        false,
                    );
                    stmt_cwd = cur_cwd.clone();
                } else if verb_base == "popd" {
                    cur_cwd = dir_stacks.get_mut("").and_then(|s| s.pop()).flatten();
                    stmt_cwd = cur_cwd.clone();
                } else if verb_base == "pop-location" {
                    cur_cwd = match extract_ps_stack_key(stmt, verb_idx) {
                        Some(stack_key) => dir_stacks
                            .get_mut(&stack_key)
                            .and_then(|s| s.pop())
                            .flatten(),
                        None => None,
                    };
                    stmt_cwd = cur_cwd.clone();
                }
            }
        }
        for tok in stmt {
            if let Some(rel) = matched_scoped_rel_for_token(
                tok,
                ctx.case_fold,
                ctx.norm_plug,
                stmt_cwd.as_deref(),
                ctx.kind,
            ) {
                out.insert(rel);
            }
            let tok_low = tok.to_ascii_lowercase();
            let mentions_kind = match ctx.kind {
                ScopedTargetKind::LegacyPy => tok_low.contains(".py"),
                ScopedTargetKind::NativeBin => tok_low.contains("carbon-stack"),
            };
            if depth < 4
                && mentions_kind
                && tok.chars().any(|c| {
                    c.is_whitespace()
                        || matches!(c, ';' | '&' | '|' | '\'' | '"' | '(' | ')' | '=' | '`')
                })
            {
                scan_shell_command_collect_targets(
                    tok,
                    ctx,
                    stmt_cwd.as_deref(),
                    depth + 1,
                    out,
                );
            }
        }
    }
}

fn collect_scoped_rels_in_command(
    cmd: &str,
    scope: HookInstanceScope<'_>,
    kind: ScopedTargetKind,
) -> BTreeSet<String> {
    let case_fold = scope_case_fold(scope);
    let norm_cfg = collapse_lexical_dot_segments(&norm_instance_path(
        &scope.config_dir.to_string_lossy(),
        case_fold,
    ));
    let norm_plug = collapse_lexical_dot_segments(&norm_instance_path(
        &scope.target_plugin_dir.to_string_lossy(),
        case_fold,
    ));
    let ctx = ShellScanCtx {
        scope,
        case_fold,
        norm_cfg: &norm_cfg,
        norm_plug: &norm_plug,
        kind,
    };
    let mut out = BTreeSet::new();
    scan_shell_command_collect_targets(cmd, &ctx, None, 0, &mut out);
    out
}

fn command_references_scoped_legacy_plugin_py(cmd: &str, scope: HookInstanceScope<'_>) -> bool {
    !collect_scoped_rels_in_command(cmd, scope, ScopedTargetKind::LegacyPy).is_empty()
}

fn command_references_scoped_native_bin(cmd: &str, scope: HookInstanceScope<'_>) -> bool {
    !collect_scoped_rels_in_command(cmd, scope, ScopedTargetKind::NativeBin).is_empty()
}

fn verify_no_unmigrated_scoped_py_commands(
    root: &Value,
    hooks_path: &Path,
    scope: HookInstanceScope<'_>,
) -> Result<(), String> {
    // INVARIANT: Refuse installation if any command in `<config_dir>/hooks.json` still points to `<target_plugin_dir>/hooks/*.py` or `tools/*.py` after auto-migration so pruning stale v1 files can never leave global hooks referencing a deleted Python script.
    let mut post_cmds = BTreeMap::new();
    collect_all_command_pointers(root, "", &mut post_cmds);
    for (ptr, cmd) in post_cmds {
        if command_references_scoped_legacy_plugin_py(&cmd, scope) {
            return Err(format!(
                "Global hooks.json entry at {} in {} still references a legacy plugin Python script ('{}') that cannot be auto-migrated; update hooks.json before upgrading",
                ptr,
                hooks_path.display(),
                cmd
            ));
        }
    }
    Ok(())
}

fn raw_text_mentions_scoped_plugin_path(raw: &str, scope: HookInstanceScope<'_>) -> bool {
    let case_fold = scope_case_fold(scope);
    let norm_raw = norm_instance_path(raw, case_fold);
    let norm_plug = norm_instance_path(&scope.target_plugin_dir.to_string_lossy(), case_fold);
    let default_plug = norm_instance_path(
        &rio::home_dir()
            .join(".gemini")
            .join("config")
            .join("plugins")
            .join(PLUGIN_NAME)
            .to_string_lossy(),
        case_fold,
    );
    norm_raw.contains(&norm_plug)
        || (norm_plug == default_plug
            && norm_raw.contains("~/.gemini/config/plugins/gemini-carbon-stack"))
}

fn raw_text_mentions_scoped_tokenade(raw: &str, scope: HookInstanceScope<'_>) -> bool {
    let norm_raw = norm_instance_path(raw, scope_case_fold(scope));
    raw_text_mentions_scoped_plugin_path(raw, scope)
        && (norm_raw.contains(".py") || norm_raw.contains("tokenade-hook"))
}

fn verify_hooks_raw_free_of_scoped_py(
    raw: &str,
    hooks_path: &Path,
    scope: HookInstanceScope<'_>,
) -> Result<(), String> {
    match serde_json::from_str::<Value>(raw) {
        Ok(val) => verify_no_unmigrated_scoped_py_commands(&val, hooks_path, scope),
        Err(e) => {
            if raw_text_mentions_scoped_tokenade(raw, scope)
                || command_references_scoped_legacy_plugin_py(raw, scope)
            {
                return Err(format!(
                    "Invalid JSON in {} while referencing legacy plugin scripts: {}",
                    hooks_path.display(),
                    e
                ));
            }
            Ok(())
        }
    }
}

fn target_tree_has_rel(t_dir: &Path, rel: &str, case_fold: bool) -> bool {
    t_dir.join(rel).is_file()
        || (case_fold
            && tree_rel_paths(t_dir)
                .iter()
                .any(|r| norm_instance_path(r, true) == rel))
}

fn verify_hooks_raw_compatible_with_plugin_tree(
    raw: &str,
    hooks_path: &Path,
    scope: HookInstanceScope<'_>,
    previously_present_py: &BTreeSet<String>,
    target_tree: Option<&Path>,
) -> Result<(), String> {
    let case_fold = scope_case_fold(scope);
    let target_has_native_bin = target_tree
        .is_some_and(|t| t.join(platform_hook_binary_rel(scope.is_windows)).is_file());
    match serde_json::from_str::<Value>(raw) {
        Ok(val) => {
            let mut cmds = BTreeMap::new();
            collect_all_command_pointers(&val, "", &mut cmds);
            for (ptr, cmd) in cmds {
                if !target_has_native_bin && command_references_scoped_native_bin(&cmd, scope) {
                    return Err(format!(
                        "Global hooks.json entry at {} in {} would still invoke native carbon-stack binary ('{}'), which is absent from the target plugin snapshot",
                        ptr,
                        hooks_path.display(),
                        cmd
                    ));
                }
                let py_rels = collect_scoped_rels_in_command(&cmd, scope, ScopedTargetKind::LegacyPy);
                for rel in py_rels {
                    match target_tree {
                        Some(t_dir) => {
                            if !target_tree_has_rel(t_dir, &rel, case_fold) {
                                return Err(format!(
                                    "Global hooks.json entry at {} in {} would still invoke legacy plugin script '{}' ('{}'), which is absent from target snapshot {}",
                                    ptr,
                                    hooks_path.display(),
                                    rel,
                                    cmd,
                                    t_dir.display()
                                ));
                            }
                        }
                        None => {
                            if previously_present_py.contains(&rel) {
                                return Err(format!(
                                    "Global hooks.json entry at {} in {} still invokes plugin script '{}' ('{}'), which would be removed by rollback",
                                    ptr,
                                    hooks_path.display(),
                                    rel,
                                    cmd
                                ));
                            }
                        }
                    }
                }
            }
            Ok(())
        }
        Err(e) => {
            let norm_raw = norm_instance_path(raw, case_fold);
            if !target_has_native_bin
                && ((raw_text_mentions_scoped_plugin_path(raw, scope)
                    && norm_raw.contains("carbon-stack"))
                    || command_references_scoped_native_bin(raw, scope))
            {
                return Err(format!(
                    "Invalid JSON in {} while referencing native carbon-stack binary: {}",
                    hooks_path.display(),
                    e
                ));
            }
            let py_rels = collect_scoped_rels_in_command(raw, scope, ScopedTargetKind::LegacyPy);
            let py_missing = py_rels.iter().any(|rel| match target_tree {
                Some(t_dir) => !target_tree_has_rel(t_dir, rel, case_fold),
                None => previously_present_py.contains(rel),
            });
            if py_missing
                || (target_tree.is_none_or(|t| !target_tree_has_rel(t, "hooks/tokenade_hook.py", case_fold))
                    && raw_text_mentions_scoped_tokenade(raw, scope)
                    && norm_raw.contains(".py"))
            {
                return Err(format!(
                    "Invalid JSON in {} while referencing legacy plugin scripts absent from target snapshot: {}",
                    hooks_path.display(),
                    e
                ));
            }
            Ok(())
        }
    }
}

#[cfg(unix)]
fn unix_fd_identity(fh: &fs::File) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let m = fh.metadata().ok()?;
    m.file_type().is_file().then(|| (m.dev(), m.ino()))
}

const HOOKS_SENTINEL_BYTES: &[u8] = b"{}\n";

struct HooksReadShareGuard {
    fh: Option<fs::File>,
    path: PathBuf,
    raw: String,
    created_sentinel: bool,
}

impl Drop for HooksReadShareGuard {
    fn drop(&mut self) {
        let _ = self.fh.take();
        if self.created_sentinel {
            let _ = win32_sqlite::remove_file_if_exact_bytes(&self.path, HOOKS_SENTINEL_BYTES);
        }
    }
}

fn cleanup_created_sentinel(hooks_path: &Path, we_created: bool) {
    if we_created {
        let _ = win32_sqlite::remove_file_if_exact_bytes(hooks_path, HOOKS_SENTINEL_BYTES);
    }
}

fn acquire_hooks_read_share_guard_mode(
    hooks_path: &Path,
    lock_missing: bool,
) -> Result<Option<HooksReadShareGuard>, String> {
    // INVARIANT: Hold a shared lock across verification and contraction — creating a temporary 3-byte `"{}\n"` sentinel when `hooks.json` is initially `NotFound` and `lock_missing` is set: on Windows `FILE_SHARE_READ` (`share_mode(1)`) mandatorily blocks all concurrent writes, `MoveFileExW`, and `ReplaceFileW` in the NT kernel; on POSIX `LOCK_SH` blocks cooperating `flock` writers while uncoordinated non-`flock` writes have a bounded single-`rename` detection/restoration window backed by pre-preflight idempotent WAL recovery.
    let mut last_err = String::new();
    let mut we_created = false;
    for attempt in 0..8u64 {
        if win32_sqlite::is_link_or_junction(hooks_path) {
            cleanup_created_sentinel(hooks_path, we_created);
            return Err(format!(
                "Refusing symlink/junction global hooks.json: {}",
                hooks_path.display()
            ));
        }
        let open_res = {
            let mut opts = fs::OpenOptions::new();
            opts.read(true);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                opts.share_mode(1);
            }
            opts.open(hooks_path)
        };
        let mut fh = match open_res {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if lock_missing {
                    if let Some(parent) = hooks_path.parent() {
                        if !parent.exists() {
                            fs::create_dir_all(parent).map_err(|pe| {
                                format!("Cannot create {}: {}", parent.display(), pe)
                            })?;
                        }
                        if win32_sqlite::is_link_or_junction(parent) {
                            return Err(format!(
                                "Refusing symlink/junction hooks parent: {}",
                                parent.display()
                            ));
                        }
                    }
                    match fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(hooks_path)
                    {
                        Ok(mut wfh) => {
                            if let Err(we) = wfh.write_all(HOOKS_SENTINEL_BYTES) {
                                drop(wfh);
                                let _ = fs::remove_file(hooks_path);
                                return Err(format!(
                                    "Cannot initialize sentinel {}: {}",
                                    hooks_path.display(),
                                    we
                                ));
                            }
                            drop(wfh);
                            we_created = true;
                            continue;
                        }
                        Err(ce) if ce.kind() == std::io::ErrorKind::AlreadyExists => {
                            continue;
                        }
                        Err(ce) => {
                            last_err = ce.to_string();
                            thread::sleep(Duration::from_millis(15 * (attempt + 1)));
                            continue;
                        }
                    }
                }
                return Ok(None);
            }
            Err(e) => {
                last_err = e.to_string();
                thread::sleep(Duration::from_millis(15 * (attempt + 1)));
                continue;
            }
        };
        #[cfg(unix)]
        {
            let _ = fh.lock_shared();
            if win32_sqlite::is_link_or_junction(hooks_path) {
                return Err(format!(
                    "Refusing symlink/junction global hooks.json: {}",
                    hooks_path.display()
                ));
            }
            if win32_sqlite::file_identity(hooks_path) != unix_fd_identity(&fh) {
                last_err = "concurrent inode replacement before shared lock".to_string();
                continue;
            }
        }
        let meta = match fh.metadata() {
            Ok(m) => m,
            Err(e) => {
                drop(fh);
                cleanup_created_sentinel(hooks_path, we_created);
                return Err(format!("Cannot inspect {}: {}", hooks_path.display(), e));
            }
        };
        if !meta.file_type().is_file() {
            drop(fh);
            cleanup_created_sentinel(hooks_path, we_created);
            return Err(format!(
                "Global hooks.json path is not a regular file: {}",
                hooks_path.display()
            ));
        }
        let mut raw = String::new();
        if let Err(e) = fh.read_to_string(&mut raw) {
            drop(fh);
            cleanup_created_sentinel(hooks_path, we_created);
            return Err(format!("Cannot read {}: {}", hooks_path.display(), e));
        }
        let created_sentinel = we_created && raw.as_bytes() == HOOKS_SENTINEL_BYTES;
        return Ok(Some(HooksReadShareGuard {
            fh: Some(fh),
            path: hooks_path.to_path_buf(),
            raw,
            created_sentinel,
        }));
    }
    cleanup_created_sentinel(hooks_path, we_created);
    Err(format!(
        "Cannot acquire read-share guard on {}: {}",
        hooks_path.display(),
        last_err
    ))
}

fn acquire_hooks_read_share_guard(
    hooks_path: &Path,
) -> Result<Option<HooksReadShareGuard>, String> {
    acquire_hooks_read_share_guard_mode(hooks_path, false)
}

fn verify_live_hooks_free_of_scoped_py(
    hooks_path: &Path,
    scope: HookInstanceScope<'_>,
) -> Result<(), String> {
    let Some(guard) = acquire_hooks_read_share_guard(hooks_path)? else {
        return Ok(());
    };
    verify_hooks_raw_free_of_scoped_py(&guard.raw, hooks_path, scope)
}

fn parse_hooks_migration_from_str(
    raw: &str,
    hooks_path: &Path,
    scope: HookInstanceScope<'_>,
) -> Result<Option<GlobalHooksPlan>, String> {
    let mut parsed: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            if raw_text_mentions_scoped_tokenade(raw, scope) {
                return Err(format!(
                    "Invalid JSON in {} prevents migrating managed tokenade hook: {}",
                    hooks_path.display(),
                    e
                ));
            }
            return Ok(None);
        }
    };
    let desired = desired_tokenade_hook_command(scope.target_plugin_dir, scope.is_windows);
    let mut migrations = Vec::new();
    collect_and_rewrite_managed_tokenade_commands(&mut parsed, scope, &desired, "", &mut migrations);
    verify_no_unmigrated_scoped_py_commands(&parsed, hooks_path, scope)?;
    if migrations.is_empty() {
        return Ok(None);
    }
    populate_migration_context_hashes(&parsed, &mut migrations);
    let rendered = serde_json::to_string_pretty(&parsed).map_err(|e| e.to_string())?;
    Ok(Some(GlobalHooksPlan {
        rendered_json: format!("{}\n", rendered),
        migrations,
    }))
}

fn stat_regular_hooks_file(hooks_path: &Path) -> Result<Option<fs::Metadata>, String> {
    if win32_sqlite::is_link_or_junction(hooks_path) {
        return Err(format!(
            "Refusing symlink/junction global hooks.json: {}",
            hooks_path.display()
        ));
    }
    let meta = match fs::symlink_metadata(hooks_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(format!(
                "Cannot inspect global hooks.json {}: {}",
                hooks_path.display(),
                e
            ));
        }
    };
    if !meta.file_type().is_file() {
        return Err(format!(
            "Global hooks.json path is not a regular file: {}",
            hooks_path.display()
        ));
    }
    Ok(Some(meta))
}

pub(crate) fn inspect_global_hooks_migration(
    config_dir: &Path,
    target_plugin_dir: &Path,
    is_windows: bool,
) -> Result<Option<GlobalHooksPlan>, String> {
    let hooks_path = config_dir.join("hooks.json");
    if stat_regular_hooks_file(&hooks_path)?.is_none() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&hooks_path)
        .map_err(|e| format!("Cannot read {}: {}", hooks_path.display(), e))?;
    let scope = HookInstanceScope {
        config_dir,
        target_plugin_dir,
        is_windows,
    };
    parse_hooks_migration_from_str(&raw, &hooks_path, scope)
}

fn write_preserved_copy_exclusive(dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut fh = opts.open(dest)?;
    let write_res = fh.write_all(bytes).and_then(|()| fh.sync_all());
    drop(fh);
    if write_res.is_err() {
        let _ = fs::remove_file(dest);
    }
    write_res
}

fn preserve_unrestored_user_hooks_file(hooks_path: &Path, candidate: &Path) -> PathBuf {
    static PRES_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let mut cached_bytes: Option<Option<Vec<u8>>> = None;
    for _ in 0..16 {
        let fname = format!(
            "hooks.json.preserved-user-save-{}-{}",
            std::process::id(),
            PRES_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let dest = hooks_path.with_file_name(fname);
        match win32_sqlite::atomic_move_noreplace(candidate, &dest) {
            Ok(()) => return dest,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => {}
        }
        let maybe_bytes = cached_bytes.get_or_insert_with(|| {
            (!win32_sqlite::is_link_or_junction(candidate))
                .then(|| fs::read(candidate).ok())
                .flatten()
        });
        let Some(ref bytes) = maybe_bytes else {
            break;
        };
        match write_preserved_copy_exclusive(&dest, bytes) {
            Ok(()) => return dest,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => break,
        }
    }
    candidate.to_path_buf()
}

fn identity_matches(expected: Option<(u64, u64)>, path: &Path) -> bool {
    match (expected, win32_sqlite::file_identity(path)) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    }
}

fn regular_file_sha_matches(path: &Path, expected_sha: &str) -> bool {
    !win32_sqlite::is_link_or_junction(path)
        && fs::read(path)
            .map(|b| rio::sha256_hex(&b) == expected_sha)
            .unwrap_or(false)
}

fn restore_displaced_linearizable<R>(
    hooks_path: &Path,
    initial_displaced: PathBuf,
    initial_expected_id: Option<(u64, u64)>,
    initial_expected_sha: String,
    mut before_restore_swap_hook: R,
) -> Result<(), (PathBuf, String)>
where
    R: FnMut(usize),
{
    // INVARIANT: Causal-monotonic restore after a detected post-verify race: retry transient sharing errors on reverse swap, promote strictly newer external saves (`Save_{k+1}` > `Save_k`), and NEVER delete an unrestored user `candidate` (if reverse swap fails or 8 concurrent saves exhaust the loop, preserve `candidate` intact on disk and return `(preserved_path, err_msg)` so caller cleanup never unlinks `preserved_path`).
    const MAX_RESTORE_ROUNDS: usize = 8;
    const MAX_RESTORE_ERR_RETRIES: u64 = 8;
    let mut candidate = initial_displaced;
    let mut expected_id = initial_expected_id;
    let mut expected_sha = initial_expected_sha;
    let mut fail_reason = format!("exhausted {} concurrent save rounds", MAX_RESTORE_ROUNDS);
    for round in 0..MAX_RESTORE_ROUNDS {
        before_restore_swap_hook(round);
        if win32_sqlite::is_link_or_junction(&candidate) || !candidate.is_file() {
            fail_reason = "displaced candidate is missing or non-regular".to_string();
            break;
        }
        let cand_id = win32_sqlite::file_identity(&candidate);
        let cand_bytes = match fs::read(&candidate) {
            Ok(b) => b,
            Err(e) => {
                fail_reason = e.to_string();
                break;
            }
        };
        let cand_sha = rio::sha256_hex(&cand_bytes);
        let mut swapped_disp: Option<PathBuf> = None;
        for err_try in 0..MAX_RESTORE_ERR_RETRIES {
            let next_slot = next_exclusive_tmp_path(hooks_path);
            match win32_sqlite::atomic_replace_capturing_displaced(
                hooks_path,
                &candidate,
                &next_slot,
            ) {
                Ok(disp_next) => {
                    swapped_disp = Some(disp_next);
                    break;
                }
                Err(e) => {
                    if let Err(rec_err) =
                        win32_sqlite::recover_stranded_displaced_file(hooks_path, &next_slot)
                    {
                        let preserved = preserve_unrestored_user_hooks_file(hooks_path, &candidate);
                        let msg = format!(
                            "{}; user save preserved intact at {}",
                            rec_err,
                            preserved.display()
                        );
                        return Err((preserved, msg));
                    }
                    if !hooks_path.exists()
                        && candidate.is_file()
                        && win32_sqlite::atomic_move_noreplace(&candidate, hooks_path).is_ok()
                    {
                        return Ok(());
                    }
                    fail_reason = e.to_string();
                    if err_try + 1 < MAX_RESTORE_ERR_RETRIES {
                        thread::sleep(Duration::from_millis(10 * (err_try + 1)));
                    }
                }
            }
        }
        let Some(disp_next) = swapped_disp else {
            break;
        };
        let matched = identity_matches(expected_id, &disp_next)
            && regular_file_sha_matches(&disp_next, &expected_sha);
        if candidate != disp_next && hooks_path.exists() {
            let _ = fs::remove_file(&candidate);
        }
        if matched {
            let _ = fs::remove_file(&disp_next);
            return Ok(());
        }
        expected_id = cand_id;
        expected_sha = cand_sha;
        candidate = disp_next;
    }
    let preserved = preserve_unrestored_user_hooks_file(hooks_path, &candidate);
    let msg = format!(
        "Could not restore concurrent external save onto {} ({}); user save preserved intact at {}",
        hooks_path.display(),
        fail_reason,
        preserved.display()
    );
    Err((preserved, msg))
}

#[cfg(test)]
fn cas_update_hooks_file<T, F>(hooks_path: &Path, transform: F) -> Result<Option<(String, T)>, String>
where
    F: FnMut(&str) -> Result<Option<(Vec<u8>, T)>, String>,
{
    let mut published_unreverted = false;
    cas_update_hooks_file_with_hooks(hooks_path, &mut published_unreverted, transform, |_| {}, |_| {})
}

fn cas_update_hooks_file_tracking<T, F>(
    hooks_path: &Path,
    published_unreverted: &mut bool,
    transform: F,
) -> Result<Option<(String, T)>, String>
where
    F: FnMut(&str) -> Result<Option<(Vec<u8>, T)>, String>,
{
    cas_update_hooks_file_with_hooks(hooks_path, published_unreverted, transform, |_| {}, |_| {})
}

fn cas_update_hooks_file_with_hooks<T, F, H, R>(
    hooks_path: &Path,
    published_unreverted: &mut bool,
    mut transform: F,
    mut post_verify_hook: H,
    mut before_restore_swap_hook: R,
) -> Result<Option<(String, T)>, String>
where
    F: FnMut(&str) -> Result<Option<(Vec<u8>, T)>, String>,
    H: FnMut(usize),
    R: FnMut(usize),
{
    // INVARIANT: Perform non-destructive atomic replacement (`ReplaceFileW` on Windows, `renameat2(RENAME_EXCHANGE)` on Linux, `renamex_np(RENAME_SWAP)` on macOS) with causal-monotonic restore on race, `published_unreverted` tracking (so WAL undo metadata is never wiped if reverse-swap fails), and atomic noreplace stranded-backup recovery (`ERROR_UNABLE_TO_MOVE_REPLACEMENT_2`).
    *published_unreverted = false;
    const MAX_CAS_ATTEMPTS: usize = 8;
    let mut attempt = 0usize;
    loop {
        let Some(meta) = stat_regular_hooks_file(hooks_path)? else {
            return Ok(None);
        };
        let orig_perms = meta.permissions();
        let orig_id = win32_sqlite::file_identity(hooks_path);
        let orig_bytes = fs::read(hooks_path)
            .map_err(|e| format!("Cannot read {}: {}", hooks_path.display(), e))?;
        let orig_sha = rio::sha256_hex(&orig_bytes);
        let orig_str = std::str::from_utf8(&orig_bytes)
            .map_err(|e| format!("Invalid UTF-8 in {}: {}", hooks_path.display(), e))?;
        let Some((new_bytes, meta_out)) = transform(orig_str)? else {
            return Ok(None);
        };
        let new_sha = rio::sha256_hex(&new_bytes);
        if let Some(parent) = hooks_path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let tmp = next_exclusive_tmp_path(hooks_path);
        let displaced_cand = next_exclusive_tmp_path(hooks_path);
        let mut preserved_path: Option<PathBuf> = None;
        let step_res: Result<Option<String>, String> = (|| {
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut tmp_fh = opts.open(&tmp).map_err(|e| e.to_string())?;
            tmp_fh.write_all(&new_bytes).map_err(|e| e.to_string())?;
            drop(tmp_fh);
            #[cfg(unix)]
            fs::set_permissions(&tmp, orig_perms.clone()).map_err(|e| e.to_string())?;
            let tmp_id = win32_sqlite::file_identity(&tmp);
            if win32_sqlite::is_link_or_junction(hooks_path) {
                return Err(format!(
                    "Refusing symlink/junction global hooks.json: {}",
                    hooks_path.display()
                ));
            }
            let cur_bytes = match fs::read(hooks_path) {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(Some("not_found".to_string()));
                }
                Err(e) => {
                    return Ok(Some(format!(
                        "Cannot re-verify {}: {}",
                        hooks_path.display(),
                        e
                    )));
                }
            };
            if !identity_matches(orig_id, hooks_path) || rio::sha256_hex(&cur_bytes) != orig_sha {
                return Ok(Some("sha256_changed".to_string()));
            }
            post_verify_hook(attempt);
            match win32_sqlite::atomic_replace_capturing_displaced(
                hooks_path,
                &tmp,
                &displaced_cand,
            ) {
                Ok(displaced_path) => {
                    let displaced_matches = identity_matches(orig_id, &displaced_path)
                        && regular_file_sha_matches(&displaced_path, &orig_sha);
                    if displaced_matches {
                        #[cfg(not(unix))]
                        {
                            let _ = fs::set_permissions(hooks_path, orig_perms.clone());
                        }
                        let _ = fs::remove_file(&displaced_path);
                        return Ok(None);
                    }
                    *published_unreverted = true;
                    if let Err((pres, msg)) = restore_displaced_linearizable(
                        hooks_path,
                        displaced_path,
                        tmp_id,
                        new_sha.clone(),
                        &mut before_restore_swap_hook,
                    ) {
                        preserved_path = Some(pres);
                        return Err(msg);
                    }
                    *published_unreverted = false;
                    Ok(Some("post_verify_concurrent_save_restored".to_string()))
                }
                Err(e) => {
                    win32_sqlite::recover_stranded_displaced_file(hooks_path, &displaced_cand)?;
                    #[cfg(unix)]
                    // WORKAROUND: Kernel returns ENOSYS (38), EINVAL (22), ENOTSUP (45, macOS), or EOPNOTSUPP (95, Linux) when the underlying filesystem lacks atomic exchange.
                    if e.kind() == std::io::ErrorKind::Unsupported
                        || matches!(e.raw_os_error(), Some(38 | 22 | 45 | 95))
                    {
                        return Err(format!(
                            "Filesystem hosting {} does not support atomic file exchange required for race-free hooks.json update: {}",
                            hooks_path.display(),
                            e
                        ));
                    }
                    Ok(Some(e.to_string()))
                }
            }
        })();
        // INVARIANT: Never unlink `tmp` or `displaced_cand` when `restore_displaced_linearizable` preserved the unrestored user save in place at that path (`tmp` on Linux/macOS atomic exchange or `displaced_cand` on Windows `ReplaceFileW`).
        let keep_tmp = preserved_path.as_deref() == Some(tmp.as_path());
        let keep_disp = preserved_path.as_deref() == Some(displaced_cand.as_path());
        if !keep_tmp {
            let _ = fs::remove_file(&tmp);
        }
        if !keep_disp && hooks_path.exists() {
            let _ = fs::remove_file(&displaced_cand);
        }
        match step_res? {
            None => return Ok(Some((new_sha, meta_out))),
            Some(retry_err) => {
                attempt += 1;
                if attempt >= MAX_CAS_ATTEMPTS {
                    return Err(format!(
                        "Concurrent modifications or lock contention on {} prevented atomic compare-and-swap update: {}",
                        hooks_path.display(),
                        retry_err
                    ));
                }
                thread::sleep(Duration::from_millis(25 * (attempt as u64)));
            }
        }
    }
}

fn sync_backup_manifest_hooks_migrations(
    stack_home: &Path,
    backup_id: &str,
    migrations: &[GlobalHookMigration],
    post_install_sha256: Option<&str>,
) -> Result<(), String> {
    if backup_id.is_empty() {
        return Ok(());
    }
    let mf_path = stack_home.join("backups").join(backup_id).join("manifest.json");
    let Some(mut mf) = rio::read_json(&mf_path) else {
        return Err(format!("Cannot read backup manifest {}", mf_path.display()));
    };
    let migs_json: Vec<Value> = migrations
        .iter()
        .map(|m| {
            json!({
                "pointer": m.pointer,
                "before": m.before,
                "after": m.after,
                "context_sha256": m.context_sha256,
                "peer_set_sha256": m.peer_set_sha256,
                "has_ambiguous_peer": m.has_ambiguous_peer,
            })
        })
        .collect();
    let norm_sha = post_install_sha256.filter(|s| !s.is_empty());
    let Some(gh) = mf
        .get_mut("targets")
        .and_then(|t| t.get_mut("global_hooks"))
        .and_then(|g| g.as_object_mut())
    else {
        return Err(format!(
            "Malformed backup manifest {}: missing targets.global_hooks",
            mf_path.display()
        ));
    };
    let already_matches = gh
        .get("migrations")
        .and_then(|v| v.as_array())
        .is_some_and(|a| a == &migs_json)
        && gh.get("post_install_sha256").and_then(|v| v.as_str()) == norm_sha;
    if already_matches {
        return Ok(());
    }
    gh.insert("migrations".to_string(), Value::Array(migs_json));
    match norm_sha {
        Some(sha) => {
            gh.insert("post_install_sha256".to_string(), Value::String(sha.to_string()));
        }
        None => {
            gh.remove("post_install_sha256");
        }
    }
    rio::write_json(&mf_path, &mf)
}

fn clear_v1_lock_epoch_checked(state_root: &Path, drain_timeout: Duration) -> Result<(), String> {
    // INVARIANT: Remove `.lock_epoch` strictly while holding `LOCK_EX` on `.v2_alive.lease` so `.lock_epoch` is never cleared concurrently with an in-flight lock transition.
    fs::create_dir_all(state_root).map_err(|e| e.to_string())?;
    let lease_path = rio::v2_lease_path(state_root);
    let lfh = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lease_path)
        .map_err(|e| format!("Cannot open {}: {}", lease_path.display(), e))?;
    let dl = Instant::now() + drain_timeout;
    loop {
        match lfh.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) => {
                if Instant::now() >= dl {
                    return Err(format!(
                        "Timed out acquiring {} before clearing .lock_epoch",
                        lease_path.display()
                    ));
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(format!("Failed locking {}: {}", lease_path.display(), e));
            }
        }
    }
    let epoch_path = rio::lock_epoch_path(state_root);
    let rm_res = match fs::remove_file(&epoch_path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("Failed removing {}: {}", epoch_path.display(), e)),
    };
    let _ = lfh.unlock();
    rm_res
}

fn v2_plugin_digest_path(state_root: &Path) -> PathBuf {
    state_root.join(".v2_plugin_digest")
}

fn manifest_digest(m: &BTreeMap<String, String>) -> String {
    let mut buf = String::new();
    for (rel, sha) in m {
        buf.push_str(rel);
        buf.push(':');
        buf.push_str(sha);
        buf.push('\n');
    }
    rio::sha256_hex(buf.as_bytes())
}

fn write_v2_plugin_digest_raw(state_root: &Path, raw_digest: &str) -> std::io::Result<()> {
    if win32_sqlite::is_link_or_junction(state_root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing symlink/junction state_root",
        ));
    }
    fs::create_dir_all(state_root)?;
    let dpath = v2_plugin_digest_path(state_root);
    if win32_sqlite::is_link_or_junction(&dpath) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing symlink/junction .v2_plugin_digest",
        ));
    }
    let tmp = next_exclusive_tmp_path(&dpath);
    let mut fh = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    let payload = format!("{}\n", raw_digest.trim());
    if let Err(e) = fh.write_all(payload.as_bytes()) {
        drop(fh);
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    drop(fh);
    if let Err(e) = fs::rename(&tmp, &dpath) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

fn write_v2_plugin_digest(state_root: &Path, m: &BTreeMap<String, String>) -> std::io::Result<()> {
    write_v2_plugin_digest_raw(state_root, &manifest_digest(m))
}

fn remove_v2_plugin_digest(state_root: &Path) {
    let dpath = v2_plugin_digest_path(state_root);
    if !win32_sqlite::is_link_or_junction(&dpath) {
        let _ = fs::remove_file(&dpath);
    }
}

fn is_verified_v2_plugin(state_root: &Path, dst_manifest: &BTreeMap<String, String>) -> bool {
    if dst_manifest.is_empty() {
        return false;
    }
    let dpath = v2_plugin_digest_path(state_root);
    if win32_sqlite::is_link_or_junction(&dpath) {
        return false;
    }
    fs::read_to_string(&dpath)
        .map(|s| s.trim() == manifest_digest(dst_manifest))
        .unwrap_or(false)
}

struct InstallerMutexGuard {
    locks: Vec<fs::File>,
}

impl Drop for InstallerMutexGuard {
    fn drop(&mut self) {
        for fh in self.locks.iter().rev() {
            let _ = fh.unlock();
        }
    }
}

fn acquire_single_kernel_lock(lock_path: &Path, deadline: Instant) -> Result<fs::File, String> {
    if win32_sqlite::is_link_or_junction(lock_path) {
        return Err(format!(
            "Refusing symlink/junction installer lock: {}",
            lock_path.display()
        ));
    }
    let fh = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .map_err(|e| format!("Cannot open {}: {}", lock_path.display(), e))?;
    loop {
        match fh.try_lock() {
            Ok(()) => return Ok(fh),
            Err(std::fs::TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "Timed out acquiring installer lock {}",
                        lock_path.display()
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(format!("Failed locking {}: {}", lock_path.display(), e));
            }
        }
    }
}

fn acquire_installer_mutex(
    config_dir: &Path,
    stack_home: &Path,
    timeout: Duration,
) -> Result<InstallerMutexGuard, String> {
    // INVARIANT: Serialize all non-dry-run `perform_install` (including `already_up_to_date`) and `perform_rollback` transitions in deterministic path order across `<stack_home>/state/.installer.lock` and `<config_dir>/.carbon-installer.lock` so a concurrent install can never clear `.lock_epoch` mid-rollback.
    let state_root = stack_home.join("state");
    fs::create_dir_all(&state_root).map_err(|e| e.to_string())?;
    fs::create_dir_all(config_dir).map_err(|e| e.to_string())?;
    let mut lock_paths = vec![
        state_root.join(".installer.lock"),
        config_dir.join(".carbon-installer.lock"),
    ];
    lock_paths.sort_by_key(|p| rio::normalize_path(&p.to_string_lossy()));
    lock_paths.dedup_by(|a, b| {
        rio::normalize_path(&a.to_string_lossy()) == rio::normalize_path(&b.to_string_lossy())
    });
    let deadline = Instant::now() + timeout;
    let mut guard = InstallerMutexGuard { locks: Vec::new() };
    for lp in &lock_paths {
        let fh = acquire_single_kernel_lock(lp, deadline)?;
        guard.locks.push(fh);
    }
    Ok(guard)
}

fn ensure_state_subdirs(stack_home: &Path) {
    let state_root = stack_home.join("state");
    for sub in ["gate", "continuity", "memory", "chips", "hygiene", "logs"] {
        let _ = fs::create_dir_all(state_root.join(sub));
    }
}

struct PreInstallEpochState<'a> {
    config_dir: &'a Path,
    stack_home: &'a Path,
    had_prior_v1_epoch: bool,
    had_existing_plugin: bool,
    pre_install_was_verified_v2: bool,
    prior_v2_digest: Option<&'a str>,
}

fn compensate_install_from_backup(
    pre: &PreInstallEpochState<'_>,
    backup_id_str: &str,
    drain_timeout: Duration,
    hooks_mutated: bool,
) -> bool {
    // INVARIANT: Restore pre-install files (`backup_id_str`), skip `hooks.json` rollback when `hooks_mutated == false` (install failed prior to replacing `hooks.json`), require zero `hooks_rollback_conflicts` when `hooks_mutated == true`, and restore the exact pre-install `.lock_epoch` before reporting `compensated_from_backup = true`.
    if backup_id_str.is_empty() {
        return false;
    }
    let rb = perform_rollback_internal(
        pre.config_dir,
        pre.stack_home,
        backup_id_str,
        RollbackOptions {
            drain_timeout,
            abort_after_plugin_restore: false,
            caller_holds_mutex: true,
            rollback_hooks: hooks_mutated,
        },
    );
    let no_hook_conflicts = rb
        .get("hooks_rollback_conflicts")
        .and_then(|v| v.as_array())
        .is_none_or(|a| a.is_empty());
    let rb_ok = rb.get("ok").and_then(|v| v.as_bool()) == Some(true) && no_hook_conflicts;
    let state_root = pre.stack_home.join("state");
    match pre.prior_v2_digest {
        Some(raw) => {
            let _ = write_v2_plugin_digest_raw(&state_root, raw);
        }
        None => remove_v2_plugin_digest(&state_root),
    }
    let should_keep_v1_epoch =
        pre.had_prior_v1_epoch || (pre.had_existing_plugin && !pre.pre_install_was_verified_v2);
    if should_keep_v1_epoch {
        rb_ok
    } else {
        let clear_ok = clear_v1_lock_epoch_checked(&state_root, drain_timeout).is_ok();
        rb_ok && clear_ok
    }
}

fn current_unix_bin_inode(target_plugin_dir: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(target_plugin_dir.join("bin").join("carbon-stack"))
            .ok()
            .map(|m| m.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = target_plugin_dir;
        None
    }
}

pub fn perform_install(
    repo_root: &Path,
    config_dir: &Path,
    stack_home: &Path,
    dry_run: bool,
    force_foreign: bool,
) -> Value {
    perform_install_with_drain_timeout(
        repo_root,
        config_dir,
        stack_home,
        dry_run,
        force_foreign,
        ROLLBACK_V2_DRAIN_TIMEOUT,
    )
}

pub(crate) fn perform_install_with_drain_timeout(
    repo_root: &Path,
    config_dir: &Path,
    stack_home: &Path,
    dry_run: bool,
    force_foreign: bool,
    drain_timeout: Duration,
) -> Value {
    let source_plugin_dir = repo_root.join("plugin");
    let source_glob_rule = repo_root.join("rules").join("uiux-design.md");
    let target_plugin_dir = config_dir.join("plugins").join(PLUGIN_NAME);
    let target_glob_rule = config_dir.join("rules").join("uiux-design.md");

    // INVARIANT: On non-dry-run installs, validate link/traversal safety, acquire `_inst_mutex`, and recover any interrupted `.carbon-stack-stage-retire-*` journal BEFORE `preflight_check_for_os_mode` so stranded user scripts (e.g. `hooks/Audit.py` after an interrupted POSIX contraction) are restored onto `target_plugin_dir` even if preflight subsequently rejects unmigrated hooks.
    let _inst_mutex = if !dry_run {
        if !validate_target_hierarchy(config_dir, &target_plugin_dir, &target_glob_rule).is_empty() {
            let pf = preflight_check_for_os_mode(repo_root, config_dir, cfg!(windows), dry_run);
            return json!({ "ok": false, "stage": "preflight", "preflight": pf });
        }
        if let Err(e) = validate_stack_home_preinstall(stack_home) {
            return json!({ "ok": false, "stage": "preflight", "error": e });
        }
        let guard = match acquire_installer_mutex(
            config_dir,
            stack_home,
            drain_timeout.max(Duration::from_secs(15)),
        ) {
            Ok(g) => g,
            Err(e) => return json!({ "ok": false, "stage": "installer_lock", "error": e }),
        };
        let pre_retire_state = stack_home.join("state").join(RETIRED_BINS_DIR_NAME);
        let pre_retire_cfg = config_dir.join(RETIRED_BINS_DIR_NAME);
        if let Err(e) =
            recover_interrupted_stage_retire_dirs(config_dir, &[&pre_retire_state, &pre_retire_cfg])
        {
            return json!({ "ok": false, "stage": "stage_retire_recovery", "error": e });
        }
        Some(guard)
    } else {
        None
    };

    let pf = preflight_check_for_os_mode(repo_root, config_dir, cfg!(windows), dry_run);
    if pf.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        return json!({ "ok": false, "stage": "preflight", "preflight": pf });
    }
    if dry_run {
        if let Err(e) = validate_stack_home_preinstall(stack_home) {
            return json!({ "ok": false, "stage": "preflight", "error": e });
        }
    }
    let bootstrap_build_req = pf
        .get("bootstrap_build_required")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if target_glob_rule.is_file() && !force_foreign {
        let txt = fs::read_to_string(&target_glob_rule).unwrap_or_default();
        if !txt.contains("Frontend UI/UX & Live Browser Verification Rules") {
            return json!({
                "ok": false,
                "stage": "conflict_check",
                "error": format!(
                    "Existing user file {} was not created by Gemini Carbon Stack. Refusing blind overwrite (pass --force-foreign to replace after backup).",
                    target_glob_rule.display()
                ),
            });
        }
    }

    let target_global_hooks = config_dir.join("hooks.json");
    let hooks_migration = match inspect_global_hooks_migration(
        config_dir,
        &target_plugin_dir,
        cfg!(windows),
    ) {
        Ok(m) => m,
        Err(e) => return json!({ "ok": false, "stage": "preflight", "error": e }),
    };

    let src_manifest = effective_source_manifest(&source_plugin_dir, cfg!(windows));
    let dst_manifest = tree_manifest(&target_plugin_dir);
    let src_rule_sha = sha256_file_full(&source_glob_rule).unwrap_or_default();
    let dst_rule_sha = if target_glob_rule.is_file() {
        sha256_file_full(&target_glob_rule).unwrap_or_default()
    } else {
        String::new()
    };

    let hook_exec_ok = has_executable_hook_mode_for_os(&target_plugin_dir, cfg!(windows));
    let plugin_identical = !bootstrap_build_req
        && src_manifest == dst_manifest
        && !dst_manifest.is_empty()
        && hook_exec_ok;
    let rule_identical = !src_rule_sha.is_empty() && src_rule_sha == dst_rule_sha;
    let hooks_identical = hooks_migration.is_none();

    let mut planned_actions: Vec<String> = Vec::new();
    if bootstrap_build_req {
        planned_actions.push(format!(
            "build native hook binary -> {}",
            source_plugin_dir
                .join(platform_hook_binary_rel(cfg!(windows)))
                .display()
        ));
    }
    if !plugin_identical {
        let verb = if target_plugin_dir.exists() {
            "update"
        } else {
            "install"
        };
        let planned_files_count = src_manifest.len() + usize::from(bootstrap_build_req);
        planned_actions.push(format!(
            "{} plugin bundle -> {} ({} files)",
            verb,
            target_plugin_dir.display(),
            planned_files_count
        ));
    }
    if !rule_identical {
        let verb = if target_glob_rule.exists() {
            "update"
        } else {
            "install"
        };
        planned_actions.push(format!(
            "{} glob rule -> {}",
            verb,
            target_glob_rule.display()
        ));
    }
    if !hooks_identical {
        planned_actions.push(format!(
            "migrate tokenade hook -> {}",
            target_global_hooks.display()
        ));
    }

    if dry_run {
        return json!({
            "ok": true,
            "dry_run": true,
            "already_up_to_date": planned_actions.is_empty(),
            "planned_actions": planned_actions,
            "preflight": pf,
        });
    }

    let state_root = stack_home.join("state");
    let had_existing_plugin = target_plugin_dir.exists();
    let had_prior_v1_epoch = fs::read_to_string(rio::lock_epoch_path(&state_root))
        .map(|s| s.trim() == "v1")
        .unwrap_or(false);
    let pre_install_was_verified_v2 =
        !had_prior_v1_epoch && is_verified_v2_plugin(&state_root, &dst_manifest);
    let prior_v2_digest = fs::read_to_string(v2_plugin_digest_path(&state_root)).ok();

    if plugin_identical && rule_identical && hooks_identical {
        let pre_pids = if !pre_install_was_verified_v2 {
            match snapshot_pre_cutover_plugin_pids(&target_plugin_dir, config_dir, &state_root) {
                Ok(m) => m,
                Err(e) => return json!({ "ok": false, "stage": "install_v1_quiesce", "error": e }),
            }
        } else {
            BTreeMap::new()
        };
        let cur_ino = current_unix_bin_inode(&target_plugin_dir);
        let roots = PluginProcRoots::new(
            &target_plugin_dir,
            config_dir,
            &state_root,
            !pre_install_was_verified_v2,
        );
        if let Err(e) = quiesce_and_clear_v1_lock_epoch(
            &roots,
            &state_root,
            &pre_pids,
            cur_ino,
            drain_timeout,
        ) {
            return json!({ "ok": false, "stage": "install_v1_quiesce", "error": e });
        }
        ensure_state_subdirs(stack_home);
        let _ = write_v2_plugin_digest(&state_root, &src_manifest);
        return json!({
            "ok": true,
            "dry_run": false,
            "already_up_to_date": true,
            "backup_id": Value::Null,
            "installed_plugin_dir": target_plugin_dir.to_string_lossy(),
            "installed_glob_rule": target_glob_rule.to_string_lossy(),
            "files_count": src_manifest.len() + 1,
        });
    }

    let backup_meta = match create_backup(config_dir, stack_home) {
        Ok(m) => m,
        Err(e) => return json!({ "ok": false, "stage": "backup", "error": e }),
    };
    let backup_id_str = backup_meta
        .get("backup_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // INVARIANT: Two-phase `v1 -> v2` migration contract: when migrating from legacy `v1` (or `.lock_epoch == "v1"`), fail closed if pre-cutover process inspection fails, commit `.lock_epoch = "v1"` under `.v2_alive.lease` `LOCK_EX` BEFORE writing `v2` binaries, and finally atomically verify zero `v1` processes/locks AND clear `.lock_epoch` inside a single `LOCK_EX` critical section.
    let migrating_from_v1 =
        (had_existing_plugin && !pre_install_was_verified_v2) || had_prior_v1_epoch;
    let pre_cutover_pids = if migrating_from_v1 && !plugin_identical {
        match snapshot_pre_cutover_plugin_pids(&target_plugin_dir, config_dir, &state_root) {
            Ok(m) => m,
            Err(e) => {
                return json!({
                    "ok": false,
                    "stage": "install_v1_quiesce",
                    "compensated_from_backup": true,
                    "error": e,
                });
            }
        }
    } else {
        BTreeMap::new()
    };
    if (had_existing_plugin && !pre_install_was_verified_v2 && !plugin_identical)
        || had_prior_v1_epoch
    {
        if let Err(busy_locks) = drain_and_sweep_v2_locks(&state_root, drain_timeout) {
            let names: Vec<String> = busy_locks.iter().map(|p| p.display().to_string()).collect();
            return json!({
                "ok": false,
                "stage": "install_lock_drain",
                "error": format!(
                    "Active v2 lock holders did not drain within {:?}: {}",
                    drain_timeout,
                    names.join(", ")
                ),
            });
        }
    }

    let retired_state = state_root.join(RETIRED_BINS_DIR_NAME);
    let retired_cfg = config_dir.join(RETIRED_BINS_DIR_NAME);
    let retire_dirs: [&Path; 2] = [&retired_state, &retired_cfg];
    let pre_epoch_state = PreInstallEpochState {
        config_dir,
        stack_home,
        had_prior_v1_epoch,
        had_existing_plugin,
        pre_install_was_verified_v2,
        prior_v2_digest: prior_v2_digest.as_deref(),
    };

    if !plugin_identical {
        if let Err(e) =
            copy_clean_tree_additive(&source_plugin_dir, &target_plugin_dir, cfg!(windows))
        {
            let comp_ok = compensate_install_from_backup(
                &pre_epoch_state,
                &backup_id_str,
                drain_timeout,
                false,
            );
            return json!({
                "ok": false,
                "stage": "copy_plugin",
                "compensated_from_backup": comp_ok,
                "error": e,
            });
        }
    }
    if !rule_identical {
        if let Err(e) = atomic_copy_file(&source_glob_rule, &target_glob_rule) {
            let comp_ok = compensate_install_from_backup(
                &pre_epoch_state,
                &backup_id_str,
                drain_timeout,
                false,
            );
            return json!({
                "ok": false,
                "stage": "copy_rule",
                "compensated_from_backup": comp_ok,
                "error": e,
            });
        }
    }
    let live_scope = HookInstanceScope {
        config_dir,
        target_plugin_dir: &target_plugin_dir,
        is_windows: cfg!(windows),
    };
    let mut hooks_mutated = false;
    let mut published_unreverted = false;
    match cas_update_hooks_file_tracking(
        &target_global_hooks,
        &mut published_unreverted,
        |live_raw| {
            let Some(plan) =
                parse_hooks_migration_from_str(live_raw, &target_global_hooks, live_scope)?
            else {
                sync_backup_manifest_hooks_migrations(stack_home, &backup_id_str, &[], None)?;
                return Ok(None);
            };
            let new_bytes = plan.rendered_json.into_bytes();
            let new_sha = rio::sha256_hex(&new_bytes);
            // INVARIANT: Persist surgical undo metadata (`migrations` + `post_install_sha256`) to `manifest.json` BEFORE `cas_update_hooks_file_tracking` renames `tmp` onto `hooks.json` (write-ahead undo log) so a manifest write failure aborts prior to modifying `hooks.json`, and any post-rename failure or crash already has `post_install_sha256` on disk.
            sync_backup_manifest_hooks_migrations(
                stack_home,
                &backup_id_str,
                &plan.migrations,
                Some(&new_sha),
            )?;
            Ok(Some((new_bytes, ())))
        },
    ) {
        Ok(Some(_)) => {
            hooks_mutated = true;
        }
        Ok(None) => {}
        Err(e) => {
            let comp_ok = if published_unreverted {
                let _ = compensate_install_from_backup(
                    &pre_epoch_state,
                    &backup_id_str,
                    drain_timeout,
                    true,
                );
                false
            } else {
                let _ = sync_backup_manifest_hooks_migrations(stack_home, &backup_id_str, &[], None);
                compensate_install_from_backup(
                    &pre_epoch_state,
                    &backup_id_str,
                    drain_timeout,
                    false,
                )
            };
            return json!({
                "ok": false,
                "stage": "migrate_global_hooks",
                "compensated_from_backup": comp_ok,
                "error": e,
            });
        }
    }

    let cur_v2_ino = current_unix_bin_inode(&target_plugin_dir);
    let proc_roots = PluginProcRoots::new(
        &target_plugin_dir,
        config_dir,
        &state_root,
        migrating_from_v1,
    );
    if let Err(e) = quiesce_and_clear_v1_lock_epoch(
        &proc_roots,
        &state_root,
        &pre_cutover_pids,
        cur_v2_ino,
        drain_timeout,
    ) {
        let comp_ok = compensate_install_from_backup(
            &pre_epoch_state,
            &backup_id_str,
            drain_timeout,
            hooks_mutated,
        );
        return json!({
            "ok": false,
            "stage": "install_v1_quiesce",
            "compensated_from_backup": comp_ok,
            "error": e,
        });
    }

    if !plugin_identical {
        // INVARIANT: Prune stale legacy `v1` files (`hooks/tokenade_hook.py`, etc.) ONLY AFTER `<config_dir>/hooks.json` has been switched to `bin/carbon-stack` AND in-flight `v1` processes have drained: on Windows when `hooks.json` exists, `acquire_hooks_read_share_guard` (`FILE_SHARE_READ`) mandatorily blocks concurrent writes/renames across pruning; where the OS lacks mandatory locks on uncreated/POSIX paths, `prune_plugin_tree_guarded_by_hooks` stages removed files in a sibling retiring dir before physical deletion, re-verifies `hooks.json`, and restores staged files on race.
        if let Err(e) = prune_plugin_tree_guarded_by_hooks(
            &source_plugin_dir,
            &target_plugin_dir,
            &target_global_hooks,
            live_scope,
            &retire_dirs,
        ) {
            let comp_ok = compensate_install_from_backup(
                &pre_epoch_state,
                &backup_id_str,
                drain_timeout,
                hooks_mutated,
            );
            return json!({
                "ok": false,
                "stage": "prune_legacy_plugin",
                "compensated_from_backup": comp_ok,
                "error": e,
            });
        }
    }

    ensure_state_subdirs(stack_home);
    let _ = write_v2_plugin_digest(&state_root, &tree_manifest(&target_plugin_dir));

    json!({
        "ok": true,
        "dry_run": false,
        "already_up_to_date": false,
        "backup_id": backup_meta.get("backup_id").cloned().unwrap_or(Value::Null),
        "installed_plugin_dir": target_plugin_dir.to_string_lossy(),
        "installed_glob_rule": target_glob_rule.to_string_lossy(),
        "files_count": src_manifest.len() + 1,
        "planned_actions": planned_actions,
    })
}

fn validate_legacy_plugin_snapshot(
    p_backup: &Path,
    actual_hashes: &BTreeMap<String, String>,
) -> Result<(), String> {
    if actual_hashes.is_empty() {
        return Err("Incomplete legacy backup: empty plugin_dir snapshot".to_string());
    }
    if !p_backup.join("rules").join("AGENTS.md").is_file() {
        return Err("Incomplete legacy backup: missing rules/AGENTS.md".to_string());
    }
    let Some(pjson) = rio::read_json(&p_backup.join("plugin.json")) else {
        return Err("Incomplete legacy backup: missing or invalid plugin.json".to_string());
    };
    if pjson.get("name").and_then(|v| v.as_str()) != Some(PLUGIN_NAME) {
        return Err("Invalid legacy backup: plugin.json name mismatch".to_string());
    }
    let Some(hjson) = rio::read_json(&p_backup.join("hooks.json")) else {
        return Err("Incomplete legacy backup: missing or invalid hooks.json".to_string());
    };
    let (hinfo, _, cmds_ok) =
        stack_doctor::inspect_hooks_json_for_os(p_backup, Some(&hjson), cfg!(windows));
    let events_ok = hinfo
        .get("missing_events")
        .and_then(|v| v.as_array())
        .map_or(false, |a| a.is_empty());
    if !cmds_ok || !events_ok {
        return Err("Incomplete legacy backup: hooks.json targets or events missing".to_string());
    }
    let hraw = hjson.to_string();
    if hraw.contains("bin/carbon-stack") || hraw.contains("bin\\carbon-stack") {
        let bin_p = p_backup.join(platform_hook_binary_rel(cfg!(windows)));
        let bin_ok = bin_p.is_file()
            && fs::metadata(&bin_p)
                .map(|m| m.len() > 0)
                .unwrap_or(false);
        if !bin_ok {
            return Err(format!(
                "Incomplete legacy backup: missing hook binary {}",
                bin_p.display()
            ));
        }
    }
    Ok(())
}

#[derive(Copy, Clone, Default)]
struct RollbackMutated {
    plugin: bool,
    rule: bool,
    hooks: bool,
}

struct RollbackStage<'a> {
    had_live_plugin: bool,
    expected_live_hashes: Option<&'a BTreeMap<String, String>>,
    had_live_rule: bool,
    expected_live_rule_sha: Option<&'a str>,
    had_live_hooks: bool,
    expected_live_hooks_sha: Option<&'a str>,
    had_prior_v1_epoch: bool,
    drain_timeout: Duration,
    config_dir: &'a Path,
    state_root: &'a Path,
    stage_root: &'a Path,
    stage_plugin: &'a Path,
    stage_rule: &'a Path,
    stage_hooks: &'a Path,
    p_target: &'a Path,
    r_target: &'a Path,
    h_target: &'a Path,
}

const STAGE_RETIRE_PREFIX: &str = ".carbon-stack-stage-retire-";
const STAGE_RETIRE_LOCK_NAME: &str = "active.lock";
const STAGE_RETIRE_JOURNAL_NAME: &str = "retire-journal.json";
static STAGE_RETIRE_SEQ: AtomicU64 = AtomicU64::new(1);

fn is_stage_control_name(name: &std::ffi::OsStr) -> bool {
    name == STAGE_RETIRE_LOCK_NAME || name == STAGE_RETIRE_JOURNAL_NAME
}

fn open_and_try_lock_stage_dir(stage_dir: &Path) -> Result<fs::File, String> {
    let lock_path = stage_dir.join(STAGE_RETIRE_LOCK_NAME);
    let lock_fh = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| format!("Cannot open {}: {}", lock_path.display(), e))?;
    lock_fh
        .try_lock()
        .map_err(|e| format!("Cannot lock {}: {}", lock_path.display(), e))?;
    Ok(lock_fh)
}

struct StageRetireLease {
    dir: PathBuf,
    lock_fh: Option<fs::File>,
}

struct StagePruneError {
    cause: String,
    preserve_stage: bool,
}

fn stale_scoped_py_rels_from_list(stale_rels: &[String], case_fold: bool) -> BTreeSet<String> {
    stale_rels
        .iter()
        .map(|r| norm_instance_path(r, case_fold))
        .filter(|norm| {
            matches_scoped_rel_for_kind(&format!("/{}", norm), ScopedTargetKind::LegacyPy)
        })
        .collect()
}

fn compute_stale_scoped_py_rels(
    src_tree: Option<&Path>,
    dst_tree: &Path,
    scope: HookInstanceScope<'_>,
) -> Result<BTreeSet<String>, String> {
    let case_fold = scope_case_fold(scope);
    let stale_rels = compute_stale_rel_paths(src_tree, dst_tree, cfg!(windows), case_fold)?;
    Ok(stale_scoped_py_rels_from_list(&stale_rels, case_fold))
}

fn write_stage_retire_journal(
    stage_dir: &Path,
    mode: &str,
    phase: &str,
    sentinel_hooks: bool,
) -> Result<(), String> {
    // INVARIANT: Store ONLY relative state-machine metadata (`mode`, `phase`, `sentinel_hooks`) — never serialized target paths — so journal recovery always derives destinations strictly under the active `config_dir`.
    let journal = json!({
        "version": 1,
        "pid": std::process::id(),
        "mode": mode,
        "phase": phase,
        "sentinel_hooks": sentinel_hooks,
    });
    rio::write_json(&stage_dir.join(STAGE_RETIRE_JOURNAL_NAME), &journal)
}

fn alloc_stage_retire_lease(
    config_dir: &Path,
    mode: &str,
    sentinel_hooks: bool,
) -> Result<StageRetireLease, String> {
    let seq = STAGE_RETIRE_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = config_dir.join(format!(
        "{}{}-{}-{}",
        STAGE_RETIRE_PREFIX,
        std::process::id(),
        nanos,
        seq
    ));
    fs::create_dir_all(&dir).map_err(|e| {
        format!(
            "Cannot create staging retire dir {}: {}",
            dir.display(),
            e
        )
    })?;
    let lock_fh = match open_and_try_lock_stage_dir(&dir) {
        Ok(fh) => fh,
        Err(e) => {
            let _ = fs::remove_dir_all(&dir);
            return Err(e);
        }
    };
    if let Err(e) = write_stage_retire_journal(&dir, mode, "contracting", sentinel_hooks) {
        drop(lock_fh);
        let _ = fs::remove_dir_all(&dir);
        return Err(format!(
            "Cannot write retire journal in {}: {}",
            dir.display(),
            e
        ));
    }
    Ok(StageRetireLease {
        dir,
        lock_fh: Some(lock_fh),
    })
}

fn remove_stage_entry(p: &Path, retire_dirs: &[&Path]) {
    if win32_sqlite::is_link_or_junction(p) {
        if fs::remove_file(p).is_err() {
            let _ = fs::remove_dir(p);
        }
    } else if p.is_dir() {
        let _ = remove_tree_or_retire_pe(p, retire_dirs);
    } else if is_windows_pe_path(p) {
        let _ = remove_file_or_retire_pe(p, retire_dirs);
    } else {
        let _ = fs::remove_file(p);
    }
}

fn stage_dir_only_control_entries(stage_dir: &Path) -> bool {
    let Ok(rd) = fs::read_dir(stage_dir) else {
        return false;
    };
    for ent_res in rd {
        let Ok(ent) = ent_res else {
            return false;
        };
        if !is_stage_control_name(&ent.file_name()) {
            return false;
        }
    }
    true
}

fn cleanup_stage_retire_dir(stage_dir: &Path, lock_fh: Option<fs::File>, retire_dirs: &[&Path]) {
    // INVARIANT: Hold `lock_fh` while removing payload entries (`files/`, `tree/`, etc.) and verify `stage_dir_only_control_entries(stage_dir)` (no remaining directory or file other than `retire-journal.json` / `active.lock`) BEFORE unlinking `retire-journal.json`, releasing `lock_fh`, unlinking `active.lock`, and removing `stage_dir`.
    if win32_sqlite::is_link_or_junction(stage_dir) {
        return;
    }
    if let Ok(rd) = fs::read_dir(stage_dir) {
        for ent in rd.flatten() {
            if is_stage_control_name(&ent.file_name()) {
                continue;
            }
            remove_stage_entry(&ent.path(), retire_dirs);
        }
    }
    if !stage_dir_only_control_entries(stage_dir) {
        return;
    }
    remove_stage_entry(&stage_dir.join(STAGE_RETIRE_JOURNAL_NAME), retire_dirs);
    drop(lock_fh);
    remove_stage_entry(&stage_dir.join(STAGE_RETIRE_LOCK_NAME), retire_dirs);
    let _ = fs::remove_dir(stage_dir);
}

fn finish_and_cleanup_stage_retire(mut lease: StageRetireLease, retire_dirs: &[&Path]) {
    let lock_fh = lease.lock_fh.take();
    cleanup_stage_retire_dir(&lease.dir, lock_fh, retire_dirs);
}

fn preserve_failed_stage_retire(mut lease: StageRetireLease) -> PathBuf {
    let _ = lease.lock_fh.take();
    lease.dir
}

fn commit_stage_retire_or_restore<F>(
    lease: StageRetireLease,
    mode: &str,
    retire_dirs: &[&Path],
    restore_fn: F,
) -> Result<(), String>
where
    F: FnOnce() -> Result<(), String>,
{
    // INVARIANT: Require `committed_delete` to be durably written BEFORE cleaning up `lease.dir` or returning `Ok(())`; if journal commit fails, roll back contraction via `restore_fn` and return `Err` so a partially remaining `contracting` journal can never resurrect deleted files after a reported success.
    if let Err(je) = write_stage_retire_journal(&lease.dir, mode, "committed_delete", false) {
        let _ = write_stage_retire_journal(&lease.dir, mode, "restoring", false);
        return match restore_fn() {
            Ok(()) => {
                finish_and_cleanup_stage_retire(lease, retire_dirs);
                Err(format!(
                    "Failed to commit stage-retire journal ({}); contraction rolled back",
                    je
                ))
            }
            Err(re) => {
                let preserved = preserve_failed_stage_retire(lease);
                Err(format!(
                    "Failed to commit stage-retire journal ({}) and failed to restore staged entries ({}); unrestored files preserved in {}",
                    je,
                    re,
                    preserved.display()
                ))
            }
        };
    }
    finish_and_cleanup_stage_retire(lease, retire_dirs);
    Ok(())
}

fn strict_stage_rel_files(root: &Path) -> Result<Vec<String>, String> {
    if win32_sqlite::is_link_or_junction(root) {
        return Err(format!(
            "Refusing symlink/junction inside stage-retire dir: {}",
            root.display()
        ));
    }
    let meta = match fs::symlink_metadata(root) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(format!(
                "Cannot stat stage-retire path {}: {}",
                root.display(),
                e
            ))
        }
    };
    if !meta.is_dir() {
        return Err(format!(
            "Unexpected non-directory stage-retire root: {}",
            root.display()
        ));
    }
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = fs::read_dir(&dir)
            .map_err(|e| format!("Cannot read stage-retire dir {}: {}", dir.display(), e))?;
        for ent_res in rd {
            let ent = ent_res
                .map_err(|e| format!("Cannot read entry in {}: {}", dir.display(), e))?;
            let p = ent.path();
            let ft = ent
                .file_type()
                .map_err(|e| format!("Cannot stat {}: {}", p.display(), e))?;
            if ft.is_symlink() || win32_sqlite::is_link_or_junction(&p) {
                return Err(format!(
                    "Refusing nested symlink/junction inside stage-retire dir: {}",
                    p.display()
                ));
            }
            if ft.is_dir() {
                stack.push(p);
            } else {
                let rel = p
                    .strip_prefix(root)
                    .map_err(|e| e.to_string())?
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push(rel);
            }
        }
    }
    out.sort();
    Ok(out)
}

fn dir_has_any_non_dir_or_link_strict(root: &Path) -> Result<bool, String> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = fs::read_dir(&dir)
            .map_err(|e| format!("Cannot inspect stage-retire dir {}: {}", dir.display(), e))?;
        for ent_res in rd {
            let ent = ent_res
                .map_err(|e| format!("Cannot read entry in {}: {}", dir.display(), e))?;
            let p = ent.path();
            let ft = ent
                .file_type()
                .map_err(|e| format!("Cannot stat {}: {}", p.display(), e))?;
            if ft.is_symlink() || win32_sqlite::is_link_or_junction(&p) {
                return Ok(true);
            }
            if ft.is_dir() {
                stack.push(p);
            } else {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn stage_dir_has_payload(stage_dir: &Path) -> Result<bool, String> {
    let rd = fs::read_dir(stage_dir)
        .map_err(|e| format!("Cannot inspect stage-retire dir {}: {}", stage_dir.display(), e))?;
    for ent_res in rd {
        let ent = ent_res
            .map_err(|e| format!("Cannot read entry in {}: {}", stage_dir.display(), e))?;
        if is_stage_control_name(&ent.file_name()) {
            continue;
        }
        let p = ent.path();
        let ft = ent
            .file_type()
            .map_err(|e| format!("Cannot stat {}: {}", p.display(), e))?;
        if ft.is_symlink() || win32_sqlite::is_link_or_junction(&p) {
            return Ok(true);
        }
        if !ft.is_dir() || dir_has_any_non_dir_or_link_strict(&p)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn restore_staged_prune_files(
    staged_files: &Path,
    dst_tree: &Path,
    moved_rels: &[String],
) -> Result<(), String> {
    // INVARIANT: Verify every nested path component of both `staged_files` and `dst_tree` via `ensure_no_links_between` (before and after `create_dir_all`), attempt every file in `moved_rels` without aborting on the first failure, and unlink each staged source ONLY after its destination is restored.
    if has_dot_components(staged_files)
        || has_dot_components(dst_tree)
        || win32_sqlite::is_link_or_junction(staged_files)
        || win32_sqlite::is_link_or_junction(dst_tree)
    {
        return Err(format!(
            "Refusing symlink/junction or traversal root during staged restore: {} -> {}",
            staged_files.display(),
            dst_tree.display()
        ));
    }
    if !dst_tree.exists() {
        fs::create_dir_all(dst_tree)
            .map_err(|e| format!("Cannot create {}: {}", dst_tree.display(), e))?;
    }
    if win32_sqlite::is_link_or_junction(dst_tree) || !dst_tree.is_dir() {
        return Err(format!(
            "Destination plugin root is not a regular directory: {}",
            dst_tree.display()
        ));
    }
    let mut errs: Vec<String> = Vec::new();
    for rel in moved_rels {
        let staged_file = staged_files.join(rel);
        if let Err(e) = ensure_no_links_between(staged_files, &staged_file) {
            errs.push(e);
            continue;
        }
        if !staged_file.is_file() {
            continue;
        }
        let dst_file = dst_tree.join(rel);
        if let Err(e) = ensure_no_links_between(dst_tree, &dst_file) {
            errs.push(e);
            continue;
        }
        if dst_file.is_dir() {
            errs.push(format!(
                "{}: destination path is an existing directory",
                dst_file.display()
            ));
            continue;
        }
        if let Some(parent) = dst_file.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                errs.push(format!("{}: {}", parent.display(), e));
                continue;
            }
        }
        if let Err(e) = ensure_no_links_between(dst_tree, &dst_file) {
            errs.push(e);
            continue;
        }
        if fs::rename(&staged_file, &dst_file).is_err() {
            match atomic_copy_file(&staged_file, &dst_file) {
                Ok(()) => {
                    let _ = fs::remove_file(&staged_file);
                }
                Err(e) => {
                    errs.push(format!("{}: {}", dst_file.display(), e));
                }
            }
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join("; "))
    }
}

fn restore_staged_full_tree(staged_tree: &Path, dst_tree: &Path) -> Result<(), String> {
    if has_dot_components(staged_tree)
        || has_dot_components(dst_tree)
        || win32_sqlite::is_link_or_junction(staged_tree)
        || win32_sqlite::is_link_or_junction(dst_tree)
    {
        return Err(format!(
            "Refusing symlink/junction or traversal root during staged tree restore: {} -> {}",
            staged_tree.display(),
            dst_tree.display()
        ));
    }
    let all_rels = strict_stage_rel_files(staged_tree)?;
    if all_rels.is_empty() {
        return Ok(());
    }
    if !dst_tree.exists() {
        if let Some(parent) = dst_tree.parent() {
            if win32_sqlite::is_link_or_junction(parent) {
                return Err(format!(
                    "Refusing symlink/junction parent directory: {}",
                    parent.display()
                ));
            }
            fs::create_dir_all(parent)
                .map_err(|e| format!("Cannot create {}: {}", parent.display(), e))?;
            if win32_sqlite::is_link_or_junction(parent) {
                return Err(format!(
                    "Refusing symlink/junction parent directory after create: {}",
                    parent.display()
                ));
            }
        }
        if !win32_sqlite::is_link_or_junction(dst_tree) && fs::rename(staged_tree, dst_tree).is_ok()
        {
            return Ok(());
        }
    }
    restore_staged_prune_files(staged_tree, dst_tree, &all_rels)
}

fn stage_retire_candidate_dirs(config_dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = fs::read_dir(config_dir) else {
        return Vec::new();
    };
    let mut candidates: Vec<PathBuf> = rd
        .flatten()
        .filter_map(|ent| {
            if !ent.file_name().to_string_lossy().starts_with(STAGE_RETIRE_PREFIX) {
                return None;
            }
            let p = ent.path();
            (!win32_sqlite::is_link_or_junction(&p) && p.is_dir()).then_some(p)
        })
        .collect();
    candidates.sort();
    candidates
}

fn list_orphaned_stage_retire_dirs(config_dir: &Path) -> Vec<String> {
    stage_retire_candidate_dirs(config_dir)
        .into_iter()
        .filter(|p| {
            match fs::OpenOptions::new()
                .read(true)
                .open(p.join(STAGE_RETIRE_LOCK_NAME))
            {
                Ok(fh) => fh.try_lock_shared().is_ok(),
                Err(_) => true,
            }
        })
        .map(|p| p.to_string_lossy().into_owned())
        .collect()
}

pub(crate) fn try_auto_heal_default_stage_retire() {
    let (cfg, shome) = resolve_paths("", "");
    if list_orphaned_stage_retire_dirs(&cfg).is_empty() {
        return;
    }
    let Ok(_guard) = acquire_installer_mutex(&cfg, &shome, Duration::from_secs(2)) else {
        return;
    };
    let ret_state = shome.join("state").join(RETIRED_BINS_DIR_NAME);
    let ret_cfg = cfg.join(RETIRED_BINS_DIR_NAME);
    let _ = recover_interrupted_stage_retire_dirs(&cfg, &[&ret_state, &ret_cfg]);
}

fn recover_interrupted_stage_retire_dirs(
    config_dir: &Path,
    retire_dirs: &[&Path],
) -> Result<(), String> {
    // INVARIANT: Derive `dst_tree` and `hooks_path` strictly from `config_dir`, preserve `<stage_dir>` and return `Err` on unreadable/corrupt journals or unknown `phase`/`mode` whenever payload exists, treat `phase == "committed_delete"` as cleanup-only, and treat `"contracting"` / `"restoring"` as a monotonic idempotent restore across retries without ever deleting `dst_tree`.
    if has_dot_components(config_dir) || win32_sqlite::is_link_or_junction(config_dir) {
        return Err(format!(
            "Refusing symlink/junction or traversal config_dir during stage-retire recovery: {}",
            config_dir.display()
        ));
    }
    let candidates = stage_retire_candidate_dirs(config_dir);
    if candidates.is_empty() {
        return Ok(());
    }
    let plugins_parent = config_dir.join("plugins");
    let dst_tree = plugins_parent.join(PLUGIN_NAME);
    let hooks_path = config_dir.join("hooks.json");
    if win32_sqlite::is_link_or_junction(&plugins_parent)
        || win32_sqlite::is_link_or_junction(&dst_tree)
        || win32_sqlite::is_link_or_junction(&hooks_path)
    {
        return Err(format!(
            "Refusing symlink/junction target under {} during stage-retire recovery",
            config_dir.display()
        ));
    }
    for stage_dir in candidates {
        let Ok(lock_fh) = open_and_try_lock_stage_dir(&stage_dir) else {
            continue;
        };
        let preserve_err = |fh: fs::File, msg: &str| -> Result<(), String> {
            drop(fh);
            Err(format!(
                "{}; staged directory preserved in {}",
                msg,
                stage_dir.display()
            ))
        };
        let journal_path = stage_dir.join(STAGE_RETIRE_JOURNAL_NAME);
        let Some(j) = rio::read_json(&journal_path) else {
            let has_payload = match stage_dir_has_payload(&stage_dir) {
                Ok(b) => b,
                Err(e) => return preserve_err(lock_fh, &e),
            };
            if !journal_path.exists() && !has_payload {
                cleanup_stage_retire_dir(&stage_dir, Some(lock_fh), retire_dirs);
                continue;
            }
            return preserve_err(lock_fh, "Missing or corrupt retire-journal.json");
        };
        let version = j.get("version").and_then(Value::as_u64);
        let mode = j.get("mode").and_then(Value::as_str).unwrap_or("");
        let phase = j.get("phase").and_then(Value::as_str).unwrap_or("");
        let sentinel_hooks_opt = j.get("sentinel_hooks").and_then(Value::as_bool);
        if version != Some(1)
            || !matches!(mode, "prune" | "remove")
            || !matches!(phase, "committed_delete" | "contracting" | "restoring")
            || sentinel_hooks_opt.is_none()
        {
            return preserve_err(
                lock_fh,
                &format!(
                    "Invalid retire-journal metadata (version={:?}, mode='{}', phase='{}')",
                    version, mode, phase
                ),
            );
        }
        if sentinel_hooks_opt == Some(true) {
            let _ = win32_sqlite::remove_file_if_exact_bytes(&hooks_path, HOOKS_SENTINEL_BYTES);
        }
        if phase == "committed_delete" {
            cleanup_stage_retire_dir(&stage_dir, Some(lock_fh), retire_dirs);
            continue;
        }
        if phase != "restoring" {
            if let Err(e) = write_stage_retire_journal(&stage_dir, mode, "restoring", false) {
                drop(lock_fh);
                return Err(format!(
                    "Cannot update retire-journal in {}: {}",
                    stage_dir.display(),
                    e
                ));
            }
        }
        if mode == "prune" {
            let staged_files = stage_dir.join("files");
            let staged_rels = match strict_stage_rel_files(&staged_files) {
                Ok(r) => r,
                Err(e) => {
                    return preserve_err(
                        lock_fh,
                        &format!("Failed to inspect stage-retire files ({})", e),
                    )
                }
            };
            if !staged_rels.is_empty() {
                if let Err(re) = restore_staged_prune_files(&staged_files, &dst_tree, &staged_rels)
                {
                    return preserve_err(
                        lock_fh,
                        &format!("Failed to recover interrupted stage-retire files ({})", re),
                    );
                }
            }
        } else {
            let staged_tree = stage_dir.join("tree");
            if let Err(re) = restore_staged_full_tree(&staged_tree, &dst_tree) {
                return preserve_err(
                    lock_fh,
                    &format!("Failed to recover interrupted stage-retire tree ({})", re),
                );
            }
        }
        if stage_dir_has_payload(&stage_dir).unwrap_or(true) {
            drop(lock_fh);
            return Err(format!(
                "Unrestored payload remains in {}; refusing to delete staging directory",
                stage_dir.display()
            ));
        }
        cleanup_stage_retire_dir(&stage_dir, Some(lock_fh), retire_dirs);
    }
    Ok(())
}

fn stage_prune_stale_tree_entries(
    src_tree: &Path,
    dst_tree: &Path,
    staged_files: &Path,
    stale_rels: &[String],
    retire_dirs: &[&Path],
) -> Result<Vec<String>, StagePruneError> {
    let mut moved_rels: Vec<String> = Vec::with_capacity(stale_rels.len());
    let fail_mid_prune =
        |err_msg: String, moved: &[String]| -> StagePruneError {
            match restore_staged_prune_files(staged_files, dst_tree, moved) {
                Ok(()) => StagePruneError {
                    cause: err_msg,
                    preserve_stage: false,
                },
                Err(re) => StagePruneError {
                    cause: format!("{}; partial rollback failure ({})", err_msg, re),
                    preserve_stage: true,
                },
            }
        };
    for rel in stale_rels {
        let stale = dst_tree.join(rel);
        if let Err(e) = ensure_no_links_between(dst_tree, &stale) {
            return Err(fail_mid_prune(e, &moved_rels));
        }
        if !stale.exists() {
            continue;
        }
        let staged_dst = staged_files.join(rel);
        if let Some(parent) = staged_dst.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                return Err(fail_mid_prune(e.to_string(), &moved_rels));
            }
        }
        if fs::rename(&stale, &staged_dst).is_err() {
            if let Err(e) = atomic_copy_file(&stale, &staged_dst)
                .and_then(|()| remove_file_or_retire_pe(&stale, retire_dirs))
            {
                return Err(fail_mid_prune(e, &moved_rels));
            }
        }
        moved_rels.push(rel.clone());
    }
    prune_stale_subdirs(src_tree, dst_tree);
    Ok(moved_rels)
}

fn verify_live_hooks_compatible_with_plugin_tree(
    hooks_path: &Path,
    scope: HookInstanceScope<'_>,
    previously_present_py: &BTreeSet<String>,
    target_tree: Option<&Path>,
) -> Result<(), String> {
    let Some(guard) = acquire_hooks_read_share_guard(hooks_path)? else {
        return Ok(());
    };
    verify_hooks_raw_compatible_with_plugin_tree(
        &guard.raw,
        hooks_path,
        scope,
        previously_present_py,
        target_tree,
    )
}

fn prune_plugin_tree_guarded_with_hook<H>(
    src_tree: &Path,
    dst_tree: &Path,
    hooks_path: &Path,
    scope: HookInstanceScope<'_>,
    retire_dirs: &[&Path],
    mut while_locked_hook: H,
) -> Result<(), String>
where
    H: FnMut(),
{
    // INVARIANT: Hold `acquire_hooks_read_share_guard_mode(..., true)` across verification, `while_locked_hook`, stage-pruning, and post-verification; re-verify live `hooks.json` immediately after `while_locked_hook`, persist monotonic `phase` transitions in `retire-journal.json`, and preserve `<stage_dir>` if restoration ever partially fails.
    let case_fold = scope_case_fold(scope);
    let stale_rels = compute_stale_rel_paths(Some(src_tree), dst_tree, cfg!(windows), case_fold)?;
    let prev_py = stale_scoped_py_rels_from_list(&stale_rels, case_fold);
    let guard = acquire_hooks_read_share_guard_mode(hooks_path, true)?;
    if let Some(ref g) = guard {
        verify_hooks_raw_compatible_with_plugin_tree(
            &g.raw,
            hooks_path,
            scope,
            &prev_py,
            Some(src_tree),
        )?;
    }
    while_locked_hook();
    verify_live_hooks_compatible_with_plugin_tree(hooks_path, scope, &prev_py, Some(src_tree))?;
    if stale_rels.is_empty() {
        prune_stale_subdirs(src_tree, dst_tree);
        let post_res = verify_live_hooks_compatible_with_plugin_tree(
            hooks_path,
            scope,
            &prev_py,
            Some(src_tree),
        );
        drop(guard);
        return post_res.map_err(|reason| {
            format!(
                "Concurrent global hooks.json edit introduced incompatible plugin reference during contraction ({})",
                reason
            )
        });
    }
    let sentinel_hooks = guard.as_ref().is_some_and(|g| g.created_sentinel);
    let lease = alloc_stage_retire_lease(scope.config_dir, "prune", sentinel_hooks)?;
    let staged_files = lease.dir.join("files");
    let prune_res =
        stage_prune_stale_tree_entries(src_tree, dst_tree, &staged_files, &stale_rels, retire_dirs);
    let moved_rels = match prune_res {
        Ok(m) => m,
        Err(pe) => {
            drop(guard);
            if pe.preserve_stage {
                let _ = write_stage_retire_journal(&lease.dir, "prune", "restoring", false);
                let preserved = preserve_failed_stage_retire(lease);
                return Err(format!(
                    "{}; unrestored files preserved in {}",
                    pe.cause,
                    preserved.display()
                ));
            }
            finish_and_cleanup_stage_retire(lease, retire_dirs);
            return Err(pe.cause);
        }
    };
    let post_res =
        verify_live_hooks_compatible_with_plugin_tree(hooks_path, scope, &prev_py, Some(src_tree));
    drop(guard);
    if let Err(reason) = post_res {
        let _ = write_stage_retire_journal(&lease.dir, "prune", "restoring", false);
        match restore_staged_prune_files(&staged_files, dst_tree, &moved_rels) {
            Ok(()) => {
                finish_and_cleanup_stage_retire(lease, retire_dirs);
                return Err(format!(
                    "Concurrent global hooks.json edit introduced incompatible plugin reference during contraction ({})",
                    reason
                ));
            }
            Err(re) => {
                let preserved = preserve_failed_stage_retire(lease);
                return Err(format!(
                    "Concurrent global hooks.json edit ({}); failed to restore staged plugin files ({}); unrestored files preserved in {}",
                    reason,
                    re,
                    preserved.display()
                ));
            }
        }
    }
    commit_stage_retire_or_restore(lease, "prune", retire_dirs, || {
        restore_staged_prune_files(&staged_files, dst_tree, &moved_rels)
    })
}

fn prune_plugin_tree_guarded_by_hooks(
    src_tree: &Path,
    dst_tree: &Path,
    hooks_path: &Path,
    scope: HookInstanceScope<'_>,
    retire_dirs: &[&Path],
) -> Result<(), String> {
    prune_plugin_tree_guarded_with_hook(src_tree, dst_tree, hooks_path, scope, retire_dirs, || {})
}

fn prune_rollback_tree_guarded_by_hooks(
    p_backup: &Path,
    p_target: &Path,
    hooks_path: &Path,
    scope: HookInstanceScope<'_>,
    retire_dirs: &[&Path],
) -> Result<(), String> {
    prune_plugin_tree_guarded_with_hook(p_backup, p_target, hooks_path, scope, retire_dirs, || {})
}

fn remove_rollback_tree_guarded_with_hook<H>(
    p_target: &Path,
    hooks_path: &Path,
    scope: HookInstanceScope<'_>,
    retire_dirs: &[&Path],
    mut while_locked_hook: H,
) -> Result<(), String>
where
    H: FnMut(),
{
    if win32_sqlite::is_link_or_junction(p_target) {
        return Err(format!(
            "Refusing symlink/junction plugin directory: {}",
            p_target.display()
        ));
    }
    let case_fold = scope_case_fold(scope);
    let stale_rels = compute_stale_rel_paths(None, p_target, cfg!(windows), case_fold)?;
    let prev_py = stale_scoped_py_rels_from_list(&stale_rels, case_fold);
    let guard = acquire_hooks_read_share_guard_mode(hooks_path, true)?;
    if let Some(ref g) = guard {
        verify_hooks_raw_compatible_with_plugin_tree(&g.raw, hooks_path, scope, &prev_py, None)?;
    }
    while_locked_hook();
    verify_live_hooks_compatible_with_plugin_tree(hooks_path, scope, &prev_py, None)?;
    if !p_target.exists() {
        let post_res =
            verify_live_hooks_compatible_with_plugin_tree(hooks_path, scope, &prev_py, None);
        drop(guard);
        return post_res.map_err(|reason| {
            format!(
                "Concurrent global hooks.json edit introduced incompatible plugin reference during contraction ({})",
                reason
            )
        });
    }
    let sentinel_hooks = guard.as_ref().is_some_and(|g| g.created_sentinel);
    let lease = alloc_stage_retire_lease(scope.config_dir, "remove", sentinel_hooks)?;
    let staged_tree = lease.dir.join("tree");
    if fs::rename(p_target, &staged_tree).is_err() {
        if let Err(e) = copy_clean_tree_for_os(p_target, &staged_tree, cfg!(windows)) {
            drop(guard);
            finish_and_cleanup_stage_retire(lease, retire_dirs);
            return Err(e);
        }
        let rm_err = match remove_tree_or_retire_pe(p_target, retire_dirs) {
            Ok(()) if p_target.exists() => {
                Some(format!("Plugin directory still exists: {}", p_target.display()))
            }
            Ok(()) => None,
            Err(e) => Some(e.to_string()),
        };
        if let Some(e) = rm_err {
            drop(guard);
            let _ = write_stage_retire_journal(&lease.dir, "remove", "restoring", false);
            match restore_staged_full_tree(&staged_tree, p_target) {
                Ok(()) => {
                    finish_and_cleanup_stage_retire(lease, retire_dirs);
                    return Err(e);
                }
                Err(re) => {
                    let preserved = preserve_failed_stage_retire(lease);
                    return Err(format!(
                        "{}; failed to restore staged plugin directory ({}); unrestored files preserved in {}",
                        e,
                        re,
                        preserved.display()
                    ));
                }
            }
        }
    }
    let post_res =
        verify_live_hooks_compatible_with_plugin_tree(hooks_path, scope, &prev_py, None);
    drop(guard);
    if let Err(reason) = post_res {
        let _ = write_stage_retire_journal(&lease.dir, "remove", "restoring", false);
        match restore_staged_full_tree(&staged_tree, p_target) {
            Ok(()) => {
                finish_and_cleanup_stage_retire(lease, retire_dirs);
                return Err(format!(
                    "Concurrent global hooks.json edit introduced incompatible plugin reference during contraction ({})",
                    reason
                ));
            }
            Err(re) => {
                let preserved = preserve_failed_stage_retire(lease);
                return Err(format!(
                    "Concurrent global hooks.json edit ({}); failed to restore staged plugin directory ({}); unrestored files preserved in {}",
                    reason,
                    re,
                    preserved.display()
                ));
            }
        }
    }
    commit_stage_retire_or_restore(lease, "remove", retire_dirs, || {
        restore_staged_full_tree(&staged_tree, p_target)
    })
}

fn remove_plugin_tree_guarded_by_hooks(
    dst_tree: &Path,
    hooks_path: &Path,
    scope: HookInstanceScope<'_>,
    retire_dirs: &[&Path],
) -> Result<(), String> {
    remove_rollback_tree_guarded_with_hook(dst_tree, hooks_path, scope, retire_dirs, || {})
}

fn compensate_plugin_rollback(
    st: &RollbackStage<'_>,
    mutated: RollbackMutated,
    mut resp: Value,
) -> Value {
    // INVARIANT: Verify that compensating restore matches pre-rollback `expected_live_hashes`, `expected_live_rule_sha`, and `expected_live_hooks_sha`, never prunes `(hooks|tools)/*.py` or `bin/carbon-stack` referenced by `<config_dir>/hooks.json` (both pre-prune and at final completion), preserves unrestored snapshots on error, and atomically quiesces `v1` processes/locks before clearing `.lock_epoch`.
    let retired_state = st.state_root.join(RETIRED_BINS_DIR_NAME);
    let retired_cfg = st.config_dir.join(RETIRED_BINS_DIR_NAME);
    let retire_dirs: [&Path; 2] = [&retired_state, &retired_cfg];
    let comp_scope = HookInstanceScope {
        config_dir: st.config_dir,
        target_plugin_dir: st.p_target,
        is_windows: cfg!(windows),
    };
    let mut comp_ok = true;
    let mut comp_err = String::new();
    let mut keep_pre_comp_stage = false;
    let pre_comp_py_rels = compute_stale_scoped_py_rels(
        st.had_live_plugin.then_some(st.stage_plugin),
        st.p_target,
        comp_scope,
    )
    .unwrap_or_default();
    let pre_comp_target_stage = st.stage_root.join("pre_comp_target");
    let had_pre_comp_target = st.p_target.exists()
        && copy_clean_tree_for_os(st.p_target, &pre_comp_target_stage, cfg!(windows)).is_ok();
    let pre_comp_v1_pids = if mutated.plugin && !st.had_prior_v1_epoch {
        snapshot_pre_cutover_plugin_pids(st.p_target, st.config_dir, st.state_root)
    } else {
        Ok(BTreeMap::new())
    };
    if st.had_live_plugin {
        let restore_tree_res = copy_clean_tree_additive(st.stage_plugin, st.p_target, true)
            .and_then(|()| {
                prune_plugin_tree_guarded_by_hooks(
                    st.stage_plugin,
                    st.p_target,
                    st.h_target,
                    comp_scope,
                    &retire_dirs,
                )
            });
        match restore_tree_res {
            Ok(()) => {
                let st_map = tree_manifest_strict(st.stage_plugin);
                let live_map = tree_manifest_strict(st.p_target);
                match (st_map, live_map) {
                    (Ok(sm), Ok(lm))
                        if sm == lm
                            && st.expected_live_hashes.map_or(true, |exp| &lm == exp) => {}
                    (Err(e), _) | (_, Err(e)) => {
                        comp_ok = false;
                        comp_err = e;
                    }
                    _ => {
                        comp_ok = false;
                        comp_err = "Compensated plugin manifest mismatch".to_string();
                    }
                }
            }
            Err(e) => {
                remove_v2_plugin_digest(st.state_root);
                comp_ok = false;
                comp_err = e;
            }
        }
    } else if st.p_target.exists() {
        if let Err(e) =
            remove_plugin_tree_guarded_by_hooks(st.p_target, st.h_target, comp_scope, &retire_dirs)
        {
            remove_v2_plugin_digest(st.state_root);
            comp_ok = false;
            comp_err = e;
        }
    }

    if comp_ok && mutated.rule {
        if st.had_live_rule {
            match atomic_copy_file(st.stage_rule, st.r_target) {
                Ok(()) => match sha256_file_full(st.r_target) {
                    Ok(actual_sha)
                        if st.expected_live_rule_sha.map_or(true, |exp| actual_sha == exp) => {}
                    Ok(_) => {
                        comp_ok = false;
                        comp_err = "Compensated rule SHA-256 mismatch".to_string();
                    }
                    Err(e) => {
                        comp_ok = false;
                        comp_err = e;
                    }
                },
                Err(e) => {
                    comp_ok = false;
                    comp_err = e;
                }
            }
        } else if st.r_target.exists() {
            if let Err(e) = fs::remove_file(st.r_target) {
                comp_ok = false;
                comp_err = e.to_string();
            } else if st.r_target.exists() {
                comp_ok = false;
                comp_err = format!("Rule file still exists: {}", st.r_target.display());
            }
        }
    }

    if comp_ok && mutated.hooks {
        if st.had_live_hooks {
            match atomic_copy_file(st.stage_hooks, st.h_target) {
                Ok(()) => match sha256_file_full(st.h_target) {
                    Ok(actual_sha)
                        if st
                            .expected_live_hooks_sha
                            .map_or(true, |exp| actual_sha == exp) => {}
                    Ok(_) => {
                        comp_ok = false;
                        comp_err = "Compensated global hooks.json SHA-256 mismatch".to_string();
                    }
                    Err(e) => {
                        comp_ok = false;
                        comp_err = e;
                    }
                },
                Err(e) => {
                    comp_ok = false;
                    comp_err = e;
                }
            }
        } else if st.h_target.exists() {
            if let Err(e) = fs::remove_file(st.h_target) {
                comp_ok = false;
                comp_err = e.to_string();
            } else if st.h_target.exists() {
                comp_ok = false;
                comp_err = format!("Global hooks.json still exists: {}", st.h_target.display());
            }
        }
    }

    if comp_ok && !st.had_prior_v1_epoch {
        match pre_comp_v1_pids {
            Ok(ref pids) => {
                let roots = PluginProcRoots::new(
                    st.p_target,
                    st.config_dir,
                    st.state_root,
                    mutated.plugin,
                );
                let cur_ino = current_unix_bin_inode(st.p_target);
                if let Err(e) = quiesce_and_clear_v1_lock_epoch(
                    &roots,
                    st.state_root,
                    pids,
                    cur_ino,
                    st.drain_timeout,
                ) {
                    comp_ok = false;
                    comp_err = e;
                }
            }
            Err(e) => {
                comp_ok = false;
                comp_err = e;
            }
        }
    }

    if comp_ok {
        if let Err(reason) = verify_live_hooks_compatible_with_plugin_tree(
            st.h_target,
            comp_scope,
            &pre_comp_py_rels,
            st.had_live_plugin.then_some(st.stage_plugin),
        ) {
            let mut restore_note = String::new();
            if had_pre_comp_target {
                if let Err(re) = restore_staged_full_tree(&pre_comp_target_stage, st.p_target) {
                    keep_pre_comp_stage = true;
                    restore_note = format!(
                        "; failed to restore pre-compensation target ({}); unrestored files preserved in {}",
                        re,
                        pre_comp_target_stage.display()
                    );
                }
            }
            remove_v2_plugin_digest(st.state_root);
            comp_ok = false;
            comp_err = format!(
                "Concurrent global hooks.json edit introduced incompatible plugin reference during compensation ({}){}",
                reason, restore_note
            );
        }
    }

    if comp_ok {
        let _ = fs::remove_dir_all(st.stage_root);
        if let Some(obj) = resp.as_object_mut() {
            obj.insert("compensated_plugin_restore".to_string(), Value::Bool(true));
        }
    } else if let Some(obj) = resp.as_object_mut() {
        obj.insert("compensated_plugin_restore".to_string(), Value::Bool(false));
        obj.insert("restore_error".to_string(), Value::String(comp_err));
        if st.had_live_plugin && st.stage_plugin.exists() {
            obj.insert(
                "recovery_snapshot_path".to_string(),
                Value::String(st.stage_plugin.to_string_lossy().into_owned()),
            );
        } else if keep_pre_comp_stage && pre_comp_target_stage.exists() {
            obj.insert(
                "recovery_snapshot_path".to_string(),
                Value::String(pre_comp_target_stage.to_string_lossy().into_owned()),
            );
        } else {
            let _ = fs::remove_dir_all(st.stage_root);
        }
    }
    resp
}

fn compensate_rollback_after_unreverted_hooks(
    rb_stage: &RollbackStage<'_>,
    rb_scope: HookInstanceScope<'_>,
    p_existed: bool,
    after_rule_mutated: RollbackMutated,
    mut base_err: Value,
) -> Value {
    // INVARIANT: When `rollback_hooks_restore` published the rolled-back `v1` hook command onto `<config_dir>/hooks.json` and reverse-swap failed (or a later rollback stage failed after `hooks.json` switched to `v1`), first try surgical CAS forward-migration back to `v2`; `compensate_plugin_rollback` then guards `p_target` pruning under `acquire_hooks_read_share_guard`.
    let mut remig_unrev = false;
    let remig_res = cas_update_hooks_file_tracking(
        rb_stage.h_target,
        &mut remig_unrev,
        |live_raw| {
            let Some(plan) = parse_hooks_migration_from_str(live_raw, rb_stage.h_target, rb_scope)?
            else {
                return Ok(None);
            };
            Ok(Some((plan.rendered_json.into_bytes(), ())))
        },
    );
    let hooks_clean_for_v2 = remig_res.is_ok()
        && !remig_unrev
        && verify_live_hooks_free_of_scoped_py(rb_stage.h_target, rb_scope).is_ok();
    if hooks_clean_for_v2 {
        return compensate_plugin_rollback(rb_stage, after_rule_mutated, base_err);
    }
    if p_existed {
        remove_v2_plugin_digest(rb_stage.state_root);
        if let Some(obj) = base_err.as_object_mut() {
            obj.insert("compensated_plugin_restore".to_string(), Value::Bool(false));
            obj.insert(
                "restore_error".to_string(),
                Value::String(
                    "Global hooks.json published legacy hook command and could not be reverted to v2; kept v1 plugin files in place so active hooks remain runnable"
                        .to_string(),
                ),
            );
            if rb_stage.had_live_plugin && rb_stage.stage_plugin.exists() {
                obj.insert(
                    "recovery_snapshot_path".to_string(),
                    Value::String(rb_stage.stage_plugin.to_string_lossy().into_owned()),
                );
            } else {
                let _ = fs::remove_dir_all(rb_stage.stage_root);
            }
        }
        return base_err;
    }
    let mut out = compensate_plugin_rollback(rb_stage, after_rule_mutated, base_err);
    if let Some(obj) = out.as_object_mut() {
        obj.insert("compensated_plugin_restore".to_string(), Value::Bool(false));
        obj.entry("restore_error".to_string()).or_insert_with(|| {
            Value::String(
                "Global hooks.json published rolled-back hook command and could not be reverted"
                    .to_string(),
            )
        });
    }
    out
}

fn is_safe_backup_id(id: &str) -> bool {
    if id.is_empty()
        || id == "."
        || id == ".."
        || id.contains('/')
        || id.contains('\\')
        || id.contains(':')
        || id.contains('\0')
    {
        return false;
    }
    let mut comps = Path::new(id).components();
    matches!(comps.next(), Some(std::path::Component::Normal(_))) && comps.next().is_none()
}

fn validate_backups_root_strict(stack_home: &Path) -> Result<Option<PathBuf>, String> {
    if has_dot_components(stack_home) {
        return Err(format!(
            "Refusing relative dot/parent traversal in stack_home: {}",
            stack_home.display()
        ));
    }
    if win32_sqlite::is_link_or_junction(stack_home) {
        return Err(format!(
            "Invalid stack_home (refusing symlink/junction): {}",
            stack_home.display()
        ));
    }
    match fs::symlink_metadata(stack_home) {
        Ok(meta) if !meta.is_dir() => {
            return Err(format!(
                "Invalid stack_home (not a directory): {}",
                stack_home.display()
            ));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(format!(
                "Cannot inspect stack_home {}: {}",
                stack_home.display(),
                e
            ));
        }
    }
    let broot = stack_home.join("backups");
    if win32_sqlite::is_link_or_junction(&broot) {
        return Err(format!(
            "Invalid backups directory (refusing symlink/junction): {}",
            broot.display()
        ));
    }
    match fs::symlink_metadata(&broot) {
        Ok(meta) if !meta.is_dir() => Err(format!(
            "Invalid backups path (not a directory): {}",
            broot.display()
        )),
        Ok(_) => Ok(Some(broot)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!(
            "Cannot inspect backups directory {}: {}",
            broot.display(),
            e
        )),
    }
}

fn validate_stack_home_preinstall(stack_home: &Path) -> Result<(), String> {
    validate_backups_root_strict(stack_home)?;
    let state_dir = stack_home.join("state");
    if win32_sqlite::is_link_or_junction(&state_dir) {
        return Err(format!(
            "Invalid state directory (refusing symlink/junction): {}",
            state_dir.display()
        ));
    }
    match fs::symlink_metadata(&state_dir) {
        Ok(meta) if !meta.is_dir() => Err(format!(
            "Invalid state path (not a directory): {}",
            state_dir.display()
        )),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!(
            "Cannot inspect state directory {}: {}",
            state_dir.display(),
            e
        )),
    }
}

fn validate_backup_entry_strict(p: &Path) -> Result<bool, String> {
    if win32_sqlite::is_link_or_junction(p) {
        return Err(format!(
            "Refusing symlink/junction inside backups directory: {}",
            p.display()
        ));
    }
    let p_meta = fs::symlink_metadata(p)
        .map_err(|e| format!("Cannot inspect backup entry {}: {}", p.display(), e))?;
    if !p_meta.is_dir() {
        return Ok(false);
    }
    let mf_path = p.join("manifest.json");
    if win32_sqlite::is_link_or_junction(&mf_path) {
        return Err(format!(
            "Refusing symlink/junction backup manifest: {}",
            mf_path.display()
        ));
    }
    match fs::symlink_metadata(&mf_path) {
        Ok(mf_meta) if mf_meta.is_file() => {
            // INVARIANT: Verify `manifest.json` can actually be opened for reading so an unreadable/locked newest backup fails closed instead of silently falling back to an older backup on `--rollback latest`.
            fs::File::open(&mf_path)
                .map_err(|e| format!("Cannot open backup manifest {}: {}", mf_path.display(), e))?;
            Ok(true)
        }
        Ok(_) => Err(format!(
            "Invalid backup manifest (not a regular file): {}",
            mf_path.display()
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!(
            "Cannot inspect backup manifest {}: {}",
            mf_path.display(),
            e
        )),
    }
}

pub fn list_backups_strict(stack_home: &Path) -> Result<Vec<PathBuf>, String> {
    let Some(broot) = validate_backups_root_strict(stack_home)? else {
        return Ok(Vec::new());
    };
    let rd = fs::read_dir(&broot)
        .map_err(|e| format!("Cannot read backups directory {}: {}", broot.display(), e))?;
    let mut out: Vec<PathBuf> = Vec::new();
    for ent_res in rd {
        let ent = ent_res.map_err(|e| {
            format!(
                "Directory entry read failed in {}: {}",
                broot.display(),
                e
            )
        })?;
        let p = ent.path();
        if validate_backup_entry_strict(&p)? {
            out.push(p);
        }
    }
    out.sort();
    Ok(out)
}

pub fn perform_rollback(config_dir: &Path, stack_home: &Path, backup_selector: &str) -> Value {
    perform_rollback_with_drain_timeout(
        config_dir,
        stack_home,
        backup_selector,
        ROLLBACK_V2_DRAIN_TIMEOUT,
    )
}

pub(crate) fn perform_rollback_with_drain_timeout(
    config_dir: &Path,
    stack_home: &Path,
    backup_selector: &str,
    drain_timeout: Duration,
) -> Value {
    perform_rollback_with_hooks(
        config_dir,
        stack_home,
        backup_selector,
        drain_timeout,
        false,
    )
}

#[derive(Clone, Copy)]
struct RollbackOptions {
    drain_timeout: Duration,
    abort_after_plugin_restore: bool,
    caller_holds_mutex: bool,
    rollback_hooks: bool,
}

pub(crate) fn perform_rollback_with_hooks(
    config_dir: &Path,
    stack_home: &Path,
    backup_selector: &str,
    drain_timeout: Duration,
    abort_after_plugin_restore: bool,
) -> Value {
    perform_rollback_internal(
        config_dir,
        stack_home,
        backup_selector,
        RollbackOptions {
            drain_timeout,
            abort_after_plugin_restore,
            caller_holds_mutex: false,
            rollback_hooks: true,
        },
    )
}

fn revert_native_commands_to_legacy_py(
    val: &mut Value,
    scope: HookInstanceScope<'_>,
    py_cmd: &str,
) -> usize {
    let mut count = 0usize;
    match val {
        Value::Object(map) => {
            if let Some(Value::String(cur)) = map.get_mut("command") {
                let is_native = split_simple_hook_tokens(cur)
                    .as_deref()
                    .map_or(false, |t| is_managed_native_carbon_tokenade_command(t, scope));
                if is_native && cur != py_cmd {
                    *cur = py_cmd.to_string();
                    count += 1;
                }
            }
            for (k, child) in map.iter_mut() {
                if k == "command" && child.is_string() {
                    continue;
                }
                count += revert_native_commands_to_legacy_py(child, scope, py_cmd);
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                count += revert_native_commands_to_legacy_py(item, scope, py_cmd);
            }
        }
        _ => {}
    }
    count
}

#[derive(Default)]
struct ExtractedRollbackHooks {
    migrations: Vec<GlobalHookMigration>,
    post_install_sha256: Option<String>,
    is_legacy_untracked: bool,
}

fn matches_pinned_target_path(raw: &str, target: &Path) -> bool {
    !raw.is_empty()
        && !has_dot_components(Path::new(raw))
        && rio::normalize_path(raw) == rio::normalize_path(&target.to_string_lossy())
}

fn opt_sha256_migration_field(item: &Value, key: &str) -> Result<String, String> {
    match item.get(key) {
        Some(Value::String(s)) if s.is_empty() || is_valid_sha256_hex(s) => Ok(s.clone()),
        Some(_) => Err(format!(
            "Invalid backup manifest.json: malformed `{}` in `global_hooks.migrations`",
            key
        )),
        None => Ok(String::new()),
    }
}

fn pointer_event_prefix(pointer: &str) -> String {
    let mut parts = pointer.trim_start_matches('/').split('/');
    let g = parts.next().unwrap_or("");
    let e = parts.next().unwrap_or("");
    format!("/{}/{}", g, e)
}

fn extract_rollback_hooks_migrations(
    h_info: Option<&Value>,
    h_target: &Path,
    h_backup: &Path,
    scope: HookInstanceScope<'_>,
) -> Result<ExtractedRollbackHooks, String> {
    // INVARIANT: Validate `global_hooks` path pinning and extract surgical command-pointer migrations (`pointer`, `before`, `after`, `context_sha256`, `post_install_sha256`) so rollback never deletes `<config_dir>/hooks.json` or overwrites reordered/edited user entries.
    let Some(hi) = h_info else {
        return Ok(ExtractedRollbackHooks {
            is_legacy_untracked: true,
            ..ExtractedRollbackHooks::default()
        });
    };
    let mh_raw = hi.get("path").and_then(|v| v.as_str()).unwrap_or("");
    if !matches_pinned_target_path(mh_raw, h_target) {
        return Err("Invalid backup manifest.json: global_hooks path mismatch".to_string());
    }
    let post_sha = match hi.get("post_install_sha256") {
        Some(Value::String(s)) if is_valid_sha256_hex(s) => Some(s.clone()),
        Some(_) => {
            return Err(
                "Invalid backup manifest.json: malformed `global_hooks.post_install_sha256`"
                    .to_string(),
            );
        }
        None => None,
    };
    if let Some(migs_val) = hi.get("migrations") {
        let Some(arr) = migs_val.as_array() else {
            return Err(
                "Invalid backup manifest.json: malformed `global_hooks.migrations` array"
                    .to_string(),
            );
        };
        let mut out = Vec::with_capacity(arr.len());
        for item in arr {
            let ptr = item.get("pointer").and_then(|v| v.as_str());
            let bef = item.get("before").and_then(|v| v.as_str());
            let aft = item.get("after").and_then(|v| v.as_str());
            let (Some(pointer), Some(before), Some(after)) = (ptr, bef, aft) else {
                return Err(
                    "Invalid backup manifest.json: malformed `global_hooks.migrations` entry"
                        .to_string(),
                );
            };
            if !pointer.is_empty() && !pointer.starts_with('/') {
                return Err(
                    "Invalid backup manifest.json: invalid JSON pointer in `global_hooks.migrations`"
                        .to_string(),
                );
            }
            let ctx_sha = opt_sha256_migration_field(item, "context_sha256")?;
            let peer_sha = opt_sha256_migration_field(item, "peer_set_sha256")?;
            let ambig_peer = match item.get("has_ambiguous_peer") {
                Some(Value::Bool(b)) => *b,
                Some(_) => {
                    return Err(
                        "Invalid backup manifest.json: malformed `has_ambiguous_peer` in `global_hooks.migrations`"
                            .to_string(),
                    );
                }
                None => false,
            };
            out.push(GlobalHookMigration {
                pointer: pointer.to_string(),
                before: before.to_string(),
                after: after.to_string(),
                context_sha256: ctx_sha,
                peer_set_sha256: peer_sha,
                has_ambiguous_peer: ambig_peer,
            });
        }
        return Ok(ExtractedRollbackHooks {
            migrations: out,
            post_install_sha256: post_sha,
            is_legacy_untracked: false,
        });
    }
    let Some(hex) = hi.get("existed").and_then(|v| v.as_bool()) else {
        return Err(
            "Invalid backup manifest.json: missing `global_hooks.migrations` or `existed`"
                .to_string(),
        );
    };
    if !hex {
        return Ok(ExtractedRollbackHooks::default());
    }
    if !h_backup.is_file() {
        return Err(format!(
            "Incomplete backup: missing global_hooks snapshot {}",
            h_backup.display()
        ));
    }
    let raw_bak_bytes =
        fs::read(h_backup).map_err(|_| "Failed to hash global_hooks backup snapshot".to_string())?;
    let actual_h_sha = rio::sha256_hex(&raw_bak_bytes);
    match hi.get("sha256") {
        Some(Value::String(exp_h_sha)) if is_valid_sha256_hex(exp_h_sha) => {
            if actual_h_sha != *exp_h_sha {
                return Err("Corrupted backup: global_hooks snapshot SHA-256 mismatch".to_string());
            }
        }
        Some(_) => {
            return Err(
                "Invalid backup manifest.json: malformed global_hooks `sha256` digest".to_string(),
            );
        }
        None => {}
    }
    let raw_bak = std::str::from_utf8(&raw_bak_bytes)
        .map_err(|e| format!("Cannot read {}: {}", h_backup.display(), e))?;
    let Ok(mut bak_val) = serde_json::from_str::<Value>(raw_bak) else {
        return Ok(ExtractedRollbackHooks::default());
    };
    let desired = desired_tokenade_hook_command(scope.target_plugin_dir, scope.is_windows);
    let mut extracted = Vec::new();
    collect_and_rewrite_managed_tokenade_commands(&mut bak_val, scope, &desired, "", &mut extracted);
    populate_migration_context_hashes(&bak_val, &mut extracted);
    Ok(ExtractedRollbackHooks {
        migrations: extracted,
        ..ExtractedRollbackHooks::default()
    })
}

struct HooksRollbackEval {
    new_bytes: Option<Vec<u8>>,
    conflicts: Vec<Value>,
    warnings: Vec<String>,
}

fn evaluate_surgical_hooks_rollback_str(
    live_raw: &str,
    h_target: &Path,
    scope: HookInstanceScope<'_>,
    extracted: &ExtractedRollbackHooks,
    legacy_v1_fallback_cmd: Option<&str>,
) -> Result<HooksRollbackEval, String> {
    // INVARIANT: Revert ONLY when the exact recorded JSON pointer still holds `m.after` AND its enclosing entry `context_sha256` matches (and no many-to-one indistinguishable twin ambiguity exists after post-install edits); report conflicts and leave user entries untouched on any reordering or modification.
    let migrations = extracted.migrations.as_slice();
    let mut live_val: Value = match serde_json::from_str(live_raw) {
        Ok(v) => v,
        Err(e) => {
            let still_has_migrated = migrations.iter().any(|m| live_raw.contains(&m.after))
                || (legacy_v1_fallback_cmd.is_some()
                    && raw_text_mentions_scoped_tokenade(live_raw, scope));
            if still_has_migrated {
                return Err(format!(
                    "Invalid JSON in {} prevents rolling back migrated tokenade hook: {}",
                    h_target.display(),
                    e
                ));
            }
            return Ok(HooksRollbackEval {
                new_bytes: None,
                conflicts: Vec::new(),
                warnings: Vec::new(),
            });
        }
    };
    let live_sha = rio::sha256_hex(live_raw.as_bytes());
    let untouched_since_install = extracted
        .post_install_sha256
        .as_deref()
        .is_some_and(|psha| psha == live_sha);
    let mut twin_befores: BTreeMap<(String, String, String), BTreeSet<String>> = BTreeMap::new();
    for m in migrations {
        twin_befores
            .entry((
                pointer_event_prefix(&m.pointer),
                m.after.clone(),
                m.context_sha256.clone(),
            ))
            .or_default()
            .insert(m.before.clone());
    }
    let mut live_cmds = BTreeMap::new();
    collect_all_command_pointers(&live_val, "", &mut live_cmds);
    let live_contexts: BTreeMap<String, String> = migrations
        .iter()
        .map(|m| {
            (
                m.pointer.clone(),
                compute_hook_pointer_context_sha(&live_val, &m.pointer),
            )
        })
        .collect();
    let mut live_peer_set_shas: BTreeMap<String, String> = BTreeMap::new();
    for m in migrations {
        live_peer_set_shas
            .entry(m.after.clone())
            .or_insert_with(|| compute_hook_peer_set_sha(&live_val, &live_cmds, &m.after));
    }
    let mut reverted = 0usize;
    let mut conflicts = Vec::new();
    let mut warnings = Vec::new();
    for m in migrations {
        let cur_str_opt = live_val
            .pointer(&m.pointer)
            .and_then(|v| v.as_str())
            .map(str::to_string);
        match cur_str_opt {
            Some(cur) if cur == m.after => {
                let ctx_mismatch = !m.context_sha256.is_empty()
                    && live_contexts.get(&m.pointer).map(String::as_str)
                        != Some(m.context_sha256.as_str());
                let peers_untouched = if !m.peer_set_sha256.is_empty() {
                    live_peer_set_shas.get(&m.after).map(String::as_str)
                        == Some(m.peer_set_sha256.as_str())
                } else {
                    untouched_since_install
                };
                let twin_key = (
                    pointer_event_prefix(&m.pointer),
                    m.after.clone(),
                    m.context_sha256.clone(),
                );
                let same_origin_installed = migrations
                    .iter()
                    .filter(|o| o.after == m.after && o.before == m.before)
                    .count();
                let live_after_total = live_cmds.values().filter(|c| *c == &m.after).count();
                let ambiguous_twins = !peers_untouched
                    && (m.has_ambiguous_peer
                        || live_after_total > same_origin_installed
                        || twin_befores
                            .get(&twin_key)
                            .is_some_and(|set| set.len() > 1));
                if ctx_mismatch || ambiguous_twins {
                    let reason = if ctx_mismatch {
                        "entry_reordered_or_context_changed"
                    } else {
                        "ambiguous_many_to_one_after_user_edit"
                    };
                    conflicts.push(json!({
                        "pointer": m.pointer,
                        "expected": m.after,
                        "reason": reason,
                    }));
                    warnings.push(format!(
                        "Skipped hooks.json rollback at {}: array order or entry attributes changed after install (left untouched).",
                        m.pointer
                    ));
                } else if let Some(slot) = live_val.pointer_mut(&m.pointer) {
                    *slot = Value::String(m.before.clone());
                    reverted += 1;
                }
            }
            Some(cur) if cur == m.before => {}
            Some(actual) => {
                conflicts.push(json!({
                    "pointer": m.pointer,
                    "expected": m.after,
                    "actual": actual,
                    "reason": "command_modified_after_install",
                }));
                warnings.push(format!(
                    "Skipped hooks.json rollback at {}: command was modified after install (left untouched).",
                    m.pointer
                ));
            }
            None => {
                conflicts.push(json!({
                    "pointer": m.pointer,
                    "expected": m.after,
                    "reason": "pointer_missing_or_moved",
                }));
                warnings.push(format!(
                    "Skipped hooks.json rollback at {}: entry was moved or removed after install (user hooks left untouched).",
                    m.pointer
                ));
            }
        }
    }
    if migrations.is_empty() {
        if let Some(py_cmd) = legacy_v1_fallback_cmd {
            reverted += revert_native_commands_to_legacy_py(&mut live_val, scope, py_cmd);
        }
    }
    let new_bytes = if reverted > 0 {
        let rendered = serde_json::to_string_pretty(&live_val).map_err(|e| e.to_string())?;
        Some(format!("{}\n", rendered).into_bytes())
    } else {
        None
    };
    Ok(HooksRollbackEval {
        new_bytes,
        conflicts,
        warnings,
    })
}

fn preflight_surgical_hooks_rollback(
    h_target: &Path,
    scope: HookInstanceScope<'_>,
    extracted: &ExtractedRollbackHooks,
    legacy_v1_fallback_cmd: Option<&str>,
) -> Result<(), String> {
    if extracted.migrations.is_empty() && legacy_v1_fallback_cmd.is_none() {
        return Ok(());
    }
    if stat_regular_hooks_file(h_target)?.is_none() {
        return Ok(());
    }
    let live_raw = fs::read_to_string(h_target)
        .map_err(|e| format!("Cannot read {}: {}", h_target.display(), e))?;
    let _ = evaluate_surgical_hooks_rollback_str(
        &live_raw,
        h_target,
        scope,
        extracted,
        legacy_v1_fallback_cmd,
    )?;
    Ok(())
}

fn perform_rollback_internal(
    config_dir: &Path,
    stack_home: &Path,
    backup_selector: &str,
    opts: RollbackOptions,
) -> Value {
    let drain_timeout = opts.drain_timeout;
    let abort_after_plugin_restore = opts.abort_after_plugin_restore;
    let caller_holds_mutex = opts.caller_holds_mutex;
    if !backup_selector.is_empty()
        && backup_selector != "latest"
        && !is_safe_backup_id(backup_selector)
    {
        return json!({
            "ok": false,
            "error": format!("Invalid backup id '{}'", backup_selector),
        });
    }
    match validate_backups_root_strict(stack_home) {
        Ok(Some(_)) => {}
        Ok(None) => {
            if !stack_home.exists() {
                return json!({
                    "ok": false,
                    "error": format!("No backups found in {}", stack_home.join("backups").display()),
                });
            }
        }
        Err(e) => return json!({ "ok": false, "error": e }),
    }
    if let Err(e) = validate_stack_home_preinstall(stack_home) {
        return json!({
            "ok": false,
            "stage": "rollback_link_check",
            "error": e,
        });
    }
    if has_dot_components(config_dir) || win32_sqlite::is_link_or_junction(config_dir) {
        return json!({
            "ok": false,
            "stage": "rollback_link_check",
            "error": format!("Refusing symlink/junction or traversal config_dir: {}", config_dir.display()),
        });
    }
    if let Ok(m) = fs::symlink_metadata(config_dir) {
        if !m.file_type().is_dir() {
            return json!({
                "ok": false,
                "stage": "rollback_validate",
                "error": format!("Target config root is not a directory: {}", config_dir.display()),
            });
        }
    }

    // INVARIANT: Acquire `_inst_mutex` BEFORE resolving `latest` or validating the selected backup so a concurrent `perform_install` (`B -> C`) always commits its backup `B` before `--rollback latest` chooses a snapshot.
    let _inst_mutex = if caller_holds_mutex {
        None
    } else {
        match acquire_installer_mutex(
            config_dir,
            stack_home,
            drain_timeout.max(Duration::from_secs(15)),
        ) {
            Ok(g) => Some(g),
            Err(e) => {
                return json!({
                    "ok": false,
                    "stage": "installer_lock",
                    "error": e,
                });
            }
        }
    };

    let rb_pre_retire_state = stack_home.join("state").join(RETIRED_BINS_DIR_NAME);
    let rb_pre_retire_cfg = config_dir.join(RETIRED_BINS_DIR_NAME);
    if let Err(e) = recover_interrupted_stage_retire_dirs(
        config_dir,
        &[&rb_pre_retire_state, &rb_pre_retire_cfg],
    ) {
        return json!({
            "ok": false,
            "stage": "stage_retire_recovery",
            "error": e,
        });
    }

    let chosen_dir = if backup_selector.is_empty() || backup_selector == "latest" {
        let backups = match list_backups_strict(stack_home) {
            Ok(b) => b,
            Err(e) => return json!({ "ok": false, "error": e }),
        };
        let Some(last) = backups.last().cloned() else {
            return json!({
                "ok": false,
                "error": format!("No backups found in {}", stack_home.join("backups").display()),
            });
        };
        last
    } else {
        // INVARIANT: Resolve explicit `--rollback <id>` directly without scanning sibling backups so a locked or damaged newer backup cannot block restoring a healthy older backup by ID.
        let broot = match validate_backups_root_strict(stack_home) {
            Ok(Some(b)) => b,
            Ok(None) => {
                return json!({
                    "ok": false,
                    "error": format!("No backups found in {}", stack_home.join("backups").display()),
                });
            }
            Err(e) => return json!({ "ok": false, "error": e }),
        };
        let candidate = broot.join(backup_selector);
        let is_missing = !win32_sqlite::is_link_or_junction(&candidate)
            && matches!(
                fs::symlink_metadata(&candidate),
                Err(ref e) if e.kind() == std::io::ErrorKind::NotFound
            );
        let validated = if is_missing {
            Ok(false)
        } else {
            validate_backup_entry_strict(&candidate)
        };
        match validated {
            Ok(true) => candidate,
            Ok(false) => {
                return json!({
                    "ok": false,
                    "error": format!("Backup '{}' not found", backup_selector),
                });
            }
            Err(e) => return json!({ "ok": false, "error": e }),
        }
    };

    let Some(manifest) = rio::read_json(&chosen_dir.join("manifest.json")) else {
        return json!({ "ok": false, "error": "Invalid backup manifest.json" });
    };
    let targets = manifest.get("targets");
    let p_info = targets.and_then(|t| t.get("plugin_dir"));
    let r_info = targets.and_then(|t| t.get("glob_rule"));
    let h_info = targets.and_then(|t| t.get("global_hooks"));
    let (Some(p_existed), Some(r_existed)) = (
        p_info.and_then(|p| p.get("existed")).and_then(|v| v.as_bool()),
        r_info.and_then(|r| r.get("existed")).and_then(|v| v.as_bool()),
    ) else {
        return json!({
            "ok": false,
            "stage": "rollback_validate",
            "error": "Invalid backup manifest.json: missing boolean `existed` flags",
        });
    };
    let p_target = config_dir.join("plugins").join(PLUGIN_NAME);
    let r_target = config_dir.join("rules").join("uiux-design.md");
    let h_target = config_dir.join("hooks.json");
    let mp_raw = p_info.and_then(|p| p.get("path")).and_then(|v| v.as_str()).unwrap_or("");
    let mr_raw = r_info.and_then(|r| r.get("path")).and_then(|v| v.as_str()).unwrap_or("");
    // INVARIANT: Pin rollback destinations to canonical `<config_dir>/plugins/gemini-carbon-stack`, `<config_dir>/rules/uiux-design.md`, and optional `<config_dir>/hooks.json` so a tampered manifest can never redirect deletion outside `config_dir`.
    if !matches_pinned_target_path(mp_raw, &p_target)
        || !matches_pinned_target_path(mr_raw, &r_target)
    {
        return json!({
            "ok": false,
            "stage": "rollback_validate",
            "error": "Invalid backup manifest.json: target path mismatch",
        });
    }
    let link_errs = validate_target_hierarchy(config_dir, &p_target, &r_target);
    if let Some(first_err) = link_errs.first() {
        return json!({
            "ok": false,
            "stage": "rollback_link_check",
            "error": first_err,
        });
    }
    let mut backup_links = Vec::new();
    collect_links_under_tree(&chosen_dir, &mut backup_links);
    if let Some(first_blnk) = backup_links.first() {
        return json!({
            "ok": false,
            "stage": "rollback_link_check",
            "error": format!("Refusing backup containing symlink/junction: {}", first_blnk.display()),
        });
    }

    let rb_type_errs = validate_target_entry_types(config_dir, &p_target, &r_target, None, cfg!(windows));
    if let Some(first_err) = rb_type_errs.first() {
        return json!({
            "ok": false,
            "stage": "rollback_validate",
            "error": first_err,
        });
    }

    let p_backup = chosen_dir.join("plugin_dir");
    let r_backup = chosen_dir.join("rules").join("uiux-design.md");
    let h_backup = chosen_dir.join("global_hooks.json");
    if p_existed {
        if !p_backup.is_dir() {
            return json!({
                "ok": false,
                "stage": "rollback_validate",
                "error": format!("Incomplete backup: missing plugin snapshot {}", p_backup.display()),
            });
        }
        let actual_hashes = match tree_manifest_strict(&p_backup) {
            Ok(m) => m,
            Err(e) => {
                return json!({
                    "ok": false,
                    "stage": "rollback_validate",
                    "error": format!("Failed to read plugin backup snapshot: {}", e),
                });
            }
        };
        match p_info.and_then(|p| p.get("files_sha256")) {
            Some(Value::Object(raw_fmap)) => {
                let mut expected_hashes = BTreeMap::new();
                for (rel_k, sha_v) in raw_fmap {
                    let Some(sha_str) = sha_v.as_str().filter(|s| is_valid_sha256_hex(s)) else {
                        return json!({
                            "ok": false,
                            "stage": "rollback_validate",
                            "error": format!("Invalid SHA-256 digest in backup manifest for {}", rel_k),
                        });
                    };
                    if rel_k.is_empty() || rel_k.starts_with('/') || has_dot_components(Path::new(rel_k)) {
                        return json!({
                            "ok": false,
                            "stage": "rollback_validate",
                            "error": format!("Invalid relative path in backup manifest: {}", rel_k),
                        });
                    }
                    expected_hashes.insert(rel_k.clone(), sha_str.to_string());
                }
                if actual_hashes != expected_hashes {
                    return json!({
                        "ok": false,
                        "stage": "rollback_validate",
                        "error": "Incomplete or corrupted backup: plugin snapshot files do not match manifest SHA-256 inventory",
                    });
                }
            }
            Some(_) => {
                return json!({
                    "ok": false,
                    "stage": "rollback_validate",
                    "error": "Invalid backup manifest.json: malformed `files_sha256` field",
                });
            }
            None => {
                if let Err(e) = validate_legacy_plugin_snapshot(&p_backup, &actual_hashes) {
                    return json!({
                        "ok": false,
                        "stage": "rollback_validate",
                        "error": e,
                    });
                }
            }
        }
    }
    if r_existed {
        if !r_backup.is_file() {
            return json!({
                "ok": false,
                "stage": "rollback_validate",
                "error": format!("Incomplete backup: missing rule snapshot {}", r_backup.display()),
            });
        }
        let Ok(actual_r_sha) = sha256_file_full(&r_backup) else {
            return json!({
                "ok": false,
                "stage": "rollback_validate",
                "error": "Failed to hash rule backup snapshot",
            });
        };
        match r_info.and_then(|r| r.get("sha256")) {
            Some(Value::String(exp_r_sha)) if is_valid_sha256_hex(exp_r_sha) => {
                if actual_r_sha != *exp_r_sha {
                    return json!({
                        "ok": false,
                        "stage": "rollback_validate",
                        "error": "Corrupted backup: rule snapshot SHA-256 mismatch",
                    });
                }
            }
            Some(_) => {
                return json!({
                    "ok": false,
                    "stage": "rollback_validate",
                    "error": "Invalid backup manifest.json: malformed rule `sha256` digest",
                });
            }
            None => {}
        }
    }
    let rb_scope = HookInstanceScope {
        config_dir,
        target_plugin_dir: &p_target,
        is_windows: cfg!(windows),
    };
    let (extracted_hooks, legacy_v1_py_cmd) = if opts.rollback_hooks {
        let extracted =
            match extract_rollback_hooks_migrations(h_info, &h_target, &h_backup, rb_scope) {
                Ok(v) => v,
                Err(e) => {
                    return json!({
                        "ok": false,
                        "stage": "rollback_validate",
                        "error": e,
                    });
                }
            };
        let leg_cmd = if extracted.is_legacy_untracked
            && p_existed
            && p_backup.join("hooks").join("tokenade_hook.py").is_file()
        {
            Some(legacy_python_tokenade_hook_command(&p_target, cfg!(windows)))
        } else {
            None
        };
        if let Err(e) = preflight_surgical_hooks_rollback(
            &h_target,
            rb_scope,
            &extracted,
            leg_cmd.as_deref(),
        ) {
            return json!({
                "ok": false,
                "stage": "rollback_validate",
                "error": e,
            });
        }
        (extracted, leg_cmd)
    } else {
        (
            ExtractedRollbackHooks {
                migrations: Vec::new(),
                post_install_sha256: None,
                is_legacy_untracked: false,
            },
            None,
        )
    };

    let state_root = stack_home.join("state");
    let had_prior_v1_epoch = fs::read_to_string(rio::lock_epoch_path(&state_root))
        .map(|s| s.trim() == "v1")
        .unwrap_or(false);
    let had_live_plugin = p_target.is_dir();
    let had_live_rule = r_target.is_file();
    let had_live_hooks = h_target.is_file();
    let stage_root = state_root.join(format!(
        "rb_stage_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let stage_plugin = stage_root.join("plugin_dir");
    let stage_rule = stage_root.join("glob_rule.md");
    let stage_hooks = stage_root.join("global_hooks.json");
    let pre_live_hashes = if had_live_plugin {
        let orig_hashes = match tree_manifest_strict(&p_target) {
            Ok(m) => m,
            Err(e) => {
                return json!({
                    "ok": false,
                    "stage": "rollback_stage",
                    "error": format!("Failed to inventory live plugin before rollback: {}", e),
                });
            }
        };
        if let Err(e) = copy_clean_tree_for_os(&p_target, &stage_plugin, true) {
            let _ = fs::remove_dir_all(&stage_root);
            return json!({
                "ok": false,
                "stage": "rollback_stage",
                "error": format!("Failed to stage live plugin before rollback: {}", e),
            });
        }
        let staged_hashes = match tree_manifest_strict(&stage_plugin) {
            Ok(m) => m,
            Err(e) => {
                let _ = fs::remove_dir_all(&stage_root);
                return json!({
                    "ok": false,
                    "stage": "rollback_stage",
                    "error": format!("Failed to verify staged live plugin: {}", e),
                });
            }
        };
        if staged_hashes != orig_hashes {
            let _ = fs::remove_dir_all(&stage_root);
            return json!({
                "ok": false,
                "stage": "rollback_stage",
                "error": "Staged live plugin inventory does not match original live plugin",
            });
        }
        Some(orig_hashes)
    } else {
        None
    };
    let mut pre_live_rule_err: Option<String> = None;
    let pre_live_rule_sha = if had_live_rule {
        match sha256_file_full(&r_target) {
            Ok(orig_r_sha) => match atomic_copy_file(&r_target, &stage_rule) {
                Ok(()) => Some(orig_r_sha),
                Err(e) => {
                    pre_live_rule_err = Some(e);
                    None
                }
            },
            Err(e) => {
                pre_live_rule_err = Some(e);
                None
            }
        }
    } else {
        None
    };
    let pre_live_hooks_sha: Option<String> = None;

    if let Err(busy_locks) = drain_and_sweep_v2_locks(&state_root, drain_timeout) {
        let names: Vec<String> = busy_locks.iter().map(|p| p.display().to_string()).collect();
        let _ = fs::remove_dir_all(&stage_root);
        return json!({
            "ok": false,
            "stage": "rollback_v2_lock_drain",
            "compensated_plugin_restore": true,
            "error": format!(
                "Active v2 lock holders did not drain within {:?}: {}",
                drain_timeout,
                names.join(", ")
            ),
        });
    }

    let rb_stage = RollbackStage {
        had_live_plugin,
        expected_live_hashes: pre_live_hashes.as_ref(),
        had_live_rule,
        expected_live_rule_sha: pre_live_rule_sha.as_deref(),
        had_live_hooks,
        expected_live_hooks_sha: pre_live_hooks_sha.as_deref(),
        had_prior_v1_epoch,
        drain_timeout,
        config_dir,
        state_root: &state_root,
        stage_root: &stage_root,
        stage_plugin: &stage_plugin,
        stage_rule: &stage_rule,
        stage_hooks: &stage_hooks,
        p_target: &p_target,
        r_target: &r_target,
        h_target: &h_target,
    };
    let retired_state = state_root.join(RETIRED_BINS_DIR_NAME);
    let retired_cfg = config_dir.join(RETIRED_BINS_DIR_NAME);
    let retire_dirs: [&Path; 2] = [&retired_state, &retired_cfg];

    let pre_rb_py_rels = compute_stale_scoped_py_rels(
        p_existed.then_some(p_backup.as_path()),
        &p_target,
        rb_scope,
    )
    .unwrap_or_default();

    // INVARIANT: Expand-Migrate-Contract rollback order: stage `p_backup` files additively first (keeping `bin/carbon-stack` and existing `.py` scripts intact), surgically roll back and bidirectionally dependency-check `<config_dir>/hooks.json` against `p_backup` BEFORE contracting `p_target`, update `r_target`, and contract `p_target` last under `acquire_hooks_read_share_guard` + sibling stage-retire restoration on race.
    if p_existed {
        if let Err(e) = copy_clean_tree_additive(&p_backup, &p_target, true) {
            return compensate_plugin_rollback(
                &rb_stage,
                RollbackMutated {
                    plugin: true,
                    ..RollbackMutated::default()
                },
                json!({ "ok": false, "error": e }),
            );
        }
    }

    if abort_after_plugin_restore {
        return json!({
            "ok": false,
            "stage": "simulated_interruption_after_plugin_restore",
        });
    }

    let mut rb_hooks_conflicts: Vec<Value> = Vec::new();
    let mut rb_hooks_warnings: Vec<String> = Vec::new();
    let mut hooks_rolled_back = false;
    let attach_hook_conflicts = |mut resp: Value, conflicts: &[Value], warnings: &[String]| -> Value {
        if !conflicts.is_empty() {
            if let Some(obj) = resp.as_object_mut() {
                obj.insert(
                    "hooks_rollback_conflicts".to_string(),
                    Value::Array(conflicts.to_vec()),
                );
                obj.insert("warnings".to_string(), json!(warnings));
            }
        }
        resp
    };

    if opts.rollback_hooks {
        let pre_hooks_mutated = RollbackMutated {
            plugin: p_existed,
            rule: false,
            hooks: false,
        };
        let target_b_opt = p_existed.then_some(p_backup.as_path());
        if !extracted_hooks.migrations.is_empty() || legacy_v1_py_cmd.is_some() {
            let mut rb_published_unreverted = false;
            match cas_update_hooks_file_tracking(
                &h_target,
                &mut rb_published_unreverted,
                |live_raw| {
                    let eval = evaluate_surgical_hooks_rollback_str(
                        live_raw,
                        &h_target,
                        rb_scope,
                        &extracted_hooks,
                        legacy_v1_py_cmd.as_deref(),
                    )?;
                    rb_hooks_conflicts = eval.conflicts;
                    rb_hooks_warnings = eval.warnings;
                    let post_raw: &str = match eval.new_bytes.as_deref() {
                        Some(b) => std::str::from_utf8(b).map_err(|e| e.to_string())?,
                        None => live_raw,
                    };
                    verify_hooks_raw_compatible_with_plugin_tree(
                        post_raw,
                        &h_target,
                        rb_scope,
                        &pre_rb_py_rels,
                        target_b_opt,
                    )?;
                    Ok(eval.new_bytes.map(|b| (b, ())))
                },
            ) {
                Ok(Some(_)) => {
                    hooks_rolled_back = true;
                }
                Ok(None) => {}
                Err(e) => {
                    let err_json = attach_hook_conflicts(
                        json!({
                            "ok": false,
                            "stage": "rollback_hooks_restore",
                            "error": e,
                        }),
                        &rb_hooks_conflicts,
                        &rb_hooks_warnings,
                    );
                    if rb_published_unreverted {
                        return compensate_rollback_after_unreverted_hooks(
                            &rb_stage,
                            rb_scope,
                            p_existed,
                            pre_hooks_mutated,
                            err_json,
                        );
                    }
                    return compensate_plugin_rollback(&rb_stage, pre_hooks_mutated, err_json);
                }
            }
        } else if let Err(dep_err) = verify_live_hooks_compatible_with_plugin_tree(
            &h_target,
            rb_scope,
            &pre_rb_py_rels,
            target_b_opt,
        ) {
            return compensate_plugin_rollback(
                &rb_stage,
                pre_hooks_mutated,
                json!({
                    "ok": false,
                    "stage": "rollback_hooks_restore",
                    "error": dep_err,
                }),
            );
        }
    }

    let compensate_post_hooks = |rule_mutated: bool, resp: Value| -> Value {
        let mut_state = RollbackMutated {
            plugin: true,
            rule: rule_mutated,
            hooks: false,
        };
        if hooks_rolled_back {
            compensate_rollback_after_unreverted_hooks(
                &rb_stage,
                rb_scope,
                p_existed,
                mut_state,
                resp,
            )
        } else {
            compensate_plugin_rollback(&rb_stage, mut_state, resp)
        }
    };

    if let Some(r_stage_err) = pre_live_rule_err {
        let stage_name = if r_existed {
            "rollback_rule_copy"
        } else {
            "rollback_rule_remove"
        };
        return compensate_post_hooks(
            false,
            json!({
                "ok": false,
                "stage": stage_name,
                "error": format!("Failed to stage live rule {}: {}", r_target.display(), r_stage_err),
            }),
        );
    }

    if r_existed {
        if let Err(e) = atomic_copy_file(&r_backup, &r_target) {
            return compensate_post_hooks(true, json!({ "ok": false, "error": e }));
        }
    } else if r_target.exists() {
        if let Err(e) = fs::remove_file(&r_target) {
            return compensate_post_hooks(
                false,
                json!({
                    "ok": false,
                    "stage": "rollback_rule_remove",
                    "error": format!("Failed to remove {}: {}", r_target.display(), e),
                }),
            );
        }
        if r_target.exists() {
            return compensate_post_hooks(
                false,
                json!({
                    "ok": false,
                    "stage": "rollback_rule_remove",
                    "error": format!("Rule file still exists after removal: {}", r_target.display()),
                }),
            );
        }
    }

    if p_existed {
        if let Err(e) = prune_rollback_tree_guarded_by_hooks(
            &p_backup,
            &p_target,
            &h_target,
            rb_scope,
            &retire_dirs,
        ) {
            return compensate_post_hooks(
                true,
                json!({
                    "ok": false,
                    "stage": "rollback_plugin_prune",
                    "error": e,
                }),
            );
        }
    } else if p_target.exists() {
        if let Err(e) = remove_rollback_tree_guarded_with_hook(
            &p_target,
            &h_target,
            rb_scope,
            &retire_dirs,
            || {},
        ) {
            return compensate_post_hooks(
                true,
                json!({
                    "ok": false,
                    "stage": "rollback_plugin_remove",
                    "error": e,
                }),
            );
        }
    }

    let _ = fs::remove_dir_all(&stage_root);
    if !caller_holds_mutex {
        remove_v2_plugin_digest(&state_root);
    }

    let mut out = json!({
        "ok": true,
        "restored_backup_id": chosen_dir.file_name().and_then(|s| s.to_str()).unwrap_or(""),
        "plugin_dir_exists_now": p_target.exists(),
        "glob_rule_exists_now": r_target.exists(),
    });
    if !rb_hooks_conflicts.is_empty() {
        if let Some(obj) = out.as_object_mut() {
            obj.insert(
                "hooks_rollback_conflicts".to_string(),
                Value::Array(rb_hooks_conflicts),
            );
            obj.insert("warnings".to_string(), json!(rb_hooks_warnings));
        }
    }
    out
}

fn collect_active_v1_locks(dir: &Path, depth: usize, out: &mut BTreeSet<PathBuf>) {
    if depth > 5 || win32_sqlite::is_link_or_junction(dir) || !dir.is_dir() {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        let p = entry.path();
        if ft.is_symlink() || (cfg!(windows) && win32_sqlite::is_link_or_junction(&p)) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if depth == 0 && (name.starts_with("rb_stage_") || name == RETIRED_BINS_DIR_NAME) {
            continue;
        }
        if name.ends_with(".flight.lock")
            || name.contains(".flight.lock.")
            || name == ".installer.lock"
            || name.starts_with(".installer.lock.")
        {
            continue;
        }
        if (name.ends_with(".lock")
            || name.ends_with(".lock.swap")
            || name.ends_with(".lock.dir"))
            && ft.is_file()
        {
            if win32_sqlite::is_active_v1_lock_file(&p, 30.0) {
                out.insert(p);
            }
        } else if ft.is_dir()
            && !name.ends_with(".lock")
            && !name.ends_with(".lock.dir")
            && !name.ends_with(".lock.swap")
        {
            collect_active_v1_locks(&p, depth + 1, out);
        }
    }
}

fn norm_proc_match_str(raw: &str) -> String {
    let slash = raw.replace('\\', "/");
    let trimmed = slash
        .strip_prefix("//?/")
        .unwrap_or(&slash)
        .trim_end_matches('/');
    if cfg!(windows) {
        trimmed.to_lowercase()
    } else {
        trimmed.to_string()
    }
}

fn compute_self_and_ancestors(procs: &[win32_sqlite::OsProcInfo]) -> BTreeSet<u32> {
    let mut ppid_map: BTreeMap<u32, u32> = BTreeMap::new();
    for p in procs {
        ppid_map.insert(p.pid, p.ppid);
    }
    let mut ancestors = BTreeSet::new();
    let mut cur = std::process::id();
    for _ in 0..64 {
        ancestors.insert(cur);
        match ppid_map.get(&cur).copied() {
            Some(next) if next > 1 && !ancestors.contains(&next) => cur = next,
            _ => break,
        }
    }
    ancestors
}

fn is_path_within_norm_dir(norm_candidate: &str, norm_dir: &str) -> bool {
    !norm_dir.is_empty()
        && (norm_candidate == norm_dir
            || norm_candidate
                .strip_prefix(norm_dir)
                .is_some_and(|rest| rest.starts_with('/')))
}

fn has_plugin_py_path_in_cmd(norm_cmd: &str, norm_plug: &str) -> bool {
    if norm_plug.is_empty() {
        return false;
    }
    let prefix = format!("{}/", norm_plug);
    let mut rest = norm_cmd;
    while let Some(pos) = rest.find(&prefix) {
        let after = &rest[pos + prefix.len()..];
        let seg_end = after
            .find(|c: char| matches!(c, ' ' | '\t' | '"' | '\'' | ';' | '&' | '|'))
            .unwrap_or(after.len());
        if after[..seg_end].ends_with(".py") {
            return true;
        }
        rest = &after[seg_end..];
    }
    false
}

struct PluginProcRoots {
    norm_plug: String,
    norm_plug_bin: String,
    norm_state_ret: String,
    norm_cfg_ret: String,
    retired_segment: String,
    check_retired_native_bins: bool,
}

impl PluginProcRoots {
    fn new(
        target_plugin_dir: &Path,
        config_dir: &Path,
        state_root: &Path,
        check_retired_native_bins: bool,
    ) -> Self {
        let norm_plug = norm_proc_match_str(&target_plugin_dir.to_string_lossy());
        let norm_plug_bin = format!("{}/bin", norm_plug);
        let norm_state_ret = norm_proc_match_str(
            &state_root
                .join(RETIRED_BINS_DIR_NAME)
                .to_string_lossy(),
        );
        let norm_cfg_ret = norm_proc_match_str(
            &config_dir
                .join(RETIRED_BINS_DIR_NAME)
                .to_string_lossy(),
        );
        let retired_segment = format!("/{}/", RETIRED_BINS_DIR_NAME);
        Self {
            norm_plug,
            norm_plug_bin,
            norm_state_ret,
            norm_cfg_ret,
            retired_segment,
            check_retired_native_bins,
        }
    }

    fn contains_exe_or_retired(&self, norm_exe: &str) -> bool {
        is_path_within_norm_dir(norm_exe, &self.norm_plug)
            || is_path_within_norm_dir(norm_exe, &self.norm_state_ret)
            || is_path_within_norm_dir(norm_exe, &self.norm_cfg_ret)
    }
}

fn match_pre_cutover_pids_from_slice(
    procs: &[win32_sqlite::OsProcInfo],
    roots: &PluginProcRoots,
) -> Result<BTreeMap<u32, u64>, String> {
    let ancestors = compute_self_and_ancestors(procs);
    let mut out = BTreeMap::new();
    for p in procs {
        if ancestors.contains(&p.pid) {
            continue;
        }
        let exe = norm_proc_match_str(p.exe_path.trim_end_matches(" (deleted)"));
        let exe_in_plugin = p.exe_known && roots.contains_exe_or_retired(&exe);
        if exe_in_plugin {
            out.insert(p.pid, p.start_token);
            continue;
        }
        if p.same_user && (!p.exe_known || !p.cmdline_known) {
            return Err(format!(
                "Incomplete process metadata (exe_known={}, cmdline_known={}) for active pid {}",
                p.exe_known, p.cmdline_known, p.pid
            ));
        }
        if !p.cmdline_known {
            continue;
        }
        let cmd = norm_proc_match_str(&p.cmdline);
        let cmd_mentions_plugin = !roots.norm_plug.is_empty() && cmd.contains(&roots.norm_plug);
        if cmd_mentions_plugin {
            out.insert(p.pid, p.start_token);
            continue;
        }
        if win32_sqlite::cmdline_may_need_cwd(&p.cmdline) {
            if !p.cwd_known {
                if p.same_user {
                    return Err(format!(
                        "Unable to determine working directory (cwd) for active candidate pid {}",
                        p.pid
                    ));
                }
                continue;
            }
            let cwd = norm_proc_match_str(&p.cwd_path);
            if is_path_within_norm_dir(&cwd, &roots.norm_plug) {
                out.insert(p.pid, p.start_token);
            }
        }
    }
    Ok(out)
}

fn snapshot_pre_cutover_plugin_pids(
    target_plugin_dir: &Path,
    config_dir: &Path,
    state_root: &Path,
) -> Result<BTreeMap<u32, u64>, String> {
    let procs = win32_sqlite::list_os_processes()?;
    let roots = PluginProcRoots::new(target_plugin_dir, config_dir, state_root, true);
    match_pre_cutover_pids_from_slice(&procs, &roots)
}

fn match_running_legacy_v1_pids_from_slice(
    procs: &[win32_sqlite::OsProcInfo],
    roots: &PluginProcRoots,
    pre_cutover_pids: &BTreeMap<u32, u64>,
    current_v2_bin_ino: Option<u64>,
) -> Result<Vec<u32>, String> {
    let ancestors = compute_self_and_ancestors(procs);
    let mut out = BTreeSet::new();
    for p in procs {
        if ancestors.contains(&p.pid) {
            continue;
        }
        if let Some(&orig_tok) = pre_cutover_pids.get(&p.pid) {
            if orig_tok == 0 || p.start_token == 0 || p.start_token == orig_tok {
                out.insert(p.pid);
                continue;
            }
        }
        let exe_raw = norm_proc_match_str(&p.exe_path);
        let exe_clean = norm_proc_match_str(p.exe_path.trim_end_matches(" (deleted)"));
        if roots.check_retired_native_bins {
            let is_retired_pe = p.exe_known
                && exe_clean.contains(&roots.retired_segment)
                && roots.contains_exe_or_retired(&exe_clean);
            let is_replaced_unix_bin = p.exe_known
                && is_path_within_norm_dir(&exe_clean, &roots.norm_plug_bin)
                && (exe_raw.ends_with(" (deleted)")
                    || matches!(
                        (p.exe_ino, current_v2_bin_ino),
                        (Some(p_ino), Some(cur_ino)) if p_ino != cur_ino
                    ));
            if is_retired_pe || is_replaced_unix_bin {
                out.insert(p.pid);
                continue;
            }
        }
        if p.same_user && (!p.exe_known || !p.cmdline_known) {
            return Err(format!(
                "Incomplete process metadata (exe_known={}, cmdline_known={}) for active pid {}",
                p.exe_known, p.cmdline_known, p.pid
            ));
        }
        if !p.cmdline_known {
            continue;
        }
        let is_native_carbon_exe =
            exe_clean.ends_with("/carbon-stack") || exe_clean.ends_with("/carbon-stack.exe");
        if is_native_carbon_exe {
            continue;
        }
        let cmd = norm_proc_match_str(&p.cmdline);
        if cmd.contains(".py") {
            if has_plugin_py_path_in_cmd(&cmd, &roots.norm_plug) {
                out.insert(p.pid);
                continue;
            }
            if !p.cwd_known {
                if p.same_user {
                    return Err(format!(
                        "Unable to determine working directory (cwd) for active Python pid {}",
                        p.pid
                    ));
                }
                continue;
            }
            let cwd = norm_proc_match_str(&p.cwd_path);
            if is_path_within_norm_dir(&cwd, &roots.norm_plug) {
                out.insert(p.pid);
            }
        }
    }
    Ok(out.into_iter().collect())
}

fn quiesce_and_clear_v1_lock_epoch(
    roots: &PluginProcRoots,
    state_root: &Path,
    pre_cutover_pids: &BTreeMap<u32, u64>,
    current_v2_bin_ino: Option<u64>,
    drain_timeout: Duration,
) -> Result<(), String> {
    quiesce_and_clear_v1_lock_epoch_with_lister(
        roots,
        state_root,
        pre_cutover_pids,
        current_v2_bin_ino,
        drain_timeout,
        win32_sqlite::list_os_processes,
    )
}

fn quiesce_and_clear_v1_lock_epoch_with_lister<F>(
    roots: &PluginProcRoots,
    state_root: &Path,
    pre_cutover_pids: &BTreeMap<u32, u64>,
    current_v2_bin_ino: Option<u64>,
    drain_timeout: Duration,
    mut list_fn: F,
) -> Result<(), String>
where
    F: FnMut() -> Result<Vec<win32_sqlite::OsProcInfo>, String>,
{
    // INVARIANT: Atomically quiesce legacy `v1` runtime AND clear `.lock_epoch` under a single `.v2_alive.lease` `LOCK_EX` hold using non-blocking kernel process inspection (`Toolhelp+NtQuery` on Windows, `/proc` on Linux, `libproc+KERN_PROCARGS2` on macOS), failing closed whenever process enumeration or required `cwd`/`cmdline` inspection returns `Err`.
    fs::create_dir_all(state_root).map_err(|e| e.to_string())?;
    let lease_path = rio::v2_lease_path(state_root);
    let lfh = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lease_path)
        .map_err(|e| format!("Cannot open {}: {}", lease_path.display(), e))?;
    let deadline = Instant::now() + drain_timeout;
    let mut backoff_ms = 10u64;
    loop {
        let mut last_proc_err: Option<String> = None;
        let mut active_locks = BTreeSet::new();
        collect_active_v1_locks(state_root, 0, &mut active_locks);
        let pids_res = list_fn().and_then(|procs| {
            match_running_legacy_v1_pids_from_slice(
                &procs,
                roots,
                pre_cutover_pids,
                current_v2_bin_ino,
            )
        });
        match pids_res {
            Ok(active_pids) => {
                if active_locks.is_empty() && active_pids.is_empty() {
                    match lfh.try_lock() {
                        Ok(()) => {
                            let mut recheck_locks = BTreeSet::new();
                            collect_active_v1_locks(state_root, 0, &mut recheck_locks);
                            let recheck_res = list_fn().and_then(|procs| {
                                match_running_legacy_v1_pids_from_slice(
                                    &procs,
                                    roots,
                                    pre_cutover_pids,
                                    current_v2_bin_ino,
                                )
                            });
                            match recheck_res {
                                Ok(recheck_pids)
                                    if recheck_locks.is_empty() && recheck_pids.is_empty() =>
                                {
                                    let epoch_path = rio::lock_epoch_path(state_root);
                                    let rm_res = match fs::remove_file(&epoch_path) {
                                        Ok(()) => Ok(()),
                                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                                            Ok(())
                                        }
                                        Err(e) => Err(format!(
                                            "Failed removing {}: {}",
                                            epoch_path.display(),
                                            e
                                        )),
                                    };
                                    let _ = lfh.unlock();
                                    return rm_res;
                                }
                                Ok(_) => {
                                    let _ = lfh.unlock();
                                }
                                Err(e) => {
                                    last_proc_err = Some(e);
                                    let _ = lfh.unlock();
                                }
                            }
                        }
                        Err(std::fs::TryLockError::WouldBlock) => {
                            if Instant::now() >= deadline {
                                return Err(format!(
                                    "Timed out acquiring {} before clearing .lock_epoch",
                                    lease_path.display()
                                ));
                            }
                            thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(std::fs::TryLockError::Error(e)) => {
                            return Err(format!("Failed locking {}: {}", lease_path.display(), e));
                        }
                    }
                }
            }
            Err(e) => {
                last_proc_err = Some(e);
            }
        }
        if Instant::now() >= deadline {
            if let Some(pe) = last_proc_err {
                return Err(format!(
                    "Legacy v1 process inspection failed within {:?}: {}",
                    drain_timeout, pe
                ));
            }
            let mut final_locks = BTreeSet::new();
            collect_active_v1_locks(state_root, 0, &mut final_locks);
            let final_pids = list_fn()
                .and_then(|procs| {
                    match_running_legacy_v1_pids_from_slice(
                        &procs,
                        roots,
                        pre_cutover_pids,
                        current_v2_bin_ino,
                    )
                })
                .unwrap_or_default();
            let lock_names: Vec<String> =
                final_locks.iter().map(|p| p.display().to_string()).collect();
            return Err(format!(
                "Legacy v1 runtime did not quiesce within {:?} (active_v1_locks=[{}], active_v1_pids={:?})",
                drain_timeout,
                lock_names.join(", "),
                final_pids
            ));
        }
        let rem = deadline.saturating_duration_since(Instant::now());
        thread::sleep(rem.min(Duration::from_millis(backoff_ms)));
        backoff_ms = (backoff_ms * 2).min(150);
    }
}

fn collect_v2_lock_bases(dir: &Path, depth: usize, out: &mut BTreeSet<PathBuf>) {
    if depth > 5 || win32_sqlite::is_link_or_junction(dir) || !dir.is_dir() {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        let p = entry.path();
        if ft.is_symlink() || (cfg!(windows) && win32_sqlite::is_link_or_junction(&p)) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if depth == 0 && (name.starts_with("rb_stage_") || name == RETIRED_BINS_DIR_NAME) {
            continue;
        }
        if name.ends_with(".flight.lock")
            || name.contains(".flight.lock.")
            || name == ".installer.lock"
            || name.starts_with(".installer.lock.")
        {
            continue;
        }
        if let Some(stem) = name
            .strip_suffix(".lock.k")
            .or_else(|| name.strip_suffix(".lock.swap"))
            .or_else(|| name.strip_suffix(".lock.dir"))
            .or_else(|| name.strip_suffix(".lock.undo"))
            .or_else(|| name.strip_suffix(".lock.undo.tmp"))
        {
            out.insert(dir.join(format!("{}.lock", stem)));
        } else if name.ends_with(".lock") {
            if win32_sqlite::is_v2_lock_artifact(&p) {
                out.insert(p);
            }
        } else if ft.is_dir() {
            collect_v2_lock_bases(&p, depth + 1, out);
        }
    }
}

fn has_v2_lock_state(lock_path: &Path) -> bool {
    win32_sqlite::legacy_swap_path(lock_path).exists()
        || win32_sqlite::legacy_dir_stage_path(lock_path).exists()
        || win32_sqlite::legacy_undo_path(lock_path).exists()
        || win32_sqlite::legacy_undo_tmp_path(lock_path).exists()
        || win32_sqlite::is_v2_lock_artifact(lock_path)
}

fn write_v1_lock_epoch(state_root: &Path) -> std::io::Result<()> {
    // INVARIANT: Reject symlinks/junctions on `state_root` and `.lock_epoch` and create a unique temp file exclusively (`create_new(true)`) inside `state_root` so a pre-existing `.lock_epoch.tmp` symlink can never truncate an outside target.
    if win32_sqlite::is_link_or_junction(state_root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing symlink/junction state_root",
        ));
    }
    let epoch_path = rio::lock_epoch_path(state_root);
    if win32_sqlite::is_link_or_junction(&epoch_path) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing symlink/junction .lock_epoch",
        ));
    }
    let tmp_path = next_exclusive_tmp_path(&epoch_path);
    let mut fh = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)?;
    if let Err(e) = fh.write_all(b"v1\n") {
        drop(fh);
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    drop(fh);
    if let Err(e) = fs::rename(&tmp_path, &epoch_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    Ok(())
}

fn drain_and_sweep_v2_locks(
    state_root: &Path,
    drain_timeout: Duration,
) -> Result<(), Vec<PathBuf>> {
    // INVARIANT: Acquire EXCLUSIVE `LOCK_EX` on `.v2_alive.lease` (waiting for every active `v2` `rio::with_file_lock` critical section to finish), sweep all crashed `v2` directories/slots/undo logs under `.k`, and persist `.lock_epoch = "v1"` BEFORE releasing `LOCK_EX` so any long-running `v2` process (e.g. a waiting `codex-lane review` holding `*.flight.lock`) switches its subsequent `with_file_lock` commits to pure `v1` regular-file locks.
    if fs::create_dir_all(state_root).is_err() {
        return Err(vec![state_root.to_path_buf()]);
    }
    let lease_path = rio::v2_lease_path(state_root);
    let Ok(lease_fh) = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lease_path)
    else {
        return Err(vec![lease_path]);
    };
    let deadline = Instant::now() + drain_timeout;
    let mut backoff_ms = 10u64;
    loop {
        if lease_fh.try_lock().is_err() {
            if Instant::now() >= deadline {
                return Err(vec![lease_path]);
            }
            thread::sleep(Duration::from_millis(10));
            continue;
        }
        let mut base_locks = BTreeSet::new();
        collect_v2_lock_bases(state_root, 0, &mut base_locks);
        let mut busy = Vec::new();
        for lock_path in base_locks {
            let kpath = rio::kernel_companion_lock_path(&lock_path);
            let Ok(kfh) = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&kpath)
            else {
                busy.push(lock_path);
                continue;
            };
            if kfh.try_lock().is_err() {
                busy.push(lock_path);
                continue;
            }
            if has_v2_lock_state(&lock_path) {
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                {
                    let _ = win32_sqlite::try_reclaim_stale_legacy_lock(&lock_path, 30.0);
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                {
                    let tmp_ex = lock_path.with_extension("lock.rb-tmp");
                    let _ = win32_sqlite::reclaim_unix_dir_lock_with_exchange(
                        &lock_path,
                        30.0,
                        |a, b| win32_sqlite::simulated_exchange_paths(a, b, &tmp_ex),
                    );
                }
                if fs::symlink_metadata(&lock_path)
                    .map(|m| m.file_type().is_dir())
                    .unwrap_or(false)
                {
                    let _ = fs::remove_dir(&lock_path);
                }
                if !win32_sqlite::legacy_swap_path(&lock_path).exists()
                    && !win32_sqlite::legacy_dir_stage_path(&lock_path).exists()
                {
                    let _ = fs::remove_file(win32_sqlite::legacy_undo_path(&lock_path));
                    let _ = fs::remove_file(win32_sqlite::legacy_undo_tmp_path(&lock_path));
                }
                if has_v2_lock_state(&lock_path) {
                    busy.push(lock_path);
                }
            }
            let _ = kfh.unlock();
        }
        if busy.is_empty() {
            let epoch_res = write_v1_lock_epoch(state_root);
            let _ = lease_fh.unlock();
            return epoch_res.map_err(|_| vec![rio::lock_epoch_path(state_root)]);
        }
        let _ = lease_fh.unlock();
        if Instant::now() >= deadline {
            return Err(busy);
        }
        let rem = deadline.saturating_duration_since(Instant::now());
        thread::sleep(rem.min(Duration::from_millis(backoff_ms)));
        backoff_ms = (backoff_ms * 2).min(150);
    }
}

pub fn perform_diagnose_for_os(
    repo_root: &Path,
    config_dir: &Path,
    stack_home: &Path,
    is_windows: bool,
) -> Value {
    // INVARIANT: `--diagnose` is read-only (`install.sh --diagnose` compiles into an ephemeral temp directory on clean Unix checkouts without mutating `plugin/bin/carbon-stack`), so allow unbuilt source-tree hook binary when `rust/Cargo.toml` is present.
    let pf = preflight_check_for_os_mode(repo_root, config_dir, is_windows, true);
    let (backups, backups_err): (Vec<String>, Option<String>) = match list_backups_strict(stack_home) {
        Ok(list) => (
            list.into_iter()
                .filter_map(|p| p.file_name().and_then(|s| s.to_str()).map(|s| s.to_string()))
                .collect(),
            None,
        ),
        Err(e) => (Vec::new(), Some(e)),
    };
    let source_plugin_dir = repo_root.join("plugin");
    let source_glob_rule = repo_root.join("rules").join("uiux-design.md");
    let target_plugin_dir = config_dir.join("plugins").join(PLUGIN_NAME);
    let target_glob_rule = config_dir.join("rules").join("uiux-design.md");

    let plugin_trees_match = target_plugin_dir.is_dir()
        && effective_source_manifest(&source_plugin_dir, is_windows)
            == tree_manifest(&target_plugin_dir);
    let hooks_migrated_ok = inspect_global_hooks_migration(config_dir, &target_plugin_dir, is_windows)
        .map(|m| m.is_none())
        .unwrap_or(false);
    let in_sync = plugin_trees_match
        && has_executable_hook_mode_for_os(&target_plugin_dir, is_windows)
        && hooks_migrated_ok
        && target_glob_rule.is_file()
        && sha256_file_full(&source_glob_rule).ok() == sha256_file_full(&target_glob_rule).ok();

    let bundle_for_doctor = if target_plugin_dir.is_dir() {
        target_plugin_dir.to_string_lossy().into_owned()
    } else {
        source_plugin_dir.to_string_lossy().into_owned()
    };
    let reused_agy_val = if !target_plugin_dir.is_dir() || plugin_trees_match {
        pf.get("agy_validation").and_then(|av| {
            if av.get("ran").and_then(|v| v.as_bool()) == Some(true) {
                let ok = av.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                let out = av
                    .get("output")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Some((ok, out))
            } else {
                None
            }
        })
    } else {
        None
    };
    let allow_unbuilt_doctor_bin = !target_plugin_dir.is_dir()
        && pf
            .get("bootstrap_build_required")
            .and_then(|v| v.as_bool())
            == Some(true);
    let doctor_out = stack_doctor::collect_doctor_report_for_os(
        &repo_root.to_string_lossy(),
        Some(bundle_for_doctor.as_str()),
        false,
        reused_agy_val,
        is_windows,
        allow_unbuilt_doctor_bin,
    );
    let pf_ok = pf.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    let doc_ok = doctor_out.get("ok").and_then(|v| v.as_bool()).unwrap_or(true);
    let orphaned_retire = list_orphaned_stage_retire_dirs(config_dir);

    let mut out = json!({
        "ok": pf_ok && doc_ok && backups_err.is_none() && orphaned_retire.is_empty(),
        "installed": target_plugin_dir.is_dir(),
        "in_sync_with_source": in_sync && orphaned_retire.is_empty(),
        "backups_count": backups.len(),
        "latest_backup": backups.last().cloned(),
        "preflight": pf,
        "doctor": doctor_out,
    });
    if !orphaned_retire.is_empty() {
        if let Some(obj) = out.as_object_mut() {
            obj.insert(
                "interrupted_stage_retire_dirs".to_string(),
                json!(orphaned_retire),
            );
        }
    }
    if let (Some(err), Some(obj)) = (backups_err, out.as_object_mut()) {
        obj.insert("backups_error".to_string(), Value::String(err));
    }
    out
}

pub fn perform_diagnose(repo_root: &Path, config_dir: &Path, stack_home: &Path) -> Value {
    perform_diagnose_for_os(repo_root, config_dir, stack_home, cfg!(windows))
}

fn take_required_value(flag: &str, args: &[String], idx: &mut usize) -> Result<String, Value> {
    if *idx + 1 >= args.len() {
        return Err(json!({
            "ok": false,
            "error": "missing_flag_value",
            "flag": flag,
            "detail": format!("Argument '{}' requires a value", flag),
        }));
    }
    let next = args[*idx + 1].as_str();
    if next.trim().is_empty() || next.starts_with('-') {
        return Err(json!({
            "ok": false,
            "error": "missing_flag_value",
            "flag": flag,
            "detail": format!("Argument '{}' requires a non-flag path/value, got '{}'", flag, next),
        }));
    }
    *idx += 1;
    Ok(next.to_string())
}

fn validate_eq_value(flag: &str, raw: &str) -> Result<String, Value> {
    if raw.trim().is_empty() {
        return Err(json!({
            "ok": false,
            "error": "missing_flag_value",
            "flag": flag,
            "detail": format!("Argument '{}' requires a non-empty value", flag),
        }));
    }
    Ok(raw.to_string())
}

pub fn run_cli(args: &[String]) -> i32 {
    let mut dry_run = false;
    let mut diagnose = false;
    let mut list_backups_flag = false;
    let mut has_rollback = false;
    let mut rollback_sel = String::new();
    let mut force_foreign = false;
    let mut repo_root_arg = String::new();
    let mut config_dir_arg = String::new();
    let mut stack_home_arg = String::new();
    let mut pretty = false;

    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--dry-run" => dry_run = true,
            "--diagnose" => diagnose = true,
            "--list-backups" => list_backups_flag = true,
            "--force" | "--force-foreign" => force_foreign = true,
            "--pretty" => pretty = true,
            "--rollback" => {
                has_rollback = true;
                if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    if args[i + 1].trim().is_empty() {
                        rio::print_cli_json(
                            &json!({
                                "ok": false,
                                "error": "missing_flag_value",
                                "flag": "--rollback",
                            }),
                            pretty,
                        );
                        return 2;
                    }
                    rollback_sel = args[i + 1].clone();
                    i += 1;
                } else {
                    rollback_sel = "latest".to_string();
                }
            }
            "--repo-root" => match take_required_value("--repo-root", args, &mut i) {
                Ok(v) => repo_root_arg = v,
                Err(err) => {
                    rio::print_cli_json(&err, pretty);
                    return 2;
                }
            },
            "--target-config-dir" | "--config-dir" => {
                match take_required_value(a, args, &mut i) {
                    Ok(v) => config_dir_arg = v,
                    Err(err) => {
                        rio::print_cli_json(&err, pretty);
                        return 2;
                    }
                }
            }
            "--stack-home" => match take_required_value("--stack-home", args, &mut i) {
                Ok(v) => stack_home_arg = v,
                Err(err) => {
                    rio::print_cli_json(&err, pretty);
                    return 2;
                }
            },
            _ if a.starts_with("--rollback=") => {
                has_rollback = true;
                match validate_eq_value("--rollback", &a["--rollback=".len()..]) {
                    Ok(v) => rollback_sel = v,
                    Err(err) => {
                        rio::print_cli_json(&err, pretty);
                        return 2;
                    }
                }
            }
            _ if a.starts_with("--repo-root=") => {
                match validate_eq_value("--repo-root", &a["--repo-root=".len()..]) {
                    Ok(v) => repo_root_arg = v,
                    Err(err) => {
                        rio::print_cli_json(&err, pretty);
                        return 2;
                    }
                }
            }
            _ if a.starts_with("--target-config-dir=") => {
                match validate_eq_value(
                    "--target-config-dir",
                    &a["--target-config-dir=".len()..],
                ) {
                    Ok(v) => config_dir_arg = v,
                    Err(err) => {
                        rio::print_cli_json(&err, pretty);
                        return 2;
                    }
                }
            }
            _ if a.starts_with("--config-dir=") => {
                match validate_eq_value("--config-dir", &a["--config-dir=".len()..]) {
                    Ok(v) => config_dir_arg = v,
                    Err(err) => {
                        rio::print_cli_json(&err, pretty);
                        return 2;
                    }
                }
            }
            _ if a.starts_with("--stack-home=") => {
                match validate_eq_value("--stack-home", &a["--stack-home=".len()..]) {
                    Ok(v) => stack_home_arg = v,
                    Err(err) => {
                        rio::print_cli_json(&err, pretty);
                        return 2;
                    }
                }
            }
            "--help" | "-h" => {
                println!(
                    "usage: carbon-stack install [--dry-run] [--diagnose] [--list-backups] [--rollback [latest|<id>]] [--force|--force-foreign] [--repo-root <dir>] [--target-config-dir <dir>] [--stack-home <dir>] [--pretty]"
                );
                return 0;
            }
            other => {
                eprintln!("carbon-stack install: unknown argument '{}'", other);
                return 2;
            }
        }
        i += 1;
    }

    let non_install_modes =
        usize::from(diagnose) + usize::from(list_backups_flag) + usize::from(has_rollback);
    if non_install_modes > 1 || (non_install_modes == 1 && (dry_run || force_foreign)) {
        let err = json!({
            "ok": false,
            "error": "conflicting_mode_flags",
            "detail": "--diagnose, --list-backups, and --rollback are mutually exclusive and cannot be combined with --dry-run or --force-foreign",
        });
        rio::print_cli_json(&err, pretty);
        return 2;
    }

    let repo_root = resolve_repo_root(&repo_root_arg);
    let (config_dir, stack_home) = resolve_paths(&config_dir_arg, &stack_home_arg);

    let res = if diagnose {
        perform_diagnose(&repo_root, &config_dir, &stack_home)
    } else if list_backups_flag {
        match list_backups_strict(&stack_home) {
            Ok(list) => {
                let backups: Vec<String> = list
                    .into_iter()
                    .filter_map(|p| p.file_name().and_then(|s| s.to_str()).map(|s| s.to_string()))
                    .collect();
                json!({
                    "ok": true,
                    "backups_count": backups.len(),
                    "backups": backups,
                    "latest_backup": backups.last().cloned(),
                })
            }
            Err(e) => json!({
                "ok": false,
                "error": "backups_read_failed",
                "detail": e,
            }),
        }
    } else if has_rollback {
        perform_rollback(&config_dir, &stack_home, &rollback_sel)
    } else {
        perform_install(&repo_root, &config_dir, &stack_home, dry_run, force_foreign)
    };
    rio::print_cli_json(&res, pretty);
    if res.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDirGuard(PathBuf);
    impl TempDirGuard {
        fn new(label: &str) -> Self {
            let p = env::temp_dir().join(format!(
                "carbon-installer-test-{}-{}-{}",
                label,
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn test_install_idempotent_foreign_conflict_and_rollback() {
        let tmp = TempDirGuard::new("full");
        let repo = tmp.0.join("repo");
        let cfg = tmp.0.join("config");
        let shome = tmp.0.join("stack-home");

        fs::create_dir_all(repo.join("plugin").join("rules")).unwrap();
        fs::create_dir_all(repo.join("plugin").join("bin")).unwrap();
        fs::create_dir_all(repo.join("rules")).unwrap();
        fs::write(
            repo.join("plugin").join("plugin.json"),
            r#"{"name":"gemini-carbon-stack","version":"0.2.0"}"#,
        )
        .unwrap();
        fs::write(
            repo.join("plugin").join("hooks.json"),
            r#"{"carbon-stack":{
                "enabled":true,
                "SessionStart":[{"type":"command","command":"bin/carbon-stack hook --event SessionStart"}],
                "PreInvocation":[{"type":"command","command":"bin/carbon-stack hook --event PreInvocation"}],
                "PreToolUse":[{"matcher":"read_file|run_command|invoke_subagent|swarm|swarm_wait|read_board|post_message|edit_file|write_file","hooks":[{"type":"command","command":"bin/carbon-stack hook --event PreToolUse"}]}],
                "PostToolUse":[{"matcher":"edit_file|write_file|run_command","hooks":[{"type":"command","command":"bin/carbon-stack hook --event PostToolUse"}]}],
                "Stop":[{"type":"command","command":"bin/carbon-stack hook --event Stop"}]
            }}"#,
        )
        .unwrap();
        fs::write(
            repo.join("plugin").join("rules").join("AGENTS.md"),
            "# Constitution\n",
        )
        .unwrap();
        fs::write(
            repo.join("rules").join("uiux-design.md"),
            "# Frontend UI/UX & Live Browser Verification Rules\n",
        )
        .unwrap();

        // INVARIANT: Preflight rejects missing/empty hook binary before touching destination.
        let missing_bin = perform_install(&repo, &cfg, &shome, false, false);
        assert_eq!(missing_bin["ok"], false);
        assert_eq!(missing_bin["stage"], "preflight");

        let bin_rel = platform_hook_binary_rel(cfg!(windows));
        let stub_bytes: &[u8] = if cfg!(windows) {
            b"MZ\x90\x00stub-hook-bin"
        } else {
            b"\x7fELFstub-hook-bin"
        };
        fs::write(repo.join("plugin").join(bin_rel), stub_bytes).unwrap();

        let dry = perform_install(&repo, &cfg, &shome, true, false);
        assert_eq!(dry["ok"], true);
        assert_eq!(dry["dry_run"], true);
        assert_eq!(dry["already_up_to_date"], false);
        assert!(!cfg.join("plugins").join(PLUGIN_NAME).exists());

        let inst1 = perform_install(&repo, &cfg, &shome, false, false);
        assert_eq!(inst1["ok"], true);
        assert_eq!(inst1["already_up_to_date"], false);
        assert!(cfg.join("plugins").join(PLUGIN_NAME).join("plugin.json").is_file());
        assert!(cfg.join("rules").join("uiux-design.md").is_file());

        // INVARIANT: Stale files left in target plugin dir from prior versions are pruned on update.
        let stale_py = cfg
            .join("plugins")
            .join(PLUGIN_NAME)
            .join("hooks")
            .join("legacy.py");
        fs::create_dir_all(stale_py.parent().unwrap()).unwrap();
        fs::write(&stale_py, "# legacy\n").unwrap();

        let inst_prune = perform_install(&repo, &cfg, &shome, false, false);
        assert_eq!(inst_prune["ok"], true);
        assert!(!stale_py.exists());

        let inst_idem = perform_install(&repo, &cfg, &shome, false, false);
        assert_eq!(inst_idem["ok"], true);
        assert_eq!(inst_idem["already_up_to_date"], true);

        // INVARIANT: Foreign `uiux-design.md` is protected unless `--force-foreign` is passed.
        fs::write(cfg.join("rules").join("uiux-design.md"), "# Custom Foreign Rule\n").unwrap();
        let blocked = perform_install(&repo, &cfg, &shome, false, false);
        assert_eq!(blocked["ok"], false);
        assert_eq!(blocked["stage"], "conflict_check");

        let forced = perform_install(&repo, &cfg, &shome, false, true);
        assert_eq!(forced["ok"], true);
        let b_id = forced["backup_id"].as_str().unwrap().to_string();

        let rolled = perform_rollback(&cfg, &shome, &b_id);
        assert_eq!(rolled["ok"], true);
        let restored_txt = fs::read_to_string(cfg.join("rules").join("uiux-design.md")).unwrap();
        assert!(restored_txt.contains("Custom Foreign Rule"));

        // INVARIANT: Unix target normalization rewrites `hooks.json` away from `.exe` and rejects Windows MZ binaries on non-Windows.
        fs::write(
            repo.join("plugin").join("hooks.json"),
            r#"{"carbon-stack":{"SessionStart":[{"type":"command","command":"bin\\carbon-stack.exe hook --event SessionStart"}]}}"#,
        )
        .unwrap();
        fs::write(repo.join("plugin").join("bin").join("carbon-stack"), b"MZ\x90\x00pe").unwrap();
        let pf_unix_mz = preflight_check_for_os(&repo, &cfg, false);
        assert_eq!(pf_unix_mz["ok"], false);

        fs::write(
            repo.join("plugin").join("bin").join("carbon-stack"),
            b"\x7fELFnative-unix-bin",
        )
        .unwrap();
        let unix_dst = tmp.0.join("unix-dst");
        copy_clean_tree_for_os(&repo.join("plugin"), &unix_dst, false).unwrap();
        let unix_hooks = fs::read_to_string(unix_dst.join("hooks.json")).unwrap();
        assert!(unix_hooks.contains("bin/carbon-stack hook --event SessionStart"));
        assert!(!unix_hooks.contains(".exe"));
        assert!(!unix_dst.join("bin").join("carbon-stack.exe").exists());
        assert_eq!(
            effective_source_manifest(&repo.join("plugin"), false),
            tree_manifest(&unix_dst)
        );

        // INVARIANT: Nested NTFS directory junction inside target plugin dir is rejected in both preflight and copy without writing outside target_plugin_dir.
        #[cfg(windows)]
        {
            let cfg_j = tmp.0.join("config-junc");
            let shome_j = tmp.0.join("stack-junc");
            let outside = tmp.0.join("outside-victim");
            fs::create_dir_all(&outside).unwrap();
            let junc_parent = cfg_j.join("plugins").join(PLUGIN_NAME);
            fs::create_dir_all(&junc_parent).unwrap();
            let junc_bin = junc_parent.join("bin");
            let mk = Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&junc_bin)
                .arg(&outside)
                .output()
                .unwrap();
            assert!(mk.status.success());

            let junc_inst = perform_install(&repo, &cfg_j, &shome_j, false, true);
            assert_eq!(junc_inst["ok"], false);
            assert_eq!(junc_inst["stage"], "preflight");
            assert!(copy_clean_tree(&repo.join("plugin"), &junc_parent).is_err());
            assert!(fs::read_dir(&outside).unwrap().next().is_none());
            let _ = fs::remove_dir(&junc_bin);
        }

        // INVARIANT: Rollback fails closed (`ok: false`) if pre-install removal of `glob_rule` or `plugin_dir` fails.
        let cfg_rb = tmp.0.join("config-rb");
        let shome_rb = tmp.0.join("stack-rb");
        let first_inst = perform_install(&repo, &cfg_rb, &shome_rb, false, true);
        assert_eq!(first_inst["ok"], true);
        let first_bid = first_inst["backup_id"].as_str().unwrap().to_string();
        let rule_path = cfg_rb.join("rules").join("uiux-design.md");
        fs::remove_file(&rule_path).unwrap();
        // INVARIANT: Replacing the file path with a directory makes `fs::remove_file` fail deterministically across OSes.
        fs::create_dir_all(rule_path.join("locked-subdir")).unwrap();
        let failed_rb = perform_rollback(&cfg_rb, &shome_rb, &first_bid);
        assert_eq!(failed_rb["ok"], false);
        assert_eq!(failed_rb["stage"], "rollback_validate");
        assert!(cfg_rb
            .join("plugins")
            .join(PLUGIN_NAME)
            .join("plugin.json")
            .is_file());
        let _ = fs::remove_dir_all(&rule_path);

        // INVARIANT: Legacy Python backups (without `files_sha256` / `sha256` fields) restore cleanly when intact and fail closed if a hook target is missing.
        fs::write(
            repo.join("plugin").join("hooks.json"),
            r#"{"carbon-stack":{
                "enabled":true,
                "SessionStart":[{"type":"command","command":"bin/carbon-stack hook --event SessionStart"}],
                "PreInvocation":[{"type":"command","command":"bin/carbon-stack hook --event PreInvocation"}],
                "PreToolUse":[{"matcher":"read_file|run_command|invoke_subagent|swarm|swarm_wait|read_board|post_message|edit_file|write_file","hooks":[{"type":"command","command":"bin/carbon-stack hook --event PreToolUse"}]}],
                "PostToolUse":[{"matcher":"edit_file|write_file|run_command","hooks":[{"type":"command","command":"bin/carbon-stack hook --event PostToolUse"}]}],
                "Stop":[{"type":"command","command":"bin/carbon-stack hook --event Stop"}]
            }}"#,
        )
        .unwrap();
        let cfg_leg = tmp.0.join("config-legacy");
        let shome_leg = tmp.0.join("stack-legacy");
        assert_eq!(perform_install(&repo, &cfg_leg, &shome_leg, false, true)["ok"], true);
        fs::write(
            repo.join("plugin").join("rules").join("AGENTS.md"),
            "# Constitution v-legacy-next\n",
        )
        .unwrap();
        let leg_upd = perform_install(&repo, &cfg_leg, &shome_leg, false, true);
        assert_eq!(leg_upd["ok"], true);
        let leg_bid = leg_upd["backup_id"].as_str().unwrap().to_string();
        let leg_mf_path = shome_leg.join("backups").join(&leg_bid).join("manifest.json");
        let mut leg_mf = rio::read_json(&leg_mf_path).unwrap();
        if let Some(p_obj) = leg_mf["targets"]["plugin_dir"].as_object_mut() {
            p_obj.remove("files_sha256");
        }
        if let Some(r_obj) = leg_mf["targets"]["glob_rule"].as_object_mut() {
            r_obj.remove("sha256");
        }
        rio::write_json(&leg_mf_path, &leg_mf).unwrap();
        let ok_leg_rb = perform_rollback(&cfg_leg, &shome_leg, &leg_bid);
        assert_eq!(ok_leg_rb["ok"], true);

        let hook_rel_leg = platform_hook_binary_rel(cfg!(windows));
        fs::remove_file(
            shome_leg
                .join("backups")
                .join(&leg_bid)
                .join("plugin_dir")
                .join(hook_rel_leg),
        )
        .unwrap();
        let broken_leg_rb = perform_rollback(&cfg_leg, &shome_leg, &leg_bid);
        assert_eq!(broken_leg_rb["ok"], false);
        assert_eq!(broken_leg_rb["stage"], "rollback_validate");

        // INVARIANT: Historical 4-group pre-Rust Python `hooks.json` backups (`0381212^`) restore cleanly and fail closed if a referenced `.py` hook is missing.
        let py_bak_dir = shome_leg.join("backups").join("install-20260101-000001-legacypy");
        fs::create_dir_all(py_bak_dir.join("plugin_dir").join("rules")).unwrap();
        fs::create_dir_all(py_bak_dir.join("plugin_dir").join("hooks")).unwrap();
        fs::create_dir_all(py_bak_dir.join("rules")).unwrap();
        fs::write(
            py_bak_dir.join("plugin_dir").join("plugin.json"),
            r#"{"name":"gemini-carbon-stack","version":"0.1.0"}"#,
        )
        .unwrap();
        fs::write(
            py_bak_dir.join("plugin_dir").join("rules").join("AGENTS.md"),
            "# Legacy Constitution\n",
        )
        .unwrap();
        fs::write(
            py_bak_dir.join("rules").join("uiux-design.md"),
            "# Frontend UI/UX & Live Browser Verification Rules\n",
        )
        .unwrap();
        for py_h in ["safety_guards.py", "continuity.py", "cwg_mark.py", "cwg_stop.py", "tokenade_hook.py"] {
            fs::write(py_bak_dir.join("plugin_dir").join("hooks").join(py_h), "# py hook\n").unwrap();
        }
        fs::write(
            py_bak_dir.join("plugin_dir").join("hooks.json"),
            r#"{
                "safety-and-quality-guards":{"PreToolUse":[{"matcher":"run_command|edit_file|write_file|swarm|read_board|swarm_wait","hooks":[{"command":"python -X utf8 hooks/safety_guards.py --event PreToolUse"}]}]},
                "continuity":{"SessionStart":[{"hooks":[{"command":"python -X utf8 hooks/continuity.py --event SessionStart"}]}],"PreInvocation":[{"hooks":[{"command":"python -X utf8 hooks/continuity.py --event PreInvocation"}]}]},
                "code-work-gate":{"PostToolUse":[{"hooks":[{"command":"python -X utf8 hooks/cwg_mark.py --event PostToolUse"}]}],"Stop":[{"hooks":[{"command":"python -X utf8 hooks/cwg_stop.py --event Stop"}]}]},
                "tokenade":{"PreToolUse":[{"matcher":"run_command","hooks":[{"command":"python -X utf8 hooks/tokenade_hook.py --event PreToolUse"}]}]}
            }"#,
        )
        .unwrap();
        rio::write_json(
            &py_bak_dir.join("manifest.json"),
            &json!({
                "backup_id": "install-20260101-000001-legacypy",
                "config_dir": cfg_leg.to_string_lossy(),
                "targets": {
                    "plugin_dir": {"path": cfg_leg.join("plugins").join(PLUGIN_NAME).to_string_lossy(), "existed": true},
                    "glob_rule": {"path": cfg_leg.join("rules").join("uiux-design.md").to_string_lossy(), "existed": true},
                }
            }),
        )
        .unwrap();
        let ok_py_rb = perform_rollback(&cfg_leg, &shome_leg, "install-20260101-000001-legacypy");
        assert_eq!(ok_py_rb["ok"], true);
        assert!(cfg_leg.join("plugins").join(PLUGIN_NAME).join("hooks").join("cwg_stop.py").is_file());

        fs::remove_file(py_bak_dir.join("plugin_dir").join("hooks").join("cwg_stop.py")).unwrap();
        let bad_py_rb = perform_rollback(&cfg_leg, &shome_leg, "install-20260101-000001-legacypy");
        assert_eq!(bad_py_rb["ok"], false);
        assert_eq!(bad_py_rb["stage"], "rollback_validate");

        // INVARIANT: When compensating plugin restore itself fails, `stage_plugin` is preserved on disk (`recovery_snapshot_path`) instead of being deleted.
        let stage_fail_root = tmp.0.join("comp-fail-stage");
        let stage_fail_plug = stage_fail_root.join("plugin_dir");
        fs::create_dir_all(&stage_fail_plug).unwrap();
        fs::write(stage_fail_plug.join("plugin.json"), r#"{"name":"gemini-carbon-stack"}"#).unwrap();
        let bad_p_dst = tmp.0.join("comp-bad-dst");
        fs::create_dir_all(bad_p_dst.join("plugin.json").join("nested-blocker")).unwrap();
        let unused_r_dst = tmp.0.join("comp-unused-rule.md");
        let unused_h_dst = tmp.0.join("comp-unused-hooks.json");
        let comp_res = compensate_plugin_rollback(
            &RollbackStage {
                had_live_plugin: true,
                expected_live_hashes: None,
                had_live_rule: false,
                expected_live_rule_sha: None,
                had_live_hooks: false,
                expected_live_hooks_sha: None,
                had_prior_v1_epoch: false,
                drain_timeout: Duration::from_millis(50),
                config_dir: &stage_fail_root,
                state_root: &stage_fail_root,
                stage_root: &stage_fail_root,
                stage_plugin: &stage_fail_plug,
                stage_rule: &unused_r_dst,
                stage_hooks: &unused_h_dst,
                p_target: &bad_p_dst,
                r_target: &unused_r_dst,
                h_target: &unused_h_dst,
            },
            RollbackMutated::default(),
            json!({"ok": false, "error": "step2_failed"}),
        );
        assert_eq!(comp_res["ok"], false);
        assert_eq!(comp_res["compensated_plugin_restore"], false);
        assert!(comp_res["recovery_snapshot_path"].as_str().is_some());
        assert!(stage_fail_plug.join("plugin.json").is_file());

        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let cfg_lock = tmp.0.join("config-comp-winlock");
            let shome_lock = tmp.0.join("stack-comp-winlock");
            let inst_lock = perform_install(&repo, &cfg_lock, &shome_lock, false, true);
            assert_eq!(inst_lock["ok"], true);
            let bid_lock = inst_lock["backup_id"].as_str().unwrap().to_string();

            // INVARIANT: Unreadable file inside live `p_target` aborts at `rollback_stage` BEFORE mutating `p_target` or `r_target`.
            let unread_agent = cfg_lock
                .join("plugins")
                .join(PLUGIN_NAME)
                .join("rules")
                .join("AGENTS.md");
            {
                let _unread_guard = fs::OpenOptions::new()
                    .read(true)
                    .share_mode(0)
                    .open(&unread_agent)
                    .unwrap();
                let stage_abort = perform_rollback(&cfg_lock, &shome_lock, &bid_lock);
                assert_eq!(stage_abort["ok"], false);
                assert_eq!(stage_abort["stage"], "rollback_stage");
                assert!(cfg_lock.join("rules").join("uiux-design.md").is_file());
            }

            let locked_rule = cfg_lock.join("rules").join("uiux-design.md");
            let _exclusive_guard = fs::OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(&locked_rule)
                .unwrap();
            let comp_win = perform_rollback(&cfg_lock, &shome_lock, &bid_lock);
            assert_eq!(comp_win["ok"], false);
            assert_eq!(comp_win["stage"], "rollback_rule_remove");
            assert_eq!(comp_win["compensated_plugin_restore"], true);
            assert!(cfg_lock.join("plugins").join(PLUGIN_NAME).join("plugin.json").is_file());
        }

        // INVARIANT: Incomplete backup (`existed: true` with missing `plugin_dir` snapshot) fails validation without deleting live plugin.
        let cfg_inc = tmp.0.join("config-incomplete");
        let shome_inc = tmp.0.join("stack-incomplete");
        assert_eq!(perform_install(&repo, &cfg_inc, &shome_inc, false, true)["ok"], true);
        fs::write(
            repo.join("plugin").join("rules").join("AGENTS.md"),
            "# Constitution v2\n",
        )
        .unwrap();
        let upd_inc = perform_install(&repo, &cfg_inc, &shome_inc, false, true);
        assert_eq!(upd_inc["ok"], true);
        let inc_bid = upd_inc["backup_id"].as_str().unwrap().to_string();
        // INVARIANT: Deleting a single critical file (`bin/carbon-stack*`) inside an existing `plugin_dir` backup fails SHA-256 inventory validation without deleting the live hook binary.
        let hook_rel = platform_hook_binary_rel(cfg!(windows));
        fs::remove_file(
            shome_inc
                .join("backups")
                .join(&inc_bid)
                .join("plugin_dir")
                .join(hook_rel),
        )
        .unwrap();
        let partial_rb = perform_rollback(&cfg_inc, &shome_inc, &inc_bid);
        assert_eq!(partial_rb["ok"], false);
        assert_eq!(partial_rb["stage"], "rollback_validate");
        assert!(cfg_inc
            .join("plugins")
            .join(PLUGIN_NAME)
            .join(hook_rel)
            .is_file());

        fs::remove_dir_all(shome_inc.join("backups").join(&inc_bid).join("plugin_dir")).unwrap();
        let bad_rb = perform_rollback(&cfg_inc, &shome_inc, &inc_bid);
        assert_eq!(bad_rb["ok"], false);
        assert_eq!(bad_rb["stage"], "rollback_validate");
        assert!(cfg_inc.join("plugins").join(PLUGIN_NAME).join("plugin.json").is_file());

        // INVARIANT: `ensure_no_links_between` and `perform_rollback` reject equal-root (`config_dir` itself) and `..` traversal targets.
        assert!(ensure_no_links_between(&cfg_inc, &cfg_inc).is_err());
        assert!(ensure_no_links_between(&cfg_inc, &cfg_inc.join("plugins").join("..")).is_err());
        let mf_path = shome_inc.join("backups").join(&inc_bid).join("manifest.json");
        let mut tampered_mf = rio::read_json(&mf_path).unwrap();
        tampered_mf["targets"]["plugin_dir"]["existed"] = json!(false);
        tampered_mf["targets"]["plugin_dir"]["path"] = json!(cfg_inc.to_string_lossy());
        rio::write_json(&mf_path, &tampered_mf).unwrap();
        let tampered_rb = perform_rollback(&cfg_inc, &shome_inc, &inc_bid);
        assert_eq!(tampered_rb["ok"], false);
        assert_eq!(tampered_rb["stage"], "rollback_validate");
        assert!(cfg_inc.is_dir());
        assert!(cfg_inc.join("plugins").join(PLUGIN_NAME).join("plugin.json").is_file());

        // INVARIANT: Redirecting parent `config/plugins` to a junction after backup is rejected on rollback before mutating the redirected target.
        #[cfg(windows)]
        {
            let outside_p = tmp.0.join("outside-plugins");
            let outside_p_bundle = outside_p.join(PLUGIN_NAME);
            fs::create_dir_all(&outside_p_bundle).unwrap();
            let victim_file = outside_p_bundle.join("keep.txt");
            fs::write(&victim_file, "keep").unwrap();

            let cfg_pj = tmp.0.join("config-parent-junc");
            let shome_pj = tmp.0.join("stack-parent-junc");
            let pj_inst = perform_install(&repo, &cfg_pj, &shome_pj, false, true);
            assert_eq!(pj_inst["ok"], true);
            let pj_bid = pj_inst["backup_id"].as_str().unwrap().to_string();
            fs::remove_dir_all(cfg_pj.join("plugins")).unwrap();
            let mk_p = Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(cfg_pj.join("plugins"))
                .arg(&outside_p)
                .output()
                .unwrap();
            assert!(mk_p.status.success());

            let pj_rb = perform_rollback(&cfg_pj, &shome_pj, &pj_bid);
            assert_eq!(pj_rb["ok"], false);
            assert_eq!(pj_rb["stage"], "rollback_link_check");
            assert!(victim_file.is_file());
            let _ = fs::remove_dir(cfg_pj.join("plugins"));
        }

        // INVARIANT: `run_agy_plugin_validate` fails closed on spawn errors and timeouts; `preflight_check_for_os_mode` allows unbuilt non-Windows hook binary only in `--dry-run` mode.
        let (ok_missing_agy, msg_missing_agy) = run_agy_plugin_validate(
            &tmp.0.join("missing-agy-binary.exe").to_string_lossy(),
            &repo.join("plugin"),
            1_000,
        );
        assert!(!ok_missing_agy);
        assert!(!msg_missing_agy.is_empty());

        #[cfg(windows)]
        {
            let slow_bat = tmp.0.join("slow-agy.cmd");
            fs::write(&slow_bat, "@echo off\r\nping -n 6 127.0.0.1 >NUL\r\n").unwrap();
            let (ok_timeout_agy, msg_timeout_agy) = run_agy_plugin_validate(
                &slow_bat.to_string_lossy(),
                &repo.join("plugin"),
                250,
            );
            assert!(!ok_timeout_agy);
            assert!(
                msg_timeout_agy.contains("timed out"),
                "expected timeout error, got: {}",
                msg_timeout_agy
            );
        }

        let clean_posix_repo = tmp.0.join("clean-posix-repo");
        fs::create_dir_all(clean_posix_repo.join("plugin").join("rules")).unwrap();
        fs::create_dir_all(clean_posix_repo.join("plugin").join("agents")).unwrap();
        fs::create_dir_all(clean_posix_repo.join("plugin").join("bin")).unwrap();
        fs::create_dir_all(clean_posix_repo.join("rules")).unwrap();
        fs::create_dir_all(clean_posix_repo.join("rust")).unwrap();
        fs::write(
            clean_posix_repo.join("plugin").join("plugin.json"),
            r#"{"name":"gemini-carbon-stack","displayName":"Gemini Carbon Stack","version":"1.0.0"}"#,
        )
        .unwrap();
        fs::write(
            clean_posix_repo.join("plugin").join("hooks.json"),
            r#"{"carbon-stack":{
                "SessionStart":[{"type":"command","command":"bin/carbon-stack hook --event SessionStart"}],
                "PreInvocation":[{"type":"command","command":"bin/carbon-stack hook --event PreInvocation"}],
                "PreToolUse":[{"matcher":"read_file|run_command|invoke_subagent|swarm|swarm_wait|read_board|post_message|edit_file|write_file","hooks":[{"type":"command","command":"bin/carbon-stack hook --event PreToolUse"}]}],
                "PostToolUse":[{"matcher":"edit_file|write_file|run_command","hooks":[{"type":"command","command":"bin/carbon-stack hook --event PostToolUse"}]}],
                "Stop":[{"type":"command","command":"bin/carbon-stack hook --event Stop"}]
            }}"#,
        )
        .unwrap();
        fs::write(
            clean_posix_repo.join("plugin").join("bin").join("carbon-stack.exe"),
            b"MZ\x90\x00windows-only-bin-in-git",
        )
        .unwrap();
        for sname in [
            "swarm-orchestration",
            "s-two",
            "s-three",
            "s-four",
            "s-five",
            "s-six",
            "s-seven",
            "s-eight",
            "s-nine",
            "s-ten",
        ] {
            let sdir = clean_posix_repo.join("plugin").join("skills").join(sname);
            fs::create_dir_all(&sdir).unwrap();
            fs::write(
                sdir.join("SKILL.md"),
                format!("---\nname: {}\ndescription: Skill {}\n---\n# {}\n", sname, sname, sname),
            )
            .unwrap();
        }
        for aname in ["a-one", "a-two", "a-three", "a-four"] {
            fs::write(
                clean_posix_repo
                    .join("plugin")
                    .join("agents")
                    .join(format!("{}.md", aname)),
                format!("---\nname: {}\ndescription: Agent {}\n---\nPrompt.\n", aname, aname),
            )
            .unwrap();
        }
        fs::copy(
            repo.join("plugin").join("rules").join("AGENTS.md"),
            clean_posix_repo.join("plugin").join("rules").join("AGENTS.md"),
        )
        .unwrap();
        fs::copy(
            repo.join("rules").join("uiux-design.md"),
            clean_posix_repo.join("rules").join("uiux-design.md"),
        )
        .unwrap();
        fs::write(
            clean_posix_repo.join("rust").join("Cargo.toml"),
            "[package]\nname = \"carbon-stack\"\nversion = \"0.2.0\"\n",
        )
        .unwrap();
        let cfg_posix_dry = tmp.0.join("cfg-posix-dry");
        let shome_posix_dry = tmp.0.join("shome-posix-dry");
        let pf_strict = preflight_check_for_os_mode(&clean_posix_repo, &cfg_posix_dry, false, false);
        assert_eq!(pf_strict["ok"], false);
        let pf_dry = preflight_check_for_os_mode(&clean_posix_repo, &cfg_posix_dry, false, true);
        assert_eq!(pf_dry["ok"], true, "pf_dry failed: {}", pf_dry);
        assert_eq!(pf_dry["bootstrap_build_required"], true);
        assert!(!clean_posix_repo.join("plugin").join("bin").join("carbon-stack").exists());
        let diag_posix = perform_diagnose_for_os(
            &clean_posix_repo,
            &cfg_posix_dry,
            &shome_posix_dry,
            false,
        );
        assert_eq!(diag_posix["ok"], true, "clean POSIX diagnose failed: {}", diag_posix);
        assert_eq!(diag_posix["installed"], false);
        assert_eq!(diag_posix["preflight"]["bootstrap_build_required"], true);
        // INVARIANT: If the plugin IS installed in `config_dir/plugins/gemini-carbon-stack` on Unix without a working `bin/carbon-stack` binary, `--diagnose` MUST return `ok: false` (`commands_ok: false`) even when run from a clean source checkout.
        let cfg_broken_posix = tmp.0.join("cfg-broken-posix");
        let broken_plug = cfg_broken_posix.join("plugins").join(PLUGIN_NAME);
        copy_clean_tree_for_os(&clean_posix_repo.join("plugin"), &broken_plug, false).unwrap();
        let _ = fs::remove_file(broken_plug.join("bin").join("carbon-stack"));
        let diag_broken_posix = perform_diagnose_for_os(
            &clean_posix_repo,
            &cfg_broken_posix,
            &shome_posix_dry,
            false,
        );
        assert_eq!(diag_broken_posix["installed"], true);
        assert_eq!(diag_broken_posix["doctor"]["hooks_json"]["commands_ok"], false);
        assert_eq!(diag_broken_posix["doctor"]["ok"], false);
        assert_eq!(diag_broken_posix["ok"], false);
        // INVARIANT: Even when `bin/carbon-stack` exists, an installed Unix `hooks.json` still pointing to `bin\\carbon-stack.exe` fails `commands_ok` and `--diagnose`.
        fs::write(broken_plug.join("bin").join("carbon-stack"), b"\x7fELFvalid").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(broken_plug.join("bin").join("carbon-stack"))
                .unwrap()
                .permissions();
            perms.set_mode(0o755);
            fs::set_permissions(broken_plug.join("bin").join("carbon-stack"), perms).unwrap();
        }
        fs::write(
            broken_plug.join("hooks.json"),
            fs::read_to_string(broken_plug.join("hooks.json"))
                .unwrap()
                .replace("bin/carbon-stack", "bin\\carbon-stack.exe"),
        )
        .unwrap();
        let diag_wrong_cmd = perform_diagnose_for_os(
            &clean_posix_repo,
            &cfg_broken_posix,
            &shome_posix_dry,
            false,
        );
        assert_eq!(diag_wrong_cmd["doctor"]["hooks_json"]["commands_ok"], false);
        assert_eq!(diag_wrong_cmd["ok"], false);
        // INVARIANT: `perform_rollback` preserves active `*.flight.lock` kernel locks (never unlinking or replacing their inode even when older than 30s), waits for in-flight `v2` `.lock.k` holders to exit/crash before sweeping left-over `.lock` directories, and fails closed with `v2` compensation if a hung `v2` holder exceeds `drain_timeout`.
        assert_eq!(perform_install(&repo, &cfg, &shome, false, true)["ok"], true);
        let flight_dir = shome.join("state").join("gate").join("codex_threads");
        fs::create_dir_all(&flight_dir).unwrap();
        let flight_lock = flight_dir.join("active-review.flight.lock");
        let flight_fh = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&flight_lock)
            .unwrap();
        flight_fh.set_modified(UNIX_EPOCH + Duration::from_secs(1_700_000_000)).unwrap();
        flight_fh.try_lock().unwrap();
        let crashed_dir_lock = shome.join("state").join("chips").join(".chips.lock");
        let transient_dir_lock = shome.join("state").join("chips").join(".transient.lock");
        fs::create_dir_all(&crashed_dir_lock).unwrap();
        fs::create_dir_all(&transient_dir_lock).unwrap();
        let transient_k = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(rio::kernel_companion_lock_path(&transient_dir_lock))
            .unwrap();
        transient_k.try_lock().unwrap();
        let crash_sim_handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            drop(transient_k);
        });
        let rb_drain_ok = perform_rollback_with_drain_timeout(
            &cfg,
            &shome,
            "latest",
            Duration::from_millis(600),
        );
        crash_sim_handle.join().unwrap();
        assert_eq!(rb_drain_ok["ok"], true);
        assert!(!crashed_dir_lock.exists());
        assert!(!transient_dir_lock.exists());
        assert_eq!(
            fs::read_to_string(rio::lock_epoch_path(&shome.join("state")))
                .unwrap()
                .trim(),
            "v1"
        );
        // INVARIANT: Simulate an already-running `v2` `codex-lane review` process (still holding `flight_fh` across `perform_rollback`) later committing its review packet via `rio::with_file_lock`: `.lock_epoch = "v1"` forces pure `v1` regular-file locking (never creating a directory or `.k` companion) so `v1`'s `fs::remove_file` can always reclaim it on crash.
        let late_pkt_lock = flight_dir.join("post-rollback-packet.lock");
        rio::with_file_lock(&late_pkt_lock, 1.0, 30.0, |acq| {
            assert!(acq);
            assert!(late_pkt_lock.is_file());
            assert!(!late_pkt_lock.is_dir());
            assert!(!rio::kernel_companion_lock_path(&late_pkt_lock).exists());
            // INVARIANT: Even on Windows, an unshared `v1` file handle drops on process exit; verify the lock file written during `v1` epoch is a regular `<pid> <ts>` file rather than a `v2` artifact.
            assert!(!win32_sqlite::is_v2_lock_artifact(&late_pkt_lock));
        });
        assert!(!late_pkt_lock.exists());
        assert!(flight_lock.is_file());
        let flight_contender = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&flight_lock)
            .unwrap();
        assert!(flight_contender.try_lock().is_err());
        drop(flight_contender);
        drop(flight_fh);

        assert_eq!(perform_install(&repo, &cfg, &shome, false, true)["ok"], true);
        assert!(!rio::lock_epoch_path(&shome.join("state")).exists());
        let lease_held_fh = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(rio::v2_lease_path(&shome.join("state")))
            .unwrap();
        lease_held_fh.try_lock_shared().unwrap();
        let rb_lease_busy = perform_rollback_with_drain_timeout(
            &cfg,
            &shome,
            "latest",
            Duration::from_millis(50),
        );
        assert_eq!(rb_lease_busy["ok"], false);
        assert_eq!(rb_lease_busy["stage"], "rollback_v2_lock_drain");
        assert_eq!(rb_lease_busy["compensated_plugin_restore"], true);
        assert!(!rio::lock_epoch_path(&shome.join("state")).exists());
        drop(lease_held_fh);
        let hung_dir_lock = shome.join("state").join("chips").join(".hung.lock");
        fs::create_dir_all(&hung_dir_lock).unwrap();
        let hung_k = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(rio::kernel_companion_lock_path(&hung_dir_lock))
            .unwrap();
        hung_k.try_lock().unwrap();
        let rb_hung = perform_rollback_with_drain_timeout(
            &cfg,
            &shome,
            "latest",
            Duration::from_millis(60),
        );
        assert_eq!(rb_hung["ok"], false);
        assert_eq!(rb_hung["stage"], "rollback_v2_lock_drain");
        assert_eq!(rb_hung["compensated_plugin_restore"], true);
        assert!(cfg.join("plugins").join(PLUGIN_NAME).is_dir());
        assert!(hung_dir_lock.is_dir());
        drop(hung_k);
        let _ = fs::remove_dir(&hung_dir_lock);

        // INVARIANT: Interruption between plugin restoration and rollback completion still leaves `.lock_epoch = "v1"` committed and all crashed `v2` lock directories swept BEFORE `v1` files were activated.
        assert_eq!(perform_install(&repo, &cfg, &shome, false, true)["ok"], true);
        let pre_abort_dir_lock = shome.join("state").join("chips").join(".pre-abort.lock");
        fs::create_dir_all(&pre_abort_dir_lock).unwrap();
        let rb_interrupted = perform_rollback_with_hooks(
            &cfg,
            &shome,
            "latest",
            Duration::from_millis(200),
            true,
        );
        assert_eq!(
            rb_interrupted["stage"],
            "simulated_interruption_after_plugin_restore"
        );
        assert!(!pre_abort_dir_lock.exists());
        assert_eq!(
            fs::read_to_string(rio::lock_epoch_path(&shome.join("state")))
                .unwrap()
                .trim(),
            "v1"
        );

        // INVARIANT: Pre-existing `.lock_epoch.tmp` symlink/junction inside `state` never truncates or overwrites its outside target during `perform_rollback`.
        assert_eq!(perform_install(&repo, &cfg, &shome, false, true)["ok"], true);
        let outside_victim = tmp.0.join("outside_victim.txt");
        fs::write(&outside_victim, "DO_NOT_OVERWRITE").unwrap();
        let planted_epoch_tmp = shome.join("state").join(".lock_epoch.tmp");
        let _ = fs::remove_file(&planted_epoch_tmp);
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside_victim, &planted_epoch_tmp).unwrap();
        }
        #[cfg(windows)]
        {
            if std::os::windows::fs::symlink_file(&outside_victim, &planted_epoch_tmp).is_err() {
                fs::hard_link(&outside_victim, &planted_epoch_tmp).unwrap();
            }
        }
        let rb_with_planted_tmp = perform_rollback_with_drain_timeout(
            &cfg,
            &shome,
            "latest",
            Duration::from_millis(200),
        );
        assert_eq!(rb_with_planted_tmp["ok"], true);
        assert_eq!(
            fs::read_to_string(&outside_victim).unwrap(),
            "DO_NOT_OVERWRITE"
        );

        #[cfg(windows)]
        {
            // INVARIANT: On Windows, rolling back while the installed `bin/carbon-stack.exe` is actively mapped as a running process succeeds both when restoring a pre-install state (`p_existed == false`, removing `p_target`) and when restoring a Python-only snapshot without `.exe`.
            let ping_sys = PathBuf::from(r"C:\Windows\System32\ping.exe");
            if ping_sys.is_file() {
                let repo_pe = tmp.0.join("repo-live-pe");
                copy_clean_tree_for_os(&repo.join("plugin"), &repo_pe.join("plugin"), true).unwrap();
                fs::create_dir_all(repo_pe.join("rules")).unwrap();
                fs::copy(
                    repo.join("rules").join("uiux-design.md"),
                    repo_pe.join("rules").join("uiux-design.md"),
                )
                .unwrap();
                fs::copy(&ping_sys, repo_pe.join("plugin").join("bin").join("carbon-stack.exe")).unwrap();
                let cfg_pe = tmp.0.join("cfg-live-pe");
                let shome_pe = tmp.0.join("shome-live-pe");
                let inst_pe_1 = perform_install(&repo_pe, &cfg_pe, &shome_pe, false, true);
                assert_eq!(inst_pe_1["ok"], true);
                let bid_no_plugin = inst_pe_1["backup_id"].as_str().unwrap().to_string();
                let live_exe = cfg_pe
                    .join("plugins")
                    .join(PLUGIN_NAME)
                    .join("bin")
                    .join("carbon-stack.exe");
                let mut child_no_plug = Command::new(&live_exe)
                    .args(["-n", "30", "127.0.0.1"])
                    .stdout( std::process::Stdio::null())
                    .stderr( std::process::Stdio::null())
                    .spawn()
                    .unwrap();
                let rb_no_plug = perform_rollback(&cfg_pe, &shome_pe, &bid_no_plugin);
                let _ = child_no_plug.kill();
                let _ = child_no_plug.wait();
                assert_eq!(rb_no_plug["ok"], true, "rb_no_plug failed: {}", rb_no_plug);
                assert!(!cfg_pe.join("plugins").join(PLUGIN_NAME).exists());

                assert_eq!(perform_install(&repo_pe, &cfg_pe, &shome_pe, false, true)["ok"], true);
                let py_pe_bak = shome_pe.join("backups").join("install-20260101-000002-pyonly");
                fs::create_dir_all(py_pe_bak.join("plugin_dir").join("hooks")).unwrap();
                fs::create_dir_all(py_pe_bak.join("plugin_dir").join("rules")).unwrap();
                fs::create_dir_all(py_pe_bak.join("rules")).unwrap();
                fs::write(
                    py_pe_bak.join("plugin_dir").join("plugin.json"),
                    r#"{"name":"gemini-carbon-stack","version":"0.1.0"}"#,
                )
                .unwrap();
                fs::write(
                    py_pe_bak.join("plugin_dir").join("rules").join("AGENTS.md"),
                    "# Legacy\n",
                )
                .unwrap();
                fs::write(
                    py_pe_bak.join("rules").join("uiux-design.md"),
                    "# Rule\n",
                )
                .unwrap();
                for py_h in ["safety_guards.py", "continuity.py", "cwg_mark.py", "cwg_stop.py", "tokenade_hook.py"] {
                    fs::write(py_pe_bak.join("plugin_dir").join("hooks").join(py_h), "# py\n").unwrap();
                }
                fs::write(
                    py_pe_bak.join("plugin_dir").join("hooks.json"),
                    r#"{
                        "safety-and-quality-guards":{"PreToolUse":[{"matcher":"run_command|edit_file|write_file|swarm|read_board|swarm_wait","hooks":[{"command":"python -X utf8 hooks/safety_guards.py --event PreToolUse"}]}]},
                        "continuity":{"SessionStart":[{"hooks":[{"command":"python -X utf8 hooks/continuity.py --event SessionStart"}]}],"PreInvocation":[{"hooks":[{"command":"python -X utf8 hooks/continuity.py --event PreInvocation"}]}]},
                        "code-work-gate":{"PostToolUse":[{"hooks":[{"command":"python -X utf8 hooks/cwg_mark.py --event PostToolUse"}]}],"Stop":[{"hooks":[{"command":"python -X utf8 hooks/cwg_stop.py --event Stop"}]}]},
                        "tokenade":{"PreToolUse":[{"matcher":"run_command","hooks":[{"command":"python -X utf8 hooks/tokenade_hook.py --event PreToolUse"}]}]}
                    }"#,
                )
                .unwrap();
                rio::write_json(
                    &py_pe_bak.join("manifest.json"),
                    &json!({
                        "backup_id": "install-20260101-000002-pyonly",
                        "config_dir": cfg_pe.to_string_lossy(),
                        "targets": {
                            "plugin_dir": {"path": cfg_pe.join("plugins").join(PLUGIN_NAME).to_string_lossy(), "existed": true},
                            "glob_rule": {"path": cfg_pe.join("rules").join("uiux-design.md").to_string_lossy(), "existed": true},
                        }
                    }),
                )
                .unwrap();
                let mut child_py_only = Command::new(&live_exe)
                    .args(["-n", "30", "127.0.0.1"])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap();
                let rb_py_only = perform_rollback(&cfg_pe, &shome_pe, "install-20260101-000002-pyonly");
                let _ = child_py_only.kill();
                let _ = child_py_only.wait();
                assert_eq!(rb_py_only["ok"], true, "rb_py_only failed: {}", rb_py_only);
                assert!(!live_exe.exists());
                assert!(cfg_pe.join("plugins").join(PLUGIN_NAME).join("hooks").join("cwg_stop.py").is_file());

                // INVARIANT: Cross-volume fallback: when `state/.retired_bins` cannot be used (e.g. different volume or non-directory blocker), `remove_tree_or_retire_pe` falls back to `config_dir/.retired_bins` (same volume as `p_target`, outside `p_target`) so `remove_dir_all(p_target)` still succeeds cleanly.
                assert_eq!(perform_install(&repo_pe, &cfg_pe, &shome_pe, false, true)["ok"], true);
                let blocked_state_retire = tmp.0.join("blocked-state-retire-file");
                fs::write(&blocked_state_retire, "blocker").unwrap();
                let cfg_retire_dir = cfg_pe.join(RETIRED_BINS_DIR_NAME);
                let mut child_xvol = Command::new(&live_exe)
                    .args(["-n", "30", "127.0.0.1"])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap();
                remove_tree_or_retire_pe(
                    &cfg_pe.join("plugins").join(PLUGIN_NAME),
                    &[&blocked_state_retire, &cfg_retire_dir],
                )
                .unwrap();
                let _ = child_xvol.kill();
                let _ = child_xvol.wait();
                assert!(!cfg_pe.join("plugins").join(PLUGIN_NAME).exists());

                // INVARIANT: Planted NTFS junction at `.retired_bins` is rejected by `prepare_retired_slot` without deleting `retired-*` files in the junction target.
                let junc_victim_dir = tmp.0.join("retired-junction-victim");
                fs::create_dir_all(&junc_victim_dir).unwrap();
                let junc_victim_file = junc_victim_dir.join("retired-keep.exe");
                fs::write(&junc_victim_file, "KEEP").unwrap();
                let junc_retired = tmp.0.join("planted-retired-junc");
                let mk_junc = Command::new("cmd")
                    .args([
                        "/C",
                        "mklink",
                        "/J",
                        &junc_retired.to_string_lossy(),
                        &junc_victim_dir.to_string_lossy(),
                    ])
                    .output()
                    .unwrap();
                assert!(mk_junc.status.success());
                assert!(prepare_retired_slot(&junc_retired, &live_exe).is_err());
                assert_eq!(fs::read_to_string(&junc_victim_file).unwrap(), "KEEP");
                let _ = win32_sqlite::remove_junction_dir(&junc_retired);
            }
        }

        // INVARIANT: `atomic_copy_file` preserves exact source file permissions (`readonly` on Windows, `mode` bits such as `0600` on Unix) on the destination file.
        let perm_src = tmp.0.join("perm_src_secret.md");
        let perm_dst = tmp.0.join("perm_dst_secret.md");
        fs::write(&perm_src, "secret-rule").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut p = fs::metadata(&perm_src).unwrap().permissions();
            p.set_mode(0o600);
            fs::set_permissions(&perm_src, p).unwrap();
        }
        #[cfg(windows)]
        {
            let mut p = fs::metadata(&perm_src).unwrap().permissions();
            p.set_readonly(true);
            fs::set_permissions(&perm_src, p).unwrap();
        }
        atomic_copy_file(&perm_src, &perm_dst).unwrap();
        assert_eq!(
            fs::metadata(&perm_dst).unwrap().permissions(),
            fs::metadata(&perm_src).unwrap().permissions()
        );
        #[cfg(windows)]
        {
            for pf in [&perm_src, &perm_dst] {
                let mut p = fs::metadata(pf).unwrap().permissions();
                p.set_readonly(false);
                let _ = fs::set_permissions(pf, p);
            }
        }

        // INVARIANT: Concurrent `perform_rollback` and `perform_install` (including `already_up_to_date`) are serialized by `acquire_installer_mutex`, so `(plugin == v1) <=> (.lock_epoch == "v1")` holds after every interleaved pair.
        let cfg_conc = tmp.0.join("cfg-conc");
        let shome_conc = tmp.0.join("shome-conc");
        let first_conc = perform_install(&repo, &cfg_conc, &shome_conc, false, true);
        assert_eq!(first_conc["ok"], true);
        let conc_bid = first_conc["backup_id"].as_str().unwrap().to_string();
        for _ in 0..4 {
            assert_eq!(perform_install(&repo, &cfg_conc, &shome_conc, false, true)["ok"], true);
            let bar = std::sync::Arc::new(std::sync::Barrier::new(2));
            let repo_c = repo.clone();
            let cfg_c1 = cfg_conc.clone();
            let shome_c1 = shome_conc.clone();
            let bar1 = bar.clone();
            let t_inst = thread::spawn(move || {
                bar1.wait();
                perform_install(&repo_c, &cfg_c1, &shome_c1, false, true)
            });
            let cfg_c2 = cfg_conc.clone();
            let shome_c2 = shome_conc.clone();
            let bid_c2 = conc_bid.clone();
            let t_rb = thread::spawn(move || {
                bar.wait();
                perform_rollback(&cfg_c2, &shome_c2, &bid_c2)
            });
            let r_inst = t_inst.join().unwrap();
            let r_rb = t_rb.join().unwrap();
            assert_eq!(r_inst["ok"], true);
            assert_eq!(r_rb["ok"], true);
            let plugin_now = cfg_conc.join("plugins").join(PLUGIN_NAME).is_dir();
            let v1_epoch_now = fs::read_to_string(rio::lock_epoch_path(&shome_conc.join("state")))
                .map(|s| s.trim() == "v1")
                .unwrap_or(false);
            assert_eq!(
                !plugin_now,
                v1_epoch_now,
                "invariant violated: plugin_now={} v1_epoch_now={}",
                plugin_now,
                v1_epoch_now
            );
        }

        // INVARIANT: Conflicting CLI modes (`--dry-run --rollback`, `--diagnose --rollback`, `--list-backups --dry-run`) fail closed with exit code 2 without mutating target config; `--list-backups` succeeds cleanly.
        assert_eq!(
            run_cli(&[
                "--dry-run".to_string(),
                "--rollback".to_string(),
                "latest".to_string(),
                "--target-config-dir".to_string(),
                cfg.to_string_lossy().into_owned(),
                "--stack-home".to_string(),
                shome.to_string_lossy().into_owned(),
            ]),
            2
        );
        assert_eq!(
            run_cli(&[
                "--diagnose".to_string(),
                "--rollback=latest".to_string(),
            ]),
            2
        );
        assert_eq!(
            run_cli(&[
                "--list-backups".to_string(),
                "--dry-run".to_string(),
            ]),
            2
        );
        assert_eq!(
            run_cli(&[
                "--list-backups".to_string(),
                "--stack-home".to_string(),
                shome.to_string_lossy().into_owned(),
            ]),
            0
        );
        // INVARIANT: Missing value for `--repo-root` / `--target-config-dir` / `--stack-home` must never swallow `--dry-run` or dispatch into `--rollback`; `--list-backups` fails closed when `--stack-home` is a file.
        assert_eq!(
            run_cli(&[
                "--repo-root".to_string(),
                "--dry-run".to_string(),
                "--rollback".to_string(),
                "latest".to_string(),
            ]),
            2
        );
        assert_eq!(
            run_cli(&[
                "--target-config-dir".to_string(),
                "--dry-run".to_string(),
            ]),
            2
        );
        assert_eq!(
            run_cli(&[
                "--stack-home=".to_string(),
                "--list-backups".to_string(),
            ]),
            2
        );
        let not_a_dir_home = tmp.0.join("stack-home-file.txt");
        fs::write(&not_a_dir_home, "not a directory").unwrap();
        assert_eq!(
            run_cli(&[
                "--list-backups".to_string(),
                "--stack-home".to_string(),
                not_a_dir_home.to_string_lossy().into_owned(),
            ]),
            1
        );
        let nonexistent_home = tmp.0.join("fresh-uninitialized-stack-home");
        assert_eq!(
            run_cli(&[
                "--list-backups".to_string(),
                "--stack-home".to_string(),
                nonexistent_home.to_string_lossy().into_owned(),
            ]),
            0
        );

        // INVARIANT: If the newest backup's `manifest.json` is unreadable/locked or not a regular file, `--rollback latest` fails closed instead of silently rolling back to an older backup.
        let cfg_2bak = tmp.0.join("cfg-2bak");
        let shome_2bak = tmp.0.join("shome-2bak");
        let inst_b1 = perform_install(&repo, &cfg_2bak, &shome_2bak, false, true);
        assert_eq!(inst_b1["ok"], true);
        thread::sleep(Duration::from_millis(15));
        fs::write(
            repo.join("plugin").join("rules").join("AGENTS.md"),
            "# Updated v2\n",
        )
        .unwrap();
        let inst_b2 = perform_install(&repo, &cfg_2bak, &shome_2bak, false, true);
        assert_eq!(inst_b2["ok"], true);
        let first_bid = inst_b1["backup_id"].as_str().unwrap().to_string();
        let latest_bid = inst_b2["backup_id"].as_str().unwrap().to_string();
        let latest_mf = shome_2bak
            .join("backups")
            .join(&latest_bid)
            .join("manifest.json");
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let locked_mf = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(0)
                .open(&latest_mf)
                .unwrap();
            let rb_locked = perform_rollback(&cfg_2bak, &shome_2bak, "latest");
            assert_eq!(rb_locked["ok"], false);
            assert!(
                cfg_2bak
                    .join("plugins")
                    .join(PLUGIN_NAME)
                    .join("plugin.json")
                    .is_file()
            );
            drop(locked_mf);
        }
        fs::remove_file(&latest_mf).unwrap();
        fs::create_dir_all(&latest_mf).unwrap();
        let rb_dir_mf = perform_rollback(&cfg_2bak, &shome_2bak, "latest");
        assert_eq!(rb_dir_mf["ok"], false);
        assert!(
            cfg_2bak
                .join("plugins")
                .join(PLUGIN_NAME)
                .join("plugin.json")
                .is_file()
        );
        // INVARIANT: Explicit `--rollback <older_id>` succeeds even when an unrelated newer backup's `manifest.json` is damaged, while path-traversal IDs are rejected.
        assert_eq!(
            perform_rollback(&cfg_2bak, &shome_2bak, "../evil")["ok"],
            false
        );
        let rb_explicit = perform_rollback(&cfg_2bak, &shome_2bak, &first_bid);
        assert_eq!(rb_explicit["ok"], true);

        // INVARIANT: Pre-existing directory at `rules/uiux-design.md` or regular file at `plugins/gemini-carbon-stack` is rejected in preflight BEFORE creating backups, deleting files, or partially updating an installed plugin.
        let cfg_rule_dir = tmp.0.join("cfg-rule-is-dir");
        let shome_rule_dir = tmp.0.join("shome-rule-is-dir");
        assert_eq!(
            perform_install(&repo, &cfg_rule_dir, &shome_rule_dir, false, true)["ok"],
            true
        );
        let orig_agents_txt = fs::read_to_string(
            cfg_rule_dir
                .join("plugins")
                .join(PLUGIN_NAME)
                .join("rules")
                .join("AGENTS.md"),
        )
        .unwrap();
        fs::remove_file(cfg_rule_dir.join("rules").join("uiux-design.md")).unwrap();
        fs::create_dir_all(cfg_rule_dir.join("rules").join("uiux-design.md")).unwrap();
        fs::write(
            repo.join("plugin").join("rules").join("AGENTS.md"),
            "# Mutated v3 that must not partially land\n",
        )
        .unwrap();
        let inst_rule_dir = perform_install(&repo, &cfg_rule_dir, &shome_rule_dir, false, true);
        assert_eq!(inst_rule_dir["ok"], false);
        assert_eq!(inst_rule_dir["stage"], "preflight");
        assert_eq!(
            fs::read_to_string(
                cfg_rule_dir
                    .join("plugins")
                    .join(PLUGIN_NAME)
                    .join("rules")
                    .join("AGENTS.md")
            )
            .unwrap(),
            orig_agents_txt
        );

        let cfg_plug_file = tmp.0.join("cfg-plug-is-file");
        let shome_plug_file = tmp.0.join("shome-plug-is-file");
        fs::create_dir_all(cfg_plug_file.join("plugins")).unwrap();
        let plug_as_file = cfg_plug_file.join("plugins").join(PLUGIN_NAME);
        fs::write(&plug_as_file, "important user file").unwrap();
        let inst_plug_file = perform_install(&repo, &cfg_plug_file, &shome_plug_file, false, true);
        assert_eq!(inst_plug_file["ok"], false);
        assert_eq!(inst_plug_file["stage"], "preflight");
        assert!(plug_as_file.is_file());
        assert_eq!(fs::read_to_string(&plug_as_file).unwrap(), "important user file");

        // INVARIANT: Reject symlink/junction `<stack_home>/backups` BEFORE creating backups or updating the installed plugin so `--rollback` and `perform_install` share identical backup-root validation.
        #[cfg(windows)]
        {
            let cfg_bj = tmp.0.join("cfg-broot-junc");
            let shome_bj = tmp.0.join("shome-broot-junc");
            let ext_bak = tmp.0.join("external-backups-target");
            fs::create_dir_all(&shome_bj).unwrap();
            fs::create_dir_all(&ext_bak).unwrap();
            let mk_bj = Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(shome_bj.join("backups"))
                .arg(&ext_bak)
                .output()
                .unwrap();
            assert!(mk_bj.status.success());
            let inst_bj = perform_install(&repo, &cfg_bj, &shome_bj, false, true);
            assert_eq!(inst_bj["ok"], false);
            assert!(!cfg_bj.join("plugins").join(PLUGIN_NAME).exists());
            let _ = win32_sqlite::remove_junction_dir(&shome_bj.join("backups"));
        }

        // INVARIANT: `perform_install_with_drain_timeout` enforces `v1 -> v2` quiesce before clearing `.lock_epoch`: a hung `v1` lock fails closed (`install_v1_quiesce`), restores the pre-install `v1` snapshot, and keeps `.lock_epoch = "v1"`, whereas a transient `v1` lock that exits within `drain_timeout` drains cleanly and clears `.lock_epoch`.
        let cfg_q = tmp.0.join("cfg-v1-quiesce");
        let shome_q = tmp.0.join("shome-v1-quiesce");
        let q_plug = cfg_q.join("plugins").join(PLUGIN_NAME);
        fs::create_dir_all(q_plug.join("hooks")).unwrap();
        fs::write(q_plug.join("plugin.json"), r#"{"name":"gemini-carbon-stack"}"#).unwrap();
        fs::write(q_plug.join("hooks").join("hooks.json"), "{}").unwrap();
        fs::write(q_plug.join("hooks").join("legacy_v1.py"), "# legacy v1\n").unwrap();
        fs::create_dir_all(shome_q.join("state").join("chips")).unwrap();
        let live_v1_lock = shome_q.join("state").join("chips").join(".active-v1.lock");
        fs::write(&live_v1_lock, format!("{} 1795000000\n", std::process::id())).unwrap();

        let q_hung = perform_install_with_drain_timeout(
            &repo,
            &cfg_q,
            &shome_q,
            false,
            true,
            Duration::from_millis(60),
        );
        assert_eq!(q_hung["ok"], false);
        assert_eq!(q_hung["stage"], "install_v1_quiesce");
        assert_eq!(q_hung["compensated_from_backup"], true);
        assert!(q_plug.join("hooks").join("legacy_v1.py").is_file());
        assert_eq!(
            fs::read_to_string(rio::lock_epoch_path(&shome_q.join("state")))
                .unwrap()
                .trim(),
            "v1"
        );

        let lock_to_release = live_v1_lock.clone();
        let releaser = thread::spawn(move || {
            thread::sleep(Duration::from_millis(45));
            let _ = fs::remove_file(&lock_to_release);
        });
        let q_ok = perform_install_with_drain_timeout(
            &repo,
            &cfg_q,
            &shome_q,
            false,
            true,
            Duration::from_millis(600),
        );
        releaser.join().unwrap();
        assert_eq!(q_ok["ok"], true);
        assert!(!q_plug.join("hooks").join("legacy_v1.py").exists());
        assert!(!rio::lock_epoch_path(&shome_q.join("state")).exists());

        // INVARIANT: Compensating a failed `v2 -> v2` update restores both the `v2` files AND the original `v2` epoch (absent `.lock_epoch`) instead of leaving the restored `v2` plugin in `v1` mode.
        let v2_orig_agents = fs::read_to_string(q_plug.join("rules").join("AGENTS.md")).unwrap();
        fs::write(
            repo.join("plugin").join("rules").join("AGENTS.md"),
            "# Mutated v2.1 that fails quiesce\n",
        )
        .unwrap();
        let v2_upd_blocker = shome_q.join("state").join("chips").join(".v2-upd-block.lock");
        fs::write(
            &v2_upd_blocker,
            format!("{} 1795000000\n", std::process::id()),
        )
        .unwrap();
        let v2_upd_fail = perform_install_with_drain_timeout(
            &repo,
            &cfg_q,
            &shome_q,
            false,
            true,
            Duration::from_millis(60),
        );
        let _ = fs::remove_file(&v2_upd_blocker);
        assert_eq!(v2_upd_fail["ok"], false);
        assert_eq!(v2_upd_fail["stage"], "install_v1_quiesce");
        assert_eq!(v2_upd_fail["compensated_from_backup"], true);
        assert_eq!(
            fs::read_to_string(q_plug.join("rules").join("AGENTS.md")).unwrap(),
            v2_orig_agents
        );
        assert!(!rio::lock_epoch_path(&shome_q.join("state")).exists());

        // INVARIANT: A live legacy `v1` hook process invoked via relative `hooks/legacy_v1.py` with `cwd = target_plugin_dir` and ZERO lock files in `state` blocks epoch switch until the process exits.
        let cfg_lp = tmp.0.join("cfg-live-rel-proc");
        let shome_lp = tmp.0.join("shome-live-rel-proc");
        let lp_plug = cfg_lp.join("plugins").join(PLUGIN_NAME);
        fs::create_dir_all(lp_plug.join("hooks")).unwrap();
        fs::write(
            lp_plug.join("plugin.json"),
            r#"{"name":"gemini-carbon-stack"}"#,
        )
        .unwrap();
        fs::write(lp_plug.join("hooks").join("hooks.json"), "{}").unwrap();
        fs::write(lp_plug.join("hooks").join("legacy_v1.py"), "import time; time.sleep(2)\n")
            .unwrap();
        fs::create_dir_all(shome_lp.join("state").join("chips")).unwrap();

        #[cfg(windows)]
        let mut live_v1_child = {
            let py_win = Path::new(r"C:\Users\in\AppData\Local\Programs\Python\Python312\python.exe");
            if py_win.is_file() {
                Command::new(py_win)
                    .arg("hooks/legacy_v1.py")
                    .current_dir(&lp_plug)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap()
            } else {
                Command::new("cmd")
                    .args(["/C", "ping -n 3 127.0.0.1 >NUL & rem hooks/legacy_v1.py"])
                    .current_dir(&lp_plug)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap()
            }
        };
        #[cfg(not(windows))]
        let mut live_v1_child = Command::new("sh")
            .args(["-c", "sleep 2", "sh", "hooks/legacy_v1.py"])
            .current_dir(&lp_plug)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();

        thread::sleep(Duration::from_millis(60));
        let lp_hung = perform_install_with_drain_timeout(
            &repo,
            &cfg_lp,
            &shome_lp,
            false,
            true,
            Duration::from_millis(70),
        );
        assert_eq!(lp_hung["ok"], false);
        assert_eq!(lp_hung["stage"], "install_v1_quiesce");
        assert_eq!(lp_hung["compensated_from_backup"], true);
        assert!(lp_plug.join("hooks").join("legacy_v1.py").is_file());
        assert_eq!(
            fs::read_to_string(rio::lock_epoch_path(&shome_lp.join("state")))
                .unwrap()
                .trim(),
            "v1"
        );

        let stopper = thread::spawn(move || {
            thread::sleep(Duration::from_millis(55));
            let _ = live_v1_child.kill();
            let _ = live_v1_child.wait();
        });
        let lp_ok = perform_install_with_drain_timeout(
            &repo,
            &cfg_lp,
            &shome_lp,
            false,
            true,
            Duration::from_millis(900),
        );
        stopper.join().unwrap();
        assert_eq!(lp_ok["ok"], true);
        assert!(!lp_plug.join("hooks").join("legacy_v1.py").exists());
        assert!(!rio::lock_epoch_path(&shome_lp.join("state")).exists());

        // INVARIANT: Process enumeration failures, missing `cwd` on relative `hooks/*.py` processes, and non-ASCII UTF-8 absolute Python hook paths (`/home/иван/...` with `cwd` outside the plugin) all preserve `.lock_epoch = "v1"` instead of falsely permitting epoch switch.
        let fc_state = tmp.0.join("shome-fail-closed-proc").join("state");
        fs::create_dir_all(&fc_state).unwrap();
        let cyr_plug = Path::new("/home/иван/.gemini/config/plugins/gemini-carbon-stack");
        let cyr_cfg = Path::new("/home/иван/.gemini/config");
        let cyr_roots = PluginProcRoots::new(cyr_plug, cyr_cfg, &fc_state, true);
        let v2_hot_roots = PluginProcRoots::new(cyr_plug, cyr_cfg, &fc_state, false);
        let v2_peer_review = vec![
            win32_sqlite::OsProcInfo {
                pid: u32::MAX - 10,
                ppid: 1,
                start_token: 90,
                same_user: true,
                exe_known: true,
                exe_path: "/usr/bin/pwsh".to_string(),
                exe_ino: None,
                cwd_known: true,
                cwd_path: "/workspace/other".to_string(),
                cmdline_known: true,
                cmdline: "pwsh -Command \"/home/иван/.gemini/config/plugins/gemini-carbon-stack/bin/carbon-stack codex-lane review --summary 'Updated office.py'\"".to_string(),
            },
            win32_sqlite::OsProcInfo {
                pid: u32::MAX - 11,
                ppid: u32::MAX - 10,
                start_token: 91,
                same_user: true,
                exe_known: true,
                exe_path: "/home/иван/.gemini/config/plugins/gemini-carbon-stack/bin/.retired_bins/retired-1-carbon-stack.exe".to_string(),
                exe_ino: Some(111),
                cwd_known: true,
                cwd_path: "/workspace/other".to_string(),
                cmdline_known: true,
                cmdline: "/home/иван/.gemini/config/plugins/gemini-carbon-stack/bin/carbon-stack codex-lane review --summary 'Updated office.py'".to_string(),
            },
        ];
        assert!(
            match_running_legacy_v1_pids_from_slice(
                &v2_peer_review,
                &v2_hot_roots,
                &BTreeMap::new(),
                Some(222),
            )
            .unwrap()
            .is_empty()
        );
        write_v1_lock_epoch(&fc_state).unwrap();

        let enum_err = quiesce_and_clear_v1_lock_epoch_with_lister(
            &cyr_roots,
            &fc_state,
            &BTreeMap::new(),
            None,
            Duration::from_millis(35),
            || Err("simulated OS process table failure".to_string()),
        );
        assert!(enum_err.is_err());
        assert_eq!(
            fs::read_to_string(rio::lock_epoch_path(&fc_state))
                .unwrap()
                .trim(),
            "v1"
        );

        let missing_cwd_err = quiesce_and_clear_v1_lock_epoch_with_lister(
            &cyr_roots,
            &fc_state,
            &BTreeMap::new(),
            None,
            Duration::from_millis(35),
            || {
                Ok(vec![win32_sqlite::OsProcInfo {
                    pid: u32::MAX - 2,
                    ppid: 1,
                    start_token: 42,
                    same_user: true,
                    exe_known: true,
                    exe_path: "/usr/bin/python3".to_string(),
                    exe_ino: None,
                    cwd_known: false,
                    cwd_path: String::new(),
                    cmdline_known: true,
                    cmdline: "python3 hooks/cwg_stop.py".to_string(),
                }])
            },
        );
        assert!(missing_cwd_err.is_err());
        assert_eq!(
            fs::read_to_string(rio::lock_epoch_path(&fc_state))
                .unwrap()
                .trim(),
            "v1"
        );

        let decoded_cyr_cmd = win32_sqlite::decode_nul_separated_cmdline(
            "python3\0/home/иван/.gemini/config/plugins/gemini-carbon-stack/hooks/codex_lane.py\0"
                .as_bytes(),
        );
        let cyr_proc = vec![win32_sqlite::OsProcInfo {
            pid: u32::MAX - 3,
            ppid: 1,
            start_token: 77,
            same_user: true,
            exe_known: true,
            exe_path: "/usr/bin/python3".to_string(),
            exe_ino: None,
            cwd_known: true,
            cwd_path: "/workspace/unrelated-repo".to_string(),
            cmdline_known: true,
            cmdline: decoded_cyr_cmd,
        }];
        assert!(match_pre_cutover_pids_from_slice(&cyr_proc, &cyr_roots)
            .unwrap()
            .contains_key(&(u32::MAX - 3)));
        assert_eq!(
            match_running_legacy_v1_pids_from_slice(&cyr_proc, &cyr_roots, &BTreeMap::new(), None)
                .unwrap(),
            vec![u32::MAX - 3]
        );
        let cyr_block = quiesce_and_clear_v1_lock_epoch_with_lister(
            &cyr_roots,
            &fc_state,
            &BTreeMap::new(),
            None,
            Duration::from_millis(35),
            || Ok(cyr_proc.clone()),
        );
        assert!(cyr_block.is_err());
        assert_eq!(
            fs::read_to_string(rio::lock_epoch_path(&fc_state))
                .unwrap()
                .trim(),
            "v1"
        );

        // INVARIANT: Legacy `<config_dir>/hooks.json` referencing `hooks/tokenade_hook.py` inside THAT specific `config_dir` instance is migrated to the platform binary while preserving unrelated user hook groups, backed up surgically, and restored on `--rollback`.
        let cfg_hk = tmp.0.join("cfg-hooks-mig");
        let shome_hk = tmp.0.join("shome-hooks-mig");
        fs::create_dir_all(&cfg_hk).unwrap();
        let cfg_hk_py = cfg_hk
            .join("plugins")
            .join(PLUGIN_NAME)
            .join("hooks")
            .join("tokenade_hook.py")
            .to_string_lossy()
            .replace('\\', "/");
        let orig_hooks_json = serde_json::to_string_pretty(&json!({
            "notebooklm-project-memory": {
                "enabled": true,
                "Stop": [{"type": "command", "command": "custom-nlm-stop", "timeout": 20}]
            },
            "tokenade": {
                "enabled": true,
                "PreToolUse": [{
                    "matcher": "run_command",
                    "hooks": [{"type": "command", "command": format!("python \"{}\"", cfg_hk_py), "timeout": 15}]
                }]
            }
        }))
        .unwrap();
        fs::write(cfg_hk.join("hooks.json"), format!("{}\n", orig_hooks_json)).unwrap();
        let posix_preview = inspect_global_hooks_migration(
            &cfg_hk,
            &cfg_hk.join("plugins").join(PLUGIN_NAME),
            false,
        )
        .unwrap()
        .unwrap();
        assert!(posix_preview
            .rendered_json
            .contains("bin/carbon-stack tokenade-hook --event PreToolUse"));
        assert!(!posix_preview.rendered_json.contains("carbon-stack.exe"));
        assert!(posix_preview.rendered_json.contains("custom-nlm-stop"));
        assert_eq!(posix_preview.migrations.len(), 1);
        assert_eq!(
            posix_preview.migrations[0].pointer,
            "/tokenade/PreToolUse/0/hooks/0/command"
        );

        let hk_inst = perform_install(&repo, &cfg_hk, &shome_hk, false, true);
        assert_eq!(hk_inst["ok"], true);
        let migrated_txt = fs::read_to_string(cfg_hk.join("hooks.json")).unwrap();
        assert!(!migrated_txt.contains("tokenade_hook.py"));
        assert!(migrated_txt.contains("tokenade-hook --event PreToolUse"));
        assert!(migrated_txt.contains("custom-nlm-stop"));
        assert_eq!(
            perform_install(&repo, &cfg_hk, &shome_hk, false, true)["already_up_to_date"],
            true
        );

        // INVARIANT: Concurrent external saves to `<config_dir>/hooks.json` WHILE `perform_rollback` is already in flight (waiting on `.v2_alive.lease` drain) are preserved via fresh CAS re-read at Step 3 while still reverting the migrated Carbon Stack pointer.
        let transient_v2_lease = rio::v2_lease_path(&shome_hk.join("state"));
        fs::create_dir_all(transient_v2_lease.parent().unwrap()).unwrap();
        let v2_lock_fh = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&transient_v2_lease)
            .unwrap();
        v2_lock_fh.try_lock_shared().unwrap();
        let cfg_hk_bg = cfg_hk.clone();
        let shome_hk_bg = shome_hk.clone();
        let hk_rb_thread = thread::spawn(move || {
            perform_rollback_with_drain_timeout(
                &cfg_hk_bg,
                &shome_hk_bg,
                "latest",
                Duration::from_secs(5),
            )
        });
        thread::sleep(Duration::from_millis(80));
        let mut live_with_concurrent_edit: Value = serde_json::from_str(&migrated_txt).unwrap();
        live_with_concurrent_edit["concurrent-during-drain"] = json!({
            "enabled": true,
            "Stop": [{"type": "command", "command": "post-install-audit --strict", "timeout": 10}]
        });
        fs::write(
            cfg_hk.join("hooks.json"),
            format!(
                "{}\n",
                serde_json::to_string_pretty(&live_with_concurrent_edit).unwrap()
            ),
        )
        .unwrap();
        let _ = v2_lock_fh.unlock();
        drop(v2_lock_fh);
        let hk_rb = hk_rb_thread.join().unwrap();
        assert_eq!(hk_rb["ok"], true);
        let after_rb_txt = fs::read_to_string(cfg_hk.join("hooks.json")).unwrap();
        assert!(after_rb_txt.contains("hooks/tokenade_hook.py"));
        assert!(after_rb_txt.contains("custom-nlm-stop"));
        assert!(after_rb_txt.contains("post-install-audit --strict"));

        // INVARIANT: If the user deletes the migrated `/tokenade` entry and adds the same native command string under a different group, rollback NEVER rewrites the other group and reports `hooks_rollback_conflicts` + `warnings`.
        assert_eq!(
            perform_install(&repo, &cfg_hk, &shome_hk, false, true)["ok"],
            true
        );
        let migrated_again = fs::read_to_string(cfg_hk.join("hooks.json")).unwrap();
        let mut moved_val: Value = serde_json::from_str(&migrated_again).unwrap();
        let native_cmd_str = moved_val
            .pointer("/tokenade/PreToolUse/0/hooks/0/command")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        moved_val.as_object_mut().unwrap().remove("tokenade");
        moved_val["separate-user-group"] = json!({
            "PreToolUse": [{"matcher": "run_command", "hooks": [{"type": "command", "command": native_cmd_str}]}]
        });
        fs::write(
            cfg_hk.join("hooks.json"),
            format!("{}\n", serde_json::to_string_pretty(&moved_val).unwrap()),
        )
        .unwrap();
        let conflict_rb = perform_rollback(&cfg_hk, &shome_hk, "latest");
        assert_eq!(conflict_rb["ok"], false);
        assert_eq!(conflict_rb["compensated_plugin_restore"], true);
        assert_eq!(
            conflict_rb["hooks_rollback_conflicts"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(!conflict_rb["warnings"].as_array().unwrap().is_empty());
        assert!(cfg_hk
            .join("plugins")
            .join(PLUGIN_NAME)
            .join(platform_hook_binary_rel(cfg!(windows)))
            .is_file());
        let after_conflict_val: Value =
            serde_json::from_str(&fs::read_to_string(cfg_hk.join("hooks.json")).unwrap()).unwrap();
        assert_eq!(
            after_conflict_val
                .pointer("/separate-user-group/PreToolUse/0/hooks/0/command")
                .unwrap()
                .as_str()
                .unwrap(),
            native_cmd_str
        );

        // INVARIANT: Swapping two migrated array elements (which had distinct `before` commands collapsed into the same `after` command) is caught via `context_sha256` so rollback NEVER assigns old commands to the wrong array entries.
        let cfg_swap = tmp.0.join("cfg-hooks-array-swap");
        let shome_swap = tmp.0.join("shome-hooks-array-swap");
        fs::create_dir_all(&cfg_swap).unwrap();
        let swap_py = cfg_swap
            .join("plugins")
            .join(PLUGIN_NAME)
            .join("hooks")
            .join("tokenade_hook.py")
            .to_string_lossy()
            .replace('\\', "/");
        let before_cmd_a = format!("python \"{}\"", swap_py);
        let before_cmd_b = format!("python3 -X utf8 \"{}\" --event PreToolUse", swap_py);
        let swap_init = json!({
            "tokenade": {
                "PreToolUse": [{
                    "matcher": "run_command",
                    "hooks": [
                        {"type": "command", "timeout": 10, "command": before_cmd_a},
                        {"type": "command", "timeout": 30, "command": before_cmd_b}
                    ]
                }]
            }
        });
        fs::write(
            cfg_swap.join("hooks.json"),
            format!("{}\n", serde_json::to_string_pretty(&swap_init).unwrap()),
        )
        .unwrap();
        assert_eq!(
            perform_install(&repo, &cfg_swap, &shome_swap, false, true)["ok"],
            true
        );
        let mut swapped_live: Value =
            serde_json::from_str(&fs::read_to_string(cfg_swap.join("hooks.json")).unwrap()).unwrap();
        let swap_native_cmd = swapped_live
            .pointer("/tokenade/PreToolUse/0/hooks/0/command")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        {
            let arr = swapped_live
                .pointer_mut("/tokenade/PreToolUse/0/hooks")
                .unwrap()
                .as_array_mut()
                .unwrap();
            arr.swap(0, 1);
        }
        fs::write(
            cfg_swap.join("hooks.json"),
            format!("{}\n", serde_json::to_string_pretty(&swapped_live).unwrap()),
        )
        .unwrap();
        let swap_rb = perform_rollback(&cfg_swap, &shome_swap, "latest");
        assert_eq!(swap_rb["ok"], false);
        assert_eq!(swap_rb["compensated_plugin_restore"], true);
        assert_eq!(
            swap_rb["hooks_rollback_conflicts"].as_array().unwrap().len(),
            2
        );
        assert!(cfg_swap
            .join("plugins")
            .join(PLUGIN_NAME)
            .join(platform_hook_binary_rel(cfg!(windows)))
            .is_file());
        let after_swap_rb: Value =
            serde_json::from_str(&fs::read_to_string(cfg_swap.join("hooks.json")).unwrap()).unwrap();
        assert_eq!(
            after_swap_rb.pointer("/tokenade/PreToolUse/0/hooks/0/timeout"),
            Some(&json!(30))
        );
        assert_eq!(
            after_swap_rb.pointer("/tokenade/PreToolUse/0/hooks/0/command"),
            Some(&Value::String(swap_native_cmd.clone()))
        );
        assert_eq!(
            after_swap_rb.pointer("/tokenade/PreToolUse/0/hooks/1/timeout"),
            Some(&json!(10))
        );
        assert_eq!(
            after_swap_rb.pointer("/tokenade/PreToolUse/0/hooks/1/command"),
            Some(&Value::String(swap_native_cmd))
        );

        // INVARIANT: If `fs::rename` fails transiently AFTER `orig_sha` verification (e.g. `FILE_SHARE_READ | FILE_SHARE_WRITE` without `FILE_SHARE_DELETE`) and an external writer saves new data before retry, `cas_update_hooks_file` discards `tmp`, re-reads from disk, and preserves the external edit.
        let cas_test_file = tmp.0.join("cas-retry-hooks.json");
        fs::write(&cas_test_file, "{\"v\":1}\n").unwrap();
        let mut cas_calls = 0usize;
        let cas_file_clone = cas_test_file.clone();
        let (_, final_calls) = cas_update_hooks_file(&cas_test_file, |raw| {
            cas_calls += 1;
            let mut v: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
            if cas_calls == 1 {
                fs::write(&cas_file_clone, "{\"v\":1,\"concurrent\":true}\n").unwrap();
            }
            v["updated"] = json!(true);
            Ok(Some((
                format!("{}\n", serde_json::to_string_pretty(&v).unwrap()).into_bytes(),
                cas_calls,
            )))
        })
        .unwrap()
        .unwrap();
        assert_eq!(final_calls, 2);
        let cas_merged: Value =
            serde_json::from_str(&fs::read_to_string(&cas_test_file).unwrap()).unwrap();
        assert_eq!(cas_merged["concurrent"], json!(true));
        assert_eq!(cas_merged["updated"], json!(true));

        // INVARIANT: External saves occurring strictly AFTER pre-check SHA-256 verification (Save A) AND even a second concurrent save (Save B) occurring right before causal-monotonic restore swap are NEVER lost: Save B supersedes Save A and is preserved + merged on CAS retry; stranded backups (`ERROR_UNABLE_TO_MOVE_REPLACEMENT_2`) are recovered without deletion.
        let post_ver_file = tmp.0.join("cas-post-verify-race.json");
        fs::write(&post_ver_file, "{\"v\":1}\n").unwrap();
        let post_ver_clone = post_ver_file.clone();
        let mut pv_calls = 0usize;
        let mut pv_unrev = false;
        let (_, pv_final_calls) = cas_update_hooks_file_with_hooks(
            &post_ver_file,
            &mut pv_unrev,
            |raw| {
                pv_calls += 1;
                let mut v: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
                v["updated"] = json!(true);
                Ok(Some((
                    format!("{}\n", serde_json::to_string_pretty(&v).unwrap()).into_bytes(),
                    pv_calls,
                )))
            },
            |attempt| {
                if attempt == 0 {
                    fs::write(
                        &post_ver_clone,
                        "{\"v\":1,\"saved_after_sha_verify\":true}\n",
                    )
                    .unwrap();
                }
            },
            |_| {},
        )
        .unwrap()
        .unwrap();
        assert!(!pv_unrev);
        assert_eq!(pv_final_calls, 2);
        let pv_merged: Value =
            serde_json::from_str(&fs::read_to_string(&post_ver_file).unwrap()).unwrap();
        assert_eq!(pv_merged["saved_after_sha_verify"], json!(true));
        assert_eq!(pv_merged["updated"], json!(true));

        let double_race_file = tmp.0.join("cas-double-save-ab-race.json");
        fs::write(&double_race_file, "{\"v\":1}\n").unwrap();
        let dr_save_a = double_race_file.clone();
        let dr_save_b = double_race_file.clone();
        let mut dr_calls = 0usize;
        let mut dr_restore_injected = false;
        let mut dr_unrev = false;
        let (_, dr_final_calls) = cas_update_hooks_file_with_hooks(
            &double_race_file,
            &mut dr_unrev,
            |raw| {
                dr_calls += 1;
                let mut v: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
                v["updated"] = json!(true);
                Ok(Some((
                    format!("{}\n", serde_json::to_string_pretty(&v).unwrap()).into_bytes(),
                    dr_calls,
                )))
            },
            |attempt| {
                if attempt == 0 {
                    fs::write(&dr_save_a, "{\"v\":1,\"save_a\":true}\n").unwrap();
                }
            },
            |round| {
                if round == 0 && !dr_restore_injected {
                    dr_restore_injected = true;
                    fs::write(&dr_save_b, "{\"v\":2,\"save_b\":true}\n").unwrap();
                }
            },
        )
        .unwrap()
        .unwrap();
        assert!(!dr_unrev);
        assert_eq!(dr_final_calls, 2);
        let dr_merged: Value =
            serde_json::from_str(&fs::read_to_string(&double_race_file).unwrap()).unwrap();
        assert_eq!(dr_merged["v"], json!(2));
        assert_eq!(dr_merged["save_b"], json!(true));
        assert!(dr_merged.get("save_a").is_none());
        assert_eq!(dr_merged["updated"], json!(true));

        // INVARIANT: Exhausting all 8 reverse-swap rounds OR hitting a reverse-swap sharing lock NEVER deletes the displaced user save: `published_unreverted` becomes `true`, `Err` names the preserved sibling file, and the preserved file contains the latest user save intact.
        let ex_race_file = tmp.0.join("cas-exhaust-restore-rounds.json");
        fs::write(&ex_race_file, "{\"v\":0}\n").unwrap();
        let ex_save_a = ex_race_file.clone();
        let ex_save_loop = ex_race_file.clone();
        let mut ex_unrev = false;
        let ex_err = cas_update_hooks_file_with_hooks(
            &ex_race_file,
            &mut ex_unrev,
            |raw| {
                let mut v: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
                v["updated"] = json!(true);
                Ok(Some((
                    format!("{}\n", serde_json::to_string_pretty(&v).unwrap()).into_bytes(),
                    (),
                )))
            },
            |attempt| {
                if attempt == 0 {
                    fs::write(&ex_save_a, "{\"seq\":1}\n").unwrap();
                }
            },
            |round| {
                fs::write(&ex_save_loop, format!("{{\"seq\":{}}}\n", round + 2)).unwrap();
            },
        )
        .unwrap_err();
        assert!(ex_unrev);
        assert!(ex_err.contains("preserved intact at"));
        let preserved_path_str = ex_err.split("preserved intact at ").nth(1).unwrap().trim();
        let preserved_val: Value =
            serde_json::from_str(&fs::read_to_string(preserved_path_str).unwrap()).unwrap();
        assert_eq!(preserved_val["seq"], json!(9));

        // INVARIANT: Even when all 16 `hooks.json.preserved-user-save-<pid>-*` slots are pre-occupied so `preserve_unrestored_user_hooks_file` falls back to returning `candidate` in place (`tmp` on Linux/macOS or `displaced_cand` on Windows), `cas_update_hooks_file_with_hooks` cleanup NEVER unlinks `preserved_path`.
        let inplace_dir = tmp.0.join("cas-inplace-preserve");
        fs::create_dir_all(&inplace_dir).unwrap();
        let inplace_file = inplace_dir.join("hooks.json");
        fs::write(&inplace_file, "{\"v\":0}\n").unwrap();
        for seq_i in 1..=64u64 {
            let occupied = inplace_dir.join(format!(
                "hooks.json.preserved-user-save-{}-{}",
                std::process::id(),
                seq_i
            ));
            fs::write(&occupied, "{\"occupied\":true}\n").unwrap();
        }
        let inp_save_a = inplace_file.clone();
        let inp_save_loop = inplace_file.clone();
        let mut inp_unrev = false;
        let inp_err = cas_update_hooks_file_with_hooks(
            &inplace_file,
            &mut inp_unrev,
            |raw| {
                let mut v: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
                v["updated"] = json!(true);
                Ok(Some((
                    format!("{}\n", serde_json::to_string_pretty(&v).unwrap()).into_bytes(),
                    (),
                )))
            },
            |attempt| {
                if attempt == 0 {
                    fs::write(&inp_save_a, "{\"inplace_seq\":1}\n").unwrap();
                }
            },
            |round| {
                fs::write(
                    &inp_save_loop,
                    format!("{{\"inplace_seq\":{}}}\n", round + 2),
                )
                .unwrap();
            },
        )
        .unwrap_err();
        assert!(inp_unrev);
        let inp_pres_str = inp_err.split("preserved intact at ").nth(1).unwrap().trim();
        assert!(Path::new(inp_pres_str).is_file());
        let inp_pres_val: Value =
            serde_json::from_str(&fs::read_to_string(inp_pres_str).unwrap()).unwrap();
        assert_eq!(inp_pres_val["inplace_seq"], json!(9));

        // INVARIANT: Also exercise Round-0 immediate reverse-swap failure (`candidate == tmp` on Linux/macOS, `candidate == displaced_cand` on Windows) with all `preserved-user-save` slots occupied so `keep_tmp` / `keep_disp` directly protects the Round-0 displaced path.
        let r0_dir = tmp.0.join("cas-r0-inplace-preserve");
        fs::create_dir_all(&r0_dir).unwrap();
        let r0_file = r0_dir.join("hooks.json");
        fs::write(&r0_file, "{\"v\":0}\n").unwrap();
        for seq_i in 1..=96u64 {
            let occupied = r0_dir.join(format!(
                "hooks.json.preserved-user-save-{}-{}",
                std::process::id(),
                seq_i
            ));
            fs::write(&occupied, "{\"occupied\":true}\n").unwrap();
        }
        let r0_save_a = r0_file.clone();
        let r0_rm_target = r0_file.clone();
        let mut r0_unrev = false;
        let r0_err = cas_update_hooks_file_with_hooks(
            &r0_file,
            &mut r0_unrev,
            |raw| {
                let mut v: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
                v["updated"] = json!(true);
                Ok(Some((
                    format!("{}\n", serde_json::to_string_pretty(&v).unwrap()).into_bytes(),
                    (),
                )))
            },
            |attempt| {
                if attempt == 0 {
                    fs::write(&r0_save_a, "{\"r0_user\":77}\n").unwrap();
                }
            },
            |round| {
                if round == 0 {
                    let _ = fs::remove_file(&r0_rm_target);
                    let _ = fs::create_dir_all(&r0_rm_target);
                }
            },
        )
        .unwrap_err();
        let _ = fs::remove_dir_all(&r0_file);
        fs::write(&r0_file, "{\"restored_placeholder\":true}\n").unwrap();
        assert!(r0_unrev);
        let r0_pres_str = r0_err.split("preserved intact at ").nth(1).unwrap().trim();
        assert!(Path::new(r0_pres_str).is_file());
        let r0_pres_val: Value =
            serde_json::from_str(&fs::read_to_string(r0_pres_str).unwrap()).unwrap();
        assert_eq!(r0_pres_val["r0_user"], json!(77));

        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let lock_rev_file = tmp.0.join("cas-reverse-swap-locked.json");
            fs::write(&lock_rev_file, "{\"v\":0}\n").unwrap();
            let lock_rev_save = lock_rev_file.clone();
            let lock_rev_hold = lock_rev_file.clone();
            let mut held_no_del: Option<fs::File> = None;
            let mut lr_unrev = false;
            let lr_err = cas_update_hooks_file_with_hooks(
                &lock_rev_file,
                &mut lr_unrev,
                |raw| {
                    let mut v: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
                    v["updated"] = json!(true);
                    Ok(Some((
                        format!("{}\n", serde_json::to_string_pretty(&v).unwrap()).into_bytes(),
                        (),
                    )))
                },
                |attempt| {
                    if attempt == 0 {
                        fs::write(&lock_rev_save, "{\"user_important\":42}\n").unwrap();
                    }
                },
                |round| {
                    if round == 0 && held_no_del.is_none() {
                        held_no_del = fs::OpenOptions::new()
                            .read(true)
                            .share_mode(1)
                            .open(&lock_rev_hold)
                            .ok();
                    }
                },
            )
            .unwrap_err();
            drop(held_no_del);
            assert!(lr_unrev);
            let lr_pres_str = lr_err.split("preserved intact at ").nth(1).unwrap().trim();
            let lr_pres_val: Value =
                serde_json::from_str(&fs::read_to_string(lr_pres_str).unwrap()).unwrap();
            assert_eq!(lr_pres_val["user_important"], json!(42));
        }

        let stranded_target = tmp.0.join("stranded-hooks.json");
        let stranded_bak = tmp.0.join("stranded-hooks.bak");
        fs::write(&stranded_bak, "{\"preserved\":true}\n").unwrap();
        win32_sqlite::recover_stranded_displaced_file(&stranded_target, &stranded_bak).unwrap();
        assert!(stranded_target.is_file());
        assert!(!stranded_bak.exists());
        assert_eq!(
            fs::read_to_string(&stranded_target).unwrap(),
            "{\"preserved\":true}\n"
        );

        let race_1177_target = tmp.0.join("race-1177-target.json");
        let race_1177_bak = tmp.0.join("race-1177-displaced.bak");
        fs::write(&race_1177_target, "{\"newly_created_by_editor\":true}\n").unwrap();
        fs::write(&race_1177_bak, "{\"stale_pre_1177\":true}\n").unwrap();
        assert_eq!(
            win32_sqlite::atomic_move_noreplace(&race_1177_bak, &race_1177_target)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::AlreadyExists
        );
        win32_sqlite::recover_stranded_displaced_file(&race_1177_target, &race_1177_bak).unwrap();
        assert!(!race_1177_bak.exists());
        assert_eq!(
            fs::read_to_string(&race_1177_target).unwrap(),
            "{\"newly_created_by_editor\":true}\n"
        );

        // INVARIANT: Additive Phase 1 (`copy_clean_tree_additive`) keeps legacy `hooks/tokenade_hook.py` alive alongside `bin/carbon-stack` until `prune_stale_tree_entries` runs after global hook cutover.
        let add_dst = tmp.0.join("additive-cutover-dst");
        fs::create_dir_all(add_dst.join("hooks")).unwrap();
        fs::write(add_dst.join("hooks").join("tokenade_hook.py"), "# v1 still runnable\n")
            .unwrap();
        copy_clean_tree_additive(&repo.join("plugin"), &add_dst, cfg!(windows)).unwrap();
        assert!(add_dst.join("hooks").join("tokenade_hook.py").is_file());
        #[cfg(windows)]
        assert!(add_dst.join("bin").join("carbon-stack.exe").is_file());
        #[cfg(not(windows))]
        assert!(add_dst.join("bin").join("carbon-stack").is_file());
        prune_stale_tree_entries(&repo.join("plugin"), &add_dst, cfg!(windows), &[]).unwrap();
        assert!(!add_dst.join("hooks").join("tokenade_hook.py").exists());

        // INVARIANT: `--event=PreToolUse` legacy commands are migrated + rolled back cleanly, while custom non-migratable commands still referencing `<target_plugin_dir>/hooks/*.py` fail closed BEFORE pruning `tokenade_hook.py`.
        let cfg_eq_ev = tmp.0.join("cfg-eq-event-mig");
        let shome_eq_ev = tmp.0.join("shome-eq-event-mig");
        let eq_plug = cfg_eq_ev.join("plugins").join(PLUGIN_NAME);
        fs::create_dir_all(eq_plug.join("hooks")).unwrap();
        fs::create_dir_all(eq_plug.join("rules")).unwrap();
        fs::write(eq_plug.join("plugin.json"), r#"{"name":"gemini-carbon-stack"}"#).unwrap();
        fs::write(eq_plug.join("rules").join("AGENTS.md"), "# v1\n").unwrap();
        fs::write(eq_plug.join("hooks").join("hooks.json"), "{}").unwrap();
        fs::write(eq_plug.join("hooks").join("tokenade_hook.py"), "# v1\n").unwrap();
        let eq_py = eq_plug
            .join("hooks")
            .join("tokenade_hook.py")
            .to_string_lossy()
            .replace('\\', "/");
        let wrapped_unmig = json!({
            "tokenade": {
                "PreToolUse": [{
                    "matcher": "run_command",
                    "hooks": [{"type": "command", "command": format!("my-wrapper && python \"{}\"", eq_py)}]
                }]
            }
        });
        fs::write(
            cfg_eq_ev.join("hooks.json"),
            format!("{}\n", serde_json::to_string_pretty(&wrapped_unmig).unwrap()),
        )
        .unwrap();
        let unmig_res = perform_install(&repo, &cfg_eq_ev, &shome_eq_ev, false, true);
        assert_eq!(unmig_res["ok"], false);
        assert!(eq_plug.join("hooks").join("tokenade_hook.py").is_file());

        let rel_cd_unmig = json!({
            "tokenade": {
                "PreToolUse": [{
                    "matcher": "run_command",
                    "hooks": [{
                        "type": "command",
                        "command": format!(
                            "cd \"{}\" && python plugins/gemini-carbon-stack/hooks/tokenade_hook.py",
                            cfg_eq_ev.to_string_lossy().replace('\\', "/")
                        )
                    }]
                }]
            }
        });
        fs::write(
            cfg_eq_ev.join("hooks.json"),
            format!("{}\n", serde_json::to_string_pretty(&rel_cd_unmig).unwrap()),
        )
        .unwrap();
        let rel_unmig_res = perform_install(&repo, &cfg_eq_ev, &shome_eq_ev, false, true);
        assert_eq!(rel_unmig_res["ok"], false);
        assert!(eq_plug.join("hooks").join("tokenade_hook.py").is_file());

        // INVARIANT: Relative `..` parent traversals (`cd "<config_dir>/rules" && python ../plugins/gemini-carbon-stack/hooks/tokenade_hook.py` and nested `-c` shell quotes) resolve lexically to `<target_plugin_dir>/hooks/tokenade_hook.py` and fail closed without false positives on foreign profiles.
        let dotdot_cd_unmig = json!({
            "tokenade": {
                "PreToolUse": [{
                    "matcher": "run_command",
                    "hooks": [{
                        "type": "command",
                        "command": format!(
                            "cd \"{}/rules\" && python ../plugins/gemini-carbon-stack/hooks/tokenade_hook.py",
                            cfg_eq_ev.to_string_lossy().replace('\\', "/")
                        )
                    }]
                }]
            }
        });
        fs::write(
            cfg_eq_ev.join("hooks.json"),
            format!("{}\n", serde_json::to_string_pretty(&dotdot_cd_unmig).unwrap()),
        )
        .unwrap();
        let dotdot_res = perform_install(&repo, &cfg_eq_ev, &shome_eq_ev, false, true);
        assert_eq!(dotdot_res["ok"], false);
        assert!(eq_plug.join("hooks").join("tokenade_hook.py").is_file());

        let nested_sh_unmig = json!({
            "tokenade": {
                "PreToolUse": [{
                    "matcher": "run_command",
                    "hooks": [{
                        "type": "command",
                        "command": format!(
                            "sh -c \"cd '{}/rules' && python ../plugins/gemini-carbon-stack/hooks/tokenade_hook.py\"",
                            cfg_eq_ev.to_string_lossy().replace('\\', "/")
                        )
                    }]
                }]
            }
        });
        fs::write(
            cfg_eq_ev.join("hooks.json"),
            format!("{}\n", serde_json::to_string_pretty(&nested_sh_unmig).unwrap()),
        )
        .unwrap();
        let nested_sh_res = perform_install(&repo, &cfg_eq_ev, &shome_eq_ev, false, true);
        assert_eq!(nested_sh_res["ok"], false);
        assert!(eq_plug.join("hooks").join("tokenade_hook.py").is_file());

        let eq_scope = HookInstanceScope {
            config_dir: &cfg_eq_ev,
            target_plugin_dir: &eq_plug,
            is_windows: cfg!(windows),
        };
        assert!(!command_references_scoped_legacy_plugin_py(
            "cd \"/foreign/other/.gemini/config/rules\" && python ../plugins/gemini-carbon-stack/hooks/tokenade_hook.py",
            eq_scope,
        ));
        let posix_cfg = Path::new("/home/me/.gemini/config");
        let posix_plug = Path::new("/home/me/.gemini/config/plugins/gemini-carbon-stack");
        let posix_scope = HookInstanceScope {
            config_dir: posix_cfg,
            target_plugin_dir: posix_plug,
            is_windows: false,
        };
        assert!(command_references_scoped_legacy_plugin_py(
            "sh -c \"python /home/me/.gemini/config/plugins/gemini-carbon-stack/hooks/tokenade_hook.py\"",
            posix_scope,
        ));
        assert!(command_references_scoped_legacy_plugin_py(
            "(cd /foreign/other/.gemini/config/rules && echo ok) && python plugins/gemini-carbon-stack/hooks/tokenade_hook.py",
            posix_scope,
        ));
        assert!(command_references_scoped_legacy_plugin_py(
            "cd \"$DYNAMIC_DIR\" && python ../plugins/gemini-carbon-stack/hooks/tokenade_hook.py",
            posix_scope,
        ));
        assert!(!command_references_scoped_legacy_plugin_py(
            "sh -c \"python /foreign/other/.gemini/config/plugins/gemini-carbon-stack/hooks/tokenade_hook.py\"",
            posix_scope,
        ));
        assert!(command_references_scoped_legacy_plugin_py(
            "Push-Location -LiteralPath '/home/me/.gemini/config/plugins/gemini-carbon-stack'; python hooks/tokenade_hook.py --event PreToolUse",
            posix_scope,
        ));
        assert!(command_references_scoped_legacy_plugin_py(
            "Set-Location -Path:'/home/me/.gemini/config/plugins/gemini-carbon-stack'; python hooks/tokenade_hook.py",
            posix_scope,
        ));
        assert!(command_references_scoped_legacy_plugin_py(
            "Push-Location '/foreign/dir'; Pop-Location; Push-Location '/home/me/.gemini/config/plugins/gemini-carbon-stack'; python hooks/tokenade_hook.py",
            posix_scope,
        ));
        assert!(command_references_scoped_legacy_plugin_py(
            "env -C /home/me/.gemini/config/plugins/gemini-carbon-stack python hooks/tokenade_hook.py",
            posix_scope,
        ));
        assert!(command_references_scoped_legacy_plugin_py(
            "cd '/home/me/.gemini/config/plugins/gemini-carbon-stack'; env -C /tmp pwd; python hooks/tokenade_hook.py",
            posix_scope,
        ));
        assert!(command_references_scoped_legacy_plugin_py(
            "Push-Location -LiteralPath '/home/me/.gemini/config/plugins/gemini-carbon-stack'; Push-Location -StackName a -LiteralPath '/tmp'; Push-Location -StackName b -LiteralPath '/var'; Pop-Location -StackName a; python hooks/tokenade_hook.py",
            posix_scope,
        ));
        assert!(!command_references_scoped_legacy_plugin_py(
            "Push-Location -LiteralPath '/foreign/dir'; Push-Location -StackName a -LiteralPath '/foreign/dir'; Push-Location -StackName b -LiteralPath '/home/me/.gemini/config/plugins/gemini-carbon-stack'; Pop-Location -StackName a; python hooks/tokenade_hook.py",
            posix_scope,
        ));

        let plain_sh_c_unmig = json!({
            "tokenade": {
                "PreToolUse": [{
                    "matcher": "run_command",
                    "hooks": [{
                        "type": "command",
                        "command": format!(
                            "sh -c \"python {}\"",
                            eq_py
                        )
                    }]
                }]
            }
        });
        fs::write(
            cfg_eq_ev.join("hooks.json"),
            format!("{}\n", serde_json::to_string_pretty(&plain_sh_c_unmig).unwrap()),
        )
        .unwrap();
        let plain_sh_c_res = perform_install(&repo, &cfg_eq_ev, &shome_eq_ev, false, true);
        assert_eq!(plain_sh_c_res["ok"], false);
        assert!(eq_plug.join("hooks").join("tokenade_hook.py").is_file());

        let push_loc_unmig = json!({
            "tokenade": {
                "PreToolUse": [{
                    "matcher": "run_command",
                    "hooks": [{
                        "type": "command",
                        "command": format!(
                            "Push-Location -LiteralPath '{}'; python hooks/tokenade_hook.py --event PreToolUse",
                            eq_plug.to_string_lossy().replace('\\', "/")
                        )
                    }]
                }]
            }
        });
        fs::write(
            cfg_eq_ev.join("hooks.json"),
            format!("{}\n", serde_json::to_string_pretty(&push_loc_unmig).unwrap()),
        )
        .unwrap();
        let push_loc_res = perform_install(&repo, &cfg_eq_ev, &shome_eq_ev, false, true);
        assert_eq!(push_loc_res["ok"], false);
        assert!(eq_plug.join("hooks").join("tokenade_hook.py").is_file());

        // INVARIANT: If rollback published a legacy `.py` command onto `hooks.json` and reverse-swap failed (`rb_published_unreverted`), `compensate_rollback_after_unreverted_hooks` keeps `v1` scripts alive and reports `compensated_plugin_restore: false` when `hooks.json` cannot be reverted to `v2`, and restores `v2` cleanly when surgical forward re-migration succeeds.
        let rb_unrev_cfg = tmp.0.join("rb-unrev-cfg");
        let rb_unrev_state = tmp.0.join("rb-unrev-state");
        let rb_unrev_stage_root = tmp.0.join("rb-unrev-stage");
        let rb_unrev_stage_plug = rb_unrev_stage_root.join("plugin");
        let rb_unrev_stage_rule = rb_unrev_stage_root.join("uiux-design.md");
        let rb_unrev_stage_hooks = rb_unrev_stage_root.join("global_hooks.json");
        let rb_unrev_ptarget = rb_unrev_cfg.join("plugins").join(PLUGIN_NAME);
        let rb_unrev_rtarget = rb_unrev_cfg.join("rules").join("uiux-design.md");
        let rb_unrev_htarget = rb_unrev_cfg.join("hooks.json");
        fs::create_dir_all(rb_unrev_ptarget.join("hooks")).unwrap();
        fs::create_dir_all(rb_unrev_rtarget.parent().unwrap()).unwrap();
        fs::create_dir_all(&rb_unrev_state).unwrap();
        fs::write(
            rb_unrev_ptarget.join("hooks").join("tokenade_hook.py"),
            "# v1 active script\n",
        )
        .unwrap();
        fs::write(&rb_unrev_rtarget, "# v1 rule\n").unwrap();
        copy_clean_tree_for_os(&repo.join("plugin"), &rb_unrev_stage_plug, true).unwrap();
        let stage_v2_hashes = tree_manifest_strict(&rb_unrev_stage_plug).unwrap();
        fs::write(&rb_unrev_stage_rule, "# v2 rule\n").unwrap();
        let stage_v2_rsha = sha256_file_full(&rb_unrev_stage_rule).unwrap();
        let unrev_py_path = rb_unrev_ptarget
            .join("hooks")
            .join("tokenade_hook.py")
            .to_string_lossy()
            .replace('\\', "/");
        let stuck_v1_hooks = json!({
            "tokenade": {
                "PreToolUse": [{
                    "matcher": "run_command",
                    "hooks": [{"type": "command", "command": format!("custom-wrap && python \"{}\"", unrev_py_path)}]
                }]
            }
        });
        fs::write(
            &rb_unrev_htarget,
            format!("{}\n", serde_json::to_string_pretty(&stuck_v1_hooks).unwrap()),
        )
        .unwrap();
        let rb_unrev_scope = HookInstanceScope {
            config_dir: &rb_unrev_cfg,
            target_plugin_dir: &rb_unrev_ptarget,
            is_windows: cfg!(windows),
        };
        let rb_unrev_stage = RollbackStage {
            had_live_plugin: true,
            expected_live_hashes: Some(&stage_v2_hashes),
            had_live_rule: true,
            expected_live_rule_sha: Some(&stage_v2_rsha),
            had_live_hooks: true,
            expected_live_hooks_sha: None,
            had_prior_v1_epoch: false,
            drain_timeout: Duration::from_millis(50),
            config_dir: &rb_unrev_cfg,
            state_root: &rb_unrev_state,
            stage_root: &rb_unrev_stage_root,
            stage_plugin: &rb_unrev_stage_plug,
            stage_rule: &rb_unrev_stage_rule,
            stage_hooks: &rb_unrev_stage_hooks,
            p_target: &rb_unrev_ptarget,
            r_target: &rb_unrev_rtarget,
            h_target: &rb_unrev_htarget,
        };
        let stuck_comp = compensate_rollback_after_unreverted_hooks(
            &rb_unrev_stage,
            rb_unrev_scope,
            true,
            RollbackMutated {
                plugin: true,
                rule: true,
                hooks: false,
            },
            json!({
                "ok": false,
                "stage": "rollback_hooks_restore",
                "error": "simulated reverse-swap failure",
            }),
        );
        assert_eq!(stuck_comp["ok"], false);
        assert_eq!(stuck_comp["compensated_plugin_restore"], false);
        assert!(rb_unrev_ptarget.join("hooks").join("tokenade_hook.py").is_file());

        let migratable_v1_hooks = json!({
            "tokenade": {
                "PreToolUse": [{
                    "matcher": "run_command",
                    "hooks": [{"type": "command", "command": format!("python \"{}\" --event PreToolUse", unrev_py_path)}]
                }]
            }
        });
        fs::write(
            &rb_unrev_htarget,
            format!("{}\n", serde_json::to_string_pretty(&migratable_v1_hooks).unwrap()),
        )
        .unwrap();
        let remig_comp = compensate_rollback_after_unreverted_hooks(
            &rb_unrev_stage,
            rb_unrev_scope,
            true,
            RollbackMutated {
                plugin: true,
                rule: true,
                hooks: false,
            },
            json!({
                "ok": false,
                "stage": "rollback_hooks_restore",
                "error": "simulated reverse-swap failure",
            }),
        );
        assert_eq!(remig_comp["ok"], false);
        assert_eq!(remig_comp["compensated_plugin_restore"], true);
        assert!(!rb_unrev_ptarget.join("hooks").join("tokenade_hook.py").exists());
        let remig_h_after: Value =
            serde_json::from_str(&fs::read_to_string(&rb_unrev_htarget).unwrap()).unwrap();
        assert_eq!(
            remig_h_after.pointer("/tokenade/PreToolUse/0/hooks/0/command"),
            Some(&Value::String(desired_tokenade_hook_command(
                &rb_unrev_ptarget,
                cfg!(windows)
            )))
        );

        // INVARIANT: `prune_plugin_tree_guarded_with_hook` holds `acquire_hooks_read_share_guard` across verification AND pruning: Antigravity reads of `hooks.json` succeed while external writes/atomic replacements on Windows are kernel-blocked (`ERROR_SHARING_VIOLATION`) until pruning finishes, and if `hooks.json` already references `.py`, pruning aborts BEFORE unlinking the script.
        copy_clean_tree_for_os(&repo.join("plugin"), &rb_unrev_stage_plug, true).unwrap();
        fs::write(&rb_unrev_stage_rule, "# v2 rule\n").unwrap();
        fs::create_dir_all(rb_unrev_ptarget.join("hooks")).unwrap();
        fs::write(
            rb_unrev_ptarget.join("hooks").join("tokenade_hook.py"),
            "# v1 active script\n",
        )
        .unwrap();
        let clean_v2_hooks = json!({
            "tokenade": {
                "PreToolUse": [{
                    "matcher": "run_command",
                    "hooks": [{"type": "command", "command": desired_tokenade_hook_command(&rb_unrev_ptarget, cfg!(windows))}]
                }]
            }
        });
        fs::write(
            &rb_unrev_htarget,
            format!("{}\n", serde_json::to_string_pretty(&clean_v2_hooks).unwrap()),
        )
        .unwrap();
        let locked_h_probe = rb_unrev_htarget.clone();
        let locked_py_probe = rb_unrev_ptarget.join("hooks").join("tokenade_hook.py");
        let mut saw_locked_probe = false;
        prune_plugin_tree_guarded_with_hook(
            &rb_unrev_stage_plug,
            &rb_unrev_ptarget,
            &rb_unrev_htarget,
            rb_unrev_scope,
            &[],
            || {
                saw_locked_probe = true;
                assert!(locked_py_probe.is_file());
                assert!(fs::read_to_string(&locked_h_probe).is_ok());
                #[cfg(windows)]
                {
                    assert!(fs::write(&locked_h_probe, "{}\n").is_err());
                    let cand_repl = locked_h_probe.with_file_name("hooks.repl.tmp");
                    let cand_disp = locked_h_probe.with_file_name("hooks.disp.tmp");
                    fs::write(&cand_repl, "{}\n").unwrap();
                    assert!(win32_sqlite::atomic_replace_capturing_displaced(
                        &locked_h_probe,
                        &cand_repl,
                        &cand_disp,
                    )
                    .is_err());
                    let _ = fs::remove_file(&cand_repl);
                    let _ = fs::remove_file(&cand_disp);
                }
            },
        )
        .unwrap();
        assert!(saw_locked_probe);
        assert!(!rb_unrev_ptarget.join("hooks").join("tokenade_hook.py").exists());

        fs::create_dir_all(rb_unrev_ptarget.join("hooks")).unwrap();
        fs::write(
            rb_unrev_ptarget.join("hooks").join("tokenade_hook.py"),
            "# v1 never unlinked\n",
        )
        .unwrap();
        fs::write(
            &rb_unrev_htarget,
            format!("{}\n", serde_json::to_string_pretty(&stuck_v1_hooks).unwrap()),
        )
        .unwrap();
        let comp_when_hooks_v1 = compensate_plugin_rollback(
            &rb_unrev_stage,
            RollbackMutated {
                plugin: true,
                rule: true,
                hooks: false,
            },
            json!({ "ok": false, "stage": "rollback_hooks_restore", "error": "race" }),
        );
        assert_eq!(comp_when_hooks_v1["compensated_plugin_restore"], false);
        assert!(rb_unrev_ptarget.join("hooks").join("tokenade_hook.py").is_file());

        let eq_cmd_before = format!("python \"{}\" --event=PreToolUse", eq_py);
        let eq_valid = json!({
            "tokenade": {
                "PreToolUse": [{
                    "matcher": "run_command",
                    "hooks": [{"type": "command", "command": eq_cmd_before}]
                }]
            }
        });
        fs::write(
            cfg_eq_ev.join("hooks.json"),
            format!("{}\n", serde_json::to_string_pretty(&eq_valid).unwrap()),
        )
        .unwrap();
        assert_eq!(
            perform_install(&repo, &cfg_eq_ev, &shome_eq_ev, false, true)["ok"],
            true
        );
        let eq_after_inst: Value =
            serde_json::from_str(&fs::read_to_string(cfg_eq_ev.join("hooks.json")).unwrap())
                .unwrap();
        assert_eq!(
            eq_after_inst.pointer("/tokenade/PreToolUse/0/hooks/0/command"),
            Some(&Value::String(desired_tokenade_hook_command(
                &eq_plug,
                cfg!(windows)
            )))
        );
        assert_eq!(
            perform_rollback(&cfg_eq_ev, &shome_eq_ev, "latest")["ok"],
            true
        );
        let eq_after_rb: Value =
            serde_json::from_str(&fs::read_to_string(cfg_eq_ev.join("hooks.json")).unwrap())
                .unwrap();
        assert_eq!(
            eq_after_rb.pointer("/tokenade/PreToolUse/0/hooks/0/command"),
            Some(&Value::String(eq_cmd_before))
        );

        // INVARIANT: Cross-group swap of a migrated hook (`/group-a`) with a pre-existing native hook (`/group-b`) followed by editing `timeout` ONLY in `/group-b` is caught via `peer_set_sha256` so rollback NEVER overwrites `/group-a`'s native hook.
        let cfg_xgrp = tmp.0.join("cfg-cross-group-peer");
        let shome_xgrp = tmp.0.join("shome-cross-group-peer");
        let xg_plug = cfg_xgrp.join("plugins").join(PLUGIN_NAME);
        fs::create_dir_all(&cfg_xgrp).unwrap();
        let xg_py = xg_plug
            .join("hooks")
            .join("tokenade_hook.py")
            .to_string_lossy()
            .replace('\\', "/");
        let xg_legacy = format!("python \"{}\"", xg_py);
        let xg_native = desired_tokenade_hook_command(&xg_plug, cfg!(windows));
        let xg_init = json!({
            "group-a": {
                "PreToolUse": [{
                    "matcher": "run_command",
                    "hooks": [{"type": "command", "timeout": 10, "command": xg_legacy}]
                }]
            },
            "group-b": {
                "PreToolUse": [{
                    "matcher": "run_command",
                    "hooks": [{"type": "command", "timeout": 10, "command": xg_native}]
                }]
            }
        });
        fs::write(
            cfg_xgrp.join("hooks.json"),
            format!("{}\n", serde_json::to_string_pretty(&xg_init).unwrap()),
        )
        .unwrap();
        assert_eq!(
            perform_install(&repo, &cfg_xgrp, &shome_xgrp, false, true)["ok"],
            true
        );
        let mut xg_swapped: Value =
            serde_json::from_str(&fs::read_to_string(cfg_xgrp.join("hooks.json")).unwrap())
                .unwrap();
        xg_swapped["group-b"]["PreToolUse"][0]["hooks"][0]["timeout"] = json!(30);
        fs::write(
            cfg_xgrp.join("hooks.json"),
            format!("{}\n", serde_json::to_string_pretty(&xg_swapped).unwrap()),
        )
        .unwrap();
        let xg_rb = perform_rollback(&cfg_xgrp, &shome_xgrp, "latest");
        assert_eq!(xg_rb["ok"], false);
        assert_eq!(xg_rb["compensated_plugin_restore"], true);
        assert_eq!(
            xg_rb["hooks_rollback_conflicts"].as_array().unwrap().len(),
            1
        );
        assert!(xg_plug.join(platform_hook_binary_rel(cfg!(windows))).is_file());
        let xg_after_rb: Value =
            serde_json::from_str(&fs::read_to_string(cfg_xgrp.join("hooks.json")).unwrap())
                .unwrap();
        assert_eq!(
            xg_after_rb.pointer("/group-a/PreToolUse/0/hooks/0/command"),
            Some(&Value::String(xg_native.clone()))
        );
        assert_eq!(
            xg_after_rb.pointer("/group-b/PreToolUse/0/hooks/0/command"),
            Some(&Value::String(xg_native))
        );
        assert_eq!(
            xg_after_rb.pointer("/group-b/PreToolUse/0/hooks/0/timeout"),
            Some(&json!(30))
        );

        // INVARIANT: Rolling back to a Python-only `v1` backup when a migrated native hook was reordered/edited (`hooks_rollback_conflicts`) refuses rollback (`ok: false`, `compensated_plugin_restore: true`) BEFORE deleting `bin/carbon-stack`.
        let cfg_v1_conf = tmp.0.join("cfg-v1-py-only-conflict");
        let shome_v1_conf = tmp.0.join("shome-v1-py-only-conflict");
        let v1c_plug = cfg_v1_conf.join("plugins").join(PLUGIN_NAME);
        fs::create_dir_all(v1c_plug.join("hooks")).unwrap();
        fs::create_dir_all(v1c_plug.join("rules")).unwrap();
        fs::write(v1c_plug.join("plugin.json"), r#"{"name":"gemini-carbon-stack"}"#).unwrap();
        fs::write(v1c_plug.join("rules").join("AGENTS.md"), "# v1\n").unwrap();
        fs::write(
            v1c_plug.join("hooks.json"),
            r#"{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"python hooks/tokenade_hook.py"}]}],"PreInvocation":[{"hooks":[{"type":"command","command":"python hooks/tokenade_hook.py"}]}],"PreToolUse":[{"matcher":".*","hooks":[{"type":"command","command":"python hooks/tokenade_hook.py"}]}],"PostToolUse":[{"matcher":".*","hooks":[{"type":"command","command":"python hooks/tokenade_hook.py"}]}],"Stop":[{"hooks":[{"type":"command","command":"python hooks/tokenade_hook.py"}]}]}}"#,
        )
        .unwrap();
        fs::write(v1c_plug.join("hooks").join("tokenade_hook.py"), "# v1\n").unwrap();
        let v1c_py = v1c_plug
            .join("hooks")
            .join("tokenade_hook.py")
            .to_string_lossy()
            .replace('\\', "/");
        let v1c_init = json!({
            "tokenade": {
                "PreToolUse": [{
                    "matcher": "run_command",
                    "hooks": [{"type": "command", "timeout": 10, "command": format!("python \"{}\"", v1c_py)}]
                }]
            }
        });
        fs::write(
            cfg_v1_conf.join("hooks.json"),
            format!("{}\n", serde_json::to_string_pretty(&v1c_init).unwrap()),
        )
        .unwrap();
        assert_eq!(
            perform_install(&repo, &cfg_v1_conf, &shome_v1_conf, false, true)["ok"],
            true
        );
        let mut v1c_edited: Value =
            serde_json::from_str(&fs::read_to_string(cfg_v1_conf.join("hooks.json")).unwrap())
                .unwrap();
        v1c_edited["tokenade"]["PreToolUse"][0]["hooks"][0]["timeout"] = json!(45);
        fs::write(
            cfg_v1_conf.join("hooks.json"),
            format!("{}\n", serde_json::to_string_pretty(&v1c_edited).unwrap()),
        )
        .unwrap();
        let v1c_rb = perform_rollback(&cfg_v1_conf, &shome_v1_conf, "latest");
        assert_eq!(v1c_rb["ok"], false);
        assert_eq!(v1c_rb["compensated_plugin_restore"], true);
        assert_eq!(
            v1c_rb["hooks_rollback_conflicts"].as_array().unwrap().len(),
            1
        );
        assert!(v1c_plug
            .join(platform_hook_binary_rel(cfg!(windows)))
            .is_file());

        // INVARIANT: Sequential rollback `v1 -> v2 (Backup A) -> v2 (Backup B) -> rollback A -> rollback B` refuses `rollback B` (`ok: false`, `compensated_plugin_restore: true`) because `Backup B` has empty `migrations` and lacks `hooks/tokenade_hook.py` referenced by live `hooks.json`; post-contraction check also catches `NotFound -> created` `hooks.json` races.
        let cfg_seq_rb = tmp.0.join("cfg-seq-v1-v2-rb");
        let shome_seq_rb = tmp.0.join("shome-seq-v1-v2-rb");
        let seq_plug = cfg_seq_rb.join("plugins").join(PLUGIN_NAME);
        fs::create_dir_all(seq_plug.join("hooks")).unwrap();
        fs::create_dir_all(seq_plug.join("rules")).unwrap();
        fs::write(seq_plug.join("plugin.json"), r#"{"name":"gemini-carbon-stack"}"#).unwrap();
        fs::write(seq_plug.join("rules").join("AGENTS.md"), "# v1\n").unwrap();
        fs::write(
            seq_plug.join("hooks.json"),
            r#"{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"python hooks/tokenade_hook.py"}]}],"PreInvocation":[{"hooks":[{"type":"command","command":"python hooks/tokenade_hook.py"}]}],"PreToolUse":[{"matcher":".*","hooks":[{"type":"command","command":"python hooks/tokenade_hook.py"}]}],"PostToolUse":[{"matcher":".*","hooks":[{"type":"command","command":"python hooks/tokenade_hook.py"}]}],"Stop":[{"hooks":[{"type":"command","command":"python hooks/tokenade_hook.py"}]}]}}"#,
        )
        .unwrap();
        fs::write(seq_plug.join("hooks").join("tokenade_hook.py"), "# v1\n").unwrap();
        let seq_py = seq_plug
            .join("hooks")
            .join("tokenade_hook.py")
            .to_string_lossy()
            .replace('\\', "/");
        let seq_h_init = json!({
            "tokenade": {
                "PreToolUse": [{
                    "matcher": "run_command",
                    "hooks": [{"type": "command", "command": format!("python \"{}\"", seq_py)}]
                }]
            }
        });
        fs::write(
            cfg_seq_rb.join("hooks.json"),
            format!("{}\n", serde_json::to_string_pretty(&seq_h_init).unwrap()),
        )
        .unwrap();
        let inst_bak_a = perform_install(&repo, &cfg_seq_rb, &shome_seq_rb, false, true);
        assert_eq!(inst_bak_a["ok"], true);
        let bak_a_id = inst_bak_a["backup_id"].as_str().unwrap().to_string();
        fs::write(seq_plug.join("rules").join("AGENTS.md"), "# v2.0 modified\n").unwrap();
        let inst_bak_b = perform_install(&repo, &cfg_seq_rb, &shome_seq_rb, false, true);
        assert_eq!(inst_bak_b["ok"], true);
        let bak_b_id = inst_bak_b["backup_id"].as_str().unwrap().to_string();
        assert_eq!(
            perform_rollback(&cfg_seq_rb, &shome_seq_rb, &bak_a_id)["ok"],
            true
        );
        assert!(seq_plug.join("hooks").join("tokenade_hook.py").is_file());
        let seq_rb_b = perform_rollback(&cfg_seq_rb, &shome_seq_rb, &bak_b_id);
        assert_eq!(seq_rb_b["ok"], false);
        assert_eq!(seq_rb_b["compensated_plugin_restore"], true);
        assert!(seq_plug.join("hooks").join("tokenade_hook.py").is_file());

        let nf_race_dir = tmp.0.join("rb-nf-race");
        let nf_race_plug = nf_race_dir.join("plugins").join(PLUGIN_NAME);
        let nf_race_hooks = nf_race_dir.join("hooks.json");
        copy_clean_tree_for_os(&repo.join("plugin"), &nf_race_plug, true).unwrap();
        let nf_scope = HookInstanceScope {
            config_dir: &nf_race_dir,
            target_plugin_dir: &nf_race_plug,
            is_windows: cfg!(windows),
        };
        let nf_native_cmd = desired_tokenade_hook_command(&nf_race_plug, cfg!(windows));
        let nf_prune_v1_src = tmp.0.join("rb-nf-prune-v1-src");
        fs::create_dir_all(nf_prune_v1_src.join("rules")).unwrap();
        fs::write(
            nf_prune_v1_src.join("plugin.json"),
            "{\"name\": \"gemini-carbon-stack\", \"version\": \"0.1.0\"}\n",
        )
        .unwrap();
        fs::write(nf_prune_v1_src.join("rules").join("AGENTS.md"), "# v1\n").unwrap();
        let nf_hooks_prune_clone = nf_race_hooks.clone();
        let nf_bin_probe = nf_race_plug.join(platform_hook_binary_rel(cfg!(windows)));
        let mut prune_cb_ran = false;
        let nf_prune_res = prune_plugin_tree_guarded_with_hook(
            &nf_prune_v1_src,
            &nf_race_plug,
            &nf_race_hooks,
            nf_scope,
            &[],
            || {
                prune_cb_ran = true;
                assert!(nf_bin_probe.is_file());
                let created = json!({
                    "tokenade": {
                        "PreToolUse": [{"matcher": "run_command", "hooks": [{"type": "command", "command": nf_native_cmd}]}]
                    }
                });
                let payload = format!("{}\n", serde_json::to_string_pretty(&created).unwrap());
                #[cfg(windows)]
                {
                    assert_eq!(fs::read_to_string(&nf_hooks_prune_clone).unwrap(), "{}\n");
                    assert!(fs::write(&nf_hooks_prune_clone, payload).is_err());
                }
                #[cfg(not(windows))]
                {
                    fs::write(&nf_hooks_prune_clone, payload).unwrap();
                }
            },
        );
        assert!(prune_cb_ran);
        #[cfg(windows)]
        {
            assert!(nf_prune_res.is_ok());
            assert!(!nf_race_hooks.exists());
            copy_clean_tree_for_os(&repo.join("plugin"), &nf_race_plug, true).unwrap();
            let nf_hooks_rm_clone = nf_race_hooks.clone();
            let mut rm_cb_ran = false;
            remove_rollback_tree_guarded_with_hook(
                &nf_race_plug,
                &nf_race_hooks,
                nf_scope,
                &[],
                || {
                    rm_cb_ran = true;
                    assert_eq!(fs::read_to_string(&nf_hooks_rm_clone).unwrap(), "{}\n");
                    assert!(fs::write(&nf_hooks_rm_clone, "{\"x\":1}\n").is_err());
                },
            )
            .unwrap();
            assert!(rm_cb_ran);
            assert!(!nf_race_plug.exists());
            assert!(!nf_race_hooks.exists());
        }
        #[cfg(not(windows))]
        {
            assert!(nf_prune_res.is_err());
            assert!(nf_bin_probe.is_file());
        }

        let ir_cfg = tmp.0.join("cfg-interrupted-retire");
        let ir_shome = tmp.0.join("shome-interrupted-retire");
        let ir_plug = ir_cfg.join("plugins").join(PLUGIN_NAME);
        fs::create_dir_all(&ir_cfg).unwrap();
        assert_eq!(
            perform_install(&repo, &ir_cfg, &ir_shome, false, true)["ok"],
            true
        );
        let ir_bin_rel = platform_hook_binary_rel(cfg!(windows));
        let ir_hooks_path = ir_cfg.join("hooks.json");
        let ir_native_hooks = json!({
            "tokenade": {
                "PreToolUse": [{"matcher": "run_command", "hooks": [{"type": "command", "command": desired_tokenade_hook_command(&ir_plug, cfg!(windows))}]}]
            }
        });
        fs::write(
            &ir_hooks_path,
            format!("{}\n", serde_json::to_string_pretty(&ir_native_hooks).unwrap()),
        )
        .unwrap();
        let ir_stage = ir_cfg.join(format!("{}999999-1-1", STAGE_RETIRE_PREFIX));
        let ir_staged_bin = ir_stage.join("files").join(ir_bin_rel);
        fs::create_dir_all(ir_staged_bin.parent().unwrap()).unwrap();
        fs::rename(ir_plug.join(ir_bin_rel), &ir_staged_bin).unwrap();
        fs::write(ir_stage.join("active.lock"), b"").unwrap();
        write_stage_retire_journal(&ir_stage, "prune", "contracting", false).unwrap();
        assert!(!ir_plug.join(ir_bin_rel).is_file());
        let diag_before_rec = perform_diagnose(&repo, &ir_cfg, &ir_shome);
        assert_eq!(diag_before_rec["ok"], false);
        assert_eq!(
            diag_before_rec["interrupted_stage_retire_dirs"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(!ir_plug.join(ir_bin_rel).is_file());
        let rec_inst = perform_install(&repo, &ir_cfg, &ir_shome, false, true);
        assert_eq!(rec_inst["ok"], true);
        assert!(ir_plug.join(ir_bin_rel).is_file());
        assert!(!ir_stage.exists());
        let diag_after_rec = perform_diagnose(&repo, &ir_cfg, &ir_shome);
        assert_eq!(diag_after_rec["in_sync_with_source"], true);
        assert!(diag_after_rec.get("interrupted_stage_retire_dirs").is_none());

        let pr_cfg = tmp.0.join("cfg-partial-restore-preserve");
        let pr_plug = pr_cfg.join("plugins").join(PLUGIN_NAME);
        fs::create_dir_all(pr_plug.join("hooks").join("a.py")).unwrap();
        let pr_stage = pr_cfg.join(format!("{}999999-2-2", STAGE_RETIRE_PREFIX));
        fs::create_dir_all(pr_stage.join("files").join("hooks")).unwrap();
        fs::write(pr_stage.join("files").join("hooks").join("a.py"), "# a\n").unwrap();
        fs::write(pr_stage.join("files").join("hooks").join("b.py"), "# b\n").unwrap();
        write_stage_retire_journal(&pr_stage, "prune", "contracting", false).unwrap();
        let pr_err = recover_interrupted_stage_retire_dirs(&pr_cfg, &[]).unwrap_err();
        assert!(pr_err.contains(&pr_stage.display().to_string()));
        assert!(pr_plug.join("hooks").join("b.py").is_file());
        assert!(pr_stage.join("files").join("hooks").join("a.py").is_file());
        let pr_err_2 = recover_interrupted_stage_retire_dirs(&pr_cfg, &[]).unwrap_err();
        assert!(pr_err_2.contains(&pr_stage.display().to_string()));
        assert!(pr_plug.join("hooks").join("b.py").is_file());
        assert!(pr_stage.join("files").join("hooks").join("a.py").is_file());
        fs::remove_dir(pr_plug.join("hooks").join("a.py")).unwrap();
        recover_interrupted_stage_retire_dirs(&pr_cfg, &[]).unwrap();
        assert!(pr_plug.join("hooks").join("a.py").is_file());
        assert!(pr_plug.join("hooks").join("b.py").is_file());
        assert!(!pr_stage.exists());

        let tr_cfg = tmp.0.join("cfg-partial-tree-preserve");
        let tr_plug = tr_cfg.join("plugins").join(PLUGIN_NAME);
        let tr_hooks = tr_cfg.join("hooks.json");
        fs::create_dir_all(tr_plug.join("hooks").join("a.py")).unwrap();
        let tr_b_cmd = format!(
            "python \"{}\"",
            tr_plug
                .join("hooks")
                .join("b.py")
                .to_string_lossy()
                .replace('\\', "/")
        );
        fs::write(
            &tr_hooks,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&json!({
                    "custom": {"PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": tr_b_cmd}]}]}
                }))
                .unwrap()
            ),
        )
        .unwrap();
        let tr_stage = tr_cfg.join(format!("{}999999-3-3", STAGE_RETIRE_PREFIX));
        fs::create_dir_all(tr_stage.join("tree").join("hooks")).unwrap();
        fs::write(tr_stage.join("tree").join("hooks").join("a.py"), "# a\n").unwrap();
        fs::write(tr_stage.join("tree").join("hooks").join("b.py"), "# b\n").unwrap();
        write_stage_retire_journal(&tr_stage, "remove", "contracting", false).unwrap();
        let tr_err = recover_interrupted_stage_retire_dirs(&tr_cfg, &[]).unwrap_err();
        assert!(tr_err.contains(&tr_stage.display().to_string()));
        assert!(tr_plug.join("hooks").join("b.py").is_file());
        assert!(tr_stage.join("tree").join("hooks").join("a.py").is_file());
        let tr_err_2 = recover_interrupted_stage_retire_dirs(&tr_cfg, &[]).unwrap_err();
        assert!(tr_err_2.contains(&tr_stage.display().to_string()));
        assert!(tr_plug.join("hooks").join("b.py").is_file());
        assert!(tr_stage.join("tree").join("hooks").join("a.py").is_file());
        fs::remove_dir(tr_plug.join("hooks").join("a.py")).unwrap();
        recover_interrupted_stage_retire_dirs(&tr_cfg, &[]).unwrap();
        assert!(tr_plug.join("hooks").join("a.py").is_file());
        assert!(tr_plug.join("hooks").join("b.py").is_file());
        assert!(!tr_stage.exists());

        let orig_iso_cfg = tmp.0.join("cfg-orig-isolation");
        let orig_iso_plug = orig_iso_cfg.join("plugins").join(PLUGIN_NAME);
        fs::create_dir_all(&orig_iso_plug).unwrap();
        fs::write(orig_iso_plug.join("sentinel.txt"), "do-not-touch\n").unwrap();
        let copy_iso_cfg = tmp.0.join("cfg-copy-isolation");
        let copy_iso_stage = copy_iso_cfg.join(format!("{}999999-4-4", STAGE_RETIRE_PREFIX));
        fs::create_dir_all(copy_iso_stage.join("tree").join("hooks")).unwrap();
        fs::write(
            copy_iso_stage.join("tree").join("hooks").join("copied.py"),
            "# copied\n",
        )
        .unwrap();
        rio::write_json(
            &copy_iso_stage.join("retire-journal.json"),
            &json!({
                "version": 1,
                "pid": 999_999u32,
                "mode": "remove",
                "phase": "contracting",
                "dst_tree": orig_iso_plug.to_string_lossy(),
                "hooks_path": orig_iso_cfg.join("hooks.json").to_string_lossy(),
                "sentinel_hooks": false,
            }),
        )
        .unwrap();
        recover_interrupted_stage_retire_dirs(&copy_iso_cfg, &[]).unwrap();
        assert!(orig_iso_plug.join("sentinel.txt").is_file());
        assert!(!orig_iso_plug.join("hooks").join("copied.py").exists());
        assert!(copy_iso_cfg
            .join("plugins")
            .join(PLUGIN_NAME)
            .join("hooks")
            .join("copied.py")
            .is_file());
        assert!(!copy_iso_stage.exists());

        let pp_cfg = tmp.0.join("cfg-pre-preflight-recover");
        let pp_shome = tmp.0.join("shome-pre-preflight-recover");
        let pp_plug = pp_cfg.join("plugins").join(PLUGIN_NAME);
        fs::create_dir_all(&pp_cfg).unwrap();
        assert_eq!(
            perform_install(&repo, &pp_cfg, &pp_shome, false, true)["ok"],
            true
        );
        let pp_stage = pp_cfg.join(format!("{}999999-5-5", STAGE_RETIRE_PREFIX));
        fs::create_dir_all(pp_stage.join("files").join("hooks")).unwrap();
        fs::write(
            pp_stage.join("files").join("hooks").join("Audit.py"),
            "# stranded audit\n",
        )
        .unwrap();
        write_stage_retire_journal(&pp_stage, "prune", "contracting", false).unwrap();
        let pp_audit_cmd = format!(
            "python \"{}\"",
            pp_plug
                .join("hooks")
                .join("Audit.py")
                .to_string_lossy()
                .replace('\\', "/")
        );
        fs::write(
            pp_cfg.join("hooks.json"),
            format!(
                "{}\n",
                serde_json::to_string_pretty(&json!({
                    "custom": {"PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": pp_audit_cmd}]}]}
                }))
                .unwrap()
            ),
        )
        .unwrap();
        let pp_inst = perform_install(&repo, &pp_cfg, &pp_shome, false, true);
        assert_eq!(pp_inst["ok"], false);
        assert_eq!(pp_inst["stage"], "preflight");
        assert!(pp_plug.join("hooks").join("Audit.py").is_file());
        assert!(!pp_stage.exists());

        let bad_j_cfg = tmp.0.join("cfg-corrupt-journal-preserve");
        let bad_j_stage = bad_j_cfg.join(format!("{}999999-6-6", STAGE_RETIRE_PREFIX));
        fs::create_dir_all(bad_j_stage.join("files").join("hooks")).unwrap();
        fs::write(
            bad_j_stage.join("files").join("hooks").join("keep.py"),
            "# keep\n",
        )
        .unwrap();
        fs::write(bad_j_stage.join("retire-journal.json"), "{corrupt-json").unwrap();
        let bad_j_err = recover_interrupted_stage_retire_dirs(&bad_j_cfg, &[]).unwrap_err();
        assert!(bad_j_err.contains(&bad_j_stage.display().to_string()));
        assert!(bad_j_stage.join("files").join("hooks").join("keep.py").is_file());
        rio::write_json(
            &bad_j_stage.join("retire-journal.json"),
            &json!({"version": 1, "pid": 999_999u32, "mode": "bogus", "phase": "contracting", "sentinel_hooks": false}),
        )
        .unwrap();
        let bad_m_err = recover_interrupted_stage_retire_dirs(&bad_j_cfg, &[]).unwrap_err();
        assert!(bad_m_err.contains(&bad_j_stage.display().to_string()));
        assert!(bad_j_stage.join("files").join("hooks").join("keep.py").is_file());
        fs::write(bad_j_cfg.join("hooks.json"), HOOKS_SENTINEL_BYTES).unwrap();
        rio::write_json(
            &bad_j_stage.join("retire-journal.json"),
            &json!({"version": 1, "pid": 999_999u32, "mode": "bogus", "phase": "committed_delete", "sentinel_hooks": true}),
        )
        .unwrap();
        let bad_cd_err = recover_interrupted_stage_retire_dirs(&bad_j_cfg, &[]).unwrap_err();
        assert!(bad_cd_err.contains(&bad_j_stage.display().to_string()));
        assert!(bad_j_cfg.join("hooks.json").is_file());
        assert!(bad_j_stage.join("files").join("hooks").join("keep.py").is_file());
        rio::write_json(
            &bad_j_stage.join("retire-journal.json"),
            &json!({"version": 1, "pid": 999_999u32, "mode": "prune", "phase": "committed_delete"}),
        )
        .unwrap();
        let bad_sh_err = recover_interrupted_stage_retire_dirs(&bad_j_cfg, &[]).unwrap_err();
        assert!(bad_sh_err.contains(&bad_j_stage.display().to_string()));
        assert!(bad_j_stage.join("files").join("hooks").join("keep.py").is_file());

        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let cd_lock_cfg = tmp.0.join("cfg-committed-delete-locked-payload");
            let cd_stage = cd_lock_cfg.join(format!("{}999999-6b-6b", STAGE_RETIRE_PREFIX));
            fs::create_dir_all(cd_stage.join("files").join("hooks")).unwrap();
            let locked_p = cd_stage.join("files").join("hooks").join("locked.txt");
            fs::write(&locked_p, "hold\n").unwrap();
            write_stage_retire_journal(&cd_stage, "prune", "committed_delete", false).unwrap();
            let hold_fh = fs::OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(&locked_p)
                .unwrap();
            recover_interrupted_stage_retire_dirs(&cd_lock_cfg, &[]).unwrap();
            assert!(locked_p.is_file());
            assert!(cd_stage.join("retire-journal.json").is_file());
            drop(hold_fh);
            recover_interrupted_stage_retire_dirs(&cd_lock_cfg, &[]).unwrap();
            assert!(!cd_stage.exists());

            let cd_dirlock_cfg = tmp.0.join("cfg-committed-delete-unreadable-subdir");
            let cd_dir_stage = cd_dirlock_cfg.join(format!("{}999999-6c-6c", STAGE_RETIRE_PREFIX));
            let unreadable_sub = cd_dir_stage.join("files").join("hooks");
            fs::create_dir_all(&unreadable_sub).unwrap();
            let hidden_pyc = unreadable_sub.join("cached.pyc");
            fs::write(&hidden_pyc, b"\x00pyc").unwrap();
            assert_eq!(stage_dir_has_payload(&cd_dir_stage).unwrap(), true);
            write_stage_retire_journal(&cd_dir_stage, "prune", "committed_delete", false).unwrap();
            let dir_hold_fh = fs::OpenOptions::new()
                .read(true)
                .custom_flags(0x0200_0000)
                .share_mode(0)
                .open(&unreadable_sub)
                .unwrap();
            assert!(fs::read_dir(&unreadable_sub).is_err());
            assert!(stage_dir_has_payload(&cd_dir_stage).is_err());
            recover_interrupted_stage_retire_dirs(&cd_dirlock_cfg, &[]).unwrap();
            assert!(cd_dir_stage.join("retire-journal.json").is_file());
            drop(dir_hold_fh);
            assert!(hidden_pyc.is_file());
            recover_interrupted_stage_retire_dirs(&cd_dirlock_cfg, &[]).unwrap();
            assert!(!cd_dir_stage.exists());
        }

        let nested_link_cfg = tmp.0.join("cfg-nested-link-restore");
        let nested_link_plug = nested_link_cfg.join("plugins").join(PLUGIN_NAME);
        let outside_escape = tmp.0.join("outside-nested-escape");
        fs::create_dir_all(&nested_link_plug).unwrap();
        fs::create_dir_all(&outside_escape).unwrap();
        let nested_hooks_link = nested_link_plug.join("hooks");
        #[cfg(windows)]
        {
            let mk = Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&nested_hooks_link)
                .arg(&outside_escape)
                .output()
                .unwrap();
            assert!(mk.status.success());
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside_escape, &nested_hooks_link).unwrap();
        }
        let nl_stage = nested_link_cfg.join(format!("{}999999-7-7", STAGE_RETIRE_PREFIX));
        fs::create_dir_all(nl_stage.join("files").join("hooks")).unwrap();
        fs::write(nl_stage.join("files").join("hooks").join("evil.py"), "# x\n").unwrap();
        write_stage_retire_journal(&nl_stage, "prune", "contracting", false).unwrap();
        let nl_err = recover_interrupted_stage_retire_dirs(&nested_link_cfg, &[]).unwrap_err();
        assert!(nl_err.contains(&nl_stage.display().to_string()));
        assert!(!outside_escape.join("evil.py").exists());
        assert!(nl_stage.join("files").join("hooks").join("evil.py").is_file());
        #[cfg(windows)]
        let _ = fs::remove_dir(&nested_hooks_link);
        #[cfg(unix)]
        let _ = fs::remove_file(&nested_hooks_link);

        let cm_fail_cfg = tmp.0.join("cfg-commit-journal-fail");
        let cm_fail_dst = cm_fail_cfg.join("plugins").join(PLUGIN_NAME);
        fs::create_dir_all(&cm_fail_dst).unwrap();
        let cm_lease = alloc_stage_retire_lease(&cm_fail_cfg, "prune", false).unwrap();
        let cm_staged_files = cm_lease.dir.join("files");
        fs::create_dir_all(cm_staged_files.join("hooks")).unwrap();
        fs::write(cm_staged_files.join("hooks").join("rolled_back.py"), "# rb\n").unwrap();
        fs::remove_file(cm_lease.dir.join("retire-journal.json")).unwrap();
        fs::create_dir_all(cm_lease.dir.join("retire-journal.json")).unwrap();
        let cm_moved = vec!["hooks/rolled_back.py".to_string()];
        let cm_err = commit_stage_retire_or_restore(cm_lease, "prune", &[], || {
            restore_staged_prune_files(&cm_staged_files, &cm_fail_dst, &cm_moved)
        })
        .unwrap_err();
        assert!(cm_err.contains("Failed to commit stage-retire journal"));
        assert!(cm_fail_dst.join("hooks").join("rolled_back.py").is_file());

        let cfg_case_rb = tmp.0.join("cfg-mixed-case-py-rb");
        let shome_case_rb = tmp.0.join("shome-mixed-case-py-rb");
        let case_plug = cfg_case_rb.join("plugins").join(PLUGIN_NAME);
        fs::create_dir_all(&cfg_case_rb).unwrap();
        let first_case_inst = perform_install(&repo, &cfg_case_rb, &shome_case_rb, false, true);
        assert_eq!(first_case_inst["ok"], true);
        let first_case_bak = first_case_inst["backup_id"].as_str().unwrap().to_string();
        fs::create_dir_all(case_plug.join("hooks")).unwrap();
        fs::write(case_plug.join("hooks").join("Audit.py"), "# mixed case\n").unwrap();
        let case_ref_name = if cfg!(windows) || path_fs_is_case_insensitive(&case_plug) {
            "audit.py"
        } else {
            "Audit.py"
        };
        let case_py_cmd = format!(
            "python \"{}\"",
            case_plug
                .join("hooks")
                .join(case_ref_name)
                .to_string_lossy()
                .replace('\\', "/")
        );
        let live_case_hooks = json!({
            "custom_audit": {
                "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": case_py_cmd}]}]
            }
        });
        fs::write(
            cfg_case_rb.join("hooks.json"),
            format!("{}\n", serde_json::to_string_pretty(&live_case_hooks).unwrap()),
        )
        .unwrap();
        let case_rb = perform_rollback(&cfg_case_rb, &shome_case_rb, &first_case_bak);
        assert_eq!(case_rb["ok"], false);
        assert_eq!(case_rb["compensated_plugin_restore"], true);
        assert!(case_plug.join("hooks").join("Audit.py").is_file());

        // INVARIANT: When an event array has BOTH a migrated legacy hook AND a pre-existing native hook with identical attributes (from an earlier `v2` install), swapping them and editing the migrated hook's `timeout` is caught via `has_ambiguous_peer` + `event_sha256` so rollback NEVER overwrites the unmigrated native hook while keeping `v2` `bin/carbon-stack` runnable.
        let cfg_pre_nat = tmp.0.join("cfg-preexisting-native-peer");
        let shome_pre_nat = tmp.0.join("shome-preexisting-native-peer");
        let pn_plug = cfg_pre_nat.join("plugins").join(PLUGIN_NAME);
        fs::create_dir_all(&cfg_pre_nat).unwrap();
        assert_eq!(
            perform_install(&repo, &cfg_pre_nat, &shome_pre_nat, false, true)["ok"],
            true
        );
        fs::write(pn_plug.join("rules").join("AGENTS.md"), "# older v2\n").unwrap();
        fs::create_dir_all(pn_plug.join("hooks")).unwrap();
        fs::write(pn_plug.join("hooks").join("tokenade_hook.py"), "# hybrid v1+v2\n").unwrap();
        let pn_py = pn_plug
            .join("hooks")
            .join("tokenade_hook.py")
            .to_string_lossy()
            .replace('\\', "/");
        let pn_before_legacy = format!("python \"{}\"", pn_py);
        let pn_desired_native = desired_tokenade_hook_command(&pn_plug, cfg!(windows));
        let pn_init = json!({
            "tokenade": {
                "PreToolUse": [{
                    "matcher": "run_command",
                    "hooks": [
                        {"type": "command", "timeout": 10, "command": pn_before_legacy},
                        {"type": "command", "timeout": 10, "command": pn_desired_native}
                    ]
                }]
            }
        });
        fs::write(
            cfg_pre_nat.join("hooks.json"),
            format!("{}\n", serde_json::to_string_pretty(&pn_init).unwrap()),
        )
        .unwrap();
        assert_eq!(
            perform_install(&repo, &cfg_pre_nat, &shome_pre_nat, false, true)["ok"],
            true
        );
        let mut pn_other_grp: Value =
            serde_json::from_str(&fs::read_to_string(cfg_pre_nat.join("hooks.json")).unwrap())
                .unwrap();
        pn_other_grp["user-group"] = json!({"Stop": [{"type": "command", "command": "ok"}]});
        fs::write(
            cfg_pre_nat.join("hooks.json"),
            format!("{}\n", serde_json::to_string_pretty(&pn_other_grp).unwrap()),
        )
        .unwrap();
        let pn_clean_rb = perform_rollback(&cfg_pre_nat, &shome_pre_nat, "latest");
        assert_eq!(pn_clean_rb["ok"], true);
        assert!(pn_clean_rb.get("hooks_rollback_conflicts").is_none());
        let pn_after_clean_rb: Value =
            serde_json::from_str(&fs::read_to_string(cfg_pre_nat.join("hooks.json")).unwrap())
                .unwrap();
        assert_eq!(
            pn_after_clean_rb.pointer("/tokenade/PreToolUse/0/hooks/0/command"),
            Some(&Value::String(pn_before_legacy.clone()))
        );
        assert_eq!(
            pn_after_clean_rb.pointer("/tokenade/PreToolUse/0/hooks/1/command"),
            Some(&Value::String(pn_desired_native.clone()))
        );

        assert_eq!(
            perform_install(&repo, &cfg_pre_nat, &shome_pre_nat, false, true)["ok"],
            true
        );
        let mut pn_reordered: Value =
            serde_json::from_str(&fs::read_to_string(cfg_pre_nat.join("hooks.json")).unwrap())
                .unwrap();
        {
            let arr = pn_reordered
                .pointer_mut("/tokenade/PreToolUse/0/hooks")
                .unwrap()
                .as_array_mut()
                .unwrap();
            arr.swap(0, 1);
            arr[1]["timeout"] = json!(30);
        }
        fs::write(
            cfg_pre_nat.join("hooks.json"),
            format!("{}\n", serde_json::to_string_pretty(&pn_reordered).unwrap()),
        )
        .unwrap();
        let pn_conflict_rb = perform_rollback(&cfg_pre_nat, &shome_pre_nat, "latest");
        assert_eq!(pn_conflict_rb["ok"], true);
        assert_eq!(
            pn_conflict_rb["hooks_rollback_conflicts"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let pn_after_conflict: Value =
            serde_json::from_str(&fs::read_to_string(cfg_pre_nat.join("hooks.json")).unwrap())
                .unwrap();
        assert_eq!(
            pn_after_conflict.pointer("/tokenade/PreToolUse/0/hooks/0/command"),
            Some(&Value::String(pn_desired_native.clone()))
        );
        assert_eq!(
            pn_after_conflict.pointer("/tokenade/PreToolUse/0/hooks/0/timeout"),
            Some(&json!(10))
        );
        assert_eq!(
            pn_after_conflict.pointer("/tokenade/PreToolUse/0/hooks/1/command"),
            Some(&Value::String(pn_desired_native))
        );
        assert_eq!(
            pn_after_conflict.pointer("/tokenade/PreToolUse/0/hooks/1/timeout"),
            Some(&json!(30))
        );

        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let ren_race_file = tmp.0.join("cas-win-rename-race.json");
            fs::write(&ren_race_file, "{\"hook\":\"old\"}\n").unwrap();
            let no_delete_share = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(1 | 2)
                .open(&ren_race_file)
                .unwrap();
            let releaser = thread::spawn(move || {
                thread::sleep(Duration::from_millis(20));
                let mut f = no_delete_share;
                use std::io::Seek;
                f.set_len(0).unwrap();
                f.seek(std::io::SeekFrom::Start(0)).unwrap();
                f.write_all(b"{\"hook\":\"old\",\"saved_during_rename_retry\":true}\n")
                    .unwrap();
                drop(f);
            });
            let _ = cas_update_hooks_file(&ren_race_file, |raw| {
                let mut v: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
                v["hook"] = json!("new");
                Ok(Some((
                    format!("{}\n", serde_json::to_string_pretty(&v).unwrap()).into_bytes(),
                    (),
                )))
            })
            .unwrap();
            releaser.join().unwrap();
            let ren_after: Value =
                serde_json::from_str(&fs::read_to_string(&ren_race_file).unwrap()).unwrap();
            assert_eq!(ren_after["hook"], json!("new"));
            assert_eq!(ren_after["saved_during_rename_retry"], json!(true));
        }

        // INVARIANT: Write-ahead undo logging persists `migrations` + `post_install_sha256` BEFORE replacing `hooks.json` (so manifest write errors abort with both twin v1 hooks intact and `compensated_from_backup == true`), post-WAL `install_v1_quiesce` failures unambiguously restore identical-attribute twin hooks, and any `hooks_rollback_conflicts` during compensation sets `compensated_from_backup == false`.
        let cfg_wal = tmp.0.join("cfg-wal-twins");
        let shome_wal = tmp.0.join("shome-wal-twins");
        let wal_plug = cfg_wal.join("plugins").join(PLUGIN_NAME);
        fs::create_dir_all(wal_plug.join("hooks")).unwrap();
        fs::create_dir_all(wal_plug.join("rules")).unwrap();
        fs::write(wal_plug.join("plugin.json"), r#"{"name":"gemini-carbon-stack"}"#).unwrap();
        fs::write(wal_plug.join("rules").join("AGENTS.md"), "# legacy v1\n").unwrap();
        fs::write(wal_plug.join("hooks").join("hooks.json"), "{}").unwrap();
        fs::write(wal_plug.join("hooks").join("tokenade_hook.py"), "# legacy v1\n").unwrap();
        let wal_py_str = wal_plug
            .join("hooks")
            .join("tokenade_hook.py")
            .to_string_lossy()
            .replace('\\', "/");
        let twin_py_a = format!("python \"{}\"", wal_py_str);
        let twin_py_b = format!("python3 -X utf8 \"{}\" --event PreToolUse", wal_py_str);
        let twin_hooks_init = json!({
            "tokenade": {
                "PreToolUse": [{
                    "matcher": "run_command",
                    "hooks": [
                        {"type": "command", "timeout": 10, "command": twin_py_a},
                        {"type": "command", "timeout": 10, "command": twin_py_b}
                    ]
                }]
            }
        });
        fs::write(
            cfg_wal.join("hooks.json"),
            format!("{}\n", serde_json::to_string_pretty(&twin_hooks_init).unwrap()),
        )
        .unwrap();

        fs::create_dir_all(shome_wal.join("state")).unwrap();
        let wal_lease_path = rio::v2_lease_path(&shome_wal.join("state"));
        let wal_lease_fh = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&wal_lease_path)
            .unwrap();
        wal_lease_fh.try_lock_shared().unwrap();
        let shome_wal_bg = shome_wal.clone();
        let wal_done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let wal_done_bg = std::sync::Arc::clone(&wal_done);
        let wal_blocker = thread::spawn(move || {
            let mut locked_mf: Option<PathBuf> = None;
            #[cfg(windows)]
            let mut share_guard: Option<fs::File> = None;
            for _ in 0..400 {
                if let Ok(rd) = fs::read_dir(shome_wal_bg.join("backups")) {
                    for ent in rd.flatten() {
                        let cand = ent.path().join("manifest.json");
                        if cand.is_file() {
                            if let Ok(m) = fs::metadata(&cand) {
                                let mut p = m.permissions();
                                p.set_readonly(true);
                                let _ = fs::set_permissions(&cand, p);
                            }
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                let _ = fs::set_permissions(
                                    ent.path(),
                                    fs::Permissions::from_mode(0o500),
                                );
                            }
                            #[cfg(windows)]
                            {
                                use std::os::windows::fs::OpenOptionsExt;
                                share_guard = fs::OpenOptions::new()
                                    .read(true)
                                    .share_mode(1)
                                    .open(&cand)
                                    .ok();
                            }
                            locked_mf = Some(cand);
                            break;
                        }
                    }
                }
                if locked_mf.is_some() {
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
            drop(wal_lease_fh);
            while !wal_done_bg.load(std::sync::atomic::Ordering::Acquire) {
                thread::sleep(Duration::from_millis(5));
            }
            #[cfg(windows)]
            drop(share_guard);
            if let Some(mf) = locked_mf {
                #[cfg(unix)]
                if let Some(parent) = mf.parent() {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
                }
                if let Ok(m) = fs::metadata(&mf) {
                    let mut p = m.permissions();
                    p.set_readonly(false);
                    let _ = fs::set_permissions(&mf, p);
                }
            }
        });
        let wal_fail = perform_install_with_drain_timeout(
            &repo,
            &cfg_wal,
            &shome_wal,
            false,
            true,
            Duration::from_secs(5),
        );
        wal_done.store(true, std::sync::atomic::Ordering::Release);
        wal_blocker.join().unwrap();
        #[cfg(not(unix))]
        let enforce_wal_ro = true;
        #[cfg(unix)]
        let enforce_wal_ro = current_process_euid() != 0;
        if enforce_wal_ro {
            assert_eq!(wal_fail["ok"], false);
            assert_eq!(wal_fail["stage"], "migrate_global_hooks");
            assert_eq!(wal_fail["compensated_from_backup"], true);
            let after_wal_fail: Value =
                serde_json::from_str(&fs::read_to_string(cfg_wal.join("hooks.json")).unwrap())
                    .unwrap();
            assert_eq!(
                after_wal_fail.pointer("/tokenade/PreToolUse/0/hooks/0/command"),
                Some(&Value::String(twin_py_a.clone()))
            );
            assert_eq!(
                after_wal_fail.pointer("/tokenade/PreToolUse/0/hooks/1/command"),
                Some(&Value::String(twin_py_b.clone()))
            );
            assert!(wal_plug.join("hooks").join("tokenade_hook.py").is_file());
            assert!(!wal_plug.join("bin").exists());
        }

        fs::create_dir_all(shome_wal.join("state").join("chips")).unwrap();
        let wal_v1_lock = shome_wal.join("state").join("chips").join(".wal-v1.lock");
        fs::write(&wal_v1_lock, format!("{} 1795000000\n", std::process::id())).unwrap();
        let wal_post_quiesce = perform_install_with_drain_timeout(
            &repo,
            &cfg_wal,
            &shome_wal,
            false,
            true,
            Duration::from_millis(60),
        );
        assert_eq!(wal_post_quiesce["ok"], false);
        assert_eq!(wal_post_quiesce["stage"], "install_v1_quiesce");
        assert_eq!(wal_post_quiesce["compensated_from_backup"], true);
        let after_post_quiesce: Value =
            serde_json::from_str(&fs::read_to_string(cfg_wal.join("hooks.json")).unwrap()).unwrap();
        assert_eq!(
            after_post_quiesce.pointer("/tokenade/PreToolUse/0/hooks/0/command"),
            Some(&Value::String(twin_py_a.clone()))
        );
        assert_eq!(
            after_post_quiesce.pointer("/tokenade/PreToolUse/0/hooks/1/command"),
            Some(&Value::String(twin_py_b.clone()))
        );
        assert!(wal_plug.join("hooks").join("tokenade_hook.py").is_file());

        let wal_hooks_bg = cfg_wal.join("hooks.json");
        let conflict_injected = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let conflict_injected_bg = std::sync::Arc::clone(&conflict_injected);
        let conflict_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let conflict_stop_bg = std::sync::Arc::clone(&conflict_stop);
        let conflict_writer = thread::spawn(move || {
            while !conflict_stop_bg.load(std::sync::atomic::Ordering::Acquire) {
                if let Ok(raw) = fs::read_to_string(&wal_hooks_bg) {
                    if raw.contains("tokenade-hook") {
                        if let Ok(mut v) = serde_json::from_str::<Value>(&raw) {
                            if let Some(slot) =
                                v.pointer_mut("/tokenade/PreToolUse/0/hooks/0/command")
                            {
                                *slot = Value::String("user-override-during-quiesce".to_string());
                                let _ = fs::write(
                                    &wal_hooks_bg,
                                    format!("{}\n", serde_json::to_string_pretty(&v).unwrap()),
                                );
                                conflict_injected_bg
                                    .store(true, std::sync::atomic::Ordering::Release);
                                break;
                            }
                        }
                    }
                }
                thread::sleep(Duration::from_millis(2));
            }
        });
        let wal_conflict_comp = perform_install_with_drain_timeout(
            &repo,
            &cfg_wal,
            &shome_wal,
            false,
            true,
            Duration::from_millis(800),
        );
        conflict_stop.store(true, std::sync::atomic::Ordering::Release);
        conflict_writer.join().unwrap();
        assert!(conflict_injected.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(wal_conflict_comp["ok"], false);
        assert_eq!(wal_conflict_comp["stage"], "install_v1_quiesce");
        assert_eq!(wal_conflict_comp["compensated_from_backup"], false);
        let after_conflict_comp: Value =
            serde_json::from_str(&fs::read_to_string(cfg_wal.join("hooks.json")).unwrap()).unwrap();
        assert_eq!(
            after_conflict_comp.pointer("/tokenade/PreToolUse/0/hooks/0/command"),
            Some(&json!("user-override-during-quiesce"))
        );
        let _ = fs::remove_file(&wal_v1_lock);

        // INVARIANT: If `<config_dir>/hooks.json` did not exist before install and the user creates it after install, `--rollback` never deletes or touches it.
        let cfg_new_hk = tmp.0.join("cfg-new-user-hooks");
        let shome_new_hk = tmp.0.join("shome-new-user-hooks");
        assert_eq!(
            perform_install(&repo, &cfg_new_hk, &shome_new_hk, false, true)["ok"],
            true
        );
        let user_created_hooks = "{\"my-own-hook\": {\"Stop\": [{\"type\": \"command\", \"command\": \"keep-me\"}]}}\n";
        fs::write(cfg_new_hk.join("hooks.json"), user_created_hooks).unwrap();
        assert_eq!(
            perform_rollback(&cfg_new_hk, &shome_new_hk, "latest")["ok"],
            true
        );
        assert_eq!(
            fs::read_to_string(cfg_new_hk.join("hooks.json")).unwrap(),
            user_created_hooks
        );

        // INVARIANT: Foreign scripts named `tokenade_hook.py`, compound shell pipelines, AND Carbon Stack paths belonging to a DIFFERENT profile (`cfg_other_profile`) are never rewritten.
        let default_home_cfg = rio::home_dir().join(".gemini").join("config");
        let default_home_plug = default_home_cfg.join("plugins").join(PLUGIN_NAME);
        let home_scope = HookInstanceScope {
            config_dir: &default_home_cfg,
            target_plugin_dir: &default_home_plug,
            is_windows: false,
        };
        assert!(!is_managed_carbon_tokenade_command_in_scope(
            "python /профиль/plugins/gemini-carbon-stack/hooks/tokenade_hook.py",
            home_scope,
        ));
        assert!(!is_managed_carbon_tokenade_command_in_scope(
            "python /Users/me/custom-tools/tokenade_hook.py",
            home_scope,
        ));
        assert!(!is_managed_carbon_tokenade_command_in_scope(
            "my-wrapper && python ~/.gemini/config/plugins/gemini-carbon-stack/hooks/tokenade_hook.py",
            home_scope,
        ));
        assert!(is_managed_carbon_tokenade_command_in_scope(
            "python3 -X utf8 \"~/.gemini/config/plugins/gemini-carbon-stack/hooks/tokenade_hook.py\" --event PreToolUse",
            home_scope,
        ));
        let cfg_foreign_hk = tmp.0.join("cfg-foreign-tok");
        let cfg_other_profile = tmp.0.join("cfg-other-profile");
        fs::create_dir_all(&cfg_foreign_hk).unwrap();
        let other_profile_py = cfg_other_profile
            .join("plugins")
            .join(PLUGIN_NAME)
            .join("hooks")
            .join("tokenade_hook.py")
            .to_string_lossy()
            .replace('\\', "/");
        let foreign_hooks_raw = serde_json::to_string_pretty(&json!({
            "tokenade": {
                "PreToolUse": [
                    {"matcher": "run_command", "hooks": [{"type": "command", "command": "python /opt/custom/tokenade_hook.py"}]},
                    {"matcher": "run_command", "hooks": [{"type": "command", "command": format!("python \"{}\"", other_profile_py)}]},
                    {"matcher": "run_command", "hooks": [{"type": "command", "command": "python ~/.gemini/config/plugins/gemini-carbon-stack/hooks/tokenade_hook.py"}]}
                ]
            }
        }))
        .unwrap();
        fs::write(cfg_foreign_hk.join("hooks.json"), foreign_hooks_raw).unwrap();
        assert!(inspect_global_hooks_migration(
            &cfg_foreign_hk,
            &cfg_foreign_hk.join("plugins").join(PLUGIN_NAME),
            false,
        )
        .unwrap()
        .is_none());

        // INVARIANT: Owner-non-executable `0650` is rejected (`mode_is_owner_executable == false`), repaired to `0750` without widening `other`, and private `0600` repairs to `0700`.
        assert!(!mode_is_owner_executable(0o650));
        assert!(mode_is_owner_executable(0o750));
        assert_eq!(ensure_owner_exec_mode_bits(0o650), 0o750);
        assert_eq!(ensure_owner_exec_mode_bits(0o600), 0o700);
        assert_eq!(ensure_owner_exec_mode_bits(0o644), 0o755);
        assert!(!posix_dac_mode_allows_exec(0o650, 1000, 1000, 1000, &[1000]));
        assert!(!posix_dac_mode_allows_exec(0o650, 1000, 1000, 0, &[0]));
        assert!(!posix_dac_mode_allows_exec(0o700, 0, 0, 1000, &[1000]));
        assert!(posix_dac_mode_allows_exec(0o750, 0, 50, 1000, &[1000, 50]));
        assert!(!posix_dac_mode_allows_exec(0o750, 0, 50, 1000, &[1000]));
        assert!(!posix_dac_mode_allows_exec(0o705, 0, 50, 1000, &[1000, 50]));
        assert!(posix_dac_mode_allows_exec(0o755, 0, 0, 1000, &[1000]));

        // INVARIANT: `--rollback latest` acquires `_inst_mutex` BEFORE selecting the latest backup, so if an upgrade `B -> C` already holds `_inst_mutex` when `--rollback latest` starts, rollback waits and restores `B` rather than stale `A`.
        let cfg_race = tmp.0.join("cfg-rb-latest-race");
        let shome_race = tmp.0.join("shome-rb-latest-race");
        fs::write(repo.join("plugin").join("rules").join("AGENTS.md"), "# Version B\n").unwrap();
        assert_eq!(
            perform_install(&repo, &cfg_race, &shome_race, false, true)["ok"],
            true
        );
        fs::write(repo.join("plugin").join("rules").join("AGENTS.md"), "# Version C\n").unwrap();
        let held_guard =
            acquire_installer_mutex(&cfg_race, &shome_race, Duration::from_secs(5)).unwrap();
        let cfg_rb_bg = cfg_race.clone();
        let shome_rb_bg = shome_race.clone();
        let rb_handle = thread::spawn(move || {
            perform_rollback_with_drain_timeout(
                &cfg_rb_bg,
                &shome_rb_bg,
                "latest",
                Duration::from_secs(5),
            )
        });
        thread::sleep(Duration::from_millis(60));
        // INVARIANT: Simulate `B -> C` completing its backup `B` and writing `C` right before releasing `_inst_mutex`.
        create_backup(&cfg_race, &shome_race).unwrap();
        fs::write(
            cfg_race
                .join("plugins")
                .join(PLUGIN_NAME)
                .join("rules")
                .join("AGENTS.md"),
            "# Version C\n",
        )
        .unwrap();
        drop(held_guard);
        let race_rb_res = rb_handle.join().unwrap();
        assert_eq!(race_rb_res["ok"], true);
        assert_eq!(
            fs::read_to_string(
                cfg_race
                    .join("plugins")
                    .join(PLUGIN_NAME)
                    .join("rules")
                    .join("AGENTS.md")
            )
            .unwrap(),
            "# Version B\n"
        );

        #[cfg(windows)]
        {
            // INVARIANT: If Step 2 of rollback fails after Step 1 restored `v1`, and an active `v1` lock/process is still running, `compensate_plugin_rollback` refuses to clear `.lock_epoch` and reports `compensated_plugin_restore: false` + `restore_error`.
            use std::os::windows::fs::OpenOptionsExt;
            let cfg_rc = tmp.0.join("cfg-rb-comp-v1");
            let shome_rc = tmp.0.join("shome-rb-comp-v1");
            assert_eq!(
                perform_install(&repo, &cfg_rc, &shome_rc, false, true)["ok"],
                true
            );
            let active_v1_during_rb = shome_rc.join("state").join("chips").join(".rb-v1.lock");
            fs::write(
                &active_v1_during_rb,
                format!("{} 1795000000\n", std::process::id()),
            )
            .unwrap();
            let locked_r = cfg_rc.join("rules").join("uiux-design.md");
            let r_guard = fs::OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(&locked_r)
                .unwrap();
            let rc_res = perform_rollback_with_drain_timeout(
                &cfg_rc,
                &shome_rc,
                "latest",
                Duration::from_millis(60),
            );
            drop(r_guard);
            let _ = fs::remove_file(&active_v1_during_rb);
            assert_eq!(rc_res["ok"], false);
            assert_eq!(rc_res["stage"], "rollback_rule_remove");
            assert_eq!(rc_res["compensated_plugin_restore"], false);
            assert!(rc_res["restore_error"].as_str().is_some());
            assert_eq!(
                fs::read_to_string(rio::lock_epoch_path(&shome_rc.join("state")))
                    .unwrap()
                    .trim(),
                "v1"
            );
        }
    }
}
