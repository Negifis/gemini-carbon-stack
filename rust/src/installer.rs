use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
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
const MAX_INSTALL_BACKUPS: usize = 10;
const STAGE_RETIRE_PREFIX: &str = ".carbon-stack-stage-retire-";
const STAGE_RETIRE_LOCK_NAME: &str = "active.lock";
const STAGE_RETIRE_JOURNAL_NAME: &str = "retire-journal.json";
const HOOKS_SENTINEL_BYTES: &[u8] = b"{}\n";

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
    path.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir))
}

fn stage_err(stage: &str, msg: impl AsRef<str>) -> Value {
    json!({ "ok": false, "stage": stage, "error": msg.as_ref() })
}

fn tree_manifest_inner(root: &Path, strict: bool, hash: bool) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    if !root.is_dir() {
        return if strict { Err(format!("Directory does not exist: {}", root.display())) } else { Ok(out) };
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = match fs::read_dir(&dir) {
            Ok(r) => r,
            Err(e) if strict => return Err(format!("{}: {}", dir.display(), e)),
            Err(_) => continue,
        };
        let (mut subdirs, mut files) = (Vec::new(), Vec::new());
        for entry_res in rd {
            let entry = match entry_res {
                Ok(ent) => ent,
                Err(e) if strict => return Err(format!("{}: {}", dir.display(), e)),
                Err(_) => continue,
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            if SKIP_NAMES.contains(&name.as_str()) || name.ends_with(".pyc") || name.ends_with(".pyo") {
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
        stack.extend(subdirs.into_iter().rev());
        files.sort_by(|a, b| a.0.cmp(&b.0));
        for (_, fpath) in files {
            let rel = fpath.strip_prefix(root).map_err(|e| e.to_string())?.to_string_lossy().replace('\\', "/");
            if !hash {
                out.insert(rel, String::new());
            } else {
                match sha256_file_full(&fpath) {
                    Ok(h) => {
                        out.insert(rel, h);
                    }
                    Err(e) if strict => return Err(e),
                    Err(_) => {}
                }
            }
        }
    }
    Ok(out)
}

fn tree_rel_paths(root: &Path) -> BTreeSet<String> {
    tree_manifest_inner(root, false, false).unwrap_or_default().into_keys().collect()
}

fn tree_manifest(root: &Path) -> BTreeMap<String, String> {
    tree_manifest_inner(root, false, true).unwrap_or_default()
}

fn tree_manifest_strict(root: &Path) -> Result<BTreeMap<String, String>, String> {
    tree_manifest_inner(root, true, true)
}

fn resolve_repo_root(explicit_repo: &str) -> PathBuf {
    if !explicit_repo.trim().is_empty() {
        return rio::resolve_abs_path(Path::new(explicit_repo.trim()));
    }
    let has_layout = |d: &Path| d.join("plugin").join("plugin.json").is_file() && d.join("rules").join("uiux-design.md").is_file();
    for start in [env::current_dir().ok(), env::current_exe().ok()].into_iter().flatten() {
        if let Some(anc) = start.ancestors().find(|&a| has_layout(a)) {
            return rio::resolve_abs_path(anc);
        }
    }
    if let Some(repo) = option_env!("CARGO_MANIFEST_DIR").and_then(|d| Path::new(d).parent()).filter(|&r| has_layout(r)) {
        return rio::resolve_abs_path(repo);
    }
    rio::resolve_abs_path(Path::new("."))
}

fn resolve_paths(config_dir_arg: &str, stack_home_arg: &str) -> (PathBuf, PathBuf) {
    let cfg = if !config_dir_arg.trim().is_empty() {
        rio::resolve_abs_path(Path::new(config_dir_arg.trim()))
    } else {
        rio::home_dir().join(".gemini").join("config")
    };
    let shome = if !stack_home_arg.trim().is_empty() {
        rio::resolve_abs_path(Path::new(stack_home_arg.trim()))
    } else if let Some(s) = env::var("CARBON_STACK_HOME").ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty()) {
        rio::resolve_abs_path(Path::new(&s))
    } else {
        rio::home_dir().join(".gemini").join("carbon-stack")
    };
    (cfg, shome)
}

fn platform_hook_binary_rel(is_windows: bool) -> &'static str {
    if is_windows { "bin/carbon-stack.exe" } else { "bin/carbon-stack" }
}

fn normalize_hooks_json_for_os(txt: &str, is_windows: bool) -> String {
    if is_windows {
        txt.replace("bin/carbon-stack.exe", "bin\\carbon-stack.exe")
            .replace("bin/carbon-stack hook", "bin\\carbon-stack.exe hook")
    } else {
        txt.replace("bin\\\\carbon-stack.exe", "bin/carbon-stack")
            .replace("bin\\carbon-stack.exe", "bin/carbon-stack")
            .replace("bin/carbon-stack.exe", "bin/carbon-stack")
    }
}

fn format_target_hook_binary(target_plugin_dir: &Path, is_windows: bool) -> String {
    let raw = rio::resolve_abs_path(&target_plugin_dir.join(platform_hook_binary_rel(is_windows)))
        .to_string_lossy()
        .into_owned();
    let full = if is_windows { raw.replace('/', "\\") } else { raw.replace('\\', "/") };
    if full.chars().any(|c| c.is_whitespace() || matches!(c, '&' | '(' | ')' | '\'' | ';' | '^' | '%')) {
        format!("\"{}\"", full)
    } else {
        full
    }
}

fn rewrite_relative_carbon_bin_cmd(cmd: &str, replacement_bin: &str) -> Option<String> {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (tok, rest) = if let Some(after_q) = trimmed.strip_prefix('"') {
        let end = after_q.find('"')?;
        (&after_q[..end], &after_q[end + 1..])
    } else if let Some(after_q) = trimmed.strip_prefix('\'') {
        let end = after_q.find('\'')?;
        (&after_q[..end], &after_q[end + 1..])
    } else {
        let end = trimmed.char_indices().find(|(_, c)| c.is_whitespace()).map_or(trimmed.len(), |(i, _)| i);
        (&trimmed[..end], &trimmed[end..])
    };
    let norm = tok.replace('\\', "/").to_ascii_lowercase();
    (norm == "bin/carbon-stack.exe" || norm == "bin/carbon-stack").then(|| format!("{}{}", replacement_bin, rest))
}

fn rewrite_hooks_json_commands_rec(val: &mut Value, replacement_bin: &str) {
    match val {
        Value::Object(map) => {
            if let Some(Value::String(cmd)) = map.get_mut("command") {
                if let Some(rewritten) = rewrite_relative_carbon_bin_cmd(cmd, replacement_bin) {
                    *cmd = rewritten;
                }
            }
            for (k, child) in map.iter_mut() {
                if k != "command" {
                    rewrite_hooks_json_commands_rec(child, replacement_bin);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|it| rewrite_hooks_json_commands_rec(it, replacement_bin)),
        _ => {}
    }
}

fn materialize_hooks_json_for_target(txt: &str, target_plugin_dir: Option<&Path>, is_windows: bool) -> String {
    if !is_windows {
        return normalize_hooks_json_for_os(txt, false);
    }
    let Some(dst_dir) = target_plugin_dir else {
        return normalize_hooks_json_for_os(txt, true);
    };
    let Ok(mut parsed) = serde_json::from_str::<Value>(txt) else {
        return normalize_hooks_json_for_os(txt, true);
    };
    rewrite_hooks_json_commands_rec(&mut parsed, &format_target_hook_binary(dst_dir, true));
    serde_json::to_string_pretty(&parsed)
        .map(|s| format!("{}\n", s))
        .unwrap_or_else(|_| normalize_hooks_json_for_os(txt, true))
}

fn effective_source_manifest_strict_for_target(
    src_plugin_dir: &Path,
    target_plugin_dir: Option<&Path>,
    is_windows: bool,
) -> Result<BTreeMap<String, String>, String> {
    let mut map = tree_manifest_strict(src_plugin_dir)?;
    if !is_windows && map.contains_key("bin/carbon-stack") {
        map.remove("bin/carbon-stack.exe");
    }
    if (!is_windows || target_plugin_dir.is_some()) && map.contains_key("hooks.json") {
        let hooks_file = src_plugin_dir.join("hooks.json");
        let raw = fs::read_to_string(&hooks_file).map_err(|e| format!("{}: {}", hooks_file.display(), e))?;
        let norm = materialize_hooks_json_for_target(&raw, target_plugin_dir, is_windows);
        map.insert("hooks.json".to_string(), rio::sha256_hex(norm.as_bytes()));
    }
    Ok(map)
}

fn effective_source_manifest_for_target(
    src_plugin_dir: &Path,
    target_plugin_dir: Option<&Path>,
    is_windows: bool,
) -> BTreeMap<String, String> {
    effective_source_manifest_strict_for_target(src_plugin_dir, target_plugin_dir, is_windows).unwrap_or_default()
}

fn collect_links_under_tree(root: &Path, out: &mut Vec<PathBuf>) {
    if win32_sqlite::is_link_or_junction(root) {
        out.push(root.to_path_buf());
        return;
    }
    if let Ok(rd) = fs::read_dir(root) {
        for p in rd.flatten().map(|e| e.path()) {
            if win32_sqlite::is_link_or_junction(&p) {
                out.push(p);
            } else if p.is_dir() {
                collect_links_under_tree(&p, out);
            }
        }
    }
}

fn ensure_no_links_between(base: &Path, target: &Path) -> Result<(), String> {
    // INVARIANT: Reject `.`/`..` traversal, equal-root targets, and any symlink/junction between `base` and `target`.
    if has_dot_components(base) || has_dot_components(target) {
        return Err(format!("Refusing dot/parent traversal: {} -> {}", base.display(), target.display()));
    }
    if win32_sqlite::is_link_or_junction(base) {
        return Err(format!("Refusing symlink/junction root: {}", base.display()));
    }
    let rel = target.strip_prefix(base).map_err(|_| format!("Target {} escapes base {}", target.display(), base.display()))?;
    let (mut cur, mut depth) = (base.to_path_buf(), 0usize);
    for comp in rel.components() {
        let Component::Normal(_) = comp else {
            return Err(format!("Refusing non-normal path component under {}: {}", base.display(), target.display()));
        };
        depth += 1;
        cur.push(comp);
        if win32_sqlite::is_link_or_junction(&cur) {
            return Err(format!("Refusing nested symlink/junction component: {}", cur.display()));
        }
    }
    if depth == 0 {
        return Err(format!("Target {} must be a strict child inside {}", target.display(), base.display()));
    }
    Ok(())
}

fn validate_target_hierarchy(config_dir: &Path, p_target: &Path, r_target: &Path) -> Vec<String> {
    let mut errs = Vec::new();
    for t in [p_target, r_target, &config_dir.join("hooks.json")] {
        if let Err(e) = ensure_no_links_between(config_dir, t) {
            errs.push(e);
        }
    }
    let mut nested = Vec::new();
    if p_target.exists() || win32_sqlite::is_link_or_junction(p_target) {
        collect_links_under_tree(p_target, &mut nested);
    }
    errs.extend(nested.into_iter().map(|l| format!("Refusing nested symlink/junction: {}", l.display())));
    errs
}

fn validate_target_entry_types(
    config_dir: &Path,
    p_target: &Path,
    r_target: &Path,
    src_plugin_dir: Option<&Path>,
    is_windows: bool,
) -> Vec<String> {
    let mut errs = Vec::new();
    let check_dir = |p: &Path, label: &str, out: &mut Vec<String>| -> bool {
        if fs::symlink_metadata(p).is_ok_and(|m| !m.file_type().is_dir()) {
            out.push(format!("{} is not a directory: {}", label, p.display()));
            return false;
        }
        true
    };
    let check_file = |p: &Path, label: &str, out: &mut Vec<String>| {
        if fs::symlink_metadata(p).is_ok_and(|m| !m.file_type().is_file()) {
            out.push(format!("{} is not a regular file: {}", label, p.display()));
        }
    };
    if !check_dir(config_dir, "Target config root", &mut errs) {
        return errs;
    }
    check_file(&config_dir.join("hooks.json"), "Target global hooks.json", &mut errs);
    for (p, lbl) in [(p_target.parent(), "Target plugins parent"), (Some(p_target), "Target plugin path"), (r_target.parent(), "Target rules parent")] {
        if let Some(dir) = p {
            check_dir(dir, lbl, &mut errs);
        }
    }
    check_file(r_target, "Target rule path", &mut errs);
    if let Some(src_dir) = src_plugin_dir.filter(|_| p_target.is_dir()) {
        for rel in effective_source_manifest_for_target(src_dir, None, is_windows).keys() {
            if let Some(rel_parent) = Path::new(rel).parent() {
                let mut cur = p_target.to_path_buf();
                for comp in rel_parent.components() {
                    cur.push(comp);
                    if !check_dir(&cur, "Target plugin subdir", &mut errs) {
                        break;
                    }
                }
            }
            check_file(&p_target.join(rel), "Target plugin file", &mut errs);
        }
    }
    errs
}

pub(crate) fn has_mz_header(path: &Path) -> bool {
    let mut buf = [0u8; 2];
    fs::File::open(path).and_then(|mut f| f.read_exact(&mut buf)).is_ok_and(|()| &buf == b"MZ")
}

fn has_elf_header(path: &Path) -> bool {
    let mut buf = [0u8; 4];
    fs::File::open(path).and_then(|mut f| f.read_exact(&mut buf)).is_ok_and(|()| &buf == b"\x7fELF")
}

pub(crate) fn run_agy_plugin_validate(agy_bin: &str, plugin_dir: &Path, timeout_ms: u64) -> (bool, String) {
    let args = vec!["plugin".to_string(), "validate".to_string(), plugin_dir.to_string_lossy().into_owned()];
    match win32_sqlite::run_command_with_job(agy_bin, &args, None, &[], None, Some(timeout_ms)) {
        Ok(res) if res.timed_out => (false, format!("`agy plugin validate` timed out after {:.1}s", (timeout_ms as f64) / 1000.0)),
        Ok(res) => (res.code == 0, format!("{}\n{}", res.stdout_str(), res.stderr_str()).trim().to_string()),
        Err(e) => (false, format!("failed to launch `agy plugin validate`: {}", e)),
    }
}

#[cfg(any(unix, test))]
fn mode_is_owner_executable(mode: u32) -> bool {
    (mode & 0o100) != 0
}

#[cfg(any(unix, test))]
fn ensure_owner_exec_mode_bits(mode: u32) -> u32 {
    mode | 0o100 | ((mode & 0o044) >> 2)
}

#[cfg(any(unix, test))]
fn posix_dac_mode_allows_exec(mode: u32, file_uid: u32, file_gid: u32, caller_euid: u32, caller_groups: &[u32]) -> bool {
    if !mode_is_owner_executable(mode) {
        return false;
    }
    if caller_euid == 0 || caller_euid == file_uid {
        return true;
    }
    if caller_groups.contains(&file_gid) { (mode & 0o010) != 0 } else { (mode & 0o001) != 0 }
}

#[cfg(unix)]
fn current_unix_euid_and_groups() -> (u32, Vec<u32>) {
    extern "C" {
        fn geteuid() -> u32;
        fn getegid() -> u32;
        fn getgroups(size: std::os::raw::c_int, list: *mut u32) -> std::os::raw::c_int;
    }
    // SAFETY: `geteuid()` and `getegid()` are thread-safe POSIX syscalls with no pointer arguments.
    let (euid, egid) = unsafe { (geteuid(), getegid()) };
    let mut groups = vec![egid];
    // SAFETY: `(0, null_mut())` queries supplementary group count without dereferencing memory.
    let count = unsafe { getgroups(0, std::ptr::null_mut()) };
    if count > 0 {
        let mut sup = vec![0u32; count as usize];
        // SAFETY: `sup` has `count` elements matching the length passed to `getgroups`.
        let got = unsafe { getgroups(count, sup.as_mut_ptr()) };
        if got > 0 {
            for &g in &sup[..got as usize] {
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
        let Ok(m) = fs::metadata(path) else { return false };
        if !m.is_file() { return false; }
        let (euid, groups) = current_unix_euid_and_groups();
        posix_dac_mode_allows_exec(m.permissions().mode(), m.uid(), m.gid(), euid, &groups)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

fn has_executable_hook_mode_for_os(plugin_dir: &Path, is_windows: bool) -> bool {
    is_windows || is_posix_executable_file(&plugin_dir.join("bin").join("carbon-stack"))
}

fn norm_instance_path(tok: &str, case_fold: bool) -> String {
    let mut out = String::with_capacity(tok.len());
    let mut prev_slash = false;
    for ch in tok.chars() {
        if ch == '\\' || ch == '/' {
            if !prev_slash { out.push('/'); }
            prev_slash = true;
        } else {
            if case_fold { out.extend(ch.to_lowercase()); } else { out.push(ch); }
            prev_slash = false;
        }
    }
    while out.len() > 1 && out.ends_with('/') { out.pop(); }
    out
}

fn expand_home_prefix(raw: &str, home: &str, is_windows: bool) -> String {
    let s = raw.replace('\\', "/");
    if home.is_empty() { return s; }
    let ht = home.trim_end_matches('/');
    if matches!(s.as_str(), "~" | "$HOME" | "${HOME}") || (is_windows && s.eq_ignore_ascii_case("%userprofile%")) { return ht.to_string(); }
    for p in ["~/", "$HOME/", "${HOME}/"] { if let Some(r) = s.strip_prefix(p) { return format!("{}/{}", ht, r); } }
    if is_windows && s.get(..14).is_some_and(|p| p.eq_ignore_ascii_case("%userprofile%/")) { return format!("{}/{}", ht, &s[14..]); }
    s
}

fn matches_target_plugin_subpath(raw_tok: &str, config_dir: &Path, target_plugin_dir: &Path, is_windows: bool, rel_subpath: &str) -> bool {
    let home = rio::home_dir().to_string_lossy().replace('\\', "/");
    let expanded = expand_home_prefix(raw_tok, &home, is_windows);
    let trimmed = expanded.strip_prefix("./").unwrap_or(&expanded);
    if trimmed.is_empty() || has_dot_components(Path::new(trimmed)) { return false; }
    let has_drive = trimmed.as_bytes().get(1) == Some(&b':') && trimmed.as_bytes()[0].is_ascii_alphabetic();
    let candidate = if has_drive || trimmed.starts_with(['/', '~', '$', '%']) { PathBuf::from(trimmed) } else { config_dir.join(trimmed) };
    norm_instance_path(&candidate.to_string_lossy(), is_windows) == norm_instance_path(&target_plugin_dir.join(rel_subpath).to_string_lossy(), is_windows)
}

fn split_simple_hook_tokens(cmd: &str) -> Option<Vec<String>> {
    let trimmed = cmd.trim();
    if trimmed.is_empty() || trimmed.contains(['\n', '\r', '\0', '`']) || trimmed.contains("$(") {
        return None;
    }
    let (mut out, mut cur, mut has_tok, mut in_sq, mut in_dq) = (Vec::new(), String::new(), false, false, false);
    let mut chars = trimmed.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\'' if in_sq => in_sq = false,
            _ if in_sq => cur.push(ch),
            '"' if in_dq => in_dq = false,
            '\\' if in_dq && chars.peek() == Some(&'"') => { let _ = chars.next(); cur.push('"'); }
            _ if in_dq => cur.push(ch),
            c if c.is_whitespace() => { if has_tok { out.push(std::mem::take(&mut cur)); has_tok = false; } }
            ';' | '&' | '|' | '>' | '<' => return None,
            '\'' => { in_sq = true; has_tok = true; }
            '"' => { in_dq = true; has_tok = true; }
            _ => { cur.push(ch); has_tok = true; }
        }
    }
    if in_sq || in_dq { return None; }
    if has_tok { out.push(cur); }
    (!out.is_empty()).then_some(out)
}

fn unwrap_single_shell_wrapper(tokens: &[String]) -> Option<&str> {
    let base = norm_instance_path(&tokens[0], true);
    let base = base.rsplit('/').next().unwrap_or(&base);
    let mut i = 1usize;
    if matches!(base, "sh" | "bash" | "dash" | "zsh" | "ash" | "ksh" | "sh.exe" | "bash.exe") {
        while tokens.get(i).is_some_and(|f| matches!(f.as_str(), "-l" | "-e" | "-u" | "-f" | "--login")) { i += 1; }
        return (tokens.get(i).is_some_and(|f| matches!(f.as_str(), "-c" | "-lc" | "-ec" | "-ce")) && i + 2 == tokens.len()).then(|| tokens[i + 1].as_str());
    }
    if matches!(base, "cmd" | "cmd.exe") {
        while tokens.get(i).is_some_and(|f| matches!(f.to_ascii_lowercase().as_str(), "/d" | "/q" | "/s" | "/a" | "/u")) { i += 1; }
        return (tokens.get(i).is_some_and(|f| f.eq_ignore_ascii_case("/c")) && i + 2 == tokens.len()).then(|| tokens[i + 1].as_str());
    }
    if matches!(base, "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe") {
        while let Some(f) = tokens.get(i).map(|s| s.to_ascii_lowercase()) {
            if matches!(f.as_str(), "-noprofile" | "-noninteractive" | "-nologo" | "-nop") { i += 1; }
            else if matches!(f.as_str(), "-executionpolicy" | "-ep") && i + 1 < tokens.len() { i += 2; }
            else { break; }
        }
        return (tokens.get(i).is_some_and(|f| matches!(f.to_ascii_lowercase().as_str(), "-command" | "-c")) && i + 2 == tokens.len()).then(|| tokens[i + 1].as_str());
    }
    None
}

fn is_legacy_managed_tokenade_command(cmd: &str, config_dir: &Path, target_plugin_dir: &Path, is_windows: bool) -> bool {
    is_legacy_managed_tokenade_command_depth(cmd, config_dir, target_plugin_dir, is_windows, 0)
}

fn strip_ps_single_call_prefix(cmd: &str) -> &str {
    let mut s = cmd.trim();
    if let Some(rest) = s.get(..5).filter(|p| p.eq_ignore_ascii_case("$null")).map(|_| s[5..].trim_start()) {
        if let Some(after_pipe) = rest.strip_prefix('|') { s = after_pipe.trim_start(); }
    }
    if let Some(after_amp) = s.strip_prefix('&') {
        if after_amp.chars().next().is_some_and(char::is_whitespace) { return after_amp.trim_start(); }
    }
    s
}

fn is_legacy_managed_tokenade_command_depth(cmd: &str, config_dir: &Path, target_plugin_dir: &Path, is_windows: bool, depth: u8) -> bool {
    let Some(tokens) = split_simple_hook_tokens(strip_ps_single_call_prefix(cmd)) else { return false };
    if depth < 2 {
        if let Some(inner) = unwrap_single_shell_wrapper(&tokens) {
            return is_legacy_managed_tokenade_command_depth(inner, config_dir, target_plugin_dir, is_windows, depth + 1);
        }
    }
    if tokens.len() >= 2 && (tokens[1] == "tokenade-hook" || (is_windows && tokens[1].eq_ignore_ascii_case("tokenade-hook"))) {
        let bin_norm = norm_instance_path(&tokens[0], is_windows);
        if matches_target_plugin_subpath(&tokens[0], config_dir, target_plugin_dir, is_windows, "bin/carbon-stack")
            || matches_target_plugin_subpath(&tokens[0], config_dir, target_plugin_dir, is_windows, "bin/carbon-stack.exe")
            || matches!(bin_norm.trim_start_matches("./"), "carbon-stack" | "carbon-stack.exe" | "bin/carbon-stack" | "bin/carbon-stack.exe")
        {
            return true;
        }
    }
    let first_norm = norm_instance_path(&tokens[0], true);
    let first_base = first_norm.rsplit('/').next().unwrap_or(&first_norm);
    let is_py = matches!(first_base, "python" | "python3" | "python.exe" | "python3.exe" | "py" | "py.exe")
        || first_base
            .strip_prefix("python3.")
            .map(|r| r.strip_suffix(".exe").unwrap_or(r))
            .is_some_and(|r| !r.is_empty() && r.chars().all(|c| c.is_ascii_digit()));
    let mut idx = usize::from(is_py);
    if is_py {
        while let Some(f) = tokens.get(idx).map(String::as_str) {
            if matches!(f, "-3" | "-u" | "-B" | "-E" | "-s" | "-S") || (f.starts_with("-X") && f.len() > 2) {
                idx += 1;
            } else if f == "-X" && idx + 1 < tokens.len() {
                idx += 2;
            } else {
                break;
            }
        }
    }
    let Some(script_tok) = tokens.get(idx) else { return false };
    let script_ok = matches_target_plugin_subpath(script_tok, config_dir, target_plugin_dir, is_windows, "hooks/tokenade_hook.py")
        || norm_instance_path(script_tok, is_windows).trim_start_matches("./") == "hooks/tokenade_hook.py";
    script_ok
        && match &tokens[idx + 1..] {
            [] => true,
            [flag] => flag.starts_with("--event="),
            [flag, _] => flag == "--event",
            _ => false,
        }
}

fn prune_hook_array(arr: &mut Vec<Value>, config_dir: &Path, target_plugin_dir: &Path, is_windows: bool) -> usize {
    let mut pruned = 0usize;
    arr.retain_mut(|entry| {
        let Some(obj) = entry.as_object_mut() else { return true };
        if obj.get("command").and_then(Value::as_str).is_some_and(|c| {
            is_legacy_managed_tokenade_command(c, config_dir, target_plugin_dir, is_windows)
        }) {
            pruned += 1;
            return false;
        }
        if let Some(Value::Array(nested)) = obj.get_mut("hooks") {
            let sub = prune_hook_array(nested, config_dir, target_plugin_dir, is_windows);
            pruned += sub;
            if sub > 0 && nested.is_empty() {
                return false;
            }
        }
        true
    });
    pruned
}

fn prune_managed_tokenade_entries(root: &mut Value, config_dir: &Path, target_plugin_dir: &Path, is_windows: bool) -> usize {
    // INVARIANT: Prune ONLY lingering `hooks/tokenade_hook.py` or `carbon-stack tokenade-hook` entries and containers emptied strictly by pruning, leaving unrelated user hooks untouched.
    let Some(root_map) = root.as_object_mut() else { return 0 };
    let mut total = 0usize;
    for key in root_map.keys().cloned().collect::<Vec<_>>() {
        let drop_key = match root_map.get_mut(&key) {
            Some(Value::Array(arr)) => {
                let p = prune_hook_array(arr, config_dir, target_plugin_dir, is_windows);
                total += p;
                p > 0 && arr.is_empty()
            }
            Some(Value::Object(grp)) => {
                let mut gp = 0usize;
                for ev in grp.keys().cloned().collect::<Vec<_>>() {
                    if grp.get_mut(&ev).and_then(Value::as_array_mut).is_some_and(|arr| {
                        let p = prune_hook_array(arr, config_dir, target_plugin_dir, is_windows);
                        gp += p;
                        p > 0 && arr.is_empty()
                    }) {
                        grp.remove(&ev);
                    }
                }
                total += gp;
                gp > 0 && !grp.values().any(Value::is_array)
            }
            _ => false,
        };
        if drop_key {
            root_map.remove(&key);
        }
    }
    total
}

fn collect_hook_commands<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
    match v {
        Value::Array(arr) => for item in arr { collect_hook_commands(item, out); },
        Value::Object(map) => {
            if let Some(cmd) = map.get("command").and_then(Value::as_str) { out.push(cmd); }
            for (k, val) in map {
                if k != "command" { collect_hook_commands(val, out); }
            }
        }
        _ => {}
    }
}

fn lexical_resolve_norm(base: &str, raw_path: &str, is_windows: bool) -> String {
    let p = raw_path.replace('\\', "/");
    let full = if (p.as_bytes().get(1) == Some(&b':') && p.as_bytes()[0].is_ascii_alphabetic()) || p.starts_with('/') { p } else { format!("{}/{}", base.trim_end_matches('/'), p) };
    let (prefix, rest) = if full.as_bytes().get(1) == Some(&b':') { (&full[..2], &full[2..]) } else if full.starts_with('/') { ("/", &full[1..]) } else { ("", full.as_str()) };
    let mut segs: Vec<&str> = Vec::new();
    for seg in rest.split('/') { match seg { "" | "." => {} ".." => { segs.pop(); } _ => segs.push(seg) } }
    let joined = if prefix == "/" { format!("/{}", segs.join("/")) } else if !prefix.is_empty() { format!("{}/{}", prefix, segs.join("/")) } else { segs.join("/") };
    if is_windows { joined.to_ascii_lowercase() } else { joined }
}

fn shell_segments_with_tokens(cmd: &str, depth: u8) -> Vec<Vec<String>> {
    // INVARIANT: Quote-aware shell argument lexer preserving spaces inside quoted paths and unwrapping `sh -c`/`cmd /c`/`pwsh -Command` wrappers recursively.
    let (mut segs, mut seg, mut cur, mut has_tok, mut in_sq, mut in_dq) = (Vec::new(), Vec::new(), String::new(), false, false, false);
    let mut chars = cmd.trim().chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\'' if in_sq => in_sq = false,
            _ if in_sq => cur.push(ch),
            '"' if in_dq => in_dq = false,
            '\\' if in_dq && matches!(chars.peek(), Some('"' | '\\')) => { cur.push(chars.next().unwrap()); }
            _ if in_dq => cur.push(ch),
            ';' | '|' | '&' | '\n' | '\r' => {
                if has_tok { seg.push(std::mem::take(&mut cur)); has_tok = false; }
                if ch == '&' && seg.is_empty() && chars.peek().is_some_and(|c| c.is_whitespace()) { continue; }
                if !seg.is_empty() { segs.push(std::mem::take(&mut seg)); }
            }
            c if c.is_whitespace() => { if has_tok { seg.push(std::mem::take(&mut cur)); has_tok = false; } }
            '\'' => { in_sq = true; has_tok = true; }
            '"' => { in_dq = true; has_tok = true; }
            _ => { cur.push(ch); has_tok = true; }
        }
    }
    if has_tok { seg.push(cur); }
    if !seg.is_empty() { segs.push(seg); }
    if depth >= 2 { return segs; }
    segs.into_iter().flat_map(|s| match unwrap_single_shell_wrapper(&s) { Some(inner) => shell_segments_with_tokens(inner, depth + 1), None => vec![s] }).collect()
}

fn find_dangling_plugin_hook_ref(root: &Value, config_dir: &Path, target_plugin_dir: &Path, next_manifest: Option<&BTreeMap<String, String>>, is_windows: bool) -> Option<String> {
    let Some(manifest) = next_manifest.filter(|m| !m.is_empty()) else { return None };
    let mut cmds = Vec::new();
    collect_hook_commands(root, &mut cmds);
    if cmds.is_empty() { return None; }
    let (home_norm, cfg_norm) = (rio::home_dir().to_string_lossy().replace('\\', "/"), lexical_resolve_norm("", &config_dir.to_string_lossy(), is_windows));
    let abs_pref = format!("{}/", lexical_resolve_norm("", &target_plugin_dir.to_string_lossy(), is_windows));
    let manifest_keys: Vec<String> = manifest.keys().map(|k| if is_windows { k.to_ascii_lowercase() } else { k.clone() }).collect();
    for cmd in cmds {
        let mut cur_dir = cfg_norm.clone();
        for seg in shell_segments_with_tokens(cmd, 0) {
            if seg.is_empty() { continue; }
            if matches!(seg[0].to_ascii_lowercase().as_str(), "cd" | "chdir" | "pushd" | "set-location" | "sl") {
                if let Some(arg) = seg[1..].iter().find(|a| !a.starts_with('-') && !a.eq_ignore_ascii_case("/d")) {
                    cur_dir = lexical_resolve_norm(&cur_dir, &expand_home_prefix(arg, &home_norm, is_windows), is_windows);
                }
                continue;
            }
            for (idx, tok) in seg.iter().enumerate() {
                let next_tok_hook = seg.get(idx + 1).is_some_and(|t| t.eq_ignore_ascii_case("tokenade-hook"));
                if next_tok_hook && matches!(tok.replace('\\', "/").to_ascii_lowercase().as_str(), "carbon-stack" | "carbon-stack.exe") {
                    return Some("carbon-stack tokenade-hook".to_string());
                }
                let exp = expand_home_prefix(tok, &home_norm, is_windows);
                if !exp.contains('/') { continue; }
                if let Some(rel) = lexical_resolve_norm(&cur_dir, &exp, is_windows).strip_prefix(&abs_pref) {
                    let rel = rel.trim_end_matches('/');
                    if rel.is_empty() { continue; }
                    if !manifest_keys.iter().any(|k| k == rel) { return Some(rel.to_string()); }
                    if next_tok_hook && matches!(rel, "bin/carbon-stack" | "bin/carbon-stack.exe") { return Some(format!("{} tokenade-hook", rel)); }
                }
            }
        }
    }
    None
}

fn plan_global_hooks_prune(
    config_dir: &Path,
    target_plugin_dir: &Path,
    next_manifest: Option<&BTreeMap<String, String>>,
    is_windows: bool,
) -> Result<Option<(String, usize, String)>, String> {
    let hooks_path = config_dir.join("hooks.json");
    if win32_sqlite::is_link_or_junction(&hooks_path) {
        return Err(format!("Refusing symlink/junction global hooks.json: {}", hooks_path.display()));
    }
    match fs::symlink_metadata(&hooks_path) {
        Ok(m) if m.file_type().is_file() => {}
        Ok(_) => return Err(format!("Global hooks.json is not a regular file: {}", hooks_path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("Cannot inspect {}: {}", hooks_path.display(), e)),
    }
    let raw_bytes = fs::read(&hooks_path).map_err(|e| format!("Cannot read {}: {}", hooks_path.display(), e))?;
    let source_sha = rio::sha256_hex(&raw_bytes);
    let raw = String::from_utf8(raw_bytes).map_err(|e| format!("Cannot decode {}: {}", hooks_path.display(), e))?;
    let mut parsed: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            let lower = raw.to_ascii_lowercase();
            if lower.contains("tokenade_hook.py") || lower.contains("tokenade-hook") || lower.contains(PLUGIN_NAME) {
                return Err(format!("Invalid JSON in {} prevents validating legacy plugin hooks: {}", hooks_path.display(), e));
            }
            return Ok(None);
        }
    };
    let pruned = prune_managed_tokenade_entries(&mut parsed, config_dir, target_plugin_dir, is_windows);
    // INVARIANT: Fail closed BEFORE modifying/pruning the plugin tree if any unpruned global hook still targets a plugin file absent from the incoming manifest.
    if let Some(dangling) = find_dangling_plugin_hook_ref(&parsed, config_dir, target_plugin_dir, next_manifest, is_windows) {
        return Err(format!(
            "Global {} still references plugin target '{}' that this install would remove; update or remove that hook entry before installing",
            hooks_path.display(),
            dangling
        ));
    }
    if pruned == 0 {
        return Ok(None);
    }
    Ok(Some((format!("{}\n", serde_json::to_string_pretty(&parsed).map_err(|e| e.to_string())?), pruned, source_sha)))
}

fn preflight_check_for_os_mode(repo_root: &Path, config_dir: &Path, is_windows: bool, allow_unbuilt_hook_bin: bool) -> Value {
    let (mut errors, mut warnings) = (Vec::new(), Vec::new());
    let source_plugin_dir = repo_root.join("plugin");
    let source_glob_rule = repo_root.join("rules").join("uiux-design.md");
    let hook_bin_path = source_plugin_dir.join(platform_hook_binary_rel(is_windows));
    let mut bootstrap_build_required = false;

    for req in [
        source_plugin_dir.join("plugin.json"),
        source_plugin_dir.join("hooks.json"),
        source_plugin_dir.join("rules").join("AGENTS.md"),
        source_glob_rule,
    ] {
        if !req.is_file() {
            errors.push(format!("Missing required source file: {}", req.display()));
        } else if req.extension().and_then(|s| s.to_str()) == Some("json") {
            match fs::read_to_string(&req) {
                Ok(txt) => if let Err(e) = serde_json::from_str::<Value>(&txt) {
                    errors.push(format!("Invalid JSON in {}: {}", req.display(), e));
                },
                Err(e) => errors.push(format!("Cannot read {}: {}", req.display(), e)),
            }
        }
    }
    if !hook_bin_path.is_file() || fs::metadata(&hook_bin_path).map_or(true, |m| m.len() == 0) {
        if allow_unbuilt_hook_bin && repo_root.join("rust").join("Cargo.toml").is_file() {
            bootstrap_build_required = true;
            warnings.push(format!("Native hook binary {} not built yet; install will build via cargo.", hook_bin_path.display()));
        } else {
            errors.push(format!("Missing or empty required hook binary: {}", hook_bin_path.display()));
        }
    } else if !is_windows && has_mz_header(&hook_bin_path) {
        errors.push(format!("Hook binary {} is a Windows PE executable on a non-Windows target", hook_bin_path.display()));
    } else if is_windows && has_elf_header(&hook_bin_path) {
        errors.push(format!("Hook binary {} is a POSIX ELF executable on a Windows target", hook_bin_path.display()));
    }
    if is_windows == cfg!(windows) {
        if let Err(e) = win32_sqlite::probe_sqlite_runtime() {
            errors.push(format!("SQLite runtime unavailable: {}", e));
        }
    }

    let target_plugin_dir = config_dir.join("plugins").join(PLUGIN_NAME);
    let target_glob_rule = config_dir.join("rules").join("uiux-design.md");
    errors.extend(validate_target_hierarchy(config_dir, &target_plugin_dir, &target_glob_rule));
    errors.extend(validate_target_entry_types(config_dir, &target_plugin_dir, &target_glob_rule, Some(&source_plugin_dir), is_windows));
    let mut src_links = Vec::new();
    collect_links_under_tree(&source_plugin_dir, &mut src_links);
    errors.extend(src_links.into_iter().map(|l| format!("Refusing nested symlink/junction: {}", l.display())));
    let preflight_manifest = (!bootstrap_build_required && source_plugin_dir.is_dir())
        .then(|| effective_source_manifest_for_target(&source_plugin_dir, Some(&target_plugin_dir), is_windows));
    if let Err(e) = plan_global_hooks_prune(config_dir, &target_plugin_dir, preflight_manifest.as_ref(), is_windows) {
        errors.push(e);
    }

    let agy_bin = rio::find_agy_cli();
    let mut agy_validation = json!({ "ran": false, "ok": true, "output": "" });
    if let Some(ref bin) = agy_bin {
        if errors.is_empty() {
            let (ok, combined) = run_agy_plugin_validate(bin, &source_plugin_dir, 12_000);
            agy_validation = json!({ "ran": true, "ok": ok, "output": combined });
            if !ok { errors.push(format!("`agy plugin validate` failed: {}", combined)); }
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
        "user_config_json_untouched": config_dir.join("config.json").exists(),
        "agy_cli": agy_bin,
        "agy_validation": agy_validation,
    })
}

fn is_windows_pe_path(p: &Path) -> bool {
    matches!(p.extension().and_then(|s| s.to_str()).map(|s| s.to_ascii_lowercase()).as_deref(), Some("exe" | "dll"))
}

fn prepare_retired_slot(retired_dir: &Path, dst_file: &Path) -> Result<PathBuf, String> {
    if has_dot_components(retired_dir)
        || win32_sqlite::is_link_or_junction(retired_dir)
        || retired_dir.parent().is_some_and(win32_sqlite::is_link_or_junction)
    {
        return Err(format!("Refusing symlink/junction retired dir: {}", retired_dir.display()));
    }
    match fs::symlink_metadata(retired_dir) {
        Ok(m) if !m.file_type().is_dir() => return Err(format!("Refusing non-directory retired path: {}", retired_dir.display())),
        Ok(_) => {}
        Err(_) => fs::create_dir_all(retired_dir).map_err(|e| e.to_string())?,
    }
    if win32_sqlite::is_link_or_junction(retired_dir) {
        return Err(format!("Refusing symlink/junction retired dir: {}", retired_dir.display()));
    }
    for rel in tree_rel_paths(retired_dir) {
        if rel.starts_with("retired-") && !rel.contains('/') {
            let ep = retired_dir.join(&rel);
            if !win32_sqlite::is_link_or_junction(&ep) { let _ = fs::remove_file(&ep); }
        }
    }
    static RETIRE_SEQ: AtomicU64 = AtomicU64::new(1);
    let ms = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis());
    let seq = RETIRE_SEQ.fetch_add(1, Ordering::Relaxed);
    let fname = dst_file.file_name().and_then(|s| s.to_str()).unwrap_or("bin.exe");
    Ok(retired_dir.join(format!("retired-{}-{}-{}-{}", std::process::id(), ms, seq, fname)))
}

fn sweep_retired_bins_dir(dir: &Path) {
    if has_dot_components(dir)
        || win32_sqlite::is_link_or_junction(dir)
        || dir.parent().is_some_and(win32_sqlite::is_link_or_junction)
        || !fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_dir())
    {
        return;
    }
    if let Ok(rd) = fs::read_dir(dir) {
        for p in rd.flatten().map(|e| e.path()) {
            if !win32_sqlite::is_link_or_junction(&p) && fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_file()) {
                let _ = fs::remove_file(&p);
            }
        }
    }
    if !win32_sqlite::is_link_or_junction(dir) {
        let _ = fs::remove_dir(dir);
    }
}

fn sweep_all_retired_bins(plugin_dir: &Path, stack_home: &Path, config_dir: &Path) {
    sweep_retired_bins_dir(&plugin_dir.join("bin").join(RETIRED_BINS_DIR_NAME));
    sweep_retired_bins_dir(&stack_home.join("state").join(RETIRED_BINS_DIR_NAME));
    sweep_retired_bins_dir(&config_dir.join(RETIRED_BINS_DIR_NAME));
}

fn retire_locked_windows_pe(dst_file: &Path, tmp: &Path) -> Result<bool, String> {
    if !cfg!(windows) || !dst_file.exists() || !is_windows_pe_path(dst_file) {
        return Ok(false);
    }
    let Some(parent) = dst_file.parent() else { return Ok(false) };
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
    let Err(e) = fs::remove_file(target_file) else { return Ok(()) };
    if !cfg!(windows) || !is_windows_pe_path(target_file) || !target_file.exists() {
        return Err(e.to_string());
    }
    let fallback = target_file.parent().map(|p| p.join(RETIRED_BINS_DIR_NAME));
    for dir in external_retired_dirs.iter().copied().chain(fallback.as_deref()) {
        if let Ok(slot) = prepare_retired_slot(dir, target_file) {
            if fs::rename(target_file, &slot).is_ok() {
                let _ = fs::remove_file(&slot);
                return Ok(());
            }
        }
    }
    Err(e.to_string())
}

fn remove_tree_or_retire_pe(target_dir: &Path, external_retired_dirs: &[&Path]) -> std::io::Result<()> {
    match fs::remove_dir_all(target_dir) {
        Ok(()) => Ok(()),
        Err(e) if cfg!(windows) => {
            for rel in tree_rel_paths(target_dir) {
                let p = target_dir.join(&rel);
                if is_windows_pe_path(&p) { let _ = remove_file_or_retire_pe(&p, external_retired_dirs); }
            }
            if !target_dir.exists() { Ok(()) } else { fs::remove_dir_all(target_dir).map_err(|_| e) }
        }
        Err(e) => Err(e),
    }
}

fn atomic_replace_file<W, F>(
    dst_file: &Path,
    desired_perms: Option<&fs::Permissions>,
    allow_pe_retire: bool,
    write_tmp: W,
    fallback_write: F,
) -> Result<(), String>
where
    W: FnOnce(&mut fs::File) -> Result<(), String>,
    F: FnOnce() -> Result<(), String>,
{
    static TMP_SEQ: AtomicU64 = AtomicU64::new(1);
    if let Some(parent) = dst_file.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let fname = dst_file.file_name().and_then(|s| s.to_str()).unwrap_or("file");
    let tmp = dst_file.with_file_name(format!(".{}.agy-tmp-{}-{}-{}", fname, std::process::id(), nanos, seq));
    let res = (|| -> Result<(), String> {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut tmp_fh = opts.open(&tmp).map_err(|e| e.to_string())?;
        write_tmp(&mut tmp_fh)?;
        drop(tmp_fh);
        #[cfg(unix)]
        if let Some(perms) = desired_perms {
            fs::set_permissions(&tmp, perms.clone()).map_err(|e| e.to_string())?;
        }
        #[cfg(not(unix))]
        if allow_pe_retire {
            if let Some(perms) = desired_perms {
                fs::set_permissions(&tmp, perms.clone()).map_err(|e| e.to_string())?;
            }
        }
        for attempt in 0..4u64 {
            match fs::rename(&tmp, dst_file) {
                Ok(()) => {
                    #[cfg(not(unix))]
                    if !allow_pe_retire {
                        if let Some(perms) = desired_perms {
                            let _ = fs::set_permissions(dst_file, perms.clone());
                        }
                    }
                    return Ok(());
                }
                Err(e) if attempt == 3 => {
                    if allow_pe_retire && retire_locked_windows_pe(dst_file, &tmp)? {
                        return Ok(());
                    }
                    if win32_sqlite::is_link_or_junction(dst_file) {
                        return Err(format!("Refusing symlink/junction target: {}", dst_file.display()));
                    }
                    fallback_write().map_err(|e2| format!("{}; {}", e, e2))?;
                    if let Some(perms) = desired_perms {
                        let _ = fs::set_permissions(dst_file, perms.clone());
                    }
                    return Ok(());
                }
                Err(_) => thread::sleep(Duration::from_millis(50 * (attempt + 1))),
            }
        }
        Ok(())
    })();
    if tmp.exists() { let _ = fs::remove_file(&tmp); }
    res
}

fn atomic_copy_file(src_file: &Path, dst_file: &Path) -> Result<(), String> {
    let mut src_fh = fs::File::open(src_file).map_err(|e| e.to_string())?;
    let src_perms = src_fh.metadata().map_err(|e| e.to_string())?.permissions();
    atomic_replace_file(
        dst_file,
        Some(&src_perms),
        true,
        move |tmp_fh| std::io::copy(&mut src_fh, tmp_fh).map(|_| ()).map_err(|e| e.to_string()),
        || fs::copy(src_file, dst_file).map(|_| ()).map_err(|e| e.to_string()),
    )
}

fn atomic_write_bytes_with_default_perms(
    dst_file: &Path,
    bytes: &[u8],
    fallback_perms: Option<fs::Permissions>,
) -> Result<(), String> {
    if win32_sqlite::is_link_or_junction(dst_file) {
        return Err(format!("Refusing symlink/junction target: {}", dst_file.display()));
    }
    let existing_perms = match fs::symlink_metadata(dst_file) {
        Ok(m) if m.file_type().is_file() => Some(m.permissions()),
        Ok(_) => return Err(format!("Refusing non-regular file target: {}", dst_file.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.to_string()),
    };
    let desired_perms = existing_perms.or(fallback_perms);
    atomic_replace_file(
        dst_file,
        desired_perms.as_ref(),
        false,
        |tmp_fh| tmp_fh.write_all(bytes).map_err(|e| e.to_string()),
        || fs::write(dst_file, bytes).map_err(|e| e.to_string()),
    )
}

fn collect_dirs_postorder(root: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = fs::read_dir(root) {
        for p in rd.flatten().map(|e| e.path()) {
            if !win32_sqlite::is_link_or_junction(&p) && p.is_dir() {
                collect_dirs_postorder(&p, out);
                out.push(p);
            }
        }
    }
}

fn copy_clean_tree_additive_for_target(src: &Path, dst: &Path, is_windows: bool, materialize_hooks_abs: bool) -> Result<(), String> {
    let mut links = Vec::new();
    collect_links_under_tree(src, &mut links);
    if dst.exists() || win32_sqlite::is_link_or_junction(dst) {
        collect_links_under_tree(dst, &mut links);
    }
    if let Some(lnk) = links.first() {
        return Err(format!("Refusing tree containing symlink/junction: {}", lnk.display()));
    }
    if fs::symlink_metadata(dst).is_ok_and(|m| !m.file_type().is_dir()) {
        return Err(format!("Refusing non-directory tree target: {}", dst.display()));
    }
    fs::create_dir_all(dst).map_err(|e| e.to_string())?;

    let target_opt = materialize_hooks_abs.then_some(dst);
    let src_map = effective_source_manifest_strict_for_target(src, target_opt, is_windows)?;
    let dst_map = tree_manifest(dst);
    for (rel, src_hash) in &src_map {
        let dst_path = dst.join(rel);
        ensure_no_links_between(dst, &dst_path)?;
        if dst_map.get(rel) != Some(src_hash) {
            if rel == "hooks.json" && (materialize_hooks_abs || !is_windows) {
                let src_file = src.join(rel);
                let norm = materialize_hooks_json_for_target(
                    &fs::read_to_string(&src_file).map_err(|e| e.to_string())?,
                    target_opt,
                    is_windows,
                );
                atomic_write_bytes_with_default_perms(&dst_path, norm.as_bytes(), fs::metadata(&src_file).ok().map(|m| m.permissions()))?;
            } else {
                atomic_copy_file(&src.join(rel), &dst_path)?;
            }
        }
        #[cfg(unix)]
        if rel == "bin/carbon-stack" {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(&dst_path).map_err(|e| e.to_string())?;
            let cur_mode = meta.permissions().mode();
            let fixed = ensure_owner_exec_mode_bits(cur_mode);
            if fixed != cur_mode {
                let mut perms = meta.permissions();
                perms.set_mode(fixed);
                fs::set_permissions(&dst_path, perms).map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}

fn prune_stale_tree_entries(src: &Path, dst: &Path, is_windows: bool, external_retired_dirs: &[&Path]) -> Result<(), String> {
    let case_fold = is_windows || cfg!(windows) || cfg!(target_os = "macos");
    let src_keys: BTreeSet<String> = effective_source_manifest_strict_for_target(src, None, is_windows)?
        .into_keys()
        .map(|k| if case_fold { norm_instance_path(&k, true) } else { k })
        .collect();
    for rel in tree_rel_paths(dst) {
        let key = if case_fold { norm_instance_path(&rel, true) } else { rel.clone() };
        if !src_keys.contains(&key) {
            let stale = dst.join(&rel);
            ensure_no_links_between(dst, &stale)?;
            if stale.exists() {
                remove_file_or_retire_pe(&stale, external_retired_dirs)?;
            }
        }
    }
    let mut subdirs = Vec::new();
    collect_dirs_postorder(dst, &mut subdirs);
    for cur in subdirs {
        let cname = cur.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if cname == RETIRED_BINS_DIR_NAME {
            let _ = fs::remove_dir(&cur);
        } else if let Ok(rel_dir) = cur.strip_prefix(dst) {
            if SKIP_NAMES.contains(&cname) || !src.join(rel_dir).is_dir() {
                let _ = fs::remove_dir_all(&cur);
            }
        }
    }
    Ok(())
}

fn copy_clean_tree_with_retire(src: &Path, dst: &Path, is_windows: bool, retired_dirs: &[&Path]) -> Result<(), String> {
    copy_clean_tree_additive_for_target(src, dst, is_windows, false)?;
    prune_stale_tree_entries(src, dst, is_windows, retired_dirs)
}

fn copy_clean_tree_for_os(src: &Path, dst: &Path, is_windows: bool) -> Result<(), String> {
    copy_clean_tree_with_retire(src, dst, is_windows, &[])
}

fn utc_backup_stamp_and_iso() -> (String, String) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let iso = win32_sqlite::format_iso_utc(now.as_secs() as f64);
    let compact: String = iso.chars().filter(char::is_ascii_digit).take(14).collect();
    let stamp = if compact.len() == 14 {
        format!("{}-{}-{:06}", &compact[..8], &compact[8..14], now.subsec_micros())
    } else {
        format!("{}-{:06}", now.as_secs(), now.subsec_micros())
    };
    (stamp.chars().take(20).collect(), iso)
}

fn is_safe_backup_id(id: &str) -> bool {
    if id.is_empty() || matches!(id, "." | "..") || id.contains(['/', '\\', ':', '\0']) {
        return false;
    }
    let mut comps = Path::new(id).components();
    matches!(comps.next(), Some(Component::Normal(_))) && comps.next().is_none()
}

fn matches_pinned_target_path(raw: &str, target: &Path) -> bool {
    !raw.is_empty()
        && !has_dot_components(Path::new(raw))
        && rio::normalize_path(raw) == rio::normalize_path(&target.to_string_lossy())
}

fn ensure_opt_dir(path: &Path, label: &str) -> Result<bool, String> {
    if win32_sqlite::is_link_or_junction(path) {
        return Err(format!("Invalid {} (refusing symlink/junction): {}", label, path.display()));
    }
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => Ok(true),
        Ok(_) => Err(format!("Invalid {} (not a directory): {}", label, path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("Cannot inspect {} {}: {}", label, path.display(), e)),
    }
}

fn validate_backups_root_strict(stack_home: &Path) -> Result<Option<PathBuf>, String> {
    if has_dot_components(stack_home) {
        return Err(format!("Refusing traversal in stack_home: {}", stack_home.display()));
    }
    if !ensure_opt_dir(stack_home, "stack_home")? {
        return Ok(None);
    }
    let broot = stack_home.join("backups");
    Ok(ensure_opt_dir(&broot, "backups directory")?.then_some(broot))
}

fn validate_stack_home_preinstall(stack_home: &Path) -> Result<(), String> {
    validate_backups_root_strict(stack_home)?;
    let _ = ensure_opt_dir(&stack_home.join("state"), "state directory")?;
    Ok(())
}

fn validate_backup_entry_strict(p: &Path) -> Result<bool, String> {
    if win32_sqlite::is_link_or_junction(p) {
        return Err(format!("Refusing symlink/junction inside backups: {}", p.display()));
    }
    if !fs::symlink_metadata(p).map_err(|e| format!("Cannot inspect {}: {}", p.display(), e))?.is_dir() {
        return Ok(false);
    }
    let mf_path = p.join("manifest.json");
    if win32_sqlite::is_link_or_junction(&mf_path) {
        return Err(format!("Refusing symlink/junction backup manifest: {}", mf_path.display()));
    }
    match fs::symlink_metadata(&mf_path) {
        Ok(m) if m.is_file() => {
            fs::File::open(&mf_path).map_err(|e| format!("Cannot open backup manifest {}: {}", mf_path.display(), e))?;
            Ok(true)
        }
        Ok(_) => Err(format!("Invalid backup manifest (not a regular file): {}", mf_path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("Cannot inspect backup manifest {}: {}", mf_path.display(), e)),
    }
}

fn list_backups_strict(stack_home: &Path) -> Result<Vec<PathBuf>, String> {
    let Some(broot) = validate_backups_root_strict(stack_home)? else { return Ok(Vec::new()) };
    let mut out = Vec::new();
    for ent_res in fs::read_dir(&broot).map_err(|e| format!("Cannot read {}: {}", broot.display(), e))? {
        let p = ent_res.map_err(|e| format!("Read failed in {}: {}", broot.display(), e))?.path();
        if validate_backup_entry_strict(&p)? {
            out.push(p);
        }
    }
    out.sort();
    Ok(out)
}

fn is_completed_backup_manifest(manifest: &Value) -> bool {
    let Some(targets) = manifest.get("targets").and_then(Value::as_object) else { return false };
    let (Some(p), Some(r)) = (
        targets.get("plugin_dir").and_then(Value::as_object),
        targets.get("glob_rule").and_then(Value::as_object),
    ) else {
        return false;
    };
    if p.get("existed").and_then(Value::as_bool).is_none()
        || r.get("existed").and_then(Value::as_bool).is_none()
        || p.get("path").and_then(Value::as_str).unwrap_or("").trim().is_empty()
        || r.get("path").and_then(Value::as_str).unwrap_or("").trim().is_empty()
    {
        return false;
    }
    targets.get("global_hooks").map_or(true, |hv| {
        hv.as_object().is_some_and(|h| {
            h.get("existed").and_then(Value::as_bool).is_some()
                || h.get("migrations").and_then(Value::as_array).is_some()
        })
    })
}

fn prune_old_install_backups(stack_home: &Path, keep: usize) -> usize {
    // INVARIANT: Count and prune ONLY completed `install-*` backups passing both `validate_backup_entry_strict == Ok(true)` and `is_completed_backup_manifest`.
    let broot = stack_home.join("backups");
    if has_dot_components(stack_home)
        || win32_sqlite::is_link_or_junction(stack_home)
        || win32_sqlite::is_link_or_junction(&broot)
        || !fs::symlink_metadata(&broot).is_ok_and(|m| m.file_type().is_dir())
    {
        return 0;
    }
    let Ok(rd) = fs::read_dir(&broot) else { return 0 };
    let mut dirs: Vec<(String, PathBuf)> = rd
        .flatten()
        .filter_map(|ent| {
            let name = ent.file_name().to_str()?.to_string();
            let p = ent.path();
            (name.starts_with("install-")
                && matches!(validate_backup_entry_strict(&p), Ok(true))
                && rio::read_json(&p.join("manifest.json")).as_ref().is_some_and(is_completed_backup_manifest))
            .then_some((name, p))
        })
        .collect();
    if dirs.len() <= keep {
        return 0;
    }
    dirs.sort_by(|a, b| b.0.cmp(&a.0));
    dirs.into_iter()
        .skip(keep)
        .filter(|(_, p)| !win32_sqlite::is_link_or_junction(p) && fs::remove_dir_all(p).is_ok())
        .count()
}

fn backup_single_file(src: &Path, dst: &Path, label: &str) -> Result<String, String> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::copy(src, dst).map_err(|e| e.to_string())?;
    let (src_sha, bak_sha) = (sha256_file_full(src)?, sha256_file_full(dst)?);
    if bak_sha != src_sha {
        return Err(format!("Backup {} snapshot verification failed", label));
    }
    Ok(bak_sha)
}

fn create_backup(config_dir: &Path, stack_home: &Path) -> Result<Value, String> {
    let target_plugin_dir = config_dir.join("plugins").join(PLUGIN_NAME);
    let target_glob_rule = config_dir.join("rules").join("uiux-design.md");
    if let Some(err) = validate_target_hierarchy(config_dir, &target_plugin_dir, &target_glob_rule).first() {
        return Err(err.clone());
    }
    if let Some(err) = validate_target_entry_types(config_dir, &target_plugin_dir, &target_glob_rule, None, cfg!(windows)).first() {
        return Err(err.clone());
    }
    let backups_root = match validate_backups_root_strict(stack_home)? {
        Some(b) => b,
        None => {
            let b = stack_home.join("backups");
            fs::create_dir_all(&b).map_err(|e| e.to_string())?;
            validate_backups_root_strict(stack_home)?.ok_or_else(|| format!("Failed to init {}", b.display()))?
        }
    };
    let (stamp, iso) = utc_backup_stamp_and_iso();
    let (mut backup_id, mut suffix) = (format!("install-{}", stamp), 1usize);
    while backups_root.join(&backup_id).exists() {
        backup_id = format!("install-{}-{}", stamp, suffix);
        suffix += 1;
    }
    let bdir = backups_root.join(&backup_id);
    fs::create_dir_all(&bdir).map_err(|e| e.to_string())?;

    let target_global_hooks = config_dir.join("hooks.json");
    let (p_ex, r_ex, h_ex) = (target_plugin_dir.is_dir(), target_glob_rule.is_file(), target_global_hooks.is_file());
    let mut plugin_target = json!({ "path": target_plugin_dir.to_string_lossy(), "existed": p_ex });
    if p_ex {
        let p_backup = bdir.join("plugin_dir");
        copy_clean_tree_for_os(&target_plugin_dir, &p_backup, true)?;
        let (src_h, bak_h) = (tree_manifest_strict(&target_plugin_dir)?, tree_manifest_strict(&p_backup)?);
        if bak_h != src_h { return Err("Backup plugin snapshot verification failed".to_string()); }
        plugin_target["files_sha256"] = json!(bak_h);
    }
    let mut rule_target = json!({ "path": target_glob_rule.to_string_lossy(), "existed": r_ex });
    if r_ex {
        rule_target["sha256"] = Value::String(backup_single_file(&target_glob_rule, &bdir.join("rules").join("uiux-design.md"), "rule")?);
        if fs::read_to_string(&target_glob_rule).is_ok_and(|t| !t.contains("Frontend UI/UX & Live Browser Verification Rules")) {
            rule_target["was_foreign_user_file"] = Value::Bool(true);
        }
    }
    let mut hooks_target = json!({ "path": target_global_hooks.to_string_lossy(), "existed": h_ex });
    if h_ex {
        hooks_target["sha256"] = Value::String(backup_single_file(&target_global_hooks, &bdir.join("global_hooks.json"), "global_hooks")?);
    }
    let manifest = json!({
        "backup_id": backup_id,
        "created_utc": iso,
        "config_dir": config_dir.to_string_lossy(),
        "targets": { "plugin_dir": plugin_target, "glob_rule": rule_target, "global_hooks": hooks_target },
    });
    rio::write_json(&bdir.join("manifest.json"), &manifest)?;
    Ok(manifest)
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

fn acquire_installer_mutex(config_dir: &Path, stack_home: &Path, timeout: Duration) -> Result<InstallerMutexGuard, String> {
    let state_root = stack_home.join("state");
    fs::create_dir_all(&state_root).map_err(|e| e.to_string())?;
    fs::create_dir_all(config_dir).map_err(|e| e.to_string())?;
    let mut lock_paths = vec![state_root.join(".installer.lock"), config_dir.join(".carbon-installer.lock")];
    lock_paths.sort_by_key(|p| rio::normalize_path(&p.to_string_lossy()));
    lock_paths.dedup_by(|a, b| rio::normalize_path(&a.to_string_lossy()) == rio::normalize_path(&b.to_string_lossy()));
    let deadline = Instant::now() + timeout;
    let mut locks = Vec::with_capacity(lock_paths.len());
    for lp in &lock_paths {
        if win32_sqlite::is_link_or_junction(lp) {
            return Err(format!("Refusing symlink/junction installer lock: {}", lp.display()));
        }
        let fh = fs::OpenOptions::new().read(true).write(true).create(true).truncate(false)
            .open(lp).map_err(|e| format!("Cannot open {}: {}", lp.display(), e))?;
        loop {
            match fh.try_lock() {
                Ok(()) => break,
                Err(fs::TryLockError::WouldBlock) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Err(fs::TryLockError::WouldBlock) => return Err(format!("Timed out acquiring installer lock {}", lp.display())),
                Err(fs::TryLockError::Error(e)) => return Err(format!("Failed locking {}: {}", lp.display(), e)),
            }
        }
        locks.push(fh);
    }
    Ok(InstallerMutexGuard { locks })
}

fn ensure_state_subdirs(stack_home: &Path) {
    let state_root = stack_home.join("state");
    for sub in ["gate", "continuity", "memory", "chips", "hygiene", "logs"] {
        let _ = fs::create_dir_all(state_root.join(sub));
    }
}

fn stage_retire_candidate_dirs(config_dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = fs::read_dir(config_dir) else { return Vec::new() };
    let mut dirs: Vec<PathBuf> = rd
        .flatten()
        .filter_map(|ent| {
            let p = ent.path();
            (ent.file_name().to_string_lossy().starts_with(STAGE_RETIRE_PREFIX)
                && !win32_sqlite::is_link_or_junction(&p)
                && p.is_dir())
            .then_some(p)
        })
        .collect();
    dirs.sort();
    dirs
}

fn list_orphaned_stage_retire_dirs(config_dir: &Path) -> Vec<String> {
    stage_retire_candidate_dirs(config_dir)
        .into_iter()
        .filter(|p| fs::OpenOptions::new().read(true).open(p.join(STAGE_RETIRE_LOCK_NAME)).map_or(true, |fh| fh.try_lock_shared().is_ok()))
        .map(|p| p.to_string_lossy().into_owned())
        .collect()
}

fn recover_interrupted_stage_retire_dirs(config_dir: &Path, retire_dirs: &[&Path]) -> Result<(), String> {
    if has_dot_components(config_dir) || win32_sqlite::is_link_or_junction(config_dir) {
        return Err(format!("Refusing symlink/junction config_dir: {}", config_dir.display()));
    }
    let candidates = stage_retire_candidate_dirs(config_dir);
    if candidates.is_empty() {
        return Ok(());
    }
    let plugins_parent = config_dir.join("plugins");
    let dst_tree = plugins_parent.join(PLUGIN_NAME);
    let hooks_path = config_dir.join("hooks.json");
    if [&plugins_parent, &dst_tree, &hooks_path].into_iter().any(|p| win32_sqlite::is_link_or_junction(p)) {
        return Err(format!("Refusing symlink/junction target under {}", config_dir.display()));
    }
    for stage_dir in candidates {
        let Ok(lock_fh) = fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(stage_dir.join(STAGE_RETIRE_LOCK_NAME)) else {
            continue;
        };
        if lock_fh.try_lock().is_err() {
            continue;
        }
        let journal_path = stage_dir.join(STAGE_RETIRE_JOURNAL_NAME);
        let Some(j) = rio::read_json(&journal_path) else {
            let has_other = fs::read_dir(&stage_dir).map_or(true, |rd| {
                rd.flatten().any(|e| e.file_name() != STAGE_RETIRE_LOCK_NAME && e.file_name() != STAGE_RETIRE_JOURNAL_NAME)
            });
            drop(lock_fh);
            if !journal_path.exists() && !has_other {
                let _ = remove_tree_or_retire_pe(&stage_dir, retire_dirs);
                continue;
            }
            return Err(format!("Missing or corrupt retire-journal in {}", stage_dir.display()));
        };
        let (ver, mode, phase, sentinel) = (
            j.get("version").and_then(Value::as_u64),
            j.get("mode").and_then(Value::as_str).unwrap_or(""),
            j.get("phase").and_then(Value::as_str).unwrap_or(""),
            j.get("sentinel_hooks").and_then(Value::as_bool),
        );
        if ver != Some(1) || !matches!(mode, "prune" | "remove") || !matches!(phase, "committed_delete" | "contracting" | "restoring") || sentinel.is_none() {
            return Err(format!("Invalid retire-journal metadata in {}", stage_dir.display()));
        }
        if sentinel == Some(true) {
            let _ = win32_sqlite::remove_file_if_exact_bytes(&hooks_path, HOOKS_SENTINEL_BYTES);
        }
        if phase != "committed_delete" {
            let payload_root = stage_dir.join(if mode == "prune" { "files" } else { "tree" });
            if payload_root.is_dir() {
                copy_clean_tree_additive_for_target(&payload_root, &dst_tree, true, false)?;
            }
        }
        drop(lock_fh);
        let _ = remove_tree_or_retire_pe(&stage_dir, retire_dirs);
    }
    Ok(())
}

fn try_auto_heal_stage_retire_for_paths(cfg: &Path, shome: &Path) {
    let has_orphaned = !list_orphaned_stage_retire_dirs(cfg).is_empty();
    let (plugins_dir, state_dir) = (cfg.join("plugins"), shome.join("state"));
    let plugin_dir = plugins_dir.join(PLUGIN_NAME);
    let plugin_bin = plugin_dir.join("bin");
    let (ret_bin, ret_state, ret_cfg) = (
        plugin_bin.join(RETIRED_BINS_DIR_NAME),
        state_dir.join(RETIRED_BINS_DIR_NAME),
        cfg.join(RETIRED_BINS_DIR_NAME),
    );
    let is_plain = |p: &Path| fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_dir()) && !win32_sqlite::is_link_or_junction(p);
    let safe_plugin = [cfg, &plugins_dir, &plugin_dir, &plugin_bin].into_iter().all(|p| !win32_sqlite::is_link_or_junction(p));
    let safe_state = !win32_sqlite::is_link_or_junction(shome) && !win32_sqlite::is_link_or_junction(&state_dir);
    let safe_cfg = !win32_sqlite::is_link_or_junction(cfg);

    if !has_orphaned && !(is_plain(&ret_bin) && safe_plugin) && !(is_plain(&ret_state) && safe_state) && !(is_plain(&ret_cfg) && safe_cfg) {
        return;
    }
    let Ok(_guard) = acquire_installer_mutex(cfg, shome, Duration::from_secs(2)) else { return };
    if has_orphaned {
        let _ = recover_interrupted_stage_retire_dirs(cfg, &[&ret_state, &ret_cfg]);
    }
    if safe_plugin { sweep_retired_bins_dir(&ret_bin); }
    if safe_state { sweep_retired_bins_dir(&ret_state); }
    if safe_cfg { sweep_retired_bins_dir(&ret_cfg); }
}

pub(crate) fn try_auto_heal_default_stage_retire() {
    let (cfg, shome) = resolve_paths("", "");
    try_auto_heal_stage_retire_for_paths(&cfg, &shome);
}

fn validate_legacy_plugin_snapshot(p_backup: &Path, expected_target_dir: Option<&Path>, actual_hashes: &BTreeMap<String, String>) -> Result<(), String> {
    if actual_hashes.is_empty() || !p_backup.join("rules").join("AGENTS.md").is_file() {
        return Err("Incomplete legacy backup: missing plugin snapshot files".to_string());
    }
    let pjson = rio::read_json(&p_backup.join("plugin.json")).ok_or("Incomplete legacy backup: missing or invalid plugin.json")?;
    if pjson.get("name").and_then(Value::as_str) != Some(PLUGIN_NAME) {
        return Err("Invalid legacy backup: plugin.json name mismatch".to_string());
    }
    let hjson = rio::read_json(&p_backup.join("hooks.json")).ok_or("Incomplete legacy backup: missing or invalid hooks.json")?;
    let (hinfo, _, cmds_ok) = stack_doctor::inspect_hooks_json_for_os_with_target(p_backup, Some(&hjson), cfg!(windows), expected_target_dir);
    if !cmds_ok || !hinfo.get("missing_events").and_then(Value::as_array).is_some_and(Vec::is_empty) {
        return Err("Incomplete legacy backup: hooks.json targets or events missing".to_string());
    }
    let hraw = hjson.to_string();
    if hraw.contains("bin/carbon-stack") || hraw.contains("bin\\carbon-stack") {
        let bin_p = p_backup.join(platform_hook_binary_rel(cfg!(windows)));
        if !bin_p.is_file() || fs::metadata(&bin_p).map_or(true, |m| m.len() == 0) {
            return Err(format!("Incomplete legacy backup: missing hook binary {}", bin_p.display()));
        }
    }
    Ok(())
}

fn verify_backup_file_sha(info: &Value, bak_path: &Path, label: &str) -> Result<String, String> {
    if !bak_path.is_file() {
        return Err(format!("Incomplete backup: missing {} snapshot {}", label, bak_path.display()));
    }
    let actual_sha = sha256_file_full(bak_path).map_err(|_| format!("Failed to hash {} backup snapshot", label))?;
    match info.get("sha256") {
        Some(Value::String(exp)) if is_valid_sha256_hex(exp) => {
            if actual_sha != *exp { return Err(format!("Corrupted backup: {} snapshot SHA-256 mismatch", label)); }
        }
        Some(_) => return Err(format!("Invalid backup manifest.json: malformed {} `sha256` digest", label)),
        None => {}
    }
    Ok(actual_sha)
}

struct RollbackStage<'a> {
    expected_live_hashes: Option<&'a BTreeMap<String, String>>,
    expected_live_rule_sha: Option<&'a str>,
    expected_live_hooks_sha: Option<&'a str>,
    stage_root: &'a Path,
    config_dir: &'a Path,
    retire_dirs: &'a [&'a Path],
}

fn compensate_rollback(st: &RollbackStage<'_>, mut_plugin: bool, mut_rule: bool, mut_hooks: bool, mut err_resp: Value) -> Value {
    let p_target = st.config_dir.join("plugins").join(PLUGIN_NAME);
    let mut comp_ok = true;
    if mut_plugin {
        comp_ok &= if st.expected_live_hashes.is_some() {
            copy_clean_tree_with_retire(&st.stage_root.join("plugin_dir"), &p_target, true, st.retire_dirs).is_ok()
                && tree_manifest_strict(&p_target).ok().as_ref() == st.expected_live_hashes
        } else {
            !p_target.exists() || (remove_tree_or_retire_pe(&p_target, st.retire_dirs).is_ok() && !p_target.exists())
        };
    }
    for (did_mut, staged, target, exp_sha) in [
        (mut_rule, st.stage_root.join("glob_rule.md"), st.config_dir.join("rules").join("uiux-design.md"), st.expected_live_rule_sha),
        (mut_hooks, st.stage_root.join("global_hooks.json"), st.config_dir.join("hooks.json"), st.expected_live_hooks_sha),
    ] {
        if did_mut {
            comp_ok &= if exp_sha.is_some() {
                atomic_copy_file(&staged, &target).is_ok() && sha256_file_full(&target).ok().as_deref() == exp_sha
            } else {
                !target.exists() || (fs::remove_file(&target).is_ok() && !target.exists())
            };
        }
    }
    if comp_ok { let _ = fs::remove_dir_all(st.stage_root); }
    if let Some(obj) = err_resp.as_object_mut() {
        obj.insert("compensated_plugin_restore".to_string(), Value::Bool(comp_ok));
        if !comp_ok {
            obj.insert("recovery_snapshot_dir".to_string(), Value::String(st.stage_root.to_string_lossy().into_owned()));
        }
    }
    err_resp
}

fn compare_and_replace_file(target: &Path, expected_sha: &str, new_bytes: &[u8]) -> Result<(), String> {
    // INVARIANT: Create empty stage privately (`0600` on Unix), verify/strip ACLs and preserve `orig_gid` BEFORE writing a single byte, apply `orig_mode` after write, swap crash-atomically capturing displaced bytes, and NEVER delete any displaced file whose SHA-256 is not proven to be `expected_sha` or `written_sha`.
    static SWAP_SEQ: AtomicU64 = AtomicU64::new(1);
    if win32_sqlite::is_link_or_junction(target) { return Err(format!("Refusing symlink/junction {}", target.display())); }
    let parent = target.parent().ok_or_else(|| format!("Invalid target path {}", target.display()))?;
    let (seq, pid) = (SWAP_SEQ.fetch_add(1, Ordering::Relaxed), std::process::id());
    let (stage, disp_slot, rev_slot) = (parent.join(format!(".hooks.stage.{}.{}.tmp", pid, seq)), parent.join(format!(".hooks.disp.{}.{}.tmp", pid, seq)), parent.join(format!(".hooks.rev.{}.{}.tmp", pid, seq)));
    let mut oo = fs::OpenOptions::new();
    oo.write(true).create_new(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; oo.mode(0o600); }
    let write_res = oo.open(&stage).and_then(|mut f| {
        #[cfg(unix)] let orig_mode = win32_sqlite::prepare_unix_stage_access_or_refuse(target, &f)?;
        f.write_all(new_bytes)?;
        #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; f.set_permissions(fs::Permissions::from_mode(orig_mode))?; }
        f.sync_all()
    });
    if let Err(e) = write_res { let _ = fs::remove_file(&stage); return Err(format!("Stage {} failed: {}", target.display(), e)); }
    let displaced = match win32_sqlite::atomic_swap_capturing_displaced(target, &stage, &disp_slot) {
        Ok(p) => p,
        Err(e) => { let _ = fs::remove_file(&stage); return Err(format!("Atomic swap {} failed: {}", target.display(), e)); }
    };
    if sha256_file_full(&displaced).ok().as_deref() == Some(expected_sha) { let _ = fs::remove_file(&displaced); return Ok(()); }
    let written_sha = rio::sha256_hex(new_bytes);
    match win32_sqlite::atomic_swap_capturing_displaced(target, &displaced, &rev_slot) {
        Ok(rev) if sha256_file_full(&rev).ok().as_deref() == Some(written_sha.as_str()) => {
            let _ = fs::remove_file(&rev); Err(format!("Global {} changed concurrently; user edits restored untouched", target.display()))
        }
        Ok(rev) => match win32_sqlite::atomic_swap_capturing_displaced(target, &rev, &parent.join(format!(".hooks.rev2.{}.{}.tmp", pid, seq))) {
            Ok(out2) if matches!(sha256_file_full(&out2).ok().as_deref(), Some(s) if s == written_sha || s == expected_sha) => {
                let _ = fs::remove_file(&out2); Err(format!("Global {} changed concurrently during recovery; latest user edits preserved", target.display()))
            }
            Ok(out2) => Err(format!("Global {} changed concurrently multiple times; conflicting user version preserved at {}", target.display(), out2.display())),
            Err(e) => Err(format!("Global {} changed concurrently; newer user edits preserved at {} (restore swap failed: {})", target.display(), rev.display(), e)),
        },
        Err(e) => Err(format!("Global {} changed concurrently and restore swap failed ({}); user version preserved at {}", target.display(), e, displaced.display())),
    }
}

fn perform_install(repo_root: &Path, config_dir: &Path, stack_home: &Path, dry_run: bool, force_foreign: bool) -> Value {
    let source_plugin_dir = repo_root.join("plugin");
    let source_glob_rule = repo_root.join("rules").join("uiux-design.md");
    let target_plugin_dir = config_dir.join("plugins").join(PLUGIN_NAME);
    let target_glob_rule = config_dir.join("rules").join("uiux-design.md");
    let (retired_state, retired_cfg) = (stack_home.join("state").join(RETIRED_BINS_DIR_NAME), config_dir.join(RETIRED_BINS_DIR_NAME));
    let retire_dirs: [&Path; 2] = [&retired_state, &retired_cfg];

    let _inst_mutex = if !dry_run {
        if !validate_target_hierarchy(config_dir, &target_plugin_dir, &target_glob_rule).is_empty() {
            let pf = preflight_check_for_os_mode(repo_root, config_dir, cfg!(windows), false);
            return json!({ "ok": false, "stage": "preflight", "preflight": pf });
        }
        if let Err(e) = validate_stack_home_preinstall(stack_home) {
            return stage_err("preflight", e);
        }
        let guard = match acquire_installer_mutex(config_dir, stack_home, Duration::from_secs(15)) {
            Ok(g) => g,
            Err(e) => return stage_err("installer_lock", e),
        };
        if let Err(e) = recover_interrupted_stage_retire_dirs(config_dir, &retire_dirs) {
            return stage_err("stage_retire_recovery", e);
        }
        Some(guard)
    } else {
        None
    };

    let pf = preflight_check_for_os_mode(repo_root, config_dir, cfg!(windows), dry_run);
    if pf.get("ok").and_then(Value::as_bool) != Some(true) {
        return json!({ "ok": false, "stage": "preflight", "preflight": pf });
    }
    if dry_run {
        if let Err(e) = validate_stack_home_preinstall(stack_home) {
            return stage_err("preflight", e);
        }
    }
    let bootstrap_req = pf.get("bootstrap_build_required").and_then(Value::as_bool).unwrap_or(false);

    if target_glob_rule.is_file() && !force_foreign
        && !fs::read_to_string(&target_glob_rule).unwrap_or_default().contains("Frontend UI/UX & Live Browser Verification Rules")
    {
        return stage_err(
            "conflict_check",
            format!("Existing user file {} was not created by Gemini Carbon Stack. Refusing blind overwrite (pass --force-foreign to replace after backup).", target_glob_rule.display()),
        );
    }

    let target_global_hooks = config_dir.join("hooks.json");
    let src_manifest = effective_source_manifest_for_target(&source_plugin_dir, Some(&target_plugin_dir), cfg!(windows));
    let hooks_prune = match plan_global_hooks_prune(config_dir, &target_plugin_dir, (!bootstrap_req).then_some(&src_manifest), cfg!(windows)) {
        Ok(p) => p,
        Err(e) => return stage_err("preflight", e),
    };
    let dst_manifest = tree_manifest(&target_plugin_dir);
    let src_rule_sha = sha256_file_full(&source_glob_rule).unwrap_or_default();
    let dst_rule_sha = if target_glob_rule.is_file() { sha256_file_full(&target_glob_rule).unwrap_or_default() } else { String::new() };

    let plugin_identical = !bootstrap_req && src_manifest == dst_manifest && !dst_manifest.is_empty() && has_executable_hook_mode_for_os(&target_plugin_dir, cfg!(windows));
    let rule_identical = !src_rule_sha.is_empty() && src_rule_sha == dst_rule_sha;
    let hooks_identical = hooks_prune.is_none();

    let mut planned_actions = Vec::new();
    if bootstrap_req {
        planned_actions.push(format!("build native hook binary -> {}", source_plugin_dir.join(platform_hook_binary_rel(cfg!(windows))).display()));
    }
    if !plugin_identical {
        planned_actions.push(format!(
            "{} plugin bundle -> {} ({} files)",
            if target_plugin_dir.exists() { "update" } else { "install" },
            target_plugin_dir.display(),
            src_manifest.len() + usize::from(bootstrap_req)
        ));
    }
    if !rule_identical {
        planned_actions.push(format!("{} glob rule -> {}", if target_glob_rule.exists() { "update" } else { "install" }, target_glob_rule.display()));
    }
    if let Some((_, cnt, _)) = &hooks_prune {
        planned_actions.push(format!("prune {} legacy tokenade hook entry(ies) -> {}", cnt, target_global_hooks.display()));
    }

    if dry_run {
        return json!({ "ok": true, "dry_run": true, "already_up_to_date": planned_actions.is_empty(), "planned_actions": planned_actions, "preflight": pf });
    }
    if plugin_identical && rule_identical && hooks_identical {
        ensure_state_subdirs(stack_home);
        sweep_all_retired_bins(&target_plugin_dir, stack_home, config_dir);
        let _ = prune_old_install_backups(stack_home, MAX_INSTALL_BACKUPS);
        return json!({
            "ok": true, "dry_run": false, "already_up_to_date": true, "backup_id": Value::Null,
            "installed_plugin_dir": target_plugin_dir.to_string_lossy(),
            "installed_glob_rule": target_glob_rule.to_string_lossy(),
            "files_count": src_manifest.len() + 1,
        });
    }

    let backup_meta = match create_backup(config_dir, stack_home) {
        Ok(m) => m,
        Err(e) => return stage_err("backup", e),
    };
    // INVARIANT: Bind global `hooks.json` publication to the exact backed-up SHA-256 and never restore `hooks.json` during compensation if install has not modified it.
    if let Some((_, _, ref planned_sha)) = hooks_prune {
        let bak_sha = backup_meta.pointer("/targets/global_hooks/sha256").and_then(Value::as_str);
        if bak_sha != Some(planned_sha.as_str()) {
            return stage_err(
                "prune_global_hooks",
                format!("Global {} changed concurrently before install; aborting without overwriting user edits", target_global_hooks.display()),
            );
        }
    }
    let backup_id_str = backup_meta.get("backup_id").and_then(Value::as_str).unwrap_or("").to_string();
    let fail_comp = |stage: &str, err: String, restore_hooks: bool| {
        let comp_ok = !backup_id_str.is_empty()
            && perform_rollback_internal(config_dir, stack_home, &backup_id_str, true, restore_hooks).get("ok").and_then(Value::as_bool) == Some(true);
        json!({ "ok": false, "stage": stage, "compensated_from_backup": comp_ok, "error": err })
    };

    if !plugin_identical {
        if let Err(e) = copy_clean_tree_additive_for_target(&source_plugin_dir, &target_plugin_dir, cfg!(windows), true) {
            return fail_comp("copy_plugin", e, false);
        }
        if let Err(e) = prune_stale_tree_entries(&source_plugin_dir, &target_plugin_dir, cfg!(windows), &retire_dirs) {
            return fail_comp("prune_legacy_plugin", e, false);
        }
    }
    if !rule_identical {
        if let Err(e) = atomic_copy_file(&source_glob_rule, &target_glob_rule) {
            return fail_comp("copy_rule", e, false);
        }
    }
    if let Some((rendered_hooks, _, planned_sha)) = hooks_prune {
        if let Err(e) = compare_and_replace_file(&target_global_hooks, &planned_sha, rendered_hooks.as_bytes()) {
            return fail_comp("prune_global_hooks", e, false);
        }
    }

    ensure_state_subdirs(stack_home);
    sweep_all_retired_bins(&target_plugin_dir, stack_home, config_dir);
    let _ = prune_old_install_backups(stack_home, MAX_INSTALL_BACKUPS);

    json!({
        "ok": true, "dry_run": false, "already_up_to_date": false,
        "backup_id": backup_meta.get("backup_id").cloned().unwrap_or(Value::Null),
        "installed_plugin_dir": target_plugin_dir.to_string_lossy(),
        "installed_glob_rule": target_glob_rule.to_string_lossy(),
        "files_count": src_manifest.len() + 1,
        "planned_actions": planned_actions,
    })
}

fn perform_rollback(config_dir: &Path, stack_home: &Path, backup_selector: &str) -> Value {
    perform_rollback_internal(config_dir, stack_home, backup_selector, false, true)
}

fn resolve_rollback_backup_dir(stack_home: &Path, backup_selector: &str) -> Result<PathBuf, Value> {
    let no_bak = || json!({ "ok": false, "error": format!("No backups found in {}", stack_home.join("backups").display()) });
    if backup_selector.is_empty() || backup_selector == "latest" {
        return list_backups_strict(stack_home).map_err(|e| json!({ "ok": false, "error": e }))?.pop().ok_or_else(no_bak);
    }
    // INVARIANT: Resolve explicit `--rollback <id>` directly so an unreadable sibling backup never blocks restoring a healthy ID.
    let broot = validate_backups_root_strict(stack_home).map_err(|e| json!({ "ok": false, "error": e }))?.ok_or_else(no_bak)?;
    let candidate = broot.join(backup_selector);
    let is_missing = !win32_sqlite::is_link_or_junction(&candidate)
        && matches!(fs::symlink_metadata(&candidate), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound);
    let valid = if is_missing { Ok(false) } else { validate_backup_entry_strict(&candidate) }.map_err(|e| json!({ "ok": false, "error": e }))?;
    if valid { Ok(candidate) } else { Err(json!({ "ok": false, "error": format!("Backup '{}' not found", backup_selector) })) }
}

fn perform_rollback_internal(config_dir: &Path, stack_home: &Path, backup_selector: &str, caller_holds_mutex: bool, restore_global_hooks: bool) -> Value {
    match perform_rollback_checked(config_dir, stack_home, backup_selector, caller_holds_mutex, restore_global_hooks) {
        Ok(v) | Err(v) => v,
    }
}

fn perform_rollback_checked(config_dir: &Path, stack_home: &Path, backup_selector: &str, caller_holds_mutex: bool, restore_global_hooks: bool) -> Result<Value, Value> {
    if !backup_selector.is_empty() && backup_selector != "latest" && !is_safe_backup_id(backup_selector) {
        return Err(json!({ "ok": false, "error": format!("Invalid backup id '{}'", backup_selector) }));
    }
    if validate_backups_root_strict(stack_home).map_err(|e| json!({ "ok": false, "error": e }))?.is_none() && !stack_home.exists() {
        return Err(json!({ "ok": false, "error": format!("No backups found in {}", stack_home.join("backups").display()) }));
    }
    validate_stack_home_preinstall(stack_home).map_err(|e| stage_err("rollback_link_check", e))?;
    if has_dot_components(config_dir) || win32_sqlite::is_link_or_junction(config_dir) {
        return Err(stage_err("rollback_link_check", format!("Refusing symlink/junction or traversal config_dir: {}", config_dir.display())));
    }
    if fs::symlink_metadata(config_dir).is_ok_and(|m| !m.file_type().is_dir()) {
        return Err(stage_err("rollback_validate", format!("Target config root is not a directory: {}", config_dir.display())));
    }
    let _inst_mutex = if caller_holds_mutex {
        None
    } else {
        Some(acquire_installer_mutex(config_dir, stack_home, Duration::from_secs(15)).map_err(|e| stage_err("installer_lock", e))?)
    };

    let state_root = stack_home.join("state");
    let (retired_state, retired_cfg) = (state_root.join(RETIRED_BINS_DIR_NAME), config_dir.join(RETIRED_BINS_DIR_NAME));
    let retire_dirs: [&Path; 2] = [&retired_state, &retired_cfg];
    recover_interrupted_stage_retire_dirs(config_dir, &retire_dirs).map_err(|e| stage_err("stage_retire_recovery", e))?;

    let chosen_dir = resolve_rollback_backup_dir(stack_home, backup_selector)?;
    let manifest = rio::read_json(&chosen_dir.join("manifest.json")).ok_or_else(|| json!({ "ok": false, "error": "Invalid backup manifest.json" }))?;
    let targets = manifest.get("targets");
    let (p_info, r_info, h_info) = (targets.and_then(|t| t.get("plugin_dir")), targets.and_then(|t| t.get("glob_rule")), targets.and_then(|t| t.get("global_hooks")));
    let (Some(p_existed), Some(r_existed)) = (
        p_info.and_then(|p| p.get("existed")).and_then(Value::as_bool),
        r_info.and_then(|r| r.get("existed")).and_then(Value::as_bool),
    ) else {
        return Err(stage_err("rollback_validate", "Invalid backup manifest.json: missing boolean `existed` flags"));
    };

    let (p_target, r_target, h_target) = (config_dir.join("plugins").join(PLUGIN_NAME), config_dir.join("rules").join("uiux-design.md"), config_dir.join("hooks.json"));
    let mp_raw = p_info.and_then(|p| p.get("path")).and_then(Value::as_str).unwrap_or("");
    let mr_raw = r_info.and_then(|r| r.get("path")).and_then(Value::as_str).unwrap_or("");
    if !matches_pinned_target_path(mp_raw, &p_target) || !matches_pinned_target_path(mr_raw, &r_target) {
        return Err(stage_err("rollback_validate", "Invalid backup manifest.json: target path mismatch"));
    }
    if let Some(err) = validate_target_hierarchy(config_dir, &p_target, &r_target).first() {
        return Err(stage_err("rollback_link_check", err));
    }
    let mut backup_links = Vec::new();
    collect_links_under_tree(&chosen_dir, &mut backup_links);
    if let Some(lnk) = backup_links.first() {
        return Err(stage_err("rollback_link_check", format!("Refusing backup containing symlink/junction: {}", lnk.display())));
    }
    if let Some(err) = validate_target_entry_types(config_dir, &p_target, &r_target, None, cfg!(windows)).first() {
        return Err(stage_err("rollback_validate", err));
    }

    let (p_backup, r_backup, h_backup) = (chosen_dir.join("plugin_dir"), chosen_dir.join("rules").join("uiux-design.md"), chosen_dir.join("global_hooks.json"));
    if p_existed {
        if !p_backup.is_dir() {
            return Err(stage_err("rollback_validate", format!("Incomplete backup: missing plugin snapshot {}", p_backup.display())));
        }
        let actual_hashes = tree_manifest_strict(&p_backup).map_err(|e| stage_err("rollback_validate", format!("Failed to read plugin snapshot: {}", e)))?;
        match p_info.and_then(|p| p.get("files_sha256")) {
            Some(Value::Object(raw_fmap)) => {
                let mut expected = BTreeMap::new();
                for (rel_k, sha_v) in raw_fmap {
                    let Some(sha_str) = sha_v.as_str().filter(|s| is_valid_sha256_hex(s)) else {
                        return Err(stage_err("rollback_validate", format!("Invalid SHA-256 digest for {}", rel_k)));
                    };
                    if rel_k.is_empty() || rel_k.starts_with('/') || has_dot_components(Path::new(rel_k)) {
                        return Err(stage_err("rollback_validate", format!("Invalid relative path in manifest: {}", rel_k)));
                    }
                    expected.insert(rel_k.clone(), sha_str.to_string());
                }
                if actual_hashes != expected {
                    return Err(stage_err("rollback_validate", "Corrupted backup: plugin snapshot SHA-256 inventory mismatch"));
                }
            }
            Some(_) => return Err(stage_err("rollback_validate", "Invalid backup manifest.json: malformed `files_sha256`")),
            None => validate_legacy_plugin_snapshot(&p_backup, Some(&p_target), &actual_hashes).map_err(|e| stage_err("rollback_validate", e))?,
        }
    }
    if r_existed {
        if let Some(ri) = r_info {
            verify_backup_file_sha(ri, &r_backup, "rule").map_err(|e| stage_err("rollback_validate", e))?;
        }
    }
    let mut restore_hooks_sha: Option<String> = None;
    if restore_global_hooks {
        if let Some(hi) = h_info {
            if !matches_pinned_target_path(hi.get("path").and_then(Value::as_str).unwrap_or(""), &h_target) {
                return Err(stage_err("rollback_validate", "Invalid backup manifest.json: global_hooks path mismatch"));
            }
            if let Some(hex) = hi.get("existed").and_then(Value::as_bool) {
                if hex {
                    restore_hooks_sha = Some(verify_backup_file_sha(hi, &h_backup, "global_hooks").map_err(|e| stage_err("rollback_validate", e))?);
                }
            } else if hi.get("migrations").and_then(Value::as_array).is_none() {
                return Err(stage_err("rollback_validate", "Invalid backup manifest.json: missing `global_hooks.existed`"));
            }
        }
    }

    let stage_root = state_root.join(format!("rb_stage_{}_{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos())));
    let pre_live_hashes = if p_target.is_dir() {
        let orig = tree_manifest_strict(&p_target).map_err(|e| stage_err("rollback_stage", format!("Inventory live plugin: {}", e)))?;
        let stage_plugin = stage_root.join("plugin_dir");
        if let Err(e) = copy_clean_tree_for_os(&p_target, &stage_plugin, true) {
            let _ = fs::remove_dir_all(&stage_root);
            return Err(stage_err("rollback_stage", format!("Stage live plugin: {}", e)));
        }
        if tree_manifest_strict(&stage_plugin).ok().as_ref() != Some(&orig) {
            let _ = fs::remove_dir_all(&stage_root);
            return Err(stage_err("rollback_stage", "Staged live plugin inventory mismatch"));
        }
        Some(orig)
    } else {
        None
    };
    let stage_one = |cond: bool, src: &Path, dst: PathBuf, label: &str| -> Result<Option<String>, Value> {
        if !cond { return Ok(None); }
        sha256_file_full(src)
            .and_then(|sha| atomic_copy_file(src, &dst).map(|()| Some(sha)))
            .map_err(|e| { let _ = fs::remove_dir_all(&stage_root); stage_err("rollback_stage", format!("Stage live {}: {}", label, e)) })
    };
    let pre_live_rule_sha = stage_one(r_target.is_file(), &r_target, stage_root.join("glob_rule.md"), "rule")?;
    let pre_live_hooks_sha = stage_one(h_target.is_file() && restore_hooks_sha.is_some(), &h_target, stage_root.join("global_hooks.json"), "hooks.json")?;
    let rb_stage = RollbackStage {
        expected_live_hashes: pre_live_hashes.as_ref(),
        expected_live_rule_sha: pre_live_rule_sha.as_deref(),
        expected_live_hooks_sha: pre_live_hooks_sha.as_deref(),
        stage_root: &stage_root,
        config_dir,
        retire_dirs: &retire_dirs,
    };

    if p_existed {
        if let Err(e) = copy_clean_tree_with_retire(&p_backup, &p_target, true, &retire_dirs) {
            return Err(compensate_rollback(&rb_stage, true, false, false, stage_err("rollback_plugin_restore", e)));
        }
    } else if p_target.exists() {
        if let Err(e) = remove_tree_or_retire_pe(&p_target, &retire_dirs) {
            return Err(compensate_rollback(&rb_stage, true, false, false, stage_err("rollback_plugin_remove", e.to_string())));
        }
    }
    if r_existed {
        if let Err(e) = atomic_copy_file(&r_backup, &r_target) {
            return Err(compensate_rollback(&rb_stage, true, true, false, stage_err("rollback_rule_copy", e)));
        }
    } else if r_target.exists() {
        if let Err(e) = fs::remove_file(&r_target) {
            return Err(compensate_rollback(&rb_stage, true, true, false, stage_err("rollback_rule_remove", format!("Failed to remove {}: {}", r_target.display(), e))));
        }
        if r_target.exists() {
            return Err(compensate_rollback(&rb_stage, true, true, false, stage_err("rollback_rule_remove", format!("Rule still exists: {}", r_target.display()))));
        }
    }
    if let Some(exp_h_sha) = restore_hooks_sha {
        if !(h_target.is_file() && sha256_file_full(&h_target).ok().as_deref() == Some(exp_h_sha.as_str())) {
            if let Err(e) = atomic_copy_file(&h_backup, &h_target) {
                return Err(compensate_rollback(&rb_stage, true, true, true, stage_err("rollback_hooks_restore", e)));
            }
        }
    }

    let _ = fs::remove_dir_all(&stage_root);
    sweep_all_retired_bins(&p_target, stack_home, config_dir);
    Ok(json!({
        "ok": true,
        "restored_backup_id": chosen_dir.file_name().and_then(|s| s.to_str()).unwrap_or(""),
        "plugin_dir_exists_now": p_target.exists(),
        "glob_rule_exists_now": r_target.exists(),
        "global_hooks_exists_now": h_target.exists(),
    }))
}

fn perform_diagnose_for_os(repo_root: &Path, config_dir: &Path, stack_home: &Path, is_windows: bool) -> Value {
    let pf = preflight_check_for_os_mode(repo_root, config_dir, is_windows, true);
    let (backups, backups_err) = match list_backups_strict(stack_home) {
        Ok(list) => (list.into_iter().filter_map(|p| p.file_name().and_then(|s| s.to_str()).map(str::to_string)).collect::<Vec<_>>(), None),
        Err(e) => (Vec::new(), Some(e)),
    };
    let (source_plugin_dir, source_glob_rule) = (repo_root.join("plugin"), repo_root.join("rules").join("uiux-design.md"));
    let (target_plugin_dir, target_glob_rule) = (config_dir.join("plugins").join(PLUGIN_NAME), config_dir.join("rules").join("uiux-design.md"));
    let binary_path = target_plugin_dir.join(platform_hook_binary_rel(is_windows));

    let src_manifest = effective_source_manifest_for_target(&source_plugin_dir, Some(&target_plugin_dir), is_windows);
    let plugin_trees_match = target_plugin_dir.is_dir() && src_manifest == tree_manifest(&target_plugin_dir);
    let hooks_clean = plan_global_hooks_prune(config_dir, &target_plugin_dir, Some(&src_manifest), is_windows).is_ok_and(|m| m.is_none());
    let in_sync = plugin_trees_match
        && has_executable_hook_mode_for_os(&target_plugin_dir, is_windows)
        && hooks_clean
        && target_glob_rule.is_file()
        && sha256_file_full(&source_glob_rule).ok() == sha256_file_full(&target_glob_rule).ok();

    let bundle_for_doctor = if target_plugin_dir.is_dir() { &target_plugin_dir } else { &source_plugin_dir }.to_string_lossy().into_owned();
    let reused_agy_val = (!target_plugin_dir.is_dir() || plugin_trees_match)
        .then(|| pf.get("agy_validation").and_then(|av| {
            (av.get("ran").and_then(Value::as_bool) == Some(true)).then(|| (
                av.get("ok").and_then(Value::as_bool).unwrap_or(false),
                av.get("output").and_then(Value::as_str).unwrap_or("").to_string(),
            ))
        }))
        .flatten();
    let allow_unbuilt = !target_plugin_dir.is_dir() && pf.get("bootstrap_build_required").and_then(Value::as_bool) == Some(true);
    let doctor_out = stack_doctor::collect_doctor_report_for_os(
        &repo_root.to_string_lossy(),
        Some(bundle_for_doctor.as_str()),
        false,
        reused_agy_val,
        is_windows,
        allow_unbuilt,
    );
    let pf_ok = pf.get("ok").and_then(Value::as_bool).unwrap_or(false);
    let doc_ok = doctor_out.get("ok").and_then(Value::as_bool).unwrap_or(true);
    let orphaned = list_orphaned_stage_retire_dirs(config_dir);

    let mut out = json!({
        "ok": pf_ok && doc_ok && backups_err.is_none() && orphaned.is_empty(),
        "installed": target_plugin_dir.is_dir(),
        "in_sync_with_source": in_sync && orphaned.is_empty(),
        "installed_plugin_dir": target_plugin_dir.to_string_lossy(),
        "binary_path": binary_path.to_string_lossy(),
        "backups_count": backups.len(),
        "latest_backup": backups.last().cloned(),
        "preflight": pf,
        "doctor": doctor_out,
    });
    if !orphaned.is_empty() { out["interrupted_stage_retire_dirs"] = json!(orphaned); }
    if let Some(err) = backups_err { out["backups_error"] = Value::String(err); }
    out
}

#[derive(Default)]
struct CliOpts {
    dry_run: bool,
    diagnose: bool,
    list_backups: bool,
    has_rollback: bool,
    rollback_sel: String,
    force_foreign: bool,
    repo_root: String,
    config_dir: String,
    stack_home: String,
    pretty: bool,
    help: bool,
}

fn missing_flag_err(flag: &str, detail: String) -> Option<Value> {
    Some(json!({ "ok": false, "error": "missing_flag_value", "flag": flag, "detail": detail }))
}

fn parse_cli(args: &[String], o: &mut CliOpts) -> Result<(), Option<Value>> {
    let take_val = |flag: &str, idx: &mut usize| -> Result<String, Option<Value>> {
        let next = args.get(*idx + 1).map(String::as_str).ok_or_else(|| missing_flag_err(flag, format!("Argument '{}' requires a value", flag)))?;
        if next.trim().is_empty() || next.starts_with('-') {
            return Err(missing_flag_err(flag, format!("Argument '{}' requires a non-flag value, got '{}'", flag, next)));
        }
        *idx += 1;
        Ok(next.to_string())
    };
    let non_empty_eq = |flag: &str, raw: &str| -> Result<String, Option<Value>> {
        if raw.trim().is_empty() {
            Err(missing_flag_err(flag, format!("Argument '{}' requires a non-empty value", flag)))
        } else {
            Ok(raw.to_string())
        }
    };
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--dry-run" => o.dry_run = true,
            "--diagnose" => o.diagnose = true,
            "--list-backups" => o.list_backups = true,
            "--force" | "--force-foreign" => o.force_foreign = true,
            "--pretty" => o.pretty = true,
            "--json" => {}
            "--help" | "-h" => { o.help = true; return Ok(()); }
            "--rollback" => {
                o.has_rollback = true;
                if let Some(next) = args.get(i + 1).filter(|s| !s.starts_with('-')) {
                    if next.trim().is_empty() {
                        return Err(Some(json!({ "ok": false, "error": "missing_flag_value", "flag": "--rollback" })));
                    }
                    o.rollback_sel = next.clone();
                    i += 1;
                } else {
                    o.rollback_sel = "latest".to_string();
                }
            }
            "--repo-root" => o.repo_root = take_val(a, &mut i)?,
            "--target-config-dir" | "--config-dir" => o.config_dir = take_val(a, &mut i)?,
            "--stack-home" => o.stack_home = take_val(a, &mut i)?,
            _ if a.starts_with("--rollback=") => {
                o.has_rollback = true;
                o.rollback_sel = non_empty_eq("--rollback", &a["--rollback=".len()..])?;
            }
            _ if a.starts_with("--repo-root=") => o.repo_root = non_empty_eq("--repo-root", &a["--repo-root=".len()..])?,
            _ if a.starts_with("--target-config-dir=") => o.config_dir = non_empty_eq("--target-config-dir", &a["--target-config-dir=".len()..])?,
            _ if a.starts_with("--config-dir=") => o.config_dir = non_empty_eq("--config-dir", &a["--config-dir=".len()..])?,
            _ if a.starts_with("--stack-home=") => o.stack_home = non_empty_eq("--stack-home", &a["--stack-home=".len()..])?,
            other => {
                eprintln!("carbon-stack install: unknown argument '{}'", other);
                return Err(None);
            }
        }
        i += 1;
    }
    Ok(())
}

pub fn run_cli(args: &[String]) -> i32 {
    let mut o = CliOpts::default();
    if let Err(err_opt) = parse_cli(args, &mut o) {
        if let Some(v) = err_opt {
            rio::print_cli_json(&v, o.pretty);
        }
        return 2;
    }
    if o.help {
        println!(
            "usage: carbon-stack install [--dry-run] [--diagnose] [--list-backups] [--rollback [latest|<id>]] [--force|--force-foreign] [--repo-root <dir>] [--config-dir <dir>] [--target-config-dir <dir>] [--stack-home <dir>] [--json] [--pretty]"
        );
        return 0;
    }
    let non_install = usize::from(o.diagnose) + usize::from(o.list_backups) + usize::from(o.has_rollback);
    if non_install > 1 || (non_install == 1 && (o.dry_run || o.force_foreign)) {
        rio::print_cli_json(
            &json!({
                "ok": false,
                "error": "conflicting_mode_flags",
                "detail": "--diagnose, --list-backups, and --rollback are mutually exclusive and cannot be combined with --dry-run or --force-foreign",
            }),
            o.pretty,
        );
        return 2;
    }

    let repo_root = resolve_repo_root(&o.repo_root);
    let (config_dir, stack_home) = resolve_paths(&o.config_dir, &o.stack_home);
    let res = if o.diagnose {
        perform_diagnose_for_os(&repo_root, &config_dir, &stack_home, cfg!(windows))
    } else if o.list_backups {
        match list_backups_strict(&stack_home) {
            Ok(list) => {
                let backups: Vec<String> = list.into_iter().filter_map(|p| p.file_name().and_then(|s| s.to_str()).map(str::to_string)).collect();
                json!({ "ok": true, "backups_count": backups.len(), "backups": backups, "latest_backup": backups.last().cloned() })
            }
            Err(e) => json!({ "ok": false, "error": "backups_read_failed", "detail": e }),
        }
    } else if o.has_rollback {
        perform_rollback(&config_dir, &stack_home, &o.rollback_sel)
    } else {
        perform_install(&repo_root, &config_dir, &stack_home, o.dry_run, o.force_foreign)
    };
    rio::print_cli_json(&res, o.pretty);
    if res.get("ok").and_then(Value::as_bool) == Some(true) { 0 } else { 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDirGuard(PathBuf);
    impl TempDirGuard {
        fn new(label: &str) -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(1);
            let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let p = env::temp_dir().join(format!("agy-inst-{}-{}-{}-{}", label, std::process::id(), nanos, seq));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn platform_stub_bin_bytes() -> &'static [u8] {
        if cfg!(windows) { b"MZ\x90\x00stub-hook-bin" } else { b"\x7fELFstub-hook-bin" }
    }

    fn make_valid_repo(root: &Path, with_bin: bool) {
        fs::create_dir_all(root.join("plugin").join("rules")).unwrap();
        fs::create_dir_all(root.join("plugin").join("bin")).unwrap();
        fs::create_dir_all(root.join("rules")).unwrap();
        fs::write(
            root.join("plugin").join("plugin.json"),
            r#"{"name":"gemini-carbon-stack","version":"0.2.0"}"#,
        )
        .unwrap();
        fs::write(
            root.join("plugin").join("hooks.json"),
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
        fs::write(root.join("plugin").join("rules").join("AGENTS.md"), "# Constitution\n").unwrap();
        fs::write(
            root.join("rules").join("uiux-design.md"),
            "# Frontend UI/UX & Live Browser Verification Rules\n",
        )
        .unwrap();
        if with_bin {
            let bin_rel = platform_hook_binary_rel(cfg!(windows));
            fs::write(root.join("plugin").join(bin_rel), platform_stub_bin_bytes()).unwrap();
        }
    }

    #[test]
    fn test_install_idempotent_stale_prune_foreign_conflict_and_rollback() {
        let tmp = TempDirGuard::new("full");
        let (repo, cfg, shome) = (tmp.0.join("repo"), tmp.0.join("config"), tmp.0.join("stack-home"));
        make_valid_repo(&repo, false);

        let missing_bin = perform_install(&repo, &cfg, &shome, false, false);
        assert_eq!(missing_bin["ok"], false);
        assert_eq!(missing_bin["stage"], "preflight");

        let bin_rel = platform_hook_binary_rel(cfg!(windows));
        fs::write(repo.join("plugin").join(bin_rel), platform_stub_bin_bytes()).unwrap();

        let dry = perform_install(&repo, &cfg, &shome, true, false);
        assert_eq!(dry["ok"], true);
        assert_eq!(dry["dry_run"], true);
        assert_eq!(dry["already_up_to_date"], false);
        assert!(!cfg.join("plugins").join(PLUGIN_NAME).exists());

        let inst1 = perform_install(&repo, &cfg, &shome, false, false);
        assert_eq!(inst1["ok"], true, "{:?}", inst1);
        assert_eq!(inst1["already_up_to_date"], false);
        assert!(cfg.join("plugins").join(PLUGIN_NAME).join("plugin.json").is_file());
        assert!(cfg.join("rules").join("uiux-design.md").is_file());

        // Stale files left in target plugin dir are pruned on update.
        let stale_py = cfg.join("plugins").join(PLUGIN_NAME).join("hooks").join("legacy.py");
        fs::create_dir_all(stale_py.parent().unwrap()).unwrap();
        fs::write(&stale_py, "# legacy\n").unwrap();
        assert_eq!(perform_install(&repo, &cfg, &shome, false, false)["ok"], true);
        assert!(!stale_py.exists());

        let inst_idem = perform_install(&repo, &cfg, &shome, false, false);
        assert_eq!(inst_idem["ok"], true);
        assert_eq!(inst_idem["already_up_to_date"], true);

        // Foreign `uiux-design.md` protected unless `--force-foreign` is passed, and restored on rollback.
        fs::write(cfg.join("rules").join("uiux-design.md"), "# Custom Foreign Rule\n").unwrap();
        let blocked = perform_install(&repo, &cfg, &shome, false, false);
        assert_eq!(blocked["ok"], false);
        assert_eq!(blocked["stage"], "conflict_check");

        let forced = perform_install(&repo, &cfg, &shome, false, true);
        assert_eq!(forced["ok"], true);
        let b_id = forced["backup_id"].as_str().unwrap().to_string();
        assert_eq!(perform_rollback(&cfg, &shome, &b_id)["ok"], true);
        assert!(fs::read_to_string(cfg.join("rules").join("uiux-design.md"))
            .unwrap()
            .contains("Custom Foreign Rule"));

        // Custom `--target-config-dir` with spaces quotes absolute Windows hook binary path cleanly.
        let (cfg_sp, shome_sp) = (tmp.0.join("cfg with spaces"), tmp.0.join("shome-spaces"));
        assert_eq!(perform_install(&repo, &cfg_sp, &shome_sp, false, true)["ok"], true);
        assert_eq!(perform_install(&repo, &cfg_sp, &shome_sp, false, true)["already_up_to_date"], true);
        if cfg!(windows) {
            let htxt = fs::read_to_string(cfg_sp.join("plugins").join(PLUGIN_NAME).join("hooks.json")).unwrap();
            assert!(htxt.contains("cfg with spaces") && htxt.contains("\\\""));
        }
    }

    #[test]
    fn test_os_normalization_pe_elf_and_posix_exec_modes() {
        let tmp = TempDirGuard::new("os-norm");
        let (repo, cfg) = (tmp.0.join("repo"), tmp.0.join("config"));
        make_valid_repo(&repo, false);

        fs::write(
            repo.join("plugin").join("hooks.json"),
            r#"{"carbon-stack":{"SessionStart":[{"type":"command","command":"bin\\carbon-stack.exe hook --event SessionStart"}]}}"#,
        )
        .unwrap();
        fs::write(repo.join("plugin").join("bin").join("carbon-stack"), b"MZ\x90\x00pe").unwrap();
        assert_eq!(preflight_check_for_os_mode(&repo, &cfg, false, false)["ok"], false);

        fs::write(repo.join("plugin").join("bin").join("carbon-stack.exe"), b"\x7fELFnot-pe").unwrap();
        assert_eq!(preflight_check_for_os_mode(&repo, &cfg, true, false)["ok"], false);

        fs::write(repo.join("plugin").join("bin").join("carbon-stack"), b"\x7fELFnative-unix").unwrap();
        let unix_dst = tmp.0.join("unix-dst");
        copy_clean_tree_for_os(&repo.join("plugin"), &unix_dst, false).unwrap();
        let unix_hooks = fs::read_to_string(unix_dst.join("hooks.json")).unwrap();
        assert!(unix_hooks.contains("bin/carbon-stack hook --event SessionStart"));
        assert!(!unix_hooks.contains(".exe"));
        assert!(!unix_dst.join("bin").join("carbon-stack.exe").exists());
        assert_eq!(
            effective_source_manifest_for_target(&repo.join("plugin"), None, false),
            tree_manifest(&unix_dst)
        );

        assert!(!mode_is_owner_executable(0o650));
        assert!(mode_is_owner_executable(0o750));
        assert_eq!(ensure_owner_exec_mode_bits(0o650), 0o750);
        assert_eq!(ensure_owner_exec_mode_bits(0o600), 0o700);
        assert_eq!(ensure_owner_exec_mode_bits(0o644), 0o755);
        assert!(!posix_dac_mode_allows_exec(0o650, 1000, 1000, 1000, &[1000]));
        assert!(posix_dac_mode_allows_exec(0o750, 1000, 1000, 1000, &[1000]));
        assert!(posix_dac_mode_allows_exec(0o750, 1000, 2000, 1001, &[2000]));
        assert!(!posix_dac_mode_allows_exec(0o750, 1000, 2000, 1001, &[3000]));
        assert!(posix_dac_mode_allows_exec(0o755, 1000, 2000, 1001, &[3000]));

        let (perm_src, perm_dst) = (tmp.0.join("perm-src.txt"), tmp.0.join("perm-dst.txt"));
        fs::write(&perm_src, b"secret-rule").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut p = fs::metadata(&perm_src).unwrap().permissions();
            p.set_mode(0o600);
            fs::set_permissions(&perm_src, p).unwrap();
            atomic_copy_file(&perm_src, &perm_dst).unwrap();
            assert_eq!(fs::metadata(&perm_dst).unwrap().permissions().mode() & 0o777, 0o600);
        }
        #[cfg(windows)]
        {
            let mut p = fs::metadata(&perm_src).unwrap().permissions();
            p.set_readonly(true);
            fs::set_permissions(&perm_src, p).unwrap();
            atomic_copy_file(&perm_src, &perm_dst).unwrap();
            assert!(fs::metadata(&perm_dst).unwrap().permissions().readonly());
            let mut clear = fs::metadata(&perm_src).unwrap().permissions();
            clear.set_readonly(false);
            let _ = fs::set_permissions(&perm_src, clear.clone());
            let _ = fs::set_permissions(&perm_dst, clear);
        }
    }

    #[test]
    fn test_symlink_junction_traversal_and_entry_type_refusal() {
        let tmp = TempDirGuard::new("safety");
        let repo = tmp.0.join("repo");
        make_valid_repo(&repo, true);

        let cfg = tmp.0.join("config");
        fs::create_dir_all(&cfg).unwrap();
        assert!(ensure_no_links_between(&cfg, &cfg).is_err());
        assert!(ensure_no_links_between(&cfg, &cfg.join("plugins").join("..")).is_err());

        let (cfg_bad_rule, shome_bad) = (tmp.0.join("cfg-bad-rule"), tmp.0.join("shome-bad"));
        fs::create_dir_all(cfg_bad_rule.join("rules").join("uiux-design.md")).unwrap();
        assert_eq!(perform_install(&repo, &cfg_bad_rule, &shome_bad, false, true)["stage"], "preflight");

        let cfg_bad_plug = tmp.0.join("cfg-bad-plug");
        fs::create_dir_all(cfg_bad_plug.join("plugins")).unwrap();
        fs::write(cfg_bad_plug.join("plugins").join(PLUGIN_NAME), "not-a-dir").unwrap();
        assert_eq!(perform_install(&repo, &cfg_bad_plug, &shome_bad, false, true)["stage"], "preflight");

        let (cfg_rb, shome_rb) = (tmp.0.join("config-rb"), tmp.0.join("stack-rb"));
        let first_inst = perform_install(&repo, &cfg_rb, &shome_rb, false, true);
        let first_bid = first_inst["backup_id"].as_str().unwrap().to_string();
        let rule_path = cfg_rb.join("rules").join("uiux-design.md");
        fs::remove_file(&rule_path).unwrap();
        fs::create_dir_all(rule_path.join("subdir")).unwrap();
        let failed_rb = perform_rollback(&cfg_rb, &shome_rb, &first_bid);
        assert_eq!(failed_rb["ok"], false);
        assert_eq!(failed_rb["stage"], "rollback_validate");
        assert!(cfg_rb.join("plugins").join(PLUGIN_NAME).join("plugin.json").is_file());
        let _ = fs::remove_dir_all(&rule_path);

        let mf_path = shome_rb.join("backups").join(&first_bid).join("manifest.json");
        let mut tampered = rio::read_json(&mf_path).unwrap();
        tampered["targets"]["plugin_dir"]["path"] = json!(cfg_rb.to_string_lossy());
        rio::write_json(&mf_path, &tampered).unwrap();
        assert_eq!(perform_rollback(&cfg_rb, &shome_rb, &first_bid)["stage"], "rollback_validate");

        #[cfg(windows)]
        {
            use std::process::Command;
            let (cfg_j, shome_j, outside) = (
                tmp.0.join("config-junc"),
                tmp.0.join("stack-junc"),
                tmp.0.join("outside-victim"),
            );
            fs::create_dir_all(&outside).unwrap();
            let junc_parent = cfg_j.join("plugins").join(PLUGIN_NAME);
            fs::create_dir_all(&junc_parent).unwrap();
            let junc_bin = junc_parent.join("bin");
            assert!(Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&junc_bin)
                .arg(&outside)
                .output()
                .unwrap()
                .status
                .success());
            assert_eq!(perform_install(&repo, &cfg_j, &shome_j, false, true)["stage"], "preflight");
            assert!(copy_clean_tree_for_os(&repo.join("plugin"), &junc_parent, true).is_err());
            assert!(fs::read_dir(&outside).unwrap().next().is_none());
            let _ = fs::remove_dir(&junc_bin);

            let ret_victim = tmp.0.join("ret-victim");
            fs::create_dir_all(&ret_victim).unwrap();
            fs::write(ret_victim.join("retired-keep.exe"), b"keep").unwrap();
            let ret_junc = tmp.0.join("ret-host").join(RETIRED_BINS_DIR_NAME);
            fs::create_dir_all(ret_junc.parent().unwrap()).unwrap();
            assert!(Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&ret_junc)
                .arg(&ret_victim)
                .output()
                .unwrap()
                .status
                .success());
            assert!(prepare_retired_slot(&ret_junc, Path::new("carbon-stack.exe")).is_err());
            assert!(ret_victim.join("retired-keep.exe").is_file());
            let _ = fs::remove_dir(&ret_junc);
        }
    }

    #[test]
    fn test_rollback_validation_legacy_backup_and_explicit_selector() {
        let tmp = TempDirGuard::new("rb-val");
        let (repo, cfg, shome) = (tmp.0.join("repo"), tmp.0.join("config"), tmp.0.join("stack-home"));
        make_valid_repo(&repo, true);

        assert_eq!(perform_install(&repo, &cfg, &shome, false, true)["ok"], true);
        fs::write(repo.join("plugin").join("rules").join("AGENTS.md"), "# Constitution v2\n").unwrap();
        let upd = perform_install(&repo, &cfg, &shome, false, true);
        let bid = upd["backup_id"].as_str().unwrap().to_string();

        let bin_rel = platform_hook_binary_rel(cfg!(windows));
        let bak_bin = shome.join("backups").join(&bid).join("plugin_dir").join(bin_rel);
        let saved_bin = fs::read(&bak_bin).unwrap();
        fs::remove_file(&bak_bin).unwrap();
        assert_eq!(perform_rollback(&cfg, &shome, &bid)["stage"], "rollback_validate");
        fs::write(&bak_bin, &saved_bin).unwrap();

        let mf_path = shome.join("backups").join(&bid).join("manifest.json");
        let mut leg_mf = rio::read_json(&mf_path).unwrap();
        leg_mf["targets"]["plugin_dir"].as_object_mut().unwrap().remove("files_sha256");
        leg_mf["targets"]["glob_rule"].as_object_mut().unwrap().remove("sha256");
        rio::write_json(&mf_path, &leg_mf).unwrap();
        assert_eq!(perform_rollback(&cfg, &shome, &bid)["ok"], true);

        fs::remove_file(&bak_bin).unwrap();
        assert_eq!(perform_rollback(&cfg, &shome, &bid)["stage"], "rollback_validate");
        fs::write(&bak_bin, &saved_bin).unwrap();

        let bad_newest = shome.join("backups").join("install-99991231-235959");
        fs::create_dir_all(bad_newest.join("manifest.json")).unwrap();
        assert_eq!(perform_rollback(&cfg, &shome, "latest")["ok"], false);
        assert_eq!(perform_rollback(&cfg, &shome, &bid)["ok"], true);
        let _ = fs::remove_dir_all(&bad_newest);

        // User hooks created AFTER install are preserved when backup had `global_hooks.existed == false`.
        rio::write_json(
            &cfg.join("hooks.json"),
            &json!({"notebooklm-project-memory":{"enabled":true,"Stop":[{"type":"command","command":"custom-post-stop"}]}}),
        )
        .unwrap();
        assert_eq!(perform_rollback(&cfg, &shome, &bid)["ok"], true);
        assert!(fs::read_to_string(cfg.join("hooks.json")).unwrap().contains("custom-post-stop"));
    }

    #[test]
    fn test_global_hooks_pruner_and_rollback_regression() {
        let tmp = TempDirGuard::new("hooks-prune");
        let (repo, cfg, shome) = (tmp.0.join("repo"), tmp.0.join("config"), tmp.0.join("stack-home"));
        make_valid_repo(&repo, true);
        fs::create_dir_all(&cfg).unwrap();

        let target_plug = cfg.join("plugins").join(PLUGIN_NAME);
        let py_hook_path = target_plug
            .join("hooks")
            .join("tokenade_hook.py")
            .to_string_lossy()
            .replace('\\', "/");
        let bin_hook_path = target_plug
            .join(platform_hook_binary_rel(cfg!(windows)))
            .to_string_lossy()
            .into_owned();

        assert!(!is_legacy_managed_tokenade_command("python /opt/custom/tokenade_hook.py", &cfg, &target_plug, false));
        assert!(!is_legacy_managed_tokenade_command("my-wrapper && python hooks/tokenade_hook.py", &cfg, &target_plug, cfg!(windows)));
        assert!(!is_legacy_managed_tokenade_command(&format!("\"{}\" hook --event PreToolUse", bin_hook_path), &cfg, &target_plug, cfg!(windows)));
        assert!(is_legacy_managed_tokenade_command(&format!("PYTHON \"{}\"", py_hook_path.to_uppercase()), &cfg, &target_plug, true));
        assert!(is_legacy_managed_tokenade_command("carbon-stack tokenade-hook --event PreToolUse", &cfg, &target_plug, true));
        // Codex C1b #4: unambiguous shell wrappers around managed legacy tokenade commands MUST be recognized & pruned.
        assert!(is_legacy_managed_tokenade_command(&format!("sh -c \"python '{}'\"", py_hook_path), &cfg, &target_plug, false));
        assert!(is_legacy_managed_tokenade_command("cmd /c \"carbon-stack tokenade-hook --event PreToolUse\"", &cfg, &target_plug, true));
        assert!(is_legacy_managed_tokenade_command(&format!("pwsh -NoProfile -Command \"& '{}' tokenade-hook --event PreToolUse\"", bin_hook_path.replace('\\', "/")), &cfg, &target_plug, true));
        assert!(is_legacy_managed_tokenade_command(&format!("$null | & '{}' tokenade-hook --event PreToolUse", bin_hook_path.replace('\\', "/")), &cfg, &target_plug, true));
        assert!(!is_legacy_managed_tokenade_command(&format!("sh -c \"echo keep && python '{}'\"", py_hook_path), &cfg, &target_plug, false));

        let orig_hooks_str = format!(
            "{}\n",
            serde_json::to_string_pretty(&json!({
                "notebooklm-project-memory": {
                    "enabled": true,
                    "Stop": [{"type": "command", "command": "custom-nlm-stop", "timeout": 20}]
                },
                "custom-team-hooks": {
                    "enabled": true,
                    "PreToolUse": [{
                        "matcher": "run_command",
                        "hooks": [
                            {"type": "command", "command": format!("\"{}\" tokenade-hook --event PreToolUse", bin_hook_path), "timeout": 10},
                            {"type": "command", "command": "my-custom-lint --strict", "timeout": 15}
                        ]
                    }]
                },
                "tokenade": {
                    "enabled": true,
                    "PreToolUse": [{
                        "matcher": "run_command",
                        "hooks": [{"type": "command", "command": format!("python \"{}\"", py_hook_path), "timeout": 15}]
                    }]
                }
            }))
            .unwrap()
        );
        let hooks_path = cfg.join("hooks.json");
        fs::write(&hooks_path, &orig_hooks_str).unwrap();

        let inst = perform_install(&repo, &cfg, &shome, false, true);
        assert_eq!(inst["ok"], true, "{:?}", inst);
        let bid = inst["backup_id"].as_str().unwrap().to_string();

        let after_txt = fs::read_to_string(&hooks_path).unwrap();
        assert!(!after_txt.contains("tokenade_hook.py"), "{}", after_txt);
        assert!(!after_txt.contains("tokenade-hook"), "{}", after_txt);
        let after_val: Value = serde_json::from_str(&after_txt).unwrap();
        assert!(after_val.get("tokenade").is_none());
        assert_eq!(after_val["notebooklm-project-memory"]["Stop"][0]["command"], "custom-nlm-stop");
        assert_eq!(after_val["custom-team-hooks"]["PreToolUse"][0]["hooks"].as_array().unwrap().len(), 1);
        assert_eq!(after_val["custom-team-hooks"]["PreToolUse"][0]["hooks"][0]["command"], "my-custom-lint --strict");

        // Do NOT rewrite `hooks.json` when nothing was pruned.
        let custom_fmt = "{\"notebooklm-project-memory\":{\"enabled\":true,\"Stop\":[{\"type\":\"command\",\"command\":\"custom-nlm-stop\"}]}}";
        fs::write(&hooks_path, custom_fmt).unwrap();
        let inst2 = perform_install(&repo, &cfg, &shome, false, true);
        assert_eq!(inst2["ok"], true);
        assert_eq!(inst2["already_up_to_date"], true);
        assert_eq!(fs::read_to_string(&hooks_path).unwrap(), custom_fmt);

        // Corrupted backed-up `global_hooks.json` fails rollback closed at `rollback_validate`.
        let bak_hooks = shome.join("backups").join(&bid).join("global_hooks.json");
        let saved_bak_hooks = fs::read(&bak_hooks).unwrap();
        fs::write(&bak_hooks, b"tampered").unwrap();
        assert_eq!(perform_rollback(&cfg, &shome, &bid)["stage"], "rollback_validate");
        fs::write(&bak_hooks, &saved_bak_hooks).unwrap();

        // Rollback restores pre-install `hooks.json` byte-for-byte.
        let rb = perform_rollback(&cfg, &shome, &bid);
        assert_eq!(rb["ok"], true, "{:?}", rb);
        assert_eq!(fs::read_to_string(&hooks_path).unwrap(), orig_hooks_str);

        // Codex C1b #4: unpruned compound/custom reference to a plugin file absent from incoming manifest MUST fail closed BEFORE deleting plugin files.
        let custom_plugin_script = target_plug.join("hooks").join("custom_user.py");
        fs::create_dir_all(custom_plugin_script.parent().unwrap()).unwrap();
        fs::write(&custom_plugin_script, "print('keep')\n").unwrap();
        let dangling_hooks = json!({
            "user-group": {
                "enabled": true,
                "PreToolUse": [{"type": "command", "command": format!("python \"{}\"", custom_plugin_script.to_string_lossy().replace('\\', "/")), "timeout": 10}]
            }
        });
        fs::write(&hooks_path, serde_json::to_string_pretty(&dangling_hooks).unwrap()).unwrap();
        let blocked = perform_install(&repo, &cfg, &shome, false, true);
        assert_eq!(blocked["ok"], false, "dangling plugin hook ref must fail closed: {:?}", blocked);
        assert_eq!(blocked["stage"], "preflight");
        assert!(custom_plugin_script.is_file(), "install must fail before pruning referenced plugin script");
        let _ = fs::remove_file(&custom_plugin_script);

        // Codex C1b #1 & #8: compare_and_replace_file swaps crash-atomically and restores user edits untouched if hooks.json changed concurrently; compensation rollback with `restore_global_hooks = false` also preserves newer user edits.
        let newer_user_hooks = "{\"user-new\":{\"enabled\":true,\"Stop\":[{\"type\":\"command\",\"command\":\"echo keep-new\"}]}}\n";
        fs::write(&hooks_path, newer_user_hooks).unwrap();
        let cas_err = compare_and_replace_file(&hooks_path, "0000000000000000000000000000000000000000000000000000000000000000", b"{}\n").unwrap_err();
        assert!(cas_err.contains("changed concurrently"), "{}", cas_err);
        assert_eq!(fs::read_to_string(&hooks_path).unwrap(), newer_user_hooks);
        let comp_rb = perform_rollback_internal(&cfg, &shome, &bid, false, false);
        assert_eq!(comp_rb["ok"], true, "{:?}", comp_rb);
        assert_eq!(fs::read_to_string(&hooks_path).unwrap(), newer_user_hooks);

        // Codex C1b R2 #4, #7 & R3 #4, #7: compound unpruned `tokenade-hook` AND `cd ... && python ../plugins/gemini-carbon-stack/hooks/tokenade_hook.py` MUST fail closed, while a Cyrillic other-profile path `/home/иван/plugins/gemini-carbon-stack/hooks/audit.py` MUST NOT panic or block install!
        let compound_tok = json!({
            "u": { "PreToolUse": [{"type": "command", "command": format!("echo hi && \"{}\" tokenade-hook --event PreToolUse", bin_hook_path.replace('\\', "/")), "timeout": 10}] }
        });
        fs::write(&hooks_path, serde_json::to_string_pretty(&compound_tok).unwrap()).unwrap();
        let blk_tok = perform_install(&repo, &cfg, &shome, false, true);
        assert_eq!(blk_tok["ok"], false, "compound tokenade-hook must fail closed: {:?}", blk_tok);
        let parent_rel_tok = json!({
            "u": { "PreToolUse": [{"type": "command", "command": format!("sh -c \"cd '{}/rules' && python ../plugins/gemini-carbon-stack/hooks/tokenade_hook.py\"", cfg.to_string_lossy().replace('\\', "/")), "timeout": 10}] }
        });
        fs::write(&hooks_path, serde_json::to_string_pretty(&parent_rel_tok).unwrap()).unwrap();
        let blk_rel = perform_install(&repo, &cfg, &shome, false, true);
        assert_eq!(blk_rel["ok"], false, "relative ../plugins/gemini-carbon-stack/hooks/tokenade_hook.py must fail closed: {:?}", blk_rel);
        // Codex C1b Closure #4 & #7: quoted path WITH SPACES targeting THIS profile MUST fail closed, while `cd '/other-profile/.gemini/config/rules' && python ../plugins/gemini-carbon-stack/hooks/audit.py` and Cyrillic `/home/иван/plugins/...` MUST be allowed!
        let spaced_cfg = tmp.0.join("Users").join("Jane Doe").join(".gemini").join("config");
        let spaced_plug = spaced_cfg.join("plugins").join(PLUGIN_NAME);
        let spaced_audit = spaced_plug.join("hooks").join("audit.py");
        let spaced_hooks = json!({
            "u": { "PreToolUse": [{"type": "command", "command": format!("python \"{}\"", spaced_audit.to_string_lossy().replace('\\', "/")), "timeout": 10}] }
        });
        let src_mf = effective_source_manifest_for_target(&repo.join("plugin"), Some(&spaced_plug), cfg!(windows));
        assert_eq!(
            find_dangling_plugin_hook_ref(&spaced_hooks, &spaced_cfg, &spaced_plug, Some(&src_mf), cfg!(windows)).as_deref(),
            Some("hooks/audit.py"),
            "quoted path with spaces targeting this profile must be caught"
        );
        // Codex C1b Closure #4 & #7: multiline `sh -c "cd ...\npython ../plugins/..."` MUST fail closed, AND Windows Cyrillic path `C:/Users/Анна/...` MUST NOT panic on `%userprofile%/` prefix check!
        let multiline_rel = json!({
            "u": { "PreToolUse": [{"type": "command", "command": format!("sh -c \"cd '{}/rules'\npython ../plugins/gemini-carbon-stack/hooks/tokenade_hook.py\"", cfg.to_string_lossy().replace('\\', "/")), "timeout": 10}] }
        });
        assert_eq!(
            find_dangling_plugin_hook_ref(&multiline_rel, &cfg, &target_plug, Some(&src_mf), cfg!(windows)).as_deref(),
            Some("hooks/tokenade_hook.py"),
            "multiline sh -c with cd + relative ../plugins must fail closed"
        );
        let win_cyr_hooks = json!({
            "win-cyr": { "PreToolUse": [{"type": "command", "command": "python \"C:/Users/Анна/.gemini/config/plugins/gemini-carbon-stack/hooks/audit.py\"", "timeout": 10}] }
        });
        assert_eq!(
            find_dangling_plugin_hook_ref(
                &win_cyr_hooks,
                Path::new("C:/Users/Анна/.gemini/config"),
                Path::new("C:/Users/Анна/.gemini/config/plugins/gemini-carbon-stack"),
                Some(&src_mf),
                true,
            ).as_deref(),
            Some("hooks/audit.py"),
            "Windows Cyrillic path must not panic and must catch target-profile dangling ref"
        );
        let other_cd_hooks = json!({
            "other-cd": { "PreToolUse": [{"type": "command", "command": "sh -c \"cd '/other-profile/.gemini/config/rules' && python ../plugins/gemini-carbon-stack/hooks/audit.py\"", "timeout": 10}] },
            "other-cyrillic": { "PreToolUse": [{"type": "command", "command": "python \"/home/иван/plugins/gemini-carbon-stack/hooks/audit.py\"", "timeout": 10}] },
            "other-win-cyr": { "PreToolUse": [{"type": "command", "command": "python \"C:/Users/Анна/.gemini/config/plugins/gemini-carbon-stack/hooks/audit.py\"", "timeout": 10}] }
        });
        fs::write(&hooks_path, serde_json::to_string_pretty(&other_cd_hooks).unwrap()).unwrap();
        let ok_other = perform_install(&repo, &cfg, &shome, false, true);
        assert_eq!(ok_other["ok"], true, "other-profile cd ../ and Cyrillic paths must not block install: {:?}", ok_other);
    }

    #[test]
    fn test_diagnose_agy_validate_and_cli_flags() {
        let tmp = TempDirGuard::new("diag-cli");
        let repo = tmp.0.join("clean-posix-repo");
        fs::create_dir_all(repo.join("plugin").join("rules")).unwrap();
        fs::create_dir_all(repo.join("plugin").join("agents")).unwrap();
        fs::create_dir_all(repo.join("plugin").join("bin")).unwrap();
        fs::create_dir_all(repo.join("rules")).unwrap();
        fs::create_dir_all(repo.join("rust")).unwrap();
        fs::write(
            repo.join("plugin").join("plugin.json"),
            r#"{"name":"gemini-carbon-stack","displayName":"Gemini Carbon Stack","version":"1.0.0"}"#,
        )
        .unwrap();
        fs::write(
            repo.join("plugin").join("hooks.json"),
            r#"{"carbon-stack":{
                "SessionStart":[{"type":"command","command":"bin/carbon-stack hook --event SessionStart"}],
                "PreInvocation":[{"type":"command","command":"bin/carbon-stack hook --event PreInvocation"}],
                "PreToolUse":[{"matcher":"read_file|run_command|invoke_subagent|swarm|swarm_wait|read_board|post_message|edit_file|write_file","hooks":[{"type":"command","command":"bin/carbon-stack hook --event PreToolUse"}]}],
                "PostToolUse":[{"matcher":"edit_file|write_file|run_command","hooks":[{"type":"command","command":"bin/carbon-stack hook --event PostToolUse"}]}],
                "Stop":[{"type":"command","command":"bin/carbon-stack hook --event Stop"}]
            }}"#,
        )
        .unwrap();
        fs::write(repo.join("plugin").join("bin").join("carbon-stack.exe"), b"MZ\x90\x00win-only").unwrap();
        for sname in [
            "swarm-orchestration", "s-two", "s-three", "s-four", "s-five",
            "s-six", "s-seven", "s-eight", "s-nine", "s-ten",
        ] {
            let sdir = repo.join("plugin").join("skills").join(sname);
            fs::create_dir_all(&sdir).unwrap();
            fs::write(
                sdir.join("SKILL.md"),
                format!("---\nname: {}\ndescription: Skill {}\n---\n# {}\n", sname, sname, sname),
            )
            .unwrap();
        }
        for aname in ["a-one", "a-two", "a-three", "a-four"] {
            fs::write(
                repo.join("plugin").join("agents").join(format!("{}.md", aname)),
                format!("---\nname: {}\ndescription: Agent {}\n---\nPrompt.\n", aname, aname),
            )
            .unwrap();
        }
        fs::write(repo.join("plugin").join("rules").join("AGENTS.md"), "# Constitution\n").unwrap();
        fs::write(
            repo.join("rules").join("uiux-design.md"),
            "# Frontend UI/UX & Live Browser Verification Rules\n",
        )
        .unwrap();
        fs::write(
            repo.join("rust").join("Cargo.toml"),
            "[package]\nname = \"carbon-stack\"\nversion = \"0.2.0\"\n",
        )
        .unwrap();

        let (ok_missing_agy, msg_missing_agy) = run_agy_plugin_validate(
            &tmp.0.join("missing-agy-binary.exe").to_string_lossy(),
            &repo.join("plugin"),
            1_000,
        );
        assert!(!ok_missing_agy && !msg_missing_agy.is_empty());

        let (cfg, shome) = (tmp.0.join("cfg-posix"), tmp.0.join("shome-posix"));
        assert_eq!(preflight_check_for_os_mode(&repo, &cfg, false, false)["ok"], false);
        let pf_dry = preflight_check_for_os_mode(&repo, &cfg, false, true);
        assert_eq!(pf_dry["ok"], true, "{}", pf_dry);
        assert_eq!(pf_dry["bootstrap_build_required"], true);

        let diag = perform_diagnose_for_os(&repo, &cfg, &shome, false);
        assert_eq!(diag["ok"], true, "{}", diag);
        assert_eq!(diag["installed"], false);
        assert!(diag["installed_plugin_dir"].as_str().unwrap().contains(PLUGIN_NAME));
        assert!(diag["binary_path"].as_str().unwrap().ends_with("carbon-stack"));

        let cfg_broken = tmp.0.join("cfg-broken");
        let broken_plug = cfg_broken.join("plugins").join(PLUGIN_NAME);
        copy_clean_tree_for_os(&repo.join("plugin"), &broken_plug, false).unwrap();
        let _ = fs::remove_file(broken_plug.join("bin").join("carbon-stack"));
        let diag_broken = perform_diagnose_for_os(&repo, &cfg_broken, &shome, false);
        assert_eq!(diag_broken["installed"], true);
        assert_eq!(diag_broken["ok"], false);

        assert_eq!(run_cli(&["--help".to_string()]), 0);
        assert_eq!(run_cli(&["--dry-run".to_string(), "--rollback".to_string()]), 2);
        assert_eq!(run_cli(&["--diagnose".to_string(), "--rollback".to_string()]), 2);
        assert_eq!(run_cli(&["--repo-root".to_string(), "--dry-run".to_string()]), 2);
        assert_eq!(
            run_cli(&[
                "--list-backups".to_string(),
                "--json".to_string(),
                "--stack-home".to_string(),
                shome.to_string_lossy().into_owned(),
            ]),
            0
        );
    }

    #[test]
    fn test_sweep_retired_bins_and_auto_heal_cleans_plugin_bin_dir() {
        let tmp = TempDirGuard::new("sweep-retired");
        let (cfg, shome) = (tmp.0.join("config"), tmp.0.join("stack-home"));
        let plugin_ret = cfg.join("plugins").join(PLUGIN_NAME).join("bin").join(RETIRED_BINS_DIR_NAME);
        let state_ret = shome.join("state").join(RETIRED_BINS_DIR_NAME);
        let cfg_ret = cfg.join(RETIRED_BINS_DIR_NAME);
        for (dir, fname) in [
            (&plugin_ret, "retired-1-carbon-stack.exe"),
            (&state_ret, "retired-2-carbon-stack.exe"),
            (&cfg_ret, "retired-3-carbon-stack.exe"),
        ] {
            fs::create_dir_all(dir).unwrap();
            fs::write(dir.join(fname), b"old-pe").unwrap();
        }
        assert!(list_orphaned_stage_retire_dirs(&cfg).is_empty());
        try_auto_heal_stage_retire_for_paths(&cfg, &shome);
        assert!(!plugin_ret.exists() && !state_ret.exists() && !cfg_ret.exists());

        let orphan_stage = cfg.join(format!("{}999-1-1", STAGE_RETIRE_PREFIX));
        fs::create_dir_all(orphan_stage.join("files").join("rules")).unwrap();
        fs::write(orphan_stage.join("files").join("rules").join("recovered.md"), "# ok\n").unwrap();
        rio::write_json(
            &orphan_stage.join(STAGE_RETIRE_JOURNAL_NAME),
            &json!({"version": 1, "pid": 999, "mode": "prune", "phase": "contracting", "sentinel_hooks": false}),
        )
        .unwrap();
        assert_eq!(list_orphaned_stage_retire_dirs(&cfg).len(), 1);
        try_auto_heal_stage_retire_for_paths(&cfg, &shome);
        assert!(!orphan_stage.exists());
        assert!(cfg.join("plugins").join(PLUGIN_NAME).join("rules").join("recovered.md").is_file());

        let direct_ret = tmp.0.join("direct").join(RETIRED_BINS_DIR_NAME);
        fs::create_dir_all(&direct_ret).unwrap();
        fs::write(direct_ret.join("retired-9-carbon-stack.exe"), b"old-pe").unwrap();
        sweep_retired_bins_dir(&direct_ret);
        assert!(!direct_ret.exists());

        let partial_ret = tmp.0.join("partial").join(RETIRED_BINS_DIR_NAME);
        let kept_sub = partial_ret.join("keep-subdir");
        fs::create_dir_all(&kept_sub).unwrap();
        fs::write(partial_ret.join("unlocked.exe"), b"old-pe").unwrap();
        sweep_retired_bins_dir(&partial_ret);
        assert!(!partial_ret.join("unlocked.exe").exists() && kept_sub.is_dir() && partial_ret.is_dir());
    }

    #[test]
    fn test_prune_old_install_backups_keeps_newest_and_preserves_other_dirs() {
        let tmp = TempDirGuard::new("prune-backups");
        let shome = tmp.0.join("stack-home");
        let broot = shome.join("backups");
        fs::create_dir_all(&broot).unwrap();

        let valid_manifest = |legacy: bool| -> String {
            if legacy {
                r#"{"targets":{"plugin_dir":{"path":"/cfg/plugins/gemini-carbon-stack","existed":false},"glob_rule":{"path":"/cfg/rules/uiux-design.md","existed":false},"global_hooks":{"path":"/cfg/hooks.json","existed":false}}}"#.to_string()
            } else {
                r#"{"targets":{"plugin_dir":{"path":"/cfg/plugins/gemini-carbon-stack","existed":false},"glob_rule":{"path":"/cfg/rules/uiux-design.md","existed":false},"global_hooks":{"path":"/cfg/hooks.json","migrations":[]}}}"#.to_string()
            }
        };
        for day in 1..=14u32 {
            let bdir = broot.join(format!("install-202611{:02}-120000", day));
            fs::create_dir_all(&bdir).unwrap();
            fs::write(bdir.join("manifest.json"), valid_manifest(day <= 2)).unwrap();
        }
        let incomplete_dir = broot.join("install-20261199-235959");
        fs::create_dir_all(&incomplete_dir).unwrap();
        let corrupt_dir = broot.join("install-20261198-235959");
        fs::create_dir_all(&corrupt_dir).unwrap();
        fs::write(corrupt_dir.join("manifest.json"), "{\"targets\":{\"plugin_dir\":").unwrap();
        let schema_bad_dir = broot.join("install-20261197-235959");
        fs::create_dir_all(&schema_bad_dir).unwrap();
        fs::write(schema_bad_dir.join("manifest.json"), "{}\n").unwrap();
        let manual_dir = broot.join("manual-snapshot");
        fs::create_dir_all(&manual_dir).unwrap();
        fs::write(manual_dir.join("keep.txt"), "do-not-delete\n").unwrap();
        let stray_file = broot.join("install-not-a-dir.txt");
        fs::write(&stray_file, "file\n").unwrap();

        assert_eq!(prune_old_install_backups(&shome, MAX_INSTALL_BACKUPS), 4);
        for day in 1..=4u32 {
            assert!(!broot.join(format!("install-202611{:02}-120000", day)).exists());
        }
        for day in 5..=14u32 {
            assert!(broot.join(format!("install-202611{:02}-120000", day)).is_dir());
        }
        assert!(incomplete_dir.is_dir() && corrupt_dir.is_dir() && schema_bad_dir.is_dir());
        assert!(manual_dir.join("keep.txt").is_file() && stray_file.is_file());
        assert_eq!(prune_old_install_backups(&shome, MAX_INSTALL_BACKUPS), 0);

        // `already_up_to_date` install path must still rotate excess valid backups.
        let (repo_up, cfg_up, shome_up) = (tmp.0.join("repo-up"), tmp.0.join("cfg-up"), tmp.0.join("shome-up"));
        make_valid_repo(&repo_up, true);
        let first_up = perform_install(&repo_up, &cfg_up, &shome_up, false, true);
        assert_eq!(first_up["ok"], true, "{:?}", first_up);
        let broot_up = shome_up.join("backups");
        for day in 1..=12u32 {
            let bdir = broot_up.join(format!("install-202501{:02}-000000", day));
            fs::create_dir_all(&bdir).unwrap();
            fs::write(bdir.join("manifest.json"), valid_manifest(false)).unwrap();
        }
        assert!(list_backups_strict(&shome_up).unwrap().len() > MAX_INSTALL_BACKUPS);
        let second_up = perform_install(&repo_up, &cfg_up, &shome_up, false, false);
        assert_eq!(second_up["ok"], true, "{:?}", second_up);
        assert_eq!(second_up["already_up_to_date"], true);
        assert_eq!(list_backups_strict(&shome_up).unwrap().len(), MAX_INSTALL_BACKUPS);
    }
}
