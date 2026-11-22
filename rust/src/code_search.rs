use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::{Regex, RegexBuilder};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::rio;
use crate::win32_sqlite::{is_link_or_junction, run_command_with_job};

pub const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
    ".next",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
];

pub const DEFAULT_WINDOWS_RG_PATH: &str =
    "C:/tools/ripgrep-15.1.0-x86_64-pc-windows-msvc/ripgrep-15.1.0-x86_64-pc-windows-msvc/rg.exe";

const MAX_SCAN_FILES: usize = 5000;
const MAX_TEXT_FILE_BYTES: u64 = 1_500_000;
const MAX_SYMBOL_FILE_BYTES: u64 = 1_000_000;

fn polyglot_symbol_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^\s*(?:export\s+)?(?:default\s+)?(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?(?P<kind>function|class|interface|type|enum|struct|trait|impl|fn|func|def)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
        )
        .expect("polyglot_symbol_re")
    })
}

fn python_symbol_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(?P<indent>[ \t]*)(?:async\s+)?(?P<kind>def|class)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")
            .expect("python_symbol_re")
    })
}

pub fn which_in_path(name: &str) -> Option<String> {
    rio::which_in_path(name)
}

pub fn find_jev() -> Option<String> {
    for name in ["jev", "jev.exe", "jev.cmd"] {
        if let Some(found) = which_in_path(name) {
            return Some(found);
        }
    }
    None
}

fn find_rg_under_prefix(parent: &Path, dir_prefix: &str, max_depth: usize) -> Option<String> {
    if !parent.is_dir() {
        return None;
    }
    let prefix_low = dir_prefix.to_ascii_lowercase();
    let Ok(entries) = fs::read_dir(parent) else {
        return None;
    };
    let mut matching_dirs: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|s| s.to_str())
                    .map_or(false, |n| n.to_ascii_lowercase().starts_with(&prefix_low))
        })
        .collect();
    // INVARIANT: Sort descending so newer versioned ripgrep directories take precedence.
    matching_dirs.sort_by(|a, b| b.cmp(a));

    for root_dir in matching_dirs {
        let mut stack: Vec<(PathBuf, usize)> = vec![(root_dir, 0)];
        while let Some((dir, depth)) = stack.pop() {
            let direct = dir.join("rg.exe");
            if direct.is_file() {
                return Some(direct.to_string_lossy().into_owned());
            }
            if depth >= max_depth {
                continue;
            }
            let Ok(sub_entries) = fs::read_dir(&dir) else {
                continue;
            };
            let mut sub_dirs: Vec<PathBuf> = sub_entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir() && !is_link_or_junction(p))
                .collect();
            sub_dirs.sort();
            for sd in sub_dirs {
                stack.push((sd, depth + 1));
            }
        }
    }
    None
}

pub fn _resolve_rg_binary() -> Option<String> {
    // INVARIANT: Resolve ripgrep in exact priority: env override -> PATH -> known Windows install locations.
    for env_key in ["RIPGREP_PATH", "CARBON_RG_BIN"] {
        if let Ok(val) = env::var(env_key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() && Path::new(trimmed).is_file() {
                return Some(trimmed.to_string());
            }
        }
    }

    for name in ["rg", "rg.exe"] {
        if let Some(on_path) = which_in_path(name) {
            return Some(on_path);
        }
    }

    #[cfg(windows)]
    {
        let home = rio::home_dir();
        let local_app = env::var("LOCALAPPDATA").unwrap_or_default();
        let mut fixed_candidates: Vec<PathBuf> = vec![
            PathBuf::from(DEFAULT_WINDOWS_RG_PATH),
            home.join("scoop").join("apps").join("ripgrep").join("current").join("rg.exe"),
            home.join("scoop").join("shims").join("rg.exe"),
            home.join(".cargo").join("bin").join("rg.exe"),
            PathBuf::from("C:/Program Files/ripgrep/rg.exe"),
        ];
        if !local_app.trim().is_empty() {
            fixed_candidates.push(
                PathBuf::from(local_app.trim())
                    .join("Microsoft")
                    .join("WinGet")
                    .join("Links")
                    .join("rg.exe"),
            );
        }
        for cand in fixed_candidates {
            if cand.is_file() {
                return Some(cand.to_string_lossy().into_owned());
            }
        }
        if let Some(found) = find_rg_under_prefix(Path::new("C:/tools"), "ripgrep", 3) {
            return Some(found);
        }
        if !local_app.trim().is_empty() {
            let winget_pkgs = PathBuf::from(local_app.trim())
                .join("Microsoft")
                .join("WinGet")
                .join("Packages");
            if let Some(found) = find_rg_under_prefix(&winget_pkgs, "BurntSushi.ripgrep", 4) {
                return Some(found);
            }
        }
    }

    None
}

pub fn find_rg() -> Option<String> {
    _resolve_rg_binary()
}

#[derive(Debug, Clone)]
pub struct SearchOptions {
    pub pattern: String,
    pub cwd: String,
    pub limit: usize,
    pub fixed: bool,
    pub ext: String,
    pub globs: Vec<String>,
    pub case_sensitive: bool,
    pub ignore_case: bool,
    pub context: usize,
    pub files_with_matches: bool,
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            pattern: String::new(),
            cwd: String::new(),
            limit: 60,
            fixed: false,
            ext: String::new(),
            globs: Vec::new(),
            case_sensitive: false,
            ignore_case: false,
            context: 0,
            files_with_matches: false,
        }
    }
}

struct GlobFilter {
    includes: Option<GlobSet>,
    excludes: Option<GlobSet>,
}

impl GlobFilter {
    fn from_globs(globs: &[String]) -> Result<Self, String> {
        let mut inc_builder = GlobSetBuilder::new();
        let mut exc_builder = GlobSetBuilder::new();
        let mut has_inc = false;
        let mut has_exc = false;

        for raw in globs {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(neg) = trimmed.strip_prefix('!') {
                if neg.is_empty() {
                    continue;
                }
                let glob = Glob::new(neg).map_err(|e| format!("invalid glob '{}': {}", raw, e))?;
                exc_builder.add(glob);
                has_exc = true;
            } else {
                let glob = Glob::new(trimmed).map_err(|e| format!("invalid glob '{}': {}", raw, e))?;
                inc_builder.add(glob);
                has_inc = true;
            }
        }

        let includes = if has_inc {
            Some(inc_builder.build().map_err(|e| format!("globset build failed: {}", e))?)
        } else {
            None
        };
        let excludes = if has_exc {
            Some(exc_builder.build().map_err(|e| format!("globset build failed: {}", e))?)
        } else {
            None
        };
        Ok(Self { includes, excludes })
    }

    fn matches(&self, rel_slash: &str, file_name: &str) -> bool {
        if let Some(ref exc) = self.excludes {
            if exc.is_match(rel_slash) || exc.is_match(file_name) {
                return false;
            }
        }
        if let Some(ref inc) = self.includes {
            return inc.is_match(rel_slash) || inc.is_match(file_name);
        }
        true
    }
}

fn parse_ext_set(glob_ext: &str) -> HashSet<String> {
    glob_ext
        .split(',')
        .map(|e| e.trim().to_ascii_lowercase())
        .filter(|e| !e.is_empty())
        .map(|e| if e.starts_with('.') { e } else { format!(".{}", e) })
        .collect()
}

pub fn iter_source_files(root: &Path, glob_ext: &str) -> Vec<PathBuf> {
    iter_source_files_filtered(root, glob_ext, None)
}

fn iter_source_files_filtered(
    root: &Path,
    glob_ext: &str,
    glob_filter: Option<&GlobFilter>,
) -> Vec<PathBuf> {
    let exts = parse_ext_set(glob_ext);
    let mut found: Vec<PathBuf> = Vec::new();
    if root.is_file() {
        found.push(root.to_path_buf());
        return found;
    }
    let abs_root = if root.as_os_str().is_empty() {
        env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    } else {
        root.to_path_buf()
    };

    let skip_set: HashSet<&str> = SKIP_DIRS.iter().copied().collect();
    let mut stack: Vec<PathBuf> = vec![abs_root.clone()];

    while let Some(cur) = stack.pop() {
        if found.len() >= MAX_SCAN_FILES {
            break;
        }
        let Ok(rd) = fs::read_dir(&cur) else {
            continue;
        };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            if found.len() >= MAX_SCAN_FILES {
                break;
            }
            let p = entry.path();
            if is_link_or_junction(&p) {
                continue;
            }
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_dir() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !skip_set.contains(name.as_str()) {
                    stack.push(p);
                }
            } else if ft.is_file() {
                if !exts.is_empty() {
                    let suf = p
                        .extension()
                        .and_then(|s| s.to_str())
                        .map(|s| format!(".{}", s.to_ascii_lowercase()))
                        .unwrap_or_default();
                    if !exts.contains(&suf) {
                        continue;
                    }
                }
                if let Some(gf) = glob_filter {
                    let rel = rel_slash_path(&p, &abs_root);
                    let fname = p
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("");
                    if !gf.matches(&rel, fname) {
                        continue;
                    }
                }
                found.push(p);
            }
        }
    }
    found
}

fn rel_slash_path(path: &Path, root: &Path) -> String {
    match path.strip_prefix(root) {
        Ok(rel) => rel.to_string_lossy().replace('\\', "/"),
        Err(_) => path.to_string_lossy().replace('\\', "/"),
    }
}

fn format_line_snippet(line: &str) -> String {
    line.trim().chars().take(200).collect()
}

pub fn text_search_with_options(opts: &SearchOptions) -> Value {
    let root_path = if opts.cwd.trim().is_empty() {
        env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    } else {
        fs::canonicalize(opts.cwd.trim()).unwrap_or_else(|_| PathBuf::from(opts.cwd.trim()))
    };
    let root_str = root_path.to_string_lossy().into_owned();
    let jev_bin = find_jev();
    let rg_bin = find_rg();
    let limit = opts.limit.max(1);

    if let Some(ref rg) = rg_bin {
        let mut cmd: Vec<String> = vec![
            "--line-number".to_string(),
            "--no-heading".to_string(),
            "--color=never".to_string(),
            "--max-count".to_string(),
            limit.to_string(),
        ];
        if opts.fixed {
            cmd.push("--fixed-strings".to_string());
        }
        if opts.case_sensitive {
            cmd.push("--case-sensitive".to_string());
        } else if opts.ignore_case {
            cmd.push("--ignore-case".to_string());
        }
        if opts.files_with_matches {
            cmd.push("--files-with-matches".to_string());
        }
        if opts.context > 0 && !opts.files_with_matches {
            cmd.push("--context".to_string());
            cmd.push(opts.context.to_string());
        }
        if !opts.ext.is_empty() {
            for e in opts.ext.split(',') {
                let clean = e.trim().trim_start_matches('.');
                if !clean.is_empty() {
                    cmd.push("-g".to_string());
                    cmd.push(format!("*.{}", clean));
                }
            }
        }
        for g in &opts.globs {
            let trimmed = g.trim();
            if !trimmed.is_empty() {
                cmd.push("-g".to_string());
                cmd.push(trimmed.to_string());
            }
        }
        cmd.push(opts.pattern.clone());
        cmd.push(root_str.clone());

        if let Ok(res) = run_command_with_job(rg, &cmd, None, &[], None, Some(10_000)) {
            if !res.timed_out && (res.code == 0 || res.code == 1) {
                let out = res.stdout_str();
                let lines: Vec<String> = out
                    .lines()
                    .filter(|ln| !ln.trim().is_empty())
                    .take(limit)
                    .map(|ln| ln.to_string())
                    .collect();
                return json!({
                    "engine": "ripgrep",
                    "jev_available": jev_bin.is_some(),
                    "count": lines.len(),
                    "matches": lines,
                });
            }
        }
    }

    // INVARIANT: Use `git grep` inside git repositories only when ripgrep-specific globs are absent.
    if opts.globs.is_empty() {
        if let Some(_git_root) = rio::git_toplevel(&root_str, false) {
            let mut g_args: Vec<String> = vec![
                "grep".to_string(),
                "-n".to_string(),
                "-I".to_string(),
                "--no-color".to_string(),
                if opts.fixed { "-F" } else { "-E" }.to_string(),
            ];
            if opts.ignore_case && !opts.case_sensitive {
                g_args.push("-i".to_string());
            }
            if opts.files_with_matches {
                g_args.push("-l".to_string());
            }
            if opts.context > 0 && !opts.files_with_matches {
                g_args.push("-C".to_string());
                g_args.push(opts.context.to_string());
            }
            g_args.push(opts.pattern.clone());
            if !opts.ext.is_empty() {
                g_args.push("--".to_string());
                for e in opts.ext.split(',') {
                    let clean = e.trim().trim_start_matches('.');
                    if !clean.is_empty() {
                        g_args.push(format!("*.{}", clean));
                    }
                }
            }
            let arg_refs: Vec<&str> = g_args.iter().map(String::as_str).collect();
            let (rc, out, _) = rio::run_git(&root_str, &arg_refs, 8.0);
            if rc == 0 || rc == 1 {
                let lines: Vec<String> = out
                    .lines()
                    .filter(|ln| !ln.trim().is_empty())
                    .take(limit)
                    .map(|ln| ln.to_string())
                    .collect();
                return json!({
                    "engine": "git-grep",
                    "jev_available": jev_bin.is_some(),
                    "count": lines.len(),
                    "matches": lines,
                });
            }
        }
    }

    rust_fallback_search(&root_path, opts, jev_bin.is_some())
}

pub fn rust_fallback_search(root_path: &Path, opts: &SearchOptions, jev_available: bool) -> Value {
    let limit = opts.limit.max(1);
    let glob_filter = match GlobFilter::from_globs(&opts.globs) {
        Ok(gf) => gf,
        Err(err) => {
            return json!({
                "engine": "rust-scan",
                "jev_available": jev_available,
                "error": err,
                "count": 0,
                "matches": [],
            });
        }
    };

    let pat_src = if opts.fixed {
        regex::escape(&opts.pattern)
    } else {
        opts.pattern.clone()
    };
    let case_insensitive = !opts.case_sensitive;
    let rx = match RegexBuilder::new(&pat_src)
        .case_insensitive(case_insensitive)
        .build()
    {
        Ok(r) => r,
        Err(err) => {
            return json!({
                "engine": "rust-scan",
                "jev_available": jev_available,
                "error": format!("invalid_regex: {}", err),
                "count": 0,
                "matches": [],
            });
        }
    };

    let mut matches: Vec<String> = Vec::new();
    let files = iter_source_files_filtered(root_path, &opts.ext, Some(&glob_filter));
    for fpath in files {
        if matches.len() >= limit {
            break;
        }
        let Ok(meta) = fs::metadata(&fpath) else {
            continue;
        };
        if meta.len() > MAX_TEXT_FILE_BYTES {
            continue;
        }
        let Ok(raw_bytes) = fs::read(&fpath) else {
            continue;
        };
        // INVARIANT: Skip binary files containing NUL bytes during pure-Rust fallback scan.
        if raw_bytes.contains(&0) {
            continue;
        }
        let text = String::from_utf8_lossy(&raw_bytes);
        let rel = rel_slash_path(&fpath, root_path);
        let lines: Vec<&str> = text.lines().collect();

        if opts.files_with_matches {
            if lines.iter().any(|ln| rx.is_match(ln)) {
                matches.push(rel);
            }
            continue;
        }

        if opts.context > 0 {
            let mut emitted: HashSet<usize> = HashSet::new();
            for (idx, ln) in lines.iter().enumerate() {
                if !rx.is_match(ln) {
                    continue;
                }
                let start = idx.saturating_sub(opts.context);
                let end = (idx + opts.context).min(lines.len().saturating_sub(1));
                for cidx in start..=end {
                    if emitted.insert(cidx) {
                        let sep = if cidx == idx { ':' } else { '-' };
                        matches.push(format!(
                            "{}:{}{}{}",
                            rel,
                            cidx + 1,
                            sep,
                            format_line_snippet(lines[cidx])
                        ));
                        if matches.len() >= limit {
                            break;
                        }
                    }
                }
                if matches.len() >= limit {
                    break;
                }
            }
        } else {
            for (idx, ln) in lines.iter().enumerate() {
                if rx.is_match(ln) {
                    matches.push(format!("{}:{}:{}", rel, idx + 1, format_line_snippet(ln)));
                    if matches.len() >= limit {
                        break;
                    }
                }
            }
        }
    }

    json!({
        "engine": "rust-scan",
        "jev_available": jev_available,
        "count": matches.len(),
        "matches": matches,
    })
}

fn indent_width(indent: &str) -> usize {
    indent
        .chars()
        .map(|c| if c == '\t' { 4 } else { 1 })
        .sum()
}

fn compute_python_block_end(lines: &[&str], start_idx: usize, base_indent: usize) -> usize {
    let mut last_body_idx = start_idx;
    for (offset, raw) in lines.iter().enumerate().skip(start_idx + 1) {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let leading_len = raw.len() - raw.trim_start_matches([' ', '\t']).len();
        let cur_indent = indent_width(&raw[..leading_len]);
        if cur_indent <= base_indent {
            break;
        }
        last_body_idx = offset;
    }
    last_body_idx + 1
}

pub fn symbol_search(query: &str, cwd: &str, limit: usize) -> Value {
    let root_path = if cwd.trim().is_empty() {
        env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    } else {
        fs::canonicalize(cwd.trim()).unwrap_or_else(|_| PathBuf::from(cwd.trim()))
    };
    let q_low = query.trim().to_ascii_lowercase();
    let max_hits = limit.max(1);
    let mut hits: Vec<Value> = Vec::new();

    for fpath in iter_source_files(&root_path, ".py,.ts,.tsx,.js,.jsx,.mjs,.go,.rs") {
        if hits.len() >= max_hits {
            break;
        }
        let Ok(meta) = fs::metadata(&fpath) else {
            continue;
        };
        if meta.len() > MAX_SYMBOL_FILE_BYTES {
            continue;
        }
        let Ok(raw_bytes) = fs::read(&fpath) else {
            continue;
        };
        if raw_bytes.contains(&0) {
            continue;
        }
        let src = String::from_utf8_lossy(&raw_bytes);
        let rel = rel_slash_path(&fpath, &root_path);
        let ext = fpath
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();

        if ext == "py" {
            let lines: Vec<&str> = src.lines().collect();
            for (idx, ln) in lines.iter().enumerate() {
                if let Some(caps) = python_symbol_re().captures(ln) {
                    let sname = caps.name("name").map_or("", |m| m.as_str());
                    if q_low.is_empty() || sname.to_ascii_lowercase().contains(&q_low) {
                        let raw_kind = caps.name("kind").map_or("def", |m| m.as_str());
                        let kind = if raw_kind == "class" { "class" } else { "def" };
                        let base_indent =
                            indent_width(caps.name("indent").map_or("", |m| m.as_str()));
                        let end_line = compute_python_block_end(&lines, idx, base_indent);
                        hits.push(json!({
                            "kind": kind,
                            "name": sname,
                            "file": rel,
                            "start_line": idx + 1,
                            "end_line": end_line,
                        }));
                        if hits.len() >= max_hits {
                            return json!({ "count": hits.len(), "symbols": hits });
                        }
                    }
                }
            }
            continue;
        }

        for (idx, ln) in src.lines().enumerate() {
            if let Some(caps) = polyglot_symbol_re().captures(ln) {
                let sname = caps.name("name").map_or("", |m| m.as_str());
                if q_low.is_empty() || sname.to_ascii_lowercase().contains(&q_low) {
                    let kind = caps.name("kind").map_or("", |m| m.as_str());
                    hits.push(json!({
                        "kind": kind,
                        "name": sname,
                        "file": rel,
                        "start_line": idx + 1,
                    }));
                    if hits.len() >= max_hits {
                        return json!({ "count": hits.len(), "symbols": hits });
                    }
                }
            }
        }
    }

    json!({ "count": hits.len(), "symbols": hits })
}

fn eprintln_line(msg: &str) {
    let mut err = std::io::stderr().lock();
    let _ = writeln!(err, "{}", msg);
}

fn take_flag_value(args: &[String], idx: &mut usize, prefix: &str) -> Result<Option<String>, String> {
    let tok = &args[*idx];
    if tok == prefix {
        if *idx + 1 >= args.len() {
            return Err(format!("missing value for {}", prefix));
        }
        *idx += 1;
        return Ok(Some(args[*idx].clone()));
    }
    let eq_prefix = format!("{}=", prefix);
    if let Some(val) = tok.strip_prefix(&eq_prefix) {
        return Ok(Some(val.to_string()));
    }
    Ok(None)
}

fn parse_grep_args(args: &[String]) -> Result<(SearchOptions, bool), String> {
    let mut opts = SearchOptions::default();
    let mut pretty = false;
    let mut positionals: Vec<String> = Vec::new();
    let mut i = 0;

    while i < args.len() {
        let tok = &args[i];
        if tok == "--" {
            positionals.extend(args[i + 1..].iter().cloned());
            break;
        }
        if let Some(val) = take_flag_value(args, &mut i, "--cwd")? {
            opts.cwd = val;
        } else if let Some(val) = take_flag_value(args, &mut i, "--ext")? {
            opts.ext = val;
        } else if let Some(val) = take_flag_value(args, &mut i, "--glob")? {
            opts.globs.push(val);
        } else if let Some(val) = take_flag_value(args, &mut i, "-g")? {
            opts.globs.push(val);
        } else if let Some(val) = take_flag_value(args, &mut i, "--limit")? {
            opts.limit = val
                .parse::<usize>()
                .map_err(|_| format!("invalid --limit '{}'", val))?;
        } else if let Some(val) = take_flag_value(args, &mut i, "--max-results")? {
            opts.limit = val
                .parse::<usize>()
                .map_err(|_| format!("invalid --max-results '{}'", val))?;
        } else if let Some(val) = take_flag_value(args, &mut i, "--context")? {
            opts.context = val
                .parse::<usize>()
                .map_err(|_| format!("invalid --context '{}'", val))?;
        } else if let Some(val) = take_flag_value(args, &mut i, "-C")? {
            opts.context = val
                .parse::<usize>()
                .map_err(|_| format!("invalid -C '{}'", val))?;
        } else {
            match tok.as_str() {
                "--fixed" | "--fixed-strings" | "-F" => opts.fixed = true,
                "--case-sensitive" | "-s" => {
                    opts.case_sensitive = true;
                    opts.ignore_case = false;
                }
                "--ignore-case" | "-i" => {
                    opts.ignore_case = true;
                    opts.case_sensitive = false;
                }
                "--files-with-matches" | "-l" => opts.files_with_matches = true,
                "--pretty" => pretty = true,
                "--json" => {}
                other if other.starts_with('-') => {
                    return Err(format!("unknown flag '{}'", other));
                }
                _ => positionals.push(tok.clone()),
            }
        }
        i += 1;
    }

    if positionals.is_empty() {
        return Err("missing search pattern".to_string());
    }
    opts.pattern = positionals[0].clone();
    if positionals.len() >= 2 && opts.cwd.is_empty() {
        opts.cwd = positionals[1].clone();
    }
    Ok((opts, pretty))
}

fn parse_symbols_args(args: &[String]) -> Result<(String, String, usize, bool), String> {
    let mut query = String::new();
    let mut cwd = String::new();
    let mut limit: usize = 50;
    let mut pretty = false;
    let mut positionals: Vec<String> = Vec::new();
    let mut i = 0;

    while i < args.len() {
        let tok = &args[i];
        if let Some(val) = take_flag_value(args, &mut i, "--cwd")? {
            cwd = val;
        } else if let Some(val) = take_flag_value(args, &mut i, "--limit")? {
            limit = val
                .parse::<usize>()
                .map_err(|_| format!("invalid --limit '{}'", val))?;
        } else if let Some(val) = take_flag_value(args, &mut i, "--max-results")? {
            limit = val
                .parse::<usize>()
                .map_err(|_| format!("invalid --max-results '{}'", val))?;
        } else if tok == "--pretty" || tok == "--json" {
            if tok == "--pretty" {
                pretty = true;
            }
        } else if tok.starts_with('-') {
            return Err(format!("unknown flag '{}'", tok));
        } else {
            positionals.push(tok.clone());
        }
        i += 1;
    }

    if let Some(q) = positionals.first() {
        query = q.clone();
    }
    Ok((query, cwd, limit, pretty))
}

pub fn run_cli(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln_line("usage: code_search <grep|symbols|engines> [options]");
        return 2;
    }
    match args[0].as_str() {
        "-h" | "--help" => {
            eprintln_line("usage: code_search <grep|symbols|engines> [options]");
            0
        }
        "grep" => match parse_grep_args(&args[1..]) {
            Ok((opts, pretty)) => {
                let res = text_search_with_options(&opts);
                rio::print_cli_json(&res, pretty);
                if res.get("error").is_some() { 2 } else { 0 }
            }
            Err(e) => {
                eprintln_line(&format!("code_search grep: {}", e));
                2
            }
        },
        "symbols" => match parse_symbols_args(&args[1..]) {
            Ok((query, cwd, limit, pretty)) => {
                rio::print_cli_json(&symbol_search(&query, &cwd, limit), pretty);
                0
            }
            Err(e) => {
                eprintln_line(&format!("code_search symbols: {}", e));
                2
            }
        },
        "engines" => {
            let mut pretty = false;
            for tok in &args[1..] {
                if tok == "--pretty" {
                    pretty = true;
                }
            }
            let payload = json!({
                "jev": find_jev(),
                "ripgrep": find_rg(),
                "git": which_in_path("git").or_else(|| which_in_path("git.exe")),
                "python_ast": false,
                "rust_scan": true,
            });
            rio::print_cli_json(&payload, pretty);
            0
        }
        _ => match parse_grep_args(args) {
            Ok((opts, pretty)) => {
                let res = text_search_with_options(&opts);
                rio::print_cli_json(&res, pretty);
                if res.get("error").is_some() { 2 } else { 0 }
            }
            Err(e) => {
                eprintln_line(&format!("code_search: {}", e));
                2
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::win32_sqlite::TEST_ENV_LOCK;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(prefix: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir = env::temp_dir().join(format!("{}-{}-{}", prefix, std::process::id(), nanos));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn test_all_regexes_compile() {
        assert!(polyglot_symbol_re().is_match("pub fn run_cli(args: &[String])"));
        assert!(polyglot_symbol_re().is_match("export async function fetchData() {"));
        assert!(python_symbol_re().is_match("    async def handle_event(x):"));
        assert!(python_symbol_re().is_match("class StackDoctor:"));
    }

    #[test]
    fn test_resolve_rg_binary_env_override() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempDir::new("cs-rg");
        let fake_rg = tmp.0.join("custom_rg.exe");
        fs::write(&fake_rg, b"MZ").unwrap();

        let prev_rg = env::var_os("RIPGREP_PATH");
        let prev_crg = env::var_os("CARBON_RG_BIN");
        env::set_var("RIPGREP_PATH", &fake_rg);
        env::remove_var("CARBON_RG_BIN");

        let resolved = _resolve_rg_binary();
        assert_eq!(resolved.as_deref(), Some(fake_rg.to_string_lossy().as_ref()));

        env::remove_var("RIPGREP_PATH");
        env::set_var("CARBON_RG_BIN", &fake_rg);
        assert_eq!(
            find_rg().as_deref(),
            Some(fake_rg.to_string_lossy().as_ref())
        );

        match prev_rg {
            Some(v) => env::set_var("RIPGREP_PATH", v),
            None => env::remove_var("RIPGREP_PATH"),
        }
        match prev_crg {
            Some(v) => env::set_var("CARBON_RG_BIN", v),
            None => env::remove_var("CARBON_RG_BIN"),
        }
    }

    #[test]
    fn test_fallback_text_search_and_symbol_search() {
        let tmp = TempDir::new("cs-scan");
        let src_dir = tmp.0.join("src");
        let skip_dir = tmp.0.join("node_modules");
        fs::create_dir_all(&src_dir).unwrap();
        fs::create_dir_all(&skip_dir).unwrap();

        fs::write(
            src_dir.join("app.py"),
            "class AlphaHandler:\n    def handle(self):\n        return 'needle_token'\n\ndef helper():\n    pass\n",
        )
        .unwrap();
        fs::write(
            src_dir.join("lib.rs"),
            "pub fn process_needle() -> i32 {\n    42\n}\n",
        )
        .unwrap();
        fs::write(skip_dir.join("ignored.js"), "const needle_token = 1;\n").unwrap();
        fs::write(src_dir.join("bin.dat"), b"\x00\x01needle_token\x00").unwrap();

        let syms = symbol_search("handle", &tmp.0.to_string_lossy(), 20);
        assert_eq!(syms["count"].as_u64(), Some(2));
        let arr = syms["symbols"].as_array().unwrap();
        assert_eq!(arr[0]["kind"], "class");
        assert_eq!(arr[0]["start_line"], 1);
        assert_eq!(arr[0]["end_line"], 3);
        assert_eq!(arr[1]["kind"], "def");

        let opts = SearchOptions {
            pattern: "needle_token".to_string(),
            cwd: tmp.0.to_string_lossy().into_owned(),
            globs: vec!["*.py".to_string()],
            ..SearchOptions::default()
        };
        let res = rust_fallback_search(&tmp.0, &opts, false);
        assert_eq!(res["engine"], "rust-scan");
        assert_eq!(res["count"].as_u64(), Some(1));
        assert!(res["matches"][0].as_str().unwrap().contains("src/app.py:3:"));

        let opts_ctx = SearchOptions {
            pattern: "NEEDLE_TOKEN".to_string(),
            case_sensitive: true,
            ..opts.clone()
        };
        let res_cs = rust_fallback_search(&tmp.0, &opts_ctx, false);
        assert_eq!(res_cs["count"].as_u64(), Some(0));

        let opts_l = SearchOptions {
            files_with_matches: true,
            ..opts
        };
        let res_l = rust_fallback_search(&tmp.0, &opts_l, false);
        assert_eq!(res_l["matches"][0], "src/app.py");
    }

    #[test]
    fn test_cli_flag_parsing() {
        let args: Vec<String> = vec![
            "needle",
            "src",
            "-g",
            "*.rs",
            "-F",
            "-s",
            "-C",
            "2",
            "--max-results",
            "15",
            "-l",
            "--json",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let (opts, pretty) = parse_grep_args(&args).unwrap();
        assert!(!pretty);
        assert_eq!(opts.pattern, "needle");
        assert_eq!(opts.cwd, "src");
        assert_eq!(opts.globs, vec!["*.rs"]);
        assert!(opts.fixed);
        assert!(opts.case_sensitive);
        assert_eq!(opts.context, 2);
        assert_eq!(opts.limit, 15);
        assert!(opts.files_with_matches);
    }
}
