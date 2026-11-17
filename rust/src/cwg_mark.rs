use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::UNIX_EPOCH;

use crate::cwg_common;
use crate::rio;
use crate::win32_sqlite::{is_link_or_junction, now_sec, run_command_with_job};

const EDIT_TOOLS: &[&str] = &["edit_file", "write_file"];
const SHELL_TOOLS: &[&str] = &["run_command"];

const NON_GIT_SCAN_MAX_FILES: usize = 400;
const NON_GIT_SCAN_MAX_DEPTH: usize = 4;
const MAX_HASHED_SNAPSHOT_BYTES: u64 = 2_000_000;
const MAX_FINGERPRINT_FILE_BYTES: u64 = 4_000_000;
const MAX_VAR_VALUE_LEN: usize = 1024;
const MAX_EXPANDED_SEG_LEN: usize = 8192;
const CLAIM_TTL_SECONDS: f64 = 600.0;

static SNAP_SEQ: AtomicU64 = AtomicU64::new(1);

const NON_GIT_SKIP_DIRS: &[&str] = &[
    ".git",
    ".gemini",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
];

const PS_BOOL_SWITCHES: &[&str] = &[
    "-force",
    "-recurse",
    "-r",
    "-confirm",
    "-whatif",
    "-passthru",
    "-verbose",
    "-debug",
    "-noclobber",
    "-append",
    "-nonewline",
    "-asbytestream",
    "-raw",
    "-container",
];

const PS_NON_PATH_VALUE_FLAGS: &[&str] = &[
    "-itemtype",
    "-type",
    "-value",
    "-encoding",
    "-erroraction",
    "-ea",
    "-warningaction",
    "-wa",
    "-informationaction",
    "-outvariable",
    "-ov",
    "-errorvariable",
    "-ev",
    "-filter",
    "-include",
    "-exclude",
    "-depth",
    "-delimiter",
    "-stream",
];

const PS_PATH_FLAGS: &[&str] = &["-path", "-p", "-literalpath", "-lp", "-filepath"];
const PS_DEST_FLAGS: &[&str] = &["-destination", "-dest", "-destinationpath"];

const SCRIPT_EXTS: &[&str] = &[".ps1", ".bat", ".cmd", ".vbs", ".wsf", ".exe", ".com", ".msi"];

const INTERPRETER_BASENAMES: &[&str] = &[
    "python",
    "python.exe",
    "python3",
    "python3.exe",
    "py",
    "py.exe",
    "node",
    "node.exe",
    "deno",
    "deno.exe",
    "bun",
    "bun.exe",
    "pwsh",
    "pwsh.exe",
    "powershell",
    "powershell.exe",
    "cmd",
    "cmd.exe",
    "bash",
    "bash.exe",
    "sh",
    "sh.exe",
    "wsl",
    "wsl.exe",
];

fn exe_pat_followed_by_space(names_pat: &str, ext_pat: &str, allow_dq_vars: bool) -> String {
    // INVARIANT: Allow quoted/path-qualified Windows executables while keeping `dq_char` branches disjoint (O(N)) and blocking `$`/backticks on allowlists.
    let dq_char = if allow_dq_vars {
        r#"(?:`[^\r\n]|""|[^"`\r\n])"#
    } else {
        r#"[^"`$\r\n]"#
    };
    let dq_sep = if allow_dq_vars { r"`?[/\\]" } else { r"[/\\]" };
    format!(
        r#"(?:'(?:(?:''|[^'\r\n])*[/\\])?(?:{names}){ext}'|"(?:{dq_char}*{dq_sep})?(?:{names}){ext}"|(?:[^\s|;&"'`$()\r\n]*[/\\])?(?:{names}){ext})"#,
        names = names_pat,
        ext = ext_pat,
        dq_char = dq_char,
        dq_sep = dq_sep,
    )
}

fn exe_pat_split_groups(names_pat: &str, ext_pat: &str, allow_dq_vars: bool) -> String {
    let dq_char = if allow_dq_vars {
        r#"(?:`[^\r\n]|""|[^"`\r\n])"#
    } else {
        r#"[^"`$\r\n]"#
    };
    let dq_sep = if allow_dq_vars { r"`?[/\\]" } else { r"[/\\]" };
    format!(
        r#"(?:(?P<q>'(?:(?:''|[^'\r\n])*[/\\])?(?:{names}){ext}'|"(?:{dq_char}*{dq_sep})?(?:{names}){ext}")|(?P<u>(?:[^\s|;&"'`$()\r\n]*[/\\])?(?:{names}){ext}))"#,
        names = names_pat,
        ext = ext_pat,
        dq_char = dq_char,
        dq_sep = dq_sep,
    )
}

fn py_interp_pat(allow_dq_vars: bool) -> String {
    let py_tok = exe_pat_followed_by_space(r"python(?:\d+(?:\.\d+)?)?", r"(?:\.exe)?", allow_dq_vars);
    let launcher_tok = exe_pat_followed_by_space("py", r"(?:\.exe)?", allow_dq_vars);
    format!(r"(?:{}|{}(?:\s+-3(?:\.\d+)?)?)", py_tok, launcher_tok)
}

const EXT_PY: &str = r"\.py";
const EXT_CMD_EXE: &str = r"(?:\.cmd|\.exe)?";
const PS_DQ_PAT: &str = r#""(?:`[\s\S]|""|[^"`])*""#;
const PS_SQ_PAT: &str = r"'(?:''|[^'])*'";
const PS_SAFE_BARE_PAT: &str = r"[A-Za-z0-9_./\\:-]+";
const PS_VAR_NAME_PAT: &str = r"[A-Za-z_]\w*(?::[A-Za-z_]\w*)?";
const PS_DQ_LITERAL_PAT: &str = r#""[^"`$]*""#;

fn cache_path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(^|/)(__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.coverage|node_modules/\.cache|\.swarm)(/|$)|\.pyc$",
        )
        .expect("cache_path_re")
    })
}

fn bookkeeping_cmd_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let py = py_interp_pat(false);
        let bk_scripts = exe_pat_followed_by_space(
            "carbon_memory|gate_inbox|chip_handoff|swarm_cache|swarm_ctl",
            EXT_PY,
            false,
        );
        let continuity = exe_pat_followed_by_space("continuity", EXT_PY, false);
        let codex_lane = exe_pat_followed_by_space("codex_lane", EXT_PY, false);
        let pat = format!(
            r"(?i)\A\s*(?:\$null\s*\|\s*)?(?:&\s*)?{py}\s+(?:-(?:X\s+utf8|[uBEsSO])\s+)*(?:{bk}|(?:{cont}\s+(?:checkpoint|show|handoff)\b|{cl}\s+(?:check|status|reset|review)\b))(?:\s+[^|;&\r\n]*)?\z",
            py = py,
            bk = bk_scripts,
            cont = continuity,
            cl = codex_lane,
        );
        Regex::new(&pat).expect("bookkeeping_cmd_re")
    })
}

fn nav_segment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\A\s*(?:cd|chdir|Set-Location|sl|Push-Location|pushd|Pop-Location|popd)\b(?:\s+[^|;&\r\n]*)?\z",
        )
        .expect("nav_segment_re")
    })
}

fn ps_safe_filter_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\A\s*(?:Select-Object|select|Where-Object|where|Measure-Object|measure|Sort-Object|sort|Format-Table|ft|Format-List|fl|Out-String|ConvertFrom-Json|ConvertTo-Json|Get-Unique)\b(?:\s+[^|;&\r\n]*)?\z",
        )
        .expect("ps_safe_filter_re")
    })
}

fn read_only_cmd_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let py = py_interp_pat(false);
        let git_tok = exe_pat_followed_by_space("git", r"(?:\.exe)?", false);
        let rg_tok = exe_pat_followed_by_space("rg", r"(?:\.exe)?", false);
        let codex_tok = exe_pat_followed_by_space("codex", EXT_CMD_EXE, false);
        let agy_tok = exe_pat_followed_by_space("agy", EXT_CMD_EXE, false);
        let tokenade_tok = exe_pat_followed_by_space("tokenade", EXT_CMD_EXE, false);
        let ro_scripts = exe_pat_followed_by_space("code_search|stack_doctor", EXT_PY, false);
        let wt_guard = exe_pat_followed_by_space("worktree_guard", EXT_PY, false);
        let pat = format!(
            r#"(?i)\A\s*(?:\$null\s*\|\s*)?(?:(?:(?:&\s*)?{git}\s+(?:--no-pager\s+)?(?:-C\s+["']?[^"'|;&\r\n]+["']?\s+)?(?:status|diff|log|show|rev-parse|ls-files|ls-tree|check-ignore|remote\s+-v|worktree\s+list)|(?:&\s*)?{rg}|findstr(?:\.exe)?\b|where(?:\.exe)?\b|Get-ChildItem\b|gci\b|Get-Content\b|gc\b|Select-String\b|sls\b|Get-Command\b|gcm\b|Test-Path\b|Get-Item\b|gi\b|Get-ItemProperty\b|gp\b|Get-ItemPropertyValue\b|gpv\b|Get-CimInstance\b|gcim\b|Get-WmiObject\b|gwmi\b|Get-WinEvent\b|Get-EventLog\b|Get-Process\b|gps\b|Get-Service\b|gsv\b|Get-Location\b|gl\b|Write-Output\b|(?:&\s*)?{codex}\s+(?:--version|login\s+status|exec\b[^|;&\r\n]*-s\s+read-only\b)|(?:&\s*)?{agy}\s+(?:--help|--version|plugin\s+(?:list|help)|mcp\s+(?:list|help)|models\b)|(?:&\s*)?{tok}\s+(?:--version|--help|help|map|query|skeleton|semantic|ask|sem|impact|expand-ref|gain|dashboard|healthcheck|detect|measure|statusline)\b|(?:&\s*)?{py}\s+(?:-(?:X\s+utf8|[uBEsSO])\s+)*(?:{ro}|{wt}\s+(?:audit|status)\b))(?:\s+[^|;&\r\n]*)?|(?:&\s*)?{git}\s+(?:--no-pager\s+)?(?:-C\s+["']?[^"'|;&\r\n]+["']?\s+)?branch(?:\s+(?:--list|-l|-a|--all|-r|--remotes|-v|-vv|--show-current|--no-color))*)\z"#,
            git = git_tok,
            rg = rg_tok,
            codex = codex_tok,
            agy = agy_tok,
            tok = tokenade_tok,
            py = py,
            ro = ro_scripts,
            wt = wt_guard,
        );
        Regex::new(&pat).expect("read_only_cmd_re")
    })
}

fn validation_non_runner_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // WORKAROUND: `install_diag_tail` uses `\s` after `install.py\s+` instead of `(?<!\S)`, preserving exact boundary without lookbehind.
        let py = py_interp_pat(false);
        let ruff = exe_pat_followed_by_space("ruff", r"(?:\.exe)?", false);
        let install = exe_pat_followed_by_space("install", EXT_PY, false);
        let agy = exe_pat_followed_by_space("agy", EXT_CMD_EXE, false);
        let pat = format!(
            r"(?i)\A\s*(?:\$null\s*\|\s*)?(?:&\s*)?(?:{ruff}\s+check\b|{py}\s+(?:-(?:X\s+utf8|[uBEsSO])\s+)*(?:-m\s+(?:pytest|unittest|py_compile|compileall|mypy|ruff|flake8)\b|{inst}\s+(?:[^\r\n|;&]*\s)?(?:--diagnose|--dry-run)(?:\z|[\s|;&]))|npm(?:\.cmd)?\s+(?:test|run\s+(?:test|lint|build|typecheck|check))\b|pnpm(?:\.cmd)?\s+(?:test|lint|build|typecheck)\b|yarn(?:\.cmd)?\s+(?:test|lint|build|typecheck)\b|npx(?:\.cmd)?\s+(?:tsc|vitest|jest|eslint|playwright\s+test)\b|cargo(?:\.exe)?\s+(?:test|check|clippy)\b|go(?:\.exe)?\s+(?:test|vet)\b|dotnet(?:\.exe)?\s+(?:test|build)\b|{agy}\s+plugin\s+validate\b)",
            ruff = ruff,
            py = py,
            inst = install,
            agy = agy,
        );
        Regex::new(&pat).expect("validation_non_runner_re")
    })
}

fn validation_runner_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let runners = exe_pat_split_groups(r"pytest|py\.test|mypy|flake8", r"(?:\.exe)?", false);
        let pat = format!(r"(?i)\A\s*(?:\$null\s*\|\s*)?(?:&\s*)?{}", runners);
        Regex::new(&pat).expect("validation_runner_re")
    })
}

fn quoted_boundary_ok(after: &str) -> bool {
    match after.chars().next() {
        None => true,
        Some(c) => c.is_whitespace() || matches!(c, '|' | ';' | '&'),
    }
}

fn unquoted_boundary_ok(after: &str) -> bool {
    match after.chars().next() {
        None => true,
        Some(c) => !(c.is_alphanumeric() || matches!(c, '_' | '.' | '-')),
    }
}

fn exe_caps_boundary_ok(caps: &regex::Captures<'_>, full_str: &str) -> bool {
    let end = caps.get(0).map_or(full_str.len(), |m| m.end());
    let after = &full_str[end..];
    if caps.name("q").is_some() {
        quoted_boundary_ok(after)
    } else {
        unquoted_boundary_ok(after)
    }
}

fn is_validation_segment(seg: &str) -> bool {
    if validation_non_runner_re().is_match(seg) {
        return true;
    }
    if let Some(caps) = validation_runner_re().captures(seg) {
        return exe_caps_boundary_ok(&caps, seg);
    }
    false
}

fn mutating_cmdlet_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:\A|[;|&({\s])(?:Set-Content|sc|Add-Content|ac|Out-File|Export-Csv|Export-Clixml|Remove-Item|ri|rm|del|erase|Move-Item|mi|mv|Copy-Item|ci|cp|New-Item|ni|mkdir|md|Rename-Item|rni|ren|Clear-Content|clc|Tee-Object|rmdir|rd|touch|chmod|chown|mklink|Expand-Archive|Compress-Archive|expand(?:\.exe)?|robocopy(?:\.exe)?|xcopy(?:\.exe)?)\b",
        )
        .expect("mutating_cmdlet_re")
    })
}

fn mutating_git_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\bgit(?:\.exe)?[^\S\r\n]+(?:--no-pager[^\S\r\n]+)?(?:-C[^\S\r\n]+\S+[^\S\r\n]+)?(?:(?:add|commit|checkout|restore|reset|clean|merge|rebase|cherry-pick|stash|apply|am|rm|mv|init|clone|pull|push|fetch|worktree[^\S\r\n]+(?:add|remove|prune)|tag[^\S\r\n]+-d)\b|branch[^\S\r\n]+(?:(?:-[A-Za-z]*[fFdDmMcC]|--force|--delete|--move|--copy|--set-upstream-to|--unset-upstream)\b|[^-\s|;&\r\n]))",
        )
        .expect("mutating_git_re")
    })
}

fn mutating_pkg_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:pip|pip3|uv\s+pip|npm|pnpm|yarn|cargo|poetry)\b[^\r\n;|&]*\b(?:install|uninstall|add|remove|upgrade|publish)\b",
        )
        .expect("mutating_pkg_re")
    })
}

fn mutating_stack_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:\bworktree_guard\.py\b[^\r\n;|&]*\b(?:snapshot|remove|restore)\b|\bchip_handoff\.py\b[^\r\n;|&]*--merge\b)",
        )
        .expect("mutating_stack_re")
    })
}

fn py_mut_clause_head_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let py = py_interp_pat(true);
        let pat = format!(
            r"(?i)\A\s*(?:\$[A-Za-z_]\w*\s*=\s*)?(?:\$null\s*\|\s*)?(?:&\s*)?{}\s+",
            py
        );
        Regex::new(&pat).expect("py_mut_clause_head_re")
    })
}

fn py_flag_x_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\A-X\s+(\S+)\s+").expect("py_flag_x_re"))
}

fn py_flag_w_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\A-\w+\s+").expect("py_flag_w_re"))
}

fn py_short_flag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\A-\w+\z").expect("py_short_flag_re"))
}

fn skip_py_any_flags(mut rest: &str) -> &str {
    // WORKAROUND: Emulates `_PY_ANY_FLAGS_PAT` (`-(?:X\s+(?!-\w+\s)\S+|\w+)\s+`) without lookahead.
    loop {
        if let Some(caps) = py_flag_x_re().captures(rest) {
            let xarg = caps.get(1).map_or("", |m| m.as_str());
            if !py_short_flag_re().is_match(xarg) {
                rest = &rest[caps.get(0).expect("g0").end()..];
                continue;
            }
        }
        if let Some(m) = py_flag_w_re().find(rest) {
            let tok = m.as_str().trim();
            if tok.eq_ignore_ascii_case("-c") || tok.eq_ignore_ascii_case("-m") {
                break;
            }
            rest = &rest[m.end()..];
            continue;
        }
        break;
    }
    rest
}

fn strip_py_mut_clause_prefix(clause: &str) -> Option<&str> {
    let m = py_mut_clause_head_re().find(clause)?;
    Some(skip_py_any_flags(&clause[m.end()..]))
}

fn wt_guard_mut_tok_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let tok = exe_pat_split_groups("worktree_guard", EXT_PY, true);
        Regex::new(&format!(r"(?i)\A{}", tok)).expect("wt_guard_mut_tok_re")
    })
}

fn wt_mut_tail_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\A[^\r\n;|&]*\b(?:snapshot|remove|restore)\b").expect("wt_mut_tail_re")
    })
}

fn chip_mut_tok_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let tok = exe_pat_split_groups("chip_handoff", EXT_PY, true);
        Regex::new(&format!(r"(?i)\A{}", tok)).expect("chip_mut_tok_re")
    })
}

fn chip_mut_tail_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\A[^\r\n;|&]*--merge\b").expect("chip_mut_tail_re"))
}

fn install_mut_tok_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let tok = exe_pat_split_groups("install", EXT_PY, true);
        Regex::new(&format!(r"(?i)\A{}", tok)).expect("install_mut_tok_re")
    })
}

fn install_diag_tail_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\A[^\r\n|;&]*\s(?:--diagnose|--dry-run)(?:\z|[\s|;&])")
            .expect("install_diag_tail_re")
    })
}

fn is_mutating_stack_seg(clause: &str) -> bool {
    let Some(rest) = strip_py_mut_clause_prefix(clause) else {
        return false;
    };
    if let Some(caps) = wt_guard_mut_tok_re().captures(rest) {
        if exe_caps_boundary_ok(&caps, rest) {
            let end = caps.get(0).expect("g0").end();
            if wt_mut_tail_re().is_match(&rest[end..]) {
                return true;
            }
        }
    }
    if let Some(caps) = chip_mut_tok_re().captures(rest) {
        if exe_caps_boundary_ok(&caps, rest) {
            let end = caps.get(0).expect("g0").end();
            if chip_mut_tail_re().is_match(&rest[end..]) {
                return true;
            }
        }
    }
    false
}

fn is_install_py_mut(clause: &str) -> bool {
    let Some(rest) = strip_py_mut_clause_prefix(clause) else {
        return false;
    };
    let Some(caps) = install_mut_tok_re().captures(rest) else {
        return false;
    };
    if !exe_caps_boundary_ok(&caps, rest) {
        return false;
    }
    let end = caps.get(0).expect("g0").end();
    !install_diag_tail_re().is_match(&rest[end..])
}

fn system_or_net_mutating_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:\b(?:Stop-Service|Start-Service|Restart-Service|Set-Service|New-Service|Suspend-Service|Resume-Service|Stop-Process|spps|taskkill|Register-ScheduledTask|Unregister-ScheduledTask|Set-ScheduledTask|Start-ScheduledTask|Set-ItemProperty|sp|New-ItemProperty|Remove-ItemProperty|rp|Rename-ItemProperty|rnp|Clear-ItemProperty|clp|Set-Item|Invoke-CimMethod|Invoke-WmiMethod|Invoke-Command|icm|Invoke-Expression|iex|Start-Process|saps|bcdedit|diskpart|pnputil|sfc|takeown|icacls|setx|msiexec|cscript|wscript)\b|\bschtasks(?:\.exe)?\s+/(?:create|delete|change|run|end)\b|\bsc(?:\.exe)?\s+(?:stop|start|pause|continue|control|sdset|config|create|delete|failure)\b|\bnet(?:\.exe)?\s+(?:stop|start|user|localgroup|share|use)\b|\breg(?:\.exe)?\s+(?:add|delete|import|restore|load|unload|copy)\b|\bdism(?:\.exe)?\b[^\r\n;|&]*/(?:online|cleanup-image|enable-feature|disable-feature|add-package|remove-package|restorehealth)\b|\[Environment\]::SetEnvironmentVariable|\[(?:System\.)?IO\.(?:File|Directory)\]::(?:Write|Append|Delete|Copy|Move|Create|Replace|OpenWrite)|\bNew-Object\b[^\r\n;|&]*\bNet\.WebClient\b|\b(?:ssh|scp|rsync|sftp)\b)",
        )
        .expect("system_or_net_mutating_re")
    })
}

fn http_cmd_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm|curl(?:\.exe)?|wget(?:\.exe)?)\b")
            .expect("http_cmd_re")
    })
}

fn http_method_flag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(?:-Method\s+|(?:--method(?:=|\s+)|-X\s*|--request(?:=|\s+)))["']?([A-Za-z]+)"#)
            .expect("http_method_flag_re")
    })
}

fn http_mutating_other_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:-(?:OutFile|Body|InFile|Form)\b|(?:\s|\A)(?:-d|--data|--data-raw|--data-binary|--post-data|--post-file|--form|-F|--upload-file|-T|-O|--remote-name)\b)",
        )
        .expect("http_mutating_other_re")
    })
}

fn is_http_mutating(core: &str) -> bool {
    if http_mutating_other_re().is_match(core) {
        return true;
    }
    for caps in http_method_flag_re().captures_iter(core) {
        let method = caps.get(1).map_or("", |m| m.as_str());
        if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("HEAD") {
            return true;
        }
    }
    false
}

fn inline_py_search_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let py = py_interp_pat(true);
        Regex::new(&format!(r"(?i)(?:\A|[;&|({{\s]){}\s+", py)).expect("inline_py_search_re")
    })
}

fn inline_py_c_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\A-c\b").expect("inline_py_c_re"))
}

fn has_inline_py(core: &str) -> bool {
    let re = inline_py_search_re();
    let mut pos = 0usize;
    while pos <= core.len() {
        let Some(m) = re.find_at(core, pos) else {
            break;
        };
        let rest = skip_py_any_flags(&core[m.end()..]);
        if inline_py_c_re().is_match(rest) {
            return true;
        }
        if let Some(ch) = core[m.start()..].chars().next() {
            pos = m.start() + ch.len_utf8();
        } else {
            break;
        }
    }
    false
}

fn starts_with_inline_py(clause: &str) -> bool {
    let Some(m) = inline_py_search_re().find(clause) else {
        return false;
    };
    if m.start() != 0 {
        return false;
    }
    let rest = skip_py_any_flags(&clause[m.end()..]);
    inline_py_c_re().is_match(rest)
}

fn inline_py_write_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\.write(?:_text|_bytes|lines)?\b|open\s*\(|\b(?:unlink|remove|rename|replace|rmdir|shutil|subprocess|os\.system|urllib|http\.client|requests|httpx|socket|winreg|ctypes|sqlite3|runpy)\b|\.(?:mkdir|makedirs|touch)\s*\(",
        )
        .expect("inline_py_write_re")
    })
}

fn ps_quoted_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(&format!("{}|({})", PS_DQ_PAT, PS_SQ_PAT)).expect("ps_quoted_re")
    })
}

fn output_flag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:\A|\s)(?:--output(?:=|\s)|-o(?:\s|\z)|-outfile(?:\s|\z))")
            .expect("output_flag_re")
    })
}

fn file_redirect_scan_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(>+)\s*(\S+)").expect("file_redirect_scan_re"))
}

fn null_redirect_target_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\A(?:\$null\b|nul\b|/dev/null\b|&[1-6]\b)")
            .expect("null_redirect_target_re")
    })
}

fn has_non_null_file_redirect(unquoted_surface: &str) -> bool {
    // WORKAROUND: Emulates `(?<!>)>>?(?!>)\s*(?!\$null\b|nul\b|/dev/null\b|&[1-6]\b)\S+` without lookaround.
    for caps in file_redirect_scan_re().captures_iter(unquoted_surface) {
        let gts = caps.get(1).map_or("", |m| m.as_str());
        let tgt = caps.get(2).map_or("", |m| m.as_str());
        if gts.len() <= 2 && !null_redirect_target_re().is_match(tgt) {
            return true;
        }
    }
    false
}

fn pre_flag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(?:\A|\s)--pre(?:=|\s|\z)").expect("pre_flag_re"))
}

fn ps_safe_bare_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(&format!(r"\A{}\z", PS_SAFE_BARE_PAT)).expect("ps_safe_bare_re"))
}

fn ps_var_ref_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(&format!(
            r"\$(?:\{{({})\}}|({}))",
            PS_VAR_NAME_PAT, PS_VAR_NAME_PAT
        ))
        .expect("ps_var_ref_re")
    })
}

fn ps_sq_full_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(&format!(r"\A{}\z", PS_SQ_PAT)).expect("ps_sq_full_re"))
}

fn ps_dq_full_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(&format!(r"\A{}\z", PS_DQ_PAT)).expect("ps_dq_full_re"))
}

fn ps_assign_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\A\s*\$(?P<var>[A-Za-z_]\w*)\s*=\s*(?P<rhs>\S[\s\S]*)\z")
            .expect("ps_assign_re")
    })
}

fn ps_join_path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let pat = format!(
            r"(?i)\AJoin-Path\s+(?:-Path\s+)?(?P<p1>{}|{}|{})\s+(?:-ChildPath\s+)?(?P<p2>{}|{}|{})\s*\z",
            PS_SQ_PAT,
            PS_DQ_LITERAL_PAT,
            PS_SAFE_BARE_PAT,
            PS_SQ_PAT,
            PS_DQ_LITERAL_PAT,
            PS_SAFE_BARE_PAT,
        );
        Regex::new(&pat).expect("ps_join_path_re")
    })
}

fn ps_redirect_inner_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let pat = format!(
            r#"(?s)(>+)\s*(?:({})|({})|([^\s|;&"']+))"#,
            PS_DQ_PAT, PS_SQ_PAT
        );
        Regex::new(&pat).expect("ps_redirect_inner_re")
    })
}

fn amp_digit_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\A&[1-6]\z").expect("amp_digit_re"))
}

fn win_drive_prefix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\A[A-Za-z]:[\\/]").expect("win_drive_prefix_re"))
}

fn ps_control_kw_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\A\s*(?:(?:if|elseif|else|try|catch|finally|do|while|switch|ForEach-Object|foreach|for)\b\s*|%(?:\z|\s+))",
        )
        .expect("ps_control_kw_re")
    })
}

fn dot_slash_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\A\.[\\/]").expect("dot_slash_re"))
}

fn out_null_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\A\s*Out-Null\s*\z").expect("out_null_re"))
}

fn user_scratch_patterns() -> &'static [Regex] {
    static RE: OnceLock<Vec<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        [
            r"(?i)/\.gemini/antigravity/brain/[^/]+/scratch(?:/|$)",
            r"(?i)/\.gemini/antigravity/brain/[^/]+/browser_sandbox(?:/|$)",
        ]
        .iter()
        .map(|p| Regex::new(p).expect("user_scratch_pattern"))
        .collect()
    })
}

fn review_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"REVIEW_ID\s*:\s*([A-Za-z0-9_-]{6,64})").expect("review_id_re"))
}

pub fn strip_single_quoted(text: &str) -> String {
    // INVARIANT: Match PowerShell double-quoted strings first so apostrophes inside "..." never pair as '...'.
    let re = ps_quoted_re();
    let mut out = String::with_capacity(text.len());
    let mut last = 0usize;
    for caps in re.captures_iter(text) {
        let whole = caps.get(0).expect("g0");
        out.push_str(&text[last..whole.start()]);
        if caps.get(1).is_some() {
            out.push_str("''");
        } else {
            out.push_str(whole.as_str());
        }
        last = whole.end();
    }
    out.push_str(&text[last..]);
    out
}

pub fn strip_quoted(text: &str) -> String {
    // INVARIANT: In Windows PowerShell 5.1 double quotes escape ONLY via backtick (`.) or doubled quote (""), never backslash (\).
    ps_quoted_re().replace_all(text, r#""""#).into_owned()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SubMode {
    Hsq,
    Hdq,
    Sq,
    Dq,
    Sub,
}

pub fn extract_ps_subexprs(text: &str) -> Vec<String> {
    // SAFETY: Extract all unescaped PowerShell $(...) bodies (including inside "..." and @"..."@) in linear O(N) time.
    if !text.contains("$(") {
        return Vec::new();
    }
    let bytes = text.as_bytes();
    let n = bytes.len();
    let mut out: Vec<String> = Vec::new();
    let mut modes: Vec<SubMode> = Vec::new();
    let mut subs: Vec<(usize, String)> = Vec::new();
    let mut i = 0usize;
    while i < n {
        let ch = bytes[i];
        let mode = modes.last().copied();
        match mode {
            Some(SubMode::Hsq) => {
                if ch == b'\''
                    && i > 0
                    && (bytes[i - 1] == b'\n' || bytes[i - 1] == b'\r')
                    && i + 1 < n
                    && bytes[i + 1] == b'@'
                {
                    if let Some((_, buf)) = subs.last_mut() {
                        buf.push_str("'@");
                    }
                    modes.pop();
                    i += 2;
                    continue;
                }
                let step = utf8_char_len(text, i);
                if let Some((_, buf)) = subs.last_mut() {
                    buf.push_str(&text[i..i + step]);
                }
                i += step;
                continue;
            }
            Some(SubMode::Hdq) => {
                if ch == b'`' && i + 1 < n {
                    let step = 1 + utf8_char_len(text, i + 1);
                    if let Some((_, buf)) = subs.last_mut() {
                        buf.push_str(&text[i..i + step]);
                    }
                    i += step;
                    continue;
                }
                if ch == b'$' && i + 1 < n && bytes[i + 1] == b'(' {
                    modes.push(SubMode::Sub);
                    subs.push((1, String::new()));
                    i += 2;
                    continue;
                }
                if ch == b'"'
                    && i > 0
                    && (bytes[i - 1] == b'\n' || bytes[i - 1] == b'\r')
                    && i + 1 < n
                    && bytes[i + 1] == b'@'
                {
                    if let Some((_, buf)) = subs.last_mut() {
                        buf.push_str(r#""@"#);
                    }
                    modes.pop();
                    i += 2;
                    continue;
                }
                let step = utf8_char_len(text, i);
                if let Some((_, buf)) = subs.last_mut() {
                    buf.push_str(&text[i..i + step]);
                }
                i += step;
                continue;
            }
            Some(SubMode::Sq) => {
                if ch == b'\'' && i + 1 < n && bytes[i + 1] == b'\'' {
                    if let Some((_, buf)) = subs.last_mut() {
                        buf.push_str("''");
                    }
                    i += 2;
                    continue;
                }
                let step = utf8_char_len(text, i);
                if let Some((_, buf)) = subs.last_mut() {
                    buf.push_str(&text[i..i + step]);
                }
                if ch == b'\'' {
                    modes.pop();
                }
                i += step;
                continue;
            }
            Some(SubMode::Dq) => {
                if ch == b'`' && i + 1 < n {
                    let step = 1 + utf8_char_len(text, i + 1);
                    if let Some((_, buf)) = subs.last_mut() {
                        buf.push_str(&text[i..i + step]);
                    }
                    i += step;
                    continue;
                }
                if ch == b'"' && i + 1 < n && bytes[i + 1] == b'"' {
                    if let Some((_, buf)) = subs.last_mut() {
                        buf.push_str(r#""""#);
                    }
                    i += 2;
                    continue;
                }
                if ch == b'$' && i + 1 < n && bytes[i + 1] == b'(' {
                    modes.push(SubMode::Sub);
                    subs.push((1, String::new()));
                    i += 2;
                    continue;
                }
                let step = utf8_char_len(text, i);
                if let Some((_, buf)) = subs.last_mut() {
                    buf.push_str(&text[i..i + step]);
                }
                if ch == b'"' {
                    modes.pop();
                }
                i += step;
                continue;
            }
            _ => {}
        }

        if ch == b'`' && i + 1 < n {
            let step = 1 + utf8_char_len(text, i + 1);
            if let Some((_, buf)) = subs.last_mut() {
                buf.push_str(&text[i..i + step]);
            }
            i += step;
            continue;
        }
        if ch == b'$' && i + 1 < n && bytes[i + 1] == b'(' {
            if let Some((_, buf)) = subs.last_mut() {
                buf.push_str(r#" "" "#);
            }
            modes.push(SubMode::Sub);
            subs.push((1, String::new()));
            i += 2;
            continue;
        }
        if ch == b'@' && i + 2 < n && (bytes[i + 1] == b'\'' || bytes[i + 1] == b'"') {
            let nl_len = if bytes[i + 2] == b'\n' {
                1
            } else if bytes[i + 2] == b'\r' && i + 3 < n && bytes[i + 3] == b'\n' {
                2
            } else {
                0
            };
            if nl_len > 0 {
                if let Some((_, buf)) = subs.last_mut() {
                    buf.push_str(&text[i..i + 2 + nl_len]);
                }
                modes.push(if bytes[i + 1] == b'\'' {
                    SubMode::Hsq
                } else {
                    SubMode::Hdq
                });
                i += 2 + nl_len;
                continue;
            }
        }
        if ch == b'\'' || ch == b'"' {
            if let Some((_, buf)) = subs.last_mut() {
                buf.push(ch as char);
            }
            modes.push(if ch == b'\'' {
                SubMode::Sq
            } else {
                SubMode::Dq
            });
            i += 1;
            continue;
        }
        if mode == Some(SubMode::Sub) {
            if ch == b'(' {
                if let Some((depth, buf)) = subs.last_mut() {
                    *depth += 1;
                    buf.push('(');
                }
                i += 1;
                continue;
            }
            if ch == b')' {
                let is_outer = subs.last().map_or(false, |(d, _)| *d <= 1);
                if !is_outer {
                    if let Some((depth, buf)) = subs.last_mut() {
                        *depth -= 1;
                        buf.push(')');
                    }
                } else {
                    modes.pop();
                    if let Some((_, body_raw)) = subs.pop() {
                        let body = body_raw.trim();
                        if !body.is_empty() {
                            out.push(body.to_string());
                        }
                    }
                }
                i += 1;
                continue;
            }
            let step = utf8_char_len(text, i);
            if let Some((_, buf)) = subs.last_mut() {
                buf.push_str(&text[i..i + step]);
            }
            i += step;
            continue;
        }
        i += utf8_char_len(text, i);
    }
    while let Some((_, body_raw)) = subs.pop() {
        let body = body_raw.trim();
        if !body.is_empty() {
            out.push(body.to_string());
        }
    }
    out
}

fn utf8_char_len(s: &str, idx: usize) -> usize {
    s[idx..].chars().next().map_or(1, |c| c.len_utf8())
}

pub fn split_shell_segments(core: &str, split_subclauses: bool) -> Vec<(String, String)> {
    let bytes = core.as_bytes();
    let n = bytes.len();
    let mut parts: Vec<(String, String)> = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<u8> = None;
    let mut prev_op = String::new();
    let mut i = 0usize;

    while i < n {
        let ch = bytes[i];
        if let Some(q) = quote {
            if q == b'\'' && ch == b'\'' && i + 1 < n && bytes[i + 1] == b'\'' {
                cur.push_str("''");
                i += 2;
                continue;
            }
            if q == b'"' && ch == b'`' && i + 1 < n {
                let step = 1 + utf8_char_len(core, i + 1);
                cur.push_str(&core[i..i + step]);
                i += step;
                continue;
            }
            if q == b'"' && ch == b'"' && i + 1 < n && bytes[i + 1] == b'"' {
                cur.push_str(r#""""#);
                i += 2;
                continue;
            }
            let step = utf8_char_len(core, i);
            cur.push_str(&core[i..i + step]);
            if ch == q {
                quote = None;
            }
            i += step;
            continue;
        }
        if ch == b'"' || ch == b'\'' {
            quote = Some(ch);
            cur.push(ch as char);
            i += 1;
            continue;
        }
        let mut sep_len = 0usize;
        let mut next_op = ";";
        if (ch == b'&' || ch == b'|') && i + 1 < n && bytes[i + 1] == ch {
            sep_len = 2;
            next_op = if ch == b'&' { "&&" } else { "||" };
        } else if split_subclauses && ch == b'$' && i + 1 < n && bytes[i + 1] == b'(' {
            sep_len = 2;
        } else if matches!(ch, b';' | b'\n' | b'\r' | b'|')
            || (split_subclauses && matches!(ch, b'(' | b')' | b'{' | b'}'))
        {
            sep_len = 1;
            next_op = if ch == b'|' { "|" } else { ";" };
        }
        if sep_len > 0 {
            let seg = cur.trim();
            if !seg.is_empty() {
                parts.push((prev_op, seg.to_string()));
            }
            prev_op = next_op.to_string();
            cur.clear();
            i += sep_len;
            continue;
        }
        let step = utf8_char_len(core, i);
        cur.push_str(&core[i..i + step]);
        i += step;
    }
    let tail = cur.trim();
    if !tail.is_empty() {
        parts.push((prev_op, tail.to_string()));
    }
    parts
}

fn split_ps_clauses(core: &str) -> Vec<String> {
    split_shell_segments(core, true)
        .into_iter()
        .map(|(_, seg)| seg)
        .collect()
}

fn all_ps_clauses(core: &str, subexprs: &[String]) -> Vec<String> {
    let mut clauses = split_ps_clauses(core);
    for sub in subexprs {
        clauses.extend(split_ps_clauses(sub));
    }
    clauses
}

fn shell_scan_surfaces(
    no_single: &str,
    unquoted: &str,
    subexprs: &[String],
) -> (String, String, String) {
    if subexprs.is_empty() {
        return (
            unquoted.to_string(),
            unquoted.to_string(),
            no_single.to_string(),
        );
    }
    let sub_raw = subexprs.join(" ; ");
    let sub_no_single = strip_single_quoted(&sub_raw);
    let sub_unquoted = strip_quoted(&sub_raw);
    (
        format!("{} {}", unquoted, sub_unquoted).trim().to_string(),
        format!("{} {}", unquoted, sub_no_single).trim().to_string(),
        format!("{} {}", no_single, sub_no_single).trim().to_string(),
    )
}

fn has_non_cmdlet_mutation(
    core: &str,
    unquoted_surface: &str,
    scan_surface: &str,
    no_single_surface: &str,
    subexprs: &[String],
) -> bool {
    if http_cmd_re().is_match(unquoted_surface) && is_http_mutating(core) {
        return true;
    }
    if mutating_git_re().is_match(scan_surface)
        || mutating_pkg_re().is_match(scan_surface)
        || mutating_stack_re().is_match(scan_surface)
        || system_or_net_mutating_re().is_match(no_single_surface)
    {
        return true;
    }
    let low_core = core.to_lowercase();
    if !low_core.contains("install.py")
        && !low_core.contains("worktree_guard.py")
        && !low_core.contains("chip_handoff.py")
    {
        return false;
    }
    // INVARIANT: Match quoted script paths (`install.py`, `worktree_guard.py`, `chip_handoff.py`) on raw clauses before `_strip_quoted` erases `'...'`.
    all_ps_clauses(core, subexprs)
        .iter()
        .any(|cl| is_install_py_mut(cl) || is_mutating_stack_seg(cl))
}

fn has_output_flag(seg: &str, seg_unq: &str) -> bool {
    !is_validation_segment(seg) && output_flag_re().is_match(seg_unq)
}

fn has_mutating_shell_pattern(
    core: &str,
    segments: &[(String, String)],
    no_single: &str,
    unquoted: &str,
    subexprs: &[String],
) -> bool {
    if has_inline_py(core) && inline_py_write_re().is_match(core) {
        return true;
    }
    let (unquoted_surface, scan_surface, no_single_surface) =
        shell_scan_surfaces(no_single, unquoted, subexprs);
    if has_non_null_file_redirect(&unquoted_surface)
        || mutating_cmdlet_re().is_match(&scan_surface)
        || has_non_cmdlet_mutation(
            core,
            &unquoted_surface,
            &scan_surface,
            &no_single_surface,
            subexprs,
        )
    {
        return true;
    }
    let mut all_segs: Vec<String> = segments.iter().map(|(_, s)| s.clone()).collect();
    for sub in subexprs {
        all_segs.extend(split_ps_clauses(sub));
    }
    for seg in &all_segs {
        if has_output_flag(seg, &strip_quoted(seg)) {
            return true;
        }
    }
    false
}

fn is_bookkeeping_segment(seg: &str) -> bool {
    let low = seg.to_lowercase();
    !low.contains("--merge")
        && !low.contains("--mirror-workspace")
        && bookkeeping_cmd_re().is_match(seg)
}

fn classify_non_mutating_segments(segments: &[(String, String)]) -> &'static str {
    if segments.is_empty() {
        return "READ_ONLY";
    }
    let mut val_count = 0usize;
    let mut last_val_idx = 0usize;
    let mut saw_bookkeeping = false;
    let mut has_or_chain = false;
    let n_segs = segments.len();

    for (idx, (op, seg)) in segments.iter().enumerate() {
        if op == "||" {
            has_or_chain = true;
        }
        if (op.is_empty() || op == ";" || op == "&&")
            && seg.trim().eq_ignore_ascii_case("$null")
            && idx + 1 < n_segs
            && segments[idx + 1].0 == "|"
        {
            continue;
        }
        if idx > 0 && op == "|" && ps_safe_filter_re().is_match(seg) {
            continue;
        }
        if is_bookkeeping_segment(seg) {
            saw_bookkeeping = true;
            continue;
        }
        if is_validation_segment(seg) {
            let is_null_pipe = op == "|"
                && idx > 0
                && (segments[idx - 1].0.is_empty()
                    || segments[idx - 1].0 == ";"
                    || segments[idx - 1].0 == "&&")
                && segments[idx - 1].1.trim().eq_ignore_ascii_case("$null");
            if !op.is_empty() && op != ";" && op != "&&" && !is_null_pipe {
                return "UNCERTAIN";
            }
            val_count += 1;
            last_val_idx = idx;
            continue;
        }
        if read_only_cmd_re().is_match(seg) || nav_segment_re().is_match(seg) {
            continue;
        }
        return "UNCERTAIN";
    }
    if val_count > 0 {
        // SAFETY: Conditional `||`, trailing segments/pipes, or multiple runners can skip or mask a test exit code.
        return if !has_or_chain && val_count == 1 && last_val_idx == n_segs - 1 {
            "VALIDATION"
        } else {
            "UNCERTAIN"
        };
    }
    if saw_bookkeeping {
        return "BOOKKEEPING";
    }
    "READ_ONLY"
}

fn has_validation_segment(cmd: &str) -> bool {
    let core = rio::unwrap_tokenade_command(cmd);
    !core.is_empty()
        && split_shell_segments(&core, false)
            .iter()
            .any(|(_, seg)| is_validation_segment(seg))
}

pub fn classify_shell_command(cmd: &str) -> &'static str {
    let core = rio::unwrap_tokenade_command(cmd);
    if core.is_empty() {
        return "READ_ONLY";
    }

    let no_single = strip_single_quoted(&core);
    let unquoted = strip_quoted(&core);
    let segments = split_shell_segments(&core, false);
    let subexprs = extract_ps_subexprs(&core);

    if has_mutating_shell_pattern(&core, &segments, &no_single, &unquoted, &subexprs) {
        return "MUTATING";
    }

    let has_dynamic_syntax = has_inline_py(&core)
        || !subexprs.is_empty()
        || unquoted.contains('(')
        || unquoted.contains(')')
        || unquoted.contains('{')
        || unquoted.contains('}')
        || unquoted.contains('`')
        || pre_flag_re().is_match(&unquoted);

    if has_dynamic_syntax {
        return "UNCERTAIN";
    }

    classify_non_mutating_segments(&segments)
}

fn abs_path_str(p: &Path) -> String {
    rio::resolve_abs_path(p).to_string_lossy().into_owned()
}

pub fn resolve_command_cwd(cmd: &str, default_cwd: &str, session: &str) -> String {
    let mut fallback_root = String::new();
    if !session.is_empty() {
        if let Some(Value::Object(existing)) = rio::read_json(&cwg_common::marker_path(session)) {
            if !json_truthy(existing.get("closed")) {
                fallback_root = existing
                    .get("git_root")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
            }
        }
    }
    rio::resolve_command_cwd(cmd, default_cwd, &fallback_root)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn meta_mtime_ns(meta: &fs::Metadata) -> u128 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos())
}

fn file_entry_token(full: &Path, prefix: &str, meta_opt: Option<&fs::Metadata>) -> String {
    let owned_meta;
    let st = match meta_opt {
        Some(m) => m,
        None => match fs::symlink_metadata(full) {
            Ok(m) => {
                owned_meta = m;
                &owned_meta
            }
            Err(e) if e.kind() == ErrorKind::NotFound => return format!("{}absent", prefix),
            Err(_) => return format!("{}stat_err", prefix),
        },
    };
    if st.file_type().is_symlink() || is_link_or_junction(full) {
        return format!("{}link:{}:{}", prefix, st.len(), meta_mtime_ns(st));
    }
    if !st.file_type().is_file() {
        return format!("{}dir:{}", prefix, meta_mtime_ns(st));
    }
    if st.len() <= MAX_HASHED_SNAPSHOT_BYTES {
        match fs::read(full) {
            Ok(bytes) => {
                let digest = sha256_hex(&bytes);
                return format!("{}{}:{}", prefix, st.len(), &digest[..20]);
            }
            Err(e) if e.kind() == ErrorKind::NotFound => return format!("{}absent", prefix),
            Err(_) => return format!("{}stat_err", prefix),
        }
    }
    format!("{}large:{}:{}", prefix, st.len(), meta_mtime_ns(st))
}

fn scan_non_git_snapshot(cwd: &str) -> Value {
    let norm_cwd = rio::normalize_path(cwd);
    let unmeasured = || -> Value {
        json!({
            "in_git": false,
            "cwd": norm_cwd,
            "unmeasured": true,
        })
    };
    if cwd.is_empty() || !Path::new(cwd).is_dir() {
        return unmeasured();
    }
    let abs_cwd = rio::resolve_abs_path(Path::new(cwd));
    let mut candidates: Vec<(PathBuf, fs::Metadata)> = Vec::new();
    let mut stack: Vec<(PathBuf, usize)> = vec![(abs_cwd.clone(), 0)];

    // INVARIANT: Enforce NON_GIT_SCAN_MAX_FILES before reading/hashing any file bytes, and mark truncated depth unmeasured.
    while let Some((cur_dir, depth)) = stack.pop() {
        let Ok(rd) = fs::read_dir(&cur_dir) else {
            return unmeasured();
        };
        for ent_res in rd {
            let Ok(ent) = ent_res else {
                return unmeasured();
            };
            let ent_path = ent.path();
            if is_link_or_junction(&ent_path) {
                continue;
            }
            let Ok(ft) = ent.file_type() else {
                return unmeasured();
            };
            if ft.is_dir() {
                let name = ent.file_name().to_string_lossy().into_owned();
                if NON_GIT_SKIP_DIRS.iter().any(|&s| s == name) {
                    continue;
                }
                if depth >= NON_GIT_SCAN_MAX_DEPTH {
                    return unmeasured();
                }
                stack.push((ent_path, depth + 1));
            } else if ft.is_file() {
                let rel = ent_path
                    .strip_prefix(&abs_cwd)
                    .map(|p| p.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_else(|_| ent_path.to_string_lossy().replace('\\', "/"));
                if cache_path_re().is_match(&rel) {
                    continue;
                }
                if candidates.len() >= NON_GIT_SCAN_MAX_FILES {
                    return unmeasured();
                }
                let Ok(st) = fs::symlink_metadata(&ent_path) else {
                    return unmeasured();
                };
                candidates.push((ent_path, st));
            }
        }
    }

    let mut entries = Map::new();
    for (fpath, st) in candidates {
        let norm_f = rio::normalize_path(&fpath.to_string_lossy());
        let tok = file_entry_token(&fpath, "F:", Some(&st));
        entries.insert(norm_f, Value::String(tok));
    }
    json!({
        "in_git": false,
        "cwd": norm_cwd,
        "entries": Value::Object(entries),
        "unmeasured": false,
    })
}

fn in_explicit_workspaces(path: &str, workspace_paths: &[String]) -> bool {
    if path.is_empty() || workspace_paths.is_empty() {
        return false;
    }
    let folded = rio::fold_path(path);
    for wp in workspace_paths {
        if !wp.trim().is_empty() {
            let fwp = rio::fold_path(wp);
            if !fwp.is_empty() && (folded == fwp || folded.starts_with(&(fwp + "/"))) {
                return true;
            }
        }
    }
    false
}

fn run_git_bytes(cwd: &str, args: &[&str], timeout_sec: f64) -> (i32, Vec<u8>) {
    let eff_to = timeout_sec.max(0.25);
    let timeout_ms = (eff_to * 1000.0).round() as u64;
    let mut full_args = Vec::with_capacity(args.len() + 1);
    full_args.push("--no-optional-locks".to_string());
    for &a in args {
        full_args.push(a.to_string());
    }
    let env_pairs = [("GIT_TERMINAL_PROMPT", "0"), ("GIT_OPTIONAL_LOCKS", "0")];
    let cwd_opt = if cwd.trim().is_empty() {
        None
    } else {
        Some(Path::new(cwd))
    };
    match run_command_with_job("git", &full_args, cwd_opt, &env_pairs, None, Some(timeout_ms)) {
        Ok(res) => {
            if res.timed_out {
                (124, Vec::new())
            } else {
                (res.code, res.stdout)
            }
        }
        Err(_) => (127, Vec::new()),
    }
}

pub fn take_git_snapshot(
    cwd: &str,
    artifact_dir: &str,
    workspace_paths: &[String],
    known_git_root: Option<&str>,
) -> Value {
    if cwd.is_empty()
        || (rio::is_plugin_runtime_dir(cwd) && !in_explicit_workspaces(cwd, workspace_paths))
    {
        // INVARIANT: Never treat or scan the installed plugin bundle directory as a fallback user project.
        return json!({
            "in_git": false,
            "cwd": "",
            "entries": {},
            "unmeasured": false,
            "no_project": true,
        });
    }
    if cwg_common::is_session_scratch_path(cwd, artifact_dir, workspace_paths) {
        return json!({
            "in_git": false,
            "cwd": rio::normalize_path(cwd),
            "entries": {},
            "unmeasured": false,
            "ephemeral_cwd": true,
        });
    }
    let root_opt = match known_git_root {
        Some(kgr) => {
            if !kgr.is_empty() && Path::new(kgr).join(".git").exists() {
                Some(kgr.to_string())
            } else {
                rio::git_toplevel(cwd, false)
            }
        }
        None => rio::git_toplevel(cwd, false),
    };
    let Some(root) = root_opt.filter(|s| !s.is_empty()) else {
        return scan_non_git_snapshot(cwd);
    };

    let (rc_h, head_out, _) = rio::run_git(&root, &["rev-parse", "--verify", "-q", "HEAD"], 3.0);
    let head = if rc_h == 0 {
        head_out.trim().to_string()
    } else {
        String::new()
    };
    let (rc_s, status_bytes) =
        run_git_bytes(&root, &["status", "--porcelain=v1", "-z", "-uall"], 5.0);
    if rc_s != 0 {
        return json!({
            "in_git": true,
            "root": rio::normalize_path(&root),
            "head": head,
            "unmeasured": true,
        });
    }

    let mut entries = Map::new();
    let records: Vec<&[u8]> = status_bytes.split(|&b| b == 0).collect();
    let mut i = 0usize;
    while i < records.len() {
        let rec = records[i];
        i += 1;
        if rec.len() < 4 {
            continue;
        }
        let xy = String::from_utf8_lossy(&rec[..2]).into_owned();
        let rel = String::from_utf8_lossy(&rec[3..]).into_owned();
        // INVARIANT: `git status --porcelain=v1 -z` emits an extra NUL-terminated original-path slot after rename/copy entries.
        if xy.contains('R') || xy.contains('C') {
            if i < records.len() {
                i += 1;
            }
        }
        if cache_path_re().is_match(&rel.replace('\\', "/")) {
            continue;
        }
        let full = Path::new(&root).join(&rel);
        let norm_full = rio::normalize_path(&full.to_string_lossy());
        let tok = file_entry_token(&full, &format!("{}:", xy), None);
        entries.insert(norm_full, Value::String(tok));
    }

    json!({
        "in_git": true,
        "root": rio::normalize_path(&root),
        "head": head,
        "entries": Value::Object(entries),
        "unmeasured": false,
    })
}

fn strip_git_xy_prefix(tok: &str) -> &str {
    let bytes = tok.as_bytes();
    if bytes.len() >= 3 && bytes[2] == b':' {
        &tok[3..]
    } else {
        tok
    }
}

fn git_entry_unchanged_on_disk(path: &str, b_tok: &str, a_tok: Option<&str>) -> bool {
    let b_xy = if b_tok.as_bytes().len() >= 3 && b_tok.as_bytes()[2] == b':' {
        &b_tok[..2]
    } else {
        ""
    };
    let b_ctok = strip_git_xy_prefix(b_tok);
    if b_ctok == "stat_err"
        || b_ctok.starts_with("link:")
        || b_ctok.starts_with("dir:")
        || b_ctok.starts_with("large:")
    {
        return false;
    }
    if b_ctok == "absent" && !b_xy.contains('D') {
        return false;
    }
    if let Some(a) = a_tok {
        let a_xy = if a.as_bytes().len() >= 3 && a.as_bytes()[2] == b':' {
            &a[..2]
        } else {
            ""
        };
        if b_ctok == "absent" {
            return a_xy.contains('D') && strip_git_xy_prefix(a) == "absent";
        }
        return strip_git_xy_prefix(a) == b_ctok;
    }
    let p = Path::new(path);
    let st = match fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::NotFound => return b_ctok == "absent",
        Err(_) => return false,
    };
    if b_ctok == "absent"
        || st.file_type().is_symlink()
        || !st.file_type().is_file()
        || is_link_or_junction(p)
        || st.len() > MAX_HASHED_SNAPSHOT_BYTES
        || !b_ctok.starts_with(&format!("{}:", st.len()))
    {
        return false;
    }
    file_entry_token(p, "", Some(&st)) == b_ctok
}

pub fn diff_git_snapshots(before: Option<&Value>, after: Option<&Value>) -> (Vec<String>, bool) {
    let (Some(Value::Object(b_obj)), Some(Value::Object(a_obj))) = (before, after) else {
        return (Vec::new(), true);
    };
    if json_truthy(b_obj.get("unmeasured")) || json_truthy(a_obj.get("unmeasured")) {
        return (Vec::new(), true);
    }
    let b_in_git = json_truthy(b_obj.get("in_git"));
    let a_in_git = json_truthy(a_obj.get("in_git"));
    if b_in_git != a_in_git {
        return (Vec::new(), true);
    }
    if !b_in_git {
        let b_cwd = b_obj.get("cwd").and_then(|v| v.as_str()).unwrap_or("");
        let a_cwd = a_obj.get("cwd").and_then(|v| v.as_str()).unwrap_or("");
        if rio::fold_path(b_cwd) != rio::fold_path(a_cwd) {
            return (Vec::new(), true);
        }
    } else {
        let b_root = b_obj.get("root").and_then(|v| v.as_str()).unwrap_or("");
        let a_root = a_obj.get("root").and_then(|v| v.as_str()).unwrap_or("");
        if rio::fold_path(b_root) != rio::fold_path(a_root) {
            return (Vec::new(), true);
        }
    }

    let mut changed: HashSet<String> = HashSet::new();
    let empty_map = Map::new();
    let b_entries = b_obj
        .get("entries")
        .and_then(|v| v.as_object())
        .unwrap_or(&empty_map);
    let a_entries = a_obj
        .get("entries")
        .and_then(|v| v.as_object())
        .unwrap_or(&empty_map);

    if !a_in_git {
        for (path, tok_v) in a_entries {
            let tok = tok_v.as_str().unwrap_or("");
            let b_tok = b_entries.get(path).and_then(|v| v.as_str());
            if b_tok != Some(tok) {
                changed.insert(path.clone());
            }
        }
        for path in b_entries.keys() {
            if !a_entries.contains_key(path) {
                changed.insert(path.clone());
            }
        }
        let mut out: Vec<String> = changed.into_iter().collect();
        out.sort();
        return (out, false);
    }

    // INVARIANT: Pure `git add` / `git commit` of already-dirty working-tree files keeps on-disk SHA-256 identical and must be treated as OPERATIONAL rather than reopening a PERSISTENT code-edit candidate.
    let mut unchanged_clean: HashSet<String> = HashSet::new();
    for (path, tok_v) in a_entries {
        let tok = tok_v.as_str().unwrap_or("");
        let b_tok = b_entries.get(path).and_then(|v| v.as_str());
        if b_tok.map_or(true, |bt| !git_entry_unchanged_on_disk(path, bt, Some(tok))) {
            changed.insert(path.clone());
        }
    }
    for (path, b_tok_v) in b_entries {
        if !a_entries.contains_key(path) {
            let b_tok = b_tok_v.as_str().unwrap_or("");
            if git_entry_unchanged_on_disk(path, b_tok, None) {
                unchanged_clean.insert(path.clone());
            } else {
                changed.insert(path.clone());
            }
        }
    }

    // INVARIANT: Files modified & committed during a shell command leave status clean, so diff HEAD transitions explicitly.
    let b_head = b_obj.get("head").and_then(|v| v.as_str()).unwrap_or("");
    let a_head = a_obj.get("head").and_then(|v| v.as_str()).unwrap_or("");
    let root = a_obj.get("root").and_then(|v| v.as_str()).unwrap_or("");
    if !a_head.is_empty() && a_head != b_head && !root.is_empty() {
        let mut diff_args: Vec<&str> = vec!["diff-tree", "--no-commit-id", "--name-only", "-r", "-z"];
        if !b_head.is_empty() {
            diff_args.push(b_head);
            diff_args.push(a_head);
        } else {
            diff_args.push("--root");
            diff_args.push(a_head);
        }
        let (rc, out_bytes) = run_git_bytes(root, &diff_args, 4.0);
        if rc != 0 {
            let mut out: Vec<String> = changed.into_iter().collect();
            out.sort();
            return (out, true);
        }
        for rel_b in out_bytes.split(|&b| b == 0) {
            if rel_b.is_empty() {
                continue;
            }
            let rel = String::from_utf8_lossy(rel_b).into_owned();
            if !cache_path_re().is_match(&rel.replace('\\', "/")) {
                let norm_p = rio::normalize_path(&Path::new(root).join(&rel).to_string_lossy());
                if !unchanged_clean.contains(&norm_p) {
                    changed.insert(norm_p);
                }
            }
        }
    }

    let mut out: Vec<String> = changed.into_iter().collect();
    out.sort();
    (out, false)
}

fn estimate_changed_lines(tool_name: &str, args: &Map<String, Value>) -> i64 {
    if tool_name == "edit_file" {
        let target = args.get("Target").and_then(|v| v.as_str()).unwrap_or("");
        let repl = args.get("Replacement").and_then(|v| v.as_str()).unwrap_or("");
        let t_lines: Vec<&str> = target.lines().collect();
        let r_lines: Vec<&str> = repl.lines().collect();
        let mut prefix = 0usize;
        while prefix < t_lines.len() && prefix < r_lines.len() && t_lines[prefix] == r_lines[prefix]
        {
            prefix += 1;
        }
        let mut suffix = 0usize;
        while suffix < (t_lines.len() - prefix)
            && suffix < (r_lines.len() - prefix)
            && t_lines[t_lines.len() - 1 - suffix] == r_lines[r_lines.len() - 1 - suffix]
        {
            suffix += 1;
        }
        let changed_t = t_lines.len().saturating_sub(prefix + suffix);
        let changed_r = r_lines.len().saturating_sub(prefix + suffix);
        return (changed_t.max(changed_r) as i64).max(1);
    }
    if tool_name == "write_file" {
        let content = args.get("Content").and_then(|v| v.as_str()).unwrap_or("");
        return (content.lines().count() as i64).max(1);
    }
    10
}

fn refresh_swarm_round_fields(marker: &mut Value, session: &str, repo_root: &str, fp: &str) {
    let paths_arr: Vec<Value> = marker
        .get("paths")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let changed_lines = marker
        .get("changed_lines")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let fresh_probe = json!({
        "paths": paths_arr,
        "changed_lines": changed_lines,
    });
    let head_seq = cwg_common::swarm_board_head_seq(session, repo_root, "", None);
    let diff_metrics = cwg_common::compute_diff_metrics(&fresh_probe, repo_root, None);
    if let Value::Object(obj) = marker {
        let round_id = obj.get("round_id").and_then(|v| v.as_i64()).unwrap_or(0) + 1;
        obj.insert("round_id".to_string(), json!(round_id));
        obj.insert("round_start_msg_id".to_string(), json!(head_seq));
        obj.insert("current_diff_hash".to_string(), Value::String(fp.to_string()));
        obj.insert("diff_metrics".to_string(), diff_metrics);
    }
}

fn resolve_known_or_git_root(known_git_root: Option<&str>, eff_cwd: &str) -> String {
    match known_git_root {
        Some(kgr) if kgr.is_empty() || Path::new(kgr).join(".git").exists() => kgr.to_string(),
        _ => {
            if eff_cwd.is_empty() {
                String::new()
            } else {
                rio::git_toplevel(eff_cwd, false).unwrap_or_default()
            }
        }
    }
}

fn update_candidate_marker(
    session: &str,
    cwd: &str,
    durable_new_paths: &[String],
    operational_mutation: bool,
    changed_lines_delta: i64,
    shell_durable_edit: bool,
    unknown_barrier: bool,
    cause_label: &str,
    known_git_root: Option<&str>,
) -> (Option<Value>, Value) {
    let now = now_sec();
    let mp = cwg_common::marker_path(session);
    let before = rio::read_json(&mp);
    let eff_cwd: String = if !cwd.is_empty() {
        cwd.to_string()
    } else if let Some(first_p) = durable_new_paths.first() {
        Path::new(first_p)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default()
    } else {
        String::new()
    };

    let (before_open, mut marker): (Option<Value>, Value) = match before {
        Some(Value::Object(ref bmap)) if !json_truthy(bmap.get("closed")) => {
            let mut m = bmap.clone();
            let cur_cwd = m.get("cwd").and_then(|v| v.as_str()).unwrap_or("");
            if cur_cwd.is_empty() && !eff_cwd.is_empty() {
                m.insert(
                    "cwd".to_string(),
                    Value::String(rio::normalize_path(&eff_cwd)),
                );
                let cur_gr = m.get("git_root").and_then(|v| v.as_str()).unwrap_or("");
                if cur_gr.is_empty() {
                    let git_top = resolve_known_or_git_root(known_git_root, &eff_cwd);
                    m.insert(
                        "git_root".to_string(),
                        Value::String(rio::normalize_path(&git_top)),
                    );
                }
            }
            (Some(Value::Object(bmap.clone())), Value::Object(m))
        }
        _ => {
            let git_top = resolve_known_or_git_root(known_git_root, &eff_cwd);
            let m = json!({
                "session": session,
                "first_ts": now,
                "last_ts": now,
                "last_durable_ts": if durable_new_paths.is_empty() { 0.0 } else { now },
                "cwd": rio::normalize_path(&eff_cwd),
                "git_root": rio::normalize_path(&git_top),
                "paths": [],
                "operational": false,
                "changed_lines": 0,
                "edits": 0,
                "shell_durable_edit": false,
                "content_marks": [],
                "closed": false,
            });
            (None, m)
        }
    };

    let cause_trunc: String = cause_label.chars().take(120).collect();
    if let Value::Object(ref mut m) = marker {
        m.insert("last_ts".to_string(), json!(now));
    }

    if !durable_new_paths.is_empty() {
        let mut combined = cwg_common::durable_paths_from_val(marker.get("paths"));
        combined.extend(durable_new_paths.iter().cloned());
        let merged_paths = cwg_common::durable_paths(&combined);
        let fp = cwg_common::content_fingerprint(&merged_paths, MAX_FINGERPRINT_FILE_BYTES);

        let mut marks = marker
            .get("content_marks")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let last_fp = marks
            .last()
            .and_then(|v| v.get("fp"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let last_unknown = marks
            .last()
            .map_or(false, |v| json_truthy(v.get("unknown")));
        let mark_unknown = fp.is_empty() && unknown_barrier;
        let changed_fp = marks.is_empty() || last_fp != fp || mark_unknown || last_unknown;
        if changed_fp {
            let mut mark_obj = Map::new();
            mark_obj.insert("ts".to_string(), json!(now));
            mark_obj.insert(
                "fp".to_string(),
                if fp.is_empty() {
                    Value::Null
                } else {
                    Value::String(fp.clone())
                },
            );
            mark_obj.insert("cause".to_string(), Value::String(cause_trunc));
            if mark_unknown {
                mark_obj.insert("unknown".to_string(), Value::Bool(true));
            }
            marks.push(Value::Object(mark_obj));
        }

        if let Value::Object(ref mut m) = marker {
            m.insert(
                "paths".to_string(),
                Value::Array(merged_paths.into_iter().map(Value::String).collect()),
            );
            m.insert("last_durable_ts".to_string(), json!(now));
            let edits = m.get("edits").and_then(|v| v.as_i64()).unwrap_or(0) + 1;
            let cl = m.get("changed_lines").and_then(|v| v.as_i64()).unwrap_or(0)
                + changed_lines_delta.max(1);
            m.insert("edits".to_string(), json!(edits));
            m.insert("changed_lines".to_string(), json!(cl));
            if shell_durable_edit {
                m.insert("shell_durable_edit".to_string(), Value::Bool(true));
            }
        }
        cwg_common::trim_content_marks(&mut marker, marks);
        let has_round_id = marker
            .get("round_id")
            .and_then(|v| v.as_i64())
            .map_or(false, |r| r != 0);
        if changed_fp || !has_round_id {
            let repo_root = marker_repo_root(&marker, &eff_cwd);
            refresh_swarm_round_fields(&mut marker, session, &repo_root, &fp);
        }
    } else if operational_mutation {
        if let Value::Object(ref mut m) = marker {
            m.insert("operational".to_string(), Value::Bool(true));
        }
        let dpaths = cwg_common::durable_paths_from_val(marker.get("paths"));
        if !dpaths.is_empty() {
            let mut marks = marker
                .get("content_marks")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let fp = cwg_common::content_fingerprint(&dpaths, MAX_FINGERPRINT_FILE_BYTES);
            let last_fp = marks
                .last()
                .and_then(|v| v.as_str().map(|_| ""))
                .or_else(|| {
                    marks
                        .last()
                        .and_then(|v| v.as_object())
                        .and_then(|o| o.get("fp"))
                        .and_then(|v| v.as_str())
                })
                .unwrap_or("");
            let last_has_fp_str = marks
                .last()
                .and_then(|v| v.as_object())
                .and_then(|o| o.get("fp"))
                .and_then(|v| v.as_str())
                .is_some();
            let repo_root = marker_repo_root(&marker, &eff_cwd);

            if fp.is_empty() {
                marks.push(json!({
                    "ts": now,
                    "fp": null,
                    "unknown": true,
                    "cause": cause_trunc,
                }));
                cwg_common::trim_content_marks(&mut marker, marks);
                refresh_swarm_round_fields(&mut marker, session, &repo_root, "");
            } else if !last_has_fp_str || fp != last_fp {
                marks.push(json!({
                    "ts": now,
                    "fp": fp,
                    "cause": cause_trunc,
                }));
                if let Value::Object(ref mut m) = marker {
                    m.insert("last_durable_ts".to_string(), json!(now));
                }
                cwg_common::trim_content_marks(&mut marker, marks);
                refresh_swarm_round_fields(&mut marker, session, &repo_root, &fp);
            } else if marks
                .last()
                .map_or(false, |v| json_truthy(v.get("unknown")))
            {
                // INVARIANT: Clear legacy unknown flag when SHA-256 fingerprint is confirmed identical.
                if let Some(Value::Object(last_obj)) = marks.last_mut() {
                    last_obj.remove("unknown");
                }
                cwg_common::trim_content_marks(&mut marker, marks);
            }
        }
    }

    let _ = rio::write_json(&mp, &marker);
    (before_open, marker)
}

fn marker_repo_root(marker: &Value, eff_cwd: &str) -> String {
    let gr = marker
        .get("git_root")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !gr.is_empty() {
        return gr.to_string();
    }
    let cwd = marker.get("cwd").and_then(|v| v.as_str()).unwrap_or("");
    if !cwd.is_empty() {
        return cwd.to_string();
    }
    eff_cwd.to_string()
}

fn build_transition_note(
    before: Option<&Value>,
    after: &Value,
    ctx: Option<&Value>,
) -> Option<String> {
    let new_class = cwg_common::candidate_class(after);
    if new_class != cwg_common::WORK_PERSISTENT {
        return None;
    }
    let owned_ctx;
    let cctx = match ctx {
        Some(c) => c,
        None => {
            owned_ctx = cwg_common::resolve_candidate_context(after, false);
            &owned_ctx
        }
    };
    let needs_simplify = json_truthy(cctx.get("needs_simplify"));
    let needs_review = json_truthy(cctx.get("needs_review"));
    if !needs_simplify && !needs_review {
        return None;
    }
    let policy = cctx.get("policy");
    let dpaths = cwg_common::durable_paths_from_val(cctx.get("dpaths"));
    let new_floor = cctx
        .get("floor")
        .and_then(|v| v.as_str())
        .unwrap_or("STANDARD");

    if let Some(b) = before {
        if cwg_common::candidate_class(b) == new_class {
            let old_cctx = cwg_common::resolve_candidate_context(b, false);
            let old_floor = old_cctx.get("floor").and_then(|v| v.as_str()).unwrap_or("");
            if old_floor == new_floor
                && json_truthy(old_cctx.get("needs_simplify")) == needs_simplify
                && json_truthy(old_cctx.get("needs_review")) == needs_review
            {
                return None;
            }
        }
    }

    let req_tests = match cctx.get("require_tests") {
        Some(Value::Bool(b)) => *b,
        _ => {
            let cwd = cctx.get("cwd").and_then(|v| v.as_str()).unwrap_or("");
            let git_root = cctx
                .get("git_root")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            cwg_common::requires_tests(new_floor, cwd, &dpaths, policy, git_root)
        }
    };

    let start = dpaths.len().saturating_sub(3);
    let shown: Vec<&str> = dpaths[start..]
        .iter()
        .map(|p| p.rsplit('/').next().unwrap_or(p.as_str()))
        .collect();
    let reqs = cwg_common::receipt_requirements_summary(new_floor, policy, req_tests);
    Some(format!(
        "[Code Work Gate] `{}` ({}ф: {}): {}. Финал: `[gate] verified: {}; <кандидат и проверки>`.",
        new_floor,
        dpaths.len(),
        shown.join(", "),
        reqs,
        new_floor,
    ))
}

fn capture_direct_codex_packet(cmd: &str, cwd: &str, session: &str) {
    let low = cmd.to_lowercase();
    if !low.contains("codex")
        || !low.contains("exec")
        || low.contains("codex_lane.py")
        || low.contains("codex-lane")
        || low.contains("codex_lane")
    {
        return;
    }
    let Some(caps) = review_id_re().captures(cmd) else {
        return;
    };
    let Some(rid) = caps.get(1).map(|m| m.as_str()) else {
        return;
    };
    let eff = if low.contains("xhigh") { "xhigh" } else { "high" };
    let _ = crate::codex_lane::record_packet(rid, cmd, cwd, eff, "ordinary", session);
}

pub fn fold_ps_line_continuations(cmd_str: &str) -> String {
    // INVARIANT: Fold only PowerShell backtick line-continuations (`` ` `` + optional horizontal space + newline) outside quotes; bare newlines and arbitrary backticks remain untouched and rejected as multi-statement / escape hazards.
    if !cmd_str.contains('`') || (!cmd_str.contains('\n') && !cmd_str.contains('\r')) {
        return cmd_str.to_string();
    }
    let bytes = cmd_str.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(n);
    let mut quote: Option<u8> = None;
    let mut i = 0usize;
    while i < n {
        let ch = bytes[i];
        if let Some(q) = quote {
            let step = utf8_char_len(cmd_str, i);
            out.push_str(&cmd_str[i..i + step]);
            if ch == q {
                if i + 1 < n && bytes[i + 1] == q {
                    out.push(q as char);
                    i += 2;
                    continue;
                }
                quote = None;
            }
            i += step;
            continue;
        }
        if ch == b'\'' || ch == b'"' {
            quote = Some(ch);
            out.push(ch as char);
            i += 1;
            continue;
        }
        if ch == b'`' {
            let mut k = i + 1;
            while k < n && (bytes[k] == b' ' || bytes[k] == b'\t') {
                k += 1;
            }
            if k < n && bytes[k] == b'\r' && k + 1 < n && bytes[k + 1] == b'\n' {
                out.push(' ');
                i = k + 2;
                continue;
            }
            if k < n && bytes[k] == b'\n' {
                out.push(' ');
                i = k + 1;
                continue;
            }
        }
        let step = utf8_char_len(cmd_str, i);
        out.push_str(&cmd_str[i..i + step]);
        i += step;
    }
    out
}

pub fn unquote_ps_literal(raw: &str) -> String {
    let s = raw.trim();
    if s.len() >= 2 && s.starts_with('\'') && s.ends_with('\'') {
        return s[1..s.len() - 1].replace("''", "'");
    }
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        let replaced = s[1..s.len() - 1].replace("\"\"", "\"");
        let mut out = String::with_capacity(replaced.len());
        let mut chars = replaced.chars();
        while let Some(c) = chars.next() {
            if c == '`' {
                if let Some(nc) = chars.next() {
                    out.push(nc);
                } else {
                    out.push('`');
                }
            } else {
                out.push(c);
            }
        }
        return out;
    }
    s.to_string()
}

fn is_safe_var_value(val: &str) -> bool {
    val.len() <= MAX_VAR_VALUE_LEN && !val.chars().any(|c| matches!(c, '"' | '`' | '$' | '\r' | '\n'))
}

fn substitute_var_refs(chunk: &str, vars_map: &std::collections::HashMap<String, String>, unquoted_mode: bool, left_adj_quote: bool, right_adj_quote: bool) -> String {
    let re = ps_var_ref_re();
    let mut out = String::with_capacity(chunk.len());
    let mut last = 0usize;
    let mut pos = 0usize;
    while pos <= chunk.len() {
        let Some(caps) = re.captures_at(chunk, pos) else {
            break;
        };
        let whole = caps.get(0).expect("g0");
        let s_idx = whole.start();
        let e_idx = whole.end();
        // WORKAROUND: Emulates `(?<!`)\$` without lookbehind.
        let escaped_by_backtick = s_idx > 0 && chunk.as_bytes()[s_idx - 1] == b'`';
        if escaped_by_backtick {
            pos = e_idx.max(pos + 1);
            continue;
        }
        let key = caps
            .get(1)
            .or_else(|| caps.get(2))
            .map_or("", |m| m.as_str())
            .to_lowercase();
        let Some(val) = vars_map.get(&key) else {
            pos = e_idx.max(pos + 1);
            continue;
        };
        if unquoted_mode {
            let adj_left = (s_idx == 0 && left_adj_quote)
                || (s_idx > 0 && matches!(chunk.as_bytes()[s_idx - 1], b'\'' | b'"'));
            let adj_right = (e_idx == chunk.len() && right_adj_quote)
                || (e_idx < chunk.len() && matches!(chunk.as_bytes()[e_idx], b'\'' | b'"'));
            if adj_left || adj_right {
                pos = e_idx.max(pos + 1);
                continue;
            }
            out.push_str(&chunk[last..s_idx]);
            if ps_safe_bare_re().is_match(val) {
                out.push_str(val);
            } else {
                out.push('\'');
                out.push_str(&val.replace('\'', "''"));
                out.push('\'');
            }
        } else {
            out.push_str(&chunk[last..s_idx]);
            out.push_str(val);
        }
        last = e_idx;
        pos = e_idx.max(pos + 1);
    }
    out.push_str(&chunk[last..]);
    out
}

fn expand_vars_outside_single_quotes(
    text: &str,
    vars_map: &std::collections::HashMap<String, String>,
) -> String {
    if vars_map.is_empty() || !text.contains('$') {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, bool)> = ps_quoted_re()
        .captures_iter(text)
        .map(|c| {
            let g0 = c.get(0).expect("g0");
            (g0.start(), g0.end(), c.get(1).is_some())
        })
        .collect();
    let mut out = String::with_capacity(text.len());
    let mut last = 0usize;
    for (idx, &(ms, me, is_sq)) in matches.iter().enumerate() {
        out.push_str(&substitute_var_refs(
            &text[last..ms],
            vars_map,
            true,
            idx > 0,
            true,
        ));
        if is_sq {
            out.push_str(&text[ms..me]);
        } else {
            out.push_str(&substitute_var_refs(&text[ms..me], vars_map, false, false, false));
        }
        last = me;
    }
    out.push_str(&substitute_var_refs(
        &text[last..],
        vars_map,
        true,
        !matches.is_empty(),
        false,
    ));
    out
}

pub fn ps_tokens(seg: &str) -> Vec<String> {
    let bytes = seg.as_bytes();
    let n = bytes.len();
    let mut tokens: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<u8> = None;
    let mut i = 0usize;
    while i < n {
        let ch = bytes[i];
        if let Some(q) = quote {
            if q == b'\'' && ch == b'\'' && i + 1 < n && bytes[i + 1] == b'\'' {
                cur.push('\'');
                i += 2;
                continue;
            }
            if q == b'"' && ch == b'"' && i + 1 < n && bytes[i + 1] == b'"' {
                cur.push('"');
                i += 2;
                continue;
            }
            if q == b'"' && ch == b'`' && i + 1 < n {
                let nc = seg[i + 1..].chars().next().unwrap_or('`');
                cur.push(nc);
                i += 1 + nc.len_utf8();
                continue;
            }
            if ch == q {
                quote = None;
                i += 1;
                continue;
            }
            let c = seg[i..].chars().next().unwrap_or('\0');
            cur.push(c);
            i += c.len_utf8();
            continue;
        }
        if ch == b'\'' || ch == b'"' {
            quote = Some(ch);
            i += 1;
            continue;
        }
        let c = seg[i..].chars().next().unwrap_or('\0');
        if c.is_whitespace() {
            if !cur.is_empty() {
                tokens.push(std::mem::take(&mut cur));
            }
            i += c.len_utf8();
            continue;
        }
        cur.push(c);
        i += c.len_utf8();
    }
    if quote.is_some() {
        return Vec::new();
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

fn is_ps_abs_path(s: &str) -> bool {
    if cfg!(windows) {
        win_drive_prefix_re().is_match(s) || s.starts_with(r"\\")
    } else {
        Path::new(s).is_absolute()
    }
}

fn resolve_ps_path(raw_path: &str, cur_cwd: &str) -> Option<String> {
    let cleaned = raw_path.trim();
    if cleaned.is_empty()
        || cleaned.contains('$')
        || cleaned.contains('`')
        || cleaned.contains(',')
    {
        return None;
    }
    if cleaned.contains(':') && !win_drive_prefix_re().is_match(cleaned) {
        return None;
    }
    if is_ps_abs_path(cleaned) {
        return Some(abs_path_str(Path::new(cleaned)));
    }
    if !cur_cwd.is_empty() {
        return Some(abs_path_str(&Path::new(cur_cwd).join(cleaned)));
    }
    None
}

fn posix_parent(norm_slashes: &str) -> String {
    let trimmed = norm_slashes.trim_end_matches('/');
    if trimmed.is_empty() {
        return if norm_slashes.starts_with('/') {
            "/".to_string()
        } else {
            ".".to_string()
        };
    }
    match trimmed.rsplit_once('/') {
        Some(("", _)) => "/".to_string(),
        Some((parent, _)) => parent.to_string(),
        None => ".".to_string(),
    }
}

fn resolve_ephemeral_target(
    raw_path: &str,
    cur_cwd: &str,
    artifact_dir: &str,
    workspace_paths: &[String],
) -> Option<String> {
    let mut cleaned = raw_path.trim().to_string();
    if cleaned.is_empty()
        || cleaned.contains('$')
        || cleaned.contains('`')
        || cleaned.contains(',')
    {
        return None;
    }
    if cleaned.contains(':') && !win_drive_prefix_re().is_match(&cleaned) {
        return None;
    }
    let norm_slashes = cleaned.replace('\\', "/");
    let parts: Vec<&str> = norm_slashes.split(|c| c == '/').filter(|p| !p.is_empty()).collect();
    if parts.len() > 1
        && parts[..parts.len() - 1]
            .iter()
            .any(|pt| pt.contains('*') || pt.contains('?'))
    {
        return None;
    }
    if parts
        .last()
        .map_or(false, |pt| pt.contains('*') || pt.contains('?'))
    {
        let parent_str = posix_parent(&norm_slashes);
        cleaned = if parent_str.is_empty() || parent_str == "." {
            cur_cwd.to_string()
        } else {
            parent_str
        };
    }
    let resolved = resolve_ps_path(&cleaned, cur_cwd)?;
    if !cwg_common::is_session_scratch_path(&resolved, artifact_dir, workspace_paths) {
        return None;
    }
    Some(resolved)
}

fn parse_cmdlet_args(
    toks: &[String],
    allow_dest: bool,
    extra_flag: &str,
) -> Option<(Vec<String>, Vec<String>, Vec<String>, String, bool)> {
    let mut path_vals = Vec::new();
    let mut dest_vals = Vec::new();
    let mut positionals = Vec::new();
    let mut extra_val = String::new();
    let mut saw_value_flag = false;
    let mut idx = 1usize;
    while idx < toks.len() {
        let tk = &toks[idx];
        let low_tk = tk.to_lowercase();
        if PS_BOOL_SWITCHES.iter().any(|&f| f == low_tk) {
            idx += 1;
        } else if PS_NON_PATH_VALUE_FLAGS.iter().any(|&f| f == low_tk) {
            if idx + 1 >= toks.len() {
                return None;
            }
            if low_tk == "-value" {
                saw_value_flag = true;
            }
            idx += 2;
        } else if PS_PATH_FLAGS.iter().any(|&f| f == low_tk) {
            if idx + 1 >= toks.len() {
                return None;
            }
            path_vals.push(toks[idx + 1].clone());
            idx += 2;
        } else if allow_dest && PS_DEST_FLAGS.iter().any(|&f| f == low_tk) {
            if idx + 1 >= toks.len() {
                return None;
            }
            dest_vals.push(toks[idx + 1].clone());
            idx += 2;
        } else if !extra_flag.is_empty()
            && (low_tk == extra_flag || (extra_flag == "-name" && low_tk == "-n"))
        {
            if idx + 1 >= toks.len() {
                return None;
            }
            extra_val = toks[idx + 1].clone();
            idx += 2;
        } else if tk.starts_with('-') {
            return None;
        } else {
            positionals.push(tk.clone());
            idx += 1;
        }
    }
    Some((path_vals, dest_vals, positionals, extra_val, saw_value_flag))
}

fn has_opaque_script_or_exec(cmd: &str) -> bool {
    let core = rio::unwrap_tokenade_command(cmd);
    if core.is_empty() {
        return false;
    }
    let subexprs = extract_ps_subexprs(&core);
    for raw_clause in all_ps_clauses(&core, &subexprs) {
        let mut s = raw_clause.trim();
        while !s.is_empty() {
            let Some(m_kw) = ps_control_kw_re().find(s) else {
                break;
            };
            s = s[m_kw.end()..].trim();
        }
        if s.is_empty() {
            continue;
        }
        if let Some(caps) = ps_assign_re().captures(s) {
            s = caps.name("rhs").map_or("", |m| m.as_str()).trim();
        }
        if s.starts_with('&') || s.starts_with(". ") || dot_slash_re().is_match(s) {
            return true;
        }
        if starts_with_inline_py(s)
            || bookkeeping_cmd_re().is_match(s)
            || is_validation_segment(s)
            || read_only_cmd_re().is_match(s)
            || nav_segment_re().is_match(s)
            || ps_safe_filter_re().is_match(s)
        {
            continue;
        }
        let toks = ps_tokens(s);
        if toks.is_empty() {
            continue;
        }
        let head_raw = &toks[0];
        if head_raw == "&" || head_raw == "." || (head_raw.starts_with('&') && head_raw.len() > 1)
        {
            return true;
        }
        let head_norm = head_raw.replace('\\', "/").to_lowercase();
        let base = head_norm.rsplit('/').next().unwrap_or("");
        if INTERPRETER_BASENAMES.iter().any(|&b| b == base)
            || SCRIPT_EXTS.iter().any(|&ext| head_norm.ends_with(ext))
        {
            return true;
        }
    }
    false
}

fn references_scratch_space(cmd: &str, artifact_dir: &str) -> bool {
    let norm_cmd = cmd.replace('\\', "/").to_lowercase();
    if !artifact_dir.is_empty() {
        let art = rio::normalize_path(artifact_dir).to_lowercase();
        if !art.is_empty() && norm_cmd.contains(&art) {
            return true;
        }
    }
    user_scratch_patterns().iter().any(|p| p.is_match(&norm_cmd))
}

pub fn extract_ps_redirections(seg: &str) -> (String, Vec<String>) {
    if !strip_quoted(seg).contains('>') {
        return (seg.to_string(), Vec::new());
    }
    let q_spans: Vec<(usize, usize)> = ps_quoted_re()
        .find_iter(seg)
        .map(|m| (m.start(), m.end()))
        .collect();
    let re = ps_redirect_inner_re();
    let mut redir_spans: Vec<(usize, usize)> = Vec::new();
    let mut targets: Vec<String> = Vec::new();
    let mut pos = 0usize;

    // WORKAROUND: Emulates `_PS_REDIRECT_TOKEN_RE` (`(?:(?<!\S)[1-6*])?(?<!>)>>?(?!>)...(?=$|[\s|;&])`) without lookaround.
    while pos <= seg.len() {
        let Some(caps) = re.captures_at(seg, pos) else {
            break;
        };
        let whole = caps.get(0).expect("g0");
        let gt = caps.get(1).expect("gt");
        if gt.as_str().len() > 2 {
            pos = gt.end().max(pos + 1);
            continue;
        }
        if !quoted_boundary_ok(&seg[whole.end()..]) {
            pos = gt.end().max(pos + 1);
            continue;
        }
        let mut rm_start = gt.start();
        if rm_start >= 1 {
            let prev_b = seg.as_bytes()[rm_start - 1];
            if matches!(prev_b, b'1'..=b'6' | b'*') {
                let before_digit = &seg[..rm_start - 1];
                if before_digit.is_empty()
                    || before_digit
                        .chars()
                        .next_back()
                        .map_or(false, char::is_whitespace)
                {
                    rm_start -= 1;
                }
            }
        }
        if q_spans.iter().any(|&(qs, qe)| qs <= rm_start && rm_start < qe) {
            pos = whole.end().max(pos + 1);
            continue;
        }
        let raw_tgt = caps
            .get(2)
            .or_else(|| caps.get(3))
            .or_else(|| caps.get(4))
            .map_or("", |m| m.as_str());
        let tgt = unquote_ps_literal(raw_tgt);
        redir_spans.push((rm_start, whole.end()));
        if !tgt.is_empty()
            && !matches!(tgt.to_lowercase().as_str(), "$null" | "nul" | "/dev/null")
            && !amp_digit_re().is_match(&tgt)
        {
            targets.push(tgt);
        }
        pos = whole.end().max(pos + 1);
    }

    if redir_spans.is_empty() {
        return (seg.to_string(), Vec::new());
    }
    let mut buf = String::with_capacity(seg.len());
    let mut prev_idx = 0usize;
    for (rs, re_end) in redir_spans {
        buf.push_str(&seg[prev_idx..rs]);
        prev_idx = re_end;
    }
    buf.push_str(&seg[prev_idx..]);
    (buf.trim().to_string(), targets)
}

pub fn is_ephemeral_only_shell_mutation(
    cmd: &str,
    artifact_dir: &str,
    workspace_paths: &[String],
    default_cwd: &str,
) -> bool {
    let core = rio::unwrap_tokenade_command(cmd);
    if core.is_empty() || core.len() > MAX_EXPANDED_SEG_LEN {
        return false;
    }
    let subexprs = extract_ps_subexprs(&core);
    if !subexprs.is_empty() || has_inline_py(&core) {
        return false;
    }
    let no_single = strip_single_quoted(&core);
    let unquoted = strip_quoted(&core);
    let (unquoted_surface, scan_surface, no_single_surface) =
        shell_scan_surfaces(&no_single, &unquoted, &subexprs);

    if has_non_cmdlet_mutation(
        &core,
        &unquoted_surface,
        &scan_surface,
        &no_single_surface,
        &subexprs,
    ) {
        return false;
    }

    let mut vars_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let raw_segments = split_shell_segments(&core, false);
    let mut cur_cwd = default_cwd.to_string();
    let mut cwd_stack: Vec<String> = Vec::new();
    let mut saw_ephemeral_mutation = false;

    for (op, raw_seg) in raw_segments {
        let mut seg = expand_vars_outside_single_quotes(&raw_seg, &vars_map)
            .trim()
            .to_string();
        if seg.is_empty() {
            continue;
        }
        if seg.len() > MAX_EXPANDED_SEG_LEN {
            return false;
        }

        if op != "|" {
            if let Some(caps) = ps_assign_re().captures(&seg) {
                let var_name = caps
                    .name("var")
                    .map_or("", |m| m.as_str())
                    .to_lowercase();
                vars_map.remove(&var_name);
                let rhs = caps.name("rhs").map_or("", |m| m.as_str()).trim();
                if ps_sq_full_re().is_match(rhs)
                    || (ps_dq_full_re().is_match(rhs) && !rhs.contains('$') && !rhs.contains('`'))
                {
                    let val = unquote_ps_literal(rhs);
                    if !is_safe_var_value(&val) {
                        return false;
                    }
                    vars_map.insert(var_name, val);
                    continue;
                }
                if let Some(m_jp) = ps_join_path_re().captures(rhs) {
                    let p1 = unquote_ps_literal(m_jp.name("p1").map_or("", |m| m.as_str()));
                    let p2 = unquote_ps_literal(m_jp.name("p2").map_or("", |m| m.as_str()));
                    let joined = Path::new(&p1).join(&p2).to_string_lossy().into_owned();
                    if is_safe_var_value(&p1)
                        && is_safe_var_value(&p2)
                        && is_safe_var_value(&joined)
                    {
                        vars_map.insert(var_name, joined);
                        continue;
                    }
                }
                if matches!(rhs.to_lowercase().as_str(), "$true" | "$false" | "$null")
                    || (!rhs.is_empty() && rhs.chars().all(|c| c.is_ascii_digit()))
                {
                    continue;
                }
                seg = rhs.to_string();
            }
        }

        if out_null_re().is_match(&seg) {
            continue;
        }
        if op == "|" && ps_safe_filter_re().is_match(&seg) {
            continue;
        }

        if nav_segment_re().is_match(&seg) {
            if strip_quoted(&seg).contains(',') {
                return false;
            }
            let toks = ps_tokens(&seg);
            if toks.is_empty() {
                return false;
            }
            let nav_cmd = toks[0].to_lowercase();
            if nav_cmd == "pop-location" || nav_cmd == "popd" {
                let Some(popped) = cwd_stack.pop() else {
                    return false;
                };
                cur_cwd = popped;
                continue;
            }
            let pos: Vec<&str> = toks[1..]
                .iter()
                .map(|s| s.as_str())
                .filter(|t| !t.starts_with('-') && !t.eq_ignore_ascii_case("/d"))
                .collect();
            if pos.len() != 1 {
                return false;
            }
            let Some(next_cwd) = resolve_ps_path(pos[0], &cur_cwd) else {
                return false;
            };
            if nav_cmd == "push-location" || nav_cmd == "pushd" {
                cwd_stack.push(cur_cwd.clone());
            }
            cur_cwd = next_cwd;
            continue;
        }

        let mut seg_unq = strip_quoted(&seg);
        if seg_unq.contains(',') || has_output_flag(&seg, &seg_unq) {
            return false;
        }

        if seg_unq.contains('>') {
            let (cleaned_seg, redir_targets) = extract_ps_redirections(&seg);
            if cleaned_seg != seg {
                for tgt in redir_targets {
                    if resolve_ephemeral_target(&tgt, &cur_cwd, artifact_dir, workspace_paths)
                        .is_none()
                    {
                        return false;
                    }
                    saw_ephemeral_mutation = true;
                }
                seg = cleaned_seg;
                if seg.is_empty() {
                    continue;
                }
                seg_unq = strip_quoted(&seg);
            }
        }

        if strip_single_quoted(&seg).contains("$(")
            || seg_unq
                .chars()
                .any(|c| matches!(c, '(' | ')' | '{' | '}' | '`' | '>' | ','))
        {
            return false;
        }

        if read_only_cmd_re().is_match(&seg) {
            continue;
        }

        let toks = ps_tokens(&seg);
        if toks.is_empty() {
            return false;
        }
        let head = toks[0].to_lowercase();

        match head.as_str() {
            "new-item" | "ni" | "mkdir" | "md" | "set-content" | "sc" | "add-content" | "ac"
            | "out-file" | "export-csv" | "export-clixml" | "tee-object" | "clear-content"
            | "clc" => {
                let extra = if head == "new-item" || head == "ni" {
                    "-name"
                } else {
                    ""
                };
                let Some((mut path_vals, _, positionals, child_name, saw_value)) =
                    parse_cmdlet_args(&toks, false, extra)
                else {
                    return false;
                };
                let is_content_cmd = matches!(head.as_str(), "set-content" | "sc" | "add-content" | "ac");
                if !path_vals.is_empty() {
                    let max_extra_pos = if is_content_cmd && !saw_value { 1 } else { 0 };
                    if positionals.len() > max_extra_pos {
                        return false;
                    }
                } else {
                    if positionals.is_empty() {
                        return false;
                    }
                    if is_content_cmd {
                        let max_pos = if saw_value { 1 } else { 2 };
                        if positionals.len() > max_pos {
                            return false;
                        }
                        path_vals = vec![positionals[0].clone()];
                    } else {
                        path_vals = positionals;
                    }
                }
                if !child_name.is_empty() {
                    if is_ps_abs_path(&child_name)
                        || child_name.contains('$')
                        || child_name.contains(':')
                    {
                        return false;
                    }
                    path_vals = path_vals
                        .into_iter()
                        .map(|p| Path::new(&p).join(&child_name).to_string_lossy().into_owned())
                        .collect();
                }
                for pv in &path_vals {
                    if resolve_ephemeral_target(pv, &cur_cwd, artifact_dir, workspace_paths)
                        .is_none()
                    {
                        return false;
                    }
                }
                saw_ephemeral_mutation = true;
            }
            "copy-item" | "ci" | "cp" | "expand-archive" => {
                let Some((src_vals, mut dest_vals, positionals, _, _)) =
                    parse_cmdlet_args(&toks, true, "")
                else {
                    return false;
                };
                if !dest_vals.is_empty() {
                    let max_pos = if src_vals.is_empty() { 1 } else { 0 };
                    if positionals.len() > max_pos {
                        return false;
                    }
                } else if !src_vals.is_empty() && positionals.len() == 1 {
                    dest_vals = vec![positionals[0].clone()];
                } else if src_vals.is_empty() && positionals.len() == 2 {
                    dest_vals = vec![positionals[1].clone()];
                } else {
                    return false;
                }
                for dv in &dest_vals {
                    if resolve_ephemeral_target(dv, &cur_cwd, artifact_dir, workspace_paths)
                        .is_none()
                    {
                        return false;
                    }
                }
                saw_ephemeral_mutation = true;
            }
            "expand" | "expand.exe" => {
                let pos: Vec<&str> = toks[1..]
                    .iter()
                    .map(|s| s.as_str())
                    .filter(|t| !t.starts_with('-') && !t.starts_with('/'))
                    .collect();
                if pos.len() != 2 {
                    return false;
                }
                if resolve_ephemeral_target(pos[1], &cur_cwd, artifact_dir, workspace_paths)
                    .is_none()
                {
                    return false;
                }
                saw_ephemeral_mutation = true;
            }
            "remove-item" | "ri" | "rm" | "del" | "erase" | "rmdir" | "rd" | "move-item"
            | "mi" | "mv" | "rename-item" | "rni" | "ren" => {
                let extra = if matches!(head.as_str(), "rename-item" | "rni" | "ren") {
                    "-newname"
                } else {
                    ""
                };
                let Some((p_vals, d_vals, positionals, mut new_name, _)) =
                    parse_cmdlet_args(&toks, true, extra)
                else {
                    return false;
                };
                let mut all_paths = Vec::with_capacity(p_vals.len() + d_vals.len() + positionals.len());
                all_paths.extend(p_vals);
                all_paths.extend(d_vals.iter().cloned());
                all_paths.extend(positionals);
                if matches!(head.as_str(), "rename-item" | "rni" | "ren") {
                    if new_name.is_empty() && all_paths.len() == 2 && d_vals.is_empty() {
                        new_name = all_paths.pop().unwrap_or_default();
                    }
                    if all_paths.len() != 1
                        || new_name.is_empty()
                        || new_name.contains('$')
                        || new_name.contains(',')
                    {
                        return false;
                    }
                    let Some(src_res) = resolve_ephemeral_target(
                        &all_paths[0],
                        &cur_cwd,
                        artifact_dir,
                        workspace_paths,
                    ) else {
                        return false;
                    };
                    let dst_cand = if is_ps_abs_path(&new_name) {
                        new_name
                    } else {
                        Path::new(&src_res)
                            .parent()
                            .map(|p| p.join(&new_name).to_string_lossy().into_owned())
                            .unwrap_or(new_name)
                    };
                    if resolve_ephemeral_target(&dst_cand, &cur_cwd, artifact_dir, workspace_paths)
                        .is_none()
                    {
                        return false;
                    }
                } else if matches!(head.as_str(), "move-item" | "mi" | "mv") {
                    if all_paths.len() != 2 {
                        return false;
                    }
                    for ap in &all_paths {
                        if resolve_ephemeral_target(ap, &cur_cwd, artifact_dir, workspace_paths)
                            .is_none()
                        {
                            return false;
                        }
                    }
                } else {
                    if all_paths.is_empty() || !d_vals.is_empty() {
                        return false;
                    }
                    for ap in &all_paths {
                        if resolve_ephemeral_target(ap, &cur_cwd, artifact_dir, workspace_paths)
                            .is_none()
                        {
                            return false;
                        }
                    }
                }
                saw_ephemeral_mutation = true;
            }
            _ => return false,
        }
    }

    saw_ephemeral_mutation
}

fn json_truthy(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map_or(false, |x| x != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(m)) => !m.is_empty(),
        _ => false,
    }
}

fn extract_workspace_paths(payload: &Value) -> Vec<String> {
    payload
        .get("workspacePaths")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

pub fn record_pre_tool_use(payload: &Value) {
    let tc = payload.get("toolCall").and_then(|v| v.as_object());
    let tool_name = tc
        .and_then(|m| m.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !SHELL_TOOLS.iter().any(|&t| t == tool_name) {
        return;
    }

    let args = tc.and_then(|m| m.get("args")).and_then(|v| v.as_object());
    let cmd = args
        .and_then(|a| a.get("CommandLine"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let policy = classify_shell_command(cmd);
    let low_cmd = cmd.to_lowercase();
    let has_direct_codex =
        low_cmd.contains("codex") && low_cmd.contains("exec") && !low_cmd.contains("codex_lane.py");
    if (policy == "READ_ONLY" || policy == "BOOKKEEPING") && !has_direct_codex {
        return;
    }

    let tp = payload
        .get("transcriptPath")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if rio::is_subagent_session(tp, None) {
        return;
    }

    let session = rio::session_key(payload);
    let cwd = rio::effective_cwd(payload);
    let fallback_id;
    let call_id = match tc
        .and_then(|m| m.get("id"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        Some(id) => id,
        None => {
            let seq = SNAP_SEQ.fetch_add(1, Ordering::Relaxed);
            let raw = format!("{}:{}:{}", std::process::id(), now_sec(), seq);
            fallback_id = sha256_hex(raw.as_bytes())[..10].to_string();
            &fallback_id
        }
    };

    if has_direct_codex {
        capture_direct_codex_packet(cmd, &cwd, &session);
    }
    if policy != "READ_ONLY" && policy != "BOOKKEEPING" {
        let wps = extract_workspace_paths(payload);
        let art_dir = payload
            .get("artifactDirectoryPath")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let cmd_cwd = resolve_command_cwd(cmd, &cwd, &session);
        cwg_common::publish_claim(&session, &[], true, &cmd_cwd);
        let mut snap = take_git_snapshot(&cmd_cwd, art_dir, &wps, None);
        let cmd_trunc: String = cmd.chars().take(240).collect();
        if let Value::Object(ref mut m) = snap {
            m.insert("cmd_cwd".to_string(), Value::String(cmd_cwd));
            m.insert("policy".to_string(), Value::String(policy.to_string()));
            m.insert("cmd".to_string(), Value::String(cmd_trunc));
            m.insert("ts".to_string(), json!(now_sec()));
        }
        let _ = rio::write_json(&cwg_common::snapshot_path(&session, call_id), &snap);
    }
}

pub fn evaluate_pre_tool_use(payload: &Value) {
    record_pre_tool_use(payload);
    rio::emit_pre_tool("allow", None, None);
}

pub fn record_post_tool_use(payload: &Value) {
    let tc = payload.get("toolCall").and_then(|v| v.as_object());
    let tool_name = tc
        .and_then(|m| m.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let is_edit = EDIT_TOOLS.iter().any(|&t| t == tool_name);
    let is_shell = SHELL_TOOLS.iter().any(|&t| t == tool_name);
    if !is_edit && !is_shell {
        return;
    }

    let empty_args = Map::new();
    let args = tc
        .and_then(|m| m.get("args"))
        .and_then(|v| v.as_object())
        .unwrap_or(&empty_args);
    let error_text = payload
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let failed = !error_text.is_empty();
    let wps = extract_workspace_paths(payload);
    let art_dir = payload
        .get("artifactDirectoryPath")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let tp = payload
        .get("transcriptPath")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let session = rio::session_key(payload);

    if is_edit {
        if failed {
            return;
        }
        let target_path = args.get("Path").and_then(|v| v.as_str()).unwrap_or("");
        if target_path.is_empty() {
            return;
        }
        // INVARIANT: Advance Loop Guard mutation stamp for subagent and scratch edits too without spawning continuity PostToolUse.
        rio::bump_mutation_stamp(&session);
        if json_truthy(args.get("ArtifactMetadata")) {
            return;
        }
        let cwd = rio::effective_cwd(payload);
        if cwg_common::is_scratch_or_ephemeral(target_path, art_dir, &wps, &cwd) {
            return;
        }
        if rio::is_subagent_session(tp, None) {
            return;
        }
        let target_vec = vec![target_path.to_string()];
        cwg_common::publish_claim(&session, &target_vec, false, &cwd);
        let base_name = Path::new(target_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(target_path);
        let (before, after) = update_candidate_marker(
            &session,
            &cwd,
            &target_vec,
            false,
            estimate_changed_lines(tool_name, args),
            false,
            false,
            &format!("{}:{}", tool_name, base_name),
            None,
        );
        let cctx = cwg_common::resolve_candidate_context(&after, false);
        if let Some(note) = build_transition_note(before.as_ref(), &after, Some(&cctx)) {
            cwg_common::queue_pending_note(&session, &note);
        }
        let floor = cctx
            .get("floor")
            .and_then(|v| v.as_str())
            .unwrap_or("STANDARD");
        rio::log_hook_event(
            "gate-events",
            "mark_edit",
            json!({
                "session": session,
                "tool": tool_name,
                "path": rio::normalize_path(target_path),
                "floor": floor,
            }),
        );
        return;
    }

    let cmd = args
        .get("CommandLine")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let policy = classify_shell_command(cmd);
    if !failed && policy == "MUTATING" {
        rio::bump_mutation_stamp(&session);
    }
    if !failed && (policy == "READ_ONLY" || policy == "BOOKKEEPING") {
        return;
    }

    if rio::is_subagent_session(tp, None) {
        return;
    }

    if failed {
        crate::codex_lane::record_from_command(cmd, error_text, 1);
    }

    if policy == "VALIDATION" || (failed && policy == "UNCERTAIN" && has_validation_segment(cmd))
    {
        let cmd_trunc: String = cmd.chars().take(240).collect();
        let err_trunc: String = if failed {
            error_text.chars().take(200).collect()
        } else {
            String::new()
        };
        let step_idx = payload.get("stepIdx").cloned().unwrap_or(Value::Null);
        let _ = rio::append_jsonl(
            &cwg_common::checks_ledger_path(&session),
            &json!({
                "kind": "check",
                "passed": !failed,
                "cmd": cmd_trunc,
                "error": err_trunc,
                "ts": now_sec(),
                "step_idx": step_idx,
            }),
            2_000_000,
        );
    }

    if policy == "READ_ONLY" || policy == "BOOKKEEPING" {
        return;
    }

    let cwd = rio::effective_cwd(payload);
    let call_id = tc
        .and_then(|m| m.get("id"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("call");
    let snap_file = cwg_common::snapshot_path(&session, call_id);
    let before_snap = rio::read_json(&snap_file);
    if snap_file.exists() {
        let _ = fs::remove_file(&snap_file);
    }

    let (cmd_cwd, prev_git_root): (String, Option<String>) = match before_snap {
        Some(Value::Object(ref bmap)) if bmap.contains_key("cmd_cwd") => {
            let cc = bmap
                .get("cmd_cwd")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let pgr = if json_truthy(bmap.get("in_git")) {
                Some(
                    bmap.get("root")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                )
            } else {
                None
            };
            (cc, pgr)
        }
        _ => (resolve_command_cwd(cmd, &cwd, &session), None),
    };

    let after_snap = take_git_snapshot(&cmd_cwd, art_dir, &wps, prev_git_root.as_deref());
    let snap_git_root: Option<String> = if json_truthy(after_snap.get("in_git")) {
        Some(
            after_snap
                .get("root")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        )
    } else if cmd_cwd.is_empty() {
        Some(String::new())
    } else {
        None
    };

    let (mut changed_paths, unmeasured) = diff_git_snapshots(before_snap.as_ref(), Some(&after_snap));
    if !changed_paths.is_empty() {
        let others: HashSet<String> = cwg_common::claimed_by_other_sessions(
            &session,
            &changed_paths,
            CLAIM_TTL_SECONDS,
        )
        .into_iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
        changed_paths.retain(|p| {
            !others.contains(&rio::fold_path(p))
                && !cwg_common::is_scratch_or_ephemeral(p, art_dir, &wps, &cmd_cwd)
        });
    }

    cwg_common::publish_claim(&session, &changed_paths, false, &cmd_cwd);

    let cmd60: String = cmd.chars().take(60).collect();
    if !changed_paths.is_empty() {
        rio::bump_mutation_stamp(&session);
        let (before, after) = update_candidate_marker(
            &session,
            &cmd_cwd,
            &changed_paths,
            false,
            10,
            true,
            unmeasured,
            &format!("run_command:{}", cmd60),
            snap_git_root.as_deref(),
        );
        let cctx = cwg_common::resolve_candidate_context(&after, false);
        if let Some(note) = build_transition_note(before.as_ref(), &after, Some(&cctx)) {
            cwg_common::queue_pending_note(&session, &note);
        }
        let floor = cctx
            .get("floor")
            .and_then(|v| v.as_str())
            .unwrap_or("STANDARD");
        rio::log_hook_event(
            "gate-events",
            "mark_shell_durable",
            json!({
                "session": session,
                "files": changed_paths.len(),
                "floor": floor,
            }),
        );
    } else if !failed {
        let has_opaque = policy == "UNCERTAIN" && has_opaque_script_or_exec(cmd);
        let opaque_unmeasured = has_opaque
            && (json_truthy(after_snap.get("ephemeral_cwd"))
                || json_truthy(after_snap.get("no_project"))
                || references_scratch_space(cmd, art_dir));
        let is_mutating_non_ephemeral = policy == "MUTATING"
            && !is_ephemeral_only_shell_mutation(cmd, art_dir, &wps, &cwd);
        if is_mutating_non_ephemeral || (policy == "UNCERTAIN" && (unmeasured || opaque_unmeasured))
        {
            let (before, after) = update_candidate_marker(
                &session,
                &cmd_cwd,
                &[],
                true,
                0,
                false,
                unmeasured || opaque_unmeasured,
                &format!("run_command:{}", cmd60),
                snap_git_root.as_deref(),
            );
            if let Some(note) = build_transition_note(before.as_ref(), &after, None) {
                cwg_common::queue_pending_note(&session, &note);
            }
            let cmd80: String = cmd.chars().take(80).collect();
            rio::log_hook_event(
                "gate-events",
                "mark_operational",
                json!({
                    "session": session,
                    "policy": policy,
                    "cmd": cmd80,
                }),
            );
        }
    }
}

pub fn evaluate_post_tool_use(payload: &Value) {
    record_post_tool_use(payload);
    rio::emit_json(&json!({}));
}

pub fn run_cli(args: &[String]) -> i32 {
    let event = rio::parse_event_arg(args, "");
    let payload = match rio::read_hook_stdin() {
        Ok(val) => val,
        Err(err) => {
            rio::log_hook_event(
                "hook-errors",
                "stdin_error",
                json!({
                    "hook": "cwg_mark",
                    "event": event,
                    "error": err,
                }),
            );
            rio::emit_default_for_event(&event);
            return 0;
        }
    };

    let actual_event = if !event.is_empty() {
        event
    } else {
        payload
            .get("hookEventName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };

    if actual_event == "PreToolUse" {
        evaluate_pre_tool_use(&payload);
    } else if actual_event == "PostToolUse" {
        evaluate_post_tool_use(&payload);
    } else {
        rio::emit_default_for_event(&actual_event);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_regexes_compile() {
        let _ = cache_path_re();
        let _ = bookkeeping_cmd_re();
        let _ = nav_segment_re();
        let _ = ps_safe_filter_re();
        let _ = read_only_cmd_re();
        let _ = validation_non_runner_re();
        let _ = validation_runner_re();
        let _ = mutating_cmdlet_re();
        let _ = mutating_git_re();
        let _ = mutating_pkg_re();
        let _ = mutating_stack_re();
        let _ = py_mut_clause_head_re();
        let _ = py_flag_x_re();
        let _ = py_flag_w_re();
        let _ = py_short_flag_re();
        let _ = wt_guard_mut_tok_re();
        let _ = wt_mut_tail_re();
        let _ = chip_mut_tok_re();
        let _ = chip_mut_tail_re();
        let _ = install_mut_tok_re();
        let _ = install_diag_tail_re();
        let _ = system_or_net_mutating_re();
        let _ = http_cmd_re();
        let _ = http_method_flag_re();
        let _ = http_mutating_other_re();
        let _ = inline_py_search_re();
        let _ = inline_py_c_re();
        let _ = inline_py_write_re();
        let _ = ps_quoted_re();
        let _ = output_flag_re();
        let _ = file_redirect_scan_re();
        let _ = null_redirect_target_re();
        let _ = pre_flag_re();
        let _ = ps_safe_bare_re();
        let _ = ps_var_ref_re();
        let _ = ps_sq_full_re();
        let _ = ps_dq_full_re();
        let _ = ps_assign_re();
        let _ = ps_join_path_re();
        let _ = ps_redirect_inner_re();
        let _ = amp_digit_re();
        let _ = win_drive_prefix_re();
        let _ = ps_control_kw_re();
        let _ = dot_slash_re();
        let _ = out_null_re();
        let _ = user_scratch_patterns();
        let _ = review_id_re();
    }

    #[test]
    fn test_classify_shell_command_matrix() {
        let py_abs = r"C:\Users\in\AppData\Local\Programs\Python\Python312\python.exe";
        let py_x86 = r"C:\Program Files (x86)\Python312\python.exe";
        let rg_abs = r"C:\tools\ripgrep-15.1.0-x86_64-pc-windows-msvc\ripgrep-15.1.0-x86_64-pc-windows-msvc\rg.exe";

        let cmd_rg = format!("$null | & '{}' -n extract_review_decision plugin", rg_abs);
        let cmd_unittest = format!(
            "Set-Location 'C:\\repo'; $null | & '{}' -X utf8 -m unittest discover -s tests -q",
            py_abs
        );
        let cmd_pytest = format!(r#"$null | & "{}" -X utf8 -m pytest -q"#, py_x86);
        let cmd_diag = format!(
            "$null | & '{}' -X utf8 'C:\\Users\\in\\repo\\install.py' --diagnose --pretty",
            py_abs
        );
        let cmd_codex_lane = format!(
            "$null | & '{}' -X utf8 'C:\\Users\\in\\.gemini\\config\\plugins\\gemini-carbon-stack\\hooks\\codex_lane.py' review --closure",
            py_abs
        );
        let cmd_install_force = format!("$null | & '{}' -X utf8 'C:\\repo\\install.py' --force", py_abs);
        let cmd_install_fake = format!("& '{}' 'C:\\repo\\install.py' --diagnose-fake", py_abs);
        let cmd_wt_rm = format!("& '{}' 'C:\\repo\\worktree_guard.py' remove C:\\wt", py_abs);
        let cmd_chip_merge = format!("& '{}' 'C:\\repo\\chip_handoff.py' --merge chip-1", py_abs);
        let cmd_py_write = format!(r#"& '{}' -X utf8 -c "open('x','w').write('1')""#, py_abs);

        let cases = [
            ("Get-ChildItem | Select-Object -First 5", "READ_ONLY"),
            ("cd tests; git status --short", "READ_ONLY"),
            ("git status --short", "READ_ONLY"),
            ("git diff --stat", "READ_ONLY"),
            ("git log -n 5 --oneline", "READ_ONLY"),
            (cmd_rg.as_str(), "READ_ONLY"),
            ("tokenade map", "READ_ONLY"),
            ("tokenade skeleton app.py", "READ_ONLY"),
            (r#""C:\tools\tokenade.exe" wrap --shell powershell 'git status --short'"#, "READ_ONLY"),
            (r#"Write-Output "python install.py --force""#, "READ_ONLY"),
            (cmd_unittest.as_str(), "VALIDATION"),
            (cmd_pytest.as_str(), "VALIDATION"),
            (cmd_diag.as_str(), "VALIDATION"),
            (r#""C:\tools\tokenade.exe" wrap --shell powershell 'python -X utf8 -m unittest discover -s tests -v'"#, "VALIDATION"),
            ("npm test", "VALIDATION"),
            ("cargo test", "VALIDATION"),
            ("cargo check", "VALIDATION"),
            ("cargo clippy", "VALIDATION"),
            ("npx tsc --noEmit", "VALIDATION"),
            (r"& 'C:\repo\.venv\Scripts\ruff.exe' check src", "VALIDATION"),
            (r#"python -X utf8 continuity.py handoff --cwd ".""#, "BOOKKEEPING"),
            ("python -X utf8 swarm_cache.py prepare", "BOOKKEEPING"),
            ("python -X utf8 swarm_ctl.py status", "BOOKKEEPING"),
            ("python -X utf8 gate_inbox.py list", "BOOKKEEPING"),
            (cmd_codex_lane.as_str(), "BOOKKEEPING"),
            (r#"git commit -m "feat: x""#, "MUTATING"),
            ("git push origin main", "MUTATING"),
            ("npm install", "MUTATING"),
            ("Get-Content a.txt > b.txt", "MUTATING"),
            ("Get-Content a.py | Out-File b.txt", "MUTATING"),
            ("Get-Content a.py | Set-Content b.py", "MUTATING"),
            ("git diff --output=out.diff", "MUTATING"),
            ("tokenade wrap 'Remove-Item C:\\outside.txt -Force'; git status", "MUTATING"),
            (cmd_install_force.as_str(), "MUTATING"),
            (cmd_install_fake.as_str(), "MUTATING"),
            (cmd_wt_rm.as_str(), "MUTATING"),
            (cmd_chip_merge.as_str(), "MUTATING"),
            (cmd_py_write.as_str(), "MUTATING"),
            (r#"python -X utf8 -c "print(42)""#, "UNCERTAIN"),
            ("Get-Content $(Get-Date)", "UNCERTAIN"),
            ("echo pytest", "UNCERTAIN"),
            ("rg --pre x.bat foo", "UNCERTAIN"),
            ("pytest.bat -q", "UNCERTAIN"),
            ("pytest -q | Select-Object -First 5", "UNCERTAIN"),
            ("git status || pytest -q", "UNCERTAIN"),
            (r"& 'C:\tmp\evil_python.exe' -m unittest", "UNCERTAIN"),
            ("python -x -u -x -u -x -u -m unittest", "UNCERTAIN"),
        ];

        for (cmd, expected) in cases {
            assert_eq!(classify_shell_command(cmd), expected, "cmd: {}", cmd);
        }
    }

    #[test]
    fn test_redirections_ephemeral_and_snapshots() {
        let (cleaned, tgts) = extract_ps_redirections("Get-Content a.txt 2>$null > out.txt");
        assert_eq!(cleaned, "Get-Content a.txt");
        assert_eq!(tgts, vec!["out.txt".to_string()]);

        let scratch_file = r"C:\Users\in\.gemini\antigravity\brain\conv-123\scratch\probe.txt";
        assert!(is_ephemeral_only_shell_mutation(
            &format!("Set-Content -Path '{}' -Value 'ok'", scratch_file),
            "",
            &[],
            r"C:\repo",
        ));
        assert!(!is_ephemeral_only_shell_mutation(
            "Set-Content -Path 'src\\app.rs' -Value 'bad'",
            "",
            &[],
            r"C:\repo",
        ));

        let b_snap = json!({
            "in_git": true,
            "root": "c:/repo",
            "head": "abc",
            "unmeasured": false,
            "entries": {
                "c:/repo/a.rs": " M:10:1234567890abcdef1234"
            }
        });
        let a_snap = json!({
            "in_git": true,
            "root": "c:/repo",
            "head": "abc",
            "unmeasured": false,
            "entries": {
                "c:/repo/a.rs": "M :10:1234567890abcdef1234"
            }
        });
        let (chg, unm) = diff_git_snapshots(Some(&b_snap), Some(&a_snap));
        assert!(chg.is_empty());
        assert!(!unm);
    }
}
