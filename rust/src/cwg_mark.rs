use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::cwg_common;
use crate::rio::{self, json_truthy, meta_mtime_ns, sha256_hex};
use crate::win32_sqlite::{is_link_or_junction, now_sec, run_command_with_job};

pub const EDIT_TOOLS: &[&str] = &["edit_file", "write_file"];
pub const SHELL_TOOLS: &[&str] = &["run_command"];

const NON_GIT_SCAN_MAX_FILES: usize = 400;
const NON_GIT_SCAN_MAX_DEPTH: usize = 4;
const MAX_HASHED_SNAPSHOT_BYTES: u64 = cwg_common::MAX_FINGERPRINT_FILE_BYTES;
const MAX_VAR_VALUE_LEN: usize = 1024;
const MAX_EXPANDED_SEG_LEN: usize = 8192;
const CLAIM_TTL_SECONDS: f64 = 600.0;
const ANON_SNAP_TTL_SECONDS: f64 = 3600.0;
const MAX_ANON_SNAP_QUEUE: usize = 16;

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
const PS_MUT_CLAUSE_LEADER: &str = r"\A\s*(?:\$[A-Za-z_]\w*\s*=\s*)?(?:\$null\s*\|\s*)?(?:&\s*)?";
const CONTINUITY_BK_SUB: &str = r"(?:checkpoint|show|handoff)\b";
const CODEX_LANE_BK_SUB: &str = r"(?:check|status|reset|review|research-reset)\b";
const CHAT_BUS_BK_SUB: &str = r"(?:wait|inbox|list|read|search|send|reply|configure|status)\b";
const WT_RO_SUB: &str = r"(?:audit|status)\b";
const WT_MUT_TAIL: &str = r"[^\r\n;|&]*\b(?:snapshot|remove|restore)\b";
const CHIP_MUT_TAIL: &str = r"[^\r\n;|&]*--merge\b";

fn cache_path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(^|/)(__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.coverage|node_modules/\.cache|\.swarm)(/|$)|\.(?:pyc|tokenade-original)$",
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
        let chat_bus_py = exe_pat_followed_by_space("chat_bus_cli", EXT_PY, false);
        let carbon_stack_bin = exe_pat_followed_by_space("carbon-stack", r"(?:\.exe)?", false);
        let chat_bus_bin = exe_pat_followed_by_space("chat-bus", r"(?:\.exe)?", false);
        let pat = format!(
            r"(?i)\A\s*(?:\$null\s*\|\s*)?(?:&\s*)?(?:{py}\s+(?:-(?:X\s+utf8|[uBEsSO])\s+)*(?:{bk}|(?:{cont}\s+{cont_sub}|{cl}\s+{cl_sub}|{cb_py}\s+{cb_sub}))|{cs}\s+(?:(?:carbon[-_]memory|gate[-_]inbox|chip[-_]handoff|swarm[-_]cache|swarm[-_]ctl)\b|continuity\s+{cont_sub}|codex[-_]lane\s+{cl_sub})|{cb}\s+{cb_sub})(?:\s+[^|;&\r\n]*)?\z",
            py = py,
            bk = bk_scripts,
            cont = continuity,
            cl = codex_lane,
            cb_py = chat_bus_py,
            cs = carbon_stack_bin,
            cb = chat_bus_bin,
            cont_sub = CONTINUITY_BK_SUB,
            cl_sub = CODEX_LANE_BK_SUB,
            cb_sub = CHAT_BUS_BK_SUB,
        );
        Regex::new(&pat).expect("bookkeeping_cmd_re")
    })
}

pub fn nav_segment_re() -> &'static Regex {
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
        let cs_tok = exe_pat_followed_by_space("carbon-stack", r"(?:\.exe)?", false);
        let pat = format!(
            r#"(?i)\A\s*(?:\$null\s*\|\s*)?(?:(?:(?:&\s*)?{git}\s+(?:--no-pager\s+)?(?:-C\s+["']?[^"'|;&\r\n]+["']?\s+)?(?:status|diff|log|show|rev-parse|ls-files|ls-tree|check-ignore|remote\s+-v|worktree\s+list)|(?:&\s*)?{rg}|findstr(?:\.exe)?\b|where(?:\.exe)?\b|Get-ChildItem\b|gci\b|Get-Content\b|gc\b|Select-String\b|sls\b|Get-Command\b|gcm\b|Test-Path\b|Get-Item\b|gi\b|Get-ItemProperty\b|gp\b|Get-ItemPropertyValue\b|gpv\b|Get-CimInstance\b|gcim\b|Get-WmiObject\b|gwmi\b|Get-WinEvent\b|Get-EventLog\b|Get-Process\b|gps\b|Get-Service\b|gsv\b|Get-Location\b|gl\b|Write-Output\b|(?:&\s*)?{codex}\s+(?:--version|login\s+status|exec\b[^|;&\r\n]*-s\s+read-only\b)|(?:&\s*)?{agy}\s+(?:--help|--version|plugin\s+(?:list|help)|mcp\s+(?:list|help)|models\b)|(?:&\s*)?{tok}\s+(?:--version|--help|help|map|query|skeleton|semantic|ask|sem|impact|expand-ref|gain|dashboard|healthcheck|detect|measure|statusline)\b|(?:&\s*)?{py}\s+(?:-(?:X\s+utf8|[uBEsSO])\s+)*(?:{ro}|{wt}\s+{wt_ro})|(?:&\s*)?{cs}\s+(?:code[-_]search\b|stack[-_]doctor\b|worktree[-_]guard\s+{wt_ro}))(?:\s+[^|;&\r\n]*)?|(?:&\s*)?{git}\s+(?:--no-pager\s+)?(?:-C\s+["']?[^"'|;&\r\n]+["']?\s+)?branch(?:\s+(?:--list|-l|-a|--all|-r|--remotes|-v|-vv|--show-current|--no-color))*)\z"#,
            git = git_tok,
            rg = rg_tok,
            codex = codex_tok,
            agy = agy_tok,
            tok = tokenade_tok,
            py = py,
            ro = ro_scripts,
            wt = wt_guard,
            cs = cs_tok,
            wt_ro = WT_RO_SUB,
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
        let mcp_exec = exe_pat_followed_by_space("mcp_env_exec", EXT_PY, false);
        let cs = exe_pat_followed_by_space("carbon-stack", r"(?:\.exe)?", false);
        let agy = exe_pat_followed_by_space("agy", EXT_CMD_EXE, false);
        let node = exe_pat_followed_by_space("node", r"(?:\.exe)?", false);
        let pkg_script =
            r"(?:[A-Za-z0-9_.-]+:)*(?:test|tests|lint|build|typecheck|check)(?:[:_-][A-Za-z0-9_:.-]+)*";
        let pat = format!(
            r#"(?i)\A\s*(?:\$null\s*\|\s*)?(?:&\s*)?(?:{ruff}\s+check\b|{py}\s+(?:-(?:X\s+utf8|[uBEsSO])\s+)*(?:-m\s+(?:pytest|unittest|py_compile|compileall|mypy|ruff|flake8)\b|{inst}\s+(?:[^\r\n|;&]*\s)?(?:--diagnose|--dry-run)(?:\z|[\s|;&])|{mcp}\s+--semgrep-scan\b)|{cs}\s+install\s+(?:[^\r\n|;&]*\s)?(?:--diagnose|--dry-run)(?:\z|[\s|;&])|(?:uvx(?:\.exe)?\s+(?:--offline\s+)?--from\s+semgrep\s+)?semgrep(?:\.exe)?\s+(?:--legacy\s+)?scan\b|{node}\s+(?:(?:--no-warnings|--experimental-[A-Za-z0-9_-]+)\s+)*(?:(?:--test|--check)(?:\z|[\s|;&])|["']?(?:\.[/\\])?(?:[A-Za-z0-9_][A-Za-z0-9_.-]*[/\\])*(?:test[-_][A-Za-z0-9_.-]*|[A-Za-z0-9_][A-Za-z0-9_.-]*[-_.]tests?|[A-Za-z0-9_][A-Za-z0-9_.-]*\.spec)\.(?:c?js|mjs)["']?(?:\z|[\s|;&]))|bun(?:\.exe)?\s+(?:test(?:\z|[\s|;&])|run\s+{pkg_s}\b)|deno(?:\.exe)?\s+(?:test|check|lint)(?:\z|[\s|;&])|npm(?:\.cmd)?\s+(?:test\b|run\s+{pkg_s}\b)|(?:pnpm|yarn)(?:\.cmd)?\s+(?:run\s+)?(?:test\b|{pkg_s}\b)|npx(?:\.cmd)?\s+(?:tsc|vitest|jest|eslint|playwright\s+test)\b|(?:flutter|dart)(?:\.bat|\.exe)?\s+(?:test|analyze)\b|cargo(?:\.exe)?\s+(?:\+[A-Za-z0-9._-]+\s+)?(?:test|check|clippy)\b|go(?:\.exe)?\s+(?:test|vet)\b|dotnet(?:\.exe)?\s+(?:test|build)\b|{agy}\s+plugin\s+validate\b)"#,
            ruff = ruff,
            py = py,
            inst = install,
            mcp = mcp_exec,
            cs = cs,
            agy = agy,
            node = node,
            pkg_s = pkg_script,
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

fn semgrep_autofix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:\A|\s)(?:--autofix(?:\z|=|\s)|-a(?:\z|\s))").expect("semgrep_autofix_re")
    })
}

fn benign_ps_env_assign_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)\A\s*\$(?:env:(?P<env>[A-Za-z_][A-Za-z0-9_]*)|(?P<pref>ErrorActionPreference|ProgressPreference|WarningPreference|VerbosePreference|InformationPreference|PSNativeCommandUseErrorActionPreference))\s*=\s*(?:'(?:''|[^'])*'|"(?:""|[^"$`\r\n])*"|\$true|\$false|\$null|[A-Za-z0-9_./:\\;-]+)\s*\z"#,
        )
        .expect("benign_ps_env_assign_re")
    })
}

fn is_benign_ps_env_assign(seg: &str) -> bool {
    // INVARIANT: Allow literal `$env:VAR=...` / PowerShell preference prefixes before validation runners while rejecting binary-search, loader-preload, compiler-wrapper, Git-dir, and gate-home hijack variables.
    let Some(caps) = benign_ps_env_assign_re().captures(seg) else {
        return false;
    };
    if caps.name("pref").is_some() {
        return true;
    }
    let Some(env_m) = caps.name("env") else {
        return false;
    };
    let up = env_m.as_str().to_ascii_uppercase();
    !matches!(
        up.as_str(),
        "PATH"
            | "PATHEXT"
            | "PSMODULEPATH"
            | "COMSPEC"
            | "LD_PRELOAD"
            | "LD_LIBRARY_PATH"
            | "DYLD_INSERT_LIBRARIES"
            | "DYLD_LIBRARY_PATH"
            | "NODE_OPTIONS"
            | "PYTHONSTARTUP"
            | "PYTHONPATH"
            | "PYTHONHOME"
            | "RUBYOPT"
            | "PERL5OPT"
            | "JAVA_TOOL_OPTIONS"
            | "JDK_JAVA_OPTIONS"
            | "DOTNET_STARTUP_HOOKS"
            | "RUSTC"
            | "RUSTC_WRAPPER"
            | "RUSTC_WORKSPACE_WRAPPER"
            | "PLUGIN_ROOT"
    ) && !up.starts_with("GIT_")
        && !up.starts_with("CARBON_")
        && !up.starts_with("CARGO_BUILD_")
        && !up.starts_with("CARGO_TARGET_")
}

fn is_validation_segment(seg: &str) -> bool {
    let low = seg.to_ascii_lowercase();
    if low.contains("semgrep") && semgrep_autofix_re().is_match(seg) {
        return false;
    }
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
        Regex::new(&format!(
            r"(?i)(?:(?:\bworktree_guard\.py|carbon-stack(?:\.exe)?\s+worktree[-_]guard)\b{}|(?:\bchip_handoff\.py|carbon-stack(?:\.exe)?\s+chip[-_]handoff)\b{})",
            WT_MUT_TAIL, CHIP_MUT_TAIL
        ))
        .expect("mutating_stack_re")
    })
}

fn py_mut_clause_head_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let py = py_interp_pat(true);
        let pat = format!(r"(?i){}{}\s+", PS_MUT_CLAUSE_LEADER, py);
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
    RE.get_or_init(|| Regex::new(&format!(r"(?i)\A{}", WT_MUT_TAIL)).expect("wt_mut_tail_re"))
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
    RE.get_or_init(|| Regex::new(&format!(r"(?i)\A{}", CHIP_MUT_TAIL)).expect("chip_mut_tail_re"))
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

fn cs_mut_clause_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let cs = exe_pat_followed_by_space("carbon-stack", r"(?:\.exe)?", true);
        Regex::new(&format!(
            r"(?i){}{}\s+(?:worktree[-_]guard\b{}|chip[-_]handoff\b{})",
            PS_MUT_CLAUSE_LEADER, cs, WT_MUT_TAIL, CHIP_MUT_TAIL
        ))
        .expect("cs_mut_clause_re")
    })
}

fn cs_install_clause_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let cs = exe_pat_followed_by_space("carbon-stack", r"(?:\.exe)?", true);
        Regex::new(&format!(
            r"(?i){}{}\s+install(?:\z|[\s|;&])",
            PS_MUT_CLAUSE_LEADER, cs
        ))
        .expect("cs_install_clause_re")
    })
}

fn is_mutating_stack_seg(clause: &str) -> bool {
    if cs_mut_clause_re().is_match(clause) {
        return true;
    }
    if let Some(m) = cs_install_clause_re().find(clause) {
        let after_install = &clause[m.end().saturating_sub(1)..];
        if !install_diag_tail_re().is_match(after_install) {
            return true;
        }
    }
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
        && !low_core.contains("carbon-stack")
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
        if read_only_cmd_re().is_match(seg)
            || nav_segment_re().is_match(seg)
            || ((op.is_empty() || op == ";" || op == "&&") && is_benign_ps_env_assign(seg))
        {
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

pub fn has_validation_segment(cmd: &str) -> bool {
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
        if let Some(Value::Object(existing)) = cwg_common::read_marker_with_pending(session) {
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
        match cwg_common::sha256_file_bounded(full, MAX_HASHED_SNAPSHOT_BYTES) {
            Ok(Some((total_len, digest))) => {
                return format!("{}{}:{}", prefix, total_len, &digest[..20]);
            }
            Ok(None) => {}
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

#[derive(Copy, Clone)]
struct CandidateMarkerUpdate<'a> {
    session: &'a str,
    cwd: &'a str,
    durable_new_paths: &'a [String],
    operational_mutation: bool,
    changed_lines_delta: i64,
    shell_durable_edit: bool,
    unknown_barrier: bool,
    cause_label: &'a str,
    known_git_root: Option<&'a str>,
    pre_marker_call_key: Option<&'a str>,
}

fn prior_closed_candidate_ts(session: &str, raw_before: Option<&Value>) -> f64 {
    let from_marker = raw_before
        .filter(|m| json_truthy(m.get("closed")))
        .map(|m| rio::val_to_f64(m.get("last_ts")).max(rio::val_to_f64(m.get("first_ts"))))
        .unwrap_or(0.0);
    from_marker.max(cwg_common::enforcement_state_closed_ts(session))
}

fn update_candidate_marker(upd: CandidateMarkerUpdate<'_>) -> (Option<Value>, Value, bool) {
    // SAFETY: Serialize candidate marker read-modify-write via `marker_lock_path`, and finalize any pre-marker `swarm_rounds` adoption ONLY after releasing `marker_lock_path` to avoid AB-BA lock inversion with `swarm_cache`.
    let (before_open, marker, ok, adopted) =
        rio::with_file_lock(&cwg_common::marker_lock_path(upd.session), 5.0, 30.0, |locked| {
            update_candidate_marker_unlocked(upd, locked)
        });
    if ok {
        if let Some((git_top, prep_ts)) = adopted {
            let _ = cwg_common::finalize_pre_marker_simplify_adoption(
                upd.session,
                &git_top,
                prep_ts,
            );
        }
    }
    (before_open, marker, ok)
}

fn update_candidate_marker_unlocked(
    upd: CandidateMarkerUpdate<'_>,
    persist: bool,
) -> (Option<Value>, Value, bool, Option<(String, f64)>) {
    let CandidateMarkerUpdate {
        session,
        cwd,
        durable_new_paths,
        operational_mutation,
        changed_lines_delta,
        shell_durable_edit,
        unknown_barrier,
        cause_label,
        known_git_root,
        pre_marker_call_key,
    } = upd;
    let now = now_sec();
    let mp = cwg_common::marker_path(session);
    let raw_before = rio::read_json(&mp);
    let (before, consumed_pending_ids) =
        cwg_common::apply_pending_marker_deltas(session, raw_before.as_ref());
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

    let (before_open, mut marker, adopted_prep): (Option<Value>, Value, Option<(String, f64)>) = match before {
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
            (Some(Value::Object(bmap.clone())), Value::Object(m), None)
        }
        _ => {
            let git_top = resolve_known_or_git_root(known_git_root, &eff_cwd);
            let adopted = if !git_top.is_empty()
                && cwg_common::has_unbound_pre_marker_simplify_rounds(session)
            {
                let prior_closed = prior_closed_candidate_ts(session, raw_before.as_ref());
                cwg_common::read_pre_marker_simplify_prepare(
                    session,
                    &git_top,
                    now,
                    prior_closed,
                    pre_marker_call_key,
                )
            } else {
                None
            };
            let eff_first_ts = adopted.as_ref().map_or(now, |(pts, _, _)| *pts);
            let mut m = json!({
                "session": session,
                "first_ts": eff_first_ts,
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
                "gate_max_review_rounds": cwg_common::MAX_ORDINARY_REVIEW_ROUNDS,
                "closed": false,
            });
            let adopted_ret = if let Some((prep_ts, _, pre_hashes)) = adopted {
                if let Value::Object(ref mut mobj) = m {
                    // INVARIANT: Anchor a newly opened marker to an active post-close pre-marker `swarm-cache prepare` on the same repo so in-flight or just-completed simplify passes remain candidate-bound.
                    mobj.insert("swarm_prepare_cycle_ts".to_string(), json!(prep_ts));
                    if !pre_hashes.is_empty() {
                        mobj.insert(
                            "simplify_verified_latched".to_string(),
                            json!({
                                "candidate_first_ts": prep_ts,
                                "reset_epoch": 0,
                                "verified_ts": now,
                                "verified_hashes": pre_hashes,
                            }),
                        );
                    }
                }
                Some((git_top, prep_ts))
            } else {
                None
            };
            (None, m, adopted_ret)
        }
    };

    let cause_trunc: String = cause_label.chars().take(120).collect();
    if let Value::Object(ref mut m) = marker {
        m.insert("last_ts".to_string(), json!(now));
    }

    if !durable_new_paths.is_empty() {
        let mut combined = cwg_common::durable_paths_from_val(marker.get("paths"));
        let prev_len = combined.len();
        combined.extend(durable_new_paths.iter().cloned());
        let merged_paths = cwg_common::durable_paths(&combined);
        let added_new_path = merged_paths.len() != prev_len;
        let fp = cwg_common::content_fingerprint(&merged_paths, cwg_common::MAX_FINGERPRINT_FILE_BYTES);

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
            // INVARIANT: Do not bump `last_durable_ts` or set `shell_durable_edit` when an in-flight shell command's `before_snap` predates an interleaved `edit_file` whose post-edit `paths` and `fp` are already recorded on `marker`.
            if changed_fp || added_new_path || !shell_durable_edit {
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
            let fp = cwg_common::content_fingerprint(&dpaths, cwg_common::MAX_FINGERPRINT_FILE_BYTES);
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

    let mut persisted_ok = false;
    if persist && rio::write_json(&mp, &marker).is_ok() {
        persisted_ok = true;
        if !consumed_pending_ids.is_empty() {
            cwg_common::ack_pending_marker_deltas(session, &consumed_pending_ids);
        }
    }
    if !persisted_ok {
        let m_cwd = marker.get("cwd").and_then(|v| v.as_str()).unwrap_or(&eff_cwd);
        let m_gr = marker.get("git_root").and_then(|v| v.as_str()).unwrap_or("");
        let m_paths = cwg_common::durable_paths_from_val(marker.get("paths"));
        let m_fp_opt = if unknown_barrier {
            None
        } else {
            cwg_common::last_mark_fp(&marker)
        };
        persisted_ok = cwg_common::append_pending_marker_delta(cwg_common::PendingMarkerDelta {
            session,
            ts: now,
            cwd: m_cwd,
            git_root: m_gr,
            durable_new_paths,
            operational_mutation,
            changed_lines_delta,
            shell_durable_edit,
            unknown_barrier,
            cause_label,
            measured_fp: m_fp_opt,
            measured_paths: &m_paths,
        })
        .is_some();
    }
    (before_open, marker, persisted_ok, adopted_prep)
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
    let Some(caps) = crate::codex_lane::review_id_re().captures(cmd) else {
        return;
    };
    let Some(rid) = caps.get(1).map(|m| m.as_str()) else {
        return;
    };
    let eff = if low.contains("xhigh") { "xhigh" } else { "high" };
    let _ = crate::codex_lane::record_packet_if_absent(rid, cmd, cwd, eff, "", session);
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
    cwg_common::user_scratch_patterns()
        .iter()
        .any(|p| p.is_match(&norm_cmd))
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

fn first_non_empty_str<'a>(map: Option<&'a Map<String, Value>>, keys: &[&str]) -> Option<&'a str> {
    let m = map?;
    keys.iter()
        .filter_map(|k| m.get(*k).and_then(Value::as_str).map(str::trim))
        .find(|s| !s.is_empty())
}

fn payload_step_idx(payload: &Value) -> Option<&Value> {
    ["stepIdx", "stepIndex", "step_index"]
        .iter()
        .filter_map(|k| payload.get(*k))
        .find(|v| v.is_i64() || v.is_u64())
}

fn tool_call_snap_key(
    payload: &Value,
    tc: Option<&Map<String, Value>>,
    cwd: &str,
    cmd: &str,
) -> (String, String, bool) {
    if let Some(id) = first_non_empty_str(tc, &["id", "callId", "toolCallId"]).or_else(|| {
        first_non_empty_str(payload.as_object(), &["toolCallId", "callId", "invocationId"])
    }) {
        return (format!("id_{}", id), String::new(), true);
    }
    if let Some(si) = payload_step_idx(payload) {
        return (format!("step_{}", si), String::new(), true);
    }
    let sig = format!("{}\0{}", rio::fold_path(cwd), cmd);
    let cmd_sha = sha256_hex(sig.as_bytes());
    (format!("anon_{}", &cmd_sha[..24]), cmd_sha, false)
}

fn with_locked_anon_queue<R, F: FnOnce() -> R>(session: &str, f: F) -> Option<R> {
    let lock_path = cwg_common::snapshot_lock_path(session);
    rio::with_file_lock(&lock_path, 2.0, 15.0, |locked| locked.then(f))
}

struct AnonBurstDoc {
    queue: Vec<Value>,
    in_flight: usize,
    burst_min_ts: f64,
    burst_max_ts: f64,
    tainted: bool,
}

fn take_live_anon_burst(snap_file: &Path, cmd_sha: &str, ref_ts: f64) -> Option<AnonBurstDoc> {
    let mut doc = rio::read_json(snap_file)?;
    if rio::val_to_str(doc.get("cmd_sha")) != cmd_sha {
        return None;
    }
    let mut queue = doc
        .get_mut("queue")
        .and_then(Value::as_array_mut)
        .map(std::mem::take)
        .unwrap_or_default();
    let prev_len = queue.len();
    queue.retain(|entry| {
        let t = rio::val_to_f64(entry.get("ts"));
        t > 0.0 && ref_ts - t < ANON_SNAP_TTL_SECONDS
    });
    let stored_min = rio::val_to_f64(doc.get("burst_min_ts"));
    let stored_max = rio::val_to_f64(doc.get("burst_max_ts"));
    let stored_in_flight = (rio::val_to_i64(doc.get("in_flight")).max(0) as usize).max(queue.len());
    let burst_fresh = stored_max > 0.0 && ref_ts - stored_max < ANON_SNAP_TTL_SECONDS;
    if queue.is_empty() && !(stored_in_flight > 0 && burst_fresh) {
        return None;
    }
    let pruned_expired = queue.len() != prev_len;
    let in_flight = if pruned_expired {
        stored_in_flight.saturating_sub(prev_len - queue.len()).max(queue.len())
    } else {
        stored_in_flight
    };
    if in_flight == 0 && queue.is_empty() {
        return None;
    }
    let (live_min, live_max) = queue
        .iter()
        .fold((f64::INFINITY, 0.0_f64), |(mn, mx), entry| {
            let t = rio::val_to_f64(entry.get("ts"));
            (mn.min(t), mx.max(t))
        });
    let burst_min_ts = if !pruned_expired && stored_min > 0.0 {
        stored_min.min(live_min)
    } else if live_min.is_finite() {
        live_min
    } else {
        stored_min
    };
    let burst_max_ts = if !pruned_expired && stored_max > 0.0 {
        stored_max.max(live_max)
    } else {
        live_max.max(stored_max)
    };
    let tainted = json_truthy(doc.get("tainted")) || pruned_expired;
    Some(AnonBurstDoc {
        queue,
        in_flight,
        burst_min_ts,
        burst_max_ts,
        tainted,
    })
}

fn write_anon_burst(snap_file: &Path, cmd_sha: &str, burst: AnonBurstDoc) {
    if burst.in_flight == 0 && burst.queue.is_empty() {
        let _ = fs::remove_file(snap_file);
    } else {
        let _ = rio::write_json(
            snap_file,
            &json!({
                "cmd_sha": cmd_sha,
                "in_flight": burst.in_flight,
                "burst_min_ts": burst.burst_min_ts,
                "burst_max_ts": burst.burst_max_ts,
                "tainted": burst.tainted,
                "queue": burst.queue,
            }),
        );
    }
}

fn push_anon_snapshot(session: &str, snap_file: &Path, cmd_sha: &str, snap: Value) {
    // INVARIANT: Track conservative `in_flight`, `burst_min_ts`, `burst_max_ts`, and `tainted` across overlapping anonymous (`!has_unique_id`) calls under a per-session lock so un-ID'd completions cannot steal a post-edit `start_ts` even when `> MAX_ANON_SNAP_QUEUE` calls overlap.
    let pre_ts = rio::val_to_f64(snap.get("ts"));
    let _ = with_locked_anon_queue(session, || {
        let mut burst = match take_live_anon_burst(snap_file, cmd_sha, pre_ts) {
            Some(mut b) => {
                if pre_ts > 0.0 {
                    b.burst_min_ts = b.burst_min_ts.min(pre_ts);
                    b.burst_max_ts = b.burst_max_ts.max(pre_ts);
                }
                b
            }
            None => AnonBurstDoc {
                queue: Vec::new(),
                in_flight: 0,
                burst_min_ts: pre_ts,
                burst_max_ts: pre_ts,
                tainted: false,
            },
        };
        burst.in_flight = burst.in_flight.saturating_add(1);
        if burst.queue.len() >= MAX_ANON_SNAP_QUEUE {
            let drop_n = burst.queue.len() + 1 - MAX_ANON_SNAP_QUEUE;
            burst.queue.drain(0..drop_n);
            burst.tainted = true;
        }
        burst.queue.push(snap);
        burst
            .queue
            .sort_by(|a, b| rio::val_to_f64(a.get("ts")).total_cmp(&rio::val_to_f64(b.get("ts"))));
        write_anon_burst(snap_file, cmd_sha, burst);
    });
}

fn pop_anon_snapshot(
    session: &str,
    snap_file: &Path,
    cmd_sha: &str,
    confirmed_sync_zero: bool,
) -> (Option<Value>, f64) {
    // INVARIANT: Credit `burst_min_ts` whenever any sibling remains `in_flight` or any call in the burst backgrounded/failed/overflowed (`tainted`); credit `burst_max_ts` only when `in_flight == 0` with every call confirmed synchronous exit-0.
    let now_ts = now_sec();
    with_locked_anon_queue(session, || {
        let Some(mut burst) = take_live_anon_burst(snap_file, cmd_sha, now_ts) else {
            let _ = fs::remove_file(snap_file);
            return (None, 0.0);
        };
        burst.in_flight = burst.in_flight.saturating_sub(1);
        let head = if burst.queue.is_empty() {
            burst.tainted = true;
            None
        } else {
            Some(burst.queue.remove(0))
        };
        if burst.in_flight < burst.queue.len() {
            burst.in_flight = burst.queue.len();
        }
        burst.tainted = burst.tainted || !confirmed_sync_zero;
        let credited_ts = if burst.in_flight == 0 && burst.queue.is_empty() && !burst.tainted {
            burst.burst_max_ts
        } else if burst.burst_min_ts > 0.0 && burst.burst_min_ts.is_finite() {
            burst.burst_min_ts
        } else {
            0.0
        };
        write_anon_burst(snap_file, cmd_sha, burst);
        (head, credited_ts)
    })
    .unwrap_or((None, 0.0))
}

fn edit_tool_call_key(
    payload: &Value,
    tc: Option<&Map<String, Value>>,
    tool_name: &str,
    cwd: &str,
    edit_path: Option<&str>,
) -> String {
    let sig = format!(
        "{}\0{}",
        tool_name,
        rio::fold_path(edit_path.unwrap_or(""))
    );
    tool_call_snap_key(payload, tc, cwd, &sig).0
}

fn latch_live_simplify_if_ready(
    session: &str,
    transcript_path: &str,
    hint_path: Option<&str>,
    hint_cwd: &str,
    call_key: &str,
) {
    if session.trim().is_empty() || session == "unknown" {
        return;
    }
    let m_raw = cwg_common::read_marker_with_pending(session);
    if let Some(m_pre) = m_raw.as_ref().filter(|m| {
        !json_truthy(m.get("closed"))
            && cwg_common::marker_has_prepare_cycle(Some(m))
            && cwg_common::active_marker_verified_simplify_hashes(m).is_empty()
    }) {
        // INVARIANT: Forward-latch live-verified simplify hashes right before the first mutating edit so applying `ACTIONABLE_FIXES` or `REVISE` fixes never breaks a verified snapshot while pre-edit drift outside `marker.paths` remains unlatched.
        let _ = crate::cwg_stop::latch_live_simplify_for_pre_edit(
            session,
            m_pre,
            transcript_path,
            hint_path,
        );
        return;
    }
    let no_open_marker = m_raw
        .as_ref()
        .map_or(true, |m| json_truthy(m.get("closed")));
    if !no_open_marker || !cwg_common::has_unbound_pre_marker_simplify_rounds(session) {
        return;
    }
    let probe_dir = hint_path
        .filter(|p| !p.trim().is_empty())
        .and_then(|p| Path::new(p).parent().map(|d| d.to_string_lossy().into_owned()))
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| hint_cwd.to_string());
    if probe_dir.is_empty() {
        let _ = cwg_common::clear_pre_marker_verified_simplify(session);
        return;
    }
    let git_top = rio::git_toplevel(&probe_dir, false).unwrap_or_default();
    if git_top.is_empty() {
        let _ = cwg_common::clear_pre_marker_verified_simplify(session);
        return;
    }
    let now = now_sec();
    let prior_closed = prior_closed_candidate_ts(session, m_raw.as_ref());
    // SAFETY: Re-probe live worktree state on every pre-marker tool invocation (never trusting cached `pre_marker_verified`), binding the fresh record strictly to `call_key` or clearing any stale record on drift/failure.
    if let Some((prep_ts, tree_oid, _)) =
        cwg_common::read_pre_marker_simplify_prepare(session, &git_top, now, prior_closed, None)
    {
        let _ = crate::cwg_stop::probe_and_record_pre_marker_simplify(
            session,
            &git_top,
            prep_ts,
            &tree_oid,
            call_key,
            transcript_path,
        );
    } else {
        let _ = cwg_common::clear_pre_marker_verified_simplify(session);
    }
}

pub fn record_pre_tool_use(payload: &Value) {
    let tc = payload.get("toolCall").and_then(|v| v.as_object());
    let tool_name = tc
        .and_then(|m| m.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let is_edit_tool = EDIT_TOOLS.iter().any(|&t| t == tool_name);
    let is_shell_tool = SHELL_TOOLS.iter().any(|&t| t == tool_name);
    if !is_edit_tool && !is_shell_tool {
        return;
    }
    let tp = payload
        .get("transcriptPath")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if is_edit_tool {
        if !rio::is_subagent_session(tp, None) {
            let session = rio::session_key(payload);
            let cwd = rio::effective_cwd(payload);
            let edit_path = tc
                .and_then(|m| m.get("args"))
                .and_then(|v| v.as_object())
                .and_then(|a| a.get("Path").or_else(|| a.get("path")))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty());
            let edit_key = edit_tool_call_key(payload, tc, tool_name, &cwd, edit_path);
            latch_live_simplify_if_ready(&session, tp, edit_path, &cwd, &edit_key);
        }
        return;
    }

    let args = tc.and_then(|m| m.get("args")).and_then(|v| v.as_object());
    let cmd = args
        .and_then(|a| a.get("CommandLine"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let policy = classify_shell_command(cmd);
    let low_cmd = cmd.to_lowercase();
    let has_direct_codex = low_cmd.contains("codex")
        && low_cmd.contains("exec")
        && !low_cmd.contains("codex_lane.py")
        && !low_cmd.contains("codex-lane")
        && !low_cmd.contains("codex_lane");
    if (policy == "READ_ONLY" || policy == "BOOKKEEPING") && !has_direct_codex {
        return;
    }

    if rio::is_subagent_session(tp, None) {
        return;
    }

    let session = rio::session_key(payload);
    let cwd = rio::effective_cwd(payload);
    let (call_key, cmd_sha, has_unique_id) = tool_call_snap_key(payload, tc, &cwd, cmd);

    if has_direct_codex {
        capture_direct_codex_packet(cmd, &cwd, &session);
    }
    if policy != "READ_ONLY" && policy != "BOOKKEEPING" {
        let cmd_cwd = resolve_command_cwd(cmd, &cwd, &session);
        latch_live_simplify_if_ready(&session, tp, None, &cmd_cwd, &call_key);
        // INVARIANT: Stamp `pre_ts` before snapshot subprocesses run so `PostToolUse` records the true pre-spawn `start_ts` on the same wall clock as `last_durable_ts`.
        let pre_ts = now_sec();
        let snap_file = cwg_common::snapshot_path(&session, &call_key);
        let cmd_trunc: String = cmd.chars().take(240).collect();
        let wps = cwg_common::extract_workspace_paths(payload);
        let art_dir = payload
            .get("artifactDirectoryPath")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        cwg_common::publish_claim(&session, &[], true, &cmd_cwd);
        let mut snap = take_git_snapshot(&cmd_cwd, art_dir, &wps, None);
        if let Value::Object(ref mut m) = snap {
            m.insert("cmd_cwd".to_string(), Value::String(cmd_cwd));
            m.insert("policy".to_string(), Value::String(policy.to_string()));
            m.insert("cmd".to_string(), Value::String(cmd_trunc));
            m.insert("ts".to_string(), json!(pre_ts));
        }
        if has_unique_id {
            let _ = rio::write_json(&snap_file, &snap);
        } else {
            push_anon_snapshot(&session, &snap_file, &cmd_sha, snap);
        }
    }
}

pub fn evaluate_pre_tool_use(payload: &Value) {
    record_pre_tool_use(payload);
    rio::emit_pre_tool("allow", None, None);
}

pub fn record_post_tool_use(payload: &Value) -> Result<(), String> {
    let tc = payload.get("toolCall").and_then(|v| v.as_object());
    let tool_name = tc
        .and_then(|m| m.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let is_edit = EDIT_TOOLS.iter().any(|&t| t == tool_name);
    let is_shell = SHELL_TOOLS.iter().any(|&t| t == tool_name);
    if !is_edit && !is_shell {
        return Ok(());
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
    let wps = cwg_common::extract_workspace_paths(payload);
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
        let is_sub = rio::is_subagent_session(tp, None);
        if failed {
            if !is_sub {
                let _ = cwg_common::clear_pre_marker_verified_simplify(&session);
            }
            return Ok(());
        }
        let target_path = args
            .get("Path")
            .or_else(|| args.get("path"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if target_path.is_empty() {
            if !is_sub {
                let _ = cwg_common::clear_pre_marker_verified_simplify(&session);
            }
            return Ok(());
        }
        // INVARIANT: Advance Loop Guard mutation stamp for subagent and scratch edits too without spawning continuity PostToolUse.
        rio::bump_mutation_stamp(&session);
        if json_truthy(args.get("ArtifactMetadata")) {
            if !is_sub {
                let _ = cwg_common::clear_pre_marker_verified_simplify(&session);
            }
            return Ok(());
        }
        let cwd = rio::effective_cwd(payload);
        if cwg_common::is_scratch_or_ephemeral(target_path, art_dir, &wps, &cwd) {
            if !is_sub {
                let _ = cwg_common::clear_pre_marker_verified_simplify(&session);
            }
            return Ok(());
        }
        if is_sub {
            return Ok(());
        }
        let edit_call_key = edit_tool_call_key(payload, tc, tool_name, &cwd, Some(target_path));
        let target_vec = vec![target_path.to_string()];
        cwg_common::publish_claim(&session, &target_vec, false, &cwd);
        let base_name = Path::new(target_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(target_path);
        let cause_lbl = format!("{}:{}", tool_name, base_name);
        let (before, after, persisted) = update_candidate_marker(CandidateMarkerUpdate {
            session: &session,
            cwd: &cwd,
            durable_new_paths: &target_vec,
            operational_mutation: false,
            changed_lines_delta: estimate_changed_lines(tool_name, args),
            shell_durable_edit: false,
            unknown_barrier: false,
            cause_label: &cause_lbl,
            known_git_root: None,
            pre_marker_call_key: Some(&edit_call_key),
        });
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
        if !persisted {
            return Err(format!("Failed to persist candidate marker delta for session {}", session));
        }
        return Ok(());
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
        return Ok(());
    }

    if rio::is_subagent_session(tp, None) {
        return Ok(());
    }

    if failed {
        crate::codex_lane::record_from_command(cmd, error_text, 1);
    }
    if policy == "READ_ONLY" || policy == "BOOKKEEPING" {
        return Ok(());
    }

    let cwd = rio::effective_cwd(payload);
    let (call_key, cmd_sha, has_unique_id) = tool_call_snap_key(payload, tc, &cwd, cmd);
    let snap_file = cwg_common::snapshot_path(&session, &call_key);
    let is_validation_like =
        policy == "VALIDATION" || (policy == "UNCERTAIN" && has_validation_segment(cmd));
    let out_txt = if is_validation_like {
        payload
            .get("toolResponse")
            .or_else(|| payload.get("response"))
            .or_else(|| payload.get("result"))
            .or_else(|| payload.get("output"))
            .map(|v| rio::val_to_str(Some(v)))
            .unwrap_or_default()
    } else {
        String::new()
    };
    let bg_tid = if is_validation_like {
        rio::extract_bg_task_id(&out_txt)
    } else {
        None
    };
    let exit_code = if is_validation_like && bg_tid.is_none() {
        cwg_common::parse_host_command_exit_code(&out_txt)
    } else {
        None
    };
    let host_nonzero = matches!(exit_code, Some(code) if code != 0);
    let check_failed = failed || host_nonzero;
    let confirmed_sync_zero = policy == "VALIDATION" && !check_failed && exit_code == Some(0);

    let (before_snap, pre_start_ts) = if has_unique_id {
        let snap = rio::read_json(&snap_file);
        let _ = fs::remove_file(&snap_file);
        let ts = snap
            .as_ref()
            .map(|s| rio::val_to_f64(s.get("ts")))
            .unwrap_or(0.0);
        (snap, ts)
    } else {
        pop_anon_snapshot(&session, &snap_file, &cmd_sha, confirmed_sync_zero)
    };

    if is_validation_like {
        let step_idx = payload_step_idx(payload).cloned().unwrap_or(Value::Null);
        let start_ts_val = if pre_start_ts > 0.0 {
            json!(pre_start_ts)
        } else {
            Value::Null
        };
        if let Some(bg_tid) = bg_tid {
            let _ = rio::append_jsonl(
                &cwg_common::checks_ledger_path(&session),
                &json!({
                    "kind": "bg_launch",
                    "task_id": bg_tid,
                    "policy": policy,
                    "start_ts": start_ts_val,
                    "ts": now_sec(),
                    "step_idx": step_idx,
                }),
                2_000_000,
            );
        } else if policy == "VALIDATION" || check_failed {
            let cmd_trunc: String = cmd.chars().take(240).collect();
            let err_trunc: String = if failed {
                error_text.chars().take(200).collect()
            } else if host_nonzero {
                "nonzero_exit_code".to_string()
            } else {
                String::new()
            };
            let _ = rio::append_jsonl(
                &cwg_common::checks_ledger_path(&session),
                &json!({
                    "kind": "check",
                    "passed": !check_failed,
                    "cmd": cmd_trunc,
                    "error": err_trunc,
                    "ts": now_sec(),
                    "start_ts": start_ts_val,
                    "step_idx": step_idx,
                }),
                2_000_000,
            );
        }
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
        let cause_lbl = format!("run_command:{}", cmd60);
        let (before, after, persisted) = update_candidate_marker(CandidateMarkerUpdate {
            session: &session,
            cwd: &cmd_cwd,
            durable_new_paths: &changed_paths,
            operational_mutation: false,
            changed_lines_delta: 10,
            shell_durable_edit: true,
            unknown_barrier: unmeasured,
            cause_label: &cause_lbl,
            known_git_root: snap_git_root.as_deref(),
            pre_marker_call_key: Some(&call_key),
        });
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
        if !persisted {
            return Err(format!("Failed to persist shell candidate marker delta for session {}", session));
        }
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
            let cause_lbl = format!("run_command:{}", cmd60);
            let (before, after, persisted) = update_candidate_marker(CandidateMarkerUpdate {
                session: &session,
                cwd: &cmd_cwd,
                durable_new_paths: &[],
                operational_mutation: true,
                changed_lines_delta: 0,
                shell_durable_edit: false,
                unknown_barrier: unmeasured || opaque_unmeasured,
                cause_label: &cause_lbl,
                known_git_root: snap_git_root.as_deref(),
                pre_marker_call_key: Some(&call_key),
            });
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
            if !persisted {
                return Err(format!("Failed to persist operational marker delta for session {}", session));
            }
        } else {
            let _ = cwg_common::clear_pre_marker_verified_simplify(&session);
        }
    } else {
        let _ = cwg_common::clear_pre_marker_verified_simplify(&session);
    }
    Ok(())
}

pub fn evaluate_post_tool_use(payload: &Value) -> i32 {
    if let Err(err) = record_post_tool_use(payload) {
        rio::log_hook_event(
            "hook-errors",
            "post_tool_persist_failed",
            json!({ "error": err }),
        );
        eprintln!("[Code Work Gate] {}", err);
        return 2;
    }
    rio::emit_json(&json!({}));
    0
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
        return evaluate_post_tool_use(&payload);
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
        let _ = cs_mut_clause_re();
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
            (
                r"$null | C:\Users\in\.gemini\config\plugins\chat-bus\bin\chat-bus.exe wait --chat a508fe71-2b38-458a-b726-7529ddc212ac",
                "BOOKKEEPING",
            ),
            (
                r#"C:\Python312\python.exe -X utf8 "C:\Users\in\.gemini\config\plugins\chat-bus\tools\chat_bus_cli.py" reply --from-chat a508 --message-id msg-1 --message ok"#,
                "BOOKKEEPING",
            ),
            (
                r"$null | C:\Users\in\.gemini\config\plugins\gemini-carbon-stack\bin\carbon-stack.exe continuity handoff --session s1 --goal g",
                "BOOKKEEPING",
            ),
            (
                r"C:\Users\in\.gemini\config\plugins\gemini-carbon-stack\bin\carbon-stack.exe code-search foo",
                "READ_ONLY",
            ),
            (
                "cargo +stable-x86_64-pc-windows-gnu test --offline",
                "VALIDATION",
            ),
            (
                "$null | node scripts/ci/test-backend-jest-modes.js",
                "VALIDATION",
            ),
            (
                r"& 'C:/Users/in/AppData/Roaming/npm/node_modules/@tokenade/cli/node_modules/@tokenade/cli-win32-x64/tokenade.exe' wrap --shell powershell '$null | node scripts/ci/test-backend-jest-modes.js'",
                "VALIDATION",
            ),
            ("node --test backend/src/foo.mjs", "VALIDATION"),
            (
                r#"$env:NODE_PATH="C:\repo\node_modules"; $null | node --test landing-legacy/explore.test.js landing-legacy/pricing.test.js"#,
                "VALIDATION",
            ),
            ("$null | npm run ux:check", "VALIDATION"),
            ("pnpm run a11y:check", "VALIDATION"),
            ("yarn test:unit", "VALIDATION"),
            (
                r"$null | C:/Python312/python.exe C:/Users/in/.gemini/config/mcp-launchers/mcp_env_exec.py --semgrep-scan --pro-intrafile --config code --quiet src/app.js",
                "VALIDATION",
            ),
            ("semgrep scan --autofix src/app.js", "UNCERTAIN"),
            (r#"$env:PATH="C:\fake"; cargo test"#, "UNCERTAIN"),
            (r#"$env:CARBON_STACK_HOME="C:\fake"; cargo test"#, "UNCERTAIN"),
            ("npm test; $env:CI='1'", "UNCERTAIN"),
            ("node --check backend/src/index.js", "VALIDATION"),
            ("node backend/src/maxClient.spec.mjs", "VALIDATION"),
            ("node --test-reporter=spec app.js", "UNCERTAIN"),
            ("node -e 'process.exit(0)' test-foo.js", "UNCERTAIN"),
            ("node scripts/migrate.js", "UNCERTAIN"),
            (
                "$null | npm.cmd test -w backend -- --runInBand; $null | git status --short",
                "UNCERTAIN",
            ),
            (
                r"& 'C:\bin\carbon-stack.exe' worktree-guard remove C:\wt",
                "MUTATING",
            ),
            (
                r"C:\bin\carbon-stack.exe chip-handoff close --merge --chip c1",
                "MUTATING",
            ),
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

        let tmp_bin = std::env::temp_dir().join(format!("cwg-mark-3mb-{}.bin", std::process::id()));
        fs::write(&tmp_bin, vec![0xABu8; 2_600_000]).unwrap();
        let tok_3mb = file_entry_token(&tmp_bin, "??:", None);
        assert!(tok_3mb.starts_with("??:2600000:"), "tok_3mb: {}", tok_3mb);
        assert!(git_entry_unchanged_on_disk(&tmp_bin.to_string_lossy(), &tok_3mb, None));
        let _ = fs::remove_file(&tmp_bin);

        // INVARIANT: `carbon-stack install --dry-run/--diagnose` is VALIDATION while `carbon-stack install` without dry-run/diagnose is MUTATING; contended `persist=false` updates never overwrite `marker_path` and journal out-of-band.
        assert_eq!(
            classify_shell_command("carbon-stack install --dry-run"),
            "VALIDATION"
        );
        assert_eq!(
            classify_shell_command("carbon-stack.exe install --diagnose --pretty"),
            "VALIDATION"
        );
        assert_eq!(
            classify_shell_command("carbon-stack install --force"),
            "MUTATING"
        );

        let _lock = crate::win32_sqlite::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp_home = std::env::temp_dir().join(format!("cwg-mark-pend-{}", std::process::id()));
        let _ = fs::create_dir_all(&tmp_home);
        let prev_sh = std::env::var_os("CARBON_STACK_HOME");
        std::env::set_var("CARBON_STACK_HOME", &tmp_home);
        let sess_p = "sess-contended-rust";
        let f_edit = tmp_home.join("mod.rs");
        fs::write(&f_edit, "pub fn a() {}\n").unwrap();
        let f_vec = vec![f_edit.to_string_lossy().into_owned()];
        let tmp_home_str = tmp_home.to_string_lossy().into_owned();
        let (_, _, ok1, _) = update_candidate_marker_unlocked(
            CandidateMarkerUpdate {
                session: sess_p,
                cwd: &tmp_home_str,
                durable_new_paths: &f_vec,
                operational_mutation: false,
                changed_lines_delta: 1,
                shell_durable_edit: false,
                unknown_barrier: false,
                cause_label: "edit:mod.rs",
                known_git_root: None,
                pre_marker_call_key: None,
            },
            false,
        );
        assert!(ok1);
        assert!(!cwg_common::marker_path(sess_p).exists());
        assert!(cwg_common::has_pending_marker_deltas(sess_p));
        assert!(cwg_common::pending_marker_mtime_ns(sess_p) > 0);
        let (_, flushed, ok2, _) = update_candidate_marker_unlocked(
            CandidateMarkerUpdate {
                session: sess_p,
                cwd: &tmp_home_str,
                durable_new_paths: &f_vec,
                operational_mutation: false,
                changed_lines_delta: 1,
                shell_durable_edit: false,
                unknown_barrier: false,
                cause_label: "edit2:mod.rs",
                known_git_root: None,
                pre_marker_call_key: None,
            },
            true,
        );
        assert!(ok2);
        assert!(cwg_common::marker_path(sess_p).is_file());
        assert!(!cwg_common::has_pending_marker_deltas(sess_p));
        assert!(cwg_common::marker_pending_dir(sess_p).is_dir());
        assert_eq!(cwg_common::pending_marker_mtime_ns(sess_p), 0);
        assert_eq!(flushed.get("edits").and_then(|v| v.as_i64()), Some(2));

        // INVARIANT: Contended journal preserves edit-time SHA-256 (never backdating later version B to earlier edit timestamp) and `ack_pending_marker_deltas` preserves concurrently appended unacknowledged deltas.
        let sess_race = "sess-journal-race";
        let f_race = tmp_home.join("race.rs");
        fs::write(&f_race, "pub fn v1() {}\n").unwrap();
        let f_race_str = f_race.to_string_lossy().into_owned();
        let race_paths = vec![f_race_str.clone()];
        let fp_v1 = cwg_common::content_fingerprint(&race_paths, cwg_common::MAX_FINGERPRINT_FILE_BYTES);
        let id1 = cwg_common::append_pending_marker_delta(cwg_common::PendingMarkerDelta {
            session: sess_race,
            ts: 10.0,
            cwd: &tmp_home_str,
            git_root: "",
            durable_new_paths: &race_paths,
            operational_mutation: false,
            changed_lines_delta: 1,
            shell_durable_edit: false,
            unknown_barrier: false,
            cause_label: "edit:v1",
            measured_fp: Some(&fp_v1),
            measured_paths: &race_paths,
        })
        .unwrap();
        fs::write(&f_race, "pub fn v2_after_review() {}\n").unwrap();
        let fp_v2 = cwg_common::content_fingerprint(&race_paths, cwg_common::MAX_FINGERPRINT_FILE_BYTES);
        assert_ne!(fp_v1, fp_v2);
        let id2 = cwg_common::append_pending_marker_delta(cwg_common::PendingMarkerDelta {
            session: sess_race,
            ts: 20.0,
            cwd: &tmp_home_str,
            git_root: "",
            durable_new_paths: &race_paths,
            operational_mutation: false,
            changed_lines_delta: 1,
            shell_durable_edit: false,
            unknown_barrier: false,
            cause_label: "edit:v2",
            measured_fp: Some(&fp_v2),
            measured_paths: &race_paths,
        })
        .unwrap();
        let (folded_opt, cids) = cwg_common::apply_pending_marker_deltas(sess_race, None);
        assert_eq!(cids, vec![id1.clone(), id2.clone()]);
        let folded_m = folded_opt.unwrap();
        let rev_at_15 = json!({"launch_ts": 15.0});
        assert!(!crate::cwg_stop::is_review_fresh(&rev_at_15, &folded_m));
        let rev_at_25 = json!({"launch_ts": 25.0});
        assert!(crate::cwg_stop::is_review_fresh(&rev_at_25, &folded_m));

        let id3_concurrent = cwg_common::append_pending_marker_delta(cwg_common::PendingMarkerDelta {
            session: sess_race,
            ts: 30.0,
            cwd: &tmp_home_str,
            git_root: "",
            durable_new_paths: &race_paths,
            operational_mutation: false,
            changed_lines_delta: 1,
            shell_durable_edit: false,
            unknown_barrier: false,
            cause_label: "edit:v3-concurrent",
            measured_fp: Some(&fp_v2),
            measured_paths: &race_paths,
        })
        .unwrap();
        cwg_common::ack_pending_marker_deltas(sess_race, &cids);
        assert!(cwg_common::has_pending_marker_deltas(sess_race));
        assert!(cwg_common::has_unconsumed_pending_deltas(sess_race, &cids));
        let (folded_after_ack, rem_ids) =
            cwg_common::apply_pending_marker_deltas(sess_race, Some(&folded_m));
        assert_eq!(rem_ids, vec![id3_concurrent]);
        assert_eq!(
            folded_after_ack.unwrap().get("edits").and_then(|v| v.as_i64()),
            Some(3)
        );

        // INVARIANT: More than `MAX_ANON_SNAP_QUEUE` (16) concurrent un-ID'd PreToolUse calls track `in_flight` accurately so the 16th drain never unlinks a shared `snap_file` while the 17th call is still running.
        let sess_burst = "sess-anon-burst-17";
        let shared_snap = tmp_home.join("shared-anon-17.json");
        let cmd_sha = "sha-burst-17";
        let shared_snap_str = shared_snap.to_string_lossy().into_owned();
        for _ in 0..17 {
            push_anon_snapshot(
                sess_burst,
                &shared_snap,
                cmd_sha,
                json!({
                    "ts": crate::win32_sqlite::now_sec(),
                    "snap_file": shared_snap_str,
                }),
            );
        }
        for i in 0..16 {
            let _ = pop_anon_snapshot(sess_burst, &shared_snap, cmd_sha, true);
            assert!(
                shared_snap.is_file(),
                "shared_snap unlinked prematurely after drain #{}",
                i + 1
            );
        }
        let last_pop = pop_anon_snapshot(sess_burst, &shared_snap, cmd_sha, true);
        assert!(last_pop.0.is_none());
        assert!(!shared_snap.exists());

        match prev_sh {
            Some(v) => std::env::set_var("CARBON_STACK_HOME", v),
            None => std::env::remove_var("CARBON_STACK_HOME"),
        }
        let _ = fs::remove_dir_all(&tmp_home);
    }
}
