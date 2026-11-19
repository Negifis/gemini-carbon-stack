use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::rio::{self, file_mtime_sec, json_truthy, val_to_f64, val_to_i64, val_to_str};
use crate::win32_sqlite::now_sec;

pub const WORK_NO_CHANGE: &str = "NO_CHANGE";
pub const WORK_OPERATIONAL: &str = "OPERATIONAL";
pub const WORK_PERSISTENT: &str = "PERSISTENT";
pub const MAX_FINGERPRINT_FILE_BYTES: u64 = 32_000_000;

pub const RISK_LOW: &str = "LOW";
pub const RISK_STANDARD: &str = "STANDARD";
pub const RISK_HIGH: &str = "HIGH";
pub const RISK_XHIGH: &str = "XHIGH";

pub const SHELL_MUTATION_SENTINEL: &str = "<shell-mutation>";
pub const MAX_CONTENT_MARKS: usize = 512;

pub const FAST_PATH_MAX_FILES: usize = 2;
pub const FAST_PATH_MAX_LINES: usize = 30;
pub const BOARD_CURSOR_THRESHOLD: usize = 15;
pub const DEFAULT_SWARM_STALL_TIMEOUT_SEC: f64 = 240.0;

pub const GATE_POLICY_WALK_DEPTH: usize = 16;
pub const TEST_HARNESS_WALK_DEPTH: usize = 8;
pub const TEST_HARNESS_SAMPLE_PATHS: usize = 8;

pub const SONNET_HIGH_MODEL: &str = "claude-sonnet-5-5-high";
pub const OPUS_HIGH_MODEL: &str = "claude-opus-5-5-high";
pub const CARBON_HIGH_MODEL: &str = "gemini-4-carbon-high";
pub const HYDROGEN_LOW_MODEL: &str = "gemini-4-hydrogen-low";
pub const HYDROGEN_MEDIUM_MODEL: &str = "gemini-4-hydrogen-medium";
pub const HYDROGEN_HIGH_MODEL: &str = "gemini-4-hydrogen-high";
pub const HYDROGEN_XHIGH_MODEL: &str = "gemini-4-hydrogen-xhigh";
pub const CODEX_SOL_MODEL: &str = "gpt-6.2-sol";
pub const CODEX_ASTRA_MODEL: &str = "gpt-6.2-astra";

pub fn is_codex_astra_model(model: &str) -> bool {
    let m = model.trim().to_ascii_lowercase();
    m == CODEX_ASTRA_MODEL
        || (m.starts_with(CODEX_ASTRA_MODEL)
            && m.as_bytes().get(CODEX_ASTRA_MODEL.len()) == Some(&b'-'))
}

pub fn is_codex_xhigh_effort(effort: &str) -> bool {
    matches!(
        effort.trim().to_ascii_lowercase().as_str(),
        "xhigh" | "max" | "ultra"
    )
}

pub fn is_codex_xhigh_turn(model: &str, effort: &str) -> bool {
    // INVARIANT: XHIGH Codex verification requires Astra 6.2 (`gpt-6.2-astra`) at XHIGH-tier reasoning; Sol stays on HIGH.
    is_codex_astra_model(model) && is_codex_xhigh_effort(effort)
}

pub const SIMPLIFY_LENSES: &[&str] = &["reuse", "quality", "efficiency"];
pub const SIMPLIFY_FALLBACK_MODEL: &str = HYDROGEN_XHIGH_MODEL;
pub const ANTHROPIC_EPHEMERAL_TTL_SECONDS: u64 = 300;
pub const SWARM_CACHE_SAFE_TTL_SECONDS: u64 = 270;
pub const MAX_CLOSURE_PASSES_PER_CYCLE: usize = 2;
pub const RESEARCH_RESET_DECISIONS: &[&str] = &["refactor", "refine"];

pub const CODEX_REVIEW_OUTPUT_BANNER: &str = "--- CODEX REVIEW OUTPUT ---";

const DOC_EXTENSIONS: &[&str] = &[".md", ".mdx", ".txt", ".rst", ".adoc", ".csv", ".tsv"];
const SIMPLIFY_AGENT_TYPES: &[&str] = &[
    "simplify-reuse-reviewer",
    "simplify-quality-reviewer",
    "simplify-efficiency-reviewer",
    "simplify-reviewer",
];

fn high_risk_patterns() -> &'static [Regex] {
    static RE: OnceLock<Vec<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        [
            r"(?i)(?:^|/)\.gemini/config/",
            r"(?i)(?:^|/)\.agents?/",
            r"(?i)(?:^|/)hooks\.json$",
            r"(?i)(?:^|/)plugin\.json$",
            r"(?i)(?:^|/)mcp_config\.json$",
            r"(?i)(?:^|/)hooks/[^/]+\.(?:py|ps1|sh|mjs|js|ts)$",
            r"(?i)(?:^|/)rules/[^/]+\.md$",
            r"(?i)(?:^|/)agents/[^/]+\.md$",
            r"(?i)(?:^|/)\.github/workflows/",
            r"(?i)(?:^|/)\.gitlab-ci\.ya?ml$",
            r"(?i)(?:^|/)(?:dockerfile|docker-compose[^/]*\.ya?ml)$",
            r"(?i)(?:^|/)(?:migrations?|alembic|prisma/migrations|db/migrate)/",
            r"(?i)(?:^|/|_|-)(?:auth|oauth\d*|jwt|crypto|security|permissions?|rbac|acl|secrets?|vault|signing)(?:/|_|-|\.|$)",
            r"(?i)(?:^|/)(?:package-lock\.json|pnpm-lock\.yaml|yarn\.lock|cargo\.lock|poetry\.lock|uv\.lock|go\.sum)$",
            r"(?i)(?:^|/)(?:pyproject\.toml|cargo\.toml|go\.mod|tsconfig\.json|webpack\.config\.|vite\.config\.)$",
            r"(?i)(?:^|/)(?:install\.py|bin/carbon-stack(?:\.exe)?|rust/src/(?:cwg_(?:common|mark|stop|pre_invocation)|codex_lane|safety_guards|tokenade_hook|installer|gate_inbox|chip_hooks|continuity_hook)\.rs)$",
        ]
        .iter()
        .map(|p| Regex::new(p).expect("high_risk_pattern"))
        .collect()
    })
}

fn chip_trees_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)/\.gemini/carbon-stack/state/chips/trees/").expect("chip_trees_re")
    })
}

fn system_generated_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)/\.system_generated(?:/|$)").expect("system_generated_re"))
}

pub(crate) fn user_scratch_patterns() -> &'static [Regex] {
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

pub(crate) fn extract_workspace_paths(payload: &Value) -> Vec<String> {
    payload
        .get("workspacePaths")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn always_ephemeral_patterns() -> &'static [Regex] {
    static RE: OnceLock<Vec<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        [
            r"(?i)/\.gemini/antigravity/brain/[^/]+/scratch(?:/|$)",
            r"(?i)/\.gemini/antigravity/brain/[^/]+/browser_sandbox(?:/|$)",
            r"(?i)/\.gemini/antigravity/brain/[^/]+/\.system_generated(?:/|$)",
            r"(?i)/\.gemini/carbon-stack/state(?:/|$)",
            r"(?i)(?:^|/)\.swarm(?:/|$)",
            r"(?i)\.tokenade-original$",
        ]
        .iter()
        .map(|p| Regex::new(p).expect("always_ephemeral_pattern"))
        .collect()
    })
}

fn os_temp_patterns() -> &'static [Regex] {
    static RE: OnceLock<Vec<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        [
            r"(?i)(?:^|/)(?:tmp|var/tmp)(?:/|$)",
            r"(?i)/appdata/local/temp(?:/|$)",
        ]
        .iter()
        .map(|p| Regex::new(p).expect("os_temp_pattern"))
        .collect()
    })
}

fn receipt_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)^\[gate\]\s+(?P<kind>verified|operational|no-change|pr-ready|draft-blocked|anomaly-reported)\s*:\s*(?P<body>\S.*)$",
        )
        .expect("receipt_line_re")
    })
}

fn verified_body_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^(?P<risk>LOW|STANDARD|HIGH|XHIGH)\s*;\s*(?P<summary>\S.*)$")
            .expect("verified_body_re")
    })
}

fn operational_body_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(?P<precheck>[^;]*\S[^;]*);\s*(?P<effect>\S.*)$")
            .expect("operational_body_re")
    })
}

fn anomaly_body_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(?P<report_id>[A-Za-z0-9_-]{6,32})\s*;\s*(?P<fact>\S.*)$")
            .expect("anomaly_body_re")
    })
}

fn verdict_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?m)^\s*(?:\*{0,2})VERDICT(?:\*{0,2})\s*:\s*(?:\*{0,2})(APPROVED|REVISE|ESCALATE)(?:\*{0,2})\b",
        )
        .expect("verdict_line_re")
    })
}

fn closure_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?m)^\s*(?:\*{0,2})CLOSURE_VALIDATION(?:\*{0,2})\s*:\s*(?:\*{0,2})(READY|BLOCKED)(?:\*{0,2})\b",
        )
        .expect("closure_line_re")
    })
}

pub fn codex_cli_wrapper_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\AREVIEW_ID:\s*[A-Za-z0-9_-]+[ \t]*\r?\n(?:(?:SESSION_ID|SESSION_MODE|ENGINE):[^\r\n]*\r?\n){0,3}--- CODEX REVIEW OUTPUT ---[ \t]*\r?\n",
        )
        .expect("codex_cli_wrapper_re")
    })
}

fn swarm_mention_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\A@[A-Za-z0-9_-]+(?:[ \t]+@[A-Za-z0-9_-]+)*[ \t]*\r?\n")
            .expect("swarm_mention_line_re")
    })
}

fn json_array_start_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"\A\[[ \t]*(?:[\{\[\"]|\][ \t]*(?:\r?\n|\z)|(?:true|false|null)[ \t]*(?:,|\][ \t]*(?:\r?\n|\z)|\r?\n|\z)|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?[ \t]*(?:,|\][ \t]*(?:\r?\n|\z)|\r?\n|\z)|\r?\n|\z)"#,
        )
        .expect("json_array_start_re")
    })
}

fn simplify_template_pair_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:(?:\*{1,2}|__|`)\s*){0,2}SIMPLIFY_(?:VERDICT|LENS)(?:(?:\*{1,2}|__|`)\s*){0,2}\s*:\s*(?:(?:\*{1,2}|__|`)\s*){0,2}(?:CLEAN|FINDINGS_REPORTED|ACTIONABLE_FIXES|REUSE|QUALITY|EFFICIENCY|ALL|COMBINED)(?:(?:\*{1,2}|__|`)\s*){0,2}\s*(?:\(|,|\||/)?\s*(?:\bor\b|\bили\b|\|)\s*(?:(?:\*{1,2}|__|`)\s*){0,2}SIMPLIFY_(?:VERDICT|LENS)(?:(?:\*{1,2}|__|`)\s*){0,2}\s*:\s*(?:(?:\*{1,2}|__|`)\s*){0,2}(?:CLEAN|FINDINGS_REPORTED|ACTIONABLE_FIXES|REUSE|QUALITY|EFFICIENCY|ALL|COMBINED)(?:(?:\*{1,2}|__|`)\s*){0,2}\)?",
        )
        .expect("simplify_template_pair_re")
    })
}

fn simplify_verdict_core_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:(?:\*{1,2}|__|`)\s*){0,2}SIMPLIFY_VERDICT(?:(?:\*{1,2}|__|`)\s*){0,2}\s*:\s*(?:(?:\*{1,2}|__|`)\s*){0,2}(CLEAN|FINDINGS_REPORTED|ACTIONABLE_FIXES)",
        )
        .expect("simplify_verdict_core_re")
    })
}

fn simplify_lens_core_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:(?:\*{1,2}|__|`)\s*){0,2}SIMPLIFY_LENS(?:(?:\*{1,2}|__|`)\s*){0,2}\s*:\s*(?:(?:\*{1,2}|__|`)\s*){0,2}(REUSE|QUALITY|EFFICIENCY)",
        )
        .expect("simplify_lens_core_re")
    })
}

fn simplify_combined_lens_core_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:(?:\*{1,2}|__|`)\s*){0,2}SIMPLIFY_LENS(?:(?:\*{1,2}|__|`)\s*){0,2}\s*:\s*(?:(?:\*{1,2}|__|`)\s*){0,2}(ALL|COMBINED)",
        )
        .expect("simplify_combined_lens_core_re")
    })
}

fn simplify_alt_tail_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // WORKAROUND: Emulates Python negative lookahead `_SIMPLIFY_ALT_TAIL` and `/(?!/)` without lookaround.
        Regex::new(
            r"(?i)\A\s*(?:(?:\*{1,2}|__|`)\s*){0,2}(?:\||/(?:[^/]|\z)|\(?\s*\b(?:or|или)\b\s+(?:(?:(?:\*{1,2}|__|`)\s*){0,2}SIMPLIFY_(?:VERDICT|LENS)(?:(?:\*{1,2}|__|`)\s*){0,2}\s*:\s*(?:(?:\*{1,2}|__|`)\s*){0,2})?(?:CLEAN|FINDINGS_REPORTED|ACTIONABLE_FIXES|REUSE|QUALITY|EFFICIENCY|ALL|COMBINED)\b|,\s*(?:(?:\*{1,2}|__|`)\s*){0,2}(?:(?:or|или)\b\s+)?(?:CLEAN|FINDINGS_REPORTED|ACTIONABLE_FIXES|REUSE|QUALITY|EFFICIENCY|ALL|COMBINED)\b)",
        )
        .expect("simplify_alt_tail_re")
    })
}

fn review_tier_xhigh_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\bREVIEW_TIER\s*:\s*XHIGH\b").expect("review_tier_xhigh_re"))
}

fn diff_hash_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\bDIFF_HASH\s*:\s*([A-Za-z0-9_.:-]+)").expect("diff_hash_re")
    })
}

fn flash_model_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\bflash(?:[-_]lite)?\b").expect("flash_model_re"))
}

fn compact_simplify_worker_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^simp-(?:reuse|quality|efficiency|efficie|all)(?:$|[-_][a-z0-9._-]*$)")
            .expect("compact_simplify_worker_re")
    })
}

fn is_ascii_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn is_unicode_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn skip_md_and_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() {
        if b[i].is_ascii_whitespace() || b[i] == b'*' || b[i] == b'`' {
            i += 1;
        } else if i + 1 < b.len() && b[i] == b'_' && b[i + 1] == b'_' {
            i += 2;
        } else {
            break;
        }
    }
    i
}

fn is_simplify_line_prefix_clean(prefix: &str) -> bool {
    // INVARIANT: Single-pass O(L) byte scanner (zero regex backtracking, zero UTF-8 str-slice panics) rejecting inline prose citations (`anom-d6ceeff0`) while allowing `@mention`, bullets, and prior tags.
    let tb = prefix.trim_start().as_bytes();
    let b = if tb.len() >= 2
        && matches!(tb[0], b'-' | b'*' | b'+' | b'>')
        && tb[1].is_ascii_whitespace()
    {
        &tb[2..]
    } else {
        tb
    };
    let mut i = 0usize;
    loop {
        i = skip_md_and_ws(b, i);
        if i >= b.len() {
            return true;
        }
        if b[i] == b'@' {
            i += 1;
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'-') {
                i += 1;
            }
            if i == start || (i < b.len() && !b[i].is_ascii_whitespace()) {
                return false;
            }
            continue;
        }
        let rest = &b[i..];
        let key_len = [
            b"SIMPLIFY_LENS".as_slice(),
            b"SIMPLIFY_VERDICT".as_slice(),
            b"DIFF_HASH".as_slice(),
        ]
        .iter()
        .find(|&&k| rest.get(..k.len()).map_or(false, |h| h.eq_ignore_ascii_case(k)))
        .map(|k| k.len());
        let Some(klen) = key_len else {
            return false;
        };
        i += klen;
        i = skip_md_and_ws(b, i);
        if i >= b.len() || b[i] != b':' {
            return false;
        }
        i += 1;
        i = skip_md_and_ws(b, i);
        let val_start = i;
        while i < b.len()
            && (b[i].is_ascii_alphanumeric() || matches!(b[i], b'_' | b'.' | b':' | b'-'))
        {
            i += 1;
        }
        if i == val_start {
            return false;
        }
        loop {
            let next_i = skip_md_and_ws(b, i);
            if next_i < b.len() && matches!(b[next_i], b',' | b'.' | b';' | b'|' | b'/' | b'-') {
                i = next_i + 1;
            } else {
                i = next_i;
                break;
            }
        }
    }
}

fn simplify_tag_prefix_ok(before: &str) -> bool {
    // WORKAROUND: Emulates `(?<![A-Za-z0-9_])(?<!\(or )(?<!\(or `)(?<!\bor )(?<!\bor `)(?<!\bили )` plus O(L) line-prefix guard (`anom-d6ceeff0`).
    if let Some(prev) = before.chars().next_back() {
        if is_ascii_ident_char(prev) {
            return false;
        }
    }
    let low = before.to_lowercase();
    if low.ends_with("(or ") || low.ends_with("(or `") {
        return false;
    }
    for suffix in ["or ", "or `", "или "] {
        if let Some(head) = low.strip_suffix(suffix) {
            let boundary_ok = head
                .chars()
                .next_back()
                .map_or(true, |c| !is_unicode_word_char(c));
            if boundary_ok {
                return false;
            }
        }
    }
    let line_before = before.rsplit('\n').next().unwrap_or(before);
    let eff_prefix = match line_before.rfind("content=") {
        Some(idx) => &line_before[idx + "content=".len()..],
        None => line_before,
    };
    is_simplify_line_prefix_clean(eff_prefix)
}

fn simplify_tag_suffix_ok(after: &str) -> bool {
    // WORKAROUND: Emulates `(?:(?![A-Za-z0-9_])|(?=__(?![A-Za-z0-9_])))` + `_SIMPLIFY_ALT_TAIL`.
    let right_boundary_ok = match after.chars().next() {
        None => true,
        Some(c) if !is_ascii_ident_char(c) => true,
        Some('_') if after.starts_with("__") => after[2..]
            .chars()
            .next()
            .map_or(true, |c| !is_ascii_ident_char(c)),
        Some(_) => false,
    };
    if !right_boundary_ok {
        return false;
    }
    !simplify_alt_tail_re().is_match(after)
}

fn find_simplify_tag_matches(core_re: &Regex, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos <= text.len() {
        let Some(caps) = core_re.captures_at(text, pos) else {
            break;
        };
        let whole = caps.get(0).expect("group 0");
        let val = caps.get(1).expect("group 1");
        let before = &text[..whole.start()];
        let after = &text[whole.end()..];
        if simplify_tag_prefix_ok(before) && simplify_tag_suffix_ok(after) {
            out.push(val.as_str().to_string());
            if whole.end() > pos {
                pos = whole.end();
            } else if let Some(ch) = text[pos..].chars().next() {
                pos += ch.len_utf8();
            } else {
                break;
            }
        } else if let Some(ch) = text[whole.start()..].chars().next() {
            pos = whole.start() + ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

fn decision_from_json_dict(obj: &Map<String, Value>) -> (Option<String>, Option<String>) {
    // INVARIANT: Inspect ONLY top-level decision keys (`closure_validation`/`verdict`), never nested finding text.
    for key in ["closure_validation", "CLOSURE_VALIDATION"] {
        if let Some(Value::String(raw_cls)) = obj.get(key) {
            let s = raw_cls.trim();
            if !s.is_empty() {
                if let Some(caps) = closure_line_re().captures(s) {
                    return (
                        Some("closure".to_string()),
                        Some(caps[1].to_uppercase()),
                    );
                }
                let up = s.trim_matches(|c: char| matches!(c, '*' | '`' | ' ' | '\t' | '\r' | '\n')).to_uppercase();
                if up == "READY" || up == "BLOCKED" {
                    return (Some("closure".to_string()), Some(up));
                }
            }
        }
    }
    for key in ["verdict", "VERDICT"] {
        if let Some(Value::String(raw_ord)) = obj.get(key) {
            let s = raw_ord.trim();
            if !s.is_empty() {
                if let Some(caps) = closure_line_re().captures(s) {
                    return (
                        Some("closure".to_string()),
                        Some(caps[1].to_uppercase()),
                    );
                }
                if let Some(caps) = verdict_line_re().captures(s) {
                    return (
                        Some("ordinary".to_string()),
                        Some(caps[1].to_uppercase()),
                    );
                }
                let up = s.trim_matches(|c: char| matches!(c, '*' | '`' | ' ' | '\t' | '\r' | '\n')).to_uppercase();
                if up == "APPROVED" || up == "REVISE" || up == "ESCALATE" {
                    return (Some("ordinary".to_string()), Some(up));
                }
                if up == "READY" || up == "BLOCKED" {
                    return (Some("closure".to_string()), Some(up));
                }
            }
        }
    }
    (None, None)
}

fn advance_json_depth(line: &str, mut depth: usize, mut in_str: bool, mut esc: bool) -> (usize, bool, bool) {
    for ch in line.chars() {
        if in_str {
            if esc {
                esc = false;
            } else if ch == '\\' {
                esc = true;
            } else if ch == '"' {
                in_str = false;
            }
        } else if ch == '"' {
            in_str = true;
        } else if ch == '{' || ch == '[' {
            depth += 1;
        } else if ch == '}' || ch == ']' {
            depth = depth.saturating_sub(1);
        }
    }
    (depth, in_str, esc)
}

fn strip_unfenced_json_blocks(lines: &[&str]) -> String {
    // SAFETY: Exclude unfenced line-anchored `{...}` / `[...]` blocks from plain-text fallback.
    let mut kept: Vec<&str> = Vec::new();
    let mut depth = 0usize;
    let mut in_str = false;
    let mut esc = false;
    for &ln in lines {
        if depth == 0 && !in_str {
            let lstripped = ln.trim_start_matches([' ', '\t']);
            if lstripped.starts_with('{') || json_array_start_re().is_match(lstripped) {
                (depth, in_str, esc) = advance_json_depth(lstripped, 0, false, false);
                continue;
            }
            kept.push(ln);
            continue;
        }
        (depth, in_str, esc) = advance_json_depth(ln, depth, in_str, esc);
    }
    kept.join("\n").trim().to_string()
}

fn extract_terminal_json_dict(text: &str) -> (Option<Map<String, Value>>, String) {
    let mut body = text.trim();
    if body.is_empty() {
        return (None, String::new());
    }
    if let Some(m) = codex_cli_wrapper_re().find(body) {
        body = body[m.end()..].trim();
    }
    if let Some(m) = swarm_mention_line_re().find(body) {
        body = body[m.end()..].trim();
    }
    if body.is_empty() {
        return (None, String::new());
    }
    if body.starts_with('{') {
        if !body.ends_with('}') {
            return (None, String::new());
        }
        if let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(body) {
            return (Some(obj), String::new());
        }
        return (None, String::new());
    }
    if json_array_start_re().is_match(body) {
        return (None, String::new());
    }
    if body.contains("```") {
        let lines: Vec<&str> = body.lines().collect();
        let fence_indices: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter_map(|(i, ln)| if ln.trim().starts_with("```") { Some(i) } else { None })
            .collect();
        let n_fences = fence_indices.len();
        let has_terminal_fence = n_fences >= 2
            && n_fences % 2 == 0
            && fence_indices[n_fences - 1] == lines.len() - 1
            && lines[lines.len() - 1].trim() == "```";
        let mut excluded_ranges: Vec<(usize, usize)> = Vec::new();
        let mut k = 0usize;
        while k + 1 < n_fences {
            excluded_ranges.push((fence_indices[k], fence_indices[k + 1]));
            k += 2;
        }
        if n_fences % 2 == 1 {
            excluded_ranges.push((fence_indices[n_fences - 1], lines.len() - 1));
        }

        let mut json_candidate: Option<Map<String, Value>> = None;
        if has_terminal_fence {
            let open_idx = fence_indices[n_fences - 2];
            let fence_hdr = lines[open_idx].trim().to_lowercase();
            let fenced = lines[open_idx + 1..lines.len() - 1].join("\n");
            let fenced_trim = fenced.trim();
            if (fence_hdr == "```" || fence_hdr == "```json")
                && fenced_trim.starts_with('{')
                && fenced_trim.ends_with('}')
            {
                if let Ok(Value::Object(parsed)) = serde_json::from_str::<Value>(fenced_trim) {
                    json_candidate = Some(parsed);
                }
            }
        }

        let mut kept_lines: Vec<&str> = Vec::new();
        let mut r_idx = 0usize;
        for (idx, &ln) in lines.iter().enumerate() {
            while r_idx < excluded_ranges.len() && idx > excluded_ranges[r_idx].1 {
                r_idx += 1;
            }
            if r_idx < excluded_ranges.len()
                && excluded_ranges[r_idx].0 <= idx
                && idx <= excluded_ranges[r_idx].1
            {
                continue;
            }
            kept_lines.push(ln);
        }
        return (json_candidate, strip_unfenced_json_blocks(&kept_lines));
    }
    let lines: Vec<&str> = body.lines().collect();
    (None, strip_unfenced_json_blocks(&lines))
}

pub fn extract_review_decision(text: &str) -> (Option<String>, Option<String>) {
    let stripped = text.trim();
    if stripped.is_empty() {
        return (None, None);
    }
    let (json_obj, prose_fallback) = extract_terminal_json_dict(stripped);
    if let Some(obj) = json_obj {
        let dec = decision_from_json_dict(&obj);
        if dec.0.is_some() || dec.1.is_some() || prose_fallback.is_empty() {
            return dec;
        }
    }
    if prose_fallback.is_empty() {
        return (None, None);
    }
    if let Some(last_cls) = closure_line_re().captures_iter(&prose_fallback).last() {
        return (
            Some("closure".to_string()),
            Some(last_cls[1].to_uppercase()),
        );
    }
    if let Some(last_ord) = verdict_line_re().captures_iter(&prose_fallback).last() {
        return (
            Some("ordinary".to_string()),
            Some(last_ord[1].to_uppercase()),
        );
    }
    (None, None)
}

pub fn extract_diff_hash(text: &str) -> String {
    diff_hash_re()
        .captures_iter(text)
        .last()
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
        .unwrap_or_default()
}

pub fn is_flash_model(model: &str) -> bool {
    flash_model_re().is_match(model.trim())
}

pub fn is_simplify_worker_name(name: &str) -> bool {
    let low = name.trim().to_lowercase();
    if low.is_empty() {
        return false;
    }
    low.contains("simplify") || compact_simplify_worker_re().is_match(&low)
}

pub fn simplify_lens_from_worker_name(name: &str) -> String {
    let low = name.trim().to_lowercase();
    if low.is_empty() {
        return String::new();
    }
    for &lens in SIMPLIFY_LENSES {
        if low.contains(lens) {
            return lens.to_string();
        }
    }
    if low.contains("efficie") && is_simplify_worker_name(&low) {
        return "efficiency".to_string();
    }
    String::new()
}

pub fn is_simplify_subagent_call(sub_type: &str, role: &str) -> bool {
    let trimmed = sub_type.trim().to_lowercase();
    let base = trimmed.rsplit(':').next().unwrap_or("");
    if SIMPLIFY_AGENT_TYPES.contains(&base) {
        return true;
    }
    (base == "research" || base == "self") && is_simplify_worker_name(role)
}

pub fn is_review_tier_xhigh(text: &str) -> bool {
    review_tier_xhigh_re().is_match(text)
}

pub fn swarm_stall_timeout_sec() -> f64 {
    let raw = env::var("SWARM_STALL_TIMEOUT_SEC").unwrap_or_default();
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return DEFAULT_SWARM_STALL_TIMEOUT_SEC;
    }
    match trimmed.parse::<f64>() {
        Ok(parsed) if parsed.is_finite() && parsed > 0.0 => parsed,
        _ => DEFAULT_SWARM_STALL_TIMEOUT_SEC,
    }
}

pub fn parse_simplify_verdict(text: &str, default_lens: Option<&str>) -> Value {
    let cleaned = simplify_template_pair_re().replace_all(text, " ");
    let has_combined = !find_simplify_tag_matches(simplify_combined_lens_core_re(), &cleaned).is_empty();
    let explicit_lenses = find_simplify_tag_matches(simplify_lens_core_re(), &cleaned);
    let mut seen = HashSet::new();
    let mut unique_lenses = Vec::new();
    for m in explicit_lenses {
        let low = m.to_lowercase();
        if seen.insert(low.clone()) {
            unique_lenses.push(low);
        }
    }
    let verdict_matches = find_simplify_tag_matches(simplify_verdict_core_re(), &cleaned);
    let verdict = verdict_matches
        .last()
        .map(|s| s.to_uppercase())
        .unwrap_or_default();
    let multi_lens_spoof = !has_combined && unique_lenses.len() > 1;
    let lens = if has_combined {
        "all".to_string()
    } else if unique_lenses.len() == 1 {
        unique_lenses[0].clone()
    } else if multi_lens_spoof {
        "combined".to_string()
    } else {
        default_lens.unwrap_or("").trim().to_lowercase()
    };
    let clean = verdict == "CLEAN";
    let combined = has_combined || multi_lens_spoof || lens == "all" || lens == "combined";
    json!({
        "lens": lens,
        "verdict": verdict,
        "clean": clean,
        "combined": combined,
        "has_explicit_all": has_combined,
        "multi_lens_spoof": multi_lens_spoof,
        "explicit_lenses": unique_lenses,
    })
}

fn normalize_diff_metrics(raw: &Map<String, Value>, default_source: &str) -> Value {
    let files_count = val_to_i64(raw.get("files_count").or_else(|| raw.get("files")));
    let additions = val_to_i64(raw.get("additions")).max(0);
    let deletions = val_to_i64(raw.get("deletions")).max(0);
    let total = match raw.get("total_lines") {
        Some(v) if !v.is_null() => val_to_i64(Some(v)).max(0),
        _ => additions + deletions,
    };
    let source = match raw.get("source") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => default_source.to_string(),
    };
    json!({
        "files_count": files_count,
        "additions": additions,
        "deletions": deletions,
        "total_lines": total,
        "source": source,
    })
}

fn probe_untracked_file_lines(fp: &Path) -> Result<(bool, i64), std::io::Error> {
    let mut fh = File::open(fp)?;
    let mut head = [0u8; 4096];
    let n = fh.read(&mut head)?;
    if n == 0 {
        return Ok((false, 0));
    }
    let slice = &head[..n];
    if slice.contains(&0u8) {
        return Ok((true, 0));
    }
    let mut newlines = slice.iter().filter(|&&b| b == b'\n').count() as i64;
    let mut last_byte = slice[n - 1];
    let mut buf = vec![0u8; 65536];
    loop {
        let m = fh.read(&mut buf)?;
        if m == 0 {
            break;
        }
        let chunk = &buf[..m];
        newlines += chunk.iter().filter(|&&b| b == b'\n').count() as i64;
        last_byte = chunk[m - 1];
    }
    let extra = if last_byte == b'\n' || last_byte == b'\r' { 0 } else { 1 };
    Ok((false, newlines + extra))
}

pub fn compute_diff_metrics(marker: &Value, repo_root: &str, diff_stats: Option<&Value>) -> Value {
    if let Some(Value::Object(ds)) = diff_stats {
        if !ds.is_empty() {
            return normalize_diff_metrics(ds, "explicit");
        }
    }
    let m_obj = marker.as_object();
    let saved = m_obj.and_then(|m| m.get("diff_metrics")).and_then(|v| v.as_object());
    if let Some(sv) = saved {
        if !sv.is_empty()
            && (repo_root.trim().is_empty()
                || sv.get("source").and_then(|v| v.as_str()) == Some("explicit"))
        {
            return normalize_diff_metrics(sv, "marker");
        }
    }

    if !repo_root.trim().is_empty() {
        let (rc, out, _) = rio::run_git(repo_root, &["rev-parse", "--verify", "HEAD"], 5.0);
        let diff_args: &[&str] = if rc == 0 && !out.trim().is_empty() {
            &["diff", "--numstat", "HEAD"]
        } else {
            &["diff", "--numstat"]
        };
        let (rc_d, out_d, _) = rio::run_git(repo_root, diff_args, 5.0);
        let (rc_u, out_u, _) = rio::run_git(repo_root, &["ls-files", "--others", "--exclude-standard"], 5.0);
        let mut git_files: HashSet<String> = HashSet::new();
        let mut adds: i64 = 0;
        let mut dels: i64 = 0;
        let mut has_binary = false;
        if rc_d == 0 && !out_d.is_empty() {
            for line in out_d.lines() {
                let mut parts = line.splitn(3, '\t');
                let (Some(a_raw), Some(d_raw), Some(rel)) = (parts.next(), parts.next(), parts.next()) else {
                    continue;
                };
                if is_scratch_or_ephemeral(rel, "", &[], repo_root) {
                    continue;
                }
                git_files.insert(rio::normalize_path(rel));
                if a_raw == "-" || d_raw == "-" {
                    has_binary = true;
                } else {
                    adds += a_raw.trim().parse::<i64>().unwrap_or(0);
                    dels += d_raw.trim().parse::<i64>().unwrap_or(0);
                }
            }
        }
        if rc_u == 0 && !out_u.is_empty() {
            let root_path = Path::new(repo_root);
            for raw_rel in out_u.lines() {
                let rel = raw_rel.trim();
                if rel.is_empty() || is_scratch_or_ephemeral(rel, "", &[], repo_root) {
                    continue;
                }
                git_files.insert(rio::normalize_path(rel));
                let fp = root_path.join(rel);
                if fp.is_file() {
                    if let Ok((f_bin, f_lines)) = probe_untracked_file_lines(&fp) {
                        if f_bin {
                            has_binary = true;
                        } else {
                            adds += f_lines;
                        }
                    }
                }
            }
        }
        if !git_files.is_empty() {
            let candidate_dpaths = durable_paths_from_val(m_obj.and_then(|m| m.get("paths")));
            let mut all_files = git_files;
            for cp in &candidate_dpaths {
                if let Some(rel_cp) = resolve_repo_rel_path(cp, repo_root) {
                    if !rel_cp.is_empty() {
                        all_files.insert(rel_cp);
                    }
                }
            }
            let total = if !has_binary {
                adds + dels
            } else {
                (adds + dels).max((FAST_PATH_MAX_LINES as i64) + 1)
            };
            let files_count = all_files.len().max(candidate_dpaths.len());
            return json!({
                "files_count": files_count,
                "additions": adds,
                "deletions": dels,
                "total_lines": total,
                "source": "git",
            });
        }
    }

    if let Some(sv) = saved {
        if !sv.is_empty() {
            return normalize_diff_metrics(sv, "marker");
        }
    }

    let dpaths = durable_paths_from_val(m_obj.and_then(|m| m.get("paths")));
    let changed_lines = val_to_i64(m_obj.and_then(|m| m.get("changed_lines"))).max(0);
    json!({
        "files_count": dpaths.len(),
        "additions": changed_lines,
        "deletions": 0,
        "total_lines": changed_lines,
        "source": "marker-fallback",
    })
}

pub fn is_simplify_fast_path_eligible(
    marker: &Value,
    swarm_ev: Option<&Value>,
    diff_stats: Option<&Value>,
    repo_root: &str,
) -> bool {
    if let Some(sev) = swarm_ev {
        if json_truthy(sev.get("multi_lens_spoof")) {
            return false;
        }
    }
    let effective_root = if !repo_root.trim().is_empty() {
        repo_root.to_string()
    } else {
        let rr = val_to_str(marker.get("repo_root"));
        if !rr.trim().is_empty() {
            rr
        } else {
            val_to_str(marker.get("cwd"))
        }
    };
    let metrics = compute_diff_metrics(marker, &effective_root, diff_stats);
    let mut files_count = val_to_i64(metrics.get("files_count")).max(0) as usize;
    let total_lines = val_to_i64(metrics.get("total_lines")).max(0) as usize;
    if files_count == 0 {
        files_count = durable_paths_from_val(marker.get("paths")).len();
    }
    files_count > 0 && files_count <= FAST_PATH_MAX_FILES && total_lines <= FAST_PATH_MAX_LINES
}

pub fn extract_msg_seq(row: &Value, fallback: i64) -> i64 {
    let raw = row
        .get("seq")
        .filter(|v| !v.is_null())
        .or_else(|| row.get("msg_id").filter(|v| !v.is_null()))
        .or_else(|| row.get("id").filter(|v| !v.is_null()));
    let Some(val) = raw else {
        return fallback;
    };
    match val {
        Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_f64().map(|f| f as i64))
            .unwrap_or(fallback),
        Value::String(s) => s.trim().parse::<i64>().unwrap_or(fallback),
        _ => fallback,
    }
}

fn swarm_board_candidates(session: &str, cwd: &str, transcript_path: &str) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();
    let mut add = |p: PathBuf| {
        let k = rio::fold_path(&p.to_string_lossy());
        if seen.insert(k) {
            candidates.push(p);
        }
    };

    let (tp_brain, tp_cid) = rio::swarm_brain_and_cid(transcript_path, session);
    let eff_session = if !tp_cid.is_empty() {
        tp_cid
    } else {
        session.trim().to_string()
    };
    if let Some(brain) = tp_brain {
        if !eff_session.is_empty() {
            add(rio::swarm_dir(&brain, &eff_session).join("board.jsonl"));
        }
    }
    if !eff_session.is_empty() {
        add(rio::swarm_dir(&rio::resolve_brain_root(""), &eff_session).join("board.jsonl"));
    }
    if !cwd.trim().is_empty() {
        let cwd_p = Path::new(cwd);
        let local_board = cwd_p.join(".swarm").join("board.jsonl");
        let local_is_file = local_board.is_file();
        let has_git = cwd_p.join(".git").exists();
        add(local_board);
        if !has_git && !local_is_file {
            if let Some(top) = rio::git_toplevel(cwd, false) {
                add(PathBuf::from(top).join(".swarm").join("board.jsonl"));
            }
        }
    }
    candidates
}

fn resolve_board_path_and_rows(
    session: &str,
    cwd: &str,
    transcript_path: &str,
) -> (Option<PathBuf>, Vec<Value>) {
    let candidates = swarm_board_candidates(session, cwd, transcript_path);
    let mut best_existing: Option<PathBuf> = None;
    let mut best_rows: Vec<Value> = Vec::new();
    let mut best_head: i64 = -1;

    for cand in &candidates {
        if cand.is_file() {
            let rows = rio::read_jsonl(cand, None);
            let head = rows
                .iter()
                .enumerate()
                .filter(|(_, r)| r.is_object())
                .map(|(idx, r)| extract_msg_seq(r, (idx + 1) as i64))
                .max()
                .unwrap_or(0);
            if !rows.is_empty() && head > best_head {
                best_existing = Some(cand.clone());
                best_rows = rows;
                best_head = head;
            } else if best_existing.is_none() {
                best_existing = Some(cand.clone());
                best_rows = rows;
            }
        }
    }

    if best_existing.is_some() {
        return (best_existing, best_rows);
    }
    (candidates.into_iter().next(), Vec::new())
}

pub fn load_swarm_board_messages(
    session: &str,
    cwd: &str,
    transcript_path: &str,
    board_path: Option<&Path>,
) -> (Option<PathBuf>, Vec<Value>) {
    let (bp, rows) = if let Some(p) = board_path {
        if !p.is_file() {
            return (Some(p.to_path_buf()), Vec::new());
        }
        (Some(p.to_path_buf()), rio::read_jsonl(p, None))
    } else {
        let (resolved, r) = resolve_board_path_and_rows(session, cwd, transcript_path);
        if resolved.is_none() || r.is_empty() {
            return (resolved, Vec::new());
        }
        (resolved, r)
    };

    let mut normalized = Vec::new();
    for (idx, row) in rows.into_iter().enumerate() {
        if let Value::Object(mut map) = row {
            let seq = extract_msg_seq(&Value::Object(map.clone()), (idx + 1) as i64);
            map.insert("_seq".to_string(), json!(seq));
            normalized.push(Value::Object(map));
        }
    }
    (bp, normalized)
}

pub fn swarm_board_head_seq(
    session: &str,
    cwd: &str,
    transcript_path: &str,
    board_path: Option<&Path>,
) -> i64 {
    let (_, msgs) = load_swarm_board_messages(session, cwd, transcript_path, board_path);
    msgs.iter()
        .map(|m| val_to_i64(m.get("_seq")))
        .max()
        .unwrap_or(0)
}

pub fn ownership_manifest_path(cwd: &str) -> Option<PathBuf> {
    if cwd.trim().is_empty() {
        return None;
    }
    let p = Path::new(cwd);
    if p.join(".swarm").join("ownership.json").is_file() || p.join(".git").exists() {
        return Some(p.join(".swarm").join("ownership.json"));
    }
    let root = rio::git_toplevel(cwd, false).unwrap_or_else(|| cwd.to_string());
    Some(PathBuf::from(root).join(".swarm").join("ownership.json"))
}

pub fn load_ownership_manifest(cwd: &str) -> Value {
    if let Some(path) = ownership_manifest_path(cwd) {
        if let Some(Value::Object(doc)) = rio::read_json(&path) {
            if doc.get("workers").map_or(false, |w| w.is_object()) {
                return Value::Object(doc);
            }
        }
    }
    json!({ "workers": {} })
}

pub fn save_ownership_manifest(cwd: &str, manifest: &Value) -> Result<PathBuf, String> {
    let path = ownership_manifest_path(cwd).ok_or_else(|| "empty cwd".to_string())?;
    rio::write_json(&path, manifest)?;
    Ok(path)
}

pub fn normalize_glob_pattern(pattern: &str) -> String {
    let mut p = pattern.trim().replace('\\', "/");
    while let Some(rest) = p.strip_prefix("./") {
        p = rest.to_string();
    }
    p = p.trim_start_matches('/').to_string();
    while p.contains("//") {
        p = p.replace("//", "/");
    }
    if p.ends_with('/') && p.len() > 1 {
        p.push_str("**");
    }
    p
}

fn split_glob_segments(pattern: &str) -> Vec<String> {
    let norm = normalize_glob_pattern(pattern);
    if norm.is_empty() {
        return Vec::new();
    }
    norm.split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn seg_patterns_intersect(p1: &str, p2: &str) -> bool {
    let a: Vec<char> = p1.to_lowercase().chars().collect();
    let b: Vec<char> = p2.to_lowercase().chars().collect();
    if a.contains(&'[') || b.contains(&'[') {
        return true;
    }
    let mut memo: HashMap<(usize, usize), bool> = HashMap::new();
    fn dp(
        i: usize,
        j: usize,
        a: &[char],
        b: &[char],
        memo: &mut HashMap<(usize, usize), bool>,
    ) -> bool {
        if let Some(&cached) = memo.get(&(i, j)) {
            return cached;
        }
        let res = if i == a.len() && j == b.len() {
            true
        } else if i < a.len() && a[i] == '*' {
            dp(i + 1, j, a, b, memo) || (j < b.len() && dp(i, j + 1, a, b, memo))
        } else if j < b.len() && b[j] == '*' {
            dp(i, j + 1, a, b, memo) || (i < a.len() && dp(i + 1, j, a, b, memo))
        } else if i < a.len() && j < b.len() {
            let ca = a[i];
            let cb = b[j];
            (ca == '?' || cb == '?' || ca == cb) && dp(i + 1, j + 1, a, b, memo)
        } else {
            false
        };
        memo.insert((i, j), res);
        res
    }
    dp(0, 0, &a, &b, &mut memo)
}

fn fnmatch_ci(name: &str, pat: &str) -> bool {
    let n: Vec<char> = name.to_lowercase().chars().collect();
    let p: Vec<char> = pat.to_lowercase().chars().collect();
    let mut memo: HashMap<(usize, usize), bool> = HashMap::new();
    fn dp(
        ni: usize,
        pi: usize,
        n: &[char],
        p: &[char],
        memo: &mut HashMap<(usize, usize), bool>,
    ) -> bool {
        if let Some(&cached) = memo.get(&(ni, pi)) {
            return cached;
        }
        let res = if pi == p.len() {
            ni == n.len()
        } else if p[pi] == '*' {
            dp(ni, pi + 1, n, p, memo) || (ni < n.len() && dp(ni + 1, pi, n, p, memo))
        } else if ni == n.len() {
            false
        } else if p[pi] == '?' {
            dp(ni + 1, pi + 1, n, p, memo)
        } else if p[pi] == '[' {
            let mut j = pi + 1;
            let mut neg = false;
            if j < p.len() && (p[j] == '!' || p[j] == '^') {
                neg = true;
                j += 1;
            }
            if j < p.len() && p[j] == ']' {
                j += 1;
            }
            while j < p.len() && p[j] != ']' {
                j += 1;
            }
            if j >= p.len() {
                n[ni] == '[' && dp(ni + 1, pi + 1, n, p, memo)
            } else {
                let start = pi + 1 + usize::from(neg);
                let ch = n[ni];
                let mut matched = false;
                let mut k = start;
                while k < j {
                    if k + 2 < j && p[k + 1] == '-' {
                        if p[k] <= ch && ch <= p[k + 2] {
                            matched = true;
                        }
                        k += 3;
                    } else {
                        if p[k] == ch {
                            matched = true;
                        }
                        k += 1;
                    }
                }
                let ok = if neg { !matched } else { matched };
                ok && dp(ni + 1, j + 1, n, p, memo)
            }
        } else {
            n[ni] == p[pi] && dp(ni + 1, pi + 1, n, p, memo)
        };
        memo.insert((ni, pi), res);
        res
    }
    dp(0, 0, &n, &p, &mut memo)
}

pub fn glob_matches_path(pattern: &str, rel_path: &str) -> bool {
    let pat_segs = split_glob_segments(pattern);
    let mut rel_norm = normalize_glob_pattern(rel_path);
    if rel_norm.ends_with("**") {
        rel_norm = rel_norm[..rel_norm.len() - 2].trim_end_matches('/').to_string();
    }
    let path_segs: Vec<String> = rel_norm
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    if pat_segs.is_empty() || path_segs.is_empty() {
        return false;
    }
    let mut memo: HashMap<(usize, usize), bool> = HashMap::new();
    fn dp(
        pi: usize,
        si: usize,
        pat_segs: &[String],
        path_segs: &[String],
        memo: &mut HashMap<(usize, usize), bool>,
    ) -> bool {
        if let Some(&cached) = memo.get(&(pi, si)) {
            return cached;
        }
        let res = if pi == pat_segs.len() && si == path_segs.len() {
            true
        } else if pi < pat_segs.len() && pat_segs[pi] == "**" {
            dp(pi + 1, si, pat_segs, path_segs, memo)
                || (si < path_segs.len() && dp(pi, si + 1, pat_segs, path_segs, memo))
        } else if pi < pat_segs.len() && si < path_segs.len() {
            fnmatch_ci(&path_segs[si], &pat_segs[pi])
                && dp(pi + 1, si + 1, pat_segs, path_segs, memo)
        } else {
            false
        };
        memo.insert((pi, si), res);
        res
    }
    dp(0, 0, &pat_segs, &path_segs, &mut memo)
}

pub fn globs_may_overlap(g1: &str, g2: &str, existing_files: Option<&[String]>) -> bool {
    let s1 = split_glob_segments(g1);
    let s2 = split_glob_segments(g2);
    if s1.is_empty() || s2.is_empty() {
        return false;
    }
    let mut memo: HashMap<(usize, usize), bool> = HashMap::new();
    fn dp(
        i: usize,
        j: usize,
        s1: &[String],
        s2: &[String],
        memo: &mut HashMap<(usize, usize), bool>,
    ) -> bool {
        if let Some(&cached) = memo.get(&(i, j)) {
            return cached;
        }
        let res = if i == s1.len() && j == s2.len() {
            true
        } else if i < s1.len() && s1[i] == "**" {
            dp(i + 1, j, s1, s2, memo) || (j < s2.len() && dp(i, j + 1, s1, s2, memo))
        } else if j < s2.len() && s2[j] == "**" {
            dp(i, j + 1, s1, s2, memo) || (i < s1.len() && dp(i + 1, j, s1, s2, memo))
        } else if i < s1.len() && j < s2.len() {
            seg_patterns_intersect(&s1[i], &s2[j]) && dp(i + 1, j + 1, s1, s2, memo)
        } else {
            false
        };
        memo.insert((i, j), res);
        res
    }
    if dp(0, 0, &s1, &s2, &mut memo) {
        return true;
    }
    if let Some(files) = existing_files {
        for rel in files {
            if glob_matches_path(g1, rel) && glob_matches_path(g2, rel) {
                return true;
            }
        }
    }
    false
}

fn list_repo_rel_files(repo_root: &str) -> Vec<String> {
    if repo_root.trim().is_empty() {
        return Vec::new();
    }
    let mut out_files = BTreeSet::new();
    let (rc, tracked, _) = rio::run_git(repo_root, &["ls-files"], 5.0);
    if rc == 0 && !tracked.is_empty() {
        for ln in tracked.lines() {
            let norm = normalize_glob_pattern(ln);
            if !norm.is_empty() && !norm.starts_with(".swarm/") {
                out_files.insert(norm);
            }
        }
    }
    let (rc_u, untracked, _) =
        rio::run_git(repo_root, &["ls-files", "--others", "--exclude-standard"], 5.0);
    if rc_u == 0 && !untracked.is_empty() {
        for ln in untracked.lines() {
            let norm = normalize_glob_pattern(ln);
            if !norm.is_empty() && !norm.starts_with(".swarm/") {
                out_files.insert(norm);
            }
        }
    }
    out_files.into_iter().collect()
}

pub fn detect_ownership_overlaps(manifest: &Value, repo_root: &str) -> Vec<Value> {
    let Some(workers) = manifest.get("workers").and_then(|v| v.as_object()) else {
        return Vec::new();
    };
    if workers.len() < 2 {
        return Vec::new();
    }
    let existing_files = if !repo_root.trim().is_empty() {
        list_repo_rel_files(repo_root)
    } else {
        Vec::new()
    };
    let mut names: Vec<String> = workers.keys().cloned().collect();
    names.sort();
    let mut conflicts = Vec::new();
    for idx in 0..names.len() {
        let w1 = &names[idx];
        let p1_list = workers
            .get(w1)
            .and_then(|v| v.get("paths"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        for w2 in &names[idx + 1..] {
            let p2_list = workers
                .get(w2)
                .and_then(|v| v.get("paths"))
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for g1_val in &p1_list {
                let g1 = val_to_str(Some(g1_val));
                for g2_val in &p2_list {
                    let g2 = val_to_str(Some(g2_val));
                    if globs_may_overlap(&g1, &g2, Some(&existing_files)) {
                        conflicts.push(json!({
                            "worker_a": w1,
                            "glob_a": g1,
                            "worker_b": w2,
                            "glob_b": g2,
                        }));
                    }
                }
            }
        }
    }
    conflicts
}

fn resolve_like_python(p: &Path) -> PathBuf {
    let abs = rio::resolve_abs_path(p);
    if let Ok(canon) = fs::canonicalize(&abs) {
        return PathBuf::from(rio::normalize_path(&canon.to_string_lossy()));
    }
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = abs.as_path();
    while let Some(name) = cur.file_name() {
        if let Some(parent) = cur.parent() {
            tail.push(name.to_os_string());
            if let Ok(canon) = fs::canonicalize(parent) {
                let mut base = PathBuf::from(rio::normalize_path(&canon.to_string_lossy()));
                for seg in tail.iter().rev() {
                    base.push(seg);
                }
                return PathBuf::from(rio::normalize_path(&base.to_string_lossy()));
            }
            cur = parent;
        } else {
            break;
        }
    }
    PathBuf::from(rio::normalize_path(&abs.to_string_lossy()))
}

pub fn resolve_repo_rel_info(file_path: &str, repo_root: &str) -> (Option<String>, bool) {
    let raw = file_path.trim();
    if raw.is_empty() {
        return (None, false);
    }
    let root_norm = rio::normalize_path(&resolve_like_python(Path::new(repo_root)).to_string_lossy());
    let p = Path::new(raw);
    let candidate = if p.is_absolute() {
        p.to_path_buf()
    } else {
        PathBuf::from(&root_norm).join(p)
    };
    let file_norm = rio::normalize_path(&resolve_like_python(&candidate).to_string_lossy());

    let root_trim = root_norm.trim_end_matches('/');
    let file_trim = file_norm.trim_end_matches('/');
    let root_segs: Vec<&str> = root_trim.split('/').filter(|s| !s.is_empty()).collect();
    let file_segs: Vec<&str> = file_trim.split('/').filter(|s| !s.is_empty()).collect();

    let same_prefix = root_segs.len() <= file_segs.len()
        && root_segs.iter().zip(&file_segs).all(|(a, b)| {
            #[cfg(windows)]
            {
                a.eq_ignore_ascii_case(b) || a.to_lowercase() == b.to_lowercase()
            }
            #[cfg(not(windows))]
            {
                a == b
            }
        });

    if same_prefix && (file_norm.starts_with('/') == root_norm.starts_with('/')) {
        let rel = file_segs[root_segs.len()..].join("/");
        return (Some(normalize_glob_pattern(&rel)), true);
    }
    let fallback = normalize_glob_pattern(raw);
    if fallback.is_empty() {
        (None, false)
    } else {
        (Some(fallback), false)
    }
}

pub fn resolve_repo_rel_path(file_path: &str, repo_root: &str) -> Option<String> {
    resolve_repo_rel_info(file_path, repo_root).0
}

pub fn path_matches_any_glob(rel_path: &str, globs: &[String]) -> bool {
    globs
        .iter()
        .any(|g| !g.trim().is_empty() && glob_matches_path(g, rel_path))
}

fn parse_ts_value(v: Option<&Value>) -> f64 {
    match v {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::String(s)) => rio::parse_iso_ts(s),
        _ => 0.0,
    }
}

fn exact_mention_in_text(text: &str, name: &str) -> bool {
    rio::text_contains_mention(text, name)
}

pub struct StallDetectInput<'a> {
    pub members: &'a Map<String, Value>,
    pub board_messages: &'a [Value],
    pub cwd: &'a str,
    pub brain_root: Option<&'a Path>,
    pub worker_last_activity: &'a HashMap<String, f64>,
    pub in_flight_names: &'a [String],
    pub now_ts: Option<f64>,
    pub timeout_sec: Option<f64>,
}

pub fn detect_stalled_workers(input: StallDetectInput<'_>) -> Vec<Value> {
    let StallDetectInput {
        members,
        board_messages,
        cwd,
        brain_root,
        worker_last_activity,
        in_flight_names,
        now_ts,
        timeout_sec,
    } = input;
    let active_set: HashSet<String> = in_flight_names
        .iter()
        .filter(|x| !x.trim().is_empty())
        .map(|x| x.split_once(':').map_or(x.as_str(), |(_, r)| r).to_string())
        .collect();
    if !in_flight_names.is_empty() && active_set.is_empty() {
        return Vec::new();
    }
    let has_in_flight_filter = !active_set.is_empty();

    let threshold = timeout_sec.unwrap_or_else(swarm_stall_timeout_sec);
    let now = now_ts.unwrap_or_else(now_sec);

    let repo_root = if !cwd.trim().is_empty() {
        let cwd_p = Path::new(cwd);
        if cwd_p.join(".swarm").is_dir() || cwd_p.join(".git").exists() {
            cwd.to_string()
        } else {
            rio::git_toplevel(cwd, false).unwrap_or_else(|| cwd.to_string())
        }
    } else {
        String::new()
    };

    let artifact_files: Vec<PathBuf> = if !repo_root.is_empty() {
        let adir = PathBuf::from(&repo_root).join(".swarm").join("artifacts");
        if adir.is_dir() {
            fs::read_dir(&adir)
                .ok()
                .map(|rd| rd.filter_map(|e| e.ok().map(|x| x.path())).collect())
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let mut board_ts_by_worker: HashMap<String, f64> = HashMap::new();
    let mut coord_mention_by_worker: HashMap<String, f64> = HashMap::new();
    for msg in board_messages {
        let Some(obj) = msg.as_object() else {
            continue;
        };
        let ts = parse_ts_value(
            obj.get("time")
                .or_else(|| obj.get("ts"))
                .or_else(|| obj.get("created_at")),
        );
        if ts <= 0.0 {
            continue;
        }
        let agent = val_to_str(obj.get("agent").or_else(|| obj.get("worker")))
            .trim()
            .to_string();
        let text = val_to_str(obj.get("text"));
        if agent == "coordinator" {
            for mname in members.keys() {
                if exact_mention_in_text(&text, mname) {
                    let prev = coord_mention_by_worker.get(mname).copied().unwrap_or(0.0);
                    if ts > prev {
                        coord_mention_by_worker.insert(mname.clone(), ts);
                    }
                }
            }
        } else if !agent.is_empty() {
            let prev = board_ts_by_worker.get(&agent).copied().unwrap_or(0.0);
            if ts > prev {
                board_ts_by_worker.insert(agent, ts);
            }
        }
    }

    let mut sorted_names: Vec<String> = members.keys().cloned().collect();
    sorted_names.sort();
    let mut stalled = Vec::new();
    for name in sorted_names {
        let Some(meta) = members.get(&name) else {
            continue;
        };
        if !meta.is_object() {
            continue;
        }
        if rio::is_swarm_role_member(&name, Some(meta)) || rio::is_swarm_member_killed(Some(meta)) {
            continue;
        }
        let coord_ts = coord_mention_by_worker.get(&name).copied().unwrap_or(0.0);
        let board_ts = board_ts_by_worker.get(&name).copied().unwrap_or(0.0);
        let already_replied = coord_ts > 0.0 && board_ts >= coord_ts;
        if already_replied && !active_set.contains(&name) {
            continue;
        }
        if has_in_flight_filter && !active_set.contains(&name) {
            continue;
        }
        let wake_mode = val_to_str(meta.get("wake_mode")).to_lowercase();
        let desired_state = val_to_str(meta.get("desired_state")).to_lowercase();
        let is_working_state = active_set.contains(&name)
            || wake_mode == "working"
            || desired_state == "working";
        if !is_working_state {
            continue;
        }

        let mut candidates_ts: Vec<f64> = Vec::new();
        if let Some(&act_ts) = worker_last_activity.get(&name) {
            if act_ts > 0.0 {
                candidates_ts.push(act_ts);
            }
        }
        if board_ts > 0.0 {
            candidates_ts.push(board_ts);
        }
        if coord_ts > 0.0 {
            candidates_ts.push(coord_ts);
        }
        for k in ["last_activity_ts", "assigned_ts", "updated_at", "started_at"] {
            let val = parse_ts_value(meta.get(k));
            if val > 0.0 {
                candidates_ts.push(val);
            }
        }
        let cid = val_to_str(meta.get("conversation_id")).trim().to_string();
        if !cid.is_empty() {
            if let Some(br) = brain_root {
                let tp = rio::member_transcript_path(br, &cid);
                if tp.exists() {
                    if let Some(mtime) = file_mtime_sec(&tp) {
                        candidates_ts.push(mtime);
                    }
                }
            }
        }
        let safe_name = rio::safe_key(&name, &name).to_lowercase();
        let low_name = name.to_lowercase();
        for af in &artifact_files {
            if let Some(fname) = af.file_name().and_then(|s| s.to_str()) {
                let low_af = fname.to_lowercase();
                if low_af.contains(&low_name) || low_af.contains(&safe_name) {
                    if let Some(mtime) = file_mtime_sec(af) {
                        candidates_ts.push(mtime);
                    }
                }
            }
        }
        let Some(last_act) = candidates_ts.into_iter().reduce(f64::max) else {
            continue;
        };
        let idle_sec = (now - last_act).max(0.0);
        if idle_sec >= threshold {
            stalled.push(json!({
                "worker": name,
                "idle_sec": (idle_sec * 10.0).round() / 10.0,
                "timeout_sec": (threshold * 10.0).round() / 10.0,
                "last_activity_ts": last_act,
                "cid": cid,
            }));
        }
    }
    stalled
}

fn gate_subdir(parts: &[&str]) -> PathBuf {
    let mut target = rio::state_dir().join("gate");
    for part in parts {
        target.push(part);
    }
    let _ = fs::create_dir_all(&target);
    target
}

pub fn gate_dir() -> PathBuf {
    gate_subdir(&[])
}

pub fn marker_path(session: &str) -> PathBuf {
    gate_subdir(&["markers"]).join(format!("{}.json", session))
}

pub fn marker_lock_path(session: &str) -> PathBuf {
    gate_subdir(&["markers"]).join(format!("{}.lock", rio::safe_key(session, "default")))
}

pub fn marker_pending_dir(session: &str) -> PathBuf {
    gate_subdir(&["markers"]).join(format!("{}.pending.d", rio::safe_key(session, "default")))
}

const MAX_PENDING_DELTA_FILES: usize = 512;
static PENDING_DELTA_SEQ: AtomicU64 = AtomicU64::new(1);

pub fn last_mark_fp(marker: &Value) -> Option<&str> {
    marker
        .get("content_marks")
        .and_then(|v| v.as_array())
        .and_then(|a| a.last())
        .and_then(|o| o.get("fp"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
}

fn pending_delta_stem(ent: &fs::DirEntry) -> Option<String> {
    if !ent.file_type().map_or(false, |ft| ft.is_file()) {
        return None;
    }
    let fname = ent.file_name();
    let stem = fname.to_str()?.strip_suffix(".json")?;
    if stem.is_empty() || stem.starts_with('.') {
        return None;
    }
    Some(stem.to_string())
}

fn list_pending_delta_files(session: &str) -> Vec<(String, PathBuf)> {
    if session.trim().is_empty() {
        return Vec::new();
    }
    let dir = marker_pending_dir(session);
    let Ok(rd) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    for ent in rd.flatten() {
        let Some(stem) = pending_delta_stem(&ent) else {
            continue;
        };
        files.push((stem, ent.path()));
        if files.len() >= MAX_PENDING_DELTA_FILES * 4 {
            break;
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    if files.len() > MAX_PENDING_DELTA_FILES {
        files.truncate(MAX_PENDING_DELTA_FILES);
    }
    files
}

pub fn has_pending_marker_deltas(session: &str) -> bool {
    if session.trim().is_empty() {
        return false;
    }
    let Ok(rd) = fs::read_dir(marker_pending_dir(session)) else {
        return false;
    };
    rd.flatten().any(|ent| pending_delta_stem(&ent).is_some())
}

pub fn pending_marker_mtime_ns(session: &str) -> u128 {
    if session.trim().is_empty() {
        return 0;
    }
    let Ok(rd) = fs::read_dir(marker_pending_dir(session)) else {
        return 0;
    };
    let mut best = 0u128;
    for ent in rd.flatten() {
        if pending_delta_stem(&ent).is_some() {
            if let Ok(meta) = ent.metadata() {
                best = best.max(rio::meta_mtime_ns(&meta));
            }
        }
    }
    best
}

pub struct PendingMarkerDelta<'a> {
    pub session: &'a str,
    pub ts: f64,
    pub cwd: &'a str,
    pub git_root: &'a str,
    pub durable_new_paths: &'a [String],
    pub operational_mutation: bool,
    pub changed_lines_delta: i64,
    pub shell_durable_edit: bool,
    pub unknown_barrier: bool,
    pub cause_label: &'a str,
    pub measured_fp: Option<&'a str>,
    pub measured_paths: &'a [String],
}

pub fn append_pending_marker_delta(delta: PendingMarkerDelta<'_>) -> Option<String> {
    let PendingMarkerDelta {
        session,
        ts,
        cwd,
        git_root,
        durable_new_paths,
        operational_mutation,
        changed_lines_delta,
        shell_durable_edit,
        unknown_barrier,
        cause_label,
        measured_fp,
        measured_paths,
    } = delta;
    // SAFETY: Write each lock-contended delta via `rio::write_json` (atomic `.tmp` + rename) under `<session>.pending.d/` so concurrent appends and per-ID acknowledgments never contend on or overwrite a shared file.
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = PENDING_DELTA_SEQ.fetch_add(1, Ordering::Relaxed);
    let delta_id = format!("pd-{:020}-{}-{:08}", ns, std::process::id(), seq);
    let cause_trunc: String = cause_label.chars().take(120).collect();
    let norm_mpaths = durable_paths(measured_paths);
    let mfp_val = match measured_fp.filter(|s| !s.is_empty() && !unknown_barrier) {
        Some(fp) => Value::String(fp.to_string()),
        None => Value::Null,
    };
    let entry = json!({
        "id": delta_id,
        "ts": ts,
        "cwd": if cwd.is_empty() { String::new() } else { rio::normalize_path(cwd) },
        "git_root": if git_root.is_empty() { String::new() } else { rio::normalize_path(git_root) },
        "durable_new_paths": durable_new_paths,
        "operational_mutation": operational_mutation,
        "changed_lines_delta": changed_lines_delta,
        "shell_durable_edit": shell_durable_edit,
        "unknown_barrier": unknown_barrier,
        "cause_label": cause_trunc,
        "measured_fp": mfp_val,
        "measured_paths": norm_mpaths,
    });
    let dst_path = marker_pending_dir(session).join(format!("{}.json", delta_id));
    if let Err(e) = rio::write_json(&dst_path, &entry) {
        rio::log_hook_event(
            "hook-errors",
            "pending_delta_write_failed",
            json!({ "session": session, "error": e }),
        );
        return None;
    }
    Some(delta_id)
}

pub fn has_unconsumed_pending_deltas(session: &str, consumed_ids: &[String]) -> bool {
    if session.trim().is_empty() {
        return false;
    }
    let Ok(rd) = fs::read_dir(marker_pending_dir(session)) else {
        return false;
    };
    let consumed_set: HashSet<&str> = consumed_ids.iter().map(|s| s.as_str()).collect();
    rd.flatten()
        .filter_map(|ent| pending_delta_stem(&ent))
        .any(|rid| !consumed_set.contains(rid.as_str()))
}

pub fn ack_pending_marker_deltas(session: &str, consumed_ids: &[String]) {
    if session.trim().is_empty() || consumed_ids.is_empty() {
        return;
    }
    // SAFETY: Unlink only acknowledged `<id>.json` files and keep `<session>.pending.d/` persistent so concurrent `PostToolUse` opens never fail with `NotFound` from a racing `remove_dir`.
    let dir = marker_pending_dir(session);
    for cid in consumed_ids {
        let safe_cid = rio::safe_key(cid, "");
        if !safe_cid.is_empty() && safe_cid == *cid {
            let _ = fs::remove_file(dir.join(format!("{}.json", safe_cid)));
        }
    }
}

pub fn read_marker_with_pending(session: &str) -> Option<Value> {
    if session.trim().is_empty() {
        return None;
    }
    let skey = rio::safe_key(session, "default");
    let base = rio::read_json(&marker_path(&skey))
        .or_else(|| (skey != session).then(|| rio::read_json(&marker_path(session))).flatten());
    apply_pending_marker_deltas(&skey, base.as_ref()).0
}

pub fn apply_pending_marker_deltas(
    session: &str,
    marker: Option<&Value>,
) -> (Option<Value>, Vec<String>) {
    let delta_files = list_pending_delta_files(session);
    if delta_files.is_empty() {
        return (marker.cloned(), Vec::new());
    }
    let mut rows: Vec<(String, Value)> = Vec::with_capacity(delta_files.len());
    for (stem_id, fpath) in delta_files {
        match rio::read_json(&fpath) {
            Some(val) if val.is_object() => rows.push((stem_id, val)),
            _ => {
                // SAFETY: Fail closed on unreadable/corrupt delta files by synthesizing an unmeasured barrier without marking `stem_id` consumed.
                rows.push((
                    String::new(),
                    json!({
                        "ts": now_sec(),
                        "operational_mutation": true,
                        "unknown_barrier": true,
                        "cause_label": "corrupt_pending_delta",
                    }),
                ));
            }
        }
    }
    if rows.is_empty() {
        return (marker.cloned(), Vec::new());
    }

    let existing_applied: HashSet<String> = marker
        .filter(|v| v.is_object() && !json_truthy(v.get("closed")))
        .and_then(|v| v.get("applied_pending_ids"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().filter(|s| !s.is_empty()).map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let mut consumed_ids: Vec<String> = Vec::new();
    let mut unapplied_rows: Vec<(String, &Map<String, Value>)> = Vec::new();
    for (stem_id, row) in &rows {
        let Some(robj) = row.as_object() else {
            continue;
        };
        if !stem_id.is_empty() {
            consumed_ids.push(stem_id.clone());
            if !existing_applied.contains(stem_id) {
                unapplied_rows.push((stem_id.clone(), robj));
            }
        } else {
            unapplied_rows.push((String::new(), robj));
        }
    }

    if unapplied_rows.is_empty() {
        return (marker.cloned(), consumed_ids);
    }

    let mut out = match marker {
        Some(v) if v.is_object() && !json_truthy(v.get("closed")) => v.clone(),
        _ => {
            let (_, first_robj) = unapplied_rows[0];
            let first_row_ts = first_robj
                .get("ts")
                .and_then(|v| v.as_f64())
                .unwrap_or_else(now_sec);
            let row_cwd = first_robj
                .get("cwd")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let row_gr = first_robj
                .get("git_root")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            json!({
                "session": session,
                "first_ts": first_row_ts,
                "last_ts": first_row_ts,
                "last_durable_ts": 0.0,
                "cwd": row_cwd,
                "git_root": row_gr,
                "paths": [],
                "operational": false,
                "changed_lines": 0,
                "edits": 0,
                "shell_durable_edit": false,
                "content_marks": [],
                "applied_pending_ids": [],
                "closed": false,
            })
        }
    };

    let mut marks = out
        .get("content_marks")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut applied_list: Vec<String> = out
        .get("applied_pending_ids")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().filter(|s| !s.is_empty()).map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    for (rid, robj) in unapplied_rows {
        if !rid.is_empty() {
            applied_list.push(rid);
        }
        let rts = robj.get("ts").and_then(|v| v.as_f64()).unwrap_or_else(now_sec);
        let new_p: Vec<String> = robj
            .get("durable_new_paths")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().filter(|s| !s.is_empty()).map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let cause = robj
            .get("cause_label")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .chars()
            .take(120)
            .collect::<String>();
        let row_unknown = json_truthy(robj.get("unknown_barrier"));
        let row_mfp = robj
            .get("measured_fp")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        let row_mpaths = durable_paths_from_val(robj.get("measured_paths"));

        if let Some(m) = out.as_object_mut() {
            let prev_last = m.get("last_ts").and_then(|v| v.as_f64()).unwrap_or(0.0);
            m.insert("last_ts".to_string(), json!(prev_last.max(rts)));
            if m.get("cwd").and_then(|v| v.as_str()).unwrap_or("").is_empty() {
                if let Some(rcwd) = robj.get("cwd").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                    m.insert("cwd".to_string(), Value::String(rcwd.to_string()));
                }
            }
            if m.get("git_root").and_then(|v| v.as_str()).unwrap_or("").is_empty() {
                if let Some(rgr) = robj.get("git_root").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                    m.insert("git_root".to_string(), Value::String(rgr.to_string()));
                }
            }
        }

        if !new_p.is_empty() {
            let mut combined = durable_paths_from_val(out.get("paths"));
            combined.extend(new_p);
            let merged = durable_paths(&combined);
            // INVARIANT: Never recompute live-disk SHA-256 under an earlier edit timestamp `rts`; only accept `measured_fp` captured at `rts` when `measured_paths == merged`, else mark `unknown: true` until caught up at `now_sec()`.
            let exact_fp = if !row_unknown && row_mpaths == merged {
                row_mfp
            } else {
                None
            };
            let mut m_entry = Map::new();
            m_entry.insert("ts".to_string(), json!(rts));
            match exact_fp {
                Some(fp) => {
                    m_entry.insert("fp".to_string(), Value::String(fp.to_string()));
                }
                None => {
                    m_entry.insert("fp".to_string(), Value::Null);
                    m_entry.insert("unknown".to_string(), Value::Bool(true));
                }
            }
            m_entry.insert("cause".to_string(), Value::String(cause));
            marks.push(Value::Object(m_entry));
            if let Some(m) = out.as_object_mut() {
                m.insert(
                    "paths".to_string(),
                    Value::Array(merged.into_iter().map(Value::String).collect()),
                );
                let prev_dur = m.get("last_durable_ts").and_then(|v| v.as_f64()).unwrap_or(0.0);
                m.insert("last_durable_ts".to_string(), json!(prev_dur.max(rts)));
                let edits = m.get("edits").and_then(|v| v.as_i64()).unwrap_or(0) + 1;
                let cl_delta = robj
                    .get("changed_lines_delta")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0)
                    .max(1);
                let cl = m.get("changed_lines").and_then(|v| v.as_i64()).unwrap_or(0) + cl_delta;
                m.insert("edits".to_string(), json!(edits));
                m.insert("changed_lines".to_string(), json!(cl));
                if json_truthy(robj.get("shell_durable_edit")) {
                    m.insert("shell_durable_edit".to_string(), Value::Bool(true));
                }
            }
        } else if json_truthy(robj.get("operational_mutation")) {
            if let Some(m) = out.as_object_mut() {
                m.insert("operational".to_string(), Value::Bool(true));
            }
            let dpaths = durable_paths_from_val(out.get("paths"));
            if !dpaths.is_empty() {
                let exact_fp = if !row_unknown && row_mpaths == dpaths {
                    row_mfp
                } else {
                    None
                };
                let mut m_entry = Map::new();
                m_entry.insert("ts".to_string(), json!(rts));
                match exact_fp {
                    Some(fp) => {
                        m_entry.insert("fp".to_string(), Value::String(fp.to_string()));
                    }
                    None => {
                        m_entry.insert("fp".to_string(), Value::Null);
                        m_entry.insert("unknown".to_string(), Value::Bool(true));
                    }
                }
                m_entry.insert("cause".to_string(), Value::String(cause));
                marks.push(Value::Object(m_entry));
            }
        }
    }

    if applied_list.len() > 128 {
        let drop_n = applied_list.len() - 128;
        applied_list.drain(0..drop_n);
    }
    if let Some(m) = out.as_object_mut() {
        m.insert(
            "applied_pending_ids".to_string(),
            Value::Array(applied_list.into_iter().map(Value::String).collect()),
        );
    }

    trim_content_marks(&mut out, marks);
    (Some(out), consumed_ids)
}

pub fn enforcement_state_path(session: &str) -> PathBuf {
    gate_subdir(&["states"]).join(format!("{}.json", session))
}

pub fn checks_ledger_path(session: &str) -> PathBuf {
    gate_subdir(&["checks"]).join(format!("{}.jsonl", session))
}

pub fn pending_notes_path(session: &str) -> PathBuf {
    gate_subdir(&["notes"]).join(format!("{}.json", session))
}

pub fn snapshot_path(session: &str, call_id: &str) -> PathBuf {
    gate_subdir(&["snapshots"]).join(format!("{}-{}.json", session, rio::safe_key(call_id, "call")))
}

pub fn claim_path(session: &str) -> PathBuf {
    gate_subdir(&["claims"]).join(format!("{}.json", session))
}

pub fn swarm_rounds_path(session: &str) -> PathBuf {
    gate_subdir(&["swarm_rounds"]).join(format!("{}.json", session))
}

pub fn is_session_scratch_path(path: &str, artifact_dir: &str, workspace_paths: &[String]) -> bool {
    let norm = rio::normalize_path(path);
    if norm.is_empty() || chip_trees_re().is_match(&norm) || system_generated_re().is_match(&norm) {
        return false;
    }
    let folded = rio::fold_path(&norm);
    let mut scratch_root = String::new();
    if !artifact_dir.trim().is_empty() {
        let art = rio::fold_path(artifact_dir);
        if !art.is_empty() && (folded == art || folded.starts_with(&format!("{}/", art))) {
            scratch_root = art;
        }
    }
    if scratch_root.is_empty() {
        for pat in user_scratch_patterns() {
            if let Some(m) = pat.find(&norm) {
                scratch_root = rio::fold_path(norm[..m.end()].trim_end_matches('/'));
                break;
            }
        }
    }
    if scratch_root.is_empty() {
        return false;
    }
    // INVARIANT: Exclude only when an explicit workspace was opened INSIDE the scratch directory itself.
    let scratch_prefix = format!("{}/", scratch_root);
    for wp in workspace_paths {
        if !wp.trim().is_empty() {
            let fwp = rio::fold_path(wp);
            if !fwp.is_empty()
                && fwp.starts_with(&scratch_prefix)
                && (folded == fwp || folded.starts_with(&format!("{}/", fwp)))
            {
                return false;
            }
        }
    }
    true
}

pub fn is_scratch_or_ephemeral(
    path: &str,
    artifact_dir: &str,
    workspace_paths: &[String],
    cwd: &str,
) -> bool {
    let norm = rio::normalize_path(path);
    if norm.is_empty() {
        return true;
    }
    if chip_trees_re().is_match(&norm) {
        return false;
    }
    if is_session_scratch_path(&norm, artifact_dir, workspace_paths) {
        return true;
    }
    let folded = rio::fold_path(&norm);
    let state_root = rio::fold_path(&rio::stack_home().join("state").to_string_lossy());
    if !state_root.is_empty()
        && (folded == state_root || folded.starts_with(&format!("{}/", state_root)))
    {
        return true;
    }
    for pat in always_ephemeral_patterns() {
        if pat.is_match(&norm) {
            return true;
        }
    }
    let mut roots: Vec<String> = workspace_paths
        .iter()
        .filter(|wp| !wp.trim().is_empty())
        .map(|wp| rio::fold_path(wp))
        .collect();
    if !cwd.trim().is_empty() {
        roots.push(rio::fold_path(cwd));
    }
    for r in roots {
        if !r.is_empty() && (folded == r || folded.starts_with(&format!("{}/", r))) {
            return false;
        }
    }
    for pat in os_temp_patterns() {
        if pat.is_match(&norm) {
            return true;
        }
    }
    false
}

pub fn is_ephemeral_path(path: &str) -> bool {
    is_scratch_or_ephemeral(path, "", &[], "")
}

pub fn default_gate_policy() -> Value {
    json!({
        "default_code_risk": "STANDARD",
        "low_risk_globs": [],
        "high_risk_globs": [],
        "xhigh_risk_globs": [],
        "require_simplify_on_standard": false,
        "require_review_on_standard": false,
        "require_tests_on_standard": null,
    })
}

fn risk_rank(risk: &str) -> usize {
    match risk.to_uppercase().as_str() {
        "LOW" => 0,
        "STANDARD" => 1,
        "HIGH" => 2,
        "XHIGH" => 3,
        _ => 0,
    }
}

pub fn is_valid_risk(risk: &str) -> bool {
    matches!(
        risk.to_uppercase().as_str(),
        "LOW" | "STANDARD" | "HIGH" | "XHIGH"
    )
}

fn resolve_against_cwd(path: &str, cwd: &str) -> String {
    let p = Path::new(path);
    if !cwd.trim().is_empty() && !p.is_absolute() {
        Path::new(cwd).join(p).to_string_lossy().into_owned()
    } else {
        path.to_string()
    }
}

fn find_gate_policy_root(
    hints: &[String],
    dir_cache: &mut HashMap<String, Option<Map<String, Value>>>,
) -> (Option<PathBuf>, Map<String, Value>) {
    let mut seen_dirs = HashSet::new();
    let mut probe_dirs = Vec::new();
    for raw in hints {
        if raw.trim().is_empty() {
            continue;
        }
        let p = PathBuf::from(raw);
        let mut cur = if p.is_dir() {
            p
        } else {
            p.parent().map(Path::to_path_buf).unwrap_or(p)
        };
        for _ in 0..GATE_POLICY_WALK_DEPTH {
            let key = rio::fold_path(&cur.to_string_lossy());
            if !seen_dirs.insert(key) {
                break;
            }
            probe_dirs.push(cur.clone());
            let Some(parent) = cur.parent() else {
                break;
            };
            if parent == cur {
                break;
            }
            cur = parent.to_path_buf();
        }
    }

    for d in probe_dirs {
        let dkey = rio::fold_path(&d.to_string_lossy());
        if let Some(cached) = dir_cache.get(&dkey) {
            if let Some(cfg_map) = cached {
                return (Some(d), cfg_map.clone());
            }
            continue;
        }
        let cfg = d.join(".agents").join("carbon-gate.json");
        let mut raw_cfg: Option<Map<String, Value>> = None;
        if cfg.is_file() {
            if let Some(Value::Object(parsed)) = rio::read_json(&cfg) {
                raw_cfg = Some(parsed);
            }
        }
        dir_cache.insert(dkey, raw_cfg.clone());
        if let Some(cfg_map) = raw_cfg {
            return (Some(d), cfg_map);
        }
    }
    (None, Map::new())
}

fn parse_gate_policy(root: Option<&Path>, raw: &Map<String, Value>) -> Value {
    let mut policy = match default_gate_policy() {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    let policy_root = root
        .map(|r| rio::normalize_path(&r.to_string_lossy()))
        .unwrap_or_default();
    policy.insert("policy_root".to_string(), Value::String(policy_root));
    if raw.is_empty() {
        return Value::Object(policy);
    }
    let default_risk = val_to_str(raw.get("default_code_risk")).to_uppercase();
    if is_valid_risk(&default_risk) {
        policy.insert("default_code_risk".to_string(), Value::String(default_risk));
    }
    for key in ["low_risk_globs", "high_risk_globs", "xhigh_risk_globs"] {
        if let Some(Value::Array(arr)) = raw.get(key) {
            let cleaned: Vec<Value> = arr
                .iter()
                .map(|v| val_to_str(Some(v)).trim().to_string())
                .filter(|s| !s.is_empty())
                .map(Value::String)
                .collect();
            policy.insert(key.to_string(), Value::Array(cleaned));
        }
    }
    for key in ["require_simplify_on_standard", "require_review_on_standard"] {
        if raw.contains_key(key) {
            policy.insert(key.to_string(), Value::Bool(json_truthy(raw.get(key))));
        }
    }
    if let Some(val) = raw.get("require_tests_on_standard") {
        if !val.is_null() {
            policy.insert(
                "require_tests_on_standard".to_string(),
                Value::Bool(json_truthy(Some(val))),
            );
        }
    }
    Value::Object(policy)
}

fn is_under_root(norm_path: &str, root: &str) -> (bool, String) {
    let rn = rio::normalize_path(root).trim_end_matches('/').to_lowercase();
    let low = norm_path.to_lowercase();
    if rn.is_empty() {
        return (
            norm_path.starts_with('/'),
            norm_path.trim_start_matches('/').to_string(),
        );
    }
    let prefix = format!("{}/", rn);
    if low.starts_with(&prefix) {
        return (true, low[prefix.len()..].to_string());
    }
    if low == rn {
        return (true, String::new());
    }
    (false, low)
}

fn load_project_gate_policy_cached(
    hints: &[String],
    cwd: &str,
    dir_cache: &mut HashMap<String, Option<Map<String, Value>>>,
) -> Value {
    let explicit_hints: Vec<String> = hints
        .iter()
        .filter(|h| !h.trim().is_empty())
        .cloned()
        .collect();
    if explicit_hints.is_empty() {
        let cwd_hints = if cwd.trim().is_empty() {
            Vec::new()
        } else {
            vec![cwd.to_string()]
        };
        let (root, raw) = find_gate_policy_root(&cwd_hints, dir_cache);
        return parse_gate_policy(root.as_deref(), &raw);
    }
    let resolved_hints: Vec<String> = explicit_hints
        .iter()
        .map(|h| resolve_against_cwd(h, cwd))
        .collect();
    if resolved_hints.len() == 1 {
        let h0 = &resolved_hints[0];
        let (root, raw) = find_gate_policy_root(&[h0.clone()], dir_cache);
        if root.is_some() {
            return parse_gate_policy(root.as_deref(), &raw);
        }
        if !cwd.trim().is_empty() {
            let (c_root, c_raw) = find_gate_policy_root(&[cwd.to_string()], dir_cache);
            if let Some(cr) = c_root {
                let cr_norm = rio::normalize_path(&cr.to_string_lossy());
                if is_under_root(&rio::normalize_path(h0), &cr_norm).0 {
                    return parse_gate_policy(Some(&cr), &c_raw);
                }
            }
        }
        return parse_gate_policy(None, &Map::new());
    }
    // INVARIANT: For multi-file hints, resolve nearest policy per parent directory so nested or cross-repo policies stay monotonic.
    let mut parent_pols: HashMap<String, Value> = HashMap::new();
    let mut first_pol: Option<Value> = None;
    for h in resolved_hints {
        let hp = PathBuf::from(&h);
        let dir = if hp.is_dir() {
            hp
        } else {
            hp.parent().map(Path::to_path_buf).unwrap_or(hp)
        };
        let pkey = rio::fold_path(&dir.to_string_lossy());
        if !parent_pols.contains_key(&pkey) {
            let pol = load_project_gate_policy_cached(&[h], cwd, dir_cache);
            if first_pol.is_none() {
                first_pol = Some(pol.clone());
            }
            parent_pols.insert(pkey, pol);
        }
    }
    let distinct_roots: HashSet<String> = parent_pols
        .values()
        .map(|p| val_to_str(p.get("policy_root")))
        .collect();
    if distinct_roots.len() == 1 {
        if let Some(pol) = first_pol {
            return pol;
        }
    }
    let mut base = parse_gate_policy(None, &Map::new());
    if let Value::Object(ref mut map) = base {
        map.insert("_multi_root".to_string(), Value::Bool(true));
    }
    base
}

pub fn load_project_gate_policy(hints: &[String], cwd: &str) -> Value {
    let mut cache = HashMap::new();
    load_project_gate_policy_cached(hints, cwd, &mut cache)
}

fn glob_to_regex(pattern: &str) -> Option<Regex> {
    static CACHE: OnceLock<std::sync::Mutex<HashMap<String, Option<Regex>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    if let Ok(guard) = cache.lock() {
        if let Some(cached) = guard.get(pattern) {
            return cached.clone();
        }
    }
    let mut out = String::from(r"\A");
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        if i + 2 < chars.len() && chars[i] == '*' && chars[i + 1] == '*' && chars[i + 2] == '/' {
            out.push_str("(?:.+/)?");
            i += 3;
        } else if i + 1 < chars.len() && chars[i] == '*' && chars[i + 1] == '*' {
            out.push_str(".*");
            i += 2;
        } else if chars[i] == '*' {
            out.push_str("[^/]*");
            i += 1;
        } else if chars[i] == '?' {
            out.push_str("[^/]");
            i += 1;
        } else {
            out.push_str(&regex::escape(&chars[i].to_string()));
            i += 1;
        }
    }
    out.push_str(r"\z");
    let compiled = Regex::new(&out).ok();
    if let Ok(mut guard) = cache.lock() {
        if guard.len() >= 256 {
            guard.clear();
        }
        guard.insert(pattern.to_string(), compiled.clone());
    }
    compiled
}

fn posix_full_match(path_str: &str, pattern: &str) -> bool {
    glob_to_regex(pattern).map_or(false, |re| re.is_match(path_str))
}

fn match_glob_patterns(path: &str, patterns: &[String], root: &str) -> bool {
    if patterns.is_empty() {
        return false;
    }
    let norm = rio::normalize_path(path).to_lowercase();
    let rel = if !root.is_empty() {
        let (inside, r) = is_under_root(&norm, root);
        if !inside || r.is_empty() {
            return false;
        }
        r
    } else {
        norm.clone()
    };
    let base = rel.rsplit('/').next().unwrap_or("");
    for raw_pat in patterns {
        let mut pat = raw_pat.trim().replace('\\', "/").to_lowercase();
        while let Some(rest) = pat.strip_prefix("./") {
            pat = rest.to_string();
        }
        pat = pat.trim_start_matches('/').to_string();
        if pat.is_empty() {
            continue;
        }
        if !pat.contains('/') && fnmatch_ci(base, &pat) {
            return true;
        }
        if !root.is_empty() {
            if posix_full_match(&rel, &pat) {
                return true;
            }
        } else if posix_full_match(&norm, &pat) || posix_full_match(&norm, &format!("**/{}", pat)) {
            return true;
        }
    }
    false
}

fn policy_globs(pol: &Value, key: &str) -> Vec<String> {
    pol.get(key)
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(|x| val_to_str(Some(x))).collect())
        .unwrap_or_default()
}

pub fn classify_path_risk(path: &str, policy: Option<&Value>) -> String {
    if path == SHELL_MUTATION_SENTINEL {
        return RISK_LOW.to_string();
    }
    let default_pol = default_gate_policy();
    let mut pol_owned: Option<Value> = None;
    let initial_pol = policy.unwrap_or(&default_pol);
    let mut pol_root = val_to_str(initial_pol.get("policy_root"));
    let norm = rio::normalize_path(path);
    let is_multi_root = json_truthy(initial_pol.get("_multi_root"));
    if policy.is_none()
        || is_multi_root
        || (!pol_root.is_empty() && !is_under_root(&norm, &pol_root).0)
    {
        // INVARIANT: Never apply repoA's `.agents/carbon-gate.json` globs or defaults to a path outside repoA.
        let loaded = load_project_gate_policy(&[path.to_string()], "");
        pol_root = val_to_str(loaded.get("policy_root"));
        pol_owned = Some(loaded);
    }
    let pol = pol_owned.as_ref().unwrap_or(initial_pol);

    if match_glob_patterns(&norm, &policy_globs(pol, "xhigh_risk_globs"), &pol_root) {
        return RISK_XHIGH.to_string();
    }
    for pat in high_risk_patterns() {
        if pat.is_match(&norm) {
            return RISK_HIGH.to_string();
        }
    }
    if match_glob_patterns(&norm, &policy_globs(pol, "high_risk_globs"), &pol_root) {
        return RISK_HIGH.to_string();
    }
    let base = norm.rsplit('/').next().unwrap_or("").to_lowercase();
    let ext = base
        .rfind('.')
        .map(|idx| &base[idx..])
        .unwrap_or("");
    if DOC_EXTENSIONS.contains(&ext)
        && !base.starts_with("agents.")
        && !base.starts_with("gemini.")
        && !base.starts_with("claude.")
    {
        return RISK_LOW.to_string();
    }
    if match_glob_patterns(&norm, &policy_globs(pol, "low_risk_globs"), &pol_root) {
        return RISK_LOW.to_string();
    }
    let default_code = val_to_str(pol.get("default_code_risk")).to_uppercase();
    if is_valid_risk(&default_code) {
        default_code
    } else {
        RISK_STANDARD.to_string()
    }
}

fn is_fast_test_code_path(path: &str) -> bool {
    let norm = rio::normalize_path(path).to_lowercase();
    let base = norm.rsplit('/').next().unwrap_or("");
    norm.ends_with(".py")
        || base.starts_with("test_")
        || base.contains("_test.")
        || base.contains(".test.")
        || base.contains(".spec.")
}

fn workspace_has_test_harness_opt(
    cwd: &str,
    paths: &[String],
    git_root_opt: Option<&str>,
) -> bool {
    let dpaths = durable_paths(paths);
    if dpaths.iter().any(|p| is_fast_test_code_path(p)) {
        return true;
    }

    let mut roots: Vec<PathBuf> = Vec::new();
    if !cwd.trim().is_empty() {
        let top = match git_root_opt {
            None => rio::git_toplevel(cwd, false),
            Some(gr) => {
                if gr.trim().is_empty() {
                    None
                } else {
                    Some(gr.to_string())
                }
            }
        };
        if let Some(t) = top {
            roots.push(PathBuf::from(t));
        }
        roots.push(PathBuf::from(cwd));
    }

    let mut non_doc = Vec::new();
    let mut non_doc_set = HashSet::new();
    let mut doc_rest = Vec::new();
    for p in &dpaths {
        let norm = rio::normalize_path(p);
        let base = norm.rsplit('/').next().unwrap_or("");
        let ext = base
            .rfind('.')
            .map(|i| base[i..].to_lowercase())
            .unwrap_or_default();
        if !DOC_EXTENSIONS.contains(&ext.as_str()) {
            non_doc_set.insert(p.clone());
            non_doc.push(p.clone());
        }
    }
    for p in &dpaths {
        if !non_doc_set.contains(p) {
            doc_rest.push(p.clone());
        }
    }
    non_doc.extend(doc_rest);
    for p in non_doc.into_iter().take(TEST_HARNESS_SAMPLE_PATHS) {
        let pp = PathBuf::from(&p);
        let mut cur = if pp.is_dir() {
            pp
        } else {
            pp.parent().map(Path::to_path_buf).unwrap_or(pp)
        };
        for _ in 0..TEST_HARNESS_WALK_DEPTH {
            roots.push(cur.clone());
            let Some(parent) = cur.parent() else {
                break;
            };
            if parent == cur {
                break;
            }
            cur = parent.to_path_buf();
        }
    }

    let mut seen = HashSet::new();
    let test_dirs = ["tests", "test", "__tests__", "spec"];
    let harness_files = [
        "pytest.ini",
        "conftest.py",
        "tox.ini",
        "pyproject.toml",
        "Cargo.toml",
        "go.mod",
        "tsconfig.json",
    ];
    for root in roots {
        if !root.is_dir() {
            continue;
        }
        let rk = rio::fold_path(&root.to_string_lossy());
        if !seen.insert(rk) {
            continue;
        }
        if let Ok(entries) = fs::read_dir(&root) {
            for entry in entries.flatten() {
                let fname = entry.file_name();
                let name = fname.to_string_lossy();
                let ft = match entry.file_type() {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                if (ft.is_dir() || entry.path().is_dir()) && test_dirs.contains(&name.as_ref()) {
                    return true;
                }
                if name == "rust" && entry.path().join("Cargo.toml").is_file() {
                    return true;
                }
                if (ft.is_file() || entry.path().is_file()) && harness_files.contains(&name.as_ref())
                {
                    return true;
                }
                if name == "package.json" && (ft.is_file() || entry.path().is_file()) {
                    if let Some(Value::Object(pkg)) = rio::read_json(&entry.path()) {
                        if let Some(Value::Object(scripts)) = pkg.get("scripts") {
                            let test_cmd = val_to_str(scripts.get("test")).trim().to_lowercase();
                            if !test_cmd.is_empty() && !test_cmd.contains("no test specified") {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

pub fn max_risk(levels: &[String]) -> String {
    let mut best = RISK_LOW.to_string();
    for lv in levels {
        let up = if lv.trim().is_empty() {
            RISK_LOW.to_string()
        } else {
            lv.to_uppercase()
        };
        if risk_rank(&up) > risk_rank(&best) {
            best = up;
        }
    }
    best
}

pub fn durable_paths(paths: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for p in paths {
        if p.is_empty() || p == SHELL_MUTATION_SENTINEL {
            continue;
        }
        let key = rio::fold_path(p);
        if seen.insert(key) {
            out.push(rio::normalize_path(p));
        }
    }
    out
}

pub fn durable_paths_from_val(val: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(arr)) = val else {
        return Vec::new();
    };
    let raw: Vec<String> = arr
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    durable_paths(&raw)
}

pub fn candidate_class(marker: &Value) -> String {
    let Some(obj) = marker.as_object() else {
        return WORK_NO_CHANGE.to_string();
    };
    if json_truthy(obj.get("closed")) {
        return WORK_NO_CHANGE.to_string();
    }
    if !durable_paths_from_val(obj.get("paths")).is_empty() {
        return WORK_PERSISTENT.to_string();
    }
    if json_truthy(obj.get("operational")) {
        return WORK_OPERATIONAL.to_string();
    }
    WORK_NO_CHANGE.to_string()
}

pub fn sha256_file_bounded(path: &Path, max_bytes: u64) -> Result<Option<(u64, String)>, std::io::Error> {
    let mut fh = File::open(path)?;
    let meta = fh.metadata()?;
    if meta.len() > max_bytes {
        return Ok(None);
    }
    // INVARIANT: Stream in 64 KiB stack chunks and re-enforce `max_bytes` on actual bytes read so concurrent growth cannot spike heap or bypass size bounds.
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut total: u64 = 0;
    loop {
        let n = fh.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if total > max_bytes {
            return Ok(None);
        }
        hasher.update(&buf[..n]);
    }
    Ok(Some((total, hex::encode(hasher.finalize()))))
}

pub fn content_fingerprint(paths: &[String], max_file_bytes: u64) -> String {
    // SAFETY: Require full-file SHA-256 within `max_file_bytes`; if any file exceeds the read budget or fails to hash, return `""` (`fp: null`) so `is_review_fresh` and `verified` closure fail closed instead of trusting partial samples.
    let mut dpaths = durable_paths(paths);
    dpaths.sort_by_key(|p| rio::fold_path(p));
    if dpaths.is_empty() {
        return "empty".to_string();
    }
    let mut hasher = Sha256::new();
    for p in dpaths {
        let key = rio::fold_path(&p);
        hasher.update(key.as_bytes());
        hasher.update(b"\0");
        let path_obj = Path::new(&p);
        if !path_obj.exists() {
            hasher.update(b"MISSING\0");
            continue;
        }
        if !path_obj.is_file() {
            hasher.update(b"NONFILE\0");
            continue;
        }
        let Ok(Some((total_len, blob_hex))) = sha256_file_bounded(path_obj, max_file_bytes) else {
            return String::new();
        };
        hasher.update(format!("BLOB:{}:{}\0", total_len, blob_hex).as_bytes());
    }
    hex::encode(hasher.finalize())
}

pub fn trim_content_marks(marker: &mut Value, marks: Vec<Value>) {
    let Some(obj) = marker.as_object_mut() else {
        return;
    };
    if marks.len() > MAX_CONTENT_MARKS {
        let evicted_idx = marks.len() - MAX_CONTENT_MARKS - 1;
        let ev_ts = marks
            .get(evicted_idx)
            .and_then(|v| v.as_object())
            .map(|m| val_to_f64(m.get("ts")))
            .unwrap_or(0.0);
        let prev_ev = val_to_f64(obj.get("marks_evicted_through_ts"));
        if ev_ts > prev_ev {
            obj.insert("marks_evicted_through_ts".to_string(), json!(ev_ts));
        }
        let kept = marks[marks.len() - MAX_CONTENT_MARKS..].to_vec();
        obj.insert("content_marks".to_string(), Value::Array(kept));
    } else {
        obj.insert("content_marks".to_string(), Value::Array(marks));
    }
}

pub fn parse_terminal_receipt(message: &str) -> Option<Value> {
    if message.trim().is_empty() {
        return None;
    }
    let non_empty: Vec<&str> = message
        .lines()
        .map(|ln| ln.trim())
        .filter(|ln| !ln.is_empty())
        .collect();
    if non_empty.is_empty() {
        return None;
    }
    let last_line = non_empty[non_empty.len() - 1];
    let Some(caps) = receipt_line_re().captures(last_line) else {
        for &earlier in &non_empty[..non_empty.len() - 1] {
            if receipt_line_re().is_match(earlier) {
                return Some(json!({
                    "kind": "misplaced",
                    "raw": earlier,
                }));
            }
        }
        return None;
    };
    let kind = caps["kind"].to_lowercase();
    let body = caps["body"].trim();
    let mut result = Map::new();
    result.insert("kind".to_string(), Value::String(kind.clone()));
    result.insert("body".to_string(), Value::String(body.to_string()));
    result.insert("raw".to_string(), Value::String(last_line.to_string()));
    result.insert("risk".to_string(), Value::Null);

    if kind == "verified" {
        let Some(vm) = verified_body_re().captures(body) else {
            return Some(json!({
                "kind": "malformed",
                "expected": "verified: <LOW|STANDARD|HIGH|XHIGH>; <candidate and checks>",
                "raw": last_line,
            }));
        };
        result.insert("risk".to_string(), Value::String(vm["risk"].to_uppercase()));
        result.insert(
            "summary".to_string(),
            Value::String(vm["summary"].trim().to_string()),
        );
    } else if kind == "operational" {
        let Some(om) = operational_body_re().captures(body) else {
            return Some(json!({
                "kind": "malformed",
                "expected": "operational: <pre-check>; <verified effect>",
                "raw": last_line,
            }));
        };
        result.insert(
            "precheck".to_string(),
            Value::String(om["precheck"].trim().to_string()),
        );
        result.insert(
            "effect".to_string(),
            Value::String(om["effect"].trim().to_string()),
        );
    } else if kind == "anomaly-reported" {
        let Some(am) = anomaly_body_re().captures(body) else {
            return Some(json!({
                "kind": "malformed",
                "expected": "anomaly-reported: <report-id>; <verified transcript fact>",
                "raw": last_line,
            }));
        };
        result.insert(
            "report_id".to_string(),
            Value::String(am["report_id"].to_string()),
        );
        result.insert(
            "fact".to_string(),
            Value::String(am["fact"].trim().to_string()),
        );
    }
    Some(Value::Object(result))
}

pub fn queue_pending_note(session: &str, note: &str) {
    if note.is_empty() {
        return;
    }
    let p = pending_notes_path(session);
    let mut notes: Vec<String> = match rio::read_json(&p) {
        Some(Value::Object(obj)) => obj
            .get("notes")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    if !notes.iter().any(|n| n == note) {
        notes.push(note.to_string());
    }
    let start = notes.len().saturating_sub(6);
    let trimmed: Vec<Value> = notes[start..].iter().cloned().map(Value::String).collect();
    let _ = rio::write_json(
        &p,
        &json!({
            "notes": trimmed,
            "updated_ts": now_sec(),
        }),
    );
}

pub fn pop_pending_notes(session: &str) -> Vec<String> {
    let p = pending_notes_path(session);
    let Some(Value::Object(data)) = rio::read_json(&p) else {
        return Vec::new();
    };
    let Some(Value::Array(raw_notes)) = data.get("notes") else {
        return Vec::new();
    };
    if raw_notes.is_empty() {
        return Vec::new();
    }
    if fs::remove_file(&p).is_err() {
        let _ = rio::write_json(&p, &json!({ "notes": [] }));
    }
    raw_notes
        .iter()
        .map(|v| val_to_str(Some(v)))
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn publish_claim(session: &str, paths: &[String], shell_active: bool, cwd: &str) {
    let now = now_sec();
    let p = claim_path(session);
    let mut cur = match rio::read_json(&p) {
        Some(Value::Object(map)) => map,
        _ => Map::new(),
    };
    let mut claimed: BTreeSet<String> = cur
        .get("paths")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    for item in paths {
        if !item.is_empty() && item != SHELL_MUTATION_SENTINEL {
            claimed.insert(rio::fold_path(item));
        }
    }
    let all_claimed: Vec<String> = claimed.into_iter().collect();
    let start = all_claimed.len().saturating_sub(200);
    let kept: Vec<Value> = all_claimed[start..]
        .iter()
        .cloned()
        .map(Value::String)
        .collect();
    cur.insert("session".to_string(), Value::String(session.to_string()));
    cur.insert("paths".to_string(), Value::Array(kept));
    cur.insert("shell_active".to_string(), Value::Bool(shell_active));
    cur.insert("cwd".to_string(), Value::String(rio::normalize_path(cwd)));
    cur.insert("updated_ts".to_string(), json!(now));
    let _ = rio::write_json(&p, &Value::Object(cur));
}

pub fn clear_claim(session: &str) {
    let _ = fs::remove_file(claim_path(session));
}

pub fn clear_swarm_rounds(session: &str) {
    let _ = fs::remove_file(swarm_rounds_path(session));
}

pub fn claimed_by_other_sessions(my_session: &str, paths: &[String], ttl: f64) -> Vec<Value> {
    let claims_dir = gate_subdir(&["claims"]);
    let now = now_sec();
    let mut others = BTreeSet::new();
    let wanted: HashSet<String> = paths.iter().map(|p| rio::fold_path(p)).collect();
    let Ok(entries) = fs::read_dir(&claims_dir) else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let ep = entry.path();
        if ep.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Some(Value::Object(data)) = rio::read_json(&ep) else {
            continue;
        };
        let updated_ts = val_to_f64(data.get("updated_ts"));
        if now - updated_ts > ttl {
            let _ = fs::remove_file(&ep);
            continue;
        }
        if data.get("session").and_then(|v| v.as_str()) == Some(my_session) {
            continue;
        }
        if let Some(Value::Array(cpaths)) = data.get("paths") {
            for cp_val in cpaths {
                if let Some(cp) = cp_val.as_str() {
                    if wanted.contains(cp) {
                        others.insert(cp.to_string());
                    }
                }
            }
        }
    }
    others.into_iter().map(Value::String).collect()
}

pub fn candidate_key(marker: &Value) -> String {
    let marks = marker.get("content_marks").and_then(|v| v.as_array());
    let latest_fp = match marks.and_then(|arr| arr.last()) {
        Some(Value::Object(last_m)) => match last_m.get("fp") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Null) | None => "None".to_string(),
            Some(other) => other.to_string(),
        },
        _ => "none".to_string(),
    };
    let mut folded_dpaths: Vec<String> = durable_paths_from_val(marker.get("paths"))
        .iter()
        .map(|p| rio::fold_path(p))
        .collect();
    folded_dpaths.sort();
    let dpaths = folded_dpaths.join(",");
    let first_ts = match marker.get("first_ts") {
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => "0".to_string(),
    };
    let op = if json_truthy(marker.get("operational")) {
        "True"
    } else {
        "False"
    };
    let raw = format!("{}|{}|{}|{}", first_ts, op, dpaths, latest_fp);
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let hex_str = hex::encode(hasher.finalize());
    hex_str[..20].to_string()
}

pub fn requires_simplify(risk: &str, policy: Option<&Value>) -> bool {
    let default_pol = default_gate_policy();
    let pol = policy.unwrap_or(&default_pol);
    let up = if risk.trim().is_empty() {
        "LOW".to_string()
    } else {
        risk.to_uppercase()
    };
    up == "HIGH"
        || up == "XHIGH"
        || (up == "STANDARD" && json_truthy(pol.get("require_simplify_on_standard")))
}

pub fn requires_review(risk: &str, policy: Option<&Value>) -> bool {
    let default_pol = default_gate_policy();
    let pol = policy.unwrap_or(&default_pol);
    let up = if risk.trim().is_empty() {
        "LOW".to_string()
    } else {
        risk.to_uppercase()
    };
    up == "HIGH"
        || up == "XHIGH"
        || (up == "STANDARD" && json_truthy(pol.get("require_review_on_standard")))
}

fn standard_requires_tests_opt(
    cwd: &str,
    paths: &[String],
    policy: Option<&Value>,
    git_root_opt: Option<&str>,
) -> bool {
    let default_pol = default_gate_policy();
    let pol = policy.unwrap_or(&default_pol);
    if let Some(cfg) = pol.get("require_tests_on_standard") {
        if !cfg.is_null() {
            return json_truthy(Some(cfg));
        }
    }
    workspace_has_test_harness_opt(cwd, paths, git_root_opt)
}

fn resolve_path_policies(
    dpaths: &[String],
    cwd: &str,
    policy: Option<&Value>,
) -> (Value, Vec<(String, Value, String)>) {
    let mut dir_cache = HashMap::new();
    if dpaths.is_empty() {
        let pol = match policy {
            Some(p) => p.clone(),
            None => load_project_gate_policy_cached(&[], cwd, &mut dir_cache),
        };
        return (pol, Vec::new());
    }
    if let Some(pol) = policy {
        if !json_truthy(pol.get("_multi_root")) {
            let items = dpaths
                .iter()
                .map(|p| {
                    let ap = resolve_against_cwd(p, cwd);
                    let risk = classify_path_risk(&ap, Some(pol));
                    (ap, pol.clone(), risk)
                })
                .collect();
            return (pol.clone(), items);
        }
    }

    let mut parent_cache: HashMap<String, Value> = HashMap::new();
    let mut items = Vec::new();
    for p in dpaths {
        let abs_p = resolve_against_cwd(p, cwd);
        let parent = Path::new(&abs_p)
            .parent()
            .map(|x| x.to_string_lossy().into_owned())
            .unwrap_or_default();
        let parent_key = rio::fold_path(&parent);
        let p_pol = if let Some(cached) = parent_cache.get(&parent_key) {
            cached.clone()
        } else {
            let loaded =
                load_project_gate_policy_cached(&[abs_p.clone()], cwd, &mut dir_cache);
            parent_cache.insert(parent_key, loaded.clone());
            loaded
        };
        let risk = classify_path_risk(&abs_p, Some(&p_pol));
        items.push((abs_p, p_pol, risk));
    }

    let distinct_roots: HashSet<String> = items
        .iter()
        .map(|(_, p_pol, _)| val_to_str(p_pol.get("policy_root")))
        .collect();
    if distinct_roots.len() == 1 {
        let pol0 = items[0].1.clone();
        return (pol0, items);
    }
    let mut multi = parse_gate_policy(None, &Map::new());
    if let Value::Object(ref mut map) = multi {
        map.insert("_multi_root".to_string(), Value::Bool(true));
    }
    (multi, items)
}

fn requires_tests_impl(
    risk: &str,
    cwd: &str,
    paths: &[String],
    policy: Option<&Value>,
    git_root_opt: Option<&str>,
    resolved_items: Option<&[(String, Value, String)]>,
) -> bool {
    let up = if risk.trim().is_empty() {
        "LOW".to_string()
    } else {
        risk.to_uppercase()
    };
    if up == "HIGH" || up == "XHIGH" {
        return true;
    }
    if up != "STANDARD" {
        return false;
    }

    let default_pol = default_gate_policy();
    let (pol_owned, items_owned, dpaths): (Value, Vec<(String, Value, String)>, Vec<String>) =
        if let Some(ritems) = resolved_items {
            let dp: Vec<String> = ritems.iter().map(|(p, _, _)| p.clone()).collect();
            (
                policy.cloned().unwrap_or_else(|| default_pol.clone()),
                ritems.to_vec(),
                dp,
            )
        } else {
            let dp = durable_paths(paths);
            if dp.is_empty() || policy.map_or(false, |p| !json_truthy(p.get("_multi_root"))) {
                let pol = match policy {
                    Some(p) => p.clone(),
                    None => load_project_gate_policy(&dp, cwd),
                };
                if !json_truthy(pol.get("_multi_root")) {
                    return standard_requires_tests_opt(cwd, &dp, Some(&pol), git_root_opt);
                }
            }
            let (pol, items) = resolve_path_policies(&dp, cwd, policy);
            (pol, items, dp)
        };

    if items_owned.is_empty() || !json_truthy(pol_owned.get("_multi_root")) {
        return standard_requires_tests_opt(cwd, &dpaths, Some(&pol_owned), git_root_opt);
    }
    if items_owned
        .iter()
        .any(|(_, _, r)| r == "HIGH" || r == "XHIGH")
    {
        return true;
    }
    let mut std_items: Vec<&(String, Value, String)> = items_owned
        .iter()
        .filter(|(_, _, r)| r == "STANDARD")
        .collect();
    if std_items.is_empty() {
        std_items = items_owned.iter().collect();
    }

    let mut unconfigured: Vec<(&str, &Value)> = Vec::new();
    for (p, p_pol, _) in std_items {
        if let Some(cfg) = p_pol.get("require_tests_on_standard") {
            if !cfg.is_null() {
                if json_truthy(Some(cfg)) {
                    return true;
                }
                continue;
            }
        }
        if is_fast_test_code_path(p) {
            return true;
        }
        unconfigured.push((p.as_str(), p_pol));
    }
    if unconfigured.is_empty() {
        return false;
    }

    let mut seen_parents = HashSet::new();
    let norm_cwd = if cwd.trim().is_empty() {
        String::new()
    } else {
        rio::normalize_path(cwd)
    };
    for (p, p_pol) in unconfigured {
        let parent = Path::new(p)
            .parent()
            .map(|x| x.to_string_lossy().into_owned())
            .unwrap_or_default();
        let pkey_dir = rio::fold_path(&parent);
        if !seen_parents.insert(pkey_dir.clone()) {
            continue;
        }
        let pol_root = val_to_str(p_pol.get("policy_root"));
        let eff_git_root: Option<String> = if !pol_root.is_empty() && Path::new(&pol_root).join(".git").exists() {
            Some(pol_root)
        } else if let Some(gr) = git_root_opt {
            if !gr.is_empty() && is_under_root(&rio::normalize_path(p), gr).0 {
                Some(gr.to_string())
            } else if gr.is_empty() && !norm_cwd.is_empty() && pkey_dir == rio::fold_path(&norm_cwd) {
                Some(String::new())
            } else {
                None
            }
        } else {
            None
        };
        if workspace_has_test_harness_opt(&parent, &[p.to_string()], eff_git_root.as_deref()) {
            return true;
        }
    }
    false
}

pub fn requires_tests(
    risk: &str,
    cwd: &str,
    paths: &[String],
    policy: Option<&Value>,
    git_root: &str,
) -> bool {
    let git_root_opt = if git_root.trim().is_empty() {
        None
    } else {
        Some(git_root)
    };
    requires_tests_impl(risk, cwd, paths, policy, git_root_opt, None)
}

pub fn resolve_candidate_context(marker: &Value, include_tests: bool) -> Value {
    let cwd = val_to_str(marker.get("cwd"));
    let dpaths = durable_paths_from_val(marker.get("paths"));
    let (mut policy, items) = resolve_path_policies(&dpaths, &cwd, None);
    let mut floors: Vec<String> = items.iter().map(|(_, _, r)| r.clone()).collect();
    if let Some(uf) = marker.get("unattributed_floor") {
        let ufs = val_to_str(Some(uf));
        if !ufs.is_empty() {
            floors.push(ufs);
        }
    }
    let floor = if floors.is_empty() {
        RISK_LOW.to_string()
    } else {
        max_risk(&floors)
    };
    let git_root_opt: Option<String> = marker
        .as_object()
        .and_then(|m| m.get("git_root"))
        .filter(|v| !v.is_null())
        .map(|v| val_to_str(Some(v)));

    let (needs_simplify, needs_review) = if !items.is_empty() {
        let ns = requires_simplify(&floor, Some(&policy))
            || items
                .iter()
                .any(|(_, p_pol, p_risk)| requires_simplify(p_risk, Some(p_pol)));
        let nr = requires_review(&floor, Some(&policy))
            || items
                .iter()
                .any(|(_, p_pol, p_risk)| requires_review(p_risk, Some(p_pol)));
        if json_truthy(policy.get("_multi_root")) && (ns || nr) {
            if let Value::Object(ref mut map) = policy {
                map.insert("require_simplify_on_standard".to_string(), Value::Bool(ns));
                map.insert("require_review_on_standard".to_string(), Value::Bool(nr));
            }
        }
        (ns, nr)
    } else {
        (
            requires_simplify(&floor, Some(&policy)),
            requires_review(&floor, Some(&policy)),
        )
    };

    let req_tests = if include_tests {
        Value::Bool(requires_tests_impl(
            &floor,
            &cwd,
            &dpaths,
            Some(&policy),
            git_root_opt.as_deref(),
            Some(&items),
        ))
    } else {
        Value::Null
    };
    let git_root_val = match git_root_opt {
        Some(gr) => Value::String(gr),
        None => Value::Null,
    };

    json!({
        "cwd": cwd,
        "git_root": git_root_val,
        "dpaths": dpaths,
        "policy": policy,
        "floor": floor,
        "require_tests": req_tests,
        "needs_simplify": needs_simplify,
        "needs_review": needs_review,
    })
}

pub fn receipt_requirements_summary(floor: &str, policy: Option<&Value>, has_tests: bool) -> String {
    let default_pol = default_gate_policy();
    let pol = policy.filter(|v| v.is_object()).unwrap_or(&default_pol);
    if floor == "LOW" {
        return "honest content/render check (no simplify or adversarial review required)"
            .to_string();
    }
    if floor == "STANDARD" {
        let mut parts = vec![if has_tests {
            "local verification/test execution".to_string()
        } else {
            "self-check (run any applicable check)".to_string()
        }];
        if json_truthy(pol.get("require_simplify_on_standard")) {
            parts.push(format!(
                "simplify on `{}` (fallback `{}`)",
                SONNET_HIGH_MODEL, SIMPLIFY_FALLBACK_MODEL
            ));
        }
        if json_truthy(pol.get("require_review_on_standard")) {
            parts.push("independent APPROVED review".to_string());
        }
        return parts.join(" + ");
    }
    if floor == "HIGH" {
        return format!(
            "decisive test/check execution -> primary independent APPROVED review (`carbon-stack codex-lane review` on `{}` -> `{}` -> `{}`) -> simplify once (`SIMPLIFY_LENS: ALL` fast-path if <=2 files & <=30 lines, else 3 separate lenses on `{}`, fallback `{}`) -> batch kill workers -> final `--closure` check",
            CODEX_SOL_MODEL, OPUS_HIGH_MODEL, CARBON_HIGH_MODEL, SONNET_HIGH_MODEL, SIMPLIFY_FALLBACK_MODEL
        );
    }
    format!(
        "decisive test/check execution -> primary XHIGH APPROVED review (`carbon-stack codex-lane review --xhigh` on `{}` -> `{}` -> `{}`) -> simplify once (`SIMPLIFY_LENS: ALL` fast-path if <=2 files & <=30 lines, else 3 separate lenses on `{}`, fallback `{}`) -> batch kill workers -> final `--xhigh --closure` check",
        CODEX_ASTRA_MODEL, OPUS_HIGH_MODEL, CARBON_HIGH_MODEL, SONNET_HIGH_MODEL, SIMPLIFY_FALLBACK_MODEL
    )
}

fn is_research_mcp_server(server_name: &str) -> bool {
    let s = server_name.trim().to_ascii_lowercase();
    s.starts_with("context7")
        || s.starts_with("gemini-api")
        || s.starts_with("google-developer-knowledge")
        || s.starts_with("v8std")
        || s.starts_with("notebooklm")
}

fn is_research_shell_cmd(raw_cmd: &str) -> bool {
    let unwrapped = rio::unwrap_tokenade_command(raw_cmd);
    let low = unwrapped.to_ascii_lowercase();
    let re = {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(
                r"(?i)(?:^|[;&|]\s*|\$null\s*\|\s*)(?:&?\s*['\x22]?[^\s'\x22]*?(?:tokenade(?:\.exe|\.cmd)?\s+(?:search|web)\b|nlm-memory(?:\.cmd|\.exe)?\s+recall\b|jev(?:\.exe|\.cmd)?\s+(?:ask|find)\b))",
            )
            .expect("research_shell_re")
        })
    };
    re.is_match(&low)
}

pub fn find_research_evidence_since(
    steps: &[Value],
    since_ts: f64,
    until_ts: Option<f64>,
) -> Vec<String> {
    // INVARIANT: Verify external docs/web research executed strictly after the blocking closure verdict before allowing a cycle reset.
    let mut found: Vec<String> = Vec::new();
    for (idx, st) in steps.iter().enumerate() {
        if st.get("source").and_then(|v| v.as_str()) != Some("MODEL")
            || st.get("type").and_then(|v| v.as_str()) != Some("PLANNER_RESPONSE")
        {
            continue;
        }
        let step_ts = st
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(rio::parse_iso_ts)
            .unwrap_or(0.0);
        let Some(tcs) = st.get("tool_calls").and_then(|v| v.as_array()) else {
            continue;
        };
        if tcs.is_empty() {
            continue;
        }
        let mut gen_results: Vec<(&str, f64)> = Vec::new();
        let mut scan_i = idx + 1;
        while scan_i < steps.len() {
            let gst = &steps[scan_i];
            if gst.get("type").and_then(|v| v.as_str()) != Some("GENERIC") {
                break;
            }
            let status = gst.get("status").and_then(|v| v.as_str()).unwrap_or("");
            let gts = gst
                .get("created_at")
                .and_then(|v| v.as_str())
                .map(rio::parse_iso_ts)
                .unwrap_or(0.0);
            gen_results.push((status, gts));
            scan_i += 1;
        }
        for (pos, tc) in tcs.iter().enumerate() {
            if pos >= gen_results.len() {
                continue;
            }
            let (g_status, g_ts) = gen_results[pos];
            if g_status == "ERROR" {
                continue;
            }
            let eff_ts = step_ts.max(g_ts);
            if eff_ts <= since_ts {
                continue;
            }
            if let Some(u_ts) = until_ts {
                if eff_ts > u_ts {
                    continue;
                }
            }
            let name = val_to_str(tc.get("name"));
            let name_low = name.trim().to_ascii_lowercase();
            let decoded_args = match tc.get("args") {
                Some(Value::String(s)) => serde_json::from_str::<Value>(s).unwrap_or(Value::Null),
                Some(v) => v.clone(),
                None => Value::Null,
            };
            let mut tag = String::new();
            if name_low == "search_web" {
                tag = "search_web".to_string();
            } else if let Some(rest) = name_low.strip_prefix("mcp_") {
                if is_research_mcp_server(rest) {
                    tag = name_low.clone();
                }
            } else if name_low == "call_mcp_tool" {
                let srv = val_to_str(decoded_args.get("ServerName"));
                if is_research_mcp_server(&srv) {
                    tag = format!("call_mcp_tool:{}", srv.trim().to_ascii_lowercase());
                }
            } else if name_low == "invoke_subagent" {
                let sub_type = val_to_str(decoded_args.get("TypeName"));
                if sub_type.trim().eq_ignore_ascii_case("research") {
                    tag = "subagent:research".to_string();
                }
            } else if name_low == "run_command" {
                let cmd_line = val_to_str(decoded_args.get("CommandLine"));
                if is_research_shell_cmd(&cmd_line) {
                    tag = "cli:research".to_string();
                }
            }
            if !tag.is_empty() && !found.contains(&tag) {
                found.push(tag);
            }
        }
    }
    found
}

pub fn last_research_reset_ts(marker: &Value) -> f64 {
    marker
        .get("research_resets")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|ent| val_to_f64(ent.get("reset_ts")))
                .fold(0.0f64, f64::max)
        })
        .unwrap_or(0.0)
}

pub fn last_research_reset_board_seq(marker: &Value) -> i64 {
    marker
        .get("research_resets")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|ent| ent.get("board_head_seq").and_then(|v| v.as_i64()))
                .fold(0i64, i64::max)
        })
        .unwrap_or(0)
}

pub fn active_marker_closure_halt(marker: &Value) -> Option<(usize, f64, Vec<String>)> {
    let ch = marker.get("closure_halt")?.as_object()?;
    let cnt = ch.get("blocked_count").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    if cnt < MAX_CLOSURE_PASSES_PER_CYCLE {
        return None;
    }
    let ch_first_ts = val_to_f64(ch.get("candidate_first_ts"));
    let marker_first_ts = val_to_f64(marker.get("first_ts"));
    if ch_first_ts > 0.0 && (ch_first_ts - marker_first_ts).abs() > 1e-6 {
        return None;
    }
    let last_blk_ts = val_to_f64(ch.get("last_blocked_ts"));
    let cycle_base_ts = val_to_f64(ch.get("cycle_base_ts"));
    let rr_ts = last_research_reset_ts(marker);
    // INVARIANT: A latched `closure_halt` is bound to `candidate_first_ts` and remains active until a verified `research_resets` entry advances `reset_ts` past `last_blocked_ts` or `cycle_base_ts`.
    if rr_ts > 0.0 && (rr_ts > last_blk_ts || rr_ts > cycle_base_ts + 1e-6) {
        return None;
    }
    let ids: Vec<String> = ch
        .get("blocked_review_ids")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|x| val_to_str(Some(x)).trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    Some((cnt, last_blk_ts, ids))
}

pub struct ClosureHaltLatch<'a> {
    pub session: &'a str,
    pub expected_first_ts: f64,
    pub expected_rr_ts: f64,
    pub expected_round_start_msg_id: i64,
    pub blocked_count: usize,
    pub last_blocked_ts: f64,
    pub blocked_ids: &'a [String],
    pub cycle_base_ts: f64,
}

pub fn latch_marker_closure_halt(latch: ClosureHaltLatch<'_>) {
    let ClosureHaltLatch {
        session,
        expected_first_ts,
        expected_rr_ts,
        expected_round_start_msg_id,
        blocked_count,
        last_blocked_ts,
        blocked_ids,
        cycle_base_ts,
    } = latch;
    if session.trim().is_empty()
        || expected_first_ts <= 0.0
        || blocked_count < MAX_CLOSURE_PASSES_PER_CYCLE
    {
        return;
    }
    let skey = rio::safe_key(session, "default");
    let mpath = marker_path(&skey);
    let _ = rio::with_file_lock(&marker_lock_path(&skey), 3.0, 30.0, |locked| {
        if !locked {
            return false;
        }
        let raw = rio::read_json(&mpath);
        let (merged_opt, consumed_ids) = apply_pending_marker_deltas(&skey, raw.as_ref());
        let Some(mut fresh) = merged_opt else {
            return false;
        };
        if !fresh.is_object() || json_truthy(fresh.get("closed")) {
            return false;
        }
        // SAFETY: Re-verify candidate identity (`first_ts`) and cycle cursors (`last_research_reset_ts`, `round_start_msg_id`) under `marker_lock_path` so concurrent candidate turnover or `research-reset` never inherits a stale halt.
        let live_first_ts = val_to_f64(fresh.get("first_ts"));
        let live_rr_ts = last_research_reset_ts(&fresh);
        let live_round_seq = fresh
            .get("round_start_msg_id")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        if (live_first_ts - expected_first_ts).abs() > 1e-6
            || (live_rr_ts - expected_rr_ts).abs() > 1e-6
            || live_round_seq != expected_round_start_msg_id
            || (live_rr_ts > 0.0 && (live_rr_ts > last_blocked_ts || live_rr_ts > cycle_base_ts + 1e-6))
        {
            return false;
        }
        if let Some((cur_cnt, cur_ts, _)) = active_marker_closure_halt(&fresh) {
            if cur_cnt >= blocked_count && cur_ts >= last_blocked_ts && consumed_ids.is_empty() {
                return true;
            }
        }
        if let Some(mobj) = fresh.as_object_mut() {
            mobj.insert(
                "closure_halt".to_string(),
                json!({
                    "candidate_first_ts": expected_first_ts,
                    "blocked_count": blocked_count,
                    "last_blocked_ts": last_blocked_ts,
                    "blocked_review_ids": blocked_ids,
                    "cycle_base_ts": cycle_base_ts,
                }),
            );
        }
        if rio::write_json(&mpath, &fresh).is_ok() {
            if !consumed_ids.is_empty() {
                ack_pending_marker_deltas(&skey, &consumed_ids);
            }
            return true;
        }
        false
    });
}

pub fn latch_marker_closure_halt_for_marker(
    session: &str,
    marker: &Value,
    blocked_count: usize,
    last_blocked_ts: f64,
    blocked_ids: &[String],
) {
    let exp_first_ts = val_to_f64(marker.get("first_ts"));
    let exp_rr_ts = last_research_reset_ts(marker);
    let exp_round_seq = val_to_i64(marker.get("round_start_msg_id"));
    latch_marker_closure_halt(ClosureHaltLatch {
        session,
        expected_first_ts: exp_first_ts,
        expected_rr_ts: exp_rr_ts,
        expected_round_start_msg_id: exp_round_seq,
        blocked_count,
        last_blocked_ts,
        blocked_ids,
        cycle_base_ts: exp_first_ts.max(exp_rr_ts),
    });
}

pub fn research_reset_epoch(marker: &Value) -> usize {
    marker
        .get("research_resets")
        .and_then(|v| v.as_array())
        .map_or(0, |arr| arr.len())
}

pub fn active_marker_declared_risk(marker: &Value) -> String {
    let Some(dr) = marker.get("cycle_declared_risk").and_then(|v| v.as_object()) else {
        return String::new();
    };
    let dr_first_ts = val_to_f64(dr.get("candidate_first_ts"));
    let marker_first_ts = val_to_f64(marker.get("first_ts"));
    if marker_first_ts <= 0.0 || (dr_first_ts - marker_first_ts).abs() > 1e-6 {
        return String::new();
    }
    let Some(dr_epoch) = dr.get("reset_epoch").and_then(|v| v.as_u64()) else {
        return String::new();
    };
    if (dr_epoch as usize) != research_reset_epoch(marker) {
        return String::new();
    }
    let r = val_to_str(dr.get("risk")).to_uppercase();
    if is_valid_risk(&r) {
        r
    } else {
        String::new()
    }
}

pub fn latch_marker_declared_risk(
    session: &str,
    expected_first_ts: Option<f64>,
    expected_reset_epoch: Option<usize>,
    risk: &str,
) -> bool {
    let risk_up = risk.trim().to_uppercase();
    if session.trim().is_empty() || !is_valid_risk(&risk_up) {
        return false;
    }
    let skey = rio::safe_key(session, "default");
    let mpath = marker_path(&skey);
    rio::with_file_lock(&marker_lock_path(&skey), 5.0, 30.0, |locked| {
        if !locked {
            return false;
        }
        let raw = rio::read_json(&mpath);
        let (merged_opt, consumed_ids) = apply_pending_marker_deltas(&skey, raw.as_ref());
        let Some(mut fresh) = merged_opt else {
            return false;
        };
        if !fresh.is_object() || json_truthy(fresh.get("closed")) {
            return false;
        }
        // SAFETY: Bind cycle-escalated risk (`--xhigh` or cycle receipt) inside `marker.json` under `marker_lock_path` to `(candidate_first_ts, reset_epoch)` so concurrent `research-reset` can never erase a new cycle's risk or inherit a stale cycle's risk.
        let live_first_ts = val_to_f64(fresh.get("first_ts"));
        if live_first_ts <= 0.0 {
            return false;
        }
        if let Some(exp_fts) = expected_first_ts {
            if (live_first_ts - exp_fts).abs() > 1e-6 {
                return false;
            }
        }
        let live_epoch = research_reset_epoch(&fresh);
        if let Some(exp_ep) = expected_reset_epoch {
            if live_epoch != exp_ep {
                return false;
            }
        }
        let cur_risk = active_marker_declared_risk(&fresh);
        let merged_risk = if cur_risk.is_empty() {
            risk_up
        } else {
            max_risk(&[cur_risk.clone(), risk_up])
        };
        if cur_risk == merged_risk && consumed_ids.is_empty() {
            return true;
        }
        if let Some(mobj) = fresh.as_object_mut() {
            mobj.insert(
                "cycle_declared_risk".to_string(),
                json!({
                    "candidate_first_ts": live_first_ts,
                    "reset_epoch": live_epoch,
                    "risk": merged_risk,
                }),
            );
        }
        if rio::write_json(&mpath, &fresh).is_ok() {
            if !consumed_ids.is_empty() {
                ack_pending_marker_deltas(&skey, &consumed_ids);
            }
            return true;
        }
        false
    })
}

pub fn latch_marker_declared_risk_for_marker(session: &str, marker: &mut Value, risk: &str) -> bool {
    let exp_fts = val_to_f64(marker.get("first_ts"));
    let exp_epoch = research_reset_epoch(marker);
    if !latch_marker_declared_risk(session, Some(exp_fts), Some(exp_epoch), risk) {
        return false;
    }
    let risk_up = risk.trim().to_uppercase();
    let cur_risk = active_marker_declared_risk(marker);
    let merged_risk = if cur_risk.is_empty() {
        risk_up
    } else {
        max_risk(&[cur_risk, risk_up])
    };
    if let Some(mobj) = marker.as_object_mut() {
        mobj.insert(
            "cycle_declared_risk".to_string(),
            json!({
                "candidate_first_ts": exp_fts,
                "reset_epoch": exp_epoch,
                "risk": merged_risk,
            }),
        );
    }
    true
}

pub fn pre_reset_worker_cids(marker: Option<&Value>) -> (bool, HashSet<String>) {
    let mut has_snapshot = false;
    let mut cids: HashSet<String> = HashSet::new();
    let Some(arr) = marker
        .and_then(|m| m.get("research_resets"))
        .and_then(|v| v.as_array())
    else {
        return (false, cids);
    };
    for ent in arr {
        if let Some(list) = ent.get("pre_reset_worker_cids").and_then(|v| v.as_array()) {
            has_snapshot = true;
            for item in list {
                let s = val_to_str(Some(item)).trim().to_string();
                if !s.is_empty() {
                    cids.insert(s);
                }
            }
        }
    }
    (has_snapshot, cids)
}

pub fn is_worker_spawned_before_reset(
    wname: &str,
    meta: Option<&Value>,
    raw_board: &[Value],
    rr_ts: f64,
    rr_board_seq: i64,
    marker: Option<&Value>,
    brain_root: Option<&Path>,
) -> bool {
    if rr_ts <= 0.0 && rr_board_seq <= 0 {
        return false;
    }
    let wcid = meta
        .and_then(|m| m.get("conversation_id").or_else(|| m.get("conversationId")))
        .map(|v| val_to_str(Some(v)).trim().to_string())
        .unwrap_or_default();
    let (has_cid_snap, old_cids) = pre_reset_worker_cids(marker);
    if !wcid.is_empty() && old_cids.contains(&wcid) {
        return true;
    }
    // INVARIANT: Bind post-reset worker freshness to the worker's own session (`conversation_id`, `created_at`, or worker transcript origin) so reusing a standard roster name like `simplify-reuse` never inherits a killed pre-reset worker's board mentions.
    if let Some(m) = meta {
        for key in ["created_at", "added_at", "started_at"] {
            let cts = match m.get(key) {
                Some(Value::String(s)) => rio::parse_iso_ts(s),
                Some(v) => val_to_f64(Some(v)),
                None => 0.0,
            };
            if rr_ts > 0.0 && cts > 0.0 {
                return cts < rr_ts - 0.001;
            }
        }
    }
    if !wcid.is_empty() && rr_ts > 0.0 {
        if let Some(br) = brain_root {
            let head = rio::read_transcript_head(
                &rio::member_transcript_path(br, &wcid).to_string_lossy(),
                4,
            );
            let w_origin_ts = head
                .iter()
                .filter_map(|s| s.get("created_at").and_then(|v| v.as_str()).map(rio::parse_iso_ts))
                .filter(|&ts| ts > 0.0)
                .fold(f64::INFINITY, f64::min);
            if w_origin_ts.is_finite() {
                return w_origin_ts < rr_ts - 0.001;
            }
        }
    }
    if has_cid_snap && !wcid.is_empty() {
        return false;
    }
    let clean_added = meta
        .and_then(|m| m.get("added_by"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    for (idx, bp) in raw_board.iter().enumerate() {
        let seq = extract_msg_seq(bp, (idx + 1) as i64);
        let poster = val_to_str(bp.get("agent"));
        let btext = val_to_str(bp.get("text"));
        let is_assigner = poster.eq_ignore_ascii_case("coordinator")
            || (!clean_added.is_empty() && poster == clean_added);
        if is_assigner && rio::text_mentions_swarm_worker(&btext, wname) {
            if rr_board_seq > 0 && seq <= rr_board_seq {
                return true;
            }
            let bts = bp
                .get("time")
                .and_then(|v| v.as_str())
                .map(rio::parse_iso_ts)
                .unwrap_or(0.0);
            if rr_ts > 0.0 && bts > 0.0 && bts <= rr_ts {
                return true;
            }
            break;
        }
    }
    false
}

pub fn verified_research_reset_state(
    marker: &Value,
    steps: Option<&[Value]>,
) -> (f64, i64, Option<String>) {
    let Some(arr) = marker.get("research_resets").and_then(|v| v.as_array()) else {
        return (0.0, 0, None);
    };
    let mut latest_ts = 0.0f64;
    let mut latest_seq = 0i64;
    for ent in arr {
        let dec = val_to_str(ent.get("decision")).trim().to_ascii_lowercase();
        let findings = val_to_str(ent.get("findings")).trim().to_string();
        let r_ts = val_to_f64(ent.get("reset_ts"));
        let blk_ts = val_to_f64(ent.get("last_blocked_ts"));
        if !RESEARCH_RESET_DECISIONS.contains(&dec.as_str())
            || findings.chars().count() < 15
            || r_ts <= 0.0
            || blk_ts <= 0.0
            || r_ts < blk_ts
        {
            return (
                0.0,
                0,
                Some("invalid `research_resets` metadata in candidate marker".to_string()),
            );
        }
        let has_recorded_tools = ent
            .get("research_tools")
            .and_then(|v| v.as_array())
            .map_or(false, |a| !a.is_empty());
        if !has_recorded_tools {
            return (
                0.0,
                0,
                Some("`research_resets` entry has empty `research_tools`".to_string()),
            );
        }
        if let Some(st) = steps {
            if st.is_empty() {
                return (
                    0.0,
                    0,
                    Some("`research_resets` entry cannot be verified against an empty transcript".to_string()),
                );
            }
            let earliest_ts = st
                .iter()
                .filter_map(|s| s.get("created_at").and_then(|v| v.as_str()).map(rio::parse_iso_ts))
                .filter(|&ts| ts > 0.0)
                .fold(f64::INFINITY, f64::min);
            if !earliest_ts.is_finite() || earliest_ts <= r_ts + 1.0 {
                let ev = find_research_evidence_since(st, blk_ts, Some(r_ts + 1.0));
                if ev.is_empty() {
                    return (
                        0.0,
                        0,
                        Some("`research_resets` entry lacks verified post-BLOCKED documentation/web research in transcript".to_string()),
                    );
                }
            }
        }
        if r_ts >= latest_ts {
            latest_ts = r_ts;
            let bseq = ent
                .get("board_head_seq")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            if bseq > latest_seq {
                latest_seq = bseq;
            }
        }
    }
    (latest_ts, latest_seq, None)
}

pub fn is_simplify_or_review_swarm_worker(name: &str, meta: Option<&Value>) -> bool {
    let low = name.trim().to_ascii_lowercase();
    if is_simplify_worker_name(&low) || !simplify_lens_from_worker_name(&low).is_empty() {
        return true;
    }
    let mdl = meta
        .and_then(|m| {
            m.get("model")
                .or_else(|| m.get("applied_model"))
                .or_else(|| m.get("desired_model"))
        })
        .map(|v| val_to_str(Some(v)).trim().to_ascii_lowercase())
        .unwrap_or_default();
    mdl == OPUS_HIGH_MODEL
        || mdl == SONNET_HIGH_MODEL
        || low.contains("review")
        || low.contains("adversarial")
        || low.contains("critic")
        || low.contains("verifier")
}

pub fn active_simplify_or_review_workers(brain_root: &Path, session: &str) -> Vec<String> {
    let members = rio::load_swarm_members(brain_root, session);
    let mut alive: Vec<String> = Vec::new();
    for (name, meta) in &members {
        if !meta.is_object()
            || rio::is_swarm_role_member(name, Some(meta))
            || rio::is_swarm_member_killed(Some(meta))
        {
            continue;
        }
        if is_simplify_or_review_swarm_worker(name, Some(meta)) {
            alive.push(name.clone());
        }
    }
    alive.sort();
    alive
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_regexes_compile_and_basic_tags() {
        let _ = high_risk_patterns();
        let _ = chip_trees_re();
        let _ = system_generated_re();
        let _ = user_scratch_patterns();
        let _ = always_ephemeral_patterns();
        let _ = os_temp_patterns();
        let _ = receipt_line_re();
        let _ = verified_body_re();
        let _ = operational_body_re();
        let _ = anomaly_body_re();
        let _ = verdict_line_re();
        let _ = closure_line_re();
        let _ = codex_cli_wrapper_re();
        let _ = swarm_mention_line_re();
        let _ = json_array_start_re();
        let _ = simplify_template_pair_re();
        let _ = simplify_verdict_core_re();
        let _ = simplify_lens_core_re();
        let _ = simplify_combined_lens_core_re();
        let _ = simplify_alt_tail_re();
        let _ = review_tier_xhigh_re();
        let _ = diff_hash_re();
        let _ = flash_model_re();
        let _ = compact_simplify_worker_re();

        assert_eq!(extract_diff_hash("DIFF_HASH: abc_123:def"), "abc_123:def");
        assert!(is_flash_model("gemini-3-flash-lite"));
        assert!(!is_flash_model(SONNET_HIGH_MODEL));
        assert!(is_review_tier_xhigh("REVIEW_TIER: XHIGH"));
        assert!(is_simplify_worker_name("simp-efficie"));
        assert_eq!(simplify_lens_from_worker_name("simp-efficie"), "efficiency");
        assert!(is_simplify_subagent_call("custom:research", "simplify-reuse"));
    }

    #[test]
    fn test_parse_simplify_verdict_and_template_filtering() {
        let template_only = "Reply with SIMPLIFY_LENS: REUSE (or QUALITY / EFFICIENCY) and SIMPLIFY_VERDICT: CLEAN | FINDINGS_REPORTED.";
        let parsed_tpl = parse_simplify_verdict(template_only, None);
        assert_eq!(parsed_tpl["verdict"], "");
        assert_eq!(parsed_tpl["clean"], false);

        let real_msg = "Checked diff.\n__SIMPLIFY_LENS: EFFICIENCY__\n**SIMPLIFY_VERDICT: CLEAN** // ok";
        let parsed_real = parse_simplify_verdict(real_msg, None);
        assert_eq!(parsed_real["verdict"], "CLEAN");
        assert_eq!(parsed_real["clean"], true);
        assert_eq!(parsed_real["lens"], "efficiency");
        assert_eq!(parsed_real["explicit_lenses"], json!(["efficiency"]));

        let combined = "SIMPLIFY_LENS: ALL\nSIMPLIFY_VERDICT: ACTIONABLE_FIXES";
        let parsed_all = parse_simplify_verdict(combined, None);
        assert_eq!(parsed_all["has_explicit_all"], true);
        assert_eq!(parsed_all["lens"], "all");
        assert_eq!(parsed_all["verdict"], "ACTIONABLE_FIXES");

        let pair_msg = "Format: SIMPLIFY_VERDICT: CLEAN or SIMPLIFY_VERDICT: FINDINGS_REPORTED\nActual:\nSIMPLIFY_VERDICT: CLEAN";
        let parsed_pair = parse_simplify_verdict(pair_msg, Some("reuse"));
        assert_eq!(parsed_pair["verdict"], "CLEAN");
        assert_eq!(parsed_pair["lens"], "reuse");

        let anom_d6ceeff0 = "@coordinator\nAll flags and tokens (`DIFF_HASH: <current_diff_hash>`, `VERDICT: APPROVED`, `SIMPLIFY_LENS: ALL`, `CLOSURE_VALIDATION: READY|BLOCKED`) are consistent.\nDIFF_HASH: 061484edee70341e\nSIMPLIFY_LENS: REUSE\nSIMPLIFY_VERDICT: CLEAN";
        let parsed_anom = parse_simplify_verdict(anom_d6ceeff0, None);
        assert_eq!(parsed_anom["lens"], "reuse");
        assert_eq!(parsed_anom["has_explicit_all"], false);
        assert_eq!(parsed_anom["combined"], false);
        assert_eq!(parsed_anom["clean"], true);
        assert_eq!(extract_diff_hash(anom_d6ceeff0), "061484edee70341e");

        let ru_prose = "Проверьте SIMPLIFY_VERDICT: CLEAN и `SIMPLIFY_LENS: ALL` в строке.\nSIMPLIFY_LENS: QUALITY\nSIMPLIFY_VERDICT: CLEAN";
        let parsed_ru = parse_simplify_verdict(ru_prose, None);
        assert_eq!(parsed_ru["lens"], "quality");
        assert_eq!(parsed_ru["has_explicit_all"], false);
        assert_eq!(parsed_ru["clean"], true);
    }

    #[test]
    fn test_parse_terminal_receipt() {
        let ok = parse_terminal_receipt("Summary done.\n[gate] verified: HIGH; cargo test passed").unwrap();
        assert_eq!(ok["kind"], "verified");
        assert_eq!(ok["risk"], "HIGH");
        assert_eq!(ok["summary"], "cargo test passed");

        let misplaced = parse_terminal_receipt("[gate] verified: LOW; ok\nextra trailing line").unwrap();
        assert_eq!(misplaced["kind"], "misplaced");

        let malformed = parse_terminal_receipt("[gate] verified: missing semicolon").unwrap();
        assert_eq!(malformed["kind"], "malformed");

        let op = parse_terminal_receipt("[gate] operational: checked ps; restarted worker").unwrap();
        assert_eq!(op["kind"], "operational");
        assert_eq!(op["precheck"], "checked ps");
        assert_eq!(op["effect"], "restarted worker");
    }

    #[test]
    fn test_classify_path_risk_and_globs_overlap() {
        assert_eq!(classify_path_risk(SHELL_MUTATION_SENTINEL, None), RISK_LOW);
        assert_eq!(classify_path_risk("docs/README.md", None), RISK_LOW);
        assert_eq!(classify_path_risk("src/auth/jwt_helper.rs", None), RISK_HIGH);
        assert_eq!(classify_path_risk("src/main.rs", None), RISK_STANDARD);
        assert_eq!(classify_path_risk("rust/src/cwg_stop.rs", None), RISK_HIGH);
        assert_eq!(classify_path_risk("plugin/bin/carbon-stack.exe", None), RISK_HIGH);

        let pol = json!({
            "policy_root": "",
            "default_code_risk": "STANDARD",
            "xhigh_risk_globs": ["src/critical/**"],
            "high_risk_globs": [],
            "low_risk_globs": [],
        });
        assert_eq!(classify_path_risk("src/critical/engine.rs", Some(&pol)), RISK_XHIGH);

        assert!(globs_may_overlap("src/**/*.rs", "src/hooks/*.rs", None));
        assert!(!globs_may_overlap("src/hooks/*.rs", "tests/*.rs", None));
        assert!(glob_matches_path("rust/src/**", "rust/src/cwg_common.rs"));
        assert!(is_ephemeral_path(
            "c:/repo/worktree/.mcp.json.tokenade-original"
        ));
        assert!(!is_ephemeral_path("c:/repo/worktree/.mcp.json"));
    }
}
