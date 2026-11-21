use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::rio;
use crate::win32_sqlite::{
    self, SqlParam, SqlVal, SqliteConn, SQLITE_OPEN_CREATE, SQLITE_OPEN_READONLY,
    SQLITE_OPEN_READWRITE,
};

pub const VALID_CATEGORIES: &[&str] = &["GOTCHA", "RISK", "DECISION", "CONSTRAINT", "COMMAND"];

struct SecretPattern {
    label: &'static str,
    regex: Regex,
}

fn secret_patterns() -> &'static [SecretPattern] {
    static PATS: OnceLock<Vec<SecretPattern>> = OnceLock::new();
    PATS.get_or_init(|| {
        vec![
            SecretPattern {
                label: "google_api_key",
                regex: Regex::new(r"\bAIza[0-9A-Za-z_-]{30,}\b").expect("google_api_key"),
            },
            SecretPattern {
                label: "openai_or_sk_key",
                regex: Regex::new(r"\bsk-(?:proj-|live-|test-)?[0-9A-Za-z_-]{20,}\b")
                    .expect("openai_or_sk_key"),
            },
            SecretPattern {
                label: "github_token",
                regex: Regex::new(
                    r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{24,}\b|\bgithub_pat_[0-9A-Za-z_]{30,}\b",
                )
                .expect("github_token"),
            },
            SecretPattern {
                label: "gitlab_token",
                regex: Regex::new(r"\bglpat-[0-9A-Za-z_-]{16,}\b").expect("gitlab_token"),
            },
            SecretPattern {
                label: "slack_token",
                regex: Regex::new(r"\bxox[baprs]-[0-9A-Za-z-]{16,}\b").expect("slack_token"),
            },
            SecretPattern {
                label: "aws_access_key",
                regex: Regex::new(r"\bAKIA[0-9A-Z]{16}\b").expect("aws_access_key"),
            },
            SecretPattern {
                label: "private_key_pem",
                regex: Regex::new(
                    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
                )
                .expect("private_key_pem"),
            },
            SecretPattern {
                label: "bearer_jwt",
                regex: Regex::new(
                    r"\bBearer\s+eyJ[0-9A-Za-z_-]{15,}\.[0-9A-Za-z_-]{15,}\.[0-9A-Za-z_-]{10,}\b",
                )
                .expect("bearer_jwt"),
            },
            SecretPattern {
                label: "stripe_key",
                regex: Regex::new(r"\b[rs]k_(?:live|test)_[0-9A-Za-z]{16,}\b")
                    .expect("stripe_key"),
            },
            SecretPattern {
                label: "telegram_bot_token",
                regex: Regex::new(r"\b\d{6,12}:[0-9A-Za-z_-]{28,}\b")
                    .expect("telegram_bot_token"),
            },
            SecretPattern {
                label: "prefixed_pat_token",
                regex: Regex::new(r"\b(?:hf|npm|pypi)_[0-9A-Za-z_-]{20,}\b")
                    .expect("prefixed_pat_token"),
            },
            SecretPattern {
                label: "uri_password",
                regex: Regex::new(r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]{4,}@[^\s/]+")
                    .expect("uri_password"),
            },
            SecretPattern {
                label: "secret_assignment",
                // INVARIANT: `(?:^|[^A-Za-z0-9])` replaces Python's `(?<![A-Za-z0-9])` lookbehind because `regex = 1.12.3` omits lookaround.
                regex: Regex::new(
                    r#"(?i)(?:^|[^A-Za-z0-9])[A-Za-z0-9_.-]{0,40}?(?:secret(?:[_-]?access)?(?:[_-]?key)?|token|pass(?:word|wd)?|pwd|credential|(?:api|access|private|signing|encryption|master|client)[_-]?key)["']?\s*[:=]\s*["']?[A-Za-z0-9/+._~!$%@&*:=-]{12,}["']?"#,
                )
                .expect("secret_assignment"),
            },
        ]
    })
}

fn extra_redaction_patterns() -> &'static [SecretPattern] {
    static EXTRA: OnceLock<Vec<SecretPattern>> = OnceLock::new();
    EXTRA.get_or_init(|| {
        vec![
            SecretPattern {
                label: "private_key_pem",
                regex: Regex::new(
                    r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
                )
                .expect("private_key_pem_block"),
            },
            SecretPattern {
                label: "webhook_url_token",
                regex: Regex::new(
                    r"(?i)\bhttps?://[^\s/]+/(?:rest/\d+/[A-Za-z0-9]{10,}|services/T[0-9A-Za-z]+/B[0-9A-Za-z]+/[0-9A-Za-z]+|api/webhooks/\d+/[0-9A-Za-z_-]{16,}|webhooks?/[0-9A-Za-z_-]{16,})[^\s]*",
                )
                .expect("webhook_url_token"),
            },
            SecretPattern {
                label: "url_secret_param",
                regex: Regex::new(
                    r"(?i)([?&](?:access_?token|api_?key|auth_?token|token|secret|key|sig|signature|password|passwd|webhook_?token)=)[^&\s#]{6,}",
                )
                .expect("url_secret_param"),
            },
            SecretPattern {
                label: "bearer_or_basic_auth",
                regex: Regex::new(
                    r"(?i)\b(?:Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{6,}\b",
                )
                .expect("bearer_or_basic_auth"),
            },
            SecretPattern {
                label: "quoted_credential_header",
                regex: Regex::new(
                    r#"(?i)(?:"(?:cookie|set-cookie|authorization|proxy-authorization|x[-_][a-z0-9_-]*(?:key|token|secret|auth|cookie))\s*:\s*[^"\r\n]+"|'(?:cookie|set-cookie|authorization|proxy-authorization|x[-_][a-z0-9_-]*(?:key|token|secret|auth|cookie))\s*:\s*[^'\r\n]+')"#,
                )
                .expect("quoted_credential_header"),
            },
            SecretPattern {
                label: "full_credential_header",
                regex: Regex::new(
                    r#"(?i)(?:^|[\s,(\[{])["']?(?:cookie|set-cookie|authorization|proxy-authorization|x[-_][a-z0-9_-]*(?:key|token|secret|auth|cookie))["']?\s*[:=]\s*(?:"[^"\r\n]+"|'[^'\r\n]+'|[^\r\n]+)"#,
                )
                .expect("full_credential_header"),
            },
            SecretPattern {
                label: "credential_header",
                regex: Regex::new(
                    r#"(?i)(?:^|[\s,;(\[{"'])(?:x[-_]?(?:api[-_]?key|auth[-_]?token|access[-_]?token|secret[-_]?key|webhook[-_]?secret|client[-_]?secret)|authorization|proxy-authorization|cookie|set-cookie|api[-_]?key|access[-_]?token|auth[-_]?token|client[-_]?secret|private[-_]?key|signing[-_]?key|webhook[-_]?secret|secret|token|password|passwd|pwd)["']?\s*[:=]\s*(?:["'][^"'\r\n]{3,}["']|[^\s"'`,;)}\]\r\n]{3,})"#,
                )
                .expect("credential_header"),
            },
        ]
    })
}

fn find_url_scheme_at(b: &[u8], pos: usize) -> Option<usize> {
    if pos > 0 && b[pos - 1].is_ascii_alphanumeric() {
        return None;
    }
    for prefix in [b"https://".as_slice(), b"http://".as_slice(), b"wss://".as_slice(), b"ws://".as_slice()] {
        let plen = prefix.len();
        if pos + plen <= b.len() && b[pos..pos + plen].eq_ignore_ascii_case(prefix) {
            return Some(plen);
        }
    }
    None
}

fn is_url_hard_stop(byte: u8) -> bool {
    byte <= 0x20 || byte == 0x7f || matches!(byte, b'"' | b'`' | b'<' | b'>')
}

fn is_closing_single_quote_stop(
    b: &[u8],
    pos: usize,
    enclosing_single_quote: bool,
    paren_depth: usize,
    bracket_depth: usize,
) -> bool {
    if !enclosing_single_quote || b[pos] != b'\'' || paren_depth > 0 || bracket_depth > 0 {
        return false;
    }
    // INVARIANT: Only treat `'` inside a single-quoted URL as the closing quote when ALL following outer punctuation/enclosing delimiters (`]`/`)`/`}`/`,`/`.`/`;`/`:`/`!`/`?`) lead directly to EOF or whitespace/hard-stop — fail closed on ambiguous unspaced continuations like `'..canary-value'` or `','https://canary-secret.invalid/next'` so embedded URLs inside query params can never leak unredacted hosts or suffixes.
    let mut j = pos + 1;
    while j < b.len()
        && matches!(
            b[j],
            b']' | b')' | b'}' | b',' | b'.' | b';' | b':' | b'!' | b'?'
        )
    {
        j += 1;
    }
    j >= b.len() || is_url_hard_stop(b[j])
}

fn sanitize_urls_in_text(text: &str) -> String {
    // INVARIANT: Structurally scan every HTTP/WS URL per RFC 3986/6874 (supporting IPv6 literals, zone IDs, and ALL RFC 3986 sub-delims including `'`, `(`, `)`, `!`, `$`, `&`, `*`, `+`, `,`, `;`, `=` inside userinfo/path/query/fragment) so credentials, paths, queries, and fragments are always redacted to origin while preserving enclosing quotes and unmatched markdown `]`/`)`/`}` (never crossing `]`/`}` or unmatched `)` in authority into a following `@mention`).
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < b.len() {
        let Some(scheme_len) = find_url_scheme_at(b, i) else {
            let ch = text[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
            continue;
        };
        let enclosing_sq = i > 0 && b[i - 1] == b'\'';
        let scheme = &text[i..i + scheme_len];
        let auth_start = i + scheme_len;

        let mut auth_end = auth_start;
        let mut auth_parens = 0usize;
        let mut in_ipv6 = false;
        let mut ipv6_closed = false;
        while auth_end < b.len() {
            let ch = b[auth_end];
            if is_url_hard_stop(ch)
                || is_closing_single_quote_stop(b, auth_end, enclosing_sq, auth_parens, usize::from(in_ipv6))
                || matches!(ch, b'/' | b'?' | b'#')
            {
                break;
            }
            if in_ipv6 {
                if ch == b']' {
                    in_ipv6 = false;
                    ipv6_closed = true;
                }
                auth_end += 1;
                continue;
            }
            match ch {
                b'[' if auth_end == auth_start || b[auth_end - 1] == b'@' => {
                    in_ipv6 = true;
                    auth_end += 1;
                }
                b'[' | b']' | b'{' | b'}' => break,
                b'(' => {
                    auth_parens += 1;
                    auth_end += 1;
                }
                b')' => {
                    if auth_parens == 0 {
                        break;
                    }
                    auth_parens -= 1;
                    auth_end += 1;
                }
                _ => auth_end += 1,
            }
        }
        if in_ipv6 {
            out.push_str(scheme);
            i = auth_start;
            continue;
        }
        let raw_auth = &text[auth_start..auth_end];
        let (has_userinfo, hostport_raw) = match raw_auth.rfind('@') {
            Some(at) => (true, &raw_auth[at + 1..]),
            None => (false, raw_auth),
        };
        let hb = hostport_raw.as_bytes();
        let hostport_end = if hb.first() == Some(&b'[') {
            if let Some(close_br) = hostport_raw.find(']') {
                let mut end = close_br + 1;
                if hb.get(end) == Some(&b':') {
                    end += 1;
                    while end < hb.len() && hb[end].is_ascii_digit() {
                        end += 1;
                    }
                }
                end
            } else {
                out.push_str(scheme);
                i = auth_start;
                continue;
            }
        } else {
            let mut end = 0usize;
            while end < hb.len() && !matches!(hb[end], b'(' | b')' | b'[' | b']' | b'{' | b'}') {
                end += 1;
            }
            end
        };
        let hostport = &hostport_raw[..hostport_end];
        if hostport.is_empty() || (hb.first() == Some(&b'[') && !ipv6_closed) {
            out.push_str(scheme);
            i = auth_start;
            continue;
        }

        out.push_str(scheme);
        if has_userinfo {
            out.push_str("[REDACTED:userinfo]@");
        }
        out.push_str(hostport);

        let host_abs_end = auth_end - (hostport_raw.len() - hostport_end);
        if host_abs_end < auth_end
            || !b.get(auth_end).is_some_and(|c| matches!(c, b'/' | b'?' | b'#'))
        {
            i = host_abs_end;
            continue;
        }

        let mut scan_end = auth_end;
        let mut scan_parens = 0usize;
        let mut scan_brackets = 0usize;
        while scan_end < b.len() {
            let ch = b[scan_end];
            if is_url_hard_stop(ch)
                || is_closing_single_quote_stop(b, scan_end, enclosing_sq, scan_parens, scan_brackets)
            {
                break;
            }
            match ch {
                b'(' => scan_parens += 1,
                b')' => scan_parens = scan_parens.saturating_sub(1),
                b'[' => scan_brackets += 1,
                b']' => scan_brackets = scan_brackets.saturating_sub(1),
                _ => {}
            }
            scan_end += 1;
        }
        let raw_tail = &text[auth_end..scan_end];
        let mut tail_end = raw_tail.len();
        if raw_tail
            .as_bytes()
            .last()
            .is_some_and(|c| matches!(c, b']' | b')' | b'}'))
        {
            let (mut open_br, mut close_br) = (0usize, 0usize);
            let (mut open_par, mut close_par) = (0usize, 0usize);
            let (mut open_cur, mut close_cur) = (0usize, 0usize);
            for &x in raw_tail.as_bytes() {
                match x {
                    b'[' => open_br += 1,
                    b']' => close_br += 1,
                    b'(' => open_par += 1,
                    b')' => close_par += 1,
                    b'{' => open_cur += 1,
                    b'}' => close_cur += 1,
                    _ => {}
                }
            }
            while tail_end > 0 {
                match raw_tail.as_bytes()[tail_end - 1] {
                    b']' if close_br > open_br => {
                        tail_end -= 1;
                        close_br -= 1;
                    }
                    b')' if close_par > open_par => {
                        tail_end -= 1;
                        close_par -= 1;
                    }
                    b'}' if close_cur > open_cur => {
                        tail_end -= 1;
                        close_cur -= 1;
                    }
                    _ => break,
                }
            }
        }
        if tail_end > 0 {
            out.push_str("/[REDACTED:url]");
        }
        out.push_str(&raw_tail[tail_end..]);
        i = scan_end;
    }
    out
}

fn raw_credential_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)^\s*(?:export\s+|set\s+|\$env:)?["']?[A-Z0-9_.-]*(?:API[_-]?KEY|SECRET|TOKEN|PASS(?:WORD|WD)?|AUTHORIZATION|COOKIE|CREDENTIAL|WEBHOOK)["']?\s*[:=]"#,
        )
        .expect("raw_credential_line_re")
    })
}

pub fn redact_secrets(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    let mut out = text.to_string();
    for pat in extra_redaction_patterns() {
        if pat.label == "url_secret_param" {
            out = pat
                .regex
                .replace_all(&out, "${1}[REDACTED:url_secret_param]")
                .into_owned();
        } else if pat.label == "quoted_credential_header" {
            out = pat
                .regex
                .replace_all(&out, "[REDACTED:credential_header]")
                .into_owned();
        } else if matches!(pat.label, "full_credential_header" | "credential_header") {
            out = pat
                .regex
                .replace_all(&out, |caps: &regex::Captures<'_>| {
                    let m = caps.get(0).map(|g| g.as_str()).unwrap_or("");
                    if let Some(first) = m.chars().next() {
                        if !first.is_ascii_alphanumeric() && first != '"' && first != '\'' {
                            return format!("{}[REDACTED:credential_header]", first);
                        }
                    }
                    "[REDACTED:credential_header]".to_string()
                })
                .into_owned();
        } else {
            let repl = format!("[REDACTED:{}]", pat.label);
            out = pat.regex.replace_all(&out, repl.as_str()).into_owned();
        }
    }
    for pat in secret_patterns() {
        let label = pat.label;
        out = pat
            .regex
            .replace_all(&out, |caps: &regex::Captures<'_>| {
                let m = caps.get(0).map(|g| g.as_str()).unwrap_or("");
                if label == "secret_assignment" {
                    if let Some(first) = m.chars().next() {
                        if !first.is_ascii_alphanumeric() {
                            return format!("{}[REDACTED:{}]", first, label);
                        }
                    }
                }
                format!("[REDACTED:{}]", label)
            })
            .into_owned();
    }
    out
}

pub fn sanitize_external_charter(text: &str) -> String {
    if text.trim().is_empty() {
        return String::new();
    }
    // INVARIANT: Strip raw credential lines, structurally sanitize every URL to origin (removing `userinfo@`, `/path`, `?query`, `#fragment`), and redact full credential headers before sending charter text externally.
    let kept: Vec<&str> = text
        .lines()
        .filter(|ln| !raw_credential_line_re().is_match(ln))
        .collect();
    let joined = kept.join("\n");
    let no_url_paths = sanitize_urls_in_text(&joined);
    redact_secrets(&no_url_paths)
}

fn recall_token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[A-Za-zА-Яа-яЁё0-9_]{2,}").expect("recall_token_re"))
}

fn eprintln_line(msg: &str) {
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(msg.as_bytes());
    let _ = err.write_all(b"\n");
    let _ = err.flush();
}

fn sha256_hex_12(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let full = hex::encode(hasher.finalize());
    full[..12].to_string()
}

fn effective_cwd_arg(cwd: &str) -> String {
    if cwd.trim().is_empty() {
        env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default()
    } else {
        cwd.to_string()
    }
}

pub fn memory_db_path() -> PathBuf {
    let dir = rio::state_dir().join("memory");
    let _ = fs::create_dir_all(&dir);
    dir.join("memory.db")
}

pub fn nlm_export_dir() -> PathBuf {
    let dir = rio::state_dir().join("memory").join("nlm_export");
    let _ = fs::create_dir_all(&dir);
    dir
}

fn which_binary(names: &[&str]) -> Option<String> {
    for name in names {
        if let Some(found) = rio::which_in_path(name) {
            return Some(found);
        }
    }
    None
}

pub fn detect_external_nlm_bridge() -> Value {
    let cli = which_binary(&["nlm-memory", "nlm-memory.cmd"]);
    let codex_bridge = rio::home_dir().join(".codex").join("notebooklm-sync");
    let codex_exists = codex_bridge.exists();
    let available = cli.is_some() || codex_exists;
    json!({
        "nlm_memory_cli": cli,
        "codex_nlm_bridge_exists": codex_exists,
        "available": available,
    })
}

pub fn scan_for_secrets(text: &str) -> Option<&'static str> {
    if text.is_empty() {
        return None;
    }
    for pat in secret_patterns() {
        if pat.regex.is_match(text) {
            return Some(pat.label);
        }
    }
    None
}

fn connect_ro(db_file: &Path) -> Result<SqliteConn, String> {
    let conn = SqliteConn::open(db_file, SQLITE_OPEN_READONLY)?;
    conn.set_busy_timeout(10_000);
    Ok(conn)
}

pub fn connect_db(read_only: bool) -> Result<SqliteConn, String> {
    let db_file = memory_db_path();
    if read_only {
        return connect_ro(&db_file);
    }
    let conn = SqliteConn::open(&db_file, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE)?;
    conn.set_busy_timeout(10_000);
    if conn
        .exec_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
        .is_err()
    {
        drop(conn);
        return connect_ro(&db_file);
    }
    conn.exec_batch(
        "CREATE TABLE IF NOT EXISTS memories (
            id TEXT PRIMARY KEY,
            scope TEXT NOT NULL,
            project_key TEXT NOT NULL,
            category TEXT NOT NULL,
            content TEXT NOT NULL,
            evidence TEXT NOT NULL DEFAULT '',
            tags TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'ACTIVE',
            superseded_by TEXT NOT NULL DEFAULT '',
            created_ts REAL NOT NULL,
            updated_ts REAL NOT NULL
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
            id UNINDEXED,
            category,
            content,
            tags,
            evidence
        );",
    )?;
    Ok(conn)
}

fn row_to_memory_json(row: &[SqlVal]) -> Value {
    json!({
        "id": row.first().map(SqlVal::as_str).unwrap_or_default(),
        "scope": row.get(1).map(SqlVal::as_str).unwrap_or_default(),
        "project_key": row.get(2).map(SqlVal::as_str).unwrap_or_default(),
        "category": row.get(3).map(SqlVal::as_str).unwrap_or_default(),
        "content": row.get(4).map(SqlVal::as_str).unwrap_or_default(),
        "evidence": row.get(5).map(SqlVal::as_str).unwrap_or_default(),
        "tags": row.get(6).map(SqlVal::as_str).unwrap_or_default(),
        "status": row.get(7).map(SqlVal::as_str).unwrap_or_default(),
        "superseded_by": row.get(8).map(SqlVal::as_str).unwrap_or_default(),
        "created_ts": row.get(9).map(SqlVal::as_f64).unwrap_or(0.0),
        "updated_ts": row.get(10).map(SqlVal::as_f64).unwrap_or(0.0),
    })
}

pub fn remember_entry(
    category: &str,
    content: &str,
    scope: &str,
    cwd: &str,
    evidence: &str,
    tags: &str,
) -> Result<Value, String> {
    let cat = category.trim().to_ascii_uppercase();
    if !VALID_CATEGORIES.contains(&cat.as_str()) {
        return Err(format!(
            "Invalid category '{}'. Must be one of: {}",
            category,
            VALID_CATEGORIES.join(", ")
        ));
    }
    let body = content.trim();
    if body.chars().count() < 8 {
        return Err(
            "Memory content must be at least 8 characters of concrete engineering fact.".to_string(),
        );
    }

    let combined = format!("{}\n{}\n{}", body, evidence, tags);
    if let Some(secret_hit) = scan_for_secrets(&combined) {
        return Err(format!(
            "Secret guard rejected memory entry (matched pattern: {}). Never store credentials.",
            secret_hit
        ));
    }

    let sc = scope.trim().to_ascii_lowercase();
    if sc != "project" && sc != "global" {
        return Err("Scope must be 'project' or 'global'.".to_string());
    }
    let eff_cwd = effective_cwd_arg(cwd);
    let pkey = if sc == "global" {
        "global".to_string()
    } else {
        rio::project_key(&eff_cwd, &[], "", "")
    };
    let now = win32_sqlite::now_sec();
    let entry_id = format!("mem-{}", sha256_hex_12(&format!("{}|{}|{}", pkey, cat, body)));
    let ev_clean = evidence.trim().to_string();
    let tags_clean = tags.trim().to_string();

    let conn = connect_db(false)?;
    conn.exec_batch("BEGIN IMMEDIATE;")?;
    let res = (|| -> Result<bool, String> {
        let existing_rows = conn.query(
            "SELECT id, status FROM memories WHERE id = ?",
            &[SqlParam::Text(entry_id.clone())],
        )?;
        let existing = !existing_rows.is_empty();
        if existing {
            conn.execute(
                "UPDATE memories SET evidence = ?, tags = ?, status = 'ACTIVE', superseded_by = '', updated_ts = ? WHERE id = ?",
                &[
                    SqlParam::Text(ev_clean.clone()),
                    SqlParam::Text(tags_clean.clone()),
                    SqlParam::Float(now),
                    SqlParam::Text(entry_id.clone()),
                ],
            )?;
            conn.execute(
                "DELETE FROM memories_fts WHERE id = ?",
                &[SqlParam::Text(entry_id.clone())],
            )?;
        } else {
            conn.execute(
                "INSERT INTO memories (id, scope, project_key, category, content, evidence, tags, status, superseded_by, created_ts, updated_ts) VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', '', ?, ?)",
                &[
                    SqlParam::Text(entry_id.clone()),
                    SqlParam::Text(sc.clone()),
                    SqlParam::Text(pkey.clone()),
                    SqlParam::Text(cat.clone()),
                    SqlParam::Text(body.to_string()),
                    SqlParam::Text(ev_clean.clone()),
                    SqlParam::Text(tags_clean.clone()),
                    SqlParam::Float(now),
                    SqlParam::Float(now),
                ],
            )?;
        }
        conn.execute(
            "INSERT INTO memories_fts (id, category, content, tags, evidence) VALUES (?, ?, ?, ?, ?)",
            &[
                SqlParam::Text(entry_id.clone()),
                SqlParam::Text(cat.clone()),
                SqlParam::Text(body.to_string()),
                SqlParam::Text(tags_clean.clone()),
                SqlParam::Text(ev_clean.clone()),
            ],
        )?;
        Ok(existing)
    })();

    match res {
        Ok(existing) => {
            conn.exec_batch("COMMIT;")?;
            Ok(json!({
                "ok": true,
                "id": entry_id,
                "scope": sc,
                "project_key": pkey,
                "category": cat,
                "deduplicated": existing,
            }))
        }
        Err(e) => {
            let _ = conn.exec_batch("ROLLBACK;");
            Err(e)
        }
    }
}

pub fn supersede_entry(
    old_id: &str,
    new_content: &str,
    category: &str,
    cwd: &str,
    evidence: &str,
    tags: &str,
) -> Result<Value, String> {
    let now = win32_sqlite::now_sec();
    let old_clean = old_id.trim();
    let (row_scope, row_cat, row_tags) = {
        let conn = connect_db(false)?;
        let rows = conn.query(
            "SELECT scope, category, tags FROM memories WHERE id = ?",
            &[SqlParam::Text(old_clean.to_string())],
        )?;
        let Some(row) = rows.first() else {
            return Err(format!("Memory id '{}' not found.", old_id));
        };
        (
            row.first().map(SqlVal::as_str).unwrap_or_default(),
            row.get(1).map(SqlVal::as_str).unwrap_or_default(),
            row.get(2).map(SqlVal::as_str).unwrap_or_default(),
        )
    };

    let mut replacement_id = String::new();
    if !new_content.trim().is_empty() {
        let eff_cat = if category.trim().is_empty() {
            row_cat.as_str()
        } else {
            category
        };
        let eff_tags = if tags.trim().is_empty() {
            row_tags.as_str()
        } else {
            tags
        };
        let eff_cwd = effective_cwd_arg(cwd);
        let res = remember_entry(eff_cat, new_content, &row_scope, &eff_cwd, evidence, eff_tags)?;
        replacement_id = res
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
    }

    let conn = connect_db(false)?;
    conn.exec_batch("BEGIN IMMEDIATE;")?;
    let sup_target = if replacement_id.is_empty() {
        "retired".to_string()
    } else {
        replacement_id.clone()
    };
    let upd_res = (|| -> Result<(), String> {
        conn.execute(
            "UPDATE memories SET status = 'SUPERSEDED', superseded_by = ?, updated_ts = ? WHERE id = ?",
            &[
                SqlParam::Text(sup_target),
                SqlParam::Float(now),
                SqlParam::Text(old_clean.to_string()),
            ],
        )?;
        conn.execute(
            "DELETE FROM memories_fts WHERE id = ?",
            &[SqlParam::Text(old_clean.to_string())],
        )?;
        Ok(())
    })();
    match upd_res {
        Ok(()) => {
            conn.exec_batch("COMMIT;")?;
            Ok(json!({
                "ok": true,
                "superseded_id": old_clean,
                "replacement_id": replacement_id,
            }))
        }
        Err(e) => {
            let _ = conn.exec_batch("ROLLBACK;");
            Err(e)
        }
    }
}

pub fn recall_entries(
    query: &str,
    cwd: &str,
    limit: i64,
    include_superseded: bool,
) -> Result<Vec<Value>, String> {
    let eff_cwd = effective_cwd_arg(cwd);
    let pkey = rio::project_key(&eff_cwd, &[], "", "");
    let status_clause = if include_superseded {
        ""
    } else {
        "AND m.status = 'ACTIVE'"
    };
    let conn = connect_db(false)?;
    let mut rows: Vec<Vec<SqlVal>> = Vec::new();

    let tokens: Vec<String> = recall_token_re()
        .find_iter(query)
        .take(8)
        .map(|m| format!("\"{}\"", m.as_str()))
        .collect();
    if !tokens.is_empty() && !include_superseded {
        let fts_q = tokens.join(" OR ");
        let sql = format!(
            "SELECT m.id, m.scope, m.project_key, m.category, m.content, m.evidence, m.tags, m.status, m.superseded_by, m.created_ts, m.updated_ts
             FROM memories_fts f
             JOIN memories m ON m.id = f.id
             WHERE memories_fts MATCH ?
               AND m.project_key IN (?, 'global')
               {}
             ORDER BY bm25(memories_fts), m.updated_ts DESC
             LIMIT ?",
            status_clause
        );
        rows = conn.query(
            &sql,
            &[
                SqlParam::Text(fts_q),
                SqlParam::Text(pkey.clone()),
                SqlParam::Int(limit),
            ],
        )?;
    }

    if rows.is_empty() {
        let sql_recent = format!(
            "SELECT m.id, m.scope, m.project_key, m.category, m.content, m.evidence, m.tags, m.status, m.superseded_by, m.created_ts, m.updated_ts
             FROM memories m
             WHERE m.project_key IN (?, 'global')
               {}
             ORDER BY CASE WHEN m.project_key = ? THEN 0 ELSE 1 END, m.updated_ts DESC
             LIMIT ?",
            status_clause
        );
        rows = conn.query(
            &sql_recent,
            &[
                SqlParam::Text(pkey.clone()),
                SqlParam::Text(pkey),
                SqlParam::Int(limit),
            ],
        )?;
    }

    Ok(rows.iter().map(|r| row_to_memory_json(r)).collect())
}

pub fn startup_memory_card(cwd: &str, limit: i64) -> String {
    let Ok(items) = recall_entries("", cwd, limit, false) else {
        return String::new();
    };
    if items.is_empty() {
        return String::new();
    }
    let mut lines = vec!["[Project Memory] Подтверждённые инженерные факты проекта:".to_string()];
    for item in items {
        let scope_tag = if item.get("scope").and_then(|v| v.as_str()) == Some("global") {
            "global"
        } else {
            "project"
        };
        let cat = item.get("category").and_then(|v| v.as_str()).unwrap_or("");
        let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let content = item.get("content").and_then(|v| v.as_str()).unwrap_or("");
        lines.push(format!("- [{}] ({}, {}) {}", cat, id, scope_tag, content));
    }
    lines.join("\n")
}

pub fn export_notebooklm_bundle(cwd: &str) -> Result<Value, String> {
    let pkey = if cwd.trim().is_empty() {
        String::new()
    } else {
        rio::project_key(cwd, &[], "", "")
    };
    let conn = connect_db(false)?;
    let rows = if !pkey.is_empty() {
        conn.query(
            "SELECT id, scope, project_key, category, content, evidence, tags, status, superseded_by, created_ts, updated_ts FROM memories WHERE project_key IN (?, 'global') ORDER BY status ASC, updated_ts DESC",
            &[SqlParam::Text(pkey.clone())],
        )?
    } else {
        conn.query(
            "SELECT id, scope, project_key, category, content, evidence, tags, status, superseded_by, created_ts, updated_ts FROM memories ORDER BY project_key, status ASC, updated_ts DESC",
            &[],
        )?
    };

    let target_name = format!(
        "{}.md",
        if pkey.is_empty() {
            "all-projects"
        } else {
            pkey.as_str()
        }
    );
    let out_path = nlm_export_dir().join(target_name);
    let items: Vec<Value> = rows.iter().map(|r| row_to_memory_json(r)).collect();
    let active: Vec<&Value> = items
        .iter()
        .filter(|r| r.get("status").and_then(|v| v.as_str()) == Some("ACTIVE"))
        .collect();
    let superseded: Vec<&Value> = items
        .iter()
        .filter(|r| r.get("status").and_then(|v| v.as_str()) != Some("ACTIVE"))
        .collect();

    let exported_utc = win32_sqlite::format_iso_utc(win32_sqlite::now_sec());
    let header_key = if pkey.is_empty() { "all" } else { pkey.as_str() };
    let mut md_lines = vec![
        format!("# Gemini Carbon Engineering Memory Export ({})", header_key),
        String::new(),
        format!("- Exported UTC: {}", exported_utc),
        format!("- Active entries: {}", active.len()),
        format!("- Superseded entries: {}", superseded.len()),
        "- External NotebookLM sync status: local export only (external `nlm-memory` bridge not installed; not synced remotely).".to_string(),
        String::new(),
        "## Active Engineering Facts".to_string(),
        String::new(),
    ];

    for r in &active {
        let cat = r.get("category").and_then(|v| v.as_str()).unwrap_or("");
        let id = r.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let scope = r.get("scope").and_then(|v| v.as_str()).unwrap_or("");
        let content = r.get("content").and_then(|v| v.as_str()).unwrap_or("");
        let evidence = r.get("evidence").and_then(|v| v.as_str()).unwrap_or("");
        let tags = r.get("tags").and_then(|v| v.as_str()).unwrap_or("");
        md_lines.push(format!("### [{}] `{}` ({})", cat, id, scope));
        md_lines.push(content.to_string());
        if !evidence.is_empty() {
            md_lines.push(format!("- Evidence: {}", evidence));
        }
        if !tags.is_empty() {
            md_lines.push(format!("- Tags: {}", tags));
        }
        md_lines.push(String::new());
    }

    if !superseded.is_empty() {
        md_lines.push("## Superseded / Retired (Do Not Resurface)".to_string());
        md_lines.push(String::new());
        for r in &superseded {
            let id = r.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let cat = r.get("category").and_then(|v| v.as_str()).unwrap_or("");
            let sup_by = r.get("superseded_by").and_then(|v| v.as_str()).unwrap_or("");
            let content = r.get("content").and_then(|v| v.as_str()).unwrap_or("");
            md_lines.push(format!("- `{}` [{}] -> `{}`: ~~{}~~", id, cat, sup_by, content));
        }
        md_lines.push(String::new());
    }

    fs::write(&out_path, md_lines.join("\n")).map_err(|e| e.to_string())?;
    let bridge = detect_external_nlm_bridge();
    Ok(json!({
        "ok": true,
        "export_path": out_path.to_string_lossy().into_owned(),
        "active_count": active.len(),
        "superseded_count": superseded.len(),
        "external_nlm_bridge": bridge,
    }))
}

pub fn memory_stats(cwd: &str) -> Value {
    let eff_cwd = effective_cwd_arg(cwd);
    let pkey = rio::project_key(&eff_cwd, &[], "", "");
    let db_file = memory_db_path();
    let res = (|| -> Result<(i64, i64, i64), String> {
        let conn = connect_db(false)?;
        let total = conn
            .query("SELECT COUNT(*) AS c FROM memories", &[])?
            .first()
            .and_then(|r| r.first())
            .map(SqlVal::as_i64)
            .unwrap_or(0);
        let active = conn
            .query("SELECT COUNT(*) AS c FROM memories WHERE status = 'ACTIVE'", &[])?
            .first()
            .and_then(|r| r.first())
            .map(SqlVal::as_i64)
            .unwrap_or(0);
        let proj_active = conn
            .query(
                "SELECT COUNT(*) AS c FROM memories WHERE status = 'ACTIVE' AND project_key = ?",
                &[SqlParam::Text(pkey.clone())],
            )?
            .first()
            .and_then(|r| r.first())
            .map(SqlVal::as_i64)
            .unwrap_or(0);
        Ok((total, active, proj_active))
    })();

    match res {
        Ok((total, active, proj_active)) => json!({
            "db_path": db_file.to_string_lossy().into_owned(),
            "project_key": pkey,
            "total_entries": total,
            "active_entries": active,
            "project_active_entries": proj_active,
            "external_nlm_bridge": detect_external_nlm_bridge(),
        }),
        Err(exc) => json!({
            "db_path": db_file.to_string_lossy().into_owned(),
            "project_key": pkey,
            "total_entries": 0,
            "active_entries": 0,
            "project_active_entries": 0,
            "read_only_fallback": true,
            "error": exc,
            "external_nlm_bridge": detect_external_nlm_bridge(),
        }),
    }
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
            "usage: carbon_memory <remember|supersede|recall|export-nlm|stats|doctor> [options]",
        );
        return 2;
    }
    match args[0].as_str() {
        "-h" | "--help" => {
            eprintln_line(
                "usage: carbon_memory <remember|supersede|recall|export-nlm|stats|doctor> [options]",
            );
            0
        }
        "remember" => {
            let mut category: Option<String> = None;
            let mut text: Option<String> = None;
            let mut scope = "project".to_string();
            let mut evidence = String::new();
            let mut tags = String::new();
            let mut cwd = String::new();
            let mut i = 1usize;
            while i < args.len() {
                let a = args[i].as_str();
                if a == "--category" || a.starts_with("--category=") {
                    match take_flag_value(args, &mut i, "--category") {
                        Ok(v) => category = Some(v),
                        Err(e) => {
                            eprintln_line(&format!("carbon_memory remember: {}", e));
                            return 2;
                        }
                    }
                } else if a == "--text" || a.starts_with("--text=") {
                    match take_flag_value(args, &mut i, "--text") {
                        Ok(v) => text = Some(v),
                        Err(e) => {
                            eprintln_line(&format!("carbon_memory remember: {}", e));
                            return 2;
                        }
                    }
                } else if a == "--scope" || a.starts_with("--scope=") {
                    match take_flag_value(args, &mut i, "--scope") {
                        Ok(v) => scope = v,
                        Err(e) => {
                            eprintln_line(&format!("carbon_memory remember: {}", e));
                            return 2;
                        }
                    }
                } else if a == "--evidence" || a.starts_with("--evidence=") {
                    match take_flag_value(args, &mut i, "--evidence") {
                        Ok(v) => evidence = v,
                        Err(e) => {
                            eprintln_line(&format!("carbon_memory remember: {}", e));
                            return 2;
                        }
                    }
                } else if a == "--tags" || a.starts_with("--tags=") {
                    match take_flag_value(args, &mut i, "--tags") {
                        Ok(v) => tags = v,
                        Err(e) => {
                            eprintln_line(&format!("carbon_memory remember: {}", e));
                            return 2;
                        }
                    }
                } else if a == "--cwd" || a.starts_with("--cwd=") {
                    match take_flag_value(args, &mut i, "--cwd") {
                        Ok(v) => cwd = v,
                        Err(e) => {
                            eprintln_line(&format!("carbon_memory remember: {}", e));
                            return 2;
                        }
                    }
                } else {
                    eprintln_line(&format!("carbon_memory remember: unrecognized argument {}", a));
                    return 2;
                }
                i += 1;
            }
            let (Some(cat), Some(txt)) = (category, text) else {
                eprintln_line("carbon_memory remember: --category and --text are required");
                return 2;
            };
            match remember_entry(&cat, &txt, &scope, &cwd, &evidence, &tags) {
                Ok(res) => {
                    rio::print_cli_json(&res, true);
                    0
                }
                Err(ve) => {
                    eprintln_line(&format!("[carbon_memory] {}", ve));
                    2
                }
            }
        }
        "supersede" => {
            let mut old_id: Option<String> = None;
            let mut text = String::new();
            let mut category = String::new();
            let mut evidence = String::new();
            let mut tags = String::new();
            let mut cwd = String::new();
            let mut i = 1usize;
            while i < args.len() {
                let a = args[i].as_str();
                if a == "--id" || a.starts_with("--id=") {
                    match take_flag_value(args, &mut i, "--id") {
                        Ok(v) => old_id = Some(v),
                        Err(e) => {
                            eprintln_line(&format!("carbon_memory supersede: {}", e));
                            return 2;
                        }
                    }
                } else if a == "--text" || a.starts_with("--text=") {
                    match take_flag_value(args, &mut i, "--text") {
                        Ok(v) => text = v,
                        Err(e) => {
                            eprintln_line(&format!("carbon_memory supersede: {}", e));
                            return 2;
                        }
                    }
                } else if a == "--category" || a.starts_with("--category=") {
                    match take_flag_value(args, &mut i, "--category") {
                        Ok(v) => category = v,
                        Err(e) => {
                            eprintln_line(&format!("carbon_memory supersede: {}", e));
                            return 2;
                        }
                    }
                } else if a == "--evidence" || a.starts_with("--evidence=") {
                    match take_flag_value(args, &mut i, "--evidence") {
                        Ok(v) => evidence = v,
                        Err(e) => {
                            eprintln_line(&format!("carbon_memory supersede: {}", e));
                            return 2;
                        }
                    }
                } else if a == "--tags" || a.starts_with("--tags=") {
                    match take_flag_value(args, &mut i, "--tags") {
                        Ok(v) => tags = v,
                        Err(e) => {
                            eprintln_line(&format!("carbon_memory supersede: {}", e));
                            return 2;
                        }
                    }
                } else if a == "--cwd" || a.starts_with("--cwd=") {
                    match take_flag_value(args, &mut i, "--cwd") {
                        Ok(v) => cwd = v,
                        Err(e) => {
                            eprintln_line(&format!("carbon_memory supersede: {}", e));
                            return 2;
                        }
                    }
                } else {
                    eprintln_line(&format!("carbon_memory supersede: unrecognized argument {}", a));
                    return 2;
                }
                i += 1;
            }
            let Some(oid) = old_id else {
                eprintln_line("carbon_memory supersede: --id is required");
                return 2;
            };
            match supersede_entry(&oid, &text, &category, &cwd, &evidence, &tags) {
                Ok(res) => {
                    rio::print_cli_json(&res, true);
                    0
                }
                Err(ve) => {
                    eprintln_line(&format!("[carbon_memory] {}", ve));
                    2
                }
            }
        }
        "recall" => {
            let mut query = String::new();
            let mut limit: i64 = 8;
            let mut include_superseded = false;
            let mut cwd = String::new();
            let mut i = 1usize;
            while i < args.len() {
                let a = args[i].as_str();
                if a == "--include-superseded" {
                    include_superseded = true;
                } else if a == "--query" || a.starts_with("--query=") {
                    match take_flag_value(args, &mut i, "--query") {
                        Ok(v) => query = v,
                        Err(e) => {
                            eprintln_line(&format!("carbon_memory recall: {}", e));
                            return 2;
                        }
                    }
                } else if a == "--limit" || a.starts_with("--limit=") {
                    match take_flag_value(args, &mut i, "--limit") {
                        Ok(v) => match v.trim().parse::<i64>() {
                            Ok(n) => limit = n,
                            Err(_) => {
                                eprintln_line(&format!(
                                    "carbon_memory recall: invalid --limit '{}'",
                                    v
                                ));
                                return 2;
                            }
                        },
                        Err(e) => {
                            eprintln_line(&format!("carbon_memory recall: {}", e));
                            return 2;
                        }
                    }
                } else if a == "--cwd" || a.starts_with("--cwd=") {
                    match take_flag_value(args, &mut i, "--cwd") {
                        Ok(v) => cwd = v,
                        Err(e) => {
                            eprintln_line(&format!("carbon_memory recall: {}", e));
                            return 2;
                        }
                    }
                } else {
                    eprintln_line(&format!("carbon_memory recall: unrecognized argument {}", a));
                    return 2;
                }
                i += 1;
            }
            match recall_entries(&query, &cwd, limit, include_superseded) {
                Ok(items) => {
                    rio::print_cli_json(
                        &json!({"count": items.len(), "entries": items}),
                        true,
                    );
                    0
                }
                Err(ve) => {
                    eprintln_line(&format!("[carbon_memory] {}", ve));
                    2
                }
            }
        }
        "export-nlm" => {
            let mut cwd = String::new();
            let mut i = 1usize;
            while i < args.len() {
                let a = args[i].as_str();
                if a == "--cwd" || a.starts_with("--cwd=") {
                    match take_flag_value(args, &mut i, "--cwd") {
                        Ok(v) => cwd = v,
                        Err(e) => {
                            eprintln_line(&format!("carbon_memory export-nlm: {}", e));
                            return 2;
                        }
                    }
                } else {
                    eprintln_line(&format!("carbon_memory export-nlm: unrecognized argument {}", a));
                    return 2;
                }
                i += 1;
            }
            match export_notebooklm_bundle(&cwd) {
                Ok(res) => {
                    rio::print_cli_json(&res, true);
                    0
                }
                Err(ve) => {
                    eprintln_line(&format!("[carbon_memory] {}", ve));
                    2
                }
            }
        }
        "stats" => {
            let mut cwd = String::new();
            let mut i = 1usize;
            while i < args.len() {
                let a = args[i].as_str();
                if a == "--cwd" || a.starts_with("--cwd=") {
                    match take_flag_value(args, &mut i, "--cwd") {
                        Ok(v) => cwd = v,
                        Err(e) => {
                            eprintln_line(&format!("carbon_memory stats: {}", e));
                            return 2;
                        }
                    }
                } else {
                    eprintln_line(&format!("carbon_memory stats: unrecognized argument {}", a));
                    return 2;
                }
                i += 1;
            }
            let mut info = memory_stats(&cwd);
            if let Some(obj) = info.as_object_mut() {
                obj.insert(
                    "secret_guard_ok".to_string(),
                    Value::Bool(
                        scan_for_secrets("api_key=sk-live-1234567890abcdefghijklmnop").is_some(),
                    ),
                );
            }
            rio::print_cli_json(&info, true);
            0
        }
        "doctor" => {
            if args.len() > 1 {
                eprintln_line(&format!(
                    "carbon_memory doctor: unrecognized argument {}",
                    args[1]
                ));
                return 2;
            }
            let mut info = memory_stats("");
            if let Some(obj) = info.as_object_mut() {
                obj.insert(
                    "secret_guard_ok".to_string(),
                    Value::Bool(
                        scan_for_secrets("api_key=sk-live-1234567890abcdefghijklmnop").is_some(),
                    ),
                );
            }
            rio::print_cli_json(&info, true);
            0
        }
        other => {
            eprintln_line(&format!("carbon_memory: unknown subcommand '{}'", other));
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
    fn test_all_regexes_compile() {
        let pats = secret_patterns();
        assert_eq!(pats.len(), 13);
        assert!(recall_token_re().is_match("FTS5 индексация memory_db"));
        for leak in [
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "DATABASE_PASSWORD=SuperSecretValue123",
            "GEMINI_API_KEY=abcdefghijklmnop1234",
            "password=Hunter2!xyz$abcdef",
            r#"{"password": "SuperSecretValue123"}"#,
            r#""api_key": "abcdefghijklmnop1234""#,
            "PGPASSWORD=SuperSecretValue123",
            "HF_TOKEN=hf_abcdefghijklmnopqrstu",
            "STRIPE_SECRET=sk_live_abcdefghijklmnop",
            "DB_PASS=SuperSecretValue123",
            "TELEGRAM_BOT_TOKEN=123456789:ABCdefghijklmnopqrstuvwxyz123456",
            "https://admin:hunter22@db.example.com/prod",
            "-----BEGIN RSA PRIVATE KEY-----",
            "AKIAIOSFODNN7EXAMPLE",
        ] {
            assert!(
                scan_for_secrets(leak).is_some(),
                "expected secret match for: {}",
                leak
            );
        }
        assert_eq!(
            scan_for_secrets("Use sqlite WAL mode with busy_timeout=10000 for concurrent readers."),
            None
        );
    }

    #[test]
    fn test_fts5_store_recall_supersede_and_export_nlm() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp_home = make_temp_dir("cmem-home");
        let proj_dir = make_temp_dir("cmem-proj");
        let prev = env::var_os("CARBON_STACK_HOME");
        env::set_var("CARBON_STACK_HOME", &tmp_home);

        let proj_s = proj_dir.to_string_lossy().into_owned();

        // INVARIANT: Verify secret guard rejects credentials before touching SQLite.
        let secret_err = remember_entry(
            "GOTCHA",
            "Never hardcode api_key=sk-live-1234567890abcdefghijklmnop in tests",
            "project",
            &proj_s,
            "",
            "",
        )
        .unwrap_err();
        assert!(secret_err.contains("Secret guard rejected"));

        let stored = remember_entry(
            "DECISION",
            "Always run cargo test inside win32 job wrapper on Windows",
            "project",
            &proj_s,
            "rust/src/win32_sqlite.rs",
            "windows,sqlite",
        )
        .unwrap();
        assert_eq!(stored["ok"], json!(true));
        assert_eq!(stored["deduplicated"], json!(false));
        let mem_id = stored["id"].as_str().unwrap().to_string();

        let dedup = remember_entry(
            "DECISION",
            "Always run cargo test inside win32 job wrapper on Windows",
            "project",
            &proj_s,
            "rust/src/win32_sqlite.rs",
            "windows,sqlite,updated",
        )
        .unwrap();
        assert_eq!(dedup["deduplicated"], json!(true));
        assert_eq!(dedup["id"], json!(mem_id));

        let global_mem = remember_entry(
            "CONSTRAINT",
            "All Rust comments must begin with INVARIANT, SAFETY, or WORKAROUND",
            "global",
            &proj_s,
            "swarm brief",
            "hygiene",
        )
        .unwrap();
        assert_eq!(global_mem["scope"], json!("global"));

        let found = recall_entries("win32 job wrapper", &proj_s, 8, false).unwrap();
        assert!(!found.is_empty());
        assert_eq!(found[0]["id"], json!(mem_id));

        let card = startup_memory_card(&proj_s, 5);
        assert!(card.contains("[Project Memory]"));
        assert!(card.contains(&mem_id));

        let sup = supersede_entry(
            &mem_id,
            "Run cargo test with --test-threads=1 when sqlite temp dirs collide",
            "GOTCHA",
            &proj_s,
            "ci log",
            "",
        )
        .unwrap();
        assert_eq!(sup["ok"], json!(true));
        assert_eq!(sup["superseded_id"], json!(mem_id));
        let rep_id = sup["replacement_id"].as_str().unwrap().to_string();
        assert!(!rep_id.is_empty());

        let active_after = recall_entries("win32 job wrapper", &proj_s, 8, false).unwrap();
        assert!(active_after.iter().all(|e| e["id"] != json!(mem_id)));

        let with_sup = recall_entries("", &proj_s, 8, true).unwrap();
        assert!(with_sup.iter().any(|e| e["id"] == json!(mem_id) && e["status"] == json!("SUPERSEDED")));

        let exported = export_notebooklm_bundle(&proj_s).unwrap();
        assert_eq!(exported["ok"], json!(true));
        assert_eq!(exported["active_count"], json!(2));
        assert_eq!(exported["superseded_count"], json!(1));
        let exp_path = PathBuf::from(exported["export_path"].as_str().unwrap());
        let md = fs::read_to_string(&exp_path).unwrap();
        assert!(md.contains("## Active Engineering Facts"));
        assert!(md.contains("## Superseded / Retired"));
        assert!(md.contains(&mem_id));
        assert!(md.contains(&rep_id));

        let st = memory_stats(&proj_s);
        assert_eq!(st["total_entries"], json!(3));
        assert_eq!(st["active_entries"], json!(2));
        assert_eq!(st["project_active_entries"], json!(1));

        assert_eq!(
            run_cli(&[
                "recall".to_string(),
                format!("--cwd={}", proj_s),
                "--limit=4".to_string(),
            ]),
            0
        );
        assert_eq!(run_cli(&["doctor".to_string()]), 0);

        match prev {
            Some(v) => env::set_var("CARBON_STACK_HOME", v),
            None => env::remove_var("CARBON_STACK_HOME"),
        }
        let _ = fs::remove_dir_all(&tmp_home);
        let _ = fs::remove_dir_all(&proj_dir);
    }
}
