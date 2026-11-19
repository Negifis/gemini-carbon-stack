use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

use crate::rio;
use crate::win32_sqlite::{
    SqlParam, SqliteConn, SQLITE_OPEN_CREATE, SQLITE_OPEN_READONLY, SQLITE_OPEN_READWRITE,
};

const SYNTHETIC_CONTINUATION_PREFIX: &str =
    "This session is being continued from a previous conversation";

const MAX_RESPONSE_CHARS: usize = 32_000;
const MAX_THINKING_CHARS: usize = 12_000;
const CHECKPOINT_TURN_THRESHOLD: usize = 16;
const CHECKPOINT_CHAR_THRESHOLD: usize = 35_000;
const KEEP_RECENT_TURNS_AFTER_CHECKPOINT: usize = 6;

const EXCLUDED_SINGLE_PROMPTS: &[&str] = &[
    "Say exactly: PONG",
    "Reply with exactly: PONG",
    "Ответь ровно одним словом: готов",
    "Ответь одним словом по-русски: столица Франции?",
    "тест",
];

// INVARIANT: Deterministic UUIDv5 namespace guarantees idempotent trajectory/step IDs across re-runs.
const NS_IMPORT_BYTES: [u8; 16] = [
    0xa4, 0xb8, 0xf1, 0x9c, 0x7d, 0x3e, 0x4b, 0x2a,
    0x9f, 0x1c, 0x6e, 0x5d, 0x4c, 0x3b, 0x2a, 0x10,
];

fn excluded_project_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(-bench$|-shim$|-scratchpad)").expect("excluded_project_re"))
}

fn shim_prompt_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^<<SYSTEM>>\s+Ты\s+—").expect("shim_prompt_re"))
}

fn home_proj_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z]--Users-[^-]+$").expect("home_proj_re"))
}

fn drive_prefix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z]--").expect("drive_prefix_re"))
}

fn drive_cwd_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^([A-Za-z])--(.+)$").expect("drive_cwd_re"))
}

fn html_tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"<[^>]+>").expect("html_tag_re"))
}

fn ws_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\s+").expect("ws_re"))
}

fn iso_frac_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\.(\d+)").expect("iso_frac_re"))
}

pub fn default_claude_projects_dir() -> PathBuf {
    rio::home_dir().join(".claude").join("projects")
}

pub fn default_antigravity_dir() -> PathBuf {
    rio::home_dir().join(".gemini").join("antigravity")
}

// INVARIANT: Self-contained RFC 3174 SHA-1 enables exact RFC 4122 UUIDv5 generation without extra crates.
pub fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, &word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn deterministic_uuid_bytes(seed: &str) -> [u8; 16] {
    let mut buf = Vec::with_capacity(16 + seed.len());
    buf.extend_from_slice(&NS_IMPORT_BYTES);
    buf.extend_from_slice(seed.as_bytes());
    let digest = sha1_digest(&buf);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out[6] = (out[6] & 0x0F) | 0x50;
    out[8] = (out[8] & 0x3F) | 0x80;
    out
}

pub fn deterministic_uuid(seed: &str) -> String {
    let h = hex::encode(deterministic_uuid_bytes(seed));
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

pub fn stable_uuid(seed: &str) -> String {
    deterministic_uuid(seed)
}

pub fn stable_hex32(seed: &str) -> String {
    hex::encode(deterministic_uuid_bytes(seed))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireValue {
    Varint(u64),
    Fixed64([u8; 8]),
    Bytes(Vec<u8>),
    Fixed32([u8; 4]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireField {
    pub fn_num: u32,
    pub wt: u8,
    pub val: WireValue,
}

pub fn encode_varint(value: i64) -> Vec<u8> {
    let mut v = value as u64;
    let mut out = Vec::new();
    loop {
        let b = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            out.push(b | 0x80);
        } else {
            out.push(b);
            break;
        }
    }
    out
}

pub fn decode_varint(buf: &[u8], pos: usize) -> Result<(u64, usize), String> {
    let mut res: u64 = 0;
    let mut shift: u32 = 0;
    let mut idx = pos;
    loop {
        if idx >= buf.len() {
            return Err(format!("Truncated varint at pos {}", idx));
        }
        let b = buf[idx];
        idx += 1;
        if shift >= 64 {
            return Err(format!("Varint overflow at pos {}", idx));
        }
        res |= ((b & 0x7F) as u64) << shift;
        if (b & 0x80) == 0 {
            return Ok((res, idx));
        }
        shift += 7;
    }
}

pub fn parse_varint_at(buf: &[u8], pos: usize) -> Result<(u64, usize), String> {
    decode_varint(buf, pos)
}

pub fn field_varint(fn_num: u32, value: i64, force: bool) -> Vec<u8> {
    if value == 0 && !force {
        return Vec::new();
    }
    let mut out = encode_varint(((fn_num as i64) << 3) | 0);
    out.extend(encode_varint(value));
    out
}

pub fn field_bool(fn_num: u32, value: bool, force: bool) -> Vec<u8> {
    field_varint(fn_num, if value { 1 } else { 0 }, force)
}

pub fn field_bytes(fn_num: u32, data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut out = encode_varint(((fn_num as i64) << 3) | 2);
    out.extend(encode_varint(data.len() as i64));
    out.extend_from_slice(data);
    out
}

pub fn field_str(fn_num: u32, text: &str) -> Vec<u8> {
    if text.is_empty() {
        return Vec::new();
    }
    field_bytes(fn_num, text.as_bytes())
}

pub fn ts_msg(sec: i64, nanos: i64) -> Vec<u8> {
    let mut out = field_varint(1, sec, false);
    out.extend(field_varint(2, nanos, false));
    out
}

pub fn encode_timestamp(sec: i64, nanos: i64) -> Vec<u8> {
    ts_msg(sec, nanos)
}

pub fn parse_wire_fields(buf: &[u8]) -> Result<Vec<WireField>, String> {
    let mut pos: usize = 0;
    let mut out: Vec<WireField> = Vec::new();
    while pos < buf.len() {
        let (tag, next_pos) = decode_varint(buf, pos)?;
        pos = next_pos;
        let fn_num = (tag >> 3) as u32;
        let wt = (tag & 7) as u8;
        let val = match wt {
            0 => {
                let (v, np) = decode_varint(buf, pos)?;
                pos = np;
                WireValue::Varint(v)
            }
            1 => {
                if pos + 8 > buf.len() {
                    return Err(format!("Truncated fixed64 at pos {}", pos));
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&buf[pos..pos + 8]);
                pos += 8;
                WireValue::Fixed64(arr)
            }
            2 => {
                let (ln_u64, np) = decode_varint(buf, pos)?;
                pos = np;
                let ln = ln_u64 as usize;
                if pos.checked_add(ln).map_or(true, |end| end > buf.len()) {
                    return Err(format!("Truncated length-delimited field at pos {}", pos));
                }
                let bytes = buf[pos..pos + ln].to_vec();
                pos += ln;
                WireValue::Bytes(bytes)
            }
            5 => {
                if pos + 4 > buf.len() {
                    return Err(format!("Truncated fixed32 at pos {}", pos));
                }
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&buf[pos..pos + 4]);
                pos += 4;
                WireValue::Fixed32(arr)
            }
            _ => return Err(format!("Unsupported wire type {} at pos {}", wt, pos)),
        };
        out.push(WireField { fn_num, wt, val });
    }
    Ok(out)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y_adj = y - if m <= 2 { 1 } else { 0 };
    let era = if y_adj >= 0 { y_adj } else { y_adj - 399 } / 400;
    let yoe = (y_adj - era * 400) as u32;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + (doe as i64) - 719468
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

fn utc_components(sec: i64) -> (i64, u32, u32, i64, i64, i64) {
    let days = sec.div_euclid(86400);
    let rem = sec.rem_euclid(86400);
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let s = rem % 60;
    let (year, month, day) = civil_from_days(days);
    (year, month, day, hour, min, s)
}

fn parse_iso_utc_sec_nanos(raw: &str) -> Option<(i64, i64)> {
    let s = raw.trim();
    let bytes = s.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || (bytes[10] != b'T' && bytes[10] != b't' && bytes[10] != b' ')
    {
        return None;
    }
    let year: i64 = s[0..4].parse().ok()?;
    let month: u32 = s[5..7].parse().ok()?;
    let day: u32 = s[8..10].parse().ok()?;
    let hour: i64 = s[11..13].parse().ok()?;
    let min: i64 = s[14..16].parse().ok()?;
    let sec: i64 = s[17..19].parse().ok()?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&min)
        || !(0..=60).contains(&sec)
    {
        return None;
    }

    let rest = &s[19..];
    let mut tz_part = rest;
    if let Some(after_dot) = rest.strip_prefix('.') {
        let digits_len = after_dot.bytes().take_while(|b| b.is_ascii_digit()).count();
        tz_part = &after_dot[digits_len..];
    }

    let tz_trim = tz_part.trim();
    let offset_secs: i64 = if tz_trim.is_empty() || tz_trim == "Z" || tz_trim == "z" {
        0
    } else {
        let sign: i64 = if tz_trim.starts_with('+') {
            1
        } else if tz_trim.starts_with('-') {
            -1
        } else {
            return None;
        };
        let off_body = &tz_trim[1..];
        let (oh_str, om_str) = if let Some((a, b)) = off_body.split_once(':') {
            (a, b)
        } else if off_body.len() == 4 {
            (&off_body[0..2], &off_body[2..4])
        } else if off_body.len() == 2 {
            (off_body, "00")
        } else {
            return None;
        };
        let oh: i64 = oh_str.parse().ok()?;
        let om: i64 = om_str.parse().ok()?;
        sign * (oh * 3600 + om * 60)
    };

    let nanos = if let Some(caps) = iso_frac_re().captures(raw) {
        let digits = caps.get(1).map_or("", |m| m.as_str());
        let mut padded = String::with_capacity(9);
        for ch in digits.chars().take(9) {
            padded.push(ch);
        }
        while padded.len() < 9 {
            padded.push('0');
        }
        padded.parse::<i64>().unwrap_or(0)
    } else {
        0
    };

    let days = days_from_civil(year, month, day);
    let epoch_secs = days * 86400 + hour * 3600 + min * 60 + sec - offset_secs;
    Some((epoch_secs, nanos.clamp(0, 999_999_999)))
}

pub fn parse_iso_timestamp(ts_str: Option<&str>, fallback_epoch: f64) -> (i64, i64) {
    if let Some(raw) = ts_str {
        if !raw.trim().is_empty() {
            if let Some(parsed) = parse_iso_utc_sec_nanos(raw) {
                return parsed;
            }
        }
    }
    let sec = fallback_epoch.trunc() as i64;
    let nanos = ((fallback_epoch - (sec as f64)) * 1_000_000_000.0) as i64;
    (sec, nanos.clamp(0, 999_999_999))
}

pub fn format_sqlite_datetime(sec: i64, nanos: i64) -> String {
    let (year, month, day, hour, min, s) = utc_components(sec);
    let ticks_7 = nanos / 100;
    if ticks_7 != 0 {
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:07}+00:00",
            year, month, day, hour, min, s, ticks_7
        )
    } else {
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}+00:00",
            year, month, day, hour, min, s
        )
    }
}

pub fn timestamp_to_epoch_ns(sec: i64, nanos: i64) -> i64 {
    sec.saturating_mul(1_000_000_000).saturating_add(nanos)
}

pub fn timestamp_to_iso_localish(sec: i64, _nanos: i64) -> String {
    let (year, month, day, hour, min, s) = utc_components(sec);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, min, s
    )
}

fn format_utc_date(sec: i64) -> String {
    let (year, month, day, _, _, _) = utc_components(sec);
    format!("{:04}-{:02}-{:02}", year, month, day)
}

fn char_len(s: &str) -> usize {
    s.chars().count()
}

fn slice_chars(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

#[derive(Debug, Clone)]
pub struct ToolInvocation {
    pub tool_id: String,
    pub name: String,
    pub arguments: Map<String, Value>,
    pub result_preview: String,
}

#[derive(Debug, Clone)]
pub struct ConversationTurn {
    pub user_uuid: String,
    pub user_text: String,
    pub user_ts: Option<String>,
    pub thinking_parts: Vec<String>,
    pub text_parts: Vec<String>,
    pub tool_calls: Vec<ToolInvocation>,
    pub first_assistant_ts: Option<String>,
    pub last_assistant_ts: Option<String>,
    pub is_continuation_summary: bool,
}

#[derive(Debug, Clone)]
pub struct ParsedSession {
    pub project_folder: String,
    pub filepath: PathBuf,
    pub session_id: String,
    pub raw_title: Option<String>,
    pub resolved_title: String,
    pub cwd: String,
    pub created_sec: i64,
    pub created_nanos: i64,
    pub last_mod_sec: i64,
    pub last_mod_nanos: i64,
    pub turns: Vec<ConversationTurn>,
    pub human_user_count: usize,
    pub assistant_record_count: usize,
    pub user_uuids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DbStep {
    pub idx: i64,
    pub step_type: i64,
    pub status: i64,
    pub metadata: Vec<u8>,
    pub step_payload: Vec<u8>,
}

pub fn clean_preview(text: &str, max_len: usize) -> String {
    let no_tags = html_tag_re().replace_all(text, " ");
    let collapsed = ws_re().replace_all(&no_tags, " ");
    let trimmed = collapsed.trim();
    if char_len(trimmed) > max_len {
        let cut = slice_chars(trimmed, max_len.saturating_sub(1)).trim_end();
        return format!("{}…", cut);
    }
    if trimmed.is_empty() {
        "Claude Code chat".to_string()
    } else {
        trimmed.to_string()
    }
}

fn json_val_to_display(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Null => "None".to_string(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

pub fn summarize_tool_args(args: &Map<String, Value>) -> String {
    if args.is_empty() {
        return "{}".to_string();
    }
    let preferred_keys = [
        "command",
        "file_path",
        "path",
        "pattern",
        "query",
        "url",
        "description",
        "prompt",
        "plan",
    ];
    let mut parts: Vec<String> = Vec::new();
    for k in preferred_keys {
        if let Some(val_v) = args.get(k) {
            if val_v.is_null() || val_v.as_str() == Some("") {
                continue;
            }
            let raw_s = json_val_to_display(val_v).replace('\n', " ");
            let mut val = raw_s.trim().to_string();
            if char_len(&val) > 110 {
                val = format!("{}...", slice_chars(&val, 107));
            }
            parts.push(format!("{}={}", k, val));
            if parts.len() >= 2 {
                break;
            }
        }
    }
    if parts.is_empty() {
        let raw = serde_json::to_string(args).unwrap_or_else(|_| "{}".to_string());
        if char_len(&raw) > 120 {
            return format!("{}...", slice_chars(&raw, 117));
        }
        return raw;
    }
    parts.join(", ")
}

pub fn truncate_text(text: &str, limit: usize) -> String {
    if char_len(text) <= limit {
        return text.to_string();
    }
    let suffix =
        "\n\n...(содержимое сокращено для производительности; полная история доступна в transcript_full.jsonl)...";
    let suffix_len = char_len(suffix);
    let keep = limit.saturating_sub(suffix_len);
    format!("{}{}", slice_chars(text, keep), suffix)
}

pub fn format_assistant_response(turn: &ConversationTurn) -> String {
    let main_text = turn
        .text_parts
        .iter()
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n");

    let mut tool_section = String::new();
    if !turn.tool_calls.is_empty() {
        let mut unique_names: Vec<String> = Vec::new();
        for tc in &turn.tool_calls {
            if !tc.name.is_empty() && !unique_names.contains(&tc.name) {
                unique_names.push(tc.name.clone());
            }
        }
        let mut names_label = unique_names
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        if unique_names.len() > 5 {
            names_label.push_str(&format!(", +{}", unique_names.len() - 5));
        }
        let mut lines: Vec<String> = vec![
            format!(
                "<details><summary>Выполнено инструментов Claude Code: {} ({})</summary>",
                turn.tool_calls.len(),
                names_label
            ),
            String::new(),
        ];
        let shown_len = turn.tool_calls.len().min(40);
        for tc in &turn.tool_calls[..shown_len] {
            let arg_str = summarize_tool_args(&tc.arguments).replace('`', "'");
            let mut line = format!("- **`{}`**: `{}`", tc.name, arg_str);
            if !tc.result_preview.is_empty() {
                let collapsed = ws_re().replace_all(&tc.result_preview, " ");
                let mut res_one = collapsed.trim().to_string();
                if char_len(&res_one) > 140 {
                    res_one = format!("{}...", slice_chars(&res_one, 137));
                }
                res_one = res_one.replace('`', "'");
                line.push_str(&format!(" -> `{}`", res_one));
            }
            lines.push(line);
        }
        if turn.tool_calls.len() > shown_len {
            lines.push(format!(
                "- ... и ещё {} вызовов",
                turn.tool_calls.len() - shown_len
            ));
        }
        lines.push("</details>".to_string());
        tool_section = lines.join("\n");
    }

    let combined = if !main_text.is_empty() && !tool_section.is_empty() {
        format!("{}\n\n{}", main_text, tool_section)
    } else if !main_text.is_empty() {
        main_text
    } else if !tool_section.is_empty() {
        tool_section
    } else {
        "(Ответ модели без текстового содержимого)".to_string()
    };

    truncate_text(&combined, MAX_RESPONSE_CHARS)
}

pub fn format_thinking(turn: &ConversationTurn) -> String {
    let raw = turn
        .thinking_parts
        .iter()
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n");
    if raw.is_empty() {
        return String::new();
    }
    truncate_text(&raw, MAX_THINKING_CHARS)
}

pub fn extract_tool_result_text(block: &Map<String, Value>) -> String {
    let Some(cnt) = block.get("content") else {
        return String::new();
    };
    match cnt {
        Value::String(s) => s.clone(),
        Value::Array(items) => {
            let mut pieces: Vec<String> = Vec::new();
            for item in items {
                if let Some(obj) = item.as_object() {
                    if obj.get("type").and_then(|v| v.as_str()) == Some("text") {
                        pieces.push(
                            obj.get("text")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                        );
                    }
                } else if let Some(s) = item.as_str() {
                    pieces.push(s.to_string());
                }
            }
            pieces.join("\n")
        }
        Value::Null => String::new(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

pub fn infer_default_cwd(project_folder: &str) -> String {
    if let Some(caps) = drive_cwd_re().captures(project_folder) {
        let drive = caps.get(1).map_or("", |m| m.as_str()).to_uppercase();
        let rest = caps.get(2).map_or("", |m| m.as_str()).replace('-', "\\");
        return format!("{}:\\{}", drive, rest);
    }
    rio::home_dir().to_string_lossy().into_owned()
}

fn json_is_truthy(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map_or(false, |x| x != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(m)) => !m.is_empty(),
        _ => false,
    }
}

pub fn parse_claude_session(project_folder: &str, filepath: &Path) -> Option<ParsedSession> {
    let session_id = filepath
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    let stat_mtime = fs::metadata(filepath)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|st| st.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    let file = File::open(filepath).ok()?;
    let mut reader = BufReader::new(file);

    let mut custom_title: Option<String> = None;
    let mut ai_title: Option<String> = None;
    let mut cwd: Option<String> = None;
    let mut first_ts: Option<String> = None;
    let mut last_ts: Option<String> = None;

    let mut turns: Vec<ConversationTurn> = Vec::new();
    let mut current_turn_idx: Option<usize> = None;
    let mut current_has_assistant = false;
    let mut tool_map: HashMap<String, (usize, usize)> = HashMap::new();

    let mut human_user_count: usize = 0;
    let mut assistant_record_count: usize = 0;
    let mut user_uuids: Vec<String> = Vec::new();

    let mut raw_buf: Vec<u8> = Vec::new();
    loop {
        raw_buf.clear();
        let n = match reader.read_until(b'\n', &mut raw_buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        let lossy = String::from_utf8_lossy(&raw_buf);
        let raw_line = lossy.trim();
        if raw_line.is_empty() {
            continue;
        }
        let Ok(obj) = serde_json::from_str::<Value>(raw_line) else {
            continue;
        };
        let Some(obj_map) = obj.as_object() else {
            continue;
        };

        let ts_opt = obj_map
            .get("timestamp")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        if let Some(ref ts) = ts_opt {
            if first_ts.is_none() {
                first_ts = Some(ts.clone());
            }
            last_ts = Some(ts.clone());
        }

        if cwd.is_none() {
            if let Some(c) = obj_map
                .get("cwd")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                cwd = Some(c.to_string());
            }
        }

        let rec_type = obj_map.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if rec_type == "custom-title" {
            if let Some(t_val) = obj_map.get("customTitle").and_then(|v| v.as_str()) {
                let trimmed = t_val.trim();
                if !trimmed.is_empty() {
                    custom_title = Some(trimmed.to_string());
                }
            }
            continue;
        }
        if rec_type == "ai-title" {
            if let Some(t_val) = obj_map.get("aiTitle").and_then(|v| v.as_str()) {
                let trimmed = t_val.trim();
                if !trimmed.is_empty() {
                    ai_title = Some(trimmed.to_string());
                }
            }
            continue;
        }

        if rec_type == "user" {
            if json_is_truthy(obj_map.get("isMeta")) {
                continue;
            }
            let Some(msg) = obj_map.get("message").and_then(|v| v.as_object()) else {
                continue;
            };
            let cnt = msg.get("content");

            if let Some(Value::Array(blocks)) = cnt {
                for block in blocks {
                    if let Some(b_map) = block.as_object() {
                        if b_map.get("type").and_then(|v| v.as_str()) == Some("tool_result") {
                            if let Some(tid) = b_map.get("tool_use_id").and_then(|v| v.as_str()) {
                                if let Some(&(t_idx, tc_idx)) = tool_map.get(tid) {
                                    let res_txt = extract_tool_result_text(b_map);
                                    turns[t_idx].tool_calls[tc_idx].result_preview =
                                        slice_chars(&res_txt, 4000).to_string();
                                }
                            }
                        }
                    }
                }
            }

            let mut human_texts: Vec<String> = Vec::new();
            match cnt {
                Some(Value::String(s)) => {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        human_texts.push(trimmed.to_string());
                    }
                }
                Some(Value::Array(blocks)) => {
                    for block in blocks {
                        if let Some(b_map) = block.as_object() {
                            if b_map.get("type").and_then(|v| v.as_str()) == Some("text") {
                                if let Some(t_txt) = b_map.get("text").and_then(|v| v.as_str()) {
                                    let trimmed = t_txt.trim();
                                    if !trimmed.is_empty() {
                                        human_texts.push(trimmed.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }

            if !human_texts.is_empty() {
                human_user_count += 1;
                let u_uuid = obj_map
                    .get("uuid")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .unwrap_or_else(|| {
                        stable_uuid(&format!("{}:user:{}", session_id, human_user_count))
                    });
                user_uuids.push(u_uuid.clone());
                let joined_user = human_texts.join("\n\n");
                let is_cont = joined_user.starts_with(SYNTHETIC_CONTINUATION_PREFIX);

                let merge_into_current = if let Some(idx) = current_turn_idx {
                    !current_has_assistant && turns[idx].is_continuation_summary == is_cont
                } else {
                    false
                };

                if merge_into_current {
                    let idx = current_turn_idx.unwrap();
                    turns[idx].user_text.push_str("\n\n");
                    turns[idx].user_text.push_str(&joined_user);
                } else {
                    turns.push(ConversationTurn {
                        user_uuid: u_uuid,
                        user_text: joined_user,
                        user_ts: ts_opt,
                        thinking_parts: Vec::new(),
                        text_parts: Vec::new(),
                        tool_calls: Vec::new(),
                        first_assistant_ts: None,
                        last_assistant_ts: None,
                        is_continuation_summary: is_cont,
                    });
                    current_turn_idx = Some(turns.len() - 1);
                    current_has_assistant = false;
                }
            }
        } else if rec_type == "assistant" {
            assistant_record_count += 1;
            let Some(msg) = obj_map.get("message").and_then(|v| v.as_object()) else {
                continue;
            };
            let cnt = msg.get("content");
            if current_turn_idx.is_none() {
                turns.push(ConversationTurn {
                    user_uuid: stable_uuid(&format!("{}:implicit_start", session_id)),
                    user_text: "(Начало сессии Claude Code)".to_string(),
                    user_ts: ts_opt.clone().or_else(|| first_ts.clone()),
                    thinking_parts: Vec::new(),
                    text_parts: Vec::new(),
                    tool_calls: Vec::new(),
                    first_assistant_ts: None,
                    last_assistant_ts: None,
                    is_continuation_summary: false,
                });
                current_turn_idx = Some(turns.len() - 1);
            }
            let t_idx = current_turn_idx.unwrap();
            current_has_assistant = true;
            if let Some(ref ts) = ts_opt {
                if turns[t_idx].first_assistant_ts.is_none() {
                    turns[t_idx].first_assistant_ts = Some(ts.clone());
                }
                turns[t_idx].last_assistant_ts = Some(ts.clone());
            }

            match cnt {
                Some(Value::String(s)) => {
                    if !s.trim().is_empty() {
                        turns[t_idx].text_parts.push(s.clone());
                    }
                }
                Some(Value::Array(blocks)) => {
                    for block in blocks {
                        let Some(b_map) = block.as_object() else {
                            continue;
                        };
                        let btype = b_map.get("type").and_then(|v| v.as_str()).unwrap_or("");
                        if btype == "thinking" {
                            if let Some(th) = b_map.get("thinking").and_then(|v| v.as_str()) {
                                if !th.trim().is_empty() {
                                    turns[t_idx].thinking_parts.push(th.to_string());
                                }
                            }
                        } else if btype == "text" {
                            if let Some(tx) = b_map.get("text").and_then(|v| v.as_str()) {
                                if !tx.trim().is_empty() {
                                    turns[t_idx].text_parts.push(tx.to_string());
                                }
                            }
                        } else if btype == "tool_use" {
                            let tid = b_map
                                .get("id")
                                .and_then(|v| v.as_str())
                                .filter(|s| !s.is_empty())
                                .map(str::to_string)
                                .unwrap_or_else(|| format!("tool_{}", turns[t_idx].tool_calls.len()));
                            let tname = b_map
                                .get("name")
                                .and_then(|v| v.as_str())
                                .filter(|s| !s.is_empty())
                                .unwrap_or("Tool")
                                .to_string();
                            let targs = match b_map.get("input") {
                                Some(Value::Object(m)) => m.clone(),
                                Some(other) => {
                                    let mut m = Map::new();
                                    m.insert("raw".to_string(), other.clone());
                                    m
                                }
                                None => {
                                    let mut m = Map::new();
                                    m.insert("raw".to_string(), Value::Null);
                                    m
                                }
                            };
                            let tc_idx = turns[t_idx].tool_calls.len();
                            turns[t_idx].tool_calls.push(ToolInvocation {
                                tool_id: tid.clone(),
                                name: tname,
                                arguments: targs,
                                result_preview: String::new(),
                            });
                            tool_map.insert(tid, (t_idx, tc_idx));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if assistant_record_count == 0 || turns.is_empty() {
        return None;
    }

    let first_prompt_stripped = turns[0].user_text.trim().to_string();
    if human_user_count == 1 && EXCLUDED_SINGLE_PROMPTS.contains(&first_prompt_stripped.as_str()) {
        return None;
    }

    let raw_title = custom_title.or(ai_title);
    // SAFETY: Exclude automated single-turn roleplay/shim prompts without explicit user title.
    if human_user_count == 1
        && raw_title.is_none()
        && shim_prompt_re().is_match(&first_prompt_stripped)
    {
        return None;
    }

    let resolved_cwd = cwd.unwrap_or_else(|| infer_default_cwd(project_folder));
    let resolved_title = match raw_title.as_deref() {
        Some(rt) if rt != "New session" => rt.to_string(),
        Some("New session") => {
            let proj_tag = home_proj_re().replace(project_folder, "Home");
            let proj_tag = drive_prefix_re().replace(&proj_tag, "").into_owned();
            if first_prompt_stripped.contains("/init") {
                format!("Инициализация {} (/init)", proj_tag)
            } else {
                format!("{} [{}]", clean_preview(&first_prompt_stripped, 55), proj_tag)
            }
        }
        _ => clean_preview(&first_prompt_stripped, 68),
    };

    let (created_sec, created_nanos) = parse_iso_timestamp(first_ts.as_deref(), stat_mtime);
    let (last_mod_sec, last_mod_nanos) =
        parse_iso_timestamp(last_ts.as_deref().or(first_ts.as_deref()), stat_mtime);

    Some(ParsedSession {
        project_folder: project_folder.to_string(),
        filepath: filepath.to_path_buf(),
        session_id,
        raw_title,
        resolved_title,
        cwd: resolved_cwd,
        created_sec,
        created_nanos,
        last_mod_sec,
        last_mod_nanos,
        turns,
        human_user_count,
        assistant_record_count,
        user_uuids,
    })
}

pub fn merge_chain_turns(sessions_chronological: &[ParsedSession]) -> Vec<ConversationTurn> {
    let mut by_uuid: HashMap<String, ConversationTurn> = HashMap::new();
    let mut ordered_uuids: Vec<String> = Vec::new();

    for sess in sessions_chronological {
        for turn in &sess.turns {
            if turn.is_continuation_summary && !ordered_uuids.is_empty() {
                continue;
            }
            let uid = &turn.user_uuid;
            if let Some(existing) = by_uuid.get(uid) {
                let existing_score = existing.text_parts.len()
                    + existing.tool_calls.len()
                    + existing.thinking_parts.len();
                let new_score =
                    turn.text_parts.len() + turn.tool_calls.len() + turn.thinking_parts.len();
                if new_score > existing_score {
                    by_uuid.insert(uid.clone(), turn.clone());
                }
            } else {
                by_uuid.insert(uid.clone(), turn.clone());
                ordered_uuids.push(uid.clone());
            }
        }
    }

    let mut last_known_ts: Option<String> = None;
    for uid in &ordered_uuids {
        if let Some(t) = by_uuid.get_mut(uid) {
            if let Some(ref ts) = t.user_ts {
                last_known_ts = Some(ts.clone());
            } else if let Some(ref known) = last_known_ts {
                t.user_ts = Some(known.clone());
            }
        }
    }

    let mut indexed: Vec<(usize, String)> = ordered_uuids.into_iter().enumerate().collect();
    indexed.sort_by_key(|(orig_idx, uid)| {
        let t = &by_uuid[uid];
        if let Some(ref ts) = t.user_ts {
            let (sec, nanos) = parse_iso_timestamp(Some(ts), 0.0);
            (sec, nanos, *orig_idx)
        } else {
            (0, 0, *orig_idx)
        }
    });

    indexed
        .into_iter()
        .filter_map(|(_, uid)| by_uuid.remove(&uid))
        .collect()
}

pub fn encode_trajectory_metadata(
    conversation_id: &str,
    created_sec: i64,
    created_nanos: i64,
    init_state_id: &str,
) -> Vec<u8> {
    let created_ts = encode_timestamp(created_sec, created_nanos);
    let mut out = Vec::new();
    out.extend(field_bytes(2, &created_ts));
    out.extend(field_str(3, init_state_id));
    out.extend(field_str(6, conversation_id));
    out.extend(field_str(18, "outside-of-project"));
    out
}

pub struct StepMetadataSpec<'a> {
    pub trajectory_id: &'a str,
    pub conversation_id: &'a str,
    pub step_idx: i64,
    pub meta_idx: i64,
    pub source: i64,
    pub created_sec: i64,
    pub created_nanos: i64,
    pub completed_sec: i64,
    pub completed_nanos: i64,
    pub exec_id: &'a str,
    pub content_id: &'a str,
    pub is_model: bool,
}

pub fn encode_step_metadata(spec: StepMetadataSpec<'_>) -> Vec<u8> {
    let StepMetadataSpec {
        trajectory_id,
        conversation_id,
        step_idx,
        meta_idx,
        source,
        created_sec,
        created_nanos,
        completed_sec,
        completed_nanos,
        exec_id,
        content_id,
        is_model,
    } = spec;
    let created_ts = encode_timestamp(created_sec, created_nanos);
    let completed_ts = encode_timestamp(completed_sec, completed_nanos);

    let mut src_traj_info = Vec::new();
    src_traj_info.extend(field_str(1, trajectory_id));
    src_traj_info.extend(field_varint(2, step_idx, false));
    src_traj_info.extend(field_varint(3, meta_idx, false));
    src_traj_info.extend(field_str(4, conversation_id));

    let mut status_transition = field_varint(1, 3, false);
    status_transition.extend(field_bytes(2, &completed_ts));
    let internal_meta = field_bytes(1, &status_transition);

    let mut buf = Vec::new();
    buf.extend(field_bytes(1, &created_ts));
    buf.extend(field_varint(3, source, false));
    if is_model {
        buf.extend(field_bytes(6, &created_ts));
        buf.extend(field_bytes(7, &completed_ts));
        buf.extend(field_bytes(8, &completed_ts));
        buf.extend(field_varint(11, 1318, false));
    }
    buf.extend(field_str(12, exec_id));
    buf.extend(field_bytes(20, &src_traj_info));
    buf.extend(field_bytes(26, &internal_meta));
    if is_model {
        buf.extend(field_bytes(32, &created_ts));
    }
    buf.extend(field_str(35, content_id));
    buf
}

pub fn encode_user_input_step(
    meta_bytes: &[u8],
    user_text: &str,
    client_msg_id: &str,
) -> Vec<u8> {
    let item_bytes = field_str(1, user_text);
    let user_agent_spec: &[u8] = b"\x1a\x08\n\x06\x08\x00\x18\x01(\x03";
    let mut user_input = Vec::new();
    user_input.extend(field_str(2, user_text));
    user_input.extend(field_bytes(3, &item_bytes));
    user_input.extend(field_bytes(18, user_agent_spec));
    user_input.extend(field_str(19, client_msg_id));

    let mut out = Vec::new();
    out.extend(field_varint(1, 14, false));
    out.extend(field_varint(4, 3, false));
    out.extend(field_bytes(5, meta_bytes));
    out.extend(field_bytes(19, &user_input));
    out
}

pub fn encode_planner_response_step(
    meta_bytes: &[u8],
    response_text: &str,
    thinking_text: &str,
    bot_msg_id: &str,
) -> Vec<u8> {
    let mut pr = Vec::new();
    pr.extend(field_str(1, response_text));
    pr.extend(field_str(3, thinking_text));
    pr.extend(field_str(6, bot_msg_id));
    pr.extend(field_str(8, response_text));
    pr.extend(field_varint(12, 2, false));

    let mut out = Vec::new();
    out.extend(field_varint(1, 15, false));
    out.extend(field_varint(4, 3, false));
    out.extend(field_bytes(5, meta_bytes));
    out.extend(field_bytes(20, &pr));
    out
}

pub struct CheckpointStepSpec<'a> {
    pub meta_bytes: &'a [u8],
    pub ckpt_idx: i64,
    pub end_step_idx: i64,
    pub title: &'a str,
    pub user_intent: &'a str,
    pub session_summary: &'a str,
    pub user_requests: &'a [String],
    pub seed_prefix: &'a str,
}

pub fn encode_checkpoint_step(spec: CheckpointStepSpec<'_>) -> Vec<u8> {
    let CheckpointStepSpec {
        meta_bytes,
        ckpt_idx,
        end_step_idx,
        title,
        user_intent,
        session_summary,
        user_requests,
        seed_prefix,
    } = spec;
    let mut buf = Vec::new();
    buf.extend(field_varint(1, ckpt_idx, false));
    buf.extend(field_str(4, user_intent));
    buf.extend(field_str(5, session_summary));
    buf.extend(field_str(10, title));
    buf.extend(field_varint(12, end_step_idx, false));
    buf.extend(field_varint(24, 1, false));
    buf.extend(field_str(28, &stable_hex32(&format!("{}:prompt", seed_prefix))));
    buf.extend(field_str(29, &stable_hex32(&format!("{}:summary", seed_prefix))));
    let start = user_requests.len().saturating_sub(25);
    for req in &user_requests[start..] {
        if !req.trim().is_empty() {
            let captured = field_str(1, slice_chars(req, 2000));
            buf.extend(field_bytes(30, &captured));
        }
    }

    let mut out = Vec::new();
    out.extend(field_varint(1, 23, false));
    out.extend(field_varint(4, 3, false));
    out.extend(field_bytes(5, meta_bytes));
    out.extend(field_bytes(30, &buf));
    out
}

pub struct CascadeSummarySpec<'a> {
    pub title: &'a str,
    pub step_count: i64,
    pub last_mod_sec: i64,
    pub last_mod_nanos: i64,
    pub trajectory_id: &'a str,
    pub created_sec: i64,
    pub created_nanos: i64,
    pub last_user_sec: i64,
    pub last_user_nanos: i64,
    pub last_user_step_idx: i64,
    pub traj_meta_bytes: &'a [u8],
}

pub fn encode_cascade_summary(spec: CascadeSummarySpec<'_>) -> Vec<u8> {
    let CascadeSummarySpec {
        title,
        step_count,
        last_mod_sec,
        last_mod_nanos,
        trajectory_id,
        created_sec,
        created_nanos,
        last_user_sec,
        last_user_nanos,
        last_user_step_idx,
        traj_meta_bytes,
    } = spec;
    let last_mod_ts = encode_timestamp(last_mod_sec, last_mod_nanos);
    let created_ts = encode_timestamp(created_sec, created_nanos);
    let last_user_ts = encode_timestamp(last_user_sec, last_user_nanos);

    let mut annotations = field_str(1, title);
    annotations.extend(field_bytes(7, &last_mod_ts));

    let mut out = Vec::new();
    out.extend(field_str(1, title));
    out.extend(field_varint(2, step_count, true));
    out.extend(field_bytes(3, &last_mod_ts));
    out.extend(field_str(4, trajectory_id));
    out.extend(field_varint(5, 1, false));
    out.extend(field_bytes(7, &created_ts));
    out.extend(field_bytes(10, &last_user_ts));
    out.extend(field_bytes(15, &annotations));
    out.extend(field_varint(16, last_user_step_idx, true));
    out.extend(field_bytes(17, traj_meta_bytes));
    out.extend(field_varint(22, 4, false));
    out.extend(field_varint(28, 4, false));
    out
}

pub fn build_checkpoint_summary_text(
    antigravity_dir: &Path,
    conv_id: &str,
    title: &str,
    cwd: &str,
    turns_covered: &[ConversationTurn],
) -> (String, String) {
    let user_intent = if let Some(first) = turns_covered.first() {
        clean_preview(&first.user_text, 240)
    } else {
        title.to_string()
    };

    let total = turns_covered.len();
    let indices: Vec<usize> = if total <= 20 {
        (0..total).collect()
    } else {
        let mut idx_set: HashSet<usize> = HashSet::new();
        for i in 0..5 {
            idx_set.insert(i);
        }
        for i in total.saturating_sub(10)..total {
            idx_set.insert(i);
        }
        let step = 1.max((total - 15) / 10);
        let mut i = 5;
        while i < total - 10 {
            idx_set.insert(i);
            i += step;
        }
        let mut v: Vec<usize> = idx_set.into_iter().collect();
        v.sort_unstable();
        v
    };

    let mut req_lines: Vec<String> = Vec::with_capacity(indices.len());
    for i in indices {
        let t = &turns_covered[i];
        req_lines.push(format!("- [{}] {}", i + 1, clean_preview(&t.user_text, 160)));
    }

    let mut last_assistant_snip = String::new();
    for t in turns_covered.iter().rev() {
        if !t.text_parts.is_empty() {
            last_assistant_snip = clean_preview(&t.text_parts.join("\n"), 500);
            break;
        }
    }

    let agy_disp = antigravity_dir.to_string_lossy();
    let mut summary_lines: Vec<String> = vec![
        "<summary>".to_string(),
        format!("## Imported Claude Code Session Summary: {}", title),
        format!("- **Conversation ID**: `{}`", conv_id),
        format!("- **Working Directory (`cwd`)**: `{}`", cwd),
        format!("- **Turns Covered Before Checkpoint**: {}", total),
        format!(
            "- **Full Transcript Log**: `{}\\brain\\{}\\.system_generated\\logs\\transcript_full.jsonl`",
            agy_disp, conv_id
        ),
        String::new(),
        "### Chronological User Requests Covered:".to_string(),
    ];
    summary_lines.extend(req_lines);
    if !last_assistant_snip.is_empty() {
        summary_lines.push(String::new());
        summary_lines.push("### Latest Pre-Checkpoint Progress:".to_string());
        summary_lines.push(last_assistant_snip);
    }
    summary_lines.push("</summary>".to_string());
    (user_intent, summary_lines.join("\n"))
}

pub fn write_transcript_logs(
    antigravity_dir: &Path,
    conv_id: &str,
    step_records: &[Value],
) -> Result<(), String> {
    let logs_dir = antigravity_dir
        .join("brain")
        .join(conv_id)
        .join(".system_generated")
        .join("logs");
    fs::create_dir_all(&logs_dir).map_err(|e| format!("create logs dir: {}", e))?;
    let compact_path = logs_dir.join("transcript.jsonl");
    let full_path = logs_dir.join("transcript_full.jsonl");

    let fc = File::create(&compact_path).map_err(|e| format!("create transcript.jsonl: {}", e))?;
    let ff =
        File::create(&full_path).map_err(|e| format!("create transcript_full.jsonl: {}", e))?;
    let mut wc = BufWriter::new(fc);
    let mut wf = BufWriter::new(ff);

    for rec in step_records {
        let full_line = serde_json::to_string(rec).map_err(|e| e.to_string())?;
        writeln!(wf, "{}", full_line).map_err(|e| e.to_string())?;

        let mut compact_map = rec.as_object().cloned().unwrap_or_default();
        let mut trunc: Vec<Value> = Vec::new();

        if let Some(Value::String(cnt)) = compact_map.get("content").cloned() {
            if char_len(&cnt) > 8000 {
                let cut = format!("{}\n...[truncated]", slice_chars(&cnt, 8000));
                compact_map.insert("content".to_string(), Value::String(cut));
                trunc.push(Value::String("content".to_string()));
            }
        }
        if let Some(Value::String(th)) = compact_map.get("thinking").cloned() {
            if char_len(&th) > 2000 {
                let cut = format!("{}\n...[truncated]", slice_chars(&th, 2000));
                compact_map.insert("thinking".to_string(), Value::String(cut));
                trunc.push(Value::String("thinking".to_string()));
            }
        }
        if let Some(Value::Array(tcs)) = compact_map.get("tool_calls").cloned() {
            let serialized = serde_json::to_string(&tcs).unwrap_or_default();
            if char_len(&serialized) > 4000 {
                let mut compacted: Vec<Value> = Vec::new();
                for tc in tcs.iter().take(25) {
                    let tc_obj = tc.as_object();
                    let name = tc_obj
                        .and_then(|m| m.get("name"))
                        .cloned()
                        .unwrap_or(Value::Null);
                    let args_map = tc_obj
                        .and_then(|m| m.get("arguments"))
                        .and_then(|v| v.as_object())
                        .cloned()
                        .unwrap_or_default();
                    compacted.push(json!({
                        "name": name,
                        "arguments_preview": summarize_tool_args(&args_map),
                    }));
                }
                compact_map.insert("tool_calls".to_string(), Value::Array(compacted));
                trunc.push(Value::String("tool_calls".to_string()));
            }
        }
        if !trunc.is_empty() {
            compact_map.insert("truncated_fields".to_string(), Value::Array(trunc));
        }

        let compact_line =
            serde_json::to_string(&Value::Object(compact_map)).map_err(|e| e.to_string())?;
        writeln!(wc, "{}", compact_line).map_err(|e| e.to_string())?;
    }
    wc.flush().map_err(|e| e.to_string())?;
    wf.flush().map_err(|e| e.to_string())?;
    Ok(())
}

pub fn write_annotation_pbtxt(
    antigravity_dir: &Path,
    conv_id: &str,
    title: &str,
    last_sec: i64,
    last_nanos: i64,
) -> Result<(), String> {
    let ann_dir = antigravity_dir.join("annotations");
    fs::create_dir_all(&ann_dir).map_err(|e| format!("create annotations dir: {}", e))?;
    let esc_title = title
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\r', " ")
        .replace('\n', " ");
    let content = format!(
        "title:\"{}\" last_user_view_time:{{seconds:{} nanos:{}}} permission_preset:AGENT_PERMISSION_PRESET_TURBO",
        esc_title, last_sec, last_nanos
    );
    let ann_path = ann_dir.join(format!("{}.pbtxt", conv_id));
    fs::write(&ann_path, content.as_bytes()).map_err(|e| format!("write pbtxt: {}", e))
}

pub fn is_continued_or_native_db(
    antigravity_dir: &Path,
    conv_id: &str,
    expected_trajectory_id: &str,
) -> bool {
    let db_path = antigravity_dir
        .join("conversations")
        .join(format!("{}.db", conv_id));
    if !db_path.exists() {
        return false;
    }
    let Ok(conn) = SqliteConn::open(&db_path, SQLITE_OPEN_READONLY) else {
        return false;
    };
    conn.set_busy_timeout(10_000);
    match conn.query("SELECT trajectory_id FROM trajectory_meta LIMIT 1", &[]) {
        Ok(rows) => {
            if let Some(first) = rows.first() {
                let existing = first[0].as_str();
                !existing.is_empty() && existing != expected_trajectory_id
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

pub fn write_conversation_db(
    antigravity_dir: &Path,
    conv_id: &str,
    trajectory_id: &str,
    traj_meta_bytes: &[u8],
    db_steps: &[DbStep],
    last_mod_sec: i64,
    force: bool,
) -> Result<(), String> {
    let conv_dir = antigravity_dir.join("conversations");
    fs::create_dir_all(&conv_dir).map_err(|e| format!("create conversations dir: {}", e))?;
    let db_path = conv_dir.join(format!("{}.db", conv_id));

    if !force && db_path.exists() {
        // SAFETY: Never overwrite a native Antigravity conversation DB whose trajectory_id differs.
        if let Ok(chk) = SqliteConn::open(&db_path, SQLITE_OPEN_READONLY) {
            chk.set_busy_timeout(10_000);
            if let Ok(rows) = chk.query("SELECT trajectory_id FROM trajectory_meta LIMIT 1", &[]) {
                if let Some(first) = rows.first() {
                    let existing = first[0].as_str();
                    if !existing.is_empty() && existing != trajectory_id {
                        return Err(format!(
                            "Refusing to overwrite existing native conversation DB: {} (trajectory_id={})",
                            conv_id, existing
                        ));
                    }
                }
            }
        }
    }

    for suffix in ["", "-wal", "-shm"] {
        let mut s = db_path.as_os_str().to_os_string();
        s.push(suffix);
        let p = PathBuf::from(s);
        if p.exists() {
            fs::remove_file(&p).map_err(|e| format!("remove {}: {}", p.display(), e))?;
        }
    }

    {
        let conn = SqliteConn::open(&db_path, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE)?;
        conn.set_busy_timeout(30_000);
        conn.exec_batch("PRAGMA page_size = 32768;")?;
        conn.exec_batch("PRAGMA user_version = 1;")?;
        conn.exec_batch("PRAGMA journal_mode = WAL;")?;
        conn.exec_batch(
            "CREATE TABLE `trajectory_meta` (
                `trajectory_id` text,
                `cascade_id` text,
                `trajectory_type` integer,
                `source` integer,
                PRIMARY KEY (`trajectory_id`)
            );
            CREATE TABLE `steps` (
                `idx` integer,
                `step_type` integer NOT NULL DEFAULT 0,
                `status` integer NOT NULL DEFAULT 0,
                `has_subtrajectory` numeric NOT NULL DEFAULT false,
                `metadata` blob,
                `error_details` blob,
                `permissions` blob,
                `task_details` blob,
                `render_info` blob,
                `step_payload` blob,
                `step_format` integer NOT NULL DEFAULT 0,
                PRIMARY KEY (`idx`)
            );
            CREATE INDEX `idx_steps_status` ON `steps`(`status`);
            CREATE INDEX `idx_steps_step_type` ON `steps`(`step_type`);
            CREATE TABLE `gen_metadata` (
                `idx` integer,
                `data` blob,
                `size` integer NOT NULL DEFAULT 0,
                PRIMARY KEY (`idx`)
            );
            CREATE TABLE `executor_metadata` (
                `idx` integer,
                `data` blob,
                PRIMARY KEY (`idx`)
            );
            CREATE TABLE `parent_references` (
                `idx` integer,
                `data` blob,
                PRIMARY KEY (`idx`)
            );
            CREATE TABLE `trajectory_metadata_blob` (
                `id` text DEFAULT \"main\",
                `data` blob,
                PRIMARY KEY (`id`)
            );
            CREATE TABLE `battle_mode_infos` (
                `idx` integer,
                `data` blob,
                PRIMARY KEY (`idx`)
            );",
        )?;

        conn.exec_batch("BEGIN IMMEDIATE;")?;
        let insert_res = (|| -> Result<(), String> {
            conn.execute(
                "INSERT INTO trajectory_meta (trajectory_id, cascade_id, trajectory_type, source) VALUES (?, ?, ?, ?)",
                &[
                    SqlParam::Text(trajectory_id.to_string()),
                    SqlParam::Text(conv_id.to_string()),
                    SqlParam::Int(4),
                    SqlParam::Int(1),
                ],
            )?;
            conn.execute(
                "INSERT INTO trajectory_metadata_blob (id, data) VALUES (?, ?)",
                &[
                    SqlParam::Text("main".to_string()),
                    SqlParam::Blob(traj_meta_bytes.to_vec()),
                ],
            )?;
            for step in db_steps {
                conn.execute(
                    "INSERT INTO steps (idx, step_type, status, has_subtrajectory, metadata, step_payload, step_format) VALUES (?, ?, ?, 0, ?, ?, 0)",
                    &[
                        SqlParam::Int(step.idx),
                        SqlParam::Int(step.step_type),
                        SqlParam::Int(step.status),
                        SqlParam::Blob(step.metadata.clone()),
                        SqlParam::Blob(step.step_payload.clone()),
                    ],
                )?;
            }
            Ok(())
        })();

        if let Err(err) = insert_res {
            let _ = conn.exec_batch("ROLLBACK;");
            return Err(err);
        }
        conn.exec_batch("COMMIT;")?;
        conn.exec_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    }

    if last_mod_sec >= 0 {
        let mtime = UNIX_EPOCH + Duration::from_secs(last_mod_sec as u64);
        if let Ok(fh) = OpenOptions::new().write(true).open(&db_path) {
            let _ = fh.set_modified(mtime);
        }
    }
    Ok(())
}

pub fn ensure_summaries_db_schema(conn: &SqliteConn) -> Result<(), String> {
    conn.exec_batch(
        "CREATE TABLE IF NOT EXISTS `conversation_summaries` (
            `conversation_id` text,
            `title` text,
            `preview` text,
            `step_count` integer,
            `last_modified_time` datetime,
            `workspace_uris` text,
            `status` text,
            `source` text,
            `project_id` text,
            `agent_name` text,
            `parent_conversation_id` text,
            `nesting_depth` integer,
            `battle_id` text,
            `winning_conversation_id` text,
            `not_fully_idle` numeric,
            `killed` numeric,
            `last_user_input_time` datetime,
            `last_user_input_step_index` integer DEFAULT -1,
            `app_data_dir` text DEFAULT '',
            `raw_summary` blob,
            `group_id` text DEFAULT '',
            PRIMARY KEY (`conversation_id`)
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS `conversations_fts` USING fts5(
            conversation_id UNINDEXED,
            chunk_index UNINDEXED,
            chunk_first_step UNINDEXED,
            chunk_last_step UNINDEXED,
            last_modified_time UNINDEXED,
            step_count UNINDEXED,
            last_step_created_at UNINDEXED,
            archived UNINDEXED,
            user_step_byte_offsets UNINDEXED,
            agent_step_byte_offsets UNINDEXED,
            title,
            workspace,
            project,
            user_body,
            agent_body
        );",
    )
}

pub fn update_agyhub_summaries_pb(
    imported_raw_summaries: &BTreeMap<String, Vec<u8>>,
    antigravity_dir: &Path,
) -> Result<(), String> {
    fs::create_dir_all(antigravity_dir).map_err(|e| format!("create antigravity dir: {}", e))?;
    let pb_path = antigravity_dir.join("agyhub_summaries_proto.pb");
    let mut preserved_entries: Vec<Vec<u8>> = Vec::new();
    let mut other_fields: Vec<Vec<u8>> = Vec::new();

    if pb_path.exists() {
        let existing_data = fs::read(&pb_path).map_err(|e| format!("read pb: {}", e))?;
        for wf in parse_wire_fields(&existing_data)? {
            if wf.fn_num == 1 && wf.wt == 2 {
                if let WireValue::Bytes(val) = wf.val {
                    let sub = parse_wire_fields(&val)?;
                    let mut key = String::new();
                    for sf in sub {
                        if sf.fn_num == 1 && sf.wt == 2 {
                            if let WireValue::Bytes(sval) = sf.val {
                                key = String::from_utf8_lossy(&sval).into_owned();
                                break;
                            }
                        }
                    }
                    if !key.is_empty() && !imported_raw_summaries.contains_key(&key) {
                        preserved_entries.push(field_bytes(1, &val));
                    }
                }
            } else if wf.fn_num == 2 && wf.wt == 2 {
                if let WireValue::Bytes(val) = wf.val {
                    other_fields.push(field_bytes(2, &val));
                }
            }
        }
    }

    let mut out: Vec<u8> = Vec::new();
    for chunk in &preserved_entries {
        out.extend_from_slice(chunk);
    }
    for (cid, raw_sum) in imported_raw_summaries {
        let mut entry = field_str(1, cid);
        entry.extend(field_bytes(2, raw_sum));
        out.extend(field_bytes(1, &entry));
    }
    for chunk in &other_fields {
        out.extend_from_slice(chunk);
    }

    let tmp_path = antigravity_dir.join(format!("agyhub_summaries_proto.pb.{}.tmp", std::process::id()));
    fs::write(&tmp_path, &out).map_err(|e| format!("write pb tmp: {}", e))?;
    let mut last_err = String::new();
    for attempt in 0..5 {
        match fs::rename(&tmp_path, &pb_path) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = e.to_string();
                thread::sleep(Duration::from_millis(10 * (attempt + 1)));
            }
        }
    }
    let _ = fs::remove_file(&tmp_path);
    Err(format!("rename pb: {}", last_err))
}

pub fn sync_pb_from_db(antigravity_dir: &Path) -> Result<usize, String> {
    let summaries_db_path = antigravity_dir.join("conversation_summaries.db");
    if !summaries_db_path.exists() {
        return Ok(0);
    }
    let raw_map: BTreeMap<String, Vec<u8>> = {
        let conn = SqliteConn::open(&summaries_db_path, SQLITE_OPEN_READONLY)?;
        conn.set_busy_timeout(30_000);
        let rows = conn.query(
            "SELECT conversation_id, raw_summary FROM conversation_summaries WHERE raw_summary IS NOT NULL",
            &[],
        )?;
        let mut map = BTreeMap::new();
        for row in rows {
            let cid = row[0].as_str();
            let blob = row[1].as_bytes();
            if !cid.is_empty() && !blob.is_empty() {
                map.insert(cid, blob.to_vec());
            }
        }
        map
    };
    update_agyhub_summaries_pb(&raw_map, antigravity_dir)?;
    Ok(raw_map.len())
}

#[derive(Debug, Clone)]
pub struct FtsChunkRow {
    pub conv_id: String,
    pub chunk_idx: i64,
    pub first_step: i64,
    pub last_step: i64,
    pub u_offsets: Vec<u8>,
    pub a_offsets: Vec<u8>,
    pub u_body: String,
    pub a_body: String,
}

pub fn build_fts_chunks(
    conv_id: &str,
    user_steps_with_text: &[(i64, String)],
    agent_steps_with_text: &[(i64, String)],
    step_count: i64,
    _last_mod_ns: i64,
) -> Vec<FtsChunkRow> {
    let u_map: HashMap<i64, &str> = user_steps_with_text
        .iter()
        .map(|(idx, t)| (*idx, t.as_str()))
        .collect();
    let a_map: HashMap<i64, &str> = agent_steps_with_text
        .iter()
        .map(|(idx, t)| (*idx, t.as_str()))
        .collect();

    let mut all_items: Vec<(i64, char, &str)> = Vec::new();
    for s_idx in 0..step_count {
        if let Some(&ut) = u_map.get(&s_idx) {
            all_items.push((s_idx, 'u', ut));
        }
        if let Some(&at) = a_map.get(&s_idx) {
            all_items.push((s_idx, 'a', at));
        }
    }

    let mut rows: Vec<FtsChunkRow> = Vec::new();
    let mut chunk_idx: i64 = 0;
    let mut u_buf: Vec<u8> = Vec::new();
    let mut a_buf: Vec<u8> = Vec::new();
    let mut u_offsets: Vec<[usize; 2]> = Vec::new();
    let mut a_offsets: Vec<[usize; 2]> = Vec::new();
    let mut cur_first: i64 = 0;
    let mut cur_last: i64 = 0;

    let flush_chunk = |rows: &mut Vec<FtsChunkRow>,
                       chunk_idx: &mut i64,
                       u_buf: &mut Vec<u8>,
                       a_buf: &mut Vec<u8>,
                       u_offsets: &mut Vec<[usize; 2]>,
                       a_offsets: &mut Vec<[usize; 2]>,
                       cur_first: i64,
                       cur_last: i64| {
        let u_off_bytes = serde_json::to_vec(u_offsets).unwrap_or_else(|_| b"[]".to_vec());
        let a_off_bytes = serde_json::to_vec(a_offsets).unwrap_or_else(|_| b"[]".to_vec());
        rows.push(FtsChunkRow {
            conv_id: conv_id.to_string(),
            chunk_idx: *chunk_idx,
            first_step: cur_first,
            last_step: cur_last,
            u_offsets: u_off_bytes,
            a_offsets: a_off_bytes,
            u_body: String::from_utf8_lossy(u_buf).into_owned(),
            a_body: String::from_utf8_lossy(a_buf).into_owned(),
        });
        *chunk_idx += 1;
        u_buf.clear();
        a_buf.clear();
        u_offsets.clear();
        a_offsets.clear();
    };

    for (s_idx, kind, text) in all_items {
        let mut line = text.trim().to_string();
        line.push('\n');
        let line_bytes = line.as_bytes();
        if u_buf.len() + a_buf.len() + line_bytes.len() > 120_000
            && (!u_buf.is_empty() || !a_buf.is_empty())
        {
            flush_chunk(
                &mut rows,
                &mut chunk_idx,
                &mut u_buf,
                &mut a_buf,
                &mut u_offsets,
                &mut a_offsets,
                cur_first,
                cur_last,
            );
            cur_first = s_idx;
        }
        cur_last = s_idx;
        if kind == 'u' {
            u_offsets.push([s_idx as usize, u_buf.len()]);
            u_buf.extend_from_slice(line_bytes);
        } else {
            a_offsets.push([s_idx as usize, a_buf.len()]);
            a_buf.extend_from_slice(line_bytes);
        }
    }

    if !u_buf.is_empty() || !a_buf.is_empty() || chunk_idx == 0 {
        flush_chunk(
            &mut rows,
            &mut chunk_idx,
            &mut u_buf,
            &mut a_buf,
            &mut u_offsets,
            &mut a_offsets,
            cur_first,
            cur_last,
        );
    }

    rows
}

pub fn resolve_project_folders(
    claude_projects_dir: &Path,
    explicit_projects: Option<&[String]>,
    include_all_projects: bool,
) -> Vec<String> {
    if let Some(ep) = explicit_projects {
        if !ep.is_empty() {
            return ep
                .iter()
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect();
        }
    }
    if !claude_projects_dir.is_dir() {
        return Vec::new();
    }
    let Ok(entries) = fs::read_dir(claude_projects_dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !include_all_projects && excluded_project_re().is_match(&name) {
            continue;
        }
        names.push(name);
    }
    names.sort();
    names
}

pub fn collect_and_prepare_sessions(
    claude_projects_dir: &Path,
    explicit_projects: Option<&[String]>,
    include_all_projects: bool,
) -> Vec<(String, String, ParsedSession, Vec<ConversationTurn>)> {
    let projects = resolve_project_folders(
        claude_projects_dir,
        explicit_projects,
        include_all_projects,
    );
    let mut sessions_by_project: BTreeMap<String, Vec<ParsedSession>> = BTreeMap::new();

    for proj in projects {
        let pdir = claude_projects_dir.join(&proj);
        if !pdir.is_dir() {
            continue;
        }
        let Ok(rd) = fs::read_dir(&pdir) else {
            continue;
        };
        let mut jsonl_files: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("jsonl"))
            .collect();
        jsonl_files.sort();

        for fp in jsonl_files {
            if let Some(parsed) = parse_claude_session(&proj, &fp) {
                sessions_by_project
                    .entry(proj.clone())
                    .or_default()
                    .push(parsed);
            }
        }
    }

    let mut prepared: Vec<(String, String, ParsedSession, Vec<ConversationTurn>)> = Vec::new();

    for (_proj, sess_list) in sessions_by_project {
        let mut by_title: BTreeMap<String, Vec<ParsedSession>> = BTreeMap::new();
        for s in sess_list {
            by_title
                .entry(s.resolved_title.clone())
                .or_default()
                .push(s);
        }

        for (title, mut group) in by_title {
            group.sort_by_key(|s| {
                (
                    s.last_mod_sec,
                    s.last_mod_nanos,
                    s.created_sec,
                    s.created_nanos,
                )
            });
            if group.len() == 1 {
                let s = group.into_iter().next().unwrap();
                let turns = s.turns.clone();
                let cid = s.session_id.clone();
                prepared.push((cid, title, s, turns));
            } else {
                let total_parts = group.len();
                let merged = merge_chain_turns(&group);
                let earliest_sec = group.iter().map(|x| x.created_sec).min().unwrap_or(0);
                let earliest_nanos = group
                    .iter()
                    .filter(|x| x.created_sec == earliest_sec)
                    .map(|x| x.created_nanos)
                    .min()
                    .unwrap_or(0);

                for (idx_in_group, mut s) in group.into_iter().enumerate() {
                    let cid = s.session_id.clone();
                    if idx_in_group == total_parts - 1 {
                        s.created_sec = earliest_sec;
                        s.created_nanos = earliest_nanos;
                        prepared.push((cid, title.clone(), s, merged.clone()));
                    } else {
                        let date_str = format_utc_date(s.last_mod_sec);
                        let seg_title =
                            format!("{} (ч. {}/{}, {})", title, idx_in_group + 1, total_parts, date_str);
                        let turns = s.turns.clone();
                        prepared.push((cid, seg_title, s, turns));
                    }
                }
            }
        }
    }

    prepared
}

pub struct BuiltSteps {
    pub db_steps: Vec<DbStep>,
    pub transcript_records: Vec<Value>,
    pub fts_user: Vec<(i64, String)>,
    pub fts_agent: Vec<(i64, String)>,
    pub last_user_sec: i64,
    pub last_user_nanos: i64,
    pub last_user_step_idx: i64,
}

pub fn build_steps_and_artifacts(
    antigravity_dir: &Path,
    conv_id: &str,
    trajectory_id: &str,
    title: &str,
    sess: &ParsedSession,
    turns: &[ConversationTurn],
) -> BuiltSteps {
    let total_chars: usize = turns
        .iter()
        .map(|t| {
            char_len(&t.user_text)
                + t.text_parts.iter().map(|p| char_len(p)).sum::<usize>()
        })
        .sum();
    let need_checkpoint =
        turns.len() > CHECKPOINT_TURN_THRESHOLD || total_chars > CHECKPOINT_CHAR_THRESHOLD;
    let split_turn_idx = if need_checkpoint {
        Some(turns.len().saturating_sub(KEEP_RECENT_TURNS_AFTER_CHECKPOINT).max(1))
    } else {
        None
    };

    let mut db_steps: Vec<DbStep> = Vec::new();
    let mut transcript_records: Vec<Value> = Vec::new();
    let mut fts_user: Vec<(i64, String)> = Vec::new();
    let mut fts_agent: Vec<(i64, String)> = Vec::new();

    let mut step_idx: i64 = 0;
    let mut meta_idx: i64 = 0;
    let mut last_user_sec = sess.created_sec;
    let mut last_user_nanos = sess.created_nanos;
    let mut last_user_step_idx: i64 = 0;
    let mut exec_id = stable_uuid(&format!("{}:exec:0", conv_id));

    for (t_i, turn) in turns.iter().enumerate() {
        if split_turn_idx == Some(t_i) {
            let turns_covered = &turns[..t_i];
            let (user_intent, summary_text) = build_checkpoint_summary_text(
                antigravity_dir,
                conv_id,
                title,
                &sess.cwd,
                turns_covered,
            );
            let last_covered = turns_covered.last();
            let ckpt_ts_ref = last_covered
                .and_then(|t| t.last_assistant_ts.as_deref().or(t.user_ts.as_deref()));
            let (ckpt_sec, ckpt_nanos) =
                parse_iso_timestamp(ckpt_ts_ref, sess.last_mod_sec as f64);

            let ckpt_cid = stable_hex32(&format!("{}:ckpt:meta", conv_id));
            let ckpt_meta = encode_step_metadata(StepMetadataSpec {
                trajectory_id,
                conversation_id: conv_id,
                step_idx,
                meta_idx,
                source: 5,
                created_sec: ckpt_sec,
                created_nanos: ckpt_nanos,
                completed_sec: ckpt_sec,
                completed_nanos: ckpt_nanos,
                exec_id: &exec_id,
                content_id: &ckpt_cid,
                is_model: false,
            });
            let user_requests: Vec<String> =
                turns_covered.iter().map(|x| x.user_text.clone()).collect();
            let ckpt_seed = format!("{}:ckpt", conv_id);
            let ckpt_payload = encode_checkpoint_step(CheckpointStepSpec {
                meta_bytes: &ckpt_meta,
                ckpt_idx: 1,
                end_step_idx: step_idx,
                title,
                user_intent: &user_intent,
                session_summary: &summary_text,
                user_requests: &user_requests,
                seed_prefix: &ckpt_seed,
            });
            db_steps.push(DbStep {
                idx: step_idx,
                step_type: 23,
                status: 3,
                metadata: ckpt_meta,
                step_payload: ckpt_payload,
            });
            transcript_records.push(json!({
                "step_index": step_idx,
                "source": "SYSTEM",
                "type": "CHECKPOINT",
                "status": "DONE",
                "created_at": timestamp_to_iso_localish(ckpt_sec, ckpt_nanos),
                "content": summary_text,
            }));
            step_idx += 1;
        }

        let (u_sec, u_nanos) =
            parse_iso_timestamp(turn.user_ts.as_deref(), sess.created_sec as f64);
        last_user_sec = u_sec;
        last_user_nanos = u_nanos;
        last_user_step_idx = step_idx;
        exec_id = stable_uuid(&format!("{}:exec:{}", conv_id, t_i));

        let u_cid = stable_hex32(&format!("{}:u:{}", conv_id, t_i));
        let u_meta = encode_step_metadata(StepMetadataSpec {
            trajectory_id,
            conversation_id: conv_id,
            step_idx,
            meta_idx,
            source: 4,
            created_sec: u_sec,
            created_nanos: u_nanos,
            completed_sec: u_sec,
            completed_nanos: u_nanos,
            exec_id: &exec_id,
            content_id: &u_cid,
            is_model: false,
        });
        let u_text_for_step = if t_i == 0 {
            // INVARIANT: Place working directory note at the end of Step 0 so userInputSummary preview starts with user prompt.
            let cwd_banner = format!("\n\n[Claude Code • Рабочая папка: `{}`]", sess.cwd);
            if !turn.user_text.contains("[Claude Code • Рабочая папка:") {
                format!("{}{}", turn.user_text, cwd_banner)
            } else {
                turn.user_text.clone()
            }
        } else {
            turn.user_text.clone()
        };

        let u_payload = encode_user_input_step(
            &u_meta,
            &truncate_text(&u_text_for_step, MAX_RESPONSE_CHARS),
            &turn.user_uuid,
        );
        db_steps.push(DbStep {
            idx: step_idx,
            step_type: 14,
            status: 3,
            metadata: u_meta,
            step_payload: u_payload,
        });
        fts_user.push((step_idx, turn.user_text.clone()));
        transcript_records.push(json!({
            "step_index": step_idx,
            "source": "USER_EXPLICIT",
            "type": "USER_INPUT",
            "status": "DONE",
            "created_at": timestamp_to_iso_localish(u_sec, u_nanos),
            "content": turn.user_text,
        }));
        step_idx += 1;
        meta_idx += 1;

        let (a_start_sec, a_start_nanos) = parse_iso_timestamp(
            turn.first_assistant_ts
                .as_deref()
                .or(turn.user_ts.as_deref()),
            u_sec as f64,
        );
        let (a_end_sec, a_end_nanos) = parse_iso_timestamp(
            turn.last_assistant_ts
                .as_deref()
                .or(turn.first_assistant_ts.as_deref())
                .or(turn.user_ts.as_deref()),
            a_start_sec as f64,
        );
        let resp_text = format_assistant_response(turn);
        let think_text = format_thinking(turn);

        let a_cid = stable_hex32(&format!("{}:a:{}", conv_id, t_i));
        let a_meta = encode_step_metadata(StepMetadataSpec {
            trajectory_id,
            conversation_id: conv_id,
            step_idx,
            meta_idx,
            source: 2,
            created_sec: a_start_sec,
            created_nanos: a_start_nanos,
            completed_sec: a_end_sec,
            completed_nanos: a_end_nanos,
            exec_id: &exec_id,
            content_id: &a_cid,
            is_model: true,
        });
        let a_payload = encode_planner_response_step(
            &a_meta,
            &resp_text,
            &think_text,
            &format!("bot-{}", stable_uuid(&format!("{}:bot:{}", conv_id, t_i))),
        );
        db_steps.push(DbStep {
            idx: step_idx,
            step_type: 15,
            status: 3,
            metadata: a_meta,
            step_payload: a_payload,
        });

        let fts_text_only = turn
            .text_parts
            .iter()
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join("\n\n");
        let agent_content = if fts_text_only.is_empty() {
            resp_text.clone()
        } else {
            fts_text_only
        };
        fts_agent.push((step_idx, agent_content.clone()));

        let mut tr_map = Map::new();
        tr_map.insert("step_index".to_string(), json!(step_idx));
        tr_map.insert("source".to_string(), json!("MODEL"));
        tr_map.insert("type".to_string(), json!("PLANNER_RESPONSE"));
        tr_map.insert("status".to_string(), json!("DONE"));
        tr_map.insert(
            "created_at".to_string(),
            json!(timestamp_to_iso_localish(a_end_sec, a_end_nanos)),
        );
        tr_map.insert("content".to_string(), json!(agent_content));
        if !turn.thinking_parts.is_empty() {
            tr_map.insert("thinking".to_string(), json!(turn.thinking_parts.join("\n\n")));
        }
        if !turn.tool_calls.is_empty() {
            let tcs: Vec<Value> = turn
                .tool_calls
                .iter()
                .map(|tc| {
                    let rp = if tc.result_preview.is_empty() {
                        String::new()
                    } else {
                        slice_chars(&tc.result_preview, 1500).to_string()
                    };
                    json!({
                        "id": tc.tool_id,
                        "name": tc.name,
                        "arguments": tc.arguments,
                        "result_preview": rp,
                    })
                })
                .collect();
            tr_map.insert("tool_calls".to_string(), Value::Array(tcs));
        }
        transcript_records.push(Value::Object(tr_map));
        step_idx += 1;
    }

    BuiltSteps {
        db_steps,
        transcript_records,
        fts_user,
        fts_agent,
        last_user_sec,
        last_user_nanos,
        last_user_step_idx,
    }
}

pub fn backup_existing_stores(antigravity_dir: &Path, backup_dir: Option<&Path>) -> Result<PathBuf, String> {
    let bdir = match backup_dir {
        Some(p) => p.to_path_buf(),
        None => antigravity_dir.join("backups").join("pre_claude_import"),
    };
    fs::create_dir_all(&bdir).map_err(|e| format!("create backup dir: {}", e))?;
    for fname in [
        "conversation_summaries.db",
        "conversation_summaries.db-wal",
        "conversation_summaries.db-shm",
        "agyhub_summaries_proto.pb",
    ] {
        let src = antigravity_dir.join(fname);
        let dst = bdir.join(fname);
        if src.exists() && !dst.exists() {
            fs::copy(&src, &dst).map_err(|e| format!("backup {}: {}", fname, e))?;
        }
    }
    Ok(bdir)
}

#[derive(Debug, Clone)]
pub struct ImportOptions {
    pub claude_projects_dir: PathBuf,
    pub antigravity_dir: PathBuf,
    pub explicit_projects: Option<Vec<String>>,
    pub include_all_projects: bool,
    pub dry_run: bool,
    pub create_backup: bool,
    pub force: bool,
    pub limit: Option<usize>,
    pub resume_checkpoint: bool,
}

impl Default for ImportOptions {
    fn default() -> Self {
        Self {
            claude_projects_dir: default_claude_projects_dir(),
            antigravity_dir: default_antigravity_dir(),
            explicit_projects: None,
            include_all_projects: false,
            dry_run: false,
            create_backup: true,
            force: false,
            limit: None,
            resume_checkpoint: false,
        }
    }
}

fn load_checkpoint_ids(ckpt_path: &Path) -> HashSet<String> {
    let mut done = HashSet::new();
    let Some(val) = rio::read_json(ckpt_path) else {
        return done;
    };
    if let Some(arr) = val.get("completed_ids").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(s) = item.as_str() {
                if !s.is_empty() {
                    done.insert(s.to_string());
                }
            }
        }
    }
    done
}

fn save_checkpoint_ids(ckpt_path: &Path, done: &HashSet<String>, finished: bool) {
    let mut sorted: Vec<String> = done.iter().cloned().collect();
    sorted.sort();
    let payload = json!({
        "completed_ids": sorted,
        "completed": finished,
    });
    let _ = rio::write_json(ckpt_path, &payload);
}

fn fetch_durable_checkpoint_raw_summary(
    antigravity_dir: &Path,
    conn: &SqliteConn,
    conv_id: &str,
) -> Option<Vec<u8>> {
    let conv_db = antigravity_dir.join("conversations").join(format!("{}.db", conv_id));
    let ann_pbtxt = antigravity_dir.join("annotations").join(format!("{}.pbtxt", conv_id));
    let logs_dir = antigravity_dir
        .join("brain")
        .join(conv_id)
        .join(".system_generated")
        .join("logs");
    if !conv_db.is_file()
        || !ann_pbtxt.is_file()
        || !logs_dir.join("transcript.jsonl").is_file()
        || !logs_dir.join("transcript_full.jsonl").is_file()
    {
        return None;
    }
    let rows = conn
        .query(
            "SELECT raw_summary FROM conversation_summaries WHERE conversation_id = ?",
            &[SqlParam::Text(conv_id.to_string())],
        )
        .ok()?;
    let raw = rows.first()?.first()?.as_bytes().to_vec();
    if raw.len() < 50 {
        return None;
    }
    let fts_rows = conn
        .query(
            "SELECT COUNT(*) FROM conversations_fts WHERE conversation_id = ?",
            &[SqlParam::Text(conv_id.to_string())],
        )
        .ok()?;
    if fts_rows.first()?.first()?.as_i64() < 1 {
        return None;
    }
    Some(raw)
}

pub fn run_import(opts: &ImportOptions) -> Result<Value, String> {
    let mut prepared = collect_and_prepare_sessions(
        &opts.claude_projects_dir,
        opts.explicit_projects.as_deref(),
        opts.include_all_projects,
    );
    if let Some(lim) = opts.limit {
        prepared.truncate(lim);
    }

    let mut by_project: BTreeMap<String, usize> = BTreeMap::new();
    for (_, _, sess, _) in &prepared {
        *by_project.entry(sess.project_folder.clone()).or_insert(0) += 1;
    }

    if opts.dry_run {
        let sessions_preview: Vec<Value> = prepared
            .iter()
            .map(|(cid, title, sess, turns)| {
                json!({
                    "conversation_id": cid,
                    "title": title,
                    "project": sess.project_folder,
                    "cwd": sess.cwd,
                    "turns": turns.len(),
                })
            })
            .collect();
        return Ok(json!({
            "ok": true,
            "dry_run": true,
            "sessions_count": prepared.len(),
            "by_project": by_project,
            "sessions": sessions_preview,
        }));
    }

    fs::create_dir_all(&opts.antigravity_dir)
        .map_err(|e| format!("create antigravity_dir: {}", e))?;
    let backup_path = if opts.create_backup {
        backup_existing_stores(&opts.antigravity_dir, None)?
            .to_string_lossy()
            .into_owned()
    } else {
        String::new()
    };

    let ckpt_path = opts.antigravity_dir.join("import_checkpoint.json");
    let mut done_ids = if opts.resume_checkpoint {
        load_checkpoint_ids(&ckpt_path)
    } else {
        HashSet::new()
    };

    let summaries_db_path = opts.antigravity_dir.join("conversation_summaries.db");
    let conn = SqliteConn::open(
        &summaries_db_path,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
    )?;
    conn.set_busy_timeout(30_000);
    ensure_summaries_db_schema(&conn)?;

    let mut imported_raw_summaries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut newly_imported_count: usize = 0;
    let mut total_steps: i64 = 0;
    let mut checkpointed: usize = 0;
    let mut preserved_active: usize = 0;

    if !opts.resume_checkpoint {
        conn.exec_batch("BEGIN IMMEDIATE;")?;
    }
    let import_res = (|| -> Result<(), String> {
        for (conv_id, final_title, sess, turns) in &prepared {
            if opts.resume_checkpoint && done_ids.contains(conv_id) {
                // SAFETY: Only skip a checkpointed session when all durable disk + SQLite/FTS layers are intact, and carry its raw_summary into `.pb` sync.
                if let Some(existing_raw) =
                    fetch_durable_checkpoint_raw_summary(&opts.antigravity_dir, &conn, conv_id)
                {
                    imported_raw_summaries.insert(conv_id.clone(), existing_raw);
                    preserved_active += 1;
                    continue;
                }
                done_ids.remove(conv_id);
            }
            let trajectory_id = stable_uuid(&format!("{}:trajectory", conv_id));
            let init_state_id = stable_uuid(&format!("{}:init_state", conv_id));

            // SAFETY: Preserve conversations already continued in Antigravity without overwriting live turns.
            if !opts.force
                && is_continued_or_native_db(&opts.antigravity_dir, conv_id, &trajectory_id)
            {
                preserved_active += 1;
                continue;
            }

            let built = build_steps_and_artifacts(
                &opts.antigravity_dir,
                conv_id,
                &trajectory_id,
                final_title,
                sess,
                turns,
            );
            let step_count = built.db_steps.len() as i64;
            total_steps += step_count;
            if built.db_steps.iter().any(|s| s.step_type == 23) {
                checkpointed += 1;
            }

            let traj_meta_bytes = encode_trajectory_metadata(
                conv_id,
                sess.created_sec,
                sess.created_nanos,
                &init_state_id,
            );
            let raw_summary = encode_cascade_summary(CascadeSummarySpec {
                title: final_title,
                step_count,
                last_mod_sec: sess.last_mod_sec,
                last_mod_nanos: sess.last_mod_nanos,
                trajectory_id: &trajectory_id,
                created_sec: sess.created_sec,
                created_nanos: sess.created_nanos,
                last_user_sec: built.last_user_sec,
                last_user_nanos: built.last_user_nanos,
                last_user_step_idx: built.last_user_step_idx,
                traj_meta_bytes: &traj_meta_bytes,
            });

            write_conversation_db(
                &opts.antigravity_dir,
                conv_id,
                &trajectory_id,
                &traj_meta_bytes,
                &built.db_steps,
                sess.last_mod_sec,
                opts.force,
            )?;
            write_annotation_pbtxt(
                &opts.antigravity_dir,
                conv_id,
                final_title,
                sess.last_mod_sec,
                sess.last_mod_nanos,
            )?;
            write_transcript_logs(&opts.antigravity_dir, conv_id, &built.transcript_records)?;

            let last_mod_str = format_sqlite_datetime(sess.last_mod_sec, sess.last_mod_nanos);
            let last_user_str =
                format_sqlite_datetime(built.last_user_sec, built.last_user_nanos);
            let preview_str = turns
                .first()
                .map(|t| clean_preview(&t.user_text, 120))
                .unwrap_or_else(|| final_title.clone());

            if opts.resume_checkpoint {
                conn.exec_batch("BEGIN IMMEDIATE;")?;
            }
            let db_step_res = (|| -> Result<(), String> {
                conn.execute(
                    "INSERT OR REPLACE INTO conversation_summaries (
                        conversation_id, title, preview, step_count, last_modified_time,
                        workspace_uris, status, source, project_id, agent_name,
                        parent_conversation_id, nesting_depth, battle_id, winning_conversation_id,
                        not_fully_idle, killed, last_user_input_time, last_user_input_step_index,
                        app_data_dir, raw_summary, group_id
                    ) VALUES (?, ?, ?, ?, ?, '', 'CASCADE_RUN_STATUS_IDLE', '', 'outside-of-project', '',
                              '', 0, '', '', 0, 0, ?, ?, 'antigravity', ?, '')",
                    &[
                        SqlParam::Text(conv_id.clone()),
                        SqlParam::Text(final_title.clone()),
                        SqlParam::Text(preview_str),
                        SqlParam::Int(step_count),
                        SqlParam::Text(last_mod_str),
                        SqlParam::Text(last_user_str),
                        SqlParam::Int(built.last_user_step_idx),
                        SqlParam::Blob(raw_summary.clone()),
                    ],
                )?;

                conn.execute(
                    "DELETE FROM conversations_fts WHERE conversation_id = ?",
                    &[SqlParam::Text(conv_id.clone())],
                )?;
                let last_mod_ns = timestamp_to_epoch_ns(sess.last_mod_sec, sess.last_mod_nanos);
                conn.execute(
                    "INSERT INTO conversations_fts (
                        conversation_id, chunk_index, chunk_first_step, chunk_last_step,
                        last_modified_time, step_count, last_step_created_at, archived,
                        user_step_byte_offsets, agent_step_byte_offsets,
                        title, workspace, project, user_body, agent_body
                    ) VALUES (?, -1, 0, 0, ?, ?, ?, 0, '', '', ?, '', '', '', '')",
                    &[
                        SqlParam::Text(conv_id.clone()),
                        SqlParam::Int(last_mod_ns),
                        SqlParam::Int(step_count),
                        SqlParam::Int(last_mod_ns),
                        SqlParam::Text(final_title.clone()),
                    ],
                )?;
                let fts_rows = build_fts_chunks(
                    conv_id,
                    &built.fts_user,
                    &built.fts_agent,
                    step_count,
                    last_mod_ns,
                );
                for frow in fts_rows {
                    conn.execute(
                        "INSERT INTO conversations_fts (
                            conversation_id, chunk_index, chunk_first_step, chunk_last_step,
                            last_modified_time, step_count, last_step_created_at, archived,
                            user_step_byte_offsets, agent_step_byte_offsets,
                            title, workspace, project, user_body, agent_body
                        ) VALUES (?, ?, ?, ?, 0, 0, 0, 0, ?, ?, '', '', '', ?, ?)",
                        &[
                            SqlParam::Text(frow.conv_id),
                            SqlParam::Int(frow.chunk_idx),
                            SqlParam::Int(frow.first_step),
                            SqlParam::Int(frow.last_step),
                            SqlParam::Blob(frow.u_offsets),
                            SqlParam::Blob(frow.a_offsets),
                            SqlParam::Text(frow.u_body),
                            SqlParam::Text(frow.a_body),
                        ],
                    )?;
                }
                Ok(())
            })();

            if let Err(err) = db_step_res {
                if opts.resume_checkpoint {
                    let _ = conn.exec_batch("ROLLBACK;");
                }
                return Err(err);
            }
            if opts.resume_checkpoint {
                conn.exec_batch("COMMIT;")?;
                done_ids.insert(conv_id.clone());
                save_checkpoint_ids(&ckpt_path, &done_ids, false);
            }

            imported_raw_summaries.insert(conv_id.clone(), raw_summary);
            newly_imported_count += 1;
        }
        Ok(())
    })();

    if let Err(err) = import_res {
        if !opts.resume_checkpoint {
            let _ = conn.exec_batch("ROLLBACK;");
        }
        return Err(err);
    }
    if !opts.resume_checkpoint {
        conn.exec_batch("COMMIT;")?;
    }
    drop(conn);

    update_agyhub_summaries_pb(&imported_raw_summaries, &opts.antigravity_dir)?;
    if opts.resume_checkpoint {
        save_checkpoint_ids(&ckpt_path, &done_ids, true);
    }

    Ok(json!({
        "ok": true,
        "dry_run": false,
        "sessions_count": newly_imported_count + preserved_active,
        "preserved_active": preserved_active,
        "total_steps": total_steps,
        "with_checkpoint": checkpointed,
        "by_project": by_project,
        "backup_dir": backup_path,
    }))
}

fn read_pb_keys(pb_path: &Path) -> Result<HashSet<String>, String> {
    let mut keys = HashSet::new();
    if !pb_path.exists() {
        return Ok(keys);
    }
    let pb_bytes = fs::read(pb_path).map_err(|e| format!("read pb: {}", e))?;
    for wf in parse_wire_fields(&pb_bytes)? {
        if wf.fn_num == 1 && wf.wt == 2 {
            if let WireValue::Bytes(val) = wf.val {
                for sf in parse_wire_fields(&val)? {
                    if sf.fn_num == 1 && sf.wt == 2 {
                        if let WireValue::Bytes(sval) = sf.val {
                            keys.insert(String::from_utf8_lossy(&sval).into_owned());
                            break;
                        }
                    }
                }
            }
        }
    }
    Ok(keys)
}

pub fn verify_import(
    claude_projects_dir: &Path,
    antigravity_dir: &Path,
    explicit_projects: Option<&[String]>,
    include_all_projects: bool,
    limit: Option<usize>,
) -> Value {
    let mut prepared = collect_and_prepare_sessions(
        claude_projects_dir,
        explicit_projects,
        include_all_projects,
    );
    if let Some(lim) = limit {
        prepared.truncate(lim);
    }
    let expected_ids: HashSet<String> = prepared.iter().map(|(cid, _, _, _)| cid.clone()).collect();
    let mut by_project: BTreeMap<String, usize> = BTreeMap::new();
    for (_, _, sess, _) in &prepared {
        *by_project.entry(sess.project_folder.clone()).or_insert(0) += 1;
    }

    let mut errors: Vec<String> = Vec::new();
    let sum_db = antigravity_dir.join("conversation_summaries.db");
    let mut expected_step_counts: HashMap<String, i64> = HashMap::new();

    if !sum_db.exists() {
        errors.push(format!("Missing conversation_summaries.db: {}", sum_db.display()));
    } else {
        match SqliteConn::open(&sum_db, SQLITE_OPEN_READONLY) {
            Err(e) => errors.push(format!("Failed opening conversation_summaries.db: {}", e)),
            Ok(sconn) => {
                sconn.set_busy_timeout(30_000);
                let mut rows_by_cid: HashMap<String, (String, i64, String, i64, i64, Vec<u8>)> =
                    HashMap::new();
                match sconn.query(
                    "SELECT conversation_id, title, step_count, status, last_user_input_step_index, length(raw_summary), raw_summary FROM conversation_summaries",
                    &[],
                ) {
                    Ok(qrows) => {
                        for r in qrows {
                            let cid = r[0].as_str();
                            let db_title = r[1].as_str();
                            let step_count = r[2].as_i64();
                            let status = r[3].as_str();
                            let last_u_idx = r[4].as_i64();
                            let raw_len = r[5].as_i64();
                            let raw_blob = r[6].as_bytes().to_vec();
                            expected_step_counts.insert(cid.clone(), step_count);
                            rows_by_cid.insert(
                                cid,
                                (db_title, step_count, status, last_u_idx, raw_len, raw_blob),
                            );
                        }
                    }
                    Err(e) => errors.push(format!("Query conversation_summaries failed: {}", e)),
                }

                for (cid, title, _, _) in &prepared {
                    let Some((db_title, step_count, status, last_u_idx, raw_len, raw_blob)) =
                        rows_by_cid.get(cid)
                    else {
                        errors.push(format!("Missing in conversation_summaries: {}", cid));
                        continue;
                    };
                    if db_title != title {
                        errors.push(format!(
                            "Title mismatch for {}: db={:?} vs expected={:?}",
                            cid, db_title, title
                        ));
                    }
                    if status != "CASCADE_RUN_STATUS_IDLE" && status != "CASCADE_RUN_STATUS_RUNNING"
                    {
                        errors.push(format!("Bad status for {}: {}", cid, status));
                    }
                    if *step_count <= 0 || *last_u_idx < -1 {
                        errors.push(format!(
                            "Invalid step counts for {}: step_count={}, last_u_idx={}",
                            cid, step_count, last_u_idx
                        ));
                    }
                    if raw_blob.is_empty() || *raw_len < 50 {
                        errors.push(format!("Invalid raw_summary blob for {}", cid));
                    } else {
                        match parse_wire_fields(raw_blob) {
                            Ok(fields) => {
                                let has_1 = fields.iter().any(|f| f.fn_num == 1);
                                let has_4 = fields.iter().any(|f| f.fn_num == 4);
                                if !has_1 || !has_4 {
                                    errors.push(format!(
                                        "Incomplete raw_summary protobuf fields for {}",
                                        cid
                                    ));
                                }
                            }
                            Err(e) => errors.push(format!(
                                "Failed parsing raw_summary protobuf for {}: {}",
                                cid, e
                            )),
                        }
                    }

                    match sconn.query(
                        "SELECT chunk_index FROM conversations_fts WHERE conversation_id = ?",
                        &[SqlParam::Text(cid.clone())],
                    ) {
                        Ok(fts_chunks) => {
                            let chunk_idxs: HashSet<i64> =
                                fts_chunks.iter().map(|r| r[0].as_i64()).collect();
                            if !chunk_idxs.contains(&-1) || !chunk_idxs.contains(&0) {
                                errors.push(format!(
                                    "Missing FTS chunks for {}: found {:?}",
                                    cid, chunk_idxs
                                ));
                            }
                        }
                        Err(e) => {
                            errors.push(format!("Query conversations_fts failed for {}: {}", cid, e))
                        }
                    }
                }
            }
        }
    }

    let pb_path = antigravity_dir.join("agyhub_summaries_proto.pb");
    let mut pb_keys: HashSet<String> = HashSet::new();
    let mut resynced_pb: usize = 0;
    match read_pb_keys(&pb_path) {
        Ok(keys) => {
            pb_keys = keys;
            let has_missing = expected_ids.iter().any(|id| !pb_keys.contains(id));
            if has_missing && sum_db.exists() {
                // WORKAROUND: Running language_server.exe flushes its startup in-memory map to agyhub_summaries_proto.pb; resync from DB.
                if let Ok(n) = sync_pb_from_db(antigravity_dir) {
                    resynced_pb = n;
                    if let Ok(refreshed) = read_pb_keys(&pb_path) {
                        pb_keys = refreshed;
                    }
                }
            }
        }
        Err(e) => errors.push(format!("Failed parsing agyhub_summaries_proto.pb: {}", e)),
    }

    let mut missing_pb: Vec<String> = expected_ids
        .iter()
        .filter(|id| !pb_keys.contains(*id))
        .cloned()
        .collect();
    missing_pb.sort();
    if !missing_pb.is_empty() {
        errors.push(format!(
            "Missing in agyhub_summaries_proto.pb: {:?}",
            missing_pb
        ));
    }

    let mut total_steps_written: i64 = 0;
    let mut checkpointed_count: usize = 0;

    for (cid, _, _, _) in &prepared {
        let db_path = antigravity_dir
            .join("conversations")
            .join(format!("{}.db", cid));
        if !db_path.exists() {
            errors.push(format!("Missing conversation DB: {}", db_path.display()));
        } else {
            match SqliteConn::open(&db_path, SQLITE_OPEN_READONLY) {
                Err(e) => errors.push(format!("Exception opening {}.db: {}", cid, e)),
                Ok(cc) => {
                    cc.set_busy_timeout(15_000);
                    let check_res = (|| -> Result<(), String> {
                        let ic = cc.query("PRAGMA integrity_check", &[])?[0][0].as_str();
                        let uv = cc.query("PRAGMA user_version", &[])?[0][0].as_i64();
                        let ps = cc.query("PRAGMA page_size", &[])?[0][0].as_i64();
                        if ic != "ok" || uv != 1 || ps != 32768 {
                            errors.push(format!(
                                "Bad SQLite pragmas for {}: ic={}, uv={}, ps={}",
                                cid, ic, uv, ps
                            ));
                        }
                        let tm = cc.query(
                            "SELECT trajectory_id, cascade_id, trajectory_type, source FROM trajectory_meta",
                            &[],
                        )?;
                        if tm.len() != 1
                            || tm[0][1].as_str() != *cid
                            || tm[0][2].as_i64() != 4
                            || tm[0][3].as_i64() != 1
                        {
                            errors.push(format!("Invalid trajectory_meta for {}", cid));
                        }
                        let tmb = cc.query(
                            "SELECT data FROM trajectory_metadata_blob WHERE id='main'",
                            &[],
                        )?;
                        if tmb.is_empty() || tmb[0][0].as_bytes().is_empty() {
                            errors.push(format!("Missing trajectory_metadata_blob for {}", cid));
                        }
                        let sc_db = cc.query("SELECT count(*) FROM steps", &[])?[0][0].as_i64();
                        let expected_sc = expected_step_counts.get(cid).copied().unwrap_or(-1);
                        if sc_db != expected_sc || sc_db <= 0 {
                            errors.push(format!(
                                "Step count mismatch for {}: steps_table={} vs summary={}",
                                cid, sc_db, expected_sc
                            ));
                        }
                        total_steps_written += sc_db;
                        let ck_cnt = cc
                            .query("SELECT count(*) FROM steps WHERE step_type=23", &[])?[0][0]
                            .as_i64();
                        if ck_cnt > 0 {
                            checkpointed_count += 1;
                        }
                        let last_idx = sc_db - 1;
                        let s_rows = cc.query(
                            "SELECT idx, step_type, status, metadata, step_payload FROM steps WHERE idx IN (0, ?)",
                            &[SqlParam::Int(last_idx)],
                        )?;
                        for s_row in s_rows {
                            let s_idx = s_row[0].as_i64();
                            let s_type = s_row[1].as_i64();
                            let s_stat = s_row[2].as_i64();
                            let s_meta = s_row[3].as_bytes();
                            let s_pay = s_row[4].as_bytes();
                            if s_stat != 3 {
                                errors.push(format!("Step {} status != 3 in {}", s_idx, cid));
                            }
                            let _ = parse_wire_fields(s_meta)?;
                            let pfields = parse_wire_fields(s_pay)?;
                            let p_type = pfields
                                .iter()
                                .find(|f| f.fn_num == 1)
                                .and_then(|f| match f.val {
                                    WireValue::Varint(v) => Some(v as i64),
                                    _ => None,
                                });
                            if p_type != Some(s_type) {
                                errors.push(format!(
                                    "Step payload type mismatch in {} idx={}",
                                    cid, s_idx
                                ));
                            }
                        }
                        Ok(())
                    })();
                    if let Err(e) = check_res {
                        errors.push(format!("Exception checking {}.db: {}", cid, e));
                    }
                }
            }
        }

        let ann_path = antigravity_dir
            .join("annotations")
            .join(format!("{}.pbtxt", cid));
        if !ann_path.exists() {
            errors.push(format!("Missing annotation pbtxt: {}", ann_path.display()));
        } else {
            match fs::read_to_string(&ann_path) {
                Ok(txt) => {
                    if !txt.contains("permission_preset:AGENT_PERMISSION_PRESET_TURBO")
                        || !txt.contains("title:\"")
                    {
                        errors.push(format!(
                            "Invalid annotation pbtxt content: {}",
                            ann_path.display()
                        ));
                    }
                }
                Err(e) => errors.push(format!("Read annotation pbtxt failed: {}", e)),
            }
        }

        for tname in ["transcript.jsonl", "transcript_full.jsonl"] {
            let tp = antigravity_dir
                .join("brain")
                .join(cid)
                .join(".system_generated")
                .join("logs")
                .join(tname);
            let non_empty = fs::metadata(&tp).map(|m| m.len() > 0).unwrap_or(false);
            if !tp.exists() || !non_empty {
                errors.push(format!("Missing or empty transcript: {}", tp.display()));
            } else if let Ok(f) = File::open(&tp) {
                let mut br = BufReader::new(f);
                let mut first_line = String::new();
                if br.read_line(&mut first_line).is_ok() {
                    match serde_json::from_str::<Value>(first_line.trim()) {
                        Ok(obj) => {
                            if obj.get("step_index").is_none() || obj.get("type").is_none() {
                                errors.push(format!("Malformed JSONL header in {}", tp.display()));
                            }
                        }
                        Err(e) => errors.push(format!(
                            "Malformed JSONL header in {}: {}",
                            tp.display(),
                            e
                        )),
                    }
                }
            }
        }
    }

    json!({
        "ok": errors.is_empty(),
        "sessions_verified": prepared.len(),
        "by_project": by_project,
        "total_steps": total_steps_written,
        "with_checkpoint": checkpointed_count,
        "pb_total_entries": pb_keys.len(),
        "resynced_pb": resynced_pb,
        "errors": errors,
    })
}

fn print_usage() {
    println!(
        "usage: carbon-stack claude-importer [--claude-projects-dir DIR] [--antigravity-dir DIR] [--projects LIST] [--include-all-projects] [--dry-run] [--sync-pb-only] [--verify|--verify-only] [--no-backup] [--force] [--limit N] [--resume] [--json]"
    );
}

pub fn run_cli(args: &[String]) -> i32 {
    let mut opts = ImportOptions::default();
    let mut explicit_projects_vec: Vec<String> = Vec::new();
    let mut sync_pb_only = false;
    let mut verify_mode = false;
    let mut json_mode = false;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "-h" | "--help" => {
                print_usage();
                return 0;
            }
            "--claude-projects-dir" | "--claude-dir" => {
                if i + 1 >= args.len() {
                    eprintln!("claude-importer: missing value for {}", arg);
                    return 2;
                }
                i += 1;
                opts.claude_projects_dir = PathBuf::from(&args[i]);
            }
            "--antigravity-dir" | "--agy-dir" => {
                if i + 1 >= args.len() {
                    eprintln!("claude-importer: missing value for {}", arg);
                    return 2;
                }
                i += 1;
                opts.antigravity_dir = PathBuf::from(&args[i]);
            }
            "--projects" | "--project" => {
                if i + 1 >= args.len() {
                    eprintln!("claude-importer: missing value for {}", arg);
                    return 2;
                }
                i += 1;
                for part in args[i].split(',') {
                    let t = part.trim();
                    if !t.is_empty() {
                        explicit_projects_vec.push(t.to_string());
                    }
                }
            }
            "--limit" => {
                if i + 1 >= args.len() {
                    eprintln!("claude-importer: missing value for --limit");
                    return 2;
                }
                i += 1;
                match args[i].parse::<usize>() {
                    Ok(n) => opts.limit = Some(n),
                    Err(_) => {
                        eprintln!("claude-importer: invalid --limit '{}'", args[i]);
                        return 2;
                    }
                }
            }
            "--include-all-projects" => opts.include_all_projects = true,
            "--dry-run" => opts.dry_run = true,
            "--sync-pb-only" => sync_pb_only = true,
            "--verify" | "--verify-only" => verify_mode = true,
            "--no-backup" => opts.create_backup = false,
            "--force" => opts.force = true,
            "--resume" => opts.resume_checkpoint = true,
            "--json" => json_mode = true,
            other => {
                if let Some(val) = other
                    .strip_prefix("--claude-projects-dir=")
                    .or_else(|| other.strip_prefix("--claude-dir="))
                {
                    opts.claude_projects_dir = PathBuf::from(val);
                } else if let Some(val) = other
                    .strip_prefix("--antigravity-dir=")
                    .or_else(|| other.strip_prefix("--agy-dir="))
                {
                    opts.antigravity_dir = PathBuf::from(val);
                } else if let Some(val) = other
                    .strip_prefix("--projects=")
                    .or_else(|| other.strip_prefix("--project="))
                {
                    for part in val.split(',') {
                        let t = part.trim();
                        if !t.is_empty() {
                            explicit_projects_vec.push(t.to_string());
                        }
                    }
                } else if let Some(val) = other.strip_prefix("--limit=") {
                    match val.parse::<usize>() {
                        Ok(n) => opts.limit = Some(n),
                        Err(_) => {
                            eprintln!("claude-importer: invalid --limit '{}'", val);
                            return 2;
                        }
                    }
                } else {
                    eprintln!("claude-importer: unknown argument '{}'", other);
                    return 2;
                }
            }
        }
        i += 1;
    }

    if !explicit_projects_vec.is_empty() {
        opts.explicit_projects = Some(explicit_projects_vec);
    }

    if sync_pb_only {
        match sync_pb_from_db(&opts.antigravity_dir) {
            Ok(n) => {
                if json_mode {
                    rio::print_cli_json(&json!({"ok": true, "synced_count": n}), false);
                } else {
                    println!(
                        "Synced {} summaries from conversation_summaries.db to agyhub_summaries_proto.pb.",
                        n
                    );
                }
                return 0;
            }
            Err(e) => {
                eprintln!("claude-importer: sync-pb failed: {}", e);
                return 1;
            }
        }
    }

    if verify_mode {
        let res = verify_import(
            &opts.claude_projects_dir,
            &opts.antigravity_dir,
            opts.explicit_projects.as_deref(),
            opts.include_all_projects,
            opts.limit,
        );
        if json_mode {
            rio::print_cli_json(&res, true);
        } else {
            println!(
                "Verified {} sessions | total_steps={} | with_checkpoint={} | pb_entries={}",
                res["sessions_verified"],
                res["total_steps"],
                res["with_checkpoint"],
                res["pb_total_entries"]
            );
            if let Some(errs) = res["errors"].as_array() {
                if errs.is_empty() {
                    println!("ALL_CHECKS_PASSED");
                } else {
                    for err in errs.iter().take(30) {
                        println!(" - {}", err.as_str().unwrap_or(""));
                    }
                }
            }
        }
        return if res["ok"].as_bool() == Some(true) {
            0
        } else {
            1
        };
    }

    match run_import(&opts) {
        Ok(res) => {
            if json_mode {
                rio::print_cli_json(&res, true);
            } else if opts.dry_run {
                println!(
                    "Dry run: found {} interactive sessions -> {}",
                    res["sessions_count"], res["by_project"]
                );
            } else {
                println!(
                    "Successfully imported {} conversations ({} steps, {} checkpoints) across all 5 Antigravity storage layers.",
                    res["sessions_count"], res["total_steps"], res["with_checkpoint"]
                );
            }
            0
        }
        Err(e) => {
            if json_mode {
                rio::print_cli_json(&json!({"ok": false, "error": e}), true);
            } else {
                eprintln!("claude-importer: {}", e);
            }
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_regexes_compile() {
        assert!(excluded_project_re().is_match("foo-bench"));
        assert!(excluded_project_re().is_match("bar-SHIM"));
        assert!(excluded_project_re().is_match("my-scratchpad-1"));
        assert!(!excluded_project_re().is_match("gemini-carbon-stack"));
        assert!(shim_prompt_re().is_match("<<SYSTEM>> Ты — помощник"));
        assert!(!shim_prompt_re().is_match("Hello world"));
        assert!(home_proj_re().is_match("C--Users-in"));
        assert!(drive_prefix_re().is_match("C--repo"));
        assert!(drive_cwd_re().is_match("D--work-app"));
        assert!(html_tag_re().is_match("<tag>x</tag>"));
        assert!(ws_re().is_match("a \n\t b"));
        assert!(iso_frac_re().is_match("2026-11-17T12:00:00.123Z"));
    }

    #[test]
    fn test_sha1_and_deterministic_uuid() {
        assert_eq!(
            hex::encode(sha1_digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex::encode(sha1_digest(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            deterministic_uuid("test-seed"),
            "02e41cc3-f56b-57e0-bf38-7fba5d585f1b"
        );
        assert_eq!(
            stable_hex32("test-seed"),
            "02e41cc3f56b57e0bf387fba5d585f1b"
        );
    }

    #[test]
    fn test_protobuf_wire_roundtrip() {
        let traj_meta = encode_trajectory_metadata("conv-123", 1_760_000_000, 123_456_789, "init-1");
        let parsed_tm = parse_wire_fields(&traj_meta).expect("parse traj_meta");
        assert!(parsed_tm.iter().any(|f| f.fn_num == 6
            && matches!(&f.val, WireValue::Bytes(b) if b == b"conv-123")));
        assert!(parsed_tm.iter().any(|f| f.fn_num == 18
            && matches!(&f.val, WireValue::Bytes(b) if b == b"outside-of-project")));

        let step_meta = encode_step_metadata(StepMetadataSpec {
            trajectory_id: "traj-1",
            conversation_id: "conv-123",
            step_idx: 0,
            meta_idx: 0,
            source: 4,
            created_sec: 1_760_000_000,
            created_nanos: 0,
            completed_sec: 1_760_000_005,
            completed_nanos: 500,
            exec_id: "exec-1",
            content_id: "content-1",
            is_model: true,
        });
        let u_step = encode_user_input_step(&step_meta, "Привет, мир!", "msg-1");
        let parsed_u = parse_wire_fields(&u_step).expect("parse u_step");
        assert_eq!(parsed_u[0].fn_num, 1);
        assert_eq!(parsed_u[0].val, WireValue::Varint(14));

        let sum = encode_cascade_summary(CascadeSummarySpec {
            title: "Test Title",
            step_count: 2,
            last_mod_sec: 1_760_000_010,
            last_mod_nanos: 0,
            trajectory_id: "traj-1",
            created_sec: 1_760_000_000,
            created_nanos: 0,
            last_user_sec: 1_760_000_000,
            last_user_nanos: 0,
            last_user_step_idx: 0,
            traj_meta_bytes: &traj_meta,
        });
        let parsed_sum = parse_wire_fields(&sum).expect("parse summary");
        assert!(parsed_sum.iter().any(|f| f.fn_num == 1
            && matches!(&f.val, WireValue::Bytes(b) if b == b"Test Title")));
        assert!(parsed_sum.iter().any(|f| f.fn_num == 2 && f.val == WireValue::Varint(2)));
        assert!(parsed_sum.iter().any(|f| f.fn_num == 16 && f.val == WireValue::Varint(0)));

        let bfield = field_bool(9, true, false);
        let parsed_b = parse_wire_fields(&bfield).expect("parse bool");
        assert_eq!(parsed_b[0].fn_num, 9);
        assert_eq!(parsed_b[0].val, WireValue::Varint(1));
    }

    #[test]
    fn test_end_to_end_import_and_verify() {
        let base = std::env::temp_dir().join(format!("claude-imp-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let claude_dir = base.join("claude_projects");
        let proj_dir = claude_dir.join("D--demo-repo");
        let agy_dir = base.join("antigravity");
        fs::create_dir_all(&proj_dir).expect("create proj_dir");

        let jsonl_path = proj_dir.join("sess-alpha-001.jsonl");
        let lines = [
            json!({
                "type": "custom-title",
                "customTitle": "Демо сессия импорта",
                "timestamp": "2026-11-17T10:00:00Z"
            }),
            json!({
                "type": "user",
                "uuid": "u-1",
                "cwd": "D:\\demo\\repo",
                "timestamp": "2026-11-17T10:00:01.250Z",
                "message": {"role": "user", "content": "Проверь статус файла main.rs"}
            }),
            json!({
                "type": "assistant",
                "timestamp": "2026-11-17T10:00:02.500Z",
                "message": {
                    "role": "assistant",
                    "content": [
                        {"type": "thinking", "thinking": "Сначала прочитаем файл."},
                        {"type": "tool_use", "id": "tu-1", "name": "Read", "input": {"file_path": "main.rs"}},
                        {"type": "text", "text": "Файл main.rs проверен."}
                    ]
                }
            }),
            json!({
                "type": "user",
                "uuid": "u-2",
                "timestamp": "2026-11-17T10:00:03.000Z",
                "message": {
                    "role": "user",
                    "content": [
                        {"type": "tool_result", "tool_use_id": "tu-1", "content": "fn main() {}"}
                    ]
                }
            }),
        ];
        let mut body = String::new();
        for l in &lines {
            body.push_str(&serde_json::to_string(l).unwrap());
            body.push('\n');
        }
        fs::write(&jsonl_path, body.as_bytes()).expect("write jsonl");

        let opts = ImportOptions {
            claude_projects_dir: claude_dir.clone(),
            antigravity_dir: agy_dir.clone(),
            explicit_projects: None,
            include_all_projects: false,
            dry_run: false,
            create_backup: false,
            force: false,
            limit: None,
            resume_checkpoint: false,
        };
        let imp = run_import(&opts).expect("run_import");
        assert_eq!(imp["ok"], json!(true));
        assert_eq!(imp["sessions_count"], json!(1));
        assert_eq!(imp["total_steps"], json!(2));

        let ver = verify_import(&claude_dir, &agy_dir, None, false, None);
        assert_eq!(ver["ok"], json!(true), "verify errors: {:?}", ver["errors"]);
        assert_eq!(ver["sessions_verified"], json!(1));
        assert_eq!(ver["total_steps"], json!(2));
        assert_eq!(ver["pb_total_entries"], json!(1));

        // INVARIANT: `--resume` recovers `.pb` when deleted post-COMMIT and re-imports any checkpoint ID missing from SQLite.
        let pb_file = agy_dir.join("agyhub_summaries_proto.pb");
        fs::remove_file(&pb_file).expect("remove pb");
        let cid = {
            let sconn = SqliteConn::open(
                &agy_dir.join("conversation_summaries.db"),
                SQLITE_OPEN_READONLY,
            )
            .unwrap();
            sconn
                .query("SELECT conversation_id FROM conversation_summaries LIMIT 1", &[])
                .unwrap()[0][0]
                .as_str()
        };
        let mut ckpt_ids = HashSet::new();
        ckpt_ids.insert(cid.clone());
        save_checkpoint_ids(&agy_dir.join("import_checkpoint.json"), &ckpt_ids, false);

        let resume_opts = ImportOptions {
            resume_checkpoint: true,
            ..opts.clone()
        };
        let res_pb = run_import(&resume_opts).expect("resume pb recovery");
        assert_eq!(res_pb["ok"], json!(true));
        assert_eq!(res_pb["preserved_active"], json!(1));
        assert!(pb_file.is_file());
        let ver_pb = verify_import(&claude_dir, &agy_dir, None, false, None);
        assert_eq!(ver_pb["ok"], json!(true), "verify after pb recovery: {:?}", ver_pb["errors"]);

        // INVARIANT: Simulate rolled-back SQLite summary while checkpoint still lists `cid` -> `--resume` must re-import instead of skipping.
        {
            let sconn = SqliteConn::open(
                &agy_dir.join("conversation_summaries.db"),
                SQLITE_OPEN_READWRITE,
            )
            .unwrap();
            sconn
                .execute(
                    "DELETE FROM conversation_summaries WHERE conversation_id = ?",
                    &[SqlParam::Text(cid.clone())],
                )
                .unwrap();
        }
        save_checkpoint_ids(&agy_dir.join("import_checkpoint.json"), &ckpt_ids, false);
        let res_rb = run_import(&resume_opts).expect("resume rolled-back recovery");
        assert_eq!(res_rb["ok"], json!(true));
        assert_eq!(res_rb["preserved_active"], json!(0));
        let ver_rb = verify_import(&claude_dir, &agy_dir, None, false, None);
        assert_eq!(ver_rb["ok"], json!(true), "verify after rollback recovery: {:?}", ver_rb["errors"]);

        let _ = fs::remove_dir_all(&base);
    }
}
