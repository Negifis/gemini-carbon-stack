use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::cwg_common;
use crate::rio::{
    self, file_mtime_ns, json_truthy, sha256_hex, truncate_chars, val_to_f64, val_to_i64,
    val_to_str,
};
use crate::win32_sqlite::{format_iso_utc, now_sec};

pub const READ_REPEAT_DENY_LIMIT: i64 = 3;
pub const CMD_REPEAT_WARN_LIMIT: i64 = 3;
pub const HANDOFF_MAX_CHARS: usize = 900;
pub const MAX_LINT_BLOCKS_PER_EPISODE: i64 = 2;
pub const TREE_LOCK_TTL_SECONDS: f64 = 1800.0;

const HANDOFF_PRIORITY_INDEX: usize = 2;
const HANDOFF_MIN_TRUNCATE_REMAINING: usize = 40;

pub const CANONICAL_SECTIONS: &[&str] = &[
    "GOAL",
    "STATUS",
    "AUTHORITATIVE STATE",
    "SUPERSEDED / CANCELLED",
    "COMPLETED",
    "CURRENT STATE",
    "DELEGATED / OWNERS",
    "NEXT ACTION",
    "ACCEPTANCE",
    "BLOCKERS",
    "STOP CONDITION",
];

fn test_runner_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:pytest|py\.test|unittest|npm\s+test|pnpm\s+test|yarn\s+test|cargo\s+test|go\s+test|dotnet\s+test)\b",
        )
        .expect("test_runner_re")
    })
}

fn strong_correction_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:\b(?:нет,\s*(?:не\s+так|переделай|отмени|убери|верни)|не\s+возвращай|вместо\s+этого\s+сделай|отменяю\s+требование|забудь\s+предыдущ)|\b(?:no,\s*(?:instead|revert|undo|drop\s+that|wrong\s+approach)|do\s+not\s+bring\s+back|discard\s+the\s+previous|stop\s+doing\s+that)\b)",
        )
        .expect("strong_correction_re")
    })
}

fn edit_residue_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:в\s+предыдущей\s+(?:версии|попытке)\s+я\s+(?:сделал|написал)|сначала\s+я\s+реализовал\s+[^.\n]{3,60},\s*но\s+затем\s+исправил|как\s+я\s+уже\s+писал\s+до\s+исправления|in\s+my\s+earlier\s+(?:attempt|draft)\s+I\s+(?:wrote|used)|initially\s+I\s+implemented\s+[^.\n]{3,60},\s*but\s+now\s+I\s+changed\s+it)",
        )
        .expect("edit_residue_re")
    })
}

fn lint_waiver_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^\[lint\]\s*intentional\s*[:-]\s*\S.*$").expect("lint_waiver_re")
    })
}

fn section_hdr_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^##\s+(.+?)\s*$").expect("section_hdr_re"))
}

fn closed_status_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^(?:done|completed|closed|cancelled|finished)\b")
            .expect("closed_status_re")
    })
}

fn char_len(s: &str) -> usize {
    s.chars().count()
}

fn eprintln_str(msg: &str) {
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(msg.as_bytes());
    let _ = err.flush();
}

pub fn continuity_dir(parts: &[&str]) -> PathBuf {
    let mut target = rio::state_dir().join("continuity");
    for part in parts {
        target.push(part);
    }
    let _ = fs::create_dir_all(&target);
    target
}

pub fn session_state_path(session: &str) -> PathBuf {
    continuity_dir(&["sessions"]).join(format!("{}.json", session))
}

pub fn checkpoint_path(pkey: &str) -> PathBuf {
    continuity_dir(&["checkpoints"]).join(format!("{}.md", pkey))
}

pub fn workspace_checkpoint_path(cwd: &str) -> PathBuf {
    Path::new(cwd).join(".agents").join("CHECKPOINT.md")
}

pub fn resolve_checkpoint_file(
    cwd: &str,
    workspace_paths: &[String],
    pkey: Option<&str>,
    session: &str,
) -> Option<PathBuf> {
    let ws_cp = if cwd.is_empty() {
        None
    } else {
        Some(workspace_checkpoint_path(cwd))
    };
    let has_ws = ws_cp.as_ref().map_or(false, |p| p.is_file());
    let eff_pkey = match pkey {
        Some(k) if !k.is_empty() => k.to_string(),
        _ => rio::project_key(cwd, workspace_paths, "", session),
    };
    let cp_file = checkpoint_path(&eff_pkey);
    let has_state = cp_file.is_file();
    if has_ws && has_state {
        if let Some(ws) = ws_cp {
            match (file_mtime_ns(&ws), file_mtime_ns(&cp_file)) {
                (Some(wm), Some(cm)) => {
                    return Some(if wm >= cm { ws } else { cp_file });
                }
                _ => return Some(ws),
            }
        }
    }
    if has_ws {
        return ws_cp;
    }
    if has_state {
        Some(cp_file)
    } else {
        None
    }
}

pub fn handoff_path(pkey: &str) -> PathBuf {
    continuity_dir(&["handoffs"]).join(format!("{}.json", pkey))
}

pub fn workspace_handoff_path(cwd: &str) -> PathBuf {
    Path::new(cwd).join(".agents").join("handoff.json")
}

fn resolve_handoff(
    cwd: &str,
    workspace_paths: &[String],
    pkey: Option<&str>,
    session: &str,
) -> (Option<PathBuf>, Option<Map<String, Value>>) {
    let ws_ho = if cwd.is_empty() {
        None
    } else {
        Some(workspace_handoff_path(cwd))
    };
    let has_ws = ws_ho.as_ref().map_or(false, |p| p.is_file());
    let eff_pkey = match pkey {
        Some(k) if !k.is_empty() => k.to_string(),
        _ => rio::project_key(cwd, workspace_paths, "", session),
    };
    let ho_file = handoff_path(&eff_pkey);
    let has_state = ho_file.is_file();
    if !has_ws && !has_state {
        return (None, None);
    }

    let ws_dict = if has_ws {
        ws_ho
            .as_ref()
            .and_then(|p| rio::read_json(p))
            .and_then(|v| match v {
                Value::Object(m) => Some(m),
                _ => None,
            })
    } else {
        None
    };
    let st_dict = if has_state {
        rio::read_json(&ho_file).and_then(|v| match v {
            Value::Object(m) => Some(m),
            _ => None,
        })
    } else {
        None
    };

    if has_ws && has_state {
        if let Some(ws) = ws_ho {
            if ws_dict.is_some() && st_dict.is_none() {
                return (Some(ws), ws_dict);
            }
            if st_dict.is_some() && ws_dict.is_none() {
                return (Some(ho_file), st_dict);
            }
            if let (Some(wd), Some(sd)) = (&ws_dict, &st_dict) {
                if let (Some(wt), Some(st)) = (wd.get("updated_ts"), sd.get("updated_ts")) {
                    if wt.is_number() && st.is_number() {
                        if val_to_f64(Some(wt)) >= val_to_f64(Some(st)) {
                            return (Some(ws), ws_dict);
                        }
                        return (Some(ho_file), st_dict);
                    }
                }
            }
            if let (Some(wm), Some(sm)) = (file_mtime_ns(&ws), file_mtime_ns(&ho_file)) {
                if wm >= sm {
                    return (Some(ws), ws_dict);
                }
                return (Some(ho_file), st_dict);
            }
            return (Some(ws), ws_dict);
        }
    }
    if has_ws {
        return (ws_ho, ws_dict);
    }
    (Some(ho_file), st_dict)
}

pub fn load_handoff(
    cwd: &str,
    workspace_paths: &[String],
    pkey: Option<&str>,
    session: &str,
) -> Option<Value> {
    resolve_handoff(cwd, workspace_paths, pkey, session)
        .1
        .map(Value::Object)
}

fn checkpoint_supersedes_closed_handoff(cp_file: &Path, ho_path: Option<&Path>) -> bool {
    let Some(hp) = ho_path else {
        return true;
    };
    match (file_mtime_ns(cp_file), file_mtime_ns(hp)) {
        (Some(cm), Some(hm)) => cm > hm,
        _ => false,
    }
}

pub fn is_closed_status(status: &str) -> bool {
    closed_status_re().is_match(status.trim())
}

pub fn handoff_items(ho: &Map<String, Value>, key: &str) -> Vec<String> {
    match ho.get(key) {
        Some(Value::String(s)) => s
            .split(';')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect(),
        Some(Value::Array(arr)) => arr
            .iter()
            .map(|x| val_to_str(Some(x)).trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

pub fn handoff_constraints(ho: &Map<String, Value>) -> (Vec<String>, Vec<String>) {
    (handoff_items(ho, "decisions"), handoff_items(ho, "superseded"))
}

pub fn active_constraints(
    cwd: &str,
    workspace_paths: &[String],
    pkey: Option<&str>,
    session: &str,
) -> (String, String) {
    let eff_pkey = match pkey {
        Some(k) if !k.is_empty() => k.to_string(),
        _ => rio::project_key(cwd, workspace_paths, "", session),
    };
    let (ho_path, raw_ho) = resolve_handoff(cwd, workspace_paths, Some(&eff_pkey), session);
    let ho_closed = raw_ho
        .as_ref()
        .map_or(false, |ho| is_closed_status(&val_to_str(ho.get("status"))));
    if let Some(ref ho) = raw_ho {
        if !ho_closed {
            let (decs, sups) = handoff_constraints(ho);
            return (
                truncate_chars(&decs.join("; "), 400).to_string(),
                truncate_chars(&sups.join("; "), 300).to_string(),
            );
        }
    }
    let cp_file = resolve_checkpoint_file(cwd, workspace_paths, Some(&eff_pkey), session);
    if let Some(cp) = cp_file {
        if raw_ho.is_none()
            || (ho_closed && checkpoint_supersedes_closed_handoff(&cp, ho_path.as_deref()))
        {
            if let Ok(text) = fs::read_to_string(&cp) {
                let secs = parse_checkpoint_sections(&text);
                let st = secs.get("STATUS").map(String::as_str).unwrap_or("");
                if !is_closed_status(st) {
                    let auth = secs
                        .get("AUTHORITATIVE STATE")
                        .map(|s| s.trim())
                        .unwrap_or("");
                    let sup = secs
                        .get("SUPERSEDED / CANCELLED")
                        .map(|s| s.trim())
                        .unwrap_or("");
                    let out_auth = if auth == "—" {
                        String::new()
                    } else {
                        truncate_chars(auth, 400).to_string()
                    };
                    let out_sup = if sup == "—" {
                        String::new()
                    } else {
                        truncate_chars(sup, 300).to_string()
                    };
                    return (out_auth, out_sup);
                }
            }
        }
    }
    (String::new(), String::new())
}

fn collect_git_brief(cwd: &str) -> Option<Map<String, Value>> {
    let git_root = rio::git_toplevel(cwd, false)?;
    let (rc_b, branch, _) = rio::run_git(&git_root, &["rev-parse", "--abbrev-ref", "HEAD"], 3.0);
    let (rc_s, st_out, _) = rio::run_git(&git_root, &["status", "--short"], 3.0);
    let (rc_d, diff_out, _) = rio::run_git(&git_root, &["diff", "--stat"], 3.0);
    let st_lines: Vec<String> = if rc_s == 0 {
        st_out
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    } else {
        Vec::new()
    };
    let diff_lines: Vec<String> = if rc_d == 0 {
        diff_out
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    } else {
        Vec::new()
    };
    let mut map = Map::new();
    map.insert(
        "git_root".to_string(),
        Value::String(rio::normalize_path(&git_root)),
    );
    map.insert(
        "branch".to_string(),
        Value::String(if rc_b == 0 {
            branch.trim().to_string()
        } else {
            String::new()
        }),
    );
    map.insert(
        "status_short".to_string(),
        Value::Array(st_lines.iter().take(6).cloned().map(Value::String).collect()),
    );
    map.insert("status_total".to_string(), json!(st_lines.len()));
    map.insert(
        "diff_stat".to_string(),
        Value::Array(diff_lines.iter().take(6).cloned().map(Value::String).collect()),
    );
    Some(map)
}

fn open_candidate_brief(session: &str) -> String {
    if session.is_empty() {
        return String::new();
    }
    let Some(Value::Object(marker)) = cwg_common::read_marker_with_pending(session) else {
        return String::new();
    };
    if json_truthy(marker.get("closed")) {
        return String::new();
    }
    let paths: Vec<String> = marker
        .get("paths")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter(|s| !s.is_empty() && *s != "<shell-mutation>")
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();
    if !paths.is_empty() {
        let names: Vec<String> = paths
            .iter()
            .take(4)
            .map(|p| {
                let norm = rio::normalize_path(p);
                norm.rsplit('/').next().unwrap_or(&norm).to_string()
            })
            .collect();
        return format!("PERSISTENT files={} ({})", paths.len(), names.join(", "));
    }
    if json_truthy(marker.get("operational")) {
        return "OPERATIONAL".to_string();
    }
    String::new()
}

pub fn tree_lock_path(pkey: &str) -> PathBuf {
    let dir = rio::state_dir().join("hygiene").join("tree_locks");
    let _ = fs::create_dir_all(&dir);
    dir.join(format!("{}.json", pkey))
}

pub fn session_index_path() -> PathBuf {
    let dir = rio::state_dir().join("hygiene");
    let _ = fs::create_dir_all(&dir);
    dir.join("sessions.jsonl")
}

pub fn load_session_state(session: &str) -> Map<String, Value> {
    if let Some(Value::Object(m)) = rio::read_json(&session_state_path(session)) {
        return m;
    }
    let mut m = Map::new();
    m.insert("session".to_string(), Value::String(session.to_string()));
    m.insert("generation".to_string(), json!(1));
    m.insert("last_user_hash".to_string(), Value::String(String::new()));
    m.insert("last_step_count".to_string(), json!(0));
    m.insert("correction_active".to_string(), Value::Bool(false));
    m.insert("strong_correction_streak".to_string(), json!(0));
    m.insert("lint_blocks".to_string(), json!(0));
    m.insert("tool_counts".to_string(), Value::Object(Map::new()));
    m.insert("pending_warnings".to_string(), Value::Array(Vec::new()));
    m.insert("updated_ts".to_string(), json!(now_sec()));
    m
}

pub fn save_session_state(session: &str, state: &mut Map<String, Value>) {
    state.insert("updated_ts".to_string(), json!(now_sec()));
    let _ = rio::write_json(&session_state_path(session), &Value::Object(state.clone()));
}

pub fn touch_tree_lock(
    session: &str,
    cwd: &str,
    workspace_paths: &[String],
    release: bool,
    known_git_root: Option<&str>,
) -> Option<String> {
    let git_root = match known_git_root {
        Some(gr) => gr.to_string(),
        None => {
            if cwd.is_empty() {
                String::new()
            } else {
                rio::git_toplevel(cwd, false).unwrap_or_default()
            }
        }
    };
    if git_root.is_empty() {
        return None;
    }
    let pkey = rio::project_key(&git_root, workspace_paths, &git_root, session);
    let lp = tree_lock_path(&pkey);
    let now = now_sec();
    let mut holders: Map<String, Value> = Map::new();
    if let Some(Value::Object(existing)) = rio::read_json(&lp) {
        if let Some(Value::Object(hmap)) = existing.get("holders") {
            for (sid, meta) in hmap {
                if let Some(mobj) = meta.as_object() {
                    let ts = val_to_f64(mobj.get("ts"));
                    if now - ts < TREE_LOCK_TTL_SECONDS {
                        holders.insert(sid.clone(), meta.clone());
                    }
                }
            }
        }
    }

    if release {
        holders.remove(session);
        let _ = rio::write_json(
            &lp,
            &json!({
                "git_root": rio::normalize_path(&git_root),
                "holders": Value::Object(holders),
            }),
        );
        return None;
    }

    let other_sessions: Vec<String> = holders
        .keys()
        .filter(|sid| sid.as_str() != session)
        .cloned()
        .collect();
    holders.insert(
        session.to_string(),
        json!({
            "ts": now,
            "cwd": rio::normalize_path(cwd),
        }),
    );
    let _ = rio::write_json(
        &lp,
        &json!({
            "git_root": rio::normalize_path(&git_root),
            "holders": Value::Object(holders),
        }),
    );

    if !other_sessions.is_empty() {
        let root_name = Path::new(&git_root)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&git_root);
        let preview: Vec<String> = other_sessions
            .iter()
            .take(2)
            .map(|s| truncate_chars(s, 12).to_string())
            .collect();
        return Some(format!(
            "[Session Hygiene] Внимание: это рабочее дерево (`{}`) сейчас открыто в другой активной сессии ({}). Не перезаписывайте чужие незакоммиченные изменения; для параллельной кодовой работы используйте изолированный worktree (`carbon-stack chip-handoff open`).",
            root_name,
            preview.join(", ")
        ));
    }
    None
}

pub fn parse_checkpoint_sections(markdown_text: &str) -> BTreeMap<String, String> {
    let mut sections: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current = String::new();
    for line in markdown_text.lines() {
        if let Some(caps) = section_hdr_re().captures(line) {
            current = caps[1].trim().to_uppercase();
            sections.entry(current.clone()).or_default();
        } else if !current.is_empty() {
            if let Some(vec) = sections.get_mut(&current) {
                vec.push(line.to_string());
            }
        }
    }
    sections
        .into_iter()
        .map(|(k, v)| (k, v.join("\n").trim().to_string()))
        .collect()
}

pub fn format_canonical_checkpoint(
    fields: &BTreeMap<String, String>,
    project_label: &str,
) -> String {
    let iso = format_iso_utc(now_sec());
    let stamped = iso.replace('T', " ").replace('Z', " +0000");
    let label_part = if project_label.is_empty() {
        String::new()
    } else {
        format!(" — {}", project_label)
    };
    let mut lines = vec![
        format!("# Canonical Engineering State{}", label_part),
        format!("_Updated: {}_", stamped),
        String::new(),
    ];
    for &sec in CANONICAL_SECTIONS {
        let raw_val = fields
            .get(sec)
            .or_else(|| fields.get(&sec.to_lowercase()))
            .map(|s| s.trim())
            .unwrap_or("");
        let val = if raw_val.is_empty() { "—" } else { raw_val };
        lines.push(format!("## {}", sec));
        lines.push(val.to_string());
        lines.push(String::new());
    }
    let mut out = lines.join("\n").trim_end().to_string();
    out.push('\n');
    out
}

fn bound_handoff_lines(lines: &[String], max_chars: usize) -> String {
    if max_chars == 0 {
        return lines.join("\n");
    }
    let mut out: Vec<String> = Vec::new();
    let mut total: usize = 0;
    for (idx, line) in lines.iter().enumerate() {
        let sep = usize::from(!out.is_empty());
        let llen = char_len(line);
        if total + sep + llen <= max_chars {
            out.push(line.clone());
            total += sep + llen;
        } else {
            if idx <= HANDOFF_PRIORITY_INDEX
                && total + sep + HANDOFF_MIN_TRUNCATE_REMAINING <= max_chars
            {
                let rem = max_chars.saturating_sub(total + sep + 3);
                out.push(format!("{}...", truncate_chars(line, rem.max(20))));
            }
            break;
        }
    }
    out.join("\n")
}

fn format_git_line(
    git_brief: &Map<String, Value>,
    status_cap: usize,
    include_diff: bool,
) -> String {
    let st_joined = git_brief
        .get("status_short")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<&str>>()
                .join(", ")
        })
        .unwrap_or_default();
    let st_items = if st_joined.is_empty() {
        "clean".to_string()
    } else {
        st_joined
    };
    let branch_raw = val_to_str(git_brief.get("branch"));
    let branch = if branch_raw.is_empty() {
        "?"
    } else {
        branch_raw.as_str()
    };
    let mut git_line = format!(
        "- GIT: branch={} changed=[{}]",
        branch,
        truncate_chars(&st_items, status_cap)
    );
    if include_diff {
        let diff_items = git_brief
            .get("diff_stat")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<&str>>()
                    .join("; ")
            })
            .unwrap_or_default();
        if !diff_items.is_empty() {
            git_line.push_str(&format!(" diff=[{}]", truncate_chars(&diff_items, 120)));
        }
    }
    git_line
}

pub fn compact_recovery_digest(cp_text: &str, mode: &str, max_chars: usize) -> String {
    let secs = parse_checkpoint_sections(cp_text);
    if secs.is_empty() {
        return String::new();
    }
    let header = if mode == "authoritative" {
        "[Continuity — AUTHORITATIVE RECOVERY (после сжатия/перезапуска)]"
    } else {
        "[Continuity — Предыдущий Checkpoint проекта (проверьте git status)]"
    };
    let mut picked = vec![header.to_string()];
    for key in [
        "GOAL",
        "STATUS",
        "AUTHORITATIVE STATE",
        "SUPERSEDED / CANCELLED",
        "NEXT ACTION",
        "BLOCKERS",
        "CURRENT STATE",
    ] {
        let collapsed = secs
            .get(key)
            .map(|v| v.split_whitespace().collect::<Vec<&str>>().join(" "))
            .unwrap_or_default();
        if !collapsed.is_empty() && collapsed != "—" {
            picked.push(format!("- **{}**: {}", key, truncate_chars(&collapsed, 200)));
        }
    }
    bound_handoff_lines(&picked, max_chars)
}

pub fn build_repo_handoff(
    cwd: &str,
    session: &str,
    workspace_paths: &[String],
    mode: &str,
    max_chars: usize,
    pkey: Option<&str>,
) -> String {
    let eff_pkey = match pkey {
        Some(k) if !k.is_empty() => k.to_string(),
        _ => rio::project_key(cwd, workspace_paths, "", session),
    };
    let (ho_path, raw_ho) = resolve_handoff(cwd, workspace_paths, Some(&eff_pkey), session);
    let ho_closed = raw_ho
        .as_ref()
        .map_or(false, |h| is_closed_status(&val_to_str(h.get("status"))));
    let cand = open_candidate_brief(session);
    let mut ho = if mode == "lead" && cand.is_empty() && ho_closed {
        None
    } else {
        raw_ho.clone()
    };

    let mut cp_text = String::new();
    if raw_ho.is_none() || ho_closed {
        if let Some(cp_file) = resolve_checkpoint_file(cwd, workspace_paths, Some(&eff_pkey), session)
        {
            if raw_ho.is_none() || checkpoint_supersedes_closed_handoff(&cp_file, ho_path.as_deref())
            {
                ho = None;
                cp_text = fs::read_to_string(&cp_file).unwrap_or_default();
                if mode == "lead" && cand.is_empty() {
                    let cp_secs = parse_checkpoint_sections(&cp_text);
                    let st = cp_secs.get("STATUS").map(String::as_str).unwrap_or("");
                    if is_closed_status(st) {
                        cp_text.clear();
                    }
                }
            }
        }
    }

    let git_brief = if mode == "authoritative" || ho.is_some() || !cp_text.is_empty() {
        collect_git_brief(cwd)
    } else {
        None
    };

    if let Some(ref ho_map) = ho {
        let header = if mode == "authoritative" {
            "[Continuity — AUTHORITATIVE RECOVERY (handoff)]"
        } else {
            "[Continuity — Active Repo Handoff (проверьте git status)]"
        };
        let mut lines = vec![header.to_string()];
        let goal = val_to_str(ho_map.get("goal"))
            .split_whitespace()
            .collect::<Vec<&str>>()
            .join(" ");
        if !goal.is_empty() {
            lines.push(format!("- GOAL: {}", truncate_chars(&goal, 180)));
        }
        let status = val_to_str(ho_map.get("status"))
            .split_whitespace()
            .collect::<Vec<&str>>()
            .join(" ");
        if !status.is_empty() {
            lines.push(format!("- STATUS: {}", truncate_chars(&status, 80)));
        }
        let (decs, sups) = handoff_constraints(ho_map);
        if !decs.is_empty() {
            let joined = decs.join("; ");
            lines.push(format!(
                "- AUTHORITATIVE STATE: {}",
                truncate_chars(&joined, 220)
            ));
        }
        if !sups.is_empty() {
            let joined = sups.join("; ");
            lines.push(format!(
                "- SUPERSEDED / CANCELLED: {}",
                truncate_chars(&joined, 180)
            ));
        }
        let rems = handoff_items(ho_map, "remaining");
        if !rems.is_empty() {
            let joined = rems.join("; ");
            lines.push(format!("- NEXT ACTION: {}", truncate_chars(&joined, 180)));
        }
        if let Some(ref gb) = git_brief {
            lines.push(format_git_line(gb, 140, true));
        }
        if !cand.is_empty() {
            lines.push(format!("- GATE: {}", cand));
        }
        return bound_handoff_lines(&lines, max_chars);
    }

    if !cp_text.is_empty() {
        let reserve = if git_brief.is_some() || !cand.is_empty() {
            160
        } else {
            0
        };
        let cp_digest = compact_recovery_digest(&cp_text, mode, max_chars.saturating_sub(reserve));
        let mut lines = if cp_digest.is_empty() {
            Vec::new()
        } else {
            vec![cp_digest]
        };
        if let Some(ref gb) = git_brief {
            if !lines.is_empty() {
                lines.push(format_git_line(gb, 120, false));
            }
        }
        if !cand.is_empty() && !lines.is_empty() {
            lines.push(format!("- GATE: {}", cand));
        }
        return bound_handoff_lines(&lines, max_chars);
    }

    let has_status_short = git_brief
        .as_ref()
        .and_then(|gb| gb.get("status_short"))
        .and_then(|v| v.as_array())
        .map_or(false, |a| !a.is_empty());
    if mode == "authoritative" && (!cand.is_empty() || has_status_short) {
        let mut lines = vec!["[Continuity — AUTHORITATIVE RECOVERY (live repo state)]".to_string()];
        if let Some(ref gb) = git_brief {
            lines.push(format_git_line(gb, 160, false));
            let diff_items = gb
                .get("diff_stat")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str())
                        .collect::<Vec<&str>>()
                        .join("; ")
                })
                .unwrap_or_default();
            if !diff_items.is_empty() {
                lines.push(format!("- DIFF: {}", truncate_chars(&diff_items, 160)));
            }
        }
        if !cand.is_empty() {
            lines.push(format!("- GATE: {}", cand));
        }
        return bound_handoff_lines(&lines, max_chars);
    }

    String::new()
}

fn gate_marker_mtime_ns(session: &str) -> u128 {
    if session.is_empty() {
        return 0;
    }
    let skey = rio::safe_key(session, "default");
    let mp = cwg_common::marker_path(&skey);
    file_mtime_ns(&mp)
        .unwrap_or(0)
        .max(cwg_common::pending_marker_mtime_ns(&skey))
}

fn mutation_sync_token(session: &str) -> String {
    format!(
        "{}:{}",
        rio::read_mutation_stamp(session),
        gate_marker_mtime_ns(session)
    )
}

pub fn evaluate_session_start(payload: &Value) -> (Option<String>, Option<String>) {
    let tp = payload
        .get("transcriptPath")
        .or_else(|| payload.get("transcript_path"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if rio::is_subagent_session(tp, None) {
        return (None, None);
    }

    let session = rio::session_key(payload);
    let cwd = rio::effective_cwd(payload);
    let wps = cwg_common::extract_workspace_paths(payload);
    let git_root = if cwd.is_empty() {
        String::new()
    } else {
        rio::git_toplevel(&cwd, false).unwrap_or_default()
    };
    let pkey = rio::project_key(&cwd, &wps, &git_root, &session);
    let source = payload
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("new")
        .to_lowercase();

    let _ = rio::append_jsonl(
        &session_index_path(),
        &json!({
            "ts": now_sec(),
            "session": session,
            "project_key": pkey,
            "cwd": rio::normalize_path(&cwd),
            "model": payload.get("modelName").and_then(|v| v.as_str()).unwrap_or(""),
            "source": source,
        }),
        2_000_000,
    );

    let mut blocks: Vec<String> = Vec::new();
    if !git_root.is_empty() {
        let lock_warn = touch_tree_lock(&session, &cwd, &wps, false, Some(&git_root));
        let mut state = load_session_state(&session);
        state.insert("locked_git_root".to_string(), Value::String(git_root));
        save_session_state(&session, &mut state);
        if let Some(warn) = lock_warn {
            blocks.push(warn);
        }
    }

    let mode = if matches!(source.as_str(), "resume" | "reload" | "compact") {
        "authoritative"
    } else {
        "lead"
    };
    let handoff_digest = build_repo_handoff(&cwd, &session, &wps, mode, HANDOFF_MAX_CHARS, Some(&pkey));
    if !handoff_digest.is_empty() {
        blocks.push(handoff_digest);
    }

    if blocks.is_empty() {
        (None, None)
    } else {
        (Some(blocks.join("\n\n")), None)
    }
}

pub fn detect_compaction(
    payload: &Value,
    state: &mut Map<String, Value>,
    steps: &[Value],
) -> bool {
    let init_steps = val_to_i64(payload.get("initialNumSteps"));
    let prev_steps = val_to_i64(state.get("last_step_count"));
    if prev_steps > 12 && init_steps > 0 && init_steps < prev_steps / 2 {
        return true;
    }
    let start = steps.len().saturating_sub(4);
    for st in &steps[start..] {
        if st.get("source").and_then(|v| v.as_str()) == Some("SYSTEM")
            && st.get("type").and_then(|v| v.as_str()) == Some("CHECKPOINT")
        {
            let cp_idx = val_to_i64(st.get("step_index"));
            let last_cp = state
                .get("last_compaction_step")
                .and_then(|v| v.as_i64())
                .unwrap_or(-1);
            if cp_idx > last_cp {
                state.insert("last_compaction_step".to_string(), json!(cp_idx));
                return true;
            }
        }
    }
    false
}

fn fence_edge(l: &str, f: Option<(u8, usize)>) -> (bool, Option<(u8, usize)>) {
    let t = l.trim_start();
    let Some(fc) = t.as_bytes().first().copied().filter(|&b| b == b'`' || b == b'~') else { return (false, f); };
    let flen = t.bytes().take_while(|&b| b == fc).count();
    if flen < 3 { (false, f) } else { match f { None => (true, Some((fc, flen))), Some((p, pl)) if fc == p && flen >= pl => (true, None), Some(prev) => (true, Some(prev)) } }
}
fn prose_lines(msg: &str) -> Vec<&str> {
    let (mut v, mut f) = (Vec::new(), None);
    for l in msg.lines() { let (d, n) = fence_edge(l, f); f = n; if !d && f.is_none() && !l.trim_start().starts_with('>') { v.push(l); } }
    v
}
fn waived_final_line(msg: &str) -> bool {
    let (mut last, mut f) = ("", None);
    for l in msg.lines() { let (d, n) = fence_edge(l, f); f = n; if d { last = ""; } else if !l.trim().is_empty() { last = if f.is_some() { "" } else { l.trim() }; } }
    !last.is_empty() && lint_waiver_re().is_match(last)
}

pub fn evaluate_pre_invocation(payload: &Value) -> Option<String> {
    let tp = payload
        .get("transcriptPath")
        .or_else(|| payload.get("transcript_path"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if rio::is_subagent_session(tp, None) {
        return None;
    }
    let steps = rio::read_transcript_steps(tp, 12);

    let session = rio::session_key(payload);
    let cwd = rio::effective_cwd(payload);
    let wps = cwg_common::extract_workspace_paths(payload);
    let mut state = load_session_state(&session);

    let mut injected: Vec<String> = state
        .get("pending_warnings")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(|w| val_to_str(Some(w))).collect())
        .unwrap_or_default();
    state.insert("pending_warnings".to_string(), Value::Array(Vec::new()));

    let user_input = payload
        .get("lastUserInput")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let user_hash = if user_input.is_empty() {
        String::new()
    } else {
        sha256_hex(user_input.as_bytes())[..16].to_string()
    };
    if !user_hash.is_empty() && user_hash != val_to_str(state.get("last_user_hash")) {
        state.insert("last_user_hash".to_string(), Value::String(user_hash));
        let gen = val_to_i64(state.get("generation")).max(1) + 1;
        state.insert("generation".to_string(), json!(gen));
        state.insert("tool_counts".to_string(), Value::Object(Map::new()));
        state.insert("lint_blocks".to_string(), json!(0));
        static HR: OnceLock<Regex> = OnceLock::new();
        let hr = HR.get_or_init(|| Regex::new(r"(?i)(?:changelog|чейнджлог|история\s+(?:изменений|правок)|что\s+изменилось|сравни(?:ть|)\s+верси|\bdiff\b|разбор\s+(?:исправлени|правок|ошиб)|миграци|before\s*/?\s*after|до\s+и\s+после|почему\s+(?:ты\s+|это\s+|оно\s+)?.{0,20}(?:ошиб|неправ|не\s+так|не\s+сработ)|что\s+пошло\s+не\s+так|\bwhat\s+went\s+wrong\b|\bwhy\s+(?:was|were|did).{0,30}wrong\b)").expect("hr"));
        state.insert("history_requested".into(), Value::Bool(hr.is_match(user_input)));

        if strong_correction_re().is_match(user_input) {
            state.insert("correction_active".to_string(), Value::Bool(true));
            let streak = val_to_i64(state.get("strong_correction_streak")) + 1;
            state.insert("strong_correction_streak".to_string(), json!(streak));
            if streak >= 2 {
                injected.push(
                    "[Continuity — Clean-Room Rebuild Escalation] Два сильных корректирующих указания подряд. Остановите инкрементальные заплатки: зафиксируйте обновлённый `AUTHORITATIVE STATE` и отменённые требования в `SUPERSEDED / CANCELLED` (через `/rebuild` или `carbon-stack continuity checkpoint`), перепроверьте состояние файлов с диска и стройте финальный ответ без упоминания отвергнутых черновиков.".to_string(),
                );
            } else {
                injected.push(
                    "[Continuity — Замена требования] Пользователь отменил или изменил прежний подход. Обновите активные требования, поместите отменённое в `SUPERSEDED / CANCELLED`, не возвращайте старую гипотезу и не описывайте отвергнутый черновик в финальном ответе.".to_string(),
                );
            }
        } else {
            state.insert("correction_active".to_string(), Value::Bool(false));
            state.insert("strong_correction_streak".to_string(), json!(0));
        }
    }

    if detect_compaction(payload, &mut state, &steps) {
        let recovery =
            build_repo_handoff(&cwd, &session, &wps, "authoritative", HANDOFF_MAX_CHARS, None);
        if !recovery.is_empty() {
            injected.push(recovery);
        }
    }

    let init_steps = val_to_i64(payload.get("initialNumSteps"));
    let next_step_count = init_steps.max(steps.len() as i64);
    state.insert("last_step_count".to_string(), json!(next_step_count));
    save_session_state(&session, &mut state);

    if injected.is_empty() {
        None
    } else {
        Some(injected.join("\n\n"))
    }
}

pub fn tool_signature(tool_name: &str, args: &Map<String, Value>) -> Option<String> {
    if tool_name == "read_file" {
        let raw_path = val_to_str(args.get("Path"));
        let p = rio::fold_path(&raw_path);
        if p.is_empty() {
            return None;
        }
        let sline = {
            let v = val_to_i64(args.get("StartLine"));
            if v != 0 {
                v
            } else {
                1
            }
        };
        let eline = match args.get("EndLine") {
            Some(v) if json_truthy(Some(v)) => val_to_str(Some(v)),
            _ => "end".to_string(),
        };
        let boff = val_to_i64(args.get("ByteOffset"));
        let mtime = if !raw_path.is_empty() && Path::new(&raw_path).is_file() {
            file_mtime_ns(Path::new(&raw_path)).unwrap_or(0)
        } else {
            0
        };
        return Some(format!("read:{}:{}:{}:{}:{}", p, sline, eline, boff, mtime));
    }

    if tool_name == "run_command" {
        let cmd = val_to_str(args.get("CommandLine"))
            .split_whitespace()
            .collect::<Vec<&str>>()
            .join(" ");
        if cmd.is_empty() {
            return None;
        }
        let digest = sha256_hex(cmd.as_bytes());
        return Some(format!("cmd:{}", &digest[..20]));
    }
    None
}

pub fn evaluate_pre_tool_use(payload: &Value) -> (String, Option<String>) {
    let session = rio::session_key(payload);
    let tc = payload.get("toolCall").and_then(|v| v.as_object());
    let tool_name = tc
        .and_then(|m| m.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let empty_args = Map::new();
    let args = tc
        .and_then(|m| m.get("args"))
        .and_then(|v| v.as_object())
        .unwrap_or(&empty_args);

    let Some(sig) = tool_signature(tool_name, args) else {
        return ("allow".to_string(), None);
    };

    let mut state = load_session_state(&session);
    let mut_tok = mutation_sync_token(&session);
    let prev_tok = match state.get("last_mutation_token") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => "0:0".to_string(),
    };
    if mut_tok != prev_tok {
        // INVARIANT: Sync loop-guard generation with monotonic edit stamp + gate marker so PostToolUse spawns are unnecessary.
        state.insert("last_mutation_token".to_string(), Value::String(mut_tok));
        let gen = val_to_i64(state.get("generation")).max(1) + 1;
        state.insert("generation".to_string(), json!(gen));
        state.insert("tool_counts".to_string(), Value::Object(Map::new()));
    }

    let mut counts: Map<String, Value> = state
        .get("tool_counts")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let new_count = val_to_i64(counts.get(&sig)) + 1;
    counts.insert(sig.clone(), json!(new_count));
    if counts.len() > 120 {
        let mut trimmed = Map::new();
        trimmed.insert(sig.clone(), json!(new_count));
        for (k, v) in counts.into_iter().filter(|(k, _)| k != &sig).take(79) {
            trimmed.insert(k, v);
        }
        counts = trimmed;
    }
    state.insert("tool_counts".to_string(), Value::Object(counts));

    let loop_warn = if tool_name == "read_file" && new_count >= READ_REPEAT_DENY_LIMIT && new_count % READ_REPEAT_DENY_LIMIT == 0 {
        Some(("loop_guard_warn_read", format!("[Continuity Loop Guard] Предупреждение: повторное чтение неизменившегося диапазона файла ({}-й раз подряд без правок). Используйте уже прочитанное содержимое или другой диапазон строк.", new_count)))
    } else if tool_name == "run_command" && !test_runner_re().is_match(&val_to_str(args.get("CommandLine"))) && new_count >= CMD_REPEAT_WARN_LIMIT && new_count % CMD_REPEAT_WARN_LIMIT == 0 {
        Some(("loop_guard_warn_cmd", format!("[Continuity Loop Guard] Одинаковая команда `run_command` вызвана {} раза подряд без изменений кода. Проверьте первопричину вместо повторения идентичного вызова.", new_count)))
    } else { None };
    if let Some((ev, msg)) = loop_warn {
        let mut w: Vec<Value> = state.get("pending_warnings").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        w.push(Value::String(msg));
        let s = w.len().saturating_sub(4);
        state.insert("pending_warnings".into(), Value::Array(w[s..].to_vec()));
        rio::log_hook_event("continuity-events", ev, json!({"session": session, "sig": sig, "count": new_count}));
    }

    save_session_state(&session, &mut state);
    ("allow".to_string(), None)
}

pub fn evaluate_post_tool_use(payload: &Value) {
    if json_truthy(payload.get("error")) {
        return;
    }
    let session = rio::session_key(payload);
    let tool_name = payload
        .get("toolCall")
        .and_then(|v| v.as_object())
        .and_then(|m| m.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if tool_name == "edit_file" || tool_name == "write_file" {
        let mut state = load_session_state(&session);
        let gen = val_to_i64(state.get("generation")).max(1) + 1;
        state.insert("generation".to_string(), json!(gen));
        state.insert("tool_counts".to_string(), Value::Object(Map::new()));
        save_session_state(&session, &mut state);
    }
}

pub fn decide_stop(payload: &Value) -> Option<String> {
    let term_reason = payload
        .get("terminationReason")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if rio::NON_ENFORCEABLE_STOP_REASONS.contains(&term_reason) || json_truthy(payload.get("error"))
    {
        return None;
    }

    let session = rio::session_key(payload);
    let cwd = rio::effective_cwd(payload);
    let mut state = load_session_state(&session);
    let locked_root = val_to_str(state.get("locked_git_root"));
    if !json_truthy(state.get("correction_active")) {
        if !locked_root.is_empty() {
            touch_tree_lock(&session, &cwd, &[], true, Some(&locked_root));
            state.insert("locked_git_root".to_string(), Value::String(String::new()));
            save_session_state(&session, &mut state);
        }
        return None;
    }

    let tp = payload
        .get("transcriptPath")
        .or_else(|| payload.get("transcript_path"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let steps = rio::read_transcript_steps(tp, 40);
    if rio::is_subagent_session(tp, Some(&steps)) {
        return None;
    }

    let explicit_msg = val_to_str(payload.get("lastAssistantMessage"));
    let msg = if !explicit_msg.is_empty() {
        explicit_msg
    } else {
        rio::last_assistant_message(&steps)
    };
    let lint_blocks = val_to_i64(state.get("lint_blocks"));
    let history_requested = json_truthy(state.get("history_requested"));
    if !msg.is_empty()
        && !history_requested
        && !waived_final_line(&msg)
        && prose_lines(&msg)
            .iter()
            .any(|line| edit_residue_re().is_match(line))
        && lint_blocks < MAX_LINT_BLOCKS_PER_EPISODE
    {
        let next_blocks = lint_blocks + 1;
        state.insert("lint_blocks".to_string(), json!(next_blocks));
        save_session_state(&session, &mut state);
        rio::log_hook_event(
            "continuity-events",
            "output_lint_block",
            json!({ "session": session, "count": next_blocks }),
        );
        return Some(
            "[Continuity Output Lint] Финальный ответ после коррекции пользователя содержит описание отвергнутых попыток/черновиков. Перепишите ответ начисто по текущему состоянию результата (либо добавьте `[lint] intentional: <причина>` последней строкой, если сравнение версий запрошено пользователем).".to_string(),
        );
    }

    state.insert("correction_active".to_string(), Value::Bool(false));
    if !locked_root.is_empty() {
        touch_tree_lock(&session, &cwd, &[], true, Some(&locked_root));
        state.insert("locked_git_root".to_string(), Value::String(String::new()));
    }
    save_session_state(&session, &mut state);
    None
}

pub fn evaluate_stop(payload: &Value) {
    match decide_stop(payload) {
        Some(reason) => rio::emit_stop_continue(&reason),
        None => rio::emit_stop_allow(),
    }
}

fn abs_path_str(raw: &str) -> String {
    rio::resolve_abs_path(Path::new(raw))
        .to_string_lossy()
        .into_owned()
}

fn cli_cwd_and_pkey(raw_cwd: &str, sess: &str) -> (String, String) {
    let cwd = if !raw_cwd.trim().is_empty() {
        abs_path_str(raw_cwd.trim())
    } else {
        let cur = env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        if cur.is_empty() || rio::is_plugin_runtime_dir(&cur) {
            String::new()
        } else {
            abs_path_str(&cur)
        }
    };
    let pkey = rio::project_key(&cwd, &[], "", sess);
    (cwd, pkey)
}

fn parse_flag_value<'a>(args: &'a [String], idx: &mut usize, flag: &str) -> Option<&'a str> {
    let cur = &args[*idx];
    if cur == flag {
        if *idx + 1 < args.len() {
            *idx += 1;
            return Some(args[*idx].as_str());
        }
        return None;
    }
    if let Some(rest) = cur.strip_prefix(&format!("{}=", flag)) {
        return Some(rest);
    }
    None
}

fn merge_handoff_items(
    existing: &[String],
    incoming: Option<&[String]>,
    replace: bool,
) -> Vec<String> {
    let Some(inc) = incoming else {
        return existing.to_vec();
    };
    let cleaned: Vec<String> = inc
        .iter()
        .flat_map(|raw| raw.split(';'))
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect();
    if replace {
        return cleaned.into_iter().take(12).collect();
    }
    let mut merged = existing.to_vec();
    for item in cleaned {
        if !merged.contains(&item) {
            merged.push(item);
        }
    }
    merged.into_iter().take(12).collect()
}

fn run_cmd_checkpoint(rest: &[String]) -> i32 {
    let mut raw_cwd = String::new();
    let mut session = String::new();
    let mut mirror_workspace = false;
    let mut updates: HashMap<&'static str, Option<String>> = HashMap::new();

    let mut i = 0;
    while i < rest.len() {
        if rest[i] == "--mirror-workspace" {
            mirror_workspace = true;
        } else if let Some(v) = parse_flag_value(rest, &mut i, "--cwd") {
            raw_cwd = v.to_string();
        } else if let Some(v) = parse_flag_value(rest, &mut i, "--session") {
            session = v.to_string();
        } else if let Some(v) = parse_flag_value(rest, &mut i, "--goal") {
            updates.insert("GOAL", Some(v.to_string()));
        } else if let Some(v) = parse_flag_value(rest, &mut i, "--status") {
            updates.insert("STATUS", Some(v.to_string()));
        } else if let Some(v) = parse_flag_value(rest, &mut i, "--authoritative") {
            updates.insert("AUTHORITATIVE STATE", Some(v.to_string()));
        } else if let Some(v) = parse_flag_value(rest, &mut i, "--superseded") {
            updates.insert("SUPERSEDED / CANCELLED", Some(v.to_string()));
        } else if let Some(v) = parse_flag_value(rest, &mut i, "--completed") {
            updates.insert("COMPLETED", Some(v.to_string()));
        } else if let Some(v) = parse_flag_value(rest, &mut i, "--current") {
            updates.insert("CURRENT STATE", Some(v.to_string()));
        } else if let Some(v) = parse_flag_value(rest, &mut i, "--delegated") {
            updates.insert("DELEGATED / OWNERS", Some(v.to_string()));
        } else if let Some(v) = parse_flag_value(rest, &mut i, "--next-action") {
            updates.insert("NEXT ACTION", Some(v.to_string()));
        } else if let Some(v) = parse_flag_value(rest, &mut i, "--acceptance") {
            updates.insert("ACCEPTANCE", Some(v.to_string()));
        } else if let Some(v) = parse_flag_value(rest, &mut i, "--blockers") {
            updates.insert("BLOCKERS", Some(v.to_string()));
        } else if let Some(v) = parse_flag_value(rest, &mut i, "--stop-condition") {
            updates.insert("STOP CONDITION", Some(v.to_string()));
        } else {
            eprintln_str(&format!("continuity checkpoint: unrecognized argument '{}'\n", rest[i]));
            return 2;
        }
        i += 1;
    }

    let (cwd, pkey) = cli_cwd_and_pkey(&raw_cwd, &session);
    let cp_file = checkpoint_path(&pkey);
    let mut merged = if cp_file.is_file() {
        fs::read_to_string(&cp_file)
            .map(|t| parse_checkpoint_sections(&t))
            .unwrap_or_default()
    } else {
        BTreeMap::new()
    };
    for (sec, val_opt) in updates {
        if let Some(val) = val_opt {
            merged.insert(sec.to_string(), val);
        }
    }

    let label = if !cwd.is_empty() {
        Path::new(&cwd)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&pkey)
            .to_string()
    } else {
        pkey.clone()
    };
    let rendered = format_canonical_checkpoint(&merged, &label);
    if let Some(parent) = cp_file.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Err(e) = fs::write(&cp_file, &rendered) {
        eprintln_str(&format!("continuity checkpoint: failed to write {}: {}\n", cp_file.display(), e));
        return 1;
    }

    let mut mirrored = false;
    if mirror_workspace && !cwd.is_empty() {
        let ws_cp = workspace_checkpoint_path(&cwd);
        if let Some(parent) = ws_cp.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if fs::write(&ws_cp, &rendered).is_ok() {
            mirrored = true;
        }
    }

    rio::print_cli_json(
        &json!({
            "ok": true,
            "project_key": pkey,
            "checkpoint_path": cp_file.to_string_lossy(),
            "mirrored_workspace": mirrored,
        }),
        false,
    );
    0
}

fn run_cmd_show(rest: &[String]) -> i32 {
    let mut raw_cwd = String::new();
    let mut session = String::new();
    let mut i = 0;
    while i < rest.len() {
        if let Some(v) = parse_flag_value(rest, &mut i, "--cwd") {
            raw_cwd = v.to_string();
        } else if let Some(v) = parse_flag_value(rest, &mut i, "--session") {
            session = v.to_string();
        } else {
            eprintln_str(&format!("continuity show: unrecognized argument '{}'\n", rest[i]));
            return 2;
        }
        i += 1;
    }

    let (cwd, pkey) = cli_cwd_and_pkey(&raw_cwd, &session);
    let Some(target) = resolve_checkpoint_file(&cwd, &[], Some(&pkey), &session) else {
        rio::print_cli_json(&json!({ "exists": false, "project_key": pkey }), false);
        return 0;
    };
    let text = fs::read_to_string(&target).unwrap_or_default();
    let sections = parse_checkpoint_sections(&text);
    rio::print_cli_json(
        &json!({
            "exists": true,
            "project_key": pkey,
            "path": target.to_string_lossy(),
            "sections": sections,
        }),
        false,
    );
    0
}

fn run_cmd_handoff(rest: &[String]) -> i32 {
    let mut raw_cwd = String::new();
    let mut session = String::new();
    let mut goal: Option<String> = None;
    let mut status: Option<String> = None;
    let mut decisions: Option<Vec<String>> = None;
    let mut superseded: Option<Vec<String>> = None;
    let mut remaining: Option<Vec<String>> = None;
    let mut replace = false;
    let mut clear = false;
    let mut show = false;
    let mut mirror_workspace = false;

    let mut i = 0;
    while i < rest.len() {
        if rest[i] == "--replace" {
            replace = true;
        } else if rest[i] == "--clear" {
            clear = true;
        } else if rest[i] == "--show" {
            show = true;
        } else if rest[i] == "--mirror-workspace" {
            mirror_workspace = true;
        } else if let Some(v) = parse_flag_value(rest, &mut i, "--cwd") {
            raw_cwd = v.to_string();
        } else if let Some(v) = parse_flag_value(rest, &mut i, "--session") {
            session = v.to_string();
        } else if let Some(v) = parse_flag_value(rest, &mut i, "--goal") {
            goal = Some(v.to_string());
        } else if let Some(v) = parse_flag_value(rest, &mut i, "--status") {
            status = Some(v.to_string());
        } else if let Some(v) = parse_flag_value(rest, &mut i, "--decision")
            .or_else(|| parse_flag_value(rest, &mut i, "--decisions"))
        {
            decisions.get_or_insert_with(Vec::new).push(v.to_string());
        } else if let Some(v) = parse_flag_value(rest, &mut i, "--superseded") {
            superseded.get_or_insert_with(Vec::new).push(v.to_string());
        } else if let Some(v) = parse_flag_value(rest, &mut i, "--remaining")
            .or_else(|| parse_flag_value(rest, &mut i, "--next"))
        {
            remaining.get_or_insert_with(Vec::new).push(v.to_string());
        } else {
            eprintln_str(&format!("continuity handoff: unrecognized argument '{}'\n", rest[i]));
            return 2;
        }
        i += 1;
    }

    let (cwd, pkey) = cli_cwd_and_pkey(&raw_cwd, &session);
    let ho_file = handoff_path(&pkey);
    let ws_ho = if cwd.is_empty() {
        None
    } else {
        Some(workspace_handoff_path(&cwd))
    };

    if clear {
        if ho_file.is_file() {
            let _ = fs::remove_file(&ho_file);
        }
        if let Some(ref w) = ws_ho {
            if w.is_file() {
                let _ = fs::remove_file(w);
            }
        }
        rio::print_cli_json(&json!({ "ok": true, "cleared": true, "project_key": pkey }), false);
        return 0;
    }

    let has_updates = goal.is_some()
        || status.is_some()
        || decisions.is_some()
        || superseded.is_some()
        || remaining.is_some();
    if !has_updates || show {
        let (resolved_path, existing) = resolve_handoff(&cwd, &[], Some(&pkey), &session);
        let digest =
            build_repo_handoff(&cwd, &session, &[], "authoritative", HANDOFF_MAX_CHARS, Some(&pkey));
        let path_str = resolved_path
            .unwrap_or_else(|| ho_file.clone())
            .to_string_lossy()
            .into_owned();
        rio::print_cli_json(
            &json!({
                "exists": existing.is_some(),
                "project_key": pkey,
                "path": path_str,
                "handoff": existing.map(Value::Object).unwrap_or(Value::Null),
                "digest": digest,
            }),
            false,
        );
        return 0;
    }

    let existing = resolve_handoff(&cwd, &[], Some(&pkey), &session)
        .1
        .unwrap_or_default();
    let existing_goal = val_to_str(existing.get("goal"));
    let goal_provided = goal.as_deref().is_some_and(|g| !g.trim().is_empty());
    let next_goal = goal.unwrap_or_else(|| existing_goal.clone());
    let existing_sess = val_to_str(existing.get("session")).trim().to_string();
    let handoff_session = if !session.trim().is_empty() {
        session.trim().to_string()
    } else {
        existing_sess.clone()
    };
    let live_cand_first_ts = if !handoff_session.is_empty() {
        cwg_common::read_marker_with_pending(&handoff_session)
            .filter(|m| !json_truthy(m.get("closed")))
            .map(|m| val_to_f64(m.get("first_ts")))
            .unwrap_or(0.0)
    } else {
        0.0
    };
    let now = now_sec();
    let existing_cand_ts = val_to_f64(existing.get("candidate_first_ts"));
    let existing_goal_ts = val_to_f64(existing.get("goal_updated_ts"));
    let kept_goal_ts = if existing_goal_ts > 0.0 {
        existing_goal_ts
    } else {
        val_to_f64(existing.get("updated_ts"))
    };
    let goal_changed = goal_provided
        && !existing_goal.trim().is_empty()
        && next_goal.trim() != existing_goal.trim();
    let session_switched = !existing_sess.is_empty()
        && !handoff_session.is_empty()
        && existing_sess != handoff_session;
    let candidate_switched = session_switched
        || (live_cand_first_ts > 0.0
            && existing_cand_ts > 0.0
            && (existing_cand_ts - live_cand_first_ts).abs() > 1.0)
        || (live_cand_first_ts > 0.0
            && existing_cand_ts <= 0.0
            && kept_goal_ts > 0.0
            && kept_goal_ts + 300.0 < live_cand_first_ts)
        || (existing_cand_ts > 0.0 && live_cand_first_ts <= 0.0 && goal_changed);
    let same_live_candidate = !session_switched
        && live_cand_first_ts > 0.0
        && existing_cand_ts > 0.0
        && (existing_cand_ts - live_cand_first_ts).abs() <= 1.0;
    // INVARIANT: When `--goal` switches to a different session/candidate OR introduces a new goal text without a matching live candidate marker (e.g. markerless task 1 -> markerless task 2), advance `goal_generation` and drop stale prior `decisions`/`superseded`/`remaining` unless explicitly re-passed, while preserving them on same-task partial updates or same-candidate goal refinements.
    let reset_prior_items = replace
        || (goal_provided && (candidate_switched || (goal_changed && !same_live_candidate)));
    let existing_goal_gen = existing
        .get("goal_generation")
        .and_then(Value::as_u64)
        .unwrap_or(if existing_goal.trim().is_empty() { 0 } else { 1 });
    let next_goal_gen = if reset_prior_items || (goal_provided && existing_goal.trim().is_empty()) {
        existing_goal_gen.saturating_add(1)
    } else {
        existing_goal_gen
    };
    let next_status = status.unwrap_or_else(|| {
        if reset_prior_items {
            "in_progress".to_string()
        } else {
            let s = val_to_str(existing.get("status"));
            if s.is_empty() {
                "in_progress".to_string()
            } else {
                s
            }
        }
    });
    let prev_decs = if reset_prior_items {
        Vec::new()
    } else {
        handoff_items(&existing, "decisions")
    };
    let prev_sups = if reset_prior_items {
        Vec::new()
    } else {
        handoff_items(&existing, "superseded")
    };
    let prev_rems = if reset_prior_items {
        Vec::new()
    } else {
        handoff_items(&existing, "remaining")
    };
    let next_decs = merge_handoff_items(&prev_decs, decisions.as_deref(), reset_prior_items);
    let next_sups = merge_handoff_items(&prev_sups, superseded.as_deref(), reset_prior_items);
    let next_rems = merge_handoff_items(&prev_rems, remaining.as_deref(), reset_prior_items);
    let git_val = if cwd.is_empty() {
        json!({})
    } else {
        collect_git_brief(&cwd).map(Value::Object).unwrap_or_else(|| json!({}))
    };

    // INVARIANT: Bind `candidate_first_ts` and `goal_updated_ts` together with the goal itself; partial updates (`--remaining`/`--decisions`) without a new `--goal` must never rebind an older goal to a new candidate.
    let (cand_first_ts, goal_updated_ts) = if goal_provided || existing_goal.trim().is_empty() {
        (live_cand_first_ts, now)
    } else {
        (existing_cand_ts, kept_goal_ts)
    };
    let updated = json!({
        "goal": next_goal,
        "goal_generation": next_goal_gen,
        "status": next_status,
        "decisions": next_decs,
        "superseded": next_sups,
        "remaining": next_rems,
        "git": git_val,
        "session": handoff_session,
        "candidate_first_ts": cand_first_ts,
        "goal_updated_ts": goal_updated_ts,
        "updated_ts": now,
    });
    let _ = rio::write_json(&ho_file, &updated);
    let mut mirrored = false;
    if mirror_workspace {
        if let Some(ref w) = ws_ho {
            if rio::write_json(w, &updated).is_ok() {
                mirrored = true;
            }
        }
    }
    let digest =
        build_repo_handoff(&cwd, &session, &[], "authoritative", HANDOFF_MAX_CHARS, Some(&pkey));
    rio::print_cli_json(
        &json!({
            "ok": true,
            "project_key": pkey,
            "handoff_path": ho_file.to_string_lossy(),
            "mirrored_workspace": mirrored,
            "digest_chars": char_len(&digest),
        }),
        false,
    );
    0
}

pub fn run_cli(args: &[String]) -> i32 {
    if let Some(first) = args.first().map(String::as_str) {
        if first == "checkpoint" {
            return run_cmd_checkpoint(&args[1..]);
        }
        if first == "show" {
            return run_cmd_show(&args[1..]);
        }
        if first == "handoff" {
            return run_cmd_handoff(&args[1..]);
        }
    }

    let event = rio::parse_event_arg(args, "");
    let payload = match rio::read_hook_stdin() {
        Ok(v) => v,
        Err(err) => {
            rio::log_hook_event(
                "hook-errors",
                "stdin_error",
                json!({
                    "hook": "continuity",
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
        val_to_str(payload.get("hookEventName"))
    };
    match actual_event.as_str() {
        "SessionStart" => {
            let (ctx, md) = evaluate_session_start(&payload);
            match ctx {
                Some(msg) => rio::emit_inject_system(&msg, md.as_deref()),
                None => rio::emit_json(&json!({})),
            }
        }
        "PreInvocation" => match evaluate_pre_invocation(&payload) {
            Some(msg) => rio::emit_inject_system(&msg, None),
            None => rio::emit_json(&json!({})),
        },
        "PreToolUse" => {
            let (decision, reason) = evaluate_pre_tool_use(&payload);
            rio::emit_pre_tool(&decision, reason.as_deref(), None);
        }
        "PostToolUse" => {
            evaluate_post_tool_use(&payload);
            rio::emit_json(&json!({}));
        }
        "Stop" => evaluate_stop(&payload),
        other => rio::emit_default_for_event(other),
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_regexes_compile() {
        assert!(test_runner_re().is_match("cargo test --release"));
        assert!(test_runner_re().is_match("python -m unittest"));
        assert!(strong_correction_re().is_match("Нет, переделай без кеша"));
        assert!(strong_correction_re().is_match("no, instead use SQLite"));
        assert!(edit_residue_re().is_match("В предыдущей версии я сделал иначе."));
        assert!(edit_residue_re().is_match("in my earlier attempt I wrote X"));
        assert!(lint_waiver_re().is_match("[lint] intentional: comparison requested"));
        assert!(section_hdr_re().is_match("## AUTHORITATIVE STATE"));
        assert!(closed_status_re().is_match("completed"));
    }

    #[test]
    fn test_loop_guard_resets_on_mutation_stamp() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp_dir = std::env::temp_dir().join(format!("continuity-lg-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();
        let prev = std::env::var_os("CARBON_STACK_HOME");
        unsafe { std::env::set_var("CARBON_STACK_HOME", &tmp_dir) };

        let target = tmp_dir.join("sample.rs");
        fs::write(&target, "fn main() {}\n").unwrap();

        let sid = "sess-loop-guard-01";
        let payload = json!({
            "conversationId": sid,
            "toolCall": {
                "id": "call-1",
                "name": "read_file",
                "args": {
                    "Path": target.to_string_lossy(),
                    "StartLine": 1,
                    "EndLine": 10,
                }
            }
        });

        assert_eq!(evaluate_pre_tool_use(&payload).0, "allow");
        assert_eq!(evaluate_pre_tool_use(&payload).0, "allow");
        let (dec3, reason3) = evaluate_pre_tool_use(&payload);
        assert_eq!(dec3, "allow");
        assert!(reason3.is_none());
        let st = load_session_state(sid);
        let warns = st.get("pending_warnings").and_then(|v| v.as_array()).unwrap();
        assert_eq!(warns.len(), 1);
        assert!(warns[0].as_str().unwrap().contains("Continuity Loop Guard"));

        let cmd_payload = json!({
            "conversationId": sid,
            "toolCall": {
                "id": "call-2",
                "name": "run_command",
                "args": {"CommandLine": "git status --short"}
            }
        });
        assert_eq!(evaluate_pre_tool_use(&cmd_payload).0, "allow");
        assert_eq!(evaluate_pre_tool_use(&cmd_payload).0, "allow");
        assert_eq!(evaluate_pre_tool_use(&cmd_payload).0, "allow");
        let st_cmd = load_session_state(sid);
        assert_eq!(st_cmd.get("pending_warnings").and_then(|v| v.as_array()).unwrap().len(), 2);

        let new_stamp = rio::bump_mutation_stamp(sid);
        assert_eq!(new_stamp, 1);

        let (dec4, reason4) = evaluate_pre_tool_use(&payload);
        assert_eq!(dec4, "allow");
        assert!(reason4.is_none());

        unsafe {
            match prev {
                Some(v) => std::env::set_var("CARBON_STACK_HOME", v),
                None => std::env::remove_var("CARBON_STACK_HOME"),
            }
        }
        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_prose_lines_waiver_and_history_exemption() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp_dir = std::env::temp_dir().join(format!("continuity-lint-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();
        let prev = std::env::var_os("CARBON_STACK_HOME");
        unsafe { std::env::set_var("CARBON_STACK_HOME", &tmp_dir) };

        let fenced_and_quoted = [
            "Clean result:",
            "```markdown",
            "In my earlier attempt I wrote X.",
            "```",
            "> В предыдущей версии я сделал иначе.",
            "Current code works cleanly.",
        ]
        .join("\n");
        let prose = prose_lines(&fenced_and_quoted);
        assert_eq!(prose, vec!["Clean result:", "Current code works cleanly."]);

        assert!(waived_final_line("Diff explanation.\n[lint] intentional: user asked"));
        assert!(!waived_final_line("[lint] intentional: mid\nTrailing summary"));
        assert!(!waived_final_line("Text\n```\n[lint] intentional: fenced\n```"));

        let sid = "sess-hist-lint-01";
        assert!(evaluate_pre_invocation(&json!({
            "conversationId": sid,
            "lastUserInput": "Нет, переделай без кеша"
        }))
        .is_some());

        let block_msg = "В предыдущей версии я сделал с кешем, но исправил.";
        let stop_blk = decide_stop(&json!({
            "conversationId": sid,
            "lastAssistantMessage": block_msg
        }));
        assert!(stop_blk.is_some());

        assert!(decide_stop(&json!({
            "conversationId": sid,
            "lastAssistantMessage": format!("{}\n[lint] intentional: comparing approaches", block_msg)
        }))
        .is_none());

        assert!(evaluate_pre_invocation(&json!({
            "conversationId": sid,
            "lastUserInput": "Нет, не так — покажи что пошло не так и история изменений"
        }))
        .is_some());
        assert!(decide_stop(&json!({
            "conversationId": sid,
            "lastAssistantMessage": block_msg
        }))
        .is_none());

        unsafe {
            match prev {
                Some(v) => std::env::set_var("CARBON_STACK_HOME", v),
                None => std::env::remove_var("CARBON_STACK_HOME"),
            }
        }
        let _ = fs::remove_dir_all(&tmp_dir);
    }
}
