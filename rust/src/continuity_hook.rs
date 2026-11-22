use regex::Regex;
use serde_json::{json, Map, Value};
use std::{collections::BTreeMap, env, fs, path::{Path, PathBuf}, sync::OnceLock};

use crate::cwg_common;
use crate::rio::{self, file_mtime_ns, json_truthy, sha256_hex, truncate_chars, val_to_f64, val_to_i64, val_to_str};
use crate::win32_sqlite::{format_iso_utc, now_sec};

const HANDOFF_MAX_CHARS: usize = 900;
const CP_FLAG_MAP: &[(&str, &str)] = &[
    ("--goal", "GOAL"), ("--status", "STATUS"), ("--authoritative", "AUTHORITATIVE STATE"),
    ("--superseded", "SUPERSEDED / CANCELLED"), ("--completed", "COMPLETED"), ("--current", "CURRENT STATE"),
    ("--delegated", "DELEGATED / OWNERS"), ("--next-action", "NEXT ACTION"), ("--acceptance", "ACCEPTANCE"),
    ("--blockers", "BLOCKERS"), ("--stop-condition", "STOP CONDITION"),
];

macro_rules! lazy_re { ($n:ident, $p:expr) => { fn $n() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| Regex::new($p).expect(stringify!($n))) } }; }
lazy_re!(test_runner_re, r"(?i)\b(?:pytest|py\.test|unittest|npm\s+test|pnpm\s+test|yarn\s+test|cargo\s+test|go\s+test|dotnet\s+test)\b");
lazy_re!(strong_correction_re, r"(?i)(?:\b(?:нет,\s*(?:не\s+так|переделай|отмени|убери|верни)|не\s+возвращай|вместо\s+этого\s+сделай|отменяю\s+требование|забудь\s+предыдущ)|\b(?:no,\s*(?:instead|revert|undo|drop\s+that|wrong\s+approach)|do\s+not\s+bring\s+back|discard\s+the\s+previous|stop\s+doing\s+that)\b)");
lazy_re!(history_re, r"(?i)(?:changelog|чейнджлог|истори[яюи]\s+(?:изменений|правок)|что\s+изменилось|сравни(?:ть|)\s+верси|\bdiff\b|разбор\s+(?:исправлени|правок|ошиб)|миграци|before\s*/?\s*after|до\s+и\s+после|почему\s+(?:ты\s+|это\s+|оно\s+)?.{0,20}(?:ошиб|неправ|не\s+так|не\s+сработ)|что\s+пошло\s+не\s+так|\bwhat\s+went\s+wrong\b|\bwhy\s+(?:was|were|did).{0,30}wrong\b)");
lazy_re!(edit_residue_re, r"(?i)(?:в\s+предыдущей\s+(?:версии|попытке)\s+я\s+(?:сделал|написал)|сначала\s+я\s+реализовал\s+[^.\n]{3,60},\s*но\s+затем\s+исправил|как\s+я\s+уже\s+писал\s+до\s+исправления|in\s+my\s+earlier\s+(?:attempt|draft)\s+I\s+(?:wrote|used)|initially\s+I\s+implemented\s+[^.\n]{3,60},\s*but\s+now\s+I\s+changed\s+it)");
lazy_re!(lint_waiver_re, r"(?i)^\[lint\]\s*intentional\s*[:-]\s*\S.*$");
lazy_re!(section_hdr_re, r"^##\s+(.+?)\s*$");
lazy_re!(closed_status_re, r"(?i)^(?:done|completed|closed|cancelled|finished)\b");

fn norm_yo(s: &str) -> String { s.replace('ё', "е").replace('Ё', "Е") }
fn collapse_ws(s: &str) -> String { s.split_whitespace().collect::<Vec<_>>().join(" ") }
fn payload_tp(p: &Value) -> &str { p.get("transcriptPath").or_else(|| p.get("transcript_path")).and_then(Value::as_str).unwrap_or("") }
fn read_json_obj(p: &Path) -> Option<Map<String, Value>> { match rio::read_json(p) { Some(Value::Object(m)) => Some(m), _ => None } }
fn continuity_file(sub: &str, name: &str) -> PathBuf { let d = rio::state_dir().join("continuity").join(sub); let _ = fs::create_dir_all(&d); d.join(name) }
fn ws_agent_path(cwd: &str, name: &str) -> Option<PathBuf> { (!cwd.is_empty()).then(|| Path::new(cwd).join(".agents").join(name)) }
fn eff_pkey(cwd: &str, wps: &[String], pkey: Option<&str>, sess: &str) -> String { match pkey { Some(k) if !k.is_empty() => k.to_string(), _ => rio::project_key(cwd, wps, "", sess) } }
fn ws_and_state(cwd: &str, wps: &[String], pkey: Option<&str>, sess: &str, ws_n: &str, sub: &str, ext: &str) -> (Option<PathBuf>, Option<PathBuf>) { (ws_agent_path(cwd, ws_n).filter(|p| p.is_file()), Some(continuity_file(sub, &format!("{}.{}", eff_pkey(cwd, wps, pkey, sess), ext))).filter(|p| p.is_file())) }
pub fn resolve_checkpoint_file(cwd: &str, workspace_paths: &[String], pkey: Option<&str>, session: &str) -> Option<PathBuf> {
    match ws_and_state(cwd, workspace_paths, pkey, session, "CHECKPOINT.md", "checkpoints", "md") { (Some(w), Some(s)) => Some(match (file_mtime_ns(&w), file_mtime_ns(&s)) { (Some(wm), Some(sm)) if sm > wm => s, _ => w }), (ws, st) => ws.or(st) }
}
fn resolve_handoff(cwd: &str, wps: &[String], pkey: Option<&str>, sess: &str) -> (Option<PathBuf>, Option<Map<String, Value>>) {
    match ws_and_state(cwd, wps, pkey, sess, "handoff.json", "handoffs", "json") {
        (Some(w), Some(s)) => {
            let (wd, sd) = (read_json_obj(&w), read_json_obj(&s));
            let pick_st = match (&wd, &sd) {
                (None, Some(_)) => true, (Some(_), None) => false,
                (Some(wm), Some(sm)) if wm.get("updated_ts").is_some_and(Value::is_number) && sm.get("updated_ts").is_some_and(Value::is_number) => val_to_f64(sm.get("updated_ts")) > val_to_f64(wm.get("updated_ts")),
                _ => matches!((file_mtime_ns(&w), file_mtime_ns(&s)), (Some(wm), Some(sm)) if sm > wm),
            };
            if pick_st { (Some(s), sd) } else { (Some(w), wd) }
        }
        (Some(p), None) | (None, Some(p)) => { let d = read_json_obj(&p); (Some(p), d) }
        (None, None) => (None, None),
    }
}
pub fn load_handoff(cwd: &str, workspace_paths: &[String], pkey: Option<&str>, session: &str) -> Option<Value> { resolve_handoff(cwd, workspace_paths, pkey, session).1.map(Value::Object) }
pub fn is_closed_status(status: &str) -> bool { closed_status_re().is_match(status.trim()) }
pub fn handoff_items(ho: &Map<String, Value>, key: &str) -> Vec<String> {
    match ho.get(key) {
        Some(Value::String(s)) => s.split(';').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect(),
        Some(Value::Array(a)) => a.iter().map(|x| val_to_str(Some(x)).trim().to_string()).filter(|s| !s.is_empty()).collect(),
        _ => Vec::new(),
    }
}
pub fn handoff_constraints(ho: &Map<String, Value>) -> (Vec<String>, Vec<String>) { (handoff_items(ho, "decisions"), handoff_items(ho, "superseded")) }
fn find_superseding_cp_path(cwd: &str, wps: &[String], pk: &str, sess: &str, no_ho: bool, ho_closed: bool, ho_path: Option<&Path>) -> Option<PathBuf> {
    if !no_ho && !ho_closed { return None; }
    let cp = resolve_checkpoint_file(cwd, wps, Some(pk), sess)?;
    (no_ho || ho_path.map_or(true, |hp| matches!((file_mtime_ns(&cp), file_mtime_ns(hp)), (Some(c), Some(h)) if c > h))).then_some(cp)
}
pub fn active_constraints(cwd: &str, workspace_paths: &[String], pkey: Option<&str>, session: &str) -> (String, String) {
    let pk = eff_pkey(cwd, workspace_paths, pkey, session);
    let (ho_path, raw_ho) = resolve_handoff(cwd, workspace_paths, Some(&pk), session);
    let ho_closed = raw_ho.as_ref().is_some_and(|h| is_closed_status(&val_to_str(h.get("status"))));
    if let Some(ref ho) = raw_ho { if !ho_closed { let (d, s) = handoff_constraints(ho); return (truncate_chars(&d.join("; "), 400).to_string(), truncate_chars(&s.join("; "), 300).to_string()); } }
    if let Some(cp) = find_superseding_cp_path(cwd, workspace_paths, &pk, session, raw_ho.is_none(), ho_closed, ho_path.as_deref()) {
        if let Ok(text) = fs::read_to_string(&cp) {
            let secs = parse_checkpoint_sections(&text);
            if !is_closed_status(secs.get("STATUS").map(String::as_str).unwrap_or("")) {
                let cl = |k: &str, n: usize| { let v = secs.get(k).map(|s| s.trim()).unwrap_or(""); if v == "—" { String::new() } else { truncate_chars(v, n).to_string() } };
                return (cl("AUTHORITATIVE STATE", 400), cl("SUPERSEDED / CANCELLED", 300));
            }
        }
    }
    (String::new(), String::new())
}

fn collect_git_brief(cwd: &str) -> Option<Map<String, Value>> {
    let gr = rio::git_toplevel(cwd, false)?;
    let gl = |a: &[&str]| -> Vec<String> { let (rc, o, _) = rio::run_git(&gr, a, 3.0); if rc == 0 { o.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect() } else { Vec::new() } };
    let (br, st, diff) = (gl(&["rev-parse", "--abbrev-ref", "HEAD"]), gl(&["status", "--short"]), gl(&["diff", "--stat"]));
    match json!({ "git_root": rio::normalize_path(&gr), "branch": br.first().map(String::as_str).unwrap_or(""), "status_short": st.iter().take(6).collect::<Vec<_>>(), "status_total": st.len(), "diff_stat": diff.iter().take(6).collect::<Vec<_>>() }) {
        Value::Object(m) => Some(m), _ => None,
    }
}
fn open_candidate_brief(session: &str) -> String {
    if session.is_empty() { return String::new(); }
    let Some(Value::Object(m)) = cwg_common::read_marker_with_pending(session).filter(|m| !json_truthy(m.get("closed"))) else { return String::new(); };
    let paths: Vec<&str> = m.get("paths").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).filter(|s| !s.is_empty() && *s != "<shell-mutation>").collect()).unwrap_or_default();
    if !paths.is_empty() {
        let names: Vec<String> = paths.iter().take(4).map(|p| { let n = rio::normalize_path(p); n.rsplit('/').next().unwrap_or(&n).to_string() }).collect();
        return format!("PERSISTENT files={} ({})", paths.len(), names.join(", "));
    }
    if json_truthy(m.get("operational")) { "OPERATIONAL".into() } else { String::new() }
}
fn load_session_state(session: &str) -> Map<String, Value> {
    read_json_obj(&continuity_file("sessions", &format!("{}.json", session))).unwrap_or_else(|| match json!({ "session": session, "generation": 1, "last_user_hash": "", "last_step_count": 0, "correction_active": false, "strong_correction_streak": 0, "lint_blocks": 0, "tool_counts": {}, "pending_warnings": [], "updated_ts": now_sec() }) { Value::Object(m) => m, _ => Map::new() })
}
fn save_session_state(session: &str, state: &mut Map<String, Value>) { state.insert("updated_ts".into(), json!(now_sec())); let _ = rio::write_json(&continuity_file("sessions", &format!("{}.json", session)), &Value::Object(state.clone())); }
fn bump_gen(st: &mut Map<String, Value>) { st.insert("generation".into(), json!(val_to_i64(st.get("generation")).max(1) + 1)); st.insert("tool_counts".into(), Value::Object(Map::new())); }
fn touch_tree_lock(session: &str, cwd: &str, wps: &[String], release: bool, known_git_root: Option<&str>) -> Option<String> {
    let gr = match known_git_root { Some(g) => g.to_string(), None if cwd.is_empty() => String::new(), None => rio::git_toplevel(cwd, false).unwrap_or_default() };
    if gr.is_empty() { return None; }
    let (lp, now) = (rio::state_dir().join("hygiene").join("tree_locks").join(format!("{}.json", rio::project_key(&gr, wps, &gr, session))), now_sec());
    let mut holders: Map<String, Value> = read_json_obj(&lp).and_then(|e| e.get("holders").and_then(Value::as_object).cloned()).unwrap_or_default().into_iter().filter(|(_, v)| v.as_object().is_some_and(|m| now - val_to_f64(m.get("ts")) < 1800.0)).collect();
    if release { holders.remove(session); let _ = rio::write_json(&lp, &json!({ "git_root": rio::normalize_path(&gr), "holders": Value::Object(holders) })); return None; }
    let others: Vec<String> = holders.keys().filter(|s| s.as_str() != session).cloned().collect();
    holders.insert(session.to_string(), json!({ "ts": now, "cwd": rio::normalize_path(cwd) }));
    let _ = rio::write_json(&lp, &json!({ "git_root": rio::normalize_path(&gr), "holders": Value::Object(holders) }));
    (!others.is_empty()).then(|| format!("[Session Hygiene] Внимание: это рабочее дерево (`{}`) сейчас открыто в другой активной сессии ({}). Не перезаписывайте чужие незакоммиченные изменения; для параллельной кодовой работы используйте изолированный worktree (`carbon-stack chip-handoff open`).", Path::new(&gr).file_name().and_then(|s| s.to_str()).unwrap_or(&gr), others.iter().take(2).map(|s| truncate_chars(s, 12)).collect::<Vec<_>>().join(", ")))
}

fn parse_checkpoint_sections(text: &str) -> BTreeMap<String, String> {
    let (mut secs, mut cur): (BTreeMap<String, Vec<String>>, String) = (BTreeMap::new(), String::new());
    for l in text.lines() { if let Some(c) = section_hdr_re().captures(l) { cur = c[1].trim().to_uppercase(); secs.entry(cur.clone()).or_default(); } else if !cur.is_empty() { if let Some(v) = secs.get_mut(&cur) { v.push(l.to_string()); } } }
    secs.into_iter().map(|(k, v)| (k, v.join("\n").trim().to_string())).collect()
}
fn format_canonical_checkpoint(fields: &BTreeMap<String, String>, label: &str) -> String {
    let mut lines = vec![format!("# Canonical Engineering State{}", if label.is_empty() { String::new() } else { format!(" — {}", label) }), format!("_Updated: {}_", format_iso_utc(now_sec()).replace('T', " ").replace('Z', " +0000")), String::new()];
    for &(_, sec) in CP_FLAG_MAP { let raw = fields.get(sec).or_else(|| fields.get(&sec.to_lowercase())).map(String::as_str).unwrap_or("").trim(); lines.extend([format!("## {}", sec), if raw.is_empty() { "—" } else { raw }.to_string(), String::new()]); }
    format!("{}\n", lines.join("\n").trim_end())
}
fn bound_handoff_lines(lines: &[String], max_chars: usize) -> String {
    if max_chars == 0 { return lines.join("\n"); }
    let (mut out, mut total) = (Vec::new(), 0usize);
    for (idx, line) in lines.iter().enumerate() {
        let (sep, llen) = (usize::from(!out.is_empty()), line.chars().count());
        if total + sep + llen <= max_chars { out.push(line.clone()); total += sep + llen; }
        else { if idx <= 2 && total + sep + 40 <= max_chars { out.push(format!("{}...", truncate_chars(line, max_chars.saturating_sub(total + sep + 3).max(20)))); } break; }
    }
    out.join("\n")
}
fn join_str_arr(obj: &Map<String, Value>, key: &str, sep: &str) -> String { obj.get(key).and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(sep)).unwrap_or_default() }
fn format_git_line(gb: &Map<String, Value>, status_cap: usize, include_diff: bool) -> String {
    let (st, br) = (join_str_arr(gb, "status_short", ", "), val_to_str(gb.get("branch")));
    let mut l = format!("- GIT: branch={} changed=[{}]", if br.is_empty() { "?" } else { br.as_str() }, truncate_chars(if st.is_empty() { "clean" } else { st.as_str() }, status_cap));
    if include_diff { let d = join_str_arr(gb, "diff_stat", "; "); if !d.is_empty() { l.push_str(&format!(" diff=[{}]", truncate_chars(&d, 120))); } }
    l
}
fn build_repo_handoff(cwd: &str, session: &str, wps: &[String], mode: &str, max_chars: usize, pkey: Option<&str>) -> String {
    let pk = eff_pkey(cwd, wps, pkey, session);
    let (ho_path, raw_ho) = resolve_handoff(cwd, wps, Some(&pk), session);
    let (no_ho, ho_closed, cand) = (raw_ho.is_none(), raw_ho.as_ref().is_some_and(|h| is_closed_status(&val_to_str(h.get("status")))), open_candidate_brief(session));
    let mut ho = if mode == "lead" && cand.is_empty() && ho_closed { None } else { raw_ho };
    let mut cp_text = String::new();
    if let Some(cp) = find_superseding_cp_path(cwd, wps, &pk, session, no_ho, ho_closed, ho_path.as_deref()) {
        // INVARIANT: Clear superseded closed handoff before reading CHECKPOINT.md so an unreadable newer checkpoint never revives closed handoff state.
        ho = None;
        if let Ok(t) = fs::read_to_string(&cp) {
            if !(mode == "lead" && cand.is_empty() && is_closed_status(parse_checkpoint_sections(&t).get("STATUS").map(String::as_str).unwrap_or(""))) { cp_text = t; }
        }
    }
    let gb = (mode == "authoritative" || ho.is_some() || !cp_text.is_empty()).then(|| collect_git_brief(cwd)).flatten();
    let mut lines = Vec::new();
    if let Some(ref hm) = ho {
        lines.push(if mode == "authoritative" { "[Continuity — AUTHORITATIVE RECOVERY (handoff)]" } else { "[Continuity — Active Repo Handoff (проверьте git status)]" }.into());
        let (decs, sups) = handoff_constraints(hm);
        for (lbl, val, cap) in [("GOAL", collapse_ws(&val_to_str(hm.get("goal"))), 180), ("STATUS", collapse_ws(&val_to_str(hm.get("status"))), 80), ("AUTHORITATIVE STATE", decs.join("; "), 220), ("SUPERSEDED / CANCELLED", sups.join("; "), 180), ("NEXT ACTION", handoff_items(hm, "remaining").join("; "), 180)] {
            if !val.is_empty() { lines.push(format!("- {}: {}", lbl, truncate_chars(&val, cap))); }
        }
        if let Some(ref g) = gb { lines.push(format_git_line(g, 140, true)); }
    } else if !cp_text.is_empty() {
        let secs = parse_checkpoint_sections(&cp_text);
        if secs.is_empty() { return String::new(); }
        let mut picked = vec![if mode == "authoritative" { "[Continuity — AUTHORITATIVE RECOVERY (после сжатия/перезапуска)]" } else { "[Continuity — Предыдущий Checkpoint проекта (проверьте git status)]" }.to_string()];
        for k in ["GOAL", "STATUS", "AUTHORITATIVE STATE", "SUPERSEDED / CANCELLED", "NEXT ACTION", "BLOCKERS", "CURRENT STATE"] {
            let c = secs.get(k).map(|v| collapse_ws(v)).unwrap_or_default();
            if !c.is_empty() && c != "—" { picked.push(format!("- **{}**: {}", k, truncate_chars(&c, 200))); }
        }
        let digest = bound_handoff_lines(&picked, max_chars.saturating_sub(if gb.is_some() || !cand.is_empty() { 160 } else { 0 }));
        if digest.is_empty() { return String::new(); }
        lines.push(digest);
        if let Some(ref g) = gb { lines.push(format_git_line(g, 120, false)); }
    } else if mode == "authoritative" && (!cand.is_empty() || gb.as_ref().and_then(|g| g.get("status_short")).and_then(Value::as_array).is_some_and(|a| !a.is_empty())) {
        lines.push("[Continuity — AUTHORITATIVE RECOVERY (live repo state)]".into());
        if let Some(ref g) = gb {
            lines.push(format_git_line(g, 160, false));
            let diff = join_str_arr(g, "diff_stat", "; ");
            if !diff.is_empty() { lines.push(format!("- DIFF: {}", truncate_chars(&diff, 160))); }
        }
    } else { return String::new(); }
    if !cand.is_empty() { lines.push(format!("- GATE: {}", cand)); }
    bound_handoff_lines(&lines, max_chars)
}

pub fn evaluate_session_start(payload: &Value) -> (Option<String>, Option<String>) {
    if rio::is_subagent_session(payload_tp(payload), None) { return (None, None); }
    let (session, cwd, wps) = (rio::session_key(payload), rio::effective_cwd(payload), cwg_common::extract_workspace_paths(payload));
    let git_root = if cwd.is_empty() { String::new() } else { rio::git_toplevel(&cwd, false).unwrap_or_default() };
    let pkey = rio::project_key(&cwd, &wps, &git_root, &session);
    let source = payload.get("source").and_then(Value::as_str).unwrap_or("new").to_lowercase();
    let _ = rio::append_jsonl(&rio::state_dir().join("hygiene").join("sessions.jsonl"), &json!({ "ts": now_sec(), "session": session, "project_key": pkey, "cwd": rio::normalize_path(&cwd), "model": payload.get("modelName").and_then(Value::as_str).unwrap_or(""), "source": source }), 2_000_000);
    let mut blocks = Vec::new();
    if !git_root.is_empty() {
        if let Some(w) = touch_tree_lock(&session, &cwd, &wps, false, Some(&git_root)) { blocks.push(w); }
        let mut st = load_session_state(&session); st.insert("locked_git_root".into(), Value::String(git_root)); save_session_state(&session, &mut st);
    }
    let mode = if matches!(source.as_str(), "resume" | "reload" | "compact") { "authoritative" } else { "lead" };
    let digest = build_repo_handoff(&cwd, &session, &wps, mode, HANDOFF_MAX_CHARS, Some(&pkey));
    if !digest.is_empty() { blocks.push(digest); }
    ((!blocks.is_empty()).then(|| blocks.join("\n\n")), None)
}

fn fence_edge(l: &str, f: Option<(u8, usize)>) -> (bool, Option<(u8, usize)>) {
    let t = l.trim_start();
    let Some(fc) = t.as_bytes().first().copied().filter(|&b| b == b'`' || b == b'~') else { return (false, f); };
    let flen = t.bytes().take_while(|&b| b == fc).count();
    if flen < 3 { (false, f) } else { match f { None => (true, Some((fc, flen))), Some((p, pl)) if fc == p && flen >= pl => (true, None), Some(prev) => (true, Some(prev)) } }
}
fn prose_lines(msg: &str) -> Vec<String> {
    let (mut v, mut f) = (Vec::new(), None);
    for l in msg.lines() { let (d, n) = fence_edge(l, f); f = n; if !d && f.is_none() && !l.trim_start().starts_with('>') { v.push(norm_yo(l)); } }
    v
}
fn waived_final_line(msg: &str) -> bool {
    let (mut last, mut f) = ("", None);
    for l in msg.lines() { let (d, n) = fence_edge(l, f); f = n; if d { last = ""; } else if !l.trim().is_empty() { last = if f.is_some() { "" } else { l.trim() }; } }
    !last.is_empty() && lint_waiver_re().is_match(last)
}

fn apply_new_user_turn(state: &mut Map<String, Value>, user_text: &str, cur_step: Option<i64>, tx_idx: Option<i64>) -> Option<String> {
    state.insert("last_user_hash".into(), Value::String(sha256_hex(user_text.as_bytes())[..16].to_string()));
    state.insert("turn_closed".into(), Value::Bool(false));
    match cur_step {
        Some(cs) => { state.insert("last_user_step".into(), json!(cs)); state.remove("last_user_base_step"); }
        None => { state.remove("last_user_step"); if let Some(bs) = tx_idx { state.insert("last_user_base_step".into(), json!(bs)); } else { state.remove("last_user_base_step"); } }
    }
    bump_gen(state); state.insert("lint_blocks".into(), json!(0));
    let norm_ui = norm_yo(user_text);
    state.insert("history_requested".into(), Value::Bool(history_re().is_match(&norm_ui)));
    if strong_correction_re().is_match(&norm_ui) {
        let streak = val_to_i64(state.get("strong_correction_streak")) + 1;
        state.insert("correction_active".into(), Value::Bool(true)); state.insert("strong_correction_streak".into(), json!(streak));
        Some(if streak >= 2 { "[Continuity — Clean-Room Rebuild Escalation] Два сильных корректирующих указания подряд. Остановите инкрементальные заплатки: зафиксируйте обновлённый `AUTHORITATIVE STATE` и отменённые требования в `SUPERSEDED / CANCELLED` (через `/rebuild` или `carbon-stack continuity checkpoint`), перепроверьте состояние файлов с диска и стройте финальный ответ без упоминания отвергнутых черновиков.".into() }
             else { "[Continuity — Замена требования] Пользователь отменил или изменил прежний подход. Обновите активные требования, поместите отменённое в `SUPERSEDED / CANCELLED`, не возвращайте старую гипотезу и не описывайте отвергнутый черновик в финальном ответе.".into() })
    } else { state.insert("correction_active".into(), Value::Bool(false)); state.insert("strong_correction_streak".into(), json!(0)); None }
}

pub fn evaluate_pre_invocation(payload: &Value) -> Option<String> {
    let tp = payload_tp(payload);
    if rio::is_subagent_session(tp, None) { return None; }
    let (steps, session, cwd, wps) = (rio::read_transcript_steps(tp, 12), rio::session_key(payload), rio::effective_cwd(payload), cwg_common::extract_workspace_paths(payload));
    let mut state = load_session_state(&session);
    let mut injected: Vec<String> = state.get("pending_warnings").and_then(Value::as_array).map(|a| a.iter().map(|w| val_to_str(Some(w))).collect()).unwrap_or_default();
    state.insert("pending_warnings".into(), Value::Array(Vec::new()));
    // INVARIANT: Live Antigravity `PreInvocation` leaves `lastUserInput` empty; fall back to `rio::last_user_input_step(tp)` with monotonic turn dedup, while never binding a new post-answer `lastUserInput` to an already answered/closed transcript step.
    let (ui, tx_step) = (payload.get("lastUserInput").and_then(Value::as_str).unwrap_or("").trim(), rio::last_user_input_step(tp));
    let tx_idx = tx_step.as_ref().map(|(i, _)| *i);
    // INVARIANT: Only `turn_closed` (set strictly when `decide_stop` allows a turn to finish, never on `Stop -> continue` lint blocks) marks a repeated identical `lastUserInput` with lagging transcript as a new user turn.
    let ui_fresh_turn = !ui.is_empty() && json_truthy(state.get("turn_closed"));
    let (user_text, cur_step) = if !ui.is_empty() { (ui.to_string(), (!ui_fresh_turn).then(|| tx_step.as_ref().filter(|(_, c)| c.trim() == ui).map(|(i, _)| *i)).flatten()) }
        else if let Some((idx, content)) = tx_step { (content.trim().to_string(), Some(idx)) } else { (String::new(), None) };
    if !user_text.is_empty() {
        let (cur_hash, prev_step, prev_base, prev_hash) = (sha256_hex(user_text.as_bytes())[..16].to_string(), state.get("last_user_step").and_then(Value::as_i64), state.get("last_user_base_step").and_then(Value::as_i64), val_to_str(state.get("last_user_hash")));
        let same_turn = !ui_fresh_turn && match (prev_step, cur_step) {
            (Some(ps), Some(cs)) => cs <= ps,
            (None, Some(cs)) if prev_base.is_some_and(|bs| cs <= bs) => true,
            (None, Some(cs)) if !prev_hash.is_empty() && cur_hash == prev_hash => { state.insert("last_user_step".into(), json!(cs)); state.remove("last_user_base_step"); true }
            (None, Some(_)) => false,
            (Some(_), None) => !prev_hash.is_empty() && cur_hash == prev_hash,
            (None, None) => cur_hash == prev_hash,
        };
        if !same_turn { if let Some(msg) = apply_new_user_turn(&mut state, &user_text, cur_step, tx_idx) { injected.push(msg); } }
    }
    let (init_s, prev_s) = (val_to_i64(payload.get("initialNumSteps")), val_to_i64(state.get("last_step_count")));
    let compacted = (prev_s > 12 && init_s > 0 && init_s < prev_s / 2) || steps[steps.len().saturating_sub(4)..].iter().any(|st| {
        st.get("source").and_then(Value::as_str) == Some("SYSTEM") && st.get("type").and_then(Value::as_str) == Some("CHECKPOINT") && {
            let idx = val_to_i64(st.get("step_index"));
            if idx > state.get("last_compaction_step").and_then(Value::as_i64).unwrap_or(-1) { state.insert("last_compaction_step".into(), json!(idx)); true } else { false }
        }
    });
    if compacted { let rec = build_repo_handoff(&cwd, &session, &wps, "authoritative", HANDOFF_MAX_CHARS, None); if !rec.is_empty() { injected.push(rec); } }
    state.insert("last_step_count".into(), json!(init_s.max(steps.len() as i64)));
    save_session_state(&session, &mut state);
    (!injected.is_empty()).then(|| injected.join("\n\n"))
}

pub fn evaluate_pre_tool_use(payload: &Value) -> (String, Option<String>) {
    let (session, tc, empty_args) = (rio::session_key(payload), payload.get("toolCall").and_then(Value::as_object), Map::new());
    let (tool_name, args) = (tc.and_then(|m| m.get("name")).and_then(Value::as_str).unwrap_or(""), tc.and_then(|m| m.get("args")).and_then(Value::as_object).unwrap_or(&empty_args));
    let sig = match tool_name {
        "read_file" => {
            let raw = val_to_str(args.get("Path")); let p = rio::fold_path(&raw); if p.is_empty() { return ("allow".into(), None); }
            let el = args.get("EndLine").filter(|v| json_truthy(Some(v))).map(|v| val_to_str(Some(v))).unwrap_or_else(|| "end".into());
            let mt = (!raw.is_empty() && Path::new(&raw).is_file()).then(|| file_mtime_ns(Path::new(&raw)).unwrap_or(0)).unwrap_or(0);
            format!("read:{}:{}:{}:{}:{}", p, match val_to_i64(args.get("StartLine")) { 0 => 1, v => v }, el, val_to_i64(args.get("ByteOffset")), mt)
        }
        "run_command" => { let c = collapse_ws(&val_to_str(args.get("CommandLine"))); if c.is_empty() { return ("allow".into(), None); } format!("cmd:{}", &sha256_hex(c.as_bytes())[..20]) }
        _ => return ("allow".into(), None),
    };
    let mut state = load_session_state(&session);
    let gate_mt = if session.is_empty() { 0 } else { let sk = rio::safe_key(&session, "default"); file_mtime_ns(&cwg_common::marker_path(&sk)).unwrap_or(0).max(cwg_common::pending_marker_mtime_ns(&sk)) };
    let mut_tok = format!("{}:{}", rio::read_mutation_stamp(&session), gate_mt);
    if mut_tok != state.get("last_mutation_token").and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or("0:0") {
        // INVARIANT: Sync loop-guard generation with monotonic edit stamp + gate marker so PostToolUse spawns are unnecessary.
        state.insert("last_mutation_token".into(), Value::String(mut_tok)); bump_gen(&mut state);
    }
    let mut counts = state.get("tool_counts").and_then(Value::as_object).cloned().unwrap_or_default();
    let n = val_to_i64(counts.get(&sig)) + 1;
    counts.insert(sig.clone(), json!(n));
    if counts.len() > 120 { counts = std::iter::once((sig.clone(), json!(n))).chain(counts.into_iter().filter(|(k, _)| k != &sig).take(79)).collect(); }
    state.insert("tool_counts".into(), Value::Object(counts));
    let warn = if n >= 3 && n % 3 == 0 && tool_name == "read_file" {
        Some(("loop_guard_warn_read", format!("[Continuity Loop Guard] Предупреждение: повторное чтение неизменившегося диапазона файла ({}-й раз подряд без правок). Используйте уже прочитанное содержимое или другой диапазон строк.", n)))
    } else if n >= 3 && n % 3 == 0 && tool_name == "run_command" && !test_runner_re().is_match(&val_to_str(args.get("CommandLine"))) {
        Some(("loop_guard_warn_cmd", format!("[Continuity Loop Guard] Одинаковая команда `run_command` вызвана {} раза подряд без изменений кода. Проверьте первопричину вместо повторения идентичного вызова.", n)))
    } else { None };
    if let Some((ev, msg)) = warn {
        let mut w = state.get("pending_warnings").and_then(Value::as_array).cloned().unwrap_or_default(); w.push(Value::String(msg));
        let s = w.len().saturating_sub(4); state.insert("pending_warnings".into(), Value::Array(w[s..].to_vec()));
        rio::log_hook_event("continuity-events", ev, json!({"session": session, "sig": sig, "count": n}));
    }
    save_session_state(&session, &mut state);
    ("allow".into(), None)
}

pub fn decide_stop(payload: &Value) -> Option<String> {
    let reason = payload.get("terminationReason").and_then(Value::as_str).unwrap_or("");
    if rio::NON_ENFORCEABLE_STOP_REASONS.contains(&reason) || json_truthy(payload.get("error")) { return None; }
    let (session, cwd, tp) = (rio::session_key(payload), rio::effective_cwd(payload), payload_tp(payload));
    let mut state = load_session_state(&session);
    // INVARIANT: Catch a newly flushed transcript USER_INPUT missed by an earlier PreInvocation lag before evaluating Stop output lint.
    if let Some((cs, content)) = rio::last_user_input_step(tp) {
        let trimmed = content.trim();
        let (ps, pb, ph) = (state.get("last_user_step").and_then(Value::as_i64), state.get("last_user_base_step").and_then(Value::as_i64), val_to_str(state.get("last_user_hash")));
        if !trimmed.is_empty() && ps.map_or(true, |p| cs > p) && pb.map_or(true, |b| cs > b) {
            if ps.is_none() && !json_truthy(state.get("turn_closed")) && !ph.is_empty() && sha256_hex(trimmed.as_bytes())[..16] == ph {
                state.insert("last_user_step".into(), json!(cs)); state.remove("last_user_base_step");
            } else {
                let _ = apply_new_user_turn(&mut state, trimmed, Some(cs), Some(cs));
            }
        }
    }
    let locked_root = val_to_str(state.get("locked_git_root"));
    if !json_truthy(state.get("correction_active")) {
        let mut dirty = !json_truthy(state.get("turn_closed"));
        state.insert("turn_closed".into(), Value::Bool(true));
        if !locked_root.is_empty() { touch_tree_lock(&session, &cwd, &[], true, Some(&locked_root)); state.insert("locked_git_root".into(), Value::String(String::new())); dirty = true; }
        if dirty { save_session_state(&session, &mut state); }
        return None;
    }
    let steps = rio::read_transcript_steps(tp, 40);
    if rio::is_subagent_session(tp, Some(&steps)) { return None; }
    let msg = match val_to_str(payload.get("lastAssistantMessage")) { s if !s.is_empty() => s, _ => rio::last_assistant_message(&steps) };
    let lint_blocks = val_to_i64(state.get("lint_blocks"));
    if !msg.is_empty() && !json_truthy(state.get("history_requested")) && !waived_final_line(&msg) && prose_lines(&msg).iter().any(|l| edit_residue_re().is_match(l)) && lint_blocks < 2 {
        state.insert("lint_blocks".into(), json!(lint_blocks + 1)); save_session_state(&session, &mut state);
        rio::log_hook_event("continuity-events", "output_lint_block", json!({ "session": session, "count": lint_blocks + 1 }));
        return Some("[Continuity Output Lint] Финальный ответ после коррекции пользователя содержит описание отвергнутых попыток/черновиков. Перепишите ответ начисто по текущему состоянию результата (либо добавьте `[lint] intentional: <причина>` последней строкой, если сравнение версий запрошено пользователем).".into());
    }
    state.insert("correction_active".into(), Value::Bool(false));
    state.insert("turn_closed".into(), Value::Bool(true));
    if !locked_root.is_empty() { touch_tree_lock(&session, &cwd, &[], true, Some(&locked_root)); state.insert("locked_git_root".into(), Value::String(String::new())); }
    save_session_state(&session, &mut state);
    None
}

fn cli_cwd_and_pkey(raw_cwd: &str, sess: &str) -> (String, String) {
    let abs = |r: &str| rio::resolve_abs_path(Path::new(r)).to_string_lossy().into_owned();
    let cwd = if !raw_cwd.trim().is_empty() { abs(raw_cwd.trim()) } else { env::current_dir().ok().map(|p| p.to_string_lossy().into_owned()).filter(|c| !c.is_empty() && !rio::is_plugin_runtime_dir(c)).map(|c| abs(&c)).unwrap_or_default() };
    let pk = rio::project_key(&cwd, &[], "", sess);
    (cwd, pk)
}
fn parse_flag_value<'a>(args: &'a [String], idx: &mut usize, flag: &str) -> Option<&'a str> {
    let cur = &args[*idx];
    if cur == flag { return (*idx + 1 < args.len()).then(|| { *idx += 1; args[*idx].as_str() }); }
    cur.strip_prefix(flag).and_then(|r| r.strip_prefix('='))
}
fn merge_handoff_items(existing: &[String], incoming: Option<&[String]>, replace: bool) -> Vec<String> {
    let Some(inc) = incoming else { return existing.to_vec(); };
    let cleaned: Vec<String> = inc.iter().flat_map(|r| r.split(';')).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    if replace { return cleaned.into_iter().take(12).collect(); }
    let mut merged = existing.to_vec();
    for item in cleaned { if !merged.contains(&item) { merged.push(item); } }
    merged.into_iter().take(12).collect()
}

fn run_cmd_checkpoint(rest: &[String]) -> i32 {
    let (mut raw_cwd, mut session, mut mirror, mut updates, mut i) = (String::new(), String::new(), false, Vec::new(), 0);
    while i < rest.len() {
        if rest[i] == "--mirror-workspace" { mirror = true; }
        else if let Some(v) = parse_flag_value(rest, &mut i, "--cwd") { raw_cwd = v.to_string(); }
        else if let Some(v) = parse_flag_value(rest, &mut i, "--session") { session = v.to_string(); }
        else if let Some((s, v)) = CP_FLAG_MAP.iter().find_map(|&(f, s)| parse_flag_value(rest, &mut i, f).map(|v| (s, v))) { updates.push((s, v.to_string())); }
        else { eprintln!("continuity checkpoint: unrecognized argument '{}'", rest[i]); return 2; }
        i += 1;
    }
    let (cwd, pkey) = cli_cwd_and_pkey(&raw_cwd, &session);
    let cp_file = continuity_file("checkpoints", &format!("{}.md", pkey));
    let mut merged = if cp_file.is_file() { fs::read_to_string(&cp_file).map(|t| parse_checkpoint_sections(&t)).unwrap_or_default() } else { BTreeMap::new() };
    for (sec, val) in updates { merged.insert(sec.to_string(), val); }
    let rendered = format_canonical_checkpoint(&merged, if !cwd.is_empty() { Path::new(&cwd).file_name().and_then(|s| s.to_str()).unwrap_or(&pkey) } else { &pkey });
    if let Err(e) = fs::write(&cp_file, &rendered) { eprintln!("continuity checkpoint: failed to write {}: {}", cp_file.display(), e); return 1; }
    let mirrored = mirror && ws_agent_path(&cwd, "CHECKPOINT.md").is_some_and(|ws| { if let Some(p) = ws.parent() { let _ = fs::create_dir_all(p); } fs::write(&ws, &rendered).is_ok() });
    rio::print_cli_json(&json!({ "ok": true, "project_key": pkey, "checkpoint_path": cp_file.to_string_lossy(), "mirrored_workspace": mirrored }), false);
    0
}
fn run_cmd_show(rest: &[String]) -> i32 {
    let (mut raw_cwd, mut session, mut i) = (String::new(), String::new(), 0);
    while i < rest.len() {
        if let Some(v) = parse_flag_value(rest, &mut i, "--cwd") { raw_cwd = v.to_string(); }
        else if let Some(v) = parse_flag_value(rest, &mut i, "--session") { session = v.to_string(); }
        else { eprintln!("continuity show: unrecognized argument '{}'", rest[i]); return 2; }
        i += 1;
    }
    let (cwd, pkey) = cli_cwd_and_pkey(&raw_cwd, &session);
    match resolve_checkpoint_file(&cwd, &[], Some(&pkey), &session) {
        None => rio::print_cli_json(&json!({ "exists": false, "project_key": pkey }), false),
        Some(t) => rio::print_cli_json(&json!({ "exists": true, "project_key": pkey, "path": t.to_string_lossy(), "sections": parse_checkpoint_sections(&fs::read_to_string(&t).unwrap_or_default()) }), false),
    }
    0
}
fn run_cmd_handoff(rest: &[String]) -> i32 {
    let (mut raw_cwd, mut session, mut goal, mut status) = (String::new(), String::new(), None::<String>, None::<String>);
    let (mut decisions, mut superseded, mut remaining) = (None::<Vec<String>>, None::<Vec<String>>, None::<Vec<String>>);
    let (mut replace, mut clear, mut show, mut mirror, mut i) = (false, false, false, false, 0);
    while i < rest.len() {
        if rest[i] == "--replace" { replace = true; } else if rest[i] == "--clear" { clear = true; } else if rest[i] == "--show" { show = true; } else if rest[i] == "--mirror-workspace" { mirror = true; }
        else if let Some(v) = parse_flag_value(rest, &mut i, "--cwd") { raw_cwd = v.to_string(); }
        else if let Some(v) = parse_flag_value(rest, &mut i, "--session") { session = v.to_string(); }
        else if let Some(v) = parse_flag_value(rest, &mut i, "--goal") { goal = Some(v.to_string()); }
        else if let Some(v) = parse_flag_value(rest, &mut i, "--status") { status = Some(v.to_string()); }
        else if let Some(v) = parse_flag_value(rest, &mut i, "--decision").or_else(|| parse_flag_value(rest, &mut i, "--decisions")) { decisions.get_or_insert_with(Vec::new).push(v.to_string()); }
        else if let Some(v) = parse_flag_value(rest, &mut i, "--superseded") { superseded.get_or_insert_with(Vec::new).push(v.to_string()); }
        else if let Some(v) = parse_flag_value(rest, &mut i, "--remaining").or_else(|| parse_flag_value(rest, &mut i, "--next")) { remaining.get_or_insert_with(Vec::new).push(v.to_string()); }
        else { eprintln!("continuity handoff: unrecognized argument '{}'", rest[i]); return 2; }
        i += 1;
    }
    let (cwd, pkey) = cli_cwd_and_pkey(&raw_cwd, &session);
    let (ho_file, ws_ho) = (continuity_file("handoffs", &format!("{}.json", pkey)), ws_agent_path(&cwd, "handoff.json"));
    if clear {
        if ho_file.is_file() { let _ = fs::remove_file(&ho_file); }
        if let Some(ref w) = ws_ho { if w.is_file() { let _ = fs::remove_file(w); } }
        rio::print_cli_json(&json!({ "ok": true, "cleared": true, "project_key": pkey }), false); return 0;
    }
    if show || (goal.is_none() && status.is_none() && decisions.is_none() && superseded.is_none() && remaining.is_none()) {
        let (resolved, existing) = resolve_handoff(&cwd, &[], Some(&pkey), &session);
        let path_str = resolved.unwrap_or(ho_file).to_string_lossy().into_owned();
        rio::print_cli_json(&json!({ "exists": existing.is_some(), "project_key": pkey, "path": path_str, "handoff": existing.map(Value::Object).unwrap_or(Value::Null), "digest": build_repo_handoff(&cwd, &session, &[], "authoritative", HANDOFF_MAX_CHARS, Some(&pkey)) }), false);
        return 0;
    }
    let existing = resolve_handoff(&cwd, &[], Some(&pkey), &session).1.unwrap_or_default();
    let (existing_goal, goal_provided) = (val_to_str(existing.get("goal")), goal.as_deref().is_some_and(|g| !g.trim().is_empty()));
    let next_goal = goal.unwrap_or_else(|| existing_goal.clone());
    let existing_sess = val_to_str(existing.get("session")).trim().to_string();
    let handoff_session = if !session.trim().is_empty() { session.trim().to_string() } else { existing_sess.clone() };
    let live_cand_ts = if !handoff_session.is_empty() { cwg_common::read_marker_with_pending(&handoff_session).filter(|m| !json_truthy(m.get("closed"))).map(|m| val_to_f64(m.get("first_ts"))).unwrap_or(0.0) } else { 0.0 };
    let (now, existing_cand_ts, kept_goal_ts) = (now_sec(), val_to_f64(existing.get("candidate_first_ts")), match val_to_f64(existing.get("goal_updated_ts")) { t if t > 0.0 => t, _ => val_to_f64(existing.get("updated_ts")) });
    let goal_changed = goal_provided && !existing_goal.trim().is_empty() && next_goal.trim() != existing_goal.trim();
    let sess_switched = !existing_sess.is_empty() && !handoff_session.is_empty() && existing_sess != handoff_session;
    let cand_switched = sess_switched || (live_cand_ts > 0.0 && existing_cand_ts > 0.0 && (existing_cand_ts - live_cand_ts).abs() > 1.0)
        || (live_cand_ts > 0.0 && existing_cand_ts <= 0.0 && kept_goal_ts > 0.0 && kept_goal_ts + 300.0 < live_cand_ts)
        || (existing_cand_ts > 0.0 && live_cand_ts <= 0.0 && goal_changed);
    let same_live_cand = !sess_switched && live_cand_ts > 0.0 && existing_cand_ts > 0.0 && (existing_cand_ts - live_cand_ts).abs() <= 1.0;
    // INVARIANT: Reset stale prior items & advance `goal_generation` on candidate/session/markerless-goal switch; preserve on partial updates or same-candidate goal refinements.
    let reset_prior = replace || (goal_provided && (cand_switched || (goal_changed && !same_live_cand)));
    let prev_gen = existing.get("goal_generation").and_then(Value::as_u64).unwrap_or(if existing_goal.trim().is_empty() { 0 } else { 1 });
    let next_gen = if reset_prior || (goal_provided && existing_goal.trim().is_empty()) { prev_gen.saturating_add(1) } else { prev_gen };
    let next_status = status.unwrap_or_else(|| { let s = if reset_prior { String::new() } else { val_to_str(existing.get("status")) }; if s.is_empty() { "in_progress".into() } else { s } });
    let merge_f = |k: &str, inc: Option<&[String]>| merge_handoff_items(&if reset_prior { Vec::new() } else { handoff_items(&existing, k) }, inc, reset_prior);
    let git_val = if cwd.is_empty() { json!({}) } else { collect_git_brief(&cwd).map(Value::Object).unwrap_or_else(|| json!({})) };
    // INVARIANT: Bind `candidate_first_ts` and `goal_updated_ts` only when `--goal` is provided or no goal existed yet.
    let (cand_first_ts, goal_updated_ts) = if goal_provided || existing_goal.trim().is_empty() { (live_cand_ts, now) } else { (existing_cand_ts, kept_goal_ts) };
    let updated = json!({ "goal": next_goal, "goal_generation": next_gen, "status": next_status, "decisions": merge_f("decisions", decisions.as_deref()), "superseded": merge_f("superseded", superseded.as_deref()), "remaining": merge_f("remaining", remaining.as_deref()), "git": git_val, "session": handoff_session, "candidate_first_ts": cand_first_ts, "goal_updated_ts": goal_updated_ts, "updated_ts": now });
    let _ = rio::write_json(&ho_file, &updated);
    let mirrored = mirror && ws_ho.as_ref().is_some_and(|w| rio::write_json(w, &updated).is_ok());
    let digest = build_repo_handoff(&cwd, &session, &[], "authoritative", HANDOFF_MAX_CHARS, Some(&pkey));
    rio::print_cli_json(&json!({ "ok": true, "project_key": pkey, "handoff_path": ho_file.to_string_lossy(), "mirrored_workspace": mirrored, "digest_chars": digest.chars().count() }), false);
    0
}

pub fn run_cli(args: &[String]) -> i32 {
    match args.first().map(String::as_str) { Some("checkpoint") => return run_cmd_checkpoint(&args[1..]), Some("show") => return run_cmd_show(&args[1..]), Some("handoff") => return run_cmd_handoff(&args[1..]), _ => {} }
    let event = rio::parse_event_arg(args, "");
    let payload = match rio::read_hook_stdin() { Ok(v) => v, Err(err) => { rio::log_hook_event("hook-errors", "stdin_error", json!({ "hook": "continuity", "event": event, "error": err })); rio::emit_default_for_event(&event); return 0; } };
    match (if !event.is_empty() { event } else { val_to_str(payload.get("hookEventName")) }).as_str() {
        "SessionStart" => match evaluate_session_start(&payload) { (Some(m), md) => rio::emit_inject_system(&m, md.as_deref()), (None, _) => rio::emit_json(&json!({})) },
        "PreInvocation" => match evaluate_pre_invocation(&payload) { Some(m) => rio::emit_inject_system(&m, None), None => rio::emit_json(&json!({})) },
        "PreToolUse" => { let (d, r) = evaluate_pre_tool_use(&payload); rio::emit_pre_tool(&d, r.as_deref(), None); }
        "PostToolUse" => {
            if !json_truthy(payload.get("error")) && matches!(payload.get("toolCall").and_then(|v| v.get("name")).and_then(Value::as_str), Some("edit_file" | "write_file")) {
                let s = rio::session_key(&payload); let mut st = load_session_state(&s); bump_gen(&mut st); save_session_state(&s, &mut st);
            }
            rio::emit_json(&json!({}));
        }
        "Stop" => match decide_stop(&payload) { Some(r) => rio::emit_stop_continue(&r), None => rio::emit_stop_allow() },
        other => rio::emit_default_for_event(other),
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    struct HomeGuard(Option<std::ffi::OsString>, PathBuf);
    impl HomeGuard {
        fn enter(prefix: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("{}-{}", prefix, std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            let prev = std::env::var_os("CARBON_STACK_HOME");
            unsafe { std::env::set_var("CARBON_STACK_HOME", &dir) };
            Self(prev, dir)
        }
    }
    impl Drop for HomeGuard {
        fn drop(&mut self) {
            unsafe {
                match self.0.take() {
                    Some(v) => std::env::set_var("CARBON_STACK_HOME", v),
                    None => std::env::remove_var("CARBON_STACK_HOME"),
                }
            }
            let _ = fs::remove_dir_all(&self.1);
        }
    }

    #[test]
    fn test_all_regexes_compile() {
        assert!(test_runner_re().is_match("cargo test --release"));
        assert!(test_runner_re().is_match("python -m unittest"));
        assert!(strong_correction_re().is_match("Нет, переделай без кеша"));
        assert!(strong_correction_re().is_match("no, instead use SQLite"));
        assert!(history_re().is_match("покажи историю изменений"));
        assert!(edit_residue_re().is_match("В предыдущей версии я сделал иначе."));
        assert!(edit_residue_re().is_match("in my earlier attempt I wrote X"));
        assert!(lint_waiver_re().is_match("[lint] intentional: comparison requested"));
        assert!(section_hdr_re().is_match("## AUTHORITATIVE STATE"));
        assert!(closed_status_re().is_match("completed"));
    }

    #[test]
    fn test_loop_guard_resets_on_mutation_stamp() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let env = HomeGuard::enter("continuity-lg-test");
        let target = env.1.join("sample.rs");
        fs::write(&target, "fn main() {}\n").unwrap();

        let sid = "sess-loop-guard-01";
        let payload = json!({
            "conversationId": sid,
            "toolCall": {
                "id": "call-1",
                "name": "read_file",
                "args": { "Path": target.to_string_lossy(), "StartLine": 1, "EndLine": 10 }
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

        assert_eq!(rio::bump_mutation_stamp(sid), 1);
        let (dec4, reason4) = evaluate_pre_tool_use(&payload);
        assert_eq!(dec4, "allow");
        assert!(reason4.is_none());
    }

    #[test]
    fn test_prose_lines_waiver_and_history_exemption() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = HomeGuard::enter("continuity-lint-test");

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
        })).is_some());

        let block_msg = "В предыдущей версии я сделал с кешем, но исправил.";
        assert!(decide_stop(&json!({
            "conversationId": sid,
            "lastAssistantMessage": block_msg
        })).is_some());

        assert!(decide_stop(&json!({
            "conversationId": sid,
            "lastAssistantMessage": format!("{}\n[lint] intentional: comparing approaches", block_msg)
        })).is_none());

        assert!(evaluate_pre_invocation(&json!({
            "conversationId": sid,
            "lastUserInput": "Нет, не так — покажи что пошло не так и история изменений"
        })).is_some());
        assert!(decide_stop(&json!({
            "conversationId": sid,
            "lastAssistantMessage": block_msg
        })).is_none());
    }

    #[test]
    fn test_pre_invocation_transcript_fallback_dedup_history_and_yo_lint() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let env = HomeGuard::enter("continuity-tx-yo-test");
        let tp = env.1.join("transcript.jsonl");
        let sample = env.1.join("a.rs");
        fs::write(&sample, "fn a() {}\n").unwrap();

        let sid = "sess-tx-fallback-01";
        let empty_ui_payload = || json!({
            "conversationId": sid,
            "transcriptPath": tp.to_string_lossy(),
            "lastUserInput": "",
        });
        let omitted_ui_payload = || json!({
            "conversationId": sid,
            "transcriptPath": tp.to_string_lossy(),
        });

        // (a) Empty lastUserInput falls back to transcript USER_INPUT and fires strong_correction_re strictly ONCE per turn without resetting tool_counts mid-turn.
        let t1 = "{\"step_index\":0,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"Нет, переделай без кеша\"}\n";
        fs::write(&tp, t1).unwrap();
        let inj1 = evaluate_pre_invocation(&empty_ui_payload()).unwrap();
        assert!(inj1.contains("Замена требования"));

        assert_eq!(evaluate_pre_tool_use(&json!({
            "conversationId": sid,
            "toolCall": { "id": "c1", "name": "read_file", "args": { "Path": sample.to_string_lossy() } }
        })).0, "allow");
        assert!(evaluate_pre_invocation(&omitted_ui_payload()).is_none());
        let st_mid = load_session_state(sid);
        assert_eq!(val_to_i64(st_mid.get("strong_correction_streak")), 1);
        assert!(!st_mid.get("tool_counts").and_then(Value::as_object).unwrap().is_empty());

        // New user turn at step 4 (even identical text) fires once, escalates streak to 2, and resets tool_counts.
        let t2 = format!("{}{}", t1, "{\"step_index\":4,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"Нет, переделай без кеша\"}\n");
        fs::write(&tp, &t2).unwrap();
        let inj2 = evaluate_pre_invocation(&empty_ui_payload()).unwrap();
        assert!(inj2.contains("Clean-Room Rebuild Escalation"));
        assert!(load_session_state(sid).get("tool_counts").and_then(Value::as_object).unwrap().is_empty());
        assert!(evaluate_pre_invocation(&empty_ui_payload()).is_none());

        // Transcript-flush lag: explicit lastUserInput fires once, stale step 4 does not clobber, and flushing step 8 does not double-fire.
        let lag_payload = json!({
            "conversationId": sid,
            "transcriptPath": tp.to_string_lossy(),
            "lastUserInput": "Нет, убери кеш полностью",
        });
        assert!(evaluate_pre_invocation(&lag_payload).is_some());
        assert!(evaluate_pre_invocation(&omitted_ui_payload()).is_none());
        let t3 = format!("{}{}", t2, "{\"step_index\":8,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"Нет, убери кеш полностью\"}\n");
        fs::write(&tp, &t3).unwrap();
        assert!(evaluate_pre_invocation(&empty_ui_payload()).is_none());

        // (b) HISTORY exemption triggers from transcript-derived user input when lastUserInput is empty.
        let t4 = format!("{}{}", t3, "{\"step_index\":12,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"Нет, не так — покажи историю изменений и что пошло не так\"}\n");
        fs::write(&tp, &t4).unwrap();
        assert!(evaluate_pre_invocation(&empty_ui_payload()).is_some());
        assert!(json_truthy(load_session_state(sid).get("history_requested")));
        assert!(decide_stop(&json!({
            "conversationId": sid,
            "transcriptPath": tp.to_string_lossy(),
            "lastAssistantMessage": "В предыдущей версии я сделал с кешем, но исправил."
        })).is_none());

        // (c) `ё -> е` and `Ё -> Е` normalization works in decide_stop output lint.
        assert_eq!(prose_lines("Ещё Ёжик"), vec!["Еще Ежик"]);
        let t5 = format!("{}{}", t4, "{\"step_index\":16,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"Нет, переделай начисто\"}\n");
        fs::write(&tp, &t5).unwrap();
        assert!(evaluate_pre_invocation(&empty_ui_payload()).is_some());
        assert!(!json_truthy(load_session_state(sid).get("history_requested")));

        let yo_lower_blk = decide_stop(&json!({
            "conversationId": sid,
            "transcriptPath": tp.to_string_lossy(),
            "lastAssistantMessage": "Сначала я реализовал старый кеш, но затём исправил."
        }));
        assert!(yo_lower_blk.unwrap().contains("Continuity Output Lint"));

        let yo_upper_blk = decide_stop(&json!({
            "conversationId": sid,
            "transcriptPath": tp.to_string_lossy(),
            "lastAssistantMessage": "КАК Я УЖЁ ПИСАЛ ДО ИСПРАВЛЕНИЯ, решение готово."
        }));
        assert!(yo_upper_blk.unwrap().contains("Continuity Output Lint"));

        // (d) Codex C3 #4 & R2 #1: mid-turn tool-call PLANNER_RESPONSE must NOT re-trigger the same correction when lastUserInput repeats; repeating identical correction AFTER a completed turn with lagging transcript MUST fire PreInvocation and re-arm Stop lint; late-flushed transcript USER_INPUT must be caught in Stop.
        let sid_rep = "sess-repeat-corr-01";
        let tp_rep = env.1.join("transcript_repeat.jsonl");
        let rep_mid = concat!(
            "{\"step_index\":0,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"Нет, переделай\"}\n",
            "{\"step_index\":1,\"source\":\"MODEL\",\"type\":\"PLANNER_RESPONSE\",\"content\":\"Читаю файл\",\"tool_calls\":[{\"name\":\"read_file\"}]}\n"
        );
        fs::write(&tp_rep, rep_mid).unwrap();
        assert!(evaluate_pre_invocation(&json!({
            "conversationId": sid_rep, "transcriptPath": tp_rep.to_string_lossy(), "lastUserInput": "Нет, переделай"
        })).is_some());
        assert_eq!(evaluate_pre_tool_use(&json!({
            "conversationId": sid_rep,
            "toolCall": { "id": "c-mid", "name": "read_file", "args": { "Path": sample.to_string_lossy() } }
        })).0, "allow");
        assert!(evaluate_pre_invocation(&json!({
            "conversationId": sid_rep, "transcriptPath": tp_rep.to_string_lossy(), "lastUserInput": "Нет, переделай"
        })).is_none(), "mid-turn tool-call PLANNER_RESPONSE must NOT re-fire same user turn");
        let st_rep_mid = load_session_state(sid_rep);
        assert_eq!(val_to_i64(st_rep_mid.get("strong_correction_streak")), 1);
        assert!(!st_rep_mid.get("tool_counts").and_then(Value::as_object).unwrap().is_empty());

        let rep_t1 = format!("{}{}", rep_mid, "{\"step_index\":2,\"source\":\"MODEL\",\"type\":\"PLANNER_RESPONSE\",\"content\":\"В предыдущей версии я сделал иначе.\",\"tool_calls\":[]}\n");
        fs::write(&tp_rep, &rep_t1).unwrap();
        // Codex C3 R3: Stop -> continue (lint block #1) followed by PreInvocation with same lastUserInput MUST preserve lint_blocks=1 and streak=1 (never reset or exceed 2-block cap).
        assert!(decide_stop(&json!({
            "conversationId": sid_rep, "transcriptPath": tp_rep.to_string_lossy(), "lastAssistantMessage": "В предыдущей версии я сделал иначе."
        })).is_some(), "Stop lint block #1 expected");
        assert!(evaluate_pre_invocation(&json!({
            "conversationId": sid_rep, "transcriptPath": tp_rep.to_string_lossy(), "lastUserInput": "Нет, переделай"
        })).is_none(), "Stop -> continue PreInvocation with same input must NOT re-trigger correction or reset lint_blocks");
        let st_after_cont = load_session_state(sid_rep);
        assert_eq!(val_to_i64(st_after_cont.get("lint_blocks")), 1);
        assert_eq!(val_to_i64(st_after_cont.get("strong_correction_streak")), 1);
        assert!(decide_stop(&json!({
            "conversationId": sid_rep, "transcriptPath": tp_rep.to_string_lossy(), "lastAssistantMessage": "В предыдущей версии я сделал иначе."
        })).is_some(), "Stop lint block #2 expected");
        assert!(evaluate_pre_invocation(&json!({
            "conversationId": sid_rep, "transcriptPath": tp_rep.to_string_lossy(), "lastUserInput": "Нет, переделай"
        })).is_none());
        assert!(decide_stop(&json!({
            "conversationId": sid_rep, "transcriptPath": tp_rep.to_string_lossy(), "lastAssistantMessage": "В предыдущей версии я сделал иначе."
        })).is_none(), "3rd Stop attempt must pass once 2-block lint cap is reached");
        // New turn repeats identical text while transcript still shows step 0..2 -> MUST fire and re-arm Stop lint!
        let rep_inj = evaluate_pre_invocation(&json!({
            "conversationId": sid_rep, "transcriptPath": tp_rep.to_string_lossy(), "lastUserInput": "Нет, переделай"
        }));
        assert!(rep_inj.is_some(), "repeated identical correction after finished turn must fire despite transcript lag");
        assert!(decide_stop(&json!({
            "conversationId": sid_rep, "transcriptPath": tp_rep.to_string_lossy(), "lastAssistantMessage": "В предыдущей версии я сделал иначе."
        })).is_some(), "Stop lint must block after repeated correction");
        assert!(decide_stop(&json!({
            "conversationId": sid_rep, "transcriptPath": tp_rep.to_string_lossy(), "lastAssistantMessage": "Исправлено начисто."
        })).is_none());
        // Late transcript flush case: PreInvocation saw empty lastUserInput & lagged transcript, then new USER_INPUT flushes before Stop.
        assert!(evaluate_pre_invocation(&json!({
            "conversationId": sid_rep, "transcriptPath": tp_rep.to_string_lossy(), "lastUserInput": ""
        })).is_none());
        fs::write(&tp_rep, format!("{}{}", rep_t1, "{\"step_index\":5,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"Нет, переделай\"}\n")).unwrap();
        assert!(decide_stop(&json!({
            "conversationId": sid_rep, "transcriptPath": tp_rep.to_string_lossy(), "lastAssistantMessage": "В предыдущей версии я сделал иначе."
        })).is_some(), "Stop must catch newly flushed USER_INPUT correction");

        // (e) Codex C3 #5: an unreadable newer CHECKPOINT.md (e.g. invalid UTF-8 / UTF-16 bytes) must NOT revive a closed handoff on SessionStart(resume).
        let ws_dir = env.1.join("repo_utf16");
        let agents_dir = ws_dir.join(".agents");
        fs::create_dir_all(&agents_dir).unwrap();
        fs::write(
            agents_dir.join("handoff.json"),
            r#"{"goal":"OLD CLOSED GOAL","status":"done","remaining":["OLD NEXT"],"updated_ts":1000.0}"#,
        ).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(30));
        // Write UTF-16LE bytes (invalid UTF-8) with newer mtime than closed handoff.json.
        fs::write(agents_dir.join("CHECKPOINT.md"), &[0xFF, 0xFE, b'#', 0x00, b' ', 0x00, b'C', 0x00]).unwrap();
        let (ss_msg, _) = evaluate_session_start(&json!({
            "conversationId": "sess-utf16-cp",
            "cwd": ws_dir.to_string_lossy(),
            "source": "resume"
        }));
        assert!(
            !ss_msg.unwrap_or_default().contains("OLD CLOSED GOAL"),
            "unreadable newer CHECKPOINT.md must not revive closed handoff.json"
        );
    }
}
