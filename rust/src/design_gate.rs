use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{cwg_common, cwg_mark, cwg_stop, rio};

pub const MAX_EVIDENCE_ENTRIES: usize = 64;
pub const MAX_SCREENSHOT_BYTES: u64 = 64 * 1024 * 1024;
const MTIME_EPS_SEC: f64 = 0.05;
const MTIME_DRIFT_TOLERANCE_SEC: f64 = 2.0;

fn now_sec() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn evidence_path(session: &str) -> PathBuf {
    let dir = rio::state_dir().join("gate").join("design");
    let _ = fs::create_dir_all(&dir);
    dir.join(format!("{}.json", rio::safe_key(session, "default")))
}

pub fn evidence_lock_path(session: &str) -> PathBuf {
    let dir = rio::state_dir().join("gate").join("design");
    let _ = fs::create_dir_all(&dir);
    dir.join(format!("{}.lock", rio::safe_key(session, "default")))
}

pub fn clear_evidence(session: &str) {
    if session.trim().is_empty() {
        return;
    }
    let _ = fs::remove_file(evidence_path(session));
}

pub fn is_valid_image_magic_bytes(buf: &[u8]) -> bool {
    if buf.len() >= 8 && &buf[..8] == b"\x89PNG\r\n\x1a\n" {
        return true;
    }
    if buf.len() >= 3 && buf[0] == 0xFF && buf[1] == 0xD8 && buf[2] == 0xFF {
        return true;
    }
    if buf.len() >= 12 && &buf[..4] == b"RIFF" && &buf[8..12] == b"WEBP" {
        return true;
    }
    if buf.len() >= 6 && (&buf[..6] == b"GIF87a" || &buf[..6] == b"GIF89a") {
        return true;
    }
    false
}

pub fn file_has_valid_image_magic(path: &Path) -> bool {
    let Ok(mut f) = fs::File::open(path) else {
        return false;
    };
    let mut buf = [0u8; 12];
    let Ok(n) = f.read(&mut buf) else {
        return false;
    };
    is_valid_image_magic_bytes(&buf[..n])
}

fn inspect_image_file(path: &Path) -> Result<(String, u64, f64), String> {
    let md = fs::metadata(path)
        .map_err(|e| format!("cannot stat screenshot `{}`: {}", path.display(), e))?;
    if !md.is_file() {
        return Err(format!(
            "screenshot path `{}` is not a regular file",
            path.display()
        ));
    }
    let size = md.len();
    if size == 0 {
        return Err(format!("screenshot `{}` is empty", path.display()));
    }
    if size > MAX_SCREENSHOT_BYTES {
        return Err(format!(
            "screenshot `{}` exceeds {} byte cap ({} bytes)",
            path.display(),
            MAX_SCREENSHOT_BYTES,
            size
        ));
    }
    let mtime = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    let mut f = fs::File::open(path)
        .map_err(|e| format!("cannot open screenshot `{}`: {}", path.display(), e))?;
    let mut hasher = Sha256::new();
    let mut header = [0u8; 12];
    let mut header_len = 0usize;
    let mut buf = [0u8; 16384];
    let mut total = 0u64;
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| format!("cannot read screenshot `{}`: {}", path.display(), e))?;
        if n == 0 {
            break;
        }
        if header_len < header.len() {
            let take = (header.len() - header_len).min(n);
            header[header_len..header_len + take].copy_from_slice(&buf[..take]);
            header_len += take;
        }
        total += n as u64;
        if total > MAX_SCREENSHOT_BYTES {
            return Err(format!(
                "screenshot `{}` grew past {} byte cap during read",
                path.display(),
                MAX_SCREENSHOT_BYTES
            ));
        }
        hasher.update(&buf[..n]);
    }
    if !is_valid_image_magic_bytes(&header[..header_len]) {
        return Err(format!(
            "file `{}` does not have a valid PNG/JPEG/WebP/GIF header",
            path.display()
        ));
    }
    Ok((hex::encode(hasher.finalize()), total, mtime))
}

fn scope_compatible(base_dir: &str, entry_root: &str) -> bool {
    let b = rio::fold_path(base_dir).trim_end_matches('/').to_string();
    let e = rio::fold_path(entry_root).trim_end_matches('/').to_string();
    if b.is_empty() || e.is_empty() {
        return true;
    }
    b == e || b.starts_with(&format!("{}/", e)) || e.starts_with(&format!("{}/", b))
}

pub fn record_screenshot(
    session: &str,
    raw_path: &str,
    cwd: Option<&str>,
    viewport: Option<&str>,
    theme: Option<&str>,
    source: Option<&str>,
) -> Result<Value, String> {
    let sess = session.trim();
    if sess.is_empty() {
        return Err("missing --session <conversation-id>".to_string());
    }
    let trimmed_raw = raw_path.trim();
    if trimmed_raw.is_empty() {
        return Err("missing --path <screenshot-file>".to_string());
    }
    let eff_cwd = cwd
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| env::current_dir().ok())
        .unwrap_or_default();

    let candidate = PathBuf::from(trimmed_raw);
    let abs_raw = if candidate.is_absolute() || eff_cwd.as_os_str().is_empty() {
        candidate
    } else {
        eff_cwd.join(candidate)
    };
    let resolved = rio::resolve_abs_path(&abs_raw);
    let (sha256, size, mtime) = inspect_image_file(&resolved)?;

    let norm_path = rio::normalize_path(&resolved.to_string_lossy());
    let norm_cwd = if eff_cwd.as_os_str().is_empty() {
        String::new()
    } else {
        rio::normalize_path(&rio::resolve_abs_path(&eff_cwd).to_string_lossy())
    };
    let git_root = (!norm_cwd.is_empty())
        .then(|| rio::git_toplevel(&norm_cwd, false))
        .flatten()
        .or_else(|| {
            resolved
                .parent()
                .and_then(|p| rio::git_toplevel(&p.to_string_lossy(), false))
        })
        .unwrap_or_default();

    let recorded_ts = now_sec();
    let entry = json!({
        "path": norm_path,
        "sha256": sha256,
        "size": size,
        "mtime": mtime,
        "recorded_ts": recorded_ts,
        "cwd": norm_cwd,
        "git_root": git_root,
        "viewport": viewport.unwrap_or("").trim(),
        "theme": theme.unwrap_or("").trim(),
        "source": source.unwrap_or("cli").trim(),
    });

    let ev_path = evidence_path(sess);
    let lock_path = evidence_lock_path(sess);
    let write_res: Result<(), String> = rio::with_file_lock(&lock_path, 3.0, 15.0, |_| {
        let mut list: Vec<Value> = rio::read_json(&ev_path)
            .and_then(|v| v.get("screenshots").and_then(Value::as_array).cloned())
            .unwrap_or_default();
        let entry_path_fold = rio::fold_path(&norm_path);
        list.retain(|item| {
            let p = item.get("path").and_then(Value::as_str).unwrap_or("");
            let h = item.get("sha256").and_then(Value::as_str).unwrap_or("");
            !(rio::fold_path(p) == entry_path_fold && h == sha256)
        });
        list.push(entry.clone());
        if list.len() > MAX_EVIDENCE_ENTRIES {
            let drop_n = list.len() - MAX_EVIDENCE_ENTRIES;
            list.drain(0..drop_n);
        }
        let doc = json!({
            "version": 1,
            "session": sess,
            "updated_ts": recorded_ts,
            "screenshots": list,
        });
        rio::write_json(&ev_path, &doc)
            .map_err(|e| format!("failed to write design evidence `{}`: {}", ev_path.display(), e))
    });
    write_res?;
    Ok(entry)
}

#[derive(Debug, Clone)]
pub struct ScreenshotArtifact {
    pub path: String,
    pub sha256: String,
    pub ts: f64,
    pub source: String,
}

#[derive(Debug, Clone)]
pub struct ReviewApproval {
    pub ts: f64,
    pub text: String,
    pub read_files: Vec<(String, f64)>,
}

pub fn verified_screenshot_artifacts(
    session: &str,
    cand_floor_ts: f64,
    design_freshness_floor: f64,
    base_dir: &str,
) -> Vec<ScreenshotArtifact> {
    if session.trim().is_empty() {
        return Vec::new();
    }
    let ev_path = evidence_path(session);
    let Some(doc) = rio::read_json(&ev_path) else {
        return Vec::new();
    };
    let Some(items) = doc.get("screenshots").and_then(Value::as_array) else {
        return Vec::new();
    };
    // INVARIANT: Require BOTH `recorded_ts >= max(cand_floor_ts, design_freshness_floor)` AND on-disk image re-verification (valid magic, exact recorded SHA-256, `live_mtime >= design_freshness_floor`, no post-record mtime touch) so neither pre-edit images nor tampered files can satisfy Design Gate.
    let req_recorded = cand_floor_ts.max(design_freshness_floor);
    let mut out = Vec::new();
    for item in items {
        let recorded_ts = item.get("recorded_ts").and_then(Value::as_f64).unwrap_or(0.0);
        let recorded_mtime = item.get("mtime").and_then(Value::as_f64).unwrap_or(0.0);
        let recorded_sha = item.get("sha256").and_then(Value::as_str).unwrap_or("");
        let path_str = item.get("path").and_then(Value::as_str).unwrap_or("");
        let entry_root = item.get("git_root").and_then(Value::as_str).unwrap_or("");
        if recorded_ts <= 0.0 || recorded_sha.is_empty() || path_str.is_empty() {
            continue;
        }
        if req_recorded > 0.0 && recorded_ts + MTIME_EPS_SEC < req_recorded {
            continue;
        }
        if design_freshness_floor > 0.0 && recorded_mtime + MTIME_EPS_SEC < design_freshness_floor {
            continue;
        }
        if !scope_compatible(base_dir, entry_root) {
            continue;
        }
        let Ok((live_sha, _, live_mtime)) = inspect_image_file(Path::new(path_str)) else {
            continue;
        };
        if live_sha != recorded_sha {
            continue;
        }
        if design_freshness_floor > 0.0 && live_mtime + MTIME_EPS_SEC < design_freshness_floor {
            continue;
        }
        if recorded_mtime > 0.0 && (live_mtime - recorded_mtime).abs() > MTIME_DRIFT_TOLERANCE_SEC {
            continue;
        }
        let honest_ts = if live_mtime > 0.0 {
            live_mtime.min(recorded_ts)
        } else {
            recorded_ts
        };
        out.push(ScreenshotArtifact {
            path: rio::normalize_path(path_str),
            sha256: recorded_sha.to_string(),
            ts: honest_ts,
            source: "cli".to_string(),
        });
    }
    out
}

pub fn verified_screenshot_ts(
    session: &str,
    cand_floor_ts: f64,
    design_freshness_floor: f64,
    base_dir: &str,
) -> f64 {
    verified_screenshot_artifacts(session, cand_floor_ts, design_freshness_floor, base_dir)
        .into_iter()
        .map(|a| a.ts)
        .fold(0.0f64, f64::max)
}

fn design_review_verdict_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:(?:\*{1,2}|__|`)[ \t]*){0,2}(VISUAL|UX)_REVIEW_VERDICT(?:(?:\*{1,2}|__|`)\s*){0,2}\s*:\s*(?:(?:\*{1,2}|__|`)\s*){0,2}(APPROVED|REVISE|BLOCKED|CHANGES_REQUESTED|REJECTED)\b",
        )
        .expect("design_review_verdict_re")
    })
}

fn design_verdict_alt_tail_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\A\s*(?:(?:\*{1,2}|__|`)\s*){0,2}(?:\||/|(?:\b(?:or|или)\b)\s+(?:APPROVED|REVISE|BLOCKED|CHANGES_REQUESTED|REJECTED)\b)",
        )
        .expect("design_verdict_alt_tail_re")
    })
}

fn design_reviewer_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:visual[-_]?(?:qa|design|critic|review)|ui[-_]?qa|uiux|ux[-_]?(?:adversarial|audit|critic|review)|design[-_]?(?:critic|audit|review|qa))",
        )
        .expect("design_reviewer_name_re")
    })
}

fn browser_qa_worker_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:browser[-_]?qa|\bbrowser\b|visual[-_]?(?:qa|design|critic|review)|ui[-_]?qa|uiux|ux[-_]?(?:adversarial|audit|critic|review)|design[-_]?(?:critic|audit|review|qa))",
        )
        .expect("browser_qa_worker_name_re")
    })
}

fn snake_cid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#""conversation_id"\s*:\s*"(?P<cid>[A-Za-z0-9._-]{4,80})""#)
            .expect("snake_cid_re")
    })
}

fn non_system_msg_sender_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\[Message\][^\r\n]*\bsender=([^\s\]]+)").expect("non_system_msg_sender_re")
    })
}

fn is_builtin_readonly_reviewer_type(type_low: &str) -> bool {
    matches!(
        type_low,
        "visual-qa-reviewer"
            | "research"
            | "adversarial-reviewer"
            | "adversarial-reviewer-xhigh"
            | "flutter_a11y_agent"
            | "code-explorer"
            | "editorial-auditor"
    )
}

#[derive(Debug, Default)]
struct ChildTranscriptAudit {
    verified_complete: bool,
    has_write_activity: bool,
    max_step_ts: f64,
    read_files: Vec<(String, f64)>,
}

fn normalize_read_path_for_match(raw_path: &str, base_cwd: &str) -> String {
    let trimmed = raw_path.trim().trim_start_matches("file:///").trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let p = Path::new(trimmed);
    if p.is_absolute() || base_cwd.trim().is_empty() {
        rio::fold_path(trimmed)
    } else {
        let joined = Path::new(base_cwd).join(p);
        rio::fold_path(&joined.to_string_lossy())
    }
}

fn audit_child_transcript(tp: &Path, base_cwd: &str) -> ChildTranscriptAudit {
    // INVARIANT: Reuse `rio::read_all_decoded_transcript_steps_checked` so `transcript_full.jsonl` is preferred, compact `transcript.jsonl` arguments are properly decoded, the ENTIRE file is audited without tail truncation, and empty/unreadable/corrupt logs fail closed (`verified_complete = false`). Treat any non-READ_ONLY/non-BOOKKEEPING `run_command` (including `UNCERTAIN` tools like `npx prettier --write`) as write activity.
    let mut out = ChildTranscriptAudit::default();
    let Ok(steps) = rio::read_all_decoded_transcript_steps_checked(&tp.to_string_lossy()) else {
        return out;
    };
    out.verified_complete = true;
    for (idx, st) in steps.iter().enumerate() {
        let st_ts = st
            .get("created_at")
            .and_then(Value::as_str)
            .map(rio::parse_iso_ts)
            .unwrap_or(0.0);
        if st_ts > 0.0 {
            out.max_step_ts = out.max_step_ts.max(st_ts);
        }
        let Some(tcs) = st.get("tool_calls").and_then(Value::as_array) else {
            continue;
        };
        let following = &steps[idx + 1..];
        let generic_resps: Vec<&Value> = following
            .iter()
            .take_while(|s| {
                let st_t = s.get("type").and_then(Value::as_str).unwrap_or("");
                st_t.is_empty() || st_t.eq_ignore_ascii_case("GENERIC")
            })
            .collect();
        for (pos, tc) in tcs.iter().enumerate() {
            let tname = tc
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            let args = tc.get("arguments").or_else(|| tc.get("args"));
            if matches!(
                tname.as_str(),
                "write_file"
                    | "edit_file"
                    | "replace_file_content"
                    | "multi_replace_file_content"
                    | "write_to_file"
                    | "create_file"
                    | "delete_file"
            ) {
                out.has_write_activity = true;
            } else if tname == "run_command" {
                let cmd = args
                    .and_then(|a| a.get("CommandLine").or_else(|| a.get("commandLine")))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if !cmd.trim().is_empty() {
                    let cls = cwg_mark::classify_shell_command_core(&rio::unwrap_tokenade_command(cmd));
                    if cls != "READ_ONLY" && cls != "BOOKKEEPING" {
                        out.has_write_activity = true;
                    }
                }
            } else if tname == "swarm" {
                let act = args
                    .and_then(|a| a.get("action"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let ws = args
                    .and_then(|a| a.get("workspace").or_else(|| a.get("workspace_mode")))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase();
                if act.eq_ignore_ascii_case("add") && matches!(ws.as_str(), "share" | "branch") {
                    out.has_write_activity = true;
                }
            } else if tname == "read_file" || tname == "view_file" {
                let p = args
                    .and_then(|a| {
                        a.get("Path")
                            .or_else(|| a.get("path"))
                            .or_else(|| a.get("AbsolutePath"))
                    })
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                if !p.is_empty() {
                    if let Some((rts, _)) =
                        confirmed_tool_response(generic_resps.get(pos).copied(), st_ts)
                    {
                        let norm = normalize_read_path_for_match(p, base_cwd);
                        if !norm.is_empty() {
                            out.read_files.push((norm, rts));
                        }
                    }
                }
            }
        }
    }
    out
}

#[derive(Debug, Default)]
pub struct DesignGateEvidence {
    pub screenshot_ts: f64,
    pub screenshots: Vec<ScreenshotArtifact>,
    pub visual_approved_ts: f64,
    pub visual_blocked_ts: f64,
    pub visual_approvals: Vec<ReviewApproval>,
    pub ux_seen: bool,
    pub ux_launched_ts: f64,
    pub ux_approved_ts: f64,
    pub ux_blocked_ts: f64,
}

impl DesignGateEvidence {
    fn push_screenshot(&mut self, artifact: ScreenshotArtifact) {
        self.screenshot_ts = self.screenshot_ts.max(artifact.ts);
        self.screenshots.push(artifact);
    }

    pub fn check_visual_binding(&self, design_freshness_floor: f64) -> Result<(), String> {
        let latest = self
            .screenshots
            .iter()
            .filter(|s| design_freshness_floor <= 0.0 || s.ts + MTIME_EPS_SEC >= design_freshness_floor)
            .max_by(|a, b| a.ts.total_cmp(&b.ts));
        let Some(latest) = latest else {
            return Ok(());
        };
        // INVARIANT: The latest verified visual approval must chronologically follow the latest captured/recorded screenshot AND bind to its artifact identity (post-capture `read_file` or SHA-256 prefix for CLI; post-capture `read_file` or path/basename citation for native path-bearing screenshots) so parallel approvals of stale images never bypass new captures.
        if self.visual_approved_ts + MTIME_EPS_SEC < latest.ts {
            return Err(
                "Design Gate: latest screenshot was captured/recorded after the last visual approval; have the independent read-only visual reviewer inspect the latest screenshot and emit a fresh `VISUAL_REVIEW_VERDICT: APPROVED`"
                    .to_string(),
            );
        }
        let target_fold = rio::fold_path(&latest.path);
        let target_raw = normalize_artifact_display_path(&latest.path).to_ascii_lowercase();
        let target_base = Path::new(&latest.path)
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let sha_prefix = if latest.sha256.len() >= 8 {
            latest.sha256[..8].to_ascii_lowercase()
        } else {
            String::new()
        };

        let bound = self.visual_approvals.iter().any(|appr| {
            if appr.ts + MTIME_EPS_SEC < latest.ts {
                return false;
            }
            if latest.path.is_empty() && sha_prefix.is_empty() {
                return true;
            }
            // INVARIANT: Only confirmed `read_file` calls on the EXACT normalized artifact path that completed AFTER capture AND AT/BEFORE the approval bind an approval to a screenshot (preventing `light/desktop.png` from matching `dark/desktop.png` or post-verdict reads from retroactively binding).
            let read_in_window = !target_fold.is_empty()
                && appr.read_files.iter().any(|(rf, rts)| {
                    *rts + MTIME_EPS_SEC >= latest.ts
                        && *rts <= appr.ts + MTIME_EPS_SEC
                        && (*rf == target_fold || (!target_raw.is_empty() && *rf == target_raw))
                });
            if read_in_window {
                return true;
            }
            let low_text = appr.text.replace('\\', "/").to_ascii_lowercase();
            if !sha_prefix.is_empty() {
                return low_text.contains(&sha_prefix);
            }
            if !target_raw.is_empty() {
                if target_raw.contains('/') {
                    return low_text.contains(&target_raw) || low_text.contains(&target_fold);
                }
                return !target_base.is_empty() && low_text.contains(&target_base);
            }
            false
        });

        if !bound {
            let hint = if !sha_prefix.is_empty() {
                format!(
                    "have the read-only visual reviewer inspect `{}` via `read_file` after capture or cite its SHA-256 prefix `{}` in `VISUAL_REVIEW_VERDICT: APPROVED`",
                    target_base, sha_prefix
                )
            } else {
                format!(
                    "have the read-only visual reviewer inspect `{}` via `read_file` after capture or reference it in `VISUAL_REVIEW_VERDICT: APPROVED`",
                    target_base
                )
            };
            return Err(format!(
                "Design Gate: visual approval is not bound to the latest verified screenshot ({}); {}",
                if target_base.is_empty() { &latest.source } else { &target_base },
                hint
            ));
        }

        if self.ux_seen && self.ux_approved_ts + MTIME_EPS_SEC < latest.ts {
            return Err(
                "Design Gate: independent UX approval predates the latest captured screenshot; re-verify the latest UI and obtain a fresh `UX_REVIEW_VERDICT: APPROVED`"
                    .to_string(),
            );
        }
        Ok(())
    }
}

fn is_design_verdict_line_prefix_clean(text: &str, match_start: usize) -> bool {
    let line_start = text[..match_start].rfind('\n').map_or(0, |i| i + 1);
    let mut prefix = text[line_start..match_start].trim();
    loop {
        let prev = prefix;
        prefix = prefix
            .trim_start_matches(|c: char| {
                matches!(c, ' ' | '\t' | '-' | '*' | '+' | '>' | '#' | '_' | '`')
            })
            .trim_start();
        if let Some(rest) = prefix.strip_prefix('[') {
            if let Some(close) = rest.find(']') {
                let tag = rest[..close].trim().to_ascii_lowercase();
                if matches!(
                    tag.as_str(),
                    "done" | "ok" | "pass" | "revise" | "blocked" | "verdict"
                ) {
                    prefix = rest[close + 1..].trim_start();
                }
            }
        }
        if prefix == prev {
            break;
        }
    }
    prefix.is_empty()
}

fn is_ux_and_uiux_role(name: &str) -> (bool, bool) {
    let low = name.to_ascii_lowercase();
    let is_uiux = low.contains("uiux")
        || low.contains("ui-ux")
        || low.contains("ui_ux")
        || (low.contains("visual") && low.contains("ux"));
    let is_ux = low.contains("ux");
    (is_ux, is_uiux)
}

fn record_design_verdicts(
    text: &str,
    ts: f64,
    is_design_agent: bool,
    is_ux_agent: bool,
    is_uiux_agent: bool,
    read_files: &[(String, f64)],
    ev: &mut DesignGateEvidence,
) {
    // INVARIANT: Only verified independent design/visual/UX reviewers may emit Design Gate verdicts; builder/coordinator prose quoting verdict tags is never accepted.
    if !is_design_agent {
        return;
    }
    let eff_ts = if ts > 0.0 { ts } else { 1.0 };
    let mut matched_explicit = false;
    for caps in design_review_verdict_re().captures_iter(text) {
        let Some(whole) = caps.get(0) else {
            continue;
        };
        if !is_design_verdict_line_prefix_clean(text, whole.start()) {
            continue;
        }
        if design_verdict_alt_tail_re().is_match(&text[whole.end()..]) {
            continue;
        }
        let is_ux_tag = caps[1].eq_ignore_ascii_case("UX");
        if is_ux_tag && !(is_ux_agent || is_uiux_agent) {
            continue;
        }
        if !is_ux_tag && is_ux_agent && !is_uiux_agent {
            continue;
        }
        matched_explicit = true;
        let is_approved = caps[2].eq_ignore_ascii_case("APPROVED");
        if is_ux_tag {
            ev.ux_seen = true;
            if is_approved {
                ev.ux_approved_ts = ev.ux_approved_ts.max(eff_ts);
            } else {
                ev.ux_blocked_ts = ev.ux_blocked_ts.max(eff_ts);
            }
        } else if is_approved {
            ev.visual_approved_ts = ev.visual_approved_ts.max(eff_ts);
            ev.visual_approvals.push(ReviewApproval {
                ts: eff_ts,
                text: text.to_string(),
                read_files: read_files.to_vec(),
            });
        } else {
            ev.visual_blocked_ts = ev.visual_blocked_ts.max(eff_ts);
        }
    }
    if matched_explicit {
        return;
    }
    let (kind_opt, Some(v)) = cwg_common::extract_review_decision(text) else {
        return;
    };
    if kind_opt.as_deref() != Some("ordinary") {
        return;
    }
    if is_ux_agent && !is_uiux_agent {
        ev.ux_seen = true;
        if v == "APPROVED" {
            ev.ux_approved_ts = ev.ux_approved_ts.max(eff_ts);
        } else {
            ev.ux_blocked_ts = ev.ux_blocked_ts.max(eff_ts);
        }
    } else if v == "APPROVED" {
        ev.visual_approved_ts = ev.visual_approved_ts.max(eff_ts);
        ev.visual_approvals.push(ReviewApproval {
            ts: eff_ts,
            text: text.to_string(),
            read_files: read_files.to_vec(),
        });
    } else {
        ev.visual_blocked_ts = ev.visual_blocked_ts.max(eff_ts);
    }
}

fn strip_generic_timestamp_headers(content: &str) -> &str {
    let mut rest = content.trim_start();
    loop {
        if rest.starts_with("Created At:") || rest.starts_with("Completed At:") {
            if let Some(nl) = rest.find('\n') {
                rest = rest[nl + 1..].trim_start();
                continue;
            }
            return "";
        }
        break;
    }
    rest
}

fn extract_json_after_headers(content: &str) -> Option<Value> {
    let body = strip_generic_timestamp_headers(content).trim();
    if body.is_empty() {
        return None;
    }
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        return Some(v);
    }
    let start = body.find('{')?;
    let end = body.rfind('}')?;
    if end > start {
        serde_json::from_str::<Value>(&body[start..=end]).ok()
    } else {
        None
    }
}

fn step_has_nonempty_error_field(step: &Value) -> bool {
    match step.get("error") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.trim().is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(m)) => !m.is_empty(),
        Some(_) => true,
    }
}

fn confirmed_tool_response(next_step: Option<&Value>, fallback_ts: f64) -> Option<(f64, String)> {
    let nxt = next_step?;
    let ntype = nxt.get("type").and_then(Value::as_str).unwrap_or("").trim();
    // INVARIANT: Accept ONLY host tool-response steps (`GENERIC` or empty type) with successful host status (`DONE`/`OK`/`SUCCESS`, never `INVALID`/`ERROR`/`FAILED`) and absent/empty top-level `error` field.
    if !ntype.is_empty() && !ntype.eq_ignore_ascii_case("GENERIC") {
        return None;
    }
    let ns = nxt
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if !ns.is_empty()
        && !(ns.eq_ignore_ascii_case("DONE")
            || ns.eq_ignore_ascii_case("OK")
            || ns.eq_ignore_ascii_case("SUCCESS"))
    {
        return None;
    }
    if step_has_nonempty_error_field(nxt) {
        return None;
    }
    let nc = nxt.get("content").and_then(Value::as_str).unwrap_or("");
    let body = strip_generic_timestamp_headers(nc).trim();
    let low = body.to_ascii_lowercase();
    if low.contains("\"iserror\":true")
        || low.contains("\"iserror\": true")
        || low.contains("\"ok\":false")
        || low.contains("\"ok\": false")
        || low.starts_with("error:")
        || low.starts_with("error invalid tool call")
        || low.starts_with("encountered error in step execution")
        || low.starts_with("mcp error")
        || low.starts_with("tool error")
        || low.starts_with("permission denied")
        || low.starts_with("invalid arguments")
    {
        return None;
    }
    let rts = nxt
        .get("created_at")
        .and_then(Value::as_str)
        .map(rio::parse_iso_ts)
        .unwrap_or(0.0);
    let ts = if rts > 0.0 {
        rts
    } else if fallback_ts > 0.0 {
        fallback_ts
    } else {
        1.0
    };
    Some((ts, body.to_string()))
}

fn normalize_artifact_display_path(raw: &str) -> String {
    let stripped = raw.trim().trim_start_matches("file:///").trim();
    if stripped.is_empty() {
        return String::new();
    }
    let mut s = stripped.replace('\\', "/");
    let bytes = s.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        let lower = (bytes[0] as char).to_ascii_lowercase();
        s.replace_range(0..1, &lower.to_string());
    }
    s
}

fn is_valid_screenshot_field_value(raw: &str) -> Option<String> {
    let v = raw
        .trim()
        .trim_matches(|c| matches!(c, '"' | '\'' | '`' | ',' | '}' | ']'))
        .trim();
    if v.is_empty() {
        return None;
    }
    let low = v.to_ascii_lowercase();
    if matches!(
        low.as_str(),
        "none" | "null" | "n/a" | "na" | "false" | "-" | "undefined" | "empty"
    ) {
        return None;
    }
    if low.contains(' ')
        && !(low.contains(".png")
            || low.contains(".webp")
            || low.contains(".jpg")
            || low.contains(".jpeg")
            || low.contains('/')
            || low.contains('\\'))
    {
        return None;
    }
    Some(normalize_artifact_display_path(v))
}

fn extract_browser_host_facts_screenshot(content: &str) -> Option<String> {
    if !content.contains("BROWSER_HOST_FACTS") {
        return None;
    }
    // INVARIANT: Never treat relayed inter-agent `[Message] ... sender=<non-system>` text that merely discusses `BROWSER_HOST_FACTS` in prose as host-injected browser evidence; require a real line-start `BROWSER_HOST_FACTS` block header and a populated screenshot artifact field inside that block.
    if let Some(caps) = non_system_msg_sender_re().captures(content) {
        let sender = caps.get(1).map_or("", |m| m.as_str()).to_ascii_lowercase();
        if !matches!(sender.as_str(), "system" | "host" | "browser" | "browser_host") {
            return None;
        }
    }
    let lines: Vec<&str> = content.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        let t = line.trim();
        let is_header = t == "BROWSER_HOST_FACTS"
            || t == "BROWSER_HOST_FACTS:"
            || t == "<BROWSER_HOST_FACTS>"
            || t == "[BROWSER_HOST_FACTS]"
            || t.starts_with("BROWSER_HOST_FACTS:")
            || t.starts_with("<BROWSER_HOST_FACTS ")
            || t.starts_with("[BROWSER_HOST_FACTS]");
        if !is_header {
            continue;
        }
        // Check inline JSON on the header line (e.g. `BROWSER_HOST_FACTS: {"latest_screenshot": "..."}`)
        if let Some((_, inline_rest)) = t.split_once(':') {
            let trimmed_rest = inline_rest.trim();
            if trimmed_rest.starts_with('{') {
                if let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(trimmed_rest) {
                    for k in ["latest_screenshot", "screenshot_path", "screenshot"] {
                        if let Some(val) = obj.get(k).and_then(Value::as_str) {
                            if let Some(clean) = is_valid_screenshot_field_value(val) {
                                return Some(clean);
                            }
                        }
                    }
                }
            }
        }
        // Scan fields inside this BROWSER_HOST_FACTS block only.
        let mut json_buf = String::new();
        let mut in_json = false;
        for &sub in &lines[idx + 1..] {
            let st = sub.trim();
            if st.eq_ignore_ascii_case("</BROWSER_HOST_FACTS>")
                || st.eq_ignore_ascii_case("</SYSTEM_MESSAGE>")
                || st == "---"
            {
                break;
            }
            if st.is_empty() {
                if in_json {
                    break;
                }
                continue;
            }
            if st.starts_with('{') || in_json {
                in_json = true;
                json_buf.push_str(st);
                if st.ends_with('}') {
                    if let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(&json_buf) {
                        for k in ["latest_screenshot", "screenshot_path", "screenshot"] {
                            if let Some(val) = obj.get(k).and_then(Value::as_str) {
                                if let Some(clean) = is_valid_screenshot_field_value(val) {
                                    return Some(clean);
                                }
                            }
                        }
                    }
                    break;
                }
                continue;
            }
            let cleaned_line = st.trim_start_matches(|c: char| matches!(c, '-' | '*' | ' ' | '\t'));
            if let Some((key, val)) = cleaned_line.split_once(':') {
                let k = key
                    .trim()
                    .trim_matches(|c| matches!(c, '"' | '\'' | '`' | '*'))
                    .to_ascii_lowercase();
                if matches!(
                    k.as_str(),
                    "latest_screenshot"
                        | "latest screenshot"
                        | "screenshot_path"
                        | "screenshot path"
                        | "screenshot"
                ) {
                    if let Some(clean) = is_valid_screenshot_field_value(val) {
                        return Some(clean);
                    }
                }
            }
        }
    }
    None
}

fn is_screenshot_mcp_tool(srv: &str, tool_low: &str) -> bool {
    if !(srv.eq_ignore_ascii_case("playwright") || srv.eq_ignore_ascii_case("chrome-devtools")) {
        return false;
    }
    // INVARIANT: Only accept image-capturing screenshot tools, never text-only accessibility snapshots (`browser_snapshot`/`take_snapshot`) or non-image audits.
    matches!(tool_low, "browser_take_screenshot" | "take_screenshot")
}

fn extract_mcp_screenshot_artifact_path(args: Option<&Value>, resp_body: &str) -> String {
    if let Some(a) = args {
        for key in ["filename", "filePath", "file_path", "path", "output"] {
            if let Some(s) = a.get(key).and_then(Value::as_str).map(str::trim) {
                if !s.is_empty() {
                    return rio::normalize_path(s);
                }
            }
        }
    }
    if let Some(Value::Object(obj)) = extract_json_after_headers(resp_body) {
        for key in ["filePath", "file_path", "path", "filename", "screenshot"] {
            if let Some(s) = obj.get(key).and_then(Value::as_str).map(str::trim) {
                if !s.is_empty() {
                    return rio::normalize_path(s);
                }
            }
        }
    }
    for tok in resp_body.split_whitespace() {
        let clean = tok.trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']' | ',' | ';' | '.'));
        let low = clean.to_ascii_lowercase();
        if low.ends_with(".png") || low.ends_with(".webp") || low.ends_with(".jpg") || low.ends_with(".jpeg") {
            return rio::normalize_path(clean.trim_start_matches("file:///"));
        }
    }
    String::new()
}

#[derive(Debug, Default, Clone)]
struct SwarmWorkerAuthority {
    is_design_name: bool,
    explicit_ro_meta: bool,
    verified_transcript_ro: bool,
    launched_in_steps: bool,
    is_ux: bool,
    is_uiux: bool,
    is_browser_qa: bool,
    tainted_writer: bool,
    cid: String,
    launched_ts: f64,
    read_files: Vec<(String, f64)>,
}

impl SwarmWorkerAuthority {
    fn can_issue_verdict(&self) -> bool {
        !self.tainted_writer
            && self.is_design_name
            && (self.explicit_ro_meta || self.verified_transcript_ro)
    }
}

fn extract_step_subagent_info(step: Option<&Value>) -> (String, String) {
    let Some(st) = step else {
        return (String::new(), String::new());
    };
    let content = st.get("content").and_then(Value::as_str).unwrap_or("");
    if let Some(caps) = cwg_stop::subagent_uri_re().captures(content) {
        let cid = caps.name("cid").map_or("", |m| m.as_str()).to_string();
        let tp = caps
            .name("uri")
            .map(|m| cwg_stop::uri_to_path(m.as_str()))
            .unwrap_or_default();
        return (cid, tp);
    }
    if let Some(caps) = snake_cid_re().captures(content) {
        let cid = caps.name("cid").map_or("", |m| m.as_str()).to_string();
        return (cid, String::new());
    }
    if let Some(Value::Object(obj)) = extract_json_after_headers(content) {
        let cid = obj
            .get("conversationId")
            .or_else(|| obj.get("conversation_id"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let tp = obj
            .get("logAbsoluteUri")
            .and_then(Value::as_str)
            .map(cwg_stop::uri_to_path)
            .unwrap_or_default();
        return (cid, tp);
    }
    (String::new(), String::new())
}

fn register_spawned_swarm_names(
    args: Option<&Value>,
    resp_step: Option<&Value>,
    spawned: &mut HashMap<String, SwarmWorkerAuthority>,
    track_ux: bool,
    eff_step_ts: f64,
) {
    let Some(wname) = args
        .and_then(|a| a.get("name"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return;
    };
    let ws = args
        .and_then(|a| a.get("workspace").or_else(|| a.get("workspace_mode")))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_ascii_lowercase();
    let is_writer_ws = matches!(ws.as_str(), "share" | "branch");
    let (resp_cid, _) = extract_step_subagent_info(resp_step);
    let mut names = Vec::new();
    let tasks_len = args
        .and_then(|a| a.get("tasks"))
        .and_then(Value::as_array)
        .map(|arr| arr.len())
        .unwrap_or(0);
    let n_val = args
        .and_then(|a| a.get("n"))
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize;
    let shard_count = if tasks_len > 0 { tasks_len } else { n_val };
    if shard_count > 1 {
        for k in 1..=shard_count {
            names.push(format!("{}-{}", wname, k));
        }
    } else {
        names.push(wname.to_string());
    }
    // INVARIANT: Never grant Swarm critic authority solely from a worker's name or `workspace: "inherit"`; record launch metadata here and require confirmed `members.json` read-only authority OR an audited non-writing child transcript before accepting verdicts.
    for nm in names {
        let low = nm.to_ascii_lowercase();
        let is_design_name = design_reviewer_name_re().is_match(&nm);
        let (is_ux, is_uiux) = is_ux_and_uiux_role(&nm);
        let is_bqa = !is_writer_ws && browser_qa_worker_name_re().is_match(&nm);
        let ent = spawned.entry(low).or_default();
        if is_writer_ws {
            ent.tainted_writer = true;
        }
        ent.is_design_name = ent.is_design_name || is_design_name;
        ent.is_ux = ent.is_ux || (track_ux && is_ux);
        ent.is_uiux = ent.is_uiux || is_uiux;
        ent.is_browser_qa = ent.is_browser_qa || is_bqa;
        if !resp_cid.is_empty() && ent.cid.is_empty() {
            ent.cid = resp_cid.clone();
        }
        ent.launched_in_steps = true;
        ent.launched_ts = ent.launched_ts.max(eff_step_ts);
    }
}

fn record_design_board_row(
    row: &Value,
    fallback_ts: f64,
    cand_floor_ts: f64,
    spawned_swarm_workers: &HashMap<String, SwarmWorkerAuthority>,
    seen_seqs: &mut HashSet<i64>,
    ev: &mut DesignGateEvidence,
) {
    if let Some(seq) = row.get("seq").and_then(Value::as_i64) {
        if !seen_seqs.insert(seq) {
            return;
        }
    }
    let agent = row
        .get("agent")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if agent.is_empty() || agent.eq_ignore_ascii_case("coordinator") {
        return;
    }
    let Some(auth) = spawned_swarm_workers.get(&agent.to_ascii_lowercase()) else {
        return;
    };
    if !auth.can_issue_verdict() {
        return;
    }
    let rts = row
        .get("time")
        .and_then(Value::as_str)
        .map(rio::parse_iso_ts)
        .unwrap_or(0.0);
    let eff_ts = if rts > 0.0 { rts } else { fallback_ts };
    if eff_ts > 0.0 && eff_ts < cand_floor_ts - cwg_common::TS_EPS {
        return;
    }
    let rtext = row.get("text").and_then(Value::as_str).unwrap_or("");
    if rtext.is_empty() {
        return;
    }
    if auth.is_ux {
        ev.ux_seen = true;
        ev.ux_launched_ts = ev
            .ux_launched_ts
            .max(if eff_ts > 0.0 { eff_ts } else { 1.0 });
    }
    record_design_verdicts(
        rtext,
        eff_ts,
        true,
        auth.is_ux,
        auth.is_uiux,
        &auth.read_files,
        ev,
    );
}

#[allow(clippy::too_many_arguments)]
fn scan_design_tool_calls(
    tcs: &[Value],
    step_idx: usize,
    step_ts: f64,
    following_steps: &[Value],
    track_roles: bool,
    subagent_def_writable: &mut HashMap<String, bool>,
    design_subagent_cids: &mut HashMap<String, (bool, bool, f64, String)>,
    browser_subagent_cids: &mut HashMap<String, String>,
    spawned_swarm_workers: &mut HashMap<String, SwarmWorkerAuthority>,
    board_response_step_indices: &mut HashSet<usize>,
    ev: &mut DesignGateEvidence,
) {
    let eff_step_ts = if step_ts > 0.0 { step_ts } else { 1.0 };
    // Collect consecutive tool-response (`GENERIC`) steps right after this `PLANNER_RESPONSE` step so `pos` aligns with host responses even if unrelated system notifications appear later.
    let generic_resps: Vec<(usize, &Value)> = following_steps
        .iter()
        .enumerate()
        .take_while(|(_, s)| {
            let st_t = s.get("type").and_then(Value::as_str).unwrap_or("");
            st_t.is_empty() || st_t.eq_ignore_ascii_case("GENERIC")
        })
        .collect();

    for (pos, tc) in tcs.iter().enumerate() {
        let resp_entry = generic_resps.get(pos).copied();
        let resp_step = resp_entry.map(|(_, s)| s);
        let tname = tc.get("name").and_then(Value::as_str).unwrap_or("");
        let args = tc.get("arguments").or_else(|| tc.get("args"));
        if tname.eq_ignore_ascii_case("define_subagent") {
            if let Some(nm) = args
                .and_then(|a| a.get("Name").or_else(|| a.get("name")))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let writable = args
                    .and_then(|a| a.get("EnableWriteTools").or_else(|| a.get("enableWriteTools")))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                subagent_def_writable.insert(nm.to_ascii_lowercase(), writable);
            }
            continue;
        }
        if tname.eq_ignore_ascii_case("read_board") || tname.eq_ignore_ascii_case("swarm_wait") {
            if track_roles {
                if let Some((rel_idx, _)) = resp_entry {
                    board_response_step_indices.insert(step_idx + 1 + rel_idx);
                }
            }
            continue;
        }
        if tname.eq_ignore_ascii_case("invoke_subagent") {
            if confirmed_tool_response(resp_step, eff_step_ts).is_none() {
                continue;
            }
            let sub_type = args
                .and_then(|a| a.get("TypeName").or_else(|| a.get("typeName")))
                .and_then(Value::as_str)
                .unwrap_or("");
            let sub_type_low = sub_type.trim().to_ascii_lowercase();
            let role = args
                .and_then(|a| a.get("Role").or_else(|| a.get("role")))
                .and_then(Value::as_str)
                .unwrap_or("");
            let (cid, log_path) = extract_step_subagent_info(resp_step);
            if (sub_type_low == "browser" || role.to_ascii_lowercase().contains("browser"))
                && !cid.is_empty()
            {
                browser_subagent_cids.insert(cid.clone(), log_path.clone());
            }
            let is_verified_ro_subagent = is_builtin_readonly_reviewer_type(&sub_type_low)
                || subagent_def_writable.get(&sub_type_low) == Some(&false);
            if track_roles
                && is_verified_ro_subagent
                && (design_reviewer_name_re().is_match(sub_type)
                    || design_reviewer_name_re().is_match(role))
                && !cid.is_empty()
            {
                let combined = format!("{} {}", sub_type, role);
                let (is_ux, is_uiux) = is_ux_and_uiux_role(&combined);
                design_subagent_cids.insert(cid, (is_ux, is_uiux, eff_step_ts, log_path));
            }
            continue;
        }
        if tname.eq_ignore_ascii_case("swarm") {
            if track_roles {
                let act = args
                    .and_then(|a| a.get("action"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if act.eq_ignore_ascii_case("add")
                    && confirmed_tool_response(resp_step, eff_step_ts).is_some()
                {
                    register_spawned_swarm_names(
                        args,
                        resp_step,
                        spawned_swarm_workers,
                        true,
                        eff_step_ts,
                    );
                }
            }
            continue;
        }
        if tname.eq_ignore_ascii_case("call_mcp_tool") {
            let srv = args
                .and_then(|a| a.get("ServerName").or_else(|| a.get("serverName")))
                .and_then(Value::as_str)
                .unwrap_or("");
            let tool = args
                .and_then(|a| a.get("ToolName").or_else(|| a.get("toolName")))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            if is_screenshot_mcp_tool(srv, &tool) {
                if let Some((ok_ts, resp_body)) = confirmed_tool_response(resp_step, eff_step_ts) {
                    let mcp_args = args.and_then(|a| a.get("Arguments").or_else(|| a.get("arguments")));
                    let art_path = extract_mcp_screenshot_artifact_path(mcp_args, &resp_body);
                    ev.push_screenshot(ScreenshotArtifact {
                        path: art_path,
                        sha256: String::new(),
                        ts: ok_ts,
                        source: format!("mcp:{}:{}", srv.to_ascii_lowercase(), tool),
                    });
                }
            }
        } else {
            let low = tname.to_ascii_lowercase();
            if matches!(low.as_str(), "browser_take_screenshot" | "take_screenshot") {
                if let Some((ok_ts, resp_body)) = confirmed_tool_response(resp_step, eff_step_ts) {
                    let art_path = extract_mcp_screenshot_artifact_path(args, &resp_body);
                    ev.push_screenshot(ScreenshotArtifact {
                        path: art_path,
                        sha256: String::new(),
                        ts: ok_ts,
                        source: format!("tool:{}", low),
                    });
                }
            }
        }
    }
}

fn scan_child_transcript_screenshots(
    sub_tp: &Path,
    child_cid: &str,
    cand_floor_ts: f64,
    image_min_ts: f64,
    base_cwd: &str,
    ev: &mut DesignGateEvidence,
) {
    // INVARIANT: Credit child browser/QA sessions strictly from structural sources: native screenshot tools, host-injected `BROWSER_HOST_FACTS`, or explicit `carbon-stack design-gate record-screenshot` entries — never stdout or prose filename guessing.
    if !child_cid.is_empty() {
        for art in verified_screenshot_artifacts(child_cid, cand_floor_ts, image_min_ts, base_cwd) {
            ev.push_screenshot(art);
        }
    }
    if !sub_tp.is_file() {
        return;
    }
    let child_steps = rio::read_transcript_steps(&sub_tp.to_string_lossy(), 400);
    let mut dummy_defs: HashMap<String, bool> = HashMap::new();
    let mut dummy_design: HashMap<String, (bool, bool, f64, String)> = HashMap::new();
    let mut dummy_browser: HashMap<String, String> = HashMap::new();
    let mut dummy_swarm: HashMap<String, SwarmWorkerAuthority> = HashMap::new();
    let mut dummy_board_idxs: HashSet<usize> = HashSet::new();
    for (idx, st) in child_steps.iter().enumerate() {
        let st_ts = st
            .get("created_at")
            .and_then(Value::as_str)
            .map(rio::parse_iso_ts)
            .unwrap_or(0.0);
        if st_ts > 0.0 && st_ts < cand_floor_ts - cwg_common::TS_EPS {
            continue;
        }
        let st_type = st.get("type").and_then(Value::as_str).unwrap_or("");
        let st_src = st.get("source").and_then(Value::as_str).unwrap_or("");
        let content = st.get("content").and_then(Value::as_str).unwrap_or("");
        if st_type.eq_ignore_ascii_case("SYSTEM_MESSAGE") || st_src.eq_ignore_ascii_case("SYSTEM") {
            if let Some(shot_path) = extract_browser_host_facts_screenshot(content) {
                ev.push_screenshot(ScreenshotArtifact {
                    path: shot_path,
                    sha256: String::new(),
                    ts: if st_ts > 0.0 { st_ts } else { 1.0 },
                    source: "browser_host_facts".to_string(),
                });
            }
        }
        let st_status = st.get("status").and_then(Value::as_str).unwrap_or("");
        if !st_status.eq_ignore_ascii_case("ERROR") && !st_status.eq_ignore_ascii_case("INVALID") {
            if let Some(tcs) = st.get("tool_calls").and_then(Value::as_array) {
                scan_design_tool_calls(
                    tcs,
                    idx,
                    st_ts,
                    &child_steps[idx + 1..],
                    false,
                    &mut dummy_defs,
                    &mut dummy_design,
                    &mut dummy_browser,
                    &mut dummy_swarm,
                    &mut dummy_board_idxs,
                    ev,
                );
            }
        }
    }
}

pub fn scan_design_gate_evidence(
    marker: &Value,
    steps: &[Value],
    transcript_path: Option<&str>,
    cand_floor_ts: f64,
    image_min_ts: f64,
    base_cwd: &str,
) -> DesignGateEvidence {
    let mut ev = DesignGateEvidence::default();
    let sess = marker.get("session").and_then(Value::as_str).unwrap_or("");

    // 1. Structured CLI evidence (`carbon-stack design-gate record-screenshot`), re-verified on disk.
    for art in verified_screenshot_artifacts(sess, cand_floor_ts, image_min_ts, base_cwd) {
        ev.push_screenshot(art);
    }

    let mut subagent_def_writable: HashMap<String, bool> = HashMap::new();
    let mut design_subagent_cids: HashMap<String, (bool, bool, f64, String)> = HashMap::new();
    let mut browser_subagent_cids: HashMap<String, String> = HashMap::new();
    let mut spawned_swarm_workers: HashMap<String, SwarmWorkerAuthority> = HashMap::new();
    let mut board_response_step_indices: HashSet<usize> = HashSet::new();
    let mut pending_board_rows: Vec<(Value, f64)> = Vec::new();
    let mut pending_subagent_verdicts: Vec<(String, String, f64)> = Vec::new();
    let mut seen_board_seqs: HashSet<i64> = HashSet::new();

    for (idx, st) in steps.iter().enumerate() {
        let st_ts = st
            .get("created_at")
            .and_then(Value::as_str)
            .map(rio::parse_iso_ts)
            .unwrap_or(0.0);
        if st_ts > 0.0 && st_ts < cand_floor_ts - cwg_common::TS_EPS {
            continue;
        }
        let content = st.get("content").and_then(Value::as_str).unwrap_or("");
        let st_type = st.get("type").and_then(Value::as_str).unwrap_or("");
        let st_src = st.get("source").and_then(Value::as_str).unwrap_or("");
        // INVARIANT: Credit `BROWSER_HOST_FACTS` strictly from structured host-injected `SYSTEM_MESSAGE` / `SYSTEM` blocks carrying a populated screenshot artifact field, never from model prose or inter-agent briefs.
        if st_type.eq_ignore_ascii_case("SYSTEM_MESSAGE") || st_src.eq_ignore_ascii_case("SYSTEM") {
            if let Some(shot_path) = extract_browser_host_facts_screenshot(content) {
                ev.push_screenshot(ScreenshotArtifact {
                    path: shot_path,
                    sha256: String::new(),
                    ts: if st_ts > 0.0 { st_ts } else { 1.0 },
                    source: "browser_host_facts".to_string(),
                });
            }
        }
        let st_status = st.get("status").and_then(Value::as_str).unwrap_or("");
        if !st_status.eq_ignore_ascii_case("ERROR") && !st_status.eq_ignore_ascii_case("INVALID") {
            if let Some(tcs) = st.get("tool_calls").and_then(Value::as_array) {
                scan_design_tool_calls(
                    tcs,
                    idx,
                    st_ts,
                    &steps[idx + 1..],
                    true,
                    &mut subagent_def_writable,
                    &mut design_subagent_cids,
                    &mut browser_subagent_cids,
                    &mut spawned_swarm_workers,
                    &mut board_response_step_indices,
                    &mut ev,
                );
            }
        }
        // INVARIANT: Never accept self-review verdicts from main-agent `PLANNER_RESPONSE`, user prompts, or injected `SYSTEM_MESSAGE`; read independent verdicts only from verified `read_board`/`swarm_wait` responses, on-disk Swarm board, or tracked read-only subagent outputs.
        if st_type.eq_ignore_ascii_case("PLANNER_RESPONSE")
            || st_type.eq_ignore_ascii_case("SYSTEM_MESSAGE")
            || st_type.eq_ignore_ascii_case("USER_INPUT")
            || st_src.eq_ignore_ascii_case("MODEL")
            || st_src.eq_ignore_ascii_case("USER_EXPLICIT")
        {
            continue;
        }
        let trimmed = content.trim();
        if trimmed.is_empty() {
            continue;
        }
        if board_response_step_indices.contains(&idx) && trimmed.contains("\"messages\"") {
            if let Some(Value::Object(obj)) = extract_json_after_headers(trimmed) {
                if let Some(Value::Array(msgs)) = obj.get("messages") {
                    for m in msgs {
                        pending_board_rows.push((m.clone(), st_ts));
                    }
                }
            }
            continue;
        }
        let has_design_tag = trimmed.contains("VISUAL_REVIEW_VERDICT")
            || trimmed.contains("UX_REVIEW_VERDICT");
        if !design_subagent_cids.is_empty()
            && (has_design_tag
                || trimmed.contains("VERDICT")
                || st_type.eq_ignore_ascii_case("SUBAGENT_MESSAGE")
                || st_src.eq_ignore_ascii_case("SUBAGENT"))
        {
            if let Some((cid, _)) = design_subagent_cids
                .iter()
                .find(|(cid, _)| trimmed.contains(cid.as_str()))
            {
                pending_subagent_verdicts.push((cid.clone(), trimmed.to_string(), st_ts));
            }
        }
    }

    let brain_root = if !sess.is_empty() {
        let tp_hint = transcript_path.unwrap_or("");
        Some(
            rio::swarm_brain_and_cid(tp_hint, sess)
                .0
                .unwrap_or_else(|| rio::resolve_brain_root("")),
        )
    } else {
        None
    };

    if let Some(ref brain_root) = brain_root {
        let members_map = rio::load_swarm_members(brain_root, sess);
        for (mname, mval) in &members_map {
            let low = mname.trim().to_ascii_lowercase();
            // INVARIANT: Antigravity host `members.json` records workspace isolation in `workspace_mode` (falling back to `workspace`); check BOTH so `"workspace_mode": "share"|"branch"` always disqualifies writers.
            let ws = mval
                .get("workspace_mode")
                .or_else(|| mval.get("workspace"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            let mrole = mval
                .get("role")
                .or_else(|| mval.get("agent_type"))
                .or_else(|| mval.get("type_name"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            let explicit_ro = mval.get("read_only").and_then(Value::as_bool) == Some(true);
            let explicit_writable = mval.get("writable").and_then(Value::as_bool) == Some(true)
                || mval.get("read_only").and_then(Value::as_bool) == Some(false)
                || matches!(ws.as_str(), "share" | "branch")
                || mrole.contains("builder")
                || mrole.contains("author")
                || mrole.contains("implementer");
            let mcid = mval
                .get("conversation_id")
                .or_else(|| mval.get("conversationId"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let m_tp = (!mcid.is_empty()).then(|| rio::member_transcript_path(brain_root, mcid));
            let audit = m_tp
                .as_ref()
                .map(|p| audit_child_transcript(p, base_cwd))
                .unwrap_or_default();
            let created_ts = mval
                .get("created_at")
                .and_then(Value::as_str)
                .map(rio::parse_iso_ts)
                .unwrap_or(0.0);
            let ent = spawned_swarm_workers.entry(low).or_default();
            if !mcid.is_empty() && ent.cid.is_empty() {
                ent.cid = mcid.to_string();
            }
            let effective_member_ts = created_ts.max(audit.max_step_ts);
            if effective_member_ts > 0.0 {
                ent.launched_ts = ent.launched_ts.max(effective_member_ts);
            }
            if !audit.read_files.is_empty() {
                ent.read_files.extend(audit.read_files.iter().cloned());
            }
            let is_design_name = design_reviewer_name_re().is_match(mname);
            let (is_ux, is_uiux) = is_ux_and_uiux_role(&format!("{} {}", mname, mrole));
            ent.is_design_name = ent.is_design_name || is_design_name;
            ent.is_ux = ent.is_ux || is_ux;
            ent.is_uiux = ent.is_uiux || is_uiux;
            if explicit_writable || audit.has_write_activity {
                ent.tainted_writer = true;
                ent.explicit_ro_meta = false;
                ent.verified_transcript_ro = false;
            } else {
                if explicit_ro {
                    ent.explicit_ro_meta = true;
                }
                if audit.verified_complete
                    && !audit.has_write_activity
                    && (ws.is_empty() || ws == "inherit")
                {
                    ent.verified_transcript_ro = true;
                }
                ent.is_browser_qa =
                    ent.is_browser_qa || browser_qa_worker_name_re().is_match(mname);
            }
            if !ent.tainted_writer && ent.is_browser_qa {
                if let Some(ref p) = m_tp {
                    scan_child_transcript_screenshots(
                        p,
                        mcid,
                        cand_floor_ts,
                        image_min_ts,
                        base_cwd,
                        &mut ev,
                    );
                }
            }
        }
        for ent in spawned_swarm_workers.values_mut() {
            if !ent.tainted_writer && !ent.cid.is_empty() {
                let m_tp = rio::member_transcript_path(brain_root, &ent.cid);
                let audit = audit_child_transcript(&m_tp, base_cwd);
                if audit.has_write_activity {
                    ent.tainted_writer = true;
                    ent.explicit_ro_meta = false;
                    ent.verified_transcript_ro = false;
                } else if audit.verified_complete {
                    ent.verified_transcript_ro = true;
                    if ent.read_files.is_empty() {
                        ent.read_files = audit.read_files;
                    }
                }
            }
        }
        for row in cwg_common::read_swarm_board_tail(brain_root, sess) {
            pending_board_rows.push((row, 0.0));
        }
    }

    // INVARIANT: Decouple UX launch obligation from read-only verdict authority, while strictly scoping `members.json` recovery to the current candidate (`launched_ts >= cand_floor_ts` from `swarm add`, `created_at`, or child transcript timestamps — NEVER carrying over timeless `KILLED` members from previously closed candidates).
    for ent in spawned_swarm_workers.values() {
        let belongs_to_candidate = if cand_floor_ts <= 0.0 {
            true
        } else if ent.launched_ts > 0.0 {
            ent.launched_ts >= cand_floor_ts - cwg_common::TS_EPS
        } else {
            ent.launched_in_steps
        };
        if ent.is_design_name && ent.is_ux && belongs_to_candidate {
            ev.ux_seen = true;
            ev.ux_launched_ts = ev
                .ux_launched_ts
                .max(if ent.launched_ts > 0.0 { ent.launched_ts } else { 1.0 });
        }
    }

    for (row, fb_ts) in &pending_board_rows {
        record_design_board_row(
            row,
            *fb_ts,
            cand_floor_ts,
            &spawned_swarm_workers,
            &mut seen_board_seqs,
            &mut ev,
        );
    }

    let mut tainted_subagents: HashSet<String> = HashSet::new();
    let mut subagent_reads: HashMap<String, Vec<(String, f64)>> = HashMap::new();
    for (bcid, blog_path) in &browser_subagent_cids {
        let sub_tp = if !blog_path.is_empty() {
            PathBuf::from(blog_path)
        } else if let Some(ref br) = brain_root {
            rio::member_transcript_path(br, bcid)
        } else {
            PathBuf::new()
        };
        scan_child_transcript_screenshots(
            &sub_tp,
            bcid,
            cand_floor_ts,
            image_min_ts,
            base_cwd,
            &mut ev,
        );
    }
    for (cid, (is_ux, is_uiux, launched_ts, log_path)) in &design_subagent_cids {
        let sub_tp = if !log_path.is_empty() {
            PathBuf::from(log_path)
        } else if let Some(ref br) = brain_root {
            rio::member_transcript_path(br, cid)
        } else {
            PathBuf::new()
        };
        let audit = if !sub_tp.as_os_str().is_empty() {
            audit_child_transcript(&sub_tp, base_cwd)
        } else {
            ChildTranscriptAudit::default()
        };
        if *is_ux {
            ev.ux_seen = true;
            ev.ux_launched_ts = ev.ux_launched_ts.max(*launched_ts);
        }
        if audit.has_write_activity {
            tainted_subagents.insert(cid.clone());
            continue;
        }
        subagent_reads.insert(cid.clone(), audit.read_files.clone());
        if !sub_tp.is_file() {
            continue;
        }
        let sub_tp_str = sub_tp.to_string_lossy();
        let (chunks, _, _) = cwg_stop::extract_subagent_timed_chunks(Some(&sub_tp_str), sess);
        for ch in chunks {
            if ch.ts > 0.0 && ch.ts < cand_floor_ts - cwg_common::TS_EPS {
                continue;
            }
            record_design_verdicts(
                &ch.text,
                ch.ts,
                true,
                *is_ux,
                *is_uiux,
                &audit.read_files,
                &mut ev,
            );
        }
    }

    for (cid, text, st_ts) in &pending_subagent_verdicts {
        if tainted_subagents.contains(cid) {
            continue;
        }
        if let Some((is_ux, is_uiux, _, _)) = design_subagent_cids.get(cid) {
            let reads = subagent_reads.get(cid).map(Vec::as_slice).unwrap_or(&[]);
            record_design_verdicts(text, *st_ts, true, *is_ux, *is_uiux, reads, &mut ev);
        }
    }

    ev
}

fn resolve_session_arg(explicit: Option<&str>, cwd: Option<&str>) -> Result<String, String> {
    if let Some(s) = explicit.map(str::trim).filter(|s| !s.is_empty()) {
        return Ok(s.to_string());
    }
    for var in ["CARBON_STACK_SESSION", "ANTIGRAVITY_CONVERSATION_ID"] {
        if let Ok(v) = env::var(var) {
            let t = v.trim();
            if !t.is_empty() {
                return Ok(t.to_string());
            }
        }
    }
    let eff_cwd = cwd
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| {
            env::current_dir()
                .ok()
                .map(|p| p.to_string_lossy().into_owned())
        })
        .unwrap_or_default();
    let target_root = rio::git_toplevel(&eff_cwd, false).unwrap_or(eff_cwd);
    let markers_dir = cwg_common::gate_dir().join("markers");
    let mut matches: Vec<String> = Vec::new();
    if let Ok(rd) = fs::read_dir(&markers_dir) {
        for ent in rd.flatten() {
            let p = ent.path();
            if p.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Some(m) = rio::read_json(&p) else {
                continue;
            };
            let msess = m
                .get("session")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("");
            if msess.is_empty() {
                continue;
            }
            let mroot = m
                .get("git_root")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .or_else(|| m.get("cwd").and_then(Value::as_str))
                .unwrap_or("");
            if !target_root.is_empty() && !mroot.is_empty() && scope_compatible(&target_root, mroot)
            {
                matches.push(msess.to_string());
            }
        }
    }
    matches.sort();
    matches.dedup();
    if matches.len() == 1 {
        return Ok(matches.remove(0));
    }
    if matches.len() > 1 {
        return Err(format!(
            "multiple active sessions match this repository ({}); pass --session <conversation-id> explicitly",
            matches.join(", ")
        ));
    }
    Err("cannot determine session automatically; pass --session <conversation-id>".to_string())
}

fn print_usage() {
    eprintln!(
        "usage: carbon-stack design-gate <record-screenshot|status|clear> [options]\n\
         \n\
         Subcommands:\n\
           record-screenshot --path <img.png> [--path <img2.png> ...] [--session <id>] [--cwd <dir>] [--viewport <label>] [--theme <label>] [--source <label>]\n\
           status [--session <id>] [--cwd <dir>]\n\
           clear [--session <id>] [--cwd <dir>]"
    );
}

pub fn run_cli(args: &[String]) -> i32 {
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        print_usage();
        return if args.is_empty() { 2 } else { 0 };
    }
    let sub = args[0].as_str();
    let mut session: Option<String> = None;
    let mut cwd: Option<String> = None;
    let mut viewport: Option<String> = None;
    let mut theme: Option<String> = None;
    let mut source: Option<String> = None;
    let mut paths: Vec<String> = Vec::new();

    let mut i = 1usize;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--session" | "-s" => {
                if i + 1 >= args.len() {
                    eprintln!("design-gate: missing value for {}", a);
                    return 2;
                }
                session = Some(args[i + 1].clone());
                i += 2;
            }
            "--cwd" => {
                if i + 1 >= args.len() {
                    eprintln!("design-gate: missing value for --cwd");
                    return 2;
                }
                cwd = Some(args[i + 1].clone());
                i += 2;
            }
            "--path" | "-p" | "--file" => {
                if i + 1 >= args.len() {
                    eprintln!("design-gate: missing value for {}", a);
                    return 2;
                }
                paths.push(args[i + 1].clone());
                i += 2;
            }
            "--viewport" => {
                if i + 1 >= args.len() {
                    eprintln!("design-gate: missing value for --viewport");
                    return 2;
                }
                viewport = Some(args[i + 1].clone());
                i += 2;
            }
            "--theme" => {
                if i + 1 >= args.len() {
                    eprintln!("design-gate: missing value for --theme");
                    return 2;
                }
                theme = Some(args[i + 1].clone());
                i += 2;
            }
            "--source" => {
                if i + 1 >= args.len() {
                    eprintln!("design-gate: missing value for --source");
                    return 2;
                }
                source = Some(args[i + 1].clone());
                i += 2;
            }
            "-h" | "--help" => {
                print_usage();
                return 0;
            }
            other if !other.starts_with('-') => {
                paths.push(other.to_string());
                i += 1;
            }
            other => {
                eprintln!("design-gate: unknown flag '{}'", other);
                return 2;
            }
        }
    }

    match sub {
        "record-screenshot" | "record" => {
            if paths.is_empty() {
                eprintln!("design-gate record-screenshot: at least one --path <image> is required");
                return 2;
            }
            let sess = match resolve_session_arg(session.as_deref(), cwd.as_deref()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{}", json!({"ok": false, "error": e}));
                    return 1;
                }
            };
            let mut recorded = Vec::new();
            for p in &paths {
                match record_screenshot(
                    &sess,
                    p,
                    cwd.as_deref(),
                    viewport.as_deref(),
                    theme.as_deref(),
                    source.as_deref(),
                ) {
                    Ok(rec) => recorded.push(rec),
                    Err(e) => {
                        eprintln!("{}", json!({"ok": false, "session": sess, "error": e}));
                        return 1;
                    }
                }
            }
            println!(
                "{}",
                json!({"ok": true, "session": sess, "count": recorded.len(), "recorded": recorded})
            );
            0
        }
        "status" => {
            let sess = match resolve_session_arg(session.as_deref(), cwd.as_deref()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{}", json!({"ok": false, "error": e}));
                    return 1;
                }
            };
            let ev_path = evidence_path(&sess);
            let doc = rio::read_json(&ev_path).unwrap_or_else(|| json!({"screenshots": []}));
            let items = doc
                .get("screenshots")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let mut status_items = Vec::new();
            for item in items {
                let p = item.get("path").and_then(Value::as_str).unwrap_or("");
                let sha = item.get("sha256").and_then(Value::as_str).unwrap_or("");
                let (valid, reason) = match inspect_image_file(Path::new(p)) {
                    Ok((live_sha, _, _)) if live_sha == sha => (true, "ok".to_string()),
                    Ok(_) => (false, "sha256_mismatch".to_string()),
                    Err(e) => (false, e),
                };
                status_items.push(json!({
                    "path": p,
                    "viewport": item.get("viewport").and_then(Value::as_str).unwrap_or(""),
                    "theme": item.get("theme").and_then(Value::as_str).unwrap_or(""),
                    "source": item.get("source").and_then(Value::as_str).unwrap_or(""),
                    "recorded_ts": item.get("recorded_ts").and_then(Value::as_f64).unwrap_or(0.0),
                    "mtime": item.get("mtime").and_then(Value::as_f64).unwrap_or(0.0),
                    "valid": valid,
                    "reason": reason,
                }));
            }
            println!(
                "{}",
                json!({"ok": true, "session": sess, "count": status_items.len(), "screenshots": status_items})
            );
            0
        }
        "clear" => {
            let sess = match resolve_session_arg(session.as_deref(), cwd.as_deref()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{}", json!({"ok": false, "error": e}));
                    return 1;
                }
            };
            clear_evidence(&sess);
            println!("{}", json!({"ok": true, "session": sess, "cleared": true}));
            0
        }
        other => {
            eprintln!("design-gate: unknown subcommand '{}'", other);
            print_usage();
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(1);

    struct TempHome {
        dir: PathBuf,
        prev_home: Option<String>,
    }

    impl TempHome {
        fn new(tag: &str) -> Self {
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = env::temp_dir().join(format!(
                "carbon-dg-{}-{}-{}",
                tag,
                std::process::id(),
                n
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            let prev_home = env::var("CARBON_STACK_HOME").ok();
            env::set_var("CARBON_STACK_HOME", &dir);
            Self { dir, prev_home }
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            if let Some(ref prev) = self.prev_home {
                env::set_var("CARBON_STACK_HOME", prev);
            } else {
                env::remove_var("CARBON_STACK_HOME");
            }
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn test_record_verify_tamper_staleness_and_cli() {
        let th = TempHome::new("verify");
        let work = th.dir.join("work");
        fs::create_dir_all(&work).unwrap();
        let png = work.join("desktop.png");
        fs::write(&png, b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR").unwrap();
        let webp = work.join("mobile.webp");
        fs::write(&webp, b"RIFF\x24\x00\x00\x00WEBPVP8 ").unwrap();

        let fake = work.join("fake.png");
        fs::write(&fake, b"not an image at all").unwrap();
        assert!(
            record_screenshot("s-dg-1", &fake.to_string_lossy(), None, None, None, None).is_err()
        );

        let before = now_sec() - 2.0;
        let cli_rc = run_cli(&[
            "record-screenshot".to_string(),
            "--session".to_string(),
            "s-dg-1".to_string(),
            "--cwd".to_string(),
            work.to_string_lossy().into_owned(),
            "--path".to_string(),
            "desktop.png".to_string(),
            "--path".to_string(),
            "mobile.webp".to_string(),
            "--viewport".to_string(),
            "desktop+mobile".to_string(),
            "--theme".to_string(),
            "dark".to_string(),
            "--source".to_string(),
            "playwright".to_string(),
        ]);
        assert_eq!(cli_rc, 0, "multi-path CLI record-screenshot must succeed");
        assert_eq!(
            run_cli(&[
                "status".to_string(),
                "--session".to_string(),
                "s-dg-1".to_string()
            ]),
            0
        );

        let ts_ok = verified_screenshot_ts("s-dg-1", before, before, "");
        assert!(ts_ok >= before, "fresh recorded screenshot must verify");

        let future = now_sec() + 30.0;
        assert_eq!(
            verified_screenshot_ts("s-dg-1", before, future, ""),
            0.0,
            "screenshot older than latest visual edit must be rejected"
        );

        // Tampering with both recorded image files invalidates SHA-256 verification.
        fs::write(&png, b"\x89PNG\r\n\x1a\n\x00\x00\x00\rTAMPER").unwrap();
        fs::write(&webp, b"RIFF\x24\x00\x00\x00WEBPTAMP").unwrap();
        assert_eq!(
            verified_screenshot_ts("s-dg-1", before, before, ""),
            0.0,
            "tampered screenshot bytes must be rejected"
        );

        assert_eq!(
            run_cli(&[
                "clear".to_string(),
                "--session".to_string(),
                "s-dg-1".to_string()
            ]),
            0
        );
        assert!(!evidence_path("s-dg-1").exists());
    }

    #[test]
    fn test_host_formats_bhf_invalid_mcp_and_wrapped_subagent() {
        // Finding #1: Wrapped Antigravity invoke_subagent response parses CID + logAbsoluteUri.
        let wrapped_sub = json!({
            "type": "GENERIC",
            "status": "DONE",
            "content": "Created At: 2026-11-21T10:00:00+05:00\nCompleted At: 2026-11-21T10:00:01+05:00\nSubagent launched:\n{\"conversationId\": \"cid-wrap-123\", \"logAbsoluteUri\": \"file:///C:/logs/sub.jsonl\"}"
        });
        let (cid, tp) = extract_step_subagent_info(Some(&wrapped_sub));
        assert_eq!(cid, "cid-wrap-123");
        assert!(tp.replace('\\', "/").ends_with("C:/logs/sub.jsonl"), "tp={}", tp);

        // Finding #2: Prose mentioning `BROWSER_HOST_FACTS` and `.png` in relayed SYSTEM_MESSAGE is rejected; real host block is accepted.
        let prose_sys = "[Message] timestamp=2026-11-16T12:51:06Z sender=26fe700b priority=HIGH content=Verify screenshot desktop.png from `BROWSER_HOST_FACTS`.\nscreenshot: desktop.png";
        assert!(extract_browser_host_facts_screenshot(prose_sys).is_none());
        let summary_sys = "Ensure you compare against `BROWSER_HOST_FACTS` and inspect hero.png";
        assert!(extract_browser_host_facts_screenshot(summary_sys).is_none());
        let real_bhf = "<SYSTEM_MESSAGE>\nBROWSER_HOST_FACTS:\nvisited_origins: http://127.0.0.1:3000\nlatest_screenshot: C:/shots/desktop.png\n</SYSTEM_MESSAGE>";
        assert_eq!(
            extract_browser_host_facts_screenshot(real_bhf).as_deref(),
            Some("c:/shots/desktop.png")
        );
        let empty_bhf = "BROWSER_HOST_FACTS:\nlatest_screenshot: none\n";
        assert!(extract_browser_host_facts_screenshot(empty_bhf).is_none());

        // Finding #3: GENERIC step with status INVALID or top-level error field is rejected.
        let invalid_step = json!({
            "type": "GENERIC",
            "status": "INVALID",
            "error": "invalid arguments: missing filename",
            "content": "Created At: 2026-11-21T10:00:00+05:00\nError invalid tool call"
        });
        assert!(confirmed_tool_response(Some(&invalid_step), 100.0).is_none());
        let err_field_step = json!({
            "type": "GENERIC",
            "status": "DONE",
            "error": "screenshot failed",
            "content": "Created At: 2026-11-21T10:00:00+05:00\nok"
        });
        assert!(confirmed_tool_response(Some(&err_field_step), 100.0).is_none());
        let ok_step = json!({
            "type": "GENERIC",
            "status": "DONE",
            "created_at": "1970-01-01T00:16:51Z",
            "content": "Created At: 2026-11-21T10:00:00+05:00\nCompleted At: 2026-11-21T10:00:01+05:00\nSaved screenshot to shots/home.png"
        });
        assert!(confirmed_tool_response(Some(&ok_step), 100.0).is_some());
    }

    #[test]
    fn test_r2_audit_completeness_exact_binding_and_ux_launch() {
        let th = TempHome::new("r2-strict");

        // Finding #4: Empty transcript fails closed (`verified_complete = false`), corrupt JSONL fails closed, and UNCERTAIN command (`npx prettier --write`) sets `has_write_activity = true`.
        let empty_tp = th.dir.join("empty.jsonl");
        fs::write(&empty_tp, "").unwrap();
        let a_empty = audit_child_transcript(&empty_tp, "");
        assert!(!a_empty.verified_complete, "empty transcript must fail closed");

        let corrupt_tp = th.dir.join("corrupt.jsonl");
        fs::write(&corrupt_tp, "{\"type\":\"USER_INPUT\"}\n{broken json\n").unwrap();
        let a_corrupt = audit_child_transcript(&corrupt_tp, "");
        assert!(!a_corrupt.verified_complete, "corrupt transcript must fail closed");

        let prettier_tp = th.dir.join("prettier.jsonl");
        fs::write(
            &prettier_tp,
            format!(
                "{}\n",
                serde_json::to_string(&json!({
                    "type": "PLANNER_RESPONSE",
                    "created_at": "1970-01-01T00:16:52Z",
                    "tool_calls": [{"name": "run_command", "arguments": {"CommandLine": "npx prettier --write src/App.tsx"}}]
                }))
                .unwrap()
            ),
        )
        .unwrap();
        let a_prettier = audit_child_transcript(&prettier_tp, "");
        assert!(a_prettier.has_write_activity, "UNCERTAIN run_command like npx prettier --write must taint critic");

        // Finding #5: `light/desktop.png` read does NOT satisfy `dark/desktop.png`, and post-verdict `read_file` (read_ts > appr.ts) does NOT retroactively bind.
        let mut ev = DesignGateEvidence::default();
        ev.push_screenshot(ScreenshotArtifact {
            path: "c:/shots/dark/desktop.png".to_string(),
            sha256: "deadbeef12345678".to_string(),
            ts: 1010.0,
            source: "cli".to_string(),
        });
        ev.visual_approved_ts = 1020.0;
        ev.visual_approvals.push(ReviewApproval {
            ts: 1020.0,
            text: "Checked desktop.png\nVISUAL_REVIEW_VERDICT: APPROVED".to_string(),
            read_files: vec![
                ("c:/shots/light/desktop.png".to_string(), 1015.0),
                ("c:/shots/dark/desktop.png".to_string(), 1025.0),
            ],
        });
        assert!(
            ev.check_visual_binding(1005.0).is_err(),
            "wrong-dir basename collision and post-verdict read must both be rejected"
        );
        ev.visual_approvals[0]
            .read_files
            .push(("c:/shots/dark/desktop.png".to_string(), 1018.0));
        assert!(
            ev.check_visual_binding(1005.0).is_ok(),
            "exact-path read within [capture_ts, approval_ts] must bind"
        );

        // Regression fix: launching UX auditor without child transcript yet STILL sets `ux_seen = true`!
        let sess_ux = "dg-ux-inflight";
        let ux_marker = json!({"session": sess_ux, "first_ts": 1000.0});
        let ux_steps = vec![
            json!({
                "type": "PLANNER_RESPONSE",
                "created_at": "1970-01-01T00:16:51Z",
                "tool_calls": [
                    {"name": "swarm", "arguments": {"action": "add", "name": "ux-adversarial-auditor", "workspace": "inherit", "brief": "Audit UX"}}
                ]
            }),
            json!({"type": "GENERIC", "status": "DONE", "created_at": "1970-01-01T00:16:52Z", "content": "spawned"}),
        ];
        let scanned = scan_design_gate_evidence(&ux_marker, &ux_steps, None, 1000.0, 1005.0, "");
        assert!(scanned.ux_seen, "launched UX auditor with pending transcript must set ux_seen=true");
        assert_eq!(scanned.ux_approved_ts, 0.0, "unverified UX auditor must not have ux_approved_ts");

        // R3 #4 & #6: Compact `transcript.jsonl` JSON-escaped args (`read_file` path + `git status` + `tokenade search`) decode cleanly via `rio`, and a writer-tainted UX auditor NEVER clears `ux_seen`.
        let compact_dir = th.dir.join("compact_audit");
        fs::create_dir_all(&compact_dir).unwrap();
        let compact_tp = compact_dir.join("transcript.jsonl");
        let shot_abs = r"C:\shots\dark\desktop.png";
        let compact_steps = format!(
            "{}\n{}\n{}\n{}\n",
            serde_json::to_string(&json!({
                "type": "PLANNER_RESPONSE",
                "created_at": "1970-01-01T00:16:52Z",
                "tool_calls": [
                    {"name": "read_file", "args": {"Path": serde_json::to_string(shot_abs).unwrap()}},
                    {"name": "run_command", "args": {"CommandLine": serde_json::to_string("git status --short").unwrap()}},
                    {"name": "run_command", "args": {"CommandLine": serde_json::to_string("tokenade search \"WCAG contrast\"").unwrap()}}
                ]
            }))
            .unwrap(),
            serde_json::to_string(&json!({"type": "GENERIC", "status": "DONE", "created_at": "1970-01-01T00:16:53Z", "content": "img"})).unwrap(),
            serde_json::to_string(&json!({"type": "GENERIC", "status": "DONE", "created_at": "1970-01-01T00:16:53Z", "content": "clean"})).unwrap(),
            serde_json::to_string(&json!({"type": "GENERIC", "status": "DONE", "created_at": "1970-01-01T00:16:53Z", "content": "results"})).unwrap(),
        );
        fs::write(&compact_tp, compact_steps).unwrap();
        let a_compact = audit_child_transcript(&compact_tp, r"C:\repo");
        assert!(a_compact.verified_complete, "compact transcript must verify complete");
        assert!(!a_compact.has_write_activity, "decoded git status + tokenade search must remain read-only");
        assert!(
            a_compact.read_files.iter().any(|(p, _)| p == "c:/shots/dark/desktop.png"),
            "compact JSON-escaped read_file path must decode cleanly without joining base_cwd: {:?}",
            a_compact.read_files
        );

        let tainted_ux_brain = th.dir.join("tainted_ux_brain");
        let tux_sess = "dg-tainted-ux";
        let tux_parent = rio::member_transcript_path(&tainted_ux_brain, tux_sess);
        fs::create_dir_all(tux_parent.parent().unwrap()).unwrap();
        fs::write(&tux_parent, "").unwrap();
        let tux_sdir = rio::swarm_dir(&tainted_ux_brain, tux_sess);
        fs::create_dir_all(&tux_sdir).unwrap();
        rio::write_json(
            &tux_sdir.join("members.json"),
            &json!({"members": {"ux-adversarial-auditor": {"conversation_id": "cid-tux", "workspace_mode": "inherit", "role": "worker"}}}),
        )
        .unwrap();
        let tux_child = rio::member_transcript_path(&tainted_ux_brain, "cid-tux");
        fs::create_dir_all(tux_child.parent().unwrap()).unwrap();
        fs::write(
            &tux_child,
            format!(
                "{}\n",
                serde_json::to_string(&json!({
                    "type": "PLANNER_RESPONSE",
                    "created_at": "1970-01-01T00:16:52Z",
                    "tool_calls": [{"name": "edit_file", "arguments": {"Path": "App.tsx"}}]
                }))
                .unwrap()
            ),
        )
        .unwrap();
        let tux_marker = json!({"session": tux_sess, "first_ts": 1000.0});
        let tux_scanned = scan_design_gate_evidence(
            &tux_marker,
            &ux_steps,
            Some(&tux_parent.to_string_lossy()),
            1000.0,
            1005.0,
            "",
        );
        assert!(tux_scanned.ux_seen, "tainted UX auditor must STILL keep ux_seen=true so gate cannot skip UX obligation");
        assert_eq!(tux_scanned.ux_approved_ts, 0.0, "tainted UX auditor must NOT credit ux_approved_ts");

        // Even when `swarm add` rolled outside the transcript window (`steps = &[]`), `members.json` recovery STILL preserves `ux_seen=true` for a tainted UX auditor active in the CURRENT candidate (`max_step_ts=1012 >= cand_floor=1000`), while a PRIOR closed candidate (`cand_floor=2000 > max_step_ts=1012`) or timeless KILLED relic does NOT bleed `ux_seen` into the next candidate!
        let tux_rolled_off = scan_design_gate_evidence(
            &tux_marker,
            &[],
            Some(&tux_parent.to_string_lossy()),
            1000.0,
            1005.0,
            "",
        );
        assert!(tux_rolled_off.ux_seen, "tainted UX auditor active in current candidate after tail rollover must STILL keep ux_seen=true");
        assert_eq!(tux_rolled_off.ux_approved_ts, 0.0);

        let next_cand_marker = json!({"session": tux_sess, "first_ts": 2000.0});
        let next_cand_scanned = scan_design_gate_evidence(
            &next_cand_marker,
            &[],
            Some(&tux_parent.to_string_lossy()),
            2000.0,
            2005.0,
            "",
        );
        assert!(
            !next_cand_scanned.ux_seen,
            "prior closed candidate's KILLED UX auditor in members.json without created_at must NOT bleed ux_seen into a new candidate"
        );
    }
}
