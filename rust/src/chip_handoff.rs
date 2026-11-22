use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::chip_hooks;
use crate::rio;
use crate::win32_sqlite;
use crate::worktree_guard;

static SHORT_ID_SEQ: AtomicU64 = AtomicU64::new(1);

fn slug_non_alnum_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[^a-z0-9]+").expect("slug_non_alnum_re"))
}

fn eprintln_line(msg: &str) {
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(msg.as_bytes());
    let _ = err.write_all(b"\n");
    let _ = err.flush();
}

fn abs_clean_path(raw: &str) -> PathBuf {
    if raw.trim().is_empty() {
        rio::resolve_abs_path(Path::new("."))
    } else {
        rio::resolve_abs_path(Path::new(raw))
    }
}

fn gen_short_hex() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = SHORT_ID_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let mut hasher = Sha256::new();
    hasher.update(nanos.to_le_bytes());
    hasher.update(pid.to_le_bytes());
    hasher.update(seq.to_le_bytes());
    let full = hex::encode(hasher.finalize());
    full[..8].to_string()
}

fn translit_char(c: char) -> &'static str {
    match c {
        'а' => "a",
        'б' => "b",
        'в' => "v",
        'г' => "g",
        'д' => "d",
        'е' | 'ё' | 'э' => "e",
        'ж' => "zh",
        'з' => "z",
        'и' => "i",
        'й' | 'ы' => "y",
        'к' => "k",
        'л' => "l",
        'м' => "m",
        'н' => "n",
        'о' => "o",
        'п' => "p",
        'р' => "r",
        'с' => "s",
        'т' => "t",
        'у' => "u",
        'ф' => "f",
        'х' => "kh",
        'ц' => "ts",
        'ч' => "ch",
        'ш' => "sh",
        'щ' => "shch",
        'ъ' | 'ь' => "",
        'ю' => "yu",
        'я' => "ya",
        _ => "",
    }
}

pub fn chip_trees_dir() -> PathBuf {
    let dir = rio::state_dir().join("chips").join("trees");
    let _ = fs::create_dir_all(&dir);
    dir
}

pub fn chip_bundles_dir() -> PathBuf {
    let dir = rio::state_dir().join("chips").join("bundles");
    let _ = fs::create_dir_all(&dir);
    dir
}

pub fn chip_lock_path() -> PathBuf {
    chip_hooks::chip_lock_path()
}

pub fn card_path(chip_id: &str) -> PathBuf {
    chip_hooks::card_path(chip_id)
}

pub fn slugify(title: &str) -> String {
    let src = if title.is_empty() { "task" } else { title };
    let low = src.to_lowercase();
    let mut translit = String::with_capacity(low.len());
    for ch in low.chars() {
        let mapped = translit_char(ch);
        if !mapped.is_empty() {
            translit.push_str(mapped);
        } else if ch != 'ъ' && ch != 'ь' {
            translit.push(ch);
        }
    }
    let replaced = slug_non_alnum_re().replace_all(&translit, "-");
    let trimmed = replaced.trim_matches('-');
    let truncated: String = trimmed.chars().take(28).collect();
    let base = if truncated.is_empty() {
        "task".to_string()
    } else {
        truncated
    };
    base.trim_end_matches('-').to_string()
}

pub fn load_all_cards() -> Vec<Value> {
    chip_hooks::load_all_cards()
}

pub fn find_card_for_cwd(cwd: &str) -> Option<Value> {
    chip_hooks::find_card_for_cwd(cwd)
}

fn val_str(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string()
}

pub fn open_chip(
    title: &str,
    cwd: &str,
    parent_session: &str,
    expected_result: &str,
    operational: bool,
) -> Result<Value, String> {
    let work_cwd_pb = abs_clean_path(cwd);
    let work_cwd = work_cwd_pb.to_string_lossy().into_owned();
    let slug = slugify(title);
    let short = gen_short_hex();
    let chip_id = format!("chip-{}-{}", slug, short);
    let now = win32_sqlite::now_sec();

    let git_root = rio::git_toplevel(&work_cwd, false);
    let code_mode = git_root.is_some() && !operational;

    let title_clean = title.trim().to_string();
    let exp_clean = if expected_result.trim().is_empty() {
        "Проверенный коммит в ветке чипа и краткий отчёт через carbon-stack chip-handoff finish".to_string()
    } else {
        expected_result.trim().to_string()
    };
    let parent_sess_clean = if parent_session.trim().is_empty() {
        String::new()
    } else {
        rio::safe_key(parent_session, "")
    };
    let parent_cwd_norm = rio::normalize_path(&work_cwd);
    let repo_root_norm = git_root
        .as_deref()
        .map(rio::normalize_path)
        .unwrap_or_default();

    let mut parent_branch = String::new();
    let mut base_sha = String::new();
    let mut chip_branch = String::new();
    let mut wt_norm = String::new();

    if code_mode {
        if let Some(ref gr) = git_root {
            let (rc_b, br_out, _) =
                rio::run_git(gr, &["symbolic-ref", "-q", "--short", "HEAD"], 3.0);
            if rc_b == 0 {
                parent_branch = br_out.trim().to_string();
            }
            let (rc_h, sha_out, err_h) = rio::run_git(gr, &["rev-parse", "--verify", "HEAD"], 3.0);
            if rc_h != 0 || sha_out.trim().is_empty() {
                return Err(format!(
                    "Cannot cut chip worktree from unborn HEAD: {}",
                    err_h.trim()
                ));
            }
            base_sha = sha_out.trim().to_string();
            chip_branch = format!("chip/{}-{}", slug, short);
            let wt_path = chip_trees_dir().join(&chip_id);
            let wt_str = wt_path.to_string_lossy().into_owned();
            let (rc_wt, _, err_wt) = rio::run_git(
                gr,
                &["worktree", "add", "-b", &chip_branch, &wt_str, &base_sha],
                15.0,
            );
            if rc_wt != 0 {
                return Err(format!("git worktree add failed: {}", err_wt.trim()));
            }
            wt_norm = rio::normalize_path(&wt_str);
        }
    }

    let mut record = json!({
        "chip_id": chip_id,
        "title": title_clean,
        "expected_result": exp_clean,
        "mode": if code_mode { "code" } else { "operational" },
        "status": "open",
        "parent_session": parent_sess_clean,
        "parent_cwd": parent_cwd_norm,
        "repo_root": repo_root_norm,
        "parent_branch": parent_branch,
        "base_sha": base_sha,
        "chip_branch": chip_branch,
        "worktree": wt_norm,
        "created_ts": now,
        "updated_ts": now,
        "parent_notified": false,
        "stop_reminders": 0,
    });

    let write_res = rio::with_file_lock(&chip_lock_path(), 5.0, 30.0, |acquired| {
        if !acquired {
            return Err("Timed out acquiring chip lock.".to_string());
        }
        rio::write_json(&card_path(&chip_id), &record)
    });
    write_res?;

    let cs_bin = rio::normalize_path(&rio::carbon_stack_bin_path().to_string_lossy());
    let work_dir = if !wt_norm.is_empty() {
        wt_norm.as_str()
    } else {
        parent_cwd_norm.as_str()
    };
    let brief = format!(
        "[Chip Handoff: {}]\n- Задача: {}\n- Рабочая директория: {}\n- Ожидаемый результат: {}\n- По завершении закоммитьте изменения (для code-чипа) и выполните:\n  & \"{}\" chip-handoff finish --chip \"{}\" --message \"<итог и выполненные проверки>\"",
        chip_id, title_clean, work_dir, exp_clean, cs_bin, chip_id
    );
    if let Some(obj) = record.as_object_mut() {
        obj.insert("handoff_brief".to_string(), Value::String(brief));
    }
    Ok(record)
}

pub fn finish_chip(chip_id: &str, message: &str, cwd: &str) -> Result<Value, String> {
    let work_cwd = abs_clean_path(cwd).to_string_lossy().into_owned();
    rio::with_file_lock(&chip_lock_path(), 5.0, 30.0, |acquired| {
        if !acquired {
            return Err("Timed out acquiring chip lock.".to_string());
        }
        let mut card = if !chip_id.trim().is_empty() {
            rio::read_json(&card_path(chip_id))
        } else {
            find_card_for_cwd(&work_cwd)
        }
        .filter(|v| v.is_object())
        .ok_or_else(|| {
            "Chip card not found. Pass `--chip <chip_id>` or run from inside the chip worktree."
                .to_string()
        })?;

        let cid = val_str(&card, "chip_id");
        let mode = val_str(&card, "mode");
        let wt = val_str(&card, "worktree");
        let mut head_sha = val_str(&card, "head_sha");

        if mode == "code" && !wt.is_empty() && Path::new(&wt).is_dir() {
            let (rc_st, st_out, _) = rio::run_git(&wt, &["status", "--porcelain=v1"], 5.0);
            if rc_st == 0 && !st_out.trim().is_empty() {
                return Err(
                    "Chip worktree still has uncommitted files. Commit your verified changes (or clean scratch files) before calling `finish`.".to_string(),
                );
            }
            let (rc_tip, tip_out, _) = rio::run_git(&wt, &["rev-parse", "--verify", "HEAD"], 3.0);
            let tip_sha = if rc_tip == 0 {
                tip_out.trim().to_string()
            } else {
                String::new()
            };
            head_sha = tip_sha.clone();
            if let Some(obj) = card.as_object_mut() {
                obj.insert("head_sha".to_string(), Value::String(tip_sha.clone()));
            }

            // INVARIANT: Create portable git bundle backup when chip branch has commits beyond base_sha (must pass ref name or HEAD, not raw tip SHA).
            let base_sha = val_str(&card, "base_sha");
            if !tip_sha.is_empty() && !base_sha.is_empty() && tip_sha != base_sha {
                let bundle_file = chip_bundles_dir().join(format!("{}.bundle", cid));
                let bundle_str = bundle_file.to_string_lossy().into_owned();
                let chip_branch_ref = val_str(&card, "chip_branch");
                let pos_ref = if chip_branch_ref.is_empty() {
                    "HEAD"
                } else {
                    chip_branch_ref.as_str()
                };
                let rev_range = format!("{}..{}", base_sha, pos_ref);
                let _ = rio::run_git(&wt, &["bundle", "create", &bundle_str, &rev_range], 10.0);
                if bundle_file.is_file() {
                    if let Some(obj) = card.as_object_mut() {
                        obj.insert(
                            "bundle_path".to_string(),
                            Value::String(rio::normalize_path(&bundle_str)),
                        );
                    }
                }
            }
        }

        let summary = if message.trim().is_empty() {
            "Completed chip task".to_string()
        } else {
            message.trim().to_string()
        };
        let now = win32_sqlite::now_sec();
        if let Some(obj) = card.as_object_mut() {
            obj.insert("status".to_string(), Value::String("handed-off".to_string()));
            obj.insert("summary".to_string(), Value::String(summary));
            obj.insert("finished_ts".to_string(), json!(now));
            obj.insert("updated_ts".to_string(), json!(now));
            obj.insert("parent_notified".to_string(), Value::Bool(false));
        }
        rio::write_json(&card_path(&cid), &card)?;
        Ok(json!({
            "ok": true,
            "chip_id": cid,
            "status": "handed-off",
            "head_sha": head_sha,
        }))
    })
}

pub fn close_chip(
    chip_id: &str,
    accept: bool,
    rework_note: &str,
    merge_into_parent: bool,
) -> Result<Value, String> {
    rio::with_file_lock(&chip_lock_path(), 5.0, 30.0, |acquired| {
        if !acquired {
            return Err("Timed out acquiring chip lock.".to_string());
        }
        let cp = card_path(chip_id);
        let mut card = rio::read_json(&cp)
            .filter(|v| v.is_object())
            .ok_or_else(|| format!("Chip '{}' not found.", chip_id))?;

        let now = win32_sqlite::now_sec();
        if !accept {
            let note = rework_note.trim().to_string();
            if let Some(obj) = card.as_object_mut() {
                obj.insert("status".to_string(), Value::String("rework".to_string()));
                obj.insert("rework_note".to_string(), Value::String(note.clone()));
                obj.insert("updated_ts".to_string(), json!(now));
                obj.insert("stop_reminders".to_string(), json!(0));
            }
            rio::write_json(&cp, &card)?;
            return Ok(json!({
                "ok": true,
                "chip_id": chip_id,
                "status": "rework",
                "rework_note": note,
            }));
        }

        let mut merged = false;
        let repo_root = val_str(&card, "repo_root");
        let chip_branch = val_str(&card, "chip_branch");
        if merge_into_parent
            && !repo_root.is_empty()
            && !chip_branch.is_empty()
            && Path::new(&repo_root).is_dir()
        {
            let (rc_m, _, err_m) =
                rio::run_git(&repo_root, &["merge", "--no-edit", &chip_branch], 15.0);
            if rc_m != 0 {
                return Err(format!(
                    "Merge into parent checkout failed: {}",
                    err_m.trim()
                ));
            }
            merged = true;
        }

        let mut cleanup_info = json!({});
        let wt = val_str(&card, "worktree");
        if !wt.is_empty() && Path::new(&wt).exists() {
            cleanup_info = worktree_guard::safe_remove_worktree(&wt, &repo_root, true);
        }

        if let Some(obj) = card.as_object_mut() {
            obj.insert("status".to_string(), Value::String("accepted".to_string()));
            obj.insert("accepted_ts".to_string(), json!(now));
            obj.insert("updated_ts".to_string(), json!(now));
            obj.insert("merged".to_string(), Value::Bool(merged));
            obj.insert("cleanup".to_string(), cleanup_info.clone());
        }
        rio::write_json(&cp, &card)?;
        Ok(json!({
            "ok": true,
            "chip_id": chip_id,
            "status": "accepted",
            "merged": merged,
            "cleanup": cleanup_info,
        }))
    })
}

pub fn recover_chips(parent_session: &str) -> Value {
    let mut items: Vec<Value> = Vec::new();
    let sess_key = if parent_session.is_empty() {
        String::new()
    } else {
        rio::safe_key(parent_session, "default")
    };

    for card in load_all_cards() {
        if val_str(&card, "status") == "accepted" {
            continue;
        }
        let card_sess = val_str(&card, "parent_session");
        if !sess_key.is_empty() && !card_sess.is_empty() && card_sess != sess_key {
            continue;
        }
        let wt = val_str(&card, "worktree");
        let mut wt_state = "no_worktree";
        let mut ahead_commits: i64 = 0;
        let mut dirty_files: usize = 0;
        if !wt.is_empty() && Path::new(&wt).is_dir() {
            wt_state = "present";
            let (rc_s, st_out, _) = rio::run_git(&wt, &["status", "--porcelain=v1"], 4.0);
            if rc_s == 0 {
                dirty_files = st_out.lines().filter(|ln| !ln.trim().is_empty()).count();
            }
            let base = val_str(&card, "base_sha");
            if !base.is_empty() {
                let rev_range = format!("{}..HEAD", base);
                let (rc_c, cnt_out, _) =
                    rio::run_git(&wt, &["rev-list", "--count", &rev_range], 4.0);
                if rc_c == 0 {
                    if let Ok(n) = cnt_out.trim().parse::<i64>() {
                        ahead_commits = n;
                    }
                }
            }
        } else if !wt.is_empty() {
            wt_state = "missing_on_disk";
        }

        items.push(json!({
            "chip_id": val_str(&card, "chip_id"),
            "title": card.get("title").cloned().unwrap_or(Value::Null),
            "status": card.get("status").cloned().unwrap_or(Value::Null),
            "mode": card.get("mode").cloned().unwrap_or(Value::Null),
            "worktree_state": wt_state,
            "ahead_commits": ahead_commits,
            "dirty_files": dirty_files,
            "chip_branch": val_str(&card, "chip_branch"),
            "bundle_path": val_str(&card, "bundle_path"),
            "summary": val_str(&card, "summary"),
        }));
    }

    json!({
        "ok": true,
        "active_count": items.len(),
        "chips": items,
    })
}

pub fn status_chips(parent_session: &str, include_all: bool) -> Value {
    let mut cards = load_all_cards();
    if !include_all {
        cards.retain(|c| val_str(c, "status") != "accepted");
    }
    if !parent_session.is_empty() {
        let sk = rio::safe_key(parent_session, "default");
        cards.retain(|c| val_str(c, "parent_session") == sk);
    }
    json!({
        "count": cards.len(),
        "chips": cards,
    })
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
        eprintln_line("usage: chip_handoff <open|finish|close|status|recover> [options]");
        return 2;
    }
    match args[0].as_str() {
        "-h" | "--help" => {
            eprintln_line("usage: chip_handoff <open|finish|close|status|recover> [options]");
            0
        }
        "open" => {
            let mut title: Option<String> = None;
            let mut expected = String::new();
            let mut session = String::new();
            let mut cwd = String::new();
            let mut operational = false;
            let mut i = 1usize;
            while i < args.len() {
                let a = args[i].as_str();
                if a == "--operational" {
                    operational = true;
                } else if a == "--title" || a.starts_with("--title=") {
                    match take_flag_value(args, &mut i, "--title") {
                        Ok(v) => title = Some(v),
                        Err(e) => {
                            eprintln_line(&format!("chip_handoff open: {}", e));
                            return 2;
                        }
                    }
                } else if a == "--expected" || a.starts_with("--expected=") {
                    match take_flag_value(args, &mut i, "--expected") {
                        Ok(v) => expected = v,
                        Err(e) => {
                            eprintln_line(&format!("chip_handoff open: {}", e));
                            return 2;
                        }
                    }
                } else if a == "--session" || a.starts_with("--session=") {
                    match take_flag_value(args, &mut i, "--session") {
                        Ok(v) => session = v,
                        Err(e) => {
                            eprintln_line(&format!("chip_handoff open: {}", e));
                            return 2;
                        }
                    }
                } else if a == "--cwd" || a.starts_with("--cwd=") {
                    match take_flag_value(args, &mut i, "--cwd") {
                        Ok(v) => cwd = v,
                        Err(e) => {
                            eprintln_line(&format!("chip_handoff open: {}", e));
                            return 2;
                        }
                    }
                } else {
                    eprintln_line(&format!("chip_handoff open: unrecognized argument {}", a));
                    return 2;
                }
                i += 1;
            }
            let Some(ttl) = title else {
                eprintln_line("chip_handoff open: --title is required");
                return 2;
            };
            match open_chip(&ttl, &cwd, &session, &expected, operational) {
                Ok(res) => {
                    rio::print_cli_json(&res, true);
                    0
                }
                Err(err) => {
                    eprintln_line(&format!("[chip_handoff] {}", err));
                    2
                }
            }
        }
        "finish" => {
            let mut chip = String::new();
            let mut message: Option<String> = None;
            let mut cwd = String::new();
            let mut i = 1usize;
            while i < args.len() {
                let a = args[i].as_str();
                if a == "--chip" || a.starts_with("--chip=") {
                    match take_flag_value(args, &mut i, "--chip") {
                        Ok(v) => chip = v,
                        Err(e) => {
                            eprintln_line(&format!("chip_handoff finish: {}", e));
                            return 2;
                        }
                    }
                } else if a == "--message" || a.starts_with("--message=") {
                    match take_flag_value(args, &mut i, "--message") {
                        Ok(v) => message = Some(v),
                        Err(e) => {
                            eprintln_line(&format!("chip_handoff finish: {}", e));
                            return 2;
                        }
                    }
                } else if a == "--cwd" || a.starts_with("--cwd=") {
                    match take_flag_value(args, &mut i, "--cwd") {
                        Ok(v) => cwd = v,
                        Err(e) => {
                            eprintln_line(&format!("chip_handoff finish: {}", e));
                            return 2;
                        }
                    }
                } else {
                    eprintln_line(&format!("chip_handoff finish: unrecognized argument {}", a));
                    return 2;
                }
                i += 1;
            }
            let Some(msg) = message else {
                eprintln_line("chip_handoff finish: --message is required");
                return 2;
            };
            match finish_chip(&chip, &msg, &cwd) {
                Ok(res) => {
                    rio::print_cli_json(&res, true);
                    0
                }
                Err(err) => {
                    eprintln_line(&format!("[chip_handoff] {}", err));
                    2
                }
            }
        }
        "close" => {
            let mut chip: Option<String> = None;
            let mut accept = false;
            let mut rework: Option<String> = None;
            let mut merge = false;
            let mut i = 1usize;
            while i < args.len() {
                let a = args[i].as_str();
                if a == "--accept" {
                    accept = true;
                } else if a == "--merge" {
                    merge = true;
                } else if a == "--chip" || a.starts_with("--chip=") {
                    match take_flag_value(args, &mut i, "--chip") {
                        Ok(v) => chip = Some(v),
                        Err(e) => {
                            eprintln_line(&format!("chip_handoff close: {}", e));
                            return 2;
                        }
                    }
                } else if a == "--rework" || a.starts_with("--rework=") {
                    match take_flag_value(args, &mut i, "--rework") {
                        Ok(v) => rework = Some(v),
                        Err(e) => {
                            eprintln_line(&format!("chip_handoff close: {}", e));
                            return 2;
                        }
                    }
                } else {
                    eprintln_line(&format!("chip_handoff close: unrecognized argument {}", a));
                    return 2;
                }
                i += 1;
            }
            let Some(cid) = chip else {
                eprintln_line("chip_handoff close: --chip is required");
                return 2;
            };
            if accept && rework.is_some() {
                eprintln_line("chip_handoff close: --rework not allowed with --accept");
                return 2;
            }
            if !accept && rework.is_none() {
                eprintln_line("chip_handoff close: one of --accept or --rework is required");
                return 2;
            }
            let rework_note = rework.unwrap_or_default();
            match close_chip(&cid, accept, &rework_note, merge) {
                Ok(res) => {
                    rio::print_cli_json(&res, true);
                    0
                }
                Err(err) => {
                    eprintln_line(&format!("[chip_handoff] {}", err));
                    2
                }
            }
        }
        "status" => {
            let mut session = String::new();
            let mut include_all = false;
            let mut i = 1usize;
            while i < args.len() {
                let a = args[i].as_str();
                if a == "--all" {
                    include_all = true;
                } else if a == "--session" || a.starts_with("--session=") {
                    match take_flag_value(args, &mut i, "--session") {
                        Ok(v) => session = v,
                        Err(e) => {
                            eprintln_line(&format!("chip_handoff status: {}", e));
                            return 2;
                        }
                    }
                } else {
                    eprintln_line(&format!("chip_handoff status: unrecognized argument {}", a));
                    return 2;
                }
                i += 1;
            }
            rio::print_cli_json(&status_chips(&session, include_all), true);
            0
        }
        "recover" => {
            let mut session = String::new();
            let mut i = 1usize;
            while i < args.len() {
                let a = args[i].as_str();
                if a == "--session" || a.starts_with("--session=") {
                    match take_flag_value(args, &mut i, "--session") {
                        Ok(v) => session = v,
                        Err(e) => {
                            eprintln_line(&format!("chip_handoff recover: {}", e));
                            return 2;
                        }
                    }
                } else {
                    eprintln_line(&format!("chip_handoff recover: unrecognized argument {}", a));
                    return 2;
                }
                i += 1;
            }
            rio::print_cli_json(&recover_chips(&session), true);
            0
        }
        other => {
            eprintln_line(&format!("chip_handoff: unknown subcommand '{}'", other));
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
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
        assert!(slug_non_alnum_re().is_match("hello world!"));
        assert_eq!(slugify("Починить Auth & RBAC (v2)"), "pochinit-auth-rbac-v2");
        assert_eq!(slugify(""), "task");
    }

    #[test]
    fn test_chip_spawn_status_sync_close_and_list() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let base = make_temp_dir("chip-handoff-test");
        let stack_home = base.join("stack");
        let repo = base.join("repo");
        fs::create_dir_all(&stack_home).unwrap();
        fs::create_dir_all(&repo).unwrap();
        let prev = env::var_os("CARBON_STACK_HOME");
        env::set_var("CARBON_STACK_HOME", &stack_home);

        let repo_s = repo.to_string_lossy().into_owned();
        let (rc_init, _, _) = rio::run_git(&repo_s, &["init"], 5.0);
        if rc_init == 0 {
            let _ = rio::run_git(&repo_s, &["config", "user.email", "t@example.com"], 5.0);
            let _ = rio::run_git(&repo_s, &["config", "user.name", "Test"], 5.0);
            fs::write(repo.join("README.md"), "base\n").unwrap();
            let _ = rio::run_git(&repo_s, &["add", "README.md"], 5.0);
            let _ = rio::run_git(&repo_s, &["commit", "-m", "init"], 5.0);

            // INVARIANT: Spawn isolated code chip and verify worktree + branch + status listing.
            let opened = open_chip(
                "Фикс очереди",
                &repo_s,
                "sess-parent-1",
                "Verified commit",
                false,
            )
            .unwrap();
            let cid = opened["chip_id"].as_str().unwrap().to_string();
            assert_eq!(opened["mode"], json!("code"));
            assert_eq!(opened["status"], json!("open"));
            let wt = opened["worktree"].as_str().unwrap().to_string();
            assert!(Path::new(&wt).is_dir());

            let listed = status_chips("sess-parent-1", false);
            assert_eq!(listed["count"], json!(1));

            // INVARIANT: Uncommitted dirty files block `finish_chip` until committed.
            fs::write(Path::new(&wt).join("feature.txt"), "chip change\n").unwrap();
            let dirty_err = finish_chip("", "done", &wt).unwrap_err();
            assert!(dirty_err.contains("uncommitted files"));

            let _ = rio::run_git(&wt, &["add", "feature.txt"], 5.0);
            let _ = rio::run_git(&wt, &["commit", "-m", "chip feature"], 5.0);

            let rec = recover_chips("sess-parent-1");
            assert_eq!(rec["active_count"], json!(1));
            assert_eq!(rec["chips"][0]["ahead_commits"], json!(1));
            assert_eq!(rec["chips"][0]["dirty_files"], json!(0));

            let finished = finish_chip("", "feature committed", &wt).unwrap();
            assert_eq!(finished["ok"], json!(true));
            assert_eq!(finished["status"], json!("handed-off"));
            let card_after_fin = rio::read_json(&card_path(&cid)).unwrap();
            let bundle_p = card_after_fin["bundle_path"].as_str().unwrap();
            assert!(Path::new(bundle_p).is_file());

            let rework = close_chip(&cid, false, "add unit test", false).unwrap();
            assert_eq!(rework["status"], json!("rework"));
            assert_eq!(rework["rework_note"], json!("add unit test"));

            let accepted = close_chip(&cid, true, "", true).unwrap();
            assert_eq!(accepted["ok"], json!(true));
            assert_eq!(accepted["status"], json!("accepted"));
            assert_eq!(accepted["merged"], json!(true));
            assert!(!Path::new(&wt).exists());
            assert!(repo.join("feature.txt").is_file());

            assert_eq!(status_chips("sess-parent-1", false)["count"], json!(0));
            assert_eq!(status_chips("sess-parent-1", true)["count"], json!(1));
        }

        // INVARIANT: Operational chip works without a git repo and supports CLI status/recover/close.
        let op_dir = base.join("ops");
        fs::create_dir_all(&op_dir).unwrap();
        let op_s = op_dir.to_string_lossy().into_owned();
        let op = open_chip("Operational check", &op_s, "sess-ops", "", true).unwrap();
        let op_id = op["chip_id"].as_str().unwrap().to_string();
        assert_eq!(op["mode"], json!("operational"));
        assert_eq!(
            run_cli(&[
                "finish".to_string(),
                "--chip".to_string(),
                op_id.clone(),
                "--message=ops complete".to_string(),
            ]),
            0
        );
        assert_eq!(run_cli(&["status".to_string(), "--session=sess-ops".to_string()]), 0);
        assert_eq!(run_cli(&["recover".to_string(), "--session=sess-ops".to_string()]), 0);
        assert_eq!(
            run_cli(&["close".to_string(), format!("--chip={}", op_id), "--accept".to_string()]),
            0
        );
        assert_eq!(run_cli(&["close".to_string(), format!("--chip={}", op_id)]), 2);

        match prev {
            Some(v) => env::set_var("CARBON_STACK_HOME", v),
            None => env::remove_var("CARBON_STACK_HOME"),
        }
        let _ = fs::remove_dir_all(&base);
    }
}
