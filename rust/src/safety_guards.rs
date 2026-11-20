use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::codex_lane::{
    find_codex_binary, required_review_timeout, DEFAULT_REVIEW_TIMEOUT_SECONDS,
    DEFAULT_XHIGH_REVIEW_TIMEOUT_SECONDS, MAX_REVIEW_TIMEOUT_SECONDS, NATIVE_REVIEWERS,
    REVIEW_BOOL_FLAGS, REVIEW_VAL_FLAGS,
};
use crate::cwg_common;
use crate::cwg_mark::{
    classify_shell_command, extract_ps_redirections, extract_ps_subexprs,
    fold_ps_line_continuations, nav_segment_re, ps_tokens, split_shell_segments, strip_quoted,
    strip_single_quoted,
};
use crate::rio::{self, json_truthy, resolve_command_cwd, val_to_i64, val_to_str};

const COPY_VERBS: &[&str] = &["copy-item", "cpi", "copy", "cp"];
const MOVE_VERBS: &[&str] = &["move-item", "mi", "move", "mv", "rename-item", "rni", "ren"];
const DELETE_OR_WRITE_VERBS: &[&str] = &[
    "remove-item",
    "ri",
    "rm",
    "del",
    "erase",
    "rmdir",
    "rd",
    "new-item",
    "ni",
    "touch",
    "set-content",
    "sc",
    "add-content",
    "ac",
    "out-file",
    "tee-object",
    "tee",
];

const PS_PATH_FLAGS: &[&str] = &["-path", "-p", "-literalpath", "-lp", "-filepath"];
const PS_DEST_FLAGS: &[&str] = &["-destination", "-dest", "-destinationpath"];
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
    "-width",
];

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

const READONLY_SWARM_CTL_SUBCMDS: &[(&str, &str)] = &[
    ("ownership", "verify-git-diff"),
    ("worktree", "status"),
    ("board", "summary"),
];

fn hydrogen_policy_msg() -> String {
    format!(
        "[Model Policy Guard] Модели Gemini Flash отключены. Используйте `Gemini 4 Hydrogen` с уровнем размышления по сложности задачи: `{}` (атомарный smoke-check, <=150 строк перевода), `{}` (стандартный UI/перевод/разведка), `{}` (сложные многошаговые сценарии и спецификации) или `{}` (тяжёлая отладка состояний и гонок).",
        cwg_common::HYDROGEN_LOW_MODEL,
        cwg_common::HYDROGEN_MEDIUM_MODEL,
        cwg_common::HYDROGEN_HIGH_MODEL,
        cwg_common::HYDROGEN_XHIGH_MODEL,
    )
}

fn bare_worktree_remove_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\bgit(?:\.exe)?\s+(?:[^\n;|&]*\s+)?worktree\s+remove\b")
            .expect("bare_worktree_remove_re")
    })
}

fn destructive_git_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\bgit(?:\.exe)?\s+(?:[^\n;|&]*\s+)?(?:reset\s+--hard|checkout\s+--\s+\.|restore\s+(?:--staged\s+--worktree\s+|--worktree\s+)?\.|clean\s+-[a-zA-Z]*f[a-zA-Z]*)",
        )
        .expect("destructive_git_re")
    })
}

fn cmd_backtick_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"`([A-Za-z0-9_-])").expect("cmd_backtick_re"))
}

fn swarm_tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)<swarm_worker>\s*You are\s+([A-Za-z0-9._-]+)").expect("swarm_tag_re")
    })
}

fn nested_subexpr_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\$\(|\&\(|\@\(|`|\b(?:Invoke-Expression|iex)\b")
            .expect("nested_subexpr_re")
    })
}

fn blocked_swarm_ctl_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\bswarm[-_]ctl(?:\.py)?\b[^\n;|&]*\b(?:ownership|worktree)\b")
            .expect("blocked_swarm_ctl_re")
    })
}

fn abspath_lexical(p: &Path) -> PathBuf {
    rio::resolve_abs_path(p)
}

fn abspath_lexical_str(raw: &str) -> String {
    abspath_lexical(Path::new(raw)).to_string_lossy().into_owned()
}

fn tok_basename_lower(tok: &str) -> String {
    let clean = tok.replace('\\', "/");
    clean
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_lowercase()
}

fn is_coordinator_role(name: &str) -> bool {
    let low = name.trim().to_lowercase();
    rio::COORDINATOR_ROLE_NAMES.contains(&low.as_str())
}

fn strip_cmd_backticks(text: &str) -> String {
    // SAFETY: Normalize PowerShell backtick-escaped command tokens in `norm_cmd` while `stripped` preserves literal paths.
    if !text.contains('`') {
        return text.to_string();
    }
    cmd_backtick_re().replace_all(text, "$1").into_owned()
}

fn codex_breaker_tripped() -> bool {
    json_truthy(crate::codex_lane::breaker_status().get("tripped"))
}

fn active_thread_state(session: &str, git_root: &str) -> Option<Map<String, Value>> {
    crate::codex_lane::active_thread_state(session, git_root, None)
}

fn pending_research_mode_deny(session: &str, cwd: &str, transcript_path: &str) -> Option<String> {
    if session.is_empty() || session == "unknown" {
        return None;
    }
    let git_root = rio::git_toplevel(cwd, false).unwrap_or_else(|| cwd.to_string());
    let (blocked_n, _, blocked_ids) =
        crate::codex_lane::active_cycle_closure_blocks(session, &git_root, transcript_path);
    if blocked_n < cwg_common::MAX_CLOSURE_PASSES_PER_CYCLE {
        return None;
    }
    let ids_note = if blocked_ids.is_empty() {
        format!("{}", blocked_n)
    } else {
        blocked_ids.join(", ")
    };
    let cwd_q = crate::codex_lane::quote_cli_arg(&git_root);
    let sess_q = crate::codex_lane::quote_cli_arg(session);
    // INVARIANT: Hard-stop review and simplify loops after 2 `CLOSURE_VALIDATION: BLOCKED` passes until Research Mode + `research-reset` completes.
    Some(format!(
        "[Gate Research Mode Required] Достигнут лимит 2 блокировок эскалации (`CLOSURE_VALIDATION: BLOCKED`: {}). Продолжение ревью или линз simplify в текущем цикле запрещено. Перейдите в режим исследования: изучите через доступные плагины и интернет актуальную документацию, рекомендации и лучшие практики по блокирующей проблеме (`search_web`, `tokenade search/web`, `Context7`, `Developer Knowledge` / `Gemini Docs`, субагент `research`), выберите сценарий (`refactor` или `refine`), завершите ожидающих воркеров через `swarm(action='kill', ...)` и выполните `carbon-stack codex-lane research-reset --cwd {} --session {} --decision <refactor|refine> --findings '...'`, чтобы обнулить раунды и начать новый цикл в чистых сессиях.",
        ids_note, cwd_q, sess_q
    ))
}

fn pending_post_block_simplify_deny(
    session: &str,
    cwd: &str,
    transcript_path: &str,
    min_risk_override: &str,
) -> Option<String> {
    if session.is_empty() || session == "unknown" {
        return None;
    }
    let git_root = rio::git_toplevel(cwd, false).unwrap_or_else(|| cwd.to_string());
    let cls_summary = crate::codex_lane::active_cycle_closure_summary_with_risk(
        session,
        &git_root,
        transcript_path,
        min_risk_override,
    );
    if cls_summary.effective_pass_count >= cwg_common::MAX_CLOSURE_PASSES_PER_CYCLE {
        if cls_summary.has_fresh_ready {
            return Some(
                "[Sandwich Gate Policy] Для кандидата уже выполнены оба прохода `--closure` (2/2) с валидным вердиктом `CLOSURE_VALIDATION: READY`: третий проход `--closure` запрещён, закрывайте гейт."
                    .to_string(),
            );
        }
        let cwd_q = crate::codex_lane::quote_cli_arg(&git_root);
        let sess_q = crate::codex_lane::quote_cli_arg(session);
        return Some(format!(
            "[Gate Research Mode Required] В текущем цикле уже израсходован лимит проходов `--closure` ({0}/{0}). Перейдите в режим исследования и выполните `carbon-stack codex-lane research-reset --cwd {1} --session {2} --decision <refactor|refine> --findings '...'`.",
            cwg_common::MAX_CLOSURE_PASSES_PER_CYCLE,
            cwd_q,
            sess_q
        ));
    }
    let blocked_n = cls_summary.blocked_count;
    let last_blk_ts = cls_summary.last_blocked_ts;
    if blocked_n < 1 || blocked_n >= cwg_common::MAX_CLOSURE_PASSES_PER_CYCLE || last_blk_ts <= 0.0 {
        return None;
    }
    let skey = rio::safe_key(session, "default");
    let mdata = cwg_common::read_marker_with_pending(&skey)?;
    if !mdata.is_object() || json_truthy(mdata.get("closed")) {
        return None;
    }
    if crate::cwg_stop::has_completed_simplify_after(session, &mdata, transcript_path, last_blk_ts) {
        return None;
    }
    // INVARIANT: Block launching closure pass 2/2 after pass 1 `BLOCKED` before a fresh simplify pass completes.
    Some(
        "[Sandwich Gate Policy] Проход эскалации 1/2 вернул `CLOSURE_VALIDATION: BLOCKED`: перед запуском финального прохода 2/2 (`--closure`) обязательно выполните свежий проход линз `simplify` на текущем кандидате."
            .to_string(),
    )
}

fn extract_codex_review_cmd_opts(cmd_str: &str) -> Vec<HashMap<String, String>> {
    let mut found: Vec<HashMap<String, String>> = Vec::new();
    let folded = fold_ps_line_continuations(cmd_str);
    for (_, seg_str) in split_shell_segments(&folded, false) {
        let seg = ps_tokens(&seg_str);
        for (idx, tok) in seg.iter().enumerate() {
            let base = tok_basename_lower(tok);
            let rem_start = if base == "codex_lane.py" {
                if idx + 1 >= seg.len() || !seg[idx + 1].eq_ignore_ascii_case("review") {
                    continue;
                }
                idx + 2
            } else if base == "carbon-stack" || base == "carbon-stack.exe" {
                if idx + 2 >= seg.len()
                    || !(seg[idx + 1].eq_ignore_ascii_case("codex-lane")
                        || seg[idx + 1].eq_ignore_ascii_case("codex_lane"))
                    || !seg[idx + 2].eq_ignore_ascii_case("review")
                {
                    continue;
                }
                idx + 3
            } else {
                continue;
            };
            let mut opts: HashMap<String, String> = HashMap::new();
            let rem = &seg[rem_start..];
            let mut j = 0usize;
            while j < rem.len() {
                let rtok = &rem[j];
                let low_rtok = rtok.to_lowercase();
                if REVIEW_BOOL_FLAGS.contains(&low_rtok.as_str()) {
                    opts.insert(low_rtok, "1".to_string());
                    j += 1;
                    continue;
                }
                let (opt, has_sep, inline_val) = match rtok.split_once('=') {
                    Some((a, b)) => (a, true, b),
                    None => (rtok.as_str(), false, ""),
                };
                let low_opt = opt.to_lowercase();
                if REVIEW_VAL_FLAGS.contains(&low_opt.as_str()) {
                    let raw_val = if has_sep {
                        j += 1;
                        inline_val.to_string()
                    } else if j + 1 < rem.len() && !rem[j + 1].starts_with("--") {
                        let v = rem[j + 1].clone();
                        j += 2;
                        v
                    } else {
                        j += 1;
                        String::new()
                    };
                    if let Some(base_opt) = low_opt.strip_suffix("-hex") {
                        if let Ok(decoded) = crate::codex_lane::decode_utf8_hex(&raw_val) {
                            opts.insert(base_opt.to_string(), decoded);
                        }
                    } else {
                        opts.insert(low_opt, raw_val);
                    }
                    continue;
                }
                j += 1;
            }
            found.push(opts);
        }
    }
    found
}

fn check_codex_review_timeout_policy(
    norm_cmd: &str,
    stripped: &str,
    cwd: &str,
    session: &str,
) -> (String, Option<String>) {
    let low_cmd = norm_cmd.to_lowercase();
    if !(low_cmd.contains("codex_lane") || low_cmd.contains("codex-lane"))
        || !low_cmd.contains("review")
    {
        return ("allow".to_string(), None);
    }
    let mut invocations = extract_codex_review_cmd_opts(norm_cmd);
    if invocations.is_empty() {
        invocations = extract_codex_review_cmd_opts(stripped);
    }
    if invocations.is_empty() {
        return ("allow".to_string(), None);
    }
    let base_cwd = resolve_command_cwd(stripped, cwd, "");
    for parsed_opts in &invocations {
        let raw_cwd_opt = parsed_opts.get("--cwd").map(|s| s.trim()).unwrap_or("");
        let eff_cwd = if !raw_cwd_opt.is_empty() {
            let p = Path::new(raw_cwd_opt);
            if p.is_absolute() {
                abspath_lexical(p).to_string_lossy().into_owned()
            } else {
                abspath_lexical(&Path::new(&base_cwd).join(p))
                    .to_string_lossy()
                    .into_owned()
            }
        } else {
            base_cwd.clone()
        };
        let git_root = rio::git_toplevel(&eff_cwd, false).unwrap_or_else(|| eff_cwd.clone());

        let raw_sess_opt = parsed_opts
            .get("--session")
            .map(|s| s.trim())
            .unwrap_or("");
        let eff_session = if !raw_sess_opt.is_empty() {
            raw_sess_opt
        } else if session != "unknown" {
            session
        } else {
            ""
        };
        if let Some(rm_deny) = pending_research_mode_deny(eff_session, &eff_cwd, "") {
            return ("deny".to_string(), Some(rm_deny));
        }
        let is_cls_opt = parsed_opts.contains_key("--closure")
            || parsed_opts
                .get("--phase")
                .map_or(false, |p| p.trim().eq_ignore_ascii_case("closure"));
        if is_cls_opt {
            let req_risk = if parsed_opts
                .get("--xhigh")
                .map_or(false, |s| !s.is_empty())
            {
                "XHIGH"
            } else {
                ""
            };
            if let Some(sim_deny) =
                pending_post_block_simplify_deny(eff_session, &eff_cwd, "", req_risk)
            {
                return ("deny".to_string(), Some(sim_deny));
            }
        }
        let raw_resume = parsed_opts.get("--resume").map(|s| s.trim()).unwrap_or("");
        if !raw_resume.is_empty() && !eff_session.is_empty() {
            let last_rr_ts = cwg_common::read_marker_with_pending(eff_session)
                .filter(|m| !json_truthy(m.get("closed")))
                .map(|m| cwg_common::last_research_reset_ts(&m))
                .unwrap_or(0.0);
            let cand_ts = crate::codex_lane::candidate_first_ts(eff_session);
            if last_rr_ts > 0.0
                && !crate::codex_lane::is_post_reset_codex_session_proven(
                    raw_resume, "", last_rr_ts, cand_ts,
                )
            {
                return (
                    "deny".to_string(),
                    Some(format!(
                        "[Gate Fresh Session Policy] Возобновление до-исследовательской сессии Codex (`--resume {}`) после `research-reset` запрещено: уберите `--resume`, чтобы новый цикл стартовал в чистой сессии ревью.",
                        raw_resume
                    )),
                );
            }
        }
        let Some(raw_to_s) = parsed_opts.get("--timeout") else {
            continue;
        };
        let raw_to = raw_to_s.trim();
        let has_new_sess = parsed_opts
            .get("--new-session")
            .map_or(false, |s| !s.is_empty());
        let is_xhigh = parsed_opts
            .get("--xhigh")
            .map_or(false, |s| !s.is_empty());
        let req_effort = if is_xhigh { "xhigh" } else { "high" };
        let req_model = crate::codex_lane::resolve_review_model(
            parsed_opts.get("--model").map(|s| s.as_str()).unwrap_or(""),
            is_xhigh,
        );
        let tstate = if has_new_sess {
            None
        } else {
            crate::codex_lane::active_thread_state_for_lane(
                eff_session,
                &git_root,
                None,
                &req_model,
                req_effort,
            )
        };
        let is_closure = parsed_opts.contains_key("--closure")
            || parsed_opts
                .get("--phase")
                .map_or(false, |p| p.trim().eq_ignore_ascii_case("closure"));
        let retry_cmd =
            crate::codex_lane::format_review_retry_cmd_phase(&req_model, is_xhigh, is_closure);

        // INVARIANT: Forbid custom upfront `--timeout` on `carbon-stack codex-lane review`; standard defaults are 600s (HIGH) and 900s (XHIGH).
        let pending_resume = tstate
            .as_ref()
            .map_or(false, |ts| json_truthy(ts.get("pending_timeout_resume")));
        if !pending_resume {
            return (
                "deny".to_string(),
                Some(format!(
                    "[Codex Timeout Policy] Запрещено передавать свой `--timeout` заранее при вызове `carbon-stack codex-lane review`: штатный таймаут уже составляет 10 минут (`{}s`) для `HIGH` и 15 минут (`{}s`) для `--xhigh`. Запустите `{}` без флага `--timeout`.",
                    DEFAULT_REVIEW_TIMEOUT_SECONDS, DEFAULT_XHIGH_REVIEW_TIMEOUT_SECONDS, retry_cmd
                )),
            );
        }

        let saved_next = tstate
            .as_ref()
            .map_or(0, |ts| val_to_i64(ts.get("next_timeout_seconds")));
        let req_min = required_review_timeout(is_xhigh, saved_next);
        let parsed_to = if !raw_to.is_empty() && raw_to.bytes().all(|b| b.is_ascii_digit()) {
            raw_to.parse::<i64>().ok()
        } else {
            None
        };
        if parsed_to.map_or(true, |v| v < req_min) {
            return (
                "deny".to_string(),
                Some(format!(
                    "[Codex Timeout Policy] После незавершённого таймаута Codex нельзя занижать `--timeout` до `{}s` (требуется `>= {}s`). Уберите флаг `--timeout` — `{}` автоматически продолжит сохранённую сессию с таймаутом `{}s` без потери раунда.",
                    raw_to, req_min, retry_cmd, req_min
                )),
            );
        }
        if parsed_to.unwrap_or(0) > MAX_REVIEW_TIMEOUT_SECONDS {
            return (
                "deny".to_string(),
                Some(format!(
                    "[Codex Timeout Policy] Значение `--timeout {}` превышает потолок `{}s`. Уберите флаг `--timeout` для автоматического продолжения сессии.",
                    raw_to, MAX_REVIEW_TIMEOUT_SECONDS
                )),
            );
        }
    }
    ("allow".to_string(), None)
}

pub fn guard_shell_command_with_session(
    cmd: &str,
    cwd: &str,
    session: &str,
) -> (String, Option<String>) {
    let stripped = rio::unwrap_tokenade_command(cmd);
    if stripped.is_empty() {
        return ("allow".to_string(), None);
    }
    let norm_cmd = strip_cmd_backticks(&stripped);

    let (to_dec, to_reason) = check_codex_review_timeout_policy(&norm_cmd, &stripped, cwd, session);
    if to_dec != "allow" {
        return (to_dec, to_reason);
    }

    let low_norm_cmd = norm_cmd.to_lowercase();
    if bare_worktree_remove_re().is_match(&norm_cmd)
        && !low_norm_cmd.contains("worktree_guard")
        && !low_norm_cmd.contains("worktree-guard")
    {
        let cs_bin = rio::normalize_path(&rio::carbon_stack_bin_path().to_string_lossy());
        return (
            "deny".to_string(),
            Some(format!(
                "[Worktree Safety Guard] Прямой вызов `git worktree remove` на Windows опасен (Git рекурсивно обходит NTFS junctions вроде `node_modules`/`.venv` и может удалить файлы основного дерева, а незакоммиченные правки теряются). Используйте безопасную обёртку: `& \"{}\" worktree-guard remove --worktree <path>`.",
                cs_bin
            )),
        );
    }

    if destructive_git_re().is_match(&norm_cmd) {
        let eff_cwd = resolve_command_cwd(&stripped, cwd, "");
        if let Some(git_root) = rio::git_toplevel(&eff_cwd, true) {
            if rio::is_unapproved_home_git_root(&eff_cwd, &git_root)
                && rio::fold_path(&abspath_lexical_str(&eff_cwd)) != rio::fold_path(&git_root)
            {
                return (
                    "deny".to_string(),
                    Some(
                        "[Dirty Worktree Protection] Разрушающая Git-команда запущена во вложенном каталоге без собственного `.git` и поднимется в корневой `$HOME/.git`, что грозит безвозвратной потерей файлов домашнего каталога."
                            .to_string(),
                    ),
                );
            }
            let (rc, st_out, _) = rio::run_git(&git_root, &["status", "--porcelain=v1"], 4.0);
            if (rc == 0 && !st_out.trim().is_empty()) || rc == 124 {
                let cs_bin = rio::normalize_path(&rio::carbon_stack_bin_path().to_string_lossy());
                return (
                    "deny".to_string(),
                    Some(format!(
                        "[Dirty Worktree Protection] Рабочее дерево содержит незакоммиченные изменения, которые будут безвозвратно уничтожены этой командой. Сначала сохраните снимок состояния без изменения индекса: `& \"{}\" worktree-guard snapshot --label before-reset`, либо откатывайте только конкретные собственные хунки.",
                        cs_bin
                    )),
                );
            }
        }
    }

    ("allow".to_string(), None)
}

pub fn guard_shell_command(cmd: &str, cwd: &str) -> (String, Option<String>) {
    guard_shell_command_with_session(cmd, cwd, "")
}

fn is_simplify_swarm_target(name: &str, brief: &str) -> bool {
    if cwg_common::is_simplify_worker_name(name) {
        return true;
    }
    let low_brief = brief.to_lowercase();
    low_brief.contains("simplify_lens:") || low_brief.contains("simplify_verdict:")
}

fn is_adversarial_review_swarm_target(name: &str, model: &str, brief: &str) -> bool {
    if is_simplify_swarm_target(name, brief) {
        return false;
    }
    let low_model = model.trim().to_lowercase();
    if low_model != cwg_common::OPUS_HIGH_MODEL
        && low_model != cwg_common::CARBON_HIGH_MODEL
        && low_model != cwg_common::NEON_XHIGH_MODEL
    {
        return false;
    }
    cwg_common::is_review_worker_hint(name, brief)
}

fn pending_codex_timeout_escalation_deny(
    payload: Option<&Value>,
    target_label: &str,
) -> Option<String> {
    let p = payload?;
    if !p.is_object() {
        return None;
    }
    let session = rio::session_key(p);
    if session.is_empty() || session == "unknown" {
        return None;
    }
    let cwd = rio::effective_cwd(p);
    let git_root = rio::git_toplevel(&cwd, false).unwrap_or(cwd);
    let tstate = active_thread_state(&session, &git_root)?;
    if !json_truthy(tstate.get("pending_timeout_resume")) {
        return None;
    }
    if codex_breaker_tripped() || find_codex_binary().is_none() {
        return None;
    }
    let next_to_raw = val_to_i64(tstate.get("next_timeout_seconds"));
    let next_to = if next_to_raw > 0 {
        next_to_raw
    } else {
        DEFAULT_XHIGH_REVIEW_TIMEOUT_SECONDS
    };
    let sid_note = tstate
        .get("session_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("auto");
    let retry_note = if json_truthy(tstate.get("legacy_unknown_tier")) {
        "`carbon-stack codex-lane review` (или `carbon-stack codex-lane review --xhigh` для `XHIGH`)"
            .to_string()
    } else {
        let eff = val_to_str(tstate.get("effort"));
        let is_xh = json_truthy(tstate.get("xhigh")) || cwg_common::is_codex_xhigh_effort(&eff);
        let mdl = val_to_str(tstate.get("model"));
        let is_cls = val_to_str(tstate.get("phase")).eq_ignore_ascii_case("closure");
        format!("`{}`", crate::codex_lane::format_review_retry_cmd_phase(&mdl, is_xh, is_cls))
    };
    // INVARIANT: Block switching to internal review after a non-network Codex thinking timeout while Codex remains healthy.
    Some(format!(
        "[Codex Timeout Policy] Переключение на внутреннее ревью (`{}`) после таймаута размышления Codex запрещено: локальный таймаут не является сбоем Codex и не расходует раунд ревью. Повторите вызов {} без флага `--timeout`, чтобы продолжить ту же сессию Codex (`{}`) с увеличенным таймаутом (`{}s`).",
        target_label, retry_note, sid_note, next_to
    ))
}

pub fn guard_swarm_invocation_with_payload(
    args: &Value,
    payload: Option<&Value>,
) -> (String, Option<String>) {
    let action = val_to_str(args.get("action")).trim().to_lowercase();
    if action != "add" && action != "model" {
        return ("allow".to_string(), None);
    }
    let model = val_to_str(args.get("model")).trim().to_string();
    if !model.is_empty() && cwg_common::is_flash_model(&model) {
        return ("deny".to_string(), Some(hydrogen_policy_msg()));
    }
    let name_str = val_to_str(args.get("name"));
    let brief_str = val_to_str(args.get("brief"));
    if is_simplify_swarm_target(&name_str, &brief_str) {
        let low_model = model.to_lowercase();
        if model.is_empty() || !cwg_common::is_simplify_allowed_model(&low_model) {
            // SAFETY: Never allow simplify workers to default to or target Carbon, preserving main-agent quota.
            let model_disp = if model.is_empty() {
                "inherit (Carbon)"
            } else {
                model.as_str()
            };
            return (
                "deny".to_string(),
                Some(format!(
                    "[Simplify Model Policy] Линзы simplify запрещено запускать на `{}`, чтобы не сжигать лимиты `{}`. Используйте `{}`, а при исчерпании квоты/сбое Sonnet — `{}` через `swarm(action='add', ..., model='{}')`.",
                    model_disp,
                    cwg_common::CARBON_HIGH_MODEL,
                    cwg_common::SONNET_HIGH_MODEL,
                    cwg_common::SIMPLIFY_FALLBACK_MODEL,
                    cwg_common::SIMPLIFY_FALLBACK_MODEL,
                )),
            );
        }
    }
    let caller_worker = payload.map(resolve_swarm_worker_identity).unwrap_or_default();
    let is_non_coord_worker = !caller_worker.is_empty() && !is_coordinator_role(&caller_worker);
    let is_simp_target = is_simplify_swarm_target(&name_str, &brief_str);
    let is_rev_target = is_adversarial_review_swarm_target(&name_str, &model, &brief_str);
    if action == "add" && !is_non_coord_worker && (is_simp_target || is_rev_target) {
        if let Some(p) = payload {
            let session = rio::session_key(p);
            let cwd = rio::effective_cwd(p);
            let tp = p.get("transcriptPath").and_then(|v| v.as_str()).unwrap_or("");
            if let Some(rm_deny) = pending_research_mode_deny(&session, &cwd, tp) {
                return ("deny".to_string(), Some(rm_deny));
            }
            let fork_str = val_to_str(args.get("fork")).trim().to_string();
            if !fork_str.is_empty() && !session.is_empty() && session != "unknown" {
                let last_rr_ts = cwg_common::read_marker_with_pending(&session)
                    .filter(|m| !json_truthy(m.get("closed")))
                    .map(|m| cwg_common::last_research_reset_ts(&m))
                    .unwrap_or(0.0);
                if last_rr_ts > 0.0 {
                    return (
                        "deny".to_string(),
                        Some(
                            "[Gate Fresh Session Policy] Создание линзы simplify или ревью через `fork` после `research-reset` запрещено: новый цикл обязан стартовать в чистой сессии без старой истории."
                                .to_string(),
                        ),
                    );
                }
            }
        }
    }
    if action == "add"
        && is_rev_target
        && !is_non_coord_worker
    {
        if brief_str.to_lowercase().contains("closure_validation:") {
            if let Some(p) = payload {
                let s = rio::session_key(p);
                let c = rio::effective_cwd(p);
                let t = p.get("transcriptPath").and_then(|v| v.as_str()).unwrap_or("");
                if let Some(sim_deny) = pending_post_block_simplify_deny(&s, &c, t, "") {
                    return ("deny".to_string(), Some(sim_deny));
                }
            }
        }
        let label = if model.is_empty() {
            name_str.as_str()
        } else {
            model.as_str()
        };
        if let Some(esc_deny) = pending_codex_timeout_escalation_deny(payload, label) {
            return ("deny".to_string(), Some(esc_deny));
        }
    }
    ("allow".to_string(), None)
}

pub fn guard_swarm_invocation(args: &Value) -> (String, Option<String>) {
    guard_swarm_invocation_with_payload(args, None)
}

fn active_constraints(cwd: &str, workspace_paths: &[String], session: &str) -> (String, String) {
    crate::continuity_hook::active_constraints(cwd, workspace_paths, None, session)
}

pub fn guard_subagent_invocation_with_payload(
    payload: &Value,
    args: &Value,
) -> (String, Option<String>, Option<Value>) {
    let transcript_path = payload
        .get("transcriptPath")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let prompt = val_to_str(args.get("Prompt")).trim().to_string();
    let role = val_to_str(args.get("Role")).trim().to_string();
    let req_model = val_to_str(args.get("Model")).trim().to_lowercase();
    let sub_type = val_to_str(args.get("TypeName")).trim().to_lowercase();
    let base_sub_type = sub_type.rsplit(':').next().unwrap_or("");
    let is_simplify_sub = cwg_common::is_simplify_subagent_call(base_sub_type, &role);

    if !req_model.is_empty() && cwg_common::is_flash_model(&req_model) {
        let suffix = if base_sub_type == "browser" {
            "Для `browser` запустите swarm-воркера на `gemini-4-hydrogen-<low|medium|high|xhigh>`, который вызовет `invoke_subagent(TypeName='browser', Model='inherit')` (либо передайте `Model='inherit'` внутри Hydrogen-сессии)."
        } else {
            "Запустите задачу через `swarm(action='add', model='gemini-4-hydrogen-<low|medium|high|xhigh>')` или передайте `Model='inherit'` внутри Hydrogen-сессии."
        };
        return (
            "deny".to_string(),
            Some(format!("{} {}", hydrogen_policy_msg(), suffix)),
            None,
        );
    }

    let steps_head = rio::read_transcript_head(transcript_path, 8);
    let is_delegated = rio::is_subagent_session(transcript_path, Some(&steps_head));
    let conv_id = payload
        .get("conversationId")
        .or_else(|| payload.get("session_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let worker_model = rio::swarm_worker_model(transcript_path, Some(&steps_head), conv_id);
    let is_swarm_worker = worker_model.is_some();

    if !is_swarm_worker && (NATIVE_REVIEWERS.contains(&base_sub_type) || is_simplify_sub) {
        let session = rio::session_key(payload);
        let cwd = rio::effective_cwd(payload);
        if let Some(rm_deny) = pending_research_mode_deny(&session, &cwd, transcript_path) {
            return ("deny".to_string(), Some(rm_deny), None);
        }
    }
    if !is_swarm_worker && NATIVE_REVIEWERS.contains(&base_sub_type) {
        if let Some(esc_deny) = pending_codex_timeout_escalation_deny(Some(payload), base_sub_type) {
            return ("deny".to_string(), Some(esc_deny), None);
        }
    }

    let simplify_fallback_ok = worker_model
        .as_deref()
        .map_or(false, |wm| cwg_common::SIMPLIFY_FALLBACK_MODELS.contains(&wm))
        && (req_model.is_empty() || req_model == "inherit");
    if is_simplify_sub && !simplify_fallback_ok {
        // SAFETY: Direct `invoke_subagent` from the main session inherits its primary model and burns quota; enforce swarm Neon/Hydrogen fallback.
        return (
            "deny".to_string(),
            Some(format!(
                "[Simplify Model Policy] Прямой вызов субагента `{}` из основной сессии наследует `{}` и сжигает квоту основной модели. Запускайте simplify через `swarm(action='add', ..., model='{}')`, а при исчерпании квоты/сбое Sonnet — через `swarm(action='add', ..., model='{}')`.",
                base_sub_type,
                cwg_common::CARBON_HIGH_MODEL,
                cwg_common::SONNET_HIGH_MODEL,
                cwg_common::SIMPLIFY_FALLBACK_MODEL,
            )),
            None,
        );
    }

    let allow_swarm_delegation = is_swarm_worker
        && (req_model.is_empty() || req_model == "inherit")
        && (base_sub_type == "browser" || is_simplify_sub);
    if is_delegated && !allow_swarm_delegation && !prompt.contains("[allow-nested-subagent]") {
        return (
            "deny".to_string(),
            Some(
                "[Subagent Nesting Guard] Вложенный запуск субагента изнутри субагента заблокирован во избежание каскадного размножения контекстов. Завершите свою ограниченную задачу и верните результат родительскому агенту."
                    .to_string(),
            ),
            None,
        );
    }

    if prompt.chars().count() < 16 {
        return (
            "deny".to_string(),
            Some(
                "[Subagent Delegation Guard] Промпт субагента слишком короткий и не содержит границ задачи и ожидаемого результата."
                    .to_string(),
            ),
            None,
        );
    }

    if !prompt.contains("[Canonical Constraints]") {
        let eff_cwd = rio::effective_cwd(payload);
        let wps: Vec<String> = payload
            .get("workspacePaths")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let session = rio::session_key(payload);
        let (active_req, cancelled_req) = active_constraints(&eff_cwd, &wps, &session);
        let mut extra_lines = Vec::new();
        if !active_req.is_empty() {
            extra_lines.push(format!("- Active Requirements: {}", active_req));
        }
        if !cancelled_req.is_empty() {
            extra_lines.push(format!("- Cancelled / Do NOT Reintroduce: {}", cancelled_req));
        }
        if !extra_lines.is_empty() {
            let enriched = format!(
                "{}\n\n[Canonical Constraints]\n{}",
                prompt,
                extra_lines.join("\n")
            );
            return ("allow".to_string(), None, Some(json!({"Prompt": enriched})));
        }
    }

    ("allow".to_string(), None, None)
}

pub fn guard_subagent_invocation(args: &Value) -> (String, Option<String>) {
    let empty_payload = Value::Object(Map::new());
    let (dec, reason, _) = guard_subagent_invocation_with_payload(&empty_payload, args);
    (dec, reason)
}

fn resolve_brain_root_for_payload(payload: &Value) -> PathBuf {
    if let Some(tp) = payload.get("transcriptPath").and_then(|v| v.as_str()) {
        if !tp.is_empty() {
            let p = fs::canonicalize(tp).unwrap_or_else(|_| abspath_lexical(Path::new(tp)));
            let is_sysgen = p
                .ancestors()
                .nth(2)
                .and_then(|a| a.file_name())
                .and_then(|n| n.to_str())
                == Some(".system_generated");
            if is_sysgen {
                if let Some(brain) = p.ancestors().nth(4) {
                    return brain.to_path_buf();
                }
            }
        }
    }
    rio::resolve_brain_root("")
}

fn find_active_worker_name<'a>(
    members: &'a Map<String, Value>,
    worker_cid: &str,
) -> Option<&'a str> {
    for (name, meta) in members {
        if !meta.is_object()
            || rio::is_swarm_member_killed(Some(meta))
            || rio::is_swarm_role_member(name, Some(meta))
        {
            continue;
        }
        let cid = meta
            .get("conversation_id")
            .or_else(|| meta.get("conversationId"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if cid == worker_cid {
            return Some(name.as_str());
        }
    }
    None
}

fn resolve_registered_worker_name(
    brain_root: &Path,
    worker_cid: &str,
    candidate_sessions: &[&str],
    allow_full_scan: bool,
) -> Option<String> {
    if worker_cid.is_empty() {
        return None;
    }
    let mut seen: HashSet<String> = HashSet::new();
    for &sid in candidate_sessions {
        let clean = sid.trim();
        if clean.is_empty() || !seen.insert(clean.to_string()) {
            continue;
        }
        let members = rio::load_swarm_members(brain_root, clean);
        if let Some(wname) = find_active_worker_name(&members, worker_cid) {
            return Some(wname.to_string());
        }
    }
    if !allow_full_scan {
        return None;
    }
    let Ok(entries) = fs::read_dir(brain_root) else {
        return None;
    };
    for ent in entries.flatten() {
        let dir_path = ent.path();
        if !dir_path.is_dir() {
            continue;
        }
        let mf = dir_path
            .join(".system_generated")
            .join("swarm")
            .join("members.json");
        if !mf.is_file() {
            continue;
        }
        let Some(sid) = dir_path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !seen.insert(sid.to_string()) {
            continue;
        }
        let members = rio::load_swarm_members(brain_root, sid);
        if let Some(wname) = find_active_worker_name(&members, worker_cid) {
            return Some(wname.to_string());
        }
    }
    None
}

pub fn resolve_swarm_worker_identity(payload: &Value) -> String {
    let tc = payload.get("toolCall");
    for container in [Some(payload), tc] {
        let Some(obj) = container.and_then(|v| v.as_object()) else {
            continue;
        };
        for key in ["worker_name", "workerName", "agent_name", "agentName"] {
            let val = val_to_str(obj.get(key)).trim().to_string();
            if !val.is_empty() {
                return if is_coordinator_role(&val) {
                    String::new()
                } else {
                    val
                };
            }
        }
    }
    for &key in rio::WORKER_ENV_KEYS {
        if let Ok(val) = env::var(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return if is_coordinator_role(trimmed) {
                    String::new()
                } else {
                    trimmed.to_string()
                };
            }
        }
    }

    let session = rio::session_key(payload);
    let tp = payload
        .get("transcriptPath")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let mut is_user_root = false;
    let mut subagent_parent: Option<String> = None;
    if !tp.is_empty() {
        let head_steps = rio::read_transcript_head(tp, 5);
        for st in head_steps.iter().take(3) {
            if let Some(content) = st.get("content").and_then(|v| v.as_str()) {
                if let Some(caps) = swarm_tag_re().captures(content) {
                    let cand_w = caps[1].trim();
                    return if is_coordinator_role(cand_w) {
                        String::new()
                    } else {
                        cand_w.to_string()
                    };
                }
            }
        }
        if let Some(winfo) = rio::resolve_swarm_worker_assignment(tp, Some(&head_steps), &session) {
            return val_to_str(winfo.get("worker_name"));
        }
        subagent_parent = rio::subagent_parent_id(tp, Some(&head_steps));
        if let Some(s0) = head_steps.first() {
            let stype = s0.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let ssource = s0.get("source").and_then(|v| v.as_str()).unwrap_or("");
            is_user_root = stype == "USER_INPUT" && (ssource == "USER_EXPLICIT" || ssource == "USER");
        }
    }

    let mut raw_id = String::new();
    for container in [Some(payload), tc] {
        let Some(obj) = container.and_then(|v| v.as_object()) else {
            continue;
        };
        for key in ["agent_id", "agentId", "worker_id", "workerId"] {
            let cand = val_to_str(obj.get(key)).trim().to_string();
            if !cand.is_empty() {
                raw_id = cand;
                break;
            }
        }
        if !raw_id.is_empty() {
            break;
        }
    }
    if raw_id.is_empty() {
        raw_id = env::var("AGENT_ID")
            .unwrap_or_default()
            .trim()
            .to_string();
    }

    let brain_root = resolve_brain_root_for_payload(payload);
    let mut lookup_cids: Vec<&str> = Vec::new();
    if !raw_id.is_empty() && raw_id != "unknown" {
        lookup_cids.push(&raw_id);
    }
    if !session.is_empty() && session != "unknown" {
        lookup_cids.push(&session);
    }
    if !lookup_cids.is_empty() && (!raw_id.is_empty() || !is_user_root) {
        let mut cand_coords: Vec<&str> = Vec::new();
        if let Some(ref pid) = subagent_parent {
            cand_coords.push(pid.as_str());
        }
        if !session.is_empty() && session != "unknown" {
            cand_coords.push(session.as_str());
        }
        let allow_full_scan = subagent_parent.is_none();
        for cid in lookup_cids {
            if let Some(wname) =
                resolve_registered_worker_name(&brain_root, cid, &cand_coords, allow_full_scan)
            {
                return wname;
            }
        }
    }
    if is_coordinator_role(&raw_id) {
        String::new()
    } else {
        raw_id
    }
}

fn prior_board_read_in_transcript(tp: &str) -> bool {
    if tp.is_empty() {
        return false;
    }
    for st in rio::read_transcript_steps(tp, 400) {
        let Some(tcs) = st.get("tool_calls").and_then(|v| v.as_array()) else {
            continue;
        };
        for call in tcs {
            if call.get("name").and_then(|v| v.as_str()) == Some("read_board") {
                return true;
            }
        }
    }
    false
}

fn cursor_state_path(session: &str) -> PathBuf {
    let dir = cwg_common::gate_dir().join("board_cursors");
    let _ = fs::create_dir_all(&dir);
    dir.join(format!("{}.json", rio::safe_key(session, "default")))
}

pub fn guard_read_board(
    payload: &Value,
    args: &Value,
    cwd: &str,
) -> (String, Option<String>) {
    let session = rio::session_key(payload);
    let tp = payload
        .get("transcriptPath")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let (_, messages) = cwg_common::load_swarm_board_messages(&session, cwd, tp, None);
    let head_seq = messages
        .iter()
        .filter_map(|m| m.get("_seq").and_then(|v| v.as_i64()))
        .max()
        .unwrap_or(0);

    let raw_since = args
        .get("since")
        .filter(|v| !v.is_null())
        .or_else(|| args.get("after").filter(|v| !v.is_null()))
        .or_else(|| args.get("cursor").filter(|v| !v.is_null()));
    let since_val = val_to_i64(raw_since);

    let cpath = cursor_state_path(&session);
    let state = rio::read_json(&cpath)
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    let mut last_seen = val_to_i64(state.get("last_seen_id"));
    let mut read_count = val_to_i64(state.get("read_count"));

    if read_count == 0 && prior_board_read_in_transcript(tp) {
        read_count = 1;
        if last_seen <= 0 {
            last_seen = if head_seq > 0 {
                head_seq
            } else {
                messages.len() as i64
            };
        }
    }

    if messages.len() > cwg_common::BOARD_CURSOR_THRESHOLD
        && since_val <= 0
        && (read_count > 0 || last_seen > 0)
    {
        let suggested = if last_seen <= 0 {
            last_seen.max(head_seq)
        } else {
            last_seen
        };
        return (
            "deny".to_string(),
            Some(format!(
                "[Swarm Cursor Guard] В `board.jsonl` накопилось {} сообщений (> {}), и доска уже читалась в этой сессии. Повторный `read_board` без курсора раздувает контекст — передайте `since={}` (текущий head=#{}).",
                messages.len(),
                cwg_common::BOARD_CURSOR_THRESHOLD,
                suggested,
                head_seq,
            )),
        );
    }

    let _ = rio::write_json(
        &cpath,
        &json!({
            "session": session,
            "last_seen_id": last_seen.max(head_seq),
            "read_count": read_count + 1,
            "total_messages": messages.len(),
        }),
    );
    ("allow".to_string(), None)
}

fn ownership_target_path(args: &Value) -> String {
    for key in ["Path", "TargetFile", "FilePath", "path", "file_path"] {
        let val = val_to_str(args.get(key)).trim().to_string();
        if !val.is_empty() {
            return val;
        }
    }
    String::new()
}

fn classify_ownership_target(raw_path: &str, repo_root: &str) -> (bool, String, bool) {
    let (rel_opt, in_repo) = cwg_common::resolve_repo_rel_info(raw_path, repo_root);
    let rel = rel_opt.unwrap_or_default();
    // SAFETY: Within `.swarm/`, only worker artifacts (`.swarm/artifacts/**`) are writable by workers; `.swarm/ownership.json` stays protected.
    if rel == ".swarm" || rel.starts_with(".swarm/") {
        return (in_repo, rel.clone(), rel.starts_with(".swarm/artifacts/"));
    }
    let probe_path = if in_repo {
        Path::new(repo_root)
            .join(&rel)
            .to_string_lossy()
            .into_owned()
    } else {
        raw_path.to_string()
    };
    let is_ephemeral = cwg_common::is_scratch_or_ephemeral(&probe_path, "", &[], repo_root);
    (in_repo, rel, is_ephemeral)
}

fn find_ownership_manifest_root(start_dir: &str) -> String {
    let Ok(cur) = fs::canonicalize(start_dir).or_else(|_| Ok::<PathBuf, std::io::Error>(abspath_lexical(Path::new(start_dir)))) else {
        return String::new();
    };
    for d in cur.ancestors() {
        if d.join(".swarm").join("ownership.json").is_file() {
            return d.to_string_lossy().into_owned();
        }
    }
    String::new()
}

fn is_isolated_worker_worktree(
    eff_cwd: &str,
    target_path: &str,
    manifest_root: &str,
    worker: &str,
) -> bool {
    let safe_worker = rio::safe_key(worker, "");
    if safe_worker.is_empty() || manifest_root.is_empty() {
        return false;
    }
    let wt_raw = Path::new(manifest_root)
        .join(".swarm")
        .join("worktrees")
        .join(&safe_worker);
    let wt_res = fs::canonicalize(&wt_raw).unwrap_or_else(|_| abspath_lexical(&wt_raw));
    let wt_fold = rio::fold_path(&wt_res.to_string_lossy());
    if wt_fold.is_empty() {
        return false;
    }
    let cwd_fold = if eff_cwd.is_empty() {
        String::new()
    } else {
        let cr = fs::canonicalize(eff_cwd).unwrap_or_else(|_| abspath_lexical(Path::new(eff_cwd)));
        rio::fold_path(&cr.to_string_lossy())
    };
    if cwd_fold != wt_fold && !cwd_fold.starts_with(&(wt_fold.clone() + "/")) {
        return false;
    }
    if target_path.is_empty() {
        return true;
    }
    let mut t_path = PathBuf::from(target_path);
    if !t_path.is_absolute() {
        t_path = Path::new(eff_cwd).join(t_path);
    }
    let t_res = fs::canonicalize(&t_path).unwrap_or_else(|_| abspath_lexical(&t_path));
    let t_fold = rio::fold_path(&t_res.to_string_lossy());
    t_fold == wt_fold || t_fold.starts_with(&(wt_fold + "/"))
}

fn resolve_target_against_cwd(raw_target: &str, seg_cwd: &str) -> String {
    let p = Path::new(raw_target);
    if p.is_absolute() || seg_cwd.is_empty() {
        raw_target.to_string()
    } else {
        Path::new(seg_cwd).join(p).to_string_lossy().into_owned()
    }
}

fn flagged_values(flagged: &HashMap<String, Vec<String>>, keys: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for &k in keys {
        if let Some(vals) = flagged.get(k) {
            out.extend(vals.iter().cloned());
        }
    }
    out
}

fn is_known_file_mutation_verb(verb: &str) -> bool {
    COPY_VERBS.contains(&verb)
        || MOVE_VERBS.contains(&verb)
        || DELETE_OR_WRITE_VERBS.contains(&verb)
}

fn extract_file_verb_targets(tokens: &[String], seg_cwd: &str) -> Vec<String> {
    if tokens.is_empty() {
        return Vec::new();
    }
    let verb = tok_basename_lower(&tokens[0]);
    if !is_known_file_mutation_verb(&verb) {
        return Vec::new();
    }
    let mut path_flags: HashSet<&str> = PS_PATH_FLAGS.iter().copied().collect();
    for &k in PS_DEST_FLAGS {
        path_flags.insert(k);
    }
    path_flags.insert("-newname");
    let val_flags: HashSet<&str> = PS_NON_PATH_VALUE_FLAGS.iter().copied().collect();

    let rest = &tokens[1..];
    let mut flagged: HashMap<String, Vec<String>> = HashMap::new();
    let mut positional: Vec<String> = Vec::new();
    let mut idx = 0usize;
    while idx < rest.len() {
        let tok = &rest[idx];
        let low = tok.to_lowercase();
        if path_flags.contains(low.as_str()) && idx + 1 < rest.len() {
            flagged.entry(low).or_default().push(rest[idx + 1].clone());
            idx += 2;
            continue;
        }
        if val_flags.contains(low.as_str()) && idx + 1 < rest.len() {
            idx += 2;
            continue;
        }
        if tok.starts_with('-') {
            idx += 1;
            continue;
        }
        positional.push(tok.clone());
        idx += 1;
    }

    let mut raw_targets: Vec<String> = Vec::new();
    if COPY_VERBS.contains(&verb.as_str()) {
        let dests = flagged_values(&flagged, PS_DEST_FLAGS);
        if !dests.is_empty() {
            raw_targets.extend(dests);
        } else if let Some(last) = positional.last() {
            raw_targets.push(last.clone());
        }
    } else if MOVE_VERBS.contains(&verb.as_str()) {
        let src_paths = flagged_values(&flagged, PS_PATH_FLAGS);
        raw_targets.extend(src_paths.clone());
        raw_targets.extend(flagged_values(&flagged, PS_DEST_FLAGS));
        if let Some(new_names) = flagged.get("-newname") {
            for new_name in new_names {
                let first_src = src_paths.first().or_else(|| positional.first());
                if let Some(src0) = first_src {
                    if !new_name.contains('/') && !new_name.contains('\\') {
                        let resolved_src = resolve_target_against_cwd(src0, seg_cwd);
                        let parent_dir = Path::new(&resolved_src)
                            .parent()
                            .unwrap_or_else(|| Path::new(""));
                        raw_targets.push(parent_dir.join(new_name).to_string_lossy().into_owned());
                        continue;
                    }
                }
                raw_targets.push(new_name.clone());
            }
        }
        raw_targets.extend(positional);
    } else {
        raw_targets.extend(flagged_values(&flagged, PS_PATH_FLAGS));
        raw_targets.extend(positional);
    }

    raw_targets
        .into_iter()
        .filter(|t| !t.trim().is_empty())
        .map(|t| resolve_target_against_cwd(&t, seg_cwd))
        .collect()
}

fn is_blocked_worker_swarm_ctl(tokens: &[String], seg_text: &str) -> bool {
    let clean_toks: Vec<String> = tokens
        .iter()
        .map(|t| t.replace('"', "").replace('\'', ""))
        .collect();
    let mut matched_idx: Option<usize> = None;
    for (idx, tok) in clean_toks.iter().enumerate() {
        let norm = tok.trim_start_matches(['&', '.']).replace('\\', "/").to_lowercase();
        let name = norm.rsplit('/').next().unwrap_or("");
        if name == "swarm_ctl"
            || name == "swarm-ctl"
            || name == "swarm_ctl.py"
            || norm == "plugin.tools.swarm_ctl"
        {
            matched_idx = Some(idx);
            break;
        }
    }
    let Some(midx) = matched_idx else {
        let stripped_low = seg_text
            .replace(['"', '\'', '`'], "")
            .to_lowercase();
        return blocked_swarm_ctl_re().is_match(&stripped_low);
    };

    let first_name = clean_toks
        .first()
        .map(|t| tok_basename_lower(t.trim_start_matches(['&', '.'])))
        .unwrap_or_default();
    let is_invoker = INTERPRETER_BASENAMES.contains(&first_name.as_str())
        || matches!(
            first_name.as_str(),
            "swarm_ctl" | "swarm-ctl" | "swarm_ctl.py" | "carbon-stack" | "carbon-stack.exe" | "env" | "&" | "."
        );

    let rest = &clean_toks[midx + 1..];
    let mut pos: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < rest.len() {
        let tok = &rest[i];
        let low = tok.to_lowercase();
        if pos.is_empty() && low == "--cwd" && i + 1 < rest.len() {
            i += 2;
            continue;
        }
        if pos.is_empty() && low.starts_with("--cwd=") {
            i += 1;
            continue;
        }
        if tok.starts_with('-') {
            break;
        }
        pos.push(low);
        i += 1;
    }

    // SAFETY: allow swarm_ctl as read target (e.g. git diff / Get-Content) only when it is not invoked and has no subcommand tokens.
    if midx > 0
        && !is_invoker
        && (pos.is_empty() || !matches!(pos[0].as_str(), "ownership" | "worktree" | "board"))
    {
        return false;
    }
    let pair = (
        pos.first().map(|s| s.as_str()).unwrap_or(""),
        pos.get(1).map(|s| s.as_str()).unwrap_or(""),
    );
    !READONLY_SWARM_CTL_SUBCMDS.contains(&pair)
}

fn guard_worker_shell_ownership(
    cmd_text: &str,
    eff_cwd: &str,
    manifest_root: &str,
    worker: &str,
    owned: &[String],
) -> (String, Option<String>) {
    let core = rio::unwrap_tokenade_command(cmd_text);
    if core.is_empty() {
        return ("allow".to_string(), None);
    }
    let unquoted_core = strip_quoted(&core);
    if !extract_ps_subexprs(&core).is_empty()
        || nested_subexpr_re().is_match(&strip_single_quoted(&core))
        || unquoted_core.chars().any(|ch| matches!(ch, '(' | ')' | '{' | '}'))
    {
        return (
            "deny".to_string(),
            Some(format!(
                "[File Ownership Guard] Вложенные shell-выражения, скобочные группы и подстановки (`(...)`, `{{...}}`, `$(...)`, backticks, `iex`) запрещены для воркера `{}` при активном `.swarm/ownership.json`.",
                worker
            )),
        );
    }

    let mut cur_cwd = if eff_cwd.is_empty() {
        manifest_root.to_string()
    } else {
        eff_cwd.to_string()
    };
    let mut segments = split_shell_segments(&core, false);
    if segments.is_empty() {
        segments.push((cur_cwd.clone(), core.clone()));
    }

    for (_, seg_text) in segments {
        let tokens = ps_tokens(&seg_text);
        if is_blocked_worker_swarm_ctl(&tokens, &seg_text) {
            return (
                "deny".to_string(),
                Some(format!(
                    "[File Ownership Guard] Воркер `{}` не может изменять манифест `.swarm/ownership.json` или структуру worktrees (`ownership set|clear`, `worktree create|cleanup` разрешены только координатору).",
                    worker
                )),
            );
        }

        let seg_cwd = cur_cwd.clone();
        let (cleaned_seg, raw_redir_targets) = extract_ps_redirections(&seg_text);
        let redir_targets: Vec<String> = raw_redir_targets
            .iter()
            .map(|rt| resolve_target_against_cwd(rt, &seg_cwd))
            .collect();

        let verb = tokens
            .first()
            .map(|t| tok_basename_lower(t))
            .unwrap_or_default();
        if matches!(
            verb.as_str(),
            "cd" | "chdir" | "set-location" | "sl" | "push-location" | "pushd"
        ) {
            let mut nav_pos: Vec<String> = Vec::new();
            let mut nav_ok = nav_segment_re().is_match(&cleaned_seg) && redir_targets.is_empty();
            if nav_ok {
                let mut ni = 1usize;
                while ni < tokens.len() {
                    let nt = &tokens[ni];
                    let nlow = nt.to_lowercase();
                    if matches!(nlow.as_str(), "-path" | "-p" | "-literalpath" | "-lp") {
                        if ni + 1 >= tokens.len() {
                            nav_ok = false;
                            break;
                        }
                        nav_pos.push(tokens[ni + 1].clone());
                        ni += 2;
                    } else if nlow == "-passthru" {
                        ni += 1;
                    } else if nt.starts_with('-') {
                        nav_ok = false;
                        break;
                    } else {
                        nav_pos.push(nt.clone());
                        ni += 1;
                    }
                }
            }
            if !nav_ok
                || nav_pos.len() > 1
                || nav_pos.first().map_or(false, |np| {
                    np.chars()
                        .any(|ch| matches!(ch, '$' | ',' | '(' | ')' | '{' | '}' | '`'))
                })
            {
                return (
                    "deny".to_string(),
                    Some(format!(
                        "[File Ownership Guard] Недопустимые аргументы или выражения в команде смены каталога `{}` воркера `{}`.",
                        verb, worker
                    )),
                );
            }
            if let Some(np) = nav_pos.first() {
                let p = Path::new(np);
                let joined = if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    Path::new(&cur_cwd).join(p)
                };
                cur_cwd = fs::canonicalize(&joined)
                    .unwrap_or_else(|_| abspath_lexical(&joined))
                    .to_string_lossy()
                    .into_owned();
            }
            continue;
        }

        let verb_targets = extract_file_verb_targets(&tokens, &seg_cwd);
        for candidate in redir_targets.iter().chain(verb_targets.iter()) {
            if candidate.chars().any(|ch| matches!(ch, '$' | ',' | '`')) {
                return (
                    "deny".to_string(),
                    Some(format!(
                        "[File Ownership Guard] Переменные и списки путей через запятую (`$`, `,`) в shell-целях запрещены для воркера `{}` при активном `.swarm/ownership.json`.",
                        worker
                    )),
                );
            }
            if is_isolated_worker_worktree(eff_cwd, candidate, manifest_root, worker) {
                continue;
            }
            let (_, rel, is_ephemeral) = classify_ownership_target(candidate, manifest_root);
            if is_ephemeral {
                continue;
            }
            if owned.is_empty() || !cwg_common::path_matches_any_glob(&rel, owned) {
                return (
                    "deny".to_string(),
                    Some(format!(
                        "[File Ownership Guard] Shell-операция воркера `{}` затрагивает `{}` вне owned_paths={:?}. Выполняйте запись только в свои файлы или через изолированный worktree.",
                        worker, rel, owned
                    )),
                );
            }
        }

        if is_known_file_mutation_verb(&verb) {
            if verb_targets.is_empty() {
                return (
                    "deny".to_string(),
                    Some(format!(
                        "[File Ownership Guard] Не удалось определить целевой путь файловой команды `{}` воркера `{}`. Используйте явный путь внутри `owned_paths` или `edit_file`/`write_file`.",
                        verb, worker
                    )),
                );
            }
            continue;
        }

        let seg_to_check = if !redir_targets.is_empty() {
            cleaned_seg.as_str()
        } else {
            seg_text.as_str()
        };
        if !seg_to_check.is_empty()
            && !matches!(
                classify_shell_command(seg_to_check),
                "READ_ONLY" | "BOOKKEEPING" | "VALIDATION"
            )
        {
            return (
                "deny".to_string(),
                Some(format!(
                    "[File Ownership Guard] Произвольная или непроверяемая shell-мутация воркера `{}` запрещена при активном `.swarm/ownership.json`: используйте `edit_file`/`write_file` в рамках owned_paths={:?} или изолированный worktree (`carbon-stack swarm-ctl worktree create`).",
                    worker, owned
                )),
            );
        }
    }

    ("allow".to_string(), None)
}

pub fn guard_file_ownership(
    payload: &Value,
    tool_name: &str,
    args: &Value,
    cwd: &str,
) -> (String, Option<String>) {
    let target_path = ownership_target_path(args);
    let eff_cwd = if !cwd.is_empty() {
        cwd.to_string()
    } else if !target_path.is_empty() {
        Path::new(&target_path)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default()
    } else {
        String::new()
    };
    let manifest_root = if eff_cwd.is_empty() {
        String::new()
    } else {
        find_ownership_manifest_root(&eff_cwd)
    };
    if manifest_root.is_empty() {
        return ("allow".to_string(), None);
    }

    let manifest_path = Path::new(&manifest_root).join(".swarm").join("ownership.json");
    let manifest_doc = rio::read_json(&manifest_path);
    let manifest = match manifest_doc {
        Some(Value::Object(m)) => Value::Object(m),
        _ => json!({"workers": {}}),
    };
    let Some(workers) = manifest.get("workers").and_then(|v| v.as_object()) else {
        return ("allow".to_string(), None);
    };
    if workers.is_empty() {
        return ("allow".to_string(), None);
    }

    let worker = resolve_swarm_worker_identity(payload);
    let cmd_text = if tool_name == "run_command" {
        val_to_str(args.get("CommandLine"))
    } else {
        String::new()
    };
    let is_coord = worker.is_empty() || is_coordinator_role(&worker);
    let is_swarm_ctl_fix = is_coord
        && (cmd_text.contains("swarm_ctl") || cmd_text.contains("swarm-ctl"))
        && cmd_text.contains("ownership");
    if !is_swarm_ctl_fix {
        // INVARIANT: PreToolUse runs pure syntactic overlap checks (O(W^2*G^2)) without spawning `git ls-files`.
        let overlaps = cwg_common::detect_ownership_overlaps(&manifest, "");
        if let Some(pair) = overlaps.first() {
            return (
                "deny".to_string(),
                Some(format!(
                    "[File Ownership Guard] Пересечение `owned_paths` в `.swarm/ownership.json`: `{}` ({}) vs `{}` ({}). Устраните пересечение через `carbon-stack swarm-ctl ownership set` или выделите изолированные `worktree create`.",
                    val_to_str(pair.get("worker_a")),
                    val_to_str(pair.get("glob_a")),
                    val_to_str(pair.get("worker_b")),
                    val_to_str(pair.get("glob_b")),
                )),
            );
        }
    }

    if is_coord {
        return ("allow".to_string(), None);
    }

    let owned: Vec<String> = workers
        .get(&worker)
        .and_then(|v| v.get("paths"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|x| val_to_str(Some(x)))
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    if matches!(tool_name, "edit_file" | "write_file") && !target_path.is_empty() {
        if is_isolated_worker_worktree(&eff_cwd, &target_path, &manifest_root, &worker) {
            return ("allow".to_string(), None);
        }
        let (_, rel, is_ephemeral) = classify_ownership_target(&target_path, &manifest_root);
        if is_ephemeral {
            return ("allow".to_string(), None);
        }
        if owned.is_empty() || !cwg_common::path_matches_any_glob(&rel, &owned) {
            return (
                "deny".to_string(),
                Some(format!(
                    "[File Ownership Guard] Воркер `{}` не владеет путём `{}` (owned_paths={:?}). Запись за пределы `owned_paths` запрещена — правьте только свои файлы или запросите `worktree create` у координатора.",
                    worker, rel, owned
                )),
            );
        }
    }

    if tool_name == "run_command" && !cmd_text.is_empty() {
        return guard_worker_shell_ownership(&cmd_text, &eff_cwd, &manifest_root, &worker, &owned);
    }
    ("allow".to_string(), None)
}

fn is_worker_silently_parked(brain_root: &Path, minfo: &Value, last_assign_seq: i64) -> bool {
    let wake_mode = val_to_str(minfo.get("wake_mode")).trim().to_lowercase();
    let mstate = val_to_str(minfo.get("state")).trim().to_lowercase();
    let wait_since = val_to_i64(minfo.get("wait_since"));
    if (mstate == "waiting" || matches!(wake_mode.as_str(), "mentions" | "all" | "waiting"))
        && wait_since >= last_assign_seq
    {
        return true;
    }

    let w_cid = minfo
        .get("conversation_id")
        .or_else(|| minfo.get("conversationId"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if w_cid.is_empty() {
        return false;
    }
    let tp = rio::member_transcript_path(brain_root, w_cid);
    let w_steps = rio::read_transcript_steps(&tp.to_string_lossy(), 60);
    if w_steps.is_empty() {
        return false;
    }
    let turn = rio::inspect_worker_turn_after_wake(&w_steps, last_assign_seq);
    let pending_nonempty = turn
        .get("pending_bg")
        .and_then(|v| v.as_array())
        .map_or(false, |a| !a.is_empty());
    if !json_truthy(turn.get("woke_for_assign"))
        || !json_truthy(turn.get("has_tail"))
        || json_truthy(turn.get("called_post"))
        || pending_nonempty
    {
        return false;
    }
    if json_truthy(turn.get("has_error")) {
        return true;
    }
    json_truthy(turn.get("saw_model")) && json_truthy(turn.get("terminal_parked"))
}

pub fn guard_swarm_wait(payload: &Value, args: Option<&Value>) -> (String, Option<String>) {
    // SAFETY: Prevent coordinator deadlock when calling `swarm_wait` after all active workers have already posted, parked without posting, or stalled.
    let tp = payload
        .get("transcriptPath")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if rio::is_subagent_session(tp, None) {
        return ("allow".to_string(), None);
    }
    let session = rio::session_key(payload);
    if session.is_empty() || session == "unknown" {
        return ("allow".to_string(), None);
    }
    let brain_root = resolve_brain_root_for_payload(payload);
    let members = rio::load_swarm_members(&brain_root, &session);
    if members.is_empty() {
        return ("allow".to_string(), None);
    }
    let board_path = rio::swarm_dir(&brain_root, &session).join("board.jsonl");
    let raw_board = rio::read_jsonl(&board_path, Some(400));
    if raw_board.is_empty() {
        return ("allow".to_string(), None);
    }

    let eff_args = args.or_else(|| payload.get("toolCall").and_then(|t| t.get("args")));
    let since_val = val_to_i64(eff_args.and_then(|a| a.get("since")));

    let mut active_workers: Vec<String> = Vec::new();
    let mut in_flight: Vec<String> = Vec::new();
    let mut unposted_parked: Vec<String> = Vec::new();

    for (mname, minfo) in &members {
        if !minfo.is_object()
            || rio::is_swarm_role_member(mname, Some(minfo))
            || rio::is_swarm_member_killed(Some(minfo))
        {
            continue;
        }
        active_workers.push(mname.clone());
        let added_by = minfo
            .get("added_by")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let (last_assign_seq, last_reply_seq) =
            rio::latest_board_assign_and_reply_seq(&raw_board, mname, added_by);
        if last_assign_seq == 0 || last_reply_seq < last_assign_seq {
            if last_assign_seq > 0 && is_worker_silently_parked(&brain_root, minfo, last_assign_seq)
            {
                unposted_parked.push(mname.clone());
            } else {
                in_flight.push(mname.clone());
            }
        }
    }

    if !in_flight.is_empty() {
        let eff_cwd = rio::effective_cwd(payload);
        let empty_act = HashMap::new();
        let stalled = cwg_common::detect_stalled_workers(cwg_common::StallDetectInput {
            members: &members,
            board_messages: &raw_board,
            cwd: &eff_cwd,
            brain_root: Some(&brain_root),
            worker_last_activity: &empty_act,
            in_flight_names: &in_flight,
            now_ts: None,
            timeout_sec: None,
        });
        if !stalled.is_empty() {
            let desc: String = stalled
                .iter()
                .map(|s| {
                    format!(
                        "`{}` ({}s >= {}s)",
                        val_to_str(s.get("worker")),
                        val_to_str(s.get("idle_sec")),
                        val_to_str(s.get("timeout_sec")),
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            return (
                "deny".to_string(),
                Some(format!(
                    "[Swarm Stall Watchdog] Зависли in-flight воркеры без новых сообщений на доске и активности в `.swarm/`: {}. Не уходите в немое ожидание `swarm_wait`: проверьте `.swarm/artifacts/`, перепинайте через `@mention` или перезапустите зависшего воркера.",
                    desc
                )),
            );
        }
    }

    if !active_workers.is_empty() && in_flight.is_empty() {
        let head_seq = raw_board
            .last()
            .and_then(|b| b.get("seq"))
            .and_then(|v| v.as_i64())
            .filter(|&x| x != 0)
            .unwrap_or(raw_board.len() as i64);
        if !unposted_parked.is_empty() {
            let since_note = if since_val > 0 {
                format!(", since={}", since_val)
            } else {
                String::new()
            };
            return (
                "deny".to_string(),
                Some(format!(
                    "[Swarm Wait Guard] Активных работающих воркеров не осталось (head=#{}{}), а воркер(ы) ({}) завершили ход в `waiting` без вызова `post_message` после задания. Вызов `swarm_wait` сейчас приведёт к вечному зависанию: разбудите воркера через `post_message('@<name> Call post_message with your result')` или перезапустите его.",
                    head_seq,
                    since_note,
                    unposted_parked.join(", "),
                )),
            );
        }
        return (
            "deny".to_string(),
            Some(format!(
                "[Swarm Wait Guard] Все активные воркеры роя ({}) уже опубликовали ответы на доске (head=#{}). Вызов `swarm_wait` сейчас приведёт к вечному ожиданию. Не вызывайте `read_board` и `swarm_wait` в одном ходе: обработайте полученные сообщения и завершите воркеров через `swarm(action='kill', ...)`.",
                active_workers.join(", "),
                head_seq,
            )),
        );
    }

    ("allow".to_string(), None)
}

pub fn guard_post_message(
    payload: &Value,
    args: &Value,
    cwd: &str,
) -> (String, Option<String>) {
    let tp = payload
        .get("transcriptPath")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if rio::is_subagent_session(tp, None) {
        return ("allow".to_string(), None);
    }
    let caller_worker = resolve_swarm_worker_identity(payload);
    if !caller_worker.is_empty() && !is_coordinator_role(&caller_worker) {
        return ("allow".to_string(), None);
    }
    let session = rio::session_key(payload);
    if session.is_empty() || session == "unknown" {
        return ("allow".to_string(), None);
    }
    let text = val_to_str(args.get("text"));
    if !text.contains('@') {
        return ("allow".to_string(), None);
    }
    let brain_root = resolve_brain_root_for_payload(payload);
    let members = rio::load_swarm_members(&brain_root, &session);
    if members.is_empty() {
        return ("allow".to_string(), None);
    }
    let mentions_all = rio::text_contains_mention(&text, "all");
    let known_workers = rio::swarm_worker_names(&members);
    let mut targeted: Vec<String> = Vec::new();
    let mut active_set: Option<std::collections::HashSet<String>> = None;
    for (mname, minfo) in &members {
        if !minfo.is_object()
            || rio::is_swarm_role_member(mname, Some(minfo))
            || rio::is_swarm_member_killed(Some(minfo))
        {
            continue;
        }
        if !(mentions_all || rio::text_mentions_swarm_worker(&text, mname)) {
            continue;
        }
        let scoped_text = cwg_common::extract_worker_scoped_brief(&text, mname, &known_workers);
        let is_target =
            cwg_common::is_simplify_or_review_swarm_worker_with_brief(
                mname,
                Some(minfo),
                &scoped_text,
            )
                || active_set
                    .get_or_insert_with(|| {
                        cwg_common::active_simplify_or_review_workers_with_members(
                            &brain_root,
                            &session,
                            &members,
                        )
                        .into_iter()
                        .collect()
                    })
                    .contains(mname);
        if is_target {
            targeted.push(mname.clone());
        }
    }
    if targeted.is_empty() {
        return ("allow".to_string(), None);
    }
    targeted.sort();
    if let Some(rm_deny) = pending_research_mode_deny(&session, cwd, tp) {
        return ("deny".to_string(), Some(rm_deny));
    }
    if text.to_lowercase().contains("closure_validation:")
        && targeted.iter().any(|w| !cwg_common::is_simplify_worker_name(w))
    {
        if let Some(sim_deny) = pending_post_block_simplify_deny(&session, cwd, tp, "") {
            return ("deny".to_string(), Some(sim_deny));
        }
    }
    if let Some(marker) = cwg_common::read_marker_with_pending(&session).filter(|m| !json_truthy(m.get("closed"))) {
        let rr_ts = cwg_common::last_research_reset_ts(&marker);
        let rr_seq = cwg_common::last_research_reset_board_seq(&marker);
        if rr_ts > 0.0 || rr_seq > 0 {
            let board_path = rio::swarm_dir(&brain_root, &session).join("board.jsonl");
            let raw_board = rio::read_jsonl(&board_path, None);
            for wname in &targeted {
                if cwg_common::is_worker_spawned_before_reset(
                    wname,
                    members.get(wname),
                    &raw_board,
                    rr_ts,
                    rr_seq,
                    Some(&marker),
                    Some(&brain_root),
                ) {
                    return (
                        "deny".to_string(),
                        Some(format!(
                            "[Gate Fresh Session Policy] Пробуждение воркера `{}` из предыдущего цикла после `research-reset` запрещено: завершите его через `swarm(action='kill', name='{}')` и создайте новую сессию линзы/ревью.",
                            wname, wname
                        )),
                    );
                }
            }
        }
    }
    ("allow".to_string(), None)
}

pub fn evaluate_pre_tool_use(payload: &Value) -> (String, Option<String>, Option<Value>) {
    let session = rio::session_key(payload);
    let cwd = rio::effective_cwd(payload);
    let tc = payload.get("toolCall").and_then(|v| v.as_object());
    let tool_name = tc
        .and_then(|m| m.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let args = tc
        .and_then(|m| m.get("args"))
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));

    match tool_name {
        "run_command" => {
            let cmd = val_to_str(args.get("CommandLine"));
            let (dec, reason) = guard_shell_command_with_session(&cmd, &cwd, &session);
            if dec != "allow" {
                rio::log_hook_event(
                    "hygiene-events",
                    "shell_guard_deny",
                    json!({"session": session, "reason": reason.as_deref().unwrap_or("")}),
                );
                return (dec, reason, None);
            }
            let (dec2, reason2) = guard_file_ownership(payload, tool_name, &args, &cwd);
            if dec2 != "allow" {
                rio::log_hook_event(
                    "hygiene-events",
                    "ownership_guard_deny",
                    json!({"session": session, "reason": reason2.as_deref().unwrap_or("")}),
                );
                return (dec2, reason2, None);
            }
        }
        "read_board" => {
            let (dec, reason) = guard_read_board(payload, &args, &cwd);
            if dec != "allow" {
                rio::log_hook_event(
                    "hygiene-events",
                    "cursor_guard_deny",
                    json!({"session": session, "reason": reason.as_deref().unwrap_or("")}),
                );
                return (dec, reason, None);
            }
        }
        "edit_file" | "write_file" => {
            let (dec, reason) = guard_file_ownership(payload, tool_name, &args, &cwd);
            if dec != "allow" {
                rio::log_hook_event(
                    "hygiene-events",
                    "ownership_guard_deny",
                    json!({"session": session, "reason": reason.as_deref().unwrap_or("")}),
                );
                return (dec, reason, None);
            }
        }
        "swarm" => {
            let (dec, reason) = guard_swarm_invocation_with_payload(&args, Some(payload));
            if dec != "allow" {
                rio::log_hook_event(
                    "hygiene-events",
                    "model_guard_deny",
                    json!({"session": session, "reason": reason.as_deref().unwrap_or("")}),
                );
                return (dec, reason, None);
            }
        }
        "post_message" => {
            let (dec, reason) = guard_post_message(payload, &args, &cwd);
            if dec != "allow" {
                rio::log_hook_event(
                    "hygiene-events",
                    "post_message_guard_deny",
                    json!({"session": session, "reason": reason.as_deref().unwrap_or("")}),
                );
                return (dec, reason, None);
            }
        }
        "swarm_wait" => {
            let (dec, reason) = guard_swarm_wait(payload, Some(&args));
            if dec != "allow" {
                rio::log_hook_event(
                    "hygiene-events",
                    "swarm_wait_guard_deny",
                    json!({"session": session, "reason": reason.as_deref().unwrap_or("")}),
                );
                return (dec, reason, None);
            }
        }
        "invoke_subagent" => {
            let (dec, reason, overwrite) = guard_subagent_invocation_with_payload(payload, &args);
            if dec != "allow" {
                let ev = if reason
                    .as_deref()
                    .unwrap_or("")
                    .contains("[Model Policy Guard]")
                {
                    "model_guard_deny"
                } else {
                    "subagent_guard_deny"
                };
                rio::log_hook_event(
                    "hygiene-events",
                    ev,
                    json!({"session": session, "reason": reason.as_deref().unwrap_or("")}),
                );
                return (dec, reason, None);
            }
            if overwrite.is_some() {
                return ("allow".to_string(), None, overwrite);
            }
        }
        _ => {}
    }

    ("allow".to_string(), None, None)
}

pub fn run_cli(_args: &[String]) -> i32 {
    match rio::read_hook_stdin() {
        Ok(payload) => {
            let (decision, reason, overwrite) = evaluate_pre_tool_use(&payload);
            rio::emit_pre_tool(&decision, reason.as_deref(), overwrite);
            0
        }
        Err(err) => {
            rio::log_hook_event(
                "hook-errors",
                "stdin_error",
                json!({"hook": "safety_guards", "error": err}),
            );
            rio::emit_pre_tool("allow", None, None);
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_regexes_compile() {
        let _ = bare_worktree_remove_re();
        let _ = destructive_git_re();
        let _ = cmd_backtick_re();
        let _ = swarm_tag_re();
        let _ = nested_subexpr_re();
        let _ = blocked_swarm_ctl_re();
        let _ = nav_segment_re();
    }

    #[test]
    fn test_guard_shell_worktree_and_dirty_protection() {
        let (dec_wt, reason_wt) = guard_shell_command("git worktree remove ../wt-1", ".");
        assert_eq!(dec_wt, "deny");
        assert!(reason_wt.unwrap().contains("Worktree Safety Guard"));

        let (dec_ok, _) = guard_shell_command("git status", ".");
        assert_eq!(dec_ok, "allow");

        let dir = env::temp_dir().join(format!("carbon-sg-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let (rc_init, _, _) = rio::run_git(&dir.to_string_lossy(), &["init"], 5.0);
        if rc_init == 0 {
            fs::write(dir.join("dirty.txt"), "uncommitted\n").unwrap();
            let (dec_dirty, reason_dirty) =
                guard_shell_command("git reset --hard", &dir.to_string_lossy());
            assert_eq!(dec_dirty, "deny");
            assert!(reason_dirty.unwrap().contains("Dirty Worktree Protection"));
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_guard_model_policies_swarm_and_subagent() {
        let (dec_flash_sw, reason_flash_sw) = guard_swarm_invocation(&json!({
            "action": "add",
            "name": "worker-1",
            "model": "gemini-3-flash-lite",
        }));
        assert_eq!(dec_flash_sw, "deny");
        assert!(reason_flash_sw.unwrap().contains("Model Policy Guard"));

        let (dec_simp_bad, reason_simp_bad) = guard_swarm_invocation(&json!({
            "action": "add",
            "name": "simplify-reuse",
            "model": "gemini-4-carbon-high",
        }));
        assert_eq!(dec_simp_bad, "deny");
        assert!(reason_simp_bad.unwrap().contains("Simplify Model Policy"));

        let (dec_simp_ok, _) = guard_swarm_invocation(&json!({
            "action": "add",
            "name": "simplify-reuse",
            "model": "claude-sonnet-5-5-high",
        }));
        assert_eq!(dec_simp_ok, "allow");

        let (dec_simp_xhigh, _) = guard_swarm_invocation(&json!({
            "action": "add",
            "name": "simplify-quality",
            "model": "gemini-4-hydrogen-xhigh",
        }));
        assert_eq!(dec_simp_xhigh, "allow");

        let (dec_simp_neon, _) = guard_swarm_invocation(&json!({
            "action": "add",
            "name": "simplify-efficiency",
            "model": "gemini-4-neon-xhigh",
        }));
        assert_eq!(dec_simp_neon, "allow");

        let (dec_simp_empty, reason_simp_empty) = guard_swarm_invocation(&json!({
            "action": "add",
            "name": "simplify-reviewer",
            "model": "",
        }));
        assert_eq!(dec_simp_empty, "deny");
        assert!(reason_simp_empty.unwrap().contains("Simplify Model Policy"));

        assert!(is_adversarial_review_swarm_target(
            "internal-reviewer",
            cwg_common::NEON_XHIGH_MODEL,
            "Read-only review; end with VERDICT: APPROVED or VERDICT: REVISE."
        ));
        assert!(is_adversarial_review_swarm_target(
            "neon-audit",
            cwg_common::NEON_XHIGH_MODEL,
            "Audit auth. Return VERDICT: APPROVED or REVISE. Do NOT edit files."
        ));
        assert!(!is_adversarial_review_swarm_target(
            "root-cause-debugger",
            cwg_common::NEON_XHIGH_MODEL,
            "Debug flaky shutdown race in test_04."
        ));
        assert!(!is_adversarial_review_swarm_target(
            "root-cause-debugger",
            cwg_common::NEON_XHIGH_MODEL,
            "Investigate race. NEVER post VERDICT:/CLOSURE_VALIDATION:."
        ));

        let (dec_sub_flash, _) = guard_subagent_invocation(&json!({
            "TypeName": "research",
            "Model": "gemini-3-flash",
            "Prompt": "Inspect codebase callers and report back",
        }));
        assert_eq!(dec_sub_flash, "deny");

        let (dec_sub_short, _) = guard_subagent_invocation(&json!({
            "TypeName": "research",
            "Prompt": "too short",
        }));
        assert_eq!(dec_sub_short, "deny");
    }

    #[test]
    fn test_shell_classification_and_ownership_guard() {
        assert_eq!(classify_shell_command("git status; Get-Content src/main.rs"), "READ_ONLY");
        assert_eq!(classify_shell_command("$null | cargo test"), "VALIDATION");
        assert_eq!(
            classify_shell_command("Set-Content -Path foo.txt -Value hi"),
            "MUTATING"
        );
        assert_eq!(
            classify_shell_command("python -X utf8 install.py --dry-run"),
            "VALIDATION"
        );
        assert_eq!(
            classify_shell_command("python -X utf8 install.py"),
            "MUTATING"
        );

        let root = env::temp_dir().join(format!("carbon-own-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join(".swarm").join("artifacts")).unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join(".swarm").join("ownership.json"),
            r#"{"workers":{"builder-a":{"paths":["src/a.rs"]},"builder-b":{"paths":["src/b.rs"]}}}"#,
        )
        .unwrap();

        let payload = json!({
            "worker_name": "builder-a",
            "cwd": root.to_string_lossy(),
            "toolCall": {
                "name": "edit_file",
                "args": {"Path": root.join("src/b.rs").to_string_lossy()}
            }
        });
        let (dec_deny, reason_deny, _) = evaluate_pre_tool_use(&payload);
        assert_eq!(dec_deny, "deny");
        assert!(reason_deny.unwrap().contains("File Ownership Guard"));

        let payload_art = json!({
            "worker_name": "builder-a",
            "cwd": root.to_string_lossy(),
            "toolCall": {
                "name": "write_file",
                "args": {"Path": root.join(".swarm/artifacts/builder-a-1.md").to_string_lossy()}
            }
        });
        let (dec_art, _, _) = evaluate_pre_tool_use(&payload_art);
        assert_eq!(dec_art, "allow");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_cursor_guard_and_swarm_wait_guard() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = env::temp_dir().join(format!("carbon-swg-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let sid = format!("test-swg-sess-{}", std::process::id());
        let brain_root = root.join("brain");
        let tp = brain_root
            .join(&sid)
            .join(".system_generated")
            .join("logs")
            .join("transcript.jsonl");
        let swarm_path = brain_root
            .join(&sid)
            .join(".system_generated")
            .join("swarm");
        fs::create_dir_all(tp.parent().unwrap()).unwrap();
        fs::create_dir_all(&swarm_path).unwrap();
        fs::write(
            &tp,
            "{\"step_index\":0,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"Run\"}\n",
        )
        .unwrap();
        fs::write(
            swarm_path.join("members.json"),
            r#"{"members":{"worker-a":{"role":"worker","state":"waiting"}}}"#,
        )
        .unwrap();

        let mut board_lines = String::new();
        for i in 1..=16 {
            let agent = if i == 1 { "coordinator" } else { "worker-a" };
            let text = if i == 1 { "@worker-a do work" } else { "done" };
            board_lines.push_str(&format!(
                "{{\"seq\":{},\"agent\":\"{}\",\"text\":\"{}\"}}\n",
                i, agent, text
            ));
        }
        fs::write(swarm_path.join("board.jsonl"), &board_lines).unwrap();

        let cpath = cursor_state_path(&sid);
        let _ = fs::remove_file(&cpath);

        let rb_first = json!({
            "conversationId": sid,
            "transcriptPath": tp.to_string_lossy(),
            "toolCall": {"name": "read_board", "args": {}}
        });
        assert_eq!(evaluate_pre_tool_use(&rb_first).0, "allow");

        let rb_repeat = json!({
            "conversationId": sid,
            "transcriptPath": tp.to_string_lossy(),
            "toolCall": {"name": "read_board", "args": {}}
        });
        let (dec_cursor, reason_cursor, _) = evaluate_pre_tool_use(&rb_repeat);
        assert_eq!(dec_cursor, "deny");
        assert!(reason_cursor.unwrap().contains("Swarm Cursor Guard"));

        let rb_with_since = json!({
            "conversationId": sid,
            "transcriptPath": tp.to_string_lossy(),
            "toolCall": {"name": "read_board", "args": {"since": 16}}
        });
        assert_eq!(evaluate_pre_tool_use(&rb_with_since).0, "allow");

        let sw_wait = json!({
            "conversationId": sid,
            "transcriptPath": tp.to_string_lossy(),
            "toolCall": {"name": "swarm_wait", "args": {"since": 16}}
        });
        let (dec_wait, reason_wait, _) = evaluate_pre_tool_use(&sw_wait);
        assert_eq!(dec_wait, "deny");
        assert!(reason_wait.unwrap().contains("Swarm Wait Guard"));

        let _ = fs::remove_file(&cpath);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_multi_recipient_post_message_preserves_non_review_worker() {
        let _guard = crate::win32_sqlite::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        struct HomeGuard(Option<std::ffi::OsString>);
        impl Drop for HomeGuard {
            fn drop(&mut self) {
                match self.0.take() {
                    Some(v) => unsafe { env::set_var("CARBON_STACK_HOME", v) },
                    None => unsafe { env::remove_var("CARBON_STACK_HOME") },
                }
            }
        }
        let _home_guard = HomeGuard(env::var_os("CARBON_STACK_HOME"));

        let root = env::temp_dir().join(format!("carbon-swg-multi-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let carbon_home = root.join("carbon-home");
        unsafe { env::set_var("CARBON_STACK_HOME", &carbon_home) };

        let sid = format!("test-swg-multi-{}", std::process::id());
        let brain_root = root.join("brain");
        let tp = brain_root
            .join(&sid)
            .join(".system_generated")
            .join("logs")
            .join("transcript.jsonl");
        let swarm_path = brain_root
            .join(&sid)
            .join(".system_generated")
            .join("swarm");
        fs::create_dir_all(tp.parent().unwrap()).unwrap();
        fs::create_dir_all(&swarm_path).unwrap();
        fs::write(
            &tp,
            "{\"step_index\":0,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"created_at\":\"2026-11-19T10:00:00Z\",\"content\":\"Run\"}\n",
        )
        .unwrap();

        fs::write(
            swarm_path.join("members.json"),
            json!({
                "members": {
                    "test-author": {
                        "role": "worker",
                        "model": cwg_common::NEON_XHIGH_MODEL,
                        "killed": false,
                        "created_at": "2026-11-19T10:00:05Z"
                    },
                    "ui-builder": {
                        "role": "worker",
                        "model": cwg_common::NEON_XHIGH_MODEL,
                        "killed": false,
                        "created_at": "2026-11-19T10:00:05Z"
                    },
                    "neon-audit": {
                        "role": "worker",
                        "model": cwg_common::NEON_XHIGH_MODEL,
                        "killed": false,
                        "created_at": "2026-11-19T10:00:25Z"
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
        fs::write(
            swarm_path.join("board.jsonl"),
            [
                json!({"seq": 1, "agent": "coordinator", "time": "2026-11-19T10:00:06Z", "text": "@test-author Report test results"}),
                json!({"seq": 6, "agent": "coordinator", "time": "2026-11-19T10:00:26Z", "text": "@neon-audit Return VERDICT: APPROVED"}),
            ]
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("\n")
                + "\n",
        )
        .unwrap();

        let rr_ts = rio::parse_iso_ts("2026-11-19T10:00:20Z");
        rio::write_json(
            &cwg_common::marker_path(&sid),
            &json!({
                "session": sid,
                "first_ts": rio::parse_iso_ts("2026-11-19T10:00:00Z"),
                "closed": false,
                "research_resets": [{"reset_ts": rr_ts, "board_head_seq": 5, "decision": "refine", "findings": "docs", "research_tools": ["search_web"]}]
            }),
        )
        .unwrap();

        let multi_allow = json!({
            "conversationId": sid,
            "transcriptPath": tp.to_string_lossy(),
            "toolCall": {
                "name": "post_message",
                "args": {"text": "@neon-audit Return VERDICT: APPROVED\n@test-author Report test results"}
            }
        });
        assert_eq!(evaluate_pre_tool_use(&multi_allow).0, "allow");

        let pre_reset_review_deny = json!({
            "conversationId": sid,
            "transcriptPath": tp.to_string_lossy(),
            "toolCall": {
                "name": "post_message",
                "args": {"text": "@test-author Return VERDICT: APPROVED"}
            }
        });
        let (dec_deny, reason_deny, _) = evaluate_pre_tool_use(&pre_reset_review_deny);
        assert_eq!(dec_deny, "deny");
        assert!(reason_deny.unwrap().contains("Gate Fresh Session Policy"));

        let trailing_review_deny = json!({
            "conversationId": sid,
            "transcriptPath": tp.to_string_lossy(),
            "toolCall": {
                "name": "post_message",
                "args": {"text": "Повтори ревью и верни VERDICT: APPROVED или REVISE, @test-author"}
            }
        });
        let (dec_trail, reason_trail, _) = evaluate_pre_tool_use(&trailing_review_deny);
        assert_eq!(dec_trail, "deny");
        assert!(reason_trail.unwrap().contains("Gate Fresh Session Policy"));

        let trailing_multi_allow = json!({
            "conversationId": sid,
            "transcriptPath": tp.to_string_lossy(),
            "toolCall": {
                "name": "post_message",
                "args": {"text": "Повтори ревью и верни VERDICT: APPROVED или REVISE, @neon-audit. Добавь тесты, @test-author."}
            }
        });
        assert_eq!(evaluate_pre_tool_use(&trailing_multi_allow).0, "allow");

        let mixed_trailing_leading_allow = json!({
            "conversationId": sid,
            "transcriptPath": tp.to_string_lossy(),
            "toolCall": {
                "name": "post_message",
                "args": {"text": "Return VERDICT: APPROVED, @neon-audit. Add tests, @test-author. @ui-builder Check layout."}
            }
        });
        assert_eq!(evaluate_pre_tool_use(&mixed_trailing_leading_allow).0, "allow");

        let excl_trailing_allow = json!({
            "conversationId": sid,
            "transcriptPath": tp.to_string_lossy(),
            "toolCall": {
                "name": "post_message",
                "args": {"text": "Review the diff and return VERDICT: APPROVED or REVISE! @neon-audit. @test-author Add tests."}
            }
        });
        assert_eq!(evaluate_pre_tool_use(&excl_trailing_allow).0, "allow");

        let lead_excl_trail_allow = json!({
            "conversationId": sid,
            "transcriptPath": tp.to_string_lossy(),
            "toolCall": {
                "name": "post_message",
                "args": {"text": "@ui-builder Edit src/ui.rs. Review src/gate.rs and return VERDICT: APPROVED! @neon-audit. @test-author Add tests."}
            }
        });
        assert_eq!(evaluate_pre_tool_use(&lead_excl_trail_allow).0, "allow");

        for tail_ping in [
            "@neon-audit Read the diff. Return VERDICT: APPROVED.\n@test-author",
            "@neon-audit Read the diff. Return VERDICT: APPROVED. @test-author",
            "@neon-audit Read the diff.\nReturn VERDICT: APPROVED. @test-author",
            "@ui-builder Edit src/ui.rs. Review the diff and prefix the result with VERDICT: @neon-audit. @test-author Add tests.",
            "@ui-builder Edit src/ui.rs. Review the diff and prefix the result with VERDICT: @neon-audit\n@test-author Add tests.",
            "@ui-builder Edit UI.\nReview the diff and return VERDICT: APPROVED! @neon-audit\n@test-author Add tests.",
            "@ui-builder Edit UI.\nReturn VERDICT: APPROVED. Check edge cases! @neon-audit\n@test-author Add tests.",
        ] {
            let tail_ping_allow = json!({
                "conversationId": sid,
                "transcriptPath": tp.to_string_lossy(),
                "toolCall": {
                    "name": "post_message",
                    "args": {"text": tail_ping}
                }
            });
            assert_eq!(evaluate_pre_tool_use(&tail_ping_allow).0, "allow");
        }

        let _ = fs::remove_dir_all(&root);
    }
}
