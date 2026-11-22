use regex::Regex;
use serde_json::{json, Map, Value};
use std::{collections::HashMap, env, fs, path::Path, sync::OnceLock};
use crate::{cwg_common, rio::{self, val_to_str}};

macro_rules! re { ($p:expr) => {{ static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| Regex::new($p).expect("re")) }}; }

fn token_for(raw: &str) -> Option<&'static str> {
    let f = Path::new(raw).file_name()?.to_str()?.to_ascii_lowercase();
    if matches!(f.as_str(), "dockerfile" | "makefile" | "vagrantfile" | "gemfile" | "rakefile" | "brewfile" | "justfile" | "caddyfile" | "procfile") { return Some("#"); }
    if f == "jenkinsfile" { return Some("//"); }
    let e = format!(" {} ", match f.rfind('.') { Some(i) if i > 0 => &f[i..], _ if f.starts_with('.') => f.as_str(), _ => return None });
    [("#", " .py .pyi .sh .bash .zsh .fish .rb .pl .r .jl .toml .yaml .yml .ini .conf .cfg .tf .tfvars .hcl .nix .ps1 .psm1 .psd1 .mk .properties .service .env .rc .gitignore .dockerignore .editorconfig .cmake "),
     ("//", " .js .mjs .cjs .jsx .ts .tsx .mts .cts .go .rs .java .c .h .cpp .hpp .cxx .hxx .cc .cs .kt .kts .swift .scala .php .dart .proto .groovy .gradle .sol .zig .v .json5 .jsonc .glsl .hlsl .ino .pde .bsl "),
     ("--", " .sql .lua .hs .elm .adb .ads .vhd .vhdl "),
     (";", " .el .lisp .clj .cljs .cljc .scm .asm .s .reg .nsi ")].into_iter().find_map(|(t, s)| s.contains(&e).then_some(t))
}
fn fstr(v: &Value, keys: &[&str]) -> String { val_to_str(keys.iter().find_map(|k| v.get(*k))) }
fn classify(lines: &[String], tok: &str) -> Vec<u8> {
    let (mut out, mut blk, mut trip, lb) = (Vec::with_capacity(lines.len()), 0u8, None::<&'static str>, lines.iter().rposition(|x| x.contains("*/")));
    let dir = re!(r"(?i)^!|^\s*-\*-|\b(?:type:\s*ignore|noqa|pylint:|pyright:|mypy:|ruff:|flake8:|fmt:\s*(?:on|off)|isort:|nosec|bandit|pragma|eslint|prettier|tslint:|biome-ignore|istanbul ignore|c8 ignore|v8 ignore|jshint|jslint|globals\s|deno-lint-ignore|stylelint|codespell|cspell|spell-checker|sourceMappingURL|go:generate|go:build|go:embed|go:linkname|\+build|nolint|golangci|shellcheck|hadolint|checkstyle|swiftlint|ktlint|rubocop|frozen_string_literal|encoding:|vim:|emacs:|region\b|endregion\b|@ts-(?:ignore|expect-error|nocheck)|@flow|@jsx|@license|@preserve|#include|#define|#if|#endif)");
    for (idx, raw) in lines.iter().enumerate() {
        let l = raw.trim();
        if let Some(m) = trip { out.push(2); if l.contains(m) { trip = None; } continue; }
        if blk != 0 { out.push(if blk == 1 { 1 } else { 2 }); if l.contains("*/") { blk = 0; } continue; }
        if l.is_empty() { out.push(2); continue; }
        if tok == "#" && (l.starts_with("\"\"\"") || l.starts_with("'''")) {
            let m = if l.starts_with("\"\"\"") { "\"\"\"" } else { "'''" };
            if !l[3..].contains(m) && lines[idx + 1..].iter().any(|x| x.contains(m)) { trip = Some(m); }
            out.push(2); continue;
        }
        if tok == "//" && l.starts_with("/*") {
            let k = if l.starts_with("/**") { 2 } else { 1 };
            if !l[2..].contains("*/") && lb.is_some_and(|m| idx < m) { blk = k; }
            out.push(k); continue;
        }
        if tok == "//" && (l.starts_with("///") || l.starts_with("//!")) { out.push(2); continue; }
        if let Some(a) = l.strip_prefix(tok) { out.push(if dir.is_match(a) { 2 } else { 1 }); continue; }
        out.push(0);
    }
    out
}
fn added_lines(old: &str, new: &str) -> Vec<String> {
    let mut pool: HashMap<&str, usize> = HashMap::new();
    for l in old.lines() { *pool.entry(l.trim()).or_insert(0) += 1; }
    new.lines().filter(|l| match pool.get_mut(l.trim()).filter(|c| **c > 0) { Some(c) => { *c -= 1; false } None => true }).map(str::to_string).collect()
}
fn collect_added_lines(tool: &str, args: &Value, p: &str) -> Option<Vec<String>> {
    match tool {
        "write_file" | "write_to_file" | "write" => {
            let old = match fs::read_to_string(Path::new(p)) { Ok(s) => s, Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(), Err(_) => return None };
            Some(added_lines(&old, &fstr(args, &["Content", "CodeContent", "content"])))
        }
        "multi_replace_file_content" | "multiedit" => Some(args.get("ReplacementChunks").or_else(|| args.get("edits")).and_then(|v| v.as_array()).into_iter().flatten().flat_map(|c| added_lines(&fstr(c, &["TargetContent", "old_string"]), &fstr(c, &["ReplacementContent", "new_string"]))).collect()),
        "edit_file" | "edit" | "replace_file_content" => Some(added_lines(&fstr(args, &["Target", "TargetContent", "old_string"]), &fstr(args, &["Replacement", "ReplacementContent", "new_string"]))),
        _ => None,
    }
}
fn inspect(lines: &[String], tok: &str) -> Option<String> {
    let kinds = classify(lines, tok);
    let code = kinds.iter().filter(|&&k| k == 0).count();
    let nh = re!(r"(?i)\b(?:we|i) (?:tried|attempted|discovered|initially|switched|decided|realised|realized)\b|\bthe user (?:asked|wanted|requested) (?:for )?(?:this|us|me)\b|\bin (?:this|the previous|the last) (?:session|conversation|turn)\b|\bas (?:discussed|mentioned|noted) (?:above|earlier|before)\b|\bbefore (?:this|the) (?:change|fix|patch)\s*[,:;]|\b(?:our|my) (?:first|second|third) attempt\b|^(?:our |my )?(?:first|second|third) attempt (?:failed|was wrong|didn't|did not)\b|\brejected (?:this|that|the) (?:approach|option|alternative|idea)\b|\bafter (?:much|hours|days|several|some)\b.{0,20}\b(?:debugging|investigation|digging|attempts|tries|testing)\b|^(?:background|history)\s*:|\bпользовател[ья] (?:просил|попросил|хотел) (?:это|этого|об этом|нас|меня)\b|\bмы (?:пробовали|решили|выяснили)\b");
    let bp = re!(r"(?i)^\s*[*\-]?\s*(?:licen[sc]e|copyright|spdx-[a-z-]+|@generated|code generated by|do not edit|autogenerated|generated by|@license|@preserve)\b");
    let tg = re!(r"(?i)^\s*[*\-]?\s*(?:safety|security|invariant|workaround|compat|compatibility|algorithm)\b");
    let er = re!(r"(?i)https?://|\bCVE-\d{4}-\d+|\bRFC\s?\d{3,}|\b(?:bug|issue|ticket|pr)\s*#?\d{2,}\b|\b[a-z][\w.-]*#\d{2,}\b|\b(?:upstream|vendor|kernel|firmware|driver|browser)\b.{0,40}\b(?:bug|issue|defect|regression|limitation|quirk)\b");
    let ns = re!(r"(?i)^previously\b|\bpreviously[,: ]+(?:this|it|we|i|the code|the implementation|the config|the default|the value)\b|\bused to be\b|\bturned out\b|\bthis (?:was|used to be) an? (?:bug|hack|workaround)\b|\bthe (?:root )?cause (?:was|turned out)\b|\b(?:postmortem|post-mortem)\b|\b(?:раньше|ранее|изначально)\s+(?:тут|здесь|это|мы|был|было|была|были|стоял|стояло|стояла|использовал|работал|делал)\w*\b|\b(?:оказалось|выяснилось)\b");
    let narr = |r: &[&str], rx: &Regex| r.iter().find(|t| rx.is_match(t)).map(|t| format!("the conversation leaking into a comment: {}", t.char_indices().nth(90).map_or(*t, |(i, _)| &t[..i])));
    let (mut cur, mut la, mut cnt, mut lp) = (Vec::new(), 0usize, 0usize, 0usize);
    let mut step = |r: &mut Vec<&str>| -> Option<String> {
        if r.is_empty() { return None; }
        let n = r.len();
        if let Some(h) = narr(r, nh) { return Some(h); }
        if !bp.is_match(r[0]) {
            let decl = tg.is_match(r[0]) || er.is_match(&r.join(" "));
            if !decl { if let Some(h) = narr(r, ns) { return Some(h); } cnt += n; lp = lp.max(n); }
            la = la.max(n);
        }
        r.clear(); None
    };
    for (l, k) in lines.iter().zip(&kinds) {
        if *k == 1 { cur.push(l.trim().trim_start_matches(['*', '/', '#', '-', ';', ' ']).trim()); }
        else if let Some(h) = step(&mut cur) { return Some(h); }
    }
    if let Some(h) = step(&mut cur) { return Some(h); }
    let run_err = |n| format!("an unbroken {}-line comment run against {} added code lines", n, code);
    if la >= 10 && code <= 2 { return Some(run_err(la)); }
    if cnt >= 5 && cnt > 3 * code { return Some(format!("{} added comment lines against {} added code lines", cnt, code)); }
    (lp >= 8 && code <= 2).then(|| run_err(lp))
}
pub fn evaluate_pre_tool_use(payload: &Value) -> (String, Option<String>) {
    if ["CARBON_COMMENT_GUARD", "CLAUDE_COMMENT_GUARD"].iter().any(|k| env::var(k).ok().is_some_and(|v| { let s = v.trim(); s == "0" || s.eq_ignore_ascii_case("off") || s.eq_ignore_ascii_case("false") })) { return ("allow".into(), None); }
    let tc = payload.get("toolCall").and_then(|v| v.as_object());
    let tool = tc.and_then(|m| m.get("name")).and_then(|v| v.as_str()).unwrap_or("").trim().to_ascii_lowercase();
    let args = tc.and_then(|m| m.get("args")).cloned().unwrap_or_else(|| json!({}));
    let tp = fstr(&args, &["Path", "TargetFile", "FilePath", "AbsolutePath", "path", "file_path", "target_file"]).trim().to_string();
    if tp.is_empty() || re!(r"(?i)(?:^|[\\/])(node_modules|vendor|\.git|dist|build|out|target|\.venv|venv|site-packages|__pycache__|\.next|\.nuxt|coverage|third_party)(?:[\\/]|$)").is_match(&tp) || re!(r"(?i)\.(?:min|bundle|generated|g|pb|lock)\.[a-z0-9]+$|_pb2\.py$").is_match(&tp) { return ("allow".into(), None); }
    let Some(tok) = token_for(&tp) else { return ("allow".into(), None); };
    let Some(lines) = collect_added_lines(&tool, &args, &tp).filter(|l| !l.is_empty()) else { return ("allow".into(), None); };
    let Some(detail) = inspect(&lines, tok) else { return ("allow".into(), None); };
    let base = Path::new(&tp).file_name().and_then(|s| s.to_str()).unwrap_or(&tp);
    let rsn = format!(
        "[Comment guard] This edit to {} was not applied — {}.\nRebuild it dense instead of resubmitting it:\n- keep only what the code cannot hold — rationale, invariant, constraint, hazard, the reason a future reader would otherwise revert this;\n- drop investigation history, attempts, rejected options, \"used to be X\", restatements of the task, the ticket or the diff — the file must read as if the answer was known from the start;\n- an obvious change gets no comment; a non-obvious one usually gets one line.\nIf the long form is genuinely load-bearing, open the first line with the category it belongs to — SAFETY:, SECURITY:, WORKAROUND:, INVARIANT:, COMPAT:, ALGORITHM:, LICENSE: or @generated — or cite the source it rests on (URL, CVE, RFC, tracker id), and keep every line load-bearing.",
        base, detail
    );
    let sess = rio::session_key(payload);
    let d = cwg_common::gate_dir().join("comment_strikes");
    let _ = fs::create_dir_all(&d);
    let store = d.join(format!("{}.json", rio::safe_key(&sess, "default")));
    let mut data = match rio::read_json(&store) { Some(Value::Object(m)) => m, _ => Map::new() };
    let k = rio::fold_path(&rio::normalize_path(&tp));
    let n = data.get(&k).and_then(|v| v.as_u64()).unwrap_or(0) + 1;
    data.insert(k, json!(n));
    let n = if rio::write_json(&store, &Value::Object(data)).is_err() { 3 } else { n };
    if n > 2 {
        cwg_common::queue_pending_note(&sess, &format!("{}\n(Strike budget for this file is spent — applied anyway. Make it dense before you finish.)", rsn));
        rio::log_hook_event("hygiene-events", "comment_density_give_up", json!({"session": sess, "path": tp, "strikes": n, "detail": detail}));
        return ("allow".into(), None);
    }
    rio::log_hook_event("hygiene-events", "comment_density_block", json!({"session": sess, "path": tp, "strikes": n, "detail": detail}));
    ("deny".into(), Some(rsn))
}

pub fn run_cli(_args: &[String]) -> i32 {
    match rio::read_hook_stdin() {
        Ok(payload) => { let (d, r) = evaluate_pre_tool_use(&payload); rio::emit_pre_tool(&d, r.as_deref(), None); }
        Err(err) => { rio::log_hook_event("hook-errors", "stdin_error", json!({"hook": "comment_density_guard", "error": err})); rio::emit_pre_tool("allow", None, None); }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::win32_sqlite::TEST_ENV_LOCK;

    struct EnvGuard {
        prev_home: Option<std::ffi::OsString>,
        prev_off: Option<std::ffi::OsString>,
        prev_claude_off: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn enter(dir: &Path) -> Self {
            let _ = fs::create_dir_all(dir);
            let prev_home = env::var_os("CARBON_STACK_HOME");
            let prev_off = env::var_os("CARBON_COMMENT_GUARD");
            let prev_claude_off = env::var_os("CLAUDE_COMMENT_GUARD");
            unsafe {
                env::set_var("CARBON_STACK_HOME", dir);
                env::remove_var("CARBON_COMMENT_GUARD");
                env::remove_var("CLAUDE_COMMENT_GUARD");
            }
            Self {
                prev_home,
                prev_off,
                prev_claude_off,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                match self.prev_home.take() {
                    Some(v) => env::set_var("CARBON_STACK_HOME", v),
                    None => env::remove_var("CARBON_STACK_HOME"),
                }
                match self.prev_off.take() {
                    Some(v) => env::set_var("CARBON_COMMENT_GUARD", v),
                    None => env::remove_var("CARBON_COMMENT_GUARD"),
                }
                match self.prev_claude_off.take() {
                    Some(v) => env::set_var("CLAUDE_COMMENT_GUARD", v),
                    None => env::remove_var("CLAUDE_COMMENT_GUARD"),
                }
            }
        }
    }

    #[test]
    fn test_bloat_and_two_strike_give_up() {
        let _lock = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = env::temp_dir().join(format!("cg-bloat-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let _env = EnvGuard::enter(&dir);

        let bloated = [
            "// load config",
            "// check env",
            "// parse args",
            "// build path",
            "// return value",
            "let x = 1;",
        ]
        .join("\n");
        let payload = json!({
            "conversationId": "cg-bloat-1",
            "toolCall": {
                "name": "edit_file",
                "args": {
                    "Path": "src/app.rs",
                    "Target": "let x = 0;",
                    "Replacement": bloated,
                }
            }
        });

        let (d1, r1) = evaluate_pre_tool_use(&payload);
        assert_eq!(d1, "deny");
        assert!(r1.unwrap().contains("5 added comment lines against 1 added code lines"));

        let (d2, r2) = evaluate_pre_tool_use(&payload);
        assert_eq!(d2, "deny");
        assert!(r2.unwrap().contains("[Comment guard]"));

        let (d3, r3) = evaluate_pre_tool_use(&payload);
        assert_eq!(d3, "allow");
        assert!(r3.is_none());
        let notes = cwg_common::pop_pending_notes("cg-bloat-1");
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("Strike budget for this file is spent"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_block_runs_narration_write_diff_and_docstring_skip() {
        let _lock = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = env::temp_dir().join(format!("cg-rules-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let _env = EnvGuard::enter(&dir);

        // Plain 8-line unbroken run with <=2 code lines triggers BLOCK; 3+ code lines passes.
        let run8_low_code = (0..8)
            .map(|i| format!("// plain {}", i))
            .chain(["let a = 1;".into(), "let b = 2;".into()])
            .collect::<Vec<_>>()
            .join("\n");
        let block8 = json!({
            "conversationId": "cg-rules-1",
            "toolCall": {
                "name": "edit_file",
                "args": {"Path": "src/a.rs", "Target": "old", "Replacement": run8_low_code}
            }
        });
        let (db8, rb8) = evaluate_pre_tool_use(&block8);
        assert_eq!(db8, "deny");
        assert!(rb8.unwrap().contains("8 added comment lines against 2 added code lines"));

        let run8_high_code = (0..8)
            .map(|i| format!("// plain {}", i))
            .chain(["let a=1;".into(), "let b=2;".into(), "let c=3;".into()])
            .collect::<Vec<_>>()
            .join("\n");
        let allow8 = json!({
            "conversationId": "cg-rules-1",
            "toolCall": {
                "name": "edit_file",
                "args": {"Path": "src/a_ok.rs", "Target": "old", "Replacement": run8_high_code}
            }
        });
        assert_eq!(evaluate_pre_tool_use(&allow8).0, "allow");

        // Declared 10-line unbroken run with <=2 code lines triggers BLOCK even with INVARIANT:.
        let run10_decl = std::iter::once("// INVARIANT: important lock order".to_string())
            .chain((1..10).map(|i| format!("// detail {}", i)))
            .chain(["lock_a();".into(), "lock_b();".into()])
            .collect::<Vec<_>>()
            .join("\n");
        let block10 = json!({
            "conversationId": "cg-rules-1",
            "toolCall": {
                "name": "edit_file",
                "args": {"Path": "src/b.rs", "Target": "old", "Replacement": run10_decl}
            }
        });
        assert_eq!(evaluate_pre_tool_use(&block10).0, "deny");

        // NARRATION_HARD fails even inside an INVARIANT: run.
        let hard_in_inv = json!({
            "conversationId": "cg-rules-1",
            "toolCall": {
                "name": "edit_file",
                "args": {
                    "Path": "src/c.rs",
                    "Target": "old",
                    "Replacement": "// INVARIANT: lock first\n// we tried switching this twice earlier\nlet x = 1;"
                }
            }
        });
        let (dh, rh) = evaluate_pre_tool_use(&hard_in_inv);
        assert_eq!(dh, "deny");
        assert!(rh.unwrap().contains("leaking into a comment"));

        // NARRATION_SOFT fails bare, passes under WORKAROUND: or URL.
        let soft_bare = json!({
            "conversationId": "cg-rules-1",
            "toolCall": {
                "name": "edit_file",
                "args": {
                    "Path": "src/d_bare.rs",
                    "Target": "old",
                    "Replacement": "// previously this used a mutex\nlet x = 1;"
                }
            }
        });
        assert_eq!(evaluate_pre_tool_use(&soft_bare).0, "deny");

        let soft_decl = json!({
            "conversationId": "cg-rules-1",
            "toolCall": {
                "name": "edit_file",
                "args": {
                    "Path": "src/d_ok.rs",
                    "Target": "old",
                    "Replacement": "// WORKAROUND: bug in driver v2\n// previously this used a mutex\nlet x = 1;"
                }
            }
        });
        assert_eq!(evaluate_pre_tool_use(&soft_decl).0, "allow");

        // `write_file` diffs against existing file on disk so untouched existing comments do not trip.
        let existing_rs = dir.join("existing.rs");
        let old_comments = (0..6)
            .map(|i| format!("// old comment {}", i))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&existing_rs, format!("{}\nfn keep() {{}}\n", old_comments)).unwrap();
        let write_diff_ok = json!({
            "conversationId": "cg-rules-1",
            "toolCall": {
                "name": "write_file",
                "args": {
                    "Path": existing_rs.to_string_lossy(),
                    "Content": format!("{}\n    fn keep() {{}}\nlet y = 2;\n", old_comments)
                }
            }
        });
        assert_eq!(evaluate_pre_tool_use(&write_diff_ok).0, "allow");

        // Python triple-quoted docstrings & JS JSDoc blocks are skipped.
        let py_doc = json!({
            "conversationId": "cg-rules-1",
            "toolCall": {
                "name": "edit_file",
                "args": {
                    "Path": "src/mod.py",
                    "Target": "pass",
                    "Replacement": "\"\"\"\nLine 1\nLine 2\nLine 3\nLine 4\nLine 5\n\"\"\"\ndef f(): return 1\n"
                }
            }
        });
        assert_eq!(evaluate_pre_tool_use(&py_doc).0, "allow");

        let js_doc = json!({
            "conversationId": "cg-rules-1",
            "toolCall": {
                "name": "edit_file",
                "args": {
                    "Path": "src/mod.ts",
                    "Target": "old",
                    "Replacement": "/**\n * One\n * Two\n * Three\n * Four\n * Five\n */\nexport const v = 1;\n"
                }
            }
        });
        assert_eq!(evaluate_pre_tool_use(&js_doc).0, "allow");

        let _ = fs::remove_dir_all(&dir);
    }
}
