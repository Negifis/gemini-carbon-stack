pub mod carbon_memory;
pub mod chip_handoff;
pub mod chip_hooks;
pub mod claude_importer;
pub mod code_search;
pub mod codex_lane;
pub mod continuity_hook;
pub mod cwg_common;
pub mod cwg_mark;
pub mod cwg_pre_invocation;
pub mod cwg_stop;
pub mod gate_inbox;
pub mod hook_dispatch;
pub mod installer;
pub mod rio;
pub mod safety_guards;
pub mod stack_doctor;
pub mod swarm_cache;
pub mod swarm_ctl;
pub mod tokenade_hook;
pub mod win32_sqlite;
pub mod worktree_guard;

use std::env;
use std::process;

fn main() {
    let all_args: Vec<String> = env::args().collect();
    if all_args.len() < 2 {
        eprintln!(
            "usage: carbon-stack <install|hook|safety-guards|tokenade-hook|continuity|chip-hooks|cwg-pre-invocation|cwg-mark|cwg-stop|codex-lane|gate-inbox|swarm-cache|swarm-ctl|worktree-guard|carbon-memory|chip-handoff|code-search|stack-doctor|claude-chat-importer|--version> [args...]"
        );
        process::exit(2);
    }
    let sub = all_args[1].as_str();
    let rest = &all_args[2..];
    let code = match sub {
        "--version" | "version" => {
            println!("carbon-stack {}", env!("CARGO_PKG_VERSION"));
            0
        }
        "install" => installer::run_cli(rest),
        "hook" => hook_dispatch::run_unified_hook(rest),
        "safety-guards" | "safety_guards" => safety_guards::run_cli(rest),
        "tokenade-hook" | "tokenade_hook" => tokenade_hook::run_cli(rest),
        "continuity" => continuity_hook::run_cli(rest),
        "chip-hooks" | "chip_hooks" => chip_hooks::run_cli(rest),
        "cwg-pre-invocation" | "cwg_pre_invocation" => cwg_pre_invocation::run_cli(rest),
        "cwg-mark" | "cwg_mark" => cwg_mark::run_cli(rest),
        "cwg-stop" | "cwg_stop" => cwg_stop::run_cli(rest),
        "codex-lane" | "codex_lane" => codex_lane::run_cli(rest),
        "gate-inbox" | "gate_inbox" => gate_inbox::run_cli(rest),
        "swarm-cache" | "swarm_cache" => swarm_cache::run_cli(rest),
        "swarm-ctl" | "swarm_ctl" => swarm_ctl::run_cli(rest),
        "worktree-guard" | "worktree_guard" => worktree_guard::run_cli(rest),
        "carbon-memory" | "carbon_memory" => carbon_memory::run_cli(rest),
        "chip-handoff" | "chip_handoff" => chip_handoff::run_cli(rest),
        "code-search" | "code_search" => code_search::run_cli(rest),
        "stack-doctor" | "stack_doctor" => stack_doctor::run_cli(rest),
        "claude-chat-importer" | "claude_chat_importer" => claude_importer::run_cli(rest),
        other => {
            eprintln!("carbon-stack: unknown subcommand '{}'", other);
            2
        }
    };
    process::exit(code);
}
