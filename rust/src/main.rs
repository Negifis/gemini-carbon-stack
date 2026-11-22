mod carbon_memory;
mod chip_handoff;
mod chip_hooks;
mod claude_importer;
mod code_search;
mod codex_lane;
mod comment_density_guard;
mod continuity_hook;
mod cwg_common;
mod cwg_mark;
mod cwg_pre_invocation;
mod cwg_stop;
mod gate_inbox;
mod hook_dispatch;
mod installer;
mod rio;
mod safety_guards;
mod stack_doctor;
mod swarm_cache;
mod swarm_ctl;
mod win32_sqlite;
mod worktree_guard;

use std::env;
use std::process;

fn print_help() {
    println!(
        concat!(
            "carbon-stack {}\n",
            "Usage: carbon-stack <command> [args...]\n\n",
            "Commands:\n",
            "  install               Install, diagnose, list backups, or rollback the plugin bundle\n",
            "  hook                  Unified Antigravity hook dispatcher (--event <Event>)\n",
            "  continuity            Session continuity ledger and resume directives\n",
            "  codex-lane            External Codex adversarial review lane and status\n",
            "  gate-inbox            Code Work Gate anomaly inbox (report/list/show/resolve)\n",
            "  swarm-cache           Swarm shared context snapshot cache\n",
            "  swarm-ctl             Swarm worker lifecycle and worktree control\n",
            "  worktree-guard        Safe git worktree audit, snapshot, removal, and link unlinking\n",
            "  carbon-memory         Local project memory store (recall/remember/sync)\n",
            "  chip-handoff          Autonomous chip task handoff cards and trees\n",
            "  code-search           Fast code search helpers\n",
            "  stack-doctor          Inspect plugin health, MCP configs, hooks, and tooling\n",
            "  claude-chat-importer  Import Claude Code chat history into Antigravity\n",
            "  --version, version    Print version and exit\n",
            "  --help, -h, help      Show this help message and exit\n\n",
            "Internal hook entrypoints:\n",
            "  safety-guards, comment-density-guard, chip-hooks,\n",
            "  cwg-pre-invocation, cwg-mark, cwg-stop\n\n",
            "Run 'carbon-stack <command> --help' for command-specific options."
        ),
        env!("CARGO_PKG_VERSION")
    );
}

fn main() {
    let all_args: Vec<String> = env::args().collect();
    if all_args.len() < 2 {
        eprintln!(
            "usage: carbon-stack <install|hook|safety-guards|comment-density-guard|continuity|chip-hooks|cwg-pre-invocation|cwg-mark|cwg-stop|codex-lane|gate-inbox|swarm-cache|swarm-ctl|worktree-guard|carbon-memory|chip-handoff|code-search|stack-doctor|claude-chat-importer|--version|--help> [args...]"
        );
        process::exit(2);
    }
    let sub = all_args[1].as_str();
    let rest = &all_args[2..];
    let code = match sub {
        "--help" | "-h" | "help" => {
            print_help();
            0
        }
        "--version" | "version" => {
            println!("carbon-stack {}", env!("CARGO_PKG_VERSION"));
            0
        }
        "install" => installer::run_cli(rest),
        "hook" => hook_dispatch::run_unified_hook(rest),
        "safety-guards" | "safety_guards" => safety_guards::run_cli(rest),
        "comment-density-guard" | "comment_density_guard" => comment_density_guard::run_cli(rest),
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
