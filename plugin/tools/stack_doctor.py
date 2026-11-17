#!/usr/bin/env python3
"""End-to-end health & live Antigravity runtime diagnostics for Gemini Carbon Engineering Stack."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import ssl
import subprocess
import sys
import urllib.request
from typing import Any

HOOKS_DIR = pathlib.Path(__file__).resolve().parent.parent / "hooks"
TOOLS_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HOOKS_DIR))
sys.path.insert(0, str(TOOLS_DIR))

import carbon_memory
import chip_handoff
import code_search
import codex_lane
import cwg_common as cwg
import gate_inbox
import runtime_io as rio
import tokenade_hook


def find_agy_cli() -> str | None:
    return rio.find_agy_cli()


def query_live_ls_plugin(plugin_name: str = "gemini-carbon-stack") -> dict[str, Any]:
    addr = os.environ.get("ANTIGRAVITY_LS_ADDRESS")
    csrf = os.environ.get("ANTIGRAVITY_CSRF_TOKEN")
    if not addr or not csrf:
        return {"connected": False, "reason": "outside_live_ls_env"}

    candidates = [addr] if addr.startswith("http") else [f"http://{addr}", f"https://{addr}"]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    body = None
    last_err = ""
    for base in candidates:
        url = f"{base.rstrip('/')}/exa.language_server_pb.LanguageServerService/GetAllPlugins"
        req = urllib.request.Request(
            url,
            data=b"{}",
            headers={
                "Content-Type": "application/json",
                "Connect-Protocol-Version": "1",
                "x-codeium-csrf-token": csrf,
            },
            method="POST",
        )
        try:
            open_kw = {"context": ctx} if base.startswith("https://") else {}
            with urllib.request.urlopen(req, timeout=5.0, **open_kw) as resp:
                body = json.loads(resp.read().decode("utf-8", errors="replace"))
            break
        except Exception as exc:
            last_err = f"{type(exc).__name__}:{exc}"

    if body is None:
        return {"connected": False, "reason": f"rpc_error:{last_err}"}

    for item in body.get("plugins") or []:
        meta = item.get("plugin") or {}
        name = item.get("name") or meta.get("name") or item.get("id")
        if name == plugin_name:
            plugin_path = item.get("path") or meta.get("path") or ""
            rule_triggers: dict[str, Any] = {}
            for r in item.get("rules") or []:
                if isinstance(r, dict):
                    ps = (r.get("scope") or {}).get("projectScope") or {}
                    raw_path = (
                        ps.get("filePath")
                        or r.get("absolutePath")
                        or r.get("memoryId")
                        or r.get("path")
                        or ""
                    )
                    rname = str(r.get("name") or (pathlib.Path(str(raw_path)).name if raw_path else "") or "?")
                    rule_triggers[rname] = ps.get("trigger") or r.get("trigger") or "unknown"
            return {
                "connected": True,
                "ingested": True,
                "enabled": not bool(item.get("disabled")),
                "skills_count": len(item.get("skills") or []),
                "agents_count": len(item.get("agents") or []),
                "rules_count": len(item.get("rules") or []),
                "rule_triggers": rule_triggers,
                "has_hooks": bool(
                    item.get("hooksJson")
                    or item.get("hooks")
                    or (plugin_path and (pathlib.Path(plugin_path) / "hooks.json").is_file())
                ),
                "errors": item.get("errors") or [],
            }
    return {"connected": True, "ingested": False}


def run_diagnostics(cwd: str = "", compact: bool = False) -> dict[str, Any]:
    installed_dir = pathlib.Path.home() / ".gemini" / "config" / "plugins" / "gemini-carbon-stack"
    bundle_dir = installed_dir if installed_dir.is_dir() else rio.plugin_root()

    plugin_json = rio.read_json(bundle_dir / "plugin.json", default=None)
    hooks_json = rio.read_json(bundle_dir / "hooks.json", default=None)
    skills = sorted(p.parent.name for p in (bundle_dir / "skills").glob("*/SKILL.md")) if (bundle_dir / "skills").is_dir() else []
    agents = sorted(p.stem for p in (bundle_dir / "agents").glob("*.md")) if (bundle_dir / "agents").is_dir() else []
    rules = sorted(p.name for p in (bundle_dir / "rules").glob("*.md")) if (bundle_dir / "rules").is_dir() else []

    agy_bin = find_agy_cli()
    agy_validate_ok = None
    agy_validate_msg = ""
    if agy_bin and bundle_dir.is_dir():
        proc = subprocess.run(
            [agy_bin, "plugin", "validate", str(bundle_dir)],
            timeout=10.0,
            **rio.subprocess_kwargs(),
        )
        agy_validate_ok = proc.returncode == 0
        agy_validate_msg = (
            ((proc.stdout or b"") + b"\n" + (proc.stderr or b"")).decode("utf-8", errors="replace").strip()
        )

    err_log = rio.state_dir("logs") / "hook-errors.jsonl"
    recent_errors = len(rio.read_jsonl(err_log))

    mcp_cfg_path = pathlib.Path.home() / ".gemini" / "config" / "mcp_config.json"
    mcp_cfg = rio.read_json(mcp_cfg_path, default={})
    raw_servers = mcp_cfg.get("mcpServers") if isinstance(mcp_cfg, dict) else None
    mcp_servers = raw_servers if isinstance(raw_servers, dict) else {}
    serena_cfg = mcp_servers.get("serena")
    cli_settings = rio.read_json(pathlib.Path.home() / ".gemini" / "antigravity-cli" / "settings.json", default={})
    token_opt_info = {
        "tokenade_cli": tokenade_hook.find_tokenade_bin(),
        "tokenade_auto_wrap": tokenade_hook.is_auto_wrap_enabled(),
        "ripgrep_cli": code_search.find_rg(),
        "uvx_cli": shutil.which("uvx") or shutil.which("uvx.exe"),
        "mcp_servers": sorted(mcp_servers.keys()),
        "serena_lazy_filtered": bool(
            isinstance(serena_cfg, dict)
            and serena_cfg.get("eager") is False
            and serena_cfg.get("enabledTools")
        ),
        "cli_use_g1_credits_safe": bool(isinstance(cli_settings, dict) and cli_settings.get("useG1Credits") is False),
    }

    mem = carbon_memory.memory_stats(cwd=cwd or os.getcwd())
    codex_info = {
        "binary": codex_lane.find_codex_binary(),
        "breaker": codex_lane.breaker_status(),
    }
    chips_info = chip_handoff.recover_chips()
    handler_sess = gate_inbox.get_handler_session()
    inbox_note = gate_inbox.unresolved_summary(handler_session=handler_sess)
    ls_info = query_live_ls_plugin("gemini-carbon-stack")

    safety_matcher = ""
    if isinstance(hooks_json, dict):
        sg_pre = (hooks_json.get("safety-and-quality-guards") or {}).get("PreToolUse") or []
        if sg_pre and isinstance(sg_pre[0], dict):
            safety_matcher = str(sg_pre[0].get("matcher") or "")
    required_guard_tools = ("read_board", "edit_file", "write_file", "swarm_wait")
    swarm_guards_ok = all(t in safety_matcher for t in required_guard_tools)
    swarm_ctl_ok = (bundle_dir / "tools" / "swarm_ctl.py").is_file()
    swarm_skill_ok = "swarm-orchestration" in skills

    git_check_dir = pathlib.Path(cwd or os.getcwd())
    gitignore_file = git_check_dir / ".gitignore"
    if not gitignore_file.is_file() and (bundle_dir.parent / ".gitignore").is_file():
        gitignore_file = bundle_dir.parent / ".gitignore"
    gitignore_has_swarm = False
    if gitignore_file.is_file():
        try:
            gitignore_has_swarm = ".swarm/" in gitignore_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            pass

    swarm_v2_info = {
        "swarm_ctl": swarm_ctl_ok,
        "swarm_orchestration_skill": swarm_skill_ok,
        "guards_matcher_ok": swarm_guards_ok,
        "fast_path_limits": {"max_files": cwg.FAST_PATH_MAX_FILES, "max_lines": cwg.FAST_PATH_MAX_LINES},
        "cursor_threshold": cwg.BOARD_CURSOR_THRESHOLD,
        "stall_timeout_sec": cwg.swarm_stall_timeout_sec(),
        "gitignore_has_swarm": gitignore_has_swarm,
    }

    ok = bool(
        isinstance(plugin_json, dict)
        and isinstance(hooks_json, dict)
        and len(skills) >= 10
        and len(agents) >= 4
        and len(rules) >= 1
        and swarm_ctl_ok
        and swarm_skill_ok
        and swarm_guards_ok
        and (agy_validate_ok in (True, None))
    )

    report: dict[str, Any] = {
        "ok": ok,
        "installed_in_global_config": installed_dir.is_dir(),
        "bundle_dir": rio.normalize_path(bundle_dir),
        "stack_home": rio.normalize_path(rio.stack_home()),
        "python": sys.version.split()[0],
        "agy_cli": agy_bin,
        "agy_plugin_validate": {"ok": agy_validate_ok, "output": agy_validate_msg},
        "language_server": ls_info,
        "counts": {
            "hook_groups": len(hooks_json or {}),
            "skills": len(skills),
            "agents": len(agents),
            "rules": len(rules),
        },
        "rules": rules,
        "swarm_v2": swarm_v2_info,
        "codex_lane": codex_info,
        "token_optimization": token_opt_info,
        "memory": mem,
        "active_chips": chips_info.get("active_count", 0),
        "gate_anomaly_handler": handler_sess or None,
        "gate_inbox": inbox_note or "clean",
        "logged_hook_errors": recent_errors,
    }
    if not compact or not ok:
        report["skills"] = skills
        report["agents"] = agents
        report["model_routing"] = {
            "pipeline_order": "unittest -> primary review -> simplify once -> batch kill -> --closure",
            "simplify_lenses": {
                "lenses": list(cwg.SIMPLIFY_LENSES),
                "standard_mode": "opt_in single_combined (simplify-reviewer) via .agents/carbon-gate.json",
                "high_xhigh_mode": "fast_path ALL (<=2 files & <=30 lines) else three_parallel_lenses (reuse, quality, efficiency)",
                "primary_model": cwg.SONNET_HIGH_MODEL,
                "fallback_model": cwg.SIMPLIFY_FALLBACK_MODEL,
                "prompt_cache_ttl_seconds": cwg.SWARM_CACHE_SAFE_TTL_SECONDS,
            },
            "external_review": "codex-cli (primary logic review + final --closure)",
            "internal_review": {
                "primary_model": cwg.OPUS_HIGH_MODEL,
                "escalation_model": cwg.CARBON_HIGH_MODEL,
            },
            "auxiliary_hydrogen": {
                "replaces": "gemini-flash (disabled)",
                "models_by_complexity": dict(cwg.HYDROGEN_MODEL_BY_LEVEL),
                "roles": ["browser", "translator", "scout_swarm", "disjoint_builder", "simplify_fallback"],
            },
        }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(prog="stack_doctor")
    parser.add_argument("--cwd", default="")
    parser.add_argument("--compact", action="store_true", help="Omit verbose static listings when healthy")
    parser.add_argument("--pretty", action="store_true", help="Format JSON output with indentation")
    args = parser.parse_args()
    report = run_diagnostics(cwd=args.cwd, compact=bool(args.compact))
    rio.print_cli_json(report, pretty=args.pretty)
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
