#!/usr/bin/env python3
"""End-to-end health & live Antigravity runtime diagnostics for Gemini Carbon Engineering Stack."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
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
import codex_lane
import cwg_common as cwg
import gate_inbox
import runtime_io as rio


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
            return {
                "connected": True,
                "ingested": True,
                "enabled": not bool(item.get("disabled")),
                "skills_count": len(item.get("skills") or []),
                "agents_count": len(item.get("agents") or []),
                "rules_count": len(item.get("rules") or []),
                "has_hooks": bool(
                    item.get("hooksJson")
                    or item.get("hooks")
                    or (plugin_path and (pathlib.Path(plugin_path) / "hooks.json").is_file())
                ),
                "errors": item.get("errors") or [],
            }
    return {"connected": True, "ingested": False}


def run_diagnostics(cwd: str = "") -> dict[str, Any]:
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
            ((proc.stdout or b"") + b"\n" + (proc.stderr or b"")).decode("utf-8", errors="replace").strip()[:300]
        )

    err_log = rio.state_dir("logs") / "hook-errors.jsonl"
    recent_errors = len(rio.read_jsonl(err_log))

    mem = carbon_memory.memory_stats(cwd=cwd or os.getcwd())
    codex_info = {
        "binary": codex_lane.find_codex_binary(),
        "breaker": codex_lane.breaker_status(),
    }
    chips_info = chip_handoff.recover_chips()
    inbox_note = gate_inbox.unresolved_summary()
    ls_info = query_live_ls_plugin("gemini-carbon-stack")

    ok = bool(
        isinstance(plugin_json, dict)
        and isinstance(hooks_json, dict)
        and len(skills) >= 10
        and len(agents) >= 4
        and len(rules) >= 1
        and (agy_validate_ok in (True, None))
    )

    return {
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
        "skills": skills,
        "agents": agents,
        "rules": rules,
        "model_routing": {
            "simplify_lenses": {
                "lenses": list(cwg.SIMPLIFY_LENSES),
                "primary_model": cwg.SONNET_HIGH_MODEL,
                "fallback_model": cwg.CARBON_HIGH_MODEL,
            },
            "external_review": "codex-cli (unchanged)",
            "internal_review": {
                "primary_model": cwg.OPUS_HIGH_MODEL,
                "escalation_model": cwg.CARBON_HIGH_MODEL,
            },
        },
        "progress_transparency": {
            "channel": "PLANNER_RESPONSE.content + PreInvocation continuity guard",
            "swarm_sidecar_uri": "sidecar://swarm/swarm_board/?auto_open=false",
        },
        "codex_lane": codex_info,
        "memory": mem,
        "active_chips": chips_info.get("active_count", 0),
        "gate_inbox": inbox_note or "clean",
        "logged_hook_errors": recent_errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="stack_doctor")
    parser.add_argument("--cwd", default="")
    args = parser.parse_args()
    report = run_diagnostics(cwd=args.cwd)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
