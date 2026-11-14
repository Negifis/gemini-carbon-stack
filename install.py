#!/usr/bin/env python3
"""Safe, idempotent installer, verifier, and rollback manager for Gemini Carbon Engineering Stack."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
from typing import Any

REPO_ROOT = pathlib.Path(__file__).resolve().parent
SOURCE_PLUGIN_DIR = REPO_ROOT / "plugin"
SOURCE_GLOB_RULE = REPO_ROOT / "rules" / "uiux-design.md"
PLUGIN_NAME = "gemini-carbon-stack"

SKIP_NAMES = frozenset({"__pycache__", ".pyc", ".pyo", ".DS_Store"})


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def tree_manifest(root: pathlib.Path) -> dict[str, str]:
    if not root.is_dir():
        return {}
    out: dict[str, str] = {}
    for p in sorted(root.rglob("*")):
        if any(part in SKIP_NAMES or part.endswith((".pyc", ".pyo")) for part in p.parts):
            continue
        if p.is_file():
            rel = p.relative_to(root).as_posix()
            out[rel] = sha256_file(p)
    return out


def is_link_or_junction(path: pathlib.Path) -> bool:
    try:
        if path.is_symlink():
            return True
        fn = getattr(os.path, "isjunction", None)
        if callable(fn) and fn(str(path)):
            return True
    except OSError:
        pass
    return False


def find_agy_cli() -> str | None:
    on_path = shutil.which("agy") or shutil.which("agy.exe")
    if on_path:
        return on_path
    win_default = pathlib.Path.home() / "AppData" / "Local" / "agy" / "bin" / "agy.exe"
    return str(win_default) if win_default.is_file() else None


def resolve_paths(config_dir_arg: str = "", stack_home_arg: str = "") -> tuple[pathlib.Path, pathlib.Path]:
    cfg = (
        pathlib.Path(config_dir_arg).resolve()
        if config_dir_arg
        else (pathlib.Path.home() / ".gemini" / "config")
    )
    shome = (
        pathlib.Path(stack_home_arg).resolve()
        if stack_home_arg
        else pathlib.Path(os.environ.get("CARBON_STACK_HOME") or (pathlib.Path.home() / ".gemini" / "carbon-stack"))
    )
    return cfg, shome


def preflight_check(config_dir: pathlib.Path) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []

    if sys.version_info < (3, 10):
        errors.append(f"Python >= 3.10 required, found {sys.version.split()[0]}")

    for required in (
        SOURCE_PLUGIN_DIR / "plugin.json",
        SOURCE_PLUGIN_DIR / "hooks.json",
        SOURCE_PLUGIN_DIR / "rules" / "AGENTS.md",
        SOURCE_GLOB_RULE,
    ):
        if not required.is_file():
            errors.append(f"Missing required source file: {required}")
        elif required.suffix == ".json":
            try:
                json.loads(required.read_text(encoding="utf-8"))
            except Exception as exc:
                errors.append(f"Invalid JSON in {required}: {exc}")

    target_plugin_dir = config_dir / "plugins" / PLUGIN_NAME
    target_glob_rule = config_dir / "rules" / "uiux-design.md"

    for t in (config_dir, target_plugin_dir, target_glob_rule):
        if t.exists() and is_link_or_junction(t):
            errors.append(f"Refusing to overwrite symlink/junction target: {t}")

    # Ensure we never touch ~/.claude or ~/.gemini/config/config.json
    user_cfg_json = config_dir / "config.json"
    agy_bin = find_agy_cli()
    agy_validation: dict[str, Any] = {"ran": False, "ok": True, "output": ""}
    if agy_bin and not errors:
        kw: dict[str, Any] = {"stdin": subprocess.DEVNULL, "capture_output": True, "timeout": 12.0}
        if os.name == "nt":
            kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        proc = subprocess.run([agy_bin, "plugin", "validate", str(SOURCE_PLUGIN_DIR)], **kw)
        out = (((proc.stdout or b"") + b"\n" + (proc.stderr or b"")).decode("utf-8", errors="replace")).strip()
        agy_validation = {"ran": True, "ok": proc.returncode == 0, "output": out[:400]}
        if proc.returncode != 0:
            errors.append(f"`agy plugin validate` failed: {out[:240]}")
    elif not agy_bin:
        warnings.append("`agy` CLI binary not found on PATH; skipped `agy plugin validate`.")

    return {
        "ok": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "config_dir": str(config_dir),
        "user_config_json_untouched": user_cfg_json.exists(),
        "agy_cli": agy_bin,
        "agy_validation": agy_validation,
    }


def copy_clean_tree(src: pathlib.Path, dst: pathlib.Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        src,
        dst,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", ".DS_Store"),
    )


def create_backup(config_dir: pathlib.Path, stack_home: pathlib.Path) -> dict[str, Any]:
    backups_root = stack_home / "backups"
    backups_root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")[:20]
    backup_id = f"install-{stamp}"
    bdir = backups_root / backup_id
    bdir.mkdir(parents=True, exist_ok=False)

    target_plugin_dir = config_dir / "plugins" / PLUGIN_NAME
    target_glob_rule = config_dir / "rules" / "uiux-design.md"

    manifest: dict[str, Any] = {
        "backup_id": backup_id,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "config_dir": str(config_dir),
        "targets": {
            "plugin_dir": {
                "path": str(target_plugin_dir),
                "existed": target_plugin_dir.is_dir(),
            },
            "glob_rule": {
                "path": str(target_glob_rule),
                "existed": target_glob_rule.is_file(),
            },
        },
    }

    if target_plugin_dir.is_dir():
        copy_clean_tree(target_plugin_dir, bdir / "plugin_dir")
    if target_glob_rule.is_file():
        (bdir / "rules").mkdir(parents=True, exist_ok=True)
        shutil.copy2(target_glob_rule, bdir / "rules" / "uiux-design.md")

    # Foreign unmanaged custom rule check: never silently clobber a non-Carbon uiux-design.md without recording
    if target_glob_rule.is_file():
        existing_txt = target_glob_rule.read_text(encoding="utf-8", errors="replace")
        if "Frontend UI/UX & Live Browser Verification Rules" not in existing_txt:
            manifest["targets"]["glob_rule"]["was_foreign_user_file"] = True

    (bdir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest


def perform_install(
    config_dir: pathlib.Path,
    stack_home: pathlib.Path,
    dry_run: bool = False,
    force_foreign: bool = False,
) -> dict[str, Any]:
    pf = preflight_check(config_dir)
    if not pf["ok"]:
        return {"ok": False, "stage": "preflight", "preflight": pf}

    target_plugin_dir = config_dir / "plugins" / PLUGIN_NAME
    target_glob_rule = config_dir / "rules" / "uiux-design.md"

    # Protect foreign user file unless --force-foreign
    if target_glob_rule.is_file() and not force_foreign:
        txt = target_glob_rule.read_text(encoding="utf-8", errors="replace")
        if "Frontend UI/UX & Live Browser Verification Rules" not in txt:
            return {
                "ok": False,
                "stage": "conflict_check",
                "error": f"Existing user file {target_glob_rule} was not created by Gemini Carbon Stack. Refusing blind overwrite (pass --force-foreign to replace after backup).",
            }

    src_manifest = tree_manifest(SOURCE_PLUGIN_DIR)
    dst_manifest = tree_manifest(target_plugin_dir)
    src_rule_sha = sha256_file(SOURCE_GLOB_RULE)
    dst_rule_sha = sha256_file(target_glob_rule) if target_glob_rule.is_file() else ""

    plugin_identical = src_manifest == dst_manifest and bool(dst_manifest)
    rule_identical = src_rule_sha == dst_rule_sha

    planned_actions: list[str] = []
    if not plugin_identical:
        planned_actions.append(
            f"{'update' if target_plugin_dir.exists() else 'install'} plugin bundle -> {target_plugin_dir} ({len(src_manifest)} files)"
        )
    if not rule_identical:
        planned_actions.append(
            f"{'update' if target_glob_rule.exists() else 'install'} glob rule -> {target_glob_rule}"
        )

    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "already_up_to_date": len(planned_actions) == 0,
            "planned_actions": planned_actions,
            "preflight": pf,
        }

    # Idempotent fast path: zero duplicate writes or unnecessary backups if already byte-identical
    if plugin_identical and rule_identical:
        # Ensure runtime state directories exist
        for sub in ("gate", "continuity", "memory", "chips", "hygiene", "logs"):
            (stack_home / "state" / sub).mkdir(parents=True, exist_ok=True)
        return {
            "ok": True,
            "dry_run": False,
            "already_up_to_date": True,
            "backup_id": None,
            "installed_plugin_dir": str(target_plugin_dir),
            "installed_glob_rule": str(target_glob_rule),
            "files_count": len(src_manifest) + 1,
        }

    backup_meta = create_backup(config_dir, stack_home)

    if not plugin_identical:
        copy_clean_tree(SOURCE_PLUGIN_DIR, target_plugin_dir)
    if not rule_identical:
        target_glob_rule.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(SOURCE_GLOB_RULE, target_glob_rule)

    for sub in ("gate", "continuity", "memory", "chips", "hygiene", "logs"):
        (stack_home / "state" / sub).mkdir(parents=True, exist_ok=True)

    return {
        "ok": True,
        "dry_run": False,
        "already_up_to_date": False,
        "backup_id": backup_meta["backup_id"],
        "installed_plugin_dir": str(target_plugin_dir),
        "installed_glob_rule": str(target_glob_rule),
        "files_count": len(src_manifest) + 1,
        "planned_actions": planned_actions,
    }


def list_backups(stack_home: pathlib.Path) -> list[pathlib.Path]:
    broot = stack_home / "backups"
    if not broot.is_dir():
        return []
    return sorted(p for p in broot.iterdir() if p.is_dir() and (p / "manifest.json").is_file())


def perform_rollback(
    config_dir: pathlib.Path,
    stack_home: pathlib.Path,
    backup_selector: str = "latest",
) -> dict[str, Any]:
    backups = list_backups(stack_home)
    if not backups:
        return {"ok": False, "error": f"No backups found in {stack_home / 'backups'}"}

    chosen: pathlib.Path | None = None
    if backup_selector == "latest":
        chosen = backups[-1]
    else:
        for b in backups:
            if b.name == backup_selector:
                chosen = b
                break
    if chosen is None:
        return {"ok": False, "error": f"Backup '{backup_selector}' not found"}

    manifest = json.loads((chosen / "manifest.json").read_text(encoding="utf-8"))
    targets = manifest.get("targets") or {}

    p_info = targets.get("plugin_dir") or {}
    p_target = pathlib.Path(p_info.get("path") or (config_dir / "plugins" / PLUGIN_NAME))
    if p_info.get("existed") and (chosen / "plugin_dir").is_dir():
        copy_clean_tree(chosen / "plugin_dir", p_target)
    elif p_target.exists():
        shutil.rmtree(p_target)

    r_info = targets.get("glob_rule") or {}
    r_target = pathlib.Path(r_info.get("path") or (config_dir / "rules" / "uiux-design.md"))
    if r_info.get("existed") and (chosen / "rules" / "uiux-design.md").is_file():
        r_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(chosen / "rules" / "uiux-design.md", r_target)
    elif r_target.exists():
        r_target.unlink()

    return {
        "ok": True,
        "restored_backup_id": chosen.name,
        "plugin_dir_exists_now": p_target.exists(),
        "glob_rule_exists_now": r_target.exists(),
    }


def perform_diagnose(config_dir: pathlib.Path, stack_home: pathlib.Path) -> dict[str, Any]:
    pf = preflight_check(config_dir)
    backups = [b.name for b in list_backups(stack_home)]
    target_plugin_dir = config_dir / "plugins" / PLUGIN_NAME
    target_glob_rule = config_dir / "rules" / "uiux-design.md"

    in_sync = False
    if target_plugin_dir.is_dir() and target_glob_rule.is_file():
        in_sync = (tree_manifest(SOURCE_PLUGIN_DIR) == tree_manifest(target_plugin_dir)) and (
            sha256_file(SOURCE_GLOB_RULE) == sha256_file(target_glob_rule)
        )

    doctor_script = (
        target_plugin_dir / "tools" / "stack_doctor.py"
        if (target_plugin_dir / "tools" / "stack_doctor.py").is_file()
        else SOURCE_PLUGIN_DIR / "tools" / "stack_doctor.py"
    )
    env = dict(os.environ, CARBON_STACK_HOME=str(stack_home))
    kw: dict[str, Any] = {"stdin": subprocess.DEVNULL, "capture_output": True, "timeout": 12.0, "env": env}
    if os.name == "nt":
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    proc = subprocess.run([sys.executable, "-X", "utf8", str(doctor_script)], **kw)
    try:
        doctor_out = json.loads((proc.stdout or b"{}").decode("utf-8", errors="replace"))
    except Exception:
        doctor_out = {"raw": (proc.stdout or b"").decode("utf-8", errors="replace")}

    return {
        "ok": pf["ok"] and bool(doctor_out.get("ok", True)),
        "installed": target_plugin_dir.is_dir(),
        "in_sync_with_source": in_sync,
        "backups_count": len(backups),
        "latest_backup": backups[-1] if backups else None,
        "preflight": pf,
        "doctor": doctor_out,
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="install.py", description="Gemini Carbon Engineering Stack Installer")
    parser.add_argument("--dry-run", action="store_true", help="Inspect and report planned actions without writing")
    parser.add_argument("--diagnose", action="store_true", help="Run preflight, sync check, and stack_doctor")
    parser.add_argument(
        "--rollback",
        nargs="?",
        const="latest",
        default="",
        help="Restore from latest or named backup id",
    )
    parser.add_argument("--force-foreign", action="store_true", help="Allow replacing foreign uiux-design.md after backup")
    parser.add_argument("--target-config-dir", default="", help="Override ~/.gemini/config (for isolated tests)")
    parser.add_argument("--stack-home", default="", help="Override ~/.gemini/carbon-stack (for isolated tests)")

    args = parser.parse_args()
    config_dir, stack_home = resolve_paths(args.target_config_dir, args.stack_home)

    if args.diagnose:
        res = perform_diagnose(config_dir, stack_home)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("ok") else 1

    if args.rollback:
        res = perform_rollback(config_dir, stack_home, backup_selector=args.rollback)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("ok") else 1

    res = perform_install(
        config_dir=config_dir,
        stack_home=stack_home,
        dry_run=bool(args.dry_run),
        force_foreign=bool(args.force_foreign),
    )
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
