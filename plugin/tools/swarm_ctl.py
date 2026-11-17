#!/usr/bin/env python3
"""Swarm 2.0 CLI utility: file ownership, isolated worktrees, and compact board summaries."""

from __future__ import annotations

import argparse
import os
import pathlib
import sys
import time
from typing import Any

_TOOLS_DIR = pathlib.Path(__file__).resolve().parent
_HOOKS_DIR = _TOOLS_DIR.parent / "hooks"
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))
if str(_HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(_HOOKS_DIR))

import cwg_common as cwg
import runtime_io as rio
import worktree_guard as wguard


def _repo_root(cwd: str) -> str:
    eff = os.path.abspath(cwd or os.getcwd())
    return rio.git_toplevel(eff) or eff


def _dirty_durable_files(repo_root: str) -> list[str]:
    files: set[str] = set()
    rc, out, _ = rio.run_git(repo_root, ["-c", "core.quotepath=false", "status", "--porcelain=v1", "-uall"])
    if rc == 0 and out:
        for line in out.splitlines():
            if len(line) < 4:
                continue
            raw_path = line[3:].strip()
            if " -> " in raw_path:
                raw_path = raw_path.split(" -> ", 1)[1].strip()
            raw_path = raw_path.strip('"')
            norm = cwg.normalize_glob_pattern(raw_path)
            if not norm or cwg.is_scratch_or_ephemeral(norm, cwd=repo_root):
                continue
            files.add(norm)
    return sorted(files)


def _caller_worker_if_non_coordinator() -> str:
    """SAFETY: detect non-coordinator swarm worker env vars for mutating CLI commands."""
    for key in rio.WORKER_ENV_KEYS:
        val = (os.environ.get(key) or "").strip()
        if val and val.lower() not in rio.COORDINATOR_ROLE_NAMES:
            return val
    return ""


def _deny_if_worker_caller() -> int | None:
    caller = _caller_worker_if_non_coordinator()
    if caller:
        rio.print_cli_json({"ok": False, "error": "coordinator_only", "worker": caller}, pretty=False)
        return 2
    return None


def cmd_ownership_set(args: argparse.Namespace) -> int:
    denied = _deny_if_worker_caller()
    if denied is not None:
        return denied
    root = _repo_root(args.cwd)
    worker = args.worker.strip()
    if not worker or worker.lower() == "coordinator":
        rio.print_cli_json({"ok": False, "error": "invalid_worker", "worker": worker}, pretty=False)
        return 2
    globs = [cwg.normalize_glob_pattern(g) for g in args.paths.split(",") if g.strip()]
    globs = list(dict.fromkeys(g for g in globs if g))
    if not globs:
        rio.print_cli_json({"ok": False, "error": "empty_paths"}, pretty=False)
        return 2

    manifest = cwg.load_ownership_manifest(root)
    candidate = {
        **manifest,
        "workers": {
            **dict(manifest.get("workers") or {}),
            worker: {"paths": globs, "updated_at": time.time()},
        },
    }
    overlaps = cwg.detect_ownership_overlaps(candidate, repo_root=root)
    if overlaps:
        rio.print_cli_json(
            {"ok": False, "error": "ownership_overlap", "worker": worker, "conflicts": overlaps},
            pretty=False,
        )
        return 2

    saved_ok, manifest_path = cwg.save_ownership_manifest(root, candidate)
    if not saved_ok:
        rio.print_cli_json(
            {"ok": False, "error": "manifest_write_failed", "manifest": rio.normalize_path(manifest_path)},
            pretty=False,
        )
        return 1
    rio.print_cli_json(
        {
            "ok": True,
            "manifest": rio.normalize_path(manifest_path),
            "worker": worker,
            "paths": globs,
        },
        pretty=False,
    )
    return 0


def cmd_ownership_clear(args: argparse.Namespace) -> int:
    denied = _deny_if_worker_caller()
    if denied is not None:
        return denied
    root = _repo_root(args.cwd)
    mpath = cwg.ownership_manifest_path(root)
    worker = (args.worker or "").strip()
    if not mpath.exists():
        rio.print_cli_json({"ok": True, "cleared": True, "manifest": rio.normalize_path(mpath)}, pretty=False)
        return 0
    if not worker:
        mpath.unlink(missing_ok=True)
        rio.print_cli_json({"ok": True, "cleared": "all", "manifest": rio.normalize_path(mpath)}, pretty=False)
        return 0
    manifest = cwg.load_ownership_manifest(root)
    workers = dict(manifest.get("workers") or {})
    removed = workers.pop(worker, None) is not None
    if workers:
        manifest["workers"] = workers
        saved_ok, _ = cwg.save_ownership_manifest(root, manifest)
        if not saved_ok:
            rio.print_cli_json(
                {"ok": False, "error": "manifest_write_failed", "manifest": rio.normalize_path(mpath)},
                pretty=False,
            )
            return 1
    else:
        mpath.unlink(missing_ok=True)
    rio.print_cli_json(
        {"ok": True, "worker": worker, "removed": removed, "remaining": sorted(workers.keys())},
        pretty=False,
    )
    return 0


def cmd_ownership_verify(args: argparse.Namespace) -> int:
    root = _repo_root(args.cwd)
    manifest = cwg.load_ownership_manifest(root)
    overlaps = cwg.detect_ownership_overlaps(manifest, repo_root=root)
    dirty_files = _dirty_durable_files(root)
    workers = manifest.get("workers") if isinstance(manifest.get("workers"), dict) else {}
    target_worker = (args.worker or "").strip()

    violations: list[dict[str, Any]] = []
    if target_worker and target_worker.lower() != "coordinator" and workers:
        entry = workers.get(target_worker)
        owned = list(entry.get("paths") or []) if isinstance(entry, dict) else []
        for rel in dirty_files:
            if not cwg.path_matches_any_glob(rel, owned):
                violations.append({"worker": target_worker, "path": rel, "owned_paths": owned})
    elif workers and args.strict:
        for rel in dirty_files:
            owners = [
                wname
                for wname, meta in workers.items()
                if isinstance(meta, dict) and cwg.path_matches_any_glob(rel, list(meta.get("paths") or []))
            ]
            if not owners or len(owners) > 1:
                violations.append({"path": rel, "owners": owners})

    ok = (not overlaps) and (not violations)
    rio.print_cli_json(
        {
            "ok": ok,
            "overlaps": overlaps,
            "violations": violations,
            "dirty_files": dirty_files,
            "workers": sorted(workers.keys()),
        },
        pretty=False,
    )
    return 0 if ok else 2


def _worktrees_base(root: str) -> pathlib.Path:
    return pathlib.Path(root) / ".swarm" / "worktrees"


def _list_git_worktrees(root: str) -> list[dict[str, Any]]:
    rc, items, _ = wguard.list_worktrees(root)
    if rc != 0:
        return []
    for item in items:
        if item.get("branch"):
            item["branch"] = str(item["branch"]).replace("refs/heads/", "")
    return items


def cmd_worktree_create(args: argparse.Namespace) -> int:
    denied = _deny_if_worker_caller()
    if denied is not None:
        return denied
    root = _repo_root(args.cwd)
    safe_worker = rio.safe_key(args.worker, "")
    if not safe_worker:
        rio.print_cli_json({"ok": False, "error": "invalid_worker"}, pretty=False)
        return 2
    base_dir = _worktrees_base(root)
    base_dir.mkdir(parents=True, exist_ok=True)
    wt_path = base_dir / safe_worker
    branch = (args.branch or f"swarm/{safe_worker}").strip()

    for existing in _list_git_worktrees(root):
        if rio.fold_path(existing["path"]) == rio.fold_path(wt_path) and wt_path.exists():
            rio.print_cli_json(
                {
                    "ok": True,
                    "reused": True,
                    "worker": args.worker,
                    "worktree": rio.normalize_path(wt_path),
                    "branch": existing.get("branch", branch),
                },
                pretty=False,
            )
            return 0

    rc_b, _, _ = rio.run_git(root, ["show-ref", "--verify", "--quiet", f"refs/heads/{branch}"])
    if rc_b == 0:
        rc, out, err = rio.run_git(root, ["worktree", "add", str(wt_path), branch])
    else:
        cmd_args = ["worktree", "add", "-b", branch, str(wt_path)]
        if args.base:
            cmd_args.append(args.base)
        rc, out, err = rio.run_git(root, cmd_args)
    if rc != 0:
        rio.print_cli_json(
            {"ok": False, "error": (err or out or "git worktree add failed").strip(), "worktree": rio.normalize_path(wt_path)},
            pretty=False,
        )
        return 1
    rio.print_cli_json(
        {
            "ok": True,
            "reused": False,
            "worker": args.worker,
            "worktree": rio.normalize_path(wt_path),
            "branch": branch,
        },
        pretty=False,
    )
    return 0


def cmd_worktree_status(args: argparse.Namespace) -> int:
    root = _repo_root(args.cwd)
    base_fold = rio.fold_path(_worktrees_base(root))
    swarm_wts: list[dict[str, Any]] = []
    for wt in _list_git_worktrees(root):
        p = str(wt.get("path") or "")
        if not rio.fold_path(p).startswith(f"{base_fold}/"):
            continue
        dirty = _dirty_durable_files(p) if os.path.isdir(p) else []
        swarm_wts.append(
            {
                "worker": pathlib.Path(p).name,
                "path": rio.normalize_path(p),
                "branch": wt.get("branch", ""),
                "exists": os.path.isdir(p),
                "dirty_count": len(dirty),
                "dirty_files": dirty,
            }
        )
    rio.print_cli_json({"ok": True, "worktrees": swarm_wts, "count": len(swarm_wts)}, pretty=False)
    return 0


def cmd_worktree_cleanup(args: argparse.Namespace) -> int:
    denied = _deny_if_worker_caller()
    if denied is not None:
        return denied
    root = _repo_root(args.cwd)
    base_dir = _worktrees_base(root)
    base_fold = rio.fold_path(base_dir)
    targets: list[pathlib.Path] = []
    if args.worker:
        targets.append(base_dir / rio.safe_key(args.worker, ""))
    else:
        seen_folds: set[str] = set()
        for wt in _list_git_worktrees(root):
            p = pathlib.Path(str(wt.get("path") or ""))
            if rio.fold_path(p).startswith(f"{base_fold}/"):
                seen_folds.add(rio.fold_path(p))
                targets.append(p)
        if base_dir.is_dir():
            for child in sorted(base_dir.iterdir()):
                if rio.fold_path(child) not in seen_folds:
                    targets.append(child)

    results: list[dict[str, Any]] = []
    all_ok = True
    for wt_path in targets:
        res = wguard.safe_remove_worktree(str(wt_path), repo_dir=root, snapshot_dirty=True)
        if args.delete_branch and res.get("ok"):
            branch_name = f"swarm/{wt_path.name}"
            rio.run_git(root, ["branch", "-D", branch_name])
        results.append(res)
        if not res.get("ok"):
            all_ok = False
    rio.run_git(root, ["worktree", "prune"])
    rio.print_cli_json({"ok": all_ok, "removed": results}, pretty=False)
    return 0 if all_ok else 1


def _load_summary_members(session: str, root: str) -> tuple[pathlib.Path | None, dict[str, Any]]:
    brain_root = rio.resolve_brain_root("")
    if session:
        members = rio.load_swarm_members(brain_root, session)
        if isinstance(members, dict) and members:
            return brain_root, members
    local_members = rio.read_json(pathlib.Path(root) / ".swarm" / "members.json", default=None)
    if isinstance(local_members, dict):
        members = local_members.get("members") if isinstance(local_members.get("members"), dict) else local_members
        if isinstance(members, dict):
            return brain_root, {k: v for k, v in members.items() if isinstance(v, dict)}
    return brain_root, {}


def cmd_board_summary(args: argparse.Namespace) -> int:
    root = _repo_root(args.cwd)
    since = max(0, int(args.since or 0))
    bp, messages = cwg.load_swarm_board_messages(session=args.session, cwd=root)
    head_seq = max((int(m.get("_seq") or 0) for m in messages), default=0)
    recent = [
        {
            "seq": int(m.get("_seq") or 0),
            "agent": str(m.get("agent") or m.get("worker") or ""),
            "preview": " ".join(str(m.get("text") or "").split())[:120],
            "time": str(m.get("time") or m.get("ts") or ""),
        }
        for m in messages
        if int(m.get("_seq") or 0) > since
    ]
    brain_root, members = _load_summary_members(args.session, root)
    worker_summary: dict[str, Any] = {}
    for name, meta in sorted(members.items()):
        if rio.is_swarm_role_member(name, meta):
            continue
        last_post_seq = max(
            (int(m.get("_seq") or 0) for m in messages if str(m.get("agent") or "") == name),
            default=0,
        )
        worker_summary[name] = {
            "state": "killed" if rio.is_swarm_member_killed(meta) else str(meta.get("wake_mode") or "active"),
            "model": str(meta.get("applied_model") or meta.get("desired_model") or meta.get("model") or ""),
            "last_seq": last_post_seq,
        }
    stalled = cwg.detect_stalled_workers(
        members=members,
        board_messages=messages,
        cwd=root,
        brain_root=brain_root,
    )
    art_dir = pathlib.Path(root) / ".swarm" / "artifacts"
    artifacts = sorted(p.name for p in art_dir.glob("*") if p.is_file()) if art_dir.is_dir() else []
    rio.print_cli_json(
        {
            "ok": True,
            "board_path": rio.normalize_path(bp) if bp else "",
            "head_seq": head_seq,
            "since": since,
            "total_messages": len(messages),
            "recent_count": len(recent),
            "recent_messages": recent,
            "workers": worker_summary,
            "stalled_workers": stalled,
            "artifacts": artifacts,
        },
        pretty=False,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="swarm_ctl")
    sub = parser.add_subparsers(dest="group", required=True)

    own = sub.add_parser("ownership")
    own_sub = own.add_subparsers(dest="action", required=True)
    own_set = own_sub.add_parser("set")
    own_set.add_argument("--worker", required=True)
    own_set.add_argument("--paths", required=True)
    own_set.add_argument("--cwd", default="")

    own_clr = own_sub.add_parser("clear")
    own_clr.add_argument("--worker", default="")
    own_clr.add_argument("--cwd", default="")

    own_ver = own_sub.add_parser("verify-git-diff")
    own_ver.add_argument("--worker", default="")
    own_ver.add_argument("--cwd", default="")
    own_ver.add_argument("--strict", action="store_true")

    wt = sub.add_parser("worktree")
    wt_sub = wt.add_subparsers(dest="action", required=True)
    wt_cr = wt_sub.add_parser("create")
    wt_cr.add_argument("--worker", required=True)
    wt_cr.add_argument("--cwd", default="")
    wt_cr.add_argument("--branch", default="")
    wt_cr.add_argument("--base", default="")

    wt_st = wt_sub.add_parser("status")
    wt_st.add_argument("--cwd", default="")

    wt_cl = wt_sub.add_parser("cleanup")
    wt_cl.add_argument("--worker", default="")
    wt_cl.add_argument("--cwd", default="")
    wt_cl.add_argument("--delete-branch", action="store_true")

    brd = sub.add_parser("board")
    brd_sub = brd.add_subparsers(dest="action", required=True)
    brd_sum = brd_sub.add_parser("summary")
    brd_sum.add_argument("--since", type=int, default=0)
    brd_sum.add_argument("--session", default="")
    brd_sum.add_argument("--cwd", default="")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.group == "ownership":
        if args.action == "set":
            return cmd_ownership_set(args)
        if args.action == "clear":
            return cmd_ownership_clear(args)
        if args.action == "verify-git-diff":
            return cmd_ownership_verify(args)
    elif args.group == "worktree":
        if args.action == "create":
            return cmd_worktree_create(args)
        if args.action == "status":
            return cmd_worktree_status(args)
        if args.action == "cleanup":
            return cmd_worktree_cleanup(args)
    elif args.group == "board":
        if args.action == "summary":
            return cmd_board_summary(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
