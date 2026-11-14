#!/usr/bin/env python3
"""Windows-safe git worktree guard: junction unlinking, git-plumbing `refs/wip/` snapshots, and worktree audit."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any

HOOKS_DIR = pathlib.Path(__file__).resolve().parent.parent / "hooks"
sys.path.insert(0, str(HOOKS_DIR))
import runtime_io as rio


def is_directory_link(path: str) -> bool:
    """Detect symlinks AND Windows NTFS directory junctions (`os.path.isjunction` on Python 3.12+)."""
    try:
        if os.path.islink(path):
            return True
        is_junc = getattr(os.path, "isjunction", None)
        if callable(is_junc) and is_junc(path):
            return True
        st = os.lstat(path)
        reparse = getattr(st, "st_reparse_tag", 0)
        return bool(reparse)
    except OSError:
        return False


def unlink_directory_links(root_dir: str) -> tuple[list[str], list[str]]:
    """Unlink symlinks and Windows junctions inside `root_dir` WITHOUT recursing into their targets."""
    unlinked: list[str] = []
    errors: list[str] = []
    if not os.path.isdir(root_dir):
        return unlinked, errors

    stack = [os.path.abspath(root_dir)]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                entries = list(it)
        except OSError as exc:
            errors.append(f"scandir:{current}:{exc}")
            continue

        for entry in entries:
            if entry.name == ".git":
                continue
            full = entry.path
            if is_directory_link(full):
                removed = False
                try:
                    if os.name == "nt" and not os.path.islink(full):
                        os.rmdir(full)
                    else:
                        os.unlink(full)
                    removed = True
                except OSError:
                    try:
                        os.rmdir(full)
                        removed = True
                    except OSError as exc:
                        errors.append(f"unlink:{full}:{exc}")
                if removed:
                    unlinked.append(rio.normalize_path(full))
            elif entry.is_dir(follow_symlinks=False):
                stack.append(full)

    return unlinked, errors


def snapshot_dirty_worktree(worktree_dir: str, label: str = "auto") -> dict[str, Any]:
    """Snapshot uncommitted tracked & untracked files into `refs/wip/<label>-<ts>` via isolated git index."""
    wt = os.path.abspath(worktree_dir)
    top = rio.git_toplevel(wt)
    if not top:
        return {"ok": False, "error": "not_a_git_worktree"}

    rc_st, status_out, _ = rio.run_git(top, ["status", "--porcelain=v1"], timeout=5.0)
    if rc_st != 0:
        return {"ok": False, "error": "git_status_failed"}
    if not str(status_out or "").strip():
        return {"ok": True, "clean": True, "ref": "", "commit": ""}

    rc_h, head_out, _ = rio.run_git(top, ["rev-parse", "--verify", "-q", "HEAD"], timeout=3.0)
    parent_sha = str(head_out or "").strip() if rc_h == 0 else ""

    # Copy current git index to a temporary file so the user's real staging area is never mutated
    rc_idx, idx_path_out, _ = rio.run_git(top, ["rev-parse", "--git-path", "index"], timeout=3.0)
    real_idx = (
        os.path.join(top, str(idx_path_out).strip())
        if rc_idx == 0 and str(idx_path_out).strip()
        else ""
    )

    tmp_dir = tempfile.mkdtemp(prefix="carbon-wip-idx-")
    tmp_index = os.path.join(tmp_dir, "index")
    try:
        if real_idx and os.path.isfile(real_idx):
            shutil.copy2(real_idx, tmp_index)

        env = dict(os.environ, GIT_INDEX_FILE=tmp_index)

        def git_env(args: list[str]) -> tuple[int, str, str]:
            proc = subprocess.run(
                ["git", "--no-optional-locks"] + args,
                cwd=top,
                env=env,
                timeout=15.0,
                **rio.subprocess_kwargs(),
            )
            return (
                proc.returncode,
                (proc.stdout or b"").decode("utf-8", errors="replace"),
                (proc.stderr or b"").decode("utf-8", errors="replace"),
            )

        rc1, _, err1 = git_env(["add", "-A"])
        if rc1 != 0:
            return {"ok": False, "error": f"git_add_failed:{err1.strip()[:160]}"}

        rc2, tree_sha, err2 = git_env(["write-tree"])
        if rc2 != 0 or not tree_sha.strip():
            return {"ok": False, "error": f"git_write_tree_failed:{err2.strip()[:160]}"}

        commit_args = ["commit-tree", tree_sha.strip(), "-m", f"WIP snapshot ({label}) at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}"]
        if parent_sha:
            commit_args[2:2] = ["-p", parent_sha]
        rc3, commit_sha, err3 = git_env(commit_args)
        if rc3 != 0 or not commit_sha.strip():
            return {"ok": False, "error": f"git_commit_tree_failed:{err3.strip()[:160]}"}

        safe_lbl = rio.safe_key(label, "wip")[:32]
        ref_name = f"refs/wip/{safe_lbl}-{int(time.time())}"
        rc4, _, err4 = git_env(["update-ref", ref_name, commit_sha.strip()])
        if rc4 != 0:
            return {"ok": False, "error": f"git_update_ref_failed:{err4.strip()[:160]}"}

        return {
            "ok": True,
            "clean": False,
            "ref": ref_name,
            "commit": commit_sha.strip(),
            "worktree": rio.normalize_path(top),
        }
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def safe_remove_worktree(
    worktree_dir: str,
    repo_dir: str = "",
    snapshot_dirty: bool = True,
) -> dict[str, Any]:
    wt = os.path.abspath(worktree_dir)
    if not os.path.exists(wt):
        return {"ok": True, "already_absent": True, "worktree": rio.normalize_path(wt)}

    rc_st, status_out, _ = rio.run_git(wt, ["status", "--porcelain=v1"], timeout=5.0)
    is_dirty = rc_st == 0 and bool(str(status_out or "").strip())

    snap_info: dict[str, Any] | None = None
    if is_dirty:
        if not snapshot_dirty:
            return {
                "ok": False,
                "error": "worktree_dirty_refused",
                "worktree": rio.normalize_path(wt),
            }
        snap_info = snapshot_dirty_worktree(wt, label=pathlib.Path(wt).name)
        if not snap_info.get("ok"):
            return {
                "ok": False,
                "error": f"dirty_snapshot_failed:{snap_info.get('error')}",
                "worktree": rio.normalize_path(wt),
            }

    # Unlink directory links/junctions BEFORE git worktree remove touches the tree
    unlinked, link_errors = unlink_directory_links(wt)
    if link_errors:
        return {
            "ok": False,
            "error": "junction_unlink_failed",
            "details": link_errors,
            "worktree": rio.normalize_path(wt),
        }

    anchor = os.path.abspath(repo_dir) if repo_dir else (rio.git_toplevel(os.path.dirname(wt)) or "")
    if not anchor:
        # Resolve common git dir from the worktree itself before removing it
        rc_c, common_out, _ = rio.run_git(wt, ["rev-parse", "--git-common-dir"], timeout=3.0)
        if rc_c == 0 and str(common_out).strip():
            cpath = str(common_out).strip()
            cabs = cpath if os.path.isabs(cpath) else os.path.abspath(os.path.join(wt, cpath))
            anchor = os.path.dirname(cabs) if os.path.basename(cabs) == ".git" else cabs

    if not anchor or not os.path.isdir(anchor):
        return {"ok": False, "error": "cannot_resolve_parent_repo"}

    rm_args = ["worktree", "remove"]
    if is_dirty and snap_info and snap_info.get("ok"):
        rm_args.append("--force")
    rm_args.append(wt)

    rc_rm, _, err_rm = rio.run_git(anchor, rm_args, timeout=15.0)
    if rc_rm != 0:
        return {
            "ok": False,
            "error": f"git_worktree_remove_failed:{err_rm.strip()[:200]}",
            "snapshot": snap_info,
            "unlinked_links": unlinked,
        }
    return {
        "ok": True,
        "worktree": rio.normalize_path(wt),
        "unlinked_links": unlinked,
        "snapshot": snap_info,
    }


def audit_worktrees(cwd: str = "") -> dict[str, Any]:
    root = rio.git_toplevel(cwd or os.getcwd())
    if not root:
        return {"ok": False, "error": "not_in_git_repo"}

    rc, out, err = rio.run_git(root, ["worktree", "list", "--porcelain"], timeout=6.0)
    if rc != 0:
        return {"ok": False, "error": err.strip()}

    trees: list[dict[str, Any]] = []
    cur: dict[str, Any] = {}
    for line in str(out).splitlines() + [""]:
        if not line.strip():
            if cur.get("worktree"):
                trees.append(cur)
            cur = {}
            continue
        if line.startswith("worktree "):
            cur["worktree"] = rio.normalize_path(line[len("worktree ") :].strip())
        elif line.startswith("HEAD "):
            cur["head"] = line[len("HEAD ") :].strip()
        elif line.startswith("branch "):
            cur["branch"] = line[len("branch ") :].strip()
        elif line == "detached":
            cur["detached"] = True

    for item in trees:
        wt_path = item["worktree"]
        if os.path.isdir(wt_path):
            rc_s, st_out, _ = rio.run_git(wt_path, ["status", "--porcelain=v1"], timeout=4.0)
            dirty_lines = [ln for ln in str(st_out or "").splitlines() if ln.strip()] if rc_s == 0 else []
            item["dirty"] = bool(dirty_lines)
            item["dirty_count"] = len(dirty_lines)
        else:
            item["missing_on_disk"] = True

    rc_wip, wip_out, _ = rio.run_git(
        root, ["for-each-ref", "--format=%(refname:short) %(objectname:short)", "refs/wip/"], timeout=4.0
    )
    wip_refs = [ln.strip() for ln in str(wip_out or "").splitlines() if ln.strip()] if rc_wip == 0 else []

    return {
        "ok": True,
        "repo_root": rio.normalize_path(root),
        "worktree_count": len(trees),
        "worktrees": trees,
        "wip_snapshots": wip_refs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="worktree_guard")
    sub = parser.add_subparsers(dest="cmd", required=True)

    aud = sub.add_parser("audit", help="Inspect git worktrees, dirty status, and refs/wip snapshots")
    aud.add_argument("--cwd", default="")

    snap = sub.add_parser("snapshot", help="Save uncommitted state into refs/wip/ without touching index")
    snap.add_argument("--worktree", default="")
    snap.add_argument("--label", default="manual")

    rem = sub.add_parser("remove", help="Safely unlink junctions, snapshot dirty work, and remove worktree")
    rem.add_argument("--worktree", required=True)
    rem.add_argument("--repo", default="")
    rem.add_argument("--no-snapshot", action="store_true")

    unl = sub.add_parser("unlink-links", help="Unlink directory symlinks and NTFS junctions inside a tree")
    unl.add_argument("--tree", required=True)

    args = parser.parse_args()
    if args.cmd == "audit":
        res = audit_worktrees(args.cwd)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("ok") else 1
    if args.cmd == "snapshot":
        res = snapshot_dirty_worktree(args.worktree or os.getcwd(), label=args.label)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("ok") else 1
    if args.cmd == "remove":
        res = safe_remove_worktree(
            args.worktree,
            repo_dir=args.repo,
            snapshot_dirty=not args.no_snapshot,
        )
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("ok") else 1
    if args.cmd == "unlink-links":
        unlinked, errs = unlink_directory_links(args.tree)
        print(json.dumps({"ok": not errs, "unlinked": unlinked, "errors": errs}, ensure_ascii=False, indent=2))
        return 0 if not errs else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
