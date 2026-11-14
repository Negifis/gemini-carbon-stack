#!/usr/bin/env python3
"""Multi-session & isolated-worktree task handoff (`chip_handoff`): open, finish, close, status, recover."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import time
import uuid
from typing import Any

HOOKS_DIR = pathlib.Path(__file__).resolve().parent.parent / "hooks"
TOOLS_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HOOKS_DIR))
sys.path.insert(0, str(TOOLS_DIR))

import runtime_io as rio
import worktree_guard

TRANSLIT_MAP = str.maketrans(
    {
        "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e", "ж": "zh",
        "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m", "н": "n", "о": "o",
        "п": "p", "р": "r", "с": "s", "т": "t", "у": "u", "ф": "f", "х": "kh", "ц": "ts",
        "ч": "ch", "ш": "sh", "щ": "shch", "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
    }
)


def chips_dir() -> pathlib.Path:
    return rio.state_dir("chips", "cards")


def chip_trees_dir() -> pathlib.Path:
    return rio.state_dir("chips", "trees")


def chip_bundles_dir() -> pathlib.Path:
    return rio.state_dir("chips", "bundles")


def chip_lock_path() -> pathlib.Path:
    return rio.state_dir("chips") / ".chips.lock"


def card_path(chip_id: str) -> pathlib.Path:
    return chips_dir() / f"{rio.safe_key(chip_id)}.json"


def slugify(title: str) -> str:
    low = (title or "task").lower().translate(TRANSLIT_MAP)
    slug = re.sub(r"[^a-z0-9]+", "-", low).strip("-")
    return (slug[:28] or "task").rstrip("-")


def load_all_cards() -> list[dict[str, Any]]:
    cards: list[dict[str, Any]] = []
    for p in sorted(chips_dir().glob("*.json")):
        c = rio.read_json(p, default=None)
        if isinstance(c, dict) and c.get("chip_id"):
            cards.append(c)
    return cards


def find_card_for_cwd(cwd: str) -> dict[str, Any] | None:
    folded = rio.fold_path(cwd)
    for card in load_all_cards():
        wt = card.get("worktree")
        if wt:
            fwt = rio.fold_path(wt)
            if folded == fwt or folded.startswith(fwt + "/"):
                return card
    return None


def open_chip(
    title: str,
    cwd: str = "",
    parent_session: str = "",
    expected_result: str = "",
    operational: bool = False,
) -> dict[str, Any]:
    work_cwd = os.path.abspath(cwd or os.getcwd())
    slug = slugify(title)
    short = uuid.uuid4().hex[:8]
    chip_id = f"chip-{slug}-{short}"
    now = time.time()

    git_root = rio.git_toplevel(work_cwd)
    code_mode = bool(git_root and not operational)

    record: dict[str, Any] = {
        "chip_id": chip_id,
        "title": title.strip(),
        "expected_result": expected_result.strip() or "Проверенный коммит в ветке чипа и краткий отчёт через chip_handoff.py finish",
        "mode": "code" if code_mode else "operational",
        "status": "open",
        "parent_session": rio.safe_key(parent_session, "") if parent_session else "",
        "parent_cwd": rio.normalize_path(work_cwd),
        "repo_root": rio.normalize_path(git_root) if git_root else "",
        "parent_branch": "",
        "base_sha": "",
        "chip_branch": "",
        "worktree": "",
        "created_ts": now,
        "updated_ts": now,
        "parent_notified": False,
        "stop_reminders": 0,
    }

    if code_mode and git_root:
        rc_b, br_out, _ = rio.run_git(git_root, ["symbolic-ref", "-q", "--short", "HEAD"], timeout=3.0)
        parent_branch = str(br_out or "").strip() if rc_b == 0 else ""
        rc_h, sha_out, err_h = rio.run_git(git_root, ["rev-parse", "--verify", "HEAD"], timeout=3.0)
        if rc_h != 0 or not str(sha_out or "").strip():
            raise RuntimeError(f"Cannot cut chip worktree from unborn HEAD: {err_h.strip()}")
        base_sha = str(sha_out).strip()
        chip_branch = f"chip/{slug}-{short}"
        wt_path = str(chip_trees_dir() / chip_id)

        rc_wt, _, err_wt = rio.run_git(
            git_root,
            ["worktree", "add", "-b", chip_branch, wt_path, base_sha],
            timeout=15.0,
        )
        if rc_wt != 0:
            raise RuntimeError(f"git worktree add failed: {err_wt.strip()}")

        record.update(
            {
                "parent_branch": parent_branch,
                "base_sha": base_sha,
                "chip_branch": chip_branch,
                "worktree": rio.normalize_path(wt_path),
            }
        )

    with rio.file_lock(chip_lock_path()):
        rio.write_json(card_path(chip_id), record)

    script_norm = rio.normalize_path(pathlib.Path(__file__).resolve())
    record["handoff_brief"] = (
        f"[Chip Handoff: {chip_id}]\n"
        f"- Задача: {record['title']}\n"
        f"- Рабочая директория: {record['worktree'] or record['parent_cwd']}\n"
        f"- Ожидаемый результат: {record['expected_result']}\n"
        f"- По завершении закоммитьте изменения (для code-чипа) и выполните:\n"
        f"  python -X utf8 \"{script_norm}\" finish --chip \"{chip_id}\" --message \"<итог и выполненные проверки>\""
    )
    return record


def finish_chip(chip_id: str = "", message: str = "", cwd: str = "") -> dict[str, Any]:
    work_cwd = os.path.abspath(cwd or os.getcwd())
    with rio.file_lock(chip_lock_path()):
        card = rio.read_json(card_path(chip_id), default=None) if chip_id else find_card_for_cwd(work_cwd)
        if not isinstance(card, dict):
            raise RuntimeError("Chip card not found. Pass `--chip <chip_id>` or run from inside the chip worktree.")

        cid = str(card["chip_id"])
        if card.get("mode") == "code" and card.get("worktree"):
            wt = str(card["worktree"])
            if os.path.isdir(wt):
                rc_st, st_out, _ = rio.run_git(wt, ["status", "--porcelain=v1"], timeout=5.0)
                if rc_st == 0 and str(st_out or "").strip():
                    raise RuntimeError(
                        "Chip worktree still has uncommitted files. Commit your verified changes (or clean scratch files) before calling `finish`."
                    )
                rc_tip, tip_out, _ = rio.run_git(wt, ["rev-parse", "--verify", "HEAD"], timeout=3.0)
                tip_sha = str(tip_out or "").strip() if rc_tip == 0 else ""
                card["head_sha"] = tip_sha

                # Create portable git bundle backup if commits were added beyond base_sha
                base_sha = str(card.get("base_sha") or "")
                if tip_sha and base_sha and tip_sha != base_sha:
                    bundle_file = str(chip_bundles_dir() / f"{cid}.bundle")
                    rio.run_git(wt, ["bundle", "create", bundle_file, f"{base_sha}..{tip_sha}"], timeout=10.0)
                    if os.path.isfile(bundle_file):
                        card["bundle_path"] = rio.normalize_path(bundle_file)

        card["status"] = "handed-off"
        card["summary"] = (message or "Completed chip task").strip()
        card["finished_ts"] = time.time()
        card["updated_ts"] = time.time()
        card["parent_notified"] = False
        rio.write_json(card_path(cid), card)
    return {"ok": True, "chip_id": card["chip_id"], "status": "handed-off", "head_sha": card.get("head_sha", "")}


def close_chip(
    chip_id: str,
    accept: bool = False,
    rework_note: str = "",
    merge_into_parent: bool = False,
) -> dict[str, Any]:
    with rio.file_lock(chip_lock_path()):
        cp = card_path(chip_id)
        card = rio.read_json(cp, default=None)
        if not isinstance(card, dict):
            raise RuntimeError(f"Chip '{chip_id}' not found.")

        now = time.time()
        if not accept:
            card["status"] = "rework"
            card["rework_note"] = rework_note.strip()
            card["updated_ts"] = now
            card["stop_reminders"] = 0
            rio.write_json(cp, card)
            return {"ok": True, "chip_id": chip_id, "status": "rework", "rework_note": card["rework_note"]}

        merged = False
        repo_root = str(card.get("repo_root") or "")
        chip_branch = str(card.get("chip_branch") or "")
        if merge_into_parent and repo_root and chip_branch and os.path.isdir(repo_root):
            rc_m, _, err_m = rio.run_git(
                repo_root, ["merge", "--no-edit", chip_branch], timeout=15.0
            )
            if rc_m != 0:
                raise RuntimeError(f"Merge into parent checkout failed: {err_m.strip()}")
            merged = True

        cleanup_info: dict[str, Any] = {}
        wt = str(card.get("worktree") or "")
        if wt and os.path.exists(wt):
            cleanup_info = worktree_guard.safe_remove_worktree(wt, repo_dir=repo_root, snapshot_dirty=True)

        card["status"] = "accepted"
        card["accepted_ts"] = now
        card["updated_ts"] = now
        card["merged"] = merged
        card["cleanup"] = cleanup_info
        rio.write_json(cp, card)
        return {"ok": True, "chip_id": chip_id, "status": "accepted", "merged": merged, "cleanup": cleanup_info}


def recover_chips(parent_session: str = "") -> dict[str, Any]:
    """Inspect open/rework/handed-off chips and surface uncommitted or unaccepted work."""
    items: list[dict[str, Any]] = []
    for card in load_all_cards():
        if card.get("status") == "accepted":
            continue
        if parent_session and card.get("parent_session") and card.get("parent_session") != rio.safe_key(parent_session):
            continue
        wt = str(card.get("worktree") or "")
        wt_state = "no_worktree"
        ahead_commits = 0
        dirty_files = 0
        if wt and os.path.isdir(wt):
            wt_state = "present"
            rc_s, st_out, _ = rio.run_git(wt, ["status", "--porcelain=v1"], timeout=4.0)
            if rc_s == 0:
                dirty_files = len([ln for ln in str(st_out or "").splitlines() if ln.strip()])
            base = str(card.get("base_sha") or "")
            if base:
                rc_c, cnt_out, _ = rio.run_git(wt, ["rev-list", "--count", f"{base}..HEAD"], timeout=4.0)
                if rc_c == 0 and str(cnt_out or "").strip().isdigit():
                    ahead_commits = int(str(cnt_out).strip())
        elif wt:
            wt_state = "missing_on_disk"

        items.append(
            {
                "chip_id": card["chip_id"],
                "title": card.get("title"),
                "status": card.get("status"),
                "mode": card.get("mode"),
                "worktree_state": wt_state,
                "ahead_commits": ahead_commits,
                "dirty_files": dirty_files,
                "chip_branch": card.get("chip_branch", ""),
                "bundle_path": card.get("bundle_path", ""),
                "summary": card.get("summary", ""),
            }
        )
    return {"ok": True, "active_count": len(items), "chips": items}


def main() -> int:
    parser = argparse.ArgumentParser(prog="chip_handoff")
    sub = parser.add_subparsers(dest="cmd", required=True)

    op = sub.add_parser("open", help="Register an isolated task chip (and cut a git worktree for code tasks)")
    op.add_argument("--title", required=True)
    op.add_argument("--expected", default="")
    op.add_argument("--session", default="")
    op.add_argument("--cwd", default="")
    op.add_argument("--operational", action="store_true")

    fin = sub.add_parser("finish", help="Hand completed chip work back to the parent")
    fin.add_argument("--chip", default="")
    fin.add_argument("--message", required=True)
    fin.add_argument("--cwd", default="")

    cls = sub.add_parser("close", help="Parent verification verdict: accept (and clean up worktree) or request rework")
    cls.add_argument("--chip", required=True)
    grp = cls.add_mutually_exclusive_group(required=True)
    grp.add_argument("--accept", action="store_true")
    grp.add_argument("--rework", default="")
    cls.add_argument("--merge", action="store_true", help="Merge chip branch into parent repo checkout upon accept")

    st = sub.add_parser("status", help="List non-accepted or all chips")
    st.add_argument("--session", default="")
    st.add_argument("--all", action="store_true")

    rec = sub.add_parser("recover", help="Inspect interrupted/stalled chips for unmerged commits or dirty files")
    rec.add_argument("--session", default="")

    args = parser.parse_args()
    try:
        if args.cmd == "open":
            res = open_chip(
                title=args.title,
                cwd=args.cwd,
                parent_session=args.session,
                expected_result=args.expected,
                operational=args.operational,
            )
            print(json.dumps(res, ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "finish":
            res = finish_chip(chip_id=args.chip, message=args.message, cwd=args.cwd)
            print(json.dumps(res, ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "close":
            res = close_chip(
                chip_id=args.chip,
                accept=bool(args.accept),
                rework_note=args.rework,
                merge_into_parent=bool(args.merge),
            )
            print(json.dumps(res, ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "status":
            cards = load_all_cards()
            if not args.all:
                cards = [c for c in cards if c.get("status") != "accepted"]
            if args.session:
                sk = rio.safe_key(args.session)
                cards = [c for c in cards if c.get("parent_session") == sk]
            print(json.dumps({"count": len(cards), "chips": cards}, ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "recover":
            print(json.dumps(recover_chips(parent_session=args.session), ensure_ascii=False, indent=2))
            return 0
    except RuntimeError as err:
        sys.stderr.write(f"[chip_handoff] {err}\n")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
