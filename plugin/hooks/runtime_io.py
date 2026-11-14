#!/usr/bin/env python3
"""Shared Antigravity 2.0 hook I/O, transcript reader, atomic storage, and git helpers."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterator

SUBAGENT_MSG_RE = re.compile(
    r"\[Message\]\s+timestamp=(?P<ts>\S+)\s+sender=(?P<sender>[A-Za-z0-9._-]{4,80})"
    r"(?:\s+priority=\S+)?\s+content=(?P<body>.*)",
    re.DOTALL,
)

NON_ENFORCEABLE_STOP_REASONS = frozenset(
    {
        "ERROR",
        "USER_CANCELED",
        "MAX_INVOCATIONS",
        "MAX_FORCED_INVOCATIONS",
        "MAX_TOKEN_BUDGET_EXCEEDED",
        "TERMINAL_CUSTOM_HOOK",
    }
)


def stack_home() -> pathlib.Path:
    override = os.environ.get("CARBON_STACK_HOME")
    if override:
        p = pathlib.Path(override)
    else:
        p = pathlib.Path.home() / ".gemini" / "carbon-stack"
    p.mkdir(parents=True, exist_ok=True)
    return p


def state_dir(*parts: str) -> pathlib.Path:
    target = stack_home() / "state"
    for part in parts:
        target = target / part
    target.mkdir(parents=True, exist_ok=True)
    return target


def plugin_root() -> pathlib.Path:
    env_root = os.environ.get("PLUGIN_ROOT")
    if env_root:
        return pathlib.Path(env_root).resolve()
    return pathlib.Path(__file__).resolve().parent.parent


def parse_event_arg(default: str = "") -> str:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--event", default=default)
    args, _ = parser.parse_known_args()
    return str(args.event or default)


def normalize_path(path: str | pathlib.Path | None) -> str:
    if not path:
        return ""
    raw = str(path).strip().strip('"')
    if not raw:
        return ""
    try:
        resolved = os.path.abspath(os.path.expanduser(raw))
    except Exception:
        resolved = raw
    norm = resolved.replace("\\", "/")
    if os.name == "nt" and len(norm) >= 2 and norm[1] == ":":
        norm = norm[0].lower() + norm[1:]
    return norm.rstrip("/") if len(norm) > 3 else norm


def fold_path(path: str | pathlib.Path | None) -> str:
    norm = normalize_path(path)
    return norm.lower() if os.name == "nt" else norm


def safe_key(value: str | None, fallback: str = "default") -> str:
    raw = (value or "").strip()
    if not raw:
        return fallback
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", raw)
    if len(cleaned) <= 72 and cleaned.strip("._-"):
        return cleaned
    digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]
    prefix = re.sub(r"[^A-Za-z0-9]+", "", raw)[:24] or "key"
    return f"{prefix}-{digest}"


def project_key(
    cwd: str | None,
    workspace_paths: list[str] | None = None,
    known_git_root: str | None = None,
) -> str:
    candidate = ""
    if workspace_paths:
        for wp in workspace_paths:
            if wp:
                candidate = wp
                break
    if not candidate:
        candidate = cwd or os.getcwd()
    git_root = known_git_root if known_git_root is not None else git_toplevel(candidate)
    anchor = fold_path(git_root or candidate)
    base = pathlib.PurePosixPath(anchor).name or "root"
    digest = hashlib.sha256(anchor.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"{safe_key(base)[:32]}-{digest}"


def session_key(payload: dict[str, Any] | None) -> str:
    if not isinstance(payload, dict):
        return "unknown"
    conv = payload.get("conversationId") or payload.get("session_id")
    if conv:
        return safe_key(str(conv), "unknown")
    tp = payload.get("transcriptPath") or payload.get("transcript_path")
    if tp:
        return safe_key(str(tp), "unknown")
    return "unknown"


def effective_cwd(payload: dict[str, Any] | None) -> str:
    if isinstance(payload, dict):
        cwd = payload.get("cwd")
        if isinstance(cwd, str) and cwd.strip() and os.path.isdir(cwd):
            return os.path.abspath(cwd)
        wps = payload.get("workspacePaths")
        if isinstance(wps, list):
            for wp in wps:
                if isinstance(wp, str) and wp.strip() and os.path.isdir(wp):
                    return os.path.abspath(wp)
    return os.getcwd()


def read_hook_stdin() -> tuple[dict[str, Any] | None, str | None]:
    """Read protojson hook payload from stdin without raising on malformed input."""
    try:
        raw = sys.stdin.buffer.read()
    except Exception as exc:
        return None, f"stdin_read_error:{type(exc).__name__}"
    if not raw or not raw.strip():
        return {}, None
    try:
        text = raw.decode("utf-8-sig", errors="strict")
        data = json.loads(text)
    except Exception as exc:
        return None, f"invalid_json:{type(exc).__name__}"
    if not isinstance(data, dict):
        return None, "payload_not_object"
    return data, None


def emit_json(obj: dict[str, Any]) -> None:
    text = json.dumps(obj, ensure_ascii=False)
    sys.stdout.buffer.write((text + "\n").encode("utf-8"))
    sys.stdout.buffer.flush()


def emit_default_for_event(event: str) -> None:
    if event == "PreToolUse":
        emit_json({"decision": "allow"})
    elif event == "Stop":
        emit_json({"decision": "allow"})
    else:
        emit_json({})


def emit_inject_system(message: str, user_markdown: str | None = None) -> None:
    if not message and not user_markdown:
        emit_json({})
        return
    sys_obj: dict[str, Any] = {"systemMessage": message or ""}
    if user_markdown:
        sys_obj["metadata"] = {"user_markdown": user_markdown}
    emit_json({"injectSteps": [{"systemMessage": sys_obj}]})


def emit_pre_tool(
    decision: str = "allow",
    reason: str | None = None,
    overwrite: dict[str, Any] | None = None,
) -> None:
    out: dict[str, Any] = {"decision": decision}
    if reason:
        out["reason"] = reason
    if overwrite:
        out["overwrite"] = overwrite
    emit_json(out)


def emit_stop_allow() -> None:
    emit_json({"decision": "allow"})


def emit_stop_continue(reason: str) -> None:
    emit_json({"decision": "continue", "reason": reason})


def read_json(path: str | pathlib.Path, default: Any = None) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default


def write_json(path: str | pathlib.Path, data: Any) -> bool:
    target = pathlib.Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
                fh.flush()
            os.replace(tmp, str(target))
            return True
        finally:
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
    except Exception:
        return False


def append_jsonl(path: str | pathlib.Path, record: dict[str, Any], max_bytes: int = 2_000_000) -> None:
    target = pathlib.Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.stat().st_size > max_bytes:
            rotated = target.with_suffix(target.suffix + ".1")
            try:
                os.replace(str(target), str(rotated))
            except OSError:
                pass
        line = json.dumps(record, ensure_ascii=False) + "\n"
        with open(target, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(line)
    except Exception:
        pass


def log_hook_event(stream: str, event_type: str, **fields: Any) -> None:
    rec = {"ts": round(time.time(), 3), "type": event_type}
    rec.update(fields)
    append_jsonl(state_dir("logs") / f"{stream}.jsonl", rec)


@contextmanager
def file_lock(lock_path: str | pathlib.Path, timeout: float = 3.0, stale: float = 30.0) -> Iterator[bool]:
    lp = pathlib.Path(lock_path)
    lp.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout
    acquired = False
    while time.monotonic() < deadline:
        try:
            fd = os.open(str(lp), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(f"{os.getpid()} {time.time()}\n")
            acquired = True
            break
        except FileExistsError:
            try:
                if time.time() - lp.stat().st_mtime > stale:
                    lp.unlink()
                    continue
            except OSError:
                pass
            time.sleep(0.03)
        except OSError:
            break
    try:
        yield acquired
    finally:
        if acquired:
            try:
                lp.unlink()
            except OSError:
                pass


def parse_iso_ts(raw: Any) -> float:
    if isinstance(raw, (int, float)):
        return float(raw)
    if not isinstance(raw, str) or not raw.strip():
        return 0.0
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        # INVARIANT: Naive strings (e.g. `board.jsonl` "YYYY-MM-DD HH:MM:SS") are local wall-clock time;
        # `datetime.timestamp()` converts naive datetimes using system local tz and aware datetimes using their offset.
        return datetime.fromisoformat(text).timestamp()
    except Exception:
        return 0.0


def _parse_jsonl_lines(lines: list[str]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for raw in lines:
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw)
        except Exception:
            continue
        if isinstance(obj, dict):
            items.append(obj)
    return items


def read_jsonl(path: str | pathlib.Path | None, max_lines: int | None = None) -> list[dict[str, Any]]:
    """Read JSONL dicts from `path`; when `max_lines` is set, preserve line 0 plus the tail without loading multi-MB files."""
    if not path:
        return []
    p = pathlib.Path(path)
    if not p.is_file():
        return []
    try:
        size = p.stat().st_size
        if max_lines is not None and max_lines > 0 and size > 131072:
            with p.open("rb") as fh:
                first_raw = fh.readline()
                first_line = first_raw.decode("utf-8", errors="replace")
                first_end = fh.tell()
                if max_lines == 1 or first_end >= size:
                    return _parse_jsonl_lines([first_line])
                window = max(65536, max_lines * 2048)
                seek_pos = max(first_end, size - window)
                fh.seek(seek_pos)
                tail_chunk = fh.read().decode("utf-8", errors="replace")
            tail_lines = tail_chunk.splitlines()
            if seek_pos > first_end and tail_lines:
                tail_lines = tail_lines[1:]
            picked = [first_line] + tail_lines[-(max_lines - 1) :]
            return _parse_jsonl_lines(picked)

        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []
    if max_lines is not None and max_lines > 0 and len(lines) > max_lines:
        lines = [lines[0]] + lines[-(max_lines - 1) :]
    return _parse_jsonl_lines(lines)


def resolve_transcript_path(transcript_path: str | None) -> pathlib.Path | None:
    if not transcript_path:
        return None
    p = pathlib.Path(transcript_path)
    if p.name == "transcript.jsonl":
        full = p.with_name("transcript_full.jsonl")
        if full.is_file():
            return full
    return p if p.is_file() else None


def read_transcript_steps(transcript_path: str | None, max_lines: int = 4000) -> list[dict[str, Any]]:
    tp = resolve_transcript_path(transcript_path)
    if tp is None:
        return []
    return read_jsonl(tp, max_lines=max_lines)


def subagent_parent_id(transcript_path: str | None, steps: list[dict[str, Any]] | None = None) -> str | None:
    items = steps if steps is not None else read_transcript_steps(transcript_path, max_lines=5)
    if not items:
        return None
    first = items[0]
    if first.get("source") == "SYSTEM" and first.get("type") == "SYSTEM_MESSAGE":
        content = str(first.get("content") or "")
        m = SUBAGENT_MSG_RE.search(content)
        if m:
            return m.group("sender")
        if "<swarm_worker>" in content or "post_message" in content or "swarm_wait" in content:
            return "swarm-coordinator"
    return None


def is_subagent_session(transcript_path: str | None, steps: list[dict[str, Any]] | None = None) -> bool:
    return subagent_parent_id(transcript_path, steps=steps) is not None


def last_assistant_message(steps: list[dict[str, Any]]) -> str:
    for step in reversed(steps):
        if step.get("source") == "MODEL" and step.get("type") == "PLANNER_RESPONSE":
            tool_calls = step.get("tool_calls")
            content = str(step.get("content") or "")
            if content.strip():
                return content
            if tool_calls:
                return ""
        if step.get("source") == "USER_EXPLICIT" and step.get("type") == "USER_INPUT":
            break
    return ""


CD_LEADING_RE = re.compile(
    r"^\s*(?:cd(?:\s+/d)?|Set-Location|Push-Location)\s+[\"']?(?P<dir>[^\"';&|\r\n]+)[\"']?",
    re.IGNORECASE,
)
GIT_DASH_C_RE = re.compile(r"\bgit(?:\.exe)?\s+-C\s+[\"']?(?P<dir>[^\"';&|\r\n]+)[\"']?", re.IGNORECASE)


def subprocess_kwargs() -> dict[str, Any]:
    kw: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "capture_output": True,
    }
    if os.name == "nt":
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    return kw


def run_git(
    cwd: str,
    args: list[str],
    timeout: float = 5.0,
    text: bool = True,
    env: dict[str, str] | None = None,
) -> tuple[int, str | bytes, str]:
    try:
        proc = subprocess.run(
            ["git", "--no-optional-locks"] + args,
            cwd=cwd,
            env=env,
            timeout=max(0.25, timeout),
            **subprocess_kwargs(),
        )
    except Exception as exc:
        return 127, "" if text else b"", str(exc)
    err = proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""
    if text:
        out = proc.stdout.decode("utf-8", errors="replace") if proc.stdout else ""
        return proc.returncode, out, err
    return proc.returncode, proc.stdout or b"", err


def git_toplevel(cwd: str | None) -> str | None:
    if not cwd or not os.path.isdir(cwd):
        return None
    rc, out, _ = run_git(cwd, ["rev-parse", "--show-toplevel"], timeout=3.0)
    if rc == 0 and isinstance(out, str) and out.strip():
        return os.path.abspath(out.strip())
    return None


def git_head_oid(git_root: str) -> str:
    if not git_root or not os.path.isdir(git_root):
        return ""
    rc, out, _ = run_git(git_root, ["rev-parse", "--verify", "-q", "HEAD"], timeout=3.0)
    return str(out or "").strip() if rc == 0 else ""


def capture_worktree_tree_oid(git_root: str, timeout: float = 15.0) -> tuple[str, str]:
    """Capture current tracked+untracked worktree state as a git tree OID without mutating `.git/index`."""
    if not git_root or not os.path.isdir(git_root):
        return "", "invalid_git_root"
    rc_idx, idx_path_out, _ = run_git(git_root, ["rev-parse", "--git-path", "index"], timeout=3.0)
    idx_rel = str(idx_path_out or "").strip() if rc_idx == 0 else ""
    real_idx = os.path.join(git_root, idx_rel) if idx_rel and not os.path.isabs(idx_rel) else idx_rel

    tmp_dir = tempfile.mkdtemp(prefix="carbon-idx-")
    tmp_index = os.path.join(tmp_dir, "index")
    try:
        if real_idx and os.path.isfile(real_idx):
            shutil.copy2(real_idx, tmp_index)
        env = dict(os.environ, GIT_INDEX_FILE=tmp_index)
        rc1, _, err1 = run_git(git_root, ["add", "-A"], timeout=timeout, text=True, env=env)
        if rc1 != 0:
            return "", f"git_add_failed:{err1.strip()[:160]}"
        rc2, tree_sha, err2 = run_git(git_root, ["write-tree"], timeout=timeout, text=True, env=env)
        tree_str = str(tree_sha or "").strip()
        if rc2 != 0 or not tree_str:
            return "", f"git_write_tree_failed:{err2.strip()[:160]}"
        return tree_str, ""
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def resolve_command_cwd(cmd: str, default_cwd: str, fallback_dir: str = "") -> str:
    for pat in (CD_LEADING_RE, GIT_DASH_C_RE):
        m = pat.search(cmd or "") if pat is GIT_DASH_C_RE else pat.match(cmd or "")
        if m:
            raw_dir = m.group("dir").strip()
            candidate = raw_dir if os.path.isabs(raw_dir) else os.path.join(default_cwd, raw_dir)
            if os.path.isdir(candidate):
                return os.path.abspath(candidate)
    if fallback_dir and os.path.isdir(fallback_dir) and not git_toplevel(default_cwd):
        return os.path.abspath(fallback_dir)
    return default_cwd


def find_agy_cli() -> str | None:
    on_path = shutil.which("agy") or shutil.which("agy.exe")
    if on_path:
        return on_path
    default_win = pathlib.Path.home() / "AppData" / "Local" / "agy" / "bin" / "agy.exe"
    return str(default_win) if default_win.is_file() else None
