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
SWARM_BOARD_WAKE_BODY_RE = re.compile(
    r"\A\[swarm\]\s+new board message\s+#\d+\s*(?:</SYSTEM_MESSAGE>)?\s*\Z"
)
SWARM_WAKE_SEQ_RE = re.compile(
    r"(?:\[swarm\]\s+new board message|recorded on the board as)\s+#(\d+)",
    re.IGNORECASE,
)
SWARM_ROLE_MEMBER_RE = re.compile(r"^(?:narrator|monitor)(?:-\d+)?$", re.IGNORECASE)
WORKER_ENV_KEYS = ("SWARM_WORKER_NAME", "WORKER_NAME", "AGY_SWARM_WORKER", "AGY_WORKER_NAME")
COORDINATOR_ROLE_NAMES = frozenset({"coordinator", "main", "primary", "root", "lead"})
BG_TASK_ID_RE = re.compile(r"running as a background task with task id:\s*(\S+)", re.IGNORECASE)

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


def chat_bus_cli_path() -> str:
    return normalize_path(plugin_root().parent / "chat-bus" / "tools" / "chat_bus_cli.py")


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


def is_plugin_runtime_dir(path: str | pathlib.Path | None) -> bool:
    norm = normalize_path(path)
    if not norm:
        return False
    folded = fold_path(norm)
    proot = fold_path(plugin_root())
    if proot and (folded == proot or folded.startswith(proot + "/")):
        return True
    low = "/" + norm.lower().lstrip("/")
    if "/.gemini/config/plugins/" in low or low.endswith("/.gemini/config/plugins"):
        return True
    if os.name == "nt" and "/appdata/local/programs/antigravity" in low:
        return True
    return False


def project_key(
    cwd: str | None,
    workspace_paths: list[str] | None = None,
    known_git_root: str | None = None,
    session: str = "",
) -> str:
    candidate = ""
    has_explicit_ws = False
    if workspace_paths:
        for wp in workspace_paths:
            if isinstance(wp, str) and wp.strip():
                candidate = wp.strip()
                has_explicit_ws = True
                break
    if not candidate and cwd and str(cwd).strip():
        cand_str = str(cwd).strip()
        if not is_plugin_runtime_dir(cand_str):
            candidate = cand_str

    # INVARIANT: Workspace-less chats must never share the installed plugin directory's project_key.
    if not candidate:
        sid = safe_key(session, "ephemeral")
        digest = hashlib.sha256(f"ephemeral-session:{sid}".encode("utf-8", errors="replace")).hexdigest()[:12]
        return f"ephemeral-{sid[:24]}-{digest}"

    git_root = known_git_root if known_git_root is not None else git_toplevel(candidate)
    if git_root and is_plugin_runtime_dir(git_root) and not has_explicit_ws:
        git_root = None
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
    if not isinstance(payload, dict):
        cwd0 = os.getcwd()
        return "" if is_plugin_runtime_dir(cwd0) else cwd0

    valid_wps: list[str] = []
    wps = payload.get("workspacePaths")
    if isinstance(wps, list):
        for wp in wps:
            if isinstance(wp, str) and wp.strip() and os.path.isdir(wp):
                valid_wps.append(os.path.abspath(wp))

    raw_cwd = payload.get("cwd")
    if isinstance(raw_cwd, str) and raw_cwd.strip() and os.path.isdir(raw_cwd):
        abs_cwd = os.path.abspath(raw_cwd)
        if not is_plugin_runtime_dir(abs_cwd):
            return abs_cwd
        folded_cwd = fold_path(abs_cwd)
        for wp in valid_wps:
            fwp = fold_path(wp)
            if folded_cwd == fwp or folded_cwd.startswith(fwp + "/"):
                return abs_cwd

    if valid_wps:
        return valid_wps[0]

    fallback = os.getcwd()
    return "" if is_plugin_runtime_dir(fallback) else fallback


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


def dump_cli_json(payload: Any, pretty: bool = False) -> str:
    if pretty:
        return json.dumps(payload, ensure_ascii=False, indent=2)
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def print_cli_json(payload: Any, pretty: bool = False) -> None:
    sys.stdout.buffer.write((dump_cli_json(payload, pretty=pretty) + "\n").encode("utf-8"))
    sys.stdout.buffer.flush()


def emit_json(obj: dict[str, Any]) -> None:
    print_cli_json(obj, pretty=False)


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
        if max_lines == 1:
            with p.open("rb") as fh:
                first_line = fh.readline().decode("utf-8", errors="replace")
            return _parse_jsonl_lines([first_line])
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


_COMPACT_JSON_SCALAR_RE = re.compile(r"^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)$")


def _decode_compact_arg_map(raw_args: dict[str, Any]) -> dict[str, Any] | None:
    decoded_map: dict[str, Any] = {}
    for k, v in raw_args.items():
        if not isinstance(v, str) or not v:
            return None
        if v[0] not in ('"', "[", "{") and not _COMPACT_JSON_SCALAR_RE.match(v):
            return None
        try:
            decoded_map[k] = json.loads(v)
        except json.JSONDecodeError:
            return None
    return decoded_map


def _decode_compact_step_args(steps: list[dict[str, Any]]) -> None:
    # INVARIANT: Antigravity's compact `transcript.jsonl` encodes every `tool_calls[*].args` value as a JSON string
    # (`map<string, string>`), whereas `transcript_full.jsonl` stores decoded JSON values. Decode compact args strictly
    # once at the `transcript.jsonl` reader boundary so downstream PowerShell/CLI parsers never strip user quotes.
    pending: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for st in steps:
        tcs = st.get("tool_calls")
        if not isinstance(tcs, list):
            continue
        for tc in tcs:
            if not isinstance(tc, dict):
                continue
            raw_args = tc.get("args")
            if not isinstance(raw_args, dict) or not raw_args:
                continue
            decoded_map = _decode_compact_arg_map(raw_args)
            if decoded_map is None:
                return
            pending.append((tc, decoded_map))
    for tc, decoded_map in pending:
        tc["args"] = decoded_map


def _read_decoded_transcript(tp: pathlib.Path, max_lines: int) -> list[dict[str, Any]]:
    steps = read_jsonl(tp, max_lines=max_lines)
    if tp.name == "transcript.jsonl" and steps:
        _decode_compact_step_args(steps)
    return steps


def read_transcript_steps(transcript_path: str | None, max_lines: int = 4000) -> list[dict[str, Any]]:
    tp = resolve_transcript_path(transcript_path)
    if tp is None:
        return []
    return _read_decoded_transcript(tp, max_lines=max_lines)


def read_compact_transcript_steps(transcript_path: str | None, max_lines: int = 16000) -> list[dict[str, Any]]:
    if not transcript_path:
        return []
    return _read_decoded_transcript(pathlib.Path(transcript_path).with_name("transcript.jsonl"), max_lines=max_lines)


def read_transcript_head(transcript_path: str | None, head_lines: int = 8) -> list[dict[str, Any]]:
    tp = resolve_transcript_path(transcript_path)
    if tp is None or head_lines <= 0:
        return []
    raw_lines: list[str] = []
    try:
        with tp.open("rb") as fh:
            for _ in range(head_lines):
                raw = fh.readline()
                if not raw:
                    break
                raw_lines.append(raw.decode("utf-8", errors="replace"))
    except OSError:
        return []
    steps = _parse_jsonl_lines(raw_lines)
    if tp.name == "transcript.jsonl" and steps:
        _decode_compact_step_args(steps)
    return steps


def _is_system_message(step: dict[str, Any] | None) -> bool:
    return bool(step and step.get("source") == "SYSTEM" and step.get("type") == "SYSTEM_MESSAGE")


def _has_prefix_slice_gap(items: list[dict[str, Any]]) -> bool:
    if not items or not isinstance(items[0], dict):
        return False
    s0 = items[0].get("step_index")
    if isinstance(s0, int) and s0 > 0:
        return True
    if len(items) < 2 or not isinstance(items[1], dict):
        return False
    s1 = items[1].get("step_index")
    if isinstance(s0, int) and isinstance(s1, int):
        return s1 > s0 + 1
    return (
        items[0].get("source") == "SYSTEM_SDK"
        and items[1].get("source") not in ("SYSTEM_SDK", "USER_EXPLICIT")
    )


has_prefix_slice_gap = _has_prefix_slice_gap


def _leading_system_messages(
    transcript_path: str | None,
    steps: list[dict[str, Any]] | None = None,
    max_lines: int = 8,
) -> list[dict[str, Any]]:
    # INVARIANT: Read true prefix lines (`read_transcript_head`) whenever `steps` is omitted or has a tail-slice gap
    # (even when the first tail step happens to be a late `SYSTEM_MESSAGE`), and never cross a `step_index` gap.
    if steps is None:
        items = read_transcript_head(transcript_path, head_lines=max_lines)
    else:
        items = steps
        if transcript_path and _has_prefix_slice_gap(items):
            head_items = read_transcript_head(transcript_path, head_lines=max_lines)
            if head_items:
                items = head_items
    out: list[dict[str, Any]] = []
    prev_idx: int | None = None
    for st in items:
        if not isinstance(st, dict):
            break
        cur_idx = st.get("step_index")
        if isinstance(cur_idx, int):
            if (prev_idx is None and cur_idx > 0) or (prev_idx is not None and cur_idx > prev_idx + 1):
                break
            prev_idx = cur_idx
        if st.get("source") == "SYSTEM_SDK":
            if out:
                break
            continue
        if _is_system_message(st):
            out.append(st)
        else:
            break
    return out


def _first_system_content(
    transcript_path: str | None, steps: list[dict[str, Any]] | None = None
) -> str | None:
    lead = _leading_system_messages(transcript_path, steps=steps)
    if lead:
        return str(lead[0].get("content") or "")
    return None


def subagent_parent_id(transcript_path: str | None, steps: list[dict[str, Any]] | None = None) -> str | None:
    for st in _leading_system_messages(transcript_path, steps=steps):
        content = str(st.get("content") or "")
        m = SUBAGENT_MSG_RE.search(content)
        if m:
            sender = m.group("sender")
            if sender.lower() == "system":
                continue
            return sender
        if content.lstrip().startswith("<swarm_worker>") or "post_message" in content or "swarm_wait" in content:
            return "swarm-coordinator"
    return None


def swarm_dir(brain_root: pathlib.Path, session: str) -> pathlib.Path:
    return brain_root / session / ".system_generated" / "swarm"


def resolve_brain_root(override: str = "") -> pathlib.Path:
    raw = (override or os.environ.get("ANTIGRAVITY_BRAIN_ROOT") or "").strip()
    if raw:
        return pathlib.Path(raw).expanduser().resolve()
    return (pathlib.Path.home() / ".gemini" / "antigravity" / "brain").resolve()


def member_transcript_path(brain_root: pathlib.Path, cid: str) -> pathlib.Path:
    return brain_root / cid / ".system_generated" / "logs" / "transcript.jsonl"


def load_swarm_members(brain_root: pathlib.Path, session: str) -> dict[str, Any]:
    doc = read_json(swarm_dir(brain_root, session) / "members.json", default=None)
    if isinstance(doc, dict) and isinstance(doc.get("members"), dict):
        return doc["members"]
    return doc if isinstance(doc, dict) else {}


def is_swarm_role_member(name: str, meta: dict[str, Any] | None = None) -> bool:
    role_val = str((meta or {}).get("role") or "worker").strip().lower()
    return (
        name == "coordinator"
        or role_val in ("coordinator", "narrator", "monitor")
        or bool(SWARM_ROLE_MEMBER_RE.match(name))
    )


def is_swarm_member_killed(meta: dict[str, Any] | None) -> bool:
    if not isinstance(meta, dict):
        return False
    return bool(
        meta.get("killed")
        or str(meta.get("phase") or "").strip().upper() == "KILLED"
        or str(meta.get("desired_state") or "").strip().upper() == "KILLED"
    )


def _swarm_brain_and_cid(
    transcript_path: str | None, conversation_id: str | None = None
) -> tuple[pathlib.Path | None, str]:
    req_cid = str(conversation_id or "").strip()
    derived_brain: pathlib.Path | None = None
    derived_cid = ""
    if transcript_path:
        try:
            tp = pathlib.Path(str(transcript_path)).resolve()
            if len(tp.parts) >= 5 and tp.parent.name == "logs" and tp.parents[1].name == ".system_generated":
                derived_cid = tp.parents[2].name
                derived_brain = tp.parents[3]
        except (OSError, ValueError, RuntimeError):
            pass
    if req_cid and derived_cid and req_cid != derived_cid:
        return None, ""
    worker_cid = req_cid or derived_cid
    if not worker_cid:
        return None, ""
    if derived_brain is None:
        env_dir = os.environ.get("ANTIGRAVITY_BRAIN_ROOT", "").strip()
        cand_brain = resolve_brain_root(env_dir)
        if env_dir or cand_brain.is_dir():
            derived_brain = cand_brain
    return derived_brain, worker_cid


def _find_active_worker_entry(
    members: dict[str, Any], worker_cid: str
) -> tuple[str, dict[str, Any]] | None:
    for name, meta in members.items():
        if not isinstance(meta, dict) or is_swarm_member_killed(meta) or is_swarm_role_member(name, meta):
            continue
        cid = str(meta.get("conversation_id") or meta.get("conversationId") or "").strip()
        if cid == worker_cid:
            return str(name), meta
    return None


def _resolve_registered_swarm_worker(
    brain_root: pathlib.Path | None,
    worker_cid: str,
    candidate_sessions: list[str] | tuple[str, ...],
) -> dict[str, Any] | None:
    if brain_root is None or not worker_cid:
        return None
    seen: set[str] = set()

    def _pack(coord_sid: str, name: str, meta: dict[str, Any]) -> dict[str, Any]:
        return {
            "coordinator": coord_sid,
            "worker_name": name,
            "model": str(meta.get("model") or "registered").strip().lower() or "registered",
            "added_by": str(meta.get("added_by") or "").strip(),
            "board_path": swarm_dir(brain_root, coord_sid) / "board.jsonl",
        }

    for sid in candidate_sessions:
        clean_sid = (sid or "").strip()
        if not clean_sid or clean_sid in seen:
            continue
        seen.add(clean_sid)
        hit = _find_active_worker_entry(load_swarm_members(brain_root, clean_sid), worker_cid)
        if hit is not None:
            return _pack(clean_sid, hit[0], hit[1])
    # INVARIANT: Peer-sender step-0 on >128KB transcripts may omit step-1 coordinator sender; scan swarm registries on disk.
    try:
        for mf in brain_root.glob("*/.system_generated/swarm/members.json"):
            sid = mf.parents[2].name
            if sid in seen:
                continue
            seen.add(sid)
            hit = _find_active_worker_entry(load_swarm_members(brain_root, sid), worker_cid)
            if hit is not None:
                return _pack(sid, hit[0], hit[1])
    except OSError:
        return None
    return None


def resolve_swarm_worker_assignment(
    transcript_path: str | None,
    steps: list[dict[str, Any]] | None = None,
    conversation_id: str | None = None,
) -> dict[str, Any] | None:
    lead = _leading_system_messages(transcript_path, steps=steps, max_lines=8)
    if not lead:
        return None
    candidate_sids: list[str] = []
    saw_swarm_wake = False
    for st in lead:
        content = str(st.get("content") or "")
        m = SUBAGENT_MSG_RE.search(content)
        if m:
            sender = m.group("sender")
            if sender.lower() != "system":
                candidate_sids.append(sender)
            if SWARM_BOARD_WAKE_BODY_RE.match(m.group("body") or ""):
                saw_swarm_wake = True
        elif content.lstrip().startswith("<swarm_worker>"):
            saw_swarm_wake = True
    if not saw_swarm_wake:
        return None
    brain_root, worker_cid = _swarm_brain_and_cid(transcript_path, conversation_id=conversation_id)
    return _resolve_registered_swarm_worker(brain_root, worker_cid, candidate_sids)


def swarm_worker_model(
    transcript_path: str | None,
    steps: list[dict[str, Any]] | None = None,
    conversation_id: str | None = None,
) -> str:
    info = resolve_swarm_worker_assignment(
        transcript_path,
        steps=steps,
        conversation_id=conversation_id,
    )
    return str(info["model"]) if info else ""


def is_swarm_worker_session(
    transcript_path: str | None,
    steps: list[dict[str, Any]] | None = None,
    conversation_id: str | None = None,
) -> bool:
    return bool(
        swarm_worker_model(
            transcript_path,
            steps=steps,
            conversation_id=conversation_id,
        )
    )


def swarm_mention_patterns(wname: str, *, include_group: bool = True) -> list[re.Pattern[str]]:
    pats = [re.compile(rf"(?<![A-Za-z0-9_-])@{re.escape(wname)}(?![A-Za-z0-9_-])", re.IGNORECASE)]
    if include_group and re.search(r"-\d+$", wname):
        group_prefix = wname.rsplit("-", 1)[0]
        if group_prefix:
            pats.append(re.compile(rf"(?<![A-Za-z0-9_-])@{re.escape(group_prefix)}(?![A-Za-z0-9_-])", re.IGNORECASE))
    return pats


def latest_board_assign_and_reply_seq(
    raw_board: list[dict[str, Any]],
    wname: str,
    added_by: str = "",
) -> tuple[int, int]:
    clean_added = added_by.strip()
    assigners = {"coordinator", clean_added} if clean_added else {"coordinator"}
    mention_pats = swarm_mention_patterns(wname)
    last_assign_seq = 0
    last_reply_seq = 0
    for idx, bp in enumerate(raw_board, start=1):
        seq = int(bp.get("seq") or idx)
        poster = str(bp.get("agent") or "")
        btext = str(bp.get("text") or "")
        if poster in assigners and (any(mp.search(btext) for mp in mention_pats) or "@all" in btext.lower()):
            last_assign_seq = seq
        elif poster == wname:
            last_reply_seq = seq
    return last_assign_seq, last_reply_seq


def inspect_worker_turn_after_wake(
    w_steps: list[dict[str, Any]],
    last_assign_seq: int,
) -> dict[str, Any]:
    last_wake_idx = -1
    max_wake_seq = 0
    for idx, st in enumerate(w_steps):
        if st.get("source") == "SYSTEM" and st.get("type") == "SYSTEM_MESSAGE":
            hits = [int(x) for x in SWARM_WAKE_SEQ_RE.findall(str(st.get("content") or ""))]
            if hits:
                max_wake_seq = max(max_wake_seq, max(hits))
                last_wake_idx = idx
    tail = w_steps[last_wake_idx + 1 :] if last_wake_idx >= 0 else w_steps
    saw_model = False
    called_post = False
    has_error = False
    pending_bg: set[str] = set()
    last_model_tcs: list[Any] = []
    for st in tail:
        stype = str(st.get("type") or "")
        sstatus = str(st.get("status") or "")
        scontent = str(st.get("content") or "")
        if st.get("source") == "SYSTEM":
            for tid in list(pending_bg):
                if f'Task id "{tid}" finished' in scontent or f'Task id "{tid}" was canceled' in scontent:
                    pending_bg.discard(tid)
        if stype == "ERROR_MESSAGE" or (st.get("source") == "MODEL" and stype != "GENERIC" and sstatus == "ERROR"):
            has_error = True
        if st.get("source") == "MODEL" and stype == "PLANNER_RESPONSE":
            saw_model = True
            last_model_tcs = st.get("tool_calls") or []
            if any(isinstance(tc, dict) and tc.get("name") == "post_message" for tc in last_model_tcs):
                called_post = True
        elif stype == "GENERIC":
            m_bg = BG_TASK_ID_RE.search(scontent)
            if m_bg:
                pending_bg.add(m_bg.group(1))

    terminal_parked = False
    if tail:
        last_st = tail[-1]
        last_type = str(last_st.get("type") or "")
        last_status = str(last_st.get("status") or "")
        if (
            last_st.get("source") == "MODEL"
            and last_type == "PLANNER_RESPONSE"
            and last_status == "DONE"
            and not (last_st.get("tool_calls") or [])
        ):
            terminal_parked = True
        else:
            prev_called_wait = len(tail) >= 2 and any(
                isinstance(tc, dict) and tc.get("name") == "swarm_wait"
                for tc in (tail[-2].get("tool_calls") or [])
            )
            terminal_parked = bool(
                last_type == "GENERIC"
                and last_status == "DONE"
                and ("waiting for a message" in str(last_st.get("content") or "").lower() or prev_called_wait)
            )

    return {
        "last_wake_idx": last_wake_idx,
        "max_wake_seq": max_wake_seq,
        "woke_for_assign": max_wake_seq >= last_assign_seq and last_wake_idx >= 0,
        "has_tail": bool(tail),
        "saw_model": saw_model,
        "called_post": called_post,
        "has_error": has_error,
        "pending_bg": pending_bg,
        "last_model_tcs": last_model_tcs,
        "terminal_parked": terminal_parked,
    }


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


def mutation_stamp_path(session: str) -> pathlib.Path:
    return state_dir("continuity", "stamps") / f"{safe_key(session)}.stamp"


def bump_mutation_stamp(session: str) -> None:
    if not session or session == "unknown":
        return
    sp = mutation_stamp_path(session)
    try:
        cur = int(sp.read_text(encoding="ascii").strip() or "0") if sp.is_file() else 0
    except (OSError, ValueError):
        cur = 0
    try:
        sp.write_text(f"{cur + 1}\n", encoding="ascii")
    except OSError:
        pass


def read_mutation_stamp(session: str) -> int:
    if not session or session == "unknown":
        return 0
    sp = mutation_stamp_path(session)
    try:
        return int(sp.read_text(encoding="ascii").strip() or "0") if sp.is_file() else 0
    except (OSError, ValueError):
        return 0


TOKENADE_WRAP_SEG_RE = re.compile(
    r"(?:^|(?<=[;\r\n|&]))\s*(?:\$null\s*\|\s*)?(?:&\s*)?"
    r"(?:'(?:''|[^'\r\n])*tokenade(?:\.cmd|\.exe)?'|\"[^\"`$\r\n]*tokenade(?:\.cmd|\.exe)?\"|[^\s|;&\"'`$()\r\n]*tokenade(?:\.cmd|\.exe)?)"
    r"\s+(?:wrap|exec-compact|raw|bypass|noproxy|shellwrap)\b(?:\s+--shell\s+[A-Za-z0-9_.-]+)?\s+"
    r"(?P<inner>'(?:''|[^'])*'|\"(?:`[\s\S]|\"\"|[^\"`])*\"|[^|;&\"'\r\n]+?)(?=\s*(?:$|[;\r\n|&]))",
    re.IGNORECASE,
)


def _unquote_wrapped_inner(m: re.Match[str]) -> str:
    inner = m.group("inner").strip()
    if len(inner) >= 2 and inner[0] == "'" and inner[-1] == "'":
        inner = inner[1:-1].replace("''", "'").strip()
    elif len(inner) >= 2 and inner[0] == '"' and inner[-1] == '"':
        inner = re.sub(r"`([\s\S])", r"\1", inner[1:-1].replace('""', '"')).strip()
    return inner


def unwrap_tokenade_command(cmd: str) -> str:
    # SAFETY: Unwrap Tokenade CLI wrappers so gate classification and destructive-command guards inspect the real payload.
    s = re.sub(r"^\s*\$null\s*\|\s*", "", (cmd or "").strip(), flags=re.IGNORECASE)
    if "tokenade" not in s.lower():
        return s
    for _ in range(3):
        nxt = TOKENADE_WRAP_SEG_RE.sub(_unquote_wrapped_inner, s)
        if nxt == s:
            break
        s = re.sub(r"^\s*\$null\s*\|\s*", "", nxt.strip(), flags=re.IGNORECASE)
    return s


def resolve_command_cwd(cmd: str, default_cwd: str, fallback_dir: str = "") -> str:
    unwrapped = unwrap_tokenade_command(cmd or "")
    for pat in (CD_LEADING_RE, GIT_DASH_C_RE):
        m = pat.search(unwrapped) if pat is GIT_DASH_C_RE else pat.match(unwrapped)
        if m:
            raw_dir = m.group("dir").strip()
            if os.path.isabs(raw_dir):
                candidate = raw_dir
            elif default_cwd:
                candidate = os.path.join(default_cwd, raw_dir)
            else:
                candidate = ""
            if candidate and os.path.isdir(candidate):
                return os.path.abspath(candidate)
    if fallback_dir and os.path.isdir(fallback_dir):
        if not default_cwd:
            return os.path.abspath(fallback_dir)
        f_def = fold_path(default_cwd)
        f_fb = fold_path(fallback_dir)
        if (f_def == f_fb or f_def.startswith(f_fb + "/")) and (pathlib.Path(fallback_dir) / ".git").exists():
            return default_cwd
        if not git_toplevel(default_cwd):
            return os.path.abspath(fallback_dir)
    return default_cwd


def find_agy_cli() -> str | None:
    on_path = shutil.which("agy") or shutil.which("agy.exe")
    if on_path:
        return on_path
    default_win = pathlib.Path.home() / "AppData" / "Local" / "agy" / "bin" / "agy.exe"
    return str(default_win) if default_win.is_file() else None
