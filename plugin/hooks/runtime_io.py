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
SWARM_ROLE_MEMBER_RE = re.compile(r"^(?:narrator|monitor)(?:-\d+)?$", re.IGNORECASE)

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


def read_transcript_steps(transcript_path: str | None, max_lines: int = 4000) -> list[dict[str, Any]]:
    tp = resolve_transcript_path(transcript_path)
    if tp is None:
        return []
    steps = read_jsonl(tp, max_lines=max_lines)
    if tp.name == "transcript.jsonl" and steps:
        _decode_compact_step_args(steps)
    return steps


def _is_system_message(step: dict[str, Any] | None) -> bool:
    return bool(step and step.get("source") == "SYSTEM" and step.get("type") == "SYSTEM_MESSAGE")


def _first_system_content(
    transcript_path: str | None, steps: list[dict[str, Any]] | None = None
) -> str | None:
    items = steps if steps is not None else read_transcript_steps(transcript_path, max_lines=1)
    if items and _is_system_message(items[0]):
        return str(items[0].get("content") or "")
    return None


def subagent_parent_id(transcript_path: str | None, steps: list[dict[str, Any]] | None = None) -> str | None:
    content = _first_system_content(transcript_path, steps=steps)
    if content is None:
        return None
    m = SUBAGENT_MSG_RE.search(content)
    if m:
        return m.group("sender")
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


def _find_active_worker_model(members: dict[str, Any], worker_cid: str) -> str | None:
    for name, meta in members.items():
        if not isinstance(meta, dict) or is_swarm_member_killed(meta) or is_swarm_role_member(name, meta):
            continue
        cid = str(meta.get("conversation_id") or meta.get("conversationId") or "").strip()
        if cid == worker_cid:
            return str(meta.get("model") or "registered").strip().lower() or "registered"
    return None


def _registered_swarm_worker_model(
    brain_root: pathlib.Path | None,
    worker_cid: str,
    candidate_sessions: list[str] | tuple[str, ...],
) -> str:
    if brain_root is None or not worker_cid:
        return ""
    seen: set[str] = set()
    for sid in candidate_sessions:
        clean_sid = (sid or "").strip()
        if not clean_sid or clean_sid in seen:
            continue
        seen.add(clean_sid)
        found = _find_active_worker_model(load_swarm_members(brain_root, clean_sid), worker_cid)
        if found is not None:
            return found
    # INVARIANT: Peer-sender step-0 on >128KB transcripts may omit step-1 coordinator sender; scan swarm registries on disk.
    try:
        for mf in brain_root.glob("*/.system_generated/swarm/members.json"):
            sid = mf.parents[2].name
            if sid in seen:
                continue
            seen.add(sid)
            found = _find_active_worker_model(load_swarm_members(brain_root, sid), worker_cid)
            if found is not None:
                return found
    except OSError:
        return ""
    return ""


def swarm_worker_model(
    transcript_path: str | None,
    steps: list[dict[str, Any]] | None = None,
    conversation_id: str | None = None,
) -> str:
    items = steps if steps is not None else read_transcript_steps(transcript_path, max_lines=5)
    if not items or not _is_system_message(items[0]):
        return ""
    m0 = SUBAGENT_MSG_RE.search(str(items[0].get("content") or ""))
    if not m0 or not SWARM_BOARD_WAKE_BODY_RE.match(m0.group("body") or ""):
        return ""

    candidate_sids = [m0.group("sender")]
    if len(items) > 1 and _is_system_message(items[1]):
        m1 = SUBAGENT_MSG_RE.search(str(items[1].get("content") or ""))
        if m1:
            candidate_sids.append(m1.group("sender"))

    brain_root, worker_cid = _swarm_brain_and_cid(transcript_path, conversation_id=conversation_id)
    return _registered_swarm_worker_model(brain_root, worker_cid, candidate_sids)


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
