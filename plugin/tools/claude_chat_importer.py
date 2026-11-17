#!/usr/bin/env python3
"""Import interactive Claude Code chat sessions (~/.claude/projects) into Google Antigravity across all 5 storage layers."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
import glob
import json
import os
import re
import shutil
import sqlite3
import sys
from typing import Any
import uuid

DEFAULT_CLAUDE_PROJECTS_DIR = os.path.join(os.path.expanduser("~"), ".claude", "projects")
DEFAULT_ANTIGRAVITY_DIR = os.path.join(os.path.expanduser("~"), ".gemini", "antigravity")

EXCLUDED_PROJECT_PATTERNS = re.compile(r"(-bench$|-shim$|-scratchpad)", re.IGNORECASE)

EXCLUDED_SINGLE_PROMPTS = frozenset(
    {
        "Say exactly: PONG",
        "Reply with exactly: PONG",
        "Ответь ровно одним словом: готов",
        "Ответь одним словом по-русски: столица Франции?",
        "тест",
    }
)

SYNTHETIC_CONTINUATION_PREFIX = "This session is being continued from a previous conversation"

MAX_RESPONSE_CHARS = 32_000
MAX_THINKING_CHARS = 12_000
CHECKPOINT_TURN_THRESHOLD = 16
CHECKPOINT_CHAR_THRESHOLD = 35_000
KEEP_RECENT_TURNS_AFTER_CHECKPOINT = 6

# INVARIANT: Deterministic UUIDv5 namespace guarantees idempotent trajectory/step IDs across re-runs.
NS_IMPORT = uuid.UUID("a4b8f19c-7d3e-4b2a-9f1c-6e5d4c3b2a10")


def stable_uuid(seed: str) -> str:
    return str(uuid.uuid5(NS_IMPORT, seed))


def stable_hex32(seed: str) -> str:
    return uuid.uuid5(NS_IMPORT, seed).hex


def encode_varint(value: int) -> bytes:
    if value < 0:
        value &= (1 << 64) - 1
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def field_varint(fn: int, value: int, force: bool = False) -> bytes:
    if not value and not force:
        return b""
    return encode_varint((fn << 3) | 0) + encode_varint(value)


def field_bytes(fn: int, data: bytes) -> bytes:
    if not data:
        return b""
    return encode_varint((fn << 3) | 2) + encode_varint(len(data)) + data


def field_str(fn: int, text: str) -> bytes:
    if not text:
        return b""
    return field_bytes(fn, text.encode("utf-8"))


def parse_varint_at(buf: bytes, pos: int) -> tuple[int, int]:
    res = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        res |= (b & 0x7F) << shift
        if not (b & 0x80):
            return res, pos
        shift += 7


def parse_wire_fields(buf: bytes) -> list[tuple[int, int, Any]]:
    pos = 0
    out: list[tuple[int, int, Any]] = []
    while pos < len(buf):
        tag, pos = parse_varint_at(buf, pos)
        fn = tag >> 3
        wt = tag & 7
        if wt == 0:
            val, pos = parse_varint_at(buf, pos)
        elif wt == 1:
            val = buf[pos : pos + 8]
            pos += 8
        elif wt == 2:
            ln, pos = parse_varint_at(buf, pos)
            val = buf[pos : pos + ln]
            pos += ln
        elif wt == 5:
            val = buf[pos : pos + 4]
            pos += 4
        else:
            raise ValueError(f"Unsupported wire type {wt} at pos {pos}")
        out.append((fn, wt, val))
    return out


def parse_iso_timestamp(ts_str: str | None, fallback_epoch: float) -> tuple[int, int]:
    if ts_str:
        try:
            s = ts_str.strip()
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            dt_utc = dt.astimezone(timezone.utc)
            sec = int(dt_utc.timestamp())
            m = re.search(r"\.(\d+)", ts_str)
            if m:
                frac = (m.group(1) + "000000000")[:9]
                nanos = int(frac)
            else:
                nanos = dt_utc.microsecond * 1000
            return sec, nanos
        except Exception:
            pass
    sec = int(fallback_epoch)
    nanos = int((fallback_epoch - sec) * 1_000_000_000)
    nanos = max(0, min(999_999_999, nanos))
    return sec, nanos


def format_sqlite_datetime(sec: int, nanos: int) -> str:
    dt = datetime.fromtimestamp(sec, tz=timezone.utc)
    ticks_7 = nanos // 100
    if ticks_7:
        return f"{dt:%Y-%m-%d %H:%M:%S}.{ticks_7:07d}+00:00"
    return f"{dt:%Y-%m-%d %H:%M:%S}+00:00"


def timestamp_to_epoch_ns(sec: int, nanos: int) -> int:
    return sec * 1_000_000_000 + nanos


def timestamp_to_iso_localish(sec: int, nanos: int) -> str:
    dt = datetime.fromtimestamp(sec, tz=timezone.utc)
    return f"{dt:%Y-%m-%dT%H:%M:%S}Z"


def encode_timestamp(sec: int, nanos: int) -> bytes:
    return field_varint(1, sec) + field_varint(2, nanos)


@dataclass
class ToolInvocation:
    tool_id: str
    name: str
    arguments: dict[str, Any]
    result_preview: str = ""


@dataclass
class ConversationTurn:
    user_uuid: str
    user_text: str
    user_ts: str | None
    thinking_parts: list[str] = field(default_factory=list)
    text_parts: list[str] = field(default_factory=list)
    tool_calls: list[ToolInvocation] = field(default_factory=list)
    first_assistant_ts: str | None = None
    last_assistant_ts: str | None = None
    is_continuation_summary: bool = False


@dataclass
class ParsedSession:
    project_folder: str
    filepath: str
    session_id: str
    raw_title: str | None
    resolved_title: str
    cwd: str
    created_sec: int
    created_nanos: int
    last_mod_sec: int
    last_mod_nanos: int
    turns: list[ConversationTurn]
    human_user_count: int
    assistant_record_count: int
    user_uuids: list[str]


def clean_preview(text: str, max_len: int = 80) -> str:
    t = re.sub(r"<[^>]+>", " ", text)
    t = re.sub(r"\s+", " ", t).strip()
    if len(t) > max_len:
        return t[: max_len - 1].rstrip() + "…"
    return t or "Claude Code chat"


def summarize_tool_args(args: dict[str, Any]) -> str:
    if not isinstance(args, dict) or not args:
        return "{}"
    preferred_keys = (
        "command",
        "file_path",
        "path",
        "pattern",
        "query",
        "url",
        "description",
        "prompt",
        "plan",
    )
    parts: list[str] = []
    for k in preferred_keys:
        if k in args and args[k] not in (None, ""):
            val = str(args[k]).replace("\n", " ").strip()
            if len(val) > 110:
                val = val[:107] + "..."
            parts.append(f"{k}={val}")
            if len(parts) >= 2:
                break
    if not parts:
        raw = json.dumps(args, ensure_ascii=False)
        if len(raw) > 120:
            raw = raw[:117] + "..."
        return raw
    return ", ".join(parts)


def truncate_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    suffix = "\n\n...(содержимое сокращено для производительности; полная история доступна в transcript_full.jsonl)..."
    keep = max(0, limit - len(suffix))
    return text[:keep] + suffix


def format_assistant_response(turn: ConversationTurn) -> str:
    main_text = "\n\n".join(p.strip() for p in turn.text_parts if p and p.strip())
    tool_section = ""
    if turn.tool_calls:
        unique_names: list[str] = []
        for tc in turn.tool_calls:
            if tc.name and tc.name not in unique_names:
                unique_names.append(tc.name)
        names_label = ", ".join(unique_names[:5])
        if len(unique_names) > 5:
            names_label += f", +{len(unique_names) - 5}"
        lines = [
            f"<details><summary>Выполнено инструментов Claude Code: {len(turn.tool_calls)} ({names_label})</summary>",
            "",
        ]
        shown = turn.tool_calls[:40]
        for tc in shown:
            arg_str = summarize_tool_args(tc.arguments).replace("`", "'")
            line = f"- **`{tc.name}`**: `{arg_str}`"
            if tc.result_preview:
                res_one = re.sub(r"\s+", " ", tc.result_preview).strip()
                if len(res_one) > 140:
                    res_one = res_one[:137] + "..."
                res_one = res_one.replace("`", "'")
                line += f" -> `{res_one}`"
            lines.append(line)
        if len(turn.tool_calls) > len(shown):
            lines.append(f"- ... и ещё {len(turn.tool_calls) - len(shown)} вызовов")
        lines.append("</details>")
        tool_section = "\n".join(lines)

    if main_text and tool_section:
        combined = f"{main_text}\n\n{tool_section}"
    elif main_text:
        combined = main_text
    elif tool_section:
        combined = tool_section
    else:
        combined = "(Ответ модели без текстового содержимого)"

    return truncate_text(combined, MAX_RESPONSE_CHARS)


def format_thinking(turn: ConversationTurn) -> str:
    raw = "\n\n".join(p.strip() for p in turn.thinking_parts if p and p.strip())
    if not raw:
        return ""
    return truncate_text(raw, MAX_THINKING_CHARS)


def extract_tool_result_text(block: dict[str, Any]) -> str:
    cnt = block.get("content")
    if isinstance(cnt, str):
        return cnt
    if isinstance(cnt, list):
        pieces = []
        for item in cnt:
            if isinstance(item, dict) and item.get("type") == "text":
                pieces.append(item.get("text", ""))
            elif isinstance(item, str):
                pieces.append(item)
        return "\n".join(pieces)
    if cnt is None:
        return ""
    return json.dumps(cnt, ensure_ascii=False)


def infer_default_cwd(project_folder: str) -> str:
    m = re.match(r"^([A-Za-z])--(.+)$", project_folder)
    if m:
        drive = m.group(1).upper()
        rest = m.group(2).replace("-", "\\")
        return f"{drive}:\\{rest}"
    return os.path.expanduser("~")


def parse_claude_session(project_folder: str, filepath: str) -> ParsedSession | None:
    session_id = os.path.splitext(os.path.basename(filepath))[0]
    stat_mtime = os.path.getmtime(filepath)

    custom_title: str | None = None
    ai_title: str | None = None
    cwd: str | None = None
    first_ts: str | None = None
    last_ts: str | None = None

    turns: list[ConversationTurn] = []
    current_turn: ConversationTurn | None = None
    current_has_assistant = False
    tool_map: dict[str, ToolInvocation] = {}

    human_user_count = 0
    assistant_record_count = 0
    user_uuids: list[str] = []

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                obj = json.loads(raw_line)
            except Exception:
                continue

            ts = obj.get("timestamp")
            if isinstance(ts, str) and ts:
                if not first_ts:
                    first_ts = ts
                last_ts = ts

            if not cwd and isinstance(obj.get("cwd"), str) and obj.get("cwd"):
                cwd = obj["cwd"]

            rec_type = obj.get("type")
            if rec_type == "custom-title":
                t_val = obj.get("customTitle")
                if isinstance(t_val, str) and t_val.strip():
                    custom_title = t_val.strip()
                continue
            if rec_type == "ai-title":
                t_val = obj.get("aiTitle")
                if isinstance(t_val, str) and t_val.strip():
                    ai_title = t_val.strip()
                continue

            if rec_type == "user":
                if obj.get("isMeta"):
                    continue
                msg = obj.get("message")
                if not isinstance(msg, dict):
                    continue
                cnt = msg.get("content")

                if isinstance(cnt, list):
                    for block in cnt:
                        if isinstance(block, dict) and block.get("type") == "tool_result":
                            tid = block.get("tool_use_id")
                            if tid and tid in tool_map:
                                res_txt = extract_tool_result_text(block)
                                tool_map[tid].result_preview = res_txt[:4000]

                human_texts: list[str] = []
                if isinstance(cnt, str):
                    if cnt.strip():
                        human_texts.append(cnt.strip())
                elif isinstance(cnt, list):
                    for block in cnt:
                        if isinstance(block, dict) and block.get("type") == "text":
                            t_txt = block.get("text", "")
                            if isinstance(t_txt, str) and t_txt.strip():
                                human_texts.append(t_txt.strip())

                if human_texts:
                    human_user_count += 1
                    u_uuid = obj.get("uuid") or stable_uuid(f"{session_id}:user:{human_user_count}")
                    user_uuids.append(u_uuid)
                    joined_user = "\n\n".join(human_texts)
                    is_cont = joined_user.startswith(SYNTHETIC_CONTINUATION_PREFIX)

                    if (
                        current_turn is not None
                        and not current_has_assistant
                        and current_turn.is_continuation_summary == is_cont
                    ):
                        current_turn.user_text = current_turn.user_text + "\n\n" + joined_user
                    else:
                        current_turn = ConversationTurn(
                            user_uuid=u_uuid,
                            user_text=joined_user,
                            user_ts=ts,
                            is_continuation_summary=is_cont,
                        )
                        turns.append(current_turn)
                        current_has_assistant = False

            elif rec_type == "assistant":
                assistant_record_count += 1
                msg = obj.get("message")
                if not isinstance(msg, dict):
                    continue
                cnt = msg.get("content")
                if current_turn is None:
                    current_turn = ConversationTurn(
                        user_uuid=stable_uuid(f"{session_id}:implicit_start"),
                        user_text="(Начало сессии Claude Code)",
                        user_ts=ts or first_ts,
                    )
                    turns.append(current_turn)

                current_has_assistant = True
                if ts:
                    if not current_turn.first_assistant_ts:
                        current_turn.first_assistant_ts = ts
                    current_turn.last_assistant_ts = ts

                if isinstance(cnt, str):
                    if cnt.strip():
                        current_turn.text_parts.append(cnt)
                elif isinstance(cnt, list):
                    for block in cnt:
                        if not isinstance(block, dict):
                            continue
                        btype = block.get("type")
                        if btype == "thinking":
                            th = block.get("thinking", "")
                            if isinstance(th, str) and th.strip():
                                current_turn.thinking_parts.append(th)
                        elif btype == "text":
                            tx = block.get("text", "")
                            if isinstance(tx, str) and tx.strip():
                                current_turn.text_parts.append(tx)
                        elif btype == "tool_use":
                            tid = block.get("id") or f"tool_{len(current_turn.tool_calls)}"
                            tname = block.get("name") or "Tool"
                            targs = block.get("input")
                            if not isinstance(targs, dict):
                                targs = {"raw": targs}
                            inv = ToolInvocation(tool_id=tid, name=tname, arguments=targs)
                            current_turn.tool_calls.append(inv)
                            tool_map[tid] = inv

    if assistant_record_count == 0 or not turns:
        return None

    first_prompt_stripped = turns[0].user_text.strip()
    if human_user_count == 1 and first_prompt_stripped in EXCLUDED_SINGLE_PROMPTS:
        return None

    raw_title = custom_title or ai_title
    # SAFETY: Exclude automated single-turn roleplay/shim prompts without explicit user title.
    if (
        human_user_count == 1
        and raw_title is None
        and re.match(r"^<<SYSTEM>>\s+Ты\s+—", first_prompt_stripped)
    ):
        return None

    if not cwd:
        cwd = infer_default_cwd(project_folder)

    if raw_title and raw_title != "New session":
        resolved_title = raw_title
    elif raw_title == "New session":
        proj_tag = re.sub(r"^[A-Za-z]--Users-[^-]+$", "Home", project_folder)
        proj_tag = re.sub(r"^[A-Za-z]--", "", proj_tag)
        if "/init" in first_prompt_stripped:
            resolved_title = f"Инициализация {proj_tag} (/init)"
        else:
            resolved_title = f"{clean_preview(first_prompt_stripped, 55)} [{proj_tag}]"
    else:
        resolved_title = clean_preview(first_prompt_stripped, 68)

    created_sec, created_nanos = parse_iso_timestamp(first_ts, stat_mtime)
    last_mod_sec, last_mod_nanos = parse_iso_timestamp(last_ts or first_ts, stat_mtime)

    return ParsedSession(
        project_folder=project_folder,
        filepath=filepath,
        session_id=session_id,
        raw_title=raw_title,
        resolved_title=resolved_title,
        cwd=cwd,
        created_sec=created_sec,
        created_nanos=created_nanos,
        last_mod_sec=last_mod_sec,
        last_mod_nanos=last_mod_nanos,
        turns=turns,
        human_user_count=human_user_count,
        assistant_record_count=assistant_record_count,
        user_uuids=user_uuids,
    )


def merge_chain_turns(sessions_chronological: list[ParsedSession]) -> list[ConversationTurn]:
    """Merge turns across multi-file continuation chains, preserving chronological order and deduplicating."""
    by_uuid: dict[str, ConversationTurn] = {}
    ordered_uuids: list[str] = []

    for sess in sessions_chronological:
        for turn in sess.turns:
            if turn.is_continuation_summary and len(ordered_uuids) > 0:
                continue
            uid = turn.user_uuid
            if uid in by_uuid:
                existing = by_uuid[uid]
                existing_score = (
                    len(existing.text_parts) + len(existing.tool_calls) + len(existing.thinking_parts)
                )
                new_score = len(turn.text_parts) + len(turn.tool_calls) + len(turn.thinking_parts)
                if new_score > existing_score:
                    by_uuid[uid] = turn
            else:
                by_uuid[uid] = turn
                ordered_uuids.append(uid)

    def sort_key(uid: str) -> tuple[int, int, int]:
        t = by_uuid[uid]
        if t.user_ts:
            sec, nanos = parse_iso_timestamp(t.user_ts, 0.0)
            return (sec, nanos, ordered_uuids.index(uid))
        return (0, 0, ordered_uuids.index(uid))

    last_known_ts: str | None = None
    for uid in ordered_uuids:
        t = by_uuid[uid]
        if t.user_ts:
            last_known_ts = t.user_ts
        elif last_known_ts:
            t.user_ts = last_known_ts

    sorted_uids = sorted(ordered_uuids, key=sort_key)
    return [by_uuid[u] for u in sorted_uids]


def encode_trajectory_metadata(
    conversation_id: str,
    created_sec: int,
    created_nanos: int,
    init_state_id: str,
) -> bytes:
    created_ts = encode_timestamp(created_sec, created_nanos)
    return (
        field_bytes(2, created_ts)
        + field_str(3, init_state_id)
        + field_str(6, conversation_id)
        + field_str(18, "outside-of-project")
    )


def encode_step_metadata(
    trajectory_id: str,
    conversation_id: str,
    step_idx: int,
    meta_idx: int,
    source: int,
    created_sec: int,
    created_nanos: int,
    completed_sec: int,
    completed_nanos: int,
    exec_id: str,
    content_id: str,
    is_model: bool = False,
) -> bytes:
    created_ts = encode_timestamp(created_sec, created_nanos)
    completed_ts = encode_timestamp(completed_sec, completed_nanos)

    src_traj_info = (
        field_str(1, trajectory_id)
        + field_varint(2, step_idx)
        + field_varint(3, meta_idx)
        + field_str(4, conversation_id)
    )
    status_transition = field_varint(1, 3) + field_bytes(2, completed_ts)
    internal_meta = field_bytes(1, status_transition)

    buf = bytearray()
    buf.extend(field_bytes(1, created_ts))
    buf.extend(field_varint(3, source))
    if is_model:
        buf.extend(field_bytes(6, created_ts))
        buf.extend(field_bytes(7, completed_ts))
        buf.extend(field_bytes(8, completed_ts))
        buf.extend(field_varint(11, 1318))
    buf.extend(field_str(12, exec_id))
    buf.extend(field_bytes(20, src_traj_info))
    buf.extend(field_bytes(26, internal_meta))
    if is_model:
        buf.extend(field_bytes(32, created_ts))
    buf.extend(field_str(35, content_id))
    return bytes(buf)


def encode_user_input_step(meta_bytes: bytes, user_text: str, client_msg_id: str) -> bytes:
    item_bytes = field_str(1, user_text)
    user_agent_spec = b"\x1a\x08\n\x06\x08\x00\x18\x01(\x03"
    user_input = (
        field_str(2, user_text)
        + field_bytes(3, item_bytes)
        + field_bytes(18, user_agent_spec)
        + field_str(19, client_msg_id)
    )
    return (
        field_varint(1, 14)
        + field_varint(4, 3)
        + field_bytes(5, meta_bytes)
        + field_bytes(19, user_input)
    )


def encode_planner_response_step(
    meta_bytes: bytes, response_text: str, thinking_text: str, bot_msg_id: str
) -> bytes:
    pr = (
        field_str(1, response_text)
        + field_str(3, thinking_text)
        + field_str(6, bot_msg_id)
        + field_str(8, response_text)
        + field_varint(12, 2)
    )
    return (
        field_varint(1, 15)
        + field_varint(4, 3)
        + field_bytes(5, meta_bytes)
        + field_bytes(20, pr)
    )


def encode_checkpoint_step(
    meta_bytes: bytes,
    ckpt_idx: int,
    end_step_idx: int,
    title: str,
    user_intent: str,
    session_summary: str,
    user_requests: list[str],
    seed_prefix: str,
) -> bytes:
    buf = bytearray()
    buf.extend(field_varint(1, ckpt_idx))
    buf.extend(field_str(4, user_intent))
    buf.extend(field_str(5, session_summary))
    buf.extend(field_str(10, title))
    buf.extend(field_varint(12, end_step_idx))
    buf.extend(field_varint(24, 1))
    buf.extend(field_str(28, stable_hex32(f"{seed_prefix}:prompt")))
    buf.extend(field_str(29, stable_hex32(f"{seed_prefix}:summary")))
    for req in user_requests[-25:]:
        if req.strip():
            captured = field_str(1, req[:2000])
            buf.extend(field_bytes(30, captured))
    return (
        field_varint(1, 23)
        + field_varint(4, 3)
        + field_bytes(5, meta_bytes)
        + field_bytes(30, bytes(buf))
    )


def encode_cascade_summary(
    title: str,
    step_count: int,
    last_mod_sec: int,
    last_mod_nanos: int,
    trajectory_id: str,
    created_sec: int,
    created_nanos: int,
    last_user_sec: int,
    last_user_nanos: int,
    last_user_step_idx: int,
    traj_meta_bytes: bytes,
) -> bytes:
    last_mod_ts = encode_timestamp(last_mod_sec, last_mod_nanos)
    created_ts = encode_timestamp(created_sec, created_nanos)
    last_user_ts = encode_timestamp(last_user_sec, last_user_nanos)
    annotations = field_str(1, title) + field_bytes(7, last_mod_ts)
    return (
        field_str(1, title)
        + field_varint(2, step_count, force=True)
        + field_bytes(3, last_mod_ts)
        + field_str(4, trajectory_id)
        + field_varint(5, 1)
        + field_bytes(7, created_ts)
        + field_bytes(10, last_user_ts)
        + field_bytes(15, annotations)
        + field_varint(16, last_user_step_idx, force=True)
        + field_bytes(17, traj_meta_bytes)
        + field_varint(22, 4)
        + field_varint(28, 4)
    )


def build_checkpoint_summary_text(
    antigravity_dir: str,
    conv_id: str,
    title: str,
    cwd: str,
    turns_covered: list[ConversationTurn],
) -> tuple[str, str]:
    user_intent = clean_preview(turns_covered[0].user_text, 240) if turns_covered else title
    req_lines: list[str] = []
    total = len(turns_covered)
    if total <= 20:
        indices = list(range(total))
    else:
        indices = sorted(
            set(
                list(range(5))
                + list(range(total - 10, total))
                + list(range(5, total - 10, max(1, (total - 15) // 10)))
            )
        )
    for i in indices:
        t = turns_covered[i]
        req_lines.append(f"- [{i + 1}] {clean_preview(t.user_text, 160)}")

    last_assistant_snip = ""
    for t in reversed(turns_covered):
        if t.text_parts:
            last_assistant_snip = clean_preview("\n".join(t.text_parts), 500)
            break

    summary_lines = [
        "<summary>",
        f"## Imported Claude Code Session Summary: {title}",
        f"- **Conversation ID**: `{conv_id}`",
        f"- **Working Directory (`cwd`)**: `{cwd}`",
        f"- **Turns Covered Before Checkpoint**: {total}",
        f"- **Full Transcript Log**: `{antigravity_dir}\\brain\\{conv_id}\\.system_generated\\logs\\transcript_full.jsonl`",
        "",
        "### Chronological User Requests Covered:",
        *req_lines,
    ]
    if last_assistant_snip:
        summary_lines.extend(["", "### Latest Pre-Checkpoint Progress:", last_assistant_snip])
    summary_lines.append("</summary>")
    return user_intent, "\n".join(summary_lines)


def write_transcript_logs(
    antigravity_dir: str,
    conv_id: str,
    step_records: list[dict[str, Any]],
) -> None:
    logs_dir = os.path.join(antigravity_dir, "brain", conv_id, ".system_generated", "logs")
    os.makedirs(logs_dir, exist_ok=True)
    compact_path = os.path.join(logs_dir, "transcript.jsonl")
    full_path = os.path.join(logs_dir, "transcript_full.jsonl")

    with (
        open(compact_path, "w", encoding="utf-8") as fc,
        open(full_path, "w", encoding="utf-8") as ff,
    ):
        for rec in step_records:
            ff.write(json.dumps(rec, ensure_ascii=False) + "\n")
            compact_rec = dict(rec)
            trunc: list[str] = []
            if len(compact_rec.get("content", "")) > 8000:
                compact_rec["content"] = compact_rec["content"][:8000] + "\n...[truncated]"
                trunc.append("content")
            if len(compact_rec.get("thinking", "")) > 2000:
                compact_rec["thinking"] = compact_rec["thinking"][:2000] + "\n...[truncated]"
                trunc.append("thinking")
            if len(json.dumps(compact_rec.get("tool_calls", []), ensure_ascii=False)) > 4000:
                compact_rec["tool_calls"] = [
                    {
                        "name": tc.get("name"),
                        "arguments_preview": summarize_tool_args(tc.get("arguments", {})),
                    }
                    for tc in compact_rec.get("tool_calls", [])[:25]
                ]
                trunc.append("tool_calls")
            if trunc:
                compact_rec["truncated_fields"] = trunc
            fc.write(json.dumps(compact_rec, ensure_ascii=False) + "\n")


def write_annotation_pbtxt(
    antigravity_dir: str, conv_id: str, title: str, last_sec: int, last_nanos: int
) -> None:
    ann_dir = os.path.join(antigravity_dir, "annotations")
    os.makedirs(ann_dir, exist_ok=True)
    esc_title = (
        title.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", " ")
        .replace("\n", " ")
    )
    content = (
        f'title:"{esc_title}" '
        f"last_user_view_time:{{seconds:{last_sec} nanos:{last_nanos}}} "
        f"permission_preset:AGENT_PERMISSION_PRESET_TURBO"
    )
    ann_path = os.path.join(ann_dir, f"{conv_id}.pbtxt")
    with open(ann_path, "w", encoding="utf-8") as f:
        f.write(content)


def is_continued_or_native_db(antigravity_dir: str, conv_id: str, expected_trajectory_id: str) -> bool:
    db_path = os.path.join(antigravity_dir, "conversations", f"{conv_id}.db")
    if not os.path.exists(db_path):
        return False
    chk = sqlite3.connect(db_path, timeout=10.0)
    try:
        row = chk.execute("SELECT trajectory_id FROM trajectory_meta LIMIT 1").fetchone()
        return bool(row and row[0] != expected_trajectory_id)
    except Exception:
        return False
    finally:
        chk.close()


def write_conversation_db(
    antigravity_dir: str,
    conv_id: str,
    trajectory_id: str,
    traj_meta_bytes: bytes,
    db_steps: list[tuple[int, int, int, bytes, bytes]],
    last_mod_epoch: float,
) -> None:
    conv_dir = os.path.join(antigravity_dir, "conversations")
    os.makedirs(conv_dir, exist_ok=True)
    db_path = os.path.join(conv_dir, f"{conv_id}.db")
    if os.path.exists(db_path):
        # SAFETY: Never overwrite a native Antigravity conversation DB whose trajectory_id differs.
        chk = sqlite3.connect(db_path, timeout=10.0)
        try:
            row = chk.execute("SELECT trajectory_id FROM trajectory_meta LIMIT 1").fetchone()
            if row and row[0] != trajectory_id:
                raise RuntimeError(
                    f"Refusing to overwrite existing native conversation DB: {conv_id} (trajectory_id={row[0]})"
                )
        finally:
            chk.close()
    for suffix in ("", "-wal", "-shm"):
        p = db_path + suffix
        if os.path.exists(p):
            os.remove(p)

    conn = sqlite3.connect(db_path, timeout=30.0)
    try:
        conn.execute("PRAGMA page_size = 32768")
        conn.execute("PRAGMA user_version = 1")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(
            """
            CREATE TABLE `trajectory_meta` (
                `trajectory_id` text,
                `cascade_id` text,
                `trajectory_type` integer,
                `source` integer,
                PRIMARY KEY (`trajectory_id`)
            );
            CREATE TABLE `steps` (
                `idx` integer,
                `step_type` integer NOT NULL DEFAULT 0,
                `status` integer NOT NULL DEFAULT 0,
                `has_subtrajectory` numeric NOT NULL DEFAULT false,
                `metadata` blob,
                `error_details` blob,
                `permissions` blob,
                `task_details` blob,
                `render_info` blob,
                `step_payload` blob,
                `step_format` integer NOT NULL DEFAULT 0,
                PRIMARY KEY (`idx`)
            );
            CREATE INDEX `idx_steps_status` ON `steps`(`status`);
            CREATE INDEX `idx_steps_step_type` ON `steps`(`step_type`);
            CREATE TABLE `gen_metadata` (
                `idx` integer,
                `data` blob,
                `size` integer NOT NULL DEFAULT 0,
                PRIMARY KEY (`idx`)
            );
            CREATE TABLE `executor_metadata` (
                `idx` integer,
                `data` blob,
                `idx_dummy` integer,
                PRIMARY KEY (`idx`)
            );
            DROP TABLE `executor_metadata`;
            CREATE TABLE `executor_metadata` (
                `idx` integer,
                `data` blob,
                PRIMARY KEY (`idx`)
            );
            CREATE TABLE `parent_references` (
                `idx` integer,
                `data` blob,
                PRIMARY KEY (`idx`)
            );
            CREATE TABLE `trajectory_metadata_blob` (
                `id` text DEFAULT "main",
                `data` blob,
                PRIMARY KEY (`id`)
            );
            CREATE TABLE `battle_mode_infos` (
                `idx` integer,
                `data` blob,
                PRIMARY KEY (`idx`)
            );
            """
        )
        conn.execute(
            "INSERT INTO trajectory_meta (trajectory_id, cascade_id, trajectory_type, source) VALUES (?, ?, ?, ?)",
            (trajectory_id, conv_id, 4, 1),
        )
        conn.execute(
            "INSERT INTO trajectory_metadata_blob (id, data) VALUES (?, ?)",
            ("main", traj_meta_bytes),
        )
        conn.executemany(
            """
            INSERT INTO steps (
                idx, step_type, status, has_subtrajectory, metadata, step_payload, step_format
            ) VALUES (?, ?, ?, 0, ?, ?, 0)
            """,
            db_steps,
        )
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        conn.close()

    os.utime(db_path, (last_mod_epoch, last_mod_epoch))


def ensure_summaries_db_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS `conversation_summaries` (
            `conversation_id` text,
            `title` text,
            `preview` text,
            `step_count` integer,
            `last_modified_time` datetime,
            `workspace_uris` text,
            `status` text,
            `source` text,
            `project_id` text,
            `agent_name` text,
            `parent_conversation_id` text,
            `nesting_depth` integer,
            `battle_id` text,
            `winning_conversation_id` text,
            `not_fully_idle` numeric,
            `killed` numeric,
            `last_user_input_time` datetime,
            `last_user_input_step_index` integer DEFAULT -1,
            `app_data_dir` text DEFAULT '',
            `raw_summary` blob,
            `group_id` text DEFAULT '',
            PRIMARY KEY (`conversation_id`)
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS `conversations_fts` USING fts5(
            conversation_id UNINDEXED,
            chunk_index UNINDEXED,
            chunk_first_step UNINDEXED,
            chunk_last_step UNINDEXED,
            last_modified_time UNINDEXED,
            step_count UNINDEXED,
            last_step_created_at UNINDEXED,
            archived UNINDEXED,
            user_step_byte_offsets UNINDEXED,
            agent_step_byte_offsets UNINDEXED,
            title,
            workspace,
            project,
            user_body,
            agent_body
        );
        """
    )


def update_agyhub_summaries_pb(
    imported_raw_summaries: dict[str, bytes],
    antigravity_dir: str = DEFAULT_ANTIGRAVITY_DIR,
) -> None:
    os.makedirs(antigravity_dir, exist_ok=True)
    pb_path = os.path.join(antigravity_dir, "agyhub_summaries_proto.pb")
    preserved_entries: list[bytes] = []
    other_fields: list[bytes] = []

    if os.path.exists(pb_path):
        with open(pb_path, "rb") as fh:
            existing_data = fh.read()
        for fn, wt, val in parse_wire_fields(existing_data):
            if fn == 1 and wt == 2:
                sub = parse_wire_fields(val)
                key = ""
                for sfn, swt, sval in sub:
                    if sfn == 1 and swt == 2:
                        key = sval.decode("utf-8", "ignore")
                        break
                if key and key not in imported_raw_summaries:
                    preserved_entries.append(field_bytes(1, val))
            elif fn == 2 and wt == 2:
                other_fields.append(field_bytes(2, val))

    out = bytearray()
    for chunk in preserved_entries:
        out.extend(chunk)
    for cid, raw_sum in imported_raw_summaries.items():
        entry = field_str(1, cid) + field_bytes(2, raw_sum)
        out.extend(field_bytes(1, entry))
    for chunk in other_fields:
        out.extend(chunk)

    tmp_path = pb_path + ".tmp"
    with open(tmp_path, "wb") as f:
        f.write(bytes(out))
    os.replace(tmp_path, pb_path)


def sync_pb_from_db(antigravity_dir: str = DEFAULT_ANTIGRAVITY_DIR) -> int:
    """Sync all raw_summary entries from conversation_summaries.db into agyhub_summaries_proto.pb."""
    summaries_db_path = os.path.join(antigravity_dir, "conversation_summaries.db")
    if not os.path.exists(summaries_db_path):
        return 0
    conn = sqlite3.connect(summaries_db_path, timeout=30.0)
    try:
        raw_map = {
            cid: bytes(blob)
            for cid, blob in conn.execute(
                "SELECT conversation_id, raw_summary FROM conversation_summaries WHERE raw_summary IS NOT NULL"
            ).fetchall()
            if blob
        }
    finally:
        conn.close()
    update_agyhub_summaries_pb(raw_map, antigravity_dir=antigravity_dir)
    return len(raw_map)


def build_fts_chunks(
    conv_id: str,
    user_steps_with_text: list[tuple[int, str]],
    agent_steps_with_text: list[tuple[int, str]],
    step_count: int,
    last_mod_ns: int,
) -> list[tuple[Any, ...]]:
    """Build FTS5 chunk rows (header chunk -1 plus content chunks <= 120KB)."""
    all_items: list[tuple[int, str, str]] = []
    u_map = dict(user_steps_with_text)
    a_map = dict(agent_steps_with_text)
    for s_idx in range(step_count):
        if s_idx in u_map:
            all_items.append((s_idx, "u", u_map[s_idx]))
        if s_idx in a_map:
            all_items.append((s_idx, "a", a_map[s_idx]))

    rows: list[tuple[Any, ...]] = []
    chunk_idx = 0
    u_buf = bytearray()
    a_buf = bytearray()
    u_offsets: list[list[int]] = []
    a_offsets: list[list[int]] = []
    cur_first = 0
    cur_last = 0

    def flush_chunk() -> None:
        nonlocal chunk_idx, u_buf, a_buf, u_offsets, a_offsets
        rows.append(
            (
                conv_id,
                chunk_idx,
                cur_first,
                cur_last,
                0,
                0,
                0,
                0,
                json.dumps(u_offsets, separators=(",", ":")).encode("utf-8"),
                json.dumps(a_offsets, separators=(",", ":")).encode("utf-8"),
                "",
                "",
                "",
                u_buf.decode("utf-8", "ignore"),
                a_buf.decode("utf-8", "ignore"),
            )
        )
        chunk_idx += 1
        u_buf = bytearray()
        a_buf = bytearray()
        u_offsets = []
        a_offsets = []

    for s_idx, kind, text in all_items:
        line_bytes = (text.strip() + "\n").encode("utf-8", "ignore")
        if len(u_buf) + len(a_buf) + len(line_bytes) > 120_000 and (u_buf or a_buf):
            flush_chunk()
            cur_first = s_idx
        cur_last = s_idx
        if kind == "u":
            u_offsets.append([s_idx, len(u_buf)])
            u_buf.extend(line_bytes)
        else:
            a_offsets.append([s_idx, len(a_buf)])
            a_buf.extend(line_bytes)

    if u_buf or a_buf or chunk_idx == 0:
        flush_chunk()

    return rows


def resolve_project_folders(
    claude_projects_dir: str,
    explicit_projects: list[str] | None = None,
    include_all_projects: bool = False,
) -> list[str]:
    if explicit_projects:
        return [p.strip() for p in explicit_projects if p.strip()]
    if not os.path.isdir(claude_projects_dir):
        return []
    out: list[str] = []
    for name in sorted(os.listdir(claude_projects_dir)):
        full = os.path.join(claude_projects_dir, name)
        if not os.path.isdir(full):
            continue
        if not include_all_projects and EXCLUDED_PROJECT_PATTERNS.search(name):
            continue
        out.append(name)
    return out


def collect_and_prepare_sessions(
    claude_projects_dir: str = DEFAULT_CLAUDE_PROJECTS_DIR,
    explicit_projects: list[str] | None = None,
    include_all_projects: bool = False,
) -> list[tuple[str, str, ParsedSession, list[ConversationTurn]]]:
    """Return list of (conv_id, final_title, primary_session, turns_to_write)."""
    projects = resolve_project_folders(claude_projects_dir, explicit_projects, include_all_projects)
    sessions_by_project: dict[str, list[ParsedSession]] = {}

    for proj in projects:
        pdir = os.path.join(claude_projects_dir, proj)
        if not os.path.isdir(pdir):
            continue
        for fp in sorted(glob.glob(os.path.join(pdir, "*.jsonl"))):
            parsed = parse_claude_session(proj, fp)
            if parsed is not None:
                sessions_by_project.setdefault(proj, []).append(parsed)

    prepared: list[tuple[str, str, ParsedSession, list[ConversationTurn]]] = []

    for proj, sess_list in sessions_by_project.items():
        by_title: dict[str, list[ParsedSession]] = {}
        for s in sess_list:
            by_title.setdefault(s.resolved_title, []).append(s)

        for title, group in by_title.items():
            group.sort(
                key=lambda s: (
                    s.last_mod_sec,
                    s.last_mod_nanos,
                    s.created_sec,
                    s.created_nanos,
                )
            )
            if len(group) == 1:
                s = group[0]
                prepared.append((s.session_id, title, s, s.turns))
            else:
                total_parts = len(group)
                for idx_in_group, s in enumerate(group):
                    if idx_in_group == total_parts - 1:
                        merged = merge_chain_turns(group)
                        earliest_sec = min(x.created_sec for x in group)
                        earliest_nanos = min(
                            x.created_nanos for x in group if x.created_sec == earliest_sec
                        )
                        s.created_sec = earliest_sec
                        s.created_nanos = earliest_nanos
                        prepared.append((s.session_id, title, s, merged))
                    else:
                        date_str = datetime.fromtimestamp(
                            s.last_mod_sec, tz=timezone.utc
                        ).strftime("%Y-%m-%d")
                        seg_title = f"{title} (ч. {idx_in_group + 1}/{total_parts}, {date_str})"
                        prepared.append((s.session_id, seg_title, s, s.turns))

    return prepared


def build_steps_and_artifacts(
    antigravity_dir: str,
    conv_id: str,
    trajectory_id: str,
    title: str,
    sess: ParsedSession,
    turns: list[ConversationTurn],
) -> tuple[
    list[tuple[int, int, int, bytes, bytes]],
    list[dict[str, Any]],
    list[tuple[int, str]],
    list[tuple[int, str]],
    int,
    int,
    int,
]:
    total_chars = sum(len(t.user_text) + sum(len(p) for p in t.text_parts) for t in turns)
    need_checkpoint = (
        len(turns) > CHECKPOINT_TURN_THRESHOLD or total_chars > CHECKPOINT_CHAR_THRESHOLD
    )
    split_turn_idx = (
        max(1, len(turns) - KEEP_RECENT_TURNS_AFTER_CHECKPOINT) if need_checkpoint else -1
    )

    db_steps: list[tuple[int, int, int, bytes, bytes]] = []
    transcript_records: list[dict[str, Any]] = []
    fts_user: list[tuple[int, str]] = []
    fts_agent: list[tuple[int, str]] = []

    step_idx = 0
    meta_idx = 0
    last_user_sec = sess.created_sec
    last_user_nanos = sess.created_nanos
    last_user_step_idx = 0
    exec_id = stable_uuid(f"{conv_id}:exec:0")

    for t_i, turn in enumerate(turns):
        if need_checkpoint and t_i == split_turn_idx:
            turns_covered = turns[:t_i]
            user_intent, summary_text = build_checkpoint_summary_text(
                antigravity_dir, conv_id, title, sess.cwd, turns_covered
            )
            ckpt_sec, ckpt_nanos = parse_iso_timestamp(
                turns_covered[-1].last_assistant_ts or turns_covered[-1].user_ts,
                float(sess.last_mod_sec),
            )
            ckpt_meta = encode_step_metadata(
                trajectory_id=trajectory_id,
                conversation_id=conv_id,
                step_idx=step_idx,
                meta_idx=meta_idx,
                source=5,
                created_sec=ckpt_sec,
                created_nanos=ckpt_nanos,
                completed_sec=ckpt_sec,
                completed_nanos=ckpt_nanos,
                exec_id=exec_id,
                content_id=stable_hex32(f"{conv_id}:ckpt:meta"),
                is_model=False,
            )
            ckpt_payload = encode_checkpoint_step(
                meta_bytes=ckpt_meta,
                ckpt_idx=1,
                end_step_idx=step_idx,
                title=title,
                user_intent=user_intent,
                session_summary=summary_text,
                user_requests=[x.user_text for x in turns_covered],
                seed_prefix=f"{conv_id}:ckpt",
            )
            db_steps.append((step_idx, 23, 3, ckpt_meta, ckpt_payload))
            transcript_records.append(
                {
                    "step_index": step_idx,
                    "source": "SYSTEM",
                    "type": "CHECKPOINT",
                    "status": "DONE",
                    "created_at": timestamp_to_iso_localish(ckpt_sec, ckpt_nanos),
                    "content": summary_text,
                }
            )
            step_idx += 1

        u_sec, u_nanos = parse_iso_timestamp(turn.user_ts, float(sess.created_sec))
        last_user_sec, last_user_nanos = u_sec, u_nanos
        last_user_step_idx = step_idx
        exec_id = stable_uuid(f"{conv_id}:exec:{t_i}")

        u_meta = encode_step_metadata(
            trajectory_id=trajectory_id,
            conversation_id=conv_id,
            step_idx=step_idx,
            meta_idx=meta_idx,
            source=4,
            created_sec=u_sec,
            created_nanos=u_nanos,
            completed_sec=u_sec,
            completed_nanos=u_nanos,
            exec_id=exec_id,
            content_id=stable_hex32(f"{conv_id}:u:{t_i}"),
            is_model=False,
        )
        u_text = turn.user_text
        if t_i == 0:
            # INVARIANT: Place working directory note at the end of Step 0 so userInputSummary preview starts with user prompt.
            cwd_banner = f"\n\n[Claude Code • Рабочая папка: `{sess.cwd}`]"
            if "[Claude Code • Рабочая папка:" not in u_text:
                u_text_for_step = u_text + cwd_banner
            else:
                u_text_for_step = u_text
        else:
            u_text_for_step = u_text

        u_payload = encode_user_input_step(
            meta_bytes=u_meta,
            user_text=truncate_text(u_text_for_step, MAX_RESPONSE_CHARS),
            client_msg_id=turn.user_uuid,
        )
        db_steps.append((step_idx, 14, 3, u_meta, u_payload))
        fts_user.append((step_idx, turn.user_text))
        transcript_records.append(
            {
                "step_index": step_idx,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "status": "DONE",
                "created_at": timestamp_to_iso_localish(u_sec, u_nanos),
                "content": turn.user_text,
            }
        )
        step_idx += 1
        meta_idx += 1

        a_start_sec, a_start_nanos = parse_iso_timestamp(
            turn.first_assistant_ts or turn.user_ts, float(u_sec)
        )
        a_end_sec, a_end_nanos = parse_iso_timestamp(
            turn.last_assistant_ts or turn.first_assistant_ts or turn.user_ts,
            float(a_start_sec),
        )
        resp_text = format_assistant_response(turn)
        think_text = format_thinking(turn)

        a_meta = encode_step_metadata(
            trajectory_id=trajectory_id,
            conversation_id=conv_id,
            step_idx=step_idx,
            meta_idx=meta_idx,
            source=2,
            created_sec=a_start_sec,
            created_nanos=a_start_nanos,
            completed_sec=a_end_sec,
            completed_nanos=a_end_nanos,
            exec_id=exec_id,
            content_id=stable_hex32(f"{conv_id}:a:{t_i}"),
            is_model=True,
        )
        a_payload = encode_planner_response_step(
            meta_bytes=a_meta,
            response_text=resp_text,
            thinking_text=think_text,
            bot_msg_id=f"bot-{stable_uuid(f'{conv_id}:bot:{t_i}')}",
        )
        db_steps.append((step_idx, 15, 3, a_meta, a_payload))

        fts_text_only = "\n\n".join(p.strip() for p in turn.text_parts if p and p.strip())
        fts_agent.append((step_idx, fts_text_only or resp_text))

        tr_rec: dict[str, Any] = {
            "step_index": step_idx,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "status": "DONE",
            "created_at": timestamp_to_iso_localish(a_end_sec, a_end_nanos),
            "content": fts_text_only or resp_text,
        }
        if turn.thinking_parts:
            tr_rec["thinking"] = "\n\n".join(turn.thinking_parts)
        if turn.tool_calls:
            tr_rec["tool_calls"] = [
                {
                    "id": tc.tool_id,
                    "name": tc.name,
                    "arguments": tc.arguments,
                    "result_preview": tc.result_preview[:1500] if tc.result_preview else "",
                }
                for tc in turn.tool_calls
            ]
        transcript_records.append(tr_rec)
        step_idx += 1

    return (
        db_steps,
        transcript_records,
        fts_user,
        fts_agent,
        last_user_sec,
        last_user_nanos,
        last_user_step_idx,
    )


def backup_existing_stores(antigravity_dir: str, backup_dir: str | None = None) -> str:
    bdir = backup_dir or os.path.join(antigravity_dir, "backups", "pre_claude_import")
    os.makedirs(bdir, exist_ok=True)
    for fname in (
        "conversation_summaries.db",
        "conversation_summaries.db-wal",
        "conversation_summaries.db-shm",
        "agyhub_summaries_proto.pb",
    ):
        src = os.path.join(antigravity_dir, fname)
        dst = os.path.join(bdir, fname)
        if os.path.exists(src) and not os.path.exists(dst):
            shutil.copy2(src, dst)
    return bdir


def run_import(
    claude_projects_dir: str = DEFAULT_CLAUDE_PROJECTS_DIR,
    antigravity_dir: str = DEFAULT_ANTIGRAVITY_DIR,
    explicit_projects: list[str] | None = None,
    include_all_projects: bool = False,
    dry_run: bool = False,
    create_backup: bool = True,
) -> dict[str, Any]:
    prepared = collect_and_prepare_sessions(
        claude_projects_dir=claude_projects_dir,
        explicit_projects=explicit_projects,
        include_all_projects=include_all_projects,
    )
    by_project: dict[str, int] = {}
    for _, _, sess, _ in prepared:
        by_project[sess.project_folder] = by_project.get(sess.project_folder, 0) + 1

    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "sessions_count": len(prepared),
            "by_project": by_project,
            "sessions": [
                {
                    "conversation_id": cid,
                    "title": title,
                    "project": sess.project_folder,
                    "cwd": sess.cwd,
                    "turns": len(turns),
                }
                for cid, title, sess, turns in prepared
            ],
        }

    os.makedirs(antigravity_dir, exist_ok=True)
    backup_path = backup_existing_stores(antigravity_dir) if create_backup else ""

    summaries_db_path = os.path.join(antigravity_dir, "conversation_summaries.db")
    conn = sqlite3.connect(summaries_db_path, timeout=30.0)
    imported_raw_summaries: dict[str, bytes] = {}
    total_steps = 0
    checkpointed = 0
    preserved_active = 0

    try:
        ensure_summaries_db_schema(conn)
        for conv_id, final_title, sess, turns in prepared:
            trajectory_id = stable_uuid(f"{conv_id}:trajectory")
            init_state_id = stable_uuid(f"{conv_id}:init_state")

            # SAFETY: Preserve conversations already continued in Antigravity without overwriting live turns.
            if is_continued_or_native_db(antigravity_dir, conv_id, trajectory_id):
                preserved_active += 1
                continue

            (
                db_steps,
                transcript_records,
                fts_user,
                fts_agent,
                last_user_sec,
                last_user_nanos,
                last_user_step_idx,
            ) = build_steps_and_artifacts(
                antigravity_dir, conv_id, trajectory_id, final_title, sess, turns
            )

            step_count = len(db_steps)
            total_steps += step_count
            if any(st == 23 for _, st, _, _, _ in db_steps):
                checkpointed += 1

            traj_meta_bytes = encode_trajectory_metadata(
                conversation_id=conv_id,
                created_sec=sess.created_sec,
                created_nanos=sess.created_nanos,
                init_state_id=init_state_id,
            )

            raw_summary = encode_cascade_summary(
                title=final_title,
                step_count=step_count,
                last_mod_sec=sess.last_mod_sec,
                last_mod_nanos=sess.last_mod_nanos,
                trajectory_id=trajectory_id,
                created_sec=sess.created_sec,
                created_nanos=sess.created_nanos,
                last_user_sec=last_user_sec,
                last_user_nanos=last_user_nanos,
                last_user_step_idx=last_user_step_idx,
                traj_meta_bytes=traj_meta_bytes,
            )
            imported_raw_summaries[conv_id] = raw_summary

            write_conversation_db(
                antigravity_dir=antigravity_dir,
                conv_id=conv_id,
                trajectory_id=trajectory_id,
                traj_meta_bytes=traj_meta_bytes,
                db_steps=db_steps,
                last_mod_epoch=float(sess.last_mod_sec),
            )
            write_annotation_pbtxt(
                antigravity_dir, conv_id, final_title, sess.last_mod_sec, sess.last_mod_nanos
            )
            write_transcript_logs(antigravity_dir, conv_id, transcript_records)

            last_mod_str = format_sqlite_datetime(sess.last_mod_sec, sess.last_mod_nanos)
            last_user_str = format_sqlite_datetime(last_user_sec, last_user_nanos)
            preview_str = clean_preview(turns[0].user_text, 120) if turns else final_title

            conn.execute(
                """
                INSERT OR REPLACE INTO conversation_summaries (
                    conversation_id, title, preview, step_count, last_modified_time,
                    workspace_uris, status, source, project_id, agent_name,
                    parent_conversation_id, nesting_depth, battle_id, winning_conversation_id,
                    not_fully_idle, killed, last_user_input_time, last_user_input_step_index,
                    app_data_dir, raw_summary, group_id
                ) VALUES (?, ?, ?, ?, ?, '', 'CASCADE_RUN_STATUS_IDLE', '', 'outside-of-project', '',
                          '', 0, '', '', 0, 0, ?, ?, 'antigravity', ?, '')
                """,
                (
                    conv_id,
                    final_title,
                    preview_str,
                    step_count,
                    last_mod_str,
                    last_user_str,
                    last_user_step_idx,
                    raw_summary,
                ),
            )

            conn.execute("DELETE FROM conversations_fts WHERE conversation_id = ?", (conv_id,))
            last_mod_ns = timestamp_to_epoch_ns(sess.last_mod_sec, sess.last_mod_nanos)
            conn.execute(
                """
                INSERT INTO conversations_fts (
                    conversation_id, chunk_index, chunk_first_step, chunk_last_step,
                    last_modified_time, step_count, last_step_created_at, archived,
                    user_step_byte_offsets, agent_step_byte_offsets,
                    title, workspace, project, user_body, agent_body
                ) VALUES (?, -1, 0, 0, ?, ?, ?, 0, '', '', ?, '', '', '', '')
                """,
                (conv_id, last_mod_ns, step_count, last_mod_ns, final_title),
            )
            fts_rows = build_fts_chunks(conv_id, fts_user, fts_agent, step_count, last_mod_ns)
            if fts_rows:
                conn.executemany(
                    """
                    INSERT INTO conversations_fts (
                        conversation_id, chunk_index, chunk_first_step, chunk_last_step,
                        last_modified_time, step_count, last_step_created_at, archived,
                        user_step_byte_offsets, agent_step_byte_offsets,
                        title, workspace, project, user_body, agent_body
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    fts_rows,
                )

        conn.commit()
    finally:
        conn.close()

    update_agyhub_summaries_pb(imported_raw_summaries, antigravity_dir=antigravity_dir)
    return {
        "ok": True,
        "dry_run": False,
        "sessions_count": len(imported_raw_summaries) + preserved_active,
        "preserved_active": preserved_active,
        "total_steps": total_steps,
        "with_checkpoint": checkpointed,
        "by_project": by_project,
        "backup_dir": backup_path,
    }


def verify_import(
    claude_projects_dir: str = DEFAULT_CLAUDE_PROJECTS_DIR,
    antigravity_dir: str = DEFAULT_ANTIGRAVITY_DIR,
    explicit_projects: list[str] | None = None,
    include_all_projects: bool = False,
) -> dict[str, Any]:
    prepared = collect_and_prepare_sessions(
        claude_projects_dir=claude_projects_dir,
        explicit_projects=explicit_projects,
        include_all_projects=include_all_projects,
    )
    expected_ids = {cid for cid, _, _, _ in prepared}
    by_project: dict[str, int] = {}
    for _, _, sess, _ in prepared:
        by_project[sess.project_folder] = by_project.get(sess.project_folder, 0) + 1

    errors: list[str] = []
    sum_db = os.path.join(antigravity_dir, "conversation_summaries.db")
    rows: dict[str, Any] = {}
    if not os.path.exists(sum_db):
        errors.append(f"Missing conversation_summaries.db: {sum_db}")
    else:
        sconn = sqlite3.connect(sum_db, timeout=30.0)
        try:
            rows = {
                r[0]: r
                for r in sconn.execute(
                    "SELECT conversation_id, title, step_count, status, last_user_input_step_index, length(raw_summary), raw_summary FROM conversation_summaries"
                ).fetchall()
            }
            for cid, title, _, _ in prepared:
                if cid not in rows:
                    errors.append(f"Missing in conversation_summaries: {cid}")
                    continue
                _, db_title, step_count, status, last_u_idx, raw_len, raw_blob = rows[cid]
                if db_title != title:
                    errors.append(f"Title mismatch for {cid}: db={db_title!r} vs expected={title!r}")
                if status not in ("CASCADE_RUN_STATUS_IDLE", "CASCADE_RUN_STATUS_RUNNING"):
                    errors.append(f"Bad status for {cid}: {status}")
                if step_count <= 0 or last_u_idx < -1:
                    errors.append(f"Invalid step counts for {cid}: step_count={step_count}, last_u_idx={last_u_idx}")
                if not raw_blob or raw_len < 50:
                    errors.append(f"Invalid raw_summary blob for {cid}")
                else:
                    try:
                        flds = dict((fn, val) for fn, wt, val in parse_wire_fields(raw_blob))
                        if 1 not in flds or 4 not in flds:
                            errors.append(f"Incomplete raw_summary protobuf fields for {cid}")
                    except Exception as exc:
                        errors.append(f"Failed parsing raw_summary protobuf for {cid}: {exc}")

                fts_chunks = sconn.execute(
                    "SELECT chunk_index FROM conversations_fts WHERE conversation_id = ?", (cid,)
                ).fetchall()
                chunk_idxs = {r[0] for r in fts_chunks}
                if -1 not in chunk_idxs or 0 not in chunk_idxs:
                    errors.append(f"Missing FTS chunks for {cid}: found {chunk_idxs}")
        finally:
            sconn.close()

    pb_path = os.path.join(antigravity_dir, "agyhub_summaries_proto.pb")

    def read_pb_keys() -> set[str]:
        keys: set[str] = set()
        if not os.path.exists(pb_path):
            return keys
        with open(pb_path, "rb") as fh:
            pb_bytes = fh.read()
        for fn, wt, val in parse_wire_fields(pb_bytes):
            if fn == 1 and wt == 2:
                for sfn, swt, sval in parse_wire_fields(val):
                    if sfn == 1 and swt == 2:
                        keys.add(sval.decode("utf-8", "ignore"))
                        break
        return keys

    pb_keys: set[str] = set()
    resynced_pb = 0
    try:
        pb_keys = read_pb_keys()
        if expected_ids - pb_keys and os.path.exists(sum_db):
            # WORKAROUND: Running language_server.exe flushes its startup in-memory map to agyhub_summaries_proto.pb; resync from DB.
            resynced_pb = sync_pb_from_db(antigravity_dir=antigravity_dir)
            pb_keys = read_pb_keys()
    except Exception as exc:
        errors.append(f"Failed parsing agyhub_summaries_proto.pb: {exc}")

    missing_pb = expected_ids - pb_keys
    if missing_pb:
        errors.append(f"Missing in agyhub_summaries_proto.pb: {sorted(missing_pb)}")

    total_steps_written = 0
    checkpointed_count = 0
    for cid, _, _, _ in prepared:
        db_path = os.path.join(antigravity_dir, "conversations", f"{cid}.db")
        if not os.path.exists(db_path):
            errors.append(f"Missing conversation DB: {db_path}")
        else:
            cc = sqlite3.connect(db_path, timeout=15.0)
            try:
                ic = cc.execute("PRAGMA integrity_check").fetchone()[0]
                uv = cc.execute("PRAGMA user_version").fetchone()[0]
                ps = cc.execute("PRAGMA page_size").fetchone()[0]
                if ic != "ok" or uv != 1 or ps != 32768:
                    errors.append(f"Bad SQLite pragmas for {cid}: ic={ic}, uv={uv}, ps={ps}")
                tm = cc.execute(
                    "SELECT trajectory_id, cascade_id, trajectory_type, source FROM trajectory_meta"
                ).fetchall()
                if len(tm) != 1 or tm[0][1] != cid or tm[0][2] != 4 or tm[0][3] != 1:
                    errors.append(f"Invalid trajectory_meta for {cid}: {tm}")
                tmb = cc.execute("SELECT data FROM trajectory_metadata_blob WHERE id='main'").fetchone()
                if not tmb or not tmb[0]:
                    errors.append(f"Missing trajectory_metadata_blob for {cid}")
                sc_db = cc.execute("SELECT count(*) FROM steps").fetchone()[0]
                expected_sc = rows[cid][2] if cid in rows else -1
                if sc_db != expected_sc or sc_db <= 0:
                    errors.append(f"Step count mismatch for {cid}: steps_table={sc_db} vs summary={expected_sc}")
                total_steps_written += sc_db
                ck_cnt = cc.execute("SELECT count(*) FROM steps WHERE step_type=23").fetchone()[0]
                if ck_cnt > 0:
                    checkpointed_count += 1
                for s_row in cc.execute(
                    "SELECT idx, step_type, status, metadata, step_payload FROM steps WHERE idx IN (0, ?)",
                    (sc_db - 1,),
                ).fetchall():
                    s_idx, s_type, s_stat, s_meta, s_pay = s_row
                    if s_stat != 3:
                        errors.append(f"Step {s_idx} status != 3 in {cid}")
                    _ = parse_wire_fields(s_meta)
                    pf = {fn: val for fn, wt, val in parse_wire_fields(s_pay)}
                    if pf.get(1) != s_type:
                        errors.append(f"Step payload type mismatch in {cid} idx={s_idx}")
            except Exception as exc:
                errors.append(f"Exception checking {cid}.db: {exc}")
            finally:
                cc.close()

        ann_path = os.path.join(antigravity_dir, "annotations", f"{cid}.pbtxt")
        if not os.path.exists(ann_path):
            errors.append(f"Missing annotation pbtxt: {ann_path}")
        else:
            with open(ann_path, "r", encoding="utf-8") as fh:
                txt = fh.read()
            if "permission_preset:AGENT_PERMISSION_PRESET_TURBO" not in txt or 'title:"' not in txt:
                errors.append(f"Invalid annotation pbtxt content: {ann_path}")

        for tname in ("transcript.jsonl", "transcript_full.jsonl"):
            tp = os.path.join(antigravity_dir, "brain", cid, ".system_generated", "logs", tname)
            if not os.path.exists(tp) or os.path.getsize(tp) == 0:
                errors.append(f"Missing or empty transcript: {tp}")
            else:
                with open(tp, "r", encoding="utf-8") as tf:
                    first_line = tf.readline().strip()
                    obj = json.loads(first_line)
                    if "step_index" not in obj or "type" not in obj:
                        errors.append(f"Malformed JSONL header in {tp}")

    return {
        "ok": len(errors) == 0,
        "sessions_verified": len(prepared),
        "by_project": by_project,
        "total_steps": total_steps_written,
        "with_checkpoint": checkpointed_count,
        "pb_total_entries": len(pb_keys),
        "resynced_pb": resynced_pb,
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Import interactive Claude Code chats into Google Antigravity across all 5 storage layers."
    )
    parser.add_argument(
        "--claude-projects-dir",
        default=DEFAULT_CLAUDE_PROJECTS_DIR,
        help="Path to ~/.claude/projects directory",
    )
    parser.add_argument(
        "--antigravity-dir",
        default=DEFAULT_ANTIGRAVITY_DIR,
        help="Path to ~/.gemini/antigravity directory",
    )
    parser.add_argument(
        "--projects",
        default="",
        help="Comma-separated list of project folders under --claude-projects-dir (default: auto-discover interactive folders)",
    )
    parser.add_argument(
        "--include-all-projects",
        action="store_true",
        help="Include benchmark/shim/scratchpad project folders",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Scan and preview sessions to import without writing to disk",
    )
    parser.add_argument(
        "--sync-pb-only",
        action="store_true",
        help="Sync raw_summary entries from conversation_summaries.db to agyhub_summaries_proto.pb",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify all imported conversations across all 5 Antigravity storage layers",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Skip pre-import backup of conversation_summaries.db and agyhub_summaries_proto.pb",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output",
    )
    args = parser.parse_args(argv)

    explicit_projects = [p.strip() for p in args.projects.split(",") if p.strip()] if args.projects else None

    if args.sync_pb_only:
        n = sync_pb_from_db(antigravity_dir=args.antigravity_dir)
        if args.json:
            print(json.dumps({"ok": True, "synced_count": n}, ensure_ascii=False))
        else:
            print(f"Synced {n} summaries from conversation_summaries.db to agyhub_summaries_proto.pb.")
        return 0

    if args.verify:
        res = verify_import(
            claude_projects_dir=args.claude_projects_dir,
            antigravity_dir=args.antigravity_dir,
            explicit_projects=explicit_projects,
            include_all_projects=args.include_all_projects,
        )
        if args.json:
            print(json.dumps(res, ensure_ascii=False, indent=2))
        else:
            print(
                f"Verified {res['sessions_verified']} sessions | total_steps={res['total_steps']} "
                f"| with_checkpoint={res['with_checkpoint']} | pb_entries={res['pb_total_entries']}"
            )
            if res["errors"]:
                for err in res["errors"][:30]:
                    print(" -", err)
            else:
                print("ALL_CHECKS_PASSED")
        return 0 if res["ok"] else 1

    res = run_import(
        claude_projects_dir=args.claude_projects_dir,
        antigravity_dir=args.antigravity_dir,
        explicit_projects=explicit_projects,
        include_all_projects=args.include_all_projects,
        dry_run=args.dry_run,
        create_backup=not args.no_backup,
    )
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    elif args.dry_run:
        print(f"Dry run: found {res['sessions_count']} interactive sessions -> {res['by_project']}")
    else:
        print(
            f"Successfully imported {res['sessions_count']} conversations "
            f"({res['total_steps']} steps, {res['with_checkpoint']} checkpoints) across all 5 Antigravity storage layers."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
