"""解读器注册表：内置解读器 + 运行时热注册的自定义解读器。

解读器协议：
    interpret(payload: bytes, meta: dict) -> result

result 可是：
  - str                        —— 等价于 {"text": result}
  - dict，建议字段（均为可选）：
      summary: str             —— 一行摘要
      text: str                —— 等宽文本块
      rows: [{label, value}]   —— 键值表
      list: [str | dict]       —— 条目列表
  - 其他 JSON 可序列化值       —— 原样展示

自定义解读器通过 Web 面板提交源码（定义 interpret 函数）即时注册，
代码与配置仅保存在内存中，不写入磁盘。
"""

from __future__ import annotations

import json
import threading
import time

from . import wsproto

CUSTOM_TIMEOUT = 5.0     # 自定义解读器执行超时（秒），防止卡死面板


def _hexdump(payload: bytes, limit: int = 1024) -> str:
    lines = []
    shown = min(len(payload), limit)
    for i in range(0, shown, 16):
        chunk = payload[i:i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hexs:<48}  {asc}")
    if len(payload) > limit:
        lines.append(f"… 共 {len(payload)} 字节，仅显示前 {limit} 字节")
    return "\n".join(lines)


def _ascii_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return printable / len(text)


# ---------------- 内置解读器 ----------------

def _interp_hexdump(payload: bytes, meta: dict):
    if not payload:
        return {"summary": "无负载数据"}
    return {
        "summary": f"{len(payload)} 字节（页面显示前 1024 字节）",
        "text": _hexdump(payload),
    }


def _interp_text(payload: bytes, meta: dict):
    if not payload:
        return {"summary": "无负载数据"}
    try:
        text = payload.decode("utf-8")
        enc = "UTF-8"
    except UnicodeDecodeError:
        text = payload.decode("latin-1", errors="replace")
        enc = "非 UTF-8，按 latin-1 容错解码"
    sample = text[:4000]
    ratio = _ascii_ratio(sample)
    return {
        "summary": f"{len(payload)} 字节，编码 {enc}，可打印率 {ratio:.0%}",
        "rows": [
            {"label": "字节数", "value": len(payload)},
            {"label": "编码", "value": enc},
            {"label": "可打印率", "value": f"{ratio:.0%}"},
        ],
        "text": sample + ("…" if len(text) > len(sample) else ""),
    }


def _interp_http(payload: bytes, meta: dict):
    if not payload:
        return {"summary": "无负载数据"}
    head = payload[:8192]
    try:
        text = head.decode("latin-1")
    except Exception:
        return {"summary": "无法解码"}
    first_line = text.split("\r\n", 1)[0] if "\r\n" in text else text[:64]
    if not (first_line.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
                                    "OPTIONS ", "PATCH ", "TRACE ", "CONNECT "))
            or first_line.startswith("HTTP/")):
        return {"summary": "非 HTTP 流量（首行：%r）" % first_line[:80]}
    parts = text.split("\r\n\r\n", 1)
    header_block = parts[0]
    lines = header_block.split("\r\n")
    body_hint = ""
    if len(parts) > 1:
        body_hint = f"，报文头后另有 {len(payload) - len(header_block) - 4} 字节体"
    rows = [{"label": "首行", "value": first_line}]
    for line in lines[1:]:
        if ":" in line:
            name, _, value = line.partition(":")
            rows.append({"label": name.strip(), "value": value.strip()})
        elif line:
            rows.append({"label": "", "value": line})
    return {
        "summary": f"HTTP 报文：{first_line[:60]}{body_hint}",
        "rows": rows[:60],
    }


def _interp_json(payload: bytes, meta: dict):
    if not payload:
        return {"summary": "无负载数据"}
    try:
        text = payload.decode("utf-8").strip()
    except UnicodeDecodeError:
        return {"summary": "非 UTF-8，无法按 JSON 解读"}
    if not (text.startswith("{") or text.startswith("[")):
        return {"summary": "负载不是 JSON 对象或数组"}
    try:
        obj = json.loads(text)
    except ValueError as e:
        return {"summary": f"JSON 解析失败：{e}"}
    return {
        "summary": "有效 JSON，已格式化",
        "text": json.dumps(obj, ensure_ascii=False, indent=2)[:8000],
    }


def _interp_stats(payload: bytes, meta: dict):
    b = meta.get("bytes", {})
    p = meta.get("pkts", {})
    dur = meta.get("duration_s") or 0.0
    rows = [
        {"label": "方向", "value": "客户端→目标（tx）" if meta.get("direction") == "tx"
                                  else "目标→客户端（rx）"},
        {"label": "本方向字节", "value": b.get(meta.get("direction"), 0)},
        {"label": "本方向报文", "value": p.get(meta.get("direction"), 0)},
        {"label": "已捕获样本", "value": meta.get("captured", {}).get(meta.get("direction"), 0)},
    ]
    avg = 0.0
    pkts = p.get(meta.get("direction"), 0)
    if pkts:
        avg = b.get(meta.get("direction"), 0) / pkts
        rows.append({"label": "平均报文长", "value": f"{avg:.1f} B"})
    if dur > 0:
        rows.append({"label": "会话时长", "value": f"{dur:.2f} s"})
        rows.append({"label": "本方向吞吐", "value": f"{b.get(meta.get('direction'), 0) / dur / 1024:.2f} KiB/s"})
    if meta.get("truncated", {}).get(meta.get("direction")):
        rows.append({"label": "样本截断", "value": "已达捕获上限"})
    return {
        "summary": f"tx {b.get('tx', 0)} B / rx {b.get('rx', 0)} B，"
                   f"tx {p.get('tx', 0)} 包 / rx {p.get('rx', 0)} 包",
        "rows": rows,
    }


def _ws_opcode_counts(frames):
    counts = {}
    for f in frames:
        if f["opcode"] is None:
            continue
        counts[f["opcode_name"]] = counts.get(f["opcode_name"], 0) + 1
    return counts


def _ws_close_text(payload):
    """RFC 6455 §5.5.1：关闭帧负载 = 2 字节状态码 + 可选 UTF-8 原因。"""
    if not payload:
        return "无状态码"
    code = int.from_bytes(payload[:2], "big")
    try:
        reason = payload[2:].decode("utf-8")
    except UnicodeDecodeError:
        reason = payload[2:].hex()
    return f"{code} {reason}".strip()


def _ws_frame_lines(frames, limit=64):
    lines = []
    for f in frames[:limit]:
        flag = "FIN " if f["fin"] else "    "
        masked = "掩码" if f["masked"] else "无掩码"
        line = (f"#{(f['index'] or 0) + 1:03d} {flag}{f['opcode_name']:<11} "
                f"{masked} len={f['declared_len']}")
        if f["truncated"]:
            line += f"（实际仅 {f['payload_len']} 字节）"
        pv = wsproto.preview_bytes(f["payload"], 32)
        if pv:
            line += f" 「{pv}」"
        if f["notes"]:
            line += " ｜ " + "；".join(f["notes"])
        lines.append(line)
    if len(frames) > limit:
        lines.append(f"… 共 {len(frames)} 帧，仅显示前 {limit} 帧")
    return lines


def _wsframes_message_view(payload: bytes, meta: dict, msg: dict):
    """单报文作用域：负载是该 WebSocket 报文装配后的负载数据——帧头已剥离、
    掩码已解除（RFC 6455 §5.4），因此不再按帧解析，直接展示报文内容。"""
    kind = msg.get("kind") or "?"
    seq = msg.get("seq", "?")
    rows = [{"label": "报文", "value": f"#{seq} {kind}，{len(payload)} 字节"}]
    notes = ["单报文作用域：负载为该报文装配后的负载数据（帧头已剥离、掩码已解除）"]
    if kind == "handshake":
        if meta.get("direction") == "rx":
            head = wsproto.parse_handshake_response(payload)
        else:
            head = wsproto.parse_handshake_request(payload)
        if head is not None:
            rows.append({"label": "首行", "value": head["start_line"]})
            for name, value in head["headers"]:
                rows.append({"label": name, "value": value})
            notes = ["单报文作用域：HTTP Upgrade 握手报文原文"]
        else:
            rows.append({"label": "首行", "value": payload[:80].decode("latin-1", errors="replace")})
    else:
        if msg.get("opcode_name"):
            rows.append({"label": "opcode", "value": msg["opcode_name"]})
        if msg.get("fragmented"):
            rows.append({"label": "分片装配", "value": f"由 {msg.get('frames', '?')} 帧拼接而成"})
        if kind == "ws-close":
            rows.append({"label": "关闭帧", "value": _ws_close_text(payload)})
        if msg.get("truncated"):
            notes.append("该报文不完整（未见 FIN 或捕获样本被截断）")
    pv = wsproto.preview_bytes(payload, 120)
    return {
        "summary": f"WebSocket 报文 #{seq}：{kind}，{len(payload)} 字节",
        "rows": rows[:80],
        "text": ((pv + "\n\n") if pv else "") + _hexdump(payload, 512),
        "list": notes,
    }


def _interp_wsframes(payload: bytes, meta: dict):
    """WebSocket 帧流解析（RFC 6455）：识别握手、逐帧解读、报文装配与
    协议合规提示。

    两种作用域：
      - 整方向流（默认）：拆出 HTTP 握手前缀后逐帧解析并装配报文；
      - 单条报文（meta['message'] 存在，即 /messages 视图）：负载是该报文
        装配后的数据，不再包含帧头。

    帧边界与 recv 边界无关：总是在拼接后的字节流上按 §5.4 装配报文，
    因此「一个会话中的多个 tx/rx」会被正确还原成 WebSocket 报文，
    而不是把每个 TCP 分段当成一个报文。
    """
    if not payload:
        return {"summary": "无负载数据"}
    prot = meta.get("protocol")
    if prot in ("http", "tls", "tcp"):
        return {"summary": f"非 WebSocket 流量（会话协议识别为 {prot}）"}
    if meta.get("message"):
        return _wsframes_message_view(payload, meta, meta["message"])
    direction = meta.get("direction")
    handshake, start = wsproto.split_handshake(payload, direction)
    parsed = wsproto.parse_frames(payload, start)
    frames = parsed["frames"]
    assembled = wsproto.assemble_messages(frames)
    msgs = assembled["messages"]
    real_frames = [f for f in frames if f["opcode"] is not None]
    # protocol 未定论意味着流像 HTTP 但头未收齐（见 wsproto.detect_protocol）：
    # 此时把任意字节按帧解析容易误判，要求必须有握手前缀才算 WebSocket
    if prot == "unknown" and handshake is None:
        return {"summary": "非 WebSocket 流量（会话协议尚未定论，且未发现 RFC 6455 握手）"}
    if prot != "websocket" and handshake is None and not any(
            f["complete"] and f["opcode"] in (0x1, 0x2, 0x8, 0x9, 0xA) for f in real_frames):
        return {"summary": "非 WebSocket 流量（未发现 RFC 6455 握手，也无可识别的数据帧）"}
    rows = []
    notes = []
    if handshake is not None:
        rows.append({"label": "握手首行", "value": handshake["start_line"]})
        for name, value in handshake["headers"]:
            rows.append({"label": name, "value": value})
    elif direction:
        rows.append({"label": "握手", "value": "无（负载不含 HTTP Upgrade 握手）"})
    counts = _ws_opcode_counts(frames)
    complete = sum(1 for f in real_frames if f["complete"])
    rows.append({"label": "帧数", "value": f"{len(real_frames)}（完整 {complete}）"})
    rows.append({"label": "报文数", "value": str(len(msgs))})
    if counts:
        rows.append({"label": "帧类型分布", "value": "、".join(
            f"{k}×{v}" for k, v in sorted(counts.items()))})
    if real_frames:
        first = real_frames[0]
        for f in real_frames[1:]:
            if f["masked"] != first["masked"]:
                notes.append("流中混有带掩码与不带掩码的帧（同一方向应一致，RFC 6455 §5.3）")
                break
        if direction == "tx":
            bare = [f for f in real_frames if not f["masked"]]
            if bare:
                notes.append(f"{len(bare)} 帧 tx 未带掩码：客户端发出的帧必须带掩码（§5.3）")
        elif direction == "rx":
            masked = [f for f in real_frames if f["masked"]]
            if masked:
                notes.append(f"{len(masked)} 帧 rx 带了掩码：服务端发出的帧必须不带掩码（§5.3）")
    for f in real_frames:
        if f["opcode"] == 0x8:
            rows.append({"label": "关闭帧", "value": _ws_close_text(f["payload"])})
            break
    if any(f["rsv"] for f in real_frames):
        notes.append("RSV 位被置位：若协商了 permessage-deflate，帧负载是 DEFLATE 压缩数据，需先解压")
    if parsed["max_frames_hit"]:
        notes.append(f"帧数超过 {wsproto.MAX_FRAMES} 上限，后续帧未解析")
    if parsed["tail_bytes"]:
        notes.append(f"流尾部有 {parsed['tail_bytes']} 字节属于不完整的帧（帧头/长度/掩码被截断）")
    if assembled["stray_continuations"]:
        notes.append(f"{assembled['stray_continuations']} 个续帧没有对应的起始数据帧（协议违规，已跳过）")
    if any(f["notes"] for f in real_frames):
        bad = sum(1 for f in real_frames if f["notes"])
        notes.append(f"{bad} 帧带有协议提示（见下方帧明细）")
    if meta.get("message"):
        notes.append("当前为单报文作用域：一帧可能跨多个报文/分段，此片段不含全部帧")
    lines = []
    if frames:
        lines.extend(_ws_frame_lines(frames))
        if msgs:
            lines.append("")
            lines.append("── 装配报文（RFC 6455 §5.4，帧可跨 TCP 分段）──")
            for m in msgs[:32]:
                tag = []
                if not m["fin_seen"]:
                    tag.append("未见 FIN")
                if m["fragmented"]:
                    tag.append(f"{m['frames']} 帧")
                if m["truncated"]:
                    tag.append("样本截断")
                suffix = ("（" + "，".join(tag) + "）") if tag else ""
                pv = wsproto.preview_bytes(m["payload"], 48)
                lines.append(f"#{m['seq']:03d} {m['opcode_name']:<8} len={m['payload_len']}{suffix}"
                             + (f" 「{pv}」" if pv else ""))
            if len(msgs) > 32:
                lines.append(f"… 共 {len(msgs)} 报文，仅显示前 32 报文")
    else:
        lines.append("（尚无帧数据）")
    handshake_len = handshake["end_offset"] if handshake is not None else 0
    return {
        "summary": (f"WebSocket：{len(real_frames)} 帧 / {len(msgs)} 报文"
                    + (f"（握手 {handshake_len} B）" if handshake is not None else "（无握手前缀）")),
        "rows": rows[:80],
        "text": "\n".join(lines + ([""] + ["⚠ " + n for n in notes] if notes else [])),
        "list": notes or None,
    }


BUILTIN_SPECS = [
    ("stats", "统计", _interp_stats, "报文/字节/吞吐统计（不依赖负载内容）"),
    ("hexdump", "Hex 转储", _interp_hexdump, "十六进制 + ASCII 转储"),
    ("text", "文本解码", _interp_text, "UTF-8/latin-1 文本解码与可打印率"),
    ("http", "HTTP 解析", _interp_http, "识别并解析 HTTP 请求/响应头"),
    ("json", "JSON 解析", _interp_json, "识别并格式化 JSON 负载"),
    ("wsframes", "WebSocket 解析", _interp_wsframes,
     "RFC 6455 帧流解析：握手识别、逐帧表、报文装配与协议合规提示"),
]


# ---------------- 注册表 ----------------

class Interpreter:
    def __init__(self, interp_id, title, run, kind="builtin",
                 description="", enabled=True, code=None):
        self.id = interp_id
        self.title = title
        self.run = run
        self.kind = kind                  # builtin | custom
        self.description = description
        self.enabled = enabled
        self.code = code
        self.registered_at = time.time()

    def info(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "kind": self.kind,
            "description": self.description,
            "enabled": self.enabled,
            "has_code": self.code is not None,
            "registered_at": self.registered_at,
        }


def _run_guarded(run, payload, meta, timeout=None):
    """执行解读器，捕获异常与超时，确保一个坏解读器不会拖垮系统。"""
    if timeout is None:
        try:
            return run(payload, meta)
        except Exception as e:
            return {"summary": f"解读器异常: {e!r}", "error": True}
    box = {}

    def target():
        try:
            box["result"] = run(payload, meta)
        except BaseException as e:            # noqa: BLE001 —— 隔离用户代码
            box["error"] = e

    t = threading.Thread(target=target, daemon=True,
                         name=f"interp-{getattr(run, '__name__', 'custom')}")
    t.start()
    t.join(timeout)
    if t.is_alive():
        return {"summary": f"解读器执行超时（{timeout:g}s），已放弃", "error": True}
    if "error" in box:
        return {"summary": f"解读器异常: {box['error']!r}", "error": True}
    return box.get("result")


class Registry:
    def __init__(self):
        self._lock = threading.RLock()
        self._items = {}
        for interp_id, title, run, desc in BUILTIN_SPECS:
            self._items[interp_id] = Interpreter(
                interp_id, title,
                (lambda p, m, _r=run: _run_guarded(_r, p, m)),
                "builtin", desc)

    def info(self) -> list:
        with self._lock:
            return [i.info() for i in self._items.values()]

    def get(self, interp_id) -> Interpreter | None:
        with self._lock:
            return self._items.get(interp_id)

    def set_enabled(self, interp_id, enabled: bool) -> None:
        with self._lock:
            interp = self._items.get(interp_id)
            if interp is None:
                raise KeyError(interp_id)
            interp.enabled = bool(enabled)

    def remove(self, interp_id) -> None:
        with self._lock:
            interp = self._items.get(interp_id)
            if interp is None:
                raise KeyError(interp_id)
            if interp.kind == "builtin":
                raise ValueError("内置解读器不可删除，可停用")
            del self._items[interp_id]

    def _compile(self, code: str):
        if not isinstance(code, str) or not code.strip():
            raise ValueError("代码不能为空")
        ns = {}
        exec(compile(code, "<custom-interpreter>", "exec"), ns)
        run = ns.get("interpret")
        if not callable(run):
            raise ValueError("代码中必须定义函数 interpret(payload: bytes, meta: dict)")
        return run

    def register_custom(self, interp_id: str, title: str, code: str,
                        enabled: bool = True) -> Interpreter:
        run = self._compile(code)
        with self._lock:
            if not interp_id:
                raise ValueError("id 不能为空")
            if interp_id in self._items and self._items[interp_id].kind == "builtin":
                raise ValueError(f"id '{interp_id}' 与内置解读器冲突")
            interp = Interpreter(interp_id, title,
                                 (lambda p, m, _r=run: _run_guarded(_r, p, m, CUSTOM_TIMEOUT)),
                                 "custom", "面板注册的自定义解读器", enabled, code)
            self._items[interp_id] = interp
            return interp

    def test_code(self, code: str, payload: bytes, meta: dict) -> dict:
        """编译并立即试运行一段解读器代码（不注册）。"""
        run = self._compile(code)
        result = _run_guarded(run, payload, meta, CUSTOM_TIMEOUT)
        return {"result": result, "payload_bytes": len(payload)}

    def run(self, payload: bytes, meta: dict) -> list:
        """对一段负载运行所有已启用的解读器。"""
        out = []
        with self._lock:
            items = list(self._items.values())
        for interp in items:
            if not interp.enabled:
                continue
            try:
                result = interp.run(payload, meta)
            except Exception as e:            # 双保险
                result = {"summary": f"解读器异常: {e!r}", "error": True}
            out.append({
                "id": interp.id,
                "title": interp.title,
                "kind": interp.kind,
                "result": result if isinstance(result, (str, dict, list, int, float, bool)) or result is None
                          else str(result),
            })
        return out
