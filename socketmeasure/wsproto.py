"""WebSocket（RFC 6455）协议解析：握手识别、帧流解析、报文装配、协议探测。

本模块是纯函数模块，没有任何状态：所有解析都作用于**某方向拼接后的完整字节流**，
而不是单个 TCP 分段。WebSocket 帧边界与 recv 边界没有任何对齐关系
（RFC 6455 §5.4：一帧可以跨多个 TCP 报文，一个报文也可以携带多帧，并且
报文可以被分片成若干连续帧，中间还能穿插控制帧），因此解析必须是可恢复的
流式解析：帧头可能只到达一半、声明长度可能尚未收齐，这些情况一律标记为
"不完整" 而不是抛异常，等流继续增长后由调用方重新解析。

方向约定与 model 一致：tx = 客户端 → 目标，rx = 目标 → 客户端。
RFC 6455 §5.3 规定：**客户端发出的帧必须带掩码，服务端发出的帧必须不带掩码**。
掩码在每帧的负载数据字节 0 处重新对齐（即 payload[i] XOR mask[i & 3]）。
"""

from __future__ import annotations

import base64
import hashlib
import re

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"  # RFC 6455 §1.3
MAX_SCAN = 16384   # 握手/协议探测最多扫描的字节数
MAX_FRAMES = 4096  # 单方向一次解析的帧数上限（防止异常流量拖垮面板）

DATA_OPCODES = (0x1, 0x2)
CONTROL_OPCODES = (0x8, 0x9, 0xA)

OPCODE_NAMES = {
    0x0: "continuation", 0x1: "text", 0x2: "binary",
    0x8: "close", 0x9: "ping", 0xA: "pong",
}


def opcode_name(opcode):
    return OPCODE_NAMES.get(opcode, "reserved(0x%02x)" % opcode) if opcode is not None else "不完整"


# ---------------------------------------------------------------- HTTP 头部

_REQUEST_LINE_RE = re.compile(r"^([A-Z]{1,20}) (\S+) (HTTP/[0-9](?:\.[0-9])?)$")
_RESPONSE_LINE_RE = re.compile(r"^(HTTP/[0-9](?:\.[0-9])?) ([0-9]{3})(?:[ \t]+(.*))?$")
_METHOD_PREFIX_RE = re.compile(rb"^([A-Z]{1,20}) ")


def looks_like_tls(data):
    """TLS 记录头特征：_CONTENT_TYPES 14-17h + 版本号 03 xx（SSLv3/TLS1.x）。"""
    if not data or len(data) < 2:
        return False
    return data[0] in (0x14, 0x15, 0x16, 0x17) and data[1] == 0x03


def looks_like_http(data):
    """字节流开头像不像 HTTP 请求行（只判断方法名 + 空格，不要求头完整）。"""
    if not data:
        return False
    if data[:5] == b"HTTP/":
        return True
    return bool(_METHOD_PREFIX_RE.match(data[:256]))


def _find_head_end(data):
    """在 data 前缀中定位 HTTP 头部结束位置（首个空行之后的偏移）。未找到返回 -1。"""
    window = data[:MAX_SCAN]
    idx = window.find(b"\r\n\r\n")
    if idx >= 0:
        return idx + 4
    idx = window.find(b"\n\n")
    if idx >= 0:
        return idx + 2
    return -1


def _decode_head(block):
    """解析一段 HTTP 头（含起始行）。返回 (start_line, [(name, value), ...]) 或 None。"""
    try:
        text = block.decode("latin-1")
    except Exception:
        return None
    lines = text.split("\n")
    start_line = lines[0].replace("\r", "").strip()
    if not start_line:
        return None
    headers = []
    for line in lines[1:]:
        line = line.rstrip("\r")
        if not line.strip():
            break  # 头部结束
        if ":" not in line:
            return None  # 坏行：不当作 HTTP 处理
        name, _, value = line.partition(":")
        headers.append((name.strip(), value.strip()))
    return start_line, headers


def _header(headers, name):
    nl = name.lower()
    return [v for k, v in headers if k.lower() == nl]


def _tokens(value):
    return {t.strip().lower() for t in (value or "").split(",") if t.strip()}


def valid_ws_key(key):
    """RFC 6455 §4.1：客户端握手头 Sec-WebSocket-Key 必须是 16 字节的 base64 编码。"""
    if not key or len(key) != 24:
        return False
    try:
        return len(base64.b64decode(key, validate=True)) == 16
    except Exception:
        return False


def expected_accept(key):
    """RFC 6455 §1.3：Sec-WebSocket-Accept = base64(SHA1(key + GUID))。"""
    digest = hashlib.sha1((key + WS_GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def parse_handshake_request(data):
    """解析客户端的 HTTP Upgrade 握手请求。完整且合法返回字典，否则 None。"""
    end = _find_head_end(data)
    if end < 0:
        return None
    head = _decode_head(data[:end])
    if head is None:
        return None
    start_line, headers = head
    m = _REQUEST_LINE_RE.match(start_line)
    if not m:
        return None
    upgrade = ", ".join(_header(headers, "Upgrade"))
    key = (_header(headers, "Sec-WebSocket-Key") or [None])[0]
    key_ok = valid_ws_key(key)
    return {
        "kind": "request",
        "start_line": start_line,
        "method": m.group(1),
        "target": m.group(2),
        "http_version": m.group(3),
        "headers": headers,
        "upgrade_tokens": _tokens(upgrade),
        "websocket_upgrade": "websocket" in _tokens(upgrade) and key_ok,
        "key": key,
        "key_ok": key_ok,
        "extensions": _header(headers, "Sec-WebSocket-Extensions"),
        "end_offset": end,
    }


def parse_handshake_response(data):
    """解析服务端的 HTTP 握手响应（101 Switching Protocols 等）。"""
    end = _find_head_end(data)
    if end < 0:
        return None
    head = _decode_head(data[:end])
    if head is None:
        return None
    start_line, headers = head
    m = _RESPONSE_LINE_RE.match(start_line)
    if not m:
        return None
    return {
        "kind": "response",
        "start_line": start_line,
        "http_version": m.group(1),
        "status": int(m.group(2)),
        "reason": (m.group(3) or "").strip(),
        "headers": headers,
        "upgrade_tokens": _tokens(", ".join(_header(headers, "Upgrade"))),
        "accept": (_header(headers, "Sec-WebSocket-Accept") or [None])[0],
        "extensions": _header(headers, "Sec-WebSocket-Extensions"),
        "end_offset": end,
    }


def handshake_view(info):
    """从握手解析结果中提取面板/API 展示字段（保留头部顺序与关键头部）。"""
    keep = ("Host", "Upgrade", "Connection", "Origin",
            "Sec-WebSocket-Key", "Sec-WebSocket-Accept", "Sec-WebSocket-Version",
            "Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions")
    lower = {}
    for k, v in info["headers"]:
        lower.setdefault(k.lower(), (k, v))
    headers = [lower[n.lower()] for n in keep if n.lower() in lower]
    return {
        "kind": info["kind"],
        "start_line": info["start_line"],
        "headers": [[k, v] for k, v in headers],
        "websocket_upgrade": bool(info.get("websocket_upgrade", False)),
        "upgrade_tokens": sorted(info.get("upgrade_tokens") or []),
        "extensions": list(info.get("extensions") or []),
        "end_offset": info["end_offset"],
        "status": info.get("status"),
        "reason": info.get("reason"),
        "method": info.get("method"),
        "target": info.get("target"),
        "key": info.get("key"),
        "accept": info.get("accept"),
    }


# ------------------------------------------------------------------- 协议探测

def detect_protocol(tx_head, rx_head):
    """根据两个方向的流前缀判断会话应用层协议。

    返回值之一：``websocket`` / ``http`` / ``tls`` / ``tcp`` / ``unknown``。
    - ``websocket``：客户端发出合法 Upgrade 请求且服务端已回 101（确定，可缓存冻结）
    - ``unknown``：还不能定论（升级请求刚发出尚未收到响应 / 头部尚未收齐），
      调用方应在版本变化后重新探测，会话关闭时再落定
    """
    tx = (tx_head or b"")[:MAX_SCAN]
    rx = (rx_head or b"")[:MAX_SCAN]
    if not tx and not rx:
        return "unknown"
    if looks_like_tls(tx):
        return "tls"
    req = parse_handshake_request(tx)
    if req is not None and req["websocket_upgrade"]:
        resp = parse_handshake_response(rx)
        if resp is not None:
            if resp["status"] == 101 and "websocket" in resp["upgrade_tokens"]:
                return "websocket"
            return "http"  # 服务端拒绝升级或返回非 101
        if not rx:
            return "unknown"  # 升级请求已发，101 尚未到达
        if rx.startswith(b"HTTP/"):
            return "unknown"  # 101 响应头还在路上（不完整）
        return "http"  # rx 非空且不是 HTTP 响应：升级失败
    if req is not None:
        return "http"
    if parse_handshake_response(rx) is not None:
        return "http"
    if not tx:
        return "unknown"
    if looks_like_http(tx):
        return "unknown"  # 像 HTTP 请求但头未完整到达，暂不定论
    return "tcp"


# ------------------------------------------------------------------- 帧解析

def unmask(payload, mask):
    """按 RFC 6455 §5.3 解除掩码：payload[i] XOR mask[i & 3]（每帧负载 0 处对齐）。"""
    if not payload or not mask:
        return payload
    n = len(payload)
    aligned = (mask * ((n + 3) // 4))[:n]
    x = int.from_bytes(payload, "big") ^ int.from_bytes(aligned, "big")
    return x.to_bytes(n, "big")


def _tail_frame(pos, n, note):
    """流尾不完整的帧（帧头/扩展长度/掩码被截断），标记而非抛异常。"""
    return {
        "index": None, "offset": pos, "end": n, "fin": None, "rsv": None,
        "opcode": None, "opcode_name": "不完整", "masked": False,
        "declared_len": None, "payload_len": 0,
        "payload": b"", "complete": False, "truncated": True, "notes": [note],
    }


def parse_frames(data, start=0, max_frames=MAX_FRAMES):
    """从字节偏移 ``start`` 起可恢复地解析 RFC 6455 帧流。

    永远不抛异常：帧头/长度/掩码不完整、声明长度超过已有数据、非法长度编码、
    保留 opcode 等情况都转化为帧对象上的标记（notes / truncated / complete）。
    不会按声明长度预分配内存，只按流中实际存在的字节数读取。

    返回::

        {"frames": [帧...], "consumed": 已消费偏移, "tail_bytes": 尾部余留字节数,
         "max_frames_hit": 是否因达到 max_frames 上限而停止}

    帧对象字段：``offset`` / ``end``（字节区间 [offset, end)）、``fin``、``rsv``、
    ``opcode``、``opcode_name``、``masked``、``declared_len``（声明负载长度）、
    ``payload_len``（实际可用字节数）、``payload``（已解除掩码的负载数据）、
    ``complete``、``truncated``、``notes``（ complying 提示列表）。
    """
    frames = []
    pos = start
    n = len(data)
    capped = False
    while pos < n:
        if len(frames) >= max_frames:
            capped = True
            break
        b0 = data[pos]
        if pos + 1 >= n:
            frames.append(_tail_frame(pos, n, "帧头不完整（仅 %d 字节）" % (n - pos)))
            break
        b1 = data[pos + 1]
        fin = bool(b0 & 0x80)
        rsv = (b0 >> 4) & 0x07
        opcode = b0 & 0x0F
        masked = bool(b1 & 0x80)
        len7 = b1 & 0x7F
        body = pos + 2
        declared = len7
        notes = []
        if len7 in (126, 127):
            ext = 2 if len7 == 126 else 8
            raw = data[body:body + ext]
            if len(raw) < ext:
                frames.append(_tail_frame(pos, n, "扩展长度字段不完整（需 %d 字节，实际 %d）" % (ext, len(raw))))
                break
            declared = int.from_bytes(raw, "big")
            body += ext
            if len7 == 126 and declared < 126:
                notes.append("非最小编码：2 字节扩展长度表示 %d（应使用 7 位长度）" % declared)
            elif len7 == 127 and declared < 65536:
                notes.append("非最小编码：8 字节扩展长度表示 %d（应使用 2 字节扩展长度）" % declared)
            elif len7 == 127 and declared >= (1 << 63):
                notes.append("声明长度非法（最高有效位被置位）")
        mask = b""
        if masked:
            mask = data[body:body + 4]
            if len(mask) < 4:
                frames.append(_tail_frame(pos, n, "掩码字段不完整（需 4 字节，实际 %d）" % len(mask)))
                break
            body += 4
        available = n - body
        take = declared if declared <= available else available
        raw = data[body:body + take]
        payload = unmask(raw, mask) if masked else raw
        truncated = take < declared
        if rsv:
            notes.append("RSV 位被置位（rsv=%d；若协商了 permessage-deflate 则负载是 DEFLATE 压缩数据）" % rsv)
        if opcode in CONTROL_OPCODES:
            if declared > 125:
                notes.append("控制帧负载超过 125 字节（协议违规）")
            if not fin:
                notes.append("控制帧被分片（协议违规）")
        elif opcode not in DATA_OPCODES and opcode != 0:
            notes.append("保留 opcode（0x%02x）" % opcode)
        frame = {
            "offset": pos, "end": body + take, "fin": fin, "rsv": rsv,
            "opcode": opcode, "opcode_name": opcode_name(opcode),
            "masked": masked, "declared_len": declared, "payload_len": take,
            "payload": payload, "complete": not truncated,
            "truncated": truncated, "notes": notes,
        }
        frame["index"] = len(frames)
        frames.append(frame)
        pos = body + take
    return {
        "frames": frames, "consumed": pos, "tail_bytes": n - pos,
        "max_frames_hit": capped,
    }


def assemble_messages(frames):
    """把帧流按 RFC 6455 §5.4 装配为报文：一个数据帧（text/binary）起始，
    若干 continuation 帧续接，直到 FIN=1；控制帧（close/ping/pong）独立、
    可穿插在分片中间，不计入数据报文。

    流尾若报文未被 FIN 终止（发送方违规或样本截断），仍返回该报文，
    但标记 ``fin_seen=False`` / ``truncated=True``。

    返回 ``{"messages": [报文...], "stray_continuations": int}``。
    报文字段：``seq``（从 1 开始）、``opcode``、``offset`` / ``end``
    （在整方向流中的字节区间）、``payload``（拼接并已解除掩码）、
    ``payload_len``、``frames``（帧数）、``fin_seen``、``fragmented``、``truncated``。
    """
    messages = []
    cur = None
    stray = 0
    for f in frames:
        opcode = f["opcode"]
        if opcode in DATA_OPCODES:
            if cur is not None:
                cur["fin_seen"] = False
                cur["truncated"] = True
                messages.append(cur)
                cur = None
            cur = {
                "opcode": opcode, "offset": f["offset"], "end": f["end"],
                "parts": [f["payload"]], "frame_count": 1,
                "fin_seen": bool(f["fin"]), "fragmented": False,
                "truncated": bool(f["truncated"]),
            }
        elif opcode == 0:
            if cur is None:
                stray += 1  # 没有起始数据帧的续帧（协议违规），跳过
                continue
            cur["fragmented"] = True
            cur["parts"].append(f["payload"])
            cur["frame_count"] += 1
            cur["end"] = f["end"]
            if f["truncated"]:
                cur["truncated"] = True
            if f["fin"]:
                cur["fin_seen"] = True
        # opcode >= 8 的控制帧为独立单元，不进入数据报文
    if cur is not None:
        if not cur["fin_seen"]:
            cur["truncated"] = True   # 流尾未见 FIN：报文不完整
        messages.append(cur)
    out = []
    for i, m in enumerate(messages):
        payload = b"".join(m["parts"])
        out.append({
            "seq": i + 1,
            "opcode": m["opcode"],
            "opcode_name": opcode_name(m["opcode"]),
            "offset": m["offset"], "end": m["end"],
            "payload": payload, "payload_len": len(payload),
            "frames": m["frame_count"],
            "fin_seen": m["fin_seen"], "fragmented": m["fragmented"],
            "truncated": m["truncated"],
        })
    return {"messages": out, "stray_continuations": stray}


def split_handshake(data, direction):
    """websocket 会话中把某方向的流拆成「HTTP 握手前缀」与「帧流起点」。

    - tx：以合法的 Upgrade 握手请求开头 → 返回 (handshake_view, 帧流起始偏移)
    - rx：以 101 Switching Protocols 响应开头 → 同上
    其余情况（例如样本从握手之后开始、或协议不是 websocket）返回 (None, 0)。
    """
    if direction == "tx":
        req = parse_handshake_request(data)
        if req is not None and req["websocket_upgrade"]:
            return handshake_view(req), req["end_offset"]
        return None, 0
    resp = parse_handshake_response(data)
    if resp is not None and resp["status"] == 101 and "websocket" in resp["upgrade_tokens"]:
        return handshake_view(resp), resp["end_offset"]
    return None, 0


def preview_bytes(data, limit=64):
    """帧/报文负载的短预览：能严格按 UTF-8 解码则给文本，否则给十六进制。"""
    if not data:
        return ""
    sample = bytes(data[:limit])
    try:
        text = sample.decode("utf-8")
        if "�" not in text:
            return text
    except UnicodeDecodeError:
        pass
    return sample.hex()
