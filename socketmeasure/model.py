"""内存数据模型：会话、事件与存储。

方向约定：
  tx = 客户端 -> 目标（上行）  rx = 目标 -> 客户端（下行）

所有内容只存在于进程内存中：会话计数、捕获的负载分片、解读结果、事件流，
均设有内存上限，程序退出即消失，永不写入磁盘。
"""

from __future__ import annotations

import base64
import bisect
import collections
import csv
import io
import secrets
import threading
import time
import uuid

from ._version import __version__
from . import wsproto

# 每个方向最多捕获的负载字节数（字节总计数不受限，仅捕获样本受限）
DEFAULT_CAPTURE_LIMIT = 1 << 20            # 1 MiB
DEFAULT_MAX_CLOSED_SESSIONS = 200          # 内存中最多保留的已关闭会话数
DEFAULT_EVENT_LOG = 500                    # 事件流条数上限
DEFAULT_API_CALL_LOG = 500                 # 外部 API 调用日志条数上限
DEFAULT_RATE_SERIES = 120                  # 速率序列秒数上限

# 逐报文视图（新增能力，均为增量字段，不改变既有接口形状）：
# detail()/meta() 中 messages 列表条数上限；/messages 视图的 limit 上下限；
# 逐报文解读的条数上限与全局墙钟预算（防止坏解读器拖垮详情请求）
MSG_LIST_LIMIT = 64
MSG_VIEW_LIMIT = 64
MSG_VIEW_LIMIT_MAX = 256
MSG_INTERP_LIMIT = 32
MSG_INTERP_BUDGET_S = 8.0

DIRECTIONS = ("tx", "rx")

TOKEN_PREFIX = "sm_"


class Token:
    """HTTP 接口调用令牌。全部信息仅存内存，进程退出即消失。

    kind 含义：
      - "panel"：面板内置令牌，随管理页面注入到浏览器，仅用于面板自身
                  调用与管理类接口（/api/tokens*），不可删除/停用；
      - "user" ：在管理页面手动创建，分发给外部 socket 流量测试工具。
    """

    def __init__(self, title: str, kind: str = "user"):
        self.id = uuid.uuid4().hex[:12]
        self.value = TOKEN_PREFIX + secrets.token_hex(24)
        self.title = str(title or "").strip() or "未命名令牌"
        self.kind = kind if kind in ("panel", "user") else "user"
        self.enabled = True
        self.created_at = time.time()
        self.last_used_at = None
        self.use_count = 0

    def touch(self) -> None:
        self.last_used_at = time.time()
        self.use_count += 1

    def summary(self) -> dict:
        return {
            "id": self.id,
            "value": self.value,
            "title": self.title,
            "kind": self.kind,
            "enabled": self.enabled,
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
            "use_count": self.use_count,
        }


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024.0 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024.0
    return str(n)


def _offset_index(starts, offset):
    """字节偏移落在哪个分片内（starts 为各分片起始偏移，升序）。返回下标。"""
    if not starts:
        return -1
    i = bisect.bisect_right(starts, offset) - 1
    return i if i >= 0 else 0


def _ws_view(parse):
    """websocket 帧流的 API 视图：不含帧负载数据，只给短预览（省流量）。"""
    frames = []
    for f in parse["frames"]:
        frames.append({
            "index": (f["index"] + 1) if f["index"] is not None else None,
            "offset": f["offset"], "end": f["end"],
            "fin": f["fin"], "rsv": f["rsv"], "opcode": f["opcode"],
            "opcode_name": f["opcode_name"], "masked": f["masked"],
            "declared_len": f["declared_len"], "payload_len": f["payload_len"],
            "complete": f["complete"], "truncated": f["truncated"],
            "preview": wsproto.preview_bytes(f["payload"], 48),
            "notes": list(f["notes"]),
        })
    return {
        "handshake": parse["handshake"],
        "handshake_len": parse["handshake_len"],
        "tail_bytes": parse["tail_bytes"],
        "frames_capped": parse["frames_capped"],
        "stray_continuations": parse["stray_continuations"],
        "frames": frames,
    }


class Session:
    """一条穿过转发监听器的 TCP 连接。线程安全。"""

    def __init__(self, listener_id, listener_name, listen_port, client_addr,
                 target_addr, capture_limit=DEFAULT_CAPTURE_LIMIT):
        self.id = uuid.uuid4().hex[:12]
        self.listener_id = listener_id
        self.listener_name = listener_name
        self.listen_port = listen_port
        self.client_addr = client_addr              # (ip, port)
        self.target_addr = target_addr              # (host, port)
        self.capture_limit = capture_limit
        self.started_at = time.time()
        self.ended_at = None
        self.state = "open"                         # open | closed | failed
        self.error = None

        self.bytes_tx = 0
        self.bytes_rx = 0
        self.pkts_tx = 0
        self.pkts_rx = 0

        self._chunks = {d: [] for d in DIRECTIONS}      # [(ts, bytes), ...]
        self.captured = {d: 0 for d in DIRECTIONS}
        self.truncated = {d: False for d in DIRECTIONS}
        self._payload_version = {d: 0 for d in DIRECTIONS}
        self._interp_cache = {}                         # direction -> (version, protocol, results)
        self._rate_sample = {d: (time.time(), 0) for d in DIRECTIONS}
        self.rate = {d: 0.0 for d in DIRECTIONS}         # bytes/s
        # 逐报文视图（新增）：协议识别结果、ws 帧流解析、报文分段，全部按负载版本缓存
        self._protocol_cache = None                     # ((tx_ver, rx_ver), protocol)
        self._ws_cache = {}                             # direction -> (version, ws parse)
        self._blob_cache = {}                           # direction -> (version, [message blobs])
        self.lock = threading.RLock()

    # ---------------- 写入 ----------------

    def record(self, direction: str, data: bytes) -> None:
        """记录一次收发：计数总是累加，负载样本按捕获上限截断。"""
        with self.lock:
            if direction == "tx":
                self.bytes_tx += len(data)
                self.pkts_tx += 1
            else:
                self.bytes_rx += len(data)
                self.pkts_rx += 1
            if self.captured[direction] < self.capture_limit:
                room = self.capture_limit - self.captured[direction]
                keep = data[:room]
                if keep:
                    self._chunks[direction].append((time.time(), bytes(keep)))
                    self.captured[direction] += len(keep)
                    self._payload_version[direction] += 1
            if self.captured[direction] >= self.capture_limit:
                self.truncated[direction] = True

    def close(self, state: str = "closed", error=None) -> None:
        with self.lock:
            if self.state == "open":
                self.state = state
            self.ended_at = time.time()
            if error:
                self.error = error

    # ---------------- 读取 ----------------

    @property
    def client(self) -> str:
        return f"{self.client_addr[0]}:{self.client_addr[1]}"

    @property
    def target(self) -> str:
        return f"{self.target_addr[0]}:{self.target_addr[1]}"

    def payload(self, direction: str) -> bytes:
        with self.lock:
            return b"".join(d for _, d in self._chunks[direction])

    def duration(self, now=None) -> float:
        now = now if now is not None else time.time()
        return (self.ended_at or now) - self.started_at

    # ---------------- 协议识别与逐报文视图（新增） ----------------

    @property
    def protocol(self) -> str:
        """会话应用层协议：websocket / http / tls / tcp / unknown。

        按 (tx 版本, rx 版本) 缓存——每方向每来一个分片最多重算一次，且只在
        每方向前 16 KiB 上扫描（wsproto.MAX_SCAN）。一旦结论是 websocket
        （服务端 101 已确认）就冻结：后续帧不可能推翻握手结论。
        unknown 只出现在「头还没收齐 / 101 还在路上」时，会话关闭后落定为
        http 或 tcp，避免长连接的 ws 会话被误判为 http。
        """
        with self.lock:
            key = (self._payload_version["tx"], self._payload_version["rx"])
            cached = self._protocol_cache
            if cached is not None:
                if cached[0] == key:
                    return cached[1]
                if cached[1] == "websocket":
                    self._protocol_cache = (key, "websocket")
                    return "websocket"
            tx_head = self.payload("tx")[:wsproto.MAX_SCAN]
            rx_head = self.payload("rx")[:wsproto.MAX_SCAN]
            prot = wsproto.detect_protocol(tx_head, rx_head)
            if prot == "unknown" and self.state != "open":
                prot = "http" if wsproto.looks_like_http(tx_head) else "tcp"
            self._protocol_cache = (key, prot)
            return prot

    def _chunk_ranges(self, direction):
        """各分片的字节区间与序号：[(start, end, ts, seq), ...]。"""
        out = []
        off = 0
        for i, (ts, d) in enumerate(self._chunks[direction]):
            out.append((off, off + len(d), ts, i + 1))
            off += len(d)
        return out

    def _ws_parse(self, direction):
        """websocket 协议下解析整方向流：拆出 HTTP 握手前缀，再解析帧流并
        装配报文。结果按该方向负载版本缓存（帧边界与 recv 边界无关，
        必须在拼接流上解析，详见 wsproto 模块头注释）。"""
        cached = self._ws_cache.get(direction)
        if cached is not None and cached[0] == self._payload_version[direction]:
            return cached[1]
        data = self.payload(direction)
        info, start = wsproto.split_handshake(data, direction)
        parsed = wsproto.parse_frames(data, start)
        assembled = wsproto.assemble_messages(parsed["frames"])
        ranges = self._chunk_ranges(direction)
        starts = [r[0] for r in ranges]
        messages = []
        for m in assembled["messages"]:
            i = _offset_index(starts, m["offset"])
            ts = ranges[i][2] if i >= 0 else None
            messages.append({
                "ts": ts, "len": m["payload_len"], "truncated": m["truncated"],
                "kind": "ws-" + m["opcode_name"],
                "opcode": m["opcode"], "opcode_name": m["opcode_name"],
                "offset": m["offset"], "end": m["end"],
                "frames": m["frames"], "fragmented": m["fragmented"],
                "fin_seen": m["fin_seen"], "payload": m["payload"],
            })
        result = {
            "handshake": info,
            "handshake_len": start,
            "frames": parsed["frames"],
            "frames_capped": parsed["max_frames_hit"],
            "tail_bytes": parsed["tail_bytes"],
            "stray_continuations": assembled["stray_continuations"],
            "messages": messages,
        }
        self._ws_cache[direction] = (self._payload_version[direction], result)
        return result

    def _message_blobs(self, direction, prot=None):
        """该方向的报文分段（含负载数据）。协议感知：

        - websocket：HTTP 握手作为第 1 条（kind=handshake），其后是按
          RFC 6455 §5.4 装配的报文（可跨多个帧、跨多个 TCP 分段）
        - 其它协议：按每次 recv 的分片边界切分（即「一个会话中的多个
          tx/rx」，与 pkts 计数一一对应）

        每项除报文字段外含 ``payload``（原始字节），按负载版本缓存。
        """
        with self.lock:
            cached = self._blob_cache.get(direction)
            if cached is not None and cached[0] == self._payload_version[direction]:
                return cached[1]
            prot = prot if prot is not None else self.protocol
            chunks = self._chunks[direction]
            last = len(chunks) - 1
            truncated = self.truncated[direction]
            blobs = []
            if prot == "websocket":
                parse = self._ws_parse(direction)
                for m in parse["messages"]:
                    blobs.append(dict(m, seq=0))
                if parse["handshake"] is not None:
                    # 握手前缀作为该方向第 1 条报文，负载即 HTTP 头部原文
                    data = self.payload(direction)
                    blobs.insert(0, {
                        "seq": 0, "ts": chunks[0][0] if chunks else None,
                        "len": parse["handshake_len"], "kind": "handshake",
                        "truncated": False,
                        "payload": data[:parse["handshake_len"]],
                    })
            else:
                for i, (ts, d) in enumerate(chunks):
                    blobs.append({
                        "seq": 0, "ts": ts, "len": len(d), "kind": "recv",
                        "truncated": bool(truncated and i == last), "payload": d,
                    })
            for i, b in enumerate(blobs):
                b["seq"] = i + 1
            self._blob_cache[direction] = (self._payload_version[direction], blobs)
            return blobs

    def messages(self, direction: str) -> list:
        """报文分段的轻量列表（不含负载数据）：每项 {seq, ts, len, kind,
        truncated}，websocket 报文另含 opcode/fragmented/frames/offset/end。
        供 detail()/meta() 与报文选择器使用。"""
        with self.lock:
            return [{k: v for k, v in b.items() if k != "payload"}
                    for b in self._message_blobs(direction)]

    def messages_view(self, direction: str, limit: int = MSG_VIEW_LIMIT,
                      offset: int = 0, run=None) -> dict:
        """``GET /api/sessions/{id}/messages`` 的数据：单方向逐报文负载
        （base64）+ 逐报文解读结果 + websocket 帧流概览。

        ``run`` 为解读器注册表的运行函数时对返回的每条报文执行全部已启用
        解读器（按 MSG_INTERP_LIMIT 条数与 MSG_INTERP_BUDGET_S 全局预算
        截断，超限报文标记 ``interpret_skipped``）。
        """
        with self.lock:
            prot = self.protocol
            blobs = self._message_blobs(direction, prot)
            total = len(blobs)
            offset = max(0, min(offset, total))
            limit = max(1, min(limit, MSG_VIEW_LIMIT_MAX))
            sel = blobs[offset:offset + limit]
            items = []
            budget_deadline = time.monotonic() + MSG_INTERP_BUDGET_S
            interp_capped = False
            for i, b in enumerate(sel):
                item = {
                    "seq": b["seq"], "ts": b["ts"], "len": b["len"],
                    "kind": b["kind"], "truncated": b["truncated"],
                }
                for extra in ("opcode", "opcode_name", "fragmented",
                              "frames", "offset", "end"):
                    if extra in b:
                        item[extra] = b[extra]
                # 解读器收到的 meta 里也会有同一条报文的描述
                msg_meta = {"seq": b["seq"], "len": b["len"], "kind": b["kind"]}
                for extra in ("opcode", "opcode_name", "fragmented", "frames"):
                    if extra in b:
                        msg_meta[extra] = b[extra]
                item["payload_b64"] = base64.b64encode(b["payload"]).decode("ascii")
                if run is not None and not interp_capped and i < MSG_INTERP_LIMIT:
                    if time.monotonic() > budget_deadline:
                        interp_capped = True
                    else:
                        meta = self.meta(direction)
                        meta["message"] = msg_meta
                        item["interpret"] = run(b["payload"], meta)
                if "interpret" not in item:
                    item["interpret_skipped"] = True
                items.append(item)
            view = {
                "session_id": self.id,
                "direction": direction,
                "protocol": prot,
                "truncated": self.truncated[direction],
                "capture_limit": self.capture_limit,
                "messages_total": total,
                "returned": len(sel),
                "offset": offset,
                "limit": limit,
                "interpret_capped": interp_capped,
                "messages": items,
            }
            if prot == "websocket":
                view["websocket"] = _ws_view(self._ws_parse(direction))
            return view

    def meta(self, direction: str) -> dict:
        with self.lock:
            msgs = self.messages(direction)
            return {
                "session_id": self.id,
                "direction": direction,
                "protocol": self.protocol,
                "listener_name": self.listener_name,
                "listen_port": self.listen_port,
                "client": f"{self.client_addr[0]}:{self.client_addr[1]}",
                "target": f"{self.target_addr[0]}:{self.target_addr[1]}",
                "bytes": {"tx": self.bytes_tx, "rx": self.bytes_rx},
                "pkts": {"tx": self.pkts_tx, "rx": self.pkts_rx},
                "captured": dict(self.captured),
                "truncated": dict(self.truncated),
                "started_at": self.started_at,
                "duration_s": round(self.duration(), 3),
                "capture_limit": self.capture_limit,
                # 新增：该方向的报文分段（轻量、截断至 MSG_LIST_LIMIT 条），
                # 让解读器与对外 API 都能看到「一个会话中的多个 tx/rx」
                "message_count": len(msgs),
                "messages": msgs[:MSG_LIST_LIMIT],
                "messages_capped": len(msgs) > MSG_LIST_LIMIT,
            }

    def summary(self) -> dict:
        with self.lock:
            return {
                "id": self.id,
                "listener_id": self.listener_id,
                "listener_name": self.listener_name,
                "listen_port": self.listen_port,
                "client": f"{self.client_addr[0]}:{self.client_addr[1]}",
                "target": f"{self.target_addr[0]}:{self.target_addr[1]}",
                "state": self.state,
                "error": self.error,
                "protocol": self.protocol,
                "bytes_tx": self.bytes_tx,
                "bytes_rx": self.bytes_rx,
                "pkts_tx": self.pkts_tx,
                "pkts_rx": self.pkts_rx,
                "rate_tx_bps": round(self.rate["tx"], 1),
                "rate_rx_bps": round(self.rate["rx"], 1),
                "started_at": self.started_at,
                "ended_at": self.ended_at,
                "duration_s": round(self.duration(), 3),
                "captured_tx": self.captured["tx"],
                "captured_rx": self.captured["rx"],
                "truncated": dict(self.truncated),
            }

    def detail(self, run_interpreters=None) -> dict:
        """汇总摘要 + base64 负载 + 解读结果（按 (负载版本, 协议) 缓存）。"""
        d = self.summary()
        with self.lock:
            payloads = {dr: b"".join(x[1] for x in self._chunks[dr]) for dr in DIRECTIONS}
            d["payload_b64"] = {dr: base64.b64encode(p).decode("ascii")
                                for dr, p in payloads.items()}
            d["payload_version"] = dict(self._payload_version)
            d["capture_limit"] = self.capture_limit
            # 新增：协议与双向报文分段（轻量、截断），供详情页报文选择器使用
            prot = self.protocol
            msgs = {dr: self.messages(dr) for dr in DIRECTIONS}
            d["messages"] = {dr: msgs[dr][:MSG_LIST_LIMIT] for dr in DIRECTIONS}
            d["messages_total"] = {dr: len(msgs[dr]) for dr in DIRECTIONS}
            d["messages_capped"] = {dr: len(msgs[dr]) > MSG_LIST_LIMIT for dr in DIRECTIONS}
            if run_interpreters is not None:
                results = {}
                for dr in DIRECTIONS:
                    cached = self._interp_cache.get(dr)
                    if (cached is not None
                            and cached[0] == self._payload_version[dr]
                            and cached[1] == prot):
                        results[dr] = cached[2]
                    else:
                        res = run_interpreters(payloads[dr], self.meta(dr))
                        self._interp_cache[dr] = (self._payload_version[dr], prot, res)
                        results[dr] = res
                d["interpret"] = results
        return d

    def invalidate_interpretation(self) -> None:
        """清除解读缓存（POST /api/sessions/{id}/interpret 调用）。

        报文分段与协议识别只依赖负载本身，不受解读器变更影响，故只清解读缓存。
        """
        with self.lock:
            self._interp_cache = {}


class Store:
    """全局内存存储：监听器、会话、事件流、速率序列。线程安全。"""

    def __init__(self, capture_limit: int = DEFAULT_CAPTURE_LIMIT,
                 max_closed_sessions: int = DEFAULT_MAX_CLOSED_SESSIONS):
        self.capture_limit = capture_limit
        self.max_closed_sessions = max_closed_sessions
        self.lock = threading.RLock()
        self.listeners = {}                  # id -> Listener
        self.sessions = {}                   # id -> Session（按插入序）
        self.events = collections.deque(maxlen=DEFAULT_EVENT_LOG)
        self._event_seq = 0
        self.rate_series = collections.deque(maxlen=DEFAULT_RATE_SERIES)  # [(ts, tx_bps, rx_bps)]
        self.started_at = time.time()
        self.tokens = {}                     # id -> Token
        self.api_calls = collections.deque(maxlen=DEFAULT_API_CALL_LOG)
        self._api_call_seq = 0
        panel = Token("面板内置令牌", kind="panel")
        self.tokens[panel.id] = panel
        self.panel_token_id = panel.id

    @property
    def panel_token(self) -> Token:
        with self.lock:
            return self.tokens[self.panel_token_id]

    # ---------------- 令牌 ----------------

    def add_token(self, token: Token) -> None:
        with self.lock:
            self.tokens[token.id] = token

    def remove_token(self, token_id: str) -> None:
        with self.lock:
            token = self.tokens.get(token_id)
            if token is None:
                raise KeyError(token_id)
            if token.kind == "panel":
                raise ValueError("面板内置令牌不可删除")
            self.tokens.pop(token_id, None)

    def find_token(self, value: str) -> Token | None:
        """按令牌值查找已启用的令牌；未找到或已停用均返回 None。"""
        if not value:
            return None
        with self.lock:
            for t in self.tokens.values():
                if secrets.compare_digest(t.value, value):
                    return t if t.enabled else None
        return None

    def token_summaries(self) -> list:
        with self.lock:
            return [t.summary() for t in self.tokens.values()]

    # ---------------- 外部 API 调用日志 ----------------

    def record_api_call(self, token: Token | None, method: str, path: str,
                        status: int | None, client: str,
                        duration_ms: float) -> int:
        """记录一次外部 /api/ 调用（面板内置令牌的调用不记录）。"""
        with self.lock:
            self._api_call_seq += 1
            self.api_calls.append({
                "seq": self._api_call_seq,
                "ts": time.time(),
                "token_id": token.id if token else None,
                "token_title": token.title if token else "未认证",
                "method": method,
                "path": path,
                "status": status,
                "client": client,
                "duration_ms": round(duration_ms, 1),
            })
            return self._api_call_seq

    def api_calls_since(self, since: int) -> list:
        with self.lock:
            return [c for c in self.api_calls if c["seq"] > since]

    # ---------------- 事件 ----------------

    def event(self, kind: str, message: str, data=None) -> int:
        with self.lock:
            self._event_seq += 1
            self.events.append({
                "seq": self._event_seq,
                "ts": time.time(),
                "kind": kind,
                "message": message,
                "data": data,
            })
            return self._event_seq

    def events_since(self, since: int) -> list:
        with self.lock:
            return [e for e in self.events if e["seq"] > since]

    # ---------------- 监听器 / 会话 ----------------

    def add_listener(self, listener) -> None:
        with self.lock:
            self.listeners[listener.id] = listener

    def remove_listener(self, listener_id) -> None:
        with self.lock:
            self.listeners.pop(listener_id, None)

    def listener_by_port(self, listen_port) -> "object | None":
        with self.lock:
            for l in self.listeners.values():
                if l.listen_port == listen_port:
                    return l
        return None

    def add_session(self, session: Session) -> None:
        with self.lock:
            self.sessions[session.id] = session

    def clear_closed_sessions(self) -> int:
        with self.lock:
            closed = [s for s in self.sessions.values() if s.state != "open"]
            drop = len(closed) - self.max_closed_sessions
            if drop > 0:
                for s in sorted(closed, key=lambda s: s.ended_at or 0)[:drop]:
                    self.sessions.pop(s.id, None)
            return drop

    # ---------------- 速率 ----------------

    def update_rates(self) -> None:
        """每秒由后台线程调用：基于计数器增量计算每会话速率与全局速率序列。"""
        now = time.time()
        agg = {"tx": 0.0, "rx": 0.0}
        with self.lock:
            for s in self.sessions.values():
                with s.lock:
                    for dr in DIRECTIONS:
                        cur = s.bytes_tx if dr == "tx" else s.bytes_rx
                        last_ts, last_bytes = s._rate_sample[dr]
                        dt = max(now - last_ts, 1e-6)
                        s.rate[dr] = max(0.0, (cur - last_bytes) / dt)
                        s._rate_sample[dr] = (now, cur)
                        agg[dr] += s.rate[dr]
            self.rate_series.append((now, agg["tx"], agg["rx"]))

    # ---------------- 快照 / 导出 ----------------

    def state(self, registry) -> dict:
        with self.lock:
            sessions = list(self.sessions.values())
            totals = {
                "sessions": len(sessions),
                "open": sum(1 for s in sessions if s.state == "open"),
                "bytes_tx": sum(s.bytes_tx for s in sessions),
                "bytes_rx": sum(s.bytes_rx for s in sessions),
                "pkts_tx": sum(s.pkts_tx for s in sessions),
                "pkts_rx": sum(s.pkts_rx for s in sessions),
                "rate_tx_bps": round(sum(s.rate["tx"] for s in sessions), 1),
                "rate_rx_bps": round(sum(s.rate["rx"] for s in sessions), 1),
            }
            return {
                "version": __version__,
                "started_at": self.started_at,
                "now": time.time(),
                "capture_limit": self.capture_limit,
                "max_closed_sessions": self.max_closed_sessions,
                "totals": totals,
                "listeners": [l.summary() for l in self.listeners.values()],
                "sessions": [s.summary() for s in reversed(sessions)],
                "interpreters": registry.info(),
                "series": [[round(ts, 1), round(tx, 1), round(rx, 1)]
                           for ts, tx, rx in self.rate_series],
                "event_seq": self._event_seq,
            }

    def export_json(self, registry, with_payloads: bool = True) -> dict:
        with self.lock:
            sessions = list(self.sessions.values())
            payload = {}
            for s in sessions:
                det = s.detail()
                payload[s.id] = {
                    "summary": det,
                    "interpret": det.get("interpret", {}),
                }
                if with_payloads:
                    payload[s.id]["payload_b64"] = det["payload_b64"]
            return {
                "exported_at": time.time(),
                "tool": "socketmeasure",
                "note": "全部数据仅存于内存，本文件为即时导出结果。",
                "capture_limit": self.capture_limit,
                "totals": {
                    "sessions": len(sessions),
                    "bytes_tx": sum(s.bytes_tx for s in sessions),
                    "bytes_rx": sum(s.bytes_rx for s in sessions),
                },
                "interpreters": registry.info(),
                "listeners": [l.summary() for l in self.listeners.values()],
                "events": list(self.events),
                "sessions": payload,
            }

    # ---------------- 重置（供外部测试建立干净基线） ----------------

    def clear_sessions(self) -> int:
        """清空全部会话与速率序列，返回被清除的会话数。

        注意：进行中的连接其会话对象仍被转发线程持有，计数会继续写入
        那些已脱离面板视图的对象，不再出现在统计中。
        """
        with self.lock:
            n = len(self.sessions)
            self.sessions.clear()
            self.rate_series.clear()
            return n

    def clear_events(self) -> int:
        with self.lock:
            n = len(self.events)
            self.events.clear()
            return n

    def take_listeners(self) -> list:
        """摘除全部监听器（返回副本），调用方负责逐个 stop()。"""
        with self.lock:
            listeners = list(self.listeners.values())
            self.listeners.clear()
            return listeners

    def export_csv(self) -> str:
        with self.lock:
            sessions = list(self.sessions.values())
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow([
            "session_id", "listener", "listen_port", "client", "target",
            "state", "bytes_tx", "bytes_rx", "pkts_tx", "pkts_rx",
            "started_at", "ended_at", "duration_s", "error",
        ])
        for s in sessions:
            sm = s.summary()
            writer.writerow([
                sm["id"], sm["listener_name"], sm["listen_port"], sm["client"],
                sm["target"], sm["state"], sm["bytes_tx"], sm["bytes_rx"],
                sm["pkts_tx"], sm["pkts_rx"],
                sm["started_at"], sm["ended_at"], sm["duration_s"],
                sm["error"] or "",
            ])
        return out.getvalue()
