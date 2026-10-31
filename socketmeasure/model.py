"""内存数据模型：会话、事件与存储。

方向约定：
  tx = 客户端 -> 目标（上行）  rx = 目标 -> 客户端（下行）

所有内容只存在于进程内存中：会话计数、捕获的负载分片、解读结果、事件流，
均设有内存上限，程序退出即消失，永不写入磁盘。
"""

from __future__ import annotations

import base64
import collections
import csv
import io
import secrets
import threading
import time
import uuid

# 每个方向最多捕获的负载字节数（字节总计数不受限，仅捕获样本受限）
DEFAULT_CAPTURE_LIMIT = 1 << 20            # 1 MiB
DEFAULT_MAX_CLOSED_SESSIONS = 200          # 内存中最多保留的已关闭会话数
DEFAULT_EVENT_LOG = 500                    # 事件流条数上限
DEFAULT_API_CALL_LOG = 500                 # 外部 API 调用日志条数上限
DEFAULT_RATE_SERIES = 120                  # 速率序列秒数上限

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
        self._interp_cache = {}                         # direction -> (version, results)
        self._rate_sample = {d: (time.time(), 0) for d in DIRECTIONS}
        self.rate = {d: 0.0 for d in DIRECTIONS}         # bytes/s
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

    def meta(self, direction: str) -> dict:
        with self.lock:
            return {
                "session_id": self.id,
                "direction": direction,
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
        """汇总摘要 + base64 负载 + 解读结果（按负载版本缓存）。"""
        d = self.summary()
        with self.lock:
            payloads = {dr: b"".join(x[1] for x in self._chunks[dr]) for dr in DIRECTIONS}
            d["payload_b64"] = {dr: base64.b64encode(p).decode("ascii")
                                for dr, p in payloads.items()}
            d["payload_version"] = dict(self._payload_version)
            d["capture_limit"] = self.capture_limit
            if run_interpreters is not None:
                results = {}
                for dr in DIRECTIONS:
                    cached = self._interp_cache.get(dr)
                    if cached is not None and cached[0] == self._payload_version[dr]:
                        results[dr] = cached[1]
                    else:
                        res = run_interpreters(payloads[dr], self.meta(dr))
                        self._interp_cache[dr] = (self._payload_version[dr], res)
                        results[dr] = res
                d["interpret"] = results
        return d

    def invalidate_interpretation(self) -> None:
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
                "version": "0.1.0",
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
