"""Web 管理面板：纯标准库 HTTP 服务，提供 REST API 与单页面控制台。

设计说明：
  - 全部接口读写均为内存数据，无任何磁盘 IO；
  - 导出接口在请求时即时生成 JSON / CSV / 原始负载，通过
    Content-Disposition 触发浏览器下载，同样不落盘；
  - 所有 /api/* 接口均需携带令牌（面板内置令牌随页面注入，用户令牌
    在「令牌与调用」页生成）；令牌管理与调用日志仅对面板内置令牌开放；
  - 默认仅绑定 127.0.0.1，仅供本机调试使用。
"""

from __future__ import annotations

import base64
import datetime
import json
import logging
import mimetypes
import pathlib
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import model
from ._version import __version__
from .model import Token
from .proxy import create_listener

log = logging.getLogger("socketmeasure.server")

STATIC_DIR = pathlib.Path(__file__).resolve().parent / "static"

INTERP_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
TOKEN_TITLE_MAX = 64


class ApiError(Exception):
    def __init__(self, message: str, code: int = 400):
        super().__init__(message)
        self.code = code


def _json_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")


class PanelHandler(BaseHTTPRequestHandler):
    server_version = "SocketMeasure/0.1"
    protocol_version = "HTTP/1.1"

    # 由 make_server 注入到 server 实例上
    @property
    def store(self):
        return self.server.store

    @property
    def registry(self):
        return self.server.registry

    # ---------------- 基础工具 ----------------

    def _send(self, code: int, body: bytes, content_type: str,
              headers: dict | None = None):
        self._status_code = code
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, code: int, obj):
        self._send(code, _json_bytes(obj), "application/json; charset=utf-8")

    def _ok(self, obj):
        self._send_json(200, obj)

    def _err(self, code: int, message: str):
        self._send_json(code, {"error": message})

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            raise ApiError(f"请求体不是合法 JSON: {e}")
        if not isinstance(obj, dict):
            raise ApiError("请求体必须是 JSON 对象")
        return obj

    def log_message(self, fmt: str, *args):
        log.debug("%s - %s", self.address_string(), fmt % args)

    # ---------------- 鉴权 ----------------

    def _token_value_from_request(self, query: dict) -> str | None:
        """令牌来源（任选其一）：Authorization: Bearer <t>、X-API-Token、?token=。"""
        auth = self.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            value = auth[7:].strip()
            if value:
                return value
        value = (self.headers.get("X-API-Token") or "").strip()
        if value:
            return value
        value = (query.get("token") or "").strip()
        return value or None

    def _authenticate(self, rest: list, query: dict) -> Token | None:
        """校验 /api/* 请求的令牌。成功返回 Token，失败抛 401 ApiError。"""
        value = self._token_value_from_request(query)
        token = self.store.find_token(value)
        is_token_admin = bool(rest) and rest[0] == "tokens"
        if is_token_admin:
            # 令牌管理（创建/列出/停用/删除）仅限面板内置令牌
            if token is None or token.kind != "panel":
                raise ApiError("令牌管理接口仅限面板内置令牌调用", 401)
            token.touch()
            return token
        if token is None:
            if value:
                raise ApiError("token 无效或已停用", 401)
            raise ApiError(
                "缺少 token：请使用 Authorization: Bearer <token>、"
                "X-API-Token 头或 ?token= 查询参数（令牌在面板「令牌与调用」页生成）",
                401)
        token.touch()
        return token

    def _record_call(self, method: str, path: str, token: Token | None,
                     started: float) -> None:
        """记录外部调用；面板内置令牌与静态资源不记录。"""
        if token is not None and token.kind == "panel":
            return
        try:
            self.store.record_api_call(
                token, method, path, self._status_code,
                self.address_string(),
                (time.monotonic() - started) * 1000.0)
        except Exception:
            log.exception("记录 API 调用日志失败")

    # ---------------- 路由 ----------------

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        self._status_code = None
        self._api_path = None
        self._auth_token = None
        token = None
        started = time.monotonic()
        try:
            parsed = urlparse(self.path)
            segments = [s for s in parsed.path.split("/") if s]
            query = {k: v[0] for k, v in parse_qs(parsed.query).items()}

            if not segments:
                return self._serve_index()

            if segments[0] != "api":
                return self._serve_static(segments)

            rest = segments[1:]
            if not rest:
                raise ApiError("未知接口", 404)

            self._api_path = parsed.path
            try:
                token = self._authenticate(rest, query)
            except ApiError as e:
                self._err(e.code, str(e))
                return
            self._auth_token = token
            self._route_api(method, rest, query)
        except ApiError as e:
            self._err(e.code, str(e))
        except BrokenPipeError:
            return
        except Exception:
            log.exception("处理请求 %s %s 时发生错误", method, self.path)
            return self._err(500, "服务器内部错误，已记录日志")
        finally:
            if self._api_path is not None:
                self._record_call(method, self._api_path, token, started)

    def _route_api(self, method: str, rest: list, query: dict) -> None:
        key = (method, rest[0])
        if key == ("GET", "state"):
            return self._ok(self.store.state(self.registry))
        if key == ("GET", "events"):
            since = int(query.get("since", "0"))
            return self._ok({"events": self.store.events_since(since)})
        if key == ("GET", "health"):
            t = self._auth_token
            return self._ok({
                "ok": True,
                "service": "socketmeasure",
                "version": __version__,
                "token_title": t.title if t else None,
                "now": time.time(),
            })
        if key == ("GET", "apicalls"):
            since = int(query.get("since", "0"))
            calls = self.store.api_calls_since(since)
            return self._ok({
                "calls": calls,
                "seq": calls[-1]["seq"] if calls else since,
            })
        if key == ("POST", "reset"):
            return self._reset()
        # 带路径参数的路由优先于列表路由
        if rest[0] == "sessions" and len(rest) >= 2:
            return self._route_session(method, rest[1:], rest[1], query)
        if rest[0] == "listeners" and len(rest) >= 2:
            return self._route_listener(method, rest[1:], rest[1])
        if rest[0] == "interpreters" and len(rest) >= 2:
            return self._route_interpreter(method, rest[1:], rest[1])
        if rest[0] == "tokens" and len(rest) >= 2:
            return self._route_token(method, rest[1:], rest[1])

        if key == ("GET", "sessions"):
            return self._ok({"sessions": [s.summary() for s in
                                          reversed(list(self.store.sessions.values()))]})
        if key == ("GET", "listeners"):
            return self._ok({"listeners": [l.summary()
                                           for l in self.store.listeners.values()]})
        if key == ("GET", "interpreters"):
            return self._ok({"interpreters": self.registry.info()})

        # /api/sessions/{id}... /api/listeners/{id} /api/interpreters/{id}...
        # /api/tokens/{id}... 见上方带参数路由

        if key == ("POST", "listeners"):
            return self._create_listener()
        if key == ("POST", "interpreters"):
            return self._register_interpreter()
        if key == ("POST", "interpreters-test"):
            return self._test_interpreter()
        if key == ("POST", "tokens"):
            return self._create_token()
        if key == ("GET", "tokens"):
            return self._ok({"tokens": self.store.token_summaries()})
        if key == ("GET", "export"):
            return self._export(query)
        raise ApiError(f"未知接口: {method} /api/{'/'.join(rest)}", 404)

    # ---------------- 令牌 ----------------

    def _create_token(self):
        body = self._read_json_body()
        title = str(body.get("title") or "").strip()
        if not title:
            raise ApiError("title 不能为空")
        if len(title) > TOKEN_TITLE_MAX:
            raise ApiError(f"title 长度不能超过 {TOKEN_TITLE_MAX} 个字符")
        token = Token(title, kind="user")
        self.store.add_token(token)
        self.store.event("token", f"创建令牌 {title}（{token.id}）")
        return self._ok({"token": token.summary()})

    def _route_token(self, method: str, rest: list, token_id: str):
        token = self.store.tokens.get(token_id)
        if token is None:
            raise ApiError(f"令牌 {token_id} 不存在", 404)
        if len(rest) >= 2 and rest[1] == "toggle" and method == "POST":
            if token.kind == "panel":
                raise ApiError("面板内置令牌不可停用", 400)
            body = self._read_json_body()
            token.enabled = bool(body.get("enabled", True))
            self.store.event("token",
                             f"{'启用' if token.enabled else '停用'}令牌 {token.title}")
            return self._ok({"token": token.summary()})
        if method == "DELETE":
            if token.kind == "panel":
                raise ApiError("面板内置令牌不可删除", 400)
            try:
                self.store.remove_token(token_id)
            except KeyError:
                raise ApiError(f"令牌 {token_id} 不存在", 404)
            self.store.event("token", f"删除令牌 {token.title}")
            return self._ok({"removed": token_id})
        raise ApiError("不支持的令牌操作", 405)

    # ---------------- 重置（外部测试建立基线） ----------------

    def _reset(self):
        body = self._read_json_body()
        do_sessions = body.get("sessions", True)
        do_listeners = bool(body.get("listeners", False))
        do_events = bool(body.get("events", False))
        result = {}
        if do_listeners:
            listeners = self.store.take_listeners()
            for l in listeners:
                l.stop()
            result["listeners_removed"] = len(listeners)
            self.store.event("listener", "reset 清空全部监听器")
        if do_sessions:
            result["sessions_removed"] = self.store.clear_sessions()
        if do_events:
            result["events_removed"] = self.store.clear_events()
        if not result:
            result["note"] = "未指定任何清理项（sessions/listeners/events 均为 false）"
        self.store.event("system", "通过 API 重置测量数据基线", result)
        return self._ok({"reset": result})

    # ---------------- 监听器 ----------------

    def _create_listener(self):
        body = self._read_json_body()
        name = str(body.get("name") or "").strip() or f"l-{body.get('listen_port')}"
        try:
            listen_port = int(body.get("listen_port"))
            target_port = int(body.get("target_port", body.get("listen_port")))
        except (TypeError, ValueError):
            raise ApiError("listen_port / target_port 必须是整数端口")
        target_host = str(body.get("target_host") or "").strip()
        if not target_host:
            raise ApiError("target_host 不能为空")
        if not (1 <= listen_port <= 65535 and 1 <= target_port <= 65535):
            raise ApiError("端口取值范围 1-65535")
        bind_ip = str(body.get("bind_ip") or "0.0.0.0").strip()
        capture_limit = body.get("capture_limit")
        if capture_limit is not None:
            capture_limit = int(capture_limit)
            if capture_limit < 0:
                raise ApiError("capture_limit 不能为负")
        if self.store.listener_by_port(listen_port):
            raise ApiError(f"端口 {listen_port} 已被占用（已有同名监听器）")
        try:
            listener = create_listener(self.store, name, listen_port,
                                       target_host, target_port, bind_ip,
                                       capture_limit)
        except OSError as e:
            raise ApiError(str(e))
        return self._ok({"listener": listener.summary()})

    def _route_listener(self, method: str, rest: list, listener_id: str):
        if method != "DELETE":
            raise ApiError("仅支持 DELETE /api/listeners/{id}", 405)
        with self.store.lock:
            listener = self.store.listeners.get(listener_id)
        if listener is None:
            raise ApiError(f"监听器 {listener_id} 不存在", 404)
        listener.stop()
        self.store.remove_listener(listener_id)
        self.store.event("listener", f"已移除监听器 {listener.name}（:{listener.listen_port}）")
        return self._ok({"removed": listener_id})

    # ---------------- 会话 ----------------

    def _route_session(self, method: str, rest: list, session_id: str, query: dict):
        session = self.store.sessions.get(session_id)
        if session is None:
            raise ApiError(f"会话 {session_id} 不存在", 404)

        # rest 形如 [id, op?, ...]
        if len(rest) >= 2 and rest[1] == "interpret" and method == "POST":
            session.invalidate_interpretation()
            return self._ok({"session": session.detail(self.registry.run)})

        if len(rest) >= 2 and rest[1] == "messages" and method == "GET":
            # 新增：逐报文视图——把一个会话中的多个 tx/rx 按协议边界拆开，
            # 每条报文单独给出负载与解读结果（原有接口保持不变）
            direction = query.get("direction", "tx")
            if direction not in ("tx", "rx"):
                raise ApiError("direction 只能是 tx 或 rx")
            try:
                limit = int(query.get("limit", model.MSG_VIEW_LIMIT))
                offset = int(query.get("offset", "0"))
            except ValueError:
                raise ApiError("limit / offset 必须是整数")
            if limit < 1 or offset < 0:
                raise ApiError("limit >= 1 且 offset >= 0")
            return self._ok(session.messages_view(direction, limit, offset,
                                                   self.registry.run))

        if len(rest) >= 2 and rest[1] == "payload" and method == "GET":
            direction = query.get("direction", "tx")
            if direction not in ("tx", "rx"):
                raise ApiError("direction 只能是 tx 或 rx")
            payload = session.payload(direction)
            enc = query.get("encoding", "bin")
            stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            if enc == "hex":
                body = payload.hex().encode("ascii")
                ctype = "text/plain; charset=utf-8"
            elif enc == "text":
                body = payload.decode("utf-8", errors="replace").encode("utf-8")
                ctype = "text/plain; charset=utf-8"
            else:
                body = payload
                ctype = "application/octet-stream"
            filename = f"session-{session_id}-{direction}-{stamp}" + (
                ".txt" if enc != "bin" else ".bin")
            self._send(200, body, ctype, {
                "Content-Disposition": f'attachment; filename="{filename}"'})
            return

        if method == "GET":
            return self._ok({"session": session.detail(self.registry.run)})

        raise ApiError("不支持的会话操作", 405)

    # ---------------- 解读器 ----------------

    def _register_interpreter(self):
        body = self._read_json_body()
        interp_id = str(body.get("id") or "").strip()
        title = str(body.get("title") or interp_id).strip()
        code = body.get("code")
        enabled = bool(body.get("enabled", True))
        if not INTERP_ID_RE.match(interp_id):
            raise ApiError("id 只能包含字母、数字、下划线、短横线，长度 1-64")
        try:
            interp = self.registry.register_custom(interp_id, title, code, enabled)
        except ValueError as e:
            raise ApiError(str(e))
        self.store.event("interpreter", f"注册解读器 {interp_id}（{title}）")
        return self._ok({"interpreter": interp.info()})

    def _route_interpreter(self, method: str, rest: list, interp_id: str):
        # rest 形如 [id, op?, ...]
        if len(rest) >= 2 and rest[1] == "toggle" and method == "POST":
            body = self._read_json_body()
            try:
                self.registry.set_enabled(interp_id, body.get("enabled", True))
            except KeyError:
                raise ApiError(f"解读器 {interp_id} 不存在", 404)
            interp = self.registry.get(interp_id)
            self.store.event("interpreter",
                             f"{'启用' if interp.enabled else '停用'}解读器 {interp_id}")
            return self._ok({"interpreter": interp.info()})
        if len(rest) >= 2 and rest[1] == "code" and method == "GET":
            interp = self.registry.get(interp_id)
            if interp is None:
                raise ApiError(f"解读器 {interp_id} 不存在", 404)
            if interp.kind != "custom":
                raise ApiError("内置解读器无源码", 400)
            return self._ok({"id": interp.id, "title": interp.title, "code": interp.code})
        if method == "DELETE":
            try:
                self.registry.remove(interp_id)
            except KeyError:
                raise ApiError(f"解读器 {interp_id} 不存在", 404)
            except ValueError as e:
                raise ApiError(str(e))
            self.store.event("interpreter", f"删除解读器 {interp_id}")
            return self._ok({"removed": interp_id})
        raise ApiError("不支持的解读器操作", 405)

    def _test_interpreter(self):
        body = self._read_json_body()
        code = body.get("code")
        direction = body.get("direction", "tx")
        if direction not in ("tx", "rx"):
            raise ApiError("direction 只能是 tx 或 rx")
        session_id = body.get("session_id")
        session = self.store.sessions.get(session_id) if session_id else None
        if session is not None:
            payload = session.payload(direction)
            meta = session.meta(direction)
        else:
            try:
                payload = base64.b64decode(str(body.get("payload_b64") or ""))
            except Exception:
                raise ApiError("payload_b64 不是合法的 base64")
            meta = {"direction": direction, "listen_port": None,
                    "listener_name": None, "protocol": "unknown",
                    "client": "?", "target": "?",
                    "bytes": {"tx": len(payload), "rx": 0},
                    "pkts": {"tx": 1, "rx": 0},
                    "started_at": None, "duration_s": 0,
                    "capture_limit": self.store.capture_limit,
                    "session_id": None,
                    "captured": {"tx": len(payload), "rx": 0},
                    "truncated": {"tx": False, "rx": False},
                    "message_count": 1,
                    "messages": [{"seq": 1, "ts": None, "len": len(payload),
                                  "kind": "recv", "truncated": False}],
                    "messages_capped": False}
        try:
            result = self.registry.test_code(code, payload, meta)
        except ValueError as e:
            raise ApiError(str(e))
        return self._ok(result)

    # ---------------- 导出 ----------------

    def _export(self, query: dict):
        fmt = query.get("format", "json").lower()
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        if fmt == "csv":
            body = self.store.export_csv().encode("utf-8-sig")
            self._send(200, body, "text/csv; charset=utf-8", {
                "Content-Disposition": f'attachment; filename="socketmeasure-{stamp}.csv"'})
            return
        if fmt != "json":
            raise ApiError("format 只能是 json 或 csv")
        payload_only = query.get("scope") == "sessions"
        if payload_only:
            obj = {"sessions": {sid: s.detail(self.registry.run)
                                for sid, s in self.store.sessions.items()}}
        else:
            obj = self.store.export_json(self.registry)
        body = _json_bytes(obj)
        self._send(200, body, "application/json; charset=utf-8", {
            "Content-Disposition": f'attachment; filename="socketmeasure-{stamp}.json"'})
        return

    # ---------------- 静态资源 ----------------

    _index_cache = None
    _index_lock = threading.Lock()

    def _serve_index(self):
        with PanelHandler._index_lock:
            if PanelHandler._index_cache is None:
                path = STATIC_DIR / "index.html"
                if not path.is_file():
                    raise ApiError("面板页面缺失：static/index.html 不存在", 500)
                html = path.read_text(encoding="utf-8")
                # 注入面板内置令牌：面板自身调用全部 /api/* 时携带
                # 同时注入版本号（来自 _version.py），页头/页脚与其保持一致
                token_value = self.store.panel_token.value
                inject = (f'<script>window.SM_PANEL_TOKEN={json.dumps(token_value)};'
                          f'window.SM_VERSION={json.dumps(__version__)};</script>')
                if "</head>" in html:
                    html = html.replace("</head>", inject + "</head>", 1)
                else:
                    html = inject + html
                PanelHandler._index_cache = html.encode("utf-8")
        self._send(200, PanelHandler._index_cache, "text/html; charset=utf-8")

    def _serve_static(self, segments: list):
        rel = pathlib.PurePosixPath(*segments)
        path = (STATIC_DIR / rel).resolve()
        try:
            path.relative_to(STATIC_DIR.resolve())
        except ValueError:
            raise ApiError("禁止访问面板目录之外", 403)
        if not path.is_file():
            raise ApiError("资源不存在", 404)
        ctype = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
        self._send(200, path.read_bytes(), ctype)


def make_server(host: str, port: int, store, registry) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), PanelHandler)
    httpd.daemon_threads = True
    httpd.store = store
    httpd.registry = registry
    return httpd
