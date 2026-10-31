"""Web 管理面板：纯标准库 HTTP 服务，提供 REST API 与单页面控制台。

设计说明：
  - 全部接口读写均为内存数据，无任何磁盘 IO；
  - 导出接口在请求时即时生成 JSON / CSV / 原始负载，通过
    Content-Disposition 触发浏览器下载，同样不落盘；
  - 默认仅绑定 127.0.0.1，面板无鉴权，仅供本机调试使用。
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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .proxy import create_listener

log = logging.getLogger("socketmeasure.server")

STATIC_DIR = pathlib.Path(__file__).resolve().parent / "static"

INTERP_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")


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

    # ---------------- 路由 ----------------

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
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

            key = (method, rest[0])
            if key == ("GET", "state"):
                return self._ok(self.store.state(self.registry))
            if key == ("GET", "events"):
                since = int(query.get("since", "0"))
                return self._ok({"events": self.store.events_since(since)})
            # 带路径参数的路由优先于列表路由
            if rest[0] == "sessions" and len(rest) >= 2:
                return self._route_session(method, rest[1:], rest[1], query)
            if rest[0] == "listeners" and len(rest) >= 2:
                return self._route_listener(method, rest[1:], rest[1])
            if rest[0] == "interpreters" and len(rest) >= 2:
                return self._route_interpreter(method, rest[1:], rest[1])

            if key == ("GET", "sessions"):
                return self._ok({"sessions": [s.summary() for s in
                                              reversed(list(self.store.sessions.values()))]})
            if key == ("GET", "listeners"):
                return self._ok({"listeners": [l.summary()
                                               for l in self.store.listeners.values()]})
            if key == ("GET", "interpreters"):
                return self._ok({"interpreters": self.registry.info()})

            # /api/sessions/{id}... /api/listeners/{id} /api/interpreters/{id}...
            # 见上方带参数路由

            if key == ("POST", "listeners"):
                return self._create_listener()
            if key == ("POST", "interpreters"):
                return self._register_interpreter()
            if key == ("POST", "interpreters-test"):
                return self._test_interpreter()
            if key == ("GET", "export"):
                return self._export(query)
            raise ApiError(f"未知接口: {method} /api/{'/'.join(rest)}", 404)
        except ApiError as e:
            return self._err(e.code, str(e))
        except BrokenPipeError:
            return
        except Exception:
            log.exception("处理请求 %s %s 时发生错误", method, self.path)
            return self._err(500, "服务器内部错误，已记录日志")

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
                    "client": "?", "target": "?",
                    "bytes": {"tx": len(payload), "rx": 0},
                    "pkts": {"tx": 1, "rx": 0},
                    "started_at": None, "duration_s": 0,
                    "capture_limit": self.store.capture_limit,
                    "session_id": None,
                    "captured": {"tx": len(payload), "rx": 0},
                    "truncated": {"tx": False, "rx": False}}
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
                PanelHandler._index_cache = path.read_text(encoding="utf-8").encode("utf-8")
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
