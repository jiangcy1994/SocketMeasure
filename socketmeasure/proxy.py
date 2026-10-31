"""TCP 端口转发测量引擎。

每条监听器绑定 (bind_ip, listen_port)，将进入的连接透明转发到
(target_host, target_port)，同时逐会话记录收发字节、报文数与负载样本。
转发是双向的：客户端->目标 记为 tx，目标->客户端 记为 rx。
"""

from __future__ import annotations

import logging
import selectors
import socket
import threading
import time
import uuid

from .model import Session

log = logging.getLogger("socketmeasure.proxy")

CHUNK_SIZE = 65536
CONNECT_TIMEOUT = 10.0


class Listener:
    def __init__(self, store, name: str, listen_port: int, target_host: str,
                 target_port: int, bind_ip: str = "0.0.0.0",
                 capture_limit: int | None = None):
        self.id = uuid.uuid4().hex[:12]
        self.store = store
        self.name = name
        self.listen_port = int(listen_port)
        self.target_host = target_host
        self.target_port = int(target_port)
        self.bind_ip = bind_ip
        self.capture_limit = capture_limit or store.capture_limit
        self.running = False
        self._sock = None
        self._thread = None
        self._conn_threads = []

    # ---------------- 生命周期 ----------------

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self.bind_ip, self.listen_port))
            sock.listen(128)
        except OSError as e:
            sock.close()
            raise OSError(f"无法在 {self.bind_ip}:{self.listen_port} 上监听：{e}") from e
        self._sock = sock
        self.running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True,
                                        name=f"listen-{self.listen_port}")
        self._thread.start()

    def stop(self) -> None:
        self.running = False
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=3.0)

    def summary(self) -> dict:
        with self.store.lock:
            mine = [s for s in self.store.sessions.values()
                    if s.listener_id == self.id]
            open_n = sum(1 for s in mine if s.state == "open")
            return {
                "id": self.id,
                "name": self.name,
                "bind_ip": self.bind_ip,
                "listen_port": self.listen_port,
                "target": f"{self.target_host}:{self.target_port}",
                "running": self.running,
                "sessions": len(mine),
                "open_sessions": open_n,
                "bytes_tx": sum(s.bytes_tx for s in mine),
                "bytes_rx": sum(s.bytes_rx for s in mine),
                "pkts_tx": sum(s.pkts_tx for s in mine),
                "pkts_rx": sum(s.pkts_rx for s in mine),
                "rate_tx_bps": round(sum(s.rate["tx"] for s in mine), 1),
                "rate_rx_bps": round(sum(s.rate["rx"] for s in mine), 1),
            }

    # ---------------- 内部 ----------------

    def _accept_loop(self) -> None:
        while self.running:
            try:
                client, addr = self._sock.accept()
            except OSError:
                if self.running:
                    log.warning("监听器 %s 的 accept 异常，退出接收循环", self.listen_port)
                break
            t = threading.Thread(target=self._handle_connection,
                                 args=(client, addr), daemon=True,
                                 name=f"conn-{self.listen_port}-{addr[1]}")
            t.start()
            self._conn_threads.append(t)
            # 防止句柄无限增长：清理已结束的线程对象
            if len(self._conn_threads) > 256:
                self._conn_threads = [t for t in self._conn_threads if t.is_alive()]

    def _handle_connection(self, client: socket.socket, client_addr) -> None:
        session = Session(self.id, self.name, self.listen_port, client_addr,
                          (self.target_host, self.target_port), self.capture_limit)
        self.store.add_session(session)
        self.store.event("session", f"新连接 {session.client} ⇄ {session.target}"
                                    f"（监听 :{self.listen_port}）", {"session_id": session.id})
        try:
            upstream = socket.create_connection(
                (self.target_host, self.target_port), timeout=CONNECT_TIMEOUT)
        except OSError as e:
            session.close("failed", f"无法连接目标 {session.target}: {e}")
            self.store.event("error", f"连接目标失败 {session.target}: {e}",
                             {"session_id": session.id})
            self._safe_close(client)
            return
        upstream.settimeout(None)
        client.settimeout(None)
        error = None
        try:
            error = self._pump(session, client, upstream)
        except Exception:
            log.exception("会话 %s 转发异常", session.id)
            error = "转发引擎内部错误"
        finally:
            self._safe_close(client)
            self._safe_close(upstream)
            session.close("closed" if error is None else "failed", error)
            self.store.event(
                "session", f"会话结束 {session.client} ⇄ {session.target}"
                           f"：发 {session.bytes_tx} B / 收 {session.bytes_rx} B",
                {"session_id": session.id})

    def _pump(self, session: Session, client: socket.socket,
              upstream: socket.socket) -> str | None:
        """双向转发并计量。任一端读关闭后，对端写半关闭；两端都关闭后退出。"""
        sel = selectors.DefaultSelector()
        sel.register(client, selectors.EVENT_READ, ("tx", upstream, "client"))
        sel.register(upstream, selectors.EVENT_READ, ("rx", client, "upstream"))
        open_sides = {"client": True, "upstream": True}
        error = None
        try:
            while any(open_sides.values()):
                if not self.running:
                    error = "监听器已停止"
                    break
                events = sel.select(timeout=1.0)
                for key, _ in events:
                    direction, dst, side = key.data
                    src = key.fileobj
                    try:
                        data = src.recv(CHUNK_SIZE)
                    except OSError:
                        data = b""
                    if not data:
                        # 该端已关闭读：对端写半关闭
                        open_sides[side] = False
                        try:
                            sel.unregister(src)
                        except Exception:
                            pass
                        try:
                            dst.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                    else:
                        session.record(direction, data)
                        try:
                            dst.sendall(data)
                        except OSError as e:
                            error = f"转发失败: {e!r}"
                            open_sides = {"client": False, "upstream": False}
                            break
        finally:
            sel.close()
        return error

    @staticmethod
    def _safe_close(sock: socket.socket) -> None:
        for action in (lambda: sock.shutdown(socket.SHUT_RDWR), sock.close):
            try:
                action()
            except OSError:
                pass


def create_listener(store, name: str, listen_port: int, target_host: str,
                    target_port: int, bind_ip: str = "0.0.0.0",
                    capture_limit: int | None = None) -> Listener:
    listener = Listener(store, name, listen_port, target_host, target_port,
                        bind_ip, capture_limit)
    listener.start()      # 绑定失败时抛 OSError，由调用方转成 400
    store.add_listener(listener)
    store.event("listener", f"新增监听器 {name}：:{listen_port} → "
                            f"{target_host}:{target_port}", {"listener_id": listener.id})
    return listener
