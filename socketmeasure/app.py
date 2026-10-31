"""命令行入口：组装并启动测量引擎 + Web 管理面板。

用法示例：
    uv run python -m socketmeasure --port 8080
    uv run python -m socketmeasure --port 8080 --forward echo:18080:127.0.0.1:18081
    （--forward 格式为 name:监听端口:目标主机:目标端口，可多次指定）
"""

from __future__ import annotations

import argparse
import logging
import signal
import threading

from .interpreters import Registry
from .model import Store
from .proxy import create_listener
from .server import make_server

log = logging.getLogger("socketmeasure")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="socketmeasure",
        description="Socket 端口收发测量工具：Web 管理面板 + 动态扩展解读器，数据仅存内存")
    parser.add_argument("--host", default="127.0.0.1",
                        help="管理面板绑定地址（默认 127.0.0.1，仅供本机访问）")
    parser.add_argument("--port", type=int, default=8080,
                        help="管理面板端口（默认 8080）")
    parser.add_argument("--capture-limit", type=int, default=1 << 20,
                        help="每个会话每个方向最多捕获的负载字节数（默认 1 MiB；"
                             "字节总计数不受限）")
    parser.add_argument("--forward", action="append", default=[], metavar="NAME:PORT:HOST:PORT",
                        help="启动时即创建转发监听器，可多次指定")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    store = Store(capture_limit=args.capture_limit)
    registry = Registry()

    for spec in args.forward:
        parts = spec.split(":")
        if len(parts) != 4:
            log.error("--forward 格式应为 NAME:监听端口:目标主机:目标端口，跳过 %r", spec)
            continue
        name, lport, thost, tport = parts
        try:
            create_listener(store, name, int(lport), thost, int(tport))
        except OSError as e:
            log.error("创建监听器 %s 失败: %s", spec, e)

    try:
        httpd = make_server(args.host, args.port, store, registry)
    except OSError as e:
        log.error("无法启动管理面板: %s", e)
        return 1

    stop = threading.Event()

    def monitor():
        while not stop.wait(1.0):
            try:
                store.update_rates()
                store.clear_closed_sessions()
            except Exception:
                log.exception("后台监控线程异常")

    monitor_thread = threading.Thread(target=monitor, daemon=True, name="monitor")
    monitor_thread.start()

    store.event("system", f"SocketMeasure 已启动，面板 http://{args.host}:{args.port}")

    def request_stop(signum, frame):
        stop.set()
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, request_stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, request_stop)

    print(f"SocketMeasure 管理面板已就绪：http://{args.host}:{args.port}")
    print("数据仅保存在内存中，关闭程序后即消失；可在面板内随时导出下载。")
    try:
        httpd.serve_forever()
    finally:
        stop.set()
        for listener in list(store.listeners.values()):
            listener.stop()
        httpd.server_close()
        log.info("SocketMeasure 已退出")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
