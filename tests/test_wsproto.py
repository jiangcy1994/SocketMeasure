"""wsproto 单元测试：RFC 6455 握手、帧解析、报文装配、协议探测。

运行：uv run python tests/test_wsproto.py
"""
from __future__ import annotations

import base64
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from socketmeasure import wsproto  # noqa: E402


def frame(opcode, payload=b"", fin=True, mask=False, mask_key=b"\x37\xfa\x21\x3d",
          rsv=0):
    """构造一个 RFC 6455 帧。"""
    b0 = (0x80 if fin else 0) | (rsv << 4) | opcode
    n = len(payload)
    if n < 126:
        head = bytes([b0, (0x80 if mask else 0) | n])
    elif n < 65536:
        head = bytes([b0, (0x80 if mask else 0) | 126]) + n.to_bytes(2, "big")
    else:
        head = bytes([b0, (0x80 if mask else 0) | 127]) + n.to_bytes(8, "big")
    if mask:
        head += mask_key
        payload = bytes(p ^ mask_key[i & 3] for i, p in enumerate(payload))
    return head + payload


HANDSHAKE_REQ = (
    b"GET /chat HTTP/1.1\r\n"
    b"Host: example.com:8000\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: Upgrade\r\n"
    b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    b"Sec-WebSocket-Protocol: chat, superchat\r\n"
    b"Sec-WebSocket-Version: 13\r\n"
    b"\r\n"
)
HANDSHAKE_RESP = (
    b"HTTP/1.1 101 Switching Protocols\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: Upgrade\r\n"
    b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
    b"\r\n"
)


class Runner:
    def __init__(self):
        self.n = 0
        self.failed = 0

    def check(self, name, cond, extra=""):
        self.n += 1
        if cond:
            print(f"PASS {name}")
        else:
            self.failed += 1
            print(f"FAIL {name} {extra}")

    def eq(self, name, got, want):
        self.check(name, got == want, f"got={got!r} want={want!r}")


def test_handshake(r):
    req = wsproto.parse_handshake_request(HANDSHAKE_REQ)
    r.check("解析握手请求", req is not None)
    r.eq("握手方法", req["method"], "GET")
    r.eq("握手目标", req["target"], "/chat")
    r.check("websocket_upgrade 为真", req["websocket_upgrade"])
    r.check("key 合法", req["key_ok"])
    # RFC 6455 §1.3：Accept = base64(SHA1(key + GUID))
    r.eq("expected_accept 官方向量", wsproto.expected_accept(req["key"]),
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
    # 头部不完整（未见空行）
    r.check("头部不完善返回 None",
            wsproto.parse_handshake_request(HANDSHAKE_REQ[:-2]) is None)
    # Key 不合法（非 24 字符 base64）
    bad = HANDSHAKE_REQ.replace(b"dGhlIHNhbXBsZSBub25jZQ==", b"short")
    bad_req = wsproto.parse_handshake_request(bad)
    r.check("key 不合法时 websocket_upgrade 为假",
            bad_req is not None and not bad_req["websocket_upgrade"])
    # 无 Upgrade 头
    no_up = HANDSHAKE_REQ.replace(b"Upgrade: websocket\r\n", b"")
    r.check("无 Upgrade 头不是 ws 握手",
            not wsproto.parse_handshake_request(no_up)["websocket_upgrade"])
    resp = wsproto.parse_handshake_response(HANDSHAKE_RESP)
    r.check("解析握手响应", resp is not None)
    r.eq("响应状态", resp["status"], 101)
    r.eq("accept 头", resp["accept"], "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
    view = wsproto.handshake_view(req)
    r.eq("handshake_view 保留首行", view["start_line"], "GET /chat HTTP/1.1")
    r.check("handshake_view end_offset 定位空行后",
            HANDSHAKE_REQ[view["end_offset"]:] == b"" or
            HANDSHAKE_REQ[view["end_offset"]:view["end_offset"] + 1] != b"\r")
    # 非 HTTP 流量
    r.check("非 HTTP 返回 None", wsproto.parse_handshake_request(b"\x00\x01\xff") is None)
    # 坏行（无冒号）
    r.check("坏头部行返回 None",
            wsproto.parse_handshake_request(b"GET / HTTP/1.1\r\nBadLine\r\n\r\n") is None)


def test_valid_key(r):
    r.check("合法 key", wsproto.valid_ws_key("dGhlIHNhbXBsZSBub25jZQ=="))
    r.check("key 过短", not wsproto.valid_ws_key("c2hvcnQ="))
    r.check("key 为空", not wsproto.valid_ws_key(None))
    r.check("key 含非法字符", not wsproto.valid_ws_key("!!!!!!!!!!!!!!!!!!!!!!!!"))


def test_unmask(r):
    # RFC 6455 §5.7 官方向量
    masked = bytes.fromhex("7f9f4d5158")
    r.eq("§5.7 掩码解除", wsproto.unmask(masked, bytes.fromhex("37fa213d")), b"Hello")
    # 空负载 / 空掩码不抛异常
    r.eq("空负载", wsproto.unmask(b"", b"\x01\x02\x03\x04"), b"")
    # 长度不是 4 的倍数（掩码在负载 0 处重新对齐）
    r.eq("掩码对齐(7 字节)",
        wsproto.unmask(bytes([0] * 7), bytes([1, 0, 0, 0])),
        bytes([1, 0, 0, 0, 1, 0, 0]))


def test_frames(r):
    # 单个无掩码文本帧
    parsed = wsproto.parse_frames(frame(0x1, b"Hello"))
    r.eq("帧数", len(parsed["frames"]), 1)
    f = parsed["frames"][0]
    r.check("完整", f["complete"])
    r.eq("opcode", f["opcode"], 0x1)
    r.eq("payload", f["payload"], b"Hello")
    r.eq("declared_len", f["declared_len"], 5)
    r.check("无 tail 余留", parsed["tail_bytes"] == 0)
    # 客户端掩码帧（§5.7 向量字节）
    parsed = wsproto.parse_frames(bytes.fromhex("818537fa213d7f9f4d5158"))
    r.eq("§5.7 向量解掩码", parsed["frames"][0]["payload"], b"Hello")
    r.check("§5.7 标记掩码", parsed["frames"][0]["masked"])
    # 长度边界：125 / 126（16 位）/ 65536（64 位）
    for n, label in [(125, "125"), (126, "126"), (65536, "65536")]:
        payload = bytes((i * 7) & 0xFF for i in range(n))
        parsed = wsproto.parse_frames(frame(0x2, payload))
        r.eq(f"长度 {label} 往返", parsed["frames"][0]["payload"], payload)
        r.check(f"长度 {label} 完整", parsed["frames"][0]["complete"])
    # 零长度帧
    parsed = wsproto.parse_frames(frame(0x1, b""))
    r.eq("零长度帧", parsed["frames"][0]["payload"], b"")
    # 声明长度超过已有数据 → 标记 truncated，不抛异常
    stream = frame(0x1, b"Hi", mask=False)
    cut = stream[:-1]                       # 少 1 字节
    parsed = wsproto.parse_frames(cut)
    f = parsed["frames"][0]
    r.check("截断帧不抛异常", True)
    r.check("截断帧标记 truncated", f["truncated"])
    r.check("截断帧不完整", not f["complete"])
    r.eq("截断帧 payload 是实际字节", f["payload"], b"H")
    # 帧头不完整（仅 1 字节）→ 尾帧标记
    parsed = wsproto.parse_frames(b"\x81")
    r.eq("帧头不完整 → 1 个尾帧", len(parsed["frames"]), 1)
    r.check("尾帧标记 opcode 未知", parsed["frames"][0]["opcode"] is None)
    # 掩码字段不完整（缺掩码键）
    parsed = wsproto.parse_frames(bytes.fromhex("818037fa"))
    r.check("掩码不完整返回尾帧而非异常",
            parsed["frames"][0]["opcode"] is None)
    # 扩展长度字段不完整
    parsed = wsproto.parse_frames(bytes.fromhex("81fe00"))
    r.check("16 位长度不完整返回尾帧",
            parsed["frames"][0]["opcode"] is None)
    # 64 位长度最高有效位置位 → 提示而非异常
    parsed = wsproto.parse_frames(bytes.fromhex("817f") + (1 << 63).to_bytes(8, "big") + b"")
    r.check("非法 64 位长度给提示",
            any("非法" in n for n in parsed["frames"][0]["notes"]))
    # 非最小编码：126 表示 < 126 的长度
    parsed = wsproto.parse_frames(bytes.fromhex("817e0005") + b"Hello")
    r.check("非最小编码(126→5)给提示",
            any("非最小编码" in n for n in parsed["frames"][0]["notes"]))
    r.eq("非最小编码仍正确读负载", parsed["frames"][0]["payload"], b"Hello")
    # 保留 opcode
    parsed = wsproto.parse_frames(frame(0x3, b"x"))
    r.check("保留 opcode 给提示",
            any("保留 opcode" in n for n in parsed["frames"][0]["notes"]))
    # 控制帧违规：负载 > 125、被分片
    parsed = wsproto.parse_frames(frame(0x8, bytes(126)))
    r.check("控制帧过长给提示",
            any("超过 125" in n for n in parsed["frames"][0]["notes"]))
    parsed = wsproto.parse_frames(frame(0x9, b"x", fin=False))
    r.check("控制帧分片给提示",
            any("控制帧被分片" in n for n in parsed["frames"][0]["notes"]))
    # RSV 位置位
    parsed = wsproto.parse_frames(frame(0x1, b"x", rsv=1))
    r.check("RSV 置位给提示",
            any("RSV" in n for n in parsed["frames"][0]["notes"]))
    # 连续多帧
    stream = frame(0x1, b"one") + frame(0x2, b"two") + frame(0x9, b"ping")
    parsed = wsproto.parse_frames(stream)
    r.eq("连续三帧", len(parsed["frames"]), 3)
    r.eq("三帧全部完整", sum(1 for f in parsed["frames"] if f["complete"]), 3)
    # 空缓冲
    parsed = wsproto.parse_frames(b"")
    r.eq("空缓冲无帧", len(parsed["frames"]), 0)
    # max_frames 上限
    stream = frame(0x1, b"x") * 10
    parsed = wsproto.parse_frames(stream, max_frames=4)
    r.eq("max_frames 上限", len(parsed["frames"]), 4)
    r.check("max_frames 标记", parsed["max_frames_hit"])


def test_assemble(r):
    # 单帧单报文
    frames = wsproto.parse_frames(frame(0x1, b"Hello"))["frames"]
    msgs = wsproto.assemble_messages(frames)["messages"]
    r.eq("单帧报文数", len(msgs), 1)
    r.eq("单帧报文负载", msgs[0]["payload"], b"Hello")
    # 分片：FIN=0 text "Hel" + FIN=1 continuation "lo"
    stream = frame(0x1, b"Hel", fin=False) + frame(0x0, b"lo", fin=True)
    frames = wsproto.parse_frames(stream)["frames"]
    msgs = wsproto.assemble_messages(frames)["messages"]
    r.eq("分片装配", len(msgs), 1)
    r.eq("分片拼接", msgs[0]["payload"], b"Hello")
    r.check("标记分片", msgs[0]["fragmented"])
    r.eq("分片帧数", msgs[0]["frames"], 2)
    # 分片中穿插控制帧（§5.4）
    stream = (frame(0x1, b"Hel", fin=False) + frame(0x9, b"!") +
              frame(0x0, b"lo", fin=True))
    frames = wsproto.parse_frames(stream)["frames"]
    out = wsproto.assemble_messages(frames)
    r.eq("穿插控制帧不影响装配", out["messages"][0]["payload"], b"Hello")
    r.eq("控制帧独立不计数", len(out["messages"]), 1)
    # 掩码分片跨帧对齐：每个帧的负载在帧内 0 处对齐掩码（frame() 自动加掩码）
    k1, k2 = b"\x01\x02\x03\x04", b"\x40\x30\x20\x10"
    stream = (frame(0x1, b"ABCD", fin=False, mask=True, mask_key=k1) +
              frame(0x0, b"EFGH", fin=True, mask=True, mask_key=k2))
    frames = wsproto.parse_frames(stream)["frames"]
    msgs = wsproto.assemble_messages(frames)["messages"]
    r.eq("跨帧掩码各自对齐", msgs[0]["payload"], b"ABCDEFGH")
    # 游离续帧（无起始数据帧）
    frames = wsproto.parse_frames(frame(0x0, b"x"))["frames"]
    out = wsproto.assemble_messages(frames)
    r.eq("游离续帧跳过", len(out["messages"]), 0)
    r.eq("游离续帧计数", out["stray_continuations"], 1)
    # 流尾未见 FIN → 仍返回报文但标记
    frames = wsproto.parse_frames(frame(0x1, b"abc", fin=False))["frames"]
    m = wsproto.assemble_messages(frames)["messages"][0]
    r.check("未见 FIN 标记", not m["fin_seen"] and m["truncated"])
    # 两个独立报文
    stream = frame(0x1, b"one") + frame(0x2, b"two")
    frames = wsproto.parse_frames(stream)["frames"]
    msgs = wsproto.assemble_messages(frames)["messages"]
    r.eq("两报文", len(msgs), 2)
    r.eq("报文 seq 从 1 开始", [m["seq"] for m in msgs], [1, 2])
    # 新数据帧打断未完成报文：前者标记 fin_seen=False
    stream = frame(0x1, b"a", fin=False) + frame(0x1, b"b")
    frames = wsproto.parse_frames(stream)["frames"]
    msgs = wsproto.assemble_messages(frames)["messages"]
    r.eq("被打断的报文也保留", len(msgs), 2)
    r.check("被打断报文标记 truncated", msgs[0]["truncated"] and not msgs[0]["fin_seen"])


def test_split_handshake(r):
    tx_wire = HANDSHAKE_REQ + frame(0x1, b"Hi", mask=True)
    hs, start = wsproto.split_handshake(tx_wire, "tx")
    r.check("tx 拆出握手", hs is not None)
    r.eq("tx 帧流起点", tx_wire[start:], frame(0x1, b"Hi", mask=True))
    r.eq("握手首行", hs["start_line"], "GET /chat HTTP/1.1")
    rx_wire = HANDSHAKE_RESP + frame(0x1, b"Hi")
    hs2, start2 = wsproto.split_handshake(rx_wire, "rx")
    r.check("rx 拆出握手", hs2 is not None)
    r.eq("rx 帧流起点", rx_wire[start2:], frame(0x1, b"Hi"))
    # 非握手前缀
    hs3, start3 = wsproto.split_handshake(frame(0x1, b"Hi"), "tx")
    r.check("无握手前缀返回 (None, 0)", hs3 is None and start3 == 0)
    # rx 方向是普通 200 响应（非 101）→ 不算握手
    hs4, _ = wsproto.split_handshake(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello", "rx")
    r.check("非 101 响应不算握手", hs4 is None)


def test_detect(r):
    r.eq("完整握手 → websocket",
        wsproto.detect_protocol(HANDSHAKE_REQ, HANDSHAKE_RESP), "websocket")
    r.eq("双方为空 → unknown", wsproto.detect_protocol(b"", b""), "unknown")
    r.eq("仅发出请求未收到响应 → unknown",
        wsproto.detect_protocol(HANDSHAKE_REQ, b""), "unknown")
    r.eq("响应头不完整 → unknown",
        wsproto.detect_protocol(HANDSHAKE_REQ, b"HTTP/1.1 101"), "unknown")
    r.eq("服务端拒绝(200) → http",
        wsproto.detect_protocol(HANDSHAKE_REQ,
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), "http")
    r.eq("完整普通 HTTP 请求 → http",
        wsproto.detect_protocol(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", b""), "http")
    r.eq("TLS 记录 → tls",
        wsproto.detect_protocol(bytes.fromhex("16030100"), b""), "tls")
    r.eq("裸 TCP 字节 → tcp",
        wsproto.detect_protocol(b"\x00\x01\x02\x03", b""), "tcp")
    r.eq("像 HTTP 但头未齐 → unknown",
        wsproto.detect_protocol(b"GET /", b""), "unknown")
    # 缓存友好：相同输入稳定返回相同结果（无随机性）
    first = wsproto.detect_protocol(HANDSHAKE_REQ, HANDSHAKE_RESP)
    r.eq("探测稳定可缓存", first, "websocket")


def test_preview(r):
    r.eq("文本预览", wsproto.preview_bytes(b"Hello"), "Hello")
    r.eq("非 UTF-8 二进制预览给 hex", wsproto.preview_bytes(b"\xff\xfe"), "fffe")
    r.eq("空预览", wsproto.preview_bytes(b""), "")
    r.eq("中文预览", wsproto.preview_bytes("你好".encode()), "你好")


def test_looks_like(r):
    r.check("TLS 记录头", wsproto.looks_like_tls(bytes.fromhex("16030100")))
    r.check("非 TLS", not wsproto.looks_like_tls(b"GET /"))
    r.check("HTTP 方法前缀", wsproto.looks_like_http(b"GET / HTTP/1.1\r\n"))
    r.check("HTTP 响应前缀", wsproto.looks_like_http(b"HTTP/1.1 200 OK\r\n"))
    r.check("非 HTTP", not wsproto.looks_like_http(b"\x00\x01"))
    r.check("空数据两者皆否",
            not wsproto.looks_like_tls(b"") and not wsproto.looks_like_http(b""))


def main():
    r = Runner()
    test_handshake(r)
    test_valid_key(r)
    test_unmask(r)
    test_frames(r)
    test_assemble(r)
    test_split_handshake(r)
    test_detect(r)
    test_preview(r)
    test_looks_like(r)
    print(f"\n{r.n} 项断言，{r.failed} 项失败")
    # 并发安全：多线程同时调用纯函数解析（注册表缓存依赖此性质）
    errors = []

    def worker():
        try:
            for _ in range(200):
                p = wsproto.parse_frames(frame(0x1, b"Hello", mask=True))
                assert wsproto.assemble_messages(p["frames"])["messages"][0]["payload"] == b"Hello"
                assert wsproto.detect_protocol(HANDSHAKE_REQ, HANDSHAKE_RESP) == "websocket"
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    r.check("8 线程 × 200 次并发解析无错误", not errors, str(errors[:1]))
    verdict = "全部通过" if not r.failed else f"存在失败（{r.failed} 项）"
    print(f"结论：{verdict}")
    sys.exit(1 if r.failed else 0)


if __name__ == "__main__":
    time.sleep(0)  # 保持与 e2e 一致的导入结构
    main()
