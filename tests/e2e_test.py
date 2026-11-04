"""端到端测试：流量 -> 计数 -> 解读器 -> 导出 -> 令牌鉴权。

用法：
    1. 启动回显目标与面板（本脚本会自建回显目标，只需面板在运行）：
         uv run python -m socketmeasure --port 8099 --forward echo:18080:127.0.0.1:18081
    2. 另开终端运行：
         uv run python tests/e2e_test.py

输出为纯 ASCII，避免 Windows 控制台编码干扰。
本脚本模拟「外部调用方」：从面板首页注入的令牌位提取内置令牌，
再用它创建一个用户令牌，后续全部请求携带用户令牌。
"""

import base64
import hashlib
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.request

BASE = os.environ.get("SM_BASE", "http://127.0.0.1:8099")
TARGET_PORT = int(os.environ.get("SM_TARGET_PORT", 18081))
ECHO_LISTEN_PORT = int(os.environ.get("SM_ECHO_LISTEN_PORT", 18080))
ok = True
TOKEN = None


def request(path, method="GET", obj=None, token=None, raw_body=False):
    """发起一次请求，返回 (status, parsed_json_or_bytes)。token 为 None 表示不带令牌。"""
    data = None
    headers = {}
    if obj is not None:
        data = json.dumps(obj).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token is not None:
        headers["X-API-Token"] = token
    req = urllib.request.Request(BASE + path, method=method, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            body = r.read()
            return r.status, (body if raw_body else json.loads(body.decode("utf-8")))
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            return e.code, (body if raw_body else json.loads(body.decode("utf-8")))
        except ValueError:
            return e.code, body


def post(path, obj=None, token=None):
    return request(path, method="POST", obj=obj, token=token)[1]


def get(path, token=None):
    return request(path, token=token, raw_body=True)[1]


def check(name, cond):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


def interp_results(det, direction="tx"):
    """从会话 detail 提取 {解读器 id: result}。"""
    return {r["id"]: r["result"] for r in (det.get("interpret") or {}).get(direction, [])}


def row_value(result, label):
    for row in (result or {}).get("rows", []):
        if row.get("label") == label:
            return row.get("value")
    return None


def push_session(data, timeout=5):
    """发送一份数据经转发（回显目标原样返回），等待会话结束后返回新会话 id。"""
    before = {s["id"] for s in json.loads(get("/api/sessions", token=TOKEN))["sessions"]}
    s = socket.create_connection(("127.0.0.1", ECHO_LISTEN_PORT), timeout=timeout)
    s.sendall(data)
    s.settimeout(2)
    try:
        while s.recv(65536):
            pass
    except socket.timeout:
        pass
    s.close()
    time.sleep(0.7)
    after = json.loads(get("/api/sessions", token=TOKEN))["sessions"]
    new = [x for x in after if x["id"] not in before]
    assert new, "未捕获到新会话（发送 %r 后）" % data[:32]
    return new[0]["id"]


def session_detail(sid):
    return json.loads(get("/api/sessions/%s" % sid, token=TOKEN))["session"]


def start_echo_target():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", TARGET_PORT))
    srv.listen(16)

    def loop():
        while True:
            c, _ = srv.accept()

            def echo(c=c):
                while True:
                    d = c.recv(65536)
                    if not d:
                        break
                    c.sendall(b"ECHO[" + d + b"]")
                c.close()

            threading.Thread(target=echo, daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()


WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"   # RFC 6455 §1.3
WS_PORT = int(os.environ.get("SM_WS_TARGET_PORT", 18084))
WS_LISTEN_PORT = int(os.environ.get("SM_WS_LISTEN_PORT", 18083))


def ws_build_frame(opcode, payload=b"", fin=True, mask=None):
    """构造一个帧：mask 为 4 字节掩码（客户端）或 None（服务端）。"""
    b0 = (0x80 if fin else 0) | opcode
    n = len(payload)
    if n < 126:
        head = bytes([b0, (0x80 if mask else 0) | n])
    elif n < 65536:
        head = bytes([b0, (0x80 if mask else 0) | 126]) + n.to_bytes(2, "big")
    else:
        head = bytes([b0, (0x80 if mask else 0) | 127]) + n.to_bytes(8, "big")
    if mask:
        head += mask
        payload = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
    return head + payload


def start_ws_target():
    """极简 RFC 6455 回显服务：完成握手后，把数据帧原样回发、ping 回 pong。"""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", WS_PORT))
    srv.listen(16)

    def handle(c):
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                d = c.recv(4096)
                if not d:
                    return
                data += d
            key = re.search(rb"Sec-WebSocket-Key:\s*(\S+)", data).group(1)
            accept = base64.b64encode(hashlib.sha1(key + WS_GUID).digest()).decode("ascii")
            c.sendall(("HTTP/1.1 101 Switching Protocols\r\n"
                       "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                       "Sec-WebSocket-Accept: %s\r\n\r\n" % accept).encode("ascii"))
            buf = b""

            def exact(n):
                nonlocal buf
                while len(buf) < n:
                    d = c.recv(65536)
                    if not d:
                        raise EOFError
                    buf += d
                out, buf = buf[:n], buf[n:]
                return out

            while True:
                hdr = exact(2)
                op = hdr[0] & 0x0F
                masked = hdr[1] & 0x80
                ln = hdr[1] & 0x7F
                if ln == 126:
                    ln = int.from_bytes(exact(2), "big")
                elif ln == 127:
                    ln = int.from_bytes(exact(8), "big")
                m = exact(4) if masked else None
                payload = exact(ln)
                if masked:
                    payload = bytes(b ^ m[i & 3] for i, b in enumerate(payload))
                if op == 0x8:                       # close -> 回 close 后断开
                    c.sendall(ws_build_frame(0x8, payload[:2] if len(payload) >= 2 else b""))
                    break
                if op == 0x9:                       # ping -> pong
                    c.sendall(ws_build_frame(0xA, payload))
                    continue
                c.sendall(ws_build_frame(0x1, payload))
        except Exception:
            pass
        finally:
            try:
                c.close()
            except Exception:
                pass

    def loop():
        while True:
            c, _ = srv.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()


def ws_session():
    """经面板监听端口（WS_LISTEN_PORT）发起一次 WebSocket 会话。

    发送：分片报文「WS-TEST-」+「payload」、单帧报文「Hello」、ping，
    断开前读取回显。返回（发送的报文负载列表，期望装配结果列表）。
    """
    s = socket.create_connection(("127.0.0.1", WS_LISTEN_PORT), timeout=5)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    s.sendall(("GET /chat HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n"
               "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
               "Sec-WebSocket-Version: 13\r\n\r\n" % key).encode("ascii"))
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        assert d, "未读到握手响应"
        buf += d
    assert buf.split(b"\r\n")[0].endswith(b"101 Switching Protocols"), "握手未通过: %r" % buf[:64]
    expected = base64.b64encode(
        hashlib.sha1(key.encode("ascii") + WS_GUID).digest()).decode("ascii")
    assert expected.encode() in buf, "握手 Accept 不匹配"

    def send(op, payload, fin=True):
        s.sendall(ws_build_frame(op, payload, fin, mask=os.urandom(4)))

    # 报文 1：分片（帧 1 不带 FIN + 续帧）
    send(0x1, b"WS-TEST-", fin=False)
    time.sleep(0.1)
    send(0x0, b"payload", fin=True)
    # 报文 2：单帧
    send(0x1, b"Hello")
    # ping（控制帧，独立单元）
    send(0x9, b"ping!")

    s.settimeout(3)
    got = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            got += d
    except socket.timeout:
        pass
    s.close()
    # 回显目标是「逐帧」回显（服务端合规：不带掩码），因此看到的是分片的两段
    # 而不是拼接后的整条报文——报文装配由面板侧负责，在 1c 段单独断言。
    assert b"WS-TEST-" in got and b"payload" in got and b"Hello" in got, \
        "回显缺失: %r" % got[:80]
    return None, [b"WS-TEST-payload", b"Hello"]


def main():
    global TOKEN
    start_echo_target()
    start_ws_target()


    # 0. 鉴权：无令牌应被拒绝；从面板首页提取内置令牌；再创建外部用户令牌
    status, body = request("/api/state")
    check("api rejects missing token", status == 401 and "error" in body)

    idx = get("/")
    m = re.search(rb'window\.SM_PANEL_TOKEN\s*=\s*"([^"]+)"', idx)
    check("panel token injected into page", bool(m))
    panel_token = m.group(1).decode("utf-8")

    status, body = request("/api/state", token=panel_token)
    check("panel token can call api", status == 200 and "totals" in body)

    status, body = request("/api/state", token="sm_invalid")
    check("invalid token rejected", status == 401)

    res = post("/api/tokens", {"title": "e2e"}, token=panel_token)
    check("create user token via api", res["token"]["title"] == "e2e")
    TOKEN = res["token"]["value"]

    status, body = request("/api/tokens", token=TOKEN)
    check("token admin rejects user token", status == 401)

    status, body = request("/api/health", token=TOKEN)
    check("health with valid token", status == 200 and body["ok"] is True
          and body["token_title"] == "e2e")
    check("api version", body["version"] == "0.2.0")

    # 1. 造流量
    payloads = [b"GET /metrics HTTP/1.1\r\nHost: t\r\n\r\n", b'{"type":"sensor","v":1}']
    s = socket.create_connection(("127.0.0.1", ECHO_LISTEN_PORT), timeout=5)
    for p in payloads:
        s.sendall(p)
        time.sleep(0.3)
    s.close()
    time.sleep(0.8)
    expected_tx = sum(len(p) for p in payloads)

    state = json.loads(get("/api/state", token=TOKEN))
    sid = state["sessions"][0]["id"]
    sess = state["sessions"][0]
    print("counts: tx=%d rx=%d pkts_tx=%d pkts_rx=%d state=%s"
          % (sess["bytes_tx"], sess["bytes_rx"], sess["pkts_tx"], sess["pkts_rx"], sess["state"]))
    check("session counted both directions", sess["bytes_tx"] == expected_tx and sess["bytes_rx"] > 0)
    check("session closed cleanly", sess["state"] == "closed")

    # 1b. 不同数据类型负载的捕获与解析
    # ASCII 文本
    sid = push_session(b"hello socketmeasure 0123456789")
    det = session_detail(sid)
    interps = interp_results(det)
    print("   interp summaries:", [ (k, v.get("summary")) for k, v in interps.items() ])
    check("ascii payload captured intact",
          base64.b64decode(det["payload_b64"]["tx"]) == b"hello socketmeasure 0123456789")
    check("text interpreter decodes ascii",
          row_value(interps.get("text"), "编码") == "UTF-8")
    check("stats interpreter sees bytes",
          interps.get("stats", {}).get("summary", "").startswith("tx 30 B"))

    # JSON
    json_doc = b'{"sensor": "temp", "values": [1, 2, 3], "ok": true}'
    sid = push_session(json_doc)
    det = session_detail(sid)
    interps = interp_results(det)
    check("json payload captured intact",
          base64.b64decode(det["payload_b64"]["tx"]) == json_doc)
    check("json interpreter parses json",
          interps.get("json", {}).get("summary") == "有效 JSON，已格式化" and
          json.loads(interps["json"]["text"]) == {"sensor": "temp", "values": [1, 2, 3], "ok": True})
    check("json payload rejected by http interpreter",
          "非 HTTP 流量" in (interps.get("http", {}) or {}).get("summary", ""))

    # HTTP 请求报文
    http_req = (b"GET /api/v1/metrics HTTP/1.1\r\nHost: localhost\r\n"
                b"User-Agent: e2e\r\nAccept: */*\r\n\r\n")
    sid = push_session(http_req)
    http_sid = sid
    det = session_detail(sid)
    interps = interp_results(det)
    http_res = interps.get("http", {})
    check("http interpreter parses request line",
          http_res.get("summary", "").startswith("HTTP 报文：GET /api/v1/metrics HTTP/1.1")
          and row_value(http_res, "首行") == "GET /api/v1/metrics HTTP/1.1"
          and row_value(http_res, "Host") == "localhost"
          and row_value(http_res, "User-Agent") == "e2e")
    check("http payload rejected by json interpreter",
          "不是 JSON" in (interps.get("json", {}) or {}).get("summary", ""))

    # UTF-8 多字节文本
    utf8_text = "你好，SocketMeasure ñ ✓".encode("utf-8")
    sid = push_session(utf8_text)
    det = session_detail(sid)
    interps = interp_results(det)
    check("utf8 payload captured intact",
          base64.b64decode(det["payload_b64"]["tx"]) == utf8_text)
    check("text interpreter decodes utf8",
          row_value(interps.get("text"), "编码") == "UTF-8" and
          interps["text"]["text"].startswith("你好"))
    txt_dl = get("/api/sessions/%s/payload?direction=tx&encoding=text" % sid, token=TOKEN)
    check("text encoding download matches utf8", txt_dl.decode("utf-8") ==
          "你好，SocketMeasure ñ ✓")

    # 二进制（含全部 256 个字节值）
    binary = bytes(range(256))
    sid = push_session(binary)
    det = session_detail(sid)
    interps = interp_results(det)
    check("binary payload captured intact",
          base64.b64decode(det["payload_b64"]["tx"]) == binary)
    check("text interpreter falls back for binary",
          row_value(interps.get("text"), "编码") == "非 UTF-8，按 latin-1 容错解码")
    hex_dl = get("/api/sessions/%s/payload?direction=tx&encoding=hex" % sid, token=TOKEN)
    check("hex encoding download round-trips binary",
          bytes.fromhex(hex_dl.decode("ascii")) == binary)
    hexd = interps.get("hexdump", {})
    check("hexdump interpreter renders all bytes",
          hexd.get("summary") == "256 字节（页面显示前 1024 字节）" and
          "ff " in hexd.get("text", ""))

    # 1c. WebSocket 会话：通过面板监听端口转发到 WS 回显目标
    ws_listener = post("/api/listeners", {"name": "ws", "listen_port": WS_LISTEN_PORT,
                                          "target_host": "127.0.0.1",
                                          "target_port": WS_PORT}, token=TOKEN)
    check("create ws listener via api", ws_listener["listener"]["listen_port"] == WS_LISTEN_PORT)
    _, msg_payloads = ws_session()
    time.sleep(0.8)
    state = json.loads(get("/api/sessions", token=TOKEN))
    ws_sid = state["sessions"][0]["id"]
    ws_sess = state["sessions"][0]
    check("ws session protocol detected", ws_sess["protocol"] == "websocket")
    det = session_detail(ws_sid)
    interps = interp_results(det)
    merged_tx = base64.b64decode(det["payload_b64"]["tx"])
    check("ws handshake visible in tx stream", merged_tx.startswith(b"GET /chat HTTP/1.1\r\n"))
    check("ws tx stream is masked (not plaintext)",
          b"Hello" not in merged_tx and b"WS-TEST" not in merged_tx)
    wsf = interps.get("wsframes", {})
    check("wsframes interpreter engaged for ws session",
          wsf.get("summary", "").startswith("WebSocket：") and
          row_value(wsf, "报文数") is not None)
    print("   wsframes summary:", wsf.get("summary"))
    check("wsframes sees handshake",
          row_value(wsf, "握手首行") == "GET /chat HTTP/1.1")
    check("wsframes assembles masked fragments",
          "装配报文" in wsf.get("text", "") and "未见 FIN" not in wsf.get("summary", ""))
    msgs = json.loads(get("/api/sessions/%s/messages?direction=tx&limit=64" % ws_sid, token=TOKEN))
    check("ws messages endpoint returns list",
          msgs.get("protocol") == "websocket" and
          0 < msgs["messages_total"] <= det["pkts_tx"] * 2 + 1 and
          msgs["returned"] == len(msgs["messages"]))
    kinds = [m["kind"] for m in msgs["messages"]]
    check("ws messages include handshake and data", "handshake" in kinds and "ws-text" in kinds)
    data_msgs = [m for m in msgs["messages"] if m["kind"] == "ws-text"]
    check("ws data messages carry unmasked payloads",
          [base64.b64decode(m["payload_b64"]) for m in data_msgs] == msg_payloads)
    if data_msgs:
        print("   ws message kinds:", kinds, "lens:", [m["len"] for m in msgs["messages"]])
    # 单报文负载：最后一条报文应能单独取到
    one = json.loads(get("/api/sessions/%s/messages?direction=tx&limit=1&offset=%d"
                         % (ws_sid, msgs["messages_total"] - 1), token=TOKEN))
    check("ws single message fetch works",
          len(one["messages"]) == 1 and one["messages"][0]["seq"] == msgs["messages_total"])
    one_det = post("/api/sessions/%s/interpret" % ws_sid, token=TOKEN)["session"]
    check("ws interpret endpoint still works", one_det["id"] == ws_sid and
          "wsframes" in {r["id"] for r in one_det["interpret"]["tx"]})
    # 非法参数应被拒绝（接口契约）
    status, body = request("/api/sessions/%s/messages?direction=xx" % ws_sid, token=TOKEN)
    check("ws messages rejects bad direction", status == 400 and "error" in body)
    status, body = request("/api/sessions/%s/messages?direction=tx&limit=0" % ws_sid, token=TOKEN)
    check("ws messages rejects limit=0", status == 400 and "error" in body)
    # 不能注册与内置解读器冲突的 id
    status, body = request("/api/interpreters", method="POST",
                           obj={"id": "wsframes", "title": "x",
                                "code": "def interpret(p, m): return {}", "enabled": True},
                           token=TOKEN)
    check("builtin interpreter id is reserved", status == 400 and "error" in body)
    # 删除 ws 监听器
    request("/api/listeners/" + ws_listener["listener"]["id"], method="DELETE", token=TOKEN)


    # 2. 注册自定义解读器
    code = (
        "def interpret(payload, meta):\n"
        "    n = len(payload)\n"
        "    first = payload[:32]\n"
        "    return {\"summary\": \"custom n=%d dir=%s\" % (n, meta.get('direction')),\n"
        "            \"rows\": [{\"label\": \"bytes\", \"value\": n},\n"
        "                      {\"label\": \"first8 hex\", \"value\": first[:8].hex()}]}\n"
    )
    res = post("/api/interpreters", {"id": "probe", "title": "Probe", "code": code, "enabled": True}, token=TOKEN)
    check("register custom interpreter", res["interpreter"]["id"] == "probe")

    # 3. 重新解读，自定义解读器应出现在结果中
    det = post("/api/sessions/%s/interpret" % sid, token=TOKEN)["session"]
    custom_tx = [r for r in det["interpret"]["tx"] if r["id"] == "probe"]
    check("custom interpreter runs on payload", bool(custom_tx))
    print("   custom result:", custom_tx[0]["result"].get("summary") if custom_tx else "-")

    # 4. 坏代码注册应失败（request 已捕获 HTTPError，不会抛出）
    status, body = request("/api/interpreters", method="POST",
                           obj={"id": "bad1", "title": "bad", "code": "x = 1"}, token=TOKEN)
    check("bad code rejected", status == 400 and "error" in body)
    print("   reject reason:", body.get("error"))

    # 5. 超时/异常代码不应拖垮面板
    evil = "def interpret(p, m):\n    while True:\n        pass\n"
    res = post("/api/interpreters-test", {"code": evil, "payload_b64": base64.b64encode(b"123").decode()}, token=TOKEN)
    check("timeout guarded", res["result"].get("error") is True)
    print("   timeout msg:", res["result"].get("summary"))

    boom = "def interpret(p, m):\n    raise RuntimeError('boom')\n"
    res = post("/api/interpreters-test", {"code": boom, "payload_b64": base64.b64encode(b"123").decode()}, token=TOKEN)
    check("exception guarded", res["result"].get("error") is True)

    # 6. 启停解读器
    post("/api/interpreters/json/toggle", {"enabled": False}, token=TOKEN)
    state = json.loads(get("/api/state", token=TOKEN))
    json_off = [i for i in state["interpreters"] if i["id"] == "json"][0]
    check("disable interpreter", json_off["enabled"] is False)
    post("/api/interpreters/json/toggle", {"enabled": True}, token=TOKEN)

    # 7. 删除自定义解读器
    request("/api/interpreters/probe", method="DELETE", token=TOKEN)
    state = json.loads(get("/api/state", token=TOKEN))
    check("delete custom interpreter", "probe" not in [i["id"] for i in state["interpreters"]])

    # 8. 导出 JSON（含负载与解读）
    data = json.loads(get("/api/export?format=json", token=TOKEN))
    check("json export has sessions", len(data["sessions"]) >= 1)
    check("json export has payloads",
          any(base64.b64decode(v["payload_b64"]["tx"]) for v in data["sessions"].values()))

    # 9. 导出 CSV（外部工具依赖的 14 列契约不变）
    csv_body = get("/api/export?format=csv", token=TOKEN).decode("utf-8-sig")
    check("csv export header unchanged (14 columns)",
          csv_body.splitlines()[0] == "session_id,listener,listen_port,client,target,"
          "state,bytes_tx,bytes_rx,pkts_tx,pkts_rx,started_at,ended_at,duration_s,error")
    print("   csv rows:", len(csv_body.strip().splitlines()) - 1)

    # 10. 原始负载下载（用上面 HTTP 报文会话）
    raw = get("/api/sessions/%s/payload?direction=tx&encoding=bin" % http_sid, token=TOKEN)
    check("raw payload download", raw.startswith(b"GET /api/v1/metrics HTTP/1.1"))

    # 11. 监听器经 API 增删
    res = post("/api/listeners", {"name": "tmp", "listen_port": 18082,
                                  "target_host": "127.0.0.1", "target_port": TARGET_PORT}, token=TOKEN)
    check("create listener via API", res["listener"]["listen_port"] == 18082)
    request("/api/listeners/" + res["listener"]["id"], method="DELETE", token=TOKEN)
    state = json.loads(get("/api/state", token=TOKEN))
    check("delete listener", all(l["listen_port"] != 18082 for l in state["listeners"]))

    # 12. 事件流与面板首页
    ev = json.loads(get("/api/events?since=0", token=TOKEN))["events"]
    check("event feed populated", len(ev) >= 3)
    check("panel page served", b"SocketMeasure" in idx and b"rateChart" in idx)

    # 13. 调用日志应记录外部调用
    calls = json.loads(get("/api/apicalls?since=0", token=TOKEN))["calls"]
    check("api call log records external calls", len(calls) >= 5)
    anon = [c for c in calls if c["token_title"] == "未认证"]  # 未认证
    check("failed auth attempts logged", bool(anon) and anon[-1]["status"] == 401)
    if calls:
        c = calls[-1]
        print("   last call: %s %s -> %s (%.1f ms)" % (c["method"], c["path"], c["status"], c["duration_ms"]))

    # 14. 重置基线：清空会话
    reset = post("/api/reset", {}, token=TOKEN)
    check("reset clears sessions", reset["reset"]["sessions_removed"] >= 1)
    state = json.loads(get("/api/state", token=TOKEN))
    check("sessions empty after reset", state["totals"]["sessions"] == 0)

    # 15. 删除令牌后调用应失败
    tokens = request("/api/tokens", token=panel_token)[1]["tokens"]
    for t in tokens:
        if t["title"] == "e2e":
            request("/api/tokens/%s" % t["id"], method="DELETE", token=panel_token)
    status, body = request("/api/health", token=TOKEN)
    check("deleted token rejected", status == 401)

    print()
    print("RESULT:", "ALL PASS" if ok else "SOME FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
