"""端到端测试：流量 -> 计数 -> 解读器 -> 导出。

用法：
    1. 启动回显目标与面板（本脚本会自建回显目标，只需面板在运行）：
         uv run python -m socketmeasure --port 8099 --forward echo:18080:127.0.0.1:18081
    2. 另开终端运行：
         uv run python tests/e2e_test.py

输出为纯 ASCII，避免 Windows 控制台编码干扰。
"""

import base64
import json
import socket
import threading
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8099"
TARGET_PORT = 18081
ok = True


def post(path, obj=None):
    req = urllib.request.Request(BASE + path, method="POST",
                                 data=json.dumps(obj or {}).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode("utf-8"))


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=15) as r:
        return r.read()


def check(name, cond):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


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


def main():
    start_echo_target()

    # 1. 造流量
    payloads = [b"GET /metrics HTTP/1.1\r\nHost: t\r\n\r\n", b'{"type":"sensor","v":1}']
    s = socket.create_connection(("127.0.0.1", 18080), timeout=5)
    for p in payloads:
        s.sendall(p)
        time.sleep(0.3)
    s.close()
    time.sleep(0.8)
    expected_tx = sum(len(p) for p in payloads)

    state = json.loads(get("/api/state"))
    sid = state["sessions"][0]["id"]
    sess = state["sessions"][0]
    print("counts: tx=%d rx=%d pkts_tx=%d pkts_rx=%d state=%s"
          % (sess["bytes_tx"], sess["bytes_rx"], sess["pkts_tx"], sess["pkts_rx"], sess["state"]))
    check("session counted both directions", sess["bytes_tx"] == expected_tx and sess["bytes_rx"] > 0)
    check("session closed cleanly", sess["state"] == "closed")

    # 2. 注册自定义解读器
    code = (
        "def interpret(payload, meta):\n"
        "    n = len(payload)\n"
        "    first = payload[:32]\n"
        "    return {\"summary\": \"custom n=%d dir=%s\" % (n, meta.get('direction')),\n"
        "            \"rows\": [{\"label\": \"bytes\", \"value\": n},\n"
        "                      {\"label\": \"first8 hex\", \"value\": first[:8].hex()}]}\n"
    )
    res = post("/api/interpreters", {"id": "probe", "title": "Probe", "code": code, "enabled": True})
    check("register custom interpreter", res["interpreter"]["id"] == "probe")

    # 3. 重新解读，自定义解读器应出现在结果中
    det = post("/api/sessions/%s/interpret" % sid)["session"]
    custom_tx = [r for r in det["interpret"]["tx"] if r["id"] == "probe"]
    check("custom interpreter runs on payload", bool(custom_tx))
    print("   custom result:", custom_tx[0]["result"].get("summary") if custom_tx else "-")

    # 4. 坏代码注册应失败
    try:
        post("/api/interpreters", {"id": "bad1", "title": "bad", "code": "x = 1"})
        check("bad code rejected", False)
    except urllib.error.HTTPError as e:
        check("bad code rejected", e.code == 400)

    # 5. 超时/异常代码不应拖垮面板
    evil = "def interpret(p, m):\n    while True:\n        pass\n"
    res = post("/api/interpreters-test", {"code": evil, "payload_b64": base64.b64encode(b"123").decode()})
    check("timeout guarded", res["result"].get("error") is True)
    print("   timeout msg:", res["result"].get("summary"))

    boom = "def interpret(p, m):\n    raise RuntimeError('boom')\n"
    res = post("/api/interpreters-test", {"code": boom, "payload_b64": base64.b64encode(b"123").decode()})
    check("exception guarded", res["result"].get("error") is True)

    # 6. 启停解读器
    post("/api/interpreters/json/toggle", {"enabled": False})
    state = json.loads(get("/api/state"))
    json_off = [i for i in state["interpreters"] if i["id"] == "json"][0]
    check("disable interpreter", json_off["enabled"] is False)
    post("/api/interpreters/json/toggle", {"enabled": True})

    # 7. 删除自定义解读器
    req = urllib.request.Request(BASE + "/api/interpreters/probe", method="DELETE")
    with urllib.request.urlopen(req, timeout=15):
        pass
    state = json.loads(get("/api/state"))
    check("delete custom interpreter", "probe" not in [i["id"] for i in state["interpreters"]])

    # 8. 导出 JSON（含负载与解读）
    data = json.loads(get("/api/export?format=json"))
    check("json export has sessions", len(data["sessions"]) >= 1)
    check("json export has payloads",
          any(base64.b64decode(v["payload_b64"]["tx"]) for v in data["sessions"].values()))

    # 9. 导出 CSV
    csv_body = get("/api/export?format=csv").decode("utf-8-sig")
    check("csv export header", csv_body.splitlines()[0].startswith("session_id,listener"))
    print("   csv rows:", len(csv_body.strip().splitlines()) - 1)

    # 10. 原始负载下载
    raw = get("/api/sessions/%s/payload?direction=tx&encoding=bin" % sid)
    check("raw payload download", raw.startswith(b"GET /metrics HTTP/1.1"))

    # 11. 监听器经 API 增删
    res = post("/api/listeners", {"name": "tmp", "listen_port": 18082,
                                  "target_host": "127.0.0.1", "target_port": TARGET_PORT})
    check("create listener via API", res["listener"]["listen_port"] == 18082)
    req = urllib.request.Request(BASE + "/api/listeners/" + res["listener"]["id"], method="DELETE")
    with urllib.request.urlopen(req, timeout=15):
        pass
    state = json.loads(get("/api/state"))
    check("delete listener", all(l["listen_port"] != 18082 for l in state["listeners"]))

    # 12. 事件流与面板首页
    ev = json.loads(get("/api/events?since=0"))["events"]
    check("event feed populated", len(ev) >= 3)
    idx = get("/")
    check("panel page served", b"SocketMeasure" in idx and b"rateChart" in idx)

    print()
    print("RESULT:", "ALL PASS" if ok else "SOME FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
