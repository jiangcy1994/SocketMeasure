"""解读器注册表：内置解读器 + 运行时热注册的自定义解读器。

解读器协议：
    interpret(payload: bytes, meta: dict) -> result

result 可是：
  - str                        —— 等价于 {"text": result}
  - dict，建议字段（均为可选）：
      summary: str             —— 一行摘要
      text: str                —— 等宽文本块
      rows: [{label, value}]   —— 键值表
      list: [str | dict]       —— 条目列表
  - 其他 JSON 可序列化值       —— 原样展示

自定义解读器通过 Web 面板提交源码（定义 interpret 函数）即时注册，
代码与配置仅保存在内存中，不写入磁盘。
"""

from __future__ import annotations

import json
import threading
import time

CUSTOM_TIMEOUT = 5.0     # 自定义解读器执行超时（秒），防止卡死面板


def _hexdump(payload: bytes, limit: int = 1024) -> str:
    lines = []
    shown = min(len(payload), limit)
    for i in range(0, shown, 16):
        chunk = payload[i:i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hexs:<48}  {asc}")
    if len(payload) > limit:
        lines.append(f"… 共 {len(payload)} 字节，仅显示前 {limit} 字节")
    return "\n".join(lines)


def _ascii_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return printable / len(text)


# ---------------- 内置解读器 ----------------

def _interp_hexdump(payload: bytes, meta: dict):
    if not payload:
        return {"summary": "无负载数据"}
    return {
        "summary": f"{len(payload)} 字节（页面显示前 1024 字节）",
        "text": _hexdump(payload),
    }


def _interp_text(payload: bytes, meta: dict):
    if not payload:
        return {"summary": "无负载数据"}
    try:
        text = payload.decode("utf-8")
        enc = "UTF-8"
    except UnicodeDecodeError:
        text = payload.decode("latin-1", errors="replace")
        enc = "非 UTF-8，按 latin-1 容错解码"
    sample = text[:4000]
    ratio = _ascii_ratio(sample)
    return {
        "summary": f"{len(payload)} 字节，编码 {enc}，可打印率 {ratio:.0%}",
        "rows": [
            {"label": "字节数", "value": len(payload)},
            {"label": "编码", "value": enc},
            {"label": "可打印率", "value": f"{ratio:.0%}"},
        ],
        "text": sample + ("…" if len(text) > len(sample) else ""),
    }


def _interp_http(payload: bytes, meta: dict):
    if not payload:
        return {"summary": "无负载数据"}
    head = payload[:8192]
    try:
        text = head.decode("latin-1")
    except Exception:
        return {"summary": "无法解码"}
    first_line = text.split("\r\n", 1)[0] if "\r\n" in text else text[:64]
    if not (first_line.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
                                    "OPTIONS ", "PATCH ", "TRACE ", "CONNECT "))
            or first_line.startswith("HTTP/")):
        return {"summary": "非 HTTP 流量（首行：%r）" % first_line[:80]}
    parts = text.split("\r\n\r\n", 1)
    header_block = parts[0]
    lines = header_block.split("\r\n")
    body_hint = ""
    if len(parts) > 1:
        body_hint = f"，报文头后另有 {len(payload) - len(header_block) - 4} 字节体"
    rows = [{"label": "首行", "value": first_line}]
    for line in lines[1:]:
        if ":" in line:
            name, _, value = line.partition(":")
            rows.append({"label": name.strip(), "value": value.strip()})
        elif line:
            rows.append({"label": "", "value": line})
    return {
        "summary": f"HTTP 报文：{first_line[:60]}{body_hint}",
        "rows": rows[:60],
    }


def _interp_json(payload: bytes, meta: dict):
    if not payload:
        return {"summary": "无负载数据"}
    try:
        text = payload.decode("utf-8").strip()
    except UnicodeDecodeError:
        return {"summary": "非 UTF-8，无法按 JSON 解读"}
    if not (text.startswith("{") or text.startswith("[")):
        return {"summary": "负载不是 JSON 对象或数组"}
    try:
        obj = json.loads(text)
    except ValueError as e:
        return {"summary": f"JSON 解析失败：{e}"}
    return {
        "summary": "有效 JSON，已格式化",
        "text": json.dumps(obj, ensure_ascii=False, indent=2)[:8000],
    }


def _interp_stats(payload: bytes, meta: dict):
    b = meta.get("bytes", {})
    p = meta.get("pkts", {})
    dur = meta.get("duration_s") or 0.0
    rows = [
        {"label": "方向", "value": "客户端→目标（tx）" if meta.get("direction") == "tx"
                                  else "目标→客户端（rx）"},
        {"label": "本方向字节", "value": b.get(meta.get("direction"), 0)},
        {"label": "本方向报文", "value": p.get(meta.get("direction"), 0)},
        {"label": "已捕获样本", "value": meta.get("captured", {}).get(meta.get("direction"), 0)},
    ]
    avg = 0.0
    pkts = p.get(meta.get("direction"), 0)
    if pkts:
        avg = b.get(meta.get("direction"), 0) / pkts
        rows.append({"label": "平均报文长", "value": f"{avg:.1f} B"})
    if dur > 0:
        rows.append({"label": "会话时长", "value": f"{dur:.2f} s"})
        rows.append({"label": "本方向吞吐", "value": f"{b.get(meta.get('direction'), 0) / dur / 1024:.2f} KiB/s"})
    if meta.get("truncated", {}).get(meta.get("direction")):
        rows.append({"label": "样本截断", "value": "已达捕获上限"})
    return {
        "summary": f"tx {b.get('tx', 0)} B / rx {b.get('rx', 0)} B，"
                   f"tx {p.get('tx', 0)} 包 / rx {p.get('rx', 0)} 包",
        "rows": rows,
    }


BUILTIN_SPECS = [
    ("stats", "统计", _interp_stats, "报文/字节/吞吐统计（不依赖负载内容）"),
    ("hexdump", "Hex 转储", _interp_hexdump, "十六进制 + ASCII 转储"),
    ("text", "文本解码", _interp_text, "UTF-8/latin-1 文本解码与可打印率"),
    ("http", "HTTP 解析", _interp_http, "识别并解析 HTTP 请求/响应头"),
    ("json", "JSON 解析", _interp_json, "识别并格式化 JSON 负载"),
]


# ---------------- 注册表 ----------------

class Interpreter:
    def __init__(self, interp_id, title, run, kind="builtin",
                 description="", enabled=True, code=None):
        self.id = interp_id
        self.title = title
        self.run = run
        self.kind = kind                  # builtin | custom
        self.description = description
        self.enabled = enabled
        self.code = code
        self.registered_at = time.time()

    def info(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "kind": self.kind,
            "description": self.description,
            "enabled": self.enabled,
            "has_code": self.code is not None,
            "registered_at": self.registered_at,
        }


def _run_guarded(run, payload, meta, timeout=None):
    """执行解读器，捕获异常与超时，确保一个坏解读器不会拖垮系统。"""
    if timeout is None:
        try:
            return run(payload, meta)
        except Exception as e:
            return {"summary": f"解读器异常: {e!r}", "error": True}
    box = {}

    def target():
        try:
            box["result"] = run(payload, meta)
        except BaseException as e:            # noqa: BLE001 —— 隔离用户代码
            box["error"] = e

    t = threading.Thread(target=target, daemon=True,
                         name=f"interp-{getattr(run, '__name__', 'custom')}")
    t.start()
    t.join(timeout)
    if t.is_alive():
        return {"summary": f"解读器执行超时（{timeout:g}s），已放弃", "error": True}
    if "error" in box:
        return {"summary": f"解读器异常: {box['error']!r}", "error": True}
    return box.get("result")


class Registry:
    def __init__(self):
        self._lock = threading.RLock()
        self._items = {}
        for interp_id, title, run, desc in BUILTIN_SPECS:
            self._items[interp_id] = Interpreter(
                interp_id, title,
                (lambda p, m, _r=run: _run_guarded(_r, p, m)),
                "builtin", desc)

    def info(self) -> list:
        with self._lock:
            return [i.info() for i in self._items.values()]

    def get(self, interp_id) -> Interpreter | None:
        with self._lock:
            return self._items.get(interp_id)

    def set_enabled(self, interp_id, enabled: bool) -> None:
        with self._lock:
            interp = self._items.get(interp_id)
            if interp is None:
                raise KeyError(interp_id)
            interp.enabled = bool(enabled)

    def remove(self, interp_id) -> None:
        with self._lock:
            interp = self._items.get(interp_id)
            if interp is None:
                raise KeyError(interp_id)
            if interp.kind == "builtin":
                raise ValueError("内置解读器不可删除，可停用")
            del self._items[interp_id]

    def _compile(self, code: str):
        if not isinstance(code, str) or not code.strip():
            raise ValueError("代码不能为空")
        ns = {}
        exec(compile(code, "<custom-interpreter>", "exec"), ns)
        run = ns.get("interpret")
        if not callable(run):
            raise ValueError("代码中必须定义函数 interpret(payload: bytes, meta: dict)")
        return run

    def register_custom(self, interp_id: str, title: str, code: str,
                        enabled: bool = True) -> Interpreter:
        run = self._compile(code)
        with self._lock:
            if not interp_id:
                raise ValueError("id 不能为空")
            if interp_id in self._items and self._items[interp_id].kind == "builtin":
                raise ValueError(f"id '{interp_id}' 与内置解读器冲突")
            interp = Interpreter(interp_id, title,
                                 (lambda p, m, _r=run: _run_guarded(_r, p, m, CUSTOM_TIMEOUT)),
                                 "custom", "面板注册的自定义解读器", enabled, code)
            self._items[interp_id] = interp
            return interp

    def test_code(self, code: str, payload: bytes, meta: dict) -> dict:
        """编译并立即试运行一段解读器代码（不注册）。"""
        run = self._compile(code)
        result = _run_guarded(run, payload, meta, CUSTOM_TIMEOUT)
        return {"result": result, "payload_bytes": len(payload)}

    def run(self, payload: bytes, meta: dict) -> list:
        """对一段负载运行所有已启用的解读器。"""
        out = []
        with self._lock:
            items = list(self._items.values())
        for interp in items:
            if not interp.enabled:
                continue
            try:
                result = interp.run(payload, meta)
            except Exception as e:            # 双保险
                result = {"summary": f"解读器异常: {e!r}", "error": True}
            out.append({
                "id": interp.id,
                "title": interp.title,
                "kind": interp.kind,
                "result": result if isinstance(result, (str, dict, list, int, float, bool)) or result is None
                          else str(result),
            })
        return out
