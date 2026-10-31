# SocketMeasure HTTP API 调用文档

SocketMeasure 面板内置一组 REST 接口，供其他 socket 流量测试工具以编程方式
获取计量数据、管理监听器与解读器、导出会话负载。所有接口均在内存中处理，
不产生磁盘文件。

- Base URL：`http://<panel_host>:<panel_port>`，默认 `http://127.0.0.1:8080`
- 数据格式：`application/json; charset=utf-8`（除导出/下载类接口）
- **所有 `/api/*` 接口均需令牌鉴权**

## 1. 鉴权

### 获取令牌

令牌在面板「令牌与调用」页生成：

1. 浏览器打开面板首页（如 <http://127.0.0.1:8099>）。
2. 进入「令牌与调用」页签，在「生成新令牌」中填写名称（如 `my-tester`），
   点击「＋ 生成令牌」。
3. 复制生成的令牌值，形如 `sm_3f9c...`（`sm_` 前缀 + 48 位十六进制）。

令牌有两类：

| 类型 | 说明 |
| --- | --- |
| `user` | 面板手动创建，分发给外部测试工具，可启用/停用/删除 |
| `panel` | 面板内置令牌，随管理页面注入浏览器，仅用于面板自身与令牌管理接口，不可删除/停用 |

> 对外部工具**只需使用 `user` 令牌**。`/api/tokens*` 管理接口仅限 `panel`
> 令牌调用，`user` 令牌调用会得到 401。

### 传递令牌（任选其一）

| 方式 | 示例 |
| --- | --- |
| Authorization 头 | `Authorization: Bearer sm_xxxxxxxx` |
| 自定义头 | `X-API-Token: sm_xxxxxxxx` |
| 查询参数 | `GET /api/state?token=sm_xxxxxxxx` |

### 鉴权失败

```json
HTTP/1.1 401 Unauthorized
{"error": "缺少 token：请使用 Authorization: Bearer <token>、X-API-Token 头或 ?token= 查询参数（令牌在面板「令牌与调用」页生成）"}
```

常见 401 原因：未带令牌、令牌拼错、令牌已被停用或删除。

### 调用记录

所有使用 `user` 令牌（以及未认证）的 `/api/*` 调用都会被记录，并展示在
面板「令牌与调用」页的「调用日志」中，包含：时间、令牌、方法、路径、
状态码与耗时（内存中最近 500 条）。面板内置令牌的调用不记录，因此面板
自身的轮询不会刷屏。

## 2. 接口总览

| 方法 | 路径 | 说明 | 需令牌 |
| --- | --- | --- | --- |
| GET | `/api/health` | 健康检查（验证令牌最便宜的方式） | 是 |
| GET | `/api/state` | 全量状态：汇总、监听器、会话、解读器、速率序列 | 是 |
| GET | `/api/events?since=N` | 事件流（`N` 为已收到的最大 seq） | 是 |
| GET | `/api/apicalls?since=N` | 调用日志（`N` 为已收到的最大 seq） | 是 |
| GET | `/api/sessions` | 会话列表（摘要，新会话在前） | 是 |
| GET | `/api/sessions/{id}` | 会话详情：base64 负载 + 各解读器结果 | 是 |
| POST | `/api/sessions/{id}/interpret` | 清除解读缓存并重新解读 | 是 |
| GET | `/api/sessions/{id}/payload?direction=tx&encoding=bin\|hex\|text` | 下载原始负载 | 是 |
| GET | `/api/listeners` | 监听器列表 | 是 |
| POST | `/api/listeners` | 新建转发监听器（**测试中可动态开端口**） | 是 |
| DELETE | `/api/listeners/{id}` | 移除监听器 | 是 |
| GET | `/api/interpreters` | 解读器列表 | 是 |
| POST | `/api/interpreters` | 注册自定义解读器 | 是 |
| POST | `/api/interpreters/{id}/toggle` | 启用/停用解读器 | 是 |
| GET | `/api/interpreters/{id}/code` | 获取自定义解读器源码 | 是 |
| DELETE | `/api/interpreters/{id}` | 删除自定义解读器 | 是 |
| POST | `/api/interpreters-test` | 试运行解读器代码（不注册） | 是 |
| GET | `/api/export?format=json\|csv` | 导出全部会话 | 是 |
| POST | `/api/reset` | 重置基线（清会话/监听器/事件） | 是 |
| GET | `/api/tokens` | 令牌列表 | 仅 panel 令牌 |
| POST | `/api/tokens` | 创建令牌（`{"title": "..."}`） | 仅 panel 令牌 |
| POST | `/api/tokens/{id}/toggle` | 启用/停用令牌 | 仅 panel 令牌 |
| DELETE | `/api/tokens/{id}` | 删除令牌 | 仅 panel 令牌 |

## 3. 典型调用流程（外部测试工具）

一个典型的 socket 流量测试工具这样使用：

1. `GET /api/health` —— 验证令牌与面板可达。
2. `POST /api/listeners` —— 按测试需要动态开一个转发监听器
   （或在启动面板时用 `--forward` 固定配置）。
3. 让被测客户端连接该监听端口，收发数据。
4. `GET /api/state` 或 `GET /api/sessions` —— 轮询/读取计量结果。
5. `GET /api/sessions/{id}` —— 拿负载样本与解读结果。
6. `GET /api/sessions/{id}/payload?...` 或 `/api/export` —— 下载原始数据。
7. `POST /api/reset` —— 清理基线，开始下一轮测试。

### curl 示例

```bash
TOKEN="sm_xxxxxxxx"
BASE="http://127.0.0.1:8099"

# 健康检查
curl -s "$BASE/api/health" -H "X-API-Token: $TOKEN"

# 动态新建转发监听器：监听 19090 -> 127.0.0.1:18888
curl -s -X POST "$BASE/api/listeners" -H "X-API-Token: $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name": "probe", "listen_port": 19090, "target_host": "127.0.0.1", "target_port": 18888}'

# 会话列表
curl -s "$BASE/api/sessions?token=$TOKEN"

# 会话详情（含 base64 负载与解读结果）
curl -s "$BASE/api/sessions/abc123def456" -H "Authorization: Bearer $TOKEN"

# 下载 tx 方向原始负载（bin/hex/text）
curl -sO "$BASE/api/sessions/abc123def456/payload?direction=tx&encoding=bin&token=$TOKEN"

# 导出全部会话为 CSV（带 UTF-8 BOM，Excel 友好）
curl -sO "$BASE/api/export?format=csv&token=$TOKEN"

# 重置基线：仅清空会话（listeners/events 默认 false）
curl -s -X POST "$BASE/api/reset" -H "X-API-Token: $TOKEN" -d '{}'
```

### Python 示例（标准库）

```python
import base64
import json
import urllib.request

BASE = "http://127.0.0.1:8099"
TOKEN = "sm_xxxxxxxx"          # 面板「令牌与调用」页生成

def api(path, method="GET", obj=None):
    data = json.dumps(obj).encode() if obj is not None else None
    req = urllib.request.Request(BASE + path, method=method, data=data,
                                 headers={"X-API-Token": TOKEN,
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())

# 1) 健康检查
print(api("/api/health"))

# 2) 开一个转发监听器
listener = api("/api/listeners", "POST", {
    "name": "probe", "listen_port": 19090,
    "target_host": "127.0.0.1", "target_port": 18888,
})["listener"]

# 3) ...被测客户端向 19090 收发数据...

# 4) 读取计量结果
state = api("/api/state")
print(state["totals"])

# 5) 会话详情：用 stats/text/hexdump/json/http 解读器解析负载数据
for s in api("/api/sessions")["sessions"]:
    det = api("/api/sessions/%s" % s["id"])["session"]
    payload = base64.b64decode(det["payload_b64"]["tx"])
    for r in det["interpret"]["tx"]:
        print(r["id"], r["result"].get("summary"))

# 6) 重置基线
api("/api/reset", "POST", {"sessions": True})
```

## 4. 接口详情

### GET /api/health

健康检查，也是验证令牌是否有效的最便宜方式。

```json
{
  "ok": true,
  "service": "socketmeasure",
  "version": "0.1.0",
  "token_title": "my-tester",
  "now": 1761900000.0
}
```

### GET /api/state

面板全量状态。`totals` 含会话数、开连接数、双向字节数与包数、当前速率；
`sessions` 为会话摘要数组（新会话在前）；`series` 为最近 120 秒速率序列；
`interpreters` 为已注册解读器信息。建议轮询间隔 ≥ 1 秒。

### GET /api/events?since=N

事件流，`N` 为上次收到的最大 `seq`，返回所有 `seq > N` 的事件
（含监听器启停、会话异常、令牌变更、解读器注册等）。

### GET /api/apicalls?since=N

调用日志，`N` 为上次收到的最大 `seq`。元素字段：

```json
{
  "seq": 12, "ts": 1761900000.0,
  "token_title": "my-tester", "method": "GET", "path": "/api/state",
  "status": 200, "client": "127.0.0.1:54321", "duration_ms": 3.2
}
```

未认证的调用以 `token_title: "未认证"` 记录（含其状态码，通常是 401）。

### GET /api/sessions

会话摘要数组，新会话在前。摘要字段：`id`、`listener_name`、`listen_port`、
`client`、`target`、`state`（`open`/`closed`/`failed`）、`bytes_tx`、`bytes_rx`、
`pkts_tx`、`pkts_rx`、`rate_tx_bps`、`rate_rx_bps`、`duration_s`、`captured_*`、
`truncated`。

方向约定：`tx` = 客户端 → 目标（上行），`rx` = 目标 → 客户端（下行）。

### GET /api/sessions/{id}

会话详情，包对象在 `session` 键下：

```json
{
  "session": {
    "id": "abc123def456",
    "...同会话摘要字段...",
    "payload_b64": {"tx": "aGVsbG8...", "rx": ""},
    "payload_version": {"tx": 2, "rx": 0},
    "capture_limit": 1048576,
    "interpret": {
      "tx": [
        {"id": "stats", "title": "统计", "result": {"summary": "tx 30 B / rx 36 B（tx 1 包 / rx 1 包）", "rows": [...]}},
        {"id": "text",  "title": "文本", "result": {"summary": "30 字节，编码 UTF-8，可打印率 100%", "text": "hello..."}}
      ],
      "rx": [...]
    }
  }
}
```

解读结果按负载版本缓存；修改解读器后想立即重算，调用
`POST /api/sessions/{id}/interpret`。

`interpret` 中的 `result` 形状由解读器决定，可能包含 `summary`（一行摘要）、
`text`（大段文本）、`rows`（`[{label, value}]` 键值表）、`error`（执行失败标记）。

### GET /api/sessions/{id}/payload

下载该方向原始负载样本（每方向最多 `capture_limit` 字节，超出截断）。

| 参数 | 值 | 说明 |
| --- | --- | --- |
| `direction` | `tx`（默认）/ `rx` | 方向 |
| `encoding` | `bin`（默认）/ `hex` / `text` | bin=原始字节，hex=十六进制文本，text=UTF-8 容错解码 |

响应带 `Content-Disposition: attachment`，文件名形如
`session-abc123def456-tx-20260101-120000.bin`。

### POST /api/listeners

动态新建转发监听器（适合需要按测试用例动态分配端口的工具）。

```json
// 请求
{"name": "probe", "listen_port": 19090, "target_host": "127.0.0.1", "target_port": 18888}
// 响应
{"listener": {"id": "...", "name": "probe", "listen_port": 19090,
              "target": "127.0.0.1:18888", "state": "listening", ...}}
```

监听端口冲突会返回 400。测试结束记得 `DELETE /api/listeners/{id}` 释放端口。

### POST /api/interpreters

注册自定义解读器（协议：`def interpret(payload: bytes, meta: dict) -> str | dict`）。
注册时代码会被编译，必须定义 `interpret` 函数，否则 400。运行时异常被捕获，
死循环有 5 秒超时保护，不会拖垮面板。

```json
{"id": "probe", "title": "Probe", "enabled": true,
 "code": "def interpret(payload, meta):\n    return {\"summary\": \"n=%d\" % len(payload)}"}
```

### POST /api/interpreters-test

试运行解读器代码（不注册），用于上线前验证：

```json
// 请求：直接给负载
{"code": "def interpret(p, m): return {\"summary\": str(len(p))}",
 "payload_b64": "MTIz"}
// 或引用某个会话的负载
{"code": "...", "session_id": "abc123def456", "direction": "tx"}
// 响应
{"result": {"summary": "3"}, "payload_bytes": 3}
```

### GET /api/export

| 参数 | 值 | 说明 |
| --- | --- | --- |
| `format` | `json`（默认）/ `csv` | json 含负载与解读结果；csv 为会话明细表（UTF-8 BOM） |
| `scope` | `sessions` | 仅 json：只导出会话 |

### POST /api/reset

重置基线，供外部测试建立干净环境。请求体均为可选布尔：

```json
{"sessions": true, "listeners": false, "events": false}
```

- `sessions`（默认 true）：清空全部会话与速率序列，返回 `sessions_removed`
- `listeners`（默认 false）：摘除并停止全部监听器，返回 `listeners_removed`
- `events`（默认 false）：清空事件流，返回 `events_removed`

注意：进行中的连接其会话对象仍被转发线程持有，计数会继续写入那些已脱离
面板视图的对象，不再出现在统计中。

### /api/tokens（仅 panel 令牌）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/tokens` | 令牌列表（含 `value`、`use_count`、`last_used_at`） |
| POST | `/api/tokens` | `{"title": "名称"}` 创建令牌，响应含完整 `value` |
| POST | `/api/tokens/{id}/toggle` | `{"enabled": true\|false}`，panel 令牌不可停用（400） |
| DELETE | `/api/tokens/{id}` | 删除令牌，panel 令牌不可删（400），不存在返回 404 |

`user` 令牌调用这些接口会得到 401（`令牌管理接口仅限面板内置令牌调用`）。

## 5. 错误码

| 状态码 | 含义 |
| --- | --- |
| 200 | 成功（导出/下载类通过 `Content-Disposition` 返回文件） |
| 400 | 参数非法：端口冲突、解读器代码无 `interpret` 函数、删除内置解读器等 |
| 401 | 未带令牌 / 令牌无效 / 已停用 / 已删除；或 `user` 令牌调用了令牌管理接口 |
| 404 | 资源不存在（会话/监听器/解读器/令牌 id 有误） |
| 405 | 方法不支持（如对 `/api/sessions/{id}` 发 POST 以外的非法操作） |
| 500 | 服务器内部错误（已记录日志，面板仍可用） |

错误响应体：

```json
{"error": "缺少 token：请使用 Authorization: Bearer <token>、X-API-Token 头或 ?token= 查询参数（令牌在面板「令牌与调用」页生成）"}
```

## 6. 安全与约束

- 令牌值只在内存中，面板进程退出即全部失效，需重新生成。
- 面板默认绑定 `127.0.0.1`；不要用 `--host 0.0.0.0` 暴露到不可信网络。
- 令牌相当于完全的 API 访问权限，请勿嵌入公开仓库或日志。
- 自定义解读器以当前进程权限执行，只用于自己编写的调试脚本。
- 每方向负载样本捕获上限 1 MiB（`--capture-limit` 可调），字节数总计数不受限；
  已关闭会话保留 200 条、事件流 500 条、调用日志 500 条、速率序列 120 秒。
