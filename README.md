# SocketMeasure

测量 TCP 端口收发信息的工具：可动态扩展解读规则、数据只存内存、通过 Web
管理面板查看与下载。纯 Python 标准库实现，零第三方依赖。

## 工作原理

以「透明转发」方式工作：在本机监听一个端口，把流量转发到目标地址，在
转发过程中完成计量。相比抓包方式不需要 Npcap 驱动和管理员权限。

```
客户端  --tx-->  监听端口  -->  目标 host:port
客户端  <--rx--  监听端口  <--  目标 host:port
```

方向约定：`tx` = 客户端 → 目标（上行），`rx` = 目标 → 客户端（下行）。

## 快速开始

使用环境中的 [uv](https://docs.astral.sh/uv/) 运行：

```bash
# 启动面板，并建立一个转发：名称 echo，监听 18080，转发到 127.0.0.1:18081
uv run python -m socketmeasure --port 8099 --forward echo:18080:127.0.0.1:18081
```

然后浏览器打开 <http://127.0.0.1:8099>。

### 命令行参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--host` | `127.0.0.1` | 面板绑定地址 |
| `--port` | `8080` | 面板端口 |
| `--forward NAME:LISTEN_PORT:TARGET_HOST:TARGET_PORT` | — | 转发监听器，可重复 |
| `--capture-limit` | `1048576` | 每个方向捕获的负载字节数上限 |
| `--log-level` | `INFO` | 日志级别 |

## 内存约束（不落盘）

所有数据只存在于进程内存中，程序退出即消失，没有任何磁盘写入：

| 项目 | 上限 |
| --- | --- |
| 每方向捕获负载样本 | 1 MiB（字节总计数不受限，仅样本截断） |
| 保留的已关闭会话数 | 200 |
| 事件流条数 | 500 |
| 速率序列 | 120 秒 |
| 外部 API 调用日志 | 500 |

导出（JSON / CSV / 原始负载）在请求时即时生成，通过 `Content-Disposition`
触发浏览器下载，不生成临时文件。

## 解读器（可动态扩展）

解读器是一个符合如下协议的 Python 函数：

```python
def interpret(payload: bytes, meta: dict) -> str | dict:
    ...
```

- `payload`：该方向的完整负载样本（可能被截断，见 `meta["truncated"]`）
- `meta`：包含 `direction`、`listen_port`、`client`、`target`、`bytes`、
  `pkts`、`captured`、`truncated`、`started_at`、`duration_s` 等
- 返回值：字符串，或字典（可含 `summary`、`text`、`rows`（键值表）、
  `list`（多块文本）键，面板会相应渲染）

内置解读器：`stats`（统计）、`hexdump`（十六进制转储）、`text`（文本）、
`http`（HTTP 请求解析）、`json`（JSON 美化）。

自定义解读器可在面板「解读器」页在线编辑、注册、试运行（`/api/interpreters-test`
支持给定负载或直接引用某个会话的负载），启用/停用、删除。注册时代码会被
执行，运行时异常会被捕获、死循环会有 5 秒超时保护，不会拖垮面板。

## 负载解析模式（会话详情页，浏览器端）

会话详情的负载区默认展示 **Raw（十六进制转储）**，可在下拉框切换多种解析模式
尝试解析当前方向的负载：

| 模式 | 说明 |
| --- | --- |
| Raw | 十六进制转储（默认；解析失败时自动回退到此模式） |
| 文本（仅 ASCII） | 全部字节均可打印时才成功 |
| 文本（UTF-8） | 严格 UTF-8 解码 |
| JSON | 解析并美化展示（自动去除 BOM） |
| HTTP 报文 | 解析请求行/状态行 + 头部表 + 消息体预览 |
| URL 表单编码 | 解析 `键=值&键=值`（自动 URL 解码） |
| Base64 文本解码 | 解码后按可打印比例展示文本或 Hex |
| Hex 文本解码 | 十六进制字符串解码为字节 |

解析全部在浏览器端完成，不经过服务端；**解析失败会弹窗提示原因并自动回退到 Raw**。
单元测试见 `tests/parse_modes_test.js`（`node tests/parse_modes_test.js`）。

## 主题切换

页头右侧可切换界面主题：

| 选项 | 说明 |
| --- | --- |
| 跟随系统 | 默认，随操作系统的浅色/深色偏好自动切换 |
| 暗夜 | 深色主题 |
| 日间 | 浅色主题 |

选择保存在浏览器 `localStorage`，下次打开自动恢复；「跟随系统」模式下系统偏好变化时即时切换。仪表盘 canvas 图表的网格、坐标轴、系列色均读取主题变量，两种主题下均保持配色校验通过。

## HTTP API

**所有 `/api/*` 接口均需令牌鉴权**（令牌在面板「令牌与调用」页生成），支持
`Authorization: Bearer <token>`、`X-API-Token` 头或 `?token=` 查询参数三种方式。
完整的调用说明、字段定义与 curl/Python 示例见 [docs/API.md](docs/API.md)。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/health` | 健康检查，返回令牌名称（验证令牌最便宜的方式） |
| GET | `/api/state` | 面板全量状态（汇总、监听器、会话、解读器、速率序列） |
| GET | `/api/events?since=N` | 事件流 |
| GET | `/api/apicalls?since=N` | 外部调用日志 |
| GET | `/api/sessions` | 会话列表 |
| GET | `/api/sessions/{id}` | 会话详情（含 base64 负载与解读结果） |
| POST | `/api/sessions/{id}/interpret` | 清除解读缓存并重新解读 |
| GET | `/api/sessions/{id}/payload?direction=tx&encoding=bin\|hex\|text` | 下载原始负载 |
| GET | `/api/listeners` | 监听器列表 |
| POST | `/api/listeners` | 新建监听器（`name`/`listen_port`/`target_host`/`target_port`） |
| DELETE | `/api/listeners/{id}` | 移除监听器 |
| GET | `/api/interpreters` | 解读器列表 |
| POST | `/api/interpreters` | 注册自定义解读器（`id`/`title`/`code`/`enabled`） |
| POST | `/api/interpreters/{id}/toggle` | 启用/停用 |
| GET | `/api/interpreters/{id}/code` | 获取自定义解读器源码 |
| DELETE | `/api/interpreters/{id}` | 删除自定义解读器（内置不可删） |
| POST | `/api/interpreters-test` | 试运行解读器（`code` + `payload_b64` 或 `session_id`） |
| GET | `/api/export?format=json\|csv&scope=sessions` | 导出 |
| POST | `/api/reset` | 重置基线（`sessions`/`listeners`/`events`） |
| GET/POST | `/api/tokens` | 令牌列表/创建（仅面板内置令牌可调用） |
| POST/DELETE | `/api/tokens/{id}` | 启用/停用/删除令牌（仅面板内置令牌可调用） |

## 令牌与调用

- **生成令牌**：面板「令牌与调用」页填写名称 → 「＋ 生成令牌」，复制
  `sm_` 开头的令牌值分发给外部工具。面板内置令牌随页面注入浏览器，
  不可删除/停用，且只有它能管理令牌。
- **调用日志**：外部工具的每次 `/api/*` 调用（含鉴权失败的匿名调用）都会
  记录在面板「令牌与调用」页，含时间、令牌、方法、路径、状态码、耗时，
  内存中保留最近 500 条；面板自身的调用不记录。

## 端到端测试

```bash
# 1. 启动面板
uv run python -m socketmeasure --port 8099 --forward echo:18080:127.0.0.1:18081
# 2. 另开终端（脚本会自建回显目标）
uv run python tests/e2e_test.py
```

## 安全说明

- 面板 HTTP 接口需令牌鉴权（令牌只存内存，进程退出即失效）；面板仍默认
  只绑定 `127.0.0.1`，仅供本机调试；不要用 `--host 0.0.0.0` 暴露到不可信网络。
- 令牌相当于完全的 API 访问权限，请勿嵌入公开仓库或日志。
- 自定义解读器的代码以当前进程权限执行，只用于自己编写的调试脚本。
- 转发监听器监听的端口不要暴露给不可信来源。

## 项目结构

```
socketmeasure/
  app.py           命令行入口、后台监控线程
  proxy.py         TCP 转发监听器（计量引擎）
  model.py         会话 / 存储 / 令牌 / 事件 / 导出（内存模型）
  interpreters.py  解读器注册表与内置解读器
  server.py        Web 面板（REST API + 单页面）
  static/index.html  单文件控制台 UI
  __main__.py      python -m 入口
docs/API.md             HTTP API 调用文档（含 curl/Python 示例）
tests/e2e_test.py        端到端测试（Python）
tests/parse_modes_test.js  负载解析模式单元测试（node 运行，无需浏览器）
```
