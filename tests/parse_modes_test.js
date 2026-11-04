/* 提取 index.html 内联脚本后运行的解析模式单元测试（node 运行） */
const fs = require("fs");
const path = require("path");

const html = fs.readFileSync(
  path.join(__dirname, "..", "socketmeasure/static/index.html"), "utf-8");
const code = /<script>([\s\S]*?)<\/script>/.exec(html)[1];

/* DOM 桩：让内联脚本的顶层语句能跑过 */
const __dataset = {};
const node = () => new Proxy({}, {
  get: (t, k) => {
    if (k === "addEventListener") return () => {};
    if (k === "classList") return { add() {}, remove() {}, toggle() {} };
    if (k === "style") return {};
    if (k === "dataset") return __dataset;
    if (["checked", "value", "textContent"].includes(k)) return "";
    if (["clientWidth", "clientHeight"].includes(k)) return 800;
    if (k === "getContext") return () => new Proxy({}, { get: () => () => {} });
    return node();
  },
  set: () => true,
});
global.document = {
  querySelector: () => node(),
  querySelectorAll: () => [],
  createElement: () => node(),
  body: node(),
  documentElement: node(),
};
global.localStorage = {
  store: {},
  getItem(k) { return this.store[k] || null; },
  setItem(k, v) { this.store[k] = v; },
};
global.matchMedia = q => ({ matches: q.includes("dark"), addEventListener() {} });
global.getComputedStyle = () => ({
  getPropertyValue: name => ({ "--series-1": "#3987e5", "--series-2": "#d95926",
    "--ink-1": "#f0efec", "--ink-3": "#898781", "--grid": "#2c2c2a",
    "--surface-1": "#1a1a19" })[name] || "",
});
global.window = { addEventListener: () => {}, devicePixelRatio: 1,
  matchMedia: q => ({ matches: q.includes("dark"), addEventListener: () => {} }) };
global.fetch = () => new Promise(() => {});
global.setInterval = () => {};
global.atob = s => Buffer.from(s, "base64").toString("binary");
global.TextDecoder = require("util").TextDecoder;

const harness = `
function bytes(s) { return new Uint8Array(Buffer.from(s, "utf-8")); }
function hex(h) { const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out; }
function test(name, mode, input, expectFail) {
  const data = typeof input === "string" ? bytes(input) : input;
  try {
    renderPayloadView(data, mode);
    console.log(expectFail ? "FAIL(应失败但成功) " + name : "PASS " + name);
  } catch (e) {
    console.log(expectFail ? "PASS(预期失败) " + name + " -> " + e.message
                           : "FAIL(意外) " + name + " -> " + e.message);
  }
}
test("raw 总能成功", "raw", "AB\\u0000\\u00ff", false);
test("ascii 成功", "ascii", "GET / HTTP/1.1\\r\\n", false);
test("ascii 失败(含0xc3)", "ascii", hex("41c3"), true);
test("utf8 成功", "utf8", "你好，世界", false);
test("utf8 失败(乱码字节)", "utf8", hex("fffe80"), true);
test("json 成功", "json", "{\\"a\\":1,\\"b\\":[1,2]}", false);
test("json 成功(BOM)", "json", hex("efbbbf7b2261223a317d"), false);
test("json 失败(HTTP文本)", "json", "GET / HTTP/1.1", true);
test("http 成功(请求)", "http", "GET /metrics HTTP/1.1\\r\\nHost: t\\r\\nUser-Agent: x\\r\\n\\r\\nbody here", false);
test("http 成功(响应)", "http", "HTTP/1.1 200 OK\\r\\nContent-Type: text/plain\\r\\n\\r\\nhello", false);
test("http 失败(JSON)", "http", "{\\"a\\":1}", true);
test("http 失败(坏头部行)", "http", "GET / HTTP/1.1\\r\\nBadHeaderLine\\r\\n\\r\\n", true);
test("http 失败(非UTF8)", "http", hex("fffe80"), true);
test("form 成功", "form", "a=1&b=hello%20world&c=", false);
test("form 失败(无等号)", "form", "abc", true);
test("form 失败(JSON)", "form", "{\\"a\\":1}", true);
test("base64 成功", "base64", "aGVsbG8gd29ybGQ=", false);
test("base64 失败(长度)", "base64", "aGVsbG8", true);
test("base64 失败(非法字符)", "base64", "aGVs!G8=", true);
test("hexstr 成功", "hexstr", "48 65 6c 6c 6f", false);
test("hexstr 失败(奇数长度)", "hexstr", "486", true);
test("hexstr 失败(非hex)", "hexstr", "zz", true);
test("空负载", "json", "", false);
console.log("未知模式回退hex:", renderPayloadView(bytes("x"), "nope").includes("hex") ? "PASS" : "FAIL");
// 弹窗与回退逻辑（模拟 change 事件处理器）
try { renderPayloadView(bytes("zz"), "hexstr"); console.log("FAIL 回退逻辑未触发"); }
catch (e) { console.log("PASS 回退逻辑可捕获:", e.message); }

// ---- WebSocket（ws 模式）----
function wstest(name, input, dir, requireStr, expectFail) {
  const data = typeof input === "string" ? bytes(input) : input;
  try {
    const html = renderPayloadView(data, "ws", dir);
    if (expectFail) { console.log("FAIL(应失败但成功) " + name); return; }
    const missing = (requireStr || []).filter(s => !html.includes(s));
    console.log(missing.length ? "FAIL " + name + " -> 缺少: " + missing.join(" / ") : "PASS " + name);
  } catch (e) {
    console.log(expectFail ? "PASS(预期失败) " + name + " -> " + e.message
                           : "FAIL(意外) " + name + " -> " + e.message);
  }
}
console.log(typeof wsView === "function" ? "PASS wsView 已定义" : "FAIL wsView 未定义");
// RFC 6455 §5.7 官方掩码示例：81 85 37 fa 21 3d 7f 9f 4d 51 58 -> "Hello"
wstest("ws 掩码客户端文本帧(§5.7 向量)", hex("818537fa213d7f9f4d5158"), "tx", ["Hello", "掩码", "1 帧 / 1 报文"]);
// 服务端无掩码文本帧
wstest("ws 无掩码服务端文本帧", hex("810548656c6c6f"), "rx", ["Hello", "无掩码"]);
// tx 未带掩码应给出 §5.3 合规提示
wstest("ws tx 未掩码触发 §5.3 提示", hex("810548656c6c6f"), "tx", ["必须带掩码"]);
// 分片报文：01 03 "Hel" + 80 02 "lo"，应装配成 1 条 "Hello"
wstest("ws 分片装配(§5.4)", hex("010348656c80026c6f"), "rx", ["装配报文", "Hello", "2 帧"]);
// 握手请求 + 掩码帧：应同时展示握手头部与帧明细
const hsReq = bytes("GET /chat HTTP/1.1\\r\\nHost: example.com\\r\\nUpgrade: websocket\\r\\n"
  + "Connection: Upgrade\\r\\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\\r\\n"
  + "Sec-WebSocket-Version: 13\\r\\n\\r\\n");
const concat = (a, b) => { const out = new Uint8Array(a.length + b.length);
  out.set(a, 0); out.set(b, a.length); return out; };
wstest("ws 握手 + 帧流", concat(hsReq, hex("818537fa213d7f9f4d5158")), "tx",
  ["Hello", "Sec-WebSocket-Key", "握手", "1 帧 / 1 报文"]);
// 单报文作用域：负载为装配后已解除掩码的报文（与 /messages 接口返回一致），不再按帧解析
try {
  const mv = renderPayloadView(bytes("Hello"), "ws", "tx",
    { kind: "ws-text", seq: 1, opcode_name: "text" });
  console.log((mv.includes("单报文作用域") && mv.includes("Hello") && mv.includes("opcode"))
    ? "PASS ws 单报文作用域" : "FAIL ws 单报文作用域 -> " + mv.slice(0, 120));
} catch (e) { console.log("FAIL(意外) ws 单报文作用域 -> " + e.message); }
// 握手报文作用域：负载为 HTTP Upgrade 原文
try {
  const hv = renderPayloadView(hsReq, "ws", "tx", { kind: "handshake", seq: 1 });
  console.log((hv.includes("Sec-WebSocket-Key") && hv.includes("HTTP Upgrade 握手报文原文"))
    ? "PASS ws 握手报文作用域" : "FAIL ws 握手报文作用域 -> " + hv.slice(0, 120));
} catch (e) { console.log("FAIL(意外) ws 握手报文作用域 -> " + e.message); }
// 非 WebSocket 的普通 HTTP 请求应抛错
wstest("ws 普通 HTTP 不误判", "GET /api/x HTTP/1.1\\r\\nHost: a\\r\\n\\r\\n", "tx", [], true);
// 任意垃圾字节（无可识别帧）应抛错，不渲染伪帧
wstest("ws 垃圾字节不误判", "hello world", "tx", [], true);
// 保留 opcode（0x0f）不作为 WebSocket 证据
wstest("ws 保留 opcode 不误判", hex("8f00"), "tx", [], true);
// 流尾被截断的帧应标记而非抛错（前面已有完整帧通过证据门）
wstest("ws 流尾截断容忍", hex("810548656c6c6f8106"), "rx", ["Hello", "实际仅 0 字节"]);
// 掩码字段不完整应标记为流尾不完整
wstest("ws 掩码字段截断容忍", hex("810548656c6c6f818037fa"), "rx", ["掩码字段不完整"]);
// 16 位扩展长度编码（len7=126，无掩码）
wstest("ws 16 位扩展长度", hex("817e000548656c6c6f"), "rx", ["Hello"]);
// 64 位扩展长度编码（len7=127，无掩码）
wstest("ws 64 位扩展长度", hex("817f000000000000000548656c6c6f"), "rx", ["Hello"]);
// 关闭帧：88 02 03 e8 = 状态码 1000 无原因
wstest("ws 关闭帧状态码", hex("880203e8"), "rx", ["1000"]);
// TLS 字节应给出需先解密的提示
wstest("ws TLS 记录提示", hex("160301"), "tx", [], true);
// 空负载提示
console.log(renderPayloadView(new Uint8Array(0), "ws", "tx").includes("暂无负载数据")
  ? "PASS ws 空负载提示" : "FAIL ws 空负载提示");

// 主题切换
function tcase(name, fn) { try { fn(); console.log("PASS " + name); }
  catch (e) { console.log("FAIL " + name + " -> " + e.message); } }
tcase("默认跟随系统(桩为dark)", () => {
  if (effectiveTheme("auto") !== "dark") throw Error("期望 dark");
});
tcase("显式 light", () => { if (effectiveTheme("light") !== "light") throw Error("期望 light"); });
tcase("显式 dark", () => { if (effectiveTheme("dark") !== "dark") throw Error("期望 dark"); });
tcase("applyTheme 写 data-theme 并持久化", () => {
  applyTheme("light");
  if (__dataset.theme !== "light") throw Error("data-theme 未设置");
  if (localStorage.getItem("socketmeasure.theme") !== "light") throw Error("未持久化");
});
tcase("applyTheme(auto) 解析为系统值", () => {
  applyTheme("auto");
  if (__dataset.theme !== "dark") throw Error("期望解析为 dark，得到 " + __dataset.theme);
});
tcase("hexA 转换", () => {
  if (hexA("#3987e5", 0.35) !== "rgba(57,135,229,0.35)") throw Error(hexA("#3987e5", 0.35));
});
`;
eval(code + harness);
