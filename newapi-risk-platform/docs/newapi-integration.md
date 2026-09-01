# New API 接入协议

本文面向 New API 二次开发方，包含两条独立链路：

1. **同步模型链路**：New API → 风控网关 → 渠道。
2. **异步追踪链路**：New API → HMAC Tracking API → PostgreSQL/Kafka。

## 一、同步模型链路

### 渠道配置

假设控制台创建了：

```text
route slug: openai-main
route inbound key: risk-route-7f...random
```

New API 渠道填写：

```text
Base URL: https://risk.example.com/gateway/openai-main
API Key:  risk-route-7f...random
```

New API 发出的请求：

```http
POST /gateway/openai-main/v1/chat/completions HTTP/1.1
Host: risk.example.com
Authorization: Bearer risk-route-7f...random
Content-Type: application/json
X-Request-ID: 4bc269ec-9a32-4ed4-b7bc-a64ff22ae86f
X-NewAPI-Request-ID: newapi-100023
X-NewAPI-User-ID: usr_7ec8a09f

{
  "model": "gpt-5",
  "messages": [
    {"role": "user", "content": "解释服务端日志如何做脱敏"}
  ],
  "stream": true
}
```

平台行为：

1. 验证渠道入口 Key。
2. 执行分布式限流与并发保护。
3. 抽取文本，但不持久化原始请求体。
4. 先执行 Cyber 规则。
5. 需要时调用小模型审计。
6. Allow 后把 Authorization 替换为真实上游密钥。
7. 转发到渠道并统一错误。
8. 异步写请求追踪。

### 请求标识

建议 New API 总是发送：

| Header | 说明 |
|---|---|
| `X-Request-ID` | 跨系统唯一请求 ID。只允许字母、数字、`.`、`_`、`:`、`-`，最多 128 字符。 |
| `X-NewAPI-Request-ID` | New API 内部请求 ID。 |
| `X-NewAPI-User-ID` | 匿名化用户 ID，不要发送手机号、邮箱、姓名或证件号。 |

平台响应会返回：

```http
X-Risk-Request-ID: 4bc269ec-9a32-4ed4-b7bc-a64ff22ae86f
```

当传入的 `X-Request-ID` 不合法时，平台生成新的 UUID。

## 二、处理错误码 555

### 非流式

```http
HTTP/1.1 555
Content-Type: application/json
X-Risk-Error-Code: 555
X-Risk-Request-ID: ...

{
  "error": {
    "message": "request rejected by risk control",
    "type": "risk_control_error",
    "code": 555,
    "risk_code": "CYBER_CREDENTIAL_THEFT",
    "request_id": "..."
  }
}
```

New API 不应只检查 `error.code`，应同时记录：

- HTTP Status；
- `error.code`；
- `error.risk_code`；
- `error.request_id`；
- `X-Risk-Request-ID`。

### 流式

首个有意义事件前发生错误时仍返回 HTTP 555。流已经开始后，网关追加：

```text
event: error
data: {"error":{"message":"upstream model stream failed","type":"upstream_error","code":555,"risk_code":"UPSTREAM_STREAM_ERROR","request_id":"..."}}

```

New API SSE 解析器应在收到 `event: error` 或 `data.error.code == 555` 时：

1. 停止向客户端继续输出；
2. 把该请求标为失败；
3. 保存 `risk_code` 与 `request_id`；
4. 不把该错误 JSON 当成普通模型文本。

### 重试建议

| 风险码 | 自动重试 |
|---|---|
| `CYBER_*` | 不重试 |
| `AUDIT_REVIEW_REQUIRED` | 不重试，进入人工/更强模型复核 |
| `AUDIT_MODEL_UNAVAILABLE` | 可短退避重试一次，持续失败时熔断 |
| `AUDIT_MODEL_ERROR` | 可短退避重试一次 |
| `UPSTREAM_CONNECTION_ERROR` | 幂等请求可重试 |
| `UPSTREAM_TIMEOUT` | 需结合是否已经开始流式输出；未输出时可重试 |
| `UPSTREAM_MODEL_ERROR` | 只对明确可重试的渠道错误重试，避免重复计费 |
| `UPSTREAM_STREAM_ERROR` | 流已开始时默认不自动重放，除非业务能去重 |

普通 `401`、`429`、`503` 按标准鉴权、限流、过载策略处理。

## 三、主动请求追踪接口

即使请求没有经过网关，New API 也可把自己的调用数据发给平台，统一查询和发送到 Kafka。

### Endpoint

```http
POST /api/v1/track/events
```

### Header

```http
Content-Type: application/json
X-Risk-Key-Id: newapi-prod
X-Risk-Timestamp: 1788234400
X-Risk-Nonce: TywnxHhJrH9J8r4zY0bN-w
X-Risk-Signature: 4ab0...hex-hmac
```

- 时间戳默认允许前后 5 分钟误差。
- Nonce 默认保存 10 分钟，相同 Key ID + Nonce 只能使用一次。
- Secret 只在控制台新建或轮换时返回一次。

### 签名原文

必须对**最终实际发送的原始字节**签名，不能先签名再由 HTTP 客户端重新格式化 JSON。

```text
body_sha256 = hex(sha256(raw_body))
canonical = timestamp + "\n" + nonce + "\n" + body_sha256
signature = hex(hmac_sha256(client_secret, canonical))
```

### 单事件 Schema

```json
{
  "event_id": "newapi-event-100023",
  "request_id": "4bc269ec-9a32-4ed4-b7bc-a64ff22ae86f",
  "route_slug": "openai-main",
  "newapi_request_id": "newapi-100023",
  "external_user_id": "usr_7ec8a09f",
  "model": "gpt-5",
  "endpoint": "/v1/chat/completions",
  "decision": "allow",
  "risk_code": "",
  "http_status": 200,
  "upstream_status": 200,
  "latency_ms": 832,
  "audit_latency_ms": 37,
  "request_bytes": 1302,
  "response_bytes": 8392,
  "prompt_hmac": "optional-precomputed-hmac",
  "occurred_at": "2026-09-01T18:20:00Z",
  "metadata": {
    "tenant_id": "tenant_42",
    "channel_id": 19,
    "billing_units": 2310
  }
}
```

`decision` 建议使用：

```text
allow | block | review | error
```

未知值会保存为 `unknown`。

### 批量 Schema

每批最多 1000 条：

```json
{
  "events": [
    {"event_id":"evt-1","request_id":"req-1","decision":"allow"},
    {"event_id":"evt-2","request_id":"req-2","decision":"error","risk_code":"UPSTREAM_TIMEOUT"}
  ]
}
```

响应：

```http
HTTP/1.1 202 Accepted

{
  "accepted": 2,
  "deferred_or_dropped": 0,
  "received_at": "2026-09-01T18:20:01Z"
}
```

`deferred_or_dropped > 0` 表示本机异步队列已满。平台会优先写 Redis DLQ，但 New API 仍应告警并保留自己的重放队列。

### 幂等

`event_id` 在每个追踪客户端范围内应稳定且唯一。平台内部幂等键为：

```text
key_id + ":" + event_id
```

重复事件在 PostgreSQL 插入阶段被忽略。建议 New API 对同一次调用重试时复用原 `event_id`，但每次 HTTP 上报都使用新的 Nonce 和时间戳。

## 四、Python 签名示例

```python
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from typing import Any

import requests


def send_event(
    endpoint: str,
    key_id: str,
    secret: str,
    event: dict[str, Any],
) -> requests.Response:
    body = json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(18)
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = f"{timestamp}\n{nonce}\n{body_hash}".encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()

    response = requests.post(
        endpoint,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Risk-Key-Id": key_id,
            "X-Risk-Timestamp": timestamp,
            "X-Risk-Nonce": nonce,
            "X-Risk-Signature": signature,
        },
        timeout=5,
    )
    response.raise_for_status()
    return response
```

## 五、Go 签名示例

```go
func sign(secret, timestamp, nonce string, body []byte) string {
    bodyHash := sha256.Sum256(body)
    canonical := timestamp + "\n" + nonce + "\n" + hex.EncodeToString(bodyHash[:])
    mac := hmac.New(sha256.New, []byte(secret))
    _, _ = mac.Write([]byte(canonical))
    return hex.EncodeToString(mac.Sum(nil))
}
```

发送时使用同一个 `body` 字节切片：

```go
request, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
request.Header.Set("Content-Type", "application/json")
request.Header.Set("X-Risk-Key-Id", keyID)
request.Header.Set("X-Risk-Timestamp", timestamp)
request.Header.Set("X-Risk-Nonce", nonce)
request.Header.Set("X-Risk-Signature", sign(secret, timestamp, nonce, body))
```

## 六、Metadata 数据最小化

平台会删除以下键及其子内容：

```text
prompt, messages, content, input, instructions, system_prompt,
request_body, response_body, api_key, authorization, password,
secret, cookie, set-cookie, access_token, refresh_token
```

同时限制：

- 对象嵌套深度；
- 数组长度；
- 单字符串长度；
- Metadata 总序列化大小。

New API 侧仍应先做数据最小化，只发送检索、计费和故障分析真正需要的字段。

## 七、推荐接入位置

在 New API 中建议拆成两个组件：

```text
ChannelTransport
  ├─ 设置 X-Request-ID / X-NewAPI-Request-ID / X-NewAPI-User-ID
  ├─ 调用风险网关
  └─ 解析 HTTP 555 与 SSE logical 555

RiskTraceReporter
  ├─ 有界内存队列
  ├─ 批量聚合（例如 100 条或 200 ms）
  ├─ HMAC 签名
  ├─ 本地持久化重试
  └─ 不阻塞主模型请求
```

追踪上报失败不应阻塞用户模型响应，但必须有本地指标、告警和重放机制。
