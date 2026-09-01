# 商业化运行手册

本手册面向生产环境的平台、SRE 和安全团队。上线前必须结合实际吞吐、审计模型时延、数据库规格和渠道 SLA 完成容量验证。

## 1. 上线拓扑

推荐拓扑：

```text
Internet / New API
        |
TLS Load Balancer / Ingress
        |
3+ Risk Platform replicas
   |        |         |
PostgreSQL  Redis HA  Small Audit Model Pool
   |
Kafka Outbox -> Kafka 3+ brokers -> Long-term consumers/storage
```

基本原则：

- 风控服务无状态，多副本横向扩容。
- PostgreSQL、Redis、Kafka 和审计模型不得与公开入口共用安全组。
- 管理界面只允许 VPN、零信任代理或管理网访问。
- Ingress 必须支持长连接和 SSE，不得缓存 `/gateway/`。
- 生产密钥进入 KMS/Secret Manager，不放入普通 ConfigMap、镜像或 Git。

## 2. 上线前门禁

必须全部通过：

```bash
cd newapi-risk-platform
go test -race -count=1 ./...
go vet ./...
CGO_ENABLED=0 go build -trimpath ./cmd/riskd

docker compose -f docker-compose.yml -f docker-compose.test.yml up -d --build
ADMIN_PASSWORD='...' TRACKING_SECRET='...' bash scripts/e2e.sh
```

GitHub Pull Request 中以下 Checks 必须为绿色：

- New API Risk Platform CI
- New API Risk Platform E2E

另外执行：

- SAST、依赖和容器漏洞扫描；
- 互联网入口 DAST；
- SSRF、鉴权绕过、Header 注入、限流绕过和重放测试；
- 小模型审计准确率评估；
- 规则误报/漏报回归；
- 目标峰值至少 1.5–2 倍的容量压测；
- 渠道故障、审计模型故障、Redis 故障、Kafka 故障和 PostgreSQL 故障演练。

## 3. 容量压测

### k6

```bash
k6 run loadtest/k6.js \
  -e BASE_URL=https://risk.example.com \
  -e ROUTE_SLUG=openai-main \
  -e GATEWAY_KEY='route-secret' \
  -e MODEL='audit-test-model' \
  -e TARGET_RPS=500 \
  -e DURATION=10m \
  -e PRE_ALLOCATED_VUS=500 \
  -e MAX_VUS=2000
```

压测文本默认是防御性安全请求，只应收到 HTTP 200。不要用生产用户内容进行压测。

观察：

- 网关 P50/P95/P99；
- 审计模型 P50/P95/P99；
- HPA 扩容速度；
- CPU、内存、连接数、GC；
- PostgreSQL 活跃连接、事务时延、WAL、磁盘 IOPS；
- Redis 命令时延、内存和拒绝连接；
- Kafka Produce 时延、Outbox 积压；
- `trace_queue_depth`、`trace_dropped`；
- 渠道限流和错误率。

### 估算连接池

设：

```text
每实例 POSTGRES_MAX_CONNS = P
最大副本数 = N
运维/迁移保留连接 = R
```

数据库连接上限至少：

```text
P × N + R
```

大规模部署建议在 PostgreSQL 前使用 PgBouncer transaction pooling，并重新压测分区写入和 Dashboard 查询。

### 审计模型吞吐

审计模型通常是关键瓶颈。粗略估算：

```text
所需并发 ≈ 峰值 RPS × 审计 P95 秒数
```

例如峰值 500 RPS、审计 P95 0.4 秒，至少需要约 200 个有效并发槽位，再加入 30%–50% 余量。必须实测模型上下文长度、动态批处理和 GPU 饱和点。

## 4. Nginx / Ingress 要点

示例 Nginx 片段：

```nginx
location /gateway/ {
    proxy_pass http://newapi_risk_platform;
    proxy_http_version 1.1;

    proxy_buffering off;
    proxy_request_buffering off;
    gzip off;

    proxy_connect_timeout 10s;
    proxy_send_timeout 3600s;
    proxy_read_timeout 3600s;

    proxy_set_header Host $host;
    proxy_set_header X-Request-ID $request_id;
    proxy_set_header X-Forwarded-Proto $scheme;
}

location /admin {
    proxy_pass http://newapi_risk_platform;
    allow 10.0.0.0/8;
    deny all;
}
```

注意：

- Nginx 能转发非标准状态 `555`，但必须在实际链路验收。
- 某些 CDN、WAF、API Gateway 或客户端 SDK 可能改写未知状态码。若链路无法保留 555，仍应保留 JSON `error.code=555` 和 `X-Risk-Error-Code: 555`，并在 New API 适配层统一识别。
- SSE 已开始后不能修改 HTTP 状态，必须识别 `event: error` 中的逻辑 555。
- 不要对 `/gateway/` 启用响应缓存、内容压缩重缓冲或短超时。

## 5. PostgreSQL 运维

### 备份

至少配置：

- 每日全量备份；
- 持续 WAL/PITR；
- 备份加密；
- 跨可用区或跨区域副本；
- 定期恢复演练。

示例逻辑备份仅用于小规模或辅助导出：

```bash
pg_dump --format=custom --no-owner --file=risk.dump "$DATABASE_URL"
pg_restore --clean --if-exists --no-owner --dbname="$RESTORE_DATABASE_URL" risk.dump
```

生产大库优先使用云数据库快照和 PITR，而不是只依赖 `pg_dump`。

### 七天窗口

`request_traces` 使用 UTC 按日分区。维护任务：

- 创建前一天、当天和未来三天分区；
- 删除完全过期分区；
- 清理边界分区中早于精确 `retention_days × 24h` 的数据；
- 多副本通过 Advisory Lock 避免重复维护。

告警条件：

- 未来 24 小时分区不存在；
- 分区维护持续失败；
- 数据盘剩余空间低于 20%；
- 长事务阻塞分区删除；
- Dashboard 查询影响写入延迟。

### 索引与膨胀

高流量环境定期检查：

```sql
SELECT relname, n_live_tup, n_dead_tup
FROM pg_stat_user_tables
ORDER BY n_dead_tup DESC;

SELECT datname, numbackends, xact_commit, xact_rollback
FROM pg_stat_database;
```

请求表以短生命周期分区删除为主，不要对每个 Metadata 字段盲目增加 GIN 索引。

## 6. Redis 运维与降级

Redis 用于：

- 分布式 Token Bucket；
- 按路由分布式并发信号量；
- Tracking Nonce 防重放；
- Redis Stream DLQ。

推荐：

- 托管高可用、Sentinel 或 Cluster；
- TLS 和 ACL；
- `noeviction` 或独立实例；
- 监控延迟、连接、内存、复制滞后和故障切换。

Redis 不可用时：

- 限流和并发控制降级为单实例内存控制，跨副本总量可能超限；
- Nonce 使用 PostgreSQL 回退；
- Redis DLQ 不可写时，队列溢出事件可能丢失并增加 `trace_dropped`。

Redis 故障期间应降低入口流量或临时缩小各实例的本地限额，恢复后确认 DLQ、追踪丢弃和上游峰值。

## 7. Kafka 与 Outbox

生产 Topic 建议：

```text
name: risk.request.events.v1
partitions: 按峰值吞吐和消费者并行度确定
replication.factor: 3
min.insync.replicas: 2
acks: all
compression: broker/client按环境配置
retention.ms: 页面期望值与 Broker 实际值保持一致
```

平台先成功写 PostgreSQL，再异步写 Kafka。Kafka 失败时写入 `outbox_events` 并指数退避重试。

需要监控：

```sql
SELECT count(*) AS pending,
       min(created_at) AS oldest_created_at,
       max(attempts) AS max_attempts
FROM outbox_events
WHERE published_at IS NULL;
```

严重告警：

- Outbox 最老事件超过 5 分钟；
- 重试次数持续增长；
- Kafka ISR 缩小；
- Broker 磁盘低；
- 消费者滞后超过业务恢复点目标。

页面修改 Kafka 保留时间需要 Topic `ALTER_CONFIGS` 权限。返回告警时，期望值已保存，但 Broker 可能尚未应用，必须由运维核对。

## 8. 密钥管理和轮换

### 可直接轮换

- 路由入口 Key；
- 上游渠道 Key；
- Tracking Client Secret；
- 管理员密码；
- JWT Secret（会使已有登录 Token 失效）。

推荐双 Key 迁移步骤：

1. 创建新路由或新 Tracking Client；
2. New API 灰度切换；
3. 观察新 Key 流量和错误；
4. 停用旧 Key；
5. 过一个最大重试窗口后删除旧配置。

### Master Key

`MASTER_KEY_B64` 同时保护：

- 上游密钥密文；
- 审计模型 API Key 密文；
- Tracking Secret 密文；
- 路由入口 Key HMAC；
- Prompt HMAC。

**不能直接替换 Master Key。** 直接替换会导致已有密文无法解密、路由 Key 全部失效，且历史 Prompt HMAC 无法关联。

正式轮换必须实现：

1. 新旧 Key 双读；
2. 后台逐条解密并用新 Key 重加密；
3. 重新计算需要验证的 HMAC；
4. 验证所有配置；
5. 停止旧 Key 读取；
6. 销毁旧 Key。

轮换前先做数据库快照，并在隔离环境演练。

## 9. Cyber 规则和模型变更

规则变更流程：

1. 在测试环境导入；
2. 使用历史匿名样本与人工标注集回放；
3. 检查误报率、漏报率和语言覆盖；
4. 宽泛模式先设为 `review`；
5. 灰度到少量路由；
6. 观察 555、申诉和业务转化；
7. 再提升为 `block`。

避免：

- 仅凭单个通用词直接 Block；
- 把防御性讨论、日志、CTF、授权测试和引用材料全部视为恶意；
- 让小模型返回自由文本并依赖正则解析；
- 未经回归直接更换系统提示词或阈值。

审计模型配置有短 TTL 缓存，控制台修改会在当前实例立即失效；多副本环境的其他实例最多在缓存 TTL 后收敛。对强一致变更可滚动重启或后续接入 Redis Pub/Sub 配置广播。

## 10. 故障处置

### 大量 `AUDIT_MODEL_ERROR`

1. 检查审计 Endpoint、DNS、TLS、Key 和模型名；
2. 检查输出是否为严格 JSON；
3. 检查模型 P95/P99 和超时；
4. 检查上下文过长与限流；
5. 不要直接全局 fail-open；如必须降级，只对低风险、受限路由短时实施并记录审批。

### 大量 `UPSTREAM_MODEL_ERROR`

1. 按 `route_slug`、`upstream_status`、时间窗口聚合；
2. 检查渠道余额、Key、模型权限、配额和地区限制；
3. 检查 HTTP 200 错误包格式变化；
4. 对明确可重试错误启用有限退避；
5. 防止流式失败后的重复计费和重复内容。

### PostgreSQL 不可用

- Readiness 失败，负载均衡应摘除实例；
- 已在处理的请求可能完成，但新配置查询和追踪持久化受影响；
- 不要在无法持久化审计状态时长期保持对外服务；
- 恢复后检查 Redis DLQ、事件丢弃、分区和 Outbox。

### 误拦截事故

1. 按 `request_id`、`risk_code`、规则 ID 和审计来源定位；
2. 保存匿名化复现样本；
3. 将问题规则从 `block` 降为 `review` 或临时停用；
4. 用回归集验证修复；
5. 记录影响范围、持续时间和修复提交。

## 11. 发布和回滚

推荐滚动发布：

- `maxUnavailable: 0`；
- `maxSurge: 1`；
- 至少 3 副本；
- PDB 至少保留 2；
- Readiness 成功后才接流量；
- 终止宽限期必须覆盖 HTTP 排空、PostgreSQL Trace Flush 和 Kafka Queue Flush。

回滚前确认数据库迁移是否向后兼容。当前迁移只做增量创建；未来删除列、改类型或重分区必须使用 expand/migrate/contract 多阶段方案。

## 12. 每日检查清单

- 555 错误率与风险码分布；
- 审计模型和渠道 P95/P99；
- Trace Queue、Dropped、Redis DLQ；
- PostgreSQL 连接、磁盘、WAL、分区；
- Kafka Outbox、ISR、消费者滞后；
- Redis 内存、延迟和主从状态；
- 最近规则、模型、路由和存储配置的管理员审计日志；
- 管理账户异常登录；
- 证书和密钥到期时间。
