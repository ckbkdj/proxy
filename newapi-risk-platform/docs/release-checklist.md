# 合并与生产发布门禁

本清单不以文档勾选结果代替 GitHub Actions、压测、安全评审或生产变更审批。

## Pull Request 合并前

- [ ] `New API Risk Platform CI` 全部通过。
- [ ] `New API Risk Platform E2E` 全部通过。
- [ ] `go test -race -count=1 ./...` 通过。
- [ ] `go vet ./...` 通过。
- [ ] `riskd` 与 `mockprovider` 静态构建通过。
- [ ] PostgreSQL 迁移、分区创建和七天清理逻辑在临时数据库验证。
- [ ] 管理登录、JWT 过期和 RBAC 权限验证。
- [ ] 路由入口 Key 错误时返回 401，而不是 555。
- [ ] Cyber 规则命中返回 HTTP 555 和逻辑码 555。
- [ ] 小模型 Block、Review/fail-closed、超时和非法 JSON 返回预期风险码。
- [ ] 上游非 2xx、HTTP 200 错误包和连接失败统一为 555。
- [ ] SSE 首事件错误返回 HTTP 555。
- [ ] SSE 中途错误返回 `event:error` 和逻辑码 555。
- [ ] HMAC Tracking 正常上报、过期时间戳、错误签名和 Nonce 重放验证。
- [ ] Metadata 敏感字段清洗验证。
- [ ] SSRF、私网地址、回环、链路本地和云元数据地址阻断验证。
- [ ] 依赖、SAST、Secret Scan 和容器漏洞扫描无未接受的高危问题。
- [ ] 文档中的环境变量、端口、命令和 API 示例与代码一致。

## 预生产环境

- [ ] 使用与生产同类型的 PostgreSQL、Redis、Kafka 和 Ingress。
- [ ] 至少三副本部署并验证滚动升级、PDB 和 HPA。
- [ ] TLS、证书链、SNI 和长连接正常。
- [ ] Nginx/CDN/WAF/API Gateway 不改写 HTTP 555；如会改写，New API 仍正确识别逻辑码和响应头。
- [ ] `/gateway/` 不缓存、不缓冲 SSE，读写超时覆盖最长模型请求。
- [ ] 管理端仅管理网/VPN/零信任入口可访问。
- [ ] PostgreSQL PITR、快照和恢复演练完成。
- [ ] Redis 故障切换、Kafka Broker 故障和 Outbox 恢复演练完成。
- [ ] 目标峰值 1.5–2 倍的 k6 压测通过。
- [ ] 审计模型容量、准确率、语言覆盖和误报率达到验收线。
- [ ] Prometheus 告警已加载并通过模拟触发验证。
- [ ] 日志、Trace 和 Kafka 事件没有原始 Prompt、渠道 Key、Token、Cookie 或个人身份信息。

## 生产变更

- [ ] 所有 Secret 由 KMS/Secret Manager 注入，示例占位符已替换。
- [ ] `MASTER_KEY_B64` 已备份并设置严格访问审计，不进行无迁移直接轮换。
- [ ] Kafka Topic 已预创建，副本因子、ISR、ACL、TLS/SASL 和保留策略正确。
- [ ] PostgreSQL 最大连接数与 `每实例连接池 × 最大副本数` 匹配，必要时启用 PgBouncer。
- [ ] Redis 使用高可用架构和 `noeviction`/专用容量策略。
- [ ] 初始 Cyber Block 规则和小模型阈值经过灰度评审。
- [ ] New API 已实现 HTTP 555、SSE logical 555、请求 ID 和有限重试策略。
- [ ] 发布、回滚、误拦截和渠道故障值班人员明确。
- [ ] 变更窗口内持续观察错误率、P95/P99、拦截率、Trace Drop、Outbox 和数据库资源。

## 合并原则

任何以下情况不得合并或上线：

- 自动化测试失败或没有运行；
- 无法解释的高危依赖/容器漏洞；
- HTTP 555 在真实链路被吞掉且 New API 未实现逻辑码回退；
- 原始用户 Prompt 或密钥进入 PostgreSQL、Redis、Kafka、日志或告警；
- 审计模型故障时的 fail-open/fail-closed 行为不明确；
- 数据库连接、审计模型容量或 SSE 超时未完成峰值验证；
- Master Key、管理员密码或渠道密钥仍为示例值。
