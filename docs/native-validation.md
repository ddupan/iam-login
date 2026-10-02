# 首轮 Native 验证范围

本页定义验收要求，不表示下列功能已实现或测试通过。MFA 首先验证 Spring 官方
WebAuthn 集成；TOTP、恢复方式与已有 Authelia MFA 的迁移方式需在实现中明确。

## 认证与身份

- 使用隔离 LDAP 测试夹具验证正确密码、错误密码、未知及禁用用户；随后验证 Samba AD
  的真实 schema、LDAPS 信任和组查询，不把通用 LDAP 测试等同于 AD 验收。
- 用户与组以 AD 为权威，直接映射；不把框架 ROLE_ 前缀或大小写转换泄露到 groups claim。
- LDAP 与 MFA 必须绑定同一个稳定主体；仅完成密码不得接受 Hydra login challenge。
- 验证 MFA 注册授权、challenge 过期与重放、其他用户凭据、重启后的持久化，以及恢复。
- 新主体映射与现役 Go 适配器的 issuer/sub 哈希不同；切换前必须制定显式连续性映射，
  不依赖可变邮箱、用户名或自动创建账号来掩盖身份变化。

## Hydra

- 认证事务绑定原始 challenge、浏览器会话和期限；成功后单次使用。
- 校验允许的 client、scope、audience 和 Hydra 返回跳转的 origin/path。
- Hydra admin 保持内部访问，业务日志不得包含密码、MFA secret、token 或 challenge。
- 原生二进制与隔离 Hydra 完成授权码链路，再验证现有 Gitea 账号及权限。

日常迭代以 JVM 测试为准，不要求每轮执行 Native 编译。Native 验证安排在阶段性验收
或新增反射、JNDI、TLS 等兼容性风险时集中进行；记录尚未覆盖的新路径。

## Native 与监控

- CI 构建 Native 产物并对该产物执行集成测试；测试报告区分 JVM 与 Native。
- 登录 Controller 与安全链使用 `@ConditionalOnProperty(iam.ad.enabled)`；AOT 在构建时
  决定 bean 是否存在。AD Native 产物必须在 AOT 阶段启用此属性，验证实际入口与兜底链，
  不能假设运行时修改属性会重新装配 bean。本轮只验证 JVM，尚未验收该 Native 路径。
- WebAuthn 新增的 JDBC/Flyway/PostgreSQL、WebAuthn4J 校验与 JSON 路径本轮仅做 JVM 验证；
  Native AOT 时还需启用 `iam.webauthn.enabled`，不得套用基础骨架的 Native 结论。
- Hydra 的 RestClient/JDK HTTP 与 JSON DTO 新增反射绑定声明；仍需在启用 `iam.hydra.enabled`
  的 Native 产物上实际运行授权码流程，JVM 接入结果不构成该项验收。
- 最终运行镜像无需 JRE，不允许以回退 JVM 的方式令 Native 验收通过。
- LDAP、MFA、数据库、TLS、JSON 和 Hydra HTTP 客户端全部在 Native 中执行。
- 纳入 Actuator、Micrometer Prometheus 与 OpenTelemetry/分布式追踪；实际发起请求后
  检查计数器、耗时分布与 trace 导出，确保 trace 属性不记录认证凭据或 challenge。
- 记录镜像大小、启动时间、空闲与负载下内存、CPU、关键请求延迟；资源预算依据实测确认。
- 将应用指标与 Native 运行时指标区分，不能假设 HotSpot JVM 仪表盘完整适用。

## 发布条件

通过上述测试后才准备生产切换；保留现役 OIDC 上游适配器作为回退路径。应用镜像以
不可变 digest 交给 homelab-infra，部署状态与真实人类 MFA 验收分别记录。

### 测试 AOT 的待排查项（2026-09-29）

本轮重构的 `processTestAot` 在处理测试上下文后未退出；线程栈显示 `DestroyJavaVM`
等待测试夹具的非 daemon LDAP listener。该轮日常验证使用
`test bootJar -x processTestAot -x compileAotTestJava -x processAotTestResources`
执行 JVM 测试，不把该结果视为测试 AOT 或 Native 验收。阶段性原生验证前需解决夹具生命周期。

### 内置授权服务器的 Native 验证（2026-10-01 起）

在 pve1 临时 LXC 上以 `-PaotArgs='--iam.ad.enabled=true --iam.webauthn.enabled=true --iam.authorization-server.enabled=true'`
编译（约 11.5 分钟，峰值约 5.4 GB），以 Native 二进制为被测对象、`nativeSmokeSupport`（模拟 AD 与夹具客户端）
加 Playwright 跑 `authorization-server.spec.ts`，完整链路通过；启动约 1.5 s、常驻约 190 MB。
JVM 下不可见的缺口集中在 `SecurityJacksonHints`：Spring Security 按类名发现 Jackson 模块、各模块
mix-in 与反序列化器、存储 JSON 中的类型、WebAuthn API 与请求/响应 DTO、WebAuthn4J 数据类型、本服务
`User` 的非 bean 访问器。WebAuthn 部分与授权服务器无关，任何 WebAuthn 路径的 Native 部署都需要。

