# 首轮 Native 验证范围

本页定义验收要求，不表示下列功能已实现或测试通过。MFA 首先验证 Spring 官方
WebAuthn 集成；TOTP 已实现（见 [第二因素](webauthn.md)），不提供恢复码，遗失全部第二因素由管理员重置。

## 认证与身份

- 使用隔离 LDAP 测试夹具验证正确密码、错误密码、未知及禁用用户；随后验证 Samba AD
  的真实 schema、LDAPS 信任和组查询，不把通用 LDAP 测试等同于 AD 验收。
- 用户与组以 AD 为权威，直接映射；不把框架 ROLE_ 前缀或大小写转换泄露到 groups claim。
- LDAP 与 MFA 必须绑定同一个稳定主体；仅完成密码不得取得授权码。
- 验证 MFA 注册授权、challenge 过期与重放、其他用户凭据、重启后的持久化，以及恢复。
- subject 由本服务签发，与旧 Go 适配器/Authelia 的 issuer/sub 不同，且决定不沿用旧值；切换时各应用
  按自己的账号关联方式重新关联一次（sub 关联的应用重新关联，按用户名或邮箱关联的无需处理）。

## 授权服务器

- 原生二进制完成授权码 + PKCE、userinfo、refresh 与 RP-Initiated Logout，再验证现有 Gitea 账号及权限。
- 业务日志不得包含密码、MFA secret、token 或授权码。
- 存储的客户端与授权以 JSON 读回，所需反射元数据集中在 `SecurityJacksonHints`（见下文）。

日常迭代以 JVM 测试为准，不要求每轮执行 Native 编译。Native 验证安排在阶段性验收
或新增反射、JNDI、TLS 等兼容性风险时集中进行；记录尚未覆盖的新路径。

## Native 与监控

- CI 构建 Native 产物并对该产物执行集成测试；测试报告区分 JVM 与 Native。
- 登录 Controller 与安全链使用 `@ConditionalOnProperty(iam.ad.enabled)`；AOT 在构建时
  决定 bean 是否存在。AD Native 产物必须在 AOT 阶段启用此属性，验证实际入口与兜底链，
  不能假设运行时修改属性会重新装配 bean。本轮只验证 JVM，尚未验收该 Native 路径。
- WebAuthn 新增的 JDBC/Flyway/PostgreSQL、WebAuthn4J 校验与 JSON 路径本轮仅做 JVM 验证；
  Native AOT 时还需启用 `iam.webauthn.enabled`，不得套用基础骨架的 Native 结论。
- 最终运行镜像无需 JRE，不允许以回退 JVM 的方式令 Native 验收通过。
- LDAP、MFA、数据库、TLS、JSON 和授权服务器全部在 Native 中执行。
- 纳入 Actuator、Micrometer Prometheus 与 OpenTelemetry/分布式追踪；实际发起请求后
  检查计数器、耗时分布与 trace 导出，确保 trace 属性不记录认证凭据或 challenge。
- 记录镜像大小、启动时间、空闲与负载下内存、CPU、关键请求延迟；资源预算依据实测确认。
- 将应用指标与 Native 运行时指标区分，不能假设 HotSpot JVM 仪表盘完整适用。

## 发布条件

2026-10-04 已切换到生产；Hydra 与 Authelia 已退役，不再保留回退路径。应用镜像以 commit tag 交给
homelab-infra。上文的监控项（指标采集、trace 导出）与资源/延迟测量尚未完成，跟踪见路线图 #84。

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

