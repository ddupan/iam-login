# AD 第一因素接入

`/signin` 接收 AD 用户名（sAMAccountName）或本域 UPN，通过 Spring LDAP `ContextSource.getContext` 以用户身份执行 LDAPS bind，
随后由 Spring Data LDAP 仓储复用这条已认证连接查询用户与组。
不使用额外目录服务账号，不写入 AD，不复制 Authelia 的绑定密码。

领域仓储接口为 `UserRepository`，`User` 为领域模型。`VerifyPassword` 应用用例以
try-with-resources 管理已认证用户仓储会话；基础设施的 `AdUserRepository` 通过
`SimpleLdapRepository<AdUserEntry>`、`LdapTemplate`、ODM 实现读取与转换，关闭后不可继续查询。
`AdUserEntry` 的 LDAP 注解不会进入领域对象。

成功后重定向到 `/signin/mfa`，显示目录账号、objectGUID、邮箱、直接所属组及组 DN。
**密码成功本身不是完整登录成功。** Spring Security 先保存仅含 `FACTOR_PASSWORD`
的认证结果；启用 [WebAuthn](webauthn.md) 后在此继续第二因素，否则停留在等待页面。
未实现的应用请求使用 `denyAll`，
不替换现役 Go/Authelia/Gitea 登录链路。

## 目录和组语义

- AD 是身份和组权威。objectGUID 按 AD 混合字节序解析为标准 UUID，作为目录稳定键；
  不是 OIDC `sub`；`sub` 由显式 subject 绑定决定，以保持现役账号关联。
- 从 `memberOf` 读取直接成员关系，保留原始 DN；CN 保留大小写，不添加 `ROLE_`，
  不把 Spring 的 `FACTOR_PASSWORD` 当作组。结果排序，不做应用专用组改写。
- 此轮不展开嵌套组、不推导 primaryGroupID，也不宣称与 Authelia 的有效组集合完全一致。
  遇到 ranged memberOf 或不同 DN 同名 CN 拒绝映射，不静默丢组或合并不同主体。
- AD bind 执行密码及账号状态检查；基础设施层将禁用、锁定、密码过期等 AD 子码转换为
  应用层认证失败原因，不向领域层泄露 LDAP/Spring 异常。
  搜索排除 computer 对象，只接受唯一用户条目和合法 objectGUID/sAMAccountName。
- 邮箱作为目录属性展示，不声称 `email_verified=true`。

## 启用

`iam.ad.enabled=true` 时才装配登录 Controller 与浏览器安全链（含 formLogin）。
未启用时入口由兜底安全链拒绝，匿名 GET 返回 401；不注册密码处理端点。

正常 JVM 构建：

```sh
IAM_DOCKER_USE_SUDO=1 scripts/gradle-in-docker test bootJar
```

Gradle 与 npm 缓存默认持久挂载，可用 `IAM_GRADLE_CACHE`、`IAM_NPM_CACHE` 指定目录。
日常迭代不必每轮跑 Native；新增 AD/JNDI/TLS 路径的原生验收留到阶段性验证。

运行时配置（非秘密）：

```yaml
iam:
  ad:
    enabled: true
    url: ldaps://dc1.ad.ddupan.top:636
    domain: ad.ddupan.top
    base-dn: DC=ad,DC=ddupan,DC=top
server:
  port: 18082
  ssl:
    enabled: true
    certificate: file:/run/iam/browser.crt
    certificate-private-key: file:/run/iam/browser.key
  servlet:
    session:
      cookie:
        secure: true
        same-site: lax
```

证书与私钥使用外部受管文件，不加入仓库。开发验收可使用本机的 Tailscale HTTPS 域名
及相应证书；用匹配证书的主机名打开，不能用 LAN IP 替代域名后跳过警告。
部署与证书自动续期归 homelab-infra，此轮本地运行不是生产部署。

LDAPS 使用默认 JSSE 信任库并执行服务端域名校验。Samba 当前证书由 OpenBao 内部 CA
签发，需把**公开 CA** 加入运行用 truststore，并通过 JVM 参数指定：

```sh
java -Djavax.net.ssl.trustStore=/run/iam/truststore \
  -Djavax.net.ssl.trustStorePassword=changeit -jar iam-login.jar
```

这里 truststore 仅含公开信任锚，口令不是目录密码。保留所需公共根证书；不得禁用
LDAP endpoint identification 或用信任所有证书的 socket factory。连接/读取超时为 3/5 秒。
AD 根范围查询可能返回 DomainDnsZones/ForestDnsZones 等分区 referral；配置为 ignore，
由仓储的 LdapTemplate 忽略 partial result，不使用 throw 打断用户查询，也不 follow 转发用户凭据。

浏览器安全链通过 Spring Security `redirectToHttps` 将明文请求重定向至 HTTPS，
重定向前不执行密码验证或退出。默认不信任转发头。若以后由代理终结 TLS，
必须配合仅受信代理可达的后端网络和转发头配置，不能公开一个信任任意 forwarded header
的 HTTP 端口。当前开发验收由应用直接终结 TLS。

## 状态与操作

React 只渲染登录页面与待 MFA 页面，原生表单 POST 由 Spring Security `formLogin`
接收。`DirectoryAuthenticationProvider` 调用目录用例并返回不含密码的 principal 和
带签发时间的 `FACTOR_PASSWORD`；目录组只保留在身份快照中，不映射为本服务权限。
框架负责 CSRF、成功/失败跳转、SecurityContext 持久化、session ID 轮换以及 POST logout。
`/signin/restart` 是框架 logout 地址；不再维护 LoginTransaction 或另一份浏览器认证状态。

待 MFA 页通过框架的 `validDuration` 要求密码因素在十分钟内完成，过期后需要重新认证。
这不是完整登录会话的过期策略；签发 token 另须 passkey 因素（见 [WebAuthn](webauthn.md)）。
`/actuator/**` 使用独立无状态 Basic 安全链，人类密码因素不能用于读取监控端点，
监控账号也不能借 Basic 进入人类登录流程。

移除原来事务内的两秒提交间隔；它不是有效的账号/IP 限流。此 PoC 仍仅供受控
LAN/Tailscale 验收，生产发布前需完善入口限流、审计与恢复策略。
页面禁止缓存，内联 JSON 转义 HTML 结束标记。错误页面只显示统一消息。

基础存活检查使用 `/actuator/health/liveness`。Boot 自动配置的 LDAP 健康项并未连接这里
按用户 bind 创建的仓储连接，不能把该项当作此认证路径的可用性验证。

## 本轮验证边界

隔离测试使用真实 TLS、LDAP bind 和搜索，校验正确/错误密码、未知账号、AD 账号状态
子码、GUID 字节序、组名、错误 TLS 主机名、CSRF、HTTPS、会话轮换、因素过期和密码成功后
仍不能访问受保护应用入口。UnboundID 的 UPN bind 与 AD 子码由测试拦截器模拟，不能替代 Samba AD。
测试证书、私钥与账号全为虚构夹具，不用于实际部署。

2026-09-27：Spring Security 重构通过 18 项 JVM 测试和 `bootJar` 构建，覆盖
密码因素的保存与有效期、会话轮换、退出、未完成 MFA 的访问限制，以及监控安全链隔离。
此前 JVM 使用受信 CA 完成 Samba AD RootDSE 查询。
浏览器已检查登录表单渲染、真实 CSRF 原生 POST 和失败后清空密码；只使用在访问 AD 前
即拒绝的合成外域用户名，不尝试猜测人类密码。浏览器回归共 1 项通过，包含移动端布局。
复现：`IAM_AD_URL=https://验收域名:端口 npm --prefix frontend run test:browser -- ad-login.spec.ts`。
重构前，维护者已在 HTTPS 页面完成真实密码验证，成功到达待 MFA 页面，并反馈目录标识、邮箱与
六个直接所属组的查询结果。该验收覆盖 Samba AD 第一因素与属性读取，不表示 MFA、
嵌套组/主组等价性或经授权服务器的应用登录已完成。Spring Security 重构后的真实人类复验仍待反馈。
不在聊天、命令行或日志中传递人类密码。
新增 AD 路径尚未进行 Native 测试，不能复用旧 UI 原型的 Native 结论。
