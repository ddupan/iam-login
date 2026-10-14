# WebAuthn 第二因素

WebAuthn 使用 Spring Security 官方过滤器、WebAuthn4J 校验和 JDBC 仓储。
PostgreSQL 保存 user handle、凭据公钥与签名计数等记录，不保存用户密码或认证器私钥。
AD 仍为用户与组权威；凭据按目录 authority + objectGUID 关联，用户名改名不会换主体。

## 登录与注册

1. `/signin` 使用原生表单 POST 验证 AD 密码，建立 `FACTOR_PASSWORD`。
2. `/signin/mfa`：没有凭据时注册 passkey；已有凭据时验证 passkey。
3. 注册只保存凭据，必须再次实际验证，才取得 `FACTOR_WEBAUTHN`。
4. `/signin/complete` 要求两种因素均在 10 分钟内有效；存在被打断的授权请求时恢复该请求（见[内置授权服务器](authorization-server.md)），否则进入账户页 `/account`。

首次注册信任近期 AD 密码验证。已有凭据后的新增注册同时要求密码与 WebAuthn 因素；
本轮 UI 只提供首次注册与验证，不提供新增管理、删除或自助恢复入口。按维护者确认的
自用范围，遗失全部 passkey 由管理员人工操作数据库恢复，不以开发恢复 UI 作为上线条件。
人工恢复只处理核实后的目标主体凭据，并按首次注册规则重新绑定；不能清空整个凭据库。
AD 用户、密码和组继续通过 RSAT 或目录命令行管理，不在本应用增加目录管理页面。
注册和验证均要求认证器 user verification（例如 PIN 或生物识别）。

Spring Security 负责因素合并、会话轮换、退出和 CSRF。应用仅补目录主体与凭据所有权
限制、首次注册并发检查，以及 challenge 的 5 分钟服务端有效期和单次消费。
HTTP session 存在数据库（Spring Session JDBC，属性为 JSON），重启或多副本不丢登录；进行中的 WebAuthn
challenge 不放 session，存于 `webauthn_challenge` 表，session 只持有其 id，消费是一条
`DELETE ... RETURNING`，并发请求中只有一个能取得（options 以 Java 序列化保存，读回只允许 WebAuthn API
与基本 JDK 类型）。
没有应用自建登录状态机或认证 Filter。上游 options Filter 位于授权 Filter 前，因而
这些检查在 RelyingPartyOperations 扩展点执行，不能仅靠 URL 授权规则。

## 账户页

`/account`（`AccountController`）显示 AD 中的账户信息（只读）、本人的 Passkey 与已授权的应用，所有路由与修改都要求
两种因素在 10 分钟内有效，即修改前的重新验证；过期后页面提示重新验证，经 `/signin` 完成后由 `/signin/complete`
回到本页。浏览器链不开请求缓存：表单登录成功时会清除会话中保存的请求，那会丢掉授权服务器链保存的授权请求。

- Passkey：添加走框架的注册端点（已有 Passkey 时同样要求完整验证）；改名 `PUT /account/passkeys/{id}/label`
  （1–64 字符）；删除 `DELETE /account/passkeys/{id}`。语句均按所有者限定，他人的 id 一律 404。
  **至少保留一种两步验证方式**：删除最后一个返回 409 `last`，在注册锁（`CredentialRegistration`）内判断，
  并发删除不能同时通过。框架自带的 `DELETE /webauthn/register/{id}` 没有这条规则，仍关闭。
- 已授权的应用：记住的同意（`oauth2_authorization_consent`）与仍在库中的授权记录（无同意页的客户端只有后者）。
  `DELETE /account/apps/{clientId}` 删除两者，refresh token 立即失效；已签发的 access token 到期前仍有效。

## 本地数据库

```sh
# 密码从 shell 或外部权限为 0600 的 env 文件提供；不要写入版本库。
docker compose -p iam-login-dev -f compose.dev.yaml up -d
```

必须设置 `IAM_DEV_DB_PASSWORD`。PostgreSQL 仅发布在 `127.0.0.1:15432`，可用
`IAM_DEV_DB_PORT` 调整端口；数据保存在 Compose named volume 中。
普通 `down` 不删数据，**不要使用 `down -v`**，否则会删除已注册凭据。

应用额外配置：

```yaml
iam:
  webauthn:
    enabled: true
    rp-id: laptop.tail7e769.ts.net
    origin: https://laptop.tail7e769.ts.net:18082
spring:
  datasource:
    url: jdbc:postgresql://127.0.0.1:15432/iam_login
    username: iam_login
    password: ${IAM_DEV_DB_PASSWORD}
```

同时启用并配置 [AD](ad-login.md)。RP ID 不含协议与端口，origin 必须与浏览器实际
HTTPS 入口完全一致；改变 RP 域名后旧凭据不能直接在新域名使用。
凭据 schema 由 Flyway 管理，采用 Spring Security 7.1.1 官方 PostgreSQL 表结构，
增加主体名称唯一约束和凭据所有者索引。未启用 WebAuthn 时不创建 DataSource，AD-only
路径不需要数据库。数据库不可用时 MFA 失败，不降级为仅密码通过。

## 验证

JVM 回归使用 Testcontainers PostgreSQL 与模拟 AD；不会向真实 AD 提交测试密码。
浏览器用 Chromium 虚拟认证器产生真实注册/断言签名，再交给后端校验：

```sh
scripts/gradle-in-docker test
scripts/gradle-in-docker webauthnBrowserFixture
# 另一终端；测试夹具固定监听 localhost:18083，使用测试证书。
IAM_WEBAUTHN_FIXTURE=1 npm --prefix frontend run test:browser -- webauthn.spec.ts
```

测试专用启动类仅在 test classpath，不进入生产 JAR，也不提供生产调试 API。
维护者已确认开发入口的 AD + passkey 人类路径能够工作。更多认证器兼容性和 Native 路径
仍需独立验收，不能套用虚拟认证器结果。生产共享 PostgreSQL 的接入留在部署阶段。

## 数据源与注册事务

PostgreSQL 是应用运行依赖，通过 `spring.datasource.*` 配置，连接池参数使用
`spring.datasource.hikari.*`。DataSource、JdbcTemplate 与事务管理器由 Boot 自动配置，
WebAuthn 配置仅装配官方凭据仓储及认证策略；不在应用配置中排除 DataSource 自动配置。
仅不涉及持久化的独立测试显式排除它。

首次注册的数据库锁由 `authentication/infrastructure/persistence/CredentialRegistration`
封装；获得用户行锁后，在同一事务中重新检查注册策略并调用官方凭据保存逻辑。
WebAuthn 策略集成不直接引用 SQL 或表结构。失败回滚与跨连接串行化由 PostgreSQL 集成测试覆盖。
