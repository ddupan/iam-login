# Passkey 与验证器 App

WebAuthn 使用 Spring Security 官方过滤器、WebAuthn4J 校验和 JDBC 仓储。
PostgreSQL 保存 user handle、凭据公钥与签名计数等记录，不保存用户密码或认证器私钥。
AD 仍为用户与组权威；凭据按目录 authority + objectGUID 关联，用户名改名不会换主体。

## 登录与注册

1. `/signin` 使用原生表单 POST 验证 AD 密码，建立 `FACTOR_PASSWORD`。
2. `/signin/mfa`：还没有第二因素时任选一种设置（Passkey 或验证器 App）；已有时验证。两种都有时先用
   Passkey，`?method=totp` 切换到验证码。
3. Passkey 注册只保存凭据，必须再次实际验证，才取得 `FACTOR_WEBAUTHN`；验证器 App 设置时输入的验证码即
   是实际验证，确认后直接取得 `FACTOR_TOTP`。
4. `/signin/complete` 要求完整登录在 10 分钟内：密码加任一第二因素（`FACTOR_WEBAUTHN` 或 `FACTOR_TOTP`），
   或单独一个 `FACTOR_WEBAUTHN`（见下）。存在被打断的授权请求时恢复该请求（见[内置授权服务器](authorization-server.md)），否则进入账户页 `/account`。

### 无密码登录

`/signin` 的“使用 Passkey 登录”不需要先输入密码：一次 Passkey 验证就是完整登录。注册和验证都要求 user
verification，服务端按 options 校验 UV 标志，所以一次验证本身就包含持有设备与 PIN/生物识别两个因素；
验证器 App 的验证码始终只作为密码之后的第二步。

同一组端点（`/webauthn/authenticate/options`、`/login/webauthn`）按会话分两种情况（`MfaPolicy.secondStep`，
`DirectoryRelyingPartyOperations`）：

- 会话里有 10 分钟内的密码：第二步。options 只列出该账号的 Passkey，断言必须属于该账号。
- 否则：无密码登录。options 不列出凭据（discoverable），由浏览器给出本站的 Passkey；验签后按凭据记录的
  `authority:objectGUID` 以服务账号读 AD，账号不存在或已禁用即失败。challenge 记为不属于任何账号
  （`SessionChallenges.PASSWORDLESS`）。换成另一个人的 Passkey 时，框架只替换认证、不合并因素
  （按用户名判断是否同一人）。

改密码不影响 Passkey 登录；但改密码之前建立的会话，无论用哪种方式登录，都要重新登录（`ActiveAccount`，
比较的是最近一次密码或 Passkey 因素）。

首次注册信任近期 AD 密码验证。已有因素后的新增注册要求完整登录（密码加第二因素，或单独 Passkey），均在 10 分钟内；
新增和删除在账户页自助完成，不提供恢复码。按维护者确认的
自用范围，遗失全部第二因素由管理员重置（管理控制台实现之前人工操作数据库），不以开发恢复 UI 作为上线条件。
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

## 验证器 App（TOTP）

RFC 6238，取所有验证器 App 都支持的参数：HMAC-SHA1、6 位、30 秒，前后各容许一个时间步的时钟偏差。
Spring Security 没有 TOTP 支持；验证码由框架通用的 `AuthenticationFilter`（开启 MFA 合并）交给
`TotpAuthenticationProvider`，因素合并与会话轮换仍由框架完成，应用只做算法与存储。

- 设置：`GET /signin/totp/setup` 生成 160 位密钥，暂存 session（`iam.totp.pending`），页面给出二维码与手输密钥；
  `POST /signin/totp/setup` 的验证码匹配后才保存。前提与新增 Passkey 相同：近期密码，已有第二因素时还要完整验证。
  再次设置（换手机）替换原密钥，每个账户最多一个。
- 验证：`POST /signin/totp`。每个账户记录已接受的最新时间步（`last_step`），同一时间步或更早的验证码一律拒绝，
  验证码不能重放；条件更新保证并发提交只有一个成功。失败与密码共用 `iam.signin.throttle` 的上限（计数独立）。
- 存储：`totp_credentials`，密钥以 AES-GCM 加密，密钥材料为 `iam.totp.key`（32 字节随机数，base64）。
  只拿到数据库不能生成验证码；更换或丢失 `iam.totp.key` 会让所有已设置的验证器 App 失效。
  `iam.totp.issuer` 是验证器 App 中显示的发行方名称（默认 `IAM Login`）。

## 账户页

`/account`（`AccountController`）显示 AD 中的账户信息（只读）、本人的 Passkey、验证器 App 与已授权的应用，所有路由与修改都要求
两种因素在 10 分钟内有效，即修改前的重新验证；过期后页面提示重新验证，经 `/signin` 完成后由 `/signin/complete`
回到本页。浏览器链不开请求缓存：表单登录成功时会清除会话中保存的请求，那会丢掉授权服务器链保存的授权请求。

- Passkey：添加走框架的注册端点（已有 Passkey 时同样要求完整验证）；改名 `PUT /account/passkeys/{id}/label`
  （1–64 字符）；删除 `DELETE /account/passkeys/{id}`。语句均按所有者限定，他人的 id 一律 404。
  删除成功后，本人的其他会话全部结束，当前会话保留（可能正是丢失的设备登录的）。
  **至少保留一种两步验证方式**（Passkey 与验证器 App 合计）：删除最后一个返回 409 `last`，在注册锁
  （`CredentialRegistration`）内判断，并发删除不能同时通过。框架自带的 `DELETE /webauthn/register/{id}` 没有这条规则，仍关闭。
- 验证器 App：设置或「换一台手机」走 `/signin/totp/setup`；删除 `DELETE /account/authenticator`，同样受上面的规则约束。
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
  totp:
    key: ${IAM_TOTP_KEY}   # openssl rand -base64 32；不要写入版本库
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
# 跳过测试 AOT：processTestAot 会因 LDAP 夹具的非守护线程挂住，夹具永远起不来。
scripts/gradle-in-docker webauthnBrowserFixture -x processTestAot -x compileAotTestJava -x processAotTestResources
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

第二因素变更的数据库锁由 `authentication/infrastructure/persistence/CredentialRegistration`
封装：按主体名称取事务级 advisory lock（只有验证器 App 的账户没有 WebAuthn 用户行可锁），在同一事务中
重新检查注册策略并调用官方凭据保存逻辑或删除。
WebAuthn 策略集成不直接引用 SQL 或表结构。失败回滚与跨连接串行化由 PostgreSQL 集成测试覆盖。
