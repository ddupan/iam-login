# WebAuthn 第二因素

WebAuthn 使用 Spring Security 官方过滤器、WebAuthn4J 校验和 JDBC 仓储。
PostgreSQL 保存 user handle、凭据公钥与签名计数等记录，不保存用户密码或认证器私钥。
AD 仍为用户与组权威；凭据按目录 authority + objectGUID 关联，用户名改名不会换主体。

## 登录与注册

1. `/signin` 使用原生表单 POST 验证 AD 密码，建立 `FACTOR_PASSWORD`。
2. `/signin/mfa`：没有凭据时注册 passkey；已有凭据时验证 passkey。
3. 注册只保存凭据，必须再次实际验证，才取得 `FACTOR_WEBAUTHN`。
4. `/signin/complete` 要求两种因素均在 10 分钟内有效；目前仅显示验证结果，尚不接受 Hydra challenge。

首次注册信任近期 AD 密码验证。已有凭据后的新增注册同时要求密码与 WebAuthn 因素；
本轮 UI 只提供首次注册与验证，不提供新增管理、删除或自助恢复入口。遗失所有 passkey
尚无自助登录途径；生产上线前需要另行确定恢复和初始注册政策，不能把数据库清空作为日常恢复方式。
注册和验证均要求认证器 user verification（例如 PIN 或生物识别）。

Spring Security 负责因素合并、会话轮换、退出和 CSRF。应用仅补目录主体与凭据所有权
限制、首次注册并发检查，以及 challenge 的 5 分钟服务端有效期和单次消费。
没有应用自建登录状态机或认证 Filter。上游 options Filter 位于授权 Filter 前，因而
这些检查在 RelyingPartyOperations 扩展点执行，不能仅靠 URL 授权规则。

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
真实用户的 passkey 注册、认证器兼容性和 Native 路径仍需独立验收；JVM/虚拟认证器通过
不能代替真实人类或 Native 验收。生产共享 PostgreSQL 的接入留在部署阶段。
