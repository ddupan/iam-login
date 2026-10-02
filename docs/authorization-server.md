# 内置授权服务器

本服务可在进程内使用 Spring Security 7 的授权服务器（原 Spring Authorization Server，已并入
Spring Security）签发 OAuth 2.0 / OIDC token，替代 Hydra。由 `iam.authorization-server.enabled`
开启，**默认关闭**，与 `iam.hydra.enabled` 互斥（同时开启拒绝启动）。迁移决策与技术验证见
wiki《独立 IAM 草案》“决策：以 Spring Authorization Server 替换 Hydra”。

## 配置

```yaml
iam:
  authorization-server:
    enabled: true
    issuer: https://auth.example.test
    subjects:                      # 与 Hydra 模式相同的显式 subject 绑定，保持下游账号关联
      - authority: example.test
        directory-id: 00112233-4455-6677-8899-aabbccddeeff
        subject: human:existing-subject
    signing-keys:                  # 由基础设施提供；首个签名，其余仅发布公钥
      - file:/run/secrets/iam/signing-key-2026-10.pem
      - file:/run/secrets/iam/signing-key-2026-07.pem
    cleanup-interval: PT1H         # 过期授权记录清理间隔（默认 1 小时）
```

同时需要启用 AD 与 WebAuthn（`iam.ad.*`、`iam.webauthn.*`）及 PostgreSQL；授权服务器的表由
Flyway `V2__authorization_server.sql` 创建（未开启时表为空，不影响其他模式）。

### 签名密钥

- PKCS#8 PEM RSA 私钥（`-----BEGIN PRIVATE KEY-----`），至少 2048 位；本服务不生成也不存储密钥。
  缺失、格式不符或过短时拒绝启动。生成：`openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`。
- 首个密钥签名，全部密钥在 `/oauth2/jwks` 发布公钥。`kid` 为 RFC 7638 指纹，重启不变。
- 轮换：把新密钥放到列表首位并部署；等旧密钥签发的 token（含 ID token）全部过期后移除旧密钥。

## 认证要求

授权端点要求十分钟内的 AD 密码与 passkey 两个因素，仅密码不能取得授权码。两层保护：

1. `/oauth2/authorize` 的访问规则要求完整 MFA，缺因素时转到对应页面；完成后经 Spring Security
   保存的请求恢复原授权请求（passkey 登录响应的 `redirectUrl`）。框架的授权端点过滤器位于
   访问规则之后。
2. 端点内的 `MfaGate` 位于框架 provider 之前，作为第二道检查。

`prompt=none` 不允许交互，访问规则放行此类请求；MFA 不完整的主体在请求转换阶段即转为匿名，
由框架在校验客户端与 `redirect_uri` 之后返回 `login_required`。此时 `MfaGate` 是唯一检查，
若仍见到带认证但缺因素的主体则失败即拒绝。注意：在 `ProviderManager` 中的 provider 抛出普通
`AuthenticationException` 时，会用原请求继续尝试下一个 provider，因此不能在 gate 内调用框架
provider 再抛错。

`prompt=login` 与 `max_age`：框架不处理。`Reauthentication` 过滤器在会话中按请求记录要求重新
认证的时刻并清除当前认证（会话、保存的请求与标记保留）；之后签发的因素满足要求，ID token 的
`auth_time`（最近因素时间）随之更新。

## Token 与策略

- `sub` 按显式绑定沿用现役值；`profile`、`email`、`groups` 按授予的 scope 释放；`groups` 同时进入
  access token。
- `offline_access`：客户端须登记 `refresh_token` 授权类型。框架默认**复用** refresh token，客户端须设置
  `reuseRefreshTokens(false)` 以轮换。
- refresh 前重新检查 subject 绑定，绑定撤销后拒绝续期。
- 框架默认对所有客户端强制 PKCE；不发送 PKCE 的旧 RP 须按客户端设置 `requireProofKey(false)`。
- `request` 参数返回 `request_not_supported`；`request_uri` 按 PAR 处理，未知引用 400 且不跳转。
  discovery 声明支持的 scope、claims，并明确不支持 request、request_uri、claims 参数。
- 授权记录 token 列使用 hash 索引；`ExpiredAuthorizations` 定时删除所有 token 均已过期的记录，
  等待 consent 的记录保留。

## 尚未实现

- 授权确认页仍为框架默认页面（英文、无本服务样式）。
- 客户端管理 API 仍只面向 Hydra；授权服务器模式下客户端通过 `RegisteredClientRepository` 管理。
- 前/后通道注销（框架仅支持 RP-Initiated Logout）。
- `acr`、`claims` 请求参数、userinfo 请求体携带 access token。

## 验证

- JVM：`AuthorizationServerIntegrationTests`（MFA、prompt/max_age、request object、discovery、
  密钥与清理）、`RefreshPolicyTests`、`SigningKeysTests`。
- 浏览器：`authorizationServerBrowserFixture` + `authorization-server.spec.ts`（真实虚拟认证器）。
- Native 与 OpenID 一致性测试的过程见 [Native 验证](native-validation.md)。一致性测试套件自带的
  HtmlUnit 无法执行 ES module 登录页或 WebAuthn，用 `frontend/tests/conformance/driver.mjs`
  （Playwright）驱动其浏览器步骤，配合 `conformanceFixture`。
