# 内置授权服务器

本服务可在进程内使用 Spring Security 7 的授权服务器（原 Spring Authorization Server，已并入
Spring Security）签发 OAuth 2.0 / OIDC token，替代 Hydra。由 `iam.authorization-server.enabled`
开启，**默认关闭**。原 Hydra 方案存档于 `archive/hydra` 分支。迁移决策与技术验证见
wiki《独立 IAM 草案》“决策：以 Spring Authorization Server 替换 Hydra”。

## 配置

```yaml
iam:
  authorization-server:
    enabled: true
    issuer: https://auth.example.test
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

- `sub` 由本服务签发：账号首次登录时生成随机 UUID，存在 `subjects` 表，之后不变、不复用。账号
  （目录 authority + 目录内不可变 ID，如 AD objectGUID）只是关联到它，所以改名不变；不在 AD 的账号、
  以及将来离开 AD，都沿用同一个 subject。从旧 issuer 迁移来的 subject 在迁移时作为普通行插入一次。
- `profile`、`email`、`groups` 按授予的 scope 释放（ID token 与 UserInfo）；`groups` 同时进入 access token。
- `offline_access`：客户端须登记 `refresh_token` 授权类型。框架默认**复用** refresh token，客户端须设置
  `reuseRefreshTokens(false)` 以轮换。
- refresh 前重新检查账号仍有 subject；删除该行即撤销身份，拒绝续期。
- device 授权（RFC 8628，客户端登记 `deviceAuthorization`）：`verification_uri` 是 `/signin/device`。未完成两步验证的访问者
  先去登录，登录后带着代码回到该页；代码交给框架的 `/oauth2/device_verification`，授权确认页与授权码流程共用
  （表单改为提交到 device 端点）。结果回到 `/signin/device?result=done|invalid|denied`。
  - 框架拒绝 device 请求里的 `openid`；OIDC 客户端（如 Incus）会带上它，OIDC 与 RFC 8628 都不禁止。先去掉 `openid`
    交给框架校验与签发，再把它放回请求的 scope：确认页显示它，access token 带上它（userinfo 需要）。仍不签发 ID token。
  - device 验证端点在因素不足时不会把请求交还登录流程（会当作成功），所以这里因素不足即拒绝（`access_denied`）；
    正常路径由 `/signin/device` 先完成登录。
- 框架默认对所有客户端强制 PKCE；不发送 PKCE 的旧 RP 由客户端管理 API 的 `pkceRequired: false` 关闭（见[客户端管理](client-management.md)）。
- `request` 参数返回 `request_not_supported`；`request_uri` 按 PAR 处理，未知引用 400 且不跳转。
  discovery 声明支持的 scope、claims，并明确不支持 request、request_uri、claims 参数。
- 授权记录 token 列使用 hash 索引；`ExpiredAuthorizations` 定时删除所有 token 均已过期的记录，
  等待 consent 的记录保留。

## 尚未实现

- 授权确认页为本服务页面 `/signin/consent`（`ConsentController`，要求完整 MFA），以白话列出请求的权限，允许提交
  全部请求的 scope（含 openid，空授权即拒绝），拒绝不提交 scope。其 CSP 的 `form-action` 额外放行该客户端回调
  的 origin：浏览器对表单提交后的跨域重定向同样执行 `form-action`，否则「允许」后无法回到应用。
- 前/后通道注销（框架仅支持 RP-Initiated Logout）。
- `acr`、`claims` 请求参数、userinfo 请求体携带 access token。
- `profile`/`email` 声明目前放在 ID token；OIDC Core 5.4 建议签发 access token 时经 userinfo 返回（一致性测试为警告）。

## 验证

- JVM：`AuthorizationServerIntegrationTests`（MFA、prompt/max_age、request object、discovery、
  密钥与清理）、`RefreshPolicyTests`、`SigningKeysTests`。
- 浏览器：`authorizationServerBrowserFixture` + `authorization-server.spec.ts`（真实虚拟认证器）。
- OpenID 一致性测试（release-v5.3.1，Basic OP，discovery + static client，2026-10-02）：1733 条件通过、
  0 失败、6 警告；`prompt=login`、`max_age=1`、非法 redirect_uri 等模块按套件要求待人工截图审查。
- Native 的过程见 [Native 验证](native-validation.md)。一致性测试套件自带的
  HtmlUnit 无法执行 ES module 登录页或 WebAuthn，用 `frontend/tests/conformance/driver.mjs`
  （Playwright）驱动其浏览器步骤，配合 `conformanceFixture`。
