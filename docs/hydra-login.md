# Hydra Login/Consent 接入

本实现使用 Hydra 的私有 Admin API，沿用 Spring Security 的 AD + WebAuthn 双因素认证。
OAuth2/OIDC 签发、客户端注册表和客户端密钥由 Hydra 持有。应用只负责身份、授权确认与
Login/Consent 接受，不自行签发 token，也不实现另一套认证状态机。

## 浏览器路径

1. 客户端发起 Hydra authorization code 请求；Hydra 将浏览器带到 `/oauth2/start?login_challenge=...`。
2. 服务端通过 Admin API 核对 client、scope、audience 与 issuer 请求地址，绑定浏览器会话，
   再进入 `/oauth2/login`。该页面由 Spring Security 要求两种因素，未满足时转到密码或 MFA 页。
3. MFA 完成后显示应用和申请范围；用户通过带 CSRF 的原生表单 POST 确认。
4. 服务端重新核对 Hydra 请求，使用显式 subject 绑定接受 login，浏览器返回 Hydra。
5. Hydra 回到 `/oauth2/consent`；服务端核对会话随机值、原始 challenge 摘要、主体、client、
   原始请求 URL 和 scope 后一次性接受 consent；Hydra 将授权码交给客户端。

只为管理员启用的第一方 client 接受 openid/profile/email/groups，不授予 access-token audience、
不申请 offline_access/refresh token。Claims 按请求 scope 释放，组保持直接 AD memberOf 的名称；
AD mail 没有邮箱所有权验证依据，`email_verified=false`。

单个浏览器会话只保存一个未完成请求，10 分钟失效，新请求替换旧请求。认证因素与会话
依然由 Spring Security 管理；`HydraBrowserRequests` 只保存待接受的 issuer 请求及回程关联，
不记录密码、私钥或 token。退出/重启后未完成请求需从应用重新发起。

Hydra v26 的 consent `login_challenge` 是内部标识，不能与浏览器收到的 opaque challenge
逐字比较。本服务在受信任的 login accept `context` 中写入原始 challenge 的 SHA-256 摘要
与会话随机值，在 consent 读回并核对；不解析 Hydra 内部格式。

确认页的 CSP 仅增加当前 Hydra 与已校验回调的 origin，允许原生表单返回 issuer 后跳转；
身份页允许向固定 Hydra origin 完成注销跳转。Hydra 返回的 redirect 必须是已配置公共 origin 下的
`/oauth2/auth`，Admin HTTP client 不跟随重定向，不向浏览器传播上游错误正文。

本轮仅覆盖交互式授权码流，不支持静默 `prompt=none`。
接受 login 时保留 Hydra 登录会话，供统一注销关联应用；会话寿命沿用 Hydra 配置，
不延长已有会话。Hydra 的 `skip` 仅表示 issuer 记得登录，不能绕过 Spring 的有效双因素、
原生表单确认与主体匹配。`prompt=login/consent/select_account` 或 `max_age` 存在时重新验证身份，
不把之前的 MFA 时间改写为新登录时间。不请求上述参数时可复用仍有效的本地双因素会话。

## 配置与主体连续性

先启用 [AD](ad-login.md) 与 [WebAuthn](webauthn.md)，再提供以下配置：

```yaml
iam:
  hydra:
    enabled: true
    admin-url: http://hydra-admin.hydra.svc.cluster.local:4445
    public-url: https://hydra.ad.ddupan.top
    http:
      connect-timeout: 3s
      read-timeout: 5s
    clients: [gitea] # 仅供尚未写入管理标记的旧客户端过渡
    subjects:
      - authority: ad.example.test
        directory-id: 00112233-4455-6677-8899-aabbccddeeff
        subject: human:EXISTING_REVIEWED_SUBJECT
```

以上主体是格式示例，不能用于真实账号。配置中的绑定按 AD authority + objectGUID 匹配，
必须唯一；未绑定用户拒绝授权。不使用用户名、邮箱、自动创建 Gitea 账号或 AD GUID 的新哈希
来替代现有主体。现役 Go 适配器使用 `human:` + SHA-256(Authelia issuer + NUL + sub)，
上线前需要取得并核对该旧主体，建立到 AD 稳定键的显式映射，确认 Gitea 的外部账号关联。
普通改名不改变绑定；删除或修改绑定属于迁移操作，需要单独审查。

Hydra 环境配置需将 login URL 指向 `/oauth2/start`，consent URL 指向 `/oauth2/consent`，
logout URL 指向 `/oauth2/logout`，默认 post-logout URL 指向本服务 `/signin`。
本仓库的实现与测试不等于这些生产设置已变更。Admin URL 可以使用现役受 NetworkPolicy
约束的集群内 HTTP，也可通过 loopback port-forward；不能公开管理端口。
HTTP client 在配置层使用 Boot 提供的 `RestClient.Builder` 装配并注入，保留框架定制与观测能力。
上述连接/读取超时有默认值且必须为正，可按部署环境覆盖；禁止跟随重定向不提供关闭开关。
Login、Consent 和 Logout 共用 `HydraGateway` 与 Admin client。
公共 origin 必须 HTTPS，HTTP 只接受隔离测试的 loopback。客户端请求必须显式带 redirect_uri。

## 客户端注册与管理边界

`clients` 领域模块提供受 Spring Security 保护的 CRUD，调用私有 Hydra Admin API。
Hydra PostgreSQL 是客户端与密钥的唯一持久化来源，不读其内部表、不建第二份注册表。
使用方式和边界见 [客户端管理接口](client-management.md)。

每次 login/consent 都重新读取 client 的 `metadata.iam_login_enabled`；显式 false 拒绝新授权。
仅当标记不存在时使用旧 `iam.hydra.clients` allowlist。通过 API 新增启用的客户端不需要修改
服务配置。禁用不能撤回已签发 token 或已建立的应用会话。公共动态注册入口不在本轮范围，
不能让未信任调用者写入该管理标记。

## 统一注销

RP 使用 Hydra discovery 的 `end_session_endpoint`，携带 ID token hint 与已登记回调。
Hydra 查询其登录会话后回到 `/oauth2/logout`；用户提交有 CSRF 与浏览器请求绑定的确认表单，
服务端重新核对 challenge、主体和登记回调，接受 Hydra logout，并通过 Spring 的
`SecurityContextLogoutHandler` 清除当前本地会话。Hydra 负责通知登记的 front/back-channel
端点并返回应用；不自行遍历客户端发 HTTP 请求。身份页也提供原生表单发起统一退出。

Hydra 会话不存在或已过期时可能直接返回应用，不经过确认页；这不证明 Spring 会话也被清除。
本地退出按钮仍能清除当前 Spring 会话。下游必须实现登记的注销协议，通知失败也不能宣称
应用已退出。统一注销不等于撤销所有已签发 token，不覆盖其他浏览器设备。

## 正式域名规划

正式入口目标为 `https://auth.ddupan.top`，替换现有 Authelia 入口，Hydra 与本服务按路径同源：

- Hydra：discovery/JWKS、`/oauth2/auth`、`/oauth2/token`、`/oauth2/revoke`、
  `/oauth2/sessions/logout`、`/userinfo` 等经核对的 public 端点。
- iam-login：`/signin`、`/signin/**`、`/webauthn/**`、`/login/webauthn`、
  `/oauth2/start`、`/oauth2/login`、`/oauth2/consent`、`/oauth2/logout`、`/api/iam/**` 和静态资源。
- 不把整个 `/oauth2/**` 路径交给 Hydra；不发布 Hydra `/admin/**` 或管理端口。

这是部署计划，不是现网配置。上线前需核对 cookie 名称、受信任代理与 TLS 转发、issuer
变更和应用配置、旧 sub 关联，以及新 WebAuthn RP ID 的凭据注册。不能仅改 DNS 后假定现有
passkey 和 OIDC 会话仍可复用；回退路径也需在基础设施 PR 中明确。

## 隔离验证与生产切换

首轮验收以现有 AD + MFA → Hydra → Gitea 原账号及仓库权限为目标，不以完整 self-service、
目录管理或自动恢复为前置条件。AD 管理与人工 MFA 恢复边界见 [第二因素](webauthn.md)。

```sh
scripts/gradle-in-docker test bootJar
scripts/gradle-in-docker hydraBrowserFixture
# 另一终端，仅连接固定的 loopback 测试夹具：
IAM_HYDRA_FIXTURE=1 npm --prefix frontend run test:browser -- hydra.spec.ts
```

夹具包含模拟 AD、临时 PostgreSQL、固定 digest 的 Hydra v26.2.0，以及测试专用 OAuth client。
Hydra 只监听 127.0.0.1:14444/14445，应用使用测试证书监听 HTTPS localhost:18083；
客户端回调由测试专用 loopback HTTP 服务接收，不在生产 JAR 中加入测试回调或 token 查看入口。
虚拟认证器产生真实 WebAuthn 签名，随后交换授权码，检查 ID token 的 JWKS 签名、issuer、
audience、nonce、有效期、预配置旧 sub、组与邮箱语义，并拒绝授权码重放。
同时验证 remembered login 仍显示授权确认、RP 发起注销、back-channel token 签名与 sid
关联，以及 Spring 会话失效。JVM 集成测试另验证真实 PostgreSQL 上客户端 CRUD、Hydra
重启后记录仍在、更新保留旧密钥与管理接口的 MFA/组/CSRF 拒绝。
这些验证不等于生产 Gitea 账号关联、真实新链路人类操作或 Native 验收。

下一步生产切换仍需完成真实 subject 映射审查、AD/WebAuthn/Hydra Native 验收、部署网络规则，
以及从 Gitea 返回原账号与原仓库权限的实际验收。现役 Go/Authelia 登录入口继续作为已验收路径。

上游接口依据：[Hydra Login/Consent](https://www.ory.com/docs/oauth2-oidc/custom-login-consent/flow)、
[客户端管理能力](https://www.ory.com/hydra)。
