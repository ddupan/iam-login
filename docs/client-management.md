# OAuth2/OIDC 客户端管理

本服务通过受限 API 管理 Hydra 中的第一方 confidential authorization-code 客户端。
领域层定义 `ClientRepository`，基础设施的 `HydraClientRepository` 实现远端持久化。
API 是主要交付物（为 IaC 等自动化准备）；`/console` 管理界面只是调用同一 API 的前端应用。

## 鉴权：只认 bearer token

`/api/iam/**` 是 OAuth2 resource server，只接受 Hydra 签发的 access token：
通过 Hydra Admin introspection 校验（`active`、`token_use=access_token`），并要求 scope
`iam.clients.manage`。浏览器 session、cookie 与 CSRF 都不是 API 凭据；已完成 MFA 的管理员
session 直接调用 API 同样返回 401。不支持 refresh token 调用。

**谁能拿到这个 scope，只在授权确认（consent）一处决定**，见 `AuthorizationPolicy`：

- 只有 `iam.clients.admin-ui-client-id` 配置的客户端可以申请该 scope，普通应用申请会被拒绝；
- 只发给直接属于 `iam.clients.admin-group-dns` 的用户（完整 DN 匹配，不展开嵌套组，
  组成员来自本次目录登录快照）；非管理员在授权确认页即被拒绝；
- 人类仍需经过 AD 密码 + passkey，consent 规则不绕过登录。

```yaml
iam:
  clients:
    admin-group-dns:
      - CN=IAM Administrators,CN=Users,DC=example,DC=test
    admin-ui-client-id: iam-admin-ui
```

未配置 `admin-ui-client-id` 时该 scope 不存在、`/console` 不提供，API 实际不可用（fail closed）。
以后自动化（Terraform、平台其他组件）如何获取带该 scope 的 token 是独立决策；只要 token
由 Hydra 签发并带有该 scope，API 行为不变。

## 接口

| 方法与路径 | 行为 |
| --- | --- |
| GET `/api/iam/clients?page=0&size=20` | 返回 Hydra 分页内支持的客户端，size 1–100 |
| POST `/api/iam/clients` | 创建，201 返回 `{client, secret}`，密钥仅此次返回 |
| GET `/api/iam/clients/{id}` | 查询，不返回密钥 |
| PUT `/api/iam/clients/{id}` | 替换可管理字段，保留现有密钥 |
| DELETE `/api/iam/clients/{id}` | 删除，204 |
| POST `/api/iam/clients/{id}/secret` | 轮换，200 返回 `{secret}`，**旧密钥立即失效** |

匿名或 token 无效返回 401，scope 不足返回 403；输入无效 400，不存在 404，ID 冲突或
非本服务可管理的客户端类型 409，Hydra 不可用 502。含密钥的响应带 `Cache-Control: no-store`。
成功变更记录 action、client ID 和 token 的 subject，不记录密钥。

POST/PUT 请求示例（PUT 的 id 必须等于路径）：

```json
{
  "id": "example-app",
  "name": "示例应用",
  "redirectUris": ["https://app.example.test/oidc/callback"],
  "scopes": ["openid", "profile", "email", "groups"],
  "postLogoutRedirectUris": ["https://app.example.test/logged-out"],
  "backchannelLogoutUri": "https://app.example.test/oidc/backchannel-logout",
  "frontchannelLogoutUri": "",
  "loginEnabled": true
}
```

回调必须 HTTPS（隔离开发允许 loopback HTTP），不允许通配符、fragment 或 URL 用户信息。
本轮固定 `authorization_code`、`code`、`client_secret_basic`、public subject；scope 限于上述
四项且要求 openid。不接收任意 Hydra 字段、密钥、签名配置或授权类型，也没有通用 Admin API
代理。不要为并不支持注销协议的应用登记虚构的端点。

### 密钥轮换

Hydra v26.2.0（当前最新正式版）没有 `/admin/clients/{id}/secrets/rotate`：该接口 2026-07-16
才合入 master，尚无发布版本。目前由本服务生成 32 字节随机密钥并以 PUT 写回，属于硬切换，
应用需同步更新。待 Hydra 发布原生轮换（支持新旧密钥并存），只需替换
`HydraClientRepository.rotateSecret`，API 不变。

## `/console` 管理界面

`/console` 是 Hydra 的普通 **public** OIDC 客户端（授权码 + PKCE，无 secret），与本服务同源
部署但不享有任何特权：页面外壳不含数据，所有数据经上面的 bearer API 获取。access token
只保存在内存中，刷新页面即重新登录；不申请 refresh token，过期后提示重新登录。

部署前提（基础设施负责）：

- 在 Hydra 登记该客户端：`token_endpoint_auth_method=none`，grant `authorization_code`，
  scope `openid iam.clients.manage`，redirect `https://<本服务>/console/callback`，
  metadata `iam_login_enabled=true`。它不是 confidential 客户端，因此不出现在本 API 的列表中，
  也无法经本 API 删除自身；登记与恢复走 Hydra Admin 带外通道。
- Hydra public 端口开启 CORS 并只允许本服务 origin：浏览器直接向 Hydra 换取 token。
  页面 CSP 的 `connect-src` 仅额外放行 issuer origin。

路径用 `/console` 而非 `/admin`，避免同源部署时与"不发布 Hydra `/admin/**`"的路由规则混淆。

## 存储与范围

客户端与生成的 secret 由 Hydra 持久化；本服务不复制或缓存它们。集成测试验证创建、
重启后读取、更新后原密钥仍能认证、轮换后旧密钥被拒且新密钥可认证、删除。测试 PostgreSQL
完全独立于真实开发 MFA 库。

列表按 Hydra 原始分页过滤不支持的授权类型，空页不表示之后必无客户端；本接口不是已有
全部 Hydra 客户端类型的迁移工具。禁用写入 Hydra metadata，后续授权即时重读并拒绝，
已签发 token 的生命周期另由 issuer 和应用控制。
