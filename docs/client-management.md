# OAuth2/OIDC 客户端管理

本服务通过受限 API 管理 Hydra 中的第一方 confidential authorization-code 客户端。
领域层定义 `ClientRepository`，基础设施的 `HydraClientRepository` 实现远端持久化。
API 是主要交付物（为 IaC 等自动化准备）；`/console` 管理界面只是调用同一 API 的前端应用。

## 鉴权：经典的 audience + groups 模型

scope 是委托，不是权限。本 API 和任何下游应用一样，是普通的 resource server：

1. 只接受 Hydra 签发的 bearer access token，经 Admin introspection 校验（`active`、
   `token_use=access_token`）。浏览器 session、cookie 与 CSRF 都不是 API 凭据。
2. **audience**：token 的 `aud` 必须包含 `iam-login`。签给其他应用的 token（例如管理员登录
   Gitea 时 Gitea 拿到的 token）即使带着管理员组也被拒绝，否则每个接入应用都能冒用用户管理 IAM。
   哪些客户端能申请该 audience 由 Hydra 按客户端登记的 `audience` 白名单执行。
3. **groups**：客户端申请 `groups` scope 时，consent 把用户的直接 AD 组名同时写入 ID token 和
   access token（introspection 的 `ext.groups`）。API 要求其中有 `iam.clients.admin-groups` 之一。

匿名、token 无效返回 401；audience 不符或不是管理员返回 403。

```yaml
iam:
  clients:
    admin-groups:
      - Domain Admins
    admin-ui-client-id: iam-admin-ui
```

按组名匹配，与下游应用看到的 `groups` 一致；组名取 memberOf DN 的 CN，只含直接组。同一
用户若有两个同名直接组，登录直接失败；他处的同名组需要 AD 建组权限才能伪造。组成员是登录时
的快照，移出管理组后最长在 access token 有效期（Hydra 当前 15 分钟）内仍可调用。

consent 不按用户筛选 scope 或 audience：两者已由 Hydra 限定在客户端登记范围内，consent 只
释放身份事实，权限由各资源自行判断。以后自动化调用方（无人类用户）如何取得 token、按何种
主体授权，另行设计；本 API 的 audience 检查不变。

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
本轮固定 `authorization_code`、`code`、`client_secret_basic`、public subject。scope 可为任意
符合 RFC 6749 的 scope-token（最多 50 个），必须含 `openid`；scope 不代表权限，所以不设白名单。
`profile`/`email`/`groups` 决定 consent 释放哪些声明，其余 scope 原样授予。登记 audience 尚未
开放（当前只有带外登记的管理客户端需要）。不接收任意 Hydra 字段、密钥、签名配置或授权类型，也没有通用 Admin API
代理。不要为并不支持注销协议的应用登记虚构的端点。

### 密钥轮换

Hydra v26.2.0（当前最新正式版）没有 `/admin/clients/{id}/secrets/rotate`：该接口 2026-07-16
才合入 master，尚无发布版本。目前由本服务生成 32 字节随机密钥并以 PUT 写回，属于硬切换，
应用需同步更新。待 Hydra 发布原生轮换（支持新旧密钥并存），只需替换
`HydraClientRepository.rotateSecret`，API 不变。

## `/console` 管理界面

`/console` 是 Hydra 的普通 **public** OIDC 客户端（授权码 + PKCE，无 secret；申请 `openid groups`
与 audience `iam-login`），与本服务同源
部署但不享有任何特权：页面外壳不含数据，所有数据经上面的 bearer API 获取。access token
只保存在内存中，刷新页面即重新登录；不申请 refresh token，过期后提示重新登录。

部署前提（基础设施负责）：

- 在 Hydra 登记该客户端：`token_endpoint_auth_method=none`，grant `authorization_code`，
  scope `openid groups`，audience `["iam-login"]`，redirect `https://<本服务>/console/callback`，
  metadata `iam_login_enabled=true`。它不是 confidential 客户端，因此不出现在本 API 的列表中，
  也无法经本 API 删除自身；登记与恢复走 Hydra Admin 带外通道。
- Hydra public 端口开启 CORS 并只允许本服务 origin：浏览器直接向 Hydra 换取 token。
  页面 CSP 的 `connect-src` 仅额外放行 issuer origin。

路径用 `/console` 而非 `/admin`，避免同源部署时与"不发布 Hydra `/admin/**`"的路由规则混淆。

## 存储与范围

客户端与生成的 secret 由 Hydra 持久化；本服务不复制或缓存它们。集成测试验证创建、
重启后读取、更新后原密钥仍能认证、轮换后旧密钥被拒且新密钥可认证、删除。测试 PostgreSQL
完全独立于真实开发 MFA 库。

`loginEnabled` 是三态：`true`/`false` 写入 Hydra metadata；`null` 表示没有该标记的旧客户端
（如带外登记的 `gitea`），其登录由 `iam.hydra.clients` 白名单决定。API 原样返回 `null`，PUT 时
`null` 保持不写标记，不会把旧客户端误读或误存为禁用。新建客户端必须明确 `true` 或 `false`，
否则 400。旧客户端显式标记后即可从白名单移除。

列表按 Hydra 原始分页过滤不支持的授权类型，空页不表示之后必无客户端；本接口不是已有
全部 Hydra 客户端类型的迁移工具。禁用写入 Hydra metadata，后续授权即时重读并拒绝，
已签发 token 的生命周期另由 issuer 和应用控制。
