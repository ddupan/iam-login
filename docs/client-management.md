# OAuth2/OIDC 客户端管理

本服务通过受限 API 管理内置授权服务器（见[内置授权服务器](authorization-server.md)）中的第一方
confidential authorization-code 客户端。领域层定义 `ClientRepository`，基础设施的 `RegisteredClients`
基于框架的 `RegisteredClientRepository`（JDBC）实现。API 是主要交付物（为 IaC 等自动化准备）；
`/console` 管理界面只是调用同一 API 的前端应用。只在 `iam.authorization-server.enabled` 时提供。

## 鉴权：audience + groups

`/api/iam/**` 是普通 resource server，只接受本服务签发的 access token（以自身签名密钥验证）：

1. **audience**：token 的 `aud` 须含 `iam-login`。签给其他应用的 token（例如管理员登录 Gitea 时
   Gitea 拿到的 token）即使带着管理员组也被拒绝。框架没有 audience 参数，客户端可获得的额外 audience
   登记在客户端设置 `settings.client.iam.audiences` 中，由 token 定制器写入；目前只有 `/console` 登记了它。
2. **groups**：客户端申请 `groups` scope 时，用户的直接 AD 组名进入 access token。API 要求其中有
   `iam.clients.admin-groups` 之一。

3. **机器（IaC）**：也可用 SPIFFE JWT-SVID 调用。token 须由配置的 SPIRE OIDC issuer 签发（按其 JWKS 验签）、
   `aud` 含 `iam-login`、未过期，且 `sub`（SPIFFE ID）在 `iam.clients.spiffe.admin-ids` 中精确列出；groups 不参与。
   按 token 的 `iss` 选择验证方式，其他 issuer 一律拒绝。未配置 issuer 时不接受 JWT-SVID。

浏览器 session、cookie 与 CSRF 都不是 API 凭据。匿名、token 无效返回 401；audience 不符或不是
管理员返回 403。

```yaml
iam:
  clients:
    admin-groups:
      - Domain Admins
    console-client-id: iam-console   # 默认值
    spiffe:                          # 可选；机器调用方
      issuer: https://spire-oidc.ad.ddupan.top
      jwk-set-uri: https://spire-oidc.ad.ddupan.top/keys
      admin-ids:
        - spiffe://ddupan.top/ci/panxiao81/homelab-infra/terraform-apply
```

按组名匹配，与下游应用看到的 `groups` 一致；组名取 memberOf DN 的 CN，只含直接组。同一用户若有
两个同名直接组，登录直接失败；他处的同名组需要 AD 建组权限才能伪造。组成员是登录时的快照，移出
管理组后最长在 access token 有效期内仍可调用。以后自动化调用方如何取得 token 另行设计；只要 token
由本服务签发、audience 与组满足要求，API 行为不变。

## 接口

| 方法与路径 | 行为 |
| --- | --- |
| GET `/api/iam/clients?page=0&size=20` | 受管理客户端列表，size 1–100 |
| POST `/api/iam/clients` | 创建，201 返回 `{client, secret}`，密钥仅此次返回 |
| GET `/api/iam/clients/{id}` | 查询，不返回密钥 |
| PUT `/api/iam/clients/{id}` | 替换可管理字段，保留现有密钥 |
| DELETE `/api/iam/clients/{id}` | 删除，204；该客户端的授权记录与 consent 一并删除 |
| POST `/api/iam/clients/{id}/secret` | 轮换，200 返回 `{secret}`，**旧密钥立即失效** |

输入无效 400，不存在 404，ID 冲突或非本 API 管理的客户端（如 `/console` 的 public 客户端）409。
含密钥的响应带 `Cache-Control: no-store`。成功变更记录 action、client ID 和 token 的 subject，不记录密钥。

```json
{
  "id": "example-app",
  "name": "示例应用",
  "redirectUris": ["https://app.example.test/oidc/callback"],
  "scopes": ["openid", "profile", "email", "groups", "offline_access"],
  "postLogoutRedirectUris": ["https://app.example.test/logged-out"],
  "loginEnabled": true,
  "pkceRequired": true,
  "publicClient": false,
  "deviceAuthorization": false,
  "audiences": []
}
```

- 回调必须 HTTPS（隔离开发允许 loopback HTTP），不允许通配符、fragment 或 URL 用户信息。
- 固定 `authorization_code`；confidential 客户端用 `client_secret_basic`。refresh token 每次使用都轮换。
- `publicClient`（可选，默认 `false`）：不签发 secret，客户端认证方式为 `none`（CLI、浏览器应用）。此时
  `pkceRequired` 必须为 `true`；创建后不可改变（换类型即换客户端），也没有 secret 可轮换（409）。
  授权码由 PKCE 绑定；device 授权与 refresh 只凭 `client_id`。public 客户端同样拿到 refresh token
  （框架默认不发），以每次轮换代替发送方绑定（RFC 9700 4.14.2）。
- `deviceAuthorization`（可选，默认 `false`）：另外登记 device 授权类型（RFC 8628），给没有浏览器的客户端。
- `audiences`（可选）：access token 额外的 `aud`，给自己校验 audience 的资源（如 Incus）。最多 10 个，
  不可含逗号。
- 客户端不做按人准入：谁能做什么由资源按 token 里的身份与组自行决定。
- `pkceRequired` 必填，缺失 400。只为不能发送 PKCE 的 confidential 客户端关闭（Gitea 1.27 的 OIDC
  登录源既不发 PKCE 也不发 nonce，只有 `state`）；RFC 9700 2.1.1 允许 confidential 客户端如此，
  但授权码注入防护随之变弱，能发 PKCE 的应用一律保持开启。
- scope 可为任意符合 RFC 6749 的 scope-token（最多 50 个），必须含 `openid`；scope 不代表权限。
  含 `offline_access` 时一并登记 `refresh_token` 授权类型（OIDC Core 11），去掉时移除。
- `loginEnabled` 必填，缺失 400。`false` 时新的授权请求返回 `unauthorized_client`，refresh 也被拒绝；
  已签发的 access token 在有效期内仍可用。
- 框架不支持前/后通道注销，不提供相应字段。
- 密钥为 32 字节随机值，以 `{bcrypt}` 编码存储，明文只在创建与轮换时返回一次。

## `/console` 管理界面

`/console` 是本服务的普通 **public** OIDC 客户端（授权码 + PKCE，无 secret，scope `openid groups`，
audience `iam-login`），与授权端点同源，不需要 CORS。客户端在每次启动时按配置自动登记或更新
（回调为 `<issuer>/console/callback`），无需带外引导。不显示授权确认页（第一方），但仍要求完整 MFA。
access token 只保存在内存中，刷新页面即重新登录；过期后提示重新登录。

## 验证

`AuthorizationServerIntegrationTests` 覆盖 API 鉴权（无凭据、session、错误 audience、非管理员）、
`/console` 的真实授权码流程及其 token 的 audience、增删改查、轮换后新旧密钥、禁用后拒绝授权、
删除级联授权记录；`OidcClientTests` 覆盖输入校验；`authorization-server.spec.ts` 在浏览器中走完
`/console` 的登录与客户端增删、轮换。
