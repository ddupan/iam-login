# OAuth2/OIDC 客户端管理

本服务通过受限 API 管理 Hydra 中的第一方 confidential authorization-code 客户端。
API 没有管理 UI，沿用浏览器 Spring session；调用者必须完成有效的密码 + WebAuthn MFA，
且直接属于配置的管理组。默认组列表为空，拒绝全部管理操作。

```yaml
iam:
  clients:
    admin-group-dns:
      - CN=IAM Administrators,CN=Users,DC=example,DC=test
```

按完整 DN 匹配，保持与 AD 仓储一致的直接组语义，不展开嵌套组。可配置一个统一粗粒度
管理组，不要求每个应用建立独立 admins 组。组成员来自本次目录登录快照，变更后需重新认证。

| 方法与路径 | 行为 |
| --- | --- |
| GET `/api/iam/session` | 获取当前 session 的 CSRF headerName/token |
| GET `/api/iam/clients?page=0&size=20` | 返回 Hydra 分页内支持的客户端，size 1–100 |
| POST `/api/iam/clients` | 创建，201 返回 `{client, secret}`，密钥仅此次返回 |
| GET `/api/iam/clients/{id}` | 查询，不返回密钥 |
| PUT `/api/iam/clients/{id}` | 替换可管理字段，保留现有密钥 |
| DELETE `/api/iam/clients/{id}` | 删除，204 |

写操作必须携带当前 session cookie 与 GET session 返回的 CSRF 请求头。匿名返回 401，
因素不足、缺少管理组或 CSRF 不符返回 403。CSRF 默认由 Spring Security 处理，没有绕过路径。
成功变更记录 action、client ID 和操作者稳定目录标识，不记录密钥。没有 bearer 管理接口。

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

客户端与生成的 secret 由 Hydra 持久化；本服务不复制或缓存它们。管理员应在创建时安全保存
secret。暂不提供密钥轮换接口。Hydra 版本固定，更新时省略 secret 以保留原值；集成测试验证
创建、重启后读取、更新后原密钥仍能认证、删除。测试 PostgreSQL 完全独立于真实开发 MFA 库。

列表按 Hydra 原始分页过滤不支持的授权类型，空页不表示之后必无客户端；本接口不是已有
全部 Hydra 客户端类型的迁移工具。禁用写入 Hydra metadata，后续授权即时重读并拒绝，
已签发 token 的生命周期另由 issuer 和应用控制。
