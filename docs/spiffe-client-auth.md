# SPIFFE 客户端认证（JWT-SVID）

机器（CI、服务）以 SPIFFE JWT-SVID 向本授权服务器认证自己，换取本服务签发的 access token，无需 client secret。
实现严格按 [draft-ietf-oauth-spiffe-client-auth-02](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-spiffe-client-auth-02)，
下文的节号指该草案。代码在 `SpiffeClients`，测试 `SpiffeClientsTests`（按条目逐项）与
`AuthorizationServerIntegrationTests.machinesAuthenticateWithAJwtSvidAtTheTokenEndpoint`（端到端）。

## 请求

```
POST /oauth2/token
grant_type=client_credentials
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-spiffe
client_assertion=<JWT-SVID，aud 为本服务 issuer>
[client_id=<客户端 ID>]
[scope=...]
```

SVID 的 `aud` 必须**只有**本服务的 issuer（如 `https://sso.ddupan.top`，不带结尾斜杠），按 SPIRE 的取法即
`spire-agent api fetch jwt -audience https://sso.ddupan.top`。不带 `client_id` 时，客户端就是以该 SPIFFE ID
本身为 client ID 登记的那个。同样的认证也适用于 revocation 与 introspection 端点。

## 校验（3.1）

1. 结构完整，`sub` 是合法 SPIFFE ID，有 `aud`、`exp`；头部 `alg` 属于 JWT-SVID 规范允许的非对称算法，`typ` 若有须为 `JWT`/`JOSE`
2. 未过期（与框架一致容许 60 秒时钟偏差）
3. `aud` 恰好只有 issuer 一个值
4. 用 SPIFFE ID **所属 trust domain** 的 bundle 中 `use=jwt-svid` 的公钥验签
5. SPIFFE ID 与客户端对应：客户端设置 `settings.client.spiffe_id`（5.1 的 `spiffe_id`）精确匹配，或以 `/*`
   结尾时按完整路径段前缀匹配；未设置时与 client ID 精确匹配

客户端必须登记认证方式 `spiffe_jwt`。任何一步失败都只返回 `invalid_client`，原因只记 debug 日志。
SVID 的 `iss` 不参与校验，也绝不用于找公钥（6.2.4、8.1）。

## 公钥（6.1）

只从配置的 SPIFFE Bundle Endpoint（WebPKI：https，证书由 JVM 信任库验证）取，按 trust domain 区分，
按 bundle 的 `spiffe_refresh_hint` 轮询（缺省 5 分钟）；刷新失败沿用上次成功的公钥。

```yaml
iam:
  spiffe:
    trust-domains:
      - name: ddupan.top
        bundle-endpoint: https://<SPIRE bundle endpoint>
```

未配置任何 trust domain 时功能关闭：不在元数据中声明，所有 JWT-SVID 断言都会失败。

## 元数据（4）

启用后 `spiffe_jwt` 出现在 `/.well-known/oauth-authorization-server` 与 `/.well-known/openid-configuration` 的
`token_endpoint_auth_methods_supported`、`revocation_endpoint_auth_methods_supported`、
`introspection_endpoint_auth_methods_supported` 中。

## 签发的 token

`sub` 为 client ID（即 SPIFFE ID），`aud` 为 client ID 加客户端登记的额外 audience，`scope` 为空格分隔字符串
（RFC 9068，与用户 token 相同）。`client_credentials` 不签发 refresh token：随时可以用新的 SVID 再换。

## 未实现

- X509-SVID（3.2，mTLS）与 WIT-SVID（3.3）：草案只要求至少支持一种
- Client ID Metadata Document（3.1.2）与 `spiffe_bundle_endpoint` 客户端元数据：trust domain 只来自本服务配置
- 机器客户端的登记：暂无 API 或控制台入口，见后续工作
