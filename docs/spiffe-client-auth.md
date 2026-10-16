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

## 登记

机器客户端经管理 API `/api/iam/machine-clients` 登记（`docs/openapi.yaml` 的 `MachineClient`），与
`/api/iam/clients` 的登录客户端互不可见：

```json
{"id": "ci-publisher", "name": "CI 发布", "spiffeId": "spiffe://ddupan.top/ci/*",
 "scopes": ["artifacts.write"], "audiences": ["artifact-keeper"], "enabled": true}
```

- client ID 是普通标识，请求时以 `client_id` 带上；`spiffeId` 写进客户端设置 `spiffe_id`，可用 `/*` 覆盖一组工作负载
- 认证方式固定 `spiffe_jwt`，只有 `client_credentials`，没有 secret
- `audiences` 加进签发 token 的 `aud`，给按 `aud` 认 token 的下游（如 Artifact Keeper 的 CI OIDC provider）
- `enabled: false` 立即停止签发；删除连同已签发的授权记录一起删

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

## Token exchange（RFC 8693）

只会 RFC 8693 的客户端（STS 风格的 SDK、各类 workload identity 配置）可以把同一个 SVID 作为
`subject_token` 交换：

```
POST /oauth2/token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<JWT-SVID，aud 为本服务 issuer>
subject_token_type=urn:ietf:params:oauth:token-type:jwt
client_id=<客户端 ID>
[scope=...]
[audience=... / resource=...]
[requested_token_type=urn:ietf:params:oauth:token-type:access_token | ...:jwt]
```

- 请求不带其他客户端凭据时，`subject_token` 就是客户端认证用的 SVID，按上面「校验」逐条检查，
  客户端须登记为 `spiffe_jwt`；`client_id` 的规则与 `client_credentials` 相同
- 签发与 `client_credentials` 完全相同的 token，响应多带 `issued_token_type`（2.2.1）
- `audience` / `resource` 只能是客户端已登记的 audience（含 client ID），否则 `invalid_target`；
  它们不改变签发 token 的 `aud`
- 不支持委托：带 `actor_token` 返回 `invalid_request`
- 其他形式的交换（`subject_token` 是本服务签发的 token）仍由框架处理，需客户端登记 token-exchange grant

代码在 `SpiffeClients.Converter` 与 `SpiffeClients.Exchange`，端到端测试
`AuthorizationServerIntegrationTests.machinesExchangeTheirJwtSvidForAnAccessToken`。

## 未实现

草案只要求三种方式至少支持一种（4），以下有意不做，条件出现时再加：

- X509-SVID（3.2，mTLS）：能拿 X509-SVID 的工作负载同样能拿 JWT-SVID，不会多接入任何调用方；
  它多给的只是证书绑定 token（RFC 8705 `cnf`），而现有下游都不检查。代价是 TLS 在 Envoy 终止，
  客户端证书只能经 `X-Forwarded-Client-Cert` 转来，而 cloudflared 直连 8080 会原样转发请求头，
  需另开仅 Envoy 可达的端口来守这条信任边界。等有下游要求证书绑定 token 时再做。
- WIT-SVID（3.3）：SPIRE 1.15 不签发 WIT，且依赖的 WIMSE workload-creds 与 attestation-based
  client auth 两份草案仍在变动。等 SPIRE 能签发时再做。
- Client ID Metadata Document（3.1.2）与 `spiffe_bundle_endpoint` 客户端元数据（5.1）：等于开放注册，
  且要由本服务去取外部给出的 URL（SSRF）。机器客户端都由本服务登记，trust domain 只来自本服务配置。
  等有不归本服务登记的外部客户端时再做，届时须有主机白名单，且不得覆盖已配置 trust domain 的公钥来源。
