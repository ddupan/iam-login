# iam-login

独立 IAM 的登录、认证与 token 签发服务，以 Java、Spring Security 和 GraalVM Native 实现。
已实现 AD 密码与直接所属组查询、WebAuthn 第二因素，以及进程内的 OAuth 2.0 / OIDC 授权服务器
（Spring Security 7）与客户端管理；生产切换仍待验收。原 Hydra Login/Consent 方案存档于
`archive/hydra` 分支，main 只保留本方案。

## 职责与边界

- 首轮直接连接 Samba AD：验证人类凭据、查询用户与组，沿用已有组名。
- 处理人类 MFA、认证事务，并签发稳定的 OIDC subject（与目录账号解耦）。
- OAuth2/OIDC 协议与下游 token 签发由进程内授权服务器完成，见[内置授权服务器](docs/authorization-server.md)。
- 独立于 Ayatori；Ayatori 是 IAM 消费者，不是本服务运行依赖。
- AD 继续作为首轮用户与组权威；迁移目录、统一组模型及 machine/agent 入口留在后续。

```text
应用 ──OIDC──→ iam-login（授权服务器 + 登录）──→ Samba AD
                     └─ passkey（WebAuthn，PostgreSQL）
```

现役 Gitea 人类登录在切换前仍由部署中的存档版本（Hydra 方案）提供；main 的部署即为切换，
须同时迁移 Gitea 登录源（issuer、客户端密钥）。

## 代码与部署归属

本仓库负责应用源码、测试、依赖、Native 构建与发布。环境部署配置、域名、网络策略和
外部秘密引用留在 [homelab-infra](https://git.ddupan.top/panxiao81/homelab-infra)。
跨服务状态与运维知识维护在
[homelab-wiki](https://git.ddupan.top/panxiao81/homelab-wiki/src/branch/main/services/hydra.md)。

## 技术选型

优先 Java 和熟悉的 Spring 生态，不引入 Kotlin。阻碍 Java 选型的是 JVM 部署与运行
开销，满足功能和资源要求的 Native 应用仍为优先选择。项目使用 Java 25、Spring Boot
4.1.1 和 Gradle；Spring Security 等库由 Boot BOM 管理，插件版本在 build.gradle 中固定。
Native 使用 GraalVM 25。

日常改动先跑 JVM 测试，不要求每轮编译 Native。Native 构建与原生二进制上的认证测试
留在阶段性验收；JVM 测试通过或 native 编译成功都不
单独构成验收。Keycloak 可作为流程与安全边界参考，不以它采用 Quarkus 作为 native
兼容性证据，不直接引入其服务端 SPI 和模型。

见 [Native 验证范围](docs/native-validation.md)和[首轮实现 issue #1](https://git.ddupan.top/panxiao81/iam-login/issues/1)。

## 开发骨架

项目由 [Spring Initializr](https://start.spring.io) 生成，参数和复现方法见
[项目初始化](docs/bootstrap.md)。使用 JDK 25 执行：

```sh
npm --prefix frontend ci
npm --prefix frontend run build
./gradlew test testAot
./gradlew bootRun
```

应用启动需要配置 PostgreSQL 数据源，连接与开发容器说明见[第二因素](docs/webauthn.md)。
测试需要可用的 Docker，生成器配置了 Grafana LGTM Testcontainer。
测试覆盖 AD 第一因素、浏览器流程和监控集成。人类登录统一从 `/signin` 进入。
使用 GraalVM 25 验证原生测试与编译：

```sh
./gradlew nativeTest
./gradlew nativeCompile
```

Docker 开发使用 `scripts/gradle-in-docker`，默认持久挂载 Gradle 缓存。
原生应用可用 `python3 scripts/native-smoke.py` 检查启动、默认访问控制和 HTTP 指标。

会话：HTTP session 存在同一 PostgreSQL（Spring Session JDBC，JSON 序列化，复用授权表的 Jackson 白名单），
部署重启不登出，也不再限制单副本；WebAuthn challenge 单独成表以保证单次消费。

配置分两层：决定装配哪些 bean 的开关（`iam.*.enabled`）在 Native 构建时固定，写在仓库内的
`application-prod.yaml`，AOT 以 `prod` profile 构建；部署同样激活 `prod`，外部配置只提供环境值（地址、issuer、
RP ID 等）。运行时开关与构建不一致时拒绝启动（`FeatureFlags`）。

发布：合并到 main 后，CI 的 native job 在 Native 浏览器测试通过后，用 `Dockerfile` 打包**同一个**
二进制并推到 `zot-push.lab.ddupan.top/iam/iam-login:<commit>`（`scripts/publish-image`，身份为 runner
上 SPIRE Agent 发的 `spiffe://ddupan.top/ci/panxiao81/iam-login/publish`），不再单独为发布编译。
部署在 homelab-infra 中按 commit tag 固定。
JVM、AOT、Native 测试及原生应用 HTTP 检查已通过，实测范围与资源数据见
[本地验证结果](docs/bootstrap.md#2026-09-25-本地验证结果)。
新增 AD 路径本轮按维护者要求只进行 JVM 验证，不沿用基线的 Native 验收结论。
重构前的真实目录密码与属性/直接所属组读取已通过维护者浏览器验收；Spring Data LDAP
版本已通过 JVM 和浏览器回归，真实人类复验待反馈。WebAuthn 实现与验证边界见 [第二因素](docs/webauthn.md)，授权服务器与主体映射见 [内置授权服务器](docs/authorization-server.md)。

## 领域与代码组织

当前限界上下文为 `authentication`、`authorization` 与 `clients`，使用 DDD 分层，依赖向领域内部收敛：

```text
interfaces/web → infrastructure/security（principal）+ domain
infrastructure/security → application → domain
infrastructure/ad → application/port + domain
configuration → 装配上述实现
```

- `authentication/domain`：`User`、`UserRepository`；稳定主体与组成员关系属于领域模型，不依赖 Spring、Servlet、LDAP 或持久化注解。
- `authentication/application`：`VerifyPassword` 用例，编排密码认证与同连接用户仓储查询；
  `port` 描述密码认证及其用户仓储会话，不暴露 `DirContext`。
- `authentication/infrastructure/ad`：AD bind、Spring Data LDAP 用户仓储、LDAP 实体与领域映射。
  使用同一次用户 bind 的连接，查询结束关闭，不新增服务账号，不保存用户密码。
- `authentication/infrastructure/security`：Provider 将目录用户转换为仅含密码因素的认证结果。
- `authentication/infrastructure/persistence`：封装注册并发锁及事务，不把表结构带入 Security 策略。
- `authentication/infrastructure/webauthn`：凭据归属与注册策略、challenge 仓储扩展；密码学校验和 JDBC 存储交给 Spring Security。
- `authentication/interfaces/web`：登录页面与上下文转换；不处理密码 POST、认证会话或退出。
- `configuration`：Spring 组件装配、安全链、静态资源和 Native hints。
- 持久化：本服务自己写的 SQL 一律用 jOOQ，表与列的类型由构建时从 Flyway 迁移脚本生成（`top.ddupan.iam.login.persistence.schema`，见 `build.gradle` 的 `jooq`）；框架自带的仓储（授权服务器、WebAuthn、Spring Session）仍用它们自己的 JDBC 实现。
- `authorization`：subject 签发（`Subjects`，`subjects` 表）；授权服务器的装配、MFA 关卡、重新认证、refresh 策略与签名密钥在 `configuration`。由 `iam.authorization-server.enabled` 开启，见[内置授权服务器](docs/authorization-server.md)。
- `clients`：客户端管理。领域契约 `ClientRepository` 由 `RegisteredClients`（内置授权服务器的客户端仓储）实现；bearer API 要求 audience `iam-login` 且 token 的 `groups` 含管理组，`/console` 为调用该 API 的 public 客户端前端，见[客户端管理](docs/client-management.md)。
- `frontend/src`：入口、页面、表单组件和页面数据契约分别维护，只包含真实登录流程。

测试覆盖应用用例、AD 仓储和完整 Spring Security 过滤器链，LDAP 夹具集中在测试 `support` 包。
界面采用 React + Vite，Spring 在 HTML 中内联当前步骤上下文，浏览器原生表单 POST，
表单由 Spring Security `formLogin` 处理，框架维护因素、SecurityContext、会话轮换和退出。
React 只替换默认登录 UI，不增加前端路由器、模板引擎或 Node 运行服务。
界面文案全部在 `frontend/src/locales/<语言>.json`（i18next），按浏览器语言选择，缺省 zh-CN；键名以 zh-CN 为准做类型检查，漏写或拼错键名 `tsc` 即失败。服务端只传错误码（如 `invalid`、`throttled`），不传句子。新增语言＝加一个语言文件并在 `frontend/src/i18n.ts` 登记。

## AD 第一因素接入

真实入口为 `/signin`，默认关闭且要求 HTTPS。密码验证通过后显示 AD 身份与直接所属组，
保存仅含 `FACTOR_PASSWORD` 的认证结果，停在等待 MFA 状态。待 MFA 页要求十分钟内的密码因素；
仅凭密码因素不能取得授权码。监控 Basic 认证使用独立无状态安全链。
配置、组语义、HTTPS 与验收边界见 [AD 接入](docs/ad-login.md)。
