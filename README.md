# iam-login

独立 IAM 的登录与认证服务，以 Java、Spring Security 和 GraalVM Native 实现，作为
Hydra 的 Login/Consent 应用。已实现 AD 密码与直接所属组查询，以及等待 MFA 的浏览器页面；MFA 与 Hydra 登录链路仍待实现。

## 职责与边界

- 首轮直接连接 Samba AD：验证人类凭据、查询用户与组，沿用已有组名。
- 处理人类 MFA、认证事务及稳定主体映射，完成 Hydra Login/Consent。
- OAuth2/OIDC 协议与下游 token 签发由 Hydra 提供。
- 独立于 Ayatori；Ayatori 是 IAM 消费者，不是本服务运行依赖。
- AD 继续作为首轮用户与组权威；迁移目录、统一组模型及 machine/agent 入口留在后续。

```text
应用 → Hydra → iam-login → Samba AD + MFA
          ↑        │
          └────────┘ 接受 Login/Consent
```

现役 Gitea 人类登录仍使用 homelab-infra 中的 Go OIDC 上游适配器和 Authelia，已通过
维护者验收。创建本仓库不表示切换生产认证入口，也不改变现有 Gitea 账号关联。

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

测试需要可用的 Docker，生成器配置了 Grafana LGTM Testcontainer。
包含隔离浏览器原型和 AD 第一因素测试；默认 Spring Security 登录页不是 IAM 登录流程。
使用 GraalVM 25 验证原生测试与编译：

```sh
./gradlew nativeTest
./gradlew nativeCompile
```

Docker 开发使用 `scripts/gradle-in-docker`，默认持久挂载 Gradle 缓存。
原生应用可用 `python3 scripts/native-smoke.py` 检查启动、默认访问控制和 HTTP 指标。
JVM、AOT、Native 测试及原生应用 HTTP 检查已通过，实测范围与资源数据见
[本地验证结果](docs/bootstrap.md#2026-09-25-本地验证结果)。
新增 AD 路径本轮按维护者要求只进行 JVM 验证，不沿用基线的 Native 验收结论。
真实目录密码与属性/直接所属组读取已通过维护者浏览器验收；MFA 与 Hydra 链路仍待实现。

## 浏览器流程预览

人类登录界面采用 React + Vite，参考 Keycloakify 的内联上下文与原生表单提交方式。
原型默认关闭，仅测试页面切换与局部交互，不执行真实认证。启动、浏览器测试和边界见
[浏览器流程原型](docs/browser-preview.md)。

## AD 第一因素接入

真实入口为 `/signin`，默认关闭且要求 HTTPS。密码验证通过后显示 AD 身份与直接所属组，
停在等待 MFA 状态，不建立完整登录身份或接受 Hydra challenge。
配置、组语义、HTTPS 与验收边界见 [AD 接入](docs/ad-login.md)。
