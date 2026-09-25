# 项目初始化

2026-09-25 使用 start.spring.io API 生成，选择当时默认正式版 Spring Boot 4.1.1、
Java 25、Gradle Groovy DSL、YAML 配置和 Jar。应用包名为 `top.ddupan.iam.login`。

```sh
curl -fsSLG https://start.spring.io/starter.zip \
  --data-urlencode type=gradle-project \
  --data-urlencode language=java \
  --data-urlencode bootVersion=4.1.1 \
  --data-urlencode javaVersion=25 \
  --data-urlencode groupId=top.ddupan.iam \
  --data-urlencode artifactId=iam-login \
  --data-urlencode name=iam-login \
  --data-urlencode packageName=top.ddupan.iam.login \
  --data-urlencode 'description=Independent IAM login and authentication service for Hydra' \
  --data-urlencode packaging=jar \
  --data-urlencode configurationFileFormat=yaml \
  --data-urlencode dependencies=native,devtools,lombok,configuration-processor,web,security,spring-security-webauthn,data-ldap,validation,actuator,prometheus,opentelemetry,distributed-tracing,unboundid-ldap,testcontainers \
  -o iam-login-starter.zip
```

生成器提供 Gradle Wrapper、应用入口、上下文测试、依赖和 Native 构建插件。
为生成的 `.gitignore` 补充秘密文件与日志忽略规则，以中文项目文档替代生成器的 `HELP.md`。
Initializr 的可选版本会变化，未来可能需要调整请求；已提交源码、Gradle Wrapper 与插件版本是构建依据。

LDAP 和 WebAuthn 依赖尚未配置为真实认证流程；数据库和 MFA 凭据持久化随首轮实现引入。
Actuator 与 Prometheus 依赖存在不等于监控端点已按生产策略开放。

## 骨架验证

构建环境为 `ghcr.io/graalvm/native-image-community:25`，固定 digest：
`sha256:0d936f32bb8acb5bc60c41b33e05f064d7a6aaf36b726538296c54949bd4a3c0`。

验证分为 `test`（JVM）、`testAot`（JVM 上的 AOT 上下文）、`nativeTest`（原生测试）
和应用二进制 HTTP 检查。JVM/AOT/Native 测试均使用真实 LGTM Testcontainer，
显式初始化指标、追踪导出器，并验证容器连接与 CPU 时间读取。结果随 PR 记录。
这些检查不连接真实 AD 或 Hydra，也不验证 MFA。

## Docker 开发与 Gradle 缓存

Linux 主机示例：将缓存保留在宿主机用户缓存目录，避免每次临时容器重新下载 Wrapper、
插件和依赖。项目工作目录也需要挂载，以保留 `build/` 和项目级 `.gradle/`。

```sh
scripts/gradle-in-docker test testAot
scripts/gradle-in-docker nativeTest nativeCompile
python3 scripts/native-smoke.py
```

`scripts/gradle-in-docker` 默认挂载 `${XDG_CACHE_HOME:-$HOME/.cache}/iam-login/gradle` 到
容器 `/gradle`，并设置 Gradle 缓存与构建用户目录到该目录，避免无 passwd 条目的宿主 UID
导致 Testcontainers 向项目内的 `?/` 写配置。原生测试同时显式传入 `user.home`。可通过 `IAM_GRADLE_CACHE` 覆盖宿主路径；
默认限制 4 CPU、8 GiB 内存，可通过 `IAM_BUILD_CPUS`、`IAM_BUILD_MEMORY` 调整。
需要 sudo 才能访问 Docker 时设置 `IAM_DOCKER_USE_SUDO=1`；只提升 Docker 命令权限，
容器内仍使用当前用户 UID/GID。

宿主机 Docker socket 供 Testcontainers 使用，host network 让测试能访问它启动的动态端口。
Docker Desktop 的网络方式需按平台调整。首次本地验证使用 `/tmp/iam-login-gradle` 作为
上述缓存目录，未写入仓库；长期开发使用持久缓存目录。构建容器使用宿主 UID/GID，
避免产物和缓存变为 root 所有。

## 原生启动检查

`native-smoke.py` 在 Linux 上直接启动 `build/native/nativeCompile/iam-login` ELF 文件，
不调用 Java。需要 Python 3 标准库及编译产物依赖的系统库；监听随机 loopback 端口，
结束时清理进程，并检查包括关闭阶段在内的 Native 注册错误；结果保存在 `build/reports/native-smoke/`。

检查匿名 liveness 端点、应用与指标端点拒绝匿名访问、使用临时测试凭据读取 Prometheus，
以及健康请求的 HTTP 计数器增长。记录二进制大小、可响应耗时和请求后 RSS；这些单次
数据不是负载基准或资源预算。脚本不请求依赖目录的聚合健康端点，
不验证目录就绪、MFA、Hydra 或追踪导出。

应用在构建期声明 `health`、`prometheus` 暴露范围与健康探针。默认安全配置继续保护
指标端点；liveness 使用应用可用性状态，不把尚未配置 AD 的聚合健康状态描述为正常。

## AOT 测试与容器连接

初始生成的 `@Bean + @ServiceConnection` 测试配置在 Boot 4.1.1 的 Native 测试中
出现过缺少 `OtlpLoggingConnectionDetails` 的启动失败。测试改用类静态字段上的
`@Container + @ServiceConnection`，由测试上下文在运行时重建连接信息，并断言日志
导出 URL 指向本次运行的 LGTM 容器。JVM 开发入口仍使用原有配置类。

`testAot` 使用生成的 AOT 测试上下文在 JVM 中运行，可先发现 AOT 装配错误；它不替代
`nativeTest`。Native 测试二进制启用 `quickBuild` 降低编译成本，应用 `nativeCompile`
保持默认优化；启动和内存数据必须来自应用二进制，不能取测试二进制的数据。

参考 [Spring Boot Testcontainers](https://docs.spring.io/spring-boot/reference/testing/testcontainers.html)
与 [Native Build Tools Gradle 配置](https://graalvm.github.io/native-build-tools/latest/gradle-plugin.html)。

## Native 反射元数据

Micrometer OTLP 使用的 Protobuf 4.35.1 通过反射调用 `ExtensionRegistry` 的
`getEmptyRegistry()` 与 `newInstance()`。实际原生应用启动曾因前一个方法缺少注册而失败，
项目的 `reachability-metadata.json` 中对 Protobuf 只补充这两个工厂方法。升级依赖时应重新验证能否移除。

上下文测试显式启用 `@AutoConfigureMetrics` 与 `@AutoConfigureTracing`，初始化真实导出器，
避免 Spring 测试默认关闭导出导致 Native 问题漏测。它验证初始化及容器连接信息，完整的
OTLP 数据接收、持久化和查询验收仍属后续观测性集成测试。

Micrometer 1.17.1 自带的反射声明已覆盖 CPU 使用率和文件描述符读取，但遗漏了
`OperatingSystemMXBean.getProcessCpuTime()`。项目只补这一项；回归测试直接读取
Prometheus 注册器中的 CPU 时间计数器并断言数值有效，避免后台导出异常被误报为测试通过。
其他 JVM 指标在 Native 中的语义仍需分别验证，不能保证 HotSpot 仪表盘完全适用。

## 2026-09-25 本地验证结果

代码版本 `4c7be4c`，Java/GraalVM 25.0.2、Gradle 9.7.1，Linux amd64，Native 目标
`x86-64-v3`。构建容器限制 4 CPU、8 GiB；应用使用默认 O2 优化，测试镜像使用 quickBuild。

| 验证 | 结果 |
|---|---|
| JVM `test` | 2 成功，0 失败，0 跳过 |
| JVM AOT `testAot` | 2 成功，0 失败，0 跳过 |
| `nativeTest` | 2 成功，0 失败，0 跳过；包含真实导出器初始化及 CPU 时间读取 |
| `nativeCompile` | 成功；生成独立 ELF，动态链接 libc、libz |
| 原生应用 liveness | UP |
| 匿名应用／指标请求 | 401 |
| 带临时测试凭据的 Prometheus 请求 | 200 |
| 额外 3 次 liveness 请求 | HTTP 计数器增加 3 |
| 运行及关闭阶段 Native 注册错误 | 未发现 |
| 启动至首次 liveness 响应 | 0.582 秒 |
| 请求后进程 RSS | 144.56 MiB |
| ELF 文件大小 | 119.88 MiB |

这是一次本地 smoke 测量，启动耗时含检查器轮询，RSS 不是峰值或负载预算，ELF 大小不等于
运行镜像大小。未验证 AD、MFA、Hydra、目录就绪或 OTLP 后端数据查询，也尚未接入 CI。
运行报告生成在 `build/reports/native-smoke/result.json`，不提交运行日志或构建产物。

手写 Native 补丁位于 `META-INF/native-image/top.ddupan.iam/iam-login-manual/`，
与 Spring AOT 生成的 `iam-login/` 目录分开，避免 `bootJar` 中同名元数据冲突。
