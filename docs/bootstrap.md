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

2026-09-25 在上述 GraalVM 容器（Java 25.0.2）中执行 `./gradlew --no-daemon --max-workers=4 test`
通过，包含测试 AOT 处理和 1 个 JVM 上下文测试。Grafana LGTM Testcontainer 实际启动成功。
当前 Gradle 骨架的 `nativeCompile` 与 `nativeTest` 尚未执行，不声明 Native 已通过。

生成的上下文测试通过 Testcontainers 启动 Grafana LGTM，需访问 Docker。
它不连接真实 AD 或 Hydra，也不验证 MFA。Native 骨架测试不代替完整认证链路验收。

## Docker 开发与 Gradle 缓存

Linux 主机示例：将缓存保留在宿主机用户缓存目录，避免每次临时容器重新下载 Wrapper、
插件和依赖。项目工作目录也需要挂载，以保留 `build/` 和项目级 `.gradle/`。

```sh
IAM_GRADLE_CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/iam-login/gradle"
mkdir -p "$IAM_GRADLE_CACHE"
docker run --rm --network host \
  --user "$(id -u):$(id -g)" \
  --group-add "$(stat -c %g /var/run/docker.sock)" \
  -e LANG=C.UTF-8 \
  -e GRADLE_USER_HOME=/gradle \
  -e TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 \
  -v "$IAM_GRADLE_CACHE:/gradle" \
  -v "$PWD:/workspace" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -w /workspace --entrypoint /bin/bash \
  ghcr.io/graalvm/native-image-community@sha256:0d936f32bb8acb5bc60c41b33e05f064d7a6aaf36b726538296c54949bd4a3c0 \
  -c './gradlew --no-daemon --max-workers=4 test'
```

宿主机 Docker socket 供 Testcontainers 使用，host network 让测试能访问它启动的动态端口。
Docker Desktop 的网络方式需按平台调整。首次本地验证使用 `/tmp/iam-login-gradle` 作为
上述缓存目录，未写入仓库；长期开发使用持久缓存目录。构建容器使用宿主 UID/GID，
避免产物和缓存变为 root 所有。
