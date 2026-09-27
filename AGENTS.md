# Agent Notes

- 后续修改必须新建分支并提交 PR；未经维护者明确指示，不直接推 main、不自行合并。
- 默认中文维护项目文档、commit、issue 和 PR；代码与上游 API 名称保留英文。
- 项目使用 Java 与 Spring；Native 是交付约束，不是可选优化，不引入 Kotlin。
- 日常变更先通过适用的 JVM 测试，不要求每轮执行耗时的 Native 编译与测试；Native 仍为交付目标，在阶段性验收或兼容性风险变化时集中验证。未执行的验证明确报告。
- 按 DDD 组织 authentication 上下文：领域拥有 User/UserRepository，应用层编排目录认证与读取，基础设施实现 AD 仓储与 Security Provider，Web 仅渲染页面；领域和应用层不依赖 Spring/Servlet/LDAP。
- 用户仓储复用本次用户 bind 的连接，不新增只读服务账号；连接限于当前用例，不保留密码或连接在 HTTP session 中。
- 选型演示在真实接入后删除，不将演示入口、状态机、验证码或开关保留为应用功能。
- 只实现当前任务范围。Hydra 负责签发，首轮 AD 负责身份和组，本服务独立于 Ayatori。
- React 只替换 Spring Security 默认登录 UI；表单认证、SecurityContext、因素状态、会话轮换与退出交给框架，不自建登录状态机。
- LDAP 密码成功可以建立仅含密码因素的 SecurityContext，但不等于完整 MFA 或 Hydra 授权；受保护操作必须检查所需因素。
- 不提交凭据、MFA secret、生产配置秘密或包含上述内容的测试输出。
- 生产部署配置属于 homelab-infra；本仓库初始化不授权切换现役登录入口。
- 文档区分计划、实现、Native 实测和人类验收，禁止将代码存在当成部署证据。
