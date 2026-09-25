# Agent Notes

- 默认中文维护项目文档、commit、issue 和 PR；代码与上游 API 名称保留英文。
- 项目使用 Java 与 Spring；Native 是交付约束，不是可选优化，不引入 Kotlin。
- 变更需通过适用的 JVM 测试和 Native 集成测试；未执行的验证明确报告。
- 只实现当前任务范围。Hydra 负责签发，首轮 AD 负责身份和组，本服务独立于 Ayatori。
- 不把 LDAP 密码成功当成完整 MFA 成功；所有因素绑定同一主体与认证事务。
- 不提交凭据、MFA secret、生产配置秘密或包含上述内容的测试输出。
- 生产部署配置属于 homelab-infra；本仓库初始化不授权切换现役登录入口。
- 文档区分计划、实现、Native 实测和人类验收，禁止将代码存在当成部署证据。
