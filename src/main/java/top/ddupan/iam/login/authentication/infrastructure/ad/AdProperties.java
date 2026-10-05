package top.ddupan.iam.login.authentication.infrastructure.ad;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Where AD is (URLs, base DN) is Boot's spring.ldap.*; only what Boot has no notion of lives here. */
@ConfigurationProperties("iam.ad")
public record AdProperties(boolean enabled, String domain) {}
