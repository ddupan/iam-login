package top.ddupan.iam.login.ad;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("iam.ad")
public record AdProperties(boolean enabled, String url, String domain, String baseDn) {}
