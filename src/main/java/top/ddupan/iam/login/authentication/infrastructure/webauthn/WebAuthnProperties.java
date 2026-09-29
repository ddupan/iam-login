package top.ddupan.iam.login.authentication.infrastructure.webauthn;

import java.net.URI;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("iam.webauthn")
public record WebAuthnProperties(boolean enabled, String rpId, String origin) {
    public WebAuthnProperties {
        if (enabled) {
            if (origin == null) throw new IllegalArgumentException("WebAuthn HTTPS origin is required");
            var uri = URI.create(origin);
            if (rpId == null || rpId.isBlank() || !"https".equals(uri.getScheme())
                    || !rpId.equals(uri.getHost()) || uri.getUserInfo() != null
                    || uri.getQuery() != null || uri.getFragment() != null
                    || (uri.getPath() != null && !uri.getPath().isEmpty())) {
                throw new IllegalArgumentException("WebAuthn requires an exact HTTPS origin and matching RP host");
            }
        }
    }
}
