package top.ddupan.iam.login.authorization.infrastructure.hydra;

import java.net.URI;
import java.util.List;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("iam.hydra")
public record HydraProperties(boolean enabled, URI adminUrl, URI publicUrl, Set<String> clients,
        List<SubjectBinding> subjects) {
    public record SubjectBinding(String authority, String directoryId, String subject) { }
    public HydraProperties {
        if (enabled) {
            validateUrl(adminUrl, true); validateUrl(publicUrl, false);
            if (subjects == null) throw new IllegalArgumentException("Hydra policy is required");
        }
    }
    private static void validateUrl(URI uri, boolean administrative) {
        if (uri == null || uri.getHost() == null || uri.getUserInfo() != null || uri.getQuery() != null
                || uri.getFragment() != null || !(uri.getPath().isEmpty() || uri.getPath().equals("/"))
                || !("https".equals(uri.getScheme()) || "http".equals(uri.getScheme())
                    && (administrative || uri.getHost().equals("localhost") || uri.getHost().equals("127.0.0.1")))) {
            throw new IllegalArgumentException("Invalid Hydra origin (public HTTP is restricted to loopback)");
        }
    }
}
