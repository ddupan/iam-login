package top.ddupan.iam.login.authentication.infrastructure.webauthn;

import java.time.Duration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagerFactories;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;

/** Enrollment policy; factor completion and freshness are evaluated by Spring Security. */
public final class MfaPolicy {
    private final PublicKeyCredentialUserEntityRepository users;
    private final UserCredentialRepository credentials;
    public final AuthorizationManager<Object> password = AuthorizationManagerFactories.<Object>multiFactor()
        .requireFactor(f -> f.passwordAuthority().validDuration(Duration.ofMinutes(10))).build().authenticated();
    public final AuthorizationManager<Object> complete = AuthorizationManagerFactories.<Object>multiFactor()
        .requireFactor(f -> f.passwordAuthority().validDuration(Duration.ofMinutes(10)))
        .requireFactor(f -> f.webauthnAuthority().validDuration(Duration.ofMinutes(10))).build().authenticated();

    public MfaPolicy(PublicKeyCredentialUserEntityRepository users, UserCredentialRepository credentials) {
        this.users = users;
        this.credentials = credentials;
    }

    public DirectoryPrincipal current() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        password.verify(() -> authentication, null);
        if (!(authentication.getPrincipal() instanceof DirectoryPrincipal principal)) {
            throw new AccessDeniedException("Directory identity required");
        }
        return principal;
    }

    public boolean enrolled(String name) {
        var user = users.findByUsername(name);
        return user != null && !credentials.findByUserId(user.getId()).isEmpty();
    }

    public void requireEnrollment(Authentication authentication) {
        password.verify(() -> authentication, null);
        if (enrolled(authentication.getName())) complete.verify(() -> authentication, null);
    }
}
