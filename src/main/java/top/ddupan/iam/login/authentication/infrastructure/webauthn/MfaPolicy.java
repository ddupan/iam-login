package top.ddupan.iam.login.authentication.infrastructure.webauthn;

import java.time.Duration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AllRequiredFactorsAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagerFactories;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;
import top.ddupan.iam.login.authentication.infrastructure.totp.TotpCredentials;

/**
 * Enrollment policy; factor completion and freshness are evaluated by Spring Security. The second factor is a
 * passkey or an authenticator app code, either one.
 */
public final class MfaPolicy {
    /** Spring Security has no authority for TOTP; named like its own. */
    public static final String TOTP_AUTHORITY = "FACTOR_TOTP";
    private static final Duration FRESH = Duration.ofMinutes(10);
    private final PublicKeyCredentialUserEntityRepository users;
    private final UserCredentialRepository credentials;
    private final TotpCredentials totp;
    public final AuthorizationManager<Object> password = AuthorizationManagerFactories.<Object>multiFactor()
        .requireFactor(f -> f.passwordAuthority().validDuration(FRESH)).build().authenticated();
    public final AuthorizationManager<Object> complete = AllRequiredFactorsAuthorizationManager.anyOf(
        withPassword(FactorGrantedAuthority.WEBAUTHN_AUTHORITY), withPassword(TOTP_AUTHORITY));

    public MfaPolicy(PublicKeyCredentialUserEntityRepository users, UserCredentialRepository credentials, TotpCredentials totp) {
        this.users = users;
        this.credentials = credentials;
        this.totp = totp;
    }

    private static AllRequiredFactorsAuthorizationManager<Object> withPassword(String second) {
        return AllRequiredFactorsAuthorizationManager.<Object>builder()
            .requireFactor(f -> f.passwordAuthority().validDuration(FRESH))
            .requireFactor(f -> f.authority(second).validDuration(FRESH)).build();
    }

    public DirectoryPrincipal current() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        password.verify(() -> authentication, null);
        if (!(authentication.getPrincipal() instanceof DirectoryPrincipal principal)) {
            throw new AccessDeniedException("Directory identity required");
        }
        return principal;
    }

    public boolean passkeys(String name) {
        var user = users.findByUsername(name);
        return user != null && !credentials.findByUserId(user.getId()).isEmpty();
    }

    public boolean totp(String name) {
        return totp.exists(name);
    }

    public boolean enrolled(String name) {
        return passkeys(name) || totp(name);
    }

    public void requireEnrollment(Authentication authentication) {
        password.verify(() -> authentication, null);
        if (enrolled(authentication.getName())) complete.verify(() -> authentication, null);
    }
}
