package top.ddupan.iam.login.authentication.infrastructure.webauthn;

import java.time.Duration;
import java.util.Optional;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
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

    /**
     * How long one sign-in keeps opening applications without asking again; an absolute limit counted from the
     * factors. The session's idle timeout follows it (application.yaml), or an idle session would end the sign-in
     * first.
     */
    @ConfigurationProperties("iam.signin.sso")
    public record Properties(@DefaultValue("12h") Duration lifetime) {
        public Properties {
            // Zero would make every application ask again, which reads as a broken sign-in; fail at startup instead.
            if (lifetime.isNegative() || lifetime.isZero()) throw new IllegalArgumentException("iam.signin.sso.lifetime must be positive");
        }
    }

    private static final Duration FRESH = Duration.ofMinutes(10);
    private final PublicKeyCredentialUserEntityRepository users;
    private final UserCredentialRepository credentials;
    private final TotpCredentials totp;
    public final AuthorizationManager<Object> password = AuthorizationManagerFactories.<Object>multiFactor()
        .requireFactor(f -> f.passwordAuthority().validDuration(FRESH)).build().authenticated();
    /**
     * Adding a factor: a fresh password (the first one is trusted to it alone), or a full fresh sign-in. Who may
     * add which is decided by {@link #requireEnrollment}; this only admits the request.
     */
    public final AuthorizationManager<Object> enroll = AllRequiredFactorsAuthorizationManager.anyOf(
        AllRequiredFactorsAuthorizationManager.<Object>builder().requireFactor(f -> f.passwordAuthority().validDuration(FRESH)).build(),
        passkeyAlone(FRESH));
    /** Just signed in: finishing a sign-in, and re-verification before changing the account. */
    public final AuthorizationManager<Object> complete = signedIn(FRESH);
    /** Signed in at some point within the SSO lifetime: enough to enter an application. */
    public final AuthorizationManager<Object> session;

    public MfaPolicy(PublicKeyCredentialUserEntityRepository users, UserCredentialRepository credentials, TotpCredentials totp,
            Duration ssoLifetime) {
        this.users = users;
        this.credentials = credentials;
        this.totp = totp;
        this.session = signedIn(ssoLifetime);
    }

    /**
     * A full sign-in: the password with either second factor, or a passkey alone. A passkey is two factors by
     * itself: the device, and the PIN or biometric that user verification (required in both ceremonies, checked
     * by the server) proves. An authenticator app code is never enough on its own.
     */
    private static AuthorizationManager<Object> signedIn(Duration validFor) {
        return AllRequiredFactorsAuthorizationManager.anyOf(
            withPassword(FactorGrantedAuthority.WEBAUTHN_AUTHORITY, validFor), withPassword(TOTP_AUTHORITY, validFor),
            passkeyAlone(validFor));
    }

    private static AllRequiredFactorsAuthorizationManager<Object> passkeyAlone(Duration validFor) {
        return AllRequiredFactorsAuthorizationManager.<Object>builder()
            .requireFactor(f -> f.authority(FactorGrantedAuthority.WEBAUTHN_AUTHORITY).validDuration(validFor)).build();
    }

    private static AllRequiredFactorsAuthorizationManager<Object> withPassword(String second, Duration validFor) {
        return AllRequiredFactorsAuthorizationManager.<Object>builder()
            .requireFactor(f -> f.passwordAuthority().validDuration(validFor))
            .requireFactor(f -> f.authority(second).validDuration(validFor)).build();
    }

    /** The account in the middle of the password sign-in: a fresh password, its second step still to come. */
    public DirectoryPrincipal current() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        password.verify(() -> authentication, null);
        return principal(authentication);
    }

    /**
     * The account a passkey ceremony belongs to, if it is the second step after a fresh password; empty means a
     * passwordless sign-in, where the passkey itself says whose it is.
     */
    public Optional<DirectoryPrincipal> secondStep() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        var fresh = authentication == null ? null : password.authorize(() -> authentication, null);
        return fresh != null && fresh.isGranted() && authentication.getPrincipal() instanceof DirectoryPrincipal principal
            ? Optional.of(principal) : Optional.empty();
    }

    /** Whoever is signed in, by whichever factors: for adding a factor, which {@link #requireEnrollment} then gates. */
    public DirectoryPrincipal signedIn() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        enroll.verify(() -> authentication, null);
        return principal(authentication);
    }

    private static DirectoryPrincipal principal(Authentication authentication) {
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

    /** The first factor is trusted to a fresh password alone; once one exists, adding another needs a full sign-in. */
    public void requireEnrollment(Authentication authentication) {
        if (enrolled(authentication.getName())) complete.verify(() -> authentication, null);
        else password.verify(() -> authentication, null);
    }
}
