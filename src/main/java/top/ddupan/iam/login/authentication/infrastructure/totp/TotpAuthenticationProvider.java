package top.ddupan.iam.login.authentication.infrastructure.totp;

import java.time.Clock;
import java.util.List;
import java.util.function.Supplier;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import top.ddupan.iam.login.authentication.infrastructure.persistence.CredentialRegistration;
import top.ddupan.iam.login.authentication.infrastructure.security.SignInThrottle;
import top.ddupan.iam.login.authentication.infrastructure.security.SignInThrottledException;
import top.ddupan.iam.login.authentication.infrastructure.webauthn.MfaPolicy;

/**
 * Checks a code against the signed-in account's key, or against the key being set up, and grants the TOTP factor.
 * Spring Security's AuthenticationFilter merges it with the password factor already in the session. Six digits
 * are guessable, so failures share the sign-in throttle's limits (with counters of their own).
 */
public final class TotpAuthenticationProvider implements AuthenticationProvider {
    private final MfaPolicy policy;
    private final TotpCredentials credentials;
    private final CredentialRegistration registrations;
    private final SignInThrottle throttle;
    private final Clock clock;

    public TotpAuthenticationProvider(MfaPolicy policy, TotpCredentials credentials, CredentialRegistration registrations,
            SignInThrottle throttle, Clock clock) {
        this.policy = policy;
        this.credentials = credentials;
        this.registrations = registrations;
        this.throttle = throttle;
        this.clock = clock;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        var request = (TotpCode) authentication;
        var current = SecurityContextHolder.getContext().getAuthentication();
        var principal = allowed(() -> {
            var directory = policy.current();
            // Setting up needs the same as adding a passkey: a fresh password, plus a fresh second factor once one exists.
            if (request.enrolling() != null) policy.requireEnrollment(current);
            return directory;
        });
        var owner = principal.getName();
        if (throttle.blocked(owner, request.address())) throw new SignInThrottledException();
        var now = clock.instant();
        boolean accepted;
        if (request.enrolling() != null) {
            var step = Totp.match(request.enrolling(), request.code(), now);
            accepted = step >= 0 && registrations.register(owner, () -> allowed(() -> {
                policy.requireEnrollment(current);
                credentials.save(owner, request.enrolling(), step);
                return true;
            }));
        } else {
            var step = credentials.key(owner).map(key -> Totp.match(key, request.code(), now)).orElse(-1L);
            accepted = step >= 0 && credentials.use(owner, step);
        }
        if (!accepted) {
            throttle.failed(owner, request.address());
            throw new BadCredentialsException("Invalid code");
        }
        throttle.succeeded(owner);
        return UsernamePasswordAuthenticationToken.authenticated(principal, null,
            List.of(FactorGrantedAuthority.withAuthority(MfaPolicy.TOTP_AUTHORITY).issuedAt(now).build()));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return TotpCode.class.isAssignableFrom(authentication);
    }

    /** Runs before the authorization rules, so a stale or missing factor is reported as an authentication failure. */
    private static <T> T allowed(Supplier<T> check) {
        try {
            return check.get();
        } catch (AccessDeniedException denied) {
            throw new InsufficientAuthenticationException("Fresh sign-in required", denied);
        }
    }
}
