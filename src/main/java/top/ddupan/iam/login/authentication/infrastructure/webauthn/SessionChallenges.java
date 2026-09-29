package top.ddupan.iam.login.authentication.infrastructure.webauthn;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.registration.PublicKeyCredentialCreationOptionsRepository;
import org.springframework.security.web.webauthn.authentication.PublicKeyCredentialRequestOptionsRepository;

/** Framework repository extension: server-side TTL, owner binding and atomic single consumption. */
public final class SessionChallenges {
    private final Clock clock;
    private final MfaPolicy policy;
    private static final Duration LIFETIME = Duration.ofMinutes(5);
    private record Challenge(Object options, String owner, Instant expiresAt) { }

    public SessionChallenges(Clock clock, MfaPolicy policy) {
        this.clock = clock;
        this.policy = policy;
    }

    private void save(HttpServletRequest request, String key, Object options) {
        // Upstream clears after load; load already consumes atomically. Do not clear a newer challenge.
        if (options == null) return;
        var owner = policy.current().getName();
        var session = request.getSession();
        synchronized (session) {
            session.setAttribute(key, new Challenge(options, owner, clock.instant().plus(LIFETIME)));
        }
    }

    private Object consume(HttpServletRequest request, String key) {
        var session = request.getSession(false);
        if (session == null) return null;
        synchronized (session) {
            var challenge = (Challenge) session.getAttribute(key);
            session.removeAttribute(key);
            var authentication = SecurityContextHolder.getContext().getAuthentication();
            if (challenge == null || !clock.instant().isBefore(challenge.expiresAt())
                    || authentication == null || !challenge.owner().equals(authentication.getName())) return null;
            var result = policy.password.authorize(() -> authentication, null);
            if (result == null || !result.isGranted()) return null;
            return challenge.options();
        }
    }

    public PublicKeyCredentialCreationOptionsRepository registration() {
        return new PublicKeyCredentialCreationOptionsRepository() {
            private static final String KEY = "iam.webauthn.registration";
            @Override public void save(HttpServletRequest r, HttpServletResponse s, PublicKeyCredentialCreationOptions o) {
                SessionChallenges.this.save(r, KEY, o);
            }
            @Override public PublicKeyCredentialCreationOptions load(HttpServletRequest r) {
                return (PublicKeyCredentialCreationOptions) consume(r, KEY);
            }
        };
    }

    public PublicKeyCredentialRequestOptionsRepository authentication() {
        return new PublicKeyCredentialRequestOptionsRepository() {
            private static final String KEY = "iam.webauthn.authentication";
            @Override public void save(HttpServletRequest r, HttpServletResponse s, PublicKeyCredentialRequestOptions o) {
                SessionChallenges.this.save(r, KEY, o);
            }
            @Override public PublicKeyCredentialRequestOptions load(HttpServletRequest r) {
                return (PublicKeyCredentialRequestOptions) consume(r, KEY);
            }
        };
    }
}
