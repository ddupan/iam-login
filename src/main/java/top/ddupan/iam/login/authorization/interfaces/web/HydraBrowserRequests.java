package top.ddupan.iam.login.authorization.interfaces.web;

import java.time.Instant;
import java.time.Duration;
import java.util.UUID;
import jakarta.servlet.http.HttpServletRequest;
import top.ddupan.iam.login.authorization.domain.AuthorizationRequest;

/** Short-lived issuer request binding only. Authentication state remains in Spring Security. */
public final class HydraBrowserRequests {
    private static final String PENDING = HydraBrowserRequests.class.getName() + ".pending";
    private static final String ACCEPTED = HydraBrowserRequests.class.getName() + ".accepted";
    public record Intent(AuthorizationRequest request, String binding, Instant expiresAt) { }
    public record Accepted(Intent intent, String directoryName, String subject) { }
    private HydraBrowserRequests() { }

    public static void start(HttpServletRequest request, AuthorizationRequest authorization) {
        var session = request.getSession();
        synchronized (session) {
            session.removeAttribute(ACCEPTED);
            session.setAttribute(PENDING, new Intent(authorization, UUID.randomUUID().toString(),
                Instant.now().plus(Duration.ofMinutes(10))));
        }
    }
    public static boolean pending(HttpServletRequest request) {
        var session = request.getSession(false);
        return session != null && session.getAttribute(PENDING) instanceof Intent;
    }
    public static Intent intent(HttpServletRequest request) {
        var session = request.getSession(false);
        var intent = session == null ? null : (Intent) session.getAttribute(PENDING);
        if (intent == null || !Instant.now().isBefore(intent.expiresAt())) {
            throw new IllegalArgumentException("No pending issuer request");
        }
        return intent;
    }
    public static Intent consume(HttpServletRequest request, String binding) {
        var session = request.getSession(false);
        if (session == null) throw new IllegalArgumentException("No browser session");
        synchronized (session) {
            var intent = intent(request);
            if (!intent.binding().equals(binding)) throw new IllegalArgumentException("Browser binding mismatch");
            session.removeAttribute(PENDING);
            return intent;
        }
    }
    public static void accepted(HttpServletRequest request, Accepted accepted) {
        request.getSession().setAttribute(ACCEPTED, accepted);
    }
    public static Accepted consumeAccepted(HttpServletRequest request) {
        var session = request.getSession(false);
        if (session == null) throw new IllegalArgumentException("No browser session");
        synchronized (session) {
            var accepted = (Accepted) session.getAttribute(ACCEPTED);
            session.removeAttribute(ACCEPTED);
            if (accepted == null || !Instant.now().isBefore(accepted.intent().expiresAt())) {
                throw new IllegalArgumentException("No accepted issuer request");
            }
            return accepted;
        }
    }
}
