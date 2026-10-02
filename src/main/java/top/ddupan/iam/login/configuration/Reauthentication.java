package top.ddupan.iam.login.configuration;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Set;
import java.util.TreeMap;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * prompt=login and max_age (OIDC Core 3.1.2.1): the framework's authorization endpoint honours neither and
 * reuses any existing session. When a request demands a fresh authentication, the time of that demand is
 * remembered in the session and the current authentication is forgotten, so the endpoint sends the browser
 * to sign in; the session itself survives, keeping the interrupted request and the marker. The request is
 * satisfied once a factor was issued after the demand, which also makes the ID token's auth_time (the latest
 * factor) move forward. Keying the marker on the request makes the resumed request, which is identical,
 * recognise its own demand instead of looping.
 */
final class Reauthentication extends OncePerRequestFilter {
    private static final String MARKER = Reauthentication.class.getName() + ".";
    private final Clock clock;
    private final SecurityContextHolderStrategy contexts = SecurityContextHolder.getContextHolderStrategy();
    private final SecurityContextRepository repository = new HttpSessionSecurityContextRepository();

    Reauthentication(Clock clock) { this.clock = clock; }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !"/oauth2/authorize".equals(request.getRequestURI()) || request.getParameter("response_type") == null;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        var prompt = request.getParameter("prompt");
        var login = prompt != null && Set.of(prompt.trim().split("\\s+")).contains("login");
        var maxAge = maxAge(request.getParameter("max_age"));
        if (!login && maxAge == null) { chain.doFilter(request, response); return; }

        var authentication = contexts.getContext().getAuthentication();
        var authenticatedAt = authenticatedAt(authentication);
        var key = MARKER + digest(request);
        var session = request.getSession(false);
        var demandedAt = session == null ? null : (Instant) session.getAttribute(key);
        var now = clock.instant();
        if (demandedAt != null && authenticatedAt != null && authenticatedAt.isAfter(demandedAt)) {
            session.removeAttribute(key); // re-authenticated since the demand
        } else if (login || authenticatedAt == null || authenticatedAt.isBefore(now.minusSeconds(maxAge))) {
            if (demandedAt == null) request.getSession(true).setAttribute(key, now);
            if (authenticatedAt != null) {
                var empty = contexts.createEmptyContext();
                contexts.setContext(empty);
                repository.saveContext(empty, request, response);
            }
        }
        chain.doFilter(request, response);
    }

    /** Same instant the framework puts into auth_time: the most recent factor. */
    private static Instant authenticatedAt(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) return null;
        return authentication.getAuthorities().stream().filter(FactorGrantedAuthority.class::isInstance)
            .map(authority -> ((FactorGrantedAuthority) authority).getIssuedAt()).max(Instant::compareTo).orElse(null);
    }

    private static Long maxAge(String value) {
        try { return value == null ? null : Math.max(0, Long.parseLong(value.trim())); }
        catch (NumberFormatException invalid) { return null; } // not a duration: ignored, as an unknown parameter would be
    }

    private static String digest(HttpServletRequest request) {
        var canonical = new StringBuilder();
        new TreeMap<>(request.getParameterMap()).forEach((name, values) -> canonical.append(name).append('=')
            .append(String.join(",", values)).append('&'));
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(canonical.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
}
