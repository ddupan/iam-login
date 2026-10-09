package top.ddupan.iam.login.authentication.infrastructure.security;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Failed password attempts per account and per client address, checked before the directory is asked. Without it
 * the public sign-in page is an unthrottled password oracle against AD, and AD's own lockout (if enabled) would let
 * anyone lock any account. Rejecting here does not touch AD, so a throttled account is not locked in the directory.
 * Counters live in memory: a restart clears them, which is acceptable for one replica.
 */
public final class SignInThrottle {
    /**
     * A key with {@code accountLimit} (or {@code addressLimit}) failures inside {@code window} is refused until that
     * window ends. The address limit is higher: a household shares one address, and LAN clients may all appear as
     * the gateway. {@code maxEntries} bounds memory against attacker-chosen usernames.
     */
    @ConfigurationProperties("iam.signin.throttle")
    public record Properties(@DefaultValue("5") int accountLimit, @DefaultValue("30") int addressLimit,
            @DefaultValue("15m") Duration window, @DefaultValue("10000") int maxEntries) {
        public Properties {
            // A zero limit would refuse every sign-in; fail at startup instead.
            if (accountLimit < 1 || addressLimit < 1 || window.isNegative() || window.isZero() || maxEntries < 1) {
                throw new IllegalArgumentException("iam.signin.throttle limits and window must be positive");
            }
        }
    }

    private record Window(int failures, Instant start) {}

    private final Map<String, Window> windows = new ConcurrentHashMap<>();
    private final Properties properties;
    private final Clock clock;

    public SignInThrottle(Properties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    public boolean blocked(String username, String address) {
        return failures("u:" + account(username)) >= properties.accountLimit()
            || failures("a:" + address) >= properties.addressLimit();
    }

    public void failed(String username, String address) {
        var now = clock.instant();
        if (windows.size() > properties.maxEntries()) windows.values().removeIf(w -> expired(w, now));
        for (var key : new String[] {"u:" + account(username), "a:" + address}) {
            windows.compute(key, (k, w) -> w == null || expired(w, now) ? new Window(1, now)
                : new Window(w.failures() + 1, w.start()));
        }
    }

    public void succeeded(String username) {
        windows.remove("u:" + account(username));
    }

    private int failures(String key) {
        var w = windows.get(key);
        return w == null || expired(w, clock.instant()) ? 0 : w.failures();
    }

    private boolean expired(Window w, Instant now) {
        return !now.isBefore(w.start().plus(properties.window()));
    }

    // "Alice", "alice" and "alice@ad.ddupan.top" are one AD account, so they share one counter.
    private static String account(String username) {
        var name = username == null ? "" : username.strip().toLowerCase(Locale.ROOT);
        var at = name.indexOf('@');
        return at < 0 ? name : name.substring(0, at);
    }
}
