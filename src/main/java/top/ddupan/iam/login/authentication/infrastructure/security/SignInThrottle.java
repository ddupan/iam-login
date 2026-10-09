package top.ddupan.iam.login.authentication.infrastructure.security;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Failed password attempts per account and per client address, checked before the directory is asked. Without it
 * the public sign-in page is an unthrottled password oracle against AD, and AD's own lockout (if enabled) would let
 * anyone lock any account. Rejecting here does not touch AD, so a throttled account is not locked in the directory.
 * ponytail: in memory, so it resets on restart and assumes one replica; move to the database if iam-login scales out.
 */
public final class SignInThrottle {
    static final int ACCOUNT_LIMIT = 5;
    // Higher than the account limit: a household shares one address, and LAN clients may all appear as the gateway.
    static final int ADDRESS_LIMIT = 30;
    static final Duration WINDOW = Duration.ofMinutes(15);
    private static final int PRUNE_ABOVE = 10_000;

    private record Window(int failures, Instant start) {}

    private final Map<String, Window> windows = new ConcurrentHashMap<>();
    private final Clock clock;

    public SignInThrottle(Clock clock) {
        this.clock = clock;
    }

    public boolean blocked(String username, String address) {
        return failures("u:" + account(username)) >= ACCOUNT_LIMIT || failures("a:" + address) >= ADDRESS_LIMIT;
    }

    public void failed(String username, String address) {
        var now = clock.instant();
        if (windows.size() > PRUNE_ABOVE) windows.values().removeIf(w -> expired(w, now));
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

    private static boolean expired(Window w, Instant now) {
        return !now.isBefore(w.start().plus(WINDOW));
    }

    // "Alice", "alice" and "alice@ad.ddupan.top" are one AD account, so they share one counter.
    private static String account(String username) {
        var name = username == null ? "" : username.strip().toLowerCase(Locale.ROOT);
        var at = name.indexOf('@');
        return at < 0 ? name : name.substring(0, at);
    }
}
