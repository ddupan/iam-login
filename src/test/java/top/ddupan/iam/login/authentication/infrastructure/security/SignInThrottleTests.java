package top.ddupan.iam.login.authentication.infrastructure.security;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class SignInThrottleTests {
    private Instant now = Instant.parse("2026-10-09T00:00:00Z");
    private final SignInThrottle.Properties limits = new SignInThrottle.Properties(5, 30, Duration.ofMinutes(15), 10_000);
    private final SignInThrottle throttle = new SignInThrottle(limits, new Clock() {
        @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    });

    @Test
    void accountIsBlockedAfterTheLimitUntilTheWindowEnds() {
        for (int i = 0; i < limits.accountLimit(); i++) throttle.failed("Alice", "a" + i);
        assertThat(throttle.blocked("alice@ad.ddupan.top", "elsewhere")).isTrue();
        assertThat(throttle.blocked("bob", "elsewhere")).isFalse();
        now = now.plus(limits.window());
        assertThat(throttle.blocked("alice", "elsewhere")).isFalse();
    }

    @Test
    void successClearsTheAccountButNotTheAddress() {
        for (int i = 0; i < limits.addressLimit(); i++) throttle.failed("user" + i, "198.51.100.7");
        throttle.failed("alice", "198.51.100.8");
        throttle.succeeded("alice");
        assertThat(throttle.blocked("someone-else", "198.51.100.7")).isTrue();
        assertThat(throttle.blocked("alice", "198.51.100.8")).isFalse();
    }
}
