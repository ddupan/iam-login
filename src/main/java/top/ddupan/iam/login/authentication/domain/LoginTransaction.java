package top.ddupan.iam.login.authentication.domain;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Owns first-factor ordering, lifetime and the identity to which further factors must bind. */
public final class LoginTransaction {
    private static final Duration LIFETIME = Duration.ofMinutes(10);
    private static final Duration ATTEMPT_INTERVAL = Duration.ofSeconds(2);

    public enum Step { PASSWORD_REQUIRED, MFA_REQUIRED }
    public enum Attempt { ALLOWED, EXPIRED, WRONG_STEP, RETRY_LATER }

    private final UUID id;
    private Step step = Step.PASSWORD_REQUIRED;
    private Instant expiresAt;
    private Instant retryAfter = Instant.MIN;
    private User identity;

    private LoginTransaction(UUID id, Instant now) {
        this.id = Objects.requireNonNull(id);
        this.expiresAt = now.plus(LIFETIME);
    }

    public static LoginTransaction start(UUID id, Instant now) {
        return new LoginTransaction(id, now);
    }

    public Attempt beginPasswordAttempt(Instant now) {
        if (expiredAt(now)) return Attempt.EXPIRED;
        if (step != Step.PASSWORD_REQUIRED) return Attempt.WRONG_STEP;
        if (now.isBefore(retryAfter)) return Attempt.RETRY_LATER;
        retryAfter = now.plus(ATTEMPT_INTERVAL);
        return Attempt.ALLOWED;
    }

    public void passwordVerified(User identity, Instant now) {
        if (expiredAt(now) || step != Step.PASSWORD_REQUIRED) {
            throw new IllegalStateException("Password verification is not allowed in this transaction state");
        }
        this.identity = Objects.requireNonNull(identity);
        this.step = Step.MFA_REQUIRED;
        this.expiresAt = now.plus(LIFETIME);
    }

    public UUID id() { return id; }
    public Step step() { return step; }
    public boolean expiredAt(Instant now) { return !now.isBefore(expiresAt); }

    public User identity() {
        if (identity == null) throw new IllegalStateException("No verified identity yet");
        return identity;
    }
}
