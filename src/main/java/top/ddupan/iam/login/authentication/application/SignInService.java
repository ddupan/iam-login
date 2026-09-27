package top.ddupan.iam.login.authentication.application;

import java.time.Clock;
import java.util.UUID;
import top.ddupan.iam.login.authentication.application.port.PasswordAuthenticator;
import top.ddupan.iam.login.authentication.domain.UserRepository;
import top.ddupan.iam.login.authentication.application.port.PasswordVerificationException;
import top.ddupan.iam.login.authentication.domain.LoginTransaction;

/** Coordinates the first-factor use case. HTTP/session/LDAP details stay in adapters. */
public final class SignInService {
    public enum PasswordResult { ACCEPTED, REJECTED, EXPIRED, WRONG_STEP, RETRY_LATER }
    private final PasswordAuthenticator authenticator;
    private final Clock clock;
    private final boolean enabled;

    public SignInService(PasswordAuthenticator authenticator, Clock clock, boolean enabled) {
        this.authenticator = authenticator;
        this.clock = clock;
        this.enabled = enabled;
    }

    public boolean enabled() { return enabled; }
    public LoginTransaction start() { return LoginTransaction.start(UUID.randomUUID(), clock.instant()); }
    public boolean expired(LoginTransaction transaction) { return transaction.expiredAt(clock.instant()); }

    public PasswordResult submitPassword(LoginTransaction transaction, String username, String password) {
        if (!enabled) throw new IllegalStateException("Human sign-in is disabled");
        var attempt = transaction.beginPasswordAttempt(clock.instant());
        if (attempt != LoginTransaction.Attempt.ALLOWED) {
            return switch (attempt) {
                case EXPIRED -> PasswordResult.EXPIRED;
                case WRONG_STEP -> PasswordResult.WRONG_STEP;
                case RETRY_LATER -> PasswordResult.RETRY_LATER;
                case ALLOWED -> throw new IllegalStateException("Unexpected attempt result");
            };
        }
        try (var session = authenticator.authenticate(username, password)) {
            var identity = session.users().findByLoginName(session.loginName());
            if (identity.isEmpty()) return PasswordResult.REJECTED;
            // A slow directory response must not revive an expired transaction.
            var verifiedAt = clock.instant();
            if (transaction.expiredAt(verifiedAt)) return PasswordResult.EXPIRED;
            transaction.passwordVerified(identity.orElseThrow(), verifiedAt);
            return PasswordResult.ACCEPTED;
        } catch (PasswordVerificationException | UserRepository.AccessFailure ex) {
            return PasswordResult.REJECTED;
        }
    }
}
