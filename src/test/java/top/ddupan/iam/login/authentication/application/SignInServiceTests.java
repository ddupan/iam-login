package top.ddupan.iam.login.authentication.application;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import top.ddupan.iam.login.authentication.application.port.AuthenticatedUserSession;
import top.ddupan.iam.login.authentication.application.port.PasswordVerificationException;
import top.ddupan.iam.login.authentication.domain.LoginTransaction;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authentication.domain.UserRepository;
import static org.assertj.core.api.Assertions.*;

class SignInServiceTests {
    static final User ALICE = new User(new User.UserId("directory", "alice-id"), "alice", "Alice", "", List.of());

    @Test
    void verifiesPasswordThenReadsTheBoundUserAndClosesTheRepositoryScope() {
        var scope = new Scope(name -> {
            assertThat(name).isEqualTo("alice@directory");
            return Optional.of(ALICE);
        });
        var service = new SignInService((username, password) -> scope, new TestClock(), true);
        var transaction = service.start();
        assertThat(service.submitPassword(transaction, "alice", "secret")).isEqualTo(SignInService.PasswordResult.ACCEPTED);
        assertThat(scope.closed).isTrue();
        assertThat(transaction.step()).isEqualTo(LoginTransaction.Step.MFA_REQUIRED);
        assertThat(transaction.identity()).isEqualTo(ALICE);
    }

    @Test
    void failedAuthenticationDoesNotAdvanceTheTransaction() {
        var service = new SignInService((username, password) -> {
            throw new PasswordVerificationException(PasswordVerificationException.Reason.REJECTED);
        }, new TestClock(), true);
        var transaction = service.start();
        assertThat(service.submitPassword(transaction, "alice", "wrong")).isEqualTo(SignInService.PasswordResult.REJECTED);
        assertThat(transaction.step()).isEqualTo(LoginTransaction.Step.PASSWORD_REQUIRED);
    }

    @Test
    void missingUserDoesNotAuthenticateAndStillClosesTheScope() {
        var scope = new Scope(name -> Optional.empty());
        var service = new SignInService((username, password) -> scope, new TestClock(), true);
        var transaction = service.start();
        assertThat(service.submitPassword(transaction, "alice", "secret")).isEqualTo(SignInService.PasswordResult.REJECTED);
        assertThat(scope.closed).isTrue();
        assertThat(transaction.step()).isEqualTo(LoginTransaction.Step.PASSWORD_REQUIRED);
    }

    @Test
    void expiredAndRepeatedAttemptsDoNotCallTheDirectory() {
        var calls = new AtomicInteger();
        var clock = new TestClock();
        var service = new SignInService((username, password) -> {
            calls.incrementAndGet();
            throw new PasswordVerificationException(PasswordVerificationException.Reason.REJECTED);
        }, clock, true);
        var transaction = service.start();
        service.submitPassword(transaction, "alice", "wrong");
        assertThat(service.submitPassword(transaction, "alice", "wrong")).isEqualTo(SignInService.PasswordResult.RETRY_LATER);
        clock.now = clock.now.plusSeconds(600);
        assertThat(service.submitPassword(transaction, "alice", "wrong")).isEqualTo(SignInService.PasswordResult.EXPIRED);
        assertThat(calls.get()).isEqualTo(1);
    }

    @Test
    void aSlowRepositoryCannotReviveAnExpiredTransaction() {
        var clock = new TestClock();
        var scope = new Scope(name -> { clock.now = clock.now.plusSeconds(600); return Optional.of(ALICE); });
        var service = new SignInService((username, password) -> scope, clock, true);
        var transaction = service.start();
        assertThat(service.submitPassword(transaction, "alice", "secret")).isEqualTo(SignInService.PasswordResult.EXPIRED);
        assertThat(transaction.step()).isEqualTo(LoginTransaction.Step.PASSWORD_REQUIRED);
        assertThat(scope.closed).isTrue();
    }

    @Test
    void repositoryFailureClosesTheScopeWithoutPromotingIdentity() {
        var scope = new Scope(name -> { throw new UserRepository.AccessFailure(); });
        var service = new SignInService((username, password) -> scope, new TestClock(), true);
        var transaction = service.start();
        assertThat(service.submitPassword(transaction, "alice", "secret")).isEqualTo(SignInService.PasswordResult.REJECTED);
        assertThat(transaction.step()).isEqualTo(LoginTransaction.Step.PASSWORD_REQUIRED);
        assertThat(scope.closed).isTrue();
    }

    private static final class Scope implements AuthenticatedUserSession {
        private final UserRepository users;
        boolean closed;
        Scope(UserRepository users) { this.users = users; }
        @Override public String loginName() { return "alice@directory"; }
        @Override public UserRepository users() { return users; }
        @Override public void close() { closed = true; }
    }

    private static final class TestClock extends Clock {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        @Override public Instant instant() { return now; }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return Clock.fixed(now, zone); }
    }
}
