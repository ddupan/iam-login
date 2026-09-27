package top.ddupan.iam.login.authentication.domain;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class LoginTransactionTests {
    static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    static final User ALICE = new User(new User.UserId("directory", "alice-id"), "alice", "Alice", "", List.of());

    @Test
    void passwordVerificationBindsIdentityAndOnlyAdvancesToMfa() {
        var transaction = LoginTransaction.start(UUID.randomUUID(), NOW);
        assertThat(transaction.beginPasswordAttempt(NOW)).isEqualTo(LoginTransaction.Attempt.ALLOWED);
        transaction.passwordVerified(ALICE, NOW);
        assertThat(transaction.step()).isEqualTo(LoginTransaction.Step.MFA_REQUIRED);
        assertThat(transaction.identity()).isEqualTo(ALICE);
        assertThat(transaction.beginPasswordAttempt(NOW.plusSeconds(3))).isEqualTo(LoginTransaction.Attempt.WRONG_STEP);
        var bob = new User(new User.UserId("directory", "bob-id"), "bob", "Bob", "", List.of());
        assertThatThrownBy(() -> transaction.passwordVerified(bob, NOW.plusSeconds(3)))
            .isInstanceOf(IllegalStateException.class);
        assertThat(transaction.identity()).isEqualTo(ALICE);
    }

    @Test
    void expiredTransactionsCannotAcceptAPasswordResult() {
        var transaction = LoginTransaction.start(UUID.randomUUID(), NOW);
        assertThat(transaction.beginPasswordAttempt(NOW.plusSeconds(600))).isEqualTo(LoginTransaction.Attempt.EXPIRED);
        assertThatThrownBy(() -> transaction.passwordVerified(ALICE, NOW.plusSeconds(600)))
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void attemptsAreSeparatedWithoutAdvancingAuthentication() {
        var transaction = LoginTransaction.start(UUID.randomUUID(), NOW);
        assertThat(transaction.beginPasswordAttempt(NOW)).isEqualTo(LoginTransaction.Attempt.ALLOWED);
        assertThat(transaction.beginPasswordAttempt(NOW.plusSeconds(1))).isEqualTo(LoginTransaction.Attempt.RETRY_LATER);
        assertThat(transaction.beginPasswordAttempt(NOW.plusSeconds(2))).isEqualTo(LoginTransaction.Attempt.ALLOWED);
        assertThat(transaction.step()).isEqualTo(LoginTransaction.Step.PASSWORD_REQUIRED);
        assertThatThrownBy(transaction::identity).isInstanceOf(IllegalStateException.class);
    }
}
