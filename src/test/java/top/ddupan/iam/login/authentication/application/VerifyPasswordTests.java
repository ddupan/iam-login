package top.ddupan.iam.login.authentication.application;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import top.ddupan.iam.login.authentication.application.port.AuthenticatedUserSession;
import top.ddupan.iam.login.authentication.application.port.PasswordVerificationException;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authentication.domain.UserRepository;
import static org.assertj.core.api.Assertions.*;

class VerifyPasswordTests {
    static final User ALICE = new User(new User.UserId("directory", "alice-id"), "alice", "Alice", "", List.of());

    @Test
    void readsTheBoundUserAndClosesTheConnection() {
        var scope = new Scope(name -> {
            assertThat(name).isEqualTo("alice@directory");
            return Optional.of(ALICE);
        });
        assertThat(new VerifyPassword((username, password) -> scope).verify("alice", "secret")).isEqualTo(ALICE);
        assertThat(scope.closed).isTrue();
    }

    @Test
    void missingUserClosesTheConnectionAndRejectsAuthentication() {
        var scope = new Scope(name -> Optional.empty());
        assertThatThrownBy(() -> new VerifyPassword((u, p) -> scope).verify("alice", "secret"))
            .isInstanceOf(PasswordVerificationException.class);
        assertThat(scope.closed).isTrue();
    }

    @Test
    void repositoryFailureStillClosesTheConnection() {
        var scope = new Scope(name -> { throw new UserRepository.AccessFailure(); });
        assertThatThrownBy(() -> new VerifyPassword((u, p) -> scope).verify("alice", "secret"))
            .isInstanceOf(UserRepository.AccessFailure.class);
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
}
