package top.ddupan.iam.login.configuration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authentication.domain.UserRepository;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;

class ActiveAccountTests {
    private final User user = new User(new User.UserId("example.test", "guid"), "alice", "Alice", "", List.of());
    private final Authentication signedIn = UsernamePasswordAuthenticationToken.authenticated(new DirectoryPrincipal(user), null, List.of());
    private final UserRepository users = mock(UserRepository.class);

    private boolean granted(boolean factors) {
        return new AuthorizationServerConfiguration.ActiveAccount((a, o) -> new AuthorizationDecision(factors), users)
            .authorize(() -> signedIn, new Object()).isGranted();
    }

    @Test void anAccountMustHoldTheFactorsAndStillBeActive() {
        when(users.findActive(user.id())).thenReturn(Optional.of(user));
        assertThat(granted(true)).isTrue();
        assertThat(granted(false)).isFalse();

        when(users.findActive(user.id())).thenReturn(Optional.empty());
        assertThat(granted(true)).as("disabled or deleted in the directory").isFalse();

        when(users.findActive(user.id())).thenThrow(new UserRepository.AccessFailure());
        assertThat(granted(true)).as("directory unreachable").isFalse();
    }
}
