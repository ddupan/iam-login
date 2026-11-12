package top.ddupan.iam.login.configuration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.FactorAuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authentication.domain.UserRepository;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;

class ActiveAccountTests {
    private final Instant signedIn = Instant.parse("2026-11-11T08:00:00Z");
    private final User user = new User(new User.UserId("example.test", "guid"), "alice", "Alice", "", List.of());
    private final Authentication session = UsernamePasswordAuthenticationToken.authenticated(new DirectoryPrincipal(user), null,
        List.of(FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY).issuedAt(signedIn).build()));
    private final UserRepository users = mock(UserRepository.class);

    private AuthorizationResult decide(boolean factors) {
        return new AuthorizationServerConfiguration.ActiveAccount((a, o) -> new AuthorizationDecision(factors), users)
            .authorize(() -> session, new Object());
    }

    private void directory(Instant passwordChangedAt) {
        when(users.findActive(user.id())).thenReturn(Optional.of(
            new User(user.id(), "alice", "Alice", "", List.of(), passwordChangedAt)));
    }

    /** Refused as a missing password factor, so the browser is sent to sign in again. */
    private void signInAgain(AuthorizationResult result) {
        assertThat(result).isInstanceOfSatisfying(FactorAuthorizationDecision.class, d -> {
            assertThat(d.isGranted()).isFalse();
            assertThat(d.getFactorErrors()).singleElement().satisfies(e -> {
                assertThat(e.isMissing()).isTrue();
                assertThat(e.getRequiredFactor().getAuthority()).isEqualTo(FactorGrantedAuthority.PASSWORD_AUTHORITY);
            });
        });
    }

    @Test void anActiveAccountWithTheFactorsEnters() {
        directory(null);
        assertThat(decide(true).isGranted()).isTrue();
        assertThat(decide(false).isGranted()).isFalse();
        directory(signedIn.minusSeconds(3600));
        assertThat(decide(true).isGranted()).as("password changed before this sign-in").isTrue();
        directory(signedIn.plusSeconds(30));
        assertThat(decide(true).isGranted()).as("within the DC clock skew").isTrue();
    }

    @Test void aPasskeySignInAfterThePasswordChangeCounts() {
        directory(signedIn.plusSeconds(600));
        // Merged into the session, the old password factor stays; the later passkey is what proves the person.
        var merged = UsernamePasswordAuthenticationToken.authenticated(new DirectoryPrincipal(user), null, List.of(
            FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY).issuedAt(signedIn).build(),
            FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.WEBAUTHN_AUTHORITY).issuedAt(signedIn.plusSeconds(900)).build()));
        var gate = new AuthorizationServerConfiguration.ActiveAccount((a, o) -> new AuthorizationDecision(true), users);
        assertThat(gate.authorize(() -> merged, new Object()).isGranted()).isTrue();
        var passkeyBefore = UsernamePasswordAuthenticationToken.authenticated(new DirectoryPrincipal(user), null, List.of(
            FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.WEBAUTHN_AUTHORITY).issuedAt(signedIn).build()));
        signInAgain(gate.authorize(() -> passkeyBefore, new Object()));
    }

    @Test void aChangedPasswordOrAnInactiveAccountMustSignInAgain() {
        directory(signedIn.plusSeconds(600));
        signInAgain(decide(true));
        directory(Instant.MAX);   // pwdLastSet 0: must change at next logon
        signInAgain(decide(true));

        when(users.findActive(user.id())).thenReturn(Optional.empty());
        signInAgain(decide(true));   // disabled or deleted in the directory
        when(users.findActive(user.id())).thenThrow(new UserRepository.AccessFailure());
        signInAgain(decide(true));   // directory unreachable
    }
}
