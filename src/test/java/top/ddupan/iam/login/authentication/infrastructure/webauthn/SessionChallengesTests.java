package top.ddupan.iam.login.authentication.infrastructure.webauthn;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.management.MapPublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.MapUserCredentialRepository;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;
import static org.assertj.core.api.Assertions.*;

class SessionChallengesTests {
    private final MfaPolicy policy = new MfaPolicy(new MapPublicKeyCredentialUserEntityRepository(), new MapUserCredentialRepository());
    @AfterEach void clear() { SecurityContextHolder.clearContext(); }

    @Test
    void challengesExpireAndAreBoundToCurrentIdentity() {
        var issued = Instant.now();
        var request = new MockHttpServletRequest();
        var response = new MockHttpServletResponse();
        identify("alice", issued);
        var repository = new SessionChallenges(Clock.fixed(issued, ZoneOffset.UTC), policy).authentication();
        var options = PublicKeyCredentialRequestOptions.builder().rpId("localhost").challenge(Bytes.random()).build();
        repository.save(request, response, options);
        var later = new SessionChallenges(Clock.fixed(issued.plusSeconds(301), ZoneOffset.UTC), policy).authentication();
        assertThat(later.load(request)).isNull();
        repository.save(request, response, options);
        identify("bob", issued);
        assertThat(repository.load(request)).isNull();
        identify("alice", issued);
        assertThat(repository.load(request)).isNull();
    }

    @Test
    void challengeIsConsumedOnceAndUpstreamCleanupCannotEraseNewChallenge() {
        var issued = Instant.now();
        identify("alice", issued);
        var request = new MockHttpServletRequest();
        var response = new MockHttpServletResponse();
        var repository = new SessionChallenges(Clock.systemUTC(), policy).authentication();
        var first = PublicKeyCredentialRequestOptions.builder().rpId("localhost").challenge(Bytes.random()).build();
        var second = PublicKeyCredentialRequestOptions.builder().rpId("localhost").challenge(Bytes.random()).build();
        repository.save(request, response, first);
        assertThat(repository.load(request)).isSameAs(first);
        assertThat(repository.load(request)).isNull();
        repository.save(request, response, second);
        repository.save(request, response, null);
        assertThat(repository.load(request)).isSameAs(second);
        repository.save(request, response, first);
        identify("alice", issued.minusSeconds(601));
        assertThat(repository.load(request)).isNull();
    }

    private static void identify(String id, Instant issued) {
        var user = new User(new User.UserId("example.test", id), id, id, "", List.of());
        SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
            new DirectoryPrincipal(user), null, List.of(FactorGrantedAuthority.withAuthority("FACTOR_PASSWORD")
                .issuedAt(issued).build())));
    }
}
