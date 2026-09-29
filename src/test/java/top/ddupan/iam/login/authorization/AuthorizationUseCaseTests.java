package top.ddupan.iam.login.authorization;

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authorization.application.*;
import top.ddupan.iam.login.authorization.application.port.HydraGateway;
import top.ddupan.iam.login.authorization.domain.AuthorizationRequest;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

class AuthorizationUseCaseTests {
    @Test void consentRejectsChangedBindingSubjectClientScopesAndOriginalChallenge() {
        var gateway = mock(HydraGateway.class);
        var user = new User(new User.UserId("directory", "id"), "alice", "Alice", "", List.of());
        var useCase = new AuthorizeApplication(new AuthorizationPolicy(Set.of("gitea"), Map.of(user.id(), "old-sub")), gateway);
        var expected = new AuthorizationRequest("opaque-login-challenge", "gitea", List.of("openid"), List.of(),
            "", null, null, "https://issuer/oauth2/auth", false);
        for (var consent : List.of(
                request("other", "old-sub", "binding", expected.challengeDigest(), List.of("openid")),
                request("gitea", "other-sub", "binding", expected.challengeDigest(), List.of("openid")),
                request("gitea", "old-sub", "other-browser", expected.challengeDigest(), List.of("openid")),
                request("gitea", "old-sub", "binding", "another-login", List.of("openid")),
                request("gitea", "old-sub", "binding", expected.challengeDigest(), List.of("openid", "groups")))) {
            when(gateway.consent("consent")).thenReturn(consent);
            assertThatIllegalArgumentException().isThrownBy(() -> useCase.consent(expected, "binding", "old-sub", user, "consent"));
        }
        verify(gateway, never()).acceptConsent(anyString(), anyList(), anyMap());
    }
    @Test void rememberedIssuerSessionStillRequiresMatchingAuthenticatedUser() {
        var gateway = mock(HydraGateway.class);
        var user = new User(new User.UserId("directory", "id"), "alice", "Alice", "", List.of());
        var useCase = new AuthorizeApplication(new AuthorizationPolicy(Set.of("gitea"), Map.of(user.id(), "old-sub")), gateway);
        var at = java.time.Instant.now();
        for (String subject : List.of("other-sub", "")) {
            var request = new AuthorizationRequest("challenge", "gitea", List.of("openid"), List.of(),
                subject, null, null, "https://issuer/oauth2/auth", true);
            when(gateway.login("challenge")).thenReturn(request);
            assertThatIllegalArgumentException().isThrownBy(() -> useCase.login(request,"binding",user,at));
        }
        verify(gateway, never()).acceptLogin(anyString(),anyString(),anyString(),any());
        var request = new AuthorizationRequest("challenge", "gitea", List.of("openid"), List.of(),
            "old-sub", null, null, "https://issuer/oauth2/auth", true);
        when(gateway.login("challenge")).thenReturn(request);
        when(gateway.acceptLogin("challenge","old-sub","binding",at)).thenReturn("https://issuer/oauth2/auth");
        assertThat(useCase.start("challenge")).isEqualTo(request);
        assertThat(useCase.login(request,"binding",user,at).subject()).isEqualTo("old-sub");
    }
    private AuthorizationRequest request(String client, String subject, String binding, String digest, List<String> scopes) {
        return new AuthorizationRequest("consent", client, scopes, List.of(), subject, digest, binding, "https://issuer/oauth2/auth", false);
    }
}
