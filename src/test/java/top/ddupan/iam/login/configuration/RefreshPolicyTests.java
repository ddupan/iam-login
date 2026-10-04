package top.ddupan.iam.login.configuration;

import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;
import top.ddupan.iam.login.authorization.application.SubjectBindings;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class RefreshPolicyTests {
    private final User user = new User(new User.UserId("example.test", "guid"), "alice", "Alice", "", List.of());
    private final RegisteredClient client = RegisteredClient.withId("id").clientId("rp")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN).redirectUri("https://rp.example/cb").build();

    @Test void refreshStopsOnceTheSubjectBindingIsWithdrawn() {
        var authorizations = mock(OAuth2AuthorizationService.class);
        when(authorizations.findByToken("refresh", OAuth2TokenType.REFRESH_TOKEN)).thenReturn(
            OAuth2Authorization.withRegisteredClient(client).principalName(user.username())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(Principal.class.getName(), UsernamePasswordAuthenticationToken.authenticated(new DirectoryPrincipal(user), null, List.of()))
                .build());
        var request = new OAuth2RefreshTokenAuthenticationToken("refresh",
            new OAuth2ClientAuthenticationToken(client, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null), Set.of(), Map.of());
        var bound = new AuthorizationConfigurationAccess(new SubjectBindings(Map.of(user.id(), "human:sub")));
        assertThat(bound.gate(authorizations).authenticate(request)).as("allowed: defer to the framework").isNull();
        var withdrawn = new AuthorizationConfigurationAccess(new SubjectBindings(Map.of(new User.UserId("example.test", "other"), "human:other")));
        assertThatThrownBy(() -> withdrawn.gate(authorizations).authenticate(request))
            .isInstanceOfSatisfying(OAuth2AuthenticationException.class, ex -> assertThat(ex.getError().getErrorCode()).isEqualTo("invalid_grant"));
    }

    private record AuthorizationConfigurationAccess(SubjectBindings policy) {
        AuthorizationServerConfiguration.RefreshPolicy gate(OAuth2AuthorizationService authorizations) {
            return new AuthorizationServerConfiguration.RefreshPolicy(authorizations, policy);
        }
    }
}
