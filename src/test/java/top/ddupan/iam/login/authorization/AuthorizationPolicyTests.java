package top.ddupan.iam.login.authorization;

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authorization.application.AuthorizationPolicy;
import top.ddupan.iam.login.authorization.domain.AuthorizationRequest;
import static org.assertj.core.api.Assertions.*;

class AuthorizationPolicyTests {
    private final User user = new User(new User.UserId("example.test", "immutable-guid"), "alice", "Alice",
        "alice@example.test", List.of(new User.GroupMembership("gitea-admins", "CN=gitea-admins,DC=example,DC=test")));
    private final AuthorizationPolicy policy = new AuthorizationPolicy(Set.of("gitea"), Map.of(user.id(), "human:old-issuer-sub-hash"));

    @Test void subjectContinuityRequiresExplicitImmutableBinding() {
        assertThat(policy.subject(user)).isEqualTo("human:old-issuer-sub-hash");
        var renamed = new User(user.id(), "renamed", "Renamed", "new@example.test", List.of());
        assertThat(policy.subject(renamed)).isEqualTo(policy.subject(user));
        var impostor = new User(new User.UserId("example.test", "another-guid"), user.username(), user.displayName(), user.email(), List.of());
        assertThatIllegalArgumentException().isThrownBy(() -> policy.subject(impostor));
        assertThatIllegalArgumentException().isThrownBy(() -> new AuthorizationPolicy(Set.of("gitea"),
            Map.of(user.id(), "same-sub", impostor.id(), "same-sub")));
    }
    @Test void claimsFollowRequestedScopesAndDoNotInventMailboxVerification() {
        assertThat(policy.claims(user, request("gitea", List.of("openid"), List.of()))).isEmpty();
        var claims = policy.claims(user, request("gitea", List.of("openid", "email", "groups"), List.of()));
        assertThat(claims).containsEntry("email_verified", false).containsEntry("groups", List.of("gitea-admins"))
            .doesNotContainKey("preferred_username");
    }
    @Test void unknownClientsAndNonOidcRequestsFailClosed() {
        assertThatIllegalArgumentException().isThrownBy(() -> policy.validate(request("other", List.of("openid"), List.of())));
        assertThatIllegalArgumentException().isThrownBy(() -> policy.validate(request("gitea", List.of("profile"), List.of())));
    }
    @Test void scopesAndAudiencesRegisteredWithTheIssuerPassThrough() {
        // Hydra has already limited both to the client's registration; neither is a permission here.
        policy.validate(request("gitea", List.of("openid", "custom.read"), List.of("some-api")));
    }
    @Test void groupsReachTheAccessTokenOnlyWhenRequested() {
        assertThat(policy.accessTokenClaims(user, request("gitea", List.of("openid", "groups"), List.of("iam-login"))))
            .isEqualTo(Map.of("groups", List.of("gitea-admins")));
        assertThat(policy.accessTokenClaims(user, request("gitea", List.of("openid", "profile"), List.of("iam-login")))).isEmpty();
    }
    @Test void registeredMetadataAllowsNewClientsAndExplicitDisableOverridesLegacyAllowlist() {
        var enabled=new AuthorizationRequest("challenge","new-client",List.of("openid"),List.of(),"",null,null,"https://issuer/oauth2/auth",false,true);
        policy.validate(enabled);
        var disabled=new AuthorizationRequest("challenge","gitea",List.of("openid"),List.of(),"",null,null,"https://issuer/oauth2/auth",false,false);
        assertThatIllegalArgumentException().isThrownBy(() -> policy.validate(disabled));
    }
    private AuthorizationRequest request(String client, List<String> scopes, List<String> audience) {
        return new AuthorizationRequest("challenge", client, scopes, audience, "", null, null, "https://issuer/oauth2/auth", false);
    }
}
