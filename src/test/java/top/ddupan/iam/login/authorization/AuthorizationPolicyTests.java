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
    @Test void clientsScopesAndAudienceFailClosed() {
        assertThatIllegalArgumentException().isThrownBy(() -> policy.validate(request("other", List.of("openid"), List.of())));
        assertThatIllegalArgumentException().isThrownBy(() -> policy.validate(request("gitea", List.of("openid", "offline_access"), List.of())));
        assertThatIllegalArgumentException().isThrownBy(() -> policy.validate(request("gitea", List.of("openid"), List.of("other-api"))));
    }
    @Test void registeredMetadataAllowsNewClientsAndExplicitDisableOverridesLegacyAllowlist() {
        var enabled=new AuthorizationRequest("challenge","new-client",List.of("openid"),List.of(),"",null,null,"https://issuer/oauth2/auth",false,true);
        policy.validate(enabled);
        var disabled=new AuthorizationRequest("challenge","gitea",List.of("openid"),List.of(),"",null,null,"https://issuer/oauth2/auth",false,false);
        assertThatIllegalArgumentException().isThrownBy(() -> policy.validate(disabled));
    }
    @Test void managementScopeOnlyForManagementClientAndDirectAdministrators() {
        var managed = new AuthorizationPolicy(Set.of("gitea", "iam-admin-ui"), Map.of(user.id(), "human:old-issuer-sub-hash"),
            "iam-admin-ui", candidate -> candidate.memberships().stream().anyMatch(group -> group.name().equals("gitea-admins")));
        var manage = List.of("openid", AuthorizationPolicy.MANAGE_CLIENTS);
        managed.permit(user, request("iam-admin-ui", manage, List.of()));
        assertThat(managed.claims(user, request("iam-admin-ui", manage, List.of()))).isEmpty();
        // Ordinary applications cannot obtain the scope, even for an administrator.
        assertThatIllegalArgumentException().isThrownBy(() -> managed.validate(request("gitea", manage, List.of())));
        var member = new User(user.id(), user.username(), user.displayName(), user.email(), List.of());
        assertThatIllegalArgumentException().isThrownBy(() -> managed.permit(member, request("iam-admin-ui", manage, List.of())));
        assertThatIllegalArgumentException().isThrownBy(() -> managed.claims(member, request("iam-admin-ui", manage, List.of())));
        managed.permit(member, request("iam-admin-ui", List.of("openid"), List.of()));
        // Without a configured management client the scope does not exist.
        assertThatIllegalArgumentException().isThrownBy(() -> policy.validate(request("gitea", manage, List.of())));
    }
    private AuthorizationRequest request(String client, List<String> scopes, List<String> audience) {
        return new AuthorizationRequest("challenge", client, scopes, audience, "", null, null, "https://issuer/oauth2/auth", false);
    }
}
