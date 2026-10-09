package top.ddupan.iam.login.clients;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import top.ddupan.iam.login.clients.domain.OidcClient;
import static org.assertj.core.api.Assertions.*;

class OidcClientTests {
    @Test void rejectsCallbackWildcardsFragmentsAndInsecureNonLoopback() {
        for (var target : List.of("https://rp.example/*", "https://rp.example/callback#x", "http://rp.example/callback",
                "https://user@rp.example/callback")) {
            assertThatIllegalArgumentException().isThrownBy(() -> client(List.of(target), Set.of("openid"), true));
        }
        client(List.of("http://localhost:8080/callback"), Set.of("openid"), true);
    }

    @Test void acceptsAnyWellFormedScopeButRequiresOpenid() {
        client(List.of("https://rp.example/cb"), Set.of("openid", "offline_access", "api:read"), true);
        for (var scopes : List.of(Set.of("profile"), Set.of("openid", "has space"), Set.of("openid", "quote\""), Set.of("openid", ""))) {
            assertThatIllegalArgumentException().isThrownBy(() -> client(List.of("https://rp.example/cb"), scopes, true));
        }
    }

    @Test void loginEnabledMustBeStated() {
        assertThatIllegalArgumentException().isThrownBy(() -> client(List.of("https://rp.example/cb"), Set.of("openid"), null));
    }

    @Test void pkceRequiredMustBeStated() {
        assertThatIllegalArgumentException().isThrownBy(
            () -> new OidcClient("id", "Name", List.of("https://rp.example/cb"), Set.of("openid"), List.of(), true, null));
    }

    @Test void newFieldsDefaultToOffAndPublicClientsNeedPkce() {
        var plain = new OidcClient("id", "Name", List.of("https://rp.example/cb"), Set.of("openid"), null, true, true, null, null, null);
        assertThat(plain.publicClient()).isFalse();
        assertThat(plain.deviceAuthorization()).isFalse();
        assertThat(plain.audiences()).isEmpty();
        assertThatIllegalArgumentException().isThrownBy(() -> new OidcClient("id", "Name", List.of("https://rp.example/cb"),
            Set.of("openid"), List.of(), true, false, true, false, List.of()));
    }

    @Test void audiencesAreSingleValuesWithoutSeparators() {
        new OidcClient("id", "Name", List.of("https://rp.example/cb"), Set.of("openid"), List.of(), true, true, false, false,
            List.of("https://incus.example"));
        for (var audience : List.of("a,b", " padded", "")) {
            assertThatIllegalArgumentException().isThrownBy(() -> new OidcClient("id", "Name", List.of("https://rp.example/cb"),
                Set.of("openid"), List.of(), true, true, false, false, List.of(audience)));
        }
    }

    private static OidcClient client(List<String> callbacks, Set<String> scopes, Boolean enabled) {
        return new OidcClient("id", "Name", callbacks, scopes, List.of(), enabled, true);
    }
}
