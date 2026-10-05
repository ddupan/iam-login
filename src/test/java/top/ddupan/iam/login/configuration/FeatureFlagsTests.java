package top.ddupan.iam.login.configuration;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import static org.assertj.core.api.Assertions.*;

class FeatureFlagsTests {
    @Test void runtimeFlagsMustMatchTheBeansTheBinaryWasBuiltWith() {
        var all = new MockEnvironment().withProperty("iam.ad.enabled", "true").withProperty("iam.webauthn.enabled", "true")
            .withProperty("iam.authorization-server.enabled", "true");
        assertThatNoException().isThrownBy(() -> FeatureFlags.check(all, type -> true));
        // Built without the authorization server, configured with it: refused instead of silently ignored.
        assertThatIllegalStateException().isThrownBy(() -> FeatureFlags.check(all,
                type -> type != AuthorizationServerConfiguration.class))
            .withMessageContaining("iam.authorization-server.enabled=true");
        // Built with everything, profile forgotten at runtime: every flag reads false.
        assertThatIllegalStateException().isThrownBy(() -> FeatureFlags.check(new MockEnvironment(), type -> true));
    }
}
