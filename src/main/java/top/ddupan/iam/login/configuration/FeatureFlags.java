package top.ddupan.iam.login.configuration;

import java.util.Map;
import java.util.function.Predicate;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import top.ddupan.iam.login.authentication.interfaces.web.SignInController;

/**
 * Native evaluates @ConditionalOnProperty when the binary is built, so a feature switched on or off only
 * at runtime would be silently ignored (or, for iam.ad.enabled, half applied: it is also read at runtime).
 * Each flag is compared with the bean it controls; on the JVM they always agree.
 */
@Configuration(proxyBeanMethods = false)
class FeatureFlags {
    /** Flag → a bean that exists exactly when the flag was on at build time. */
    private static final Map<String, Class<?>> CONTROLLED = Map.of(
        "iam.ad.enabled", SignInController.class,
        "iam.webauthn.enabled", WebAuthnConfiguration.class,
        "iam.authorization-server.enabled", AuthorizationServerConfiguration.class);

    @Bean ApplicationRunner featureFlagsMatchBuild(Environment environment, ApplicationContext context) {
        return arguments -> check(environment, type -> context.getBeanNamesForType(type).length > 0);
    }

    static void check(Environment environment, Predicate<Class<?>> present) {
        CONTROLLED.forEach((flag, type) -> {
            boolean configured = environment.getProperty(flag, Boolean.class, false);
            if (configured != present.test(type)) {
                throw new IllegalStateException(flag + "=" + configured + " at runtime, but the binary was built with it "
                    + (present.test(type) ? "on" : "off") + "; feature flags are fixed at build time (profile prod)");
            }
        });
    }
}
