package top.ddupan.iam.login;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authorization.AuthorizationManager;
import top.ddupan.iam.login.authentication.infrastructure.webauthn.MfaPolicy;

/**
 * Test-only: the OpenID conformance suite drives login with a headless browser that cannot perform
 * WebAuthn, so authorization requires the password factor alone. The protocol is what is under test;
 * MFA enforcement is covered by the integration and browser tests. Never on the production classpath.
 *
 * Deliberately NOT annotated @Configuration: it lives in the application's base package, so component
 * scanning would put it into every test context and silently drop the passkey requirement (the
 * authorization-server integration test then issues a code after the password alone). It is only ever
 * added explicitly, by the conformance fixture.
 */
class ConformanceOverrides {
    @Bean @Primary AuthorizationManager<Object> conformanceFactors(MfaPolicy mfa) { return mfa.password; }
}
