package top.ddupan.iam.login.configuration;

import java.util.List;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.webauthn.authentication.PublicKeyCredentialRequestOptionsFilter;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationFilter;
import top.ddupan.iam.login.authentication.infrastructure.webauthn.*;

/** Wires official filters through their public extension points; no custom authentication filter. */
final class WebAuthnBrowserConfigurer {
    private final WebAuthnProperties properties;
    final MfaPolicy policy;
    private final SessionChallenges challenges;

    WebAuthnBrowserConfigurer(WebAuthnProperties properties, MfaPolicy policy, SessionChallenges challenges) {
        this.properties = properties;
        this.policy = policy;
        this.challenges = challenges;
    }

    void configure(HttpSecurity http) throws Exception {
        http.setSharedObject(UserDetailsService.class, name -> {
            if (!policy.current().getName().equals(name)) throw new UsernameNotFoundException("Directory identity mismatch");
            // Spring Security merges the existing password factor, retaining its original issue time.
            return new User(name, "", List.of());
        });
        http.webAuthn(web -> web.rpId(properties.rpId()).rpName("IAM Login")
            .allowedOrigins(properties.origin()).disableDefaultRegistrationPage(true)
            .creationOptionsRepository(challenges.registration()));
        http.exceptionHandling(exceptions -> exceptions.defaultDeniedHandlerForMissingAuthority(
            new LoginUrlAuthenticationEntryPoint("/signin/mfa"), FactorGrantedAuthority.WEBAUTHN_AUTHORITY));
    }

    SecurityFilterChain finish(HttpSecurity http, SecurityFilterChain chain) {
        var repository = challenges.authentication();
        // Security 7.1 exposes these setters but does not expose the assertion repository in its DSL.
        for (var filter : chain.getFilters()) {
            if (filter instanceof PublicKeyCredentialRequestOptionsFilter options) {
                options.setRequestOptionsRepository(repository);
            }
            if (filter instanceof WebAuthnAuthenticationFilter authentication) {
                authentication.setRequestOptionsRepository(repository);
                authentication.setSessionAuthenticationStrategy(http.getSharedObject(
                    SessionAuthenticationStrategy.class));
            }
        }
        return chain;
    }
}
