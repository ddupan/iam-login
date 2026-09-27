package top.ddupan.iam.login.configuration;

import java.time.Duration;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authorization.AuthorizationManagerFactories;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.authorization.EnableMultiFactorAuthentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import top.ddupan.iam.login.authentication.application.VerifyPassword;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryAuthenticationProvider;

@Configuration(proxyBeanMethods = false)
@EnableMultiFactorAuthentication(authorities = {})
class SecurityConfiguration {
    // Operational Basic authentication is isolated from human first-factor authentication.
    @Bean
    @Order(1)
    SecurityFilterChain management(HttpSecurity http) throws Exception {
        return http.securityMatcher("/actuator/**")
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health/**").permitAll()
                .anyRequest().authenticated())
            .securityContext(context -> context.securityContextRepository(
                new org.springframework.security.web.context.NullSecurityContextRepository()))
            .sessionManagement(session -> session.sessionCreationPolicy(
                org.springframework.security.config.http.SessionCreationPolicy.STATELESS))
            .httpBasic(Customizer.withDefaults())
            .build();
    }

    @Bean
    @Order(2)
    @ConditionalOnProperty(prefix = "iam.ad", name = "enabled", havingValue = "true")
    SecurityFilterChain browser(HttpSecurity http, VerifyPassword passwords,
            ObjectProvider<WebAuthnBrowserConfigurer> webAuthn) throws Exception {
        var passwordFactor = AuthorizationManagerFactories.<RequestAuthorizationContext>multiFactor()
            .requireFactor(factor -> factor.passwordAuthority().validDuration(Duration.ofMinutes(10)))
            .build();
        var mfa = webAuthn.getIfAvailable();
        http.securityMatcher("/signin", "/signin/**", "/assets/**", "/webauthn/**", "/login/webauthn")
            .redirectToHttps(Customizer.withDefaults())
            .authenticationManager(new ProviderManager(new DirectoryAuthenticationProvider(passwords)))
            .authorizeHttpRequests(auth -> {
                if (mfa != null) {
                    auth.requestMatchers("/signin/complete").access(mfa.policy.complete);
                    auth.requestMatchers(org.springframework.http.HttpMethod.POST, "/webauthn/register")
                        .access(mfa.policy.password);
                }
                auth.requestMatchers("/error", "/signin", "/signin/password", "/assets/**").permitAll()
                .requestMatchers("/signin/mfa").access(passwordFactor.authenticated())
                // Credential deletion and all unimplemented routes remain closed.
                .anyRequest().denyAll();
            })
            .formLogin(form -> form.loginPage("/signin").loginProcessingUrl("/signin/password")
                .defaultSuccessUrl("/signin/mfa", true).failureUrl("/signin?error"))
            .logout(logout -> logout.logoutUrl("/signin/restart").logoutSuccessUrl("/signin"))
            .exceptionHandling(exceptions -> exceptions
                .defaultAuthenticationEntryPointFor(new LoginUrlAuthenticationEntryPoint("/signin"),
                    PathPatternRequestMatcher.withDefaults().matcher("/signin/**"))
                .defaultAuthenticationEntryPointFor(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                    org.springframework.security.web.util.matcher.AnyRequestMatcher.INSTANCE))
            .requestCache(cache -> cache.disable())
            .headers(headers -> headers.contentSecurityPolicy(csp -> csp.policyDirectives(
                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                + "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")));
        if (mfa != null) mfa.configure(http);
        var chain = http.build();
        return mfa == null ? chain : mfa.finish(http, chain);
    }

    @Bean
    @Order(3)
    SecurityFilterChain fallback(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/error").permitAll()
                .anyRequest().denyAll())
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
            .requestCache(cache -> cache.disable())
            .logout(logout -> logout.disable())
            .build();
    }

}
