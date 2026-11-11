package top.ddupan.iam.login.configuration;

import java.time.Clock;
import java.time.Duration;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.ldap.autoconfigure.LdapProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authorization.AuthorizationManagerFactories;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authorization.EnableMultiFactorAuthentication;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import top.ddupan.iam.login.authentication.infrastructure.ad.ActiveDirectory;
import top.ddupan.iam.login.authentication.infrastructure.ad.AdProperties;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryAuthenticationProvider;
import top.ddupan.iam.login.authentication.infrastructure.security.SignInThrottle;
import top.ddupan.iam.login.authentication.infrastructure.security.SignInThrottledException;
import top.ddupan.iam.login.authentication.interfaces.web.PageRenderer;

@Configuration(proxyBeanMethods = false)
@EnableMultiFactorAuthentication(authorities = {})
@EnableConfigurationProperties(SignInThrottle.Properties.class)
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
                new NullSecurityContextRepository()))
            .sessionManagement(session -> session.sessionCreationPolicy(
                SessionCreationPolicy.STATELESS))
            .httpBasic(Customizer.withDefaults())
            .build();
    }

    @Bean
    @Order(3)
    @ConditionalOnProperty(prefix = "iam.ad", name = "enabled", havingValue = "true")
    SecurityFilterChain browser(HttpSecurity http, AdProperties ad, LdapProperties ldap, SignInThrottle.Properties throttle,
            ObjectProvider<WebAuthnBrowserConfigurer> webAuthn) throws Exception {
        var passwordFactor = AuthorizationManagerFactories.<RequestAuthorizationContext>multiFactor()
            .requireFactor(factor -> factor.passwordAuthority().validDuration(Duration.ofMinutes(10)))
            .build();
        var mfa = webAuthn.getIfAvailable();
        // /oauth2/** belongs to the authorization server's own chain.
        http.securityMatcher("/", "/signin", "/signin/**", "/assets/**", "/webauthn/**", "/login/webauthn", "/account", "/account/**")
            .redirectToHttps(Customizer.withDefaults())
            .authenticationManager(new ProviderManager(
                new DirectoryAuthenticationProvider(ActiveDirectory.provider(ad, ldap), ad.domain(),
                    new SignInThrottle(throttle, Clock.systemUTC()))))
            .authorizeHttpRequests(auth -> {
                if (mfa != null) {
                    auth.requestMatchers("/signin/complete").access(mfa.policy.complete);
                    auth.requestMatchers("/signin/consent").access(mfa.policy.session);
                    // Both factors fresh (10 minutes) for the page and every change on it: the re-verification
                    // before adding, renaming or removing a factor or revoking an application.
                    auth.requestMatchers("/account", "/account/**").access(mfa.policy.complete);
                    auth.requestMatchers(HttpMethod.POST, "/webauthn/register")
                        .access(mfa.policy.password);
                    // Like adding a passkey; the page itself asks for the second factor too once one exists.
                    auth.requestMatchers(HttpMethod.GET, WebAuthnBrowserConfigurer.TOTP_SETUP).access(mfa.policy.password);
                }
                // /signin/device decides itself: it saves the request before sending a visitor to sign in.
                // "/" only redirects to /account, which then asks for whatever sign-in is missing.
                auth.requestMatchers("/", "/error", "/signin", "/signin/password", "/signin/device", "/assets/**").permitAll()
                .requestMatchers("/signin/mfa").access(passwordFactor.authenticated())
                // The framework's credential deletion (DELETE /webauthn/register/{id}, no last-factor rule) and all
                // unimplemented routes remain closed; removal goes through /account.
                .anyRequest().denyAll();
            })
            .formLogin(form -> form.loginPage("/signin").loginProcessingUrl("/signin/password")
                .defaultSuccessUrl("/signin/mfa", true).failureHandler((request, response, exception) ->
                    // No exception in the session (attributes must be JSON, SessionConfiguration). Only a directory
                    // outage is told apart: wrong password, locked, disabled and expired stay one message, so the
                    // page does not reveal account state.
                    response.sendRedirect(request.getContextPath() + switch (exception) {
                        case InternalAuthenticationServiceException e -> "/signin?error=unavailable";
                        case SignInThrottledException e -> "/signin?error=throttled";
                        default -> "/signin?error";
                    })))
            // Signing out of this service only; relying parties use RP-initiated logout (/connect/logout).
            .logout(logout -> logout.logoutRequestMatcher(PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/signin/restart"))
                .logoutSuccessHandler((request, response, authentication) -> {
                    response.setStatus(303);
                    response.setHeader("Location", "/signin");
                }))
            .exceptionHandling(exceptions -> exceptions
                .defaultAuthenticationEntryPointFor(new LoginUrlAuthenticationEntryPoint("/signin"),
                    PathPatternRequestMatcher.withDefaults().matcher("/signin/**"))
                .defaultAuthenticationEntryPointFor(new LoginUrlAuthenticationEntryPoint("/signin"),
                    PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, "/account"))
                .defaultAuthenticationEntryPointFor(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                    AnyRequestMatcher.INSTANCE))
            // Not even for /account: form login's success handler clears the saved request, which would drop an
            // authorization request saved by the authorization server's chain. /signin/complete lands on /account.
            .requestCache(cache -> cache.disable())
            .headers(headers -> headers.contentSecurityPolicy(csp -> csp.policyDirectives(
                PageRenderer.CONTENT_SECURITY_POLICY)));
        if (mfa != null) mfa.configure(http);
        var chain = http.build();
        return mfa == null ? chain : mfa.finish(http, chain);
    }

    @Bean
    @Order(4)
    SecurityFilterChain fallback(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/error").permitAll()
                .anyRequest().denyAll())
            // Nothing is served here, so to anyone it is not found. sendError, not a bare status, so a browser
            // gets the error page (ErrorPages) instead of an empty body.
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint((request, response, ex) -> response.sendError(HttpStatus.NOT_FOUND.value()))
                .accessDeniedHandler((request, response, ex) -> response.sendError(HttpStatus.NOT_FOUND.value())))
            .requestCache(cache -> cache.disable())
            .logout(logout -> logout.disable())
            .build();
    }

}
