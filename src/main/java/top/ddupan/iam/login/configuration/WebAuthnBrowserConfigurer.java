package top.ddupan.iam.login.configuration;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;
import java.util.List;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.webauthn.authentication.PublicKeyCredentialRequestOptionsFilter;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationFilter;
import top.ddupan.iam.login.authentication.infrastructure.security.SignInThrottledException;
import top.ddupan.iam.login.authentication.infrastructure.totp.TotpAuthenticationProvider;
import top.ddupan.iam.login.authentication.infrastructure.totp.TotpCode;
import top.ddupan.iam.login.authentication.infrastructure.webauthn.*;

/** Wires official filters through their public extension points; no custom authentication filter. */
final class WebAuthnBrowserConfigurer {
    static final String TOTP = "/signin/totp";
    static final String TOTP_SETUP = "/signin/totp/setup";
    private final WebAuthnProperties properties;
    final MfaPolicy policy;
    private final SessionChallenges challenges;
    private final TotpAuthenticationProvider totp;

    WebAuthnBrowserConfigurer(WebAuthnProperties properties, MfaPolicy policy, SessionChallenges challenges,
            TotpAuthenticationProvider totp) {
        this.properties = properties;
        this.policy = policy;
        this.challenges = challenges;
        this.totp = totp;
    }

    void configure(HttpSecurity http) throws Exception {
        http.setSharedObject(UserDetailsService.class, name -> {
            // Called after the relying party verified the passkey and resolved its account (passwordless included).
            if (policy.secondStep().filter(p -> !p.getName().equals(name)).isPresent()) {
                throw new UsernameNotFoundException("Directory identity mismatch");
            }
            // Spring Security merges the existing password factor, retaining its original issue time.
            return new User(name, "", List.of());
        });
        http.webAuthn(web -> web.rpId(properties.rpId()).rpName("IAM Login")
            .allowedOrigins(properties.origin()).disableDefaultRegistrationPage(true)
            .creationOptionsRepository(challenges.registration()));
        http.addFilter(totpFilter());
        http.exceptionHandling(exceptions -> exceptions
            .defaultDeniedHandlerForMissingAuthority(new LoginUrlAuthenticationEntryPoint("/signin/mfa"), FactorGrantedAuthority.WEBAUTHN_AUTHORITY)
            .defaultDeniedHandlerForMissingAuthority(new LoginUrlAuthenticationEntryPoint("/signin/mfa"), MfaPolicy.TOTP_AUTHORITY));
    }

    /**
     * Authenticator app codes, posted as a form: verifying (/signin/totp) or confirming the key being set up
     * (/signin/totp/setup, the key from the session). The framework's generic filter merges the new factor with
     * the password factor and rotates the session id.
     */
    private AuthenticationFilter totpFilter() {
        var paths = PathPatternRequestMatcher.withDefaults();
        var setupPath = paths.matcher(HttpMethod.POST, TOTP_SETUP);
        var filter = new AuthenticationFilter(new ProviderManager(totp), request -> {
            var setup = setupPath.matches(request);
            var session = request.getSession(false);
            var pending = setup && session != null && session.getAttribute(TotpCode.PENDING) instanceof String key
                ? Base64.getDecoder().decode(key) : null;
            // Nothing being set up (the session expired, or it was already confirmed): the page starts over.
            if (setup && pending == null) throw new BadCredentialsException("No authenticator app being set up");
            return new TotpCode(request.getParameter("code"), pending, request.getRemoteAddr());
        });
        filter.setRequestMatcher(new OrRequestMatcher(paths.matcher(HttpMethod.POST, TOTP), setupPath));
        filter.setMfaEnabled(true);
        filter.setSecurityContextRepository(new HttpSessionSecurityContextRepository());
        filter.setSuccessHandler(new AuthenticationSuccessHandler() {
            // The filter calls this variant, which by default continues the chain (it is made for API requests);
            // a form post ends with the redirect.
            @Override
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                    Authentication authentication) throws IOException {
                onAuthenticationSuccess(request, response, authentication);
            }

            @Override
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                    Authentication authentication) throws IOException {
                request.getSession().removeAttribute(TotpCode.PENDING);
                response.sendRedirect("/signin/complete");
            }
        });
        filter.setFailureHandler((request, response, exception) -> {
            var error = exception instanceof SignInThrottledException ? "throttled" : "invalid";
            response.sendRedirect(setupPath.matches(request) ? TOTP_SETUP + "?error=" + error
                : "/signin/mfa?method=totp&error=" + error);
        });
        return filter;
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
