package top.ddupan.iam.login.configuration;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.net.URI;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;
import top.ddupan.iam.login.authentication.infrastructure.webauthn.MfaPolicy;
import top.ddupan.iam.login.authorization.application.AuthorizationPolicy;
import top.ddupan.iam.login.authorization.infrastructure.hydra.HydraProperties;

/**
 * Spike: Spring Security's own authorization server, in process, replacing Hydra.
 * Mutually exclusive with {@code iam.hydra.enabled}. Signing keys are ephemeral (see {@link #jwkSource}).
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "iam.authorization-server", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(AuthorizationServerConfiguration.Properties.class)
@org.springframework.context.annotation.ImportRuntimeHints(SecurityJacksonHints.class)
class AuthorizationServerConfiguration {
    @ConfigurationProperties("iam.authorization-server")
    record Properties(boolean enabled, URI issuer, List<HydraProperties.SubjectBinding> subjects) { }

    @Bean @Order(2)
    SecurityFilterChain authorizationServer(HttpSecurity http, MfaPolicy mfa,
            AuthorizationPolicy policy, OAuth2AuthorizationService authorizations) throws Exception {
        var requiredFactors = mfa.complete;
        http.oauth2AuthorizationServer(as -> {
            http.securityMatcher(as.getEndpointsMatcher());
            as.oidc(Customizer.withDefaults())
                // The endpoint only asks "is the principal authenticated?". A password-only session is,
                // so both steps that can yield a code must also demand the full MFA, or a stolen
                // password alone would be enough to obtain tokens.
                // Gates go first and defer (null) once MFA is satisfied; the framework's own providers
                // must stay in the list unchanged, as the endpoint configurer looks them up by type.
                .authorizationEndpoint(endpoint -> endpoint.authenticationProviders(providers -> {
                    providers.addFirst(new MfaGate(OAuth2AuthorizationConsentAuthenticationToken.class, requiredFactors));
                    providers.addFirst(new MfaGate(OAuth2AuthorizationCodeRequestAuthenticationToken.class, requiredFactors));
                }))
                .tokenEndpoint(endpoint -> endpoint.authenticationProviders(providers ->
                    providers.addFirst(new RefreshPolicy(authorizations, policy))));
        })
            // Only the user-facing endpoint needs a human with both factors; token, introspection and
            // revocation authenticate the client, and discovery/JWKS are public.
            .authorizeHttpRequests(auth -> auth.requestMatchers("/oauth2/authorize").access(requiredFactors)
                .anyRequest().authenticated())
            // userinfo is called with the access tokens this server issued.
            .oauth2ResourceServer(resource -> resource.jwt(Customizer.withDefaults()))
            .requestCache(cache -> cache.requestCache(new HttpSessionRequestCache()))
            .exceptionHandling(exceptions -> exceptions
                .defaultAuthenticationEntryPointFor(new LoginUrlAuthenticationEntryPoint("/signin"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML))
                .defaultDeniedHandlerForMissingAuthority(new LoginUrlAuthenticationEntryPoint("/signin/mfa"),
                    FactorGrantedAuthority.WEBAUTHN_AUTHORITY)
                .defaultDeniedHandlerForMissingAuthority(new LoginUrlAuthenticationEntryPoint("/signin"),
                    FactorGrantedAuthority.PASSWORD_AUTHORITY));
        return http.build();
    }

    /**
     * Treats a principal without both fresh factors as not yet authenticated for this endpoint: returning
     * the unauthenticated request makes the endpoint fall through to authorization, which redirects to the
     * missing factor's page. With MFA satisfied it returns null, so the next (framework) provider runs.
     */
    record MfaGate(Class<? extends Authentication> type, AuthorizationManager<Object> requiredFactors) implements AuthenticationProvider {
        @Override public Authentication authenticate(Authentication request) throws AuthenticationException {
            var principal = (Authentication) request.getPrincipal();
            var decision = requiredFactors.authorize(() -> principal, null);
            return decision != null && decision.isGranted() ? null : request;
        }
        @Override public boolean supports(Class<?> candidate) { return type.isAssignableFrom(candidate); }
    }

    /**
     * Refresh does not pass through login, so policy that must still hold is re-checked here. Spike rule:
     * the subject binding must still exist; withdrawing it stops refresh immediately (Hydra cannot do this).
     */
    record RefreshPolicy(OAuth2AuthorizationService authorizations, AuthorizationPolicy policy) implements AuthenticationProvider {
        @Override public Authentication authenticate(Authentication request) throws AuthenticationException {
            var refresh = (OAuth2RefreshTokenAuthenticationToken) request;
            var authorization = authorizations.findByToken(refresh.getRefreshToken(), OAuth2TokenType.REFRESH_TOKEN);
            var stored = authorization == null ? null : authorization.<Authentication>getAttribute(java.security.Principal.class.getName());
            try {
                if (stored != null && stored.getPrincipal() instanceof DirectoryPrincipal principal) policy.subject(principal.user());
            } catch (IllegalArgumentException withdrawn) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
            }
            return null; // allowed: the framework's refresh provider does the actual work
        }
        @Override public boolean supports(Class<?> type) { return OAuth2RefreshTokenAuthenticationToken.class.isAssignableFrom(type); }
    }

    @Bean AuthorizationPolicy authorizationServerPolicy(Properties properties) {
        return new AuthorizationPolicy(null, properties.subjects().stream().collect(Collectors.toMap(
            binding -> new User.UserId(binding.authority(), binding.directoryId()), HydraProperties.SubjectBinding::subject)));
    }

    /** Existing subjects are preserved, so downstream account links survive the issuer change. */
    @Bean OAuth2TokenCustomizer<JwtEncodingContext> claims(AuthorizationPolicy policy) {
        return context -> {
            if (!(context.getPrincipal().getPrincipal() instanceof DirectoryPrincipal principal)) return;
            var user = principal.user();
            var scopes = context.getAuthorizedScopes();
            context.getClaims().subject(policy.subject(user));
            if (scopes.contains("groups")) {
                context.getClaims().claim("groups", user.memberships().stream().map(User.GroupMembership::name).toList());
            }
            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                if (scopes.contains("profile")) {
                    context.getClaims().claim("preferred_username", user.username()).claim("name", user.displayName());
                }
                if (scopes.contains("email") && !user.email().isBlank()) {
                    context.getClaims().claim("email", user.email()).claim("email_verified", false);
                }
            }
        };
    }

    @Bean RegisteredClientRepository registeredClients(JdbcOperations jdbc) {
        return new JdbcRegisteredClientRepository(jdbc);
    }

    // The stored authorization carries the authenticated principal for later refreshes; the directory
    // snapshot must be on Jackson's allowlist for that to deserialize.
    @Bean OAuth2AuthorizationService authorizations(JdbcOperations jdbc, RegisteredClientRepository clients) {
        var service = new JdbcOAuth2AuthorizationService(jdbc, clients);
        var json = JsonMapper.builder()
            .addModules(SecurityJacksonModules.getModules(getClass().getClassLoader(),
                // After a real passkey step the session holds WebAuthnAuthentication, not the password token.
                allowlist(BasicPolymorphicTypeValidator.builder().allowIfSubType(DirectoryPrincipal.class)
                    .allowIfSubType(org.springframework.security.web.webauthn.authentication.WebAuthnAuthentication.class))))
            .addMixIn(User.class, PrincipalJson.UserMixin.class)
            .addMixIn(DirectoryPrincipal.class, PrincipalJson.DirectoryPrincipalMixin.class)
            .addMixIn(org.springframework.security.web.webauthn.authentication.WebAuthnAuthentication.class, PrincipalJson.WebAuthnAuthenticationMixin.class)
            .build();
        var rows = new JdbcOAuth2AuthorizationService.JsonMapperOAuth2AuthorizationRowMapper(clients, json);
        service.setAuthorizationRowMapper(rows);
        service.setAuthorizationParametersMapper(new JdbcOAuth2AuthorizationService.JsonMapperOAuth2AuthorizationParametersMapper(json));
        return service;
    }

    private static BasicPolymorphicTypeValidator.Builder allowlist(BasicPolymorphicTypeValidator.Builder builder) {
        for (var type : PrincipalJson.immutableLists()) builder.allowIfSubType(type);
        return builder;
    }

    @Bean OAuth2AuthorizationConsentService consents(JdbcOperations jdbc, RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationConsentService(jdbc, clients);
    }

    // ponytail: ephemeral signing key, regenerated on every start (all tokens die with the process).
    // Persist and rotate it (OpenBao or the database) before anything real depends on it.
    @Bean JWKSource<SecurityContext> jwkSource() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var keys = generator.generateKeyPair();
        var jwk = new RSAKey.Builder((RSAPublicKey) keys.getPublic()).privateKey((RSAPrivateKey) keys.getPrivate())
            .keyID(UUID.randomUUID().toString()).build();
        return new ImmutableJWKSet<>(new JWKSet(jwk));
    }

    @Bean org.springframework.security.oauth2.jwt.JwtDecoder jwtDecoder(JWKSource<SecurityContext> keys) {
        return org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration.jwtDecoder(keys);
    }

    @Bean AuthorizationServerSettings authorizationServerSettings(Properties properties) {
        return AuthorizationServerSettings.builder().issuer(properties.issuer().toString()).build();
    }
}
