package top.ddupan.iam.login.configuration;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.security.Principal;
import java.time.Clock;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportRuntimeHints;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthentication;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;
import top.ddupan.iam.login.authentication.infrastructure.webauthn.MfaPolicy;
import top.ddupan.iam.login.authorization.application.AuthorizationPolicy;
import top.ddupan.iam.login.authorization.infrastructure.hydra.HydraProperties;

/**
 * Spring Security's own authorization server, in process, replacing Hydra. Mutually exclusive with
 * {@code iam.hydra.enabled}. Signing keys come from configuration (see {@link SigningKeys}).
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "iam.authorization-server", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(AuthorizationServerConfiguration.Properties.class)
@ImportRuntimeHints(SecurityJacksonHints.class)
@EnableScheduling
class AuthorizationServerConfiguration {
    @ConfigurationProperties("iam.authorization-server")
    record Properties(boolean enabled, URI issuer, List<HydraProperties.SubjectBinding> subjects,
            List<Resource> signingKeys) { }

    @Bean @Order(2)
    SecurityFilterChain authorizationServer(HttpSecurity http, MfaPolicy mfa,
            AuthorizationPolicy policy, OAuth2AuthorizationService authorizations,
            @Value("${iam.hydra.enabled:false}") boolean hydra) throws Exception {
        // Both would serve /oauth2/**, and Hydra-mode login pages would hand out Hydra challenges.
        if (hydra) throw new IllegalStateException("iam.authorization-server.enabled and iam.hydra.enabled are mutually exclusive");
        var requiredFactors = mfa.complete;
        // Registered at the authorization endpoint's position before the endpoint itself (added later, while
        // building); filters of equal order keep insertion order, so this runs first.
        http.addFilterBefore(new Reauthentication(Clock.systemUTC()),
            AbstractPreAuthenticatedProcessingFilter.class);
        http.oauth2AuthorizationServer(as -> {
            http.securityMatcher(as.getEndpointsMatcher());
            as.oidc(oidc -> oidc.providerConfigurationEndpoint(discovery -> discovery.providerConfigurationCustomizer(metadata -> {
                    // Advertise what consent actually releases; clients and conformance tests rely on it.
                    metadata.scopes(scopes -> { scopes.removeAll(SCOPES); scopes.addAll(SCOPES); });
                    metadata.claim("claims_supported", CLAIMS);
                    // Request objects are rejected (rejectRequestObjects); request_uri defaults to true if absent.
                    metadata.claim("request_parameter_supported", false);
                    metadata.claim("request_uri_parameter_supported", false);
                    metadata.claim("claims_parameter_supported", false);
                })))
                // The endpoint only asks "is the principal authenticated?". A password-only session is,
                // so both steps that can yield a code must also demand the full MFA, or a stolen
                // password alone would be enough to obtain tokens.
                // Gates go first and defer (null) once MFA is satisfied; the framework's own providers
                // must stay in the list unchanged, as the endpoint configurer looks them up by type.
                .authorizationEndpoint(endpoint -> endpoint
                    // prompt=none without full MFA is converted as anonymous, so every later step (pre-validation,
                    // the gates, the framework provider) sees no user and the framework answers login_required.
                    .authorizationRequestConverters(converters -> converters.replaceAll(converter ->
                        converter instanceof OAuth2AuthorizationCodeRequestAuthenticationConverter
                            ? new PromptNoneWithoutMfa(converter, requiredFactors) : converter))
                    .authenticationProviders(providers -> {
                        providers.stream().filter(OAuth2AuthorizationCodeRequestAuthenticationProvider.class::isInstance)
                            .map(OAuth2AuthorizationCodeRequestAuthenticationProvider.class::cast)
                            .forEach(codeRequests -> codeRequests.setAuthenticationValidator(
                                new OAuth2AuthorizationCodeRequestAuthenticationValidator()
                                    .andThen(AuthorizationServerConfiguration::rejectRequestObjects)));
                        providers.addFirst(new MfaGate(OAuth2AuthorizationConsentAuthenticationToken.class, requiredFactors));
                        providers.addFirst(new MfaGate(OAuth2AuthorizationCodeRequestAuthenticationToken.class, requiredFactors));
                    }))
                .tokenEndpoint(endpoint -> endpoint.authenticationProviders(providers ->
                    providers.addFirst(new RefreshPolicy(authorizations, policy))));
        })
            // Only the user-facing endpoint needs a human with both factors; token, introspection and
            // revocation authenticate the client, and discovery/JWKS are public. The endpoint filter runs after
            // this rule, so without the exemption prompt=none would be sent to the login page instead of
            // being answered; for those requests the MfaGate above is what withholds the code.
            .authorizeHttpRequests(auth -> auth.requestMatchers(AuthorizationServerConfiguration::promptNone).permitAll()
                .requestMatchers("/oauth2/authorize").access(requiredFactors)
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
     * Second line behind the access rule on /oauth2/authorize (which runs before the endpoint): a principal
     * without both fresh factors is treated as not yet authenticated. Returning the unauthenticated request
     * makes the endpoint fall through to the login pages; with MFA satisfied it returns null, so the next
     * (framework) provider runs.
     * <p>
     * prompt=none requests are exempt from the access rule, so for them this gate is the only check. They
     * arrive anonymous when MFA is incomplete (PromptNoneWithoutMfa) and are deferred to the framework, which
     * answers login_required. An authenticated principal here would mean that conversion did not happen;
     * rather than defer (the framework would issue a code) it fails closed. It must not throw an ordinary
     * AuthenticationException: ProviderManager would then try the next provider with the same request.
     */
    record MfaGate(Class<? extends Authentication> type, AuthorizationManager<Object> requiredFactors) implements AuthenticationProvider {
        @Override public Authentication authenticate(Authentication request) throws AuthenticationException {
            var principal = (Authentication) request.getPrincipal();
            var decision = requiredFactors.authorize(() -> principal, null);
            if (decision != null && decision.isGranted()) return null;
            if (request instanceof OAuth2AuthorizationCodeRequestAuthenticationToken code && prompts(code).contains("none")) {
                if (principal instanceof AnonymousAuthenticationToken) return null;
                throw new InternalAuthenticationServiceException(
                    "prompt=none reached the MFA gate with an authenticated principal lacking factors");
            }
            return request;
        }
        @Override public boolean supports(Class<?> candidate) { return type.isAssignableFrom(candidate); }
    }

    /** See MfaGate: converts prompt=none requests as anonymous unless the principal already holds full MFA. */
    record PromptNoneWithoutMfa(AuthenticationConverter delegate,
            AuthorizationManager<Object> requiredFactors) implements AuthenticationConverter {
        private static final Authentication ANONYMOUS = new AnonymousAuthenticationToken("iam-login", "anonymousUser",
            AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
        @Override public Authentication convert(HttpServletRequest request) {
            var converted = delegate.convert(request);
            if (!(converted instanceof OAuth2AuthorizationCodeRequestAuthenticationToken code) || !prompts(code).contains("none")) {
                return converted;
            }
            var principal = (Authentication) code.getPrincipal();
            var decision = requiredFactors.authorize(() -> principal, null);
            if (decision != null && decision.isGranted()) return converted;
            return new OAuth2AuthorizationCodeRequestAuthenticationToken(code.getAuthorizationUri(), code.getClientId(),
                ANONYMOUS, code.getRedirectUri(), code.getState(), code.getScopes(), code.getAdditionalParameters());
        }
    }

    private static boolean promptNone(HttpServletRequest request) {
        var prompt = request.getParameter("prompt");
        return "/oauth2/authorize".equals(request.getRequestURI()) && request.getParameter("response_type") != null
            && prompt != null && Set.of(prompt.trim().split("\\s+")).contains("none");
    }

    static Set<String> prompts(OAuth2AuthorizationCodeRequestAuthenticationToken code) {
        return code.getAdditionalParameters().get("prompt") instanceof String prompt
            ? Set.of(prompt.trim().split("\\s+")) : Set.of();
    }

    /**
     * Request objects are not supported. Ignoring them (the framework's default) silently drops the state and
     * nonce they carry; OIDC Core 6.1 requires request_not_supported instead. Runs after the framework's own
     * validation, so the client and redirect URI the error is sent to are already verified. (request_uri never
     * gets here: the framework reads it as a pushed authorization request and rejects unknown ones itself.)
     */
    static void rejectRequestObjects(OAuth2AuthorizationCodeRequestAuthenticationContext context) {
        OAuth2AuthorizationCodeRequestAuthenticationToken code = context.getAuthentication();
        if (code.getAdditionalParameters().containsKey("request")) {
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(new OAuth2Error("request_not_supported"), code);
        }
    }

    private static final List<String> SCOPES = List.of("openid", "profile", "email", "groups", "offline_access");
    private static final List<String> CLAIMS = List.of("sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "sid",
        "name", "preferred_username", "email", "email_verified", "groups");

    /**
     * Refresh does not pass through login, so policy that must still hold is re-checked here. Spike rule:
     * the subject binding must still exist; withdrawing it stops refresh immediately (Hydra cannot do this).
     */
    record RefreshPolicy(OAuth2AuthorizationService authorizations, AuthorizationPolicy policy) implements AuthenticationProvider {
        @Override public Authentication authenticate(Authentication request) throws AuthenticationException {
            var refresh = (OAuth2RefreshTokenAuthenticationToken) request;
            var authorization = authorizations.findByToken(refresh.getRefreshToken(), OAuth2TokenType.REFRESH_TOKEN);
            var stored = authorization == null ? null : authorization.<Authentication>getAttribute(Principal.class.getName());
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
                    .allowIfSubType(WebAuthnAuthentication.class))))
            .addMixIn(User.class, PrincipalJson.UserMixin.class)
            .addMixIn(DirectoryPrincipal.class, PrincipalJson.DirectoryPrincipalMixin.class)
            .addMixIn(WebAuthnAuthentication.class, PrincipalJson.WebAuthnAuthenticationMixin.class)
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

    @Bean ExpiredAuthorizations expiredAuthorizations(JdbcOperations jdbc) {
        return new ExpiredAuthorizations(jdbc, Clock.systemUTC());
    }

    @Bean OAuth2AuthorizationConsentService consents(JdbcOperations jdbc, RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationConsentService(jdbc, clients);
    }

    // All configured keys: the JWKS endpoint publishes their public halves; userinfo verifies against them.
    @Bean JWKSource<SecurityContext> jwkSource(Properties properties) {
        return new ImmutableJWKSet<>(new JWKSet(List.copyOf(SigningKeys.load(properties.signingKeys()))));
    }

    // Signing uses the first key only; the framework takes a JwtEncoder bean over building one from all keys.
    @Bean JwtEncoder jwtEncoder(Properties properties) {
        return new NimbusJwtEncoder(
            new ImmutableJWKSet<>(new JWKSet(SigningKeys.load(properties.signingKeys()).getFirst())));
    }

    @Bean JwtDecoder jwtDecoder(JWKSource<SecurityContext> keys) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(keys);
    }

    @Bean AuthorizationServerSettings authorizationServerSettings(Properties properties) {
        return AuthorizationServerSettings.builder().issuer(properties.issuer().toString()).build();
    }
}
