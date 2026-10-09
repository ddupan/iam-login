package top.ddupan.iam.login.configuration;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.security.Principal;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jooq.DSLContext;
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
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceAuthorizationConsentAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceAuthorizationRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceAuthorizationRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceVerificationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;
import top.ddupan.iam.login.authentication.infrastructure.webauthn.MfaPolicy;
import top.ddupan.iam.login.authorization.infrastructure.persistence.Subjects;
import top.ddupan.iam.login.clients.infrastructure.RegisteredClients;

/**
 * Spring Security's own authorization server, in process: the token issuer of this IAM. Signing keys come
 * from configuration (see {@link SigningKeys}).
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "iam.authorization-server", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(AuthorizationServerConfiguration.Properties.class)
@ImportRuntimeHints(SecurityJacksonHints.class)
@EnableScheduling
class AuthorizationServerConfiguration {
    @ConfigurationProperties("iam.authorization-server")
    record Properties(boolean enabled, URI issuer, List<Resource> signingKeys) { }

    @Bean @Order(2)
    SecurityFilterChain authorizationServer(HttpSecurity http, MfaPolicy mfa,
            Subjects subjects, OAuth2AuthorizationService authorizations, RegisteredClientRepository clients,
            AuthorizationServerSettings settings) throws Exception {
        var requiredFactors = mfa.complete;
        // Registered at the authorization endpoint's position before the endpoint itself (added later, while
        // building); filters of equal order keep insertion order, so this runs first.
        http.addFilterBefore(new Reauthentication(Clock.systemUTC()),
            AbstractPreAuthenticatedProcessingFilter.class);
        http.oauth2AuthorizationServer(as -> {
            http.securityMatcher(as.getEndpointsMatcher());
            // Public clients outside the authorization-code exchange (PublicClients). Custom converters and providers
            // go ahead of the framework's, whose public-client provider would reject these requests (no code_verifier).
            as.clientAuthentication(authentication -> authentication
                .authenticationConverter(new PublicClients.Converter(settings.getDeviceAuthorizationEndpoint()))
                .authenticationProvider(new PublicClients.Provider(clients)));
            as.oidc(oidc -> oidc.providerConfigurationEndpoint(discovery -> discovery.providerConfigurationCustomizer(metadata -> {
                    // Advertise what consent actually releases; clients and conformance tests rely on it.
                    metadata.scopes(scopes -> { scopes.removeAll(SCOPES); scopes.addAll(SCOPES); });
                    metadata.claim("claims_supported", CLAIMS);
                    metadata.tokenEndpointAuthenticationMethods(methods -> methods.add(ClientAuthenticationMethod.NONE.getValue()));
                    // Request objects are rejected (requestPolicy); request_uri defaults to true if absent.
                    metadata.claim("request_parameter_supported", false);
                    metadata.claim("request_uri_parameter_supported", false);
                    metadata.claim("claims_parameter_supported", false);
                }))
                // OIDC Core 5.4: with an access token issued, scope claims belong in UserInfo. The default mapper
                // knows only the standard scopes and would drop groups.
                .userInfoEndpoint(userInfo -> userInfo.userInfoMapper(AuthorizationServerConfiguration::userInfo)))
                // The endpoint only asks "is the principal authenticated?". A password-only session is,
                // so both steps that can yield a code must also demand the full MFA, or a stolen
                // password alone would be enough to obtain tokens.
                // Gates go first and defer (null) once MFA is satisfied; the framework's own providers
                // must stay in the list unchanged, as the endpoint configurer looks them up by type.
                .authorizationEndpoint(endpoint -> endpoint
                    // Our page (ConsentController) instead of the framework's default one.
                    .consentPage("/signin/consent")
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
                                    .andThen(AuthorizationServerConfiguration::requestPolicy)));
                        providers.addFirst(new MfaGate(OAuth2AuthorizationConsentAuthenticationToken.class, requiredFactors));
                        providers.addFirst(new MfaGate(OAuth2AuthorizationCodeRequestAuthenticationToken.class, requiredFactors));
                    }))
                // Device grant (RFC 8628). The user enters the code on our page; the outcome comes back to it.
                // Custom providers run ahead of the framework's, in the order added.
                .deviceAuthorizationEndpoint(endpoint -> endpoint.verificationUri("/signin/device")
                    .authenticationProvider(new DeviceLoginEnabled())
                    .authenticationProvider(new DeviceOpenIdScope(new OAuth2DeviceAuthorizationRequestAuthenticationProvider(authorizations), authorizations)))
                .deviceVerificationEndpoint(endpoint -> endpoint.consentPage("/signin/consent")
                    .deviceVerificationResponseHandler((request, response, authentication) ->
                        response.sendRedirect(request.getContextPath() + "/signin/device?result=done"))
                    .errorResponseHandler((request, response, exception) -> response.sendRedirect(request.getContextPath()
                        + "/signin/device?result=" + (exception instanceof OAuth2AuthenticationException oauth
                            && OAuth2ErrorCodes.ACCESS_DENIED.equals(oauth.getError().getErrorCode()) ? "denied" : "invalid")))
                    .authenticationProvider(new DeviceMfaGate(OAuth2DeviceVerificationAuthenticationToken.class, requiredFactors))
                    .authenticationProvider(new DeviceMfaGate(OAuth2DeviceAuthorizationConsentAuthenticationToken.class, requiredFactors)))
                .tokenEndpoint(endpoint -> endpoint.authenticationProviders(providers ->
                    providers.addFirst(new RefreshPolicy(authorizations, subjects))));
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

    /**
     * MfaGate for the device grant. Unlike the authorization endpoint, the verification endpoint does not hand an
     * unauthenticated result on to the login pages (it would report success), so missing factors are a denial.
     * Users reach it from /signin/device, which has them sign in first; this only stops a direct request, or a
     * consent submitted after the factors went stale.
     */
    record DeviceMfaGate(Class<? extends Authentication> type, AuthorizationManager<Object> requiredFactors) implements AuthenticationProvider {
        @Override public Authentication authenticate(Authentication request) throws AuthenticationException {
            var decision = requiredFactors.authorize(() -> (Authentication) request.getPrincipal(), null);
            if (decision != null && decision.isGranted()) return null;
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
        }
        @Override public boolean supports(Class<?> candidate) { return type.isAssignableFrom(candidate); }
    }

    /**
     * The framework refuses openid in a device authorization request (the device grant issues no ID token), but OIDC
     * clients ask for it there too: Incus requests its configured scopes, openid included. Neither OIDC nor RFC 8628
     * forbids it. The request is validated and issued without openid, then openid is put back among the requested
     * scopes, so consent shows it and the access token carries it (userinfo needs it). Still no ID token.
     */
    record DeviceOpenIdScope(AuthenticationProvider framework, OAuth2AuthorizationService authorizations) implements AuthenticationProvider {
        private static final OAuth2TokenType DEVICE_CODE = new OAuth2TokenType(OAuth2ParameterNames.DEVICE_CODE);

        @Override public Authentication authenticate(Authentication request) throws AuthenticationException {
            var device = (OAuth2DeviceAuthorizationRequestAuthenticationToken) request;
            if (!device.getScopes().contains(OidcScopes.OPENID)) return null;
            if (!(device.getPrincipal() instanceof OAuth2ClientAuthenticationToken client) || client.getRegisteredClient() == null
                    || !client.getRegisteredClient().getScopes().contains(OidcScopes.OPENID)) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
            }
            var others = new HashSet<>(device.getScopes());
            others.remove(OidcScopes.OPENID);
            var result = (OAuth2DeviceAuthorizationRequestAuthenticationToken) framework.authenticate(
                new OAuth2DeviceAuthorizationRequestAuthenticationToken(client, device.getAuthorizationUri(), others,
                    device.getAdditionalParameters()));
            var stored = authorizations.findByToken(result.getDeviceCode().getTokenValue(), DEVICE_CODE);
            authorizations.save(OAuth2Authorization.from(stored).attribute(OAuth2ParameterNames.SCOPE, new HashSet<>(device.getScopes())).build());
            return result;
        }
        @Override public boolean supports(Class<?> candidate) {
            return OAuth2DeviceAuthorizationRequestAuthenticationToken.class.isAssignableFrom(candidate);
        }
    }

    /** A client disabled for login gets no device code either (requestPolicy covers the authorization endpoint). */
    record DeviceLoginEnabled() implements AuthenticationProvider {
        @Override public Authentication authenticate(Authentication request) throws AuthenticationException {
            if (request.getPrincipal() instanceof OAuth2ClientAuthenticationToken client && client.getRegisteredClient() != null
                    && !RegisteredClients.loginEnabled(client.getRegisteredClient())) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
            }
            return null;
        }
        @Override public boolean supports(Class<?> candidate) {
            return OAuth2DeviceAuthorizationRequestAuthenticationToken.class.isAssignableFrom(candidate);
        }
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
     * Runs after the framework's own validation, so the client and redirect URI an error is sent to are
     * already verified.
     * <ul>
     * <li>A client disabled for login (client management) gets unauthorized_client.</li>
     * <li>Request objects are not supported. Ignoring them (the framework's default) silently drops the state
     * and nonce they carry; OIDC Core 6.1 requires request_not_supported instead. (request_uri never gets
     * here: the framework reads it as a pushed authorization request and rejects unknown ones itself.)</li>
     * </ul>
     */
    static void requestPolicy(OAuth2AuthorizationCodeRequestAuthenticationContext context) {
        OAuth2AuthorizationCodeRequestAuthenticationToken code = context.getAuthentication();
        if (!RegisteredClients.loginEnabled(context.getRegisteredClient())) {
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(new OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT), code);
        }
        if (code.getAdditionalParameters().containsKey("request")) {
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(new OAuth2Error("request_not_supported"), code);
        }
    }

    /** The ID token's claims, limited to the scopes on the presented access token. */
    static OidcUserInfo userInfo(OidcUserInfoAuthenticationContext context) {
        var scopes = context.getAccessToken().getScopes();
        var released = new HashSet<>(Set.of("sub"));
        SCOPE_CLAIMS.forEach((scope, claims) -> { if (scopes.contains(scope)) released.addAll(claims); });
        var idToken = context.getAuthorization().getToken(OidcIdToken.class).getToken().getClaims();
        var claims = new HashMap<String, Object>();
        idToken.forEach((name, value) -> { if (released.contains(name)) claims.put(name, value); });
        return new OidcUserInfo(claims);
    }

    private static final Map<String, List<String>> SCOPE_CLAIMS = Map.of(
        "profile", List.of("name", "preferred_username"),
        "email", List.of("email", "email_verified"),
        "groups", List.of("groups"));
    private static final List<String> SCOPES = List.of("openid", "profile", "email", "groups", "offline_access");
    private static final List<String> CLAIMS = List.of("sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "sid",
        "name", "preferred_username", "email", "email_verified", "groups");

    /**
     * Refresh does not pass through login, so policy that must still hold is re-checked here: the client must
     * still be enabled for login, and the account must still have its subject. Either change stops refresh
     * immediately (Hydra could not do this).
     */
    record RefreshPolicy(OAuth2AuthorizationService authorizations, Subjects subjects) implements AuthenticationProvider {
        @Override public Authentication authenticate(Authentication request) throws AuthenticationException {
            var refresh = (OAuth2RefreshTokenAuthenticationToken) request;
            if (refresh.getPrincipal() instanceof OAuth2ClientAuthenticationToken client && client.getRegisteredClient() != null
                    && !RegisteredClients.loginEnabled(client.getRegisteredClient())) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
            }
            var authorization = authorizations.findByToken(refresh.getRefreshToken(), OAuth2TokenType.REFRESH_TOKEN);
            var stored = authorization == null ? null : authorization.<Authentication>getAttribute(Principal.class.getName());
            if (stored != null && stored.getPrincipal() instanceof DirectoryPrincipal principal
                    && subjects.find(principal.user().id()).isEmpty()) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
            }
            return null; // allowed: the framework's refresh provider does the actual work
        }
        @Override public boolean supports(Class<?> type) { return OAuth2RefreshTokenAuthenticationToken.class.isAssignableFrom(type); }
    }

    @Bean Subjects subjects(DSLContext db) {
        return new Subjects(db);
    }

    @Bean OAuth2TokenCustomizer<JwtEncodingContext> claims(Subjects subjects) {
        return context -> {
            if (!(context.getPrincipal().getPrincipal() instanceof DirectoryPrincipal principal)) return;
            var user = principal.user();
            var scopes = context.getAuthorizedScopes();
            context.getClaims().subject(subjects.issue(user.id()));
            if (scopes.contains("groups")) {
                context.getClaims().claim("groups", user.memberships().stream().map(User.GroupMembership::name).toList());
            }
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())
                    && context.getRegisteredClient().getClientSettings().getSetting(RegisteredClients.AUDIENCES) instanceof String extra) {
                // Resource audiences registered for the client (the framework has no audience parameter).
                var audience = new ArrayList<>(List.of(context.getRegisteredClient().getClientId()));
                for (var value : extra.split(",")) if (!value.isBlank() && !audience.contains(value.trim())) audience.add(value.trim());
                context.getClaims().audience(audience);
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
        var json = PrincipalJson.mapper(getClass().getClassLoader());
        var rows = new JdbcOAuth2AuthorizationService.JsonMapperOAuth2AuthorizationRowMapper(clients, json);
        service.setAuthorizationRowMapper(rows);
        service.setAuthorizationParametersMapper(new JdbcOAuth2AuthorizationService.JsonMapperOAuth2AuthorizationParametersMapper(json));
        return service;
    }

    @Bean ExpiredAuthorizations expiredAuthorizations(DSLContext db) {
        return new ExpiredAuthorizations(db, Clock.systemUTC());
    }

    @Bean OAuth2AuthorizationConsentService consents(JdbcOperations jdbc, RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationConsentService(jdbc, clients);
    }

    // All configured keys: the JWKS endpoint publishes their public halves; userinfo verifies against them.
    @Bean JWKSource<SecurityContext> jwkSource(Properties properties) {
        return new ImmutableJWKSet<>(new JWKSet(List.copyOf(SigningKeys.load(properties.signingKeys()))));
    }

    // Signing uses the first key only; the framework takes a JwtEncoder bean over building one from all keys.
    /** The framework's generators, except that refresh tokens also go to public clients (PublicClients). */
    @Bean OAuth2TokenGenerator<?> tokenGenerator(JwtEncoder encoder, OAuth2TokenCustomizer<JwtEncodingContext> claims) {
        var jwt = new JwtGenerator(encoder);
        jwt.setJwtCustomizer(claims);
        return new DelegatingOAuth2TokenGenerator(jwt, new OAuth2AccessTokenGenerator(), new PublicClients.RefreshTokens());
    }

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
