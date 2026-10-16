package top.ddupan.iam.login.configuration;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;
import top.ddupan.iam.login.clients.domain.MachineClient;
import top.ddupan.iam.login.clients.infrastructure.RegisteredClients;

/**
 * OAuth SPIFFE Client Authentication with JWT-SVIDs, as draft-ietf-oauth-spiffe-client-auth-02 specifies it:
 * the client authenticates at the token (and revocation, introspection) endpoint with a JWT-SVID as
 * {@code client_assertion}, of type {@code urn:ietf:params:oauth:client-assertion-type:jwt-spiffe}. Section numbers
 * below refer to that draft. Only the JWT-SVID method is implemented; X509-SVIDs and WIT-SVIDs are not.
 *
 * Keys come only from the SPIFFE Bundle Endpoint configured for the trust domain in the SPIFFE ID (6.1); the
 * token's {@code iss} is never used to find keys (6.2.4, 8.1), and is otherwise ignored.
 *
 * The same JWT-SVID is also accepted as the {@code subject_token} of an RFC 8693 token exchange, for clients that
 * speak token exchange but not this draft: see {@link Converter} and {@link Exchange}.
 */
final class SpiffeClients {
    private SpiffeClients() { }

    /** The method name advertised in metadata (4) and registered on clients. */
    static final ClientAuthenticationMethod SPIFFE_JWT = RegisteredClients.SPIFFE_JWT;
    static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe";
    /** RFC 8693 3: the token types an SVID exchange takes and issues. */
    static final String JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
    static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

    /** Out-of-band trust (5): which bundle endpoint holds the keys of which trust domain (6.1). */
    @ConfigurationProperties("iam.spiffe")
    record Properties(List<TrustDomain> trustDomains) {
        Properties {
            trustDomains = trustDomains == null ? List.of() : List.copyOf(trustDomains);
            if (trustDomains.stream().map(TrustDomain::name).distinct().count() != trustDomains.size()) {
                throw new IllegalArgumentException("iam.spiffe.trust-domains: a trust domain is listed twice");
            }
        }
        record TrustDomain(String name, URI bundleEndpoint) {
            TrustDomain {
                if (name == null || !TRUST_DOMAIN.matcher(name).matches()) throw new IllegalArgumentException("Invalid trust domain " + name);
                // WebPKI flavour (6.1): an https endpoint whose certificate the JVM trusts.
                if (bundleEndpoint == null || !"https".equals(bundleEndpoint.getScheme()) && !loopback(bundleEndpoint)) {
                    throw new IllegalArgumentException("The bundle endpoint of " + name + " must be https");
                }
            }
            private static boolean loopback(URI uri) {
                return "http".equals(uri.getScheme()) && Set.of("127.0.0.1", "localhost").contains(uri.getHost());
            }
        }
        boolean enabled() { return !trustDomains.isEmpty(); }
    }

    private static final Pattern TRUST_DOMAIN = Pattern.compile("[a-z0-9._-]+");
    /** The trust domain of a well-formed SPIFFE ID, or null. */
    static @Nullable String trustDomain(@Nullable String spiffeId) { return MachineClient.trustDomain(spiffeId); }

    /** 5.1: exact, or with a trailing "/*" a prefix of whole path segments. */
    static boolean matches(String registered, String spiffeId) {
        if (!registered.endsWith("/*")) return registered.equals(spiffeId);
        var prefix = registered.substring(0, registered.length() - 1);
        return spiffeId.startsWith(prefix) && spiffeId.length() > prefix.length();
    }

    /** A request authenticating with a JWT-SVID; verified by {@link Provider}. */
    static final class Assertion extends OAuth2ClientAuthenticationToken {
        Assertion(String clientId, String assertion) {
            super(clientId, SPIFFE_JWT, assertion, null);
        }
    }

    /**
     * 3.1: client_assertion_type and a single client_assertion. client_id is optional; without it the client is the
     * one registered under the SPIFFE ID itself, read from the (not yet verified) sub only to look the client up.
     *
     * A token exchange with a JWT subject_token and no client credential of its own is read the same way: the
     * subject_token is the SVID that authenticates the client, and {@link Exchange} issues for it.
     */
    static final class Converter implements AuthenticationConverter {
        @Override public @Nullable Authentication convert(HttpServletRequest request) {
            if (!"POST".equals(request.getMethod())) return null;
            if (exchange(request)) {
                var subjects = request.getParameterValues(OAuth2ParameterNames.SUBJECT_TOKEN);
                var ids = request.getParameterValues(OAuth2ParameterNames.CLIENT_ID);
                // Malformed exchanges are the framework converter's to reject, with its error.
                if (subjects == null || subjects.length != 1 || ids != null && ids.length != 1) return null;
                String clientId = ids != null ? ids[0] : subject(subjects[0]);
                return clientId == null || clientId.isBlank() ? null : new Assertion(clientId, subjects[0]);
            }
            if (!ASSERTION_TYPE.equals(request.getParameter(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE))) return null;
            var types = request.getParameterValues(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE);
            var assertions = request.getParameterValues(OAuth2ParameterNames.CLIENT_ASSERTION);
            var ids = request.getParameterValues(OAuth2ParameterNames.CLIENT_ID);
            // RFC 6749 2.3: one authentication method per request.
            if (types.length != 1 || assertions == null || assertions.length != 1 || ids != null && ids.length != 1
                    || request.getHeader(HttpHeaders.AUTHORIZATION) != null || request.getParameter(OAuth2ParameterNames.CLIENT_SECRET) != null) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
            }
            String clientId = ids != null ? ids[0] : subject(assertions[0]);
            if (clientId == null || clientId.isBlank()) throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
            return new Assertion(clientId, assertions[0]);
        }

        private static boolean exchange(HttpServletRequest request) {
            return AuthorizationGrantType.TOKEN_EXCHANGE.getValue().equals(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))
                && JWT_TOKEN_TYPE.equals(request.getParameter(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE))
                && request.getParameter(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE) == null
                && request.getParameter(OAuth2ParameterNames.CLIENT_SECRET) == null
                && request.getHeader(HttpHeaders.AUTHORIZATION) == null;
        }

        private static @Nullable String subject(String assertion) {
            try { return SignedJWT.parse(assertion).getJWTClaimsSet().getSubject(); }
            catch (ParseException ex) { return null; }
        }
    }

    /** 3.1, steps 1-5, against the keys of the SVID's own trust domain. */
    static final class Provider implements AuthenticationProvider {
        private static final Logger LOG = LoggerFactory.getLogger(Provider.class);
        /** JWT-SVID specification 3: the algorithms a JWT-SVID may be signed with. */
        private static final Set<JWSAlgorithm> ALGORITHMS = Set.of(JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
            JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512, JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512);
        /** The framework's allowance for clock differences in its own JWT validation. */
        private static final Duration SKEW = Duration.ofSeconds(60);
        private final RegisteredClientRepository clients;
        private final String issuer;
        private final Function<String, List<JWK>> keys;
        private final Clock clock;

        /** {@code keys}: the JWT-SVID keys of a trust domain, empty when it is not trusted. */
        Provider(RegisteredClientRepository clients, String issuer, Function<String, List<JWK>> keys, Clock clock) {
            this.clients = clients;
            this.issuer = issuer;
            this.keys = keys;
            this.clock = clock;
        }

        @Override public Authentication authenticate(Authentication authentication) {
            var request = (Assertion) authentication;
            var assertion = String.valueOf(request.getCredentials());
            RegisteredClient client = clients.findByClientId(String.valueOf(request.getPrincipal()));
            if (client == null || !client.getClientAuthenticationMethods().contains(SPIFFE_JWT)) throw invalid("unknown client");
            // The console's emergency stop; client_credentials has no authorization or refresh step to stop it at.
            if (!RegisteredClients.loginEnabled(client)) throw invalid("disabled");
            try {
                var jwt = SignedJWT.parse(assertion);
                var header = jwt.getHeader();
                if (!ALGORITHMS.contains(header.getAlgorithm())) throw invalid("algorithm");
                if (header.getType() != null && !JOSEObjectType.JWT.equals(header.getType()) && !JOSEObjectType.JOSE.equals(header.getType())) {
                    throw invalid("typ");
                }
                var claims = jwt.getJWTClaimsSet();
                // 1: well-formed, with a SPIFFE ID in sub, aud and exp.
                var spiffeId = claims.getSubject();
                var trustDomain = trustDomain(spiffeId);
                if (trustDomain == null || claims.getAudience() == null || claims.getAudience().isEmpty() || claims.getExpirationTime() == null) {
                    throw invalid("claims");
                }
                // 2: not expired.
                if (!clock.instant().isBefore(claims.getExpirationTime().toInstant().plus(SKEW))) throw invalid("expired");
                // 3: the issuer identifier as the sole audience.
                if (!claims.getAudience().equals(List.of(issuer))) throw invalid("audience");
                // 4: signed by a key of the trust domain the SPIFFE ID belongs to.
                if (!verified(jwt, keys.apply(trustDomain))) throw invalid("signature");
                // 5: the SPIFFE ID belongs to the client.
                String registered = client.getClientSettings().getSetting(RegisteredClients.SPIFFE_ID);
                if (!matches(registered != null ? registered : client.getClientId(), spiffeId)) throw invalid("subject");
            } catch (ParseException ex) {
                throw invalid("malformed");
            }
            return new OAuth2ClientAuthenticationToken(client, SPIFFE_JWT, assertion);
        }

        private static boolean verified(SignedJWT jwt, List<JWK> candidates) {
            var kid = jwt.getHeader().getKeyID();
            for (var key : candidates) {
                if (kid != null && !kid.equals(key.getKeyID()) || !(key instanceof AsymmetricJWK asymmetric)) continue;
                try {
                    if (jwt.verify(new DefaultJWSVerifierFactory().createJWSVerifier(jwt.getHeader(), asymmetric.toPublicKey()))) return true;
                } catch (JOSEException ex) {
                    // A key of another type or curve; try the next.
                }
            }
            return false;
        }

        // The reason stays in the log; the client learns only invalid_client.
        private static OAuth2AuthenticationException invalid(String reason) {
            LOG.debug("SPIFFE client authentication rejected: {}", reason);
            return new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
        }

        @Override public boolean supports(Class<?> type) {
            return Assertion.class.isAssignableFrom(type);
        }
    }

    /**
     * RFC 8693 for a client that authenticated with its JWT-SVID as the subject_token ({@link Converter}): the
     * workload exchanges its SPIFFE identity for its own access token, exactly what client_credentials issues it
     * (sub = client ID, aud = client ID plus registered audiences), with issued_token_type added (2.2.1). Any other
     * exchange goes to the framework's provider, which this one replaces: the provider manager would otherwise try
     * that one after an error here and answer with its error instead. No delegation: an actor_token is refused, and
     * audience or resource may only name an audience the client is registered for.
     */
    static final class Exchange implements AuthenticationProvider {
        private final AuthenticationProvider clientCredentials;
        private final AuthenticationProvider framework;

        Exchange(AuthenticationProvider clientCredentials, AuthenticationProvider framework) {
            this.clientCredentials = clientCredentials;
            this.framework = framework;
        }

        @Override public @Nullable Authentication authenticate(Authentication authentication) {
            var request = (OAuth2TokenExchangeAuthenticationToken) authentication;
            if (!(request.getPrincipal() instanceof OAuth2ClientAuthenticationToken client)
                    || !SPIFFE_JWT.equals(client.getClientAuthenticationMethod())
                    || !request.getSubjectToken().equals(client.getCredentials())) {
                return framework.authenticate(authentication);
            }
            if (request.getActorToken() != null) throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
            var type = request.getRequestedTokenType();
            if (!ACCESS_TOKEN_TYPE.equals(type) && !JWT_TOKEN_TYPE.equals(type)) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
            }
            var targets = new HashSet<>(request.getAudiences());
            targets.addAll(request.getResources());
            // 2.2.2: a target this server will not issue for.
            if (!RegisteredClients.tokenAudiences(client.getRegisteredClient()).containsAll(targets)) {
                throw new OAuth2AuthenticationException(new OAuth2Error("invalid_target"));
            }
            var issued = (OAuth2AccessTokenAuthenticationToken) clientCredentials.authenticate(
                new OAuth2ClientCredentialsAuthenticationToken(client, request.getScopes(), Map.of()));
            var parameters = new HashMap<>(issued.getAdditionalParameters());
            parameters.put(OAuth2ParameterNames.ISSUED_TOKEN_TYPE, type);
            return new OAuth2AccessTokenAuthenticationToken(issued.getRegisteredClient(), (Authentication) issued.getPrincipal(),
                issued.getAccessToken(), issued.getRefreshToken(), parameters);
        }

        @Override public boolean supports(Class<?> type) {
            return OAuth2TokenExchangeAuthenticationToken.class.isAssignableFrom(type);
        }
    }

    /**
     * 6.1: each trust domain's SPIFFE Bundle Endpoint, polled as its spiffe_refresh_hint says. Only keys whose use
     * is jwt-svid count. A failed refresh keeps the keys from the last successful one. SPIRE publishes a new key in
     * the bundle before signing with it, so polling is enough to follow rotation.
     */
    static final class Bundles implements Function<String, List<JWK>> {
        private static final Logger LOG = LoggerFactory.getLogger(Bundles.class);
        private static final Duration DEFAULT_REFRESH = Duration.ofMinutes(5);
        private record Cached(List<JWK> keys, Instant fetched, Duration refresh) { }

        private final Map<String, URI> endpoints = new HashMap<>();
        private final Map<String, Cached> cache = new HashMap<>();
        private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        private final Clock clock;

        Bundles(Properties properties, Clock clock) {
            properties.trustDomains().forEach(domain -> endpoints.put(domain.name(), domain.bundleEndpoint()));
            this.clock = clock;
        }

        @Override public synchronized List<JWK> apply(String trustDomain) {
            var endpoint = endpoints.get(trustDomain);
            if (endpoint == null) return List.of();
            var cached = cache.get(trustDomain);
            var now = clock.instant();
            if (cached == null || now.isAfter(cached.fetched().plus(cached.refresh()))) {
                var fetched = fetch(trustDomain, endpoint, now);
                if (fetched != null) cache.put(trustDomain, cached = fetched);
            }
            return cached == null ? List.of() : cached.keys();
        }

        private @Nullable Cached fetch(String trustDomain, URI endpoint, Instant now) {
            try {
                var response = http.send(HttpRequest.newBuilder(endpoint).timeout(Duration.ofSeconds(5)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) throw new IOException("status " + response.statusCode());
                var bundle = JWKSet.parse(response.body());
                var keys = bundle.getKeys().stream().filter(key -> key.getKeyUse() != null && "jwt-svid".equals(key.getKeyUse().identifier())).toList();
                var hint = bundle.getAdditionalMembers().get("spiffe_refresh_hint");
                var refresh = hint instanceof Number seconds && seconds.longValue() > 0 ? Duration.ofSeconds(seconds.longValue()) : DEFAULT_REFRESH;
                return new Cached(keys, now, refresh);
            } catch (IOException | ParseException ex) {
                LOG.warn("SPIFFE bundle of {} could not be fetched from {}: {}", trustDomain, endpoint, ex.toString());
                return null;
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                return null;
            }
        }
    }
}
