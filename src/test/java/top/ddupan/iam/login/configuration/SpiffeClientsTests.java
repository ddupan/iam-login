package top.ddupan.iam.login.configuration;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import top.ddupan.iam.login.support.SpiffeFixture;
import static org.assertj.core.api.Assertions.*;

/** draft-ietf-oauth-spiffe-client-auth-02, section 3.1 (JWT-SVID) and 5.1 (spiffe_id); one test per requirement. */
class SpiffeClientsTests {
    private static final String ISSUER = "https://as.example.test";
    private static final String MACHINE = "spiffe://example.test/ci/machine";
    private static final Instant NOW = Instant.parse("2026-10-15T12:00:00Z");
    private static final ECKey KEY = generate("current");
    private static final ECKey FOREIGN = generate("foreign");
    private static final SpiffeFixture SPIRE = new SpiffeFixture();
    @AfterAll static void close() { SPIRE.close(); }

    private final InMemoryRegisteredClientRepository clients = new InMemoryRegisteredClientRepository(
        client(MACHINE, null), client("named-machine", "spiffe://example.test/ci/named"),
        client("workloads", "spiffe://example.test/workloads/*"),
        RegisteredClient.withId(UUID.randomUUID().toString()).clientId("spiffe://example.test/ci/secret")
            .clientSecret("{noop}x").authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build());
    // example.test trusts KEY; other.test is trusted too, with FOREIGN.
    private final SpiffeClients.Provider provider = new SpiffeClients.Provider(clients, ISSUER,
        domain -> switch (domain) { case "example.test" -> List.<JWK>of(KEY.toPublicJWK()); case "other.test" -> List.<JWK>of(FOREIGN.toPublicJWK()); default -> List.of(); },
        Clock.fixed(NOW, ZoneOffset.UTC));

    @Test void aValidJwtSvidAuthenticatesTheClientRegisteredUnderItsSpiffeId() {
        var authenticated = (OAuth2ClientAuthenticationToken) provider.authenticate(new SpiffeClients.Assertion(MACHINE, svid(c -> c)));
        assertThat(authenticated.isAuthenticated()).isTrue();
        assertThat(authenticated.getRegisteredClient().getClientId()).isEqualTo(MACHINE);
        assertThat(authenticated.getClientAuthenticationMethod()).isEqualTo(SpiffeClients.SPIFFE_JWT);
    }

    @Test void step1RequiresSubAudAndExpWithASpiffeIdInSub() {
        rejected(MACHINE, svid(c -> c.subject(null)));
        rejected(MACHINE, svid(c -> c.audience(List.of())));
        rejected(MACHINE, svid(c -> c.expirationTime(null)));
        rejected("spiffe://example.test/ci/../machine", svid(c -> c.subject("spiffe://example.test/ci/../machine")));
        rejected("https://example.test/ci/machine", svid(c -> c.subject("https://example.test/ci/machine")));
        rejected(MACHINE, "not-a-jwt");
    }

    @Test void step2RejectsAnExpiredSvid() {
        rejected(MACHINE, svid(c -> c.expirationTime(Date.from(NOW.minusSeconds(61)))));
    }

    @Test void step3RequiresTheIssuerAsTheSoleAudience() {
        rejected(MACHINE, svid(c -> c.audience(List.of(ISSUER, "other"))));
        rejected(MACHINE, svid(c -> c.audience(List.of(ISSUER + "/"))));
        rejected(MACHINE, svid(c -> c.audience(List.of("iam-login"))));
    }

    @Test void step4VerifiesWithTheKeysOfTheSpiffeIdsOwnTrustDomain() {
        // A trusted key, but of another trust domain.
        rejected(MACHINE, sign(FOREIGN, JWSAlgorithm.ES256, null, c -> c));
        rejected(MACHINE, sign(generate("current"), JWSAlgorithm.ES256, null, c -> c));
        // JWT-SVIDs are asymmetric; a MAC "signature" is not one.
        rejected(MACHINE, hmac());
    }

    @Test void step4UsesOnlyJwtSvidKeysFromTheBundleEndpoint() {
        var bundles = new SpiffeClients.Bundles(new SpiffeClients.Properties(List.of(
            new SpiffeClients.Properties.TrustDomain("example.test", URI.create(SPIRE.bundleEndpoint())))), Clock.systemUTC());
        var spire = new SpiffeClients.Provider(clients, ISSUER, bundles, Clock.systemUTC());
        assertThat(spire.authenticate(new SpiffeClients.Assertion(MACHINE,
            SPIRE.svid(MACHINE, List.of(ISSUER), SpiffeFixture.ISSUER, Instant.now().plusSeconds(300)))).isAuthenticated()).isTrue();
        assertThat(bundles.apply("example.test")).extracting(JWK::getKeyID).containsExactly("spire-fixture");
        assertThatThrownBy(() -> spire.authenticate(new SpiffeClients.Assertion(MACHINE, SPIRE.svidSignedWithX509Key(MACHINE, List.of(ISSUER)))))
            .isInstanceOf(OAuth2AuthenticationException.class);
        // No bundle endpoint configured: no keys at all.
        assertThat(bundles.apply("other.test")).isEmpty();
    }

    @Test void step5MatchesTheSpiffeIdToTheClientExactlyOrByWholeSegments() {
        assertThat(provider.authenticate(new SpiffeClients.Assertion("named-machine",
            svid(c -> c.subject("spiffe://example.test/ci/named")))).isAuthenticated()).isTrue();
        rejected("named-machine", svid(c -> c.subject(MACHINE)));
        assertThat(provider.authenticate(new SpiffeClients.Assertion("workloads",
            svid(c -> c.subject("spiffe://example.test/workloads/a/b")))).isAuthenticated()).isTrue();
        rejected("workloads", svid(c -> c.subject("spiffe://example.test/workloads")));
        rejected("workloads", svid(c -> c.subject("spiffe://example.test/workloadsx/a")));
        assertThat(SpiffeClients.matches("spiffe://example.org/client/*", "spiffe://example.org/client/123")).isTrue();
        assertThat(SpiffeClients.matches("spiffe://example.org/client/*", "spiffe://example.org/client123")).isFalse();
    }

    @Test void onlyClientsRegisteredForTheMethodAreAccepted() {
        rejected("spiffe://example.test/ci/secret", svid(c -> c.subject("spiffe://example.test/ci/secret")));
        rejected("spiffe://example.test/ci/unknown", svid(c -> c.subject("spiffe://example.test/ci/unknown")));
    }

    @Test void theJwtSvidHeaderIsChecked() {
        rejected(MACHINE, sign(KEY, JWSAlgorithm.ES256, new JOSEObjectType("at+jwt"), c -> c));
        assertThat(provider.authenticate(new SpiffeClients.Assertion(MACHINE,
            sign(KEY, JWSAlgorithm.ES256, JOSEObjectType.JWT, c -> c))).isAuthenticated()).isTrue();
    }

    @Test void theConverterTakesOnlyItsAssertionTypeAndOneCredential() {
        var converter = new SpiffeClients.Converter();
        var other = request(Map.of("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion", svid(c -> c)));
        assertThat(converter.convert(other)).isNull();
        // Without client_id, the client is the one registered under the SPIFFE ID.
        var bare = request(Map.of("client_assertion_type", SpiffeClients.ASSERTION_TYPE, "client_assertion", svid(c -> c)));
        assertThat(converter.convert(bare).getPrincipal()).isEqualTo(MACHINE);
        var named = request(Map.of("client_assertion_type", SpiffeClients.ASSERTION_TYPE, "client_assertion", svid(c -> c),
            "client_id", "named-machine"));
        assertThat(converter.convert(named).getPrincipal()).isEqualTo("named-machine");
        var twice = request(Map.of("client_assertion_type", SpiffeClients.ASSERTION_TYPE, "client_assertion", svid(c -> c)));
        twice.addParameter("client_assertion", svid(c -> c));
        assertThatThrownBy(() -> converter.convert(twice)).isInstanceOfSatisfying(OAuth2AuthenticationException.class,
            ex -> assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST));
        var withSecret = request(Map.of("client_assertion_type", SpiffeClients.ASSERTION_TYPE, "client_assertion", svid(c -> c),
            "client_secret", "x"));
        assertThatThrownBy(() -> converter.convert(withSecret)).isInstanceOf(OAuth2AuthenticationException.class);
    }

    private void rejected(String clientId, String assertion) {
        assertThatThrownBy(() -> provider.authenticate(new SpiffeClients.Assertion(clientId, assertion)))
            .isInstanceOfSatisfying(OAuth2AuthenticationException.class,
                ex -> assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT));
    }

    private static String svid(UnaryOperator<JWTClaimsSet.Builder> change) {
        return sign(KEY, JWSAlgorithm.ES256, null, change);
    }

    private static String sign(ECKey key, JWSAlgorithm algorithm, JOSEObjectType type, UnaryOperator<JWTClaimsSet.Builder> change) {
        return sign(ecdsa(key), new JWSHeader.Builder(algorithm).keyID(key.getKeyID()).type(type).build(), change);
    }

    private static String hmac() {
        try {
            return sign(new MACSigner(new byte[32]), new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(KEY.getKeyID()).build(), c -> c);
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private static String sign(JWSSigner signer, JWSHeader header, UnaryOperator<JWTClaimsSet.Builder> change) {
        try {
            var jwt = new SignedJWT(header, change.apply(new JWTClaimsSet.Builder().subject(MACHINE).audience(List.of(ISSUER))
                .issueTime(Date.from(NOW)).expirationTime(Date.from(NOW.plusSeconds(300)))).build());
            jwt.sign(signer);
            return jwt.serialize();
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private static JWSSigner ecdsa(ECKey key) {
        try { return new ECDSASigner(key); } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private static ECKey generate(String kid) {
        try { return new ECKeyGenerator(Curve.P_256).keyID(kid).generate(); }
        catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private static RegisteredClient client(String clientId, String spiffeId) {
        var settings = ClientSettings.builder();
        if (spiffeId != null) settings.setting(SpiffeClients.SPIFFE_ID, spiffeId);
        return RegisteredClient.withId(UUID.randomUUID().toString()).clientId(clientId)
            .clientAuthenticationMethod(SpiffeClients.SPIFFE_JWT)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).clientSettings(settings.build()).build();
    }

    private static MockHttpServletRequest request(Map<String, String> parameters) {
        var request = new MockHttpServletRequest("POST", "/oauth2/token");
        parameters.forEach(request::addParameter);
        return request;
    }
}
