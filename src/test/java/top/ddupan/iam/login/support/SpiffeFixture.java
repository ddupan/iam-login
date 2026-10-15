package top.ddupan.iam.login.support;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * A stand-in SPIRE: serves its JWT keys over plain loopback HTTP both as the OIDC provider's JWKS and as a SPIFFE
 * Bundle Endpoint, and mints JWT-SVIDs.
 */
public final class SpiffeFixture implements AutoCloseable {
    public static final String ISSUER = "https://spire-oidc.example.test";
    private final RSAKey key;
    /** In the bundle for X509-SVIDs only: a JWT signed with it must not be accepted. */
    private final RSAKey x509Key;
    private final HttpServer server;

    public SpiffeFixture() {
        try {
            key = new RSAKeyGenerator(2048).keyID("spire-fixture").generate();
            x509Key = new RSAKeyGenerator(2048).keyID("spire-x509").generate();
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        } catch (JOSEException ex) {
            throw new IllegalStateException(ex);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        var jwks = new JWKSet(key.toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8);
        server.createContext("/keys", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, jwks.length);
            try (var body = exchange.getResponseBody()) { body.write(jwks); }
        });
        var bundle = new JWKSet(List.<JWK>of(new RSAKey.Builder(key.toPublicJWK()).keyUse(new KeyUse("jwt-svid")).build(),
                new RSAKey.Builder(x509Key.toPublicJWK()).keyUse(new KeyUse("x509-svid")).build()),
            Map.of("spiffe_sequence", 1, "spiffe_refresh_hint", 300)).toString().getBytes(StandardCharsets.UTF_8);
        server.createContext("/bundle", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bundle.length);
            try (var body = exchange.getResponseBody()) { body.write(bundle); }
        });
        server.start();
    }

    public String jwkSetUri() { return "http://127.0.0.1:" + server.getAddress().getPort() + "/keys"; }
    public String bundleEndpoint() { return "http://127.0.0.1:" + server.getAddress().getPort() + "/bundle"; }

    /** A JWT-SVID shaped like SPIRE's: subject is the SPIFFE ID, short-lived. */
    public String svid(String spiffeId, List<String> audience, String issuer, Instant expires) {
        return sign(key, spiffeId, audience, issuer, expires);
    }

    /** Shaped like a JWT-SVID but signed with the bundle's X509-SVID key. */
    public String svidSignedWithX509Key(String spiffeId, List<String> audience) {
        return sign(x509Key, spiffeId, audience, ISSUER, Instant.now().plusSeconds(300));
    }

    private static String sign(RSAKey key, String spiffeId, List<String> audience, String issuer, Instant expires) {
        try {
            var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
                new JWTClaimsSet.Builder().issuer(issuer).subject(spiffeId).audience(audience)
                    .issueTime(Date.from(Instant.now())).expirationTime(Date.from(expires)).build());
            jwt.sign(new RSASSASigner(key));
            return jwt.serialize();
        } catch (JOSEException ex) {
            throw new IllegalStateException(ex);
        }
    }

    public String svid(String spiffeId) {
        return svid(spiffeId, List.of("iam-login"), ISSUER, Instant.now().plusSeconds(3600));
    }

    @Override public void close() { server.stop(0); }
}
