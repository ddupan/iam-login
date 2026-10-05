package top.ddupan.iam.login.authorization;

import com.nimbusds.jose.jwk.RSAKey;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.core.convert.ConversionService;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.web.util.UriComponentsBuilder;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;
import tools.jackson.databind.json.JsonMapper;
import top.ddupan.iam.login.configuration.ExpiredAuthorizations;
import top.ddupan.iam.login.support.AdDirectoryFixture;
import top.ddupan.iam.login.support.SessionRoundTrip;
import top.ddupan.iam.login.support.SigningKeyFixture;
import top.ddupan.iam.login.support.SpiffeFixture;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Spike: the in-process authorization server against simulated AD and a disposable database. */
// Container sessions: MockMvc hands sessions over as MockHttpSession, which Spring Session's cookie-based
// filter would ignore. What the database store must hold is checked by SessionRoundTrip.
@SpringBootTest(properties = {"spring.autoconfigure.exclude=org.springframework.boot.session.jdbc.autoconfigure.JdbcSessionAutoConfiguration", "iam.ad.enabled=true", "iam.ad.domain=example.test", "spring.ldap.base=dc=example,dc=test",
    "spring.datasource.hikari.maximum-pool-size=3",
    "iam.webauthn.enabled=true", "iam.webauthn.rp-id=localhost", "iam.webauthn.origin=https://localhost",
    "iam.authorization-server.enabled=true", "iam.authorization-server.issuer=https://localhost",
    "iam.authorization-server.subjects[0].authority=example.test",
    "iam.authorization-server.subjects[0].directory-id=00112233-4455-6677-8899-aabbccddeeff",
    "iam.authorization-server.subjects[0].subject=human:existing-subject",
    "management.otlp.metrics.export.enabled=false", "spring.security.user.password=fixture-monitor-password",
    "iam.clients.admin-groups[0]=gitea-admins",
    "iam.clients.spiffe.issuer=" + SpiffeFixture.ISSUER, "iam.clients.spiffe.admin-ids[0]=spiffe://example.test/ci/terraform"})
@AutoConfigureMockMvc
class AuthorizationServerIntegrationTests {
    static class Fixtures {
        static final AdDirectoryFixture DIRECTORY = new AdDirectoryFixture();
        static final PostgreSQLContainer DATABASE = new PostgreSQLContainer(DockerImageName.parse(
            "postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873")
            .asCompatibleSubstituteFor("postgres"));
        static { DATABASE.start(); }
        static final Path ACTIVE_KEY = SigningKeyFixture.write();
        static final Path PREVIOUS_KEY = SigningKeyFixture.write();
        static final SpiffeFixture SPIRE = new SpiffeFixture();
    }
    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) {
        r.add("spring.ldap.urls", () -> Fixtures.DIRECTORY.url());
        r.add("spring.datasource.url", () -> Fixtures.DATABASE.getJdbcUrl());
        r.add("spring.datasource.username", () -> Fixtures.DATABASE.getUsername());
        r.add("spring.datasource.password", () -> Fixtures.DATABASE.getPassword());
        r.add("iam.authorization-server.signing-keys[0]", () -> "file:" + Fixtures.ACTIVE_KEY);
        r.add("iam.authorization-server.signing-keys[1]", () -> "file:" + Fixtures.PREVIOUS_KEY);
        r.add("iam.clients.spiffe.jwk-set-uri", () -> Fixtures.SPIRE.jwkSetUri());
    }
    @AfterAll static void close() { Fixtures.DIRECTORY.close(); Fixtures.DATABASE.stop(); Fixtures.SPIRE.close(); }

    private static final String CALLBACK = "https://rp.example/cb";
    @Autowired MockMvc mvc;
    @Autowired RegisteredClientRepository clients;

    @BeforeEach void client() {
        if (clients.findByClientId("spike-rp") != null) return;
        clients.save(RegisteredClient.withId(UUID.randomUUID().toString()).clientId("spike-rp")
            .clientSecret("{noop}spike-secret").clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri(CALLBACK).scope("openid").scope("profile").scope("groups").scope("offline_access")
            .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
            // The framework reuses refresh tokens by default; rotation must be set per client.
            .tokenSettings(TokenSettings.builder()
                .reuseRefreshTokens(false).build())
            .build());
    }

    // Overall health includes Boot's LDAP check, which must reach the configured AD (here the fixture)
    // over LDAPS, not some auto-configured default.
    @Test void overallHealthIsUpAgainstTheConfiguredDirectory() throws Exception {
        mvc.perform(get("/actuator/health")).andExpect(status().isOk()).andExpect(jsonPath("status").value("UP"));
    }

    // Interrupted authorization request (saved request), both factors, CSRF token, prompt=login marker:
    // everything this flow leaves in the session must be storable in the database session store.
    @Test void sessionContentsOfALoginRoundTripThroughTheSessionStore(
            @Autowired @Qualifier("springSessionConversionService") ConversionService store) throws Exception {
        var session = new MockHttpSession();
        mvc.perform(get(URI.create(authorize(verifier()))).session(session).with(https()).accept(MediaType.TEXT_HTML))
            .andExpect(status().is3xxRedirection());
        mvc.perform(get("/signin").session(session).with(https())).andExpect(status().isOk());
        password(session);
        secondFactor(session);
        location(session, authorize(verifier(), Map.of("prompt", "login")));
        SessionRoundTrip.assertStorable(session, store);
    }

    @Test void noCodeIsIssuedUntilBothFactorsAreFresh() throws Exception {
        var verifier = verifier();
        mvc.perform(get(URI.create(authorize(verifier))).with(https()).accept(MediaType.TEXT_HTML))
            .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/signin"));
        var session = login();
        var passwordOnly = mvc.perform(get(URI.create(authorize(verifier))).with(https()).session(session).accept(MediaType.TEXT_HTML))
            .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
        assertThat(passwordOnly).startsWith("/signin/mfa").doesNotContain("code=");
        secondFactor(session);
        // The interrupted request is resumed after the passkey step.
        var resumed = mvc.perform(get("/signin/complete").with(https()).session(session))
            .andExpect(status().isSeeOther()).andReturn().getResponse().getHeader("Location");
        assertThat(resumed).contains("/oauth2/authorize").contains("client_id=spike-rp");
        assertThat(code(session, verifier)).isNotBlank();
    }

    @Test void codeExchangeKeepsExistingSubjectReleasesGroupsAndRefreshes() throws Exception {
        var verifier = verifier();
        var session = login(); secondFactor(session);
        var tokens = json(mvc.perform(post("/oauth2/token").with(https()).with(httpBasic("spike-rp", "spike-secret"))
                .param("grant_type", "authorization_code").param("code", code(session, verifier))
                .param("redirect_uri", CALLBACK).param("code_verifier", verifier))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        var idToken = claims((String) tokens.get("id_token"));
        assertThat(idToken).containsEntry("sub", "human:existing-subject").containsEntry("preferred_username", "alice");
        assertThat(idToken.get("groups")).asInstanceOf(InstanceOfAssertFactories.LIST).contains("gitea-admins");
        assertThat(claims((String) tokens.get("access_token"))).containsEntry("sub", "human:existing-subject");
        assertThat(tokens.get("refresh_token")).as("offline_access was granted").isNotNull();
        // Refresh reloads the stored principal from the database (Jackson allowlist round trip).
        var refreshed = json(mvc.perform(post("/oauth2/token").with(https()).with(httpBasic("spike-rp", "spike-secret"))
                .param("grant_type", "refresh_token").param("refresh_token", (String) tokens.get("refresh_token")))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertThat(claims((String) refreshed.get("access_token"))).containsEntry("sub", "human:existing-subject");
        assertThat(refreshed.get("refresh_token")).isNotEqualTo(tokens.get("refresh_token"));
        mvc.perform(post("/oauth2/token").with(https()).with(httpBasic("spike-rp", "spike-secret"))
                .param("grant_type", "refresh_token").param("refresh_token", (String) tokens.get("refresh_token")))
            .andExpect(status().isBadRequest());
    }

    @Test void promptNoneAnswersTheClientInsteadOfShowingLogin() throws Exception {
        var none = authorize(verifier(), Map.of("prompt", "none"));
        // No session, and a password-only session: the client gets login_required, never a page or a code.
        var anonymous = location(null, none);
        assertThat(anonymous).startsWith(CALLBACK);
        assertThat(query(anonymous)).containsEntry("error", "login_required").containsEntry("state", "spike-state").doesNotContainKey("code");
        var session = login();
        assertThat(query(location(session, none))).containsEntry("error", "login_required").doesNotContainKey("code");
        secondFactor(session);
        assertThat(query(location(session, none))).containsKey("code");
        // The error goes to the client only once its redirect URI is verified.
        var foreign = none.replace("redirect_uri=" + CALLBACK, "redirect_uri=https://attacker.example/cb");
        assertThat(foreign).isNotEqualTo(none);
        mvc.perform(get(URI.create(foreign)).with(https()).accept(MediaType.TEXT_HTML)).andExpect(status().isBadRequest());
    }

    @Test void promptLoginAndMaxAgeDemandAFreshAuthentication() throws Exception {
        var session = login(); secondFactor(session);
        var login = authorize(verifier(), Map.of("prompt", "login"));
        assertThat(location(session, login)).isEqualTo("/signin");
        // Signing in again (password + passkey) satisfies the same request, which then yields a code.
        password(session); secondFactor(session);
        assertThat(query(location(session, login))).containsKey("code");

        // Five minutes old: still within the MFA policy's own freshness window, but beyond max_age=60.
        var old = login(); secondFactor(old, Instant.now().minusSeconds(300));
        assertThat(query(location(old, authorize(verifier(), Map.of("max_age", "86400"))))).containsKey("code");
        var recent = authorize(verifier(), Map.of("max_age", "60"));
        assertThat(location(old, recent)).isEqualTo("/signin");
        password(old); secondFactor(old);
        assertThat(query(location(old, recent))).containsKey("code");
    }

    @Test void requestObjectsAreRejectedRatherThanIgnored() throws Exception {
        var session = login(); secondFactor(session);
        assertThat(query(location(session, authorize(verifier(), Map.of("request", "eyJhbGciOiJub25lIn0.e30.")))))
            .containsEntry("error", "request_not_supported").doesNotContainKey("code");
        // request_uri is read as a pushed authorization request reference; an unknown one is refused without
        // redirecting anywhere.
        mvc.perform(get(URI.create(authorize(verifier(), Map.of("request_uri", "urn:ietf:params:oauth:request_uri:unknown"))))
            .with(https()).session(session).accept(MediaType.TEXT_HTML)).andExpect(status().isBadRequest());
    }

    @Test void discoveryDescribesWhatIsSupported() throws Exception {
        var metadata = json(mvc.perform(get("/.well-known/openid-configuration").with(https()))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertThat(metadata.get("scopes_supported")).asInstanceOf(InstanceOfAssertFactories.LIST)
            .contains("openid", "profile", "email", "groups", "offline_access").doesNotHaveDuplicates();
        assertThat(metadata).containsEntry("request_parameter_supported", false)
            .containsEntry("request_uri_parameter_supported", false).containsEntry("claims_parameter_supported", false);
        assertThat(metadata.get("claims_supported")).asInstanceOf(InstanceOfAssertFactories.LIST).contains("groups", "auth_time");
    }

    @Test void tokensAreSignedByTheFirstKeyAndAllKeysArePublished() throws Exception {
        var jwks = json(mvc.perform(get("/oauth2/jwks").with(https())).andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString());
        var keys = (List<Map<String, Object>>) jwks.get("keys");
        assertThat(keys).hasSize(2).allSatisfy(key -> assertThat(key).doesNotContainKeys("d", "p", "q"));
        var active = thumbprint(Fixtures.ACTIVE_KEY);
        assertThat(keys).extracting(key -> key.get("kid")).containsExactly(active, thumbprint(Fixtures.PREVIOUS_KEY));
        var session = login(); secondFactor(session);
        var verifier = verifier();
        var tokens = json(mvc.perform(post("/oauth2/token").with(https()).with(httpBasic("spike-rp", "spike-secret"))
                .param("grant_type", "authorization_code").param("code", code(session, verifier))
                .param("redirect_uri", CALLBACK).param("code_verifier", verifier))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        var header = json(new String(Base64.getUrlDecoder().decode(((String) tokens.get("id_token")).split("\\.")[0]), StandardCharsets.UTF_8));
        assertThat(header).containsEntry("kid", active);
    }

    @Test void expiredAuthorizationsArePurged(@Autowired OAuth2AuthorizationService authorizations,
            @Autowired ExpiredAuthorizations expired) {
        var client = clients.findByClientId("spike-rp");
        var now = Instant.now();
        var stale = authorization(client, now.minusSeconds(7200), now.minusSeconds(3600));
        var live = authorization(client, now.minusSeconds(60), now.plusSeconds(3600));
        authorizations.save(stale); authorizations.save(live);
        expired.purge();
        assertThat(authorizations.findById(stale.getId())).isNull();
        assertThat(authorizations.findById(live.getId())).isNotNull();
    }

    private static OAuth2Authorization authorization(
            RegisteredClient client, Instant issued, Instant expires) {
        return OAuth2Authorization.withRegisteredClient(client)
            .principalName("purge-test").authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .token(new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, UUID.randomUUID().toString(), issued, expires))
            .build();
    }

    private static String thumbprint(Path pem) throws Exception {
        var der = Base64.getMimeDecoder().decode(Files.readString(pem).replaceAll("-----(BEGIN|END) PRIVATE KEY-----", ""));
        var key = (RSAPrivateCrtKey) KeyFactory.getInstance("RSA")
            .generatePrivate(new PKCS8EncodedKeySpec(der));
        return new RSAKey.Builder((RSAPublicKey) KeyFactory.getInstance("RSA")
            .generatePublic(new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent())))
            .build().computeThumbprint().toString();
    }

    @Test void clientApiRequiresATokenForItsAudienceWhoseSubjectIsAnAdministrator() throws Exception {
        mvc.perform(get("/api/iam/clients").with(https())).andExpect(status().isUnauthorized());
        // A fully authenticated administrator's browser session is not an API credential.
        var session = login(); secondFactor(session);
        mvc.perform(get("/api/iam/clients").session(session).with(https())).andExpect(status().isUnauthorized());
        // An administrator's token issued to another application must not work here (audience).
        mvc.perform(get("/api/iam/clients").with(https()).with(token(List.of("spike-rp"), List.of("gitea-admins")))).andExpect(status().isForbidden());
        mvc.perform(get("/api/iam/clients").with(https()).with(token(List.of("iam-login"), List.of("MixedCase")))).andExpect(status().isForbidden());
        mvc.perform(get("/api/iam/clients").with(https()).with(token(List.of("iam-login"), List.of("gitea-admins")))).andExpect(status().isOk());
    }

    @Test void consoleIsAPublicClientWhoseTokensCarryTheApiAudience() throws Exception {
        var console = clients.findByClientId("iam-console");
        assertThat(console.getClientAuthenticationMethods()).containsExactly(ClientAuthenticationMethod.NONE);
        assertThat(console.getRedirectUris()).containsExactly("https://localhost/console/callback");
        mvc.perform(get("/console").with(https())).andExpect(status().isOk())
            .andExpect(content().string(Matchers.containsString("\"clientId\":\"iam-console\"")));
        // The real flow: password + passkey, PKCE, no secret, no consent page.
        var session = login(); secondFactor(session);
        var verifier = verifier();
        var challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        var authorize = UriComponentsBuilder.fromPath("/oauth2/authorize").queryParam("response_type", "code")
            .queryParam("client_id", "iam-console").queryParam("redirect_uri", "https://localhost/console/callback")
            .queryParam("scope", "openid groups").queryParam("state", "console-state")
            .queryParam("code_challenge", challenge).queryParam("code_challenge_method", "S256").encode().build().toUriString();
        var callback = location(session, authorize);
        assertThat(callback).startsWith("https://localhost/console/callback");
        var tokens = json(mvc.perform(post("/oauth2/token").with(https()).param("grant_type", "authorization_code")
                .param("client_id", "iam-console").param("code", query(callback).get("code"))
                .param("redirect_uri", "https://localhost/console/callback").param("code_verifier", verifier))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        var access = claims((String) tokens.get("access_token"));
        assertThat(access.get("aud")).asInstanceOf(InstanceOfAssertFactories.LIST).contains("iam-console", "iam-login");
        mvc.perform(get("/api/iam/clients").with(https()).header("Authorization", "Bearer " + tokens.get("access_token")))
            .andExpect(status().isOk());
    }

    // Machines (IaC) present a SPIFFE JWT-SVID: allowed only for listed SPIFFE IDs, for audience iam-login,
    // from the SPIRE issuer, and still valid. Groups play no part.
    @Test void spiffeIdentitiesOnTheAllowlistManageClients() throws Exception {
        var spire = Fixtures.SPIRE;
        mvc.perform(get("/api/iam/clients").with(https()).header("Authorization", "Bearer " + spire.svid("spiffe://example.test/ci/terraform")))
            .andExpect(status().isOk());
        mvc.perform(get("/api/iam/clients").with(https()).header("Authorization", "Bearer " + spire.svid("spiffe://example.test/ci/other")))
            .andExpect(status().isForbidden());
        for (var rejected : List.of(
                spire.svid("spiffe://example.test/ci/terraform", List.of("zot"), SpiffeFixture.ISSUER, Instant.now().plusSeconds(600)),
                spire.svid("spiffe://example.test/ci/terraform", List.of("iam-login"), SpiffeFixture.ISSUER, Instant.now().minusSeconds(600)),
                spire.svid("spiffe://example.test/ci/terraform", List.of("iam-login"), "https://elsewhere.example", Instant.now().plusSeconds(600)))) {
            mvc.perform(get("/api/iam/clients").with(https()).header("Authorization", "Bearer " + rejected))
                .andExpect(status().isUnauthorized());
        }
    }

    @Test void clientsAreManagedThroughTheApi(@Autowired OAuth2AuthorizationService authorizations) throws Exception {
        var admin = token(List.of("iam-login"), List.of("gitea-admins"));
        var body = """
            {"id":"managed-app","name":"Managed","redirectUris":["https://rp.example/managed"],
             "scopes":["openid","profile","offline_access"],"postLogoutRedirectUris":[],"loginEnabled":true,"pkceRequired":true}
            """;
        var created = json(mvc.perform(post("/api/iam/clients").with(https()).with(admin).contentType(MediaType.APPLICATION_JSON).content(body))
            .andExpect(status().isCreated()).andExpect(header().string("Cache-Control", "no-store"))
            .andReturn().getResponse().getContentAsString());
        var secret = (String) created.get("secret");
        assertThat(tokenError("managed-app", secret)).isEqualTo("invalid_grant");
        mvc.perform(post("/api/iam/clients").with(https()).with(admin).contentType(MediaType.APPLICATION_JSON).content(body))
            .andExpect(status().isConflict());
        // offline_access brings the refresh_token grant (OIDC Core 11); the secret is stored encoded.
        var registered = clients.findByClientId("managed-app");
        assertThat(registered.getAuthorizationGrantTypes()).contains(AuthorizationGrantType.REFRESH_TOKEN);
        assertThat(registered.getClientSecret()).startsWith("{bcrypt}").doesNotContain(secret);
        mvc.perform(get("/api/iam/clients").with(https()).with(admin)).andExpect(status().isOk())
            .andExpect(jsonPath("$[?(@.id=='managed-app')]").exists()).andExpect(jsonPath("$[?(@.id=='iam-console')]").doesNotExist());
        assertThat(registered.getClientSettings().isRequireProofKey()).isTrue();
        // Missing loginEnabled or pkceRequired is rejected rather than defaulted.
        for (var flag : List.of(",\"loginEnabled\":true", ",\"pkceRequired\":true")) {
            mvc.perform(post("/api/iam/clients").with(https()).with(admin).contentType(MediaType.APPLICATION_JSON)
                    .content(body.replace("managed-app", "no-flag").replace(flag, "")))
                .andExpect(status().isBadRequest());
        }

        var rotated = (String) json(mvc.perform(post("/api/iam/clients/managed-app/secret").with(https()).with(admin))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).get("secret");
        assertThat(tokenError("managed-app", secret)).isEqualTo("invalid_client");
        assertThat(tokenError("managed-app", rotated)).isEqualTo("invalid_grant");

        // Disabled: the client is refused authorization (after redirect URI verification).
        mvc.perform(put("/api/iam/clients/managed-app").with(https()).with(admin).contentType(MediaType.APPLICATION_JSON)
                .content(body.replace("\"loginEnabled\":true", "\"loginEnabled\":false"))).andExpect(status().isOk())
            .andExpect(jsonPath("loginEnabled").value(false));
        var session = login(); secondFactor(session);
        var disabled = UriComponentsBuilder.fromPath("/oauth2/authorize").queryParam("response_type", "code")
            .queryParam("client_id", "managed-app").queryParam("redirect_uri", "https://rp.example/managed")
            .queryParam("scope", "openid").queryParam("state", "s").queryParam("code_challenge", "x".repeat(43))
            .queryParam("code_challenge_method", "S256").encode().build().toUriString();
        assertThat(query(location(session, disabled))).containsEntry("error", "unauthorized_client").doesNotContainKey("code");

        // PKCE can be turned off for a confidential client that cannot send it (Gitea).
        mvc.perform(put("/api/iam/clients/managed-app").with(https()).with(admin).contentType(MediaType.APPLICATION_JSON)
                .content(body.replace("\"pkceRequired\":true", "\"pkceRequired\":false"))).andExpect(status().isOk())
            .andExpect(jsonPath("pkceRequired").value(false));
        assertThat(clients.findByClientId("managed-app").getClientSettings().isRequireProofKey()).isFalse();

        // Deleting removes the client's authorizations with it.
        var authorization = authorization(clients.findByClientId("managed-app"), Instant.now(), Instant.now().plusSeconds(600));
        authorizations.save(authorization);
        mvc.perform(delete("/api/iam/clients/managed-app").with(https()).with(admin)).andExpect(status().isNoContent());
        mvc.perform(get("/api/iam/clients/managed-app").with(https()).with(admin)).andExpect(status().isNotFound());
        assertThat(authorizations.findById(authorization.getId())).isNull();
        // The console client is not managed through the API.
        mvc.perform(delete("/api/iam/clients/iam-console").with(https()).with(admin)).andExpect(status().isConflict());
    }

    private String tokenError(String client, String secret) throws Exception {
        return (String) json(mvc.perform(post("/oauth2/token").with(https()).with(httpBasic(client, secret))
                .param("grant_type", "authorization_code").param("code", "invalid-code")
                .param("redirect_uri", "https://rp.example/managed").param("code_verifier", verifier()))
            .andReturn().getResponse().getContentAsString()).get("error");
    }

    private static RequestPostProcessor token(List<String> audience, List<String> groups) {
        return jwt().jwt(jwt -> jwt.audience(audience).claim("groups", groups));
    }

    private String code(MockHttpSession session, String verifier) throws Exception {
        var location = mvc.perform(get(URI.create(authorize(verifier))).with(https()).session(session).accept(MediaType.TEXT_HTML))
            .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
        assertThat(location).startsWith(CALLBACK);
        return UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst("code");
    }
    private static String authorize(String verifier) throws Exception { return authorize(verifier, Map.of()); }
    private static String authorize(String verifier, Map<String, String> extra) throws Exception {
        var challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        var builder = UriComponentsBuilder.fromPath("/oauth2/authorize");
        extra.forEach(builder::queryParam);
        return builder.queryParam("response_type", "code")
            .queryParam("client_id", "spike-rp").queryParam("redirect_uri", CALLBACK)
            .queryParam("scope", "openid profile groups offline_access").queryParam("state", "spike-state")
            .queryParam("nonce", "spike-nonce").queryParam("code_challenge", challenge)
            .queryParam("code_challenge_method", "S256").encode().build().toUriString();
    }
    private static String verifier() { return UUID.randomUUID() + "-" + UUID.randomUUID(); }
    private static Map<String, Object> json(String body) { return JsonMapper.builder().build().readValue(body, Map.class); }
    private static Map<String, Object> claims(String jwt) {
        return json(new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8));
    }
    private MockHttpSession login() throws Exception { return password(new MockHttpSession()); }
    private MockHttpSession password(MockHttpSession session) throws Exception {
        mvc.perform(post("/signin/password").session(session).with(https()).with(csrf())
            .param("username", "alice").param("password", "fixture-password"))
            .andExpect(redirectedUrl("/signin/mfa"));
        return session;
    }
    private static void secondFactor(MockHttpSession session) { secondFactor(session, Instant.now()); }
    /** Adds the passkey factor and backdates every factor to {@code at}. */
    private static void secondFactor(MockHttpSession session, Instant at) {
        var context = (SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT");
        var previous = context.getAuthentication();
        var factors = new ArrayList<GrantedAuthority>();
        for (var authority : previous.getAuthorities()) {
            factors.add(authority instanceof FactorGrantedAuthority factor
                ? FactorGrantedAuthority.withAuthority(factor.getAuthority()).issuedAt(at).build() : authority);
        }
        factors.add(FactorGrantedAuthority.withAuthority("FACTOR_WEBAUTHN").issuedAt(at).build());
        context.setAuthentication(UsernamePasswordAuthenticationToken.authenticated(previous.getPrincipal(), null, factors));
    }
    private String location(MockHttpSession session, String url) throws Exception {
        var request = get(URI.create(url)).with(https()).accept(MediaType.TEXT_HTML);
        if (session != null) request.session(session);
        return mvc.perform(request).andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
    }
    private static Map<String, String> query(String location) {
        return UriComponentsBuilder.fromUriString(location).build().getQueryParams().toSingleValueMap();
    }
    private static RequestPostProcessor https() {
        return request -> { request.setScheme("https"); request.setSecure(true); request.setServerPort(443); return request; };
    }
}
