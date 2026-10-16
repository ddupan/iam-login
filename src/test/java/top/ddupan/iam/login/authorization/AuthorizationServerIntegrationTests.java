package top.ddupan.iam.login.authorization;

import com.nimbusds.jose.jwk.RSAKey;
import java.net.URI;
import java.net.URLDecoder;
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
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import java.util.UUID;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.hamcrest.Matchers;
import org.jooq.DSLContext;
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
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.util.UriComponentsBuilder;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;
import org.yaml.snakeyaml.Yaml;
import tools.jackson.databind.json.JsonMapper;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authorization.infrastructure.persistence.Subjects;
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
import static top.ddupan.iam.login.persistence.schema.Tables.SPRING_SESSION;
import static top.ddupan.iam.login.persistence.schema.Tables.SUBJECTS;
import static top.ddupan.iam.login.persistence.schema.Tables.TOTP_CREDENTIALS;

/** Spike: the in-process authorization server against simulated AD and a disposable database. */
// Container sessions: MockMvc hands sessions over as MockHttpSession, which Spring Session's cookie-based
// filter would ignore. What the database store must hold is checked by SessionRoundTrip.
@SpringBootTest(properties = {"spring.autoconfigure.exclude=org.springframework.boot.session.jdbc.autoconfigure.JdbcSessionAutoConfiguration", "iam.ad.enabled=true", "iam.ad.domain=example.test", "spring.ldap.base=dc=example,dc=test",
    "spring.datasource.hikari.maximum-pool-size=3",
    "iam.webauthn.enabled=true", "iam.webauthn.rp-id=localhost", "iam.webauthn.origin=https://localhost", "iam.totp.key=Zml4dHVyZS1vbmx5LXRvdHAta2V5LTMyLWJ5dGVzISE=",
    "iam.authorization-server.enabled=true", "iam.authorization-server.issuer=https://localhost",
    "management.otlp.metrics.export.enabled=false", "spring.security.user.password=fixture-monitor-password",
    "iam.clients.admin-groups[0]=gitea-admins",
    "iam.clients.spiffe.issuer=" + SpiffeFixture.ISSUER, "iam.clients.spiffe.admin-ids[0]=spiffe://example.test/ci/terraform"})
@AutoConfigureMockMvc
class AuthorizationServerIntegrationTests {
    static class Fixtures {
        static final AdDirectoryFixture DIRECTORY = new AdDirectoryFixture();
        static final PostgreSQLContainer DATABASE = new PostgreSQLContainer(DockerImageName.parse(
            "postgres:18.6")
            .asCompatibleSubstituteFor("postgres"));
        static { DATABASE.start(); }
        static final Path ACTIVE_KEY = SigningKeyFixture.write();
        static final Path PREVIOUS_KEY = SigningKeyFixture.write();
        static final SpiffeFixture SPIRE = new SpiffeFixture();
    }
    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) {
        r.add("spring.ldap.urls", () -> Fixtures.DIRECTORY.url());
        r.add("spring.ldap.username", () -> AdDirectoryFixture.SERVICE_USER);
        r.add("spring.ldap.password", () -> AdDirectoryFixture.SERVICE_PASSWORD);
        r.add("spring.datasource.url", () -> Fixtures.DATABASE.getJdbcUrl());
        r.add("spring.datasource.username", () -> Fixtures.DATABASE.getUsername());
        r.add("spring.datasource.password", () -> Fixtures.DATABASE.getPassword());
        r.add("iam.authorization-server.signing-keys[0]", () -> "file:" + Fixtures.ACTIVE_KEY);
        r.add("iam.authorization-server.signing-keys[1]", () -> "file:" + Fixtures.PREVIOUS_KEY);
        r.add("iam.clients.spiffe.jwk-set-uri", () -> Fixtures.SPIRE.jwkSetUri());
        // One property source for the whole list entry: Boot does not merge an indexed list across sources.
        r.add("iam.spiffe.trust-domains[0].name", () -> "example.test");
        r.add("iam.spiffe.trust-domains[0].bundle-endpoint", () -> Fixtures.SPIRE.bundleEndpoint());
    }
    @AfterAll static void close() { Fixtures.DIRECTORY.close(); Fixtures.DATABASE.stop(); Fixtures.SPIRE.close(); }

    private static final String CALLBACK = "https://rp.example/cb";
    @Autowired MockMvc mvc;
    @Autowired RegisteredClientRepository clients;
    @Autowired DSLContext db;
    @Autowired Subjects subjects;

    @BeforeEach void client() {
        // alice's subject was carried over from the previous issuer, as the migration inserts it.
        db.insertInto(SUBJECTS).set(SUBJECTS.SUBJECT, "human:existing-subject").set(SUBJECTS.AUTHORITY, "example.test")
            .set(SUBJECTS.DIRECTORY_ID, "00112233-4455-6677-8899-aabbccddeeff").onConflictDoNothing().execute();
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

    // Our consent page replaces the framework's: it needs the full MFA, its CSP lets the decision redirect to the
    // client's callback origin, "allow" with only openid issues a code, and "deny" answers access_denied.
    @Test void consentPageShowsTheRequestAndHandsTheDecisionBackToTheFramework() throws Exception {
        if (clients.findByClientId("consent-rp") == null) {
            clients.save(RegisteredClient.withId(UUID.randomUUID().toString()).clientId("consent-rp").clientName("Consent RP")
                .clientSecret("{noop}consent-secret").clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("https://consent.example/cb")
                .scope("openid").scope("groups")
                .clientSettings(ClientSettings.builder().requireProofKey(false).requireAuthorizationConsent(true).build()).build());
        }
        var request = UriComponentsBuilder.fromPath("/oauth2/authorize").queryParam("response_type", "code")
            .queryParam("client_id", "consent-rp").queryParam("redirect_uri", "https://consent.example/cb")
            .queryParam("scope", "openid groups").queryParam("state", "rp-state").encode().build().toUriString();
        // Deny first: an allow is remembered, and the next request skips the page.
        for (var decision : List.of("deny", "allow")) {
            var session = login(); secondFactor(session);
            var consentPage = location(session, request);
            assertThat(URI.create(consentPage).getPath()).isEqualTo("/signin/consent");
            var page = mvc.perform(get(URI.create(consentPage)).with(https()).session(session)).andExpect(status().isOk())
                .andExpect(header().string("Content-Security-Policy", Matchers.containsString("form-action 'self' https://consent.example")))
                .andReturn().getResponse().getContentAsString();
            assertThat(page).contains("\"clientName\":\"Consent RP\"", "\"scopes\":[\"openid\",\"groups\"]");
            var post = post("/oauth2/authorize").with(https()).session(session)
                .param("client_id", "consent-rp")
                // query() keeps values URL-encoded; the browser's form gets the decoded state.
                .param("state", URLDecoder.decode(query(consentPage).get("state"), StandardCharsets.UTF_8));
            if (decision.equals("allow")) post = post.param("scope", "openid").param("scope", "groups");
            var redirect = mvc.perform(post).andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
            assertThat(redirect).startsWith("https://consent.example/cb");
            if (decision.equals("allow")) assertThat(query(redirect)).containsKey("code").containsEntry("state", "rp-state");
            else assertThat(query(redirect)).containsEntry("error", "access_denied").doesNotContainKey("code");
        }
        // Without the full MFA the page is not served.
        mvc.perform(get("/signin/consent").with(https()).session(login())
                .param("client_id", "consent-rp").param("state", "x").param("scope", "openid"))
            .andExpect(status().is3xxRedirection());
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
        // UserInfo releases the same scope claims (OIDC Core 5.4), groups included; email was not requested.
        var userInfo = json(mvc.perform(get("/userinfo").with(https()).header("Authorization", "Bearer " + tokens.get("access_token")))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertThat(userInfo).containsEntry("sub", "human:existing-subject").containsEntry("preferred_username", "alice")
            .doesNotContainKey("email");
        assertThat(userInfo.get("groups")).asInstanceOf(InstanceOfAssertFactories.LIST).contains("gitea-admins");
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

    @Test void accountsWithoutASubjectAreIssuedOneThatNeverChanges() {
        var account = new User.UserId("local", UUID.randomUUID().toString());
        assertThat(subjects.find(account)).isEmpty();
        var issued = subjects.issue(account);
        assertThat(UUID.fromString(issued)).hasToString(issued);
        assertThat(subjects.issue(account)).isEqualTo(issued);
        assertThat(subjects.issue(new User.UserId("local", UUID.randomUUID().toString()))).isNotEqualTo(issued);
        assertThat(subjects.issue(new User.UserId("example.test", "00112233-4455-6677-8899-aabbccddeeff")))
            .as("carried over").isEqualTo("human:existing-subject");
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

    @Test void administratorsResetAnAccountsSecondFactorsAndEndItsSessions() throws Exception {
        var owner = "example.test:00000000-0000-0000-0000-000000000000";   // bob
        db.insertInto(TOTP_CREDENTIALS).set(TOTP_CREDENTIALS.OWNER, owner).set(TOTP_CREDENTIALS.SECRET, new byte[]{1})
            .set(TOTP_CREDENTIALS.LAST_STEP, 0L).onConflictDoNothing().execute();
        db.insertInto(SPRING_SESSION).set(SPRING_SESSION.PRIMARY_ID, UUID.randomUUID().toString())
            .set(SPRING_SESSION.SESSION_ID, UUID.randomUUID().toString()).set(SPRING_SESSION.CREATION_TIME, 0L)
            .set(SPRING_SESSION.LAST_ACCESS_TIME, 0L).set(SPRING_SESSION.MAX_INACTIVE_INTERVAL, 1800)
            .set(SPRING_SESSION.EXPIRY_TIME, Long.MAX_VALUE).set(SPRING_SESSION.PRINCIPAL_NAME, owner).execute();
        var admin = token(List.of("iam-login"), List.of("gitea-admins"));

        mvc.perform(get("/api/iam/users/bob").with(https()).with(token(List.of("iam-login"), List.of("staff"))))
            .andExpect(status().isForbidden());
        mvc.perform(get("/api/iam/users/bob").with(https()).with(admin)).andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value("bob")).andExpect(jsonPath("$.passkeys").isEmpty())
            .andExpect(jsonPath("$.authenticator.created").isNotEmpty());
        // Disabled, unknown, and a filter rather than a name.
        for (var name : List.of("carol", "nobody", "*")) {
            mvc.perform(get("/api/iam/users/{name}", name).with(https()).with(admin)).andExpect(status().isNotFound());
        }

        mvc.perform(delete("/api/iam/users/bob/second-factors").with(https()).with(admin)).andExpect(status().isNoContent());
        assertThat(db.fetchCount(TOTP_CREDENTIALS, TOTP_CREDENTIALS.OWNER.eq(owner))).isZero();
        assertThat(db.fetchCount(SPRING_SESSION, SPRING_SESSION.PRINCIPAL_NAME.eq(owner))).isZero();
        mvc.perform(get("/api/iam/users/bob").with(https()).with(admin)).andExpect(jsonPath("$.authenticator").isEmpty());
        mvc.perform(delete("/api/iam/users/nobody/second-factors").with(https()).with(admin)).andExpect(status().isNotFound());
    }

    /** docs/openapi.yaml is hand-written: it must list exactly the management routes the code maps. */
    @Test void apiDefinitionListsExactlyTheMappedManagementRoutes(
            @Autowired @Qualifier("requestMappingHandlerMapping") RequestMappingHandlerMapping mappings) throws Exception {
        var mapped = new TreeSet<String>();
        mappings.getHandlerMethods().keySet().forEach(info -> info.getPatternValues().stream()
            .filter(path -> path.startsWith("/api/iam/"))
            .forEach(path -> info.getMethodsCondition().getMethods().forEach(method -> mapped.add(method + " " + path))));
        var defined = new TreeSet<String>();
        Map<String, Map<String, Object>> paths = new Yaml().<Map<String, Map<String, Map<String, Object>>>>load(
            Files.readString(Path.of("docs/openapi.yaml"))).get("paths");
        paths.forEach((path, operations) -> operations.keySet().stream().filter(key -> !key.equals("parameters"))
            .forEach(method -> defined.add(method.toUpperCase(Locale.ROOT) + " " + path)));
        assertThat(defined).isNotEmpty().isEqualTo(mapped);
    }

    /** draft-ietf-oauth-spiffe-client-auth-02: a machine authenticates with its JWT-SVID, no secret. */
    @Test void machinesAuthenticateWithAJwtSvidAtTheTokenEndpoint() throws Exception {
        var machine = "spiffe://example.test/ci/machine";
        if (clients.findByClientId(machine) == null) {
            clients.save(RegisteredClient.withId(UUID.randomUUID().toString()).clientId(machine)
                .clientAuthenticationMethod(new ClientAuthenticationMethod("spiffe_jwt"))
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope("machine.read").build());
        }
        var svid = Fixtures.SPIRE.svid(machine, List.of("https://localhost"), SpiffeFixture.ISSUER, Instant.now().plusSeconds(300));
        var tokens = json(mvc.perform(post("/oauth2/token").with(https()).param("grant_type", "client_credentials")
                .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe")
                .param("client_assertion", svid).param("scope", "machine.read"))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertThat(claims((String) tokens.get("access_token"))).containsEntry("sub", machine).containsEntry("scope", "machine.read");
        assertThat(tokens).doesNotContainKey("refresh_token");
        // An SVID for another audience (here: what the management API accepts directly) is not a client credential.
        mvc.perform(post("/oauth2/token").with(https()).param("grant_type", "client_credentials")
                .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe")
                .param("client_assertion", Fixtures.SPIRE.svid(machine)))
            .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error").value("invalid_client"));
        // Section 4: advertised in both metadata documents, for every endpoint that authenticates clients.
        for (var metadata : List.of("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration")) {
            mvc.perform(get(metadata).with(https())).andExpect(status().isOk())
                .andExpect(jsonPath("$.token_endpoint_auth_methods_supported", Matchers.hasItem("spiffe_jwt")))
                .andExpect(jsonPath("$.revocation_endpoint_auth_methods_supported", Matchers.hasItem("spiffe_jwt")))
                .andExpect(jsonPath("$.introspection_endpoint_auth_methods_supported", Matchers.hasItem("spiffe_jwt")));
        }
    }

    /** Machine clients: registered through their own API, then authenticated by any SVID their spiffeId covers. */
    @Test void machineClientsAreManagedThroughTheirOwnApi() throws Exception {
        var admin = token(List.of("iam-login"), List.of("gitea-admins"));
        var body = """
            {"id":"ci-publisher","name":"CI","spiffeId":"spiffe://example.test/ci/*","scopes":["artifacts.write"],
             "audiences":["artifact-keeper"],"enabled":true}
            """;
        mvc.perform(post("/api/iam/machine-clients").with(https()).with(admin).contentType(MediaType.APPLICATION_JSON).content(body))
            .andExpect(status().isCreated()).andExpect(jsonPath("spiffeId").value("spiffe://example.test/ci/*"));
        mvc.perform(post("/api/iam/machine-clients").with(https()).with(admin).contentType(MediaType.APPLICATION_JSON).content(body))
            .andExpect(status().isConflict());
        // A wildcard only on a whole segment; enabled is required, not defaulted.
        for (var invalid : List.of(body.replace("ci/*", "ci*"), body.replace(",\"enabled\":true", ""))) {
            mvc.perform(post("/api/iam/machine-clients").with(https()).with(admin).contentType(MediaType.APPLICATION_JSON)
                    .content(invalid.replace("ci-publisher", "invalid"))).andExpect(status().isBadRequest());
        }
        // Each API sees only its own kind.
        mvc.perform(get("/api/iam/machine-clients").with(https()).with(admin)).andExpect(status().isOk())
            .andExpect(jsonPath("$[?(@.id=='ci-publisher')]").exists()).andExpect(jsonPath("$[?(@.id=='spike-rp')]").doesNotExist());
        mvc.perform(get("/api/iam/clients").with(https()).with(admin)).andExpect(status().isOk())
            .andExpect(jsonPath("$[?(@.id=='ci-publisher')]").doesNotExist());
        mvc.perform(get("/api/iam/clients/ci-publisher").with(https()).with(admin)).andExpect(status().isConflict());
        mvc.perform(delete("/api/iam/machine-clients/iam-console").with(https()).with(admin)).andExpect(status().isConflict());

        var svid = Fixtures.SPIRE.svid("spiffe://example.test/ci/publisher", List.of("https://localhost"), SpiffeFixture.ISSUER,
            Instant.now().plusSeconds(300));
        var tokens = json(machineToken("ci-publisher", svid).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertThat(claims((String) tokens.get("access_token"))).containsEntry("sub", "ci-publisher")
            .containsEntry("scope", "artifacts.write").containsEntry("aud", List.of("ci-publisher", "artifact-keeper"));
        var outside = Fixtures.SPIRE.svid("spiffe://example.test/cicd", List.of("https://localhost"), SpiffeFixture.ISSUER,
            Instant.now().plusSeconds(300));
        machineToken("ci-publisher", outside).andExpect(status().isUnauthorized());

        // Disabled: no more tokens.
        mvc.perform(put("/api/iam/machine-clients/ci-publisher").with(https()).with(admin).contentType(MediaType.APPLICATION_JSON)
                .content(body.replace("\"enabled\":true", "\"enabled\":false"))).andExpect(status().isOk())
            .andExpect(jsonPath("enabled").value(false));
        machineToken("ci-publisher", svid).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error").value("invalid_client"));

        mvc.perform(delete("/api/iam/machine-clients/ci-publisher").with(https()).with(admin)).andExpect(status().isNoContent());
        mvc.perform(get("/api/iam/machine-clients/ci-publisher").with(https()).with(admin)).andExpect(status().isNotFound());
    }

    private ResultActions machineToken(String clientId, String svid) throws Exception {
        return mvc.perform(post("/oauth2/token").with(https()).param("grant_type", "client_credentials").param("client_id", clientId)
            .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe").param("client_assertion", svid)
            .param("scope", "artifacts.write"));
    }

    @Test void consoleIsAPublicClientWhoseTokensCarryTheApiAudience() throws Exception {
        var console = clients.findByClientId("iam-console");
        assertThat(console.getClientAuthenticationMethods()).containsExactly(ClientAuthenticationMethod.NONE);
        assertThat(console.getRedirectUris()).containsExactly("https://localhost/console/callback");
        assertThat(console.getPostLogoutRedirectUris()).containsExactly("https://localhost/signin");
        // Every console path is the page shell, so a reload or a shared link stays on its view.
        for (var path : List.of("/console", "/console/users", "/console/clients/spike-rp/edit")) {
            mvc.perform(get(path).with(https())).andExpect(status().isOk())
                .andExpect(content().string(Matchers.containsString("\"clientId\":\"iam-console\"")));
        }
        // The bare host name leads to the account page (which asks to sign in first).
        mvc.perform(get("/").with(https())).andExpect(status().isFound()).andExpect(redirectedUrl("/account"));
        // The real flow: password + passkey, PKCE, no secret, no consent page.
        var session = login(); secondFactor(session);
        var verifier = verifier();
        var challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        var authorize = UriComponentsBuilder.fromPath("/oauth2/authorize").queryParam("response_type", "code")
            .queryParam("client_id", "iam-console").queryParam("redirect_uri", "https://localhost/console/callback")
            .queryParam("scope", "openid profile groups").queryParam("state", "console-state")
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

    // A CLI or browser app: no secret, PKCE for the code, then refreshes with client_id alone. The framework
    // covers only the PKCE exchange; refresh tokens and client_id-only requests are PublicClients.
    @Test void publicClientsRefreshWithClientIdAloneAndRotate() throws Exception {
        var admin = token(List.of("iam-login"), List.of("gitea-admins"));
        var body = """
            {"id":"public-app","name":"Public","redirectUris":["http://127.0.0.1/cb"],"scopes":["openid","offline_access"],
             "postLogoutRedirectUris":[],"loginEnabled":true,"pkceRequired":true,"publicClient":true,
             "audiences":["https://resource.example"]}
            """;
        var created = json(mvc.perform(post("/api/iam/clients").with(https()).with(admin).contentType(MediaType.APPLICATION_JSON).content(body))
            .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString());
        assertThat(created.get("secret")).isNull();
        assertThat((Map<String, Object>) created.get("client")).containsEntry("publicClient", true)
            .containsEntry("audiences", List.of("https://resource.example"));
        mvc.perform(post("/api/iam/clients").with(https()).with(admin).contentType(MediaType.APPLICATION_JSON)
                .content(body.replace("public-app", "public-no-pkce").replace("\"pkceRequired\":true", "\"pkceRequired\":false")))
            .andExpect(status().isBadRequest());
        // A public client has no secret to rotate, and cannot be turned into a confidential one.
        mvc.perform(post("/api/iam/clients/public-app/secret").with(https()).with(admin)).andExpect(status().isConflict());
        mvc.perform(put("/api/iam/clients/public-app").with(https()).with(admin).contentType(MediaType.APPLICATION_JSON)
                .content(body.replace("\"publicClient\":true", "\"publicClient\":false"))).andExpect(status().isBadRequest());
        // Consent is the framework's page here; this test is about the token endpoint.
        clients.save(RegisteredClient.from(clients.findByClientId("public-app")).clientSettings(ClientSettings.withSettings(
            clients.findByClientId("public-app").getClientSettings().getSettings()).requireAuthorizationConsent(false).build()).build());

        var session = login(); secondFactor(session);
        var verifier = verifier();
        var challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        var callback = location(session, UriComponentsBuilder.fromPath("/oauth2/authorize").queryParam("response_type", "code")
            .queryParam("client_id", "public-app").queryParam("redirect_uri", "http://127.0.0.1/cb")
            .queryParam("scope", "openid offline_access").queryParam("state", "s")
            .queryParam("code_challenge", challenge).queryParam("code_challenge_method", "S256").encode().build().toUriString());
        var tokens = json(mvc.perform(post("/oauth2/token").with(https()).param("grant_type", "authorization_code")
                .param("client_id", "public-app").param("code", query(callback).get("code"))
                .param("redirect_uri", "http://127.0.0.1/cb").param("code_verifier", verifier))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertThat(claims((String) tokens.get("access_token")).get("aud")).asInstanceOf(InstanceOfAssertFactories.LIST)
            .contains("public-app", "https://resource.example");
        assertThat(claims((String) tokens.get("access_token")).get("scope")).as("RFC 9068: space-delimited string")
            .isInstanceOf(String.class);
        var refresh = (String) tokens.get("refresh_token");
        assertThat(refresh).as("refresh token for a public client").isNotNull();

        var refreshed = json(mvc.perform(post("/oauth2/token").with(https()).param("grant_type", "refresh_token")
                .param("client_id", "public-app").param("refresh_token", refresh))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertThat(refreshed.get("refresh_token")).isNotNull().isNotEqualTo(refresh);
        mvc.perform(post("/oauth2/token").with(https()).param("grant_type", "refresh_token")
                .param("client_id", "public-app").param("refresh_token", refresh))
            .andExpect(status().isBadRequest()).andExpect(jsonPath("error").value("invalid_grant"));
        // A confidential client is not let in for leaving out its secret.
        mvc.perform(post("/oauth2/token").with(https()).param("grant_type", "refresh_token")
                .param("client_id", "spike-rp").param("refresh_token", (String) refreshed.get("refresh_token")))
            .andExpect(status().isUnauthorized()).andExpect(jsonPath("error").value("invalid_client"));
        mvc.perform(get("/.well-known/openid-configuration").with(https()))
            .andExpect(jsonPath("token_endpoint_auth_methods_supported").value(Matchers.hasItem("none")));
    }

    // RFC 8628 with a public client (the Incus CLI): the user enters the code on our page after signing in,
    // consents, and the device polls the token endpoint with client_id alone.
    @Test void deviceGrantGoesThroughSignInAndConsent() throws Exception {
        var admin = token(List.of("iam-login"), List.of("gitea-admins"));
        mvc.perform(post("/api/iam/clients").with(https()).with(admin).contentType(MediaType.APPLICATION_JSON).content("""
                {"id":"device-app","name":"Device","redirectUris":["http://127.0.0.1/cb"],"scopes":["openid","offline_access"],
                 "postLogoutRedirectUris":[],"loginEnabled":true,"pkceRequired":true,"publicClient":true,"deviceAuthorization":true}
                """)).andExpect(status().isCreated());
        mvc.perform(get("/.well-known/openid-configuration").with(https()))
            .andExpect(jsonPath("device_authorization_endpoint").value("https://localhost/oauth2/device_authorization"));
        var device = json(mvc.perform(post("/oauth2/device_authorization").with(https())
                .param("client_id", "device-app").param("scope", "openid offline_access"))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        var userCode = (String) device.get("user_code");
        assertThat(device.get("verification_uri")).isEqualTo("https://localhost/signin/device");

        // Not signed in: sent to sign in, and brought back (with the code) by /signin/complete afterwards.
        var session = new MockHttpSession();
        mvc.perform(get("/signin/device").param("user_code", userCode).with(https()).session(session))
            .andExpect(status().isSeeOther()).andExpect(header().string("Location", "/signin"));
        assertThat(session.getAttribute("SPRING_SECURITY_SAVED_REQUEST")).isNotNull();
        password(session); secondFactor(session);
        mvc.perform(get("/signin/device").param("user_code", userCode).with(https()).session(session))
            .andExpect(status().isOk()).andExpect(content().string(Matchers.containsString("\"userCode\":\"" + userCode + "\"")));

        // The endpoint reads a GET's user_code from the query string, as a browser's form submission sends it.
        var consent = mvc.perform(get("/oauth2/device_verification?user_code=" + userCode).with(https()).session(session))
            .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
        assertThat(consent).contains("/signin/consent");
        var parameters = query(consent);
        mvc.perform(get(URI.create(consent)).with(https()).session(session)).andExpect(status().isOk())
            .andExpect(content().string(Matchers.containsString("\"action\":\"/oauth2/device_verification\"")));
        mvc.perform(post("/oauth2/device_verification").with(https()).session(session)
                .param("client_id", "device-app").param("state", URLDecoder.decode(parameters.get("state"), StandardCharsets.UTF_8))
                .param("user_code", userCode)
                .param("scope", "openid").param("scope", "offline_access"))
            .andExpect(redirectedUrl("/signin/device?result=done"));

        var tokens = json(mvc.perform(post("/oauth2/token").with(https())
                .param("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
                .param("device_code", (String) device.get("device_code")).param("client_id", "device-app"))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertThat(tokens).containsKeys("access_token", "refresh_token");

        mvc.perform(get("/oauth2/device_verification?user_code=BCDF-GHJK").with(https()).session(session))
            .andExpect(redirectedUrl("/signin/device?result=invalid"));
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
