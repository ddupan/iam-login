package top.ddupan.iam.login.authentication.infrastructure.webauthn;

import com.zaxxer.hikari.HikariDataSource;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;
import javax.sql.DataSource;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.opaqueToken;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;
import top.ddupan.iam.login.authentication.infrastructure.persistence.JdbcCredentialRegistration;
import top.ddupan.iam.login.authorization.application.port.HydraGateway;
import top.ddupan.iam.login.authorization.domain.AuthorizationRequest;
import top.ddupan.iam.login.authorization.interfaces.web.HydraBrowserRequests;
import top.ddupan.iam.login.clients.domain.ClientRepository;
import top.ddupan.iam.login.support.AdDirectoryFixture;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {"iam.ad.enabled=true", "iam.ad.domain=example.test", "iam.ad.base-dn=dc=example,dc=test",
    "spring.datasource.hikari.maximum-pool-size=3", "iam.clients.admin-group-dns[0]=CN=gitea-admins,dc=example,dc=test", "iam.clients.admin-ui-client-id=iam-admin-ui", "iam.hydra.enabled=true", "iam.hydra.admin-url=http://127.0.0.1:14445", "iam.hydra.public-url=http://localhost:14444",
    "iam.hydra.clients[0]=gitea-fixture", "iam.hydra.subjects[0].authority=example.test",
    "iam.hydra.subjects[0].directory-id=00112233-4455-6677-8899-aabbccddeeff",
    "iam.hydra.subjects[0].subject=human:existing-subject",
    "iam.webauthn.enabled=true", "iam.webauthn.rp-id=localhost", "iam.webauthn.origin=https://localhost",
    "management.otlp.metrics.export.enabled=false", "spring.security.user.password=fixture-monitor-password"})
@AutoConfigureMockMvc
class WebAuthnIntegrationTests {
    static class Fixtures {
        static final AdDirectoryFixture DIRECTORY = new AdDirectoryFixture();
        static final PostgreSQLContainer DATABASE = new PostgreSQLContainer(DockerImageName.parse(
            "postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873")
            .asCompatibleSubstituteFor("postgres"));
        static { DATABASE.start(); }
    }
    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) {
        r.add("iam.ad.url", () -> Fixtures.DIRECTORY.url());
        r.add("spring.datasource.url", () -> Fixtures.DATABASE.getJdbcUrl());
        r.add("spring.datasource.username", () -> Fixtures.DATABASE.getUsername());
        r.add("spring.datasource.password", () -> Fixtures.DATABASE.getPassword());
    }
    @AfterAll static void close() { Fixtures.DIRECTORY.close(); Fixtures.DATABASE.stop(); }
    @Autowired MockMvc mvc;
    @Autowired JdbcOperations jdbc;
    @MockitoBean
    HydraGateway hydra;


    @MockitoBean
    ClientRepository clients;

    @Autowired PlatformTransactionManager transactionManager;
    @Autowired DataSource dataSource;

    @Test void registrationLockSerializesAndRollsBackOnFailure() throws Exception {
        assertThat(((HikariDataSource)dataSource).getMaximumPoolSize()).isEqualTo(3);
        var registrations = new JdbcCredentialRegistration(
            jdbc, new TransactionTemplate(transactionManager));
        String id = UUID.randomUUID().toString();
        jdbc.update("insert into user_entities(id,name,display_name) values (?,?,?)", id,id,"before");
        var locked = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var started = new CountDownLatch(1);
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            var first = executor.submit(() -> registrations.register(id, () -> {
                jdbc.update("update user_entities set display_name='committed' where id=?",id);
                locked.countDown();
                try {
                    if (!release.await(5,TimeUnit.SECONDS)) throw new IllegalStateException("Test timed out");
                } catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
                return true;
            }));
            try {
                assertThat(locked.await(5,TimeUnit.SECONDS)).isTrue();
                var second = executor.submit(() -> {
                    started.countDown();
                    return registrations.register(id, () -> jdbc.queryForObject(
                        "select display_name from user_entities where id=?",String.class,id));
                });
                assertThat(started.await(5,TimeUnit.SECONDS)).isTrue();
                assertThatThrownBy(() -> second.get(200,TimeUnit.MILLISECONDS))
                    .isInstanceOf(TimeoutException.class);
                release.countDown();
                assertThat(first.get(5,TimeUnit.SECONDS)).isTrue();
                assertThat(second.get(5,TimeUnit.SECONDS)).isEqualTo("committed");
            } finally { release.countDown(); }
        }
        assertThatThrownBy(() -> registrations.register(id, () -> {
            jdbc.update("update user_entities set display_name='rolled back' where id=?",id);
            throw new IllegalStateException("Registration rejected");
        })).isInstanceOf(IllegalStateException.class);
        assertThat(jdbc.queryForObject("select display_name from user_entities where id=?",String.class,id))
            .isEqualTo("committed");
        jdbc.update("delete from user_entities where id=?",id);
    }

    @Test
    void clientApiAcceptsOnlyBearerTokensCarryingTheManagementScope() throws Exception {
        mvc.perform(get("/api/iam/clients").with(https())).andExpect(status().isUnauthorized());
        // A fully authenticated administrator's browser session is not an API credential.
        var session=login(); secondFactor(session);
        mvc.perform(get("/api/iam/clients").session(session).with(https())).andExpect(status().isUnauthorized());
        var ordinary=opaqueToken().authorities(new SimpleGrantedAuthority("SCOPE_openid"));
        mvc.perform(get("/api/iam/clients").with(https()).with(ordinary)).andExpect(status().isForbidden());
        var manage=opaqueToken().authorities(new SimpleGrantedAuthority("SCOPE_iam.clients.manage"));
        Mockito.when(clients.list(0,20)).thenReturn(List.of());
        mvc.perform(get("/api/iam/clients").with(https()).with(manage)).andExpect(status().isOk());
        // Bearer requests carry no ambient cookie credential, so no CSRF token is involved.
        mvc.perform(delete("/api/iam/clients/example").with(https()).with(manage)).andExpect(status().isNoContent());
        Mockito.verify(clients).delete("example");
        Mockito.when(clients.rotateSecret("example")).thenReturn("fixture-rotated-secret");
        mvc.perform(post("/api/iam/clients/example/secret").with(https()).with(manage)).andExpect(status().isOk())
            .andExpect(header().string("Cache-Control","no-store")).andExpect(jsonPath("secret").value("fixture-rotated-secret"));
        mvc.perform(get("/api/iam/session").with(https()).with(manage)).andExpect(status().isNotFound());
        mvc.perform(post("/api/iam/clients").with(https()).with(manage).contentType("application/json").content("""
            {"id":"no-policy","name":"No policy","redirectUris":["https://app.example.test/cb"],"scopes":["openid"]}
            """)).andExpect(status().isBadRequest());
        Mockito.verify(clients,Mockito.never()).create(ArgumentMatchers.any());
    }

    @Test
    void consolePageIsAPublicShellThatMayOnlyFetchFromTheIssuer() throws Exception {
        mvc.perform(get("/console").with(https())).andExpect(status().isOk())
            .andExpect(header().string("Content-Security-Policy",Matchers.containsString("connect-src 'self' http://localhost:14444;")))
            .andExpect(content().string(Matchers.containsString("\"clientId\":\"iam-admin-ui\"")));
        mvc.perform(get("/console/clients").with(https())).andExpect(status().isUnauthorized());
    }

    @Test
    void logoutRequiresCsrfBrowserBindingAndInvalidatesLocalSession() throws Exception {
        var session=login(); secondFactor(session);
        var data=new HydraGateway.LogoutRequest(
            "logout-challenge","human:existing-subject","sid","");
        Mockito.when(hydra.logout("logout-challenge")).thenReturn(data);
        Mockito.when(hydra.logoutUrl()).thenReturn("http://localhost:14444/oauth2/sessions/logout");
        Mockito.when(hydra.acceptLogout("logout-challenge")).thenReturn("http://localhost:14444/oauth2/sessions/logout?logout_verifier=fixture");
        var html=mvc.perform(get("/oauth2/logout").session(session).with(https()).param("logout_challenge","logout-challenge"))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        var match=Pattern.compile("\"binding\":\"([^\"]+)\"").matcher(html);
        assertThat(match.find()).isTrue(); var binding=match.group(1);
        mvc.perform(post("/oauth2/logout").session(session).with(https()).param("binding",binding)).andExpect(status().isForbidden());
        mvc.perform(post("/oauth2/logout").session(session).with(https()).with(csrf()).param("binding","other"))
            .andExpect(status().isBadRequest());
        mvc.perform(post("/oauth2/logout").session(session).with(https()).with(csrf()).param("binding",binding))
            .andExpect(status().isSeeOther());
        assertThat(session.isInvalid()).isTrue();
        Mockito.verify(hydra).acceptLogout("logout-challenge");
    }

    @Test
    void passwordOnlyCanEnrollButCannotCompleteOrDelete() throws Exception {
        var session = login();
        mvc.perform(post("/webauthn/register/options").session(session).with(https()))
            .andExpect(status().isForbidden());
        mvc.perform(post("/webauthn/register/options").session(session).with(https()).with(csrf()))
            .andExpect(status().isOk()).andExpect(jsonPath("rp.id").value("localhost"))
            .andExpect(jsonPath("authenticatorSelection.userVerification").value("required"));
        assertThat(jdbc.queryForObject("select count(*) from user_entities", Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("select count(*) from user_credentials", Integer.class)).isZero();
        mvc.perform(get("/signin/complete").session(session).with(https()))
            .andExpect(redirectedUrlPattern("/signin/mfa?*"));
        mvc.perform(delete("/webauthn/register/unused").session(session).with(https()).with(csrf()))
            .andExpect(status().isForbidden());
    }

    @Test
    void optionsRequireFreshPasswordEvenThoughFrameworkProcessesThemBeforeAuthorization() throws Exception {
        mvc.perform(post("/webauthn/authenticate/options").with(https()).with(csrf()))
            .andExpect(status().isUnauthorized());
        var session = login();
        var context = (SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT");
        var auth = context.getAuthentication();
        context.setAuthentication(UsernamePasswordAuthenticationToken.authenticated(auth.getPrincipal(), null,
            List.of(FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
                .issuedAt(Instant.now().minusSeconds(601)).build())));
        mvc.perform(post("/webauthn/register/options").session(session).with(https()).with(csrf()))
            .andExpect(status().is3xxRedirection());
    }

    private static final String AUTH_URL = "http://localhost:14444/oauth2/auth?client_id=gitea-fixture&response_type=code";
    private AuthorizationRequest hydraRequest(String challenge, String subject,
            String login, String binding) {
        return new AuthorizationRequest(challenge, "gitea-fixture",
            List.of("openid", "profile", "groups"), List.of(), subject,
            login == null ? null : AuthorizationRequest.digest(login), binding, AUTH_URL, false);
    }
    private void secondFactor(MockHttpSession session) {
        var context = (SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT");
        var previous = context.getAuthentication();
        var factors = new ArrayList<GrantedAuthority>(previous.getAuthorities());
        factors.add(FactorGrantedAuthority.withAuthority("FACTOR_WEBAUTHN").issuedAt(Instant.now()).build());
        context.setAuthentication(UsernamePasswordAuthenticationToken.authenticated(previous.getPrincipal(), null, factors));
    }

    @Test
    void hydraRequiresMfaCsrfBrowserBindingAndConsumesBothChallengesOnce() throws Exception {
        Mockito.when(hydra.login("login-challenge")).thenReturn(hydraRequest("login-challenge", "", null, null));
        var session = login();
        mvc.perform(get("/oauth2/start").with(https()).session(session).param("login_challenge", "login-challenge"))
            .andExpect(redirectedUrl("/oauth2/login"));
        var intent = HydraBrowserRequests.intent(
            new MockHttpServletRequest() {{ setSession(session); }});
        mvc.perform(post("/oauth2/login").with(https()).session(session).with(csrf()).param("binding", intent.binding()))
            .andExpect(status().is3xxRedirection());
        Mockito.verify(hydra, Mockito.never()).acceptLogin(ArgumentMatchers.anyString(),
            ArgumentMatchers.anyString(), ArgumentMatchers.anyString(), ArgumentMatchers.any());
        secondFactor(session);
        mvc.perform(post("/oauth2/login").with(https()).session(session).param("binding", intent.binding()))
            .andExpect(status().isForbidden());
        mvc.perform(post("/oauth2/login").with(https()).session(session).with(csrf()).param("binding", "other-browser"))
            .andExpect(status().isBadRequest());
        Mockito.when(hydra.acceptLogin(ArgumentMatchers.eq("login-challenge"),
            ArgumentMatchers.eq("human:existing-subject"), ArgumentMatchers.eq(intent.binding()),
            ArgumentMatchers.any())).thenReturn("http://localhost:14444/oauth2/auth?login_verifier=fixture");
        mvc.perform(post("/oauth2/login").with(https()).session(session).with(csrf()).param("binding", intent.binding()))
            .andExpect(status().isSeeOther());
        mvc.perform(post("/oauth2/login").with(https()).session(session).with(csrf()).param("binding", intent.binding()))
            .andExpect(status().isBadRequest());
        Mockito.when(hydra.consent("consent-challenge")).thenReturn(
            hydraRequest("consent-challenge", "human:existing-subject", "login-challenge", intent.binding()));
        Mockito.when(hydra.acceptConsent(ArgumentMatchers.eq("consent-challenge"),
            ArgumentMatchers.anyList(), ArgumentMatchers.anyMap()))
            .thenReturn("http://localhost:14444/oauth2/auth?consent_verifier=fixture");
        mvc.perform(get("/oauth2/consent").with(https()).session(session).param("consent_challenge", "consent-challenge"))
            .andExpect(status().isSeeOther());
        mvc.perform(get("/oauth2/consent").with(https()).session(session).param("consent_challenge", "consent-challenge"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void consentCannotStartInAnotherBrowserEvenAfterMfa() throws Exception {
        var session = login(); secondFactor(session);
        mvc.perform(get("/oauth2/consent").with(https()).session(session).param("consent_challenge", "stolen-challenge"))
            .andExpect(status().isBadRequest());
        Mockito.verifyNoInteractions(hydra);
    }

    private MockHttpSession login() throws Exception {
        var session = new MockHttpSession();
        mvc.perform(post("/signin/password").session(session).with(https()).with(csrf())
            .param("username", "alice").param("password", "fixture-password"))
            .andExpect(redirectedUrl("/signin/mfa"));
        return session;
    }
    private static RequestPostProcessor https() {
        return request -> { request.setScheme("https"); request.setSecure(true); request.setServerPort(443); return request; };
    }
}
