package top.ddupan.iam.login.authentication.interfaces.web;

import java.time.Instant;
import java.util.List;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.micrometer.metrics.test.autoconfigure.AutoConfigureMetrics;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.ImportRuntimeHints;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import top.ddupan.iam.login.support.AdDirectoryFixture;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Real LDAPS sockets and Spring Data LDAP; AD bind/subcode semantics are simulated. */
@SpringBootTest(properties = {"spring.autoconfigure.exclude=org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration", "iam.ad.enabled=true", "iam.ad.domain=example.test", "spring.ldap.base=dc=example,dc=test",
    "management.otlp.metrics.export.enabled=false", "spring.security.user.name=fixture-monitor", "spring.security.user.password=fixture-monitor-password"})
@AutoConfigureMockMvc
@AutoConfigureMetrics
@ImportRuntimeHints(SignInIntegrationTests.FixtureHints.class)
class SignInIntegrationTests {
    static class FixtureHints implements RuntimeHintsRegistrar {
        @Override
        public void registerHints(RuntimeHints hints, ClassLoader loader) {
            hints.resources().registerPattern("ldap/fixture.p12");
        }
    }

    static class Directory {
        static final AdDirectoryFixture INSTANCE = new AdDirectoryFixture();
    }

    @DynamicPropertySource
    static void directory(DynamicPropertyRegistry registry) {
        registry.add("spring.ldap.urls", () -> Directory.INSTANCE.url());
    }

    @AfterAll
    static void close() { Directory.INSTANCE.close(); }

    @Autowired MockMvc mvc;

    @Test
    void browserRequiresHttpsCsrfAndOrderedSteps() throws Exception {
        mvc.perform(get("/signin")).andExpect(redirectedUrl("https://localhost/signin"));
        mvc.perform(get("/signin/mfa").with(https())).andExpect(redirectedUrl("/signin"));
        mvc.perform(post("/signin/password").with(https()).param("username", "alice")
            .param("password", "fixture-password")).andExpect(status().isForbidden());
    }

    @Test
    void successfulPasswordRotatesSessionAndStopsBeforeMfa() throws Exception {
        var session = new MockHttpSession();
        mvc.perform(get("/signin").with(https()).session(session)).andExpect(status().isOk());
        String oldId = session.getId();
        // A browser sends its session cookie; without a requested session ID MockMvc (spring-test 7.0.10+) reports
        // it invalid and Spring Security skips session fixation protection.
        mvc.perform(post("/signin/password").with(https()).session(session).with(csrf())
            .with(request -> { request.setRequestedSessionId(oldId); return request; })
            .param("username", "alice").param("password", "fixture-password"))
            .andExpect(redirectedUrl("/signin/mfa"));
        assertThat(session.getId()).isNotEqualTo(oldId);
        var html = mvc.perform(get("/signin/mfa").with(https()).session(session))
            .andExpect(status().isOk()).andExpect(header().string("Cache-Control", "no-store"))
            .andReturn().getResponse().getContentAsString();
        assertThat(html).contains("mfa-pending", "gitea-admins", "\\u003c/script\\u003e")
            .doesNotContain("fixture-password", "</script><script>attack()");
        var authentication = ((SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT")).getAuthentication();
        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(authentication.getCredentials()).isNull();
        assertThat(authentication.getAuthorities()).extracting("authority").containsExactly("FACTOR_PASSWORD");
        // Any other route stays closed to a session with only the password: nothing is served there.
        mvc.perform(get("/unmapped").with(https()).session(session).accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isNotFound());

    }

    @Test
    void failedPasswordDoesNotRetainIdentityAndRestartInvalidatesSession() throws Exception {
        var session = new MockHttpSession();
        mvc.perform(get("/signin").with(https()).session(session));
        mvc.perform(post("/signin/password").with(https()).session(session).with(csrf())
            .param("username", "alice").param("password", "wrong"))
            .andExpect(redirectedUrl("/signin?error"));
        assertThat(session.getAttribute("SPRING_SECURITY_CONTEXT")).isNull();
        mvc.perform(get("/signin").with(https()).param("error", "").session(session))
            .andExpect(content().string(Matchers.containsString("\"error\":\"invalid\"")));
        // A directory outage is the only failure told apart; account states stay the generic message.
        mvc.perform(get("/signin").with(https()).param("error", "unavailable").session(session))
            .andExpect(content().string(Matchers.containsString("\"error\":\"unavailable\"")));
        mvc.perform(post("/signin/restart").with(https()).session(session).with(csrf()))
            .andExpect(redirectedUrl("/signin"));
        assertThat(session.isInvalid()).isTrue();
    }
    @Test
    void identifierFirstGivesUnknownNamesThePasswordStepAndCountsThem() throws Exception {
        var session = new MockHttpSession();
        mvc.perform(get("/signin").with(https()).session(session))
            .andExpect(content().string(Matchers.containsString("\"step\":\"identify\"")));
        // Without passkeys (none in this context) an account signs in with its password.
        for (int i = 0; i < 6; i++) {
            mvc.perform(post("/signin/identify").with(https()).session(session).with(csrf()).param("username", "alice"))
                .andExpect(status().isSeeOther()).andExpect(redirectedUrl("/signin"));
        }
        mvc.perform(get("/signin").with(https()).session(session))
            .andExpect(content().string(Matchers.containsString("\"step\":\"password\"")))
            .andExpect(content().string(Matchers.containsString("\"name\":\"alice\"")));
        // An unknown name: the same step, but each look-up counts like a failed password.
        var unknown = new MockHttpSession();
        for (int i = 0; i < 5; i++) {
            mvc.perform(post("/signin/identify").with(https()).session(unknown).with(csrf()).param("username", "nobody"))
                .andExpect(redirectedUrl("/signin"));
        }
        mvc.perform(get("/signin").with(https()).session(unknown))
            .andExpect(content().string(Matchers.containsString("\"step\":\"password\"")));
        mvc.perform(post("/signin/identify").with(https()).session(unknown).with(csrf()).param("username", "nobody"))
            .andExpect(redirectedUrl("/signin?error=throttled"));
        mvc.perform(post("/signin/identify").with(https()).with(csrf()).param("username", "alice")).andExpect(redirectedUrl("/signin"));
        mvc.perform(post("/signin/identify").with(https()).param("username", "alice")).andExpect(status().isForbidden());
    }

    @Test
    void repeatedFailuresAreRejectedWithoutAskingTheDirectory() throws Exception {
        for (int i = 0; i < 5; i++) {
            mvc.perform(post("/signin/password").with(https()).with(csrf())
                .param("username", "guessed").param("password", "wrong-" + i))
                .andExpect(redirectedUrl("/signin?error"));
        }
        int before = Directory.INSTANCE.binds.get();
        mvc.perform(post("/signin/password").with(https()).with(csrf())
            .param("username", "Guessed@example.test").param("password", "wrong"))
            .andExpect(redirectedUrl("/signin?error=throttled"));
        assertThat(Directory.INSTANCE.binds.get()).isEqualTo(before);
        mvc.perform(get("/signin").with(https()).param("error", "throttled"))
            .andExpect(content().string(Matchers.containsString("\"error\":\"throttled\"")));
    }

    @Test
    void plaintextPasswordPostCannotReachDirectory() throws Exception {
        int before = Directory.INSTANCE.binds.get();
        mvc.perform(post("/signin/password").with(csrf()).param("username", "alice")
            .param("password", "fixture-password")).andExpect(redirectedUrl("https://localhost/signin/password"));
        assertThat(Directory.INSTANCE.binds.get()).isEqualTo(before);
    }

    @Test
    void expiredPasswordFactorCannotOpenPendingPage() throws Exception {
        var session = login();
        var context = (SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT");
        var previous = context.getAuthentication();
        context.setAuthentication(UsernamePasswordAuthenticationToken.authenticated(previous.getPrincipal(), null,
            List.of(FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
                .issuedAt(Instant.now().minusSeconds(601)).build())));
        mvc.perform(get("/signin/mfa").with(https()).session(session))
            .andExpect(status().is3xxRedirection());
    }

    @Test
    void directorySessionCannotScrapeManagementAndLogoutClearsAuthentication() throws Exception {
        var session = login();
        mvc.perform(get("/actuator/prometheus").with(https()).session(session))
            .andExpect(status().isUnauthorized());
        mvc.perform(post("/signin/restart").session(session).with(csrf()))
            .andExpect(redirectedUrl("https://localhost/signin/restart"));
        assertThat(session.isInvalid()).isFalse();
        mvc.perform(post("/signin/restart").with(https()).session(session))
            .andExpect(status().isForbidden());
        mvc.perform(post("/signin/restart").with(https()).session(session).with(csrf()))
            .andExpect(redirectedUrl("/signin"));
        assertThat(session.isInvalid()).isTrue();
        mvc.perform(get("/signin/mfa").with(https())).andExpect(status().is3xxRedirection());
    }

    @Test
    void managementBasicCredentialsCannotAuthenticateBrowserLogin() throws Exception {
        mvc.perform(get("/actuator/prometheus").with(https()).with(
            SecurityMockMvcRequestPostProcessors
                .httpBasic("fixture-monitor", "fixture-monitor-password")))
            .andExpect(status().isOk());
        mvc.perform(get("/signin/mfa").with(https()).with(
            SecurityMockMvcRequestPostProcessors
                .httpBasic("fixture-monitor", "fixture-monitor-password")))
            .andExpect(status().is3xxRedirection());
    }

    private static RequestPostProcessor https() {
        return request -> {
            request.setScheme("https");
            request.setSecure(true);
            request.setServerPort(443);
            return request;
        };
    }

    private MockHttpSession login() throws Exception {
        var session = new MockHttpSession();
        mvc.perform(post("/signin/password").with(https()).session(session).with(csrf())
            .param("username", "alice").param("password", "fixture-password"))
            .andExpect(redirectedUrl("/signin/mfa"));
        return session;
    }

}
