package top.ddupan.iam.login.authentication.interfaces.web;

import top.ddupan.iam.login.support.AdDirectoryFixture;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.context.annotation.ImportRuntimeHints;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import java.time.Instant;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Real LDAPS sockets and Spring Data LDAP; AD bind/subcode semantics are simulated. */
@SpringBootTest(properties = {"iam.ad.enabled=true", "iam.ad.domain=example.test", "iam.ad.base-dn=dc=example,dc=test",
    "management.otlp.metrics.export.enabled=false", "spring.security.user.name=fixture-monitor", "spring.security.user.password=fixture-monitor-password"})
@AutoConfigureMockMvc
@org.springframework.boot.micrometer.metrics.test.autoconfigure.AutoConfigureMetrics
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
        registry.add("iam.ad.url", () -> Directory.INSTANCE.url());
    }

    @AfterAll
    static void close() { Directory.INSTANCE.close(); }

    @Autowired MockMvc mvc;

    @Test
    void browserRequiresHttpsCsrfAndOrderedSteps() throws Exception {
        mvc.perform(get("/signin")).andExpect(status().isUpgradeRequired());
        mvc.perform(get("/signin/mfa").secure(true)).andExpect(redirectedUrl("/signin"));
        mvc.perform(post("/signin/password").secure(true).param("username", "alice")
            .param("password", "fixture-password")).andExpect(status().isForbidden());
    }

    @Test
    void successfulPasswordRotatesSessionAndStopsBeforeMfa() throws Exception {
        var session = new MockHttpSession();
        mvc.perform(get("/signin").secure(true).session(session)).andExpect(status().isOk());
        String oldId = session.getId();
        mvc.perform(post("/signin/password").secure(true).session(session).with(csrf())
            .param("username", "alice").param("password", "fixture-password"))
            .andExpect(redirectedUrl("/signin/mfa"));
        assertThat(session.getId()).isNotEqualTo(oldId);
        var html = mvc.perform(get("/signin/mfa").secure(true).session(session))
            .andExpect(status().isOk()).andExpect(header().string("Cache-Control", "no-store"))
            .andReturn().getResponse().getContentAsString();
        assertThat(html).contains("mfa-pending", "gitea-admins", "\\u003c/script\\u003e")
            .doesNotContain("fixture-password", "</script><script>attack()");
        var authentication = ((SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT")).getAuthentication();
        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(authentication.getCredentials()).isNull();
        assertThat(authentication.getAuthorities()).extracting("authority").containsExactly("FACTOR_PASSWORD");
        mvc.perform(get("/").secure(true).session(session).accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isForbidden());

    }

    @Test
    void failedPasswordDoesNotRetainIdentityAndRestartInvalidatesSession() throws Exception {
        var session = new MockHttpSession();
        mvc.perform(get("/signin").secure(true).session(session));
        mvc.perform(post("/signin/password").secure(true).session(session).with(csrf())
            .param("username", "alice").param("password", "wrong"))
            .andExpect(redirectedUrl("/signin?error"));
        assertThat(session.getAttribute("SPRING_SECURITY_CONTEXT")).isNull();
        mvc.perform(get("/signin").secure(true).param("error", "").session(session))
            .andExpect(content().string(org.hamcrest.Matchers.containsString("无法验证账号")));
        mvc.perform(post("/signin/restart").secure(true).session(session).with(csrf()))
            .andExpect(redirectedUrl("/signin"));
        assertThat(session.isInvalid()).isTrue();
    }
    @Test
    void plaintextPasswordPostCannotReachDirectory() throws Exception {
        int before = Directory.INSTANCE.binds.get();
        mvc.perform(post("/signin/password").with(csrf()).param("username", "alice")
            .param("password", "fixture-password")).andExpect(status().isUpgradeRequired());
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
        mvc.perform(get("/signin/mfa").secure(true).session(session))
            .andExpect(status().is3xxRedirection());
    }

    @Test
    void directorySessionCannotScrapeManagementAndLogoutClearsAuthentication() throws Exception {
        var session = login();
        mvc.perform(get("/actuator/prometheus").secure(true).session(session))
            .andExpect(status().isUnauthorized());
        mvc.perform(post("/signin/restart").session(session).with(csrf()))
            .andExpect(status().isUpgradeRequired());
        assertThat(session.isInvalid()).isFalse();
        mvc.perform(post("/signin/restart").secure(true).session(session))
            .andExpect(status().isForbidden());
        mvc.perform(post("/signin/restart").secure(true).session(session).with(csrf()))
            .andExpect(redirectedUrl("/signin"));
        assertThat(session.isInvalid()).isTrue();
        mvc.perform(get("/signin/mfa").secure(true)).andExpect(status().is3xxRedirection());
    }

    @Test
    void managementBasicCredentialsCannotAuthenticateBrowserLogin() throws Exception {
        mvc.perform(get("/actuator/prometheus").secure(true).with(
            org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors
                .httpBasic("fixture-monitor", "fixture-monitor-password")))
            .andExpect(status().isOk());
        mvc.perform(get("/signin/mfa").secure(true).with(
            org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors
                .httpBasic("fixture-monitor", "fixture-monitor-password")))
            .andExpect(status().is3xxRedirection());
    }

    private MockHttpSession login() throws Exception {
        var session = new MockHttpSession();
        mvc.perform(post("/signin/password").secure(true).session(session).with(csrf())
            .param("username", "alice").param("password", "fixture-password"))
            .andExpect(redirectedUrl("/signin/mfa"));
        return session;
    }

}
