package top.ddupan.iam.login.ad;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSimpleBindRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import java.net.InetAddress;
import java.security.KeyStore;
import java.time.Instant;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.context.annotation.ImportRuntimeHints;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Real LDAPS sockets and Spring's AD provider; AD bind/subcode semantics are simulated. */
@SpringBootTest(properties = {"iam.ad.enabled=true", "iam.ad.domain=example.test", "iam.ad.base-dn=dc=example,dc=test"})
@AutoConfigureMockMvc
@ImportRuntimeHints(AdIntegrationTests.FixtureHints.class)
class AdIntegrationTests {
    static class FixtureHints implements RuntimeHintsRegistrar {
        @Override
        public void registerHints(RuntimeHints hints, ClassLoader loader) {
            hints.resources().registerPattern("ldap/fixture.p12");
        }
    }

    static final String BASE = "dc=example,dc=test";
    static final String USER_DN = "cn=Alice," + BASE;
    static final byte[] GUID = java.util.HexFormat.of().parseHex("33221100554477668899aabbccddeeff");
    static class Fixture {
    static final SSLContext ORIGINAL;
    static final InMemoryDirectoryServer LDAP;
    static {
        try {
            ORIGINAL = SSLContext.getDefault();
            var store = KeyStore.getInstance("PKCS12");
            try (var stream = AdIntegrationTests.class.getResourceAsStream("/ldap/fixture.p12")) {
                store.load(stream, "fixture-only".toCharArray());
            }
            var keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keys.init(store, "fixture-only".toCharArray());
            var trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trust.init(store);
            var ssl = SSLContext.getInstance("TLS");
            ssl.init(keys.getKeyManagers(), trust.getTrustManagers(), null);
            SSLContext.setDefault(ssl);
            var config = new InMemoryDirectoryServerConfig(BASE);
            config.setSchema(null);
            config.setListenerConfigs(InMemoryListenerConfig.createLDAPSConfig("ldaps",
                InetAddress.getByName("127.0.0.1"), 0, ssl.getServerSocketFactory(), ssl.getSocketFactory()));
            config.addInMemoryOperationInterceptor(new InMemoryOperationInterceptor() {
                @Override
                public void processSearchResult(InMemoryInterceptedSearchResult result) {
                    try {
                        // Like Samba AD's DomainDnsZones/ForestDnsZones continuation references.
                        // A client following this reference would fail instead of returning the user.
                        result.sendSearchReference(new SearchResultReference(
                            new String[]{"ldap://127.0.0.1:1/DC=other,DC=test"}, null));
                    } catch (LDAPException ex) { throw new IllegalStateException(ex); }
                }

                @Override
                public void processSimpleBindRequest(InMemoryInterceptedSimpleBindRequest request) throws LDAPException {
                    String name = request.getRequest().getBindDN();
                    String subcode = switch (name) {
                        case "disabled@example.test" -> "533";
                        case "locked@example.test" -> "775";
                        case "expired@example.test" -> "532";
                        default -> null;
                    };
                    if (subcode != null) throw new LDAPException(ResultCode.INVALID_CREDENTIALS,
                        "80090308: LdapErr: DSID-0C090334, comment: AcceptSecurityContext error, data " + subcode + ", v1db1");
                    if (name.equalsIgnoreCase("alice@example.test")) {
                        request.setRequest(new SimpleBindRequest(USER_DN, request.getRequest().getPassword().getValue()));
                    } else if (!name.equals(USER_DN)) {
                        throw new LDAPException(ResultCode.INVALID_CREDENTIALS, "Invalid credentials");
                    }
                }
            });
            LDAP = new InMemoryDirectoryServer(config);
            LDAP.startListening();
            LDAP.add(new Entry(BASE, new com.unboundid.ldap.sdk.Attribute("objectClass", "domain"),
                new com.unboundid.ldap.sdk.Attribute("dc", "example")));
            LDAP.add(new Entry(USER_DN,
                new com.unboundid.ldap.sdk.Attribute("objectClass", "user"),
                new com.unboundid.ldap.sdk.Attribute("cn", "Alice"),
                new com.unboundid.ldap.sdk.Attribute("sAMAccountName", "alice"),
                new com.unboundid.ldap.sdk.Attribute("userPrincipalName", "alice@example.test"),
                new com.unboundid.ldap.sdk.Attribute("userPassword", "fixture-password"),
                new com.unboundid.ldap.sdk.Attribute("displayName", "Alice </script><script>attack()</script>"),
                new com.unboundid.ldap.sdk.Attribute("mail", "alice@example.test"),
                new com.unboundid.ldap.sdk.Attribute("objectGUID", GUID),
                new com.unboundid.ldap.sdk.Attribute("memberOf", "CN=gitea-admins," + BASE, "CN=MixedCase," + BASE)));
        } catch (Exception ex) { throw new ExceptionInInitializerError(ex); }
    }

    }

    @DynamicPropertySource
    static void directory(DynamicPropertyRegistry registry) {
        registry.add("iam.ad.url", () -> "ldaps://localhost:" + Fixture.LDAP.getListenPort());
    }

    @AfterAll
    static void close() { Fixture.LDAP.shutDown(true); SSLContext.setDefault(Fixture.ORIGINAL); }

    @Autowired AdPasswordVerifier verifier;
    @Autowired MockMvc mvc;

    @Test
    void passwordReadsGuidAndExactGroupsOverTlsDespitePartitionReferrals() {
        var identity = verifier.verify("alice", "fixture-password");
        assertThat(identity.objectGuid()).isEqualTo("00112233-4455-6677-8899-aabbccddeeff");
        assertThat(identity.groups()).containsExactly("MixedCase", "gitea-admins");
        assertThat(identity.groupDns()).containsExactly("CN=MixedCase," + BASE, "CN=gitea-admins," + BASE);
        assertThat(verifier.verify("alice@example.test", "fixture-password")).isEqualTo(identity);
    }

    @Test
    void rejectsPasswordsUnknownUsersAndAdAccountStates() {
        assertThatThrownBy(() -> verifier.verify("alice", "wrong")).isInstanceOf(BadCredentialsException.class);
        assertThatThrownBy(() -> verifier.verify("alice", "")).isInstanceOf(BadCredentialsException.class);
        assertThatThrownBy(() -> verifier.verify("unknown", "fixture-password")).isInstanceOf(BadCredentialsException.class);
        assertThatThrownBy(() -> verifier.verify("alice@other.test", "fixture-password")).isInstanceOf(BadCredentialsException.class);
        assertThatThrownBy(() -> verifier.verify("disabled", "fixture-password")).isInstanceOf(DisabledException.class);
        assertThatThrownBy(() -> verifier.verify("locked", "fixture-password")).isInstanceOf(LockedException.class);
        assertThatThrownBy(() -> verifier.verify("expired", "fixture-password")).isInstanceOf(CredentialsExpiredException.class);
    }

    @Test
    void rejectsWrongTlsHostnameAndPlainLdapConfiguration() {
        var wrongName = new AdPasswordVerifier(new AdProperties(true,
            "ldaps://127.0.0.1:" + Fixture.LDAP.getListenPort(), "example.test", BASE));
        assertThatThrownBy(() -> wrongName.verify("alice", "fixture-password"))
            .hasStackTraceContaining("No subject alternative names matching IP address");
        assertThatThrownBy(() -> new AdPasswordVerifier(new AdProperties(true,
            "ldap://localhost:389", "example.test", BASE))).isInstanceOf(IllegalArgumentException.class);
    }

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
        assertThat(session.getAttribute("SPRING_SECURITY_CONTEXT")).isNull();
        mvc.perform(get("/").secure(true).session(session).accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isUnauthorized());
        var state = (AdLoginController.State) session.getAttribute(AdLoginController.STATE);
        state.expires = Instant.EPOCH;
        mvc.perform(get("/signin/mfa").secure(true).session(session)).andExpect(redirectedUrl("/signin"));
    }

    @Test
    void failedPasswordDoesNotRetainIdentityAndRestartInvalidatesSession() throws Exception {
        var session = new MockHttpSession();
        mvc.perform(get("/signin").secure(true).session(session));
        mvc.perform(post("/signin/password").secure(true).session(session).with(csrf())
            .param("username", "alice").param("password", "wrong"))
            .andExpect(redirectedUrl("/signin"));
        var state = (AdLoginController.State) session.getAttribute(AdLoginController.STATE);
        assertThat(state.identity).isNull();
        assertThat(state.error).isNotBlank().doesNotContain("LDAP", "wrong");
        mvc.perform(post("/signin/restart").secure(true).session(session).with(csrf()))
            .andExpect(redirectedUrl("/signin"));
        assertThat(session.isInvalid()).isTrue();
    }
}
