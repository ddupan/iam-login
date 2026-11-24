package top.ddupan.iam.login.authentication.infrastructure.webauthn;

import com.zaxxer.hikari.HikariDataSource;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;
import javax.sql.DataSource;
import org.hamcrest.Matchers;
import org.jooq.DSLContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.TypeReference;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.core.convert.ConversionService;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutableCredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCose;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;
import top.ddupan.iam.login.authentication.infrastructure.persistence.CredentialRegistration;
import top.ddupan.iam.login.authentication.infrastructure.totp.Totp;
import top.ddupan.iam.login.authentication.infrastructure.totp.TotpCode;
import top.ddupan.iam.login.support.AdDirectoryFixture;
import top.ddupan.iam.login.support.SessionRoundTrip;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static top.ddupan.iam.login.persistence.schema.Tables.OAUTH2_AUTHORIZATION;
import static top.ddupan.iam.login.persistence.schema.Tables.OAUTH2_AUTHORIZATION_CONSENT;
import static top.ddupan.iam.login.persistence.schema.Tables.OAUTH2_REGISTERED_CLIENT;
import static top.ddupan.iam.login.persistence.schema.Tables.SPRING_SESSION;
import static top.ddupan.iam.login.persistence.schema.Tables.TOTP_CREDENTIALS;
import static top.ddupan.iam.login.persistence.schema.Tables.USER_CREDENTIALS;
import static top.ddupan.iam.login.persistence.schema.Tables.USER_ENTITIES;
import static top.ddupan.iam.login.persistence.schema.Tables.WEBAUTHN_CHALLENGE;

// Container sessions, see AuthorizationServerIntegrationTests.
@SpringBootTest(properties = {"spring.autoconfigure.exclude=org.springframework.boot.session.jdbc.autoconfigure.JdbcSessionAutoConfiguration", "iam.ad.enabled=true", "iam.ad.domain=example.test", "spring.ldap.base=dc=example,dc=test",
    "spring.datasource.hikari.maximum-pool-size=3",     "iam.webauthn.enabled=true", "iam.webauthn.rp-id=localhost", "iam.webauthn.origin=https://localhost", "iam.totp.key=Zml4dHVyZS1vbmx5LXRvdHAta2V5LTMyLWJ5dGVzISE=",
    "management.otlp.metrics.export.enabled=false", "spring.security.user.password=fixture-monitor-password"})
@AutoConfigureMockMvc
class WebAuthnIntegrationTests {
    static class Fixtures {
        static final AdDirectoryFixture DIRECTORY = new AdDirectoryFixture();
        static final PostgreSQLContainer DATABASE = new PostgreSQLContainer(DockerImageName.parse(
            "postgres:18.6")
            .asCompatibleSubstituteFor("postgres"));
        static { DATABASE.start(); }
    }
    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) {
        r.add("spring.ldap.urls", () -> Fixtures.DIRECTORY.url());
        r.add("spring.ldap.username", () -> AdDirectoryFixture.SERVICE_USER);
        r.add("spring.ldap.password", () -> AdDirectoryFixture.SERVICE_PASSWORD);
        r.add("spring.datasource.url", () -> Fixtures.DATABASE.getJdbcUrl());
        r.add("spring.datasource.username", () -> Fixtures.DATABASE.getUsername());
        r.add("spring.datasource.password", () -> Fixtures.DATABASE.getPassword());
    }
    @AfterAll static void close() { Fixtures.DIRECTORY.close(); Fixtures.DATABASE.stop(); }
    @Autowired MockMvc mvc;
    @Autowired DSLContext db;



    @Autowired PlatformTransactionManager transactionManager;
    @Autowired DataSource dataSource;

    // Pending ceremonies are stored with Java serialization, which a native image allows only for registered
    // classes. Real options (registration and authentication, with credentials listed) are read back here
    // recording every class in them; each must be registered by SecurityJacksonHints, or the native login
    // fails with "SerializationConstructorAccessor class not found" (it did, for Arrays$ArrayList).
    @Test void everyClassInStoredCeremoniesIsRegisteredForNativeSerialization(
            @Autowired PublicKeyCredentialUserEntityRepository users, @Autowired UserCredentialRepository credentials) throws Exception {
        var session = login();
        mvc.perform(post("/webauthn/register/options").session(session).with(https()).with(csrf())).andExpect(status().isOk());
        var name = ((SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT")).getAuthentication().getName();
        credentials.save(ImmutableCredentialRecord.builder().credentialType(PublicKeyCredentialType.PUBLIC_KEY)
            .credentialId(Bytes.random()).userEntityUserId(users.findByUsername(name).getId())
            .publicKey(new ImmutablePublicKeyCose(Bytes.random().getBytes())).signatureCount(0).uvInitialized(true)
            .transports(Set.of(AuthenticatorTransport.INTERNAL, AuthenticatorTransport.HYBRID))
            .backupEligible(false).backupState(false).attestationObject(Bytes.random()).attestationClientDataJSON(Bytes.random())
            .created(Instant.now()).lastUsed(Instant.now()).label("fixture").build());
        secondFactor(session);
        mvc.perform(post("/webauthn/register/options").session(session).with(https()).with(csrf())).andExpect(status().isOk());
        mvc.perform(post("/webauthn/authenticate/options").session(session).with(https()).with(csrf())).andExpect(status().isOk());

        var classes = new TreeSet<String>();
        for (var bytes : db.select(WEBAUTHN_CHALLENGE.OPTIONS).from(WEBAUTHN_CHALLENGE).fetch(WEBAUTHN_CHALLENGE.OPTIONS)) {
            try (var in = new ObjectInputStream(new ByteArrayInputStream(bytes)) {
                @Override protected Class<?> resolveClass(ObjectStreamClass type) throws IOException, ClassNotFoundException {
                    classes.add(type.getName());
                    return super.resolveClass(type);
                }
            }) {
                in.readObject();
            }
        }
        assertThat(classes).contains(PublicKeyCredentialCreationOptions.class.getName(), PublicKeyCredentialRequestOptions.class.getName());
        var hints = new RuntimeHints();
        var registrar = Class.forName("top.ddupan.iam.login.configuration.SecurityJacksonHints").getDeclaredConstructor();
        registrar.setAccessible(true);
        ((RuntimeHintsRegistrar) registrar.newInstance()).registerHints(hints, getClass().getClassLoader());
        assertThat(classes).allSatisfy(type -> {
            var hint = hints.reflection().getTypeHint(TypeReference.of(Class.forName(type)));
            assertThat(hint != null && hint.hasJavaSerialization()).as(type).isTrue();
        });
    }

    @Test void registrationLockSerializesAndRollsBackOnFailure() throws Exception {
        assertThat(((HikariDataSource)dataSource).getMaximumPoolSize()).isEqualTo(3);
        var registrations = new CredentialRegistration(db, new TransactionTemplate(transactionManager));
        String id = UUID.randomUUID().toString();
        db.insertInto(USER_ENTITIES).set(USER_ENTITIES.ID, id).set(USER_ENTITIES.NAME, id).set(USER_ENTITIES.DISPLAY_NAME, "before").execute();
        var locked = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var started = new CountDownLatch(1);
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            var first = executor.submit(() -> registrations.register(id, () -> {
                displayName(id, "committed");
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
                    return registrations.register(id, () -> displayName(id));
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
            displayName(id, "rolled back");
            throw new IllegalStateException("Registration rejected");
        })).isInstanceOf(IllegalStateException.class);
        assertThat(displayName(id)).isEqualTo("committed");
        db.deleteFrom(USER_ENTITIES).where(USER_ENTITIES.ID.eq(id)).execute();
    }

    private String displayName(String id) {
        return db.select(USER_ENTITIES.DISPLAY_NAME).from(USER_ENTITIES).where(USER_ENTITIES.ID.eq(id)).fetchSingle(USER_ENTITIES.DISPLAY_NAME);
    }

    private void displayName(String id, String value) {
        db.update(USER_ENTITIES).set(USER_ENTITIES.DISPLAY_NAME, value).where(USER_ENTITIES.ID.eq(id)).execute();
    }

    @Test
    void passwordOnlyCanEnrollButCannotCompleteOrDelete(
            @Autowired @Qualifier("springSessionConversionService") ConversionService store) throws Exception {
        var session = login();
        mvc.perform(post("/webauthn/register/options").session(session).with(https()))
            .andExpect(status().isForbidden());
        mvc.perform(post("/webauthn/register/options").session(session).with(https()).with(csrf()))
            .andExpect(status().isOk()).andExpect(jsonPath("rp.id").value("localhost"))
            .andExpect(jsonPath("authenticatorSelection.userVerification").value("required"));
        assertThat(db.fetchCount(USER_ENTITIES)).isEqualTo(1);
        assertThat(db.fetchCount(USER_CREDENTIALS)).isZero();
        mvc.perform(get("/signin/complete").session(session).with(https()))
            .andExpect(redirectedUrlPattern("/signin/mfa?*"));
        mvc.perform(delete("/webauthn/register/unused").session(session).with(https()).with(csrf()))
            .andExpect(status().isForbidden());
        // A pending registration ceremony (its id) and the password-only context must survive the store.
        SessionRoundTrip.assertStorable(session, store);
    }

    @Test
    void passwordlessOptionsListNoPasskeysButRegistrationStillNeedsAFreshPassword() throws Exception {
        // Nobody signed in: a passwordless ceremony. No passkeys listed, user verification demanded.
        mvc.perform(post("/webauthn/authenticate/options").with(https()).with(csrf())).andExpect(status().isOk())
            .andExpect(jsonPath("allowCredentials").isEmpty()).andExpect(jsonPath("userVerification").value("required"));
        mvc.perform(post("/webauthn/register/options").with(https()).with(csrf())).andExpect(status().is4xxClientError());
        var session = login();
        var context = (SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT");
        var auth = context.getAuthentication();
        context.setAuthentication(UsernamePasswordAuthenticationToken.authenticated(auth.getPrincipal(), null,
            List.of(FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
                .issuedAt(Instant.now().minusSeconds(601)).build())));
        mvc.perform(post("/webauthn/register/options").session(session).with(https()).with(csrf()))
            .andExpect(status().is3xxRedirection());
    }

    @Test
    void aPasskeyAloneIsAFullSignInAndMayAddFactors(@Autowired PublicKeyCredentialUserEntityRepository users,
            @Autowired UserCredentialRepository credentials) throws Exception {
        var session = login();
        mvc.perform(post("/webauthn/register/options").session(session).with(https()).with(csrf())).andExpect(status().isOk());
        var context = (SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT");
        var principal = context.getAuthentication().getPrincipal();
        credential(credentials, users.findByUsername(context.getAuthentication().getName()).getId(), "laptop");
        try {
            // Identifier first: an account with a passkey is asked for it, and may switch to its password.
            var fresh = new MockHttpSession();
            mvc.perform(post("/signin/identify").session(fresh).with(https()).with(csrf()).param("username", "alice"))
                .andExpect(redirectedUrl("/signin"));
            mvc.perform(get("/signin").session(fresh).with(https()))
                .andExpect(content().string(Matchers.containsString("\"step\":\"passkey\"")));
            mvc.perform(get("/signin").param("method", "password").session(fresh).with(https()))
                .andExpect(content().string(Matchers.containsString("\"step\":\"password\"")));
            passkeyOnly(context, principal, Instant.now());
            mvc.perform(get("/account").session(session).with(https())).andExpect(status().isOk());
            mvc.perform(get("/signin/complete").session(session).with(https())).andExpect(redirectedUrl("/account"));
            mvc.perform(post("/webauthn/register/options").session(session).with(https()).with(csrf())).andExpect(status().isOk());
            mvc.perform(get("/signin/totp/setup").session(session).with(https())).andExpect(status().isOk());
            // A code is only ever the second step after the password.
            mvc.perform(post("/signin/totp").session(session).with(https()).with(csrf()).param("code", "000000"))
                .andExpect(redirectedUrlPattern("/signin/mfa?*"));
            // Stale: re-verify before changing the account.
            passkeyOnly(context, principal, Instant.now().minusSeconds(601));
            mvc.perform(get("/account").session(session).with(https())).andExpect(status().is3xxRedirection());
        } finally {
            db.deleteFrom(USER_CREDENTIALS).execute();
        }
    }

    private static void passkeyOnly(SecurityContext context, Object principal, Instant issued) {
        context.setAuthentication(UsernamePasswordAuthenticationToken.authenticated(principal, null,
            List.of(FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.WEBAUTHN_AUTHORITY).issuedAt(issued).build())));
    }

    @Test
    void accountPageNeedsBothFreshFactorsAndKeepsTheLastPasskey(@Autowired PublicKeyCredentialUserEntityRepository users,
            @Autowired UserCredentialRepository credentials) throws Exception {
        mvc.perform(get("/account").with(https())).andExpect(redirectedUrl("/signin"));
        var session = login();
        mvc.perform(get("/account").session(session).with(https())).andExpect(redirectedUrlPattern("/signin/mfa?*"));
        mvc.perform(post("/webauthn/register/options").session(session).with(https()).with(csrf())).andExpect(status().isOk());
        var name = ((SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT")).getAuthentication().getName();
        var owner = users.findByUsername(name).getId();
        var first = credential(credentials, owner, "laptop");
        var second = credential(credentials, owner, "phone");
        // Another account's passkey: its id must match nothing through this account's page.
        var stranger = Bytes.random();
        db.insertInto(USER_ENTITIES).set(USER_ENTITIES.ID, stranger.toBase64UrlString()).set(USER_ENTITIES.NAME, "example.test:stranger")
            .set(USER_ENTITIES.DISPLAY_NAME, "stranger").execute();
        var foreign = credential(credentials, stranger, "theirs");
        try {
            mvc.perform(put("/account/passkeys/" + first + "/label").session(session).with(https()).with(csrf())
                .contentType("application/json").content("{\"label\":\"x\"}")).andExpect(redirectedUrlPattern("/signin/mfa?*"));
            secondFactor(session);
            mvc.perform(get("/account").session(session).with(https())).andExpect(status().isOk())
                .andExpect(content().string(Matchers.containsString("\"step\":\"account\"")))
                .andExpect(content().string(Matchers.containsString("laptop")))
                .andExpect(content().string(Matchers.not(Matchers.containsString("theirs"))));
            mvc.perform(put("/account/passkeys/" + first + "/label").session(session).with(https())
                .contentType("application/json").content("{\"label\":\"x\"}")).andExpect(status().isForbidden());
            mvc.perform(put("/account/passkeys/" + first + "/label").session(session).with(https()).with(csrf())
                .contentType("application/json").content("{\"label\":\"  work laptop  \"}")).andExpect(status().isNoContent());
            assertThat(credentials.findByCredentialId(Bytes.fromBase64(first)).getLabel()).isEqualTo("work laptop");
            mvc.perform(put("/account/passkeys/" + first + "/label").session(session).with(https()).with(csrf())
                .contentType("application/json").content("{\"label\":\" \"}")).andExpect(status().isBadRequest())
                .andExpect(jsonPath("error").value("invalid"));
            mvc.perform(put("/account/passkeys/" + foreign + "/label").session(session).with(https()).with(csrf())
                .contentType("application/json").content("{\"label\":\"mine\"}")).andExpect(status().isNotFound());
            mvc.perform(delete("/account/passkeys/" + foreign).session(session).with(https()).with(csrf()))
                .andExpect(status().isNotFound());
            // Sessions as Spring Session JDBC stores them: this browser's, another of this account's, a stranger's.
            storedSession(session.getId(), name);
            var elsewhere = storedSession(UUID.randomUUID().toString(), name);
            var theirs = storedSession(UUID.randomUUID().toString(), "example.test:stranger");
            mvc.perform(delete("/account/passkeys/" + second).session(session).with(https()).with(csrf()))
                .andExpect(status().isNoContent());
            // session_id is CHAR(36): a short test id comes back space-padded.
            assertThat(db.select(SPRING_SESSION.SESSION_ID).from(SPRING_SESSION).fetch(r -> r.value1().strip()))
                .as("the account's other sessions end; this one and other accounts' stay")
                .contains(session.getId(), theirs).doesNotContain(elsewhere);
            mvc.perform(delete("/account/passkeys/" + first).session(session).with(https()).with(csrf()))
                .andExpect(status().isConflict()).andExpect(jsonPath("error").value("last"));
            assertThat(credentials.findByUserId(owner)).hasSize(1);
            assertThat(credentials.findByUserId(stranger)).hasSize(1);
        } finally {
            db.deleteFrom(USER_CREDENTIALS).execute();
            db.deleteFrom(SPRING_SESSION).execute();
            db.deleteFrom(USER_ENTITIES).where(USER_ENTITIES.ID.eq(stranger.toBase64UrlString())).execute();
        }
    }

    @Test
    void authenticatorAppIsConfirmedBySetUpThenSignsInOnceRejectingReplays(@Autowired PublicKeyCredentialUserEntityRepository users,
            @Autowired UserCredentialRepository credentials) throws Exception {
        var session = login();
        mvc.perform(post("/signin/totp/setup").session(session).with(https()).with(csrf()).param("code", "000000"))
            .andExpect(redirectedUrl("/signin/totp/setup?error=invalid"));
        mvc.perform(get("/signin/totp/setup").session(session).with(https())).andExpect(status().isOk())
            .andExpect(content().string(Matchers.containsString("otpauth://totp/IAM%20Login:alice?secret=")));
        var key = Base64.getDecoder().decode((String) session.getAttribute(TotpCode.PENDING));
        var step = Instant.now().getEpochSecond() / 30;
        var wrong = Totp.code(key, step - 3);
        mvc.perform(post("/signin/totp/setup").session(session).with(https()).with(csrf()).param("code", wrong))
            .andExpect(redirectedUrl("/signin/totp/setup?error=invalid"));
        // A failed code shows the same key again, so the app already holding it keeps working.
        mvc.perform(get("/signin/totp/setup").session(session).param("error", "invalid").with(https())).andExpect(status().isOk());
        assertThat(Base64.getDecoder().decode((String) session.getAttribute(TotpCode.PENDING))).isEqualTo(key);
        try {
            mvc.perform(post("/signin/totp/setup").session(session).with(https()).with(csrf()).param("code", Totp.code(key, step)))
                .andExpect(redirectedUrl("/signin/complete"));
            assertThat(session.getAttribute(TotpCode.PENDING)).isNull();
            mvc.perform(get("/account").session(session).with(https())).andExpect(status().isOk())
                .andExpect(content().string(Matchers.containsString("\"authenticator\":{\"")));
            // Encrypted at rest.
            assertThat(db.select(TOTP_CREDENTIALS.SECRET).from(TOTP_CREDENTIALS).fetchSingle(TOTP_CREDENTIALS.SECRET)).isNotEqualTo(key);

            var next = login();
            mvc.perform(get("/signin/mfa").session(next).with(https()))
                .andExpect(content().string(Matchers.containsString("\"factor\":\"totp\"")));
            mvc.perform(post("/signin/totp").session(next).with(https())).andExpect(status().isForbidden());
            mvc.perform(post("/signin/totp").session(next).with(https()).with(csrf()).param("code", Totp.code(key, step)))
                .andExpect(redirectedUrl("/signin/mfa?method=totp&error=invalid"));
            // Setting up again (another phone) needs the second factor, not just the password.
            mvc.perform(get("/signin/totp/setup").session(next).with(https())).andExpect(redirectedUrlPattern("/signin/mfa?*"));
            mvc.perform(post("/signin/totp").session(next).with(https()).with(csrf()).param("code", Totp.code(key, step + 1)))
                .andExpect(redirectedUrl("/signin/complete"));
            mvc.perform(get("/account").session(next).with(https())).andExpect(status().isOk());

            mvc.perform(delete("/account/authenticator").session(next).with(https()).with(csrf()))
                .andExpect(status().isConflict()).andExpect(jsonPath("error").value("last"));
            mvc.perform(post("/webauthn/register/options").session(next).with(https()).with(csrf())).andExpect(status().isOk());
            var name = ((SecurityContext) next.getAttribute("SPRING_SECURITY_CONTEXT")).getAuthentication().getName();
            var passkey = credential(credentials, users.findByUsername(name).getId(), "laptop");
            mvc.perform(get("/signin/mfa").session(login()).with(https()))
                .andExpect(content().string(Matchers.containsString("\"factor\":\"passkey\"")))
                .andExpect(content().string(Matchers.containsString("\"other\":true")));
            mvc.perform(delete("/account/authenticator").session(next).with(https()).with(csrf())).andExpect(status().isNoContent());
            mvc.perform(delete("/account/passkeys/" + passkey).session(next).with(https()).with(csrf()))
                .andExpect(status().isConflict()).andExpect(jsonPath("error").value("last"));
        } finally {
            db.deleteFrom(TOTP_CREDENTIALS).execute();
            db.deleteFrom(USER_CREDENTIALS).execute();
        }
    }

    @Test
    void revokingAnApplicationRemovesItsConsentAndAuthorizations() throws Exception {
        var session = login();
        secondFactor(session);
        var name = ((SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT")).getAuthentication().getName();
        db.insertInto(OAUTH2_REGISTERED_CLIENT).set(OAUTH2_REGISTERED_CLIENT.ID, "rp-id").set(OAUTH2_REGISTERED_CLIENT.CLIENT_ID, "rp")
            .set(OAUTH2_REGISTERED_CLIENT.CLIENT_NAME, "Fixture RP").set(OAUTH2_REGISTERED_CLIENT.CLIENT_AUTHENTICATION_METHODS, "client_secret_basic")
            .set(OAUTH2_REGISTERED_CLIENT.AUTHORIZATION_GRANT_TYPES, "authorization_code").set(OAUTH2_REGISTERED_CLIENT.SCOPES, "openid,groups")
            .set(OAUTH2_REGISTERED_CLIENT.CLIENT_SETTINGS, "{}").set(OAUTH2_REGISTERED_CLIENT.TOKEN_SETTINGS, "{}").execute();
        try {
            db.insertInto(OAUTH2_AUTHORIZATION_CONSENT).set(OAUTH2_AUTHORIZATION_CONSENT.REGISTERED_CLIENT_ID, "rp-id")
                .set(OAUTH2_AUTHORIZATION_CONSENT.PRINCIPAL_NAME, name).set(OAUTH2_AUTHORIZATION_CONSENT.AUTHORITIES, "SCOPE_openid,SCOPE_groups").execute();
            for (var principal : List.of(name, "example.test:someone-else")) {
                db.insertInto(OAUTH2_AUTHORIZATION).set(OAUTH2_AUTHORIZATION.ID, UUID.randomUUID().toString())
                    .set(OAUTH2_AUTHORIZATION.REGISTERED_CLIENT_ID, "rp-id").set(OAUTH2_AUTHORIZATION.PRINCIPAL_NAME, principal)
                    .set(OAUTH2_AUTHORIZATION.AUTHORIZATION_GRANT_TYPE, "authorization_code")
                    .set(OAUTH2_AUTHORIZATION.AUTHORIZED_SCOPES, "openid,offline_access").execute();
            }
            mvc.perform(get("/account").session(session).with(https())).andExpect(status().isOk())
                .andExpect(content().string(Matchers.containsString("Fixture RP")))
                .andExpect(content().string(Matchers.containsString("offline_access")));
            mvc.perform(delete("/account/apps/rp").session(session).with(https()).with(csrf())).andExpect(status().isNoContent());
            assertThat(db.fetchCount(OAUTH2_AUTHORIZATION_CONSENT)).isZero();
            assertThat(db.fetch(OAUTH2_AUTHORIZATION).getValues(OAUTH2_AUTHORIZATION.PRINCIPAL_NAME)).containsExactly("example.test:someone-else");
            mvc.perform(delete("/account/apps/rp").session(session).with(https()).with(csrf())).andExpect(status().isNotFound());
        } finally {
            db.deleteFrom(OAUTH2_AUTHORIZATION).execute();
            db.deleteFrom(OAUTH2_AUTHORIZATION_CONSENT).execute();
            db.deleteFrom(OAUTH2_REGISTERED_CLIENT).where(OAUTH2_REGISTERED_CLIENT.ID.eq("rp-id")).execute();
        }
    }

    private static String credential(UserCredentialRepository credentials, Bytes owner, String label) {
        var id = Bytes.random();
        credentials.save(ImmutableCredentialRecord.builder().credentialType(PublicKeyCredentialType.PUBLIC_KEY)
            .credentialId(id).userEntityUserId(owner).publicKey(new ImmutablePublicKeyCose(Bytes.random().getBytes()))
            .signatureCount(0).uvInitialized(true).backupEligible(false).backupState(false)
            .created(Instant.now()).lastUsed(Instant.now()).label(label).build());
        return id.toBase64UrlString();
    }

    private void secondFactor(MockHttpSession session) {
        var context = (SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT");
        var previous = context.getAuthentication();
        var factors = new ArrayList<GrantedAuthority>(previous.getAuthorities());
        factors.add(FactorGrantedAuthority.withAuthority("FACTOR_WEBAUTHN").issuedAt(Instant.now()).build());
        context.setAuthentication(UsernamePasswordAuthenticationToken.authenticated(previous.getPrincipal(), null, factors));
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

    private String storedSession(String id, String owner) {
        db.insertInto(SPRING_SESSION).set(SPRING_SESSION.PRIMARY_ID, UUID.randomUUID().toString())
            .set(SPRING_SESSION.SESSION_ID, id).set(SPRING_SESSION.CREATION_TIME, 0L)
            .set(SPRING_SESSION.LAST_ACCESS_TIME, 0L).set(SPRING_SESSION.MAX_INACTIVE_INTERVAL, 1800)
            .set(SPRING_SESSION.EXPIRY_TIME, Long.MAX_VALUE).set(SPRING_SESSION.PRINCIPAL_NAME, owner).execute();
        return id;
    }
}
