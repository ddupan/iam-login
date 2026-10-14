package top.ddupan.iam.login;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jooq.DSLContext;
import org.springframework.boot.SpringApplication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;
import top.ddupan.iam.login.support.AdDirectoryFixture;
import top.ddupan.iam.login.support.SigningKeyFixture;
import static top.ddupan.iam.login.persistence.schema.Tables.SUBJECTS;

/** Test-only HTTPS application with simulated AD and disposable PostgreSQL. Never connects to real AD. */
public final class WebAuthnBrowserFixture {
    public static void main(String[] args) {
        var directory = new AdDirectoryFixture();
        var database = new PostgreSQLContainer(DockerImageName.parse(
            "postgres:18.6")
            .asCompatibleSubstituteFor("postgres"));
        database.start();
        var application = new SpringApplication(IamLoginApplication.class);
        var properties = new HashMap<String, Object>(Map.ofEntries(
            Map.entry("server.address", "127.0.0.1"), Map.entry("server.port", "18083"),
            Map.entry("server.ssl.enabled", "true"), Map.entry("server.ssl.key-store", "classpath:ldap/fixture.p12"),
            Map.entry("server.ssl.key-store-password", "fixture-only"),
            Map.entry("iam.ad.enabled", "true"), Map.entry("iam.ad.domain", "example.test"),
            Map.entry("spring.ldap.base", "dc=example,dc=test"), Map.entry("spring.ldap.urls", directory.url()),
            Map.entry("spring.ldap.username", AdDirectoryFixture.SERVICE_USER), Map.entry("spring.ldap.password", AdDirectoryFixture.SERVICE_PASSWORD),
            Map.entry("iam.webauthn.enabled", "true"), Map.entry("iam.webauthn.rp-id", "localhost"),
            Map.entry("iam.webauthn.origin", "https://localhost:18083"),
            Map.entry("spring.datasource.url", database.getJdbcUrl()),
            Map.entry("spring.datasource.username", database.getUsername()),
            Map.entry("spring.datasource.password", database.getPassword()),
            Map.entry("spring.security.user.password", "fixture-monitor-password"),
            Map.entry("management.otlp.metrics.export.enabled", "false")));
        var conformance = Boolean.getBoolean("iam.fixture.conformance");
        var authorizationServer = conformance || Boolean.getBoolean("iam.fixture.authorization-server");
        if (authorizationServer) {
            properties.put("iam.authorization-server.enabled", "true");
            properties.put("iam.authorization-server.issuer", "https://localhost:18083");
            properties.put("iam.clients.admin-groups[0]", "gitea-admins");
            properties.put("iam.authorization-server.signing-keys[0]", "file:" + SigningKeyFixture.write());
        }
        application.setDefaultProperties(properties);
        var context = application.run(args);
        if (authorizationServer) {
            // A subject carried over from an earlier issuer, as a migration inserts it.
            context.getBean(DSLContext.class).insertInto(SUBJECTS).set(SUBJECTS.SUBJECT, "human:fixture-existing-oidc-subject")
                .set(SUBJECTS.AUTHORITY, "example.test").set(SUBJECTS.DIRECTORY_ID, "00112233-4455-6677-8899-aabbccddeeff")
                .onConflictDoNothing().execute();
            context.getBean(RegisteredClientRepository.class).save(
                RegisteredClient.withId("fixture-rp")
                    .clientId("fixture-rp").clientSecret("{noop}fixture-client-secret")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("http://localhost:14446/callback").postLogoutRedirectUri("http://localhost:14446/logged-out")
                    .scope("openid").scope("profile").scope("email").scope("groups").scope("offline_access")
                    .clientSettings(ClientSettings.builder()
                        .requireProofKey(true).requireAuthorizationConsent(true).build())
                    .tokenSettings(TokenSettings.builder()
                        .reuseRefreshTokens(false).build())
                    .build());
        }
        if (conformance) {
            var clients = context.getBean(RegisteredClientRepository.class);
            for (var id : List.of("conformance-1", "conformance-2")) {
                clients.save(RegisteredClient.withId(id)
                    .clientId(id)
                    // >= 32 bytes: the logout plan signs an HS256 id_token_hint with it.
                    .clientSecret("{noop}" + id + "-conformance-client-secret")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("https://localhost.emobix.co.uk:8443/test/a/iam-login/callback")
                    .postLogoutRedirectUri("https://localhost.emobix.co.uk:8443/test/a/iam-login/post_logout_redirect")
                    .scope("openid").scope("profile").scope("email").scope("address").scope("phone").scope("groups").scope("offline_access")
                    // The Basic OP plan exercises classic confidential clients without PKCE; the framework
                    // requires PKCE for every client by default (OAuth 2.1).
                    .clientSettings(ClientSettings.builder()
                        .requireProofKey(false).requireAuthorizationConsent(false).build())
                    .tokenSettings(TokenSettings.builder()
                        .reuseRefreshTokens(false).build())
                    .build());
            }
            // The app reports ready before these clients exist; scripts/conformance waits for this line.
            System.out.println("CONFORMANCE_CLIENTS_REGISTERED");
            System.out.flush();
        }
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            context.close(); directory.close(); database.stop();
        }));
    }
}
