package top.ddupan.iam.login;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
import top.ddupan.iam.login.support.HydraFixture;
import top.ddupan.iam.login.support.SigningKeyFixture;

/** Test-only HTTPS application with simulated AD and disposable PostgreSQL. Never connects to real AD. */
public final class WebAuthnBrowserFixture {
    public static void main(String[] args) {
        var directory = new AdDirectoryFixture();
        var database = new PostgreSQLContainer(DockerImageName.parse(
            "postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873")
            .asCompatibleSubstituteFor("postgres"));
        database.start();
        var application = new SpringApplication(IamLoginApplication.class);
        var properties = new HashMap<String, Object>(Map.ofEntries(
            Map.entry("server.address", "127.0.0.1"), Map.entry("server.port", "18083"),
            Map.entry("server.ssl.enabled", "true"), Map.entry("server.ssl.key-store", "classpath:ldap/fixture.p12"),
            Map.entry("server.ssl.key-store-password", "fixture-only"),
            Map.entry("iam.ad.enabled", "true"), Map.entry("iam.ad.domain", "example.test"),
            Map.entry("iam.ad.base-dn", "dc=example,dc=test"), Map.entry("iam.ad.url", directory.url()),
            Map.entry("iam.webauthn.enabled", "true"), Map.entry("iam.webauthn.rp-id", "localhost"),
            Map.entry("iam.webauthn.origin", "https://localhost:18083"),
            Map.entry("spring.datasource.url", database.getJdbcUrl()),
            Map.entry("spring.datasource.username", database.getUsername()),
            Map.entry("spring.datasource.password", database.getPassword()),
            Map.entry("spring.security.user.password", "fixture-monitor-password"),
            Map.entry("management.otlp.metrics.export.enabled", "false")));
        var hydra = Boolean.getBoolean("iam.fixture.hydra") ? new HydraFixture() : null;
        if (hydra != null) {
            properties.put("iam.hydra.enabled", "true");
            properties.put("iam.hydra.admin-url", "http://127.0.0.1:14445");
            properties.put("iam.hydra.public-url", "http://localhost:14444");
            properties.put("iam.clients.admin-group-dns[0]", "CN=gitea-admins,dc=example,dc=test");
            properties.put("iam.clients.admin-ui-client-id", "iam-admin-ui");
            properties.put("iam.hydra.subjects[0].authority", "example.test");
            properties.put("iam.hydra.subjects[0].directory-id", "00112233-4455-6677-8899-aabbccddeeff");
            properties.put("iam.hydra.subjects[0].subject", "human:fixture-existing-oidc-subject");
        }
        var conformance = Boolean.getBoolean("iam.fixture.conformance");
        var authorizationServer = conformance || Boolean.getBoolean("iam.fixture.authorization-server");
        if (authorizationServer) {
            properties.put("iam.authorization-server.enabled", "true");
            properties.put("iam.authorization-server.issuer", "https://localhost:18083");
            properties.put("iam.authorization-server.signing-keys[0]", "file:" + SigningKeyFixture.write());
            properties.put("iam.authorization-server.subjects[0].authority", "example.test");
            properties.put("iam.authorization-server.subjects[0].directory-id", "00112233-4455-6677-8899-aabbccddeeff");
            properties.put("iam.authorization-server.subjects[0].subject", "human:fixture-existing-oidc-subject");
        }
        application.setDefaultProperties(properties);
        var context = application.run(args);
        if (authorizationServer) {
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
                    .clientId(id).clientSecret("{noop}" + id + "-secret")
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
        }
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            context.close(); directory.close(); database.stop();
            if (hydra != null) hydra.close();
        }));
    }
}
