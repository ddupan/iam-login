package top.ddupan.iam.login;

import java.util.Map;
import org.springframework.boot.SpringApplication;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;
import top.ddupan.iam.login.support.AdDirectoryFixture;

/** Test-only HTTPS application with simulated AD and disposable PostgreSQL. Never connects to real AD. */
public final class WebAuthnBrowserFixture {
    public static void main(String[] args) {
        var directory = new AdDirectoryFixture();
        var database = new PostgreSQLContainer(DockerImageName.parse(
            "postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873")
            .asCompatibleSubstituteFor("postgres"));
        database.start();
        var application = new SpringApplication(IamLoginApplication.class);
        var properties = new java.util.HashMap<String, Object>(Map.ofEntries(
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
        var hydra = Boolean.getBoolean("iam.fixture.hydra") ? new top.ddupan.iam.login.support.HydraFixture() : null;
        if (hydra != null) {
            properties.put("iam.hydra.enabled", "true");
            properties.put("iam.hydra.admin-url", "http://127.0.0.1:14445");
            properties.put("iam.hydra.public-url", "http://localhost:14444");
            properties.put("iam.clients.admin-group-dns[0]", "CN=gitea-admins,dc=example,dc=test");
            properties.put("iam.hydra.subjects[0].authority", "example.test");
            properties.put("iam.hydra.subjects[0].directory-id", "00112233-4455-6677-8899-aabbccddeeff");
            properties.put("iam.hydra.subjects[0].subject", "human:fixture-existing-oidc-subject");
        }
        application.setDefaultProperties(properties);
        var context = application.run(args);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            context.close(); directory.close(); database.stop();
            if (hydra != null) hydra.close();
        }));
    }
}
