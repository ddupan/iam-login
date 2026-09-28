package top.ddupan.iam.login.clients;

import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.startupcheck.OneShotStartupCheckStrategy;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;
import top.ddupan.iam.login.authorization.infrastructure.hydra.HydraProperties;
import top.ddupan.iam.login.clients.application.ClientRegistryException;
import top.ddupan.iam.login.clients.domain.OidcClient;
import top.ddupan.iam.login.clients.infrastructure.HydraClientRegistry;
import static org.assertj.core.api.Assertions.*;

class HydraRegistryIntegrationTests {
    private static final String IMAGE="oryd/hydra:v26.2.0@sha256:ff67c7fb5f95074fa53374d41151713554960504b340cd3f95b09e65deaea2a9";
    private static final URI ADMIN=URI.create("http://127.0.0.1:14845");
    @Test void crudPersistsAcrossIssuerRestartAndDoesNotReturnSecretsOnRead() throws Exception {
        try (var database=new PostgreSQLContainer(DockerImageName.parse(
                "postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873").asCompatibleSubstituteFor("postgres"))) {
            database.start();
            String dsn="postgres://"+database.getUsername()+":"+database.getPassword()+"@127.0.0.1:"
                +database.getMappedPort(5432)+"/"+database.getDatabaseName()+"?sslmode=disable";
            try (var migrate=new GenericContainer<>(DockerImageName.parse(IMAGE)).withNetworkMode("host")
                    .withEnv("DSN",dsn).withCommand("migrate","sql","-e","--yes")
                    .withStartupCheckStrategy(new OneShotStartupCheckStrategy())) { migrate.start(); }
            try (var hydra=new GenericContainer<>(DockerImageName.parse(IMAGE)).withNetworkMode("host")
                    .withEnv("DSN",dsn).withEnv("SERVE_PUBLIC_HOST","127.0.0.1").withEnv("SERVE_PUBLIC_PORT","14844")
                    .withEnv("SERVE_ADMIN_HOST","127.0.0.1").withEnv("SERVE_ADMIN_PORT","14845")
                    .withEnv("URLS_SELF_ISSUER","http://localhost:14844/").withEnv("LOG_LEVEL","error")
                    .withEnv("SECRETS_SYSTEM","fixture-only-stable-system-secret-32-characters").withCommand("serve","all","--dev")) {
                hydra.start(); ready();
                var registry=new HydraClientRegistry(new HydraProperties(true,ADMIN,URI.create("http://localhost:14844"),Set.of(),List.of()));
                var client=new OidcClient("managed-fixture","Fixture",List.of("https://rp.example/callback"),Set.of("openid","groups"),
                    List.of("https://rp.example/bye"),"https://rp.example/backchannel","",true);
                var created=registry.create(client);
                assertThat(created.client()).isEqualTo(client);
                assertThat(created.secret()).isNotBlank();
                assertThat(created.toString()).doesNotContain(created.secret());
                assertThat(registry.list(0,20)).contains(client);
                hydra.getDockerClient().restartContainerCmd(hydra.getContainerId()).exec(); ready();
                assertThat(registry.get(client.id())).isEqualTo(client);
                var changed=new OidcClient(client.id(),"Updated",List.of("https://rp.example/new-callback"),Set.of("openid"),
                    List.of(),"","",false);
                assertThat(registry.update(changed)).isEqualTo(changed);
                assertThat(registry.get(client.id()).loginEnabled()).isFalse();
                try (var http=HttpClient.newHttpClient()) {
                    String basic=Base64.getEncoder().encodeToString((client.id()+":"+created.secret()).getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    var response=http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:14844/oauth2/token"))
                        .header("Authorization","Basic "+basic).header("Content-Type","application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString("grant_type=authorization_code&code=invalid-code&redirect_uri=https%3A%2F%2Frp.example%2Fnew-callback"))
                        .build(),HttpResponse.BodyHandlers.ofString());
                    assertThat(response.statusCode()).isEqualTo(400);
                    assertThat(response.body()).contains("invalid_grant").doesNotContain("invalid_client");
                }
                registry.delete(client.id());
                assertThatThrownBy(() -> registry.get(client.id())).isInstanceOfSatisfying(ClientRegistryException.class,
                    ex -> assertThat(ex.kind()).isEqualTo(ClientRegistryException.Kind.NOT_FOUND));
            }
        }
    }
    private static void ready() throws Exception {
        try (var http=HttpClient.newHttpClient()) {
            for (int i=0;i<100;i++) {
                try {
                    if(http.send(HttpRequest.newBuilder(ADMIN.resolve("/health/ready")).timeout(Duration.ofSeconds(1)).GET().build(),
                        HttpResponse.BodyHandlers.discarding()).statusCode()==200) return;
                } catch (java.io.IOException ignored) { }
                Thread.sleep(200);
            }
        }
        throw new IllegalStateException("Fixture issuer not ready");
    }
    @Test void rejectsCallbackWildcardsFragmentsAndInsecureNonLoopback() {
        for (var target:List.of("https://rp.example/*","https://rp.example/callback#x","http://rp.example/callback","https://user@rp.example/callback")) {
            assertThatIllegalArgumentException().isThrownBy(() -> new OidcClient("id","Name",List.of(target),Set.of("openid"),List.of(),"","",true));
        }
    }
}
