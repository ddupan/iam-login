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
import top.ddupan.iam.login.clients.domain.ClientRepositoryException;
import top.ddupan.iam.login.clients.domain.OidcClient;
import top.ddupan.iam.login.clients.infrastructure.HydraClientRepository;
import static org.assertj.core.api.Assertions.*;

class HydraRepositoryIntegrationTests {
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
                var registry=new HydraClientRepository(org.springframework.web.client.RestClient.builder().baseUrl(ADMIN.toString()).build());
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
                // Legacy (no flag): reads back as null, never as disabled, and saving keeps it unflagged.
                var legacy=new OidcClient(changed.id(),changed.name(),changed.redirectUris(),changed.scopes(),List.of(),"","",null);
                assertThat(registry.update(legacy).loginEnabled()).isNull();
                assertThat(registry.get(client.id()).loginEnabled()).isNull();
                assertThat(registry.update(changed).loginEnabled()).isFalse();
                // invalid_grant means the client authenticated and only the (deliberately bogus) code failed.
                assertThat(tokenError(client.id(),created.secret())).contains("invalid_grant").doesNotContain("invalid_client");
                var rotated=registry.rotateSecret(client.id());
                assertThat(rotated).isNotBlank().isNotEqualTo(created.secret());
                assertThat(tokenError(client.id(),created.secret())).contains("invalid_client");
                assertThat(tokenError(client.id(),rotated)).contains("invalid_grant");
                assertThat(registry.get(client.id())).isEqualTo(changed);
                registry.delete(client.id());
                assertThatThrownBy(() -> registry.get(client.id())).isInstanceOfSatisfying(ClientRepositoryException.class,
                    ex -> assertThat(ex.kind()).isEqualTo(ClientRepositoryException.Kind.NOT_FOUND));
            }
        }
    }
    private static String tokenError(String id,String secret) throws Exception {
        try (var http=HttpClient.newHttpClient()) {
            String basic=Base64.getEncoder().encodeToString((id+":"+secret).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            var response=http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:14844/oauth2/token"))
                .header("Authorization","Basic "+basic).header("Content-Type","application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=authorization_code&code=invalid-code&redirect_uri=https%3A%2F%2Frp.example%2Fnew-callback"))
                .build(),HttpResponse.BodyHandlers.ofString());
            assertThat(response.statusCode()).isIn(400,401);
            return response.body();
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
