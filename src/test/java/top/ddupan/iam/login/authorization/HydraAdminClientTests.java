package top.ddupan.iam.login.authorization;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;
import top.ddupan.iam.login.authorization.infrastructure.hydra.*;
import static org.assertj.core.api.Assertions.*;

class HydraAdminClientTests {
    private RestClient http(HttpServer server) {
        var factory = new JdkClientHttpRequestFactory(
            HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build());
        return RestClient.builder()
            .baseUrl("http://127.0.0.1:" + server.getAddress().getPort()).requestFactory(factory).build();
    }

    @Test void logoutAcceptsOriginRelativeRequestsButRejectsForeignOrigins() throws Exception {
        var payload = new AtomicReference<String>();
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            var bytes = payload.get().getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes); exchange.close();
        });
        server.start();
        try {
            var client = new HydraAdminClient(new HydraProperties(true,
                URI.create("http://127.0.0.1:" + server.getAddress().getPort()), URI.create("http://localhost:14444"),
                Set.of(), List.of()), http(server));
            payload.set("{\"challenge\":\"challenge\",\"subject\":\"subject\",\"sid\":\"session\",\"request_url\":\"/oauth2/sessions/logout\"}");
            assertThat(client.logout("challenge").subject()).isEqualTo("subject");
            for (String url : List.of("//attacker.example/oauth2/sessions/logout", "https://attacker.example/oauth2/sessions/logout", "/admin/clients")) {
                payload.set("{\"challenge\":\"challenge\",\"request_url\":\"" + url + "\"}");
                assertThatIllegalArgumentException().isThrownBy(() -> client.logout("challenge"));
            }
        } finally { server.stop(0); }
    }
    @Test void acceptsOnlyIssuerAuthorizationRedirectsAndNeverFollowsAdminRedirects() throws Exception {
        var status = new AtomicInteger(200);
        var payload = new AtomicReference<>("{\"redirect_to\":\"http://localhost:14444/oauth2/auth?login_verifier=fixture\"}");
        var requests = new AtomicInteger();
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            requests.incrementAndGet(); exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("Location", "http://127.0.0.1:" + server.getAddress().getPort() + "/redirected");
            var bytes = payload.get().getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status.get(), bytes.length);
            exchange.getResponseBody().write(bytes); exchange.close();
        });
        server.start();
        try {
            var client = new HydraAdminClient(new HydraProperties(true,
                URI.create("http://127.0.0.1:" + server.getAddress().getPort()), URI.create("http://localhost:14444"),
                Set.of("gitea"), List.of()), http(server));
            assertThat(client.acceptLogin("challenge", "subject", "binding", Instant.now()))
                .startsWith("http://localhost:14444/oauth2/auth?");
            for (var target : List.of("https://attacker.example/oauth2/auth", "http://localhost:14444/admin/clients",
                    "http://localhost:14444/oauth2/auth#fragment", "http://user@localhost:14444/oauth2/auth")) {
                payload.set("{\"redirect_to\":\"" + target + "\"}");
                assertThatIllegalArgumentException().isThrownBy(() -> client.acceptLogin("challenge", "subject", "binding", Instant.now()));
            }
            status.set(302); var before = requests.get();
            assertThatIllegalArgumentException().isThrownBy(() -> client.login("challenge"));
            assertThat(requests.get()).isEqualTo(before + 1);
        } finally { server.stop(0); }
    }
}
