package top.ddupan.iam.login.support;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.AbstractWaitStrategy;
import org.testcontainers.utility.DockerImageName;

/** Disposable issuer, bound to loopback only. Contains no production clients, secrets or users. */
public final class HydraFixture implements AutoCloseable {
    private final GenericContainer<?> hydra;
    public HydraFixture() {
        hydra = new GenericContainer<>(DockerImageName.parse(
            "oryd/hydra:v26.2.0@sha256:ff67c7fb5f95074fa53374d41151713554960504b340cd3f95b09e65deaea2a9"))
            .withNetworkMode("host")
            .withEnv("DSN", "memory")
            .withEnv("SERVE_PUBLIC_HOST", "127.0.0.1").withEnv("SERVE_PUBLIC_PORT", "14444")
            .withEnv("SERVE_ADMIN_HOST", "127.0.0.1").withEnv("SERVE_ADMIN_PORT", "14445")
            .withEnv("URLS_SELF_ISSUER", "http://localhost:14444/")
            .withEnv("URLS_LOGIN", "https://localhost:18083/oauth2/start")
            .withEnv("URLS_CONSENT", "https://localhost:18083/oauth2/consent")
            .withEnv("URLS_LOGOUT", "https://localhost:18083/oauth2/logout")
            .withEnv("URLS_POST_LOGOUT_REDIRECT", "https://localhost:18083/signin")
            // The admin UI exchanges its code from the browser, so the issuer must allow that origin.
            .withEnv("SERVE_PUBLIC_CORS_ENABLED", "true")
            .withEnv("SERVE_PUBLIC_CORS_ALLOWED_ORIGINS", "https://localhost:18083")
            .withEnv("LOG_LEVEL", "error")
            .withEnv("SECRETS_SYSTEM", "fixture-only-hydra-system-secret-32-characters")
            .withCommand("serve", "all", "--dev")
            .waitingFor(new AbstractWaitStrategy() {
                @Override protected void waitUntilReady() {
                    try (var http = HttpClient.newHttpClient()) {
                        for (int attempt = 0; attempt < 100; attempt++) {
                            try {
                                var response = http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:14445/health/ready"))
                                    .timeout(Duration.ofSeconds(1)).GET().build(), HttpResponse.BodyHandlers.discarding());
                                if (response.statusCode() == 200) return;
                            } catch (java.io.IOException ignored) { }
                            Thread.sleep(200);
                        }
                        throw new IllegalStateException("Fixture Hydra did not become ready");
                    } catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
                }
            });
        hydra.start();
        try (var http = HttpClient.newHttpClient()) {
            var response = http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:14445/admin/clients"))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString("""
                {"client_id":"gitea-fixture","client_secret":"fixture-client-secret",
                 "redirect_uris":["http://localhost:14446/callback"],"grant_types":["authorization_code"],
                 "response_types":["code"],"scope":"openid profile email groups",
                 "token_endpoint_auth_method":"client_secret_basic","subject_type":"public",
                 "metadata":{"iam_login_enabled":true},
                 "backchannel_logout_uri":"http://localhost:14446/backchannel",
                 "backchannel_logout_session_required":true,
                 "post_logout_redirect_uris":["http://localhost:14446/logged-out"]}
                """)).build(), HttpResponse.BodyHandlers.discarding());
            if (response.statusCode() != 201) throw new IllegalStateException("Unable to create fixture client");
            var admin = http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:14445/admin/clients"))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString("""
                {"client_id":"iam-admin-ui","client_name":"IAM 管理","redirect_uris":["https://localhost:18083/console/callback"],
                 "grant_types":["authorization_code"],"response_types":["code"],"scope":"openid groups","audience":["iam-login"],
                 "token_endpoint_auth_method":"none","subject_type":"public","metadata":{"iam_login_enabled":true}}
                """)).build(), HttpResponse.BodyHandlers.discarding());
            if (admin.statusCode() != 201) throw new IllegalStateException("Unable to create fixture admin UI client");
            var offline = http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:14445/admin/clients"))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString("""
                {"client_id":"offline-fixture","client_secret":"fixture-offline-secret",
                 "redirect_uris":["http://localhost:14446/callback"],"grant_types":["authorization_code","refresh_token"],
                 "response_types":["code"],"scope":"openid offline_access","token_endpoint_auth_method":"client_secret_basic",
                 "subject_type":"public","metadata":{"iam_login_enabled":true}}
                """)).build(), HttpResponse.BodyHandlers.discarding());
            if (offline.statusCode() != 201) throw new IllegalStateException("Unable to create fixture offline client");
        } catch (Exception ex) { hydra.stop(); throw new IllegalStateException("Fixture client initialization failed", ex); }
    }
    @Override public void close() { hydra.stop(); }
}
