package top.ddupan.iam.login.clients.application;

import java.util.List;
import top.ddupan.iam.login.clients.domain.OidcClient;

/** Hydra is the sole persistence authority. Secrets exist only in create/rotate responses. */
public interface ClientRegistry {
    record Created(OidcClient client, String secret) {
        @Override public String toString() { return "Created[client=" + client.id() + ", secret=REDACTED]"; }
    }
    List<OidcClient> list(int page, int size);
    OidcClient get(String id);
    Created create(OidcClient client);
    OidcClient update(OidcClient client);
    void delete(String id);
}
