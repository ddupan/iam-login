package top.ddupan.iam.login.clients.domain;

import java.util.List;

/** Client persistence contract. Secrets exist only in create responses. */
public interface ClientRepository {
    record Created(OidcClient client, String secret) {
        @Override public String toString() { return "Created[client=" + client.id() + ", secret=REDACTED]"; }
    }
    List<OidcClient> list(int page, int size);
    OidcClient get(String id);
    Created create(OidcClient client);
    OidcClient update(OidcClient client);
    void delete(String id);
}
