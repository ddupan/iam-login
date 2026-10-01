package top.ddupan.iam.login.clients.infrastructure;

import java.util.*;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.web.client.RestClient;
import top.ddupan.iam.login.clients.domain.*;
import top.ddupan.iam.login.clients.domain.OidcClient;

public final class HydraClientRepository implements ClientRepository {
    public static final String ENABLED = "iam_login_enabled";
    private static final ParameterizedTypeReference<Map<String,Object>> OBJECT = new ParameterizedTypeReference<>() {};
    private static final ParameterizedTypeReference<List<Map<String,Object>>> ARRAY = new ParameterizedTypeReference<>() {};
    private static final java.security.SecureRandom RANDOM = new java.security.SecureRandom();
    private static final Base64.Encoder SECRETS = Base64.getUrlEncoder().withoutPadding();
    private final RestClient http;
    public HydraClientRepository(RestClient client) {
        http = client.mutate()
            .defaultStatusHandler(status -> !status.is2xxSuccessful(), (request, response) -> {
                throw new ClientRepositoryException(switch (response.getStatusCode().value()) {
                    case 404 -> ClientRepositoryException.Kind.NOT_FOUND;
                    case 400, 409 -> ClientRepositoryException.Kind.CONFLICT;
                    default -> ClientRepositoryException.Kind.UNAVAILABLE;
                });
            }).build();
    }
    private <T> T call(java.util.function.Supplier<T> operation) {
        try { return operation.get(); }
        catch (ClientRepositoryException ex) { throw ex; }
        catch (RuntimeException ex) { throw new ClientRepositoryException(ClientRepositoryException.Kind.UNAVAILABLE); }
    }
    @Override public List<OidcClient> list(int page, int size) {
        if (page < 0 || size < 1 || size > 100) throw new IllegalArgumentException("Invalid pagination");
        return call(() -> Objects.requireNonNull(http.get().uri(b -> b.path("/admin/clients")
            .queryParam("page", page).queryParam("page_size", size).build()).retrieve().body(ARRAY))
            .stream().filter(this::supported).map(this::view).toList());
    }
    private Map<String,Object> read(String id) {
        OidcClient.requireId(id);
        return Objects.requireNonNull(http.get().uri("/admin/clients/{id}", id).retrieve().body(OBJECT));
    }
    @Override public OidcClient get(String id) { return call(() -> view(read(id))); }
    @Override public Created create(OidcClient client) {
        return call(() -> {
            var result = Objects.requireNonNull(http.post().uri("/admin/clients").body(payload(client))
                .retrieve().body(OBJECT));
            return new Created(view(result), Objects.toString(result.get("client_secret"), ""));
        });
    }
    @Override public OidcClient update(OidcClient client) {
        return call(() -> {
            var previous = read(client.id());
            if (!supported(previous)) throw new ClientRepositoryException(ClientRepositoryException.Kind.CONFLICT);
            // Preserve issuer-owned fields and metadata, but never send back a stored secret/hash.
            var update = new LinkedHashMap<>(previous); update.remove("client_secret");
            var metadata = new LinkedHashMap<String,Object>();
            if (previous.get("metadata") instanceof Map<?,?> map) map.forEach((k,v) -> metadata.put(k.toString(),v));
            if (client.loginEnabled() == null) metadata.remove(ENABLED); else metadata.put(ENABLED, client.loginEnabled());
            update.putAll(payload(client)); update.put("metadata", metadata);
            return view(Objects.requireNonNull(http.put().uri("/admin/clients/{id}", client.id())
                .body(update).retrieve().body(OBJECT)));
        });
    }
    @Override public String rotateSecret(String id) {
        return call(() -> {
            var current = read(id);
            if (!supported(current)) throw new ClientRepositoryException(ClientRepositoryException.Kind.CONFLICT);
            // ponytail: hard cut-over via PUT. Hydra master has POST /secrets/rotate with a grace period,
            // but no release ships it yet (v26.2.0); switch here once one does.
            var secret = SECRETS.encodeToString(randomBytes());
            var update = new LinkedHashMap<>(current); update.put("client_secret", secret);
            http.put().uri("/admin/clients/{id}", id).body(update).retrieve().toBodilessEntity();
            return secret;
        });
    }
    private static byte[] randomBytes() { var bytes = new byte[32]; RANDOM.nextBytes(bytes); return bytes; }
    @Override public void delete(String id) {
        OidcClient.requireId(id);
        call(() -> { http.delete().uri("/admin/clients/{id}",id).retrieve().toBodilessEntity(); return null; });
    }
    private boolean supported(Map<String,Object> data) {
        return List.of("authorization_code").equals(data.get("grant_types"))
            && "client_secret_basic".equals(data.get("token_endpoint_auth_method"));
    }
    private Map<String,Object> payload(OidcClient c) {
        var map = new LinkedHashMap<String,Object>();
        map.put("client_id",c.id()); map.put("client_name",c.name()); map.put("redirect_uris",c.redirectUris());
        map.put("scope",String.join(" ",new TreeSet<>(c.scopes())));
        map.put("grant_types",List.of("authorization_code")); map.put("response_types",List.of("code"));
        map.put("token_endpoint_auth_method","client_secret_basic"); map.put("subject_type","public");
        map.put("post_logout_redirect_uris",c.postLogoutRedirectUris());
        map.put("backchannel_logout_uri",c.backchannelLogoutUri());
        map.put("backchannel_logout_session_required",true);
        map.put("frontchannel_logout_uri",c.frontchannelLogoutUri());
        map.put("frontchannel_logout_session_required",true);
        if (c.loginEnabled() != null) map.put("metadata",Map.of(ENABLED,c.loginEnabled()));
        return map;
    }
    @SuppressWarnings("unchecked") private OidcClient view(Map<String,Object> m) {
        if (!supported(m)) throw new ClientRepositoryException(ClientRepositoryException.Kind.CONFLICT);
        String id = (String)m.get("client_id");
        String name = Objects.toString(m.get("client_name"),"");
        return new OidcClient(id, name.isBlank() ? id : name,
            (List<String>)m.get("redirect_uris"),new HashSet<>(Arrays.asList(Objects.toString(m.get("scope"),"").split(" +"))),
            (List<String>)m.get("post_logout_redirect_uris"),(String)m.get("backchannel_logout_uri"),
            (String)m.get("frontchannel_logout_uri"),m.get("metadata") instanceof Map<?,?> meta && meta.get(ENABLED) instanceof Boolean b ? b : null);
    }
}
