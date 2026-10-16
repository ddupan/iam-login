package top.ddupan.iam.login.clients.domain;

import java.net.URI;
import java.util.List;
import java.util.Set;

/**
 * First-party authorization-code client. Grants follow from the fields; there is no caller-controlled metadata.
 * {@code loginEnabled} is required: a request that omits it must not silently disable (or enable) a client.
 * {@code pkceRequired} is required for the same reason; turning it off is only for confidential clients that
 * cannot send PKCE (Gitea 1.27 sends neither PKCE nor nonce), which RFC 9700 2.1.1 still permits.
 * <ul>
 * <li>{@code publicClient}: no secret (a CLI, a browser app). PKCE is then mandatory; fixed at creation.</li>
 * <li>{@code deviceAuthorization}: also the device grant (RFC 8628), for clients without a browser.</li>
 * <li>{@code audiences}: extra access-token audiences, for resources that check {@code aud} (Incus).</li>
 * <li>{@code tokenEndpointAuthMethod}: how a confidential client sends its secret, {@code client_secret_basic} unless
 * the application can only send it in the form ({@code client_secret_post}, Artifact Keeper); {@code none} for a public
 * client, whatever was asked.</li>
 * </ul>
 * Who may do what is the resource's decision, from the token's claims; a client admits everyone who can sign in.
 * These are optional so that callers predating them keep working; absent means off / empty / basic.
 */
public record OidcClient(String id, String name, List<String> redirectUris, Set<String> scopes,
        List<String> postLogoutRedirectUris, Boolean loginEnabled, Boolean pkceRequired, Boolean publicClient,
        Boolean deviceAuthorization, List<String> audiences, String tokenEndpointAuthMethod) {
    public static final String CLIENT_SECRET_BASIC = "client_secret_basic";
    public static final String CLIENT_SECRET_POST = "client_secret_post";
    public static final String NONE = "none";

    public OidcClient(String id, String name, List<String> redirectUris, Set<String> scopes,
            List<String> postLogoutRedirectUris, Boolean loginEnabled, Boolean pkceRequired) {
        this(id, name, redirectUris, scopes, postLogoutRedirectUris, loginEnabled, pkceRequired, false, false, List.of());
    }
    public OidcClient(String id, String name, List<String> redirectUris, Set<String> scopes,
            List<String> postLogoutRedirectUris, Boolean loginEnabled, Boolean pkceRequired, Boolean publicClient,
            Boolean deviceAuthorization, List<String> audiences) {
        this(id, name, redirectUris, scopes, postLogoutRedirectUris, loginEnabled, pkceRequired, publicClient,
            deviceAuthorization, audiences, null);
    }

    public OidcClient {
        requireId(id);
        if (name == null || name.isBlank() || name.length() > 200) throw new IllegalArgumentException("Invalid name");
        if (redirectUris == null || redirectUris.isEmpty() || redirectUris.size() > 20) throw new IllegalArgumentException("Invalid callbacks");
        redirectUris = List.copyOf(redirectUris);
        // Scopes are delegation, not permission (resources check audience and identity), so any well-formed
        // RFC 6749 scope-token is accepted; openid is required because login is OIDC.
        if (scopes == null || !scopes.contains("openid")) throw new IllegalArgumentException("Invalid scopes");
        scopes = requireScopes(scopes);
        postLogoutRedirectUris = postLogoutRedirectUris == null ? List.of() : List.copyOf(postLogoutRedirectUris);
        if (postLogoutRedirectUris.size() > 20) throw new IllegalArgumentException("Too many logout redirects");
        redirectUris.forEach(OidcClient::requireUri); postLogoutRedirectUris.forEach(OidcClient::requireUri);
        if (loginEnabled == null) throw new IllegalArgumentException("loginEnabled is required");
        if (pkceRequired == null) throw new IllegalArgumentException("pkceRequired is required");
        publicClient = Boolean.TRUE.equals(publicClient);
        deviceAuthorization = Boolean.TRUE.equals(deviceAuthorization);
        // Without a secret, PKCE is what binds the code to the client that asked for it.
        if (publicClient && !pkceRequired) throw new IllegalArgumentException("Public clients require PKCE");
        audiences = requireAudiences(audiences);
        if (publicClient) {
            if (tokenEndpointAuthMethod != null && !NONE.equals(tokenEndpointAuthMethod)) throw new IllegalArgumentException("Public clients have no secret");
            tokenEndpointAuthMethod = NONE;
        } else {
            if (tokenEndpointAuthMethod == null) tokenEndpointAuthMethod = CLIENT_SECRET_BASIC;
            if (!Set.of(CLIENT_SECRET_BASIC, CLIENT_SECRET_POST).contains(tokenEndpointAuthMethod))
                throw new IllegalArgumentException("Invalid token endpoint authentication method");
        }
    }
    /** Well-formed RFC 6749 scope-tokens, at most 50. */
    static Set<String> requireScopes(Set<String> scopes) {
        if (scopes.size() > 50 || !scopes.stream().allMatch(scope -> scope != null && scope.matches("[\\x21\\x23-\\x5B\\x5D-\\x7E]{1,128}")))
            throw new IllegalArgumentException("Invalid scopes");
        return Set.copyOf(scopes);
    }
    /** At most 10; absent means none. */
    static List<String> requireAudiences(List<String> audiences) {
        audiences = audiences == null ? List.of() : List.copyOf(audiences);
        // Stored comma-separated (RegisteredClients.AUDIENCES).
        if (audiences.size() > 10 || !audiences.stream().allMatch(a -> a != null && !a.isBlank() && a.length() <= 2048
                && !a.contains(",") && a.equals(a.strip()))) throw new IllegalArgumentException("Invalid audiences");
        return audiences;
    }
    public static void requireId(String id) {
        if (id == null || !id.matches("[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}")) throw new IllegalArgumentException("Invalid client ID");
    }
    private static void requireUri(String value) {
        if (value == null || value.length() > 2048 || value.contains("*")) throw new IllegalArgumentException("Invalid URI");
        var uri = URI.create(value);
        if (uri.getHost() == null || uri.getUserInfo() != null || uri.getFragment() != null
                || !("https".equals(uri.getScheme()) || "http".equals(uri.getScheme())
                    && Set.of("localhost", "127.0.0.1", "[::1]").contains(uri.getHost())))
            throw new IllegalArgumentException("HTTPS or loopback callback required");
    }
}
