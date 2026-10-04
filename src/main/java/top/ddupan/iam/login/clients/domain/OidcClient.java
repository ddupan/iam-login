package top.ddupan.iam.login.clients.domain;

import java.net.URI;
import java.util.List;
import java.util.Set;

/**
 * First-party confidential authorization-code client. No caller-controlled grants or metadata.
 * {@code loginEnabled} is required: a request that omits it must not silently disable (or enable) a client.
 */
public record OidcClient(String id, String name, List<String> redirectUris, Set<String> scopes,
        List<String> postLogoutRedirectUris, Boolean loginEnabled) {
    public OidcClient {
        requireId(id);
        if (name == null || name.isBlank() || name.length() > 200) throw new IllegalArgumentException("Invalid name");
        if (redirectUris == null || redirectUris.isEmpty() || redirectUris.size() > 20) throw new IllegalArgumentException("Invalid callbacks");
        redirectUris = List.copyOf(redirectUris);
        // Scopes are delegation, not permission (resources check audience and identity), so any well-formed
        // RFC 6749 scope-token is accepted; openid is required because login is OIDC.
        if (scopes == null || !scopes.contains("openid") || scopes.size() > 50
                || !scopes.stream().allMatch(scope -> scope != null && scope.matches("[\\x21\\x23-\\x5B\\x5D-\\x7E]{1,128}")))
            throw new IllegalArgumentException("Invalid scopes");
        scopes = Set.copyOf(scopes);
        postLogoutRedirectUris = postLogoutRedirectUris == null ? List.of() : List.copyOf(postLogoutRedirectUris);
        if (postLogoutRedirectUris.size() > 20) throw new IllegalArgumentException("Too many logout redirects");
        redirectUris.forEach(OidcClient::requireUri); postLogoutRedirectUris.forEach(OidcClient::requireUri);
        if (loginEnabled == null) throw new IllegalArgumentException("loginEnabled is required");
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
