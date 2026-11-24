package top.ddupan.iam.login.clients.domain;

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import org.jspecify.annotations.Nullable;

/**
 * A workload that authenticates with its SPIFFE JWT-SVID (draft-ietf-oauth-spiffe-client-auth) and gets
 * {@code client_credentials} tokens for itself; no secret, no browser, no user. {@code spiffeId} is the client
 * metadata of the same name (5.1): exact, or ending in {@code /*} for every workload under that path.
 * {@code enabled} is required for the same reason as {@link OidcClient#loginEnabled()}.
 */
public record MachineClient(String id, String name, String spiffeId, Set<String> scopes, List<String> audiences,
        Boolean enabled) {
    /** SPIFFE ID: scheme, trust domain, then segments that are neither empty, "." nor "..". */
    private static final Pattern SPIFFE_ID = Pattern.compile("spiffe://([a-z0-9._-]+)((?:/[A-Za-z0-9._-]+)*)");

    public MachineClient {
        OidcClient.requireId(id);
        if (name == null || name.isBlank() || name.length() > 200) throw new IllegalArgumentException("Invalid name");
        if (spiffeId == null || trustDomain(spiffeId.endsWith("/*") ? spiffeId.substring(0, spiffeId.length() - 2) : spiffeId) == null)
            throw new IllegalArgumentException("Invalid SPIFFE ID");
        scopes = OidcClient.requireScopes(scopes == null ? Set.of() : scopes);
        audiences = OidcClient.requireAudiences(audiences);
        if (enabled == null) throw new IllegalArgumentException("enabled is required");
    }

    /** The trust domain of a well-formed SPIFFE ID, or null. */
    public static @Nullable String trustDomain(@Nullable String spiffeId) {
        if (spiffeId == null || spiffeId.length() > 2048) return null;
        var match = SPIFFE_ID.matcher(spiffeId);
        if (!match.matches()) return null;
        for (var segment : match.group(2).split("/", -1)) if (segment.equals(".") || segment.equals("..")) return null;
        return match.group(1);
    }
}
