package top.ddupan.iam.login.authorization.application;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authorization.domain.AuthorizationRequest;

/**
 * Explicit first-party policy; never infers account continuity from email or username.
 * Scopes are delegation, not permission: this policy only releases identity facts (such as groups);
 * each resource decides what those facts allow, after checking the token's audience is itself.
 */
public final class AuthorizationPolicy {
    private final Set<String> clients;
    private final Map<User.UserId, String> subjects;

    public AuthorizationPolicy(Set<String> clients, Map<User.UserId, String> subjects) {
        this.clients = clients == null ? Set.of() : Set.copyOf(clients);
        this.subjects = Map.copyOf(subjects);
        if (subjects.isEmpty() || subjects.values().stream().anyMatch(s -> s == null || s.isBlank())
                || subjects.values().stream().distinct().count() != subjects.size()) {
            throw new IllegalArgumentException("Explicit unique subject bindings and clients are required");
        }
    }

    // Hydra already limits scopes and audiences to what the client is registered for.
    public void validate(AuthorizationRequest request) {
        if (!(request.loginEnabled() == null ? clients.contains(request.clientId()) : request.loginEnabled())
                || !request.scopes().contains("openid")) {
            throw new IllegalArgumentException("Authorization request is outside configured policy");
        }
    }

    public String subject(User user) {
        var subject = subjects.get(user.id());
        if (subject == null) throw new IllegalArgumentException("No reviewed subject binding");
        return subject;
    }

    public Map<String, Object> claims(User user, AuthorizationRequest request) {
        validate(request);
        var claims = new LinkedHashMap<String, Object>();
        if (request.scopes().contains("profile")) {
            claims.put("preferred_username", user.username());
            claims.put("name", user.displayName());
        }
        if (request.scopes().contains("email") && !user.email().isBlank()) {
            claims.put("email", user.email());
            // AD mail is a directory attribute, not evidence of mailbox verification.
            claims.put("email_verified", false);
        }
        if (request.scopes().contains("groups")) {
            claims.put("groups", user.memberships().stream().map(User.GroupMembership::name).toList());
        }
        return Map.copyOf(claims);
    }

    /** Identity facts for resource servers, which see the access token (via introspection), not the ID token. */
    public Map<String, Object> accessTokenClaims(User user, AuthorizationRequest request) {
        validate(request);
        return request.scopes().contains("groups")
            ? Map.of("groups", user.memberships().stream().map(User.GroupMembership::name).toList()) : Map.of();
    }
}
