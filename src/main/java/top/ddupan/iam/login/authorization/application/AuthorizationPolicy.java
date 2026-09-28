package top.ddupan.iam.login.authorization.application;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authorization.domain.AuthorizationRequest;

/** Explicit first-party policy; never infers account continuity from email or username. */
public final class AuthorizationPolicy {
    private static final Set<String> SCOPES = Set.of("openid", "profile", "email", "groups");
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

    public void validate(AuthorizationRequest request) {
        if (!(request.loginEnabled() == null ? clients.contains(request.clientId()) : request.loginEnabled()) || !request.audience().isEmpty()
                || !request.scopes().contains("openid") || !SCOPES.containsAll(request.scopes())) {
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
}
