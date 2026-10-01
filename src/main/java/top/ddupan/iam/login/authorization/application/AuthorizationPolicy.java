package top.ddupan.iam.login.authorization.application;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authorization.domain.AuthorizationRequest;

/** Explicit first-party policy; never infers account continuity from email or username. */
public final class AuthorizationPolicy {
    private static final Set<String> SCOPES = Set.of("openid", "profile", "email", "groups");
    /** Grants the client-management API. Decided here, at consent, so the API only checks the scope. */
    public static final String MANAGE_CLIENTS = "iam.clients.manage";
    private final Set<String> clients;
    private final Map<User.UserId, String> subjects;
    private final String managementClient;
    private final Predicate<User> administrator;

    public AuthorizationPolicy(Set<String> clients, Map<User.UserId, String> subjects) {
        this(clients, subjects, null, user -> false);
    }

    public AuthorizationPolicy(Set<String> clients, Map<User.UserId, String> subjects,
            String managementClient, Predicate<User> administrator) {
        this.clients = clients == null ? Set.of() : Set.copyOf(clients);
        this.subjects = Map.copyOf(subjects);
        this.managementClient = managementClient;
        this.administrator = administrator;
        if (subjects.isEmpty() || subjects.values().stream().anyMatch(s -> s == null || s.isBlank())
                || subjects.values().stream().distinct().count() != subjects.size()) {
            throw new IllegalArgumentException("Explicit unique subject bindings and clients are required");
        }
    }

    public void validate(AuthorizationRequest request) {
        if (!(request.loginEnabled() == null ? clients.contains(request.clientId()) : request.loginEnabled()) || !request.audience().isEmpty()
                || !request.scopes().contains("openid") || !request.scopes().stream().allMatch(scope ->
                    SCOPES.contains(scope) || MANAGE_CLIENTS.equals(scope) && request.clientId().equals(managementClient))) {
            throw new IllegalArgumentException("Authorization request is outside configured policy");
        }
    }

    /** Per-user part of the policy; only direct administrators may receive the management scope. */
    public void permit(User user, AuthorizationRequest request) {
        validate(request);
        if (request.scopes().contains(MANAGE_CLIENTS) && !administrator.test(user)) {
            throw new IllegalArgumentException("Management scope requires a direct administrator");
        }
    }

    public String subject(User user) {
        var subject = subjects.get(user.id());
        if (subject == null) throw new IllegalArgumentException("No reviewed subject binding");
        return subject;
    }

    public Map<String, Object> claims(User user, AuthorizationRequest request) {
        permit(user, request);
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
