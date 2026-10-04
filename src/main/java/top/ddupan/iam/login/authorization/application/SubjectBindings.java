package top.ddupan.iam.login.authorization.application;

import java.util.Map;
import top.ddupan.iam.login.authentication.domain.User;

/**
 * Explicit, reviewed mapping from a stable directory identity to the OIDC subject downstream applications
 * already know. Never inferred from email or username, so renames keep the subject and look-alikes get none.
 */
public final class SubjectBindings {
    private final Map<User.UserId, String> subjects;

    public SubjectBindings(Map<User.UserId, String> subjects) {
        if (subjects == null || subjects.isEmpty() || subjects.values().stream().anyMatch(s -> s == null || s.isBlank())
                || subjects.values().stream().distinct().count() != subjects.size()) {
            throw new IllegalArgumentException("Explicit unique subject bindings are required");
        }
        this.subjects = Map.copyOf(subjects);
    }

    /** @throws IllegalArgumentException when the user has no reviewed binding (or it was withdrawn) */
    public String subject(User user) {
        var subject = subjects.get(user.id());
        if (subject == null) throw new IllegalArgumentException("No reviewed subject binding");
        return subject;
    }
}
