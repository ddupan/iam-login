package top.ddupan.iam.login.authentication.domain;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Directory-owned user aggregate. Identity is stable while profile and membership may change. */
public final class User {
    private final UserId id;
    private final String username;
    private final String displayName;
    private final String email;
    private final List<GroupMembership> memberships;
    private final Instant passwordChangedAt;

    /** Without the password's change time; also how a user comes back out of a stored session. */
    public User(UserId id, String username, String displayName, String email, List<GroupMembership> memberships) {
        this(id, username, displayName, email, memberships, null);
    }

    /**
     * {@code passwordChangedAt} is null when unknown. {@link Instant#MAX} means the password must be changed before
     * it can be used again, so no earlier sign-in with it still counts.
     */
    public User(UserId id, String username, String displayName, String email, List<GroupMembership> memberships,
            Instant passwordChangedAt) {
        this.id = Objects.requireNonNull(id);
        if (username == null || username.isBlank()) throw new IllegalArgumentException("Missing username");
        this.username = username;
        this.displayName = Objects.requireNonNull(displayName);
        this.email = Objects.requireNonNull(email);
        this.memberships = List.copyOf(memberships);
        this.passwordChangedAt = passwordChangedAt;
    }

    public UserId id() { return id; }
    public String username() { return username; }
    public String displayName() { return displayName; }
    public String email() { return email; }
    public List<GroupMembership> memberships() { return memberships; }
    /** Read from the directory each time; not kept in the session (PrincipalJson). */
    public Optional<Instant> passwordChangedAt() { return Optional.ofNullable(passwordChangedAt); }

    @Override public boolean equals(Object other) { return other instanceof User user && id.equals(user.id); }
    @Override public int hashCode() { return id.hashCode(); }

    public record UserId(String authority, String value) {
        public UserId {
            if (authority == null || authority.isBlank() || value == null || value.isBlank()) {
                throw new IllegalArgumentException("Missing user identifier");
            }
        }
    }

    /** External group identifiers are opaque to the domain. */
    public record GroupMembership(String name, String externalId) {
        public GroupMembership {
            if (name == null || name.isBlank() || externalId == null || externalId.isBlank()) {
                throw new IllegalArgumentException("Missing group identifier");
            }
        }
    }
}
