package top.ddupan.iam.login.authentication.domain;

import java.util.List;
import java.util.Objects;

/** Directory-owned user aggregate. Identity is stable while profile and membership may change. */
public final class User {
    private final UserId id;
    private final String username;
    private final String displayName;
    private final String email;
    private final List<GroupMembership> memberships;

    public User(UserId id, String username, String displayName, String email, List<GroupMembership> memberships) {
        this.id = Objects.requireNonNull(id);
        if (username == null || username.isBlank()) throw new IllegalArgumentException("Missing username");
        this.username = username;
        this.displayName = Objects.requireNonNull(displayName);
        this.email = Objects.requireNonNull(email);
        this.memberships = List.copyOf(memberships);
    }

    public UserId id() { return id; }
    public String username() { return username; }
    public String displayName() { return displayName; }
    public String email() { return email; }
    public List<GroupMembership> memberships() { return memberships; }

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
