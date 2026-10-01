package top.ddupan.iam.login.configuration;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import top.ddupan.iam.login.authentication.domain.User;

/** Jackson mappings kept out of the domain: the directory snapshot stored with an authorization. */
final class PrincipalJson {
    private PrincipalJson() { }

    /** The concrete types List.copyOf produces, which default typing records for the memberships list. */
    static Class<?>[] immutableLists() {
        return new Class<?>[] {List.of().getClass(), List.of(1).getClass(), List.of(1, 2, 3).getClass()};
    }

    abstract static class UserMixin {
        @JsonCreator UserMixin(@JsonProperty("id") User.UserId id, @JsonProperty("username") String username,
                @JsonProperty("displayName") String displayName, @JsonProperty("email") String email,
                @JsonProperty("memberships") List<User.GroupMembership> memberships) { }
        @JsonProperty("id") abstract User.UserId id();
        @JsonProperty("username") abstract String username();
        @JsonProperty("displayName") abstract String displayName();
        @JsonProperty("email") abstract String email();
        @JsonProperty("memberships") abstract List<User.GroupMembership> memberships();
    }

    // Derived accessors from the WebAuthn user-entity interface are recomputed, not stored.
    @JsonIgnoreProperties(value = {"name", "displayName", "id"}, ignoreUnknown = true)
    abstract static class DirectoryPrincipalMixin { }
}
