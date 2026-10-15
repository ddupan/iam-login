package top.ddupan.iam.login.authentication.domain;

import java.util.Optional;

/** Read-only user collection; directory entries and LDAP types never cross this boundary. */
public interface UserRepository {
    /** Without a directory: nothing can vouch for an account. */
    UserRepository NONE = new UserRepository() {
        @Override public Optional<User> findActive(User.UserId id) { return Optional.empty(); }
        @Override public Optional<User> findActive(String username) { return Optional.empty(); }
    };

    /** The account, read without its owner present, if it still exists and is not disabled. */
    Optional<User> findActive(User.UserId id);

    /** The same, by sign-in name, for an administrator looking an account up. */
    Optional<User> findActive(String username);

    final class AccessFailure extends RuntimeException {
        public AccessFailure() { super("User repository is unavailable or returned an invalid user"); }
        public AccessFailure(Throwable cause) { super("User repository is unavailable", cause); }
    }
}
