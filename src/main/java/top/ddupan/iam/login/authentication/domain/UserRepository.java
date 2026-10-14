package top.ddupan.iam.login.authentication.domain;

import java.util.Optional;

/** Read-only user collection; directory entries and LDAP types never cross this boundary. */
public interface UserRepository {
    /** The account, read without its owner present, if it still exists and is not disabled. */
    Optional<User> findActive(User.UserId id);

    final class AccessFailure extends RuntimeException {
        public AccessFailure() { super("User repository is unavailable or returned an invalid user"); }
        public AccessFailure(Throwable cause) { super("User repository is unavailable", cause); }
    }
}
