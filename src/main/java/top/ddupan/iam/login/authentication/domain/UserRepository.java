package top.ddupan.iam.login.authentication.domain;

import java.util.Optional;

/** Read-only user collection; directory entries and LDAP types never cross this boundary. */
public interface UserRepository {
    Optional<User> findByLoginName(String loginName);

    final class AccessFailure extends RuntimeException {
        public AccessFailure() { super("User repository is unavailable or returned an invalid user"); }
    }
}
