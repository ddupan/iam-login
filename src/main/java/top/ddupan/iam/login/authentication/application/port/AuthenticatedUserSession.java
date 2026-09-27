package top.ddupan.iam.login.authentication.application.port;

import top.ddupan.iam.login.authentication.domain.UserRepository;

/** Uses the authenticated user's connection, without exposing connection or credential objects. */
public interface AuthenticatedUserSession extends AutoCloseable {
    String loginName();
    UserRepository users();
    @Override void close();
}
