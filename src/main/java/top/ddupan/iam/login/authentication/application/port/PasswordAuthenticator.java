package top.ddupan.iam.login.authentication.application.port;

/** Password authentication opens a short-lived user repository scope. */
public interface PasswordAuthenticator {
    AuthenticatedUserSession authenticate(String username, String password);
}
