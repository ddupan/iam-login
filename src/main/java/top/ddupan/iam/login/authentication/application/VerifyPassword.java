package top.ddupan.iam.login.authentication.application;

import top.ddupan.iam.login.authentication.application.port.PasswordAuthenticator;
import top.ddupan.iam.login.authentication.application.port.PasswordVerificationException;
import top.ddupan.iam.login.authentication.application.port.PasswordVerificationException.Reason;
import top.ddupan.iam.login.authentication.domain.User;

/** Resolves the user through the same authenticated directory connection. */
public final class VerifyPassword {
    private final PasswordAuthenticator authenticator;

    public VerifyPassword(PasswordAuthenticator authenticator) {
        this.authenticator = authenticator;
    }

    public User verify(String username, String password) {
        try (var session = authenticator.authenticate(username, password)) {
            return session.users().findByLoginName(session.loginName())
                .orElseThrow(() -> new PasswordVerificationException(Reason.REJECTED));
        }
    }
}
