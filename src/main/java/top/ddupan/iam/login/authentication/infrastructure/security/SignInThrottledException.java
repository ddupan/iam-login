package top.ddupan.iam.login.authentication.infrastructure.security;

import org.springframework.security.core.AuthenticationException;

/** Too many failed attempts; the directory was not asked. */
public final class SignInThrottledException extends AuthenticationException {
    public SignInThrottledException() {
        super("Too many failed attempts");
    }
}
