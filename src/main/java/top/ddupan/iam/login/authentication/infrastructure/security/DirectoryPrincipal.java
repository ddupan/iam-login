package top.ddupan.iam.login.authentication.infrastructure.security;

import org.springframework.security.core.AuthenticatedPrincipal;
import top.ddupan.iam.login.authentication.domain.User;

/** An immutable directory snapshot; never contains credentials or connections. */
public record DirectoryPrincipal(User user) implements AuthenticatedPrincipal {
    @Override
    public String getName() {
        return user.id().authority() + ":" + user.id().value();
    }
}
