package top.ddupan.iam.login.authentication.infrastructure.security;

import java.util.Optional;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import top.ddupan.iam.login.authentication.domain.User;

/** An immutable directory snapshot; never contains credentials or connections. */
public record DirectoryPrincipal(User user, Bytes credentialUserId)
        implements AuthenticatedPrincipal, PublicKeyCredentialUserEntity {
    public DirectoryPrincipal(User user) { this(user, null); }
    @Override public Bytes getId() { return credentialUserId; }
    @Override public String getDisplayName() { return user.displayName(); }
    @Override
    public String getName() {
        return user.id().authority() + ":" + user.id().value();
    }

    /** The inverse of {@link #getName()}; empty for anything it did not write. */
    public static Optional<User.UserId> userId(String name) {
        int colon = name == null ? -1 : name.indexOf(':');
        if (colon <= 0 || colon == name.length() - 1) return Optional.empty();
        return Optional.of(new User.UserId(name.substring(0, colon), name.substring(colon + 1)));
    }
}
