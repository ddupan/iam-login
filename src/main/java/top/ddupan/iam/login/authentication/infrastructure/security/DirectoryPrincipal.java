package top.ddupan.iam.login.authentication.infrastructure.security;

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
}
