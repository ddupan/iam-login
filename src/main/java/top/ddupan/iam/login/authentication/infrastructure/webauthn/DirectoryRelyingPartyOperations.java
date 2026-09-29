package top.ddupan.iam.login.authentication.infrastructure.webauthn;

import top.ddupan.iam.login.authentication.infrastructure.persistence.JdbcCredentialRegistration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.webauthn.api.*;
import org.springframework.security.web.webauthn.management.*;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;

/** Adds directory ownership/enrollment policy; verification and storage remain upstream implementations. */
public final class DirectoryRelyingPartyOperations implements WebAuthnRelyingPartyOperations {
    private final WebAuthnRelyingPartyOperations delegate;
    private final MfaPolicy policy;
    private final PublicKeyCredentialUserEntityRepository users;
    private final UserCredentialRepository credentials;
    private final JdbcCredentialRegistration registrations;

    public DirectoryRelyingPartyOperations(WebAuthnRelyingPartyOperations delegate, MfaPolicy policy,
            PublicKeyCredentialUserEntityRepository users, UserCredentialRepository credentials,
            JdbcCredentialRegistration registrations) {
        this.delegate = delegate;
        this.policy = policy;
        this.users = users;
        this.credentials = credentials;
        this.registrations = registrations;
    }

    @Override
    public PublicKeyCredentialCreationOptions createPublicKeyCredentialCreationOptions(
            PublicKeyCredentialCreationOptionsRequest request) {
        policy.current();
        policy.requireEnrollment(request.getAuthentication());
        return delegate.createPublicKeyCredentialCreationOptions(request);
    }

    @Override
    public CredentialRecord registerCredential(RelyingPartyRegistrationRequest request) {
        var principal = policy.current();
        var owner = request.getCreationOptions().getUser();
        if (!principal.getName().equals(owner.getName())) throw new AccessDeniedException("Credential owner mismatch");
        return registrations.register(owner.getId().toBase64UrlString(), () -> {
            policy.requireEnrollment(SecurityContextHolder.getContext().getAuthentication());
            return delegate.registerCredential(request);
        });
    }

    @Override
    public PublicKeyCredentialRequestOptions createCredentialRequestOptions(PublicKeyCredentialRequestOptionsRequest request) {
        policy.current();
        return delegate.createCredentialRequestOptions(request);
    }

    @Override
    public PublicKeyCredentialUserEntity authenticate(RelyingPartyAuthenticationRequest request) {
        var principal = policy.current();
        var owner = users.findByUsername(principal.getName());
        var credential = credentials.findByCredentialId(request.getPublicKey().getRawId());
        if (owner == null || credential == null || !owner.getId().equals(credential.getUserEntityUserId())) {
            throw new AccessDeniedException("Credential owner mismatch");
        }
        var verified = delegate.authenticate(request);
        if (!verified.getName().equals(principal.getName())) throw new AccessDeniedException("Credential owner mismatch");
        return new DirectoryPrincipal(principal.user(), verified.getId());
    }
}
