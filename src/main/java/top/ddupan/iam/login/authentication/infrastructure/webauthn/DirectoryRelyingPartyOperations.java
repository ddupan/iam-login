package top.ddupan.iam.login.authentication.infrastructure.webauthn;

import top.ddupan.iam.login.authentication.infrastructure.persistence.CredentialRegistration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.webauthn.api.*;
import org.springframework.security.web.webauthn.management.*;
import top.ddupan.iam.login.authentication.domain.UserRepository;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;

/**
 * Adds directory ownership/enrollment policy; verification and storage remain upstream implementations.
 * <p>
 * Assertions come in two kinds, told apart by the session (MfaPolicy.secondStep): the second step after a fresh
 * password, where only that account's passkeys count, and a passwordless sign-in, where the verified passkey
 * names its account. Either way the account is read from the directory, so a disabled one cannot sign in.
 */
public final class DirectoryRelyingPartyOperations implements WebAuthnRelyingPartyOperations {
    private final WebAuthnRelyingPartyOperations delegate;
    private final MfaPolicy policy;
    private final PublicKeyCredentialUserEntityRepository users;
    private final UserCredentialRepository credentials;
    private final CredentialRegistration registrations;
    private final UserRepository directory;

    public DirectoryRelyingPartyOperations(WebAuthnRelyingPartyOperations delegate, MfaPolicy policy,
            PublicKeyCredentialUserEntityRepository users, UserCredentialRepository credentials,
            CredentialRegistration registrations, UserRepository directory) {
        this.delegate = delegate;
        this.policy = policy;
        this.users = users;
        this.credentials = credentials;
        this.registrations = registrations;
        this.directory = directory;
    }

    @Override
    public PublicKeyCredentialCreationOptions createPublicKeyCredentialCreationOptions(
            PublicKeyCredentialCreationOptionsRequest request) {
        policy.signedIn();
        policy.requireEnrollment(request.getAuthentication());
        return delegate.createPublicKeyCredentialCreationOptions(request);
    }

    @Override
    public CredentialRecord registerCredential(RelyingPartyRegistrationRequest request) {
        var principal = policy.signedIn();
        var owner = request.getCreationOptions().getUser();
        if (!principal.getName().equals(owner.getName())) throw new AccessDeniedException("Credential owner mismatch");
        return registrations.register(owner.getName(), () -> {
            policy.requireEnrollment(SecurityContextHolder.getContext().getAuthentication());
            return delegate.registerCredential(request);
        });
    }

    @Override
    public PublicKeyCredentialRequestOptions createCredentialRequestOptions(PublicKeyCredentialRequestOptionsRequest request) {
        // Second step: this account's passkeys. Passwordless: none listed (null authentication), so the browser
        // offers every passkey it holds for this site.
        return delegate.createCredentialRequestOptions(policy.secondStep().isPresent() ? request
            : new ImmutablePublicKeyCredentialRequestOptionsRequest(null));
    }

    @Override
    public PublicKeyCredentialUserEntity authenticate(RelyingPartyAuthenticationRequest request) {
        var secondStep = policy.secondStep();
        if (secondStep.isPresent()) {
            var principal = secondStep.get();
            var owner = users.findByUsername(principal.getName());
            var credential = credentials.findByCredentialId(request.getPublicKey().getRawId());
            if (owner == null || credential == null || !owner.getId().equals(credential.getUserEntityUserId())) {
                throw new AccessDeniedException("Credential owner mismatch");
            }
        }
        var verified = delegate.authenticate(request);
        if (secondStep.isPresent()) {
            var principal = secondStep.get();
            if (!verified.getName().equals(principal.getName())) throw new AccessDeniedException("Credential owner mismatch");
            return new DirectoryPrincipal(principal.user(), verified.getId());
        }
        // Passwordless: the verified passkey's owner, as the directory has it now. Its name is what DirectoryPrincipal
        // wrote at registration (authority:objectGUID), so a renamed account is still found.
        var user = DirectoryPrincipal.userId(verified.getName()).flatMap(directory::findActive)
            .orElseThrow(() -> new DisabledException("Account not active in the directory"));
        return new DirectoryPrincipal(user, verified.getId());
    }
}
