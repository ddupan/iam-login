package top.ddupan.iam.login.authorization.application;

import java.time.Instant;
import java.util.Set;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authorization.application.port.HydraGateway;
import top.ddupan.iam.login.authorization.domain.AuthorizationRequest;

/** Issuer authorization use case; independent of Servlet and Spring authentication/session state. */
public final class AuthorizeApplication {
    public record AcceptedLogin(String subject, String redirect) { }
    private final AuthorizationPolicy policy;
    private final HydraGateway hydra;
    public AuthorizeApplication(AuthorizationPolicy policy, HydraGateway hydra) {
        this.policy = policy; this.hydra = hydra;
    }
    public AuthorizationRequest start(String challenge) {
        var request = hydra.login(challenge);
        policy.validate(request);
        return request;
    }
    public String subject(User user) { return policy.subject(user); }
    public AcceptedLogin login(AuthorizationRequest expected, String binding, User user, Instant authenticatedAt) {
        var current = hydra.login(expected.challenge());
        sameRequest(expected, current);
        var subject = policy.subject(user);
        if (current.skip() && !subject.equals(current.subject())
                || current.subject() != null && !current.subject().isBlank() && !current.subject().equals(subject)) {
            throw new IllegalArgumentException("Issuer subject mismatch");
        }
        return new AcceptedLogin(subject, hydra.acceptLogin(current.challenge(), subject, binding, authenticatedAt));
    }
    public String consent(AuthorizationRequest expected, String binding, String subject, User user, String challenge) {
        var current = hydra.consent(challenge);
        sameRequest(expected, current);
        if (!subject.equals(current.subject()) || !policy.subject(user).equals(current.subject())
                || !binding.equals(current.binding()) || !expected.challengeDigest().equals(current.loginChallengeDigest())) {
            throw new IllegalArgumentException("Issuer/browser binding mismatch");
        }
        return hydra.acceptConsent(challenge, current.scopes(), policy.claims(user, current));
    }
    private void sameRequest(AuthorizationRequest expected, AuthorizationRequest current) {
        policy.validate(current);
        if (!expected.clientId().equals(current.clientId()) || !Set.copyOf(expected.scopes()).equals(Set.copyOf(current.scopes()))
                || !expected.requestUrl().equals(current.requestUrl())) throw new IllegalArgumentException("Issuer request changed");
    }
}
