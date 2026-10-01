package top.ddupan.iam.login.authentication.interfaces.web;

import java.util.Map;
import org.springframework.beans.factory.ObjectProvider;
import top.ddupan.iam.login.authentication.infrastructure.webauthn.MfaPolicy;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import top.ddupan.iam.login.authentication.domain.User.GroupMembership;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;

/** Renders Spring Security's login pages; form processing belongs to the security filters. */
@RestController
@ConditionalOnProperty(prefix = "iam.ad", name = "enabled", havingValue = "true")
public class SignInController {
    private final PageRenderer renderer;
    private final ObjectProvider<MfaPolicy> policies;

    private final ObjectProvider<top.ddupan.iam.login.authorization.application.port.HydraGateway> logout;
    public SignInController(PageRenderer renderer, ObjectProvider<MfaPolicy> policies,
            ObjectProvider<top.ddupan.iam.login.authorization.application.port.HydraGateway> logout) {
        this.logout=logout;
        this.renderer = renderer;
        this.policies = policies;
    }

    @GetMapping(value = "/signin", produces = MediaType.TEXT_HTML_VALUE)
    ResponseEntity<String> page(@RequestParam(required = false) String error, CsrfToken csrf) {
        return renderer.render(Map.of("step", "password", "name", "",
            "error", error == null ? "" : "无法验证账号，请检查凭据与账号状态，或稍后重试。",
            "action", "/signin/password", "csrf", csrf(csrf)));
    }

    @GetMapping(value = "/signin/mfa", produces = MediaType.TEXT_HTML_VALUE)
    ResponseEntity<String> pending(@AuthenticationPrincipal DirectoryPrincipal principal, CsrfToken csrf) {
        var policy = policies.getIfAvailable();
        return identity(principal, csrf, "mfa-pending", policy == null ? "unavailable"
            : policy.enrolled(principal.getName()) ? "authenticate" : "register");
    }

    @GetMapping(value = "/signin/complete", produces = MediaType.TEXT_HTML_VALUE)
    ResponseEntity<String> complete(@AuthenticationPrincipal DirectoryPrincipal principal, CsrfToken csrf,
            jakarta.servlet.http.HttpServletRequest request, jakarta.servlet.http.HttpServletResponse response) {
        // An authorization request interrupted for login (in-process authorization server) resumes here.
        var cache = new org.springframework.security.web.savedrequest.HttpSessionRequestCache();
        var saved = cache.getRequest(request, response);
        if (saved != null) {
            cache.removeRequest(request, response);
            return ResponseEntity.status(303).header("Cache-Control", "no-store").location(java.net.URI.create(saved.getRedirectUrl())).build();
        }
        if (top.ddupan.iam.login.authorization.interfaces.web.HydraBrowserRequests.pending(request)) {
            return ResponseEntity.status(303).header("Cache-Control", "no-store").location(java.net.URI.create("/oauth2/login")).build();
        }
        return identity(principal, csrf, "mfa-complete", "authenticate");
    }

    private ResponseEntity<String> identity(DirectoryPrincipal principal, CsrfToken csrf, String step, String passkey) {
        var user = principal.user();
        var page = renderer.render(Map.of("step", step, "passkey", passkey, "name", user.displayName(),
            "error", "", "action", "/signin/restart", "logoutAction", logout.getIfAvailable()==null ? "" : "/signin/logout", "csrf", csrf(csrf),
            "identity", Map.of("username", user.username(), "subjectId", user.id().value(),
                "email", user.email(),
                "groups", user.memberships().stream().map(GroupMembership::name).toList(),
                "groupDns", user.memberships().stream().map(GroupMembership::externalId).toList())));
        var gateway = logout.getIfAvailable();
        if (gateway == null) return page;
        var uri = java.net.URI.create(gateway.logoutUrl());
        return ResponseEntity.ok().headers(page.getHeaders()).header("Content-Security-Policy",
            PageRenderer.CONTENT_SECURITY_POLICY.replace("form-action 'self'",
                "form-action 'self' " + uri.getScheme() + "://" + uri.getRawAuthority())).body(page.getBody());
    }

    private static Map<String, String> csrf(CsrfToken token) {
        return Map.of("name", token.getParameterName(), "value", token.getToken(), "headerName", token.getHeaderName());
    }
}
