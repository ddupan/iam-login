package top.ddupan.iam.login.authentication.interfaces.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.util.Map;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import top.ddupan.iam.login.authentication.domain.User.GroupMembership;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;
import top.ddupan.iam.login.authentication.infrastructure.webauthn.MfaPolicy;

/** Renders Spring Security's login pages; form processing belongs to the security filters. */
@RestController
@ConditionalOnProperty(prefix = "iam.ad", name = "enabled", havingValue = "true")
public class SignInController {
    private final PageRenderer renderer;
    private final ObjectProvider<MfaPolicy> policies;
    private final ObjectProvider<RegisteredClientRepository> clients;

    public SignInController(PageRenderer renderer, ObjectProvider<MfaPolicy> policies,
            ObjectProvider<RegisteredClientRepository> clients) {
        this.renderer = renderer;
        this.policies = policies;
        this.clients = clients;
    }

    @GetMapping(value = "/signin", produces = MediaType.TEXT_HTML_VALUE)
    ResponseEntity<String> page(@RequestParam(required = false) String error, CsrfToken csrf,
            HttpServletRequest request, HttpServletResponse response) {
        return renderer.render(Map.of("step", "password", "name", "", "app", app(request, response),
            // A code, not a sentence: the page translates it into the browser's language.
            "error", error == null ? "" : switch (error) {
                case "unavailable", "throttled" -> error;
                default -> "invalid";
            },
            "action", "/signin/password", "csrf", csrf(csrf)));
    }

    @GetMapping(value = "/signin/mfa", produces = MediaType.TEXT_HTML_VALUE)
    ResponseEntity<String> pending(@AuthenticationPrincipal DirectoryPrincipal principal, CsrfToken csrf,
            HttpServletRequest request, HttpServletResponse response) {
        var policy = policies.getIfAvailable();
        return identity(principal, csrf, "mfa-pending", policy == null ? "unavailable"
            : policy.enrolled(principal.getName()) ? "authenticate" : "register", app(request, response));
    }

    @GetMapping(value = "/signin/complete", produces = MediaType.TEXT_HTML_VALUE)
    ResponseEntity<String> complete(@AuthenticationPrincipal DirectoryPrincipal principal, CsrfToken csrf,
            HttpServletRequest request, HttpServletResponse response) {
        // An authorization request interrupted for login resumes here.
        var cache = new HttpSessionRequestCache();
        var saved = cache.getRequest(request, response);
        if (saved != null) {
            cache.removeRequest(request, response);
            return ResponseEntity.status(303).header("Cache-Control", "no-store").location(URI.create(saved.getRedirectUrl())).build();
        }
        return identity(principal, csrf, "mfa-complete", "authenticate", "");
    }

    private ResponseEntity<String> identity(DirectoryPrincipal principal, CsrfToken csrf, String step, String passkey,
            String app) {
        var user = principal.user();
        return renderer.render(Map.of("step", step, "passkey", passkey, "name", user.displayName(), "app", app,
            "error", "", "action", "/signin/restart", "csrf", csrf(csrf),
            "identity", Map.of("username", user.username(), "subjectId", user.id().value(),
                "email", user.email(),
                "groups", user.memberships().stream().map(GroupMembership::name).toList(),
                "groupDns", user.memberships().stream().map(GroupMembership::externalId).toList())));
    }

    /** Name of the application whose authorization request was interrupted for login, or "". */
    private String app(HttpServletRequest request, HttpServletResponse response) {
        var repository = clients.getIfAvailable();
        var saved = new HttpSessionRequestCache().getRequest(request, response);
        if (repository == null || saved == null) return "";
        var clientId = saved.getParameterValues("client_id");
        if (clientId == null || clientId.length != 1) return "";
        var client = repository.findByClientId(clientId[0]);
        return client == null ? "" : client.getClientName();
    }

    private static Map<String, String> csrf(CsrfToken token) {
        return Map.of("name", token.getParameterName(), "value", token.getToken(), "headerName", token.getHeaderName());
    }
}
