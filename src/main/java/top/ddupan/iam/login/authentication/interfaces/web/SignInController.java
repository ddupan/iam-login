package top.ddupan.iam.login.authentication.interfaces.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriUtils;
import top.ddupan.iam.login.authentication.domain.User.GroupMembership;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;
import top.ddupan.iam.login.authentication.infrastructure.totp.Totp;
import top.ddupan.iam.login.authentication.infrastructure.totp.TotpCode;
import top.ddupan.iam.login.authentication.infrastructure.totp.TotpProperties;
import top.ddupan.iam.login.authentication.infrastructure.webauthn.MfaPolicy;

/** Renders Spring Security's login pages; form processing belongs to the security filters. */
@RestController
@ConditionalOnProperty(prefix = "iam.ad", name = "enabled", havingValue = "true")
public class SignInController {
    private final PageRenderer renderer;
    private final ObjectProvider<MfaPolicy> policies;
    private final ObjectProvider<RegisteredClientRepository> clients;
    private final ObjectProvider<TotpProperties> totp;

    public SignInController(PageRenderer renderer, ObjectProvider<MfaPolicy> policies,
            ObjectProvider<RegisteredClientRepository> clients, ObjectProvider<TotpProperties> totp) {
        this.renderer = renderer;
        this.policies = policies;
        this.clients = clients;
        this.totp = totp;
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

    /**
     * The second step: set one up (no factor yet), or verify with a passkey or an authenticator app code. With both
     * set up, the passkey comes first and {@code method=totp} switches.
     */
    @GetMapping(value = "/signin/mfa", produces = MediaType.TEXT_HTML_VALUE)
    ResponseEntity<String> pending(@AuthenticationPrincipal DirectoryPrincipal principal, CsrfToken csrf,
            @RequestParam(required = false) String method, @RequestParam(required = false) String error,
            HttpServletRequest request, HttpServletResponse response) {
        var policy = policies.getIfAvailable();
        var passkey = policy != null && policy.passkeys(principal.getName());
        var totp = policy != null && policy.totp(principal.getName());
        var factor = policy == null ? "unavailable" : !passkey && !totp ? "choose"
            : totp && (!passkey || "totp".equals(method)) ? "totp" : "passkey";
        return identity(principal, csrf, "mfa-pending", factor, passkey && totp, code(error), app(request, response));
    }

    /**
     * Setting up an authenticator app: a new key, kept in the session until a code confirms it
     * (POST /signin/totp/setup, WebAuthnBrowserConfigurer). A failed code shows the same key again.
     */
    @GetMapping(value = "/signin/totp/setup", produces = MediaType.TEXT_HTML_VALUE)
    ResponseEntity<String> totpSetup(@AuthenticationPrincipal DirectoryPrincipal principal, CsrfToken csrf,
            @RequestParam(required = false) String error, HttpServletRequest request) {
        var policy = policies.getObject();
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        policy.requireEnrollment(authentication);
        var session = request.getSession();
        var shown = error != null && session.getAttribute(TotpCode.PENDING) instanceof String key ? key : null;
        var pending = shown != null ? shown : Base64.getEncoder().encodeToString(Totp.newKey());
        session.setAttribute(TotpCode.PENDING, pending);
        var secret = Totp.base32(Base64.getDecoder().decode(pending));
        var issuer = totp.getObject().issuer();
        var account = principal.user().username();
        var label = UriUtils.encodePath(issuer + ":" + account, StandardCharsets.UTF_8);
        var uri = "otpauth://totp/" + label + "?secret=" + secret + "&issuer=" + UriUtils.encodeQueryParam(issuer, StandardCharsets.UTF_8);
        return renderer.render(Map.of("step", "totp-setup", "name", principal.user().displayName(), "error", code(error),
            "action", "/signin/totp/setup", "csrf", csrf(csrf),
            "totp", Map.of("uri", uri, "secret", secret, "account", account, "issuer", issuer),
            // Adding one from the account page goes back there; during sign-in, back to choosing.
            "back", policy.complete.authorize(() -> authentication, null).isGranted() ? "/account" : "/signin/mfa"));
    }

    /** Both factors done: an authorization request interrupted for login resumes, otherwise the account page. */
    @GetMapping(value = "/signin/complete", produces = MediaType.TEXT_HTML_VALUE)
    ResponseEntity<String> complete(HttpServletRequest request, HttpServletResponse response) {
        var cache = new HttpSessionRequestCache();
        var saved = cache.getRequest(request, response);
        if (saved != null) cache.removeRequest(request, response);
        return ResponseEntity.status(303).header("Cache-Control", "no-store")
            .location(URI.create(saved != null ? saved.getRedirectUrl() : "/account")).build();
    }

    private ResponseEntity<String> identity(DirectoryPrincipal principal, CsrfToken csrf, String step, String factor,
            boolean other, String error, String app) {
        var user = principal.user();
        return renderer.render(Map.of("step", step, "factor", factor, "other", other, "name", user.displayName(), "app", app,
            "error", error, "action", "/signin/restart", "csrf", csrf(csrf),
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

    /** A code, not a sentence: the page translates it. */
    private static String code(String error) {
        return error == null ? "" : "throttled".equals(error) ? "throttled" : "invalid";
    }

    private static Map<String, String> csrf(CsrfToken token) {
        return Map.of("name", token.getParameterName(), "value", token.getToken(), "headerName", token.getHeaderName());
    }
}
