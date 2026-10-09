package top.ddupan.iam.login.authorization.interfaces.web;

import java.net.URI;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import top.ddupan.iam.login.authentication.domain.User.GroupMembership;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;
import top.ddupan.iam.login.authentication.interfaces.web.PageRenderer;

/**
 * The authorization server's consent page (in place of the framework's default). The form posts back to
 * /oauth2/authorize (or, for the device grant, /oauth2/device_verification with the user code), which validates
 * everything again; this page only presents the request. Allow submits all
 * requested scopes (openid included: an empty approval is a denial), deny submits none (the framework
 * answers access_denied).
 */
@RestController
@ConditionalOnProperty(prefix = "iam.authorization-server", name = "enabled", havingValue = "true")
class ConsentController {
    private final RegisteredClientRepository clients;
    private final OAuth2AuthorizationConsentService consents;
    private final PageRenderer renderer;

    ConsentController(RegisteredClientRepository clients, OAuth2AuthorizationConsentService consents, PageRenderer renderer) {
        this.clients = clients; this.consents = consents; this.renderer = renderer;
    }

    @GetMapping(value = "/signin/consent", produces = MediaType.TEXT_HTML_VALUE)
    ResponseEntity<String> consent(@AuthenticationPrincipal DirectoryPrincipal principal,
            @RequestParam("client_id") String clientId, @RequestParam(defaultValue = "") String scope,
            @RequestParam String state, @RequestParam(name = "user_code", required = false) String userCode, CsrfToken csrf) {
        var client = clients.findByClientId(clientId);
        if (client == null) return ResponseEntity.badRequest().build();
        var granted = consents.findById(client.getId(), principal.getName());
        var requested = new LinkedHashSet<>(List.of(scope.trim().split("\\s+")));
        requested.remove("");
        var user = principal.user();
        // The device grant redirects nowhere: its outcome comes back to this server (DeviceController).
        var device = userCode != null;
        var consent = new HashMap<String, Object>(Map.of("clientId", clientId, "clientName", client.getClientName(), "state", state,
            "scopes", List.copyOf(requested),
            "previouslyGranted", granted == null ? List.of() : List.copyOf(granted.getScopes()),
            "returnHosts", device ? List.of() : List.copyOf(hosts(client.getRedirectUris())),
            "username", user.username(), "email", user.email(),
            "groups", user.memberships().stream().map(GroupMembership::name).toList()));
        if (device) consent.put("userCode", userCode);
        var page = renderer.render(Map.of("step", "consent", "name", user.displayName(), "error", "",
            "action", device ? "/oauth2/device_verification" : "/oauth2/authorize",
            "csrf", Map.of("name", csrf.getParameterName(), "value", csrf.getToken(), "headerName", csrf.getHeaderName()),
            "consent", consent));
        if (device) return page;
        // The decision is a form post whose response redirects to the client: browsers apply form-action to
        // that redirect too, so the client's callback origins must be allowed here or "allow" goes nowhere.
        return ResponseEntity.status(page.getStatusCode()).headers(page.getHeaders())
            .header("Content-Security-Policy", PageRenderer.CONTENT_SECURITY_POLICY.replace("form-action 'self'",
                "form-action 'self' " + String.join(" ", origins(client.getRedirectUris()))))
            .body(page.getBody());
    }

    private static Set<String> hosts(Set<String> redirectUris) {
        var hosts = new LinkedHashSet<String>();
        for (var uri : redirectUris) hosts.add(URI.create(uri).getHost());
        return hosts;
    }

    private static Set<String> origins(Set<String> redirectUris) {
        var origins = new LinkedHashSet<String>();
        for (var value : redirectUris) {
            var uri = URI.create(value);
            origins.add(uri.getScheme() + "://" + uri.getAuthority());
        }
        return origins;
    }
}
