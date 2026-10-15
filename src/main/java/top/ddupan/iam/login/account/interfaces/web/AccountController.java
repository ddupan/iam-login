package top.ddupan.iam.login.account.interfaces.web;

import java.net.URI;
import java.time.ZoneOffset;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import top.ddupan.iam.login.account.infrastructure.persistence.Grants;
import top.ddupan.iam.login.account.infrastructure.persistence.SecondFactors;
import top.ddupan.iam.login.authentication.domain.User.GroupMembership;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;
import top.ddupan.iam.login.authentication.interfaces.web.PageRenderer;

/**
 * The signed-in account's own page: profile (read-only, from the directory), second factors (passkeys and the
 * authenticator app) and granted applications.
 * Every route needs both factors fresh (browser chain), which is the re-verification before a change.
 * Errors are codes; the page translates them.
 */
@RestController
@ConditionalOnProperty(prefix = "iam.webauthn", name = "enabled", havingValue = "true")
class AccountController {
    private static final int MAX_LABEL = 64;
    private final PageRenderer renderer;
    private final SecondFactors factors;
    private final Grants grants;

    AccountController(PageRenderer renderer, SecondFactors factors, Grants grants) {
        this.renderer = renderer;
        this.factors = factors;
        this.grants = grants;
    }

    record Label(String label) { }

    /** The bare host name: what a person typing it wants is their account (signing in first if needed). */
    @GetMapping("/")
    ResponseEntity<Void> root() {
        return ResponseEntity.status(302).location(URI.create("/account")).build();
    }

    @GetMapping(value = "/account", produces = MediaType.TEXT_HTML_VALUE)
    ResponseEntity<String> page(@AuthenticationPrincipal DirectoryPrincipal principal, CsrfToken csrf) {
        var user = principal.user();
        return renderer.render(Map.of("step", "account", "name", user.displayName(), "error", "", "action", "/signin/restart",
            "csrf", Map.of("name", csrf.getParameterName(), "value", csrf.getToken(), "headerName", csrf.getHeaderName()),
            "profile", Map.of("username", user.username(), "displayName", user.displayName(), "email", user.email(),
                "directory", user.id().authority(), "groups", user.memberships().stream().map(GroupMembership::name).toList()),
            // Spring Security writes these columns from Instants in the JVM's zone, which is UTC here.
            "passkeys", factors.passkeys(principal.getName()).stream().map(p -> Map.of("id", p.id(), "label", p.label(),
                "created", p.created() == null ? "" : p.created().toInstant(ZoneOffset.UTC).toString(),
                "lastUsed", p.lastUsed() == null ? "" : p.lastUsed().toInstant(ZoneOffset.UTC).toString())).toList(),
            // Present only when one is set up.
            "authenticator", factors.authenticator(principal.getName()).map(a -> Map.of("created", a.created().toInstant().toString(),
                "lastUsed", a.lastUsed() == null ? "" : a.lastUsed().toInstant().toString())).orElse(Map.of()),
            "apps", grants.list(principal.getName()).stream().map(g -> Map.of("clientId", g.clientId(), "name", g.name(),
                "scopes", g.scopes(), "lastIssued", g.lastIssued() == null ? "" : g.lastIssued().toInstant().toString())).toList()));
    }

    @PutMapping("/account/passkeys/{id}/label")
    ResponseEntity<Map<String, String>> rename(@AuthenticationPrincipal DirectoryPrincipal principal, @PathVariable String id,
            @RequestBody Label body) {
        var label = body.label() == null ? "" : body.label().strip();
        if (label.isEmpty() || label.length() > MAX_LABEL || label.chars().anyMatch(Character::isISOControl)) {
            return error(400, "invalid");
        }
        return factors.rename(principal.getName(), id, label) ? ResponseEntity.noContent().build() : error(404, "missing");
    }

    @DeleteMapping("/account/passkeys/{id}")
    ResponseEntity<Map<String, String>> remove(@AuthenticationPrincipal DirectoryPrincipal principal, @PathVariable String id) {
        return removed(factors.removePasskey(principal.getName(), id));
    }

    @DeleteMapping("/account/authenticator")
    ResponseEntity<Map<String, String>> removeAuthenticator(@AuthenticationPrincipal DirectoryPrincipal principal) {
        return removed(factors.removeAuthenticator(principal.getName()));
    }

    private static ResponseEntity<Map<String, String>> removed(SecondFactors.Removal removal) {
        return switch (removal) {
            case REMOVED -> ResponseEntity.noContent().build();
            case NOT_FOUND -> error(404, "missing");
            case LAST -> error(409, "last");
        };
    }

    @DeleteMapping("/account/apps/{clientId}")
    ResponseEntity<Map<String, String>> revoke(@AuthenticationPrincipal DirectoryPrincipal principal, @PathVariable String clientId) {
        return grants.revoke(principal.getName(), clientId) ? ResponseEntity.noContent().build() : error(404, "missing");
    }

    private static ResponseEntity<Map<String, String>> error(int status, String code) {
        return ResponseEntity.status(status).body(Map.of("error", code));
    }
}
