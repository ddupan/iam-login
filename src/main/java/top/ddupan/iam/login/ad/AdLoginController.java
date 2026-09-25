package top.ddupan.iam.login.ad;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.time.Instant;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import top.ddupan.iam.login.preview.PageRenderer;

/** Human first-factor PoC. No SecurityContext, MFA acceptance, or Hydra calls. */
@RestController
public class AdLoginController {
    static final String STATE = AdLoginController.class.getName() + ".state";
    private final AdPasswordVerifier verifier;
    private final PageRenderer renderer;

    public AdLoginController(AdPasswordVerifier verifier, PageRenderer renderer) {
        this.verifier = verifier;
        this.renderer = renderer;
    }

    @GetMapping(value = "/signin", produces = MediaType.TEXT_HTML_VALUE)
    ResponseEntity<String> page(HttpServletRequest request, CsrfToken csrf) {
        requireAvailable(request);
        var session = request.getSession();
        synchronized (session) {
            var state = state(session);
            if (state.identity != null) return redirect("/signin/mfa");
            return renderer.render(Map.of("step", "password", "name", state.username,
                "error", state.error, "action", "/signin/password", "csrf", csrf(csrf)));
        }
    }

    @PostMapping("/signin/password")
    ResponseEntity<String> password(HttpServletRequest request,
            @RequestParam(defaultValue = "") String username,
            @RequestParam(defaultValue = "") String password) {
        requireAvailable(request);
        var session = request.getSession(false);
        if (session == null) throw new ResponseStatusException(HttpStatus.CONFLICT);
        synchronized (session) {
            var state = (State) session.getAttribute(STATE);
            if (state == null || state.identity != null || state.expires.isBefore(Instant.now())) {
                return redirect("/signin");
            }
            // Prevent double submissions in this transaction; perimeter rate limits belong at ingress.
            if (state.retryAfter.isAfter(Instant.now())) throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS);
            state.retryAfter = Instant.now().plusSeconds(2);
            state.username = username.length() <= 256 ? username : "";
            try {
                var identity = verifier.verify(username, password);
                request.changeSessionId();
                state.identity = identity;
                state.error = "";
                state.expires = Instant.now().plusSeconds(600);
                return redirect("/signin/mfa");
            } catch (AuthenticationException | org.springframework.dao.DataAccessException ex) {
                // Neither directory exception details nor passwords enter HTML/session/logs.
                state.error = "无法验证账号，请检查凭据与账号状态，或稍后重试。";
                return redirect("/signin");
            }
        }
    }

    @GetMapping(value = "/signin/mfa", produces = MediaType.TEXT_HTML_VALUE)
    ResponseEntity<String> pending(HttpServletRequest request, CsrfToken csrf) {
        requireAvailable(request);
        var session = request.getSession(false);
        if (session == null) return redirect("/signin");
        synchronized (session) {
            var state = state(session);
            if (state.identity == null) return redirect("/signin");
            var identity = state.identity;
            return renderer.render(Map.of("step", "mfa-pending", "name", identity.displayName(),
                "error", "", "action", "/signin/restart", "csrf", csrf(csrf),
                "identity", Map.of("username", identity.username(), "objectGuid", identity.objectGuid(),
                    "email", identity.email(), "groups", identity.groups(), "groupDns", identity.groupDns())));
        }
    }

    @PostMapping("/signin/restart")
    ResponseEntity<String> restart(HttpServletRequest request) {
        requireAvailable(request);
        var session = request.getSession(false);
        if (session != null) session.invalidate();
        return redirect("/signin");
    }

    private void requireAvailable(HttpServletRequest request) {
        if (!verifier.enabled()) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        if (!request.isSecure()) throw new ResponseStatusException(HttpStatus.UPGRADE_REQUIRED, "HTTPS required");
    }

    private static Map<String, String> csrf(CsrfToken token) {
        return Map.of("name", token.getParameterName(), "value", token.getToken());
    }

    private static State state(HttpSession session) {
        var state = (State) session.getAttribute(STATE);
        if (state == null || state.expires.isBefore(Instant.now())) {
            state = new State();
            session.setAttribute(STATE, state);
        }
        return state;
    }

    private static ResponseEntity<String> redirect(String location) {
        return ResponseEntity.status(HttpStatus.SEE_OTHER).header("Location", location)
            .header("Cache-Control", "no-store").build();
    }

    static final class State {
        String username = "";
        String error = "";
        DirectoryIdentity identity;
        Instant expires = Instant.now().plusSeconds(600);
        Instant retryAfter = Instant.EPOCH;
    }
}
