package top.ddupan.iam.login.authentication.interfaces.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import top.ddupan.iam.login.authentication.application.SignInService;
import top.ddupan.iam.login.authentication.domain.LoginTransaction.Step;
import top.ddupan.iam.login.authentication.domain.User.GroupMembership;

/** Translates browser requests and use-case outcomes; no directory or authentication policy here. */
@RestController
public class SignInController {
    static final String STATE = SignInController.class.getName() + ".state";
    private final SignInService signIn;
    private final PageRenderer renderer;

    public SignInController(SignInService signIn, PageRenderer renderer) {
        this.signIn = signIn;
        this.renderer = renderer;
    }

    @GetMapping(value = "/signin", produces = MediaType.TEXT_HTML_VALUE)
    ResponseEntity<String> page(HttpServletRequest request, CsrfToken csrf) {
        requireAvailable(request);
        var session = request.getSession();
        synchronized (session) {
            var state = state(session);
            if (state.transaction.step() == Step.MFA_REQUIRED) return redirect("/signin/mfa");
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
            var state = (BrowserSignInState) session.getAttribute(STATE);
            if (state == null) return redirect("/signin");
            state.username = username.length() <= 256 ? username : "";
            return switch (signIn.submitPassword(state.transaction, username, password)) {
                case ACCEPTED -> {
                    request.changeSessionId();
                    state.error = "";
                    yield redirect("/signin/mfa");
                }
                case REJECTED -> {
                    state.error = "无法验证账号，请检查凭据与账号状态，或稍后重试。";
                    yield redirect("/signin");
                }
                case EXPIRED, WRONG_STEP -> redirect("/signin");
                case RETRY_LATER -> throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS);
            };
        }
    }

    @GetMapping(value = "/signin/mfa", produces = MediaType.TEXT_HTML_VALUE)
    ResponseEntity<String> pending(HttpServletRequest request, CsrfToken csrf) {
        requireAvailable(request);
        var session = request.getSession(false);
        if (session == null) return redirect("/signin");
        synchronized (session) {
            var state = state(session);
            if (state.transaction.step() != Step.MFA_REQUIRED) return redirect("/signin");
            var user = state.transaction.identity();
            return renderer.render(Map.of("step", "mfa-pending", "name", user.displayName(),
                "error", "", "action", "/signin/restart", "csrf", csrf(csrf),
                "identity", Map.of("username", user.username(), "subjectId", user.id().value(),
                    "email", user.email(),
                    "groups", user.memberships().stream().map(GroupMembership::name).toList(),
                    "groupDns", user.memberships().stream().map(GroupMembership::externalId).toList())));
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
        if (!signIn.enabled()) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        if (!request.isSecure()) throw new ResponseStatusException(HttpStatus.UPGRADE_REQUIRED, "HTTPS required");
    }

    private BrowserSignInState state(HttpSession session) {
        var state = (BrowserSignInState) session.getAttribute(STATE);
        if (state == null || signIn.expired(state.transaction)) {
            state = new BrowserSignInState(signIn.start());
            session.setAttribute(STATE, state);
        }
        return state;
    }

    private static Map<String, String> csrf(CsrfToken token) {
        return Map.of("name", token.getParameterName(), "value", token.getToken());
    }

    private static ResponseEntity<String> redirect(String location) {
        return ResponseEntity.status(HttpStatus.SEE_OTHER).header("Location", location)
            .header("Cache-Control", "no-store").build();
    }
}
