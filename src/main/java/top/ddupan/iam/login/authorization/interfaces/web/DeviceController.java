package top.ddupan.iam.login.authorization.interfaces.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.util.Map;
import java.util.Set;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;
import top.ddupan.iam.login.authentication.infrastructure.webauthn.MfaPolicy;
import top.ddupan.iam.login.authentication.interfaces.web.PageRenderer;

/**
 * The device grant's verification URI (RFC 8628 3.3): where the user enters the code a device shows, and where
 * the verification endpoint sends the outcome back to. The code goes to the framework's verification endpoint,
 * which checks it and asks for consent; this page only presents it. A visitor without both factors is sent to
 * sign in first and returns here afterwards (/signin/complete resumes the saved request), code included.
 */
@RestController
@ConditionalOnProperty(prefix = "iam.authorization-server", name = "enabled", havingValue = "true")
class DeviceController {
    static final String PATH = "/signin/device";
    private static final Set<String> RESULTS = Set.of("done", "invalid", "denied");
    private final MfaPolicy policy;
    private final PageRenderer renderer;

    DeviceController(MfaPolicy policy, PageRenderer renderer) {
        this.policy = policy; this.renderer = renderer;
    }

    @GetMapping(value = PATH, produces = MediaType.TEXT_HTML_VALUE)
    ResponseEntity<String> device(@RequestParam(name = "user_code", defaultValue = "") String userCode,
            @RequestParam(defaultValue = "") String result, HttpServletRequest request, HttpServletResponse response,
            CsrfToken csrf) {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!granted(policy.session.authorize(() -> authentication, null))) {
            new HttpSessionRequestCache().saveRequest(request, response);
            var next = granted(policy.password.authorize(() -> authentication, null)) ? "/signin/mfa" : "/signin";
            return ResponseEntity.status(303).header("Cache-Control", "no-store").location(URI.create(next)).build();
        }
        var principal = (DirectoryPrincipal) authentication.getPrincipal();
        // Shown back in the form only; the endpoint decides whether it is valid.
        var code = userCode.matches("[A-Za-z0-9-]{1,20}") ? userCode : "";
        return renderer.render(Map.of("step", "device", "name", principal.user().displayName(), "error", "",
            "action", "/oauth2/device_verification",
            "csrf", Map.of("name", csrf.getParameterName(), "value", csrf.getToken(), "headerName", csrf.getHeaderName()),
            "device", Map.of("username", principal.user().username(), "userCode", code,
                "result", RESULTS.contains(result) ? result : "")));
    }

    private static boolean granted(AuthorizationResult result) {
        return result != null && result.isGranted();
    }
}
