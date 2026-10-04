package top.ddupan.iam.login.authorization.interfaces.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;
import top.ddupan.iam.login.authentication.interfaces.web.PageRenderer;
import top.ddupan.iam.login.authorization.application.AuthorizeApplication;

@RestController
@ConditionalOnProperty(prefix = "iam.hydra", name = "enabled", havingValue = "true")
public class HydraController {
    private final AuthorizeApplication policy;
    private final PageRenderer renderer;
    public HydraController(AuthorizeApplication policy, PageRenderer renderer) {
        this.policy = policy; this.renderer = renderer;
    }
    @GetMapping("/oauth2/start")
    ResponseEntity<Void> start(@RequestParam("login_challenge") String challenge,
            HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        var login = policy.start(challenge);
        var query = UriComponentsBuilder.fromUriString(login.requestUrl()).build().getQueryParams();
        if (query.containsKey("prompt") || query.containsKey("max_age")) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }
        HydraBrowserRequests.start(request, login);
        return redirect("/oauth2/login");
    }
    @GetMapping("/oauth2/login")
    ResponseEntity<String> login(HttpServletRequest request, @AuthenticationPrincipal DirectoryPrincipal principal,
            CsrfToken csrf) {
        var intent = HydraBrowserRequests.intent(request);
        policy.subject(principal.user());
        policy.permit(principal.user(), intent.request());
        var page = renderer.render(Map.of("step", "authorize", "name", principal.user().displayName(), "error", "",
            "action", "/oauth2/login", "csrf", Map.of("name", csrf.getParameterName(), "value", csrf.getToken(),
                "headerName", csrf.getHeaderName()), "binding", intent.binding(),
            "client", intent.request().clientId(), "scopes", intent.request().scopes()));
        var authorization = URI.create(intent.request().requestUrl());
        var rawCallback = UriComponentsBuilder.fromUri(authorization).build()
            .getQueryParams().getFirst("redirect_uri");
        if (rawCallback == null) throw new IllegalArgumentException("Explicit callback is required");
        var callback = URI.create(URLDecoder.decode(rawCallback, StandardCharsets.UTF_8));
        var targets = formOrigin(authorization) + " " + formOrigin(callback);
        return ResponseEntity.ok().headers(page.getHeaders()).header("Content-Security-Policy",
            PageRenderer.CONTENT_SECURITY_POLICY.replace("form-action 'self'", "form-action 'self' " + targets))
            .body(page.getBody());
    }
    @PostMapping("/oauth2/login")
    ResponseEntity<Void> accept(@RequestParam String binding, HttpServletRequest request,
            @AuthenticationPrincipal DirectoryPrincipal principal, Authentication authentication) {
        var intent = HydraBrowserRequests.consume(request, binding);
        var authenticatedAt = authentication.getAuthorities().stream()
            .filter(FactorGrantedAuthority.class::isInstance).map(FactorGrantedAuthority.class::cast)
            .map(FactorGrantedAuthority::getIssuedAt).max(Instant::compareTo).orElseThrow();
        var accepted = policy.login(intent.request(), intent.binding(), principal.user(), authenticatedAt);
        HydraBrowserRequests.accepted(request, new HydraBrowserRequests.Accepted(intent, principal.getName(), accepted.subject()));
        return redirect(accepted.redirect());
    }
    @GetMapping("/oauth2/consent")
    ResponseEntity<Void> consent(@RequestParam("consent_challenge") String challenge, HttpServletRequest request,
            @AuthenticationPrincipal DirectoryPrincipal principal) {
        var accepted = HydraBrowserRequests.consumeAccepted(request);
        if (!principal.getName().equals(accepted.directoryName())) throw new IllegalArgumentException("Browser identity changed");
        return redirect(policy.consent(accepted.intent().request(), accepted.intent().binding(), accepted.subject(),
            principal.user(), challenge));
    }
    @ExceptionHandler(IllegalArgumentException.class)
    ResponseEntity<String> invalid() {
        return ResponseEntity.badRequest().header("Cache-Control", "no-store")
            .body("授权请求无效或已过期，请从应用重新开始。");
    }
    private static String formOrigin(URI uri) {
        if (uri.getHost() == null || uri.getUserInfo() != null || uri.getFragment() != null
                || !("https".equals(uri.getScheme()) || "http".equals(uri.getScheme())
                    && Set.of("localhost", "127.0.0.1").contains(uri.getHost()))) {
            throw new IllegalArgumentException("Unexpected form destination");
        }
        return uri.getScheme() + "://" + uri.getRawAuthority();
    }
    private static ResponseEntity<Void> redirect(String target) {
        return ResponseEntity.status(303).header("Cache-Control", "no-store").location(URI.create(target)).build();
    }
}
