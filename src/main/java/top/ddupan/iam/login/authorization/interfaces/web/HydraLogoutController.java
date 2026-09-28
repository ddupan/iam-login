package top.ddupan.iam.login.authorization.interfaces.web;

import java.net.URI;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import top.ddupan.iam.login.authentication.interfaces.web.PageRenderer;
import top.ddupan.iam.login.authorization.application.port.LogoutGateway;
import top.ddupan.iam.login.authorization.application.AuthorizationPolicy;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;

@RestController
@ConditionalOnProperty(prefix="iam.hydra",name="enabled",havingValue="true")
public class HydraLogoutController {
    private static final String KEY = HydraLogoutController.class.getName();
    private record Pending(LogoutGateway.Request request,String binding,Instant expires) { }
    private final LogoutGateway hydra;
    private final PageRenderer renderer;
    private final AuthorizationPolicy policy;
    public HydraLogoutController(LogoutGateway hydra,PageRenderer renderer,AuthorizationPolicy policy) {
        this.hydra=hydra; this.renderer=renderer; this.policy=policy;
    }
    @GetMapping("/oauth2/logout") ResponseEntity<String> page(@RequestParam("logout_challenge") String challenge,
            HttpServletRequest request,Authentication auth,CsrfToken csrf) {
        var logout = hydra.request(challenge);
        if (auth != null && auth.getPrincipal() instanceof DirectoryPrincipal principal && logout.subject()!=null
                && !logout.subject().isBlank() && !policy.subject(principal.user()).equals(logout.subject()))
            throw new IllegalArgumentException("Different logout subject");
        var pending = new Pending(logout,UUID.randomUUID().toString(),Instant.now().plusSeconds(300));
        request.getSession().setAttribute(KEY,pending);
        var page = renderer.render(Map.of("step","logout","name","","error","","action","/oauth2/logout",
            "binding",pending.binding(),"csrf",Map.of("name",csrf.getParameterName(),"value",csrf.getToken(),"headerName",csrf.getHeaderName())));
        String targets=origin(hydra.startUrl());
        if (!logout.postLogoutRedirectUri().isEmpty()) targets += " " + origin(logout.postLogoutRedirectUri());
        return ResponseEntity.ok().headers(page.getHeaders()).header("Content-Security-Policy",
            PageRenderer.CONTENT_SECURITY_POLICY.replace("form-action 'self'", "form-action 'self' " + targets))
            .body(page.getBody());
    }
    @PostMapping("/oauth2/logout") ResponseEntity<Void> logout(@RequestParam String binding,HttpServletRequest request,
            HttpServletResponse response,Authentication authentication) {
        var session=request.getSession(false);
        if (session==null) throw new IllegalArgumentException("No logout session");
        Pending pending;
        synchronized(session) {
            pending=(Pending)session.getAttribute(KEY);
            if (pending==null || !pending.binding().equals(binding) || !Instant.now().isBefore(pending.expires()))
                throw new IllegalArgumentException("Invalid logout binding");
            session.removeAttribute(KEY);
        }
        var current=hydra.request(pending.request().challenge());
        if (!Objects.equals(current,pending.request())) throw new IllegalArgumentException("Logout request changed");
        var target=hydra.accept(current.challenge());
        new SecurityContextLogoutHandler().logout(request,response,authentication);
        return ResponseEntity.status(303).header("Cache-Control","no-store").location(URI.create(target)).build();
    }
    private static String origin(String url) { var uri=URI.create(url); return uri.getScheme()+"://"+uri.getRawAuthority(); }
    @ExceptionHandler(IllegalArgumentException.class) ResponseEntity<String> invalid() {
        return ResponseEntity.badRequest().header("Cache-Control","no-store").body("注销请求无效或已过期，请重新发起。");
    }
}
