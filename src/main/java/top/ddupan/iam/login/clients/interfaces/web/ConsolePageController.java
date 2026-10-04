package top.ddupan.iam.login.clients.interfaces.web;

import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import top.ddupan.iam.login.authentication.interfaces.web.PageRenderer;
import top.ddupan.iam.login.authorization.infrastructure.hydra.HydraProperties;

/** Admin UI shell. It is an ordinary public OIDC client of Hydra; this only tells it where Hydra is. */
@RestController
@ConditionalOnProperty(prefix="iam.clients", name="admin-ui-client-id")
public class ConsolePageController {
    private final PageRenderer renderer;
    private final Map<String,String> context;
    private final String csp;
    public ConsolePageController(PageRenderer renderer, HydraProperties hydra,
            @Value("${iam.clients.admin-ui-client-id}") String clientId) {
        this.renderer = renderer;
        var issuer = hydra.publicUrl();
        this.context = Map.of("step","admin","authority",issuer.toString(),"clientId",clientId);
        // The browser exchanges the code with Hydra directly, so its origin must be reachable by fetch.
        this.csp = PageRenderer.CONTENT_SECURITY_POLICY.replace("default-src 'self';",
            "default-src 'self'; connect-src 'self' " + issuer.getScheme() + "://" + issuer.getRawAuthority() + ";");
    }
    @GetMapping({"/console", "/console/callback"}) ResponseEntity<String> page() {
        var page = renderer.render(context);
        return ResponseEntity.ok().headers(page.getHeaders()).header("Content-Security-Policy", csp).body(page.getBody());
    }
}
