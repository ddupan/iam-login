package top.ddupan.iam.login.clients.interfaces.web;

import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import top.ddupan.iam.login.authentication.interfaces.web.PageRenderer;

/**
 * Admin UI shell. It is an ordinary public OIDC client of this server's own authorization endpoint (same
 * origin, so the default content security policy already allows the token exchange).
 */
@RestController
@ConditionalOnProperty(prefix = "iam.authorization-server", name = "enabled", havingValue = "true")
public class ConsolePageController {
    private final PageRenderer renderer;
    private final Map<String, String> context;

    public ConsolePageController(PageRenderer renderer, @Value("${iam.authorization-server.issuer}") String issuer,
            @Value("${iam.clients.console-client-id:iam-console}") String clientId) {
        this.renderer = renderer;
        this.context = Map.of("step", "admin", "authority", issuer, "clientId", clientId);
    }

    @GetMapping({"/console", "/console/callback"}) ResponseEntity<String> page() {
        return renderer.render(context);
    }
}
