package top.ddupan.iam.login.clients.interfaces.web;

import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import top.ddupan.iam.login.clients.application.*;
import top.ddupan.iam.login.clients.domain.OidcClient;

@RestController
@ConditionalOnProperty(prefix="iam.hydra", name="enabled", havingValue="true")
public class ClientsController {
    private final ClientRegistry registry;
    private static final org.slf4j.Logger AUDIT = org.slf4j.LoggerFactory.getLogger("iam.audit.clients");
    public ClientsController(ClientRegistry registry) { this.registry = registry; }
    @GetMapping("/api/iam/session") Object session(CsrfToken csrf) {
        return Map.of("csrf",Map.of("headerName",csrf.getHeaderName(),"token",csrf.getToken()));
    }
    @GetMapping("/api/iam/clients") Object list(@RequestParam(defaultValue="0") int page,
            @RequestParam(defaultValue="20") int size) { return registry.list(page,size); }
    @GetMapping("/api/iam/clients/{id}") OidcClient get(@PathVariable String id) { return registry.get(id); }
    @PostMapping("/api/iam/clients") ResponseEntity<ClientRegistry.Created> create(@RequestBody OidcClient input, Authentication auth) {
        var created = registry.create(input); audit("create",input.id(),auth);
        return ResponseEntity.status(201).header("Cache-Control","no-store").body(created);
    }
    @PutMapping("/api/iam/clients/{id}") OidcClient update(@PathVariable String id, @RequestBody OidcClient input, Authentication auth) {
        if (!id.equals(input.id())) throw new IllegalArgumentException("Client ID mismatch");
        var updated = registry.update(input); audit("update",id,auth); return updated;
    }
    @DeleteMapping("/api/iam/clients/{id}") ResponseEntity<Void> delete(@PathVariable String id, Authentication auth) {
        registry.delete(id); audit("delete",id,auth); return ResponseEntity.noContent().build();
    }
    private void audit(String action,String id,Authentication auth) {
        AUDIT.info("client action={} client={} actor={}",action,id,auth.getName());
    }
    @ExceptionHandler(IllegalArgumentException.class) ResponseEntity<?> invalid() {
        return ResponseEntity.badRequest().body(Map.of("error","invalid_client_request"));
    }
    @ExceptionHandler(ClientRegistryException.class) ResponseEntity<?> unavailable(ClientRegistryException ex) {
        int status = switch (ex.kind()) { case NOT_FOUND -> 404; case CONFLICT -> 409; case UNAVAILABLE -> 502; };
        return ResponseEntity.status(status).body(Map.of("error",ex.kind().name().toLowerCase(java.util.Locale.ROOT)));
    }
}
