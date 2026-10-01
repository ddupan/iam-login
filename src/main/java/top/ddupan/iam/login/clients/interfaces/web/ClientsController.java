package top.ddupan.iam.login.clients.interfaces.web;

import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import top.ddupan.iam.login.clients.domain.*;
import top.ddupan.iam.login.clients.domain.OidcClient;

@RestController
@ConditionalOnProperty(prefix="iam.hydra", name="enabled", havingValue="true")
public class ClientsController {
    private final ClientRepository repository;
    private static final org.slf4j.Logger AUDIT = org.slf4j.LoggerFactory.getLogger("iam.audit.clients");
    public ClientsController(ClientRepository repository) { this.repository = repository; }
    @GetMapping("/api/iam/clients") Object list(@RequestParam(defaultValue="0") int page,
            @RequestParam(defaultValue="20") int size) { return repository.list(page,size); }
    @GetMapping("/api/iam/clients/{id}") OidcClient get(@PathVariable String id) { return repository.get(id); }
    @PostMapping("/api/iam/clients") ResponseEntity<ClientRepository.Created> create(@RequestBody OidcClient input, Authentication auth) {
        var created = repository.create(input); audit("create",input.id(),auth);
        return ResponseEntity.status(201).header("Cache-Control","no-store").body(created);
    }
    @PutMapping("/api/iam/clients/{id}") OidcClient update(@PathVariable String id, @RequestBody OidcClient input, Authentication auth) {
        if (!id.equals(input.id())) throw new IllegalArgumentException("Client ID mismatch");
        var updated = repository.update(input); audit("update",id,auth); return updated;
    }
    @DeleteMapping("/api/iam/clients/{id}") ResponseEntity<Void> delete(@PathVariable String id, Authentication auth) {
        repository.delete(id); audit("delete",id,auth); return ResponseEntity.noContent().build();
    }
    @PostMapping("/api/iam/clients/{id}/secret") ResponseEntity<Map<String,String>> rotate(@PathVariable String id, Authentication auth) {
        var secret = repository.rotateSecret(id); audit("rotate-secret",id,auth);
        return ResponseEntity.ok().header("Cache-Control","no-store").body(Map.of("secret",secret));
    }
    private void audit(String action,String id,Authentication auth) {
        AUDIT.info("client action={} client={} actor={}",action,id,auth.getName());
    }
    @ExceptionHandler(IllegalArgumentException.class) ResponseEntity<?> invalid() {
        return ResponseEntity.badRequest().body(Map.of("error","invalid_client_request"));
    }
    @ExceptionHandler(ClientRepositoryException.class) ResponseEntity<?> unavailable(ClientRepositoryException ex) {
        int status = switch (ex.kind()) { case NOT_FOUND -> 404; case CONFLICT -> 409; case UNAVAILABLE -> 502; };
        return ResponseEntity.status(status).body(Map.of("error",ex.kind().name().toLowerCase(java.util.Locale.ROOT)));
    }
}
