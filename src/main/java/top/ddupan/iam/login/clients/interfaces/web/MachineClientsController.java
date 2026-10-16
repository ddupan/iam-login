package top.ddupan.iam.login.clients.interfaces.web;

import java.util.Locale;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import top.ddupan.iam.login.clients.domain.ClientRepositoryException;
import top.ddupan.iam.login.clients.domain.MachineClient;
import top.ddupan.iam.login.clients.domain.MachineClientRepository;

@RestController
@ConditionalOnProperty(prefix="iam.authorization-server", name="enabled", havingValue="true")
public class MachineClientsController {
    private final MachineClientRepository repository;
    private static final Logger AUDIT = LoggerFactory.getLogger("iam.audit.clients");
    public MachineClientsController(MachineClientRepository repository) { this.repository = repository; }
    @GetMapping("/api/iam/machine-clients") Object list(@RequestParam(defaultValue="0") int page,
            @RequestParam(defaultValue="20") int size) { return repository.listMachines(page,size); }
    @GetMapping("/api/iam/machine-clients/{id}") MachineClient get(@PathVariable String id) { return repository.getMachine(id); }
    @PostMapping("/api/iam/machine-clients") ResponseEntity<MachineClient> create(@RequestBody MachineClient input, Authentication auth) {
        var created = repository.createMachine(input); audit("create",input.id(),auth);
        return ResponseEntity.status(201).body(created);
    }
    @PutMapping("/api/iam/machine-clients/{id}") MachineClient update(@PathVariable String id, @RequestBody MachineClient input, Authentication auth) {
        if (!id.equals(input.id())) throw new IllegalArgumentException("Client ID mismatch");
        var updated = repository.updateMachine(input); audit("update",id,auth); return updated;
    }
    @DeleteMapping("/api/iam/machine-clients/{id}") ResponseEntity<Void> delete(@PathVariable String id, Authentication auth) {
        repository.deleteMachine(id); audit("delete",id,auth); return ResponseEntity.noContent().build();
    }
    private void audit(String action,String id,Authentication auth) {
        AUDIT.info("machine-client action={} client={} actor={}",action,id,auth.getName());
    }
    @ExceptionHandler(IllegalArgumentException.class) ResponseEntity<?> invalid() {
        return ResponseEntity.badRequest().body(Map.of("error","invalid_client_request"));
    }
    @ExceptionHandler(ClientRepositoryException.class) ResponseEntity<?> unavailable(ClientRepositoryException ex) {
        int status = switch (ex.kind()) { case NOT_FOUND -> 404; case CONFLICT -> 409; case UNAVAILABLE -> 502; };
        return ResponseEntity.status(status).body(Map.of("error",ex.kind().name().toLowerCase(Locale.ROOT)));
    }
}
