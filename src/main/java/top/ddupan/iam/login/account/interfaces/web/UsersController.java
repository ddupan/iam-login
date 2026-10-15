package top.ddupan.iam.login.account.interfaces.web;

import java.time.ZoneOffset;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import top.ddupan.iam.login.account.infrastructure.persistence.SecondFactors;
import top.ddupan.iam.login.authentication.domain.UserRepository;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;

/**
 * The console's users: an account looked up in the directory, its second factors, and the reset for a lost device.
 * The accounts themselves are managed in the directory. Under /api/iam, so only administrators get here
 * (ClientManagementConfiguration); every condition below is needed for that chain, the directory and the factors.
 */
@RestController
@ConditionalOnProperty(prefix = "iam.authorization-server", name = "enabled", havingValue = "true")
@ConditionalOnProperty(prefix = "iam.webauthn", name = "enabled", havingValue = "true")
@ConditionalOnProperty(prefix = "iam.ad", name = "enabled", havingValue = "true")
class UsersController {
    private static final Logger AUDIT = LoggerFactory.getLogger("iam.audit.users");
    private final UserRepository users;
    private final SecondFactors factors;

    UsersController(UserRepository users, SecondFactors factors) {
        this.users = users;
        this.factors = factors;
    }

    @GetMapping("/api/iam/users/{username}")
    ResponseEntity<?> get(@PathVariable String username) {
        return users.findActive(username).<ResponseEntity<?>>map(user -> {
            var owner = new DirectoryPrincipal(user).getName();
            return ResponseEntity.ok(Map.of("username", user.username(), "displayName", user.displayName(),
                "directory", user.id().authority(),
                // Spring Security writes these columns from Instants in the JVM's zone, which is UTC here.
                "passkeys", factors.passkeys(owner).stream().map(p -> Map.of("label", p.label(),
                    "created", p.created() == null ? "" : p.created().toInstant(ZoneOffset.UTC).toString(),
                    "lastUsed", p.lastUsed() == null ? "" : p.lastUsed().toInstant(ZoneOffset.UTC).toString())).toList(),
                "authenticator", factors.authenticator(owner).map(a -> Map.of("created", a.created().toInstant().toString(),
                    "lastUsed", a.lastUsed() == null ? "" : a.lastUsed().toInstant().toString())).orElse(Map.of())));
        }).orElseGet(UsersController::missing);
    }

    @DeleteMapping("/api/iam/users/{username}/second-factors")
    ResponseEntity<?> reset(@PathVariable String username, Authentication auth) {
        return users.findActive(username).<ResponseEntity<?>>map(user -> {
            int removed = factors.reset(new DirectoryPrincipal(user).getName());
            AUDIT.info("user action=reset-second-factors user={} removed={} actor={}", user.username(), removed, auth.getName());
            return ResponseEntity.noContent().build();
        }).orElseGet(UsersController::missing);
    }

    private static ResponseEntity<?> missing() {
        return ResponseEntity.status(404).body(Map.of("error", "missing"));
    }

    @ExceptionHandler(UserRepository.AccessFailure.class) ResponseEntity<?> unavailable() {
        return ResponseEntity.status(502).body(Map.of("error", "unavailable"));
    }
}
