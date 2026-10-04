package top.ddupan.iam.login.authorization;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authorization.application.SubjectBindings;
import static org.assertj.core.api.Assertions.*;

class SubjectBindingsTests {
    private final User user = new User(new User.UserId("example.test", "immutable-guid"), "alice", "Alice", "alice@example.test", List.of());

    @Test void subjectContinuityRequiresExplicitImmutableBinding() {
        var bindings = new SubjectBindings(Map.of(user.id(), "human:old-issuer-sub-hash"));
        assertThat(bindings.subject(user)).isEqualTo("human:old-issuer-sub-hash");
        var renamed = new User(user.id(), "renamed", "Renamed", "new@example.test", List.of());
        assertThat(bindings.subject(renamed)).isEqualTo(bindings.subject(user));
        var impostor = new User(new User.UserId("example.test", "another-guid"), user.username(), user.displayName(), user.email(), List.of());
        assertThatIllegalArgumentException().isThrownBy(() -> bindings.subject(impostor));
    }

    @Test void bindingsMustBeExplicitAndUnique() {
        var other = new User.UserId("example.test", "another-guid");
        assertThatIllegalArgumentException().isThrownBy(() -> new SubjectBindings(Map.of()));
        assertThatIllegalArgumentException().isThrownBy(() -> new SubjectBindings(Map.of(user.id(), "same", other, "same")));
        assertThatIllegalArgumentException().isThrownBy(() -> new SubjectBindings(Map.of(user.id(), " ")));
    }
}
