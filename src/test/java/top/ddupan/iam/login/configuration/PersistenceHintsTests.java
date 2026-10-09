package top.ddupan.iam.login.configuration;

import java.time.OffsetDateTime;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.predicate.RuntimeHintsPredicates;
import top.ddupan.iam.login.persistence.schema.tables.records.SubjectsRecord;
import top.ddupan.iam.login.persistence.schema.tables.records.WebauthnChallengeRecord;
import static org.assertj.core.api.Assertions.*;

// The native image only learns these from the hints; a missing one fails at startup (DSLContext) or at the first
// statement, never in JVM tests. main's native run is the end-to-end check.
class PersistenceHintsTests {
    private final RuntimeHints hints = new RuntimeHints();

    PersistenceHintsTests() {
        new PersistenceConfiguration.JooqHints().registerHints(hints, getClass().getClassLoader());
    }

    @Test void everyBuiltInDataTypeHasItsArrayTypeInTheImage() {
        var types = PersistenceConfiguration.JooqHints.builtInTypes(getClass().getClassLoader());
        // SQLDataType alone has dozens; the dialect classes add their own (PostgreSQL's among them).
        assertThat(types).contains(String.class, Integer.class, OffsetDateTime.class, UUID.class);
        assertThat(types).allSatisfy(type -> assertThat(RuntimeHintsPredicates.reflection().onType(type.arrayType())).accepts(hints));
    }

    @Test void generatedRecordsCanBeInstantiated() {
        for (var record : new Class<?>[] {SubjectsRecord.class, WebauthnChallengeRecord.class}) {
            assertThat(RuntimeHintsPredicates.reflection().onType(record).withMemberCategory(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS))
                .accepts(hints);
        }
    }
}
