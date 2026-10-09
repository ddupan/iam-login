package top.ddupan.iam.login.authentication.infrastructure.persistence;

import java.util.function.Supplier;
import org.jooq.DSLContext;
import org.springframework.transaction.support.TransactionTemplate;
import static top.ddupan.iam.login.persistence.schema.Tables.USER_ENTITIES;

/** Serializes registration per user across sessions/processes in the same database transaction. */
public final class CredentialRegistration {
    private final DSLContext db;
    private final TransactionTemplate transactions;

    public CredentialRegistration(DSLContext db, TransactionTemplate transactions) {
        this.db = db;
        this.transactions = transactions;
    }

    public <T> T register(String userId, Supplier<T> registration) {
        return transactions.execute(status -> {
            db.select(USER_ENTITIES.ID).from(USER_ENTITIES).where(USER_ENTITIES.ID.eq(userId)).forUpdate().fetchSingle();
            return registration.get();
        });
    }
}
