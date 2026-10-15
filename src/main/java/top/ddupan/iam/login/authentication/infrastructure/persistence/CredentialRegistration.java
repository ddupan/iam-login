package top.ddupan.iam.login.authentication.infrastructure.persistence;

import java.util.function.Supplier;
import org.jooq.DSLContext;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Serializes changes to one account's second factors (passkeys and the authenticator app) across sessions and
 * processes: a transaction-scoped advisory lock on the account name, so adding and removing see each other and
 * the last factor cannot be removed twice. Not a row lock: an account with only an authenticator app has no
 * WebAuthn user entity to lock.
 */
public final class CredentialRegistration {
    private final DSLContext db;
    private final TransactionTemplate transactions;

    public CredentialRegistration(DSLContext db, TransactionTemplate transactions) {
        this.db = db;
        this.transactions = transactions;
    }

    public <T> T register(String owner, Supplier<T> registration) {
        return transactions.execute(status -> {
            db.fetch("select pg_advisory_xact_lock(hashtextextended(?, 0))", owner);
            return registration.get();
        });
    }
}
