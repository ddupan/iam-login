package top.ddupan.iam.login.authentication.infrastructure.persistence;

import java.util.function.Supplier;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.transaction.support.TransactionTemplate;

/** Serializes registration per user across sessions/processes in the same database transaction. */
public final class JdbcCredentialRegistration {
    private final JdbcOperations jdbc;
    private final TransactionTemplate transactions;

    public JdbcCredentialRegistration(JdbcOperations jdbc, TransactionTemplate transactions) {
        this.jdbc = jdbc;
        this.transactions = transactions;
    }

    public <T> T register(String userId, Supplier<T> registration) {
        return transactions.execute(status -> {
            jdbc.queryForObject("select id from user_entities where id = ? for update", String.class, userId);
            return registration.get();
        });
    }
}
