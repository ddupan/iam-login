package top.ddupan.iam.login.account.infrastructure.persistence;

import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.jooq.DSLContext;
import org.springframework.transaction.support.TransactionTemplate;
import static org.jooq.impl.DSL.greatest;
import static top.ddupan.iam.login.persistence.schema.Tables.OAUTH2_AUTHORIZATION;
import static top.ddupan.iam.login.persistence.schema.Tables.OAUTH2_AUTHORIZATION_CONSENT;
import static top.ddupan.iam.login.persistence.schema.Tables.OAUTH2_REGISTERED_CLIENT;

/**
 * Applications the account has granted access to: a remembered consent, or authorizations still on record (clients
 * without a consent page have only those). Revoking removes both, so refresh tokens stop working at once.
 */
public final class Grants {
    public record Grant(String clientId, String name, Set<String> scopes, OffsetDateTime lastIssued) { }

    private final DSLContext db;
    private final TransactionTemplate transactions;

    public Grants(DSLContext db, TransactionTemplate transactions) {
        this.db = db;
        this.transactions = transactions;
    }

    public List<Grant> list(String principal) {
        var grants = new LinkedHashMap<String, Grant>();
        db.select(OAUTH2_REGISTERED_CLIENT.CLIENT_ID, OAUTH2_REGISTERED_CLIENT.CLIENT_NAME, OAUTH2_AUTHORIZATION_CONSENT.AUTHORITIES)
            .from(OAUTH2_AUTHORIZATION_CONSENT).join(OAUTH2_REGISTERED_CLIENT)
            .on(OAUTH2_REGISTERED_CLIENT.ID.eq(OAUTH2_AUTHORIZATION_CONSENT.REGISTERED_CLIENT_ID))
            .where(OAUTH2_AUTHORIZATION_CONSENT.PRINCIPAL_NAME.eq(principal))
            .forEach(r -> grants.put(r.value1(), new Grant(r.value1(), r.value2(), scopes(r.value3(), "SCOPE_"), null)));
        var issued = greatest(OAUTH2_AUTHORIZATION.AUTHORIZATION_CODE_ISSUED_AT, OAUTH2_AUTHORIZATION.ACCESS_TOKEN_ISSUED_AT,
            OAUTH2_AUTHORIZATION.REFRESH_TOKEN_ISSUED_AT);
        db.select(OAUTH2_REGISTERED_CLIENT.CLIENT_ID, OAUTH2_REGISTERED_CLIENT.CLIENT_NAME, OAUTH2_AUTHORIZATION.AUTHORIZED_SCOPES, issued)
            .from(OAUTH2_AUTHORIZATION).join(OAUTH2_REGISTERED_CLIENT)
            .on(OAUTH2_REGISTERED_CLIENT.ID.eq(OAUTH2_AUTHORIZATION.REGISTERED_CLIENT_ID))
            .where(OAUTH2_AUTHORIZATION.PRINCIPAL_NAME.eq(principal))
            .forEach(r -> grants.merge(r.value1(), new Grant(r.value1(), r.value2(), scopes(r.value3(), ""), r.value4()),
                (a, b) -> new Grant(a.clientId(), a.name(), union(a.scopes(), b.scopes()), latest(a.lastIssued(), b.lastIssued()))));
        return grants.values().stream().sorted(Comparator.comparing(Grant::name, String.CASE_INSENSITIVE_ORDER)).toList();
    }

    /** False when the account had nothing granted to that client. */
    public boolean revoke(String principal, String clientId) {
        return Boolean.TRUE.equals(transactions.execute(status -> {
            var client = db.select(OAUTH2_REGISTERED_CLIENT.ID).from(OAUTH2_REGISTERED_CLIENT)
                .where(OAUTH2_REGISTERED_CLIENT.CLIENT_ID.eq(clientId)).fetchOne(OAUTH2_REGISTERED_CLIENT.ID);
            if (client == null) return false;
            int removed = db.deleteFrom(OAUTH2_AUTHORIZATION_CONSENT).where(OAUTH2_AUTHORIZATION_CONSENT.REGISTERED_CLIENT_ID.eq(client),
                OAUTH2_AUTHORIZATION_CONSENT.PRINCIPAL_NAME.eq(principal)).execute();
            removed += db.deleteFrom(OAUTH2_AUTHORIZATION).where(OAUTH2_AUTHORIZATION.REGISTERED_CLIENT_ID.eq(client),
                OAUTH2_AUTHORIZATION.PRINCIPAL_NAME.eq(principal)).execute();
            return removed > 0;
        }));
    }

    private static Set<String> scopes(String value, String prefix) {
        var scopes = new TreeSet<String>();
        if (value == null) return scopes;
        Arrays.stream(value.split(",")).map(String::trim).filter(s -> s.startsWith(prefix) && s.length() > prefix.length())
            .forEach(s -> scopes.add(s.substring(prefix.length())));
        return scopes;
    }

    private static Set<String> union(Set<String> a, Set<String> b) {
        var all = new TreeSet<>(a);
        all.addAll(b);
        return all;
    }

    private static OffsetDateTime latest(OffsetDateTime a, OffsetDateTime b) {
        return a == null ? b : b == null ? a : a.isAfter(b) ? a : b;
    }
}
