package top.ddupan.iam.login.account.infrastructure.persistence;

import java.time.LocalDateTime;
import java.util.List;
import org.jooq.DSLContext;
import top.ddupan.iam.login.authentication.infrastructure.persistence.CredentialRegistration;
import static top.ddupan.iam.login.persistence.schema.Tables.USER_CREDENTIALS;
import static top.ddupan.iam.login.persistence.schema.Tables.USER_ENTITIES;

/**
 * The signed-in account's own passkeys, in Spring Security's WebAuthn tables. Every statement is scoped to the
 * owner, so another account's credential id simply matches nothing.
 */
public final class Passkeys {
    public record Passkey(String id, String label, LocalDateTime created, LocalDateTime lastUsed) { }
    public enum Removal { REMOVED, NOT_FOUND, LAST }

    private final DSLContext db;
    private final CredentialRegistration registrations;

    public Passkeys(DSLContext db, CredentialRegistration registrations) {
        this.db = db;
        this.registrations = registrations;
    }

    public List<Passkey> list(String owner) {
        return db.select(USER_CREDENTIALS.CREDENTIAL_ID, USER_CREDENTIALS.LABEL, USER_CREDENTIALS.CREATED, USER_CREDENTIALS.LAST_USED)
            .from(USER_CREDENTIALS).join(USER_ENTITIES).on(USER_ENTITIES.ID.eq(USER_CREDENTIALS.USER_ENTITY_USER_ID))
            .where(USER_ENTITIES.NAME.eq(owner)).orderBy(USER_CREDENTIALS.CREATED)
            .fetch(r -> new Passkey(r.value1(), r.value2(), r.value3(), r.value4()));
    }

    public boolean rename(String owner, String id, String label) {
        return db.update(USER_CREDENTIALS).set(USER_CREDENTIALS.LABEL, label)
            .where(USER_CREDENTIALS.CREDENTIAL_ID.eq(id), USER_CREDENTIALS.USER_ENTITY_USER_ID.eq(userId(owner)))
            .execute() == 1;
    }

    /** At least one second factor must remain; under the registration lock, so two removals cannot both pass. */
    public Removal remove(String owner, String id) {
        var user = userId(owner);
        if (user == null) return Removal.NOT_FOUND;
        return registrations.register(user, () -> {
            var mine = db.fetchExists(USER_CREDENTIALS, USER_CREDENTIALS.CREDENTIAL_ID.eq(id), USER_CREDENTIALS.USER_ENTITY_USER_ID.eq(user));
            if (!mine) return Removal.NOT_FOUND;
            if (db.fetchCount(USER_CREDENTIALS, USER_CREDENTIALS.USER_ENTITY_USER_ID.eq(user)) <= 1) return Removal.LAST;
            db.deleteFrom(USER_CREDENTIALS).where(USER_CREDENTIALS.CREDENTIAL_ID.eq(id)).execute();
            return Removal.REMOVED;
        });
    }

    private String userId(String owner) {
        return db.select(USER_ENTITIES.ID).from(USER_ENTITIES).where(USER_ENTITIES.NAME.eq(owner)).fetchOne(USER_ENTITIES.ID);
    }
}
