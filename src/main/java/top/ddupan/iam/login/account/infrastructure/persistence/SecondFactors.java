package top.ddupan.iam.login.account.infrastructure.persistence;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import org.jooq.DSLContext;
import top.ddupan.iam.login.authentication.infrastructure.persistence.CredentialRegistration;
import static top.ddupan.iam.login.persistence.schema.Tables.SPRING_SESSION;
import static top.ddupan.iam.login.persistence.schema.Tables.TOTP_CREDENTIALS;
import static top.ddupan.iam.login.persistence.schema.Tables.USER_CREDENTIALS;
import static top.ddupan.iam.login.persistence.schema.Tables.USER_ENTITIES;

/**
 * An account's second factors: passkeys, in Spring Security's WebAuthn tables, and the
 * authenticator app. Every statement is scoped to the owner, so another account's credential id simply matches
 * nothing. At least one factor must remain, short of an administrator's reset; removals run under the registration lock, so two cannot both pass.
 */
public final class SecondFactors {
    public record Passkey(String id, String label, LocalDateTime created, LocalDateTime lastUsed) { }
    public record Authenticator(OffsetDateTime created, OffsetDateTime lastUsed) { }
    public enum Removal { REMOVED, NOT_FOUND, LAST }

    private final DSLContext db;
    private final CredentialRegistration registrations;

    public SecondFactors(DSLContext db, CredentialRegistration registrations) {
        this.db = db;
        this.registrations = registrations;
    }

    public List<Passkey> passkeys(String owner) {
        return db.select(USER_CREDENTIALS.CREDENTIAL_ID, USER_CREDENTIALS.LABEL, USER_CREDENTIALS.CREATED, USER_CREDENTIALS.LAST_USED)
            .from(USER_CREDENTIALS).join(USER_ENTITIES).on(USER_ENTITIES.ID.eq(USER_CREDENTIALS.USER_ENTITY_USER_ID))
            .where(USER_ENTITIES.NAME.eq(owner)).orderBy(USER_CREDENTIALS.CREATED)
            .fetch(r -> new Passkey(r.value1(), r.value2(), r.value3(), r.value4()));
    }

    public Optional<Authenticator> authenticator(String owner) {
        return db.select(TOTP_CREDENTIALS.CREATED, TOTP_CREDENTIALS.LAST_USED).from(TOTP_CREDENTIALS)
            .where(TOTP_CREDENTIALS.OWNER.eq(owner)).fetchOptional(r -> new Authenticator(r.value1(), r.value2()));
    }

    public boolean rename(String owner, String id, String label) {
        return db.update(USER_CREDENTIALS).set(USER_CREDENTIALS.LABEL, label)
            .where(USER_CREDENTIALS.CREDENTIAL_ID.eq(id), USER_CREDENTIALS.USER_ENTITY_USER_ID.eq(userId(owner)))
            .execute() == 1;
    }

    /**
     * Removing a factor also ends every other session of the account ({@code currentSession} stays): the factor may
     * be the one a lost device signed in with, and a session outlives its factors by up to the SSO lifetime.
     */
    public Removal removePasskey(String owner, String id, String currentSession) {
        var user = userId(owner);
        if (user == null) return Removal.NOT_FOUND;
        return registrations.register(owner, () -> {
            var mine = db.fetchExists(USER_CREDENTIALS, USER_CREDENTIALS.CREDENTIAL_ID.eq(id), USER_CREDENTIALS.USER_ENTITY_USER_ID.eq(user));
            if (!mine) return Removal.NOT_FOUND;
            if (count(owner) <= 1) return Removal.LAST;
            db.deleteFrom(USER_CREDENTIALS).where(USER_CREDENTIALS.CREDENTIAL_ID.eq(id)).execute();
            endOtherSessions(owner, currentSession);
            return Removal.REMOVED;
        });
    }

    /** As {@link #removePasskey}: other sessions end. */
    public Removal removeAuthenticator(String owner, String currentSession) {
        return registrations.register(owner, () -> {
            if (!db.fetchExists(TOTP_CREDENTIALS, TOTP_CREDENTIALS.OWNER.eq(owner))) return Removal.NOT_FOUND;
            if (count(owner) <= 1) return Removal.LAST;
            db.deleteFrom(TOTP_CREDENTIALS).where(TOTP_CREDENTIALS.OWNER.eq(owner)).execute();
            endOtherSessions(owner, currentSession);
            return Removal.REMOVED;
        });
    }

    /**
     * An administrator's reset: every factor of the account, and every session it has, so a sign-in already under
     * way cannot finish with the lost device. Its next sign-in sets a factor up again after the password.
     * Returns how many factors were removed.
     */
    public int reset(String owner) {
        return registrations.register(owner, () -> {
            var user = userId(owner);
            int removed = (user == null ? 0 : db.deleteFrom(USER_CREDENTIALS).where(USER_CREDENTIALS.USER_ENTITY_USER_ID.eq(user)).execute())
                + db.deleteFrom(TOTP_CREDENTIALS).where(TOTP_CREDENTIALS.OWNER.eq(owner)).execute();
            // Spring Session indexes each session by the authentication's name, which is the owner.
            db.deleteFrom(SPRING_SESSION).where(SPRING_SESSION.PRINCIPAL_NAME.eq(owner)).execute();
            return removed;
        });
    }

    /** Spring Session indexes each session by the authentication's name, which is the owner (see reset). */
    private void endOtherSessions(String owner, String currentSession) {
        db.deleteFrom(SPRING_SESSION).where(SPRING_SESSION.PRINCIPAL_NAME.eq(owner), SPRING_SESSION.SESSION_ID.ne(currentSession)).execute();
    }

    private int count(String owner) {
        return db.fetchCount(USER_CREDENTIALS, USER_CREDENTIALS.USER_ENTITY_USER_ID.eq(userId(owner)))
            + db.fetchCount(TOTP_CREDENTIALS, TOTP_CREDENTIALS.OWNER.eq(owner));
    }

    private String userId(String owner) {
        return db.select(USER_ENTITIES.ID).from(USER_ENTITIES).where(USER_ENTITIES.NAME.eq(owner)).fetchOne(USER_ENTITIES.ID);
    }
}
