package top.ddupan.iam.login.authentication.infrastructure.totp;

import java.util.Optional;
import org.jooq.DSLContext;
import org.jooq.impl.DSL;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import static top.ddupan.iam.login.persistence.schema.Tables.TOTP_CREDENTIALS;

/** Each account's authenticator app key, encrypted at rest. */
public final class TotpCredentials {
    private final DSLContext db;
    private final BytesEncryptor encryptor;

    public TotpCredentials(DSLContext db, BytesEncryptor encryptor) {
        this.db = db;
        this.encryptor = encryptor;
    }

    public boolean exists(String owner) {
        return db.fetchExists(TOTP_CREDENTIALS, TOTP_CREDENTIALS.OWNER.eq(owner));
    }

    public Optional<byte[]> key(String owner) {
        return db.select(TOTP_CREDENTIALS.SECRET).from(TOTP_CREDENTIALS).where(TOTP_CREDENTIALS.OWNER.eq(owner))
            .fetchOptional(TOTP_CREDENTIALS.SECRET).map(encryptor::decrypt);
    }

    /** Sets up (or replaces) the account's key; the code that confirmed it counts as used. */
    public void save(String owner, byte[] key, long step) {
        var secret = encryptor.encrypt(key);
        db.insertInto(TOTP_CREDENTIALS).set(TOTP_CREDENTIALS.OWNER, owner).set(TOTP_CREDENTIALS.SECRET, secret)
            .set(TOTP_CREDENTIALS.LAST_USED, DSL.currentOffsetDateTime()).set(TOTP_CREDENTIALS.LAST_STEP, step)
            .onConflict(TOTP_CREDENTIALS.OWNER).doUpdate().set(TOTP_CREDENTIALS.SECRET, secret)
            .set(TOTP_CREDENTIALS.CREATED, DSL.currentOffsetDateTime()).set(TOTP_CREDENTIALS.LAST_USED, DSL.currentOffsetDateTime())
            .set(TOTP_CREDENTIALS.LAST_STEP, step).execute();
    }

    /** Records the step as used; false when it, or a later one, already was: a replayed code. */
    public boolean use(String owner, long step) {
        return db.update(TOTP_CREDENTIALS).set(TOTP_CREDENTIALS.LAST_STEP, step)
            .set(TOTP_CREDENTIALS.LAST_USED, DSL.currentOffsetDateTime())
            .where(TOTP_CREDENTIALS.OWNER.eq(owner), TOTP_CREDENTIALS.LAST_STEP.lt(step)).execute() == 1;
    }
}
