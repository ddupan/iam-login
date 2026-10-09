package top.ddupan.iam.login.authorization.infrastructure.persistence;

import java.util.Optional;
import java.util.UUID;
import org.jooq.DSLContext;
import top.ddupan.iam.login.authentication.domain.User;
import static top.ddupan.iam.login.persistence.schema.Tables.SUBJECTS;

/**
 * The OIDC subject of each account: a random UUID issued on first sign-in and never changed or reused. The account
 * (directory authority + immutable directory id) is only linked to it, so renames keep the subject and a different
 * account never gets one that was issued before. Subjects carried over from an earlier issuer are rows like any
 * other, inserted once during that migration.
 */
public class Subjects {
    private final DSLContext db;

    public Subjects(DSLContext db) {
        this.db = db;
    }

    /** The account's subject, issuing one on first use; concurrent first sign-ins agree on a single subject. */
    public String issue(User.UserId account) {
        db.insertInto(SUBJECTS, SUBJECTS.SUBJECT, SUBJECTS.AUTHORITY, SUBJECTS.DIRECTORY_ID)
            .values(UUID.randomUUID().toString(), account.authority(), account.value())
            .onConflict(SUBJECTS.AUTHORITY, SUBJECTS.DIRECTORY_ID).doNothing()
            .execute();
        return find(account).orElseThrow();
    }

    /** Without issuing: an account whose subject was removed has no identity here any more. */
    public Optional<String> find(User.UserId account) {
        return db.select(SUBJECTS.SUBJECT).from(SUBJECTS)
            .where(SUBJECTS.AUTHORITY.eq(account.authority()), SUBJECTS.DIRECTORY_ID.eq(account.value()))
            .fetchOptional(SUBJECTS.SUBJECT);
    }
}
