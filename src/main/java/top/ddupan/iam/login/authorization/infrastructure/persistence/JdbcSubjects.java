package top.ddupan.iam.login.authorization.infrastructure.persistence;

import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcOperations;
import top.ddupan.iam.login.authentication.domain.User;

/**
 * The OIDC subject of each account: a random UUID issued on first sign-in and never changed or reused. The account
 * (directory authority + immutable directory id) is only linked to it, so renames keep the subject and a different
 * account never gets one that was issued before. Subjects carried over from an earlier issuer are rows like any
 * other, inserted once during that migration.
 */
public class JdbcSubjects {
    private final JdbcOperations jdbc;

    public JdbcSubjects(JdbcOperations jdbc) {
        this.jdbc = jdbc;
    }

    /** The account's subject, issuing one on first use; concurrent first sign-ins agree on a single subject. */
    public String issue(User.UserId account) {
        jdbc.update("insert into subjects (subject, authority, directory_id) values (?, ?, ?) "
            + "on conflict (authority, directory_id) do nothing",
            UUID.randomUUID().toString(), account.authority(), account.value());
        return find(account).orElseThrow();
    }

    /** Without issuing: an account whose subject was removed has no identity here any more. */
    public Optional<String> find(User.UserId account) {
        return jdbc.queryForList("select subject from subjects where authority = ? and directory_id = ?",
            String.class, account.authority(), account.value()).stream().findFirst();
    }
}
