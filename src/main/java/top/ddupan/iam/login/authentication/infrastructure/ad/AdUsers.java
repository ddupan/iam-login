package top.ddupan.iam.login.authentication.infrastructure.ad;

import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;
import org.springframework.ldap.NamingException;
import org.springframework.ldap.core.LdapOperations;
import org.springframework.ldap.filter.HardcodedFilter;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authentication.domain.UserRepository;
import static org.springframework.ldap.query.LdapQueryBuilder.query;

/**
 * Directory reads without the user present, over Boot's connection (the read-only service account). Looked up by
 * objectGUID, the immutable id the subject is linked to, so a renamed account is still found.
 */
public final class AdUsers implements UserRepository {
    private static final int ACCOUNT_DISABLED = 0x2;   // userAccountControl ACCOUNTDISABLE
    private final LdapOperations ldap;
    private final String authority;

    public AdUsers(LdapOperations ldap, String authority) {
        this.ldap = ldap;
        this.authority = authority;
    }

    @Override
    public Optional<User> findActive(User.UserId id) {
        if (!authority.equals(id.authority())) return Optional.empty();
        UUID guid;
        try { guid = UUID.fromString(id.value()); } catch (IllegalArgumentException ex) { return Optional.empty(); }
        // Every byte escaped: an octet-string value has no other safe filter encoding.
        var value = HexFormat.ofDelimiter("\\").withPrefix("").formatHex(AdUserDetailsMapper.guidBytes(guid));
        try {
            // ODM adds objectClass=user; computer accounts are users too.
            var found = ldap.find(query().filter(new HardcodedFilter("(&(!(objectClass=computer))(objectGUID=\\" + value + "))")),
                AdUserEntry.class);
            if (found.size() > 1) throw new AccessFailure();
            if (found.isEmpty() || disabled(found.getFirst())) return Optional.empty();
            return Optional.of(AdUserDetailsMapper.toUser(found.getFirst(), authority));
        } catch (NamingException ex) {
            throw new AccessFailure(ex);
        }
    }

    private static boolean disabled(AdUserEntry entry) {
        try {
            return (Integer.parseInt(entry.getAccountControl()) & ACCOUNT_DISABLED) != 0;
        } catch (NumberFormatException ex) {
            throw new AccessFailure();   // AD always has it; without it, "enabled" cannot be told
        }
    }
}
