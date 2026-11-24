package top.ddupan.iam.login.authentication.infrastructure.ad;

import java.util.Locale;
import javax.naming.NamingException;
import org.springframework.LdapDataEntry;
import org.springframework.ldap.odm.core.impl.DefaultObjectDirectoryMapper;
import top.ddupan.iam.login.authentication.domain.UserRepository;

/** Keep Spring's ODM mapping while refusing silently truncated AD group attributes. Boot's LdapTemplate uses it too. */
public final class AdEntryMapper extends DefaultObjectDirectoryMapper {
    @Override
    public <T> T mapFromLdapDataEntry(LdapDataEntry entry, Class<T> type) {
        var ids = entry.getAttributes().getIDs();
        try {
            while (ids.hasMore()) {
                if (ids.next().toLowerCase(Locale.ROOT).startsWith("memberof;")) {
                    throw new UserRepository.AccessFailure();
                }
            }
        } catch (NamingException ex) {
            throw new UserRepository.AccessFailure();
        } finally {
            try { ids.close(); } catch (NamingException ignored) { /* already failed or done; nothing to recover */ }
        }
        return super.mapFromLdapDataEntry(entry, type);
    }
}
