package top.ddupan.iam.login.authentication.infrastructure.ad;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;
import java.util.Optional;
import java.util.TreeMap;
import java.util.UUID;
import javax.naming.NamingException;
import javax.naming.ldap.LdapName;
import org.springframework.dao.DataAccessException;
import org.springframework.data.ldap.repository.LdapRepository;
import org.springframework.ldap.core.support.SingleContextSource;
import top.ddupan.iam.login.authentication.application.port.AuthenticatedUserSession;
import top.ddupan.iam.login.authentication.domain.User.GroupMembership;
import top.ddupan.iam.login.authentication.domain.User.UserId;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authentication.domain.UserRepository;
import static org.springframework.ldap.query.LdapQueryBuilder.query;

/** One authenticated connection and one Spring Data repository per use-case scope. */
final class AdUserRepository implements UserRepository, AuthenticatedUserSession {
    private final LdapRepository<AdUserEntry> entries;
    private final SingleContextSource connection;
    private final String authority;
    private final String loginName;
    private boolean closed;

    AdUserRepository(LdapRepository<AdUserEntry> entries, SingleContextSource connection,
            String authority, String loginName) {
        this.entries = entries;
        this.connection = connection;
        this.authority = authority;
        this.loginName = loginName;
    }

    @Override
    public Optional<User> findByLoginName(String name) {
        requireOpen();
        try {
            return entries.findOne(query().where("objectClass").is("user")
                .and("objectClass").not().is("computer")
                .and(query().where("sAMAccountName").is(name).or("userPrincipalName").is(name)))
                .map(this::toUser);
        } catch (org.springframework.ldap.NamingException | DataAccessException | IllegalArgumentException ex) {
            throw new UserRepository.AccessFailure();
        }
    }

    private User toUser(AdUserEntry entry) {
        var groups = new TreeMap<String, GroupMembership>();
        for (String dn : entry.getMemberOf() == null ? List.<String>of() : entry.getMemberOf()) {
            try {
                var name = new LdapName(dn);
                var rdn = name.getRdn(name.size() - 1);
                if (!rdn.getType().equalsIgnoreCase("CN")) throw new UserRepository.AccessFailure();
                String cn = rdn.getValue().toString();
                if (groups.putIfAbsent(cn, new GroupMembership(cn, dn)) != null) {
                    throw new UserRepository.AccessFailure();
                }
            } catch (NamingException ex) { throw new UserRepository.AccessFailure(); }
        }
        return new User(new UserId(authority, guid(entry.getObjectGuid())), entry.getAccountName(),
            entry.getDisplayName() == null ? entry.getAccountName() : entry.getDisplayName(),
            entry.getEmail() == null ? "" : entry.getEmail(), List.copyOf(groups.values()));
    }

    static String guid(byte[] bytes) {
        if (bytes == null || bytes.length != 16) throw new UserRepository.AccessFailure();
        var little = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        long most = Integer.toUnsignedLong(little.getInt()) << 32
            | (long) Short.toUnsignedInt(little.getShort()) << 16
            | Short.toUnsignedInt(little.getShort());
        return new UUID(most, ByteBuffer.wrap(bytes, 8, 8).getLong()).toString();
    }

    @Override public String loginName() { requireOpen(); return loginName; }
    @Override public UserRepository users() { requireOpen(); return this; }
    private void requireOpen() { if (closed) throw new IllegalStateException("User repository scope is closed"); }
    @Override public void close() {
        if (!closed) { closed = true; connection.destroy(); }
    }
}
