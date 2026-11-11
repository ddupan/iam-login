package top.ddupan.iam.login.authentication.infrastructure.ad;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.TreeMap;
import java.util.UUID;
import javax.naming.NamingException;
import javax.naming.ldap.LdapName;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;
import top.ddupan.iam.login.authentication.domain.User.GroupMembership;
import top.ddupan.iam.login.authentication.domain.User.UserId;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authentication.domain.UserRepository;

/**
 * Turns the entry the AD provider found, read over the user's own bind, into our user. Goes through the same ODM
 * mapping (and truncation check) as any other read of {@link AdUserEntry}.
 */
final class AdUserDetailsMapper implements UserDetailsContextMapper {
    private final AdEntryMapper entries = new AdEntryMapper();
    private final String authority;

    AdUserDetailsMapper(String authority) {
        this.authority = authority;
    }

    @Override
    public UserDetails mapUserFromContext(DirContextOperations context, String username,
            Collection<? extends GrantedAuthority> authorities) {
        var entry = entries.mapFromLdapDataEntry(context, AdUserEntry.class);
        if (entry == null) throw new UserRepository.AccessFailure();
        return new AdUser(toUser(entry, authority));
    }

    @Override
    public void mapUserToContext(UserDetails user, DirContextAdapter context) {
        throw new UnsupportedOperationException("The directory is read-only here");
    }

    static User toUser(AdUserEntry entry, String authority) {
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
            entry.getEmail() == null ? "" : entry.getEmail(), List.copyOf(groups.values()),
            passwordChangedAt(entry.getPasswordLastSet()));
    }

    /** 100 ns intervals between 1601-01-01 (FILETIME's epoch) and 1970-01-01. */
    private static final long FILETIME_UNIX_EPOCH = 116_444_736_000_000_000L;

    /**
     * pwdLastSet is a FILETIME. 0 means "must change at next logon" (an administrator reset or forced it); absent
     * means unknown, which revokes nothing.
     */
    static Instant passwordChangedAt(String pwdLastSet) {
        if (pwdLastSet == null || pwdLastSet.isBlank()) return null;
        long filetime;
        try { filetime = Long.parseLong(pwdLastSet.strip()); } catch (NumberFormatException ex) { throw new UserRepository.AccessFailure(); }
        if (filetime == 0) return Instant.MAX;
        long units = filetime - FILETIME_UNIX_EPOCH;
        return Instant.ofEpochSecond(Math.floorDiv(units, 10_000_000L), Math.floorMod(units, 10_000_000L) * 100);
    }

    static String guid(byte[] bytes) {
        if (bytes == null || bytes.length != 16) throw new UserRepository.AccessFailure();
        var little = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        long most = Integer.toUnsignedLong(little.getInt()) << 32
            | (long) Short.toUnsignedInt(little.getShort()) << 16
            | Short.toUnsignedInt(little.getShort());
        return new UUID(most, ByteBuffer.wrap(bytes, 8, 8).getLong()).toString();
    }

    /** The inverse of {@link #guid}: AD stores the first three fields little-endian. */
    static byte[] guidBytes(UUID guid) {
        long most = guid.getMostSignificantBits();
        return ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
            .putInt((int) (most >>> 32)).putShort((short) (most >>> 16)).putShort((short) most)
            .order(ByteOrder.BIG_ENDIAN).putLong(guid.getLeastSignificantBits()).array();
    }
}
