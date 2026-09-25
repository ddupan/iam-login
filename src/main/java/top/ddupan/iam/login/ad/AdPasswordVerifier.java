package top.ddupan.iam.login.ad;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.naming.NamingException;
import javax.naming.ldap.LdapName;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;
import org.springframework.stereotype.Service;

/** Invoke explicitly as a first factor; never register this as a web AuthenticationProvider. */
@Service
@EnableConfigurationProperties(AdProperties.class)
public class AdPasswordVerifier {
    private final ActiveDirectoryLdapAuthenticationProvider provider;
    private final AdProperties properties;

    public AdPasswordVerifier(AdProperties properties) {
        this.properties = properties;
        if (!properties.enabled()) {
            provider = null;
            return;
        }
        URI uri = URI.create(properties.url());
        if (!"ldaps".equals(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                || uri.getQuery() != null || uri.getFragment() != null
                || properties.domain() == null || properties.domain().isBlank()
                || properties.baseDn() == null || properties.baseDn().isBlank()) {
            throw new IllegalArgumentException("AD requires an LDAPS URL, domain and base DN");
        }
        provider = new ActiveDirectoryLdapAuthenticationProvider(
            properties.domain(), properties.url(), properties.baseDn());
        provider.setConvertSubErrorCodesToExceptions(true);
        provider.setUseAuthenticationRequestCredentials(false);
        provider.setSearchFilter("(&(objectClass=user)(!(objectClass=computer))(userPrincipalName={0}))");
        // AD domain searches include other naming-context references. Ignore them (never follow
        // with user credentials); Spring's AD provider already ignores partial-result exceptions.
        provider.setContextEnvironmentProperties(Map.of(
            "com.sun.jndi.ldap.connect.timeout", "3000",
            "com.sun.jndi.ldap.read.timeout", "5000",
            "java.naming.ldap.attributes.binary", "objectGUID",
            "java.naming.referral", "ignore"));
        // Directory groups are mapped independently; do not confuse FACTOR_PASSWORD with a group.
        provider.setAuthoritiesPopulator((entry, username) -> List.of());
        provider.setUserDetailsContextMapper(new IdentityMapper());
    }

    public boolean enabled() { return properties.enabled(); }

    public DirectoryIdentity verify(String username, String password) {
        if (provider == null) throw new IllegalStateException("AD login is disabled");
        if (username == null || username.isBlank() || username.length() > 256
                || username.contains("\\") || !username.equals(username.strip())
                || (username.contains("@") && !username.toLowerCase(java.util.Locale.ROOT)
                    .endsWith("@" + properties.domain().toLowerCase(java.util.Locale.ROOT)))
                || password == null || password.isEmpty() || password.length() > 1024) {
            throw new BadCredentialsException("Invalid credentials");
        }
        var token = UsernamePasswordAuthenticationToken.unauthenticated(username, password);
        try {
            var result = provider.authenticate(token);
            try {
                return ((IdentityUser) result.getPrincipal()).identity;
            } finally {
                if (result instanceof org.springframework.security.core.CredentialsContainer credentials) {
                    credentials.eraseCredentials();
                }
            }
        } finally {
            token.eraseCredentials();
        }
    }

    static final class IdentityUser extends User {
        final DirectoryIdentity identity;
        IdentityUser(DirectoryIdentity identity) {
            super(identity.username(), "", List.of());
            this.identity = identity;
        }
    }

    static final class IdentityMapper implements UserDetailsContextMapper {
        @Override
        public UserDetails mapUserFromContext(DirContextOperations entry, String username,
                Collection<? extends GrantedAuthority> authorities) {
            try {
                // Refuse an incomplete ranged result instead of silently dropping groups.
                var ids = entry.getAttributes().getIDs();
                try {
                    while (ids.hasMore()) {
                        if (ids.next().toLowerCase(java.util.Locale.ROOT).startsWith("memberof;")) {
                            throw new IllegalArgumentException("Ranged membership is not supported yet");
                        }
                    }
                } finally { ids.close(); }
                String account = required(entry, "sAMAccountName");
                String display = entry.getStringAttribute("displayName");
                String email = entry.getStringAttribute("mail");
                String[] membership = entry.getStringAttributes("memberOf");
                List<String> dns = membership == null ? List.of() : Arrays.stream(membership).sorted().toList();
                var groups = new java.util.TreeSet<String>();
                for (String dn : dns) {
                    var name = new LdapName(dn);
                    var rdn = name.getRdn(name.size() - 1);
                    if (!rdn.getType().equalsIgnoreCase("CN")) throw new IllegalArgumentException("Group has no CN");
                    if (!groups.add(rdn.getValue().toString())) throw new IllegalArgumentException("Ambiguous group CN");
                }
                return new IdentityUser(new DirectoryIdentity(
                    guid((byte[]) entry.getObjectAttribute("objectGUID")), account,
                    display == null ? account : display, email == null ? "" : email,
                    List.copyOf(groups), dns));
            } catch (NamingException | IllegalArgumentException | ClassCastException ex) {
                throw new InternalAuthenticationServiceException("Directory identity cannot be mapped", ex);
            }
        }

        @Override
        public void mapUserToContext(UserDetails user, DirContextAdapter context) {
            throw new UnsupportedOperationException("Read-only directory integration");
        }

        private static String required(DirContextOperations entry, String attribute) {
            String value = entry.getStringAttribute(attribute);
            if (value == null || value.isBlank()) throw new IllegalArgumentException("Missing directory attribute");
            return value;
        }
    }

    static String guid(byte[] bytes) {
        if (bytes == null || bytes.length != 16) throw new IllegalArgumentException("Invalid objectGUID");
        var little = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        long most = Integer.toUnsignedLong(little.getInt()) << 32
            | (long) Short.toUnsignedInt(little.getShort()) << 16
            | Short.toUnsignedInt(little.getShort());
        long least = ByteBuffer.wrap(bytes, 8, 8).getLong();
        return new UUID(most, least).toString();
    }
}
