package top.ddupan.iam.login.authentication.infrastructure.ad;

import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import org.springframework.boot.ldap.autoconfigure.LdapProperties;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;

/** Spring Security's AD provider, configured from the same spring.ldap.* Boot uses for its ContextSource. */
public final class ActiveDirectory {
    // {0} is the bind principal (user@domain), {1} the name as typed: either the UPN or the account name.
    private static final String USER_FILTER =
        "(&(objectClass=user)(!(objectClass=computer))(|(userPrincipalName={0})(sAMAccountName={1})))";

    private ActiveDirectory() { }

    /** Not a bean on purpose: an AuthenticationProvider bean would also serve the management chain's Basic login. */
    public static ActiveDirectoryLdapAuthenticationProvider provider(AdProperties ad, LdapProperties ldap) {
        if (ldap.getUrls() == null || ldap.getUrls().length == 0
                || !Arrays.stream(ldap.getUrls()).allMatch(ActiveDirectory::isLdaps)
                || ad.domain() == null || ad.domain().isBlank()
                || ldap.getBase() == null || ldap.getBase().isBlank()) {
            throw new IllegalArgumentException("AD requires LDAPS spring.ldap.urls, spring.ldap.base and iam.ad.domain");
        }
        // JNDI tries space-separated URLs in order, as Boot's ContextSource does.
        var provider = new ActiveDirectoryLdapAuthenticationProvider(ad.domain(), String.join(" ", ldap.getUrls()),
            ldap.getBase());
        provider.setSearchFilter(USER_FILTER);
        // Locked, disabled and expired become their own exceptions instead of a bare bad-credentials failure.
        provider.setConvertSubErrorCodesToExceptions(true);
        // Referrals ignored, objectGUID binary and the timeouts: the same environment as Boot's ContextSource.
        provider.setContextEnvironmentProperties(new HashMap<>(ldap.getBaseEnvironment()));
        provider.setUserDetailsContextMapper(new AdUserDetailsMapper(ad.domain()));
        return provider;
    }

    private static boolean isLdaps(String url) {
        var uri = URI.create(url);
        return "ldaps".equals(uri.getScheme()) && uri.getHost() != null && uri.getUserInfo() == null
            && uri.getQuery() == null && uri.getFragment() == null;
    }
}
