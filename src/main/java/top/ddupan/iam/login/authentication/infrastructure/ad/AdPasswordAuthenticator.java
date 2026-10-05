package top.ddupan.iam.login.authentication.infrastructure.ad;

import java.net.URI;
import java.util.Arrays;
import java.util.Locale;
import java.util.regex.Pattern;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.ldap.autoconfigure.LdapProperties;
import org.springframework.dao.DataAccessException;
import org.springframework.data.ldap.repository.support.SimpleLdapRepository;
import org.springframework.ldap.AuthenticationException;
import org.springframework.ldap.NamingException;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.support.SingleContextSource;
import org.springframework.stereotype.Component;
import top.ddupan.iam.login.authentication.application.port.AuthenticatedUserSession;
import top.ddupan.iam.login.authentication.application.port.PasswordAuthenticator;
import top.ddupan.iam.login.authentication.application.port.PasswordVerificationException.Reason;
import top.ddupan.iam.login.authentication.application.port.PasswordVerificationException;

/** Bind authenticates; the scoped Spring Data repository owns all user and membership reads. */
@Component
@EnableConfigurationProperties(AdProperties.class)
public final class AdPasswordAuthenticator implements PasswordAuthenticator {
    private static final Pattern AD_SUBCODE = Pattern.compile("\\bdata\\s+([0-9a-f]+)", Pattern.CASE_INSENSITIVE);
    private final AdProperties properties;
    private final ContextSource contexts;

    /**
     * Binds through Boot's auto-configured ContextSource (spring.ldap.*), so Boot's LDAP health indicator
     * checks the same LDAPS connection users bind over. Read-only contexts are anonymous: there is no
     * service account, and the health check only opens a connection.
     */
    public AdPasswordAuthenticator(AdProperties properties, LdapProperties ldap, ContextSource contexts) {
        if (properties.enabled() && (ldap.getUrls() == null || ldap.getUrls().length == 0
                || !Arrays.stream(ldap.getUrls()).allMatch(AdPasswordAuthenticator::isLdaps)
                || properties.domain() == null || properties.domain().isBlank()
                || ldap.getBase() == null || ldap.getBase().isBlank())) {
            throw new IllegalArgumentException("AD requires LDAPS spring.ldap.urls, spring.ldap.base and iam.ad.domain");
        }
        this.properties = properties;
        this.contexts = properties.enabled() ? contexts : null;
    }

    private static boolean isLdaps(String url) {
        var uri = URI.create(url);
        return "ldaps".equals(uri.getScheme()) && uri.getHost() != null && uri.getUserInfo() == null
            && uri.getQuery() == null && uri.getFragment() == null;
    }

    @Override
    public AuthenticatedUserSession authenticate(String username, String password) {
        if (contexts == null) throw new PasswordVerificationException(Reason.UNAVAILABLE);
        if (username == null || username.isBlank() || username.length() > 256
                || username.contains("\\") || !username.equals(username.strip())
                || (username.contains("@") && !username.toLowerCase(Locale.ROOT)
                    .endsWith("@" + properties.domain().toLowerCase(Locale.ROOT)))
                || password == null || password.isEmpty() || password.length() > 1024) {
            throw new PasswordVerificationException(Reason.REJECTED);
        }
        String principal = username.contains("@") ? username : username + "@" + properties.domain();
        try {
            var connection = new SingleContextSource(contexts.getContext(principal, password));
            try {
                var mapper = new AdEntryMapper();
                var operations = new LdapTemplate(connection);
                operations.setIgnorePartialResultException(true);
                operations.setObjectDirectoryMapper(mapper);
                var entries = new SimpleLdapRepository<>(operations, mapper, AdUserEntry.class);
                return new AdUserRepository(entries, connection, properties.domain(), principal);
            } catch (RuntimeException ex) {
                connection.destroy();
                throw ex;
            }
        } catch (AuthenticationException ex) {
            throw new PasswordVerificationException(reason(ex));
        } catch (NamingException | DataAccessException ex) {
            throw new PasswordVerificationException(Reason.UNAVAILABLE);
        }
    }

    private static Reason reason(AuthenticationException exception) {
        // Translate AD's diagnostic codes; never expose the diagnostic or credentials to the use case.
        var matcher = AD_SUBCODE.matcher(exception.getMessage() == null ? "" : exception.getMessage());
        if (!matcher.find()) return Reason.REJECTED;
        return switch (matcher.group(1).toLowerCase(Locale.ROOT)) {
            case "533" -> Reason.DISABLED;
            case "775" -> Reason.LOCKED;
            case "532", "773" -> Reason.PASSWORD_EXPIRED;
            case "701" -> Reason.ACCOUNT_EXPIRED;
            default -> Reason.REJECTED;
        };
    }
}
