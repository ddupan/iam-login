package top.ddupan.iam.login.authentication.infrastructure.ad;

import java.net.URI;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.dao.DataAccessException;
import org.springframework.data.ldap.repository.support.SimpleLdapRepository;
import org.springframework.ldap.AuthenticationException;
import org.springframework.ldap.NamingException;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
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
    private final LdapContextSource contexts;

    public AdPasswordAuthenticator(AdProperties properties) {
        this.properties = properties;
        if (!properties.enabled()) { contexts = null; return; }
        var uri = URI.create(properties.url());
        if (!"ldaps".equals(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                || uri.getQuery() != null || uri.getFragment() != null
                || properties.domain() == null || properties.domain().isBlank()
                || properties.baseDn() == null || properties.baseDn().isBlank()) {
            throw new IllegalArgumentException("AD requires an LDAPS URL, domain and base DN");
        }
        contexts = new LdapContextSource();
        contexts.setUrl(properties.url());
        contexts.setBase(properties.baseDn());
        contexts.setPooled(false);
        contexts.setReferral("ignore");
        contexts.setBaseEnvironmentProperties(Map.of(
            "com.sun.jndi.ldap.connect.timeout", "3000",
            "com.sun.jndi.ldap.read.timeout", "5000",
            "java.naming.ldap.attributes.binary", "objectGUID"));
        contexts.afterPropertiesSet();
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
