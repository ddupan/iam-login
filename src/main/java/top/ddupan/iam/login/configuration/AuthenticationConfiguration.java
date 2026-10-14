package top.ddupan.iam.login.configuration;

import javax.naming.directory.DirContext;
import javax.naming.ldap.LdapContext;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.annotation.RegisterReflectionForBinding;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportRuntimeHints;
import org.springframework.ldap.core.DirContextProxy;
import org.springframework.ldap.core.LdapOperations;
import org.springframework.ldap.odm.core.ObjectDirectoryMapper;
import top.ddupan.iam.login.authentication.domain.UserRepository;
import top.ddupan.iam.login.authentication.infrastructure.ad.AdEntryMapper;
import top.ddupan.iam.login.authentication.infrastructure.ad.AdProperties;
import top.ddupan.iam.login.authentication.infrastructure.ad.AdUserEntry;
import top.ddupan.iam.login.authentication.infrastructure.ad.AdUsers;

/** Directory settings, reads without the user present, and the native-image metadata the LDAP mapping needs. */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(AdProperties.class)
@RegisterReflectionForBinding(AdUserEntry.class)
@ImportRuntimeHints(AuthenticationConfiguration.DirectoryHints.class)
class AuthenticationConfiguration {
    /** Replaces Boot's mapper, so its LdapTemplate refuses truncated memberOf like the sign-in mapping does. */
    @Bean ObjectDirectoryMapper objectDirectoryMapper() {
        return new AdEntryMapper();
    }

    @Bean @ConditionalOnProperty(prefix = "iam.ad", name = "enabled", havingValue = "true")
    UserRepository users(LdapOperations ldap, AdProperties ad) {
        return new AdUsers(ldap, ad.domain());
    }

    static class DirectoryHints implements RuntimeHintsRegistrar {
        @Override
        public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
            hints.proxies().registerJdkProxy(LdapContext.class, DirContextProxy.class);
            hints.proxies().registerJdkProxy(DirContext.class, DirContextProxy.class);
        }
    }
}
