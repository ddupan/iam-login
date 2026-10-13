package top.ddupan.iam.login.configuration;

import javax.naming.directory.DirContext;
import javax.naming.ldap.LdapContext;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.annotation.RegisterReflectionForBinding;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportRuntimeHints;
import org.springframework.ldap.core.DirContextProxy;
import top.ddupan.iam.login.authentication.infrastructure.ad.AdProperties;
import top.ddupan.iam.login.authentication.infrastructure.ad.AdUserEntry;

/** Directory settings and the native-image metadata the LDAP mapping needs. */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(AdProperties.class)
@RegisterReflectionForBinding(AdUserEntry.class)
@ImportRuntimeHints(AuthenticationConfiguration.DirectoryHints.class)
class AuthenticationConfiguration {
    static class DirectoryHints implements RuntimeHintsRegistrar {
        @Override
        public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
            hints.proxies().registerJdkProxy(LdapContext.class, DirContextProxy.class);
            hints.proxies().registerJdkProxy(DirContext.class, DirContextProxy.class);
        }
    }
}
