package top.ddupan.iam.login.configuration;

import java.time.Clock;
import javax.naming.directory.DirContext;
import javax.naming.ldap.LdapContext;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.annotation.RegisterReflectionForBinding;
import org.springframework.context.annotation.ImportRuntimeHints;
import org.springframework.ldap.core.DirContextProxy;
import top.ddupan.iam.login.authentication.infrastructure.ad.AdUserEntry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import top.ddupan.iam.login.authentication.application.SignInService;
import top.ddupan.iam.login.authentication.application.port.PasswordAuthenticator;
import top.ddupan.iam.login.authentication.infrastructure.ad.AdProperties;

/** Composition root: dependencies point inward, framework wiring stays outside the model. */
@Configuration(proxyBeanMethods = false)
@RegisterReflectionForBinding(AdUserEntry.class)
@ImportRuntimeHints(AuthenticationConfiguration.DirectoryHints.class)
class AuthenticationConfiguration {
    @Bean
    SignInService signInService(PasswordAuthenticator authenticator, AdProperties properties) {
        return new SignInService(authenticator, Clock.systemUTC(), properties.enabled());
    }
    static class DirectoryHints implements RuntimeHintsRegistrar {
        @Override
        public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
            hints.proxies().registerJdkProxy(LdapContext.class, DirContextProxy.class);
            hints.proxies().registerJdkProxy(DirContext.class, DirContextProxy.class);
        }
    }
}
