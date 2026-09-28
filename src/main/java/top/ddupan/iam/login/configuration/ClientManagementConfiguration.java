package top.ddupan.iam.login.configuration;

import java.util.Set;
import javax.naming.ldap.LdapName;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;
import top.ddupan.iam.login.authentication.infrastructure.webauthn.MfaPolicy;
import top.ddupan.iam.login.authorization.infrastructure.hydra.HydraProperties;
import top.ddupan.iam.login.clients.application.ClientRegistry;
import top.ddupan.iam.login.clients.infrastructure.HydraClientRegistry;
import top.ddupan.iam.login.clients.domain.OidcClient;

@Configuration(proxyBeanMethods=false)
@ConditionalOnProperty(prefix="iam.hydra",name="enabled",havingValue="true")
@EnableConfigurationProperties(ClientManagementConfiguration.Access.class)
@org.springframework.aot.hint.annotation.RegisterReflectionForBinding({OidcClient.class,ClientRegistry.Created.class})
class ClientManagementConfiguration {
    @ConfigurationProperties("iam.clients")
    record Access(Set<String> adminGroupDns) {
        Access { adminGroupDns = adminGroupDns == null ? Set.of() : Set.copyOf(adminGroupDns); adminGroupDns.forEach(Access::dn); }
        static LdapName dn(String value) {
            try { return new LdapName(value); } catch (javax.naming.InvalidNameException ex) { throw new IllegalArgumentException("Invalid administrator group DN"); }
        }
        boolean allowed(DirectoryPrincipal principal) {
            return principal.user().memberships().stream().anyMatch(group ->
                adminGroupDns.stream().anyMatch(admin -> dn(admin).equals(dn(group.externalId()))));
        }
    }
    @Bean ClientRegistry clientRegistry(HydraProperties properties) { return new HydraClientRegistry(properties); }
    @Bean @Order(2) SecurityFilterChain clientManagement(HttpSecurity http,MfaPolicy mfa,Access access) throws Exception {
        return http.securityMatcher("/api/iam/**").redirectToHttps(org.springframework.security.config.Customizer.withDefaults())
            .authorizeHttpRequests(auth -> auth.anyRequest().access((authentication,request) -> {
                var current = authentication.get();
                var factors = mfa.complete.authorize(authentication,request);
                return new AuthorizationDecision(current != null && current.getPrincipal() instanceof DirectoryPrincipal principal
                    && factors != null && factors.isGranted() && access.allowed(principal));
            }))
            .exceptionHandling(ex -> ex.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
            .requestCache(cache -> cache.disable()).logout(logout -> logout.disable()).build();
    }
}
