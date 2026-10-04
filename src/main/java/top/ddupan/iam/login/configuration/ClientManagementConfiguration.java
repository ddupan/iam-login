package top.ddupan.iam.login.configuration;

import java.net.http.HttpClient;
import java.util.Set;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import org.springframework.aot.hint.annotation.RegisterReflectionForBinding;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authorization.application.AuthorizationPolicy;
import top.ddupan.iam.login.authorization.infrastructure.hydra.HydraHttpProperties;
import top.ddupan.iam.login.authorization.infrastructure.hydra.HydraProperties;
import top.ddupan.iam.login.clients.domain.ClientRepository;
import top.ddupan.iam.login.clients.domain.OidcClient;
import top.ddupan.iam.login.clients.infrastructure.HydraClientRepository;

@Configuration(proxyBeanMethods=false)
@ConditionalOnProperty(prefix="iam.hydra",name="enabled",havingValue="true")
@EnableConfigurationProperties(ClientManagementConfiguration.Access.class)
@RegisterReflectionForBinding({OidcClient.class,ClientRepository.Created.class})
class ClientManagementConfiguration {
    /** Who may be granted the management scope, and which Hydra client (the admin UI) may request it. */
    @ConfigurationProperties("iam.clients")
    record Access(Set<String> adminGroupDns, String adminUiClientId) {
        Access { adminGroupDns = adminGroupDns == null ? Set.of() : Set.copyOf(adminGroupDns); adminGroupDns.forEach(Access::dn); }
        static LdapName dn(String value) {
            try { return new LdapName(value); } catch (InvalidNameException ex) { throw new IllegalArgumentException("Invalid administrator group DN"); }
        }
        boolean allowed(User user) {
            return user.memberships().stream().anyMatch(group ->
                adminGroupDns.stream().anyMatch(admin -> dn(admin).equals(dn(group.externalId()))));
        }
    }
    @Bean ClientRepository clientRepository(RestClient hydraAdminHttpClient) { return new HydraClientRepository(hydraAdminHttpClient); }

    // Hydra admin introspection needs no client credentials; it is reachable only on the private admin port.
    @Bean OpaqueTokenIntrospector hydraIntrospector(HydraProperties hydra, HydraHttpProperties timeouts) {
        var http = HttpClient.newBuilder().connectTimeout(timeouts.connectTimeout())
            .followRedirects(HttpClient.Redirect.NEVER).build();
        var factory = new JdkClientHttpRequestFactory(http);
        factory.setReadTimeout(timeouts.readTimeout());
        var delegate = new SpringOpaqueTokenIntrospector(hydra.adminUrl().resolve("/admin/oauth2/introspect").toString(),
            new RestTemplate(factory));
        return token -> {
            var principal = delegate.introspect(token);
            // Introspection also answers for refresh tokens; only access tokens may call the API.
            if (!"access_token".equals(principal.getAttribute("token_use"))) throw new BadOpaqueTokenException("Not an access token");
            return principal;
        };
    }

    // Bearer only: the admin UI and any future automation use the same token check; who receives the
    // scope is decided once, at consent (AuthorizationPolicy), not here.
    @Bean @Order(2) SecurityFilterChain clientManagement(HttpSecurity http, OpaqueTokenIntrospector introspector) throws Exception {
        return http.securityMatcher("/api/iam/**").redirectToHttps(Customizer.withDefaults())
            .authorizeHttpRequests(auth -> auth.anyRequest().hasAuthority("SCOPE_" + AuthorizationPolicy.MANAGE_CLIENTS))
            .oauth2ResourceServer(server -> server.opaqueToken(token -> token.introspector(introspector)))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .requestCache(cache -> cache.disable()).logout(logout -> logout.disable()).build();
    }

    // The page shell carries no data; everything it shows comes from the bearer API above.
    @Bean @Order(2) SecurityFilterChain consolePage(HttpSecurity http) throws Exception {
        return http.securityMatcher("/console", "/console/callback").redirectToHttps(Customizer.withDefaults())
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .requestCache(cache -> cache.disable()).logout(logout -> logout.disable()).build();
    }
}
