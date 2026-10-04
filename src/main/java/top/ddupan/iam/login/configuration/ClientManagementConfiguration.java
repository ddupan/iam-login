package top.ddupan.iam.login.configuration;

import java.net.URI;
import java.util.Collection;
import java.util.Set;
import java.util.UUID;
import org.springframework.aot.hint.annotation.RegisterReflectionForBinding;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import top.ddupan.iam.login.clients.domain.ClientRepository;
import top.ddupan.iam.login.clients.domain.OidcClient;
import top.ddupan.iam.login.clients.infrastructure.RegisteredClients;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "iam.authorization-server", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(ClientManagementConfiguration.Access.class)
@RegisterReflectionForBinding({OidcClient.class, ClientRepository.Created.class})
class ClientManagementConfiguration {
    /** The audience the client-management API accepts; only clients registered for it receive it. */
    static final String AUDIENCE = "iam-login";

    /**
     * The API is an ordinary resource server: the token must be issued for it (audience) and its subject
     * must be in an administrator group, taken from the token's groups claim. Matching is by group name,
     * the same value every downstream application sees. A user with two same-named direct groups cannot
     * log in at all; a look-alike group elsewhere needs AD rights to create.
     */
    @ConfigurationProperties("iam.clients")
    record Access(Set<String> adminGroups, String consoleClientId) {
        Access {
            adminGroups = adminGroups == null ? Set.of() : Set.copyOf(adminGroups);
            consoleClientId = consoleClientId == null || consoleClientId.isBlank() ? "iam-console" : consoleClientId;
        }
        boolean allowed(JwtAuthenticationToken token) {
            var jwt = token.getToken();
            return jwt.getAudience() != null && jwt.getAudience().contains(AUDIENCE)
                && jwt.getClaims().get("groups") instanceof Collection<?> groups
                && groups.stream().anyMatch(adminGroups::contains);
        }
    }

    // Client secrets are stored encoded ({bcrypt} for new ones); the framework matches with the same encoder.
    @Bean PasswordEncoder clientSecrets() { return PasswordEncoderFactories.createDelegatingPasswordEncoder(); }

    @Bean ClientRepository clientRepository(RegisteredClientRepository clients, JdbcOperations jdbc,
            PlatformTransactionManager transactions, PasswordEncoder clientSecrets) {
        return new RegisteredClients(clients, jdbc, new TransactionTemplate(transactions), clientSecrets);
    }

    // Bearer only, verified against this server's own signing keys; the console and any future caller go
    // through the same audience + group check.
    @Bean @Order(2) SecurityFilterChain clientManagement(HttpSecurity http, JwtDecoder tokens, Access access) throws Exception {
        return http.securityMatcher("/api/iam/**").redirectToHttps(Customizer.withDefaults())
            .authorizeHttpRequests(auth -> auth.anyRequest().access((authentication, request) -> new AuthorizationDecision(
                authentication.get() instanceof JwtAuthenticationToken token && access.allowed(token))))
            .oauth2ResourceServer(server -> server.jwt(jwt -> jwt.decoder(tokens)))
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

    /**
     * The console is a public client of this same server (same origin, PKCE, no secret). It is kept in step
     * with configuration at every start, so it never needs out-of-band registration. No consent page:
     * it is first-party, and the full MFA is still required to authorize it.
     */
    @Bean ApplicationRunner consoleClient(RegisteredClientRepository clients, Access access,
            AuthorizationServerConfiguration.Properties server) {
        return arguments -> {
            var existing = clients.findByClientId(access.consoleClientId());
            var builder = existing == null ? RegisteredClient.withId(UUID.randomUUID().toString()) : RegisteredClient.from(existing);
            clients.save(builder.clientId(access.consoleClientId()).clientName("IAM 管理")
                .clientAuthenticationMethods(methods -> { methods.clear(); methods.add(ClientAuthenticationMethod.NONE); })
                .authorizationGrantTypes(grants -> { grants.clear(); grants.add(AuthorizationGrantType.AUTHORIZATION_CODE); })
                .redirectUris(uris -> { uris.clear(); uris.add(URI.create(server.issuer() + "/").resolve("console/callback").toString()); })
                .scopes(scopes -> { scopes.clear(); scopes.add("openid"); scopes.add("groups"); })
                .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false)
                    .setting(RegisteredClients.AUDIENCES, AUDIENCE).setting(RegisteredClients.LOGIN_ENABLED, true).build())
                .build());
        };
    }
}
