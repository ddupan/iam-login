package top.ddupan.iam.login.clients.infrastructure;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.transaction.support.TransactionOperations;
import top.ddupan.iam.login.clients.domain.ClientRepository;
import top.ddupan.iam.login.clients.domain.ClientRepositoryException;
import top.ddupan.iam.login.clients.domain.OidcClient;

/**
 * Clients of the in-process authorization server. Only confidential authorization-code clients are
 * managed here; others (such as the public console client) are invisible to this API and cannot be
 * changed or deleted through it. Secrets are stored encoded; the plain value is returned once.
 */
public final class RegisteredClients implements ClientRepository {
    /** Client setting: false stops new authorizations and refreshes for the client. Absent means enabled. */
    public static final String LOGIN_ENABLED = "settings.client.iam.login-enabled";
    /** Client setting: comma-separated extra audiences for its access tokens (the framework has no audience parameter). */
    public static final String AUDIENCES = "settings.client.iam.audiences";

    private static final SecureRandom RANDOM = new SecureRandom();
    private final RegisteredClientRepository clients;
    private final JdbcOperations jdbc;
    private final TransactionOperations transactions;
    private final PasswordEncoder passwords;

    public RegisteredClients(RegisteredClientRepository clients, JdbcOperations jdbc, TransactionOperations transactions,
            PasswordEncoder passwords) {
        this.clients = clients; this.jdbc = jdbc; this.transactions = transactions; this.passwords = passwords;
    }

    public static boolean loginEnabled(RegisteredClient client) {
        return !Boolean.FALSE.equals(client.getClientSettings().getSetting(LOGIN_ENABLED));
    }

    @Override public List<OidcClient> list(int page, int size) {
        if (page < 0 || size < 1 || size > 100) throw new IllegalArgumentException("Invalid pagination");
        // ponytail: pages over all registrations, then drops unmanaged ones; a page can come back short.
        return jdbc.queryForList("SELECT client_id FROM oauth2_registered_client ORDER BY client_id LIMIT ? OFFSET ?",
                String.class, size, (long) page * size).stream()
            .map(clients::findByClientId).filter(Objects::nonNull).filter(RegisteredClients::managed)
            .map(RegisteredClients::view).toList();
    }

    @Override public OidcClient get(String id) { return view(managedClient(id)); }

    @Override public Created create(OidcClient client) {
        if (clients.findByClientId(client.id()) != null) throw new ClientRepositoryException(ClientRepositoryException.Kind.CONFLICT);
        var secret = newSecret();
        var registered = apply(RegisteredClient.withId(UUID.randomUUID().toString()).clientId(client.id())
            .clientSecret(passwords.encode(secret))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            // Rotate refresh tokens; the framework reuses them by default.
            .tokenSettings(TokenSettings.builder().reuseRefreshTokens(false).build()), client, ClientSettings.builder()
            .requireProofKey(true).requireAuthorizationConsent(true).build()).build();
        clients.save(registered);
        return new Created(view(registered), secret);
    }

    @Override public OidcClient update(OidcClient client) {
        var existing = managedClient(client.id());
        var updated = apply(RegisteredClient.from(existing), client, existing.getClientSettings()).build();
        clients.save(updated);
        return view(updated);
    }

    @Override public void delete(String id) {
        var existing = managedClient(id);
        // The framework cannot load an authorization whose client is gone, so they go together.
        transactions.executeWithoutResult(status -> {
            jdbc.update("DELETE FROM oauth2_authorization WHERE registered_client_id = ?", existing.getId());
            jdbc.update("DELETE FROM oauth2_authorization_consent WHERE registered_client_id = ?", existing.getId());
            jdbc.update("DELETE FROM oauth2_registered_client WHERE id = ?", existing.getId());
        });
    }

    @Override public String rotateSecret(String id) {
        var secret = newSecret();
        clients.save(RegisteredClient.from(managedClient(id)).clientSecret(passwords.encode(secret)).build());
        return secret;
    }

    /** Copies the managed fields onto a registration. offline_access needs the refresh_token grant (OIDC Core 11). */
    private static RegisteredClient.Builder apply(RegisteredClient.Builder builder, OidcClient client, ClientSettings settings) {
        return builder.clientName(client.name())
            .authorizationGrantTypes(grants -> {
                grants.clear();
                grants.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                if (client.scopes().contains("offline_access")) grants.add(AuthorizationGrantType.REFRESH_TOKEN);
            })
            .redirectUris(uris -> { uris.clear(); uris.addAll(client.redirectUris()); })
            .postLogoutRedirectUris(uris -> { uris.clear(); uris.addAll(client.postLogoutRedirectUris()); })
            .scopes(scopes -> { scopes.clear(); scopes.addAll(client.scopes()); })
            .clientSettings(ClientSettings.withSettings(settings.getSettings()).setting(LOGIN_ENABLED, client.loginEnabled())
                .requireProofKey(client.pkceRequired()).build());
    }

    private RegisteredClient managedClient(String id) {
        OidcClient.requireId(id);
        var client = clients.findByClientId(id);
        if (client == null) throw new ClientRepositoryException(ClientRepositoryException.Kind.NOT_FOUND);
        if (!managed(client)) throw new ClientRepositoryException(ClientRepositoryException.Kind.CONFLICT);
        return client;
    }

    private static boolean managed(RegisteredClient client) {
        return client.getClientAuthenticationMethods().equals(Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
            && client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)
            && client.getAuthorizationGrantTypes().stream().allMatch(grant -> grant.equals(AuthorizationGrantType.AUTHORIZATION_CODE)
                || grant.equals(AuthorizationGrantType.REFRESH_TOKEN));
    }

    private static OidcClient view(RegisteredClient client) {
        return new OidcClient(client.getClientId(), client.getClientName(), List.copyOf(client.getRedirectUris()),
            new HashSet<>(client.getScopes()), List.copyOf(client.getPostLogoutRedirectUris()), loginEnabled(client),
            client.getClientSettings().isRequireProofKey());
    }

    private static String newSecret() {
        var bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
