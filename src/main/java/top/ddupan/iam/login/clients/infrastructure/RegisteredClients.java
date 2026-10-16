package top.ddupan.iam.login.clients.infrastructure;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.jooq.DSLContext;
import org.jspecify.annotations.Nullable;
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
import top.ddupan.iam.login.clients.domain.MachineClient;
import top.ddupan.iam.login.clients.domain.MachineClientRepository;
import top.ddupan.iam.login.clients.domain.OidcClient;
import static top.ddupan.iam.login.persistence.schema.Tables.OAUTH2_AUTHORIZATION;
import static top.ddupan.iam.login.persistence.schema.Tables.OAUTH2_AUTHORIZATION_CONSENT;
import static top.ddupan.iam.login.persistence.schema.Tables.OAUTH2_REGISTERED_CLIENT;

/**
 * Clients of the in-process authorization server. Only clients created through this API (marked {@link #MANAGED}),
 * and confidential authorization-code clients registered before the mark existed, are managed here; others (such
 * as the console client) are invisible to this API and cannot be changed or deleted through it. Secrets are stored
 * encoded; the plain value is returned once. Machine clients (authenticated by {@link #SPIFFE_JWT}) are managed
 * through {@link MachineClientRepository} only; each API sees only its own kind.
 */
public final class RegisteredClients implements ClientRepository, MachineClientRepository {
    /** draft-ietf-oauth-spiffe-client-auth: client authentication with a JWT-SVID. */
    public static final ClientAuthenticationMethod SPIFFE_JWT = new ClientAuthenticationMethod("spiffe_jwt");
    /** Client metadata spiffe_id (5.1); a client without it is matched by its client_id. */
    public static final String SPIFFE_ID = "settings.client.spiffe_id";
    /** Client setting: false stops new authorizations and refreshes for the client. Absent means enabled. */
    public static final String LOGIN_ENABLED = "settings.client.iam.login-enabled";
    /** Client setting: comma-separated extra audiences for its access tokens (the framework has no audience parameter). */
    public static final String AUDIENCES = "settings.client.iam.audiences";
    /** Client setting: created through the client API. */
    private static final String MANAGED = "settings.client.iam.managed";

    private static final SecureRandom RANDOM = new SecureRandom();
    private final RegisteredClientRepository clients;
    private final DSLContext db;
    private final TransactionOperations transactions;
    private final PasswordEncoder passwords;

    public RegisteredClients(RegisteredClientRepository clients, DSLContext db, TransactionOperations transactions,
            PasswordEncoder passwords) {
        this.clients = clients; this.db = db; this.transactions = transactions; this.passwords = passwords;
    }

    public static boolean loginEnabled(RegisteredClient client) {
        return !Boolean.FALSE.equals(client.getClientSettings().getSetting(LOGIN_ENABLED));
    }

    @Override public List<OidcClient> list(int page, int size) {
        return ids(page, size).stream().map(clients::findByClientId).filter(Objects::nonNull).filter(RegisteredClients::managed)
            .map(RegisteredClients::view).toList();
    }

    @Override public List<MachineClient> listMachines(int page, int size) {
        return ids(page, size).stream().map(clients::findByClientId).filter(Objects::nonNull)
            .filter(RegisteredClients::machine).map(RegisteredClients::machineView).toList();
    }

    @Override public MachineClient getMachine(String id) { return machineView(machineClient(id)); }

    @Override public MachineClient createMachine(MachineClient client) {
        if (clients.findByClientId(client.id()) != null) throw new ClientRepositoryException(ClientRepositoryException.Kind.CONFLICT);
        var registered = applyMachine(RegisteredClient.withId(UUID.randomUUID().toString()).clientId(client.id()), client,
            ClientSettings.builder().setting(MANAGED, true).build()).build();
        clients.save(registered);
        return machineView(registered);
    }

    @Override public MachineClient updateMachine(MachineClient client) {
        var existing = machineClient(client.id());
        var updated = applyMachine(RegisteredClient.from(existing), client, existing.getClientSettings()).build();
        clients.save(updated);
        return machineView(updated);
    }

    @Override public void deleteMachine(String id) { remove(machineClient(id)); }

    private List<String> ids(int page, int size) {
        if (page < 0 || size < 1 || size > 100) throw new IllegalArgumentException("Invalid pagination");
        // ponytail: pages over all registrations, then drops other kinds; a page can come back short.
        return db.select(OAUTH2_REGISTERED_CLIENT.CLIENT_ID).from(OAUTH2_REGISTERED_CLIENT)
            .orderBy(OAUTH2_REGISTERED_CLIENT.CLIENT_ID).limit(size).offset((long) page * size)
            .fetch(OAUTH2_REGISTERED_CLIENT.CLIENT_ID);
    }

    @Override public OidcClient get(String id) { return view(managedClient(id)); }

    @Override public Created create(OidcClient client) {
        if (clients.findByClientId(client.id()) != null) throw new ClientRepositoryException(ClientRepositoryException.Kind.CONFLICT);
        var secret = client.publicClient() ? null : newSecret();
        var builder = RegisteredClient.withId(UUID.randomUUID().toString()).clientId(client.id())
            // Rotate refresh tokens; the framework reuses them by default. For public clients this rotation is what
            // RFC 9700 4.14.2 asks of refresh tokens that are not sender-constrained.
            .tokenSettings(TokenSettings.builder().reuseRefreshTokens(false).build());
        if (secret != null) builder.clientSecret(passwords.encode(secret));
        var registered = apply(builder, client, ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(true)
            .setting(MANAGED, true).build()).build();
        clients.save(registered);
        return new Created(view(registered), secret);
    }

    @Override public OidcClient update(OidcClient client) {
        var existing = managedClient(client.id());
        // Public or confidential decides how the client authenticates; a different kind is a different client.
        if (isPublic(existing) != client.publicClient()) throw new IllegalArgumentException("publicClient cannot change");
        var updated = apply(RegisteredClient.from(existing), client, existing.getClientSettings()).build();
        clients.save(updated);
        return view(updated);
    }

    @Override public void delete(String id) { remove(managedClient(id)); }

    private void remove(RegisteredClient existing) {
        // The framework cannot load an authorization whose client is gone, so they go together.
        transactions.executeWithoutResult(status -> {
            db.deleteFrom(OAUTH2_AUTHORIZATION).where(OAUTH2_AUTHORIZATION.REGISTERED_CLIENT_ID.eq(existing.getId())).execute();
            db.deleteFrom(OAUTH2_AUTHORIZATION_CONSENT)
                .where(OAUTH2_AUTHORIZATION_CONSENT.REGISTERED_CLIENT_ID.eq(existing.getId())).execute();
            db.deleteFrom(OAUTH2_REGISTERED_CLIENT).where(OAUTH2_REGISTERED_CLIENT.ID.eq(existing.getId())).execute();
        });
    }

    @Override public String rotateSecret(String id) {
        var existing = managedClient(id);
        if (isPublic(existing)) throw new ClientRepositoryException(ClientRepositoryException.Kind.CONFLICT);
        var secret = newSecret();
        clients.save(RegisteredClient.from(existing).clientSecret(passwords.encode(secret)).build());
        return secret;
    }

    /** Copies the managed fields onto a registration. offline_access needs the refresh_token grant (OIDC Core 11). */
    private static RegisteredClient.Builder apply(RegisteredClient.Builder builder, OidcClient client, ClientSettings settings) {
        return builder.clientName(client.name())
            // One method each; public clients are "none" (OidcClient).
            .clientAuthenticationMethods(methods -> {
                methods.clear();
                methods.add(new ClientAuthenticationMethod(client.tokenEndpointAuthMethod()));
            })
            .authorizationGrantTypes(grants -> {
                grants.clear();
                grants.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                if (client.scopes().contains("offline_access")) grants.add(AuthorizationGrantType.REFRESH_TOKEN);
                if (client.deviceAuthorization()) grants.add(AuthorizationGrantType.DEVICE_CODE);
            })
            .redirectUris(uris -> { uris.clear(); uris.addAll(client.redirectUris()); })
            .postLogoutRedirectUris(uris -> { uris.clear(); uris.addAll(client.postLogoutRedirectUris()); })
            .scopes(scopes -> { scopes.clear(); scopes.addAll(client.scopes()); })
            .clientSettings(ClientSettings.withSettings(settings(settings, client)).requireProofKey(client.pkceRequired()).build());
    }

    private static Map<String, Object> settings(ClientSettings current, OidcClient client) {
        var settings = new HashMap<>(current.getSettings());
        settings.put(LOGIN_ENABLED, client.loginEnabled());
        // Plain strings: the stored settings are JSON read back through Jackson's allowlist.
        settings.remove(AUDIENCES);
        if (!client.audiences().isEmpty()) settings.put(AUDIENCES, String.join(",", client.audiences()));
        return settings;
    }

    /** Only client_credentials: a machine acts for itself. No refresh token; a fresh SVID gets a fresh token. */
    private static RegisteredClient.Builder applyMachine(RegisteredClient.Builder builder, MachineClient client, ClientSettings current) {
        var settings = new HashMap<>(current.getSettings());
        settings.put(LOGIN_ENABLED, client.enabled());
        settings.put(SPIFFE_ID, client.spiffeId());
        settings.remove(AUDIENCES);
        if (!client.audiences().isEmpty()) settings.put(AUDIENCES, String.join(",", client.audiences()));
        return builder.clientName(client.name())
            .clientAuthenticationMethods(methods -> { methods.clear(); methods.add(SPIFFE_JWT); })
            .authorizationGrantTypes(grants -> { grants.clear(); grants.add(AuthorizationGrantType.CLIENT_CREDENTIALS); })
            .scopes(scopes -> { scopes.clear(); scopes.addAll(client.scopes()); })
            .clientSettings(ClientSettings.withSettings(settings).build());
    }

    private RegisteredClient machineClient(String id) {
        OidcClient.requireId(id);
        var client = clients.findByClientId(id);
        if (client == null) throw new ClientRepositoryException(ClientRepositoryException.Kind.NOT_FOUND);
        if (!machine(client)) throw new ClientRepositoryException(ClientRepositoryException.Kind.CONFLICT);
        return client;
    }

    private static boolean machine(RegisteredClient client) {
        return Boolean.TRUE.equals(client.getClientSettings().getSetting(MANAGED))
            && client.getClientAuthenticationMethods().equals(Set.of(SPIFFE_JWT));
    }

    private static MachineClient machineView(RegisteredClient client) {
        var settings = client.getClientSettings();
        return new MachineClient(client.getClientId(), client.getClientName(), settings.getSetting(SPIFFE_ID),
            new HashSet<>(client.getScopes()), audiences(settings.getSetting(AUDIENCES)), loginEnabled(client));
    }

    private RegisteredClient managedClient(String id) {
        OidcClient.requireId(id);
        var client = clients.findByClientId(id);
        if (client == null) throw new ClientRepositoryException(ClientRepositoryException.Kind.NOT_FOUND);
        if (!managed(client)) throw new ClientRepositoryException(ClientRepositoryException.Kind.CONFLICT);
        return client;
    }

    private static boolean managed(RegisteredClient client) {
        if (machine(client)) return false;
        if (Boolean.TRUE.equals(client.getClientSettings().getSetting(MANAGED))) return true;
        // Registered before the mark: gitea and the first clients after it.
        return client.getClientAuthenticationMethods().equals(Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
            && client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)
            && client.getAuthorizationGrantTypes().stream().allMatch(grant -> grant.equals(AuthorizationGrantType.AUTHORIZATION_CODE)
                || grant.equals(AuthorizationGrantType.REFRESH_TOKEN));
    }

    private static boolean isPublic(RegisteredClient client) {
        return client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE);
    }

    private static List<String> audiences(@Nullable Object setting) {
        return setting instanceof String joined && !joined.isEmpty() ? List.of(joined.split(",")) : List.of();
    }

    private static OidcClient view(RegisteredClient client) {
        var settings = client.getClientSettings();
        return new OidcClient(client.getClientId(), client.getClientName(), List.copyOf(client.getRedirectUris()),
            new HashSet<>(client.getScopes()), List.copyOf(client.getPostLogoutRedirectUris()), loginEnabled(client),
            settings.isRequireProofKey(), isPublic(client),
            client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.DEVICE_CODE),
            audiences(settings.getSetting(AUDIENCES)),
            client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                ? OidcClient.CLIENT_SECRET_POST : null);
    }

    private static String newSecret() {
        var bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
