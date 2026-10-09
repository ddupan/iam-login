package top.ddupan.iam.login;

import org.jooq.SQLDialect;
import org.jooq.impl.DSL;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import top.ddupan.iam.login.support.AdDirectoryFixture;
import top.ddupan.iam.login.support.SpiffeFixture;
import static top.ddupan.iam.login.persistence.schema.Tables.SUBJECTS;

/**
 * Test-only companion for running the browser test against a native binary: simulated AD for the binary
 * to bind to, a stand-in SPIRE JWKS with one JWT-SVID, and the fixture client written once the binary's Flyway has created the tables.
 * Args: JDBC URL, user, password. Runs until killed.
 */
public final class NativeSmokeSupport {
    public static void main(String[] args) throws Exception {
        var directory = new AdDirectoryFixture();
        System.out.println("LDAP_URL=" + directory.url());
        // A stand-in SPIRE OIDC provider: the binary trusts its JWKS; the SVID (fixture key, test-only) calls the API.
        var spire = new SpiffeFixture();
        System.out.println("SPIFFE_JWKS=" + spire.jwkSetUri());
        System.out.println("SPIFFE_SVID=" + spire.svid("spiffe://example.test/ci/terraform"));
        System.out.flush();
        var source = new DriverManagerDataSource(args[0], args[1], args[2]);
        var db = DSL.using(source, SQLDialect.POSTGRES);
        for (int attempt = 0; ; attempt++) {
            // subjects comes from the last migration, so every table exists once it does.
            try { db.fetchCount(SUBJECTS); break; }
            catch (RuntimeException notYet) { if (attempt > 300) throw notYet; Thread.sleep(1000); }
        }
        // A subject carried over from an earlier issuer, as a migration inserts it.
        db.insertInto(SUBJECTS).set(SUBJECTS.SUBJECT, "human:fixture-existing-oidc-subject")
            .set(SUBJECTS.AUTHORITY, "example.test").set(SUBJECTS.DIRECTORY_ID, "00112233-4455-6677-8899-aabbccddeeff").execute();
        new JdbcRegisteredClientRepository(new JdbcTemplate(source)).save(RegisteredClient.withId("fixture-rp").clientId("fixture-rp")
            .clientSecret("{noop}fixture-client-secret").clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri("http://localhost:14446/callback").postLogoutRedirectUri("http://localhost:14446/logged-out")
            .scope("openid").scope("profile").scope("email").scope("groups").scope("offline_access")
            .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(true).build())
            .tokenSettings(TokenSettings.builder().reuseRefreshTokens(false).build()).build());
        System.out.println("CLIENT_REGISTERED");
        System.out.flush();
        Thread.currentThread().join();
    }
}
