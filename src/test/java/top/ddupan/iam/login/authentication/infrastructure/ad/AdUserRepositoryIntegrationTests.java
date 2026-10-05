package top.ddupan.iam.login.authentication.infrastructure.ad;

import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.ldap.autoconfigure.LdapProperties;
import org.springframework.ldap.core.support.LdapContextSource;
import top.ddupan.iam.login.authentication.application.port.PasswordVerificationException;
import top.ddupan.iam.login.authentication.application.port.PasswordVerificationException.Reason;
import top.ddupan.iam.login.authentication.domain.User.GroupMembership;
import top.ddupan.iam.login.support.AdDirectoryFixture;
import static org.assertj.core.api.Assertions.*;

class AdUserRepositoryIntegrationTests {
    private static AdDirectoryFixture directory;
    private static AdPasswordAuthenticator authenticator;

    @BeforeAll static void start() {
        directory = new AdDirectoryFixture();
        authenticator = authenticator(directory.url());
    }
    @AfterAll static void close() { directory.close(); }

    @Test
    void repositoryUsesTheBoundConnectionAndMapsGuidAndGroupsDespiteReferrals() {
        int before = directory.binds.get();
        try (var session = authenticator.authenticate("alice", "fixture-password")) {
            var user = session.users().findByLoginName(session.loginName()).orElseThrow();
            assertThat(user.id().value()).isEqualTo("00112233-4455-6677-8899-aabbccddeeff");
            assertThat(user.memberships()).extracting(GroupMembership::name).containsExactly("MixedCase", "gitea-admins", "staff");
            assertThat(session.users().findByLoginName("alice")).contains(user);
            assertThat(directory.binds.get() - before).isEqualTo(1);
            assertThat(directory.searchConnection).isEqualTo(directory.bindConnection);
        }
    }

    @Test
    void closingTheScopePreventsFurtherRepositoryUse() {
        var session = authenticator.authenticate("alice@example.test", "fixture-password");
        var users = session.users();
        session.close();
        assertThatThrownBy(() -> users.findByLoginName("alice")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(session::users).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void wrongPasswordsUnknownAccountsAndAdAccountStatesAreTranslated() {
        rejected("alice", "wrong", Reason.REJECTED);
        rejected("unknown", "fixture-password", Reason.REJECTED);
        rejected("disabled", "fixture-password", Reason.DISABLED);
        rejected("locked", "fixture-password", Reason.LOCKED);
        rejected("expired", "fixture-password", Reason.PASSWORD_EXPIRED);
    }

    @Test
    void emptyPasswordsAndForeignDomainsNeverAttemptBind() {
        int before = directory.binds.get();
        rejected("alice", "", Reason.REJECTED);
        rejected("alice@other.test", "fixture-password", Reason.REJECTED);
        assertThat(directory.binds.get()).isEqualTo(before);
    }

    @Test
    void rejectsWrongTlsHostnameAndPlainLdapConfiguration() {
        var wrongName = authenticator(directory.mismatchedHostnameUrl());
        assertThatThrownBy(() -> wrongName.authenticate("alice", "fixture-password"))
            .isInstanceOfSatisfying(PasswordVerificationException.class,
                ex -> assertThat(ex.reason()).isEqualTo(Reason.UNAVAILABLE));
        assertThatThrownBy(() -> authenticator("ldap://localhost:389")).isInstanceOf(IllegalArgumentException.class);
    }

    /** The same ContextSource Boot builds from spring.ldap.* with the application.yaml defaults. */
    private static AdPasswordAuthenticator authenticator(String url) {
        var ldap = new LdapProperties();
        ldap.setUrls(new String[] {url});
        ldap.setBase("dc=example,dc=test");
        var contexts = new LdapContextSource();
        contexts.setUrl(url);
        contexts.setBase(ldap.getBase());
        contexts.setAnonymousReadOnly(true);
        contexts.setBaseEnvironmentProperties(Map.of("java.naming.referral", "ignore",
            "java.naming.ldap.attributes.binary", "objectGUID"));
        contexts.afterPropertiesSet();
        return new AdPasswordAuthenticator(new AdProperties(true, "example.test"), ldap, contexts);
    }

    private static void rejected(String username, String password, Reason reason) {
        assertThatThrownBy(() -> authenticator.authenticate(username, password))
            .isInstanceOfSatisfying(PasswordVerificationException.class,
                ex -> assertThat(ex.reason()).isEqualTo(reason));
    }
}
