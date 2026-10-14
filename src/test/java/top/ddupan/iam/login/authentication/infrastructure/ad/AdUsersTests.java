package top.ddupan.iam.login.authentication.infrastructure.ad;

import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authentication.domain.UserRepository;
import top.ddupan.iam.login.support.AdDirectoryFixture;
import static org.assertj.core.api.Assertions.*;

class AdUsersTests {
    private static final String ALICE = "00112233-4455-6677-8899-aabbccddeeff";
    private static AdDirectoryFixture directory;
    private static AdUsers users;

    @BeforeAll static void start() {
        directory = new AdDirectoryFixture();
        users = users(directory.url());
    }
    @AfterAll static void close() { directory.close(); }

    @Test
    void findsTheAccountByObjectGuidOverTheServiceAccount() {
        int before = directory.binds.get();
        var user = users.findActive(new User.UserId("example.test", ALICE)).orElseThrow();
        assertThat(user.username()).isEqualTo("alice");
        assertThat(user.memberships()).extracting(User.GroupMembership::name).containsExactly("MixedCase", "gitea-admins", "staff");
        assertThat(directory.binds.get() - before).as("bound as the service account").isEqualTo(1);
    }

    @Test
    void disabledUnknownAndForeignAccountsAreNotActive() {
        assertThat(users.findActive(new User.UserId("example.test", AdDirectoryFixture.DISABLED_GUID))).isEmpty();
        assertThat(users.findActive(new User.UserId("example.test", UUID.randomUUID().toString()))).isEmpty();
        assertThat(users.findActive(new User.UserId("other.test", ALICE))).isEmpty();
        assertThat(users.findActive(new User.UserId("example.test", "not-a-guid"))).isEmpty();
    }

    @Test
    void anUnreachableDirectoryIsAFailureNotAnAbsence() {
        assertThatThrownBy(() -> users("ldaps://localhost:1").findActive(new User.UserId("example.test", ALICE)))
            .isInstanceOf(UserRepository.AccessFailure.class);
    }

    @Test
    void guidBytesInvertTheDirectoryByteOrder() {
        var guid = UUID.fromString(ALICE);
        assertThat(AdUserDetailsMapper.guid(AdUserDetailsMapper.guidBytes(guid))).isEqualTo(ALICE);
    }

    /** Boot's connection as application.yaml configures it, with the service account. */
    private static AdUsers users(String url) {
        var source = new LdapContextSource();
        source.setUrl(url);
        source.setBase("dc=example,dc=test");
        source.setUserDn(AdDirectoryFixture.SERVICE_USER);
        source.setPassword(AdDirectoryFixture.SERVICE_PASSWORD);
        source.setBaseEnvironmentProperties(Map.of("java.naming.referral", "ignore",
            "java.naming.ldap.attributes.binary", "objectGUID", "com.sun.jndi.ldap.connect.timeout", "3000"));
        source.afterPropertiesSet();
        var ldap = new LdapTemplate(source);
        ldap.setObjectDirectoryMapper(new AdEntryMapper());
        ldap.setIgnorePartialResultException(true);
        return new AdUsers(ldap, "example.test");
    }
}
