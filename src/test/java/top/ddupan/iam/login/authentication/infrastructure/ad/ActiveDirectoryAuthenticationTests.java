package top.ddupan.iam.login.authentication.infrastructure.ad;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.ldap.autoconfigure.LdapProperties;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import top.ddupan.iam.login.authentication.domain.User.GroupMembership;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryAuthenticationProvider;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;
import top.ddupan.iam.login.authentication.infrastructure.security.SignInThrottle;
import top.ddupan.iam.login.support.AdDirectoryFixture;
import static org.assertj.core.api.Assertions.*;

class ActiveDirectoryAuthenticationTests {
    private static AdDirectoryFixture directory;
    private static DirectoryAuthenticationProvider provider;

    @BeforeAll static void start() {
        directory = new AdDirectoryFixture();
        provider = provider(directory.url());
    }
    @AfterAll static void close() { directory.close(); }

    @Test
    void readsTheUserOverItsOwnBindAndMapsGuidAndGroupsDespiteReferrals() {
        for (var name : List.of("alice", "alice@example.test")) {
            int before = directory.binds.get();
            var result = provider.authenticate(request(name, "fixture-password"));
            var user = ((DirectoryPrincipal) result.getPrincipal()).user();
            assertThat(user.id().value()).isEqualTo("00112233-4455-6677-8899-aabbccddeeff");
            assertThat(user.username()).isEqualTo("alice");
            assertThat(user.memberships()).extracting(GroupMembership::name).containsExactly("MixedCase", "gitea-admins", "staff");
            assertThat(result.getAuthorities()).extracting(GrantedAuthority::getAuthority)
                .containsExactly(FactorGrantedAuthority.PASSWORD_AUTHORITY);
            assertThat(result.getCredentials()).isNull();
            assertThat(directory.binds.get() - before).isEqualTo(1);
            assertThat(directory.searchConnection).isEqualTo(directory.bindConnection);
        }
    }

    @Test
    void wrongPasswordsUnknownAccountsAndAdAccountStatesAreOneFailure() {
        for (var name : List.of("unknown", "disabled", "locked", "expired")) rejected(name, "fixture-password");
        rejected("alice", "wrong");
    }

    @Test
    void emptyPasswordsAndForeignDomainsNeverAttemptBind() {
        int before = directory.binds.get();
        rejected("alice", "");
        rejected("alice@other.test", "fixture-password");
        rejected("EXAMPLE\\alice", "fixture-password");
        assertThat(directory.binds.get()).isEqualTo(before);
    }

    @Test
    void rejectsWrongTlsHostnameAndPlainLdapConfiguration() {
        var wrongName = provider(directory.mismatchedHostnameUrl());
        assertThatThrownBy(() -> wrongName.authenticate(request("alice", "fixture-password")))
            .isInstanceOf(InternalAuthenticationServiceException.class);
        assertThatThrownBy(() -> provider("ldap://localhost:389")).isInstanceOf(IllegalArgumentException.class);
    }

    /** spring.ldap.* as application.yaml sets it, the way the browser chain builds the provider. */
    private static DirectoryAuthenticationProvider provider(String url) {
        var ldap = new LdapProperties();
        ldap.setUrls(new String[] {url});
        ldap.setBase("dc=example,dc=test");
        ldap.getBaseEnvironment().putAll(Map.of("java.naming.referral", "ignore",
            "java.naming.ldap.attributes.binary", "objectGUID"));
        var ad = new AdProperties(true, "example.test");
        return new DirectoryAuthenticationProvider(ActiveDirectory.provider(ad, ldap), ad.domain(),
            new SignInThrottle(new SignInThrottle.Properties(1000, 1000, Duration.ofMinutes(15), 10000), Clock.systemUTC()));
    }

    private static UsernamePasswordAuthenticationToken request(String username, String password) {
        return UsernamePasswordAuthenticationToken.unauthenticated(username, password);
    }

    private static void rejected(String username, String password) {
        assertThatThrownBy(() -> provider.authenticate(request(username, password)))
            .isInstanceOf(BadCredentialsException.class);
    }
}
