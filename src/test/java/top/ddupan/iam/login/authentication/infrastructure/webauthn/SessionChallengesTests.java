package top.ddupan.iam.login.authentication.infrastructure.webauthn;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.flywaydb.core.Flyway;
import org.jooq.DSLContext;
import org.jooq.SQLDialect;
import org.jooq.impl.DSL;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.management.MapPublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.MapUserCredentialRepository;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;
import static org.assertj.core.api.Assertions.*;

class SessionChallengesTests {
    static final PostgreSQLContainer DATABASE = new PostgreSQLContainer(DockerImageName.parse(
        "postgres:18.6").asCompatibleSubstituteFor("postgres"));
    static DSLContext db;
    private final MfaPolicy policy = new MfaPolicy(new MapPublicKeyCredentialUserEntityRepository(), new MapUserCredentialRepository(), null, Duration.ofHours(12));

    @BeforeAll static void database() {
        DATABASE.start();
        var source = new DriverManagerDataSource(DATABASE.getJdbcUrl(), DATABASE.getUsername(), DATABASE.getPassword());
        Flyway.configure().dataSource(source).load().migrate();
        db = DSL.using(source, SQLDialect.POSTGRES);
    }
    @AfterAll static void stop() { DATABASE.stop(); }
    @AfterEach void clear() { SecurityContextHolder.clearContext(); }

    @Test
    void challengesExpireAndAreBoundToCurrentIdentity() {
        var issued = Instant.now();
        var request = new MockHttpServletRequest();
        var response = new MockHttpServletResponse();
        identify("alice", issued);
        var repository = new SessionChallenges(Clock.fixed(issued, ZoneOffset.UTC), policy, db).authentication();
        var options = PublicKeyCredentialRequestOptions.builder().rpId("localhost").challenge(Bytes.random()).build();
        repository.save(request, response, options);
        var later = new SessionChallenges(Clock.fixed(issued.plusSeconds(301), ZoneOffset.UTC), policy, db).authentication();
        assertThat(later.load(request)).isNull();
        repository.save(request, response, options);
        identify("bob", issued);
        assertThat(repository.load(request)).isNull();
        identify("alice", issued);
        assertThat(repository.load(request)).isNull();
    }

    @Test
    void challengeIsConsumedOnceAndUpstreamCleanupCannotEraseNewChallenge() {
        var issued = Instant.now();
        identify("alice", issued);
        var request = new MockHttpServletRequest();
        var response = new MockHttpServletResponse();
        var repository = new SessionChallenges(Clock.systemUTC(), policy, db).authentication();
        var first = PublicKeyCredentialRequestOptions.builder().rpId("localhost").challenge(Bytes.random()).build();
        var second = PublicKeyCredentialRequestOptions.builder().rpId("localhost").challenge(Bytes.random()).build();
        repository.save(request, response, first);
        assertThat(challenge(repository.load(request))).isEqualTo(challenge(first));
        assertThat(repository.load(request)).isNull();
        repository.save(request, response, second);
        repository.save(request, response, null);
        assertThat(challenge(repository.load(request))).isEqualTo(challenge(second));
        // A second step's challenge belongs to its account: not to a session that is no longer it.
        repository.save(request, response, first);
        SecurityContextHolder.clearContext();
        assertThat(repository.load(request)).isNull();
        // Without a fresh password the session is signing in afresh (passwordless): the challenge belongs to no one
        // yet, and the passkey it is answered with will say whose it is.
        identify("alice", issued.minusSeconds(601));
        repository.save(request, response, second);
        SecurityContextHolder.clearContext();
        assertThat(challenge(repository.load(request))).isEqualTo(challenge(second));
    }

    // Requests of one session each load their own copy of it (sessions live in the database), so two
    // concurrent requests see the same challenge id; the database lets only one of them consume it.
    @Test
    void concurrentRequestsOfOneSessionConsumeAChallengeOnce() throws Exception {
        var issued = Instant.now();
        identify("alice", issued);
        var repository = new SessionChallenges(Clock.systemUTC(), policy, db).authentication();
        var original = new MockHttpServletRequest();
        repository.save(original, new MockHttpServletResponse(),
            PublicKeyCredentialRequestOptions.builder().rpId("localhost").challenge(Bytes.random()).build());
        var context = SecurityContextHolder.getContext();
        var start = new CountDownLatch(1);
        try (var pool = Executors.newFixedThreadPool(8)) {
            var results = new ArrayList<Future<PublicKeyCredentialRequestOptions>>();
            for (int i = 0; i < 8; i++) {
                var copy = new MockHttpServletRequest();
                copy.getSession().setAttribute("iam.webauthn.authentication",
                    original.getSession().getAttribute("iam.webauthn.authentication"));
                results.add(pool.submit(() -> {
                    SecurityContextHolder.setContext(context);
                    start.await();
                    return repository.load(copy);
                }));
            }
            start.countDown();
            int consumed = 0;
            for (var result : results) if (result.get() != null) consumed++;
            assertThat(consumed).isEqualTo(1);
        }
    }

    private static String challenge(PublicKeyCredentialRequestOptions options) { return options.getChallenge().toBase64UrlString(); }

    private static void identify(String id, Instant issued) {
        var user = new User(new User.UserId("example.test", id), id, id, "", List.of());
        SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
            new DirectoryPrincipal(user), null, List.of(FactorGrantedAuthority.withAuthority("FACTOR_PASSWORD")
                .issuedAt(issued).build())));
    }
}
