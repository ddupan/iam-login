package top.ddupan.iam.login.configuration;

import java.time.Clock;
import java.time.Duration;
import java.util.Set;
import org.jooq.DSLContext;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.web.webauthn.api.AuthenticatorSelectionCriteria;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRpEntity;
import org.springframework.security.web.webauthn.api.ResidentKeyRequirement;
import org.springframework.security.web.webauthn.api.UserVerificationRequirement;
import org.springframework.security.web.webauthn.management.*;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import top.ddupan.iam.login.authentication.infrastructure.persistence.CredentialRegistration;
import top.ddupan.iam.login.authentication.infrastructure.webauthn.*;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "iam.webauthn", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(WebAuthnProperties.class)
class WebAuthnConfiguration {
    @Bean
    PublicKeyCredentialUserEntityRepository credentialUsers(JdbcOperations jdbc) {
        return new JdbcPublicKeyCredentialUserEntityRepository(jdbc);
    }

    @Bean
    UserCredentialRepository credentials(JdbcOperations jdbc) {
        return new JdbcUserCredentialRepository(jdbc);
    }

    @Bean
    MfaPolicy mfaPolicy(PublicKeyCredentialUserEntityRepository users, UserCredentialRepository credentials) {
        return new MfaPolicy(users, credentials);
    }

    @Bean
    SessionChallenges challenges(MfaPolicy policy, DSLContext db) {
        return new SessionChallenges(Clock.systemUTC(), policy, db);
    }

    @Bean
    WebAuthnRelyingPartyOperations relyingParty(WebAuthnProperties properties, MfaPolicy policy,
            PublicKeyCredentialUserEntityRepository users, UserCredentialRepository credentials,
            DSLContext db, PlatformTransactionManager transactions) {
        var delegate = new Webauthn4JRelyingPartyOperations(users, credentials,
            PublicKeyCredentialRpEntity.builder().id(properties.rpId()).name("IAM Login").build(),
            Set.of(properties.origin()));
        delegate.setCustomizeCreationOptions(options -> options.timeout(Duration.ofMinutes(5))
            .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                .residentKey(ResidentKeyRequirement.REQUIRED)
                .userVerification(UserVerificationRequirement.REQUIRED).build()));
        delegate.setCustomizeRequestOptions(options -> options.timeout(Duration.ofMinutes(5))
            .userVerification(UserVerificationRequirement.REQUIRED));
        return new DirectoryRelyingPartyOperations(delegate, policy, users, credentials,
            new CredentialRegistration(db, new TransactionTemplate(transactions)));
    }

    @Bean
    WebAuthnBrowserConfigurer webAuthnBrowser(WebAuthnProperties properties, MfaPolicy policy,
            SessionChallenges challenges) {
        return new WebAuthnBrowserConfigurer(properties, policy, challenges);
    }
}
