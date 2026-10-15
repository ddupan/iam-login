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
import org.springframework.security.crypto.encrypt.AesBytesEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.web.webauthn.api.AuthenticatorSelectionCriteria;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRpEntity;
import org.springframework.security.web.webauthn.api.ResidentKeyRequirement;
import org.springframework.security.web.webauthn.api.UserVerificationRequirement;
import org.springframework.security.web.webauthn.management.*;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import top.ddupan.iam.login.account.infrastructure.persistence.Grants;
import top.ddupan.iam.login.account.infrastructure.persistence.SecondFactors;
import top.ddupan.iam.login.authentication.infrastructure.persistence.CredentialRegistration;
import top.ddupan.iam.login.authentication.infrastructure.security.SignInThrottle;
import top.ddupan.iam.login.authentication.infrastructure.totp.TotpAuthenticationProvider;
import top.ddupan.iam.login.authentication.infrastructure.totp.TotpCredentials;
import top.ddupan.iam.login.authentication.infrastructure.totp.TotpProperties;
import top.ddupan.iam.login.authentication.infrastructure.webauthn.*;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "iam.webauthn", name = "enabled", havingValue = "true")
@EnableConfigurationProperties({WebAuthnProperties.class, TotpProperties.class})
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
    MfaPolicy mfaPolicy(PublicKeyCredentialUserEntityRepository users, UserCredentialRepository credentials,
            TotpCredentials totp) {
        return new MfaPolicy(users, credentials, totp);
    }

    @Bean
    TotpCredentials totpCredentials(DSLContext db, TotpProperties properties) {
        return new TotpCredentials(db, new AesBytesEncryptor(properties.secretKey(), KeyGenerators.secureRandom(12),
            AesBytesEncryptor.CipherAlgorithm.GCM));
    }

    @Bean
    SessionChallenges challenges(MfaPolicy policy, DSLContext db) {
        return new SessionChallenges(Clock.systemUTC(), policy, db);
    }

    @Bean
    WebAuthnRelyingPartyOperations relyingParty(WebAuthnProperties properties, MfaPolicy policy,
            PublicKeyCredentialUserEntityRepository users, UserCredentialRepository credentials,
            CredentialRegistration registrations) {
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
            registrations);
    }

    @Bean
    CredentialRegistration credentialRegistration(DSLContext db, PlatformTransactionManager transactions) {
        return new CredentialRegistration(db, new TransactionTemplate(transactions));
    }

    // The account page's own second factors and granted applications (AccountController).
    @Bean
    SecondFactors secondFactors(DSLContext db, CredentialRegistration registrations) {
        return new SecondFactors(db, registrations);
    }

    @Bean
    Grants grants(DSLContext db, PlatformTransactionManager transactions) {
        return new Grants(db, new TransactionTemplate(transactions));
    }

    @Bean
    WebAuthnBrowserConfigurer webAuthnBrowser(WebAuthnProperties properties, MfaPolicy policy,
            SessionChallenges challenges, TotpCredentials totp, CredentialRegistration registrations,
            SignInThrottle.Properties throttle) {
        // Not a bean: a lone AuthenticationProvider bean would replace Boot's global authentication manager
        // (the actuator's Basic authentication).
        return new WebAuthnBrowserConfigurer(properties, policy, challenges, new TotpAuthenticationProvider(policy, totp,
            registrations, new SignInThrottle(throttle, Clock.systemUTC()), Clock.systemUTC()));
    }
}
