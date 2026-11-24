package top.ddupan.iam.login.configuration;

import java.nio.charset.StandardCharsets;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.encrypt.AesBytesEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;
import static org.assertj.core.api.Assertions.assertThat;

class TotpEncryptorTests {
    @Test @SuppressWarnings("deprecation")
    void readsSecretsStoredByTheDeprecatedEncryptor() {
        var key = new SecretKeySpec(new byte[32], "AES");
        var secret = "stored-totp-seed".getBytes(StandardCharsets.US_ASCII);
        var stored = new AesBytesEncryptor(key, KeyGenerators.secureRandom(12), AesBytesEncryptor.CipherAlgorithm.GCM).encrypt(secret);
        assertThat(WebAuthnConfiguration.totpEncryptor(key).decrypt(stored)).isEqualTo(secret);
    }
}
