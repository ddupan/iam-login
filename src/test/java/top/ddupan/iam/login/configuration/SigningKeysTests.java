package top.ddupan.iam.login.configuration;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.FileSystemResource;
import top.ddupan.iam.login.support.SigningKeyFixture;
import static org.assertj.core.api.Assertions.*;

class SigningKeysTests {
    @Test void startupFailsWithoutUsableKeys() throws Exception {
        assertThatIllegalStateException().isThrownBy(() -> SigningKeys.load(List.of()));
        assertThatIllegalStateException().isThrownBy(() -> SigningKeys.load(null));
        assertThatIllegalStateException().isThrownBy(() -> SigningKeys.load(List.of(new ByteArrayResource(
            "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n".getBytes(StandardCharsets.US_ASCII)))));
        var weak = KeyPairGenerator.getInstance("RSA");
        weak.initialize(1024);
        var pem = "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder().encodeToString(weak.generateKeyPair().getPrivate().getEncoded())
            + "\n-----END PRIVATE KEY-----\n";
        assertThatIllegalStateException().isThrownBy(() -> SigningKeys.load(List.of(new ByteArrayResource(pem.getBytes(StandardCharsets.US_ASCII)))))
            .withMessageContaining("2048");
    }

    @Test void keyIdsAreStableThumbprints() {
        var file = new FileSystemResource(SigningKeyFixture.write());
        var first = SigningKeys.load(List.of(file)).getFirst();
        assertThat(SigningKeys.load(List.of(file)).getFirst().getKeyID()).isEqualTo(first.getKeyID());
        assertThat(first.isPrivate()).isTrue();
    }
}
