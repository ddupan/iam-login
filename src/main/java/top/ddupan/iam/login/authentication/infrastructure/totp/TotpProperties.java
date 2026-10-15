package top.ddupan.iam.login.authentication.infrastructure.totp;

import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * {@code key}: 32 random bytes, base64, encrypting the authenticator app keys at rest. Losing or changing it
 * makes every set-up app unusable (those accounts sign in with a passkey, or an administrator resets them).
 * {@code issuer}: the name authenticator apps list the account under.
 */
@ConfigurationProperties("iam.totp")
public record TotpProperties(String key, @DefaultValue("IAM Login") String issuer) {
    public TotpProperties {
        if (key == null || decode(key).length != 32) throw new IllegalArgumentException("iam.totp.key must be 32 random bytes, base64");
        if (issuer.isBlank() || issuer.contains(":")) throw new IllegalArgumentException("iam.totp.issuer must be a name without ':'");
    }

    public SecretKey secretKey() {
        return new SecretKeySpec(decode(key), "AES");
    }

    private static byte[] decode(String value) {
        try {
            return Base64.getDecoder().decode(value.strip());
        } catch (IllegalArgumentException invalid) {
            return new byte[0];
        }
    }
}
