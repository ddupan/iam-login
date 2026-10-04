package top.ddupan.iam.login.configuration;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.List;
import org.springframework.core.io.Resource;

/**
 * Token signing keys, owned by infrastructure (key material is never generated or stored here). The first
 * key signs; the rest stay published so tokens they signed still verify. Rotation: put the new key first,
 * remove the old one once its tokens have expired. Key IDs are RFC 7638 thumbprints, stable across restarts.
 */
final class SigningKeys {
    private SigningKeys() { }

    static List<RSAKey> load(List<Resource> resources) {
        if (resources == null || resources.isEmpty()) {
            throw new IllegalStateException("iam.authorization-server.signing-keys must list at least one PKCS#8 RSA private key (PEM)");
        }
        return resources.stream().map(SigningKeys::load).toList();
    }

    private static RSAKey load(Resource resource) {
        try {
            var pem = resource.getContentAsString(StandardCharsets.US_ASCII);
            if (!pem.contains("-----BEGIN PRIVATE KEY-----")) {
                throw new IllegalStateException("Signing key is not a PKCS#8 PEM private key: " + resource.getDescription());
            }
            var der = Base64.getMimeDecoder().decode(pem.replaceAll("-----(BEGIN|END) PRIVATE KEY-----", ""));
            var factory = KeyFactory.getInstance("RSA");
            var privateKey = (RSAPrivateCrtKey) factory.generatePrivate(new PKCS8EncodedKeySpec(der));
            var publicKey = (RSAPublicKey) factory.generatePublic(
                new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent()));
            if (publicKey.getModulus().bitLength() < 2048) {
                throw new IllegalStateException("Signing key shorter than 2048 bits: " + resource.getDescription());
            }
            return new RSAKey.Builder(publicKey).privateKey(privateKey).keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256).keyIDFromThumbprint().build();
        } catch (IOException | GeneralSecurityException | JOSEException | ClassCastException ex) {
            throw new IllegalStateException("Cannot load signing key " + resource.getDescription(), ex);
        }
    }
}
