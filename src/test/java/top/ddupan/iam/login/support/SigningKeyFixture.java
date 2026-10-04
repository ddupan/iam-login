package top.ddupan.iam.login.support;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/** Test-only: a fresh RSA signing key as a PKCS#8 PEM file, as infrastructure would provide it. */
public final class SigningKeyFixture {
    private SigningKeyFixture() { }

    public static Path write() {
        try {
            var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            var file = Files.createTempFile("iam-signing-key", ".pem");
            file.toFile().deleteOnExit();
            Files.writeString(file, "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(generator.generateKeyPair().getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n");
            return file;
        } catch (IOException ex) { throw new UncheckedIOException(ex); }
        catch (NoSuchAlgorithmException ex) { throw new IllegalStateException(ex); }
    }
}
