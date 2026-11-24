package top.ddupan.iam.login.authentication.infrastructure.totp;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import static java.nio.charset.StandardCharsets.US_ASCII;

/** RFC 6238 with the only parameters every authenticator app supports: HMAC-SHA1, 6 digits, 30-second steps. */
public final class Totp {
    private static final long STEP_SECONDS = 30;
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final SecureRandom RANDOM = new SecureRandom();

    private Totp() { }

    /** 160 bits, the key length RFC 4226 recommends for HMAC-SHA1. */
    public static byte[] newKey() {
        var key = new byte[20];
        RANDOM.nextBytes(key);
        return key;
    }

    /** The step the code was generated for, allowing one step of clock drift either way; -1 when none matches. */
    public static long match(byte[] key, String code, Instant now) {
        if (code == null || !code.matches("[0-9]{6}")) return -1;
        var current = now.getEpochSecond() / STEP_SECONDS;
        for (var step = current - 1; step <= current + 1; step++) {
            if (MessageDigest.isEqual(code(key, step).getBytes(US_ASCII), code.getBytes(US_ASCII))) return step;
        }
        return -1;
    }

    public static String code(byte[] key, long step) {
        try {
            var mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            var hash = mac.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(step).array());
            var binary = ByteBuffer.wrap(hash, hash[hash.length - 1] & 0xf, Integer.BYTES).getInt() & 0x7fffffff;
            return "%06d".formatted(binary % 1_000_000);
        } catch (GeneralSecurityException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    /** RFC 4648 base32 without padding, the form authenticator apps take, typed or in an otpauth URI. */
    public static String base32(byte[] bytes) {
        var out = new StringBuilder();
        int buffer = 0, bits = 0;
        for (var b : bytes) {
            buffer = (buffer << 8) | (b & 0xff);
            bits += 8;
            for (; bits >= 5; bits -= 5) out.append(ALPHABET.charAt((buffer >> (bits - 5)) & 31));
        }
        if (bits > 0) out.append(ALPHABET.charAt((buffer << (5 - bits)) & 31));
        return out.toString();
    }
}
