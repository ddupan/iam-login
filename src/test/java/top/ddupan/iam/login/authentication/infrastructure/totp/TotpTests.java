package top.ddupan.iam.login.authentication.infrastructure.totp;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.assertj.core.api.Assertions.assertThat;

class TotpTests {
    // RFC 6238 appendix B, SHA-1 seed; the 8-digit values end in these 6 digits.
    private static final byte[] SEED = "12345678901234567890".getBytes(US_ASCII);

    @Test void matchesTheRfcVectors() {
        assertThat(Totp.code(SEED, 59 / 30)).isEqualTo("287082");
        assertThat(Totp.code(SEED, 1111111109 / 30)).isEqualTo("081804");
        assertThat(Totp.code(SEED, 1234567890 / 30)).isEqualTo("005924");
        assertThat(Totp.code(SEED, 20000000000L / 30)).isEqualTo("353130");
    }

    @Test void acceptsOneStepOfDriftAndReportsTheStep() {
        var now = Instant.ofEpochSecond(1234567890);
        var step = now.getEpochSecond() / 30;
        assertThat(Totp.match(SEED, Totp.code(SEED, step - 1), now)).isEqualTo(step - 1);
        assertThat(Totp.match(SEED, Totp.code(SEED, step + 1), now)).isEqualTo(step + 1);
        assertThat(Totp.match(SEED, Totp.code(SEED, step - 2), now)).isEqualTo(-1);
        assertThat(Totp.match(SEED, "12345", now)).isEqualTo(-1);
        assertThat(Totp.match(SEED, null, now)).isEqualTo(-1);
    }

    @Test void encodesBase32LikeRfc4648() {
        assertThat(Totp.base32("foobar".getBytes(US_ASCII))).isEqualTo("MZXW6YTBOI");
        assertThat(Totp.base32("fooba".getBytes(US_ASCII))).isEqualTo("MZXW6YTB");
        assertThat(Totp.base32(Totp.newKey())).hasSize(32);
    }
}
