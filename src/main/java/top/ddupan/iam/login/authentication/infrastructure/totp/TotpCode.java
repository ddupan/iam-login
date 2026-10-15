package top.ddupan.iam.login.authentication.infrastructure.totp;

import java.util.List;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * A code submitted for the signed-in account. {@code enrolling} is the key being set up, held in the session
 * under {@link #PENDING} (base64) until a code confirms it; null when verifying the key already saved.
 */
public final class TotpCode extends AbstractAuthenticationToken {
    public static final String PENDING = "iam.totp.pending";
    private final String code;
    private final byte[] enrolling;
    private final String address;

    public TotpCode(String code, byte[] enrolling, String address) {
        super(List.of());
        this.code = code;
        this.enrolling = enrolling;
        this.address = address;
    }

    public String code() { return code; }
    public byte[] enrolling() { return enrolling; }
    public String address() { return address; }
    @Override public Object getCredentials() { return code; }
    @Override public Object getPrincipal() { return null; }
}
