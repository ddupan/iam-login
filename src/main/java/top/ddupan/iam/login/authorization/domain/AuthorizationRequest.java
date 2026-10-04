package top.ddupan.iam.login.authorization.domain;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;

/** Verified metadata read from the issuer's private administrative API. */
public record AuthorizationRequest(String challenge, String clientId, List<String> scopes,
        List<String> audience, String subject, String loginChallengeDigest, String binding, String requestUrl,
        boolean skip, Boolean loginEnabled) {
    public AuthorizationRequest(String challenge, String clientId, List<String> scopes, List<String> audience,
            String subject, String loginChallengeDigest, String binding, String requestUrl, boolean skip) {
        this(challenge,clientId,scopes,audience,subject,loginChallengeDigest,binding,requestUrl,skip,null);
    }
    public AuthorizationRequest {
        scopes = List.copyOf(scopes);
        audience = List.copyOf(audience);
    }
    public String challengeDigest() { return digest(challenge); }
    public static String digest(String challenge) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(challenge.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) { throw new IllegalStateException("SHA-256 unavailable", ex); }
    }
}
