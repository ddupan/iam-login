package top.ddupan.iam.login.authorization.domain;

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
            return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                .digest(challenge.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException ex) { throw new IllegalStateException("SHA-256 unavailable", ex); }
    }
}
