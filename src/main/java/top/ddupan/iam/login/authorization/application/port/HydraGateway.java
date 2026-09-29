package top.ddupan.iam.login.authorization.application.port;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import top.ddupan.iam.login.authorization.domain.AuthorizationRequest;

public interface HydraGateway {
    record LogoutRequest(String challenge, String subject, String sid, String postLogoutRedirectUri) { }
    LogoutRequest logout(String challenge);
    String acceptLogout(String challenge);
    String logoutUrl();
    AuthorizationRequest login(String challenge);
    AuthorizationRequest consent(String challenge);
    String acceptLogin(String challenge, String subject, String binding, Instant authenticatedAt);
    String acceptConsent(String challenge, List<String> scopes, Map<String, Object> claims);
}
