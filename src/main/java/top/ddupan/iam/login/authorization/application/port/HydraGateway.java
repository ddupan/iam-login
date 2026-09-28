package top.ddupan.iam.login.authorization.application.port;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import top.ddupan.iam.login.authorization.domain.AuthorizationRequest;

public interface HydraGateway {
    AuthorizationRequest login(String challenge);
    AuthorizationRequest consent(String challenge);
    String acceptLogin(String challenge, String subject, String binding, Instant authenticatedAt);
    String acceptConsent(String challenge, List<String> scopes, Map<String, Object> claims);
}
