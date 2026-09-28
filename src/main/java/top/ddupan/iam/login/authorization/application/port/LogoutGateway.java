package top.ddupan.iam.login.authorization.application.port;

public interface LogoutGateway {
    record Request(String challenge, String subject, String sid, String postLogoutRedirectUri) { }
    Request request(String challenge);
    String accept(String challenge);
    String startUrl();
}
