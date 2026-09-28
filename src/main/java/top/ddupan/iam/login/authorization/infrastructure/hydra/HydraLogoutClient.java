package top.ddupan.iam.login.authorization.infrastructure.hydra;

import java.net.URI;
import java.util.Objects;
import org.springframework.web.client.RestClient;
import top.ddupan.iam.login.authorization.application.port.LogoutGateway;

public final class HydraLogoutClient implements LogoutGateway {
    private final RestClient http;
    private final URI origin;
    public HydraLogoutClient(HydraProperties properties) {
        origin = properties.publicUrl();
        http = HydraAdminClient.restClient(properties).mutate()
            .defaultStatusHandler(status -> !status.is2xxSuccessful(), (req,res) -> { throw new IllegalArgumentException("Logout unavailable"); }).build();
    }
    @com.fasterxml.jackson.annotation.JsonIgnoreProperties(ignoreUnknown=true)
    public record Response(String challenge,String subject,String sid,String request_url, LogoutClient client) { }
    @com.fasterxml.jackson.annotation.JsonIgnoreProperties(ignoreUnknown=true)
    public record LogoutClient(java.util.List<String> post_logout_redirect_uris) { }
    @Override public Request request(String challenge) {
        validate(challenge);
        try {
            var result = Objects.requireNonNull(http.get().uri(b -> b.path("/admin/oauth2/auth/requests/logout")
                .queryParam("logout_challenge","{challenge}").build(challenge)).retrieve().body(Response.class));
            if (!challenge.equals(result.challenge())) throw new IllegalArgumentException("Wrong challenge");
            // Hydra stores the original HTTP request-target, which may be origin-relative.
            validateTarget(origin.resolve(result.request_url()).toString());
            String callback = "";
            var query = URI.create(result.request_url()).getRawQuery();
            if (query != null) for (var part : query.split("&")) {
                var pair = part.split("=",2);
                if ("post_logout_redirect_uri".equals(java.net.URLDecoder.decode(pair[0],java.nio.charset.StandardCharsets.UTF_8))) {
                    if (!callback.isEmpty() || pair.length!=2) throw new IllegalArgumentException("Duplicate logout redirect");
                    callback=java.net.URLDecoder.decode(pair[1],java.nio.charset.StandardCharsets.UTF_8);
                }
            }
            if (!callback.isEmpty()) {
                if (result.client()==null || result.client().post_logout_redirect_uris()==null
                    || !result.client().post_logout_redirect_uris().contains(callback)) throw new IllegalArgumentException("Unregistered logout redirect");
                var uri = URI.create(callback);
                if (uri.getHost()==null || uri.getUserInfo()!=null || uri.getFragment()!=null
                    || !("https".equals(uri.getScheme()) || "http".equals(uri.getScheme())
                        && java.util.Set.of("localhost","127.0.0.1").contains(uri.getHost())))
                    throw new IllegalArgumentException("Invalid logout callback");
            }
            return new Request(challenge,result.subject(),result.sid(),callback);
        } catch (RuntimeException ex) { throw new IllegalArgumentException("Logout request unavailable"); }
    }
    @Override public String accept(String challenge) {
        validate(challenge);
        try {
            var result = Objects.requireNonNull(http.put().uri(b -> b.path("/admin/oauth2/auth/requests/logout/accept")
                .queryParam("logout_challenge","{challenge}").build(challenge)).retrieve().body(HydraAdminClient.Redirect.class));
            validateTarget(result.redirect_to()); return result.redirect_to();
        } catch (RuntimeException ex) { throw new IllegalArgumentException("Logout acceptance unavailable"); }
    }
    @Override public String startUrl() { return origin.resolve("/oauth2/sessions/logout").toString(); }
    private void validateTarget(String target) {
        var uri = URI.create(target);
        if (!origin.getScheme().equals(uri.getScheme()) || !origin.getRawAuthority().equals(uri.getRawAuthority())
                || uri.getUserInfo()!=null || uri.getFragment()!=null || !"/oauth2/sessions/logout".equals(uri.getRawPath()))
            throw new IllegalArgumentException("Invalid logout redirect");
    }
    private void validate(String challenge) {
        if (challenge == null || challenge.isBlank() || challenge.length()>8192) throw new IllegalArgumentException("Invalid challenge");
    }
}
