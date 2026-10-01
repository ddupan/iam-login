package top.ddupan.iam.login.authorization.infrastructure.hydra;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.web.client.RestClient;
import top.ddupan.iam.login.authorization.application.port.HydraGateway;
import top.ddupan.iam.login.authorization.domain.AuthorizationRequest;

/** Private, fixed-origin admin client. Never follows redirects or forwards upstream errors/challenges. */
public final class HydraAdminClient implements HydraGateway {
    private final RestClient client;
    private final URI publicUrl;
    public HydraAdminClient(HydraProperties properties, RestClient http) {
        client = http.mutate()
            .defaultStatusHandler(status -> !status.is2xxSuccessful(), (request, response) -> {
                throw new IllegalArgumentException("Hydra returned a non-success status");
            }).build();
        publicUrl = properties.publicUrl();
    }
    @com.fasterxml.jackson.annotation.JsonIgnoreProperties(ignoreUnknown = true)
    public record Client(String client_id, Map<String,Object> metadata) { }
    @com.fasterxml.jackson.annotation.JsonIgnoreProperties(ignoreUnknown = true)
    public record Context(String browser_binding, String login_challenge_digest) { }
    @com.fasterxml.jackson.annotation.JsonIgnoreProperties(ignoreUnknown = true)
    public record Request(String challenge, Client client, List<String> requested_scope,
            List<String> requested_access_token_audience, String subject, String login_challenge,
            Context context, String request_url, boolean skip) { }
    @com.fasterxml.jackson.annotation.JsonIgnoreProperties(ignoreUnknown = true)
    public record Redirect(String redirect_to) { }

    @Override public AuthorizationRequest login(String challenge) { return request("login", challenge); }
    @Override public AuthorizationRequest consent(String challenge) { return request("consent", challenge); }

    private AuthorizationRequest request(String kind, String challenge) {
        validateChallenge(challenge);
        try {
            var result = client.get().uri(builder -> builder.path("/admin/oauth2/auth/requests/" + kind)
                .queryParam(kind + "_challenge", "{challenge}").build(challenge)).retrieve().body(Request.class);
            if (result == null || result.client() == null || !challenge.equals(result.challenge())) {
                throw new IllegalArgumentException("Invalid issuer response");
            }
            validateAuthorizationUrl(result.request_url());
            var registered = client.get().uri("/admin/clients/{id}", result.client().client_id()).retrieve().body(Client.class);
            if (registered == null || !result.client().client_id().equals(registered.client_id()))
                throw new IllegalArgumentException("Client no longer registered");
            var eligibility = registered.metadata() == null ? null : registered.metadata().get("iam_login_enabled");
            Boolean enabled = eligibility == null ? null : Boolean.TRUE.equals(eligibility);
            return new AuthorizationRequest(challenge, result.client().client_id(),
                result.requested_scope() == null ? List.of() : result.requested_scope(),
                result.requested_access_token_audience() == null ? List.of() : result.requested_access_token_audience(),
                result.subject(), result.context() == null ? null : result.context().login_challenge_digest(), result.context() == null ? null : result.context().browser_binding(),
                result.request_url(), result.skip(), enabled);
        } catch (RuntimeException ex) {
            throw new IllegalArgumentException("Hydra request unavailable");
        }
    }
    @Override public String acceptLogin(String challenge, String subject, String binding, Instant authenticatedAt) {
        return accept("login", challenge, Map.of("subject", subject, "remember", true,
            "authenticated_at", authenticatedAt.toString(), "amr", List.of("pwd", "mfa"),
            "context", Map.of("browser_binding", binding, "login_challenge_digest", AuthorizationRequest.digest(challenge))));
    }
    @Override public String acceptConsent(String challenge, List<String> scopes, List<String> audience,
            Map<String, Object> idTokenClaims, Map<String, Object> accessTokenClaims) {
        // Requested audiences were already checked by Hydra against the client's registration.
        return accept("consent", challenge, Map.of("grant_scope", scopes, "grant_access_token_audience", audience,
            "remember", false, "session", Map.of("id_token", idTokenClaims, "access_token", accessTokenClaims)));
    }
    private String accept(String kind, String challenge, Object payload) {
        validateChallenge(challenge);
        try {
            var result = client.put().uri(builder -> builder.path("/admin/oauth2/auth/requests/" + kind + "/accept")
                .queryParam(kind + "_challenge", "{challenge}").build(challenge)).body(payload)
                .retrieve().body(Redirect.class);
            if (result == null) throw new IllegalArgumentException("Missing redirect");
            var target = URI.create(result.redirect_to());
            if (!publicUrl.getScheme().equals(target.getScheme()) || !publicUrl.getRawAuthority().equals(target.getRawAuthority())
                    || target.getUserInfo() != null || target.getFragment() != null || !"/oauth2/auth".equals(target.getRawPath())) {
                throw new IllegalArgumentException("Invalid redirect");
            }
            return target.toString();
        } catch (RuntimeException ex) {
            throw new IllegalArgumentException("Hydra acceptance unavailable");
        }
    }
    private void validateAuthorizationUrl(String value) {
        var uri = URI.create(value);
        if (!publicUrl.getScheme().equals(uri.getScheme()) || !publicUrl.getRawAuthority().equals(uri.getRawAuthority())
                || uri.getUserInfo() != null || uri.getFragment() != null || !"/oauth2/auth".equals(uri.getRawPath())) {
            throw new IllegalArgumentException("Unexpected authorization origin");
        }
        var parameters = new java.util.HashMap<String, String>();
        for (var pair : uri.getRawQuery().split("&")) {
            var parts = pair.split("=", 2);
            var key = java.net.URLDecoder.decode(parts[0], java.nio.charset.StandardCharsets.UTF_8);
            var parameter = java.net.URLDecoder.decode(parts.length == 2 ? parts[1] : "", java.nio.charset.StandardCharsets.UTF_8);
            if (parameters.putIfAbsent(key, parameter) != null) throw new IllegalArgumentException("Duplicate OAuth parameter");
        }
        if (!"code".equals(parameters.get("response_type"))
                || parameters.containsKey("prompt") && !Set.of("login", "consent", "select_account").contains(parameters.get("prompt"))) {
            throw new IllegalArgumentException("Only interactive authorization code is enabled");
        }
        if (parameters.containsKey("max_age") && Long.parseLong(parameters.get("max_age")) < 0) {
            throw new IllegalArgumentException("Invalid max_age");
        }
    }
    private static void validateChallenge(String challenge) {
        if (challenge == null || challenge.isBlank() || challenge.length() > 8192) {
            throw new IllegalArgumentException("Invalid challenge");
        }
    }
    @com.fasterxml.jackson.annotation.JsonIgnoreProperties(ignoreUnknown=true)
    public record LogoutResponse(String challenge,String subject,String sid,String request_url, LogoutClient client) { }
    @com.fasterxml.jackson.annotation.JsonIgnoreProperties(ignoreUnknown=true)
    public record LogoutClient(java.util.List<String> post_logout_redirect_uris) { }
    @Override public LogoutRequest logout(String challenge) {
        validateChallenge(challenge);
        try {
            var result = java.util.Objects.requireNonNull(client.get().uri(b -> b.path("/admin/oauth2/auth/requests/logout")
                .queryParam("logout_challenge","{challenge}").build(challenge)).retrieve().body(LogoutResponse.class));
            if (!challenge.equals(result.challenge())) throw new IllegalArgumentException("Wrong challenge");
            // Hydra stores the original HTTP request-target, which may be origin-relative.
            validateTarget(publicUrl.resolve(result.request_url()).toString());
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
            return new LogoutRequest(challenge,result.subject(),result.sid(),callback);
        } catch (RuntimeException ex) { throw new IllegalArgumentException("Logout request unavailable"); }
    }
    @Override public String acceptLogout(String challenge) {
        validateChallenge(challenge);
        try {
            var result = java.util.Objects.requireNonNull(client.put().uri(b -> b.path("/admin/oauth2/auth/requests/logout/accept")
                .queryParam("logout_challenge","{challenge}").build(challenge)).retrieve().body(HydraAdminClient.Redirect.class));
            validateTarget(result.redirect_to()); return result.redirect_to();
        } catch (RuntimeException ex) { throw new IllegalArgumentException("Logout acceptance unavailable"); }
    }
    @Override public String logoutUrl() { return publicUrl.resolve("/oauth2/sessions/logout").toString(); }
    private void validateTarget(String target) {
        var uri = URI.create(target);
        if (!publicUrl.getScheme().equals(uri.getScheme()) || !publicUrl.getRawAuthority().equals(uri.getRawAuthority())
                || uri.getUserInfo()!=null || uri.getFragment()!=null || !"/oauth2/sessions/logout".equals(uri.getRawPath()))
            throw new IllegalArgumentException("Invalid logout redirect");
    }
}
