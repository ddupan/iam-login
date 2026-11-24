package top.ddupan.iam.login.configuration;

import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.Base64;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.authentication.AuthenticationConverter;

/**
 * Public clients (no secret) beyond what the framework covers. It authenticates a public client only through PKCE,
 * that is only when exchanging an authorization code. The device authorization request and the device_code and
 * refresh_token grants carry nothing but client_id, so the framework would reject a public client there. And it
 * issues no refresh token to a public client after an authorization code, which signs a browser-based client out
 * whenever its access token expires.
 */
final class PublicClients {
    private PublicClients() { }

    /** A request naming a public client by client_id alone; authenticated by {@link Provider}. */
    static final class ClientIdOnly extends OAuth2ClientAuthenticationToken {
        private static final long serialVersionUID = 1L;
        ClientIdOnly(String clientId) {
            super(clientId, ClientAuthenticationMethod.NONE, null, null);
        }
    }

    /**
     * The device authorization request, and token requests for the device_code and refresh_token grants, that
     * present no client credentials. Authorization-code exchanges are left to the framework (PKCE).
     */
    record Converter(String deviceAuthorizationPath) implements AuthenticationConverter {
        @Override public @Nullable Authentication convert(HttpServletRequest request) {
            if (!"POST".equals(request.getMethod())) return null;
            var grant = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
            var deviceAuthorization = request.getRequestURI().equals(request.getContextPath() + deviceAuthorizationPath);
            if (!deviceAuthorization && !AuthorizationGrantType.DEVICE_CODE.getValue().equals(grant)
                    && !AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(grant)) return null;
            if (request.getHeader(HttpHeaders.AUTHORIZATION) != null || request.getParameter(OAuth2ParameterNames.CLIENT_SECRET) != null
                    || request.getParameter(OAuth2ParameterNames.CLIENT_ASSERTION) != null) return null;
            var ids = request.getParameterValues(OAuth2ParameterNames.CLIENT_ID);
            if (ids == null) return null;
            if (ids.length != 1 || ids[0].isBlank()) throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
            return new ClientIdOnly(ids[0]);
        }
    }

    /** Accepts {@link ClientIdOnly} for a client registered without a secret, and nothing else. */
    record Provider(RegisteredClientRepository clients) implements AuthenticationProvider {
        @Override public Authentication authenticate(Authentication authentication) {
            var request = (ClientIdOnly) authentication;
            var client = clients.findByClientId(String.valueOf(request.getPrincipal()));
            // A confidential client must not be let in for having left out its secret.
            if (client == null || !client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE)) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
            }
            return new OAuth2ClientAuthenticationToken(client, ClientAuthenticationMethod.NONE, null);
        }

        @Override public boolean supports(Class<?> type) {
            return ClientIdOnly.class.isAssignableFrom(type);
        }
    }

    /**
     * Refresh tokens for every client registered for the refresh_token grant, public ones included. Clients rotate
     * them on each use (reuseRefreshTokens is off for every managed client), which RFC 9700 4.14.2 accepts for
     * public clients in place of sender-constraining.
     */
    static final class RefreshTokens implements OAuth2TokenGenerator<OAuth2RefreshToken> {
        private final StringKeyGenerator keys = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

        @Override public @Nullable OAuth2RefreshToken generate(OAuth2TokenContext context) {
            if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) return null;
            var issued = Instant.now();
            return new OAuth2RefreshToken(keys.generateKey(), issued,
                issued.plus(context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive()));
        }
    }
}
