package top.ddupan.iam.login.authentication.infrastructure.security;

import java.util.List;
import java.util.Locale;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import top.ddupan.iam.login.authentication.infrastructure.ad.AdUser;

/**
 * Sign-in throttling and input limits around the directory's own provider, and the result reduced to what the rest
 * of the service uses: a directory principal holding the password factor.
 */
public final class DirectoryAuthenticationProvider implements AuthenticationProvider {
    private final AuthenticationProvider directory;
    private final String domain;
    private final SignInThrottle throttle;

    public DirectoryAuthenticationProvider(AuthenticationProvider directory, String domain, SignInThrottle throttle) {
        this.directory = directory;
        this.domain = domain.toLowerCase(Locale.ROOT);
        this.throttle = throttle;
    }

    @Override
    public Authentication authenticate(Authentication request) {
        // The remote address honours X-Forwarded-For from trusted proxies (server.forward-headers-strategy).
        var address = request.getDetails() instanceof WebAuthenticationDetails details
            ? String.valueOf(details.getRemoteAddress()) : "";
        String username = request.getName();
        if (throttle.blocked(username, address)) throw new SignInThrottledException();
        String password = request.getCredentials() instanceof String value ? value : null;
        Authentication result;
        try {
            // Malformed input is a failed attempt too, but never reaches the directory.
            if (!wellFormed(username, password)) throw new BadCredentialsException("Malformed credentials");
            result = directory.authenticate(UsernamePasswordAuthenticationToken.unauthenticated(username, password));
        } catch (BadCredentialsException | AccountStatusException | UsernameNotFoundException ex) {
            // Locked, disabled and expired count too: the page reports them all as one failure.
            throttle.failed(username, address);
            throw new BadCredentialsException("Unable to verify credentials");
        } catch (RuntimeException ex) {
            // Connection, TLS and mapping failures: the directory, not the user, is the problem.
            throw new InternalAuthenticationServiceException("Directory unavailable");
        }
        if (result == null || !(result.getPrincipal() instanceof AdUser user)) {
            throw new InternalAuthenticationServiceException("Directory unavailable");
        }
        throttle.succeeded(username);
        // Directory groups remain profile data, not local application authorities.
        return UsernamePasswordAuthenticationToken.authenticated(new DirectoryPrincipal(user.user()), null,
            List.of(FactorGrantedAuthority.fromAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)));
    }

    private boolean wellFormed(String username, String password) {
        return username != null && !username.isBlank() && username.length() <= 256
            && !username.contains("\\") && username.equals(username.strip())
            && (!username.contains("@") || username.toLowerCase(Locale.ROOT).endsWith("@" + domain))
            && password != null && !password.isEmpty() && password.length() <= 1024;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.equals(authentication);
    }
}
