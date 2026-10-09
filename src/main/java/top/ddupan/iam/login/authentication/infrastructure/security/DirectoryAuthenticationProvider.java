package top.ddupan.iam.login.authentication.infrastructure.security;

import java.util.List;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import top.ddupan.iam.login.authentication.application.VerifyPassword;
import top.ddupan.iam.login.authentication.application.port.PasswordVerificationException;
import top.ddupan.iam.login.authentication.domain.UserRepository;

/** Bridges directory authentication into Spring Security's form-login lifecycle. */
public final class DirectoryAuthenticationProvider implements AuthenticationProvider {
    private final VerifyPassword passwords;
    private final SignInThrottle throttle;

    public DirectoryAuthenticationProvider(VerifyPassword passwords, SignInThrottle throttle) {
        this.passwords = passwords;
        this.throttle = throttle;
    }

    @Override
    public Authentication authenticate(Authentication request) {
        // The remote address honours X-Forwarded-For from trusted proxies (server.forward-headers-strategy).
        var address = request.getDetails() instanceof WebAuthenticationDetails details
            ? String.valueOf(details.getRemoteAddress()) : "";
        if (throttle.blocked(request.getName(), address)) throw new SignInThrottledException();
        try {
            var user = passwords.verify(request.getName(),
                request.getCredentials() instanceof String password ? password : null);
            throttle.succeeded(request.getName());
            // Directory groups remain profile data, not local application authorities.
            return UsernamePasswordAuthenticationToken.authenticated(new DirectoryPrincipal(user), null,
                List.of(FactorGrantedAuthority.fromAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)));
        } catch (PasswordVerificationException ex) {
            if (ex.reason() == PasswordVerificationException.Reason.UNAVAILABLE) {
                throw new InternalAuthenticationServiceException("Directory unavailable");
            }
            // Locked, disabled and expired count too: the page reports them all as a failure.
            throttle.failed(request.getName(), address);
            throw new BadCredentialsException("Unable to verify credentials");
        } catch (UserRepository.AccessFailure ex) {
            throw new InternalAuthenticationServiceException("Directory unavailable");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.equals(authentication);
    }
}
