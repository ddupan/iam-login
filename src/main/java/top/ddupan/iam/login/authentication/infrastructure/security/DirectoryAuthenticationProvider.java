package top.ddupan.iam.login.authentication.infrastructure.security;

import java.util.List;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import top.ddupan.iam.login.authentication.application.VerifyPassword;
import top.ddupan.iam.login.authentication.application.port.PasswordVerificationException;
import top.ddupan.iam.login.authentication.domain.UserRepository;

/** Bridges directory authentication into Spring Security's form-login lifecycle. */
public final class DirectoryAuthenticationProvider implements AuthenticationProvider {
    private final VerifyPassword passwords;

    public DirectoryAuthenticationProvider(VerifyPassword passwords) {
        this.passwords = passwords;
    }

    @Override
    public Authentication authenticate(Authentication request) {
        try {
            var user = passwords.verify(request.getName(),
                request.getCredentials() instanceof String password ? password : null);
            // Directory groups remain profile data, not local application authorities.
            return UsernamePasswordAuthenticationToken.authenticated(new DirectoryPrincipal(user), null,
                List.of(FactorGrantedAuthority.fromAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)));
        } catch (PasswordVerificationException ex) {
            if (ex.reason() == PasswordVerificationException.Reason.UNAVAILABLE) {
                throw new InternalAuthenticationServiceException("Directory unavailable");
            }
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
