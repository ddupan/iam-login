package top.ddupan.iam.login.authentication.infrastructure.ad;

import java.util.Collection;
import java.util.List;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import top.ddupan.iam.login.authentication.domain.User;

/** What the AD provider hands back: the user, and nothing it could confuse with credentials or authorities. */
public record AdUser(User user) implements UserDetails {
    // Directory groups are profile data, not application authorities.
    @Override public Collection<? extends GrantedAuthority> getAuthorities() { return List.of(); }
    @Override public String getPassword() { return null; }
    @Override public String getUsername() { return user.username(); }
}
