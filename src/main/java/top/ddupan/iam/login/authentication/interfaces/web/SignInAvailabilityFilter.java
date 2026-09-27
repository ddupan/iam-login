package top.ddupan.iam.login.authentication.interfaces.web;

import java.io.IOException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

/** Rejects disabled or plaintext sign-in before any credentials reach authentication. */
public final class SignInAvailabilityFilter extends OncePerRequestFilter {
    private final boolean enabled;

    public SignInAvailabilityFilter(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        if (path.isEmpty()) path = request.getRequestURI().substring(request.getContextPath().length());
        return !path.equals("/signin") && !path.startsWith("/signin/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {
        if (!enabled || !request.isSecure()) {
            response.setHeader("Cache-Control", "no-store");
            response.setStatus(enabled ? 426 : 404);
            return;
        }
        chain.doFilter(request, response);
    }
}
