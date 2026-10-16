package top.ddupan.iam.login.authentication.interfaces.web;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.boot.webmvc.autoconfigure.error.ErrorViewResolver;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;

/**
 * Error pages for browsers, in the same shell as every other page. Boot asks only for requests that accept HTML;
 * API and protocol clients keep its JSON body. The page shows only the status, never the exception or message.
 */
@Component
public class ErrorPages implements ErrorViewResolver {
    private final PageRenderer renderer;

    public ErrorPages(PageRenderer renderer) { this.renderer = renderer; }

    @Override public ModelAndView resolveErrorView(HttpServletRequest request, HttpStatus status, Map<String, Object> model) {
        var page = renderer.render(Map.of("step", "error", "status", status.value()));
        // The error controller has already set the status; only the body and its headers are written here.
        return new ModelAndView((ignored, req, response) -> {
            page.getHeaders().forEach((name, values) -> values.forEach(value -> response.addHeader(name, value)));
            response.getWriter().write(page.getBody());
        });
    }
}
