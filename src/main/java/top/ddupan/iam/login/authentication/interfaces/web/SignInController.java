package top.ddupan.iam.login.authentication.interfaces.web;

import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import top.ddupan.iam.login.authentication.domain.User.GroupMembership;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;

/** Renders Spring Security's login pages; form processing belongs to the security filters. */
@RestController
public class SignInController {
    private final PageRenderer renderer;

    public SignInController(PageRenderer renderer) {
        this.renderer = renderer;
    }

    @GetMapping(value = "/signin", produces = MediaType.TEXT_HTML_VALUE)
    ResponseEntity<String> page(@RequestParam(required = false) String error, CsrfToken csrf) {
        return renderer.render(Map.of("step", "password", "name", "",
            "error", error == null ? "" : "无法验证账号，请检查凭据与账号状态，或稍后重试。",
            "action", "/signin/password", "csrf", csrf(csrf)));
    }

    @GetMapping(value = "/signin/mfa", produces = MediaType.TEXT_HTML_VALUE)
    ResponseEntity<String> pending(@AuthenticationPrincipal DirectoryPrincipal principal, CsrfToken csrf) {
        var user = principal.user();
        return renderer.render(Map.of("step", "mfa-pending", "name", user.displayName(),
            "error", "", "action", "/signin/restart", "csrf", csrf(csrf),
            "identity", Map.of("username", user.username(), "subjectId", user.id().value(),
                "email", user.email(),
                "groups", user.memberships().stream().map(GroupMembership::name).toList(),
                "groupDns", user.memberships().stream().map(GroupMembership::externalId).toList())));
    }

    private static Map<String, String> csrf(CsrfToken token) {
        return Map.of("name", token.getParameterName(), "value", token.getToken());
    }
}
