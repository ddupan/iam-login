package top.ddupan.iam.login.preview;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/** An isolated UI experiment. It never creates an authenticated SecurityContext. */
@RestController
class PreviewController {
    private static final String STATE = PreviewController.class.getName() + ".state";
    private final boolean enabled;
    private final PageRenderer renderer;

    PreviewController(@Value("${iam.ui-preview.enabled:false}") boolean enabled, PageRenderer renderer) {
        this.enabled = enabled;
        this.renderer = renderer;
    }

    @GetMapping(value = {"/preview", "/preview/verify", "/preview/complete"}, produces = MediaType.TEXT_HTML_VALUE)
    ResponseEntity<String> page(HttpServletRequest request, CsrfToken csrf) {
        requireEnabled();
        var session = request.getSession();
        synchronized (session) {
            var state = state(session);
            var path = request.getRequestURI().substring(request.getContextPath().length());
            if (path.equals("/preview")) {
                if (!state.step.equals("identity")) state.error = "";
                state.step = "identity";
            } else if (!path.equals(pathFor(state.step))) {
                return redirect(pathFor(state.step));
            }
            var context = Map.of("step", state.step, "name", state.name, "error", state.error,
                "action", switch (state.step) {
                    case "identity" -> "/preview/identify";
                    case "verification" -> "/preview/verify";
                    default -> "/preview/restart";
                }, "csrf", Map.of("name", csrf.getParameterName(), "value", csrf.getToken()));
            return renderer.render(context);
        }
    }

    @PostMapping("/preview/identify")
    ResponseEntity<String> identify(@RequestParam(defaultValue = "") String name, HttpSession session) {
        requireEnabled();
        synchronized (session) {
            var state = state(session);
            requireStep(state, "identity");
            if (name.isBlank() || name.length() > 64) {
                state.error = "称呼须为 1 到 64 个字符。";
                return redirect("/preview");
            }
            state.name = name.strip();
            state.error = "";
            state.step = "verification";
            return redirect("/preview/verify");
        }
    }

    @PostMapping("/preview/verify")
    ResponseEntity<String> verify(@RequestParam(defaultValue = "") String code, HttpSession session) {
        requireEnabled();
        synchronized (session) {
            var state = state(session);
            requireStep(state, "verification");
            if (!code.equals("123456")) {
                state.error = "演示码不正确，请输入 123456。";
                return redirect("/preview/verify");
            }
            state.error = "";
            state.step = "complete";
            return redirect("/preview/complete");
        }
    }

    @PostMapping("/preview/restart")
    ResponseEntity<String> restart(HttpSession session) {
        requireEnabled();
        synchronized (session) {
            session.removeAttribute(STATE);
            return redirect("/preview");
        }
    }

    private void requireEnabled() {
        if (!enabled) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
    }

    private static void requireStep(State state, String step) {
        if (!state.step.equals(step)) throw new ResponseStatusException(HttpStatus.CONFLICT, "页面已过期，请重新打开预览");
    }

    private static State state(HttpSession session) {
        var state = (State) session.getAttribute(STATE);
        if (state == null) {
            state = new State();
            session.setAttribute(STATE, state);
        }
        return state;
    }

    private static String pathFor(String step) {
        return switch (step) {
            case "verification" -> "/preview/verify";
            case "complete" -> "/preview/complete";
            default -> "/preview";
        };
    }

    private static ResponseEntity<String> redirect(String path) {
        return ResponseEntity.status(HttpStatus.SEE_OTHER).header("Location", path)
            .header("Cache-Control", "no-store").build();
    }

    private static class State {
        String step = "identity";
        String name = "";
        String error = "";
    }
}
