package top.ddupan.iam.login.authentication.interfaces.web;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

/** Shared HTML shell; the page context is data, never executable JavaScript. */
@Component
public class PageRenderer {
    private static final String SLOT = "__IAM_PAGE_CONTEXT__";
    private final String shell;
    private final JsonMapper json = JsonMapper.builder().build();

    public PageRenderer() throws IOException {
        shell = new ClassPathResource("ui/index.html").getContentAsString(StandardCharsets.UTF_8);
        if (shell.indexOf(SLOT) < 0 || shell.indexOf(SLOT) != shell.lastIndexOf(SLOT)) {
            throw new IllegalStateException("Expected exactly one UI context slot");
        }
    }

    public ResponseEntity<String> render(Object context) {
        String safe = json.writeValueAsString(context).replace("<", "\\u003c")
            .replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029");
        return ResponseEntity.ok().header("Cache-Control", "no-store")
            .contentType(new MediaType(MediaType.TEXT_HTML, StandardCharsets.UTF_8)).body(shell.replace(SLOT, safe));
    }
}
