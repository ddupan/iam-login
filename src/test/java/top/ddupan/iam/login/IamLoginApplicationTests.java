package top.ddupan.iam.login;

import io.micrometer.core.instrument.MeterRegistry;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.micrometer.metrics.test.autoconfigure.AutoConfigureMetrics;
import org.springframework.boot.micrometer.tracing.test.autoconfigure.AutoConfigureTracing;
import org.springframework.boot.opentelemetry.autoconfigure.logging.otlp.OtlpLoggingConnectionDetails;
import org.springframework.boot.opentelemetry.autoconfigure.logging.otlp.Transport;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.grafana.LgtmStackContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "iam.ui-preview.enabled=true")
@AutoConfigureMockMvc
@AutoConfigureMetrics
@AutoConfigureTracing
@Testcontainers
class IamLoginApplicationTests {

    // Field-based service connections are recreated by the test context in AOT mode.
    @Container
    @ServiceConnection
    static final LgtmStackContainer grafanaLgtm = new LgtmStackContainer(
            DockerImageName.parse(TestcontainersConfiguration.LGTM_IMAGE));

    @Autowired
    OtlpLoggingConnectionDetails loggingConnectionDetails;

    @Autowired
    @Qualifier("prometheusMeterRegistry")
    MeterRegistry prometheus;

    @Autowired
    MockMvc mvc;

    @Test
    void previewHasInlineContextAndNoCache() throws Exception {
        var result = mvc.perform(get("/preview"))
            .andExpect(status().isOk())
            .andExpect(header().string("Cache-Control", "no-store"))
            .andReturn();
        assertThat(result.getResponse().getContentAsString()).contains("login-context", "identity", "_csrf")
            .doesNotContain("__IAM_PAGE_CONTEXT__");
    }

    @Test
    void previewRejectsMissingCsrf() throws Exception {
        mvc.perform(post("/preview/identify").param("name", "测试"))
            .andExpect(status().isForbidden());
    }

    @Test
    void previewChecksStepsAndEscapesScriptEndTags() throws Exception {
        var session = new MockHttpSession();
        mvc.perform(post("/preview/verify")
                .session(session).with(csrf())
                .param("code", "123456"))
            .andExpect(status().isConflict());
        mvc.perform(post("/preview/identify")
                .session(session).with(csrf())
                .param("name", "</script><script>alert(1)</script>"))
            .andExpect(status().isSeeOther());
        var html = mvc.perform(get("/preview/verify").session(session))
            .andExpect(status().isOk()).andReturn()
            .getResponse().getContentAsString();
        assertThat(html).doesNotContain("</script><script>alert(1)</script>")
            .contains("\\u003c/script\\u003e");
    }

    @Test
    void previewRetriesAndCompletesWithoutAuthenticating() throws Exception {
        var session = new MockHttpSession();
        mvc.perform(post("/preview/identify")
                .session(session).with(csrf())
                .param("name", "测试"))
            .andExpect(redirectedUrl("/preview/verify"));
        mvc.perform(post("/preview/verify")
                .session(session).with(csrf())
                .param("code", "000000"))
            .andExpect(redirectedUrl("/preview/verify"));
        var retry = mvc.perform(get("/preview/verify").session(session))
            .andReturn().getResponse();
        assertThat(retry.getContentAsString(StandardCharsets.UTF_8)).contains("演示码不正确");
        mvc.perform(post("/preview/verify")
                .session(session).with(csrf())
                .param("code", "123456"))
            .andExpect(redirectedUrl("/preview/complete"));
        mvc.perform(get("/").session(session)
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isUnauthorized());
        assertThat(session.getAttribute("SPRING_SECURITY_CONTEXT")).isNull();
    }

    @Test
    void processCpuTimeCanBeRead() {
        assertThat(prometheus.get("process.cpu.time").functionCounter().count()).isFinite().isNotNegative();
    }

    @Test
    void loggingConnectionUsesRunningContainer() {
        assertThat(grafanaLgtm.isRunning()).isTrue();
        assertThat(loggingConnectionDetails.getUrl(Transport.HTTP))
                .isEqualTo(grafanaLgtm.getOtlpHttpUrl() + "/v1/logs");
    }

}
