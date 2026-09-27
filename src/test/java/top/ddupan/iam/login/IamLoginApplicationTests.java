package top.ddupan.iam.login;

import io.micrometer.core.instrument.MeterRegistry;
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
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.grafana.LgtmStackContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
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
    void signInIsDisabledUntilDirectoryIsConfigured() throws Exception {
        mvc.perform(get("/signin").secure(true)).andExpect(status().isNotFound());
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/signin/password")
            .secure(true).with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf()))
            .andExpect(status().isNotFound());
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
