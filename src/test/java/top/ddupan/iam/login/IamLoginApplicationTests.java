package top.ddupan.iam.login;

import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.micrometer.metrics.test.autoconfigure.AutoConfigureMetrics;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// No OTLP backend: the LGTM container only exercised Boot's service connection, and it does not start reliably
// in a CI pod (2 CPU / 4Gi). TestIamLoginApplication still runs it for local development.
@SpringBootTest(properties = {"spring.autoconfigure.exclude=org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration",
    "management.otlp.metrics.export.enabled=false"})
@AutoConfigureMockMvc
@AutoConfigureMetrics
class IamLoginApplicationTests {

    @Autowired
    @Qualifier("prometheusMeterRegistry")
    MeterRegistry prometheus;

    @Autowired
    MockMvc mvc;

    @Test
    void signInIsDisabledUntilDirectoryIsConfigured() throws Exception {
        mvc.perform(get("/signin").secure(true)).andExpect(status().isUnauthorized());
        mvc.perform(MockMvcRequestBuilders.post("/signin/password")
            .secure(true).with(SecurityMockMvcRequestPostProcessors.csrf()))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void processCpuTimeCanBeRead() {
        assertThat(prometheus.get("process.cpu.time").functionCounter().count()).isFinite().isNotNegative();
    }

}
