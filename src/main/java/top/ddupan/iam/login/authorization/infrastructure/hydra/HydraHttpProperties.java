package top.ddupan.iam.login.authorization.infrastructure.hydra;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties("iam.hydra.http")
public record HydraHttpProperties(@DefaultValue("3s") Duration connectTimeout,
        @DefaultValue("5s") Duration readTimeout) {
    public HydraHttpProperties {
        if (connectTimeout == null || readTimeout == null || connectTimeout.isNegative()
                || connectTimeout.isZero() || readTimeout.isNegative() || readTimeout.isZero()) {
            throw new IllegalArgumentException("Hydra HTTP timeouts must be positive");
        }
    }
}
