package top.ddupan.iam.login.configuration;

import java.util.stream.Collectors;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authentication.infrastructure.webauthn.MfaPolicy;
import top.ddupan.iam.login.authorization.application.AuthorizeApplication;
import top.ddupan.iam.login.authorization.application.AuthorizationPolicy;
import top.ddupan.iam.login.authorization.application.port.HydraGateway;
import top.ddupan.iam.login.authorization.infrastructure.hydra.*;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "iam.hydra", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(HydraProperties.class)
@org.springframework.aot.hint.annotation.RegisterReflectionForBinding({HydraAdminClient.Request.class,
    HydraLogoutClient.Response.class, HydraLogoutClient.LogoutClient.class, HydraAdminClient.Client.class, HydraAdminClient.Context.class, HydraAdminClient.Redirect.class})
class HydraConfiguration {
    @Bean top.ddupan.iam.login.authorization.application.port.LogoutGateway logoutGateway(HydraProperties properties) {
        return new HydraLogoutClient(properties);
    }
    @Bean HydraGateway hydraGateway(HydraProperties properties, MfaPolicy requiredMfa) {
        return new HydraAdminClient(properties);
    }
    @Bean AuthorizationPolicy authorizationPolicy(HydraProperties properties) {
        return new AuthorizationPolicy(properties.clients(), properties.subjects().stream().collect(Collectors.toMap(
            binding -> new User.UserId(binding.authority(), binding.directoryId()), HydraProperties.SubjectBinding::subject)));
    }
    @Bean AuthorizeApplication authorizeApplication(AuthorizationPolicy policy, HydraGateway hydra) {
        return new AuthorizeApplication(policy, hydra);
    }
}
