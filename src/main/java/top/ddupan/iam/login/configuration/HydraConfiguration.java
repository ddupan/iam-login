package top.ddupan.iam.login.configuration;

import java.net.http.HttpClient;
import java.util.stream.Collectors;
import org.springframework.aot.hint.annotation.RegisterReflectionForBinding;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authentication.infrastructure.webauthn.MfaPolicy;
import top.ddupan.iam.login.authorization.application.AuthorizationPolicy;
import top.ddupan.iam.login.authorization.application.AuthorizeApplication;
import top.ddupan.iam.login.authorization.application.port.HydraGateway;
import top.ddupan.iam.login.authorization.infrastructure.hydra.*;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "iam.hydra", name = "enabled", havingValue = "true")
@EnableConfigurationProperties({HydraProperties.class, HydraHttpProperties.class})
@RegisterReflectionForBinding({HydraAdminClient.Request.class,
    HydraAdminClient.LogoutResponse.class, HydraAdminClient.LogoutClient.class, HydraAdminClient.Client.class, HydraAdminClient.Context.class, HydraAdminClient.Redirect.class})
class HydraConfiguration {
    @Bean
    RestClient hydraAdminHttpClient(
            RestClient.Builder builder, HydraProperties properties,
            HydraHttpProperties timeouts) {
        var http = HttpClient.newBuilder().connectTimeout(timeouts.connectTimeout())
            .followRedirects(HttpClient.Redirect.NEVER).build();
        var factory = new JdkClientHttpRequestFactory(http);
        factory.setReadTimeout(timeouts.readTimeout());
        return builder.baseUrl(properties.adminUrl().toString()).requestFactory(factory).build();
    }
    @Bean HydraGateway hydraGateway(HydraProperties properties, MfaPolicy requiredMfa,
            RestClient hydraAdminHttpClient) {
        return new HydraAdminClient(properties, hydraAdminHttpClient);
    }
    @Bean AuthorizationPolicy authorizationPolicy(HydraProperties properties) {
        return new AuthorizationPolicy(properties.clients(), properties.subjects().stream().collect(Collectors.toMap(
            binding -> new User.UserId(binding.authority(), binding.directoryId()), HydraProperties.SubjectBinding::subject)));
    }
    @Bean AuthorizeApplication authorizeApplication(AuthorizationPolicy policy, HydraGateway hydra) {
        return new AuthorizeApplication(policy, hydra);
    }
}
