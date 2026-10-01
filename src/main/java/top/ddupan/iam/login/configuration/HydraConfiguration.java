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
@EnableConfigurationProperties({HydraProperties.class, HydraHttpProperties.class})
@org.springframework.aot.hint.annotation.RegisterReflectionForBinding({HydraAdminClient.Request.class,
    HydraAdminClient.LogoutResponse.class, HydraAdminClient.LogoutClient.class, HydraAdminClient.Client.class, HydraAdminClient.Context.class, HydraAdminClient.Redirect.class})
class HydraConfiguration {
    @Bean
    org.springframework.web.client.RestClient hydraAdminHttpClient(
            org.springframework.web.client.RestClient.Builder builder, HydraProperties properties,
            HydraHttpProperties timeouts) {
        var http = java.net.http.HttpClient.newBuilder().connectTimeout(timeouts.connectTimeout())
            .followRedirects(java.net.http.HttpClient.Redirect.NEVER).build();
        var factory = new org.springframework.http.client.JdkClientHttpRequestFactory(http);
        factory.setReadTimeout(timeouts.readTimeout());
        return builder.baseUrl(properties.adminUrl().toString()).requestFactory(factory).build();
    }
    @Bean HydraGateway hydraGateway(HydraProperties properties, MfaPolicy requiredMfa,
            org.springframework.web.client.RestClient hydraAdminHttpClient) {
        return new HydraAdminClient(properties, hydraAdminHttpClient);
    }
    @Bean AuthorizationPolicy authorizationPolicy(HydraProperties properties, ClientManagementConfiguration.Access access) {
        return new AuthorizationPolicy(properties.clients(), properties.subjects().stream().collect(Collectors.toMap(
            binding -> new User.UserId(binding.authority(), binding.directoryId()), HydraProperties.SubjectBinding::subject)),
            access.adminUiClientId(), access::allowed);
    }
    @Bean AuthorizeApplication authorizeApplication(AuthorizationPolicy policy, HydraGateway hydra) {
        return new AuthorizeApplication(policy, hydra);
    }
}
