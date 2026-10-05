package top.ddupan.iam.login.configuration;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Collection;
import java.util.List;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthentication;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

/**
 * Jackson mappings kept out of the domain: the directory snapshot stored with an authorization and in the
 * HTTP session. Polymorphic types are restricted to Spring Security's own allowlist plus ours.
 */
final class PrincipalJson {
    private PrincipalJson() { }

    /** The mapper for authorizations and session attributes. */
    static JsonMapper mapper(ClassLoader classLoader) {
        var allowed = BasicPolymorphicTypeValidator.builder()
            // After a real passkey step the session holds WebAuthnAuthentication, not the password token.
            .allowIfSubType(DirectoryPrincipal.class).allowIfSubType(WebAuthnAuthentication.class);
        for (var type : immutableLists()) allowed.allowIfSubType(type);
        return JsonMapper.builder()
            .addModules(SecurityJacksonModules.getModules(classLoader, allowed))
            .addMixIn(User.class, UserMixin.class)
            .addMixIn(DirectoryPrincipal.class, DirectoryPrincipalMixin.class)
            .addMixIn(WebAuthnAuthentication.class, WebAuthnAuthenticationMixin.class)
            .build();
    }

    /** The concrete types List.copyOf produces, which default typing records for the memberships list. */
    static Class<?>[] immutableLists() {
        return new Class<?>[] {List.of().getClass(), List.of(1).getClass(), List.of(1, 2, 3).getClass()};
    }

    abstract static class UserMixin {
        @JsonCreator UserMixin(@JsonProperty("id") User.UserId id, @JsonProperty("username") String username,
                @JsonProperty("displayName") String displayName, @JsonProperty("email") String email,
                @JsonProperty("memberships") List<User.GroupMembership> memberships) { }
        @JsonProperty("id") abstract User.UserId id();
        @JsonProperty("username") abstract String username();
        @JsonProperty("displayName") abstract String displayName();
        @JsonProperty("email") abstract String email();
        @JsonProperty("memberships") abstract List<User.GroupMembership> memberships();
    }

    // Derived accessors from the WebAuthn user-entity interface are recomputed, not stored.
    @JsonIgnoreProperties(value = {"name", "displayName", "id"}, ignoreUnknown = true)
    abstract static class DirectoryPrincipalMixin { }

    // Spring Security 7.1 ships no Jackson mapping for the passkey authentication result, which is what
    // the session holds after the second factor. Rebuilt through its public constructor.
    // The constructor already marks it authenticated; the setter refuses external trust, so never call it.
    @JsonIgnoreProperties(value = {"authenticated", "details", "credentials", "name"}, ignoreUnknown = true)
    abstract static class WebAuthnAuthenticationMixin {
        @JsonCreator WebAuthnAuthenticationMixin(@JsonProperty("principal") PublicKeyCredentialUserEntity principal,
                @JsonProperty("authorities") Collection<? extends GrantedAuthority> authorities) { }
    }
}
