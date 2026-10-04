package top.ddupan.iam.login.configuration;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Arrays;
import java.util.stream.Stream;
import org.springframework.aot.hint.BindingReflectionHintsRegistrar;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.TypeReference;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.type.classreading.SimpleMetadataReaderFactory;
import top.ddupan.iam.login.authentication.domain.User;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;

/**
 * Reflection the native image needs to read back stored registered clients and authorizations. JSON in
 * those tables names its types ("@class"), resolved by Class.forName at runtime; none of this is visible
 * on the JVM. Spring Security 7.1 does not ship these hints for its Jackson 3 path.
 */
final class SecurityJacksonHints implements RuntimeHintsRegistrar {
    // Type ids written into client settings and authorization attributes.
    private static final String[] STORED_TYPES = {
        "org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat",
        "org.springframework.security.oauth2.jose.jws.SignatureAlgorithm",
        "org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest",
        "org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType",
        "org.springframework.security.oauth2.core.AuthorizationGrantType",
        "org.springframework.security.authentication.UsernamePasswordAuthenticationToken",
        "org.springframework.security.core.authority.FactorGrantedAuthority",
        "org.springframework.security.core.authority.SimpleGrantedAuthority",
        "org.springframework.security.web.authentication.WebAuthenticationDetails",
        "org.springframework.security.web.webauthn.authentication.WebAuthnAuthentication",
        "org.springframework.security.web.webauthn.api.Bytes",
        "java.time.Duration", "java.time.Instant",
        "java.util.Collections$UnmodifiableMap", "java.util.Collections$UnmodifiableSet",
        "java.util.Collections$UnmodifiableRandomAccessList", "java.util.Collections$UnmodifiableCollection",
        "java.util.Collections$EmptyList", "java.util.Collections$EmptyMap", "java.util.Collections$EmptySet",
        "java.util.Collections$SingletonList", "java.util.Collections$SingletonSet",
        "java.util.ImmutableCollections$List12", "java.util.ImmutableCollections$ListN",
        "java.util.ImmutableCollections$Set12", "java.util.ImmutableCollections$SetN",
        "java.util.ImmutableCollections$Map1", "java.util.ImmutableCollections$MapN",
        "java.util.ArrayList", "java.util.HashSet", "java.util.LinkedHashSet", "java.util.TreeSet",
        "java.util.HashMap", "java.util.LinkedHashMap", "java.util.TreeMap",
        // Written to the browser after the passkey login: without it "redirectUrl" vanishes and the
        // interrupted authorization request cannot be resumed.
        "org.springframework.security.web.authentication.HttpMessageConverterAuthenticationSuccessHandler$AuthenticationSuccess",
    };
    @Override public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
        // Spring Security's Jackson 3 packages: SecurityJacksonModules finds its modules by name, and the
        // modules' mix-ins and deserializers are read reflectively. Scanned at build time so an upgrade
        // that adds one cannot silently leave it out.
        try {
            var resolver = new PathMatchingResourcePatternResolver(classLoader);
            var readers = new SimpleMetadataReaderFactory(classLoader);
            // WebAuthn's JSON in both directions: API types written to the browser (without their getters,
            // fields such as "challenge" silently disappear) and the filters' request DTOs read back from it
            // (registration fails with a bare 400). Includes nested classes.
            var patterns = Stream.of("classpath*:org/springframework/security/**/jackson/*.class",
                "classpath*:org/springframework/security/web/webauthn/**/*.class",
                // WebAuthn4J parses client data, attestation objects and (polymorphic) attestation statements
                // with Jackson as well, and ships no native metadata for it.
                "classpath*:com/webauthn4j/**/*.class");
            for (var resource : patterns.flatMap(pattern -> {
                    try { return Arrays.stream(resolver.getResources(pattern)); }
                    catch (IOException ex) { throw new UncheckedIOException(ex); }
                }).toList()) {
                var name = readers.getMetadataReader(resource).getClassMetadata().getClassName();
                if (name.endsWith("package-info")) continue;
                hints.reflection().registerTypeIfPresent(classLoader, name, MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
                    MemberCategory.INVOKE_DECLARED_METHODS, MemberCategory.ACCESS_DECLARED_FIELDS);
            }
        } catch (IOException | UncheckedIOException ex) {
            throw new IllegalStateException("Cannot scan Spring Security Jackson classes", ex);
        }
        for (var type : STORED_TYPES) {
            hints.reflection().registerType(TypeReference.of(type), MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
                MemberCategory.INVOKE_DECLARED_METHODS, MemberCategory.INVOKE_PUBLIC_METHODS, MemberCategory.ACCESS_DECLARED_FIELDS);
        }
        // Our own stored types and the Jackson mix-ins describing them.
        new BindingReflectionHintsRegistrar().registerReflectionHints(hints.reflection(),
            DirectoryPrincipal.class, User.class, User.UserId.class, User.GroupMembership.class);
        // Stored lists are immutable List.of(...); from three elements on that is ImmutableCollections.ListN,
        // whose E[] constructor makes Jackson instantiate the element's array type when building the serializer.
        // One or two groups (List12) never reach it, so only users with 3+ groups failed in production.
        hints.reflection().registerType(TypeReference.of(User.GroupMembership[].class));
        // User is not a bean (id(), username(), ...): the mix-in maps those accessors, which the binding
        // registrar above does not cover.
        hints.reflection().registerType(User.class, MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
            MemberCategory.INVOKE_DECLARED_METHODS, MemberCategory.INVOKE_PUBLIC_METHODS);
        for (var mixin : new Class<?>[] {PrincipalJson.UserMixin.class, PrincipalJson.DirectoryPrincipalMixin.class,
                PrincipalJson.WebAuthnAuthenticationMixin.class}) {
            hints.reflection().registerType(mixin, MemberCategory.INVOKE_DECLARED_CONSTRUCTORS, MemberCategory.INVOKE_DECLARED_METHODS);
        }
    }
}
