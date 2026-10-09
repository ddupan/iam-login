package top.ddupan.iam.login.configuration;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.Modifier;
import java.util.LinkedHashSet;
import java.util.Set;
import org.jooq.DataType;
import org.jooq.impl.SQLDataType;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportRuntimeHints;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.type.classreading.CachingMetadataReaderFactory;
import org.springframework.util.ClassUtils;

/** jOOQ under GraalVM native: Spring Boot's DSLContext needs these hints, and the reachability repository has none. */
@Configuration(proxyBeanMethods = false)
@ImportRuntimeHints(PersistenceConfiguration.JooqHints.class)
class PersistenceConfiguration {

    /**
     * <ul>
     * <li>jOOQ registers an array type for every built-in data type when it first loads (DefaultDataType), via
     * {@link Class#arrayType()}, which returns null in a native image for an array class the image does not contain:
     * DSLContext then fails to initialise. Loading SQLDataType loads every dialect's data types, so their Java types
     * are read from those classes at build time.</li>
     * <li>Generated records and tables are instantiated reflectively (a statement's returning(), fetchInto()).</li>
     * </ul>
     */
    static class JooqHints implements RuntimeHintsRegistrar {
        static final String SCHEMA = "top.ddupan.iam.login.persistence.schema";

        @Override public void registerHints(RuntimeHints hints, ClassLoader loader) {
            for (var type : builtInTypes(loader)) hints.reflection().registerType(type.arrayType());
            for (var generated : classes(loader, SCHEMA.replace('.', '/') + "/**/*.class")) {
                hints.reflection().registerType(generated, MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
                    MemberCategory.ACCESS_DECLARED_FIELDS);
            }
        }

        static Set<Class<?>> builtInTypes(ClassLoader loader) {
            var holders = new LinkedHashSet<Class<?>>();
            holders.add(SQLDataType.class);
            holders.addAll(classes(loader, "org/jooq/util/*/*DataType.class"));
            var types = new LinkedHashSet<Class<?>>();
            for (var holder : holders) {
                for (var field : holder.getFields()) {
                    if (!Modifier.isStatic(field.getModifiers()) || !DataType.class.isAssignableFrom(field.getType())) continue;
                    try {
                        var type = ((DataType<?>) field.get(null)).getType();
                        if (!type.isArray()) types.add(type);
                    } catch (IllegalAccessException ex) {
                        throw new IllegalStateException(ex);
                    }
                }
            }
            return types;
        }

        private static Set<Class<?>> classes(ClassLoader loader, String pattern) {
            var resolver = new PathMatchingResourcePatternResolver(loader);
            var readers = new CachingMetadataReaderFactory(resolver);
            var classes = new LinkedHashSet<Class<?>>();
            try {
                for (var resource : resolver.getResources("classpath*:" + pattern)) {
                    var name = readers.getMetadataReader(resource).getClassMetadata().getClassName();
                    classes.add(ClassUtils.resolveClassName(name, loader));
                }
            } catch (IOException ex) {
                throw new UncheckedIOException(ex);
            }
            return classes;
        }
    }
}
