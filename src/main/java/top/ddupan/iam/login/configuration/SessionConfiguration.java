package top.ddupan.iam.login.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.support.GenericConversionService;

/**
 * HTTP sessions live in the database (Spring Session JDBC, auto-configured when a DataSource exists), so a
 * restart or another replica keeps logins. Attributes are stored as JSON through the same allowlisted mapper
 * as authorizations, not Java serialization: nothing is deserialized beyond Spring Security's types and ours.
 * Values must therefore round-trip through JSON (SessionAttributesRoundTripTests): a final JDK type like
 * Instant comes back as a number, so attributes of our own are plain strings.
 */
@Configuration(proxyBeanMethods = false)
class SessionConfiguration {
    /** Picked up by name by Spring Session's JDBC repository. */
    @Bean GenericConversionService springSessionConversionService() {
        var json = PrincipalJson.mapper(getClass().getClassLoader());
        var conversions = new GenericConversionService();
        conversions.addConverter(Object.class, byte[].class, json::writeValueAsBytes);
        conversions.addConverter(byte[].class, Object.class, bytes -> json.readValue(bytes, Object.class));
        return conversions;
    }
}
