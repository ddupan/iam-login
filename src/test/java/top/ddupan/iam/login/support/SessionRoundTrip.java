package top.ddupan.iam.login.support;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import org.springframework.core.convert.ConversionService;
import org.springframework.mock.web.MockHttpSession;
import static org.assertj.core.api.Assertions.*;

/**
 * The integration tests keep container sessions (MockMvc passes MockHttpSession, which Spring Session's
 * cookie-based filter would ignore). This proves that whatever a real flow left in such a session survives
 * the database session store's JSON conversion: same type back, and nothing lost beyond the first pass.
 * The first pass may round one thing: Spring Security's FactorGrantedAuthority JSON writes issuedAt as
 * decimal seconds and reads it back through a double (sub-microsecond digits), as in the authorization table.
 */
public final class SessionRoundTrip {
    private SessionRoundTrip() { }

    private static String json(byte[] bytes) { return new String(bytes, StandardCharsets.UTF_8); }

    public static void assertStorable(MockHttpSession session, ConversionService store) {
        var names = Collections.list(session.getAttributeNames());
        assertThat(names).isNotEmpty();
        for (var name : names) {
            var value = session.getAttribute(name);
            var back = store.convert(store.convert(value, byte[].class), Object.class);
            assertThat(back).as(name).isInstanceOf(value.getClass());
            var stable = store.convert(back, byte[].class);
            assertThat(json(store.convert(store.convert(stable, Object.class), byte[].class))).as(name).isEqualTo(json(stable));
        }
    }
}
