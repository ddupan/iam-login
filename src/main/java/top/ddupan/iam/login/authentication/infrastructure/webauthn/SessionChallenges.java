package top.ddupan.iam.login.authentication.infrastructure.webauthn;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.io.UncheckedIOException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.authentication.PublicKeyCredentialRequestOptionsRepository;
import org.springframework.security.web.webauthn.registration.PublicKeyCredentialCreationOptionsRepository;

/**
 * Framework repository extension: server-side TTL, owner binding and atomic single consumption.
 * The ceremony lives in the webauthn_challenge table, the session holds only its id: sessions are stored
 * in the database too, and concurrent requests each load their own copy, so only a DELETE ... RETURNING
 * can make a challenge single-use.
 */
public final class SessionChallenges {
    private static final Duration LIFETIME = Duration.ofMinutes(5);
    /**
     * Options are written with Java serialization: Spring Security's WebAuthn types are Serializable (that is
     * how its own session repositories keep them) but its Jackson support only writes them. Rows are written
     * by this class alone, and reading back admits only the WebAuthn API and the JDK types they contain.
     */
    private static final ObjectInputFilter OPTIONS = ObjectInputFilter.Config.createFilter(
        "org.springframework.security.web.webauthn.api.*;java.lang.*;java.util.*;java.time.*;maxdepth=20;!*");
    private record Stored(String owner, byte[] options, Instant expiresAt) { }
    private final Clock clock;
    private final MfaPolicy policy;
    private final JdbcOperations jdbc;

    public SessionChallenges(Clock clock, MfaPolicy policy, JdbcOperations jdbc) {
        this.clock = clock;
        this.policy = policy;
        this.jdbc = jdbc;
    }

    private void save(HttpServletRequest request, String purpose, Serializable options) {
        // Upstream clears after load; load already consumes atomically. Do not clear a newer challenge.
        if (options == null) return;
        var owner = policy.current().getName();
        var session = request.getSession();
        var now = clock.instant();
        // Expired ceremonies of anyone, and this session's previous one for the same purpose.
        jdbc.update("DELETE FROM webauthn_challenge WHERE expires_at <= ?", Timestamp.from(now));
        if (session.getAttribute(purpose) instanceof String previous) {
            jdbc.update("DELETE FROM webauthn_challenge WHERE id = ?", UUID.fromString(previous));
        }
        var id = UUID.randomUUID();
        jdbc.update("INSERT INTO webauthn_challenge (id, purpose, owner, options, expires_at) VALUES (?, ?, ?, ?, ?)",
            id, purpose, owner, serialize(options), Timestamp.from(now.plus(LIFETIME)));
        session.setAttribute(purpose, id.toString());
    }

    private Object consume(HttpServletRequest request, String purpose) {
        var session = request.getSession(false);
        if (session == null || !(session.getAttribute(purpose) instanceof String id)) return null;
        session.removeAttribute(purpose);
        var rows = jdbc.query("DELETE FROM webauthn_challenge WHERE id = ? AND purpose = ? RETURNING owner, options, expires_at",
            (row, n) -> new Stored(row.getString(1), row.getBytes(2), row.getTimestamp(3).toInstant()),
            UUID.fromString(id), purpose);
        if (rows.isEmpty()) return null;
        var stored = rows.getFirst();
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!clock.instant().isBefore(stored.expiresAt())
                || authentication == null || !stored.owner().equals(authentication.getName())) return null;
        var result = policy.password.authorize(() -> authentication, null);
        if (result == null || !result.isGranted()) return null;
        return deserialize(stored.options());
    }

    private static byte[] serialize(Serializable options) {
        var bytes = new ByteArrayOutputStream();
        try (var out = new ObjectOutputStream(bytes)) {
            out.writeObject(options);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        return bytes.toByteArray();
    }

    private static Object deserialize(byte[] bytes) {
        try (var in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            in.setObjectInputFilter(OPTIONS);
            return in.readObject();
        } catch (IOException | ClassNotFoundException ex) {
            throw new IllegalStateException("Unreadable WebAuthn challenge", ex);
        }
    }

    public PublicKeyCredentialCreationOptionsRepository registration() {
        return new PublicKeyCredentialCreationOptionsRepository() {
            private static final String PURPOSE = "iam.webauthn.registration";
            @Override public void save(HttpServletRequest r, HttpServletResponse s, PublicKeyCredentialCreationOptions o) {
                SessionChallenges.this.save(r, PURPOSE, o);
            }
            @Override public PublicKeyCredentialCreationOptions load(HttpServletRequest r) {
                return (PublicKeyCredentialCreationOptions) consume(r, PURPOSE);
            }
        };
    }

    public PublicKeyCredentialRequestOptionsRepository authentication() {
        return new PublicKeyCredentialRequestOptionsRepository() {
            private static final String PURPOSE = "iam.webauthn.authentication";
            @Override public void save(HttpServletRequest r, HttpServletResponse s, PublicKeyCredentialRequestOptions o) {
                SessionChallenges.this.save(r, PURPOSE, o);
            }
            @Override public PublicKeyCredentialRequestOptions load(HttpServletRequest r) {
                return (PublicKeyCredentialRequestOptions) consume(r, PURPOSE);
            }
        };
    }
}
