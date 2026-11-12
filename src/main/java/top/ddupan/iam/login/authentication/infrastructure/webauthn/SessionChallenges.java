package top.ddupan.iam.login.authentication.infrastructure.webauthn;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.io.UncheckedIOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.jooq.DSLContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.authentication.PublicKeyCredentialRequestOptionsRepository;
import org.springframework.security.web.webauthn.registration.PublicKeyCredentialCreationOptionsRepository;
import top.ddupan.iam.login.authentication.infrastructure.security.DirectoryPrincipal;
import static top.ddupan.iam.login.persistence.schema.Tables.WEBAUTHN_CHALLENGE;

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
    private final Clock clock;
    private final MfaPolicy policy;
    private final DSLContext db;

    public SessionChallenges(Clock clock, MfaPolicy policy, DSLContext db) {
        this.clock = clock;
        this.policy = policy;
        this.db = db;
    }

    /** Owner of a passwordless assertion challenge: no account yet, the passkey will say whose it is. */
    static final String PASSWORDLESS = "-";

    private void save(HttpServletRequest request, String purpose, String owner, Serializable options) {
        // Upstream clears after load; load already consumes atomically. Do not clear a newer challenge.
        if (options == null) return;
        var session = request.getSession();
        var now = clock.instant().atOffset(ZoneOffset.UTC);
        // Expired ceremonies of anyone, and this session's previous one for the same purpose.
        db.deleteFrom(WEBAUTHN_CHALLENGE).where(WEBAUTHN_CHALLENGE.EXPIRES_AT.le(now)).execute();
        if (session.getAttribute(purpose) instanceof String previous) {
            db.deleteFrom(WEBAUTHN_CHALLENGE).where(WEBAUTHN_CHALLENGE.ID.eq(UUID.fromString(previous))).execute();
        }
        var id = UUID.randomUUID();
        db.insertInto(WEBAUTHN_CHALLENGE)
            .set(WEBAUTHN_CHALLENGE.ID, id)
            .set(WEBAUTHN_CHALLENGE.PURPOSE, purpose)
            .set(WEBAUTHN_CHALLENGE.OWNER, owner)
            .set(WEBAUTHN_CHALLENGE.OPTIONS, serialize(options))
            .set(WEBAUTHN_CHALLENGE.EXPIRES_AT, now.plus(LIFETIME))
            .execute();
        session.setAttribute(purpose, id.toString());
    }

    private Object consume(HttpServletRequest request, String purpose) {
        var session = request.getSession(false);
        if (session == null || !(session.getAttribute(purpose) instanceof String id)) return null;
        session.removeAttribute(purpose);
        // Deleting and reading in one statement: concurrent requests of one session consume a challenge once.
        var stored = db.deleteFrom(WEBAUTHN_CHALLENGE)
            .where(WEBAUTHN_CHALLENGE.ID.eq(UUID.fromString(id)), WEBAUTHN_CHALLENGE.PURPOSE.eq(purpose))
            .returning(WEBAUTHN_CHALLENGE.OWNER, WEBAUTHN_CHALLENGE.OPTIONS, WEBAUTHN_CHALLENGE.EXPIRES_AT)
            .fetchOne();
        if (stored == null || !clock.instant().isBefore(stored.getExpiresAt().toInstant())) return null;
        // A challenge made for one account is useless to a session that has since become another (or none). Which
        // factors the session needs is checked again where the result is used (DirectoryRelyingPartyOperations).
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!PASSWORDLESS.equals(stored.getOwner())
                && (authentication == null || !stored.getOwner().equals(authentication.getName()))) return null;
        return deserialize(stored.getOptions());
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
                SessionChallenges.this.save(r, PURPOSE, policy.signedIn().getName(), o);
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
                SessionChallenges.this.save(r, PURPOSE, policy.secondStep().map(DirectoryPrincipal::getName).orElse(PASSWORDLESS), o);
            }
            @Override public PublicKeyCredentialRequestOptions load(HttpServletRequest r) {
                return (PublicKeyCredentialRequestOptions) consume(r, PURPOSE);
            }
        };
    }
}
