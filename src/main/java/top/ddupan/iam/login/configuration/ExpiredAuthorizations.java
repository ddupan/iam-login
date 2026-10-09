package top.ddupan.iam.login.configuration;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import org.jooq.DSLContext;
import org.jooq.Field;
import org.jooq.impl.DSL;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import static top.ddupan.iam.login.persistence.schema.Tables.OAUTH2_AUTHORIZATION;

/**
 * The framework never deletes authorizations. A row goes once every token it holds has expired (a refresh
 * token keeps it alive). Rows holding no token at all (a request still awaiting consent) are kept.
 * ponytail: abandoned consent requests therefore accumulate; purge them by age if that ever matters.
 */
public final class ExpiredAuthorizations {
    private static final Logger LOG = LoggerFactory.getLogger(ExpiredAuthorizations.class);
    private static final List<Field<OffsetDateTime>> EXPIRIES = List.of(
        OAUTH2_AUTHORIZATION.AUTHORIZATION_CODE_EXPIRES_AT, OAUTH2_AUTHORIZATION.ACCESS_TOKEN_EXPIRES_AT,
        OAUTH2_AUTHORIZATION.REFRESH_TOKEN_EXPIRES_AT, OAUTH2_AUTHORIZATION.OIDC_ID_TOKEN_EXPIRES_AT,
        OAUTH2_AUTHORIZATION.USER_CODE_EXPIRES_AT, OAUTH2_AUTHORIZATION.DEVICE_CODE_EXPIRES_AT);
    private final DSLContext db;
    private final Clock clock;

    ExpiredAuthorizations(DSLContext db, Clock clock) { this.db = db; this.clock = clock; }

    @Scheduled(fixedDelayString = "${iam.authorization-server.cleanup-interval:PT1H}", initialDelayString = "PT1M")
    public int purge() {
        var now = clock.instant().atOffset(ZoneOffset.UTC);
        // Holds at least one token, and every token it holds has expired.
        var holdsToken = DSL.coalesce(EXPIRIES.getFirst(), EXPIRIES.subList(1, EXPIRIES.size()).toArray(Field[]::new)).isNotNull();
        var allExpired = DSL.and(EXPIRIES.stream().map(expiry -> expiry.isNull().or(expiry.lt(now))).toList());
        int deleted = db.deleteFrom(OAUTH2_AUTHORIZATION).where(holdsToken, allExpired).execute();
        if (deleted > 0) LOG.info("Removed {} expired authorizations", deleted);
        return deleted;
    }
}
