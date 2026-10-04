package top.ddupan.iam.login.configuration;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * The framework never deletes authorizations. A row goes once every token it holds has expired (a refresh
 * token keeps it alive). Rows holding no token at all (a request still awaiting consent) are kept.
 * ponytail: abandoned consent requests therefore accumulate; purge them by age if that ever matters.
 */
public final class ExpiredAuthorizations {
    private static final Logger LOG = LoggerFactory.getLogger(ExpiredAuthorizations.class);
    private static final String[] TOKENS = {"authorization_code", "access_token", "refresh_token", "oidc_id_token",
        "user_code", "device_code"};
    private static final String DELETE;
    static {
        var sql = new StringBuilder("DELETE FROM oauth2_authorization WHERE coalesce(");
        for (int i = 0; i < TOKENS.length; i++) sql.append(i == 0 ? "" : ", ").append(TOKENS[i]).append("_expires_at");
        sql.append(") IS NOT NULL");
        for (var token : TOKENS) sql.append(" AND (").append(token).append("_expires_at IS NULL OR ").append(token).append("_expires_at < ?)");
        DELETE = sql.toString();
    }
    private final JdbcOperations jdbc;
    private final Clock clock;

    ExpiredAuthorizations(JdbcOperations jdbc, Clock clock) { this.jdbc = jdbc; this.clock = clock; }

    @Scheduled(fixedDelayString = "${iam.authorization-server.cleanup-interval:PT1H}", initialDelayString = "PT1M")
    public int purge() {
        var now = Timestamp.from(clock.instant());
        var args = new Object[TOKENS.length];
        Arrays.fill(args, now);
        int deleted = jdbc.update(DELETE, args);
        if (deleted > 0) LOG.info("Removed {} expired authorizations", deleted);
        return deleted;
    }
}
