package top.ddupan.iam.login.authentication.infrastructure.ad;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import top.ddupan.iam.login.authentication.domain.UserRepository;

class AdUserDetailsMapperTests {
    @Test void pwdLastSetIsAFiletime() {
        assertThat(AdUserDetailsMapper.passwordChangedAt("116444736000000000")).isEqualTo(Instant.EPOCH);
        assertThat(AdUserDetailsMapper.passwordChangedAt("116444736015000001")).isEqualTo(Instant.ofEpochSecond(1, 500_000_100));
        assertThat(AdUserDetailsMapper.passwordChangedAt("0")).as("must change at next logon").isEqualTo(Instant.MAX);
        assertThat(AdUserDetailsMapper.passwordChangedAt(null)).as("unknown").isNull();
        assertThatThrownBy(() -> AdUserDetailsMapper.passwordChangedAt("soon")).isInstanceOf(UserRepository.AccessFailure.class);
    }
}
