package vn.edu.hcmut.co3103.identity.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.util.UUID;
import static org.assertj.core.api.Assertions.*;

class RecoveryTokensTest {
    @ParameterizedTest
    @ValueSource(strings = {"", "not base64!", "c2hvcnQ="})
    void requiresSeparateFullLengthKeyWithoutLeakingItsValue(String value) {
        assertThatThrownBy(() -> new RecoveryTokens(value)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void retriesAndRestartsDeriveSameStrongTokenWhileOtherJobsAndKeysDiffer() {
        String key = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";
        UUID id = UUID.randomUUID();
        var tokens = new RecoveryTokens(key);
        String token = tokens.token(id);
        assertThat(token).matches("[A-Za-z0-9_-]{43}").isEqualTo(new RecoveryTokens(key).token(id));
        assertThat(tokens.token(UUID.randomUUID())).isNotEqualTo(token);
        assertThat(new RecoveryTokens("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").token(id)).isNotEqualTo(token);
        assertThat(RecoveryTokens.hash(token)).hasSize(64).isNotEqualTo(token);
    }
}
