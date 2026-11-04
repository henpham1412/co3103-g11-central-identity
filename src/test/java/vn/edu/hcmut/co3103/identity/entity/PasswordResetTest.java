package vn.edu.hcmut.co3103.identity.entity;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class PasswordResetTest {

    @Test
    void expiresAtTheExactDeadlineRegardlessOfUsage() {
        Instant expiresAt = Instant.parse("2026-10-31T12:00:00Z");
        var reset = PasswordReset.builder().expiresAt(expiresAt).build();

        assertThat(reset.isUsed()).isFalse();
        assertThat(reset.isExpired(expiresAt.minusNanos(1))).isFalse();
        assertThat(reset.isExpired(expiresAt)).isTrue();
        assertThat(reset.isExpired(expiresAt.plusNanos(1))).isTrue();

        reset.setUsed(true);
        assertThat(reset.isUsed()).isTrue();
        assertThat(reset.isExpired(expiresAt.minusNanos(1))).isFalse();
    }
}
