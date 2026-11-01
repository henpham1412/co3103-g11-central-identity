package vn.edu.hcmut.co3103.identity.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import vn.edu.hcmut.co3103.identity.dto.auth.request.ForgotPasswordRequest;
import vn.edu.hcmut.co3103.identity.dto.auth.request.ResetPasswordRequest;
import vn.edu.hcmut.co3103.identity.entity.PasswordReset;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.entity.UserStatus;
import vn.edu.hcmut.co3103.identity.exception.InvalidPasswordResetTokenException;
import vn.edu.hcmut.co3103.identity.repository.PasswordResetRepository;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;
import vn.edu.hcmut.co3103.identity.repository.RecoveryQueue;
import java.net.InetAddress;
import vn.edu.hcmut.co3103.identity.service.impl.PasswordResetServiceImpl;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PasswordResetServiceTest {
    @Mock private UserRepository users;
    @Mock private PasswordResetRepository resets;
    @Mock private PasswordEncoder encoder;
    @Mock private RecoveryQueue queue;
    private final RecoveryTokens tokens = new RecoveryTokens("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=");
    private RecoveryQueue.Job job;

    private PasswordResetService service;
    private User user;

    @BeforeEach
    void setUp() {
        service = new PasswordResetServiceImpl(users, resets, encoder, queue, tokens);
        user = User.builder().userId(UUID.randomUUID()).email("student@example.com")
                .passwordHash("old-hash").fullName("Student").build();
        job = new RecoveryQueue.Job(UUID.randomUUID(), user.getEmail(), InetAddress.ofLiteral("203.0.113.9"),
                UUID.randomUUID(), 1, null);
        lenient().when(queue.lockRequest(job)).thenReturn(true);
        lenient().when(resets.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void admissionPersistsImmutableRequestMetadataBeforeAccountLookup() {
        service.forgotPassword(new ForgotPasswordRequest("  STUDENT@EXAMPLE.COM  "), job.clientIp());
        verify(queue).admit(user.getEmail(), job.clientIp());
        verifyNoInteractions(users, resets, encoder);
    }

    @Test
    void forgotStoresOnlyHashOfFreshSecureTokenWithFifteenMinuteLifetime() throws Exception {
        when(users.findByEmailForUpdate(user.getEmail())).thenReturn(Optional.of(user));
        Instant before = Instant.now();
        service.issuePasswordReset(job);

        var saved = ArgumentCaptor.forClass(PasswordReset.class);
        verify(resets).saveAndFlush(saved.capture());
        String token = tokens.token(job.id());
        PasswordReset reset = saved.getValue();
        assertThat(token).matches("[A-Za-z0-9_-]{43}");
        assertThat(reset.getTokenHash()).isEqualTo(hash(token)).isNotEqualTo(token);
        assertThat(reset.getUserId()).isEqualTo(user.getUserId());
        assertThat(reset.getIpRequested()).isEqualTo(job.clientIp());
        verify(queue).ready(job, reset.getResetId(), reset.getExpiresAt());
        assertThat(reset.getExpiresAt()).isBetween(before.plusSeconds(900), Instant.now().plusSeconds(900));
        assertThat(reset.isUsed()).isFalse();
        assertThat(reset.getUsedAt()).isNull();
    }

    @Test
    void forgotWithinCooldownChecksUnderUserLockAndSuppressesIssuance() {
        when(users.findByEmailForUpdate(user.getEmail())).thenReturn(Optional.of(user));
        when(resets.existsByUserIdAndCreatedAtAfter(eq(user.getUserId()), any(Instant.class))).thenReturn(true);
        Instant before = Instant.now();

        service.issuePasswordReset(job);

        var cutoff = ArgumentCaptor.forClass(Instant.class);
        var order = inOrder(users, resets);
        order.verify(users).findByEmailForUpdate(user.getEmail());
        order.verify(resets).existsByUserIdAndCreatedAtAfter(eq(user.getUserId()), cutoff.capture());
        assertThat(cutoff.getValue()).isBetween(before.minusSeconds(60), Instant.now().minusSeconds(60));
        verify(resets, never()).save(any());
        verify(resets, never()).saveAndFlush(any());
        verifyNoInteractions(encoder);
    }

    @Test
    void forgotUnknownEmailDoesNotIssueToken() {
        when(users.findByEmailForUpdate(user.getEmail())).thenReturn(Optional.empty());
        service.issuePasswordReset(job);
        verifyNoInteractions(resets, encoder);
    }

    @ParameterizedTest
    @EnumSource(value = UserStatus.class, names = {"SUSPENDED", "DEACTIVATED"})
    void forgotNonActiveUserDoesNotIssueToken(UserStatus status) {
        user.setStatus(status);
        when(users.findByEmailForUpdate(user.getEmail())).thenReturn(Optional.of(user));
        service.issuePasswordReset(job);
        verifyNoInteractions(resets, encoder);
    }

    @Test
    void resetEncodesPasswordAndRecordsConsumption() throws Exception {
        PasswordReset reset = validReset();
        when(resets.findByTokenHashForUpdate(hash("raw-token"))).thenReturn(Optional.of(reset));
        when(users.findByIdForUpdate(user.getUserId())).thenReturn(Optional.of(user));
        when(encoder.encode("NewPassword123!")).thenReturn("new-bcrypt-hash");
        Instant before = Instant.now();

        service.resetPassword(new ResetPasswordRequest("raw-token", "NewPassword123!"));

        assertThat(user.getPasswordHash()).isEqualTo("new-bcrypt-hash");
        assertThat(reset.isUsed()).isTrue();
        assertThat(reset.getUsedAt()).isBetween(before, Instant.now());
        verify(users).save(user);
        verify(resets).save(reset);
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "expired", "used", "usedAt"})
    void invalidTokensNeverChangePassword(String scenario) throws Exception {
        PasswordReset reset = validReset();
        if (scenario.equals("expired")) reset.setExpiresAt(Instant.now().minusSeconds(1));
        if (scenario.equals("used")) reset.setUsed(true); // Legacy row without used_at.
        if (scenario.equals("usedAt")) reset.setUsedAt(Instant.now());
        when(resets.findByTokenHashForUpdate(hash("raw-token")))
                .thenReturn(scenario.equals("missing") ? Optional.empty() : Optional.of(reset));

        assertThatThrownBy(() -> service.resetPassword(new ResetPasswordRequest("raw-token", "NewPassword123!")))
                .isInstanceOf(InvalidPasswordResetTokenException.class)
                .hasMessage("Invalid or expired password reset token");
        verifyNoInteractions(users, encoder);
        verify(resets, never()).save(any());
        verify(resets, never()).saveAndFlush(any());
    }

    @ParameterizedTest
    @EnumSource(value = UserStatus.class, names = {"SUSPENDED", "DEACTIVATED"})
    void resetRejectsAccountDisabledAfterIssuance(UserStatus status) throws Exception {
        user.setStatus(status);
        PasswordReset reset = validReset();
        when(resets.findByTokenHashForUpdate(hash("raw-token"))).thenReturn(Optional.of(reset));
        when(users.findByIdForUpdate(user.getUserId())).thenReturn(Optional.of(user));
        assertThatThrownBy(() -> service.resetPassword(new ResetPasswordRequest("raw-token", "NewPassword123!")))
                .isInstanceOf(InvalidPasswordResetTokenException.class);
        verifyNoInteractions(encoder);
        verify(resets, never()).save(any());
        verify(resets, never()).saveAndFlush(any());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"       ", "short"})
    void serviceAlsoValidatesPasswordWhenCalledWithoutHttp(String password) {
        assertThatThrownBy(() -> service.resetPassword(new ResetPasswordRequest("raw-token", password)))
                .isInstanceOf(IllegalArgumentException.class);
        verifyNoInteractions(users, resets, encoder);
    }

    @Test
    void serviceRejectsPasswordsBeyondBcryptByteLimit() {
        assertThatThrownBy(() -> service.resetPassword(new ResetPasswordRequest("raw-token", "é".repeat(37))))
                .isInstanceOf(IllegalArgumentException.class);
        verifyNoInteractions(users, resets, encoder);
    }

    private PasswordReset validReset() {
        return PasswordReset.builder().userId(user.getUserId()).expiresAt(Instant.now().plusSeconds(900)).build();
    }

    private String hash(String token) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
    }
}
