package vn.edu.hcmut.co3103.identity.repository;

import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import vn.edu.hcmut.co3103.identity.entity.PasswordReset;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.entity.UserProfile;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@Transactional
class ProfileRecoveryRepositoryIntegrationTest {

    @Autowired
    private PasswordResetRepository passwordResetRepository;
    @Autowired
    private UserProfileRepository userProfileRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private EntityManager entityManager;
    @Autowired
    private JdbcTemplate jdbcTemplate;

    @ParameterizedTest
    @ValueSource(strings = {"192.0.2.10", "2001:db8::10"})
    void roundTripsResetWithPostgresInetAndPreservesCreationTimeOnUpdate(String address)
            throws UnknownHostException {
        var reset = newReset(newUser().getUserId());
        reset.setIpRequested(InetAddress.getByName(address));
        passwordResetRepository.saveAndFlush(reset);
        entityManager.clear();

        var stored = passwordResetRepository.findByTokenHash(reset.getTokenHash()).orElseThrow();
        assertThat(stored.getResetId()).isNotNull().isEqualTo(reset.getResetId());
        assertThat(stored.getUserId()).isEqualTo(reset.getUserId());
        assertThat(stored.getTokenHash()).isEqualTo(reset.getTokenHash());
        assertThat(stored.getExpiresAt()).isEqualTo(reset.getExpiresAt());
        assertThat(stored.getIpRequested()).isEqualTo(reset.getIpRequested());
        assertThat(stored.isUsed()).isFalse();
        assertThat(stored.getCreatedAt()).isNotNull().isBefore(stored.getExpiresAt());
        Instant createdAt = stored.getCreatedAt();

        stored.setUsed(true);
        stored.setCreatedAt(createdAt.minusSeconds(60));
        passwordResetRepository.saveAndFlush(stored);
        entityManager.clear();
        var updated = passwordResetRepository.findById(reset.getResetId()).orElseThrow();
        assertThat(updated.isUsed()).isTrue();
        assertThat(updated.getCreatedAt()).isEqualTo(createdAt);
    }

    @Test
    void permitsMissingRequestedIpAndReturnsEmptyForUnknownTokenOrUser() {
        var reset = passwordResetRepository.saveAndFlush(newReset(newUser().getUserId()));
        entityManager.clear();
        assertThat(passwordResetRepository.findById(reset.getResetId()).orElseThrow().getIpRequested()).isNull();
        assertThat(passwordResetRepository.findByTokenHash("missing-" + UUID.randomUUID())).isEmpty();
        assertThat(passwordResetRepository.findByUserIdOrderByCreatedAtDesc(UUID.randomUUID())).isEmpty();
    }

    @Test
    void listsOnlyRequestedUsersResetsFromNewestToOldest() {
        UUID userId = newUser().getUserId();
        var oldest = passwordResetRepository.saveAndFlush(newReset(userId));
        var newest = passwordResetRepository.saveAndFlush(newReset(userId));
        var middle = passwordResetRepository.saveAndFlush(newReset(userId));
        passwordResetRepository.saveAndFlush(newReset(newUser().getUserId()));
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        setCreatedAt(oldest, now.minusSeconds(120));
        setCreatedAt(newest, now);
        setCreatedAt(middle, now.minusSeconds(60));
        entityManager.clear();

        assertThat(passwordResetRepository.findByUserIdOrderByCreatedAtDesc(userId))
                .extracting(PasswordReset::getResetId)
                .containsExactly(newest.getResetId(), middle.getResetId(), oldest.getResetId());
    }

    @Test
    void deletesAllResetsForOnlyTheRequestedUser() {
        UUID userId = newUser().getUserId();
        passwordResetRepository.saveAndFlush(newReset(userId));
        passwordResetRepository.saveAndFlush(newReset(userId));
        var other = passwordResetRepository.saveAndFlush(newReset(newUser().getUserId()));

        passwordResetRepository.deleteByUserId(userId);
        passwordResetRepository.deleteByUserId(UUID.randomUUID());
        passwordResetRepository.flush();
        entityManager.clear();

        assertThat(passwordResetRepository.findByUserIdOrderByCreatedAtDesc(userId)).isEmpty();
        assertThat(passwordResetRepository.findById(other.getResetId())).isPresent();
        assertThat(userRepository.findById(userId)).isPresent();
    }

    @Test
    void rejectsDuplicateTokenHashesEvenForDifferentUsers() {
        var first = passwordResetRepository.saveAndFlush(newReset(newUser().getUserId()));
        var duplicate = newReset(newUser().getUserId());
        duplicate.setTokenHash(first.getTokenHash());

        assertThrows(DataIntegrityViolationException.class,
                () -> passwordResetRepository.saveAndFlush(duplicate));
    }

    @Test
    void rejectsResetForNonexistentUser() {
        var reset = newReset(UUID.randomUUID());
        var error = assertThrows(DataIntegrityViolationException.class,
                () -> passwordResetRepository.saveAndFlush(reset));
        assertThat(error.getMostSpecificCause()).hasMessageContaining("fk_password_resets_user");
    }

    @Test
    void rejectsResetThatExpiresBeforeCreation() {
        var reset = newReset(newUser().getUserId());
        reset.setExpiresAt(Instant.now().minusSeconds(60));

        var error = assertThrows(DataIntegrityViolationException.class,
                () -> passwordResetRepository.saveAndFlush(reset));
        assertThat(error.getMostSpecificCause()).hasMessageContaining("chk_password_resets_expiry");
    }

    @Test
    void savesReadsAndUpdatesProfileUsingUserIdAsPrimaryKey() {
        var user = newUser();
        assertThat(userProfileRepository.findById(user.getUserId())).isEmpty();
        var profile = UserProfile.builder().user(user).avatarUrl("https://example.com/avatar.png")
                .bio("Student").phoneNumber("+84912345678").dateOfBirth(LocalDate.of(2000, 1, 2))
                .locale("vi-VN").timezone("Asia/Ho_Chi_Minh").build();
        userProfileRepository.saveAndFlush(profile);
        entityManager.clear();

        var stored = userProfileRepository.findById(user.getUserId()).orElseThrow();
        assertThat(stored.getUserId()).isEqualTo(user.getUserId());
        assertThat(stored.getUser().getUserId()).isEqualTo(user.getUserId());
        assertThat(stored.getAvatarUrl()).isEqualTo(profile.getAvatarUrl());
        assertThat(stored.getBio()).isEqualTo(profile.getBio());
        assertThat(stored.getPhoneNumber()).isEqualTo(profile.getPhoneNumber());
        assertThat(stored.getDateOfBirth()).isEqualTo(profile.getDateOfBirth());
        assertThat(stored.getLocale()).isEqualTo(profile.getLocale());
        assertThat(stored.getTimezone()).isEqualTo(profile.getTimezone());
        assertThat(stored.getUpdatedAt()).isNotNull();
        Instant updatedAt = stored.getUpdatedAt();

        stored.setBio("Updated biography");
        userProfileRepository.saveAndFlush(stored);
        entityManager.clear();
        var updated = userProfileRepository.findById(user.getUserId()).orElseThrow();
        assertThat(updated.getBio()).isEqualTo("Updated biography");
        assertThat(updated.getUpdatedAt()).isAfterOrEqualTo(updatedAt);
    }

    @Test
    void savesProfileWithDefaultsAndNullableFields() {
        var user = newUser();
        userProfileRepository.saveAndFlush(UserProfile.builder().user(user).build());
        entityManager.clear();

        var stored = userProfileRepository.findById(user.getUserId()).orElseThrow();
        assertThat(stored.getAvatarUrl()).isNull();
        assertThat(stored.getBio()).isNull();
        assertThat(stored.getPhoneNumber()).isNull();
        assertThat(stored.getDateOfBirth()).isNull();
        assertThat(stored.getLocale()).isEqualTo("vi");
        assertThat(stored.getTimezone()).isEqualTo("Asia/Ho_Chi_Minh");
    }

    @Test
    void migrationCreatesPasswordResetLookupIndexes() {
        assertThat(jdbcTemplate.queryForList("""
                SELECT indexname FROM pg_indexes
                WHERE schemaname = current_schema() AND tablename = 'password_resets'
                """, String.class))
                .contains("idx_password_resets_user_id", "idx_password_resets_expires_at");
    }

    private User newUser() {
        return userRepository.saveAndFlush(User.builder().email("recovery-" + UUID.randomUUID() + "@example.com")
                .passwordHash("test-password-hash").fullName("Profile Recovery Test").build());
    }

    private PasswordReset newReset(UUID userId) {
        return PasswordReset.builder().userId(userId).tokenHash("test-hash-" + UUID.randomUUID())
                .expiresAt(Instant.now().plusSeconds(3600).truncatedTo(ChronoUnit.MICROS)).build();
    }

    private void setCreatedAt(PasswordReset reset, Instant createdAt) {
        jdbcTemplate.update("UPDATE password_resets SET created_at = ? WHERE reset_id = ?",
                Timestamp.from(createdAt), reset.getResetId());
    }
}
