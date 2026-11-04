package vn.edu.hcmut.co3103.identity.service;

import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import vn.edu.hcmut.co3103.identity.config.LoginPolicyProperties;
import vn.edu.hcmut.co3103.identity.dto.auth.request.LoginRequest;
import vn.edu.hcmut.co3103.identity.dto.auth.request.ResetPasswordRequest;
import vn.edu.hcmut.co3103.identity.dto.user.request.UpdateProfileRequest;
import vn.edu.hcmut.co3103.identity.entity.PasswordReset;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.exception.AccountLockedException;
import vn.edu.hcmut.co3103.identity.exception.InvalidCredentialsException;
import vn.edu.hcmut.co3103.identity.exception.InvalidPasswordResetTokenException;
import vn.edu.hcmut.co3103.identity.repository.PasswordResetRepository;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;

/** Real PostgreSQL locks, with only the save boundary paused to force overlapping transactions. */
@SpringBootTest
class UserServiceConcurrencyTest {
    private static final String OLD_PASSWORD = "OriginalPassword123!";
    private static final String NEW_PASSWORD = "NewPassword456!";

    @Autowired private UserService profiles;
    @Autowired private PasswordResetService recovery;
    @Autowired private AuthService auth;
    @Autowired private PasswordEncoder encoder;
    @Autowired private PasswordResetRepository resets;
    @Autowired private EntityManager entityManager;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private LoginPolicyProperties loginPolicy;
    @MockitoSpyBean private UserRepository users;

    private User user;

    @BeforeEach
    void createUser() {
        user = users.saveAndFlush(User.builder().email("profile-race-" + UUID.randomUUID() + "@example.com")
                .passwordHash(encoder.encode(OLD_PASSWORD)).fullName("Original name").build());
    }

    @AfterEach
    void cleanUp() {
        resets.deleteByUserId(user.getUserId());
        users.deleteById(user.getUserId());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void overlappingProfileAndResetPreserveTheNewPasswordAndConsumedToken(boolean profileFirst) throws Exception {
        String token = "profile-reset-" + UUID.randomUUID();
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(token.getBytes(StandardCharsets.UTF_8)));
        resets.saveAndFlush(PasswordReset.builder().userId(user.getUserId()).tokenHash(hash)
                .expiresAt(Instant.now().plusSeconds(900)).build());

        runOverlapping(profileFirst, () -> recovery.resetPassword(new ResetPasswordRequest(token, NEW_PASSWORD)));

        User saved = users.findById(user.getUserId()).orElseThrow();
        assertThat(saved.getFullName()).isEqualTo("Updated name");
        assertThat(encoder.matches(NEW_PASSWORD, saved.getPasswordHash())).isTrue();
        assertThat(encoder.matches(OLD_PASSWORD, saved.getPasswordHash())).isFalse();
        assertThat(auth.login(login(NEW_PASSWORD)).getAccessToken()).isNotBlank();
        assertThatThrownBy(() -> auth.login(login(OLD_PASSWORD))).isInstanceOf(InvalidCredentialsException.class);
        PasswordReset consumed = resets.findByTokenHash(hash).orElseThrow();
        assertThat(consumed.isUsed()).isTrue();
        assertThat(consumed.getUsedAt()).isNotNull();
        assertThatThrownBy(() -> recovery.resetPassword(new ResetPasswordRequest(token, OLD_PASSWORD)))
                .isInstanceOf(InvalidPasswordResetTokenException.class);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void overlappingProfileAndFailedLoginPreserveLockout(boolean profileFirst) throws Exception {
        user.setFailedLoginAttempts(loginPolicy.getMaxFailedAttempts() - 1);
        users.saveAndFlush(user);

        runOverlapping(profileFirst, () -> assertThatThrownBy(() -> auth.login(login("WrongPassword123!")))
                .isInstanceOf(InvalidCredentialsException.class));

        User saved = users.findById(user.getUserId()).orElseThrow();
        assertThat(saved.getFullName()).isEqualTo("Updated name");
        assertThat(saved.getFailedLoginAttempts()).isEqualTo(loginPolicy.getMaxFailedAttempts());
        assertThat(saved.getLockedUntil()).isAfter(Instant.now());
        assertThat(saved.getPasswordHash()).isEqualTo(user.getPasswordHash());
        assertThatThrownBy(() -> auth.login(login(OLD_PASSWORD))).isInstanceOf(AccountLockedException.class);
    }

    private LoginRequest login(String password) {
        return LoginRequest.builder().email(user.getEmail()).password(password).build();
    }

    private void runOverlapping(boolean profileFirst, Runnable securityWrite) throws Exception {
        CountDownLatch firstRead = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger firstBackend = new AtomicInteger();
        doAnswer(invocation -> {
            if (Thread.currentThread().getName().equals("profile-race-first")) {
                firstBackend.set(jdbc.queryForObject("SELECT pg_backend_pid()", Integer.class));
                firstRead.countDown();
                assertThat(release.await(15, TimeUnit.SECONDS)).isTrue();
            }
            return entityManager.merge(invocation.getArgument(0, User.class));
        }).when(users).save(any(User.class));

        Runnable profileWrite = () -> profiles.updateProfile(user.getUserId(),
                UpdateProfileRequest.builder().fullName("Updated name").build());
        var workers = Executors.newFixedThreadPool(2);
        try {
            var first = workers.submit(() -> {
                Thread.currentThread().setName("profile-race-first");
                (profileFirst ? profileWrite : securityWrite).run();
            });
            assertThat(firstRead.await(10, TimeUnit.SECONDS)).isTrue();
            var second = workers.submit(profileFirst ? securityWrite : profileWrite);
            // Observe a real database lock wait instead of relying on scheduling or a sleep.
            await().atMost(Duration.ofSeconds(10)).untilAsserted(() ->
                    assertThat(jdbc.queryForObject("""
                            SELECT count(*) FROM pg_stat_activity
                            WHERE datname = current_database() AND ? = ANY(pg_blocking_pids(pid))
                            """, Integer.class, firstBackend.get())).isPositive());
            release.countDown();
            first.get(15, TimeUnit.SECONDS);
            second.get(15, TimeUnit.SECONDS);
        } finally {
            release.countDown();
            workers.shutdownNow();
            assertThat(workers.awaitTermination(20, TimeUnit.SECONDS)).isTrue();
        }
    }
}
