package vn.edu.hcmut.co3103.identity.service;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import vn.edu.hcmut.co3103.identity.config.LoginPolicyProperties;
import vn.edu.hcmut.co3103.identity.dto.auth.request.LoginRequest;
import vn.edu.hcmut.co3103.identity.dto.auth.request.RegisterRequest;
import vn.edu.hcmut.co3103.identity.exception.AccountLockedException;
import vn.edu.hcmut.co3103.identity.exception.InvalidCredentialsException;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest(properties = {"auth.login.max-failed-attempts=2", "auth.login.lockout-duration=90s"})
class LoginPolicyIntegrationTest {

    @Autowired
    private AuthService authService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private LoginPolicyProperties policy;

    @Test
    void customPolicyCommitsLockAndAllowsLoginAfterExpiry() {
        String email = "policy-" + UUID.randomUUID() + "@example.com";
        var registered = authService.register(RegisterRequest.builder().email(email).password("Password123!")
                .fullName("Policy Test").build());
        var wrong = LoginRequest.builder().email(email).password("WrongPassword!").build();
        var correct = LoginRequest.builder().email(email).password("Password123!").build();
        try {
            assertThat(policy.getMaxFailedAttempts()).isEqualTo(2);
            assertThat(policy.getLockoutDuration()).isEqualTo(Duration.ofSeconds(90));
            assertThrows(InvalidCredentialsException.class, () -> authService.login(wrong));
            var first = userRepository.findById(registered.getUserId()).orElseThrow();
            assertThat(first.getFailedLoginAttempts()).isEqualTo(1);
            assertThat(first.getLockedUntil()).isNull();
            Instant before = Instant.now();
            assertThrows(InvalidCredentialsException.class, () -> authService.login(wrong));
            var locked = userRepository.findById(registered.getUserId()).orElseThrow();
            assertThat(locked.getFailedLoginAttempts()).isEqualTo(2);
            assertThat(locked.getLockedUntil()).isBetween(before.plusSeconds(90), Instant.now().plusSeconds(90));
            assertThat(locked.getLastLoginAt()).isNull();
            assertThrows(AccountLockedException.class, () -> authService.login(correct));
            assertThrows(AccountLockedException.class, () -> authService.login(wrong));
            assertThat(userRepository.findById(registered.getUserId()).orElseThrow().getFailedLoginAttempts())
                    .isEqualTo(2);
            assertThat(userRepository.findById(registered.getUserId()).orElseThrow().getLockedUntil())
                    .isEqualTo(locked.getLockedUntil());
            locked.setLockedUntil(Instant.now().minusSeconds(1));
            userRepository.saveAndFlush(locked);
            assertThat(authService.login(correct).getAccessToken()).isNotBlank();
            var unlocked = userRepository.findById(registered.getUserId()).orElseThrow();
            assertThat(unlocked.getFailedLoginAttempts()).isZero();
            assertThat(unlocked.getLockedUntil()).isNull();
            assertThat(unlocked.getLastLoginAt()).isNotNull();
        } finally {
            userRepository.deleteById(registered.getUserId());
        }
    }
}
