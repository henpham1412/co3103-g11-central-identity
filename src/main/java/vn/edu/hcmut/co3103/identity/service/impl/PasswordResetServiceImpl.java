package vn.edu.hcmut.co3103.identity.service.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import vn.edu.hcmut.co3103.identity.dto.auth.request.ForgotPasswordRequest;
import vn.edu.hcmut.co3103.identity.dto.auth.request.ResetPasswordRequest;
import vn.edu.hcmut.co3103.identity.entity.PasswordReset;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.entity.UserStatus;
import vn.edu.hcmut.co3103.identity.exception.InvalidPasswordResetTokenException;
import vn.edu.hcmut.co3103.identity.repository.PasswordResetRepository;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;
import vn.edu.hcmut.co3103.identity.service.PasswordResetNotificationService;
import vn.edu.hcmut.co3103.identity.service.PasswordResetService;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

@Service
@RequiredArgsConstructor
public class PasswordResetServiceImpl implements PasswordResetService {
    private static final Duration TOKEN_LIFETIME = Duration.ofMinutes(15);
    private static final Duration REQUEST_COOLDOWN = Duration.ofMinutes(1);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final UserRepository userRepository;
    private final PasswordResetRepository passwordResetRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordResetNotificationService notifications;

    // Return the same HTTP acknowledgement before any account-dependent DB or delivery work.
    @Override
    @Async
    @Transactional
    public void forgotPassword(ForgotPasswordRequest request) {
        // Serialize issuance for this normalized email, including across application instances.
        User user = userRepository.findByEmailForUpdate(request.getEmail()).orElse(null);
        if (user == null || user.getStatus() != UserStatus.ACTIVE) {
            return;
        }

        Instant now = Instant.now();
        if (passwordResetRepository.existsByUserIdAndCreatedAtAfter(user.getUserId(), now.minus(REQUEST_COOLDOWN))) {
            return;
        }

        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        passwordResetRepository.save(PasswordReset.builder()
                .userId(user.getUserId()).tokenHash(hashToken(token))
                .expiresAt(now.plus(TOKEN_LIFETIME)).build());
        notifications.send(user.getEmail(), token);
    }

    @Override
    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        String password = request.getNewPassword();
        if (password == null || password.isBlank() || password.length() < 8
                || password.getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new IllegalArgumentException("Password does not meet the password policy");
        }
        if (request.getToken() == null || request.getToken().isBlank()) {
            throw new InvalidPasswordResetTokenException();
        }
        // Serialize competing submissions so only one transaction can consume a token.
        PasswordReset reset = passwordResetRepository.findByTokenHashForUpdate(hashToken(request.getToken()))
                .orElseThrow(InvalidPasswordResetTokenException::new);
        if (reset.isUsed() || reset.getUsedAt() != null || reset.isExpired(Instant.now())) {
            throw new InvalidPasswordResetTokenException();
        }
        // Login also locks this row: it must not overwrite the newly encoded password.
        User user = userRepository.findByIdForUpdate(reset.getUserId())
                .orElseThrow(InvalidPasswordResetTokenException::new);
        Instant now = Instant.now();
        if (user.getStatus() != UserStatus.ACTIVE || reset.isExpired(now)) {
            throw new InvalidPasswordResetTokenException();
        }
        user.setPasswordHash(passwordEncoder.encode(password));
        reset.setUsed(true);
        reset.setUsedAt(now);
        userRepository.save(user);
        passwordResetRepository.save(reset);
    }

    private static String hashToken(String token) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java runtime", exception);
        }
    }
}
