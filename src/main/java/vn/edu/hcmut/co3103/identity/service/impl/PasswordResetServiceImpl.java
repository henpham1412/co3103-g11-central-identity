package vn.edu.hcmut.co3103.identity.service.impl;

import lombok.RequiredArgsConstructor;
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
import vn.edu.hcmut.co3103.identity.repository.RecoveryQueue;
import vn.edu.hcmut.co3103.identity.service.RecoveryTokens;
import vn.edu.hcmut.co3103.identity.service.PasswordResetService;
import vn.edu.hcmut.co3103.identity.validation.PasswordPolicy;
import vn.edu.hcmut.co3103.identity.security.SecurityAudit;
import vn.edu.hcmut.co3103.identity.service.AccountNotificationService;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;

@Service
@RequiredArgsConstructor
public class PasswordResetServiceImpl implements PasswordResetService {
    private static final Duration TOKEN_LIFETIME = Duration.ofMinutes(15);
    private static final Duration REQUEST_COOLDOWN = Duration.ofMinutes(1);

    private final UserRepository userRepository;
    private final PasswordResetRepository passwordResetRepository;
    private final PasswordEncoder passwordEncoder;
    private final RecoveryQueue queue;
    private final RecoveryTokens tokens;
    private final AccountNotificationService accountNotifications;

    // Commit durable admission before acknowledging; no account lookup or SMTP on the HTTP thread.
    @Override
    @Transactional
    public void forgotPassword(ForgotPasswordRequest request, InetAddress clientIp) {
        queue.admit(request.getEmail(), clientIp);
        SecurityAudit.success("password_reset_requested", request.getEmail(), "central-identity");
    }

    @Override
    @Transactional
    public void issuePasswordReset(RecoveryQueue.Job job) {
        if (!queue.lockRequest(job)) return;
        // Serialize issuance for this normalized email, including across application instances.
        User user = userRepository.findByEmailForUpdate(job.email()).orElse(null);
        if (user == null || user.getStatus() != UserStatus.ACTIVE) {
            queue.complete(job);
            return;
        }

        Instant now = Instant.now();
        if (passwordResetRepository.existsByUserIdAndCreatedAtAfter(user.getUserId(), now.minus(REQUEST_COOLDOWN))) {
            queue.complete(job);
            return;
        }

        String token = tokens.token(job.id());
        PasswordReset reset = passwordResetRepository.saveAndFlush(PasswordReset.builder()
                .userId(user.getUserId()).tokenHash(hashToken(token)).ipRequested(job.clientIp())
                .expiresAt(now.plus(TOKEN_LIFETIME)).build());
        // The token and delivery job become visible together, or both roll back.
        queue.ready(job, reset.getResetId(), reset.getExpiresAt());
    }

    @Override
    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        String password = request.getNewPassword();
        PasswordPolicy.validate(password);
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
        accountNotifications.passwordChanged(user.getEmail());
        SecurityAudit.success("password_reset_succeeded", user.getUserId().toString(), "central-identity");
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
