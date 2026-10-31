package vn.edu.hcmut.co3103.identity.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/** Sends recovery email only after the token has committed; credentials never belong in logs. */
@Service
@Slf4j
public class PasswordResetNotificationService {
    private static final int MAX_DELIVERY_ATTEMPTS = 3;
    private final JavaMailSender mailSender;
    private final String from;
    private final String baseUrl;

    public PasswordResetNotificationService(
            JavaMailSender mailSender,
            @Value("${spring.mail.username:}") String from,
            @Value("${app.reset-password.base-url:http://localhost:3000/reset-password}") String baseUrl) {
        this.mailSender = mailSender;
        this.from = from;
        this.baseUrl = baseUrl;
    }

    public void send(String email, String token) {
        String resetLink = baseUrl + "?token=" + token;
        if (TransactionSynchronizationManager.isActualTransactionActive()) {
            // Never deliver a link for a token whose transaction later rolls back.
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    deliver(email, resetLink);
                }
            });
        } else {
            deliver(email, resetLink);
        }
    }

    void deliver(String email, String resetLink) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(email);
        message.setSubject("Reset your Central Identity password");
        message.setText("Use the following link to reset your password. It expires in 15 minutes.\n\n"
                + resetLink + "\n\nIf you did not request a password reset, ignore this email.");
        for (int attempt = 1; attempt <= MAX_DELIVERY_ATTEMPTS; attempt++) {
            try {
                mailSender.send(message);
                log.info("Password reset email delivered to {} (attempt {})", email, attempt);
                return;
            } catch (MailException exception) {
                // Mail exceptions can embed credentials or the entire message. Never log them.
                if (attempt == MAX_DELIVERY_ATTEMPTS) {
                    log.warn("Password reset email delivery failed for {} after {} attempts ({})",
                            email, attempt, exception.getClass().getSimpleName());
                }
            }
        }
    }
}
