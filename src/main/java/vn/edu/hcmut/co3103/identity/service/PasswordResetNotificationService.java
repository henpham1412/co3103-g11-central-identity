package vn.edu.hcmut.co3103.identity.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;

/** Sends recovery email only after the token has committed; credentials never belong in logs. */
@Service
@Slf4j
public class PasswordResetNotificationService {
    private static final int MAX_DELIVERY_ATTEMPTS = 3;
    private final JavaMailSender mailSender;
    private final Executor deliveryExecutor;
    private final String from;
    private final String baseUrl;

    public PasswordResetNotificationService(
            JavaMailSender mailSender,
            @Qualifier("applicationTaskExecutor") Executor deliveryExecutor,
            @Value("${spring.mail.username:}") String from,
            @Value("${app.reset-password.base-url:http://localhost:3000/reset-password}") String baseUrl) {
        this.mailSender = mailSender;
        this.deliveryExecutor = deliveryExecutor;
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
                    enqueue(email, resetLink);
                }
            });
        } else {
            enqueue(email, resetLink);
        }
    }

    private void enqueue(String email, String resetLink) {
        try {
            // afterCommit still holds the transaction's connection until this callback returns.
            deliveryExecutor.execute(() -> deliver(email, resetLink));
        } catch (RejectedExecutionException exception) {
            // Never fall back to SMTP on the committing thread or log task/exception contents.
            log.warn("Password reset email could not be queued for {} ({})",
                    email, exception.getClass().getSimpleName());
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
