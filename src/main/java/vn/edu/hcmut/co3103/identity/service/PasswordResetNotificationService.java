package vn.edu.hcmut.co3103.identity.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/** Log-based delivery adapter. The delivery log contains a bearer link and must be access restricted. */
@Service
@Slf4j
public class PasswordResetNotificationService {
    private final String baseUrl;

    public PasswordResetNotificationService(
            @Value("${app.reset-password.base-url:http://localhost:3000/reset-password}") String baseUrl) {
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
        log.info("Password reset delivery to {}: {}", email, resetLink);
    }
}
