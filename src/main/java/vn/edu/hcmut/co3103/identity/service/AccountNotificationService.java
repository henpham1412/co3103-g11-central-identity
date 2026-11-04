package vn.edu.hcmut.co3103.identity.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.task.TaskExecutor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/** Best-effort account notices; only immutable, non-secret data crosses the commit boundary. */
@Service
public class AccountNotificationService {
    private static final Logger LOG = LoggerFactory.getLogger(AccountNotificationService.class);
    private final JavaMailSender mailSender;
    private final TaskExecutor executor;
    private final String from;

    public AccountNotificationService(JavaMailSender mailSender,
            @Qualifier("accountNotificationExecutor") TaskExecutor executor,
            @Value("${spring.mail.username:}") String from) {
        this.mailSender = mailSender;
        this.executor = executor;
        this.from = from;
    }

    public void registrationConfirmed(String email) {
        afterCommit(email, "Welcome to Central Identity",
                "Your Central Identity account has been created and is active. You can now sign in.");
    }

    public void passwordChanged(String email) {
        afterCommit(email, "Your password has been changed",
                "Your Central Identity password has been changed. If you did not make this change, "
                        + "use password recovery to secure your account and contact support.");
    }

    private void afterCommit(String email, String subject, String body) {
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override public void afterCommit() {
                try {
                    executor.execute(() -> send(email, subject, body));
                } catch (RuntimeException exception) {
                    // Rejection/shutdown must never turn a committed operation into an HTTP failure.
                    LOG.warn("event=account_notification_failed reason=executor_unavailable");
                }
            }
        });
    }

    private void send(String email, String subject, String body) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(from);
            message.setTo(email);
            message.setSubject(subject);
            message.setText(body);
            mailSender.send(message);
        } catch (RuntimeException exception) {
            // SMTP exceptions can contain recipients, message bodies, and credentials.
            LOG.warn("event=account_notification_failed reason=delivery_failed");
        }
    }
}
