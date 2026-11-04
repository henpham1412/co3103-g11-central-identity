package vn.edu.hcmut.co3103.identity.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import vn.edu.hcmut.co3103.identity.repository.RecoveryQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;

@Component
@ConditionalOnProperty(name = "app.recovery.worker-enabled", havingValue = "true", matchIfMissing = true)
@Slf4j
public class RecoveryWorker {
    private final RecoveryQueue queue;
    private final PasswordResetService service;
    private final PasswordResetNotificationService notifications;
    private final RecoveryTokens tokens;
    private final Executor issuance;
    private final Executor delivery;

    public RecoveryWorker(RecoveryQueue queue, PasswordResetService service,
            PasswordResetNotificationService notifications, RecoveryTokens tokens,
            @Qualifier("recoveryIssuanceExecutor") Executor issuance,
            @Qualifier("recoveryDeliveryExecutor") Executor delivery) {
        this.queue = queue;
        this.service = service;
        this.notifications = notifications;
        this.tokens = tokens;
        this.issuance = issuance;
        this.delivery = delivery;
    }

    @Scheduled(fixedDelayString = "${app.recovery.poll-interval-ms:250}")
    public void poll() {
        // Claim only after executor admission: rejection leaves durable work untouched.
        for (int i = 0; i < 2; i++) submit(issuance, false);
        for (int i = 0; i < 4; i++) submit(delivery, true);
    }

    @Scheduled(fixedDelay = 60000)
    public void expire() {
        int expired = queue.discardExpiredDeliveries();
        if (expired > 0) log.warn("Expired {} undelivered password recovery jobs", expired);
    }

    private void submit(Executor executor, boolean isDelivery) {
        try {
            executor.execute(() -> process(isDelivery));
        } catch (RejectedExecutionException exception) {
            // Normal backpressure. No job has been removed or leased yet.
        }
    }

    private void process(boolean isDelivery) {
        RecoveryQueue.Job job = null;
        try {
            job = queue.claim(isDelivery); // Short transaction ends before SMTP.
            if (job == null) return;
            if (isDelivery) {
                String token = tokens.token(job.id());
                if (!RecoveryTokens.hash(token).equals(job.tokenHash()))
                    throw new IllegalStateException("Recovery token key does not match pending work");
                notifications.send(job.email(), token);
                queue.complete(job);
            } else {
                service.issuePasswordReset(job);
            }
        } catch (RuntimeException exception) {
            // Transport/DB exception messages can contain credentials. Log only type and opaque job ID.
            log.warn("Password recovery {} failed; retained for retry (job {}, {})",
                    isDelivery ? "delivery" : "issuance", job == null ? "unclaimed" : job.id(),
                    exception.getClass().getSimpleName());
            if (job != null) {
                try {
                    queue.retry(job);
                } catch (RuntimeException retryFailure) {
                    // Database unavailable: the persisted lease expires and another worker retries.
                    log.warn("Password recovery retry will resume after lease expiry ({})",
                            retryFailure.getClass().getSimpleName());
                }
            }
        }
    }
}
