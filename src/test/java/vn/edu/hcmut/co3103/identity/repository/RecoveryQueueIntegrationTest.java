package vn.edu.hcmut.co3103.identity.repository;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.exception.InvalidEmailException;
import vn.edu.hcmut.co3103.identity.exception.RecoveryUnavailableException;
import vn.edu.hcmut.co3103.identity.service.*;
import vn.edu.hcmut.co3103.identity.support.InMemoryMailSender;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.UUID;
import java.util.concurrent.*;
import static org.assertj.core.api.Assertions.*;

@SpringBootTest
class RecoveryQueueIntegrationTest {
    @Autowired JdbcTemplate jdbc;
    @Autowired RecoveryQueue queue;
    @Autowired PlatformTransactionManager transactions;
    @Autowired PasswordResetService service;
    @Autowired PasswordResetNotificationService notifications;
    @Autowired RecoveryTokens tokens;
    @Autowired UserRepository users;
    @Autowired PasswordResetRepository resets;
    @Autowired InMemoryMailSender mailbox;
    private User user;

    @AfterEach
    void cleanup() {
        jdbc.update("DELETE FROM recovery_jobs");
        jdbc.update("DELETE FROM recovery_admissions");
        if (user != null) { resets.deleteByUserId(user.getUserId()); users.deleteById(user.getUserId()); }
        mailbox.clear();
    }

    @ParameterizedTest
    @MethodSource("vn.edu.hcmut.co3103.identity.support.UnicodeInputs#malformedEmails")
    void malformedEmailCannotConsumeAdmissionBudgetOrCreateWork(String email) {
        var ip = InetAddress.ofLiteral("192.0.2.1");
        var connection = org.mockito.Mockito.mock(JdbcTemplate.class);
        var directQueue = new RecoveryQueue(connection, 20, 10, 200, 1000);
        assertThatExceptionOfType(InvalidEmailException.class).isThrownBy(() -> directQueue.admit(email, ip));
        org.mockito.Mockito.verifyNoInteractions(connection);

        var before = jdbc.queryForList("SELECT * FROM recovery_admissions");
        assertThatExceptionOfType(InvalidEmailException.class).isThrownBy(() -> queue.admit(email, ip));
        assertThatExceptionOfType(InvalidEmailException.class).isThrownBy(() -> service.forgotPassword(
                new vn.edu.hcmut.co3103.identity.dto.auth.request.ForgotPasswordRequest(email), ip));
        assertThat(jdbc.queryForList("SELECT * FROM recovery_admissions")).isEqualTo(before);
        assertThat(jobCount()).isZero();
        assertThat(mailbox.getMessages()).isEmpty();
    }

    @ParameterizedTest
    @MethodSource("vn.edu.hcmut.co3103.identity.support.UnicodeInputs#validEmails")
    @org.junit.jupiter.params.provider.ValueSource(strings = {"member\ud83d\ude00@example.com"})
    void wellFormedEmailKeepsItsIdentityAndAdmissionHash(String email) {
        queue.admit(email, InetAddress.ofLiteral("192.0.2.1"));
        assertThat(jdbc.queryForObject("SELECT email FROM recovery_jobs", String.class)).isEqualTo(email);
        assertThat(jdbc.queryForObject("SELECT email_hash FROM recovery_admissions", String.class))
                .isEqualTo(RecoveryTokens.hash(email));
    }

    @Test
    void unknownFloodIsLimitedPerIpWithoutConsumingAnotherSourcesBudget() {
        var limiter = new RecoveryQueue(jdbc, 2, 10, 10, 10);
        admit(limiter, "missing-1@example.com", "192.0.2.1");
        admit(limiter, "missing-2@example.com", "192.0.2.1");
        for (String email : new String[]{"missing-3@example.com", "known@example.com"}) {
            assertThatThrownBy(() -> admit(limiter, email, "192.0.2.1"))
                    .isInstanceOf(RecoveryUnavailableException.class)
                    .satisfies(e -> assertThat(((RecoveryUnavailableException) e).isRateLimited()).isTrue());
        }
        admit(limiter, "known@example.com", "192.0.2.2");
        assertThat(jobCount()).isEqualTo(3);
    }

    @Test
    void perAccountLimitAppliesToUnknownAddressesAcrossDifferentIpsAndInstances() {
        var first = new RecoveryQueue(jdbc, 10, 2, 10, 10);
        var second = new RecoveryQueue(jdbc, 10, 2, 10, 10);
        admit(first, "missing@example.com", "192.0.2.1");
        admit(second, "missing@example.com", "192.0.2.2");
        assertThatThrownBy(() -> admit(second, "missing@example.com", "192.0.2.3"))
                .isInstanceOf(RecoveryUnavailableException.class);
        assertThat(jobCount()).isEqualTo(2);
    }

    @Test
    void globalBudgetIsAtomicAcrossConcurrentAdmissions() throws Exception {
        var limiter = new RecoveryQueue(jdbc, 20, 20, 3, 20);
        var start = new CountDownLatch(1);
        try (var workers = Executors.newFixedThreadPool(8)) {
            var calls = new ArrayList<Future<Boolean>>();
            for (int i = 0; i < 8; i++) {
                final int n = i;
                calls.add(workers.submit(() -> {
                    start.await();
                    try { admit(limiter, "missing-" + n + "@example.com", "192.0.2." + (n + 1)); return true; }
                    catch (RecoveryUnavailableException e) { assertThat(e.isRateLimited()).isTrue(); return false; }
                }));
            }
            start.countDown();
            int accepted = 0;
            for (var call : calls) if (call.get(10, TimeUnit.SECONDS)) accepted++;
            assertThat(accepted).isEqualTo(3);
        }
        assertThat(jobCount()).isEqualTo(3);
    }

    @Test
    void capacityRejectsUniformlyWithoutAcknowledgingOrPersistingWork() {
        var limiter = new RecoveryQueue(jdbc, 20, 20, 20, 1);
        admit(limiter, "missing@example.com", "192.0.2.1");
        assertThatThrownBy(() -> admit(limiter, "other@example.com", "192.0.2.2"))
                .isInstanceOf(RecoveryUnavailableException.class)
                .satisfies(e -> assertThat(((RecoveryUnavailableException) e).isRateLimited()).isFalse());
        assertThat(jobCount()).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM recovery_admissions", Integer.class)).isEqualTo(1);
    }

    @Test
    void admissionBudgetExpiresAndItsStateStaysBounded() {
        var limiter = new RecoveryQueue(jdbc, 1, 1, 1, 10);
        admit(limiter, "missing@example.com", "192.0.2.1");
        jdbc.update("UPDATE recovery_admissions SET accepted_at = CURRENT_TIMESTAMP - INTERVAL '61 seconds'");
        admit(limiter, "missing@example.com", "192.0.2.1");
        assertThat(jobCount()).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM recovery_admissions", Integer.class)).isEqualTo(1);
    }

    @Test
    void expiredLeaseResumesCommittedDeliveryWithSameTokenAfterWorkerRestart() {
        user = users.saveAndFlush(User.builder().email("durable-" + UUID.randomUUID() + "@example.com")
                .passwordHash("unused").fullName("Queue test").build());
        queue.admit(user.getEmail(), InetAddress.ofLiteral("192.0.2.9"));
        var issuance = queue.claim(false);
        service.issuePasswordReset(issuance);
        var abandoned = queue.claim(true);
        assertThat(queue.claim(true)).isNull();
        String originalHash = resets.findByUserIdOrderByCreatedAtDesc(user.getUserId()).getFirst().getTokenHash();
        assertThat(originalHash).isEqualTo(RecoveryTokens.hash(tokens.token(abandoned.id())));
        assertThat(jdbc.queryForObject("SELECT row_to_json(j)::text FROM recovery_jobs j", String.class))
                .doesNotContain(tokens.token(abandoned.id()));
        jdbc.update("UPDATE recovery_jobs SET available_at = CURRENT_TIMESTAMP - INTERVAL '1 second'");
        // A fresh worker has no in-memory task/token state.
        var restarted = new RecoveryWorker(queue, service, notifications, tokens, Runnable::run, Runnable::run);
        restarted.poll();
        assertThat(jobCount()).isZero();
        assertThat(mailbox.getMessages()).singleElement().satisfies(message ->
                assertThat(message.getText()).contains(tokens.token(abandoned.id())));
        assertThat(resets.findByUserIdOrderByCreatedAtDesc(user.getUserId())).hasSize(1);
    }

    @Test
    void rejectedExecutorsLeaveDurableWorkUnclaimed() {
        queue.admit("missing@example.com", InetAddress.ofLiteral("192.0.2.9"));
        Executor rejecting = task -> { throw new RejectedExecutionException("full"); };
        new RecoveryWorker(queue, service, notifications, tokens, rejecting, rejecting).poll();
        assertThat(jobCount()).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT attempts FROM recovery_jobs", Integer.class)).isZero();
        new RecoveryWorker(queue, service, notifications, tokens, Runnable::run, Runnable::run).poll();
        assertThat(jobCount()).isZero();
    }

    @Test
    void staleWorkerCannotRemoveOrPostponeReclaimedJob() {
        queue.admit("missing@example.com", InetAddress.ofLiteral("192.0.2.9"));
        var old = queue.claim(false);
        jdbc.update("UPDATE recovery_jobs SET available_at = CURRENT_TIMESTAMP - INTERVAL '1 second'");
        var fresh = queue.claim(false);
        assertThat(fresh.lease()).isNotEqualTo(old.lease());
        queue.complete(old);
        queue.retry(old);
        assertThat(jobCount()).isEqualTo(1);
        service.issuePasswordReset(old);
        assertThat(jobCount()).isEqualTo(1);
        service.issuePasswordReset(fresh);
        assertThat(jobCount()).isZero();
    }

    @Test
    void transientFailuresBeyondThreeAttemptsRetainSameLinkUntilSuccess() {
        prepareDelivery();
        var sender = org.mockito.Mockito.mock(org.springframework.mail.javamail.JavaMailSender.class);
        org.mockito.Mockito.doThrow(new org.springframework.mail.MailSendException("transient transport failure"))
                .when(sender).send(org.mockito.ArgumentMatchers.any(org.springframework.mail.SimpleMailMessage.class));
        var worker = new RecoveryWorker(queue, service,
                new PasswordResetNotificationService(sender, "identity@example.com", "https://example.com/reset"),
                tokens, Runnable::run, Runnable::run);
        for (int attempt = 1; attempt <= 4; attempt++) {
            worker.poll();
            assertThat(jobCount()).isEqualTo(1);
            assertThat(jdbc.queryForObject("SELECT attempts FROM recovery_jobs", Integer.class)).isEqualTo(attempt);
            assertThat(jdbc.queryForObject("SELECT available_at > CURRENT_TIMESTAMP FROM recovery_jobs", Boolean.class)).isTrue();
            jdbc.update("UPDATE recovery_jobs SET available_at = CURRENT_TIMESTAMP");
        }
        org.mockito.Mockito.doNothing().when(sender).send(org.mockito.ArgumentMatchers.any(org.springframework.mail.SimpleMailMessage.class));
        worker.poll();
        assertThat(jobCount()).isZero();
        var captured = org.mockito.ArgumentCaptor.forClass(org.springframework.mail.SimpleMailMessage.class);
        org.mockito.Mockito.verify(sender, org.mockito.Mockito.times(5)).send(captured.capture());
        assertThat(captured.getAllValues()).extracting(org.springframework.mail.SimpleMailMessage::getText)
                .containsOnly(captured.getValue().getText());
        assertThat(resets.findByUserIdOrderByCreatedAtDesc(user.getUserId())).hasSize(1);
    }

    @Test
    void mismatchedKeyRetainsWorkWithoutSendingInvalidLinkAndExpiryFreesCapacity() {
        prepareDelivery();
        var wrongKey = new RecoveryTokens("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        var worker = new RecoveryWorker(queue, service, notifications, wrongKey, Runnable::run, Runnable::run);
        worker.poll();
        assertThat(jobCount()).isEqualTo(1);
        assertThat(mailbox.getMessages()).isEmpty();
        jdbc.update("UPDATE recovery_jobs SET expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second'");
        assertThat(queue.discardExpiredDeliveries()).isEqualTo(1);
        assertThat(jobCount()).isZero();
    }

    private void prepareDelivery() {
        user = users.saveAndFlush(User.builder().email("retry-" + UUID.randomUUID() + "@example.com")
                .passwordHash("unused").fullName("Retry test").build());
        queue.admit(user.getEmail(), InetAddress.ofLiteral("192.0.2.9"));
        service.issuePasswordReset(queue.claim(false));
    }

    private int jobCount() { return jdbc.queryForObject("SELECT count(*) FROM recovery_jobs", Integer.class); }
    private void admit(RecoveryQueue limiter, String email, String ip) {
        new TransactionTemplate(transactions).executeWithoutResult(tx -> limiter.admit(email, InetAddress.ofLiteral(ip)));
    }
}
