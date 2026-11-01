package vn.edu.hcmut.co3103.identity.security;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityAuditTest {
    private final Logger logger = (Logger) LoggerFactory.getLogger(SecurityAudit.class);
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

    @BeforeEach void capture() { appender.start(); logger.addAppender(appender); }
    @AfterEach void cleanup() {
        logger.detachAppender(appender);
        RequestContextHolder.resetRequestAttributes();
        TransactionSynchronizationManager.clear();
    }

    @Test
    void writesStructuredBoundedContextWithoutReadingCredentialsOrAllowingForgedLines() {
        var request = new MockHttpServletRequest();
        request.setRemoteAddr("192.0.2.20");
        request.addHeader("User-Agent", "audit-client\r\nforged-event" + "x".repeat(300));
        request.addHeader("X-Forwarded-For", "untrusted-peer");
        request.addHeader("Authorization", "Bearer private-access-token");
        request.setQueryString("token=private-reset-token");
        request.setContent("{\"password\":\"private-password\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        SecurityAudit.failure("login_failed", "attempt@example.com", "lms-client", "bad_credentials");
        assertThat(appender.list).singleElement().satisfies(event -> {
            assertThat(event.getLevel()).isEqualTo(Level.WARN);
            assertThat(event.getThrowableProxy()).isNull();
            String text = event.getFormattedMessage();
            assertThat(text).doesNotContain("\r", "\n", "private-access-token", "private-reset-token",
                    "private-password", "untrusted-peer");
            var json = JsonMapper.builder().build().readTree(text);
            assertThat(json.get("event").asText()).isEqualTo("login_failed");
            assertThat(json.get("identifier").asText()).isEqualTo("attempt@example.com");
            assertThat(json.get("client_id").asText()).isEqualTo("lms-client");
            assertThat(json.get("ip").asText()).isEqualTo("192.0.2.20");
            assertThat(json.get("user_agent").asText()).hasSize(256);
        });
    }

    @Test
    void successIsEmittedAtInfoOnlyAfterCommitAndRetainsRequestContext() {
        var request = new MockHttpServletRequest();
        request.addHeader("User-Agent", "before-commit-agent");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);
        SecurityAudit.success("password_reset_succeeded", "user-id", "central-identity");
        assertThat(appender.list).isEmpty();
        RequestContextHolder.resetRequestAttributes();
        TransactionSynchronizationManager.getSynchronizations().forEach(TransactionSynchronization::afterCommit);
        assertThat(appender.list).singleElement().satisfies(event -> {
            assertThat(event.getLevel()).isEqualTo(Level.INFO);
            assertThat(event.getFormattedMessage()).contains("password_reset_succeeded", "before-commit-agent");
        });
    }

    @Test
    void rolledBackOperationsDoNotEmitSuccess() {
        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);
        SecurityAudit.success("login_succeeded", "user-id", "central-identity");
        SecurityAudit.failureAfterCommit("account_lockout", "user-id", "central-identity", "failed_attempts_limit");
        TransactionSynchronizationManager.getSynchronizations().forEach(sync ->
                sync.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK));
        assertThat(appender.list).isEmpty();
    }
}
