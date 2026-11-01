package vn.edu.hcmut.co3103.identity.security;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import tools.jackson.databind.json.JsonMapper;

import java.util.Map;

/** An allowlist of audit fields. Never pass requests, exceptions, credentials, or tokens. */
public final class SecurityAudit {
    private static final Logger LOG = LoggerFactory.getLogger(SecurityAudit.class);
    private static final JsonMapper JSON = JsonMapper.builder().build();

    private SecurityAudit() {}

    public static void success(String event, String identifier, String clientId) {
        String message = message(event, identifier, clientId, "success", currentRequest());
        afterCommit(() -> LOG.info("{}", message));
    }

    public static void failureAfterCommit(String event, String identifier, String clientId, String reason) {
        String message = message(event, identifier, clientId, reason, currentRequest());
        afterCommit(() -> LOG.warn("{}", message));
    }

    private static void afterCommit(Runnable log) {
        if (TransactionSynchronizationManager.isActualTransactionActive()
                && TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override public void afterCommit() { log.run(); }
            });
        } else {
            log.run();
        }
    }

    public static void failure(String event, String identifier, String clientId, String reason) {
        failure(event, identifier, clientId, reason, currentRequest());
    }

    public static void failure(String event, String identifier, String clientId, String reason,
                               HttpServletRequest request) {
        LOG.warn("{}", message(event, identifier, clientId, reason, request));
    }

    private static HttpServletRequest currentRequest() {
        return RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes
                ? attributes.getRequest() : null;
    }

    private static String message(String event, String identifier, String clientId, String reason,
                                  HttpServletRequest request) {
        // JSON escaping prevents forged lines; bounds prevent untrusted metadata flooding the logs.
        // Use the socket peer, never blindly trust X-Forwarded-For.
        return JSON.writeValueAsString(Map.of("event", event, "identifier", bounded(identifier),
                "client_id", bounded(clientId), "reason", reason,
                "ip", bounded(request == null ? null : request.getRemoteAddr()),
                "user_agent", bounded(request == null ? null : request.getHeader("User-Agent"))));
    }

    private static String bounded(String value) {
        return value == null ? "" : value.substring(0, Math.min(value.length(), 256));
    }
}
