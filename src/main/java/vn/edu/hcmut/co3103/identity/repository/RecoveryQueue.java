package vn.edu.hcmut.co3103.identity.repository;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import vn.edu.hcmut.co3103.identity.exception.RecoveryUnavailableException;
import vn.edu.hcmut.co3103.identity.exception.InvalidEmailException;
import vn.edu.hcmut.co3103.identity.service.RecoveryTokens;
import vn.edu.hcmut.co3103.identity.validation.Utf8ByteLengthValidator;
import java.net.InetAddress;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;

/** PostgreSQL is the bounded queue and shared admission authority across application instances. */
@Repository
public class RecoveryQueue {
    public record Job(UUID id, String email, InetAddress clientIp, UUID lease, int attempts, String tokenHash) {}

    private final JdbcTemplate jdbc;
    private final int perIp;
    private final int perEmail;
    private final int global;
    private final int capacity;

    public RecoveryQueue(JdbcTemplate jdbc,
            @Value("${app.recovery.per-ip-per-minute:20}") int perIp,
            @Value("${app.recovery.per-email-per-minute:10}") int perEmail,
            @Value("${app.recovery.global-per-minute:200}") int global,
            @Value("${app.recovery.capacity:1000}") int capacity) {
        if (perIp < 1 || perEmail < 1 || global < 1 || capacity < 1)
            throw new IllegalArgumentException("Recovery admission limits must be positive");
        this.jdbc = jdbc;
        this.perIp = perIp;
        this.perEmail = perEmail;
        this.global = global;
        this.capacity = capacity;
    }

    @Transactional
    public void admit(String email, InetAddress ip) {
        if (!Utf8ByteLengthValidator.isValid(email, Integer.MAX_VALUE)) {
            throw new InvalidEmailException();
        }
        // Serialize only short admission transactions; SMTP and issuance never acquire this lock.
        jdbc.execute("SET LOCAL lock_timeout = '1s'");
        jdbc.execute("SELECT pg_advisory_xact_lock(310301)");
        String emailHash = RecoveryTokens.hash(email);
        jdbc.update("DELETE FROM recovery_admissions WHERE accepted_at <= CURRENT_TIMESTAMP - INTERVAL '1 minute'");
        long[] counts = jdbc.queryForObject("""
                SELECT count(*), count(*) FILTER (WHERE client_ip = CAST(? AS inet)),
                       count(*) FILTER (WHERE email_hash = ?)
                FROM recovery_admissions
                """, (row, index) -> new long[]{row.getLong(1), row.getLong(2), row.getLong(3)},
                ip.getHostAddress(), emailHash);
        if (counts[0] >= global || counts[1] >= perIp || counts[2] >= perEmail)
            throw new RecoveryUnavailableException(true);
        if (jdbc.queryForObject("SELECT count(*) FROM recovery_jobs", Long.class) >= capacity)
            throw new RecoveryUnavailableException(false);
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO recovery_admissions(request_id, email_hash, client_ip) VALUES (?, ?, CAST(? AS inet))",
                id, emailHash, ip.getHostAddress());
        jdbc.update("INSERT INTO recovery_jobs(request_id, email, client_ip) VALUES (?, ?, CAST(? AS inet))",
                id, email, ip.getHostAddress());
    }

    @Transactional
    public Job claim(boolean delivery) {
        UUID lease = UUID.randomUUID();
        // A lease recovers work after process failure. SKIP LOCKED allows independent workers/instances.
        var jobs = jdbc.query("""
                WITH candidate AS (
                    SELECT request_id FROM recovery_jobs
                    WHERE state = ? AND available_at <= CURRENT_TIMESTAMP
                      AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
                    ORDER BY available_at, created_at LIMIT 1 FOR UPDATE SKIP LOCKED
                )
                UPDATE recovery_jobs j SET lease_id = ?, attempts = attempts + 1,
                    available_at = CURRENT_TIMESTAMP + INTERVAL '60 seconds'
                FROM candidate c WHERE j.request_id = c.request_id
                RETURNING j.*, (SELECT token_hash FROM password_resets r WHERE r.reset_id = j.reset_id) AS token_hash
                """, (row, index) -> new Job(row.getObject("request_id", UUID.class), row.getString("email"),
                InetAddress.ofLiteral(row.getString("client_ip")), lease, row.getInt("attempts"), row.getString("token_hash")),
                delivery ? "DELIVERY" : "REQUESTED", lease);
        return jobs.isEmpty() ? null : jobs.getFirst();
    }

    public boolean lockRequest(Job job) {
        return !jdbc.queryForList("""
                SELECT request_id FROM recovery_jobs WHERE request_id = ? AND lease_id = ?
                AND state = 'REQUESTED' FOR UPDATE
                """, UUID.class, job.id(), job.lease()).isEmpty();
    }

    public void ready(Job job, UUID resetId, Instant expiresAt) {
        jdbc.update("""
                UPDATE recovery_jobs SET state = 'DELIVERY', reset_id = ?, expires_at = ?,
                    available_at = CURRENT_TIMESTAMP, lease_id = NULL, attempts = 0
                WHERE request_id = ? AND lease_id = ?
                """, resetId, Timestamp.from(expiresAt), job.id(), job.lease());
    }

    public void complete(Job job) {
        jdbc.update("DELETE FROM recovery_jobs WHERE request_id = ? AND lease_id = ?", job.id(), job.lease());
    }

    public void retry(Job job) {
        int delaySeconds = Math.min(60, 1 << Math.min(job.attempts(), 6));
        jdbc.update("""
                UPDATE recovery_jobs SET available_at = CURRENT_TIMESTAMP + (? * INTERVAL '1 second')
                WHERE request_id = ? AND lease_id = ?
                """, delaySeconds, job.id(), job.lease());
    }

    public int discardExpiredDeliveries() {
        return jdbc.update("""
                DELETE FROM recovery_jobs WHERE state = 'DELIVERY' AND expires_at <= CURRENT_TIMESTAMP
                """);
    }
}
