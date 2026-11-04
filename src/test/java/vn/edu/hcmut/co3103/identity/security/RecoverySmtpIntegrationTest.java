package vn.edu.hcmut.co3103.identity.security;

import com.zaxxer.hikari.HikariDataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.ObjectMapper;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.repository.*;
import vn.edu.hcmut.co3103.identity.support.SlowSmtpServer;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.ArrayList;
import java.util.UUID;
import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.profiles.active=smtp-test", "app.recovery.worker-enabled=true",
        "spring.datasource.hikari.maximum-pool-size=2", "spring.datasource.hikari.minimum-idle=2",
        "spring.mail.host=127.0.0.1", "spring.mail.properties.mail.smtp.auth=false",
        "spring.mail.properties.mail.smtp.localhost=loopback.test",
        "spring.mail.properties.mail.smtp.starttls.enable=false", "spring.mail.properties.mail.smtp.starttls.required=false"
})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class RecoverySmtpIntegrationTest {
    static final SlowSmtpServer smtp;
    static {
        try { smtp = new SlowSmtpServer(); }
        catch (Exception e) { throw new ExceptionInInitializerError(e); }
    }
    @DynamicPropertySource
    static void smtpPort(DynamicPropertyRegistry registry) { registry.add("spring.mail.port", smtp::port); }
    @AfterAll static void closeSmtp() throws Exception { smtp.close(); }
    @Value("${local.server.port}") int port;
    @Autowired UserRepository users;
    @Autowired PasswordResetRepository resets;
    @Autowired JdbcTemplate jdbc;
    @Autowired HikariDataSource dataSource;
    @Autowired JavaMailSender sender;
    @Autowired ObjectMapper mapper;

    @Test
    void slowSmtpAndUnknownEmailFloodCannotSilentlyLoseAcceptedRecovery() throws Exception {
        assertThat(sender).isExactlyInstanceOf(JavaMailSenderImpl.class);
        assertThat(((JavaMailSenderImpl) sender).getJavaMailProperties()).containsEntry("mail.smtp.timeout", "5000");
        var recipients = new ArrayList<User>();
        try (var client = HttpClient.newHttpClient()) {
            try {
                for (int i = 0; i < 5; i++) recipients.add(users.saveAndFlush(User.builder()
                        .email("smtp-" + UUID.randomUUID() + "@example.com").passwordHash("unused").fullName("SMTP test").build()));
                for (int i = 0; i < 4; i++) assertThat(post(client, recipients.get(i).getEmail()).statusCode()).isEqualTo(200);
                await().atMost(Duration.ofSeconds(10)).untilAsserted(() ->
                        assertThat(smtp.blocked.get()).as("SMTP commands: %s", smtp.commands).isGreaterThanOrEqualTo(4));
                // All SMTP workers are occupied. A fifth account must still receive a committed token.
                assertThat(post(client, recipients.get(4).getEmail()).statusCode()).isEqualTo(200);
                await().atMost(Duration.ofSeconds(3)).untilAsserted(() ->
                        assertThat(resets.findByUserIdOrderByCreatedAtDesc(recipients.get(4).getUserId())).hasSize(1));
                for (int i = 0; i < 15; i++) assertThat(post(client, "unknown-" + i + "@example.com").statusCode()).isEqualTo(200);
                var unknown = post(client, "unknown-over-budget@example.com");
                var known = post(client, recipients.get(4).getEmail());
                assertThat(unknown.statusCode()).isEqualTo(429);
                assertThat(known.statusCode()).isEqualTo(unknown.statusCode());
                assertThat(known.headers().firstValue("Retry-After")).contains("60");
                assertThat(mapper.readTree(known.body()).get("message")).isEqualTo(mapper.readTree(unknown.body()).get("message"));
                assertThat(mapper.readTree(known.body()).get("code")).isEqualTo(mapper.readTree(unknown.body()).get("code"));
                await().atMost(Duration.ofSeconds(2)).untilAsserted(() ->
                        assertThat(dataSource.getHikariPoolMXBean().getActiveConnections()).isZero());
                // Both DB connections remain available while the SMTP DATA commands are stalled.
                try (var first = dataSource.getConnection(); var second = dataSource.getConnection()) {
                    assertThat(first.isValid(1)).isTrue();
                    assertThat(second.isValid(1)).isTrue();
                }
            } finally {
                smtp.release.countDown();
            }
            await().atMost(Duration.ofSeconds(15)).untilAsserted(() -> {
                assertThat(jdbc.queryForObject("SELECT count(*) FROM recovery_jobs", Integer.class)).isZero();
                for (var user : recipients) {
                    assertThat(resets.findByUserIdOrderByCreatedAtDesc(user.getUserId())).hasSize(1);
                    assertThat(smtp.messages).anySatisfy(message -> assertThat(message).contains("To: " + user.getEmail()));
                }
            });
        } finally {
            jdbc.update("DELETE FROM recovery_jobs");
            jdbc.update("DELETE FROM recovery_admissions");
            for (var user : recipients) { resets.deleteByUserId(user.getUserId()); users.deleteById(user.getUserId()); }
        }
    }

    private HttpResponse<String> post(HttpClient client, String email) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/api/v1/auth/forgot-password"))
                .timeout(Duration.ofSeconds(10)).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"email\":\"" + email + "\"}")).build(), HttpResponse.BodyHandlers.ofString());
    }
}
