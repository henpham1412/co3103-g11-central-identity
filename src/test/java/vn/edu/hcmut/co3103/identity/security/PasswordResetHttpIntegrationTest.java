package vn.edu.hcmut.co3103.identity.security;

import com.zaxxer.hikari.HikariDataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import tools.jackson.databind.ObjectMapper;
import vn.edu.hcmut.co3103.identity.entity.PasswordReset;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.entity.UserStatus;
import vn.edu.hcmut.co3103.identity.service.PasswordResetNotificationService;
import vn.edu.hcmut.co3103.identity.support.InMemoryMailSender;
import vn.edu.hcmut.co3103.identity.support.UnicodeInputs;
import vn.edu.hcmut.co3103.identity.repository.PasswordResetRepository;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;

import static vn.edu.hcmut.co3103.identity.support.ErrorResponseAssertions.assertErrorEnvelope;
import static vn.edu.hcmut.co3103.identity.support.ErrorResponseAssertions.validationMessage;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Real HTTP and PostgreSQL transactions, including asynchronous issuance and single-use races. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "app.reset-password.base-url=https://frontend.example/reset-password",
                "app.recovery.worker-enabled=true",
                "spring.datasource.hikari.maximum-pool-size=2",
                "spring.datasource.hikari.minimum-idle=2",
                "spring.datasource.hikari.connection-timeout=1000"
        })
@ExtendWith(OutputCaptureExtension.class)
@org.springframework.test.annotation.DirtiesContext(classMode = org.springframework.test.annotation.DirtiesContext.ClassMode.AFTER_CLASS)
class PasswordResetHttpIntegrationTest {
    private static final String OLD_PASSWORD = "OriginalPassword123!";
    private static final String NEW_PASSWORD = "NewPassword456!";
    private static final String FORGOT_MESSAGE =
            "If the email is eligible for recovery, password reset instructions have been sent.";
    @Value("${local.server.port}") private int port;
    @MockitoSpyBean private UserRepository users;
    @MockitoSpyBean private PasswordResetRepository resets;
    @MockitoSpyBean private PasswordResetNotificationService notifications;
    @MockitoSpyBean private InMemoryMailSender mailbox;
    @Autowired private PasswordEncoder encoder;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private HikariDataSource dataSource;
    @Autowired private ObjectMapper mapper;
    @Autowired @Qualifier("recoveryIssuanceExecutor") private ThreadPoolTaskExecutor executor;
    @Autowired @Qualifier("recoveryDeliveryExecutor") private ThreadPoolTaskExecutor deliveryExecutor;
    @MockitoSpyBean private vn.edu.hcmut.co3103.identity.repository.RecoveryQueue queue;

    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private final List<UUID> userIds = new ArrayList<>();

    @AfterEach
    void cleanUp() {
        awaitIdle();
        mailbox.clear();
        jdbc.update("DELETE FROM recovery_admissions");
        for (UUID id : userIds) {
            resets.deleteByUserId(id);
            users.deleteById(id);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"/auth", "/api/v1/auth"})
    void recoveryChangesLoginPasswordAndRejectsReplay(String prefix, CapturedOutput output) throws Exception {
        User user = createUser(UserStatus.ACTIVE);
        var acknowledgement = post(prefix + "/forgot-password", "{\"email\":\"" + user.getEmail() + "\"}");
        assertThat(acknowledgement.statusCode()).isEqualTo(200);
        String link = deliveredLink(user);
        assertThat(link).startsWith("https://frontend.example/reset-password?token=");
        String token = URI.create(link).getRawQuery().substring("token=".length());
        assertThat(token).matches("[A-Za-z0-9_-]{43}");
        PasswordReset reset = resets.findByTokenHash(hash(token)).orElseThrow();
        assertThat(reset.isUsed()).isFalse();
        assertThat(reset.getUsedAt()).isNull();
        assertThat(reset.getExpiresAt()).isAfter(Instant.now()).isBefore(Instant.now().plusSeconds(901));
        assertThat(reset.getTokenHash()).isNotEqualTo(token);
        Instant before = Instant.now();

        var response = post(prefix + "/reset-password", resetBody(token, NEW_PASSWORD));
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        assertThat(mapper.readTree(response.body()).size()).isEqualTo(1);
        assertThat(mapper.readTree(response.body()).get("message").asText()).isEqualTo(
                "Password has been reset successfully. Please log in with your new password.");
        User persisted = users.findById(user.getUserId()).orElseThrow();
        assertThat(encoder.matches(NEW_PASSWORD, persisted.getPasswordHash())).isTrue();
        assertThat(encoder.matches(OLD_PASSWORD, persisted.getPasswordHash())).isFalse();
        PasswordReset consumed = resets.findById(reset.getResetId()).orElseThrow();
        assertThat(consumed.isUsed()).isTrue();
        assertThat(consumed.getUsedAt()).isBetween(before, Instant.now());
        assertInvalid(post(prefix + "/reset-password", resetBody(token, "AnotherPassword789!")));
        assertThat(users.findById(user.getUserId()).orElseThrow().getPasswordHash()).isEqualTo(persisted.getPasswordHash());
        assertThat(post(prefix + "/login", loginBody(user, OLD_PASSWORD)).statusCode()).isEqualTo(401);
        assertThat(post(prefix + "/login", loginBody(user, NEW_PASSWORD)).statusCode()).isEqualTo(200);
        assertThat(output.getAll()).doesNotContain(token, link, OLD_PASSWORD, NEW_PASSWORD);
    }

    @ParameterizedTest
    @EnumSource(UserStatus.class)
    void existingAndUnknownEmailsHaveIdenticalResponses(UserStatus status) throws Exception {
        User user = createUser(status);
        var known = post("/auth/forgot-password", "{\"email\":\"" + user.getEmail() + "\"}");
        String unknownEmail = "unknown-" + UUID.randomUUID() + "@example.com";
        var unknown = post("/auth/forgot-password", "{\"email\":\"" + unknownEmail + "\"}");
        assertThat(known.statusCode()).isEqualTo(200);
        assertThat(unknown.statusCode()).isEqualTo(200);
        assertThat(known.body()).isEqualTo(unknown.body());
        verify(users, timeout(10000)).findByEmailForUpdate(unknownEmail);
        verify(users, timeout(10000)).findByEmailForUpdate(user.getEmail());
        awaitIdle();
        var issued = resets.findByUserIdOrderByCreatedAtDesc(user.getUserId());
        assertThat(issued).hasSize(status == UserStatus.ACTIVE ? 1 : 0);
        assertThat(mailbox.getMessages()).hasSize(status == UserStatus.ACTIVE ? 1 : 0);
        assertThat(mailbox.getMessages()).allSatisfy(message -> assertThat(message.getTo()).containsExactly(user.getEmail()));
        if (status != UserStatus.ACTIVE) verifyNoInteractions(notifications);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/auth", "/api/v1/auth"})
    void cooldownSuppressesNormalizedDuplicatesAndAllowsRecoveryAfterExpiry(String prefix) throws Exception {
        User user = createUser(UserStatus.ACTIVE);
        String token = requestToken(prefix, user);
        // Consuming the token must not allow another email within the cooldown.
        assertThat(post(prefix + "/reset-password", resetBody(token, NEW_PASSWORD)).statusCode()).isEqualTo(200);
        String body = "{\"email\":\"  " + user.getEmail().toUpperCase(java.util.Locale.ROOT) + "  \"}";
        var duplicate = post(prefix + "/forgot-password", body);
        var unknown = post(prefix + "/forgot-password", "{\"email\":\"unknown@example.com\"}");
        assertThat(duplicate.statusCode()).isEqualTo(200);
        assertThat(duplicate.body()).isEqualTo(unknown.body());
        awaitIdle();
        assertThat(resets.findByUserIdOrderByCreatedAtDesc(user.getUserId())).hasSize(1);
        assertThat(mailbox.getMessages()).hasSize(1);

        jdbc.update("UPDATE password_resets SET created_at = CURRENT_TIMESTAMP - INTERVAL '61 seconds' WHERE user_id = ?",
                user.getUserId());
        assertThat(post(prefix + "/forgot-password", body).body()).isEqualTo(duplicate.body());
        awaitIdle();
        assertThat(resets.findByUserIdOrderByCreatedAtDesc(user.getUserId())).hasSize(2)
                .extracting(PasswordReset::getTokenHash).doesNotHaveDuplicates();
        assertThat(mailbox.getMessages()).hasSize(2);
    }

    @Test
    void concurrentRecoveryRequestsIssueOnlyOneTokenAndEmail() throws Exception {
        User user = createUser(UserStatus.ACTIVE);
        var start = new CountDownLatch(1);
        try (var workers = Executors.newFixedThreadPool(6)) {
            var requests = new ArrayList<java.util.concurrent.Future<HttpResponse<String>>>();
            for (int i = 0; i < 6; i++) {
                String path = i % 2 == 0 ? "/auth/forgot-password" : "/api/v1/auth/forgot-password";
                String email = i % 2 == 0 ? user.getEmail() : "  " + user.getEmail().toUpperCase(java.util.Locale.ROOT) + "  ";
                requests.add(workers.submit(() -> {
                    start.await();
                    return post(path, "{\"email\":\"" + email + "\"}");
                }));
            }
            start.countDown();
            for (var request : requests) {
                var response = request.get(15, TimeUnit.SECONDS);
                assertThat(response.statusCode()).isEqualTo(200);
                assertThat(mapper.readTree(response.body()).get("message").asText()).isEqualTo(FORGOT_MESSAGE);
            }
        }
        awaitIdle();
        assertThat(resets.findByUserIdOrderByCreatedAtDesc(user.getUserId())).hasSize(1);
        assertThat(mailbox.getMessages()).hasSize(1);
    }

    @Test
    void saturatedIssuanceExecutorRetainsAcceptedRequestsUntilCapacityReturns() throws Exception {
        User user = createUser(UserStatus.ACTIVE);
        var release = new CountDownLatch(1);
        try {
            saturateExecutor(executor, release);
            for (String email : List.of(user.getEmail(), "unknown@example.com")) {
                var response = post("/auth/forgot-password", "{\"email\":\"" + email + "\"}");
                assertThat(response.statusCode()).isEqualTo(200);
            }
            assertThat(jdbc.queryForObject("SELECT count(*) FROM recovery_jobs", Integer.class)).isEqualTo(2);
            assertThat(resets.findByUserIdOrderByCreatedAtDesc(user.getUserId())).isEmpty();
        } finally {
            release.countDown();
        }
        awaitIdle();
        assertThat(resets.findByUserIdOrderByCreatedAtDesc(user.getUserId())).hasSize(1);
        assertThat(mailbox.getMessages()).hasSize(1);
    }

    @Test
    void saturatedDeliveryExecutorDoesNotBlockIssuanceAndRetainsDeliveryForRetry() throws Exception {
        User user = createUser(UserStatus.ACTIVE);
        var release = new CountDownLatch(1);
        try {
            saturateExecutor(deliveryExecutor, release);
            assertThat(post("/auth/forgot-password", "{\"email\":\"" + user.getEmail() + "\"}").statusCode()).isEqualTo(200);
            await().atMost(Duration.ofSeconds(5)).untilAsserted(() ->
                    assertThat(resets.findByUserIdOrderByCreatedAtDesc(user.getUserId())).hasSize(1));
            assertThat(jdbc.queryForObject("SELECT count(*) FROM recovery_jobs WHERE state = 'DELIVERY'", Integer.class))
                    .isEqualTo(1);
            assertThat(mailbox.getMessages()).isEmpty();
        } finally {
            release.countDown();
        }
        awaitIdle();
        assertThat(mailbox.getMessages()).hasSize(1);
    }

    @Test
    void forgotPasswordPersistsRequestIpAndIgnoresUntrustedForwardingHeaders() throws Exception {
        User user = createUser(UserStatus.ACTIVE);
        var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/api/v1/auth/forgot-password"))
                .header("Content-Type", "application/json").header("X-Forwarded-For", "198.51.100.42")
                .POST(HttpRequest.BodyPublishers.ofString("{\"email\":\"" + user.getEmail() + "\"}")).build();
        assertThat(client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(200);
        awaitIdle();
        var reset = resets.findByUserIdOrderByCreatedAtDesc(user.getUserId()).getFirst();
        assertThat(reset.getIpRequested().getHostAddress()).isEqualTo("127.0.0.1");
        assertThat(client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(200);
        awaitIdle();
        assertThat(resets.findById(reset.getResetId()).orElseThrow().getIpRequested()).isEqualTo(reset.getIpRequested());
        assertThat(resets.findByUserIdOrderByCreatedAtDesc(user.getUserId())).hasSize(1);
    }

    @ParameterizedTest
    @ValueSource(strings = {"expired", "used", "legacyUsed", "missing"})
    void invalidTokensDoNotChangeDatabase(String scenario) throws Exception {
        User user = createUser(UserStatus.ACTIVE);
        String token = requestToken("/auth", user);
        PasswordReset reset = resets.findByTokenHash(hash(token)).orElseThrow();
        if (scenario.equals("expired")) {
            jdbc.update("UPDATE password_resets SET created_at = CURRENT_TIMESTAMP - INTERVAL '2 hours',"
                    + " expires_at = CURRENT_TIMESTAMP - INTERVAL '1 hour' WHERE reset_id = ?", reset.getResetId());
        } else if (scenario.equals("used") || scenario.equals("legacyUsed")) {
            reset.setUsed(true);
            reset.setUsedAt(scenario.equals("used") ? Instant.now() : null);
            resets.saveAndFlush(reset);
        } else {
            token = "unknown-token";
        }
        PasswordReset before = resets.findById(reset.getResetId()).orElseThrow();
        assertInvalid(post("/auth/reset-password", resetBody(token, NEW_PASSWORD)));
        assertThat(users.findById(user.getUserId()).orElseThrow().getPasswordHash()).isEqualTo(user.getPasswordHash());
        PasswordReset after = resets.findById(reset.getResetId()).orElseThrow();
        assertThat(after.isUsed()).isEqualTo(before.isUsed());
        assertThat(after.getUsedAt()).isEqualTo(before.getUsedAt());
    }

    @Test
    void twoConcurrentSubmissionsConsumeTokenExactlyOnce() throws Exception {
        User user = createUser(UserStatus.ACTIVE);
        String token = requestToken("/auth", user);
        var start = new CountDownLatch(1);
        try (var workers = Executors.newFixedThreadPool(2)) {
            var first = workers.submit(() -> { start.await(); return post("/auth/reset-password", resetBody(token, NEW_PASSWORD)); });
            var second = workers.submit(() -> { start.await(); return post("/auth/reset-password", resetBody(token, "OtherPassword789!")); });
            start.countDown();
            var responses = List.of(first.get(20, TimeUnit.SECONDS), second.get(20, TimeUnit.SECONDS));
            assertThat(responses).extracting(HttpResponse::statusCode).containsExactlyInAnyOrder(200, 401);
            assertInvalid(responses.stream().filter(response -> response.statusCode() == 401).findFirst().orElseThrow());
            String winningPassword = responses.getFirst().statusCode() == 200 ? NEW_PASSWORD : "OtherPassword789!";
            assertThat(encoder.matches(winningPassword, users.findById(user.getUserId()).orElseThrow().getPasswordHash())).isTrue();
        }
        assertThat(resets.findByTokenHash(hash(token)).orElseThrow().getUsedAt()).isNotNull();
    }

    @Test
    void failureSavingConsumptionRollsBackPasswordUpdate() throws Exception {
        User user = createUser(UserStatus.ACTIVE);
        String token = requestToken("/auth", user);
        doThrow(new IllegalStateException("simulated persistence failure"))
                .when(resets).save(argThat(reset -> reset != null && reset.isUsed()));
        assertThat(post("/auth/reset-password", resetBody(token, NEW_PASSWORD)).statusCode()).isEqualTo(500);
        assertThat(users.findById(user.getUserId()).orElseThrow().getPasswordHash()).isEqualTo(user.getPasswordHash());
        PasswordReset reset = resets.findByTokenHash(hash(token)).orElseThrow();
        assertThat(reset.isUsed()).isFalse();
        assertThat(reset.getUsedAt()).isNull();
    }

    @Test
    void forgotResponseDoesNotWaitForAccountLookup() throws Exception {
        String email = "blocked-lookup@example.com";
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        doAnswer(invocation -> {
            entered.countDown();
            assertThat(release.await(10, TimeUnit.SECONDS)).isTrue();
            return Optional.empty();
        }).when(users).findByEmailForUpdate(email);
        try {
            var response = client.sendAsync(request("/auth/forgot-password", "{\"email\":\"" + email + "\"}"),
                    HttpResponse.BodyHandlers.ofString());
            assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
            assertThat(response.get(2, TimeUnit.SECONDS).statusCode()).isEqualTo(200);
        } finally {
            release.countDown();
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2, 4})
    void stalledSmtpDeliveryReleasesAllDatabaseConnections(int requestCount) throws Exception {
        var recipients = new ArrayList<User>();
        for (int i = 0; i < requestCount; i++) recipients.add(createUser(UserStatus.ACTIVE));
        var entered = new CountDownLatch(requestCount);
        var release = new CountDownLatch(1);
        doAnswer(invocation -> {
            entered.countDown();
            assertThat(release.await(30, TimeUnit.SECONDS)).as("SMTP was released during cleanup").isTrue();
            return invocation.callRealMethod();
        }).when(mailbox).send(any(SimpleMailMessage.class));

        try {
            for (User user : recipients) {
                assertThat(post("/auth/forgot-password", "{\"email\":\"" + user.getEmail() + "\"}").statusCode())
                        .isEqualTo(200);
            }
            assertThat(entered.await(5, TimeUnit.SECONDS)).as("all SMTP sends started, including requests beyond pool size")
                    .isTrue();
            await().atMost(Duration.ofSeconds(3)).untilAsserted(() -> {
                assertThat(dataSource.getHikariPoolMXBean().getActiveConnections())
                        .as("committed reset transactions release their connections while SMTP is stalled").isZero();
                assertThat(dataSource.getHikariPoolMXBean().getIdleConnections()).isEqualTo(2);
            });
            for (User user : recipients) {
                assertThat(resets.findByUserIdOrderByCreatedAtDesc(user.getUserId())).hasSize(1);
            }
            assertThat(mailbox.getMessages()).isEmpty();

            // Borrow the entire real Hikari pool and execute SQL before allowing SMTP to finish.
            try (var first = dataSource.getConnection(); var second = dataSource.getConnection();
                 var firstStatement = first.createStatement(); var secondStatement = second.createStatement();
                 var firstResult = firstStatement.executeQuery("SELECT 1");
                 var secondResult = secondStatement.executeQuery("SELECT 1")) {
                assertThat(firstResult.next()).isTrue();
                assertThat(firstResult.getInt(1)).isEqualTo(1);
                assertThat(secondResult.next()).isTrue();
                assertThat(secondResult.getInt(1)).isEqualTo(1);
                assertThat(release.getCount()).isEqualTo(1);
            }
        } finally {
            release.countDown();
            awaitIdle();
        }
        assertThat(mailbox.getMessages()).hasSize(requestCount);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/auth", "/api/v1/auth"})
    void deliveryFailureDoesNotRevealAccountExistenceOrLogSecrets(String prefix, CapturedOutput output) throws Exception {
        User user = createUser(UserStatus.ACTIVE);
        var sendEntered = new CountDownLatch(1);
        var failDelivery = new CountDownLatch(1);
        var retryCompleted = new CountDownLatch(1);
        doAnswer(invocation -> {
            SimpleMailMessage message = invocation.getArgument(0);
            sendEntered.countDown();
            assertThat(failDelivery.await(10, TimeUnit.SECONDS)).as("delivery failure was released").isTrue();
            throw new MailSendException("simulated delivery failure containing body: " + message.getText());
        }).when(mailbox).send(any(SimpleMailMessage.class));
        doAnswer(invocation -> {
            Object result = invocation.callRealMethod();
            retryCompleted.countDown();
            return result;
        }).when(queue).retry(any());
        HttpResponse<String> response;
        try {
            response = post(prefix + "/forgot-password", "{\"email\":\"" + user.getEmail() + "\"}");
            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(mapper.readTree(response.body()).get("message").asText()).isEqualTo(FORGOT_MESSAGE);
            assertThat(sendEntered.await(5, TimeUnit.SECONDS)).isTrue();
            UUID jobId = jdbc.queryForObject("SELECT request_id FROM recovery_jobs WHERE email = ?", UUID.class,
                    user.getEmail());
            String warning = "delivery failed; retained for retry (job " + jobId;
            assertThat(resets.findByUserIdOrderByCreatedAtDesc(user.getUserId())).hasSize(1);
            assertThat(mailbox.getMessages()).isEmpty();
            var token = ArgumentCaptor.forClass(String.class);
            verify(notifications, atLeastOnce()).send(eq(user.getEmail()), token.capture());
            // Force the first log check to happen before the send throws; only then release the worker.
            await().atMost(Duration.ofSeconds(5)).conditionEvaluationListener(condition -> failDelivery.countDown())
                    .untilAsserted(() -> {
                        assertThat(output.getAll()).contains(warning)
                                .doesNotContain(token.getValue(), "https://frontend.example/reset-password?token=");
                        assertThat(retryCompleted.getCount()).as("delivery retry state was persisted").isZero();
                    });
        } finally {
            failDelivery.countDown();
            await().atMost(Duration.ofSeconds(5)).until(() -> deliveryExecutor.getActiveCount() == 0);
            doCallRealMethod().when(mailbox).send(any(SimpleMailMessage.class));
            doCallRealMethod().when(queue).retry(any());
            jdbc.update("UPDATE recovery_jobs SET available_at = CURRENT_TIMESTAMP");
            awaitIdle();
        }
        assertThat(mailbox.getMessages()).hasSize(1);
        var unknown = post(prefix + "/forgot-password", "{\"email\":\"unknown@example.com\"}");
        assertThat(unknown.statusCode()).isEqualTo(response.statusCode());
        assertThat(unknown.body()).isEqualTo(response.body());
        verify(users, timeout(10000)).findByEmailForUpdate("unknown@example.com");
    }

    @Test
    void rolledBackIssuanceRetainsRequestAndNeverDeliversUncommittedToken(CapturedOutput output) throws Exception {
        User user = createUser(UserStatus.ACTIVE);
        doThrow(new IllegalStateException("simulated outbox failure")).when(queue).ready(any(), any(), any());
        try {
            assertThat(post("/auth/forgot-password", "{\"email\":\"" + user.getEmail() + "\"}").statusCode()).isEqualTo(200);
            verify(queue, timeout(10000)).ready(any(), any(), any());
            await().atMost(Duration.ofSeconds(5)).until(() -> executor.getActiveCount() == 0);
            assertThat(resets.findByUserIdOrderByCreatedAtDesc(user.getUserId())).isEmpty();
            assertThat(mailbox.getMessages()).isEmpty();
            assertThat(jdbc.queryForObject("SELECT state FROM recovery_jobs WHERE email = ?", String.class, user.getEmail()))
                    .isEqualTo("REQUESTED");
        } finally {
            doCallRealMethod().when(queue).ready(any(), any(), any());
            jdbc.update("UPDATE recovery_jobs SET available_at = CURRENT_TIMESTAMP");
        }
        awaitIdle();
        assertThat(resets.findByUserIdOrderByCreatedAtDesc(user.getUserId())).hasSize(1);
        assertThat(mailbox.getMessages()).hasSize(1);
        assertThat(output.getAll()).doesNotContain("https://frontend.example/reset-password?token=");
    }

    @Test
    void recoveryValidationUsesSpecificCodesWithoutDatabaseChanges() throws Exception {
        User user = createUser(UserStatus.ACTIVE);
        String token = requestToken("/auth", user);
        for (String path : List.of("/auth/forgot-password", "/auth/reset-password")) {
            var malformed = post(path, "{");
            assertThat(malformed.statusCode()).isEqualTo(400);
            var error = mapper.readTree(malformed.body());
            assertErrorEnvelope(error);
            assertThat(error.get("code").asText()).isEqualTo("BAD_REQUEST");
            assertThat(error.get("details").isEmpty()).isTrue();
        }
        assertValidation(post("/auth/forgot-password", "{}"), "BAD_REQUEST", "email");
        assertValidation(post("/auth/reset-password", resetBody(token, "short")),
                "PASSWORD_POLICY_VIOLATION", "new_password");
        assertValidation(post("/auth/reset-password", "{\"new_password\":\"" + NEW_PASSWORD + "\"}"),
                "VALIDATION_ERROR", "token");
        assertThat(users.findById(user.getUserId()).orElseThrow().getPasswordHash()).isEqualTo(user.getPasswordHash());
        var issued = resets.findByUserIdOrderByCreatedAtDesc(user.getUserId());
        assertThat(issued).hasSize(1);
        assertThat(issued.getFirst().isUsed()).isFalse();
        assertThat(issued.getFirst().getUsedAt()).isNull();
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.MethodSource("vn.edu.hcmut.co3103.identity.support.UnicodeInputs#malformedUnicode")
    void malformedPasswordsCannotResetRegisterOrAuthenticate(String password) throws Exception {
        User user = createUser(UserStatus.ACTIVE);
        String token = requestToken("/api/v1/auth", user);
        var userBefore = jdbc.queryForMap("SELECT * FROM users WHERE user_id = ?", user.getUserId());
        UUID resetId = resets.findByTokenHash(hash(token)).orElseThrow().getResetId();
        var resetBefore = jdbc.queryForMap("SELECT * FROM password_resets WHERE reset_id = ?", resetId);
        String quoted = vn.edu.hcmut.co3103.identity.support.UnicodeInputs.jsonString(password);
        String registrationEmail = "unicode-" + UUID.randomUUID() + "@example.com";
        for (String prefix : new String[]{"/auth", "/api/v1/auth"}) {
            assertValidation(post(prefix + "/reset-password", "{\"token\":\"" + token + "\",\"new_password\":"
                    + quoted + "}"), "PASSWORD_POLICY_VIOLATION", "new_password");
            assertValidation(post(prefix + "/login", "{\"email\":\"" + user.getEmail() + "\",\"password\":"
                    + quoted + "}"), "BAD_REQUEST", "password");
            assertValidation(post(prefix + "/register", "{\"email\":\"" + registrationEmail
                    + "\",\"full_name\":\"Unicode Test\",\"password\":" + quoted + "}"), "BAD_REQUEST", "password");
            assertValidation(post(prefix + "/register", "{\"email\":\"" + registrationEmail
                    + "\",\"password\":\"ValidPassword123!\",\"full_name\":" + quoted + "}"), "BAD_REQUEST", "full_name");
        }
        assertThat(users.findByEmail(registrationEmail)).isEmpty();
        assertThat(jdbc.queryForMap("SELECT * FROM users WHERE user_id = ?", user.getUserId())).isEqualTo(userBefore);
        assertThat(jdbc.queryForMap("SELECT * FROM password_resets WHERE reset_id = ?", resetId)).isEqualTo(resetBefore);
        assertThat(encoder.matches(OLD_PASSWORD, users.findById(user.getUserId()).orElseThrow().getPasswordHash())).isTrue();
        assertThat(post("/api/v1/auth/login", loginBody(user, password.replaceAll("[\\uD800-\\uDFFF]", "?")))
                .statusCode()).isEqualTo(401);
        // The rejected request did not consume the token; a valid supplementary password still works.
        String valid = "MậtKhẩu😀123!";
        assertThat(post("/api/v1/auth/reset-password", resetBody(token, valid)).statusCode()).isEqualTo(200);
        assertThat(post("/api/v1/auth/login", loginBody(user, valid)).statusCode()).isEqualTo(200);
    }

    @Test
    void questionMarkPasswordDoesNotAuthenticateEitherSurrogateVariant() throws Exception {
        User user = createUser(UserStatus.ACTIVE);
        String token = requestToken("/api/v1/auth", user);
        assertThat(post("/api/v1/auth/reset-password", resetBody(token, "????????")).statusCode()).isEqualTo(200);
        var before = jdbc.queryForMap("SELECT * FROM users WHERE user_id = ?", user.getUserId());
        for (String malformed : new String[]{"\\ud800".repeat(8), "\\udfff".repeat(8)}) {
            assertValidation(post("/api/v1/auth/login", loginBody(user, malformed)), "BAD_REQUEST", "password");
            assertThat(jdbc.queryForMap("SELECT * FROM users WHERE user_id = ?", user.getUserId())).isEqualTo(before);
        }
        assertThat(post("/api/v1/auth/login", loginBody(user, "????????")).statusCode()).isEqualTo(200);
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.MethodSource("vn.edu.hcmut.co3103.identity.support.UnicodeInputs#malformedEmails")
    void malformedEmailsCannotCreateOrAliasAnIdentityOrQueueRecovery(String input) throws Exception {
        String email = UUID.randomUUID().toString().replace("-", "") + "-" + input;
        String substituted = new String(email.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);
        User user = users.saveAndFlush(User.builder().email(substituted).fullName("Email Test")
                .passwordHash(encoder.encode(OLD_PASSWORD)).status(UserStatus.ACTIVE).failedLoginAttempts(2).build());
        userIds.add(user.getUserId());
        jdbc.update("INSERT INTO user_profiles(user_id, bio) VALUES (?, ?)", user.getUserId(), "Unchanged profile");
        var userBefore = jdbc.queryForMap("SELECT * FROM users WHERE user_id = ?", user.getUserId());
        var profilesBefore = jdbc.queryForList("SELECT * FROM user_profiles");
        long usersBefore = users.count();
        long resetsBefore = resets.count();
        var admissionsBefore = jdbc.queryForList("SELECT * FROM recovery_admissions");
        String quoted = UnicodeInputs.jsonString(email);
        for (String prefix : new String[]{"/auth", "/api/v1/auth"}) {
            assertValidation(post(prefix + "/register", "{\"email\":" + quoted
                    + ",\"password\":\"" + OLD_PASSWORD + "\",\"full_name\":\"Email Test\"}"), "BAD_REQUEST", "email");
            // A distinct address would be inserted if the registration guard were missing.
            assertValidation(post(prefix + "/register", "{\"email\":" + UnicodeInputs.jsonString("new-" + email)
                    + ",\"password\":\"" + OLD_PASSWORD + "\",\"full_name\":\"Email Test\"}"), "BAD_REQUEST", "email");
            for (String password : new String[]{OLD_PASSWORD, "WrongPassword123!"}) {
                assertValidation(post(prefix + "/login", "{\"email\":" + quoted + ",\"password\":\""
                        + password + "\"}"), "BAD_REQUEST", "email");
            }
            assertValidation(post(prefix + "/forgot-password", "{\"email\":" + quoted + "}"), "BAD_REQUEST", "email");
        }
        awaitIdle();
        assertThat(users.count()).isEqualTo(usersBefore);
        assertThat(jdbc.queryForMap("SELECT * FROM users WHERE user_id = ?", user.getUserId())).isEqualTo(userBefore);
        assertThat(jdbc.queryForList("SELECT * FROM user_profiles")).isEqualTo(profilesBefore);
        assertThat(jdbc.queryForList("SELECT * FROM recovery_admissions")).isEqualTo(admissionsBefore);
        assertThat(resets.count()).isEqualTo(resetsBefore);
        assertThat(mailbox.getMessages()).isEmpty();
        verify(queue, never()).admit(anyString(), any());
        verify(notifications, never()).send(anyString(), anyString());
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.MethodSource("vn.edu.hcmut.co3103.identity.support.UnicodeInputs#validEmails")
    void wellFormedEmailsSurviveRegistrationLoginAndRecovery(String input) throws Exception {
        for (String prefix : new String[]{"/auth", "/api/v1/auth"}) {
            String email = UUID.randomUUID().toString().replace("-", "") + "-" + input;
            String quoted = UnicodeInputs.jsonString("  " + email + "  ");
            var registered = post(prefix + "/register", "{\"email\":" + quoted
                    + ",\"password\":\"" + OLD_PASSWORD + "\",\"full_name\":\"Email Test\"}");
            assertThat(registered.statusCode()).as(registered.body()).isEqualTo(201);
            User user = users.findByEmail(email).orElseThrow();
            userIds.add(user.getUserId());
            assertThat(mapper.readTree(registered.body()).get("email").asText()).isEqualTo(email);
            var loggedIn = post(prefix + "/login", "{\"email\":" + quoted + ",\"password\":\"" + OLD_PASSWORD + "\"}");
            assertThat(loggedIn.statusCode()).as(loggedIn.body()).isEqualTo(200);
            var identity = mapper.readTree(loggedIn.body()).get("user");
            assertThat(identity.get("email").asText()).isEqualTo(email);
            assertThat(identity.get("user_id").asText()).isEqualTo(user.getUserId().toString());
            requestToken(prefix, user); // Includes exact recipient and persisted reset hash checks.
            mailbox.clear();
        }
    }

    private void assertValidation(HttpResponse<String> response, String code, String field) {
        assertThat(response.statusCode()).as(response.body()).isEqualTo(400);
        var error = mapper.readTree(response.body());
        assertErrorEnvelope(error);
        assertThat(error.get("code").asText()).isEqualTo(code);

        assertThat(validationMessage(error, field)).isNotBlank();
    }

    private String requestToken(String prefix, User user) throws Exception {
        var response = post(prefix + "/forgot-password", "{\"email\":\"" + user.getEmail() + "\"}");
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        assertThat(mapper.readTree(response.body()).get("message").asText()).isEqualTo(FORGOT_MESSAGE);
        String token = URI.create(deliveredLink(user)).getRawQuery().substring("token=".length());
        assertThat(resets.findByTokenHash(hash(token))).isPresent();
        return token;
    }

    private String deliveredLink(User user) {
        await().atMost(Duration.ofSeconds(10)).until(() -> !mailbox.getMessages().isEmpty());
        awaitIdle();
        assertThat(mailbox.getMessages()).singleElement().satisfies(message -> {
            assertThat(message.getFrom()).isEqualTo("identity@example.com");
            assertThat(message.getTo()).containsExactly(user.getEmail());
            assertThat(message.getSubject()).isEqualTo("Reset your Central Identity password");
        });
        return mailbox.getMessages().getFirst().getText().lines()
                .filter(line -> line.startsWith("https://frontend.example/reset-password?token="))
                .findFirst().orElseThrow();
    }

    private void awaitIdle() {
        await().atMost(Duration.ofSeconds(10)).until(() -> executor.getActiveCount() == 0
                && deliveryExecutor.getActiveCount() == 0
                && jdbc.queryForObject("SELECT count(*) FROM recovery_jobs", Integer.class) == 0);
    }

    private void saturateExecutor(ThreadPoolTaskExecutor pool, CountDownLatch release) throws InterruptedException {
        awaitIdle();
        var entered = new CountDownLatch(pool.getMaxPoolSize());
        Runnable blocker = () -> {
            entered.countDown();
            try { assertThat(release.await(30, TimeUnit.SECONDS)).isTrue(); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new AssertionError(e); }
        };
        for (int i = 0; i < pool.getMaxPoolSize(); i++) {
            // The scheduled worker can take a slot even after awaitIdle(). With no queue,
            // retry only rejected submissions; accepted blockers must never be submitted twice.
            await().atMost(Duration.ofSeconds(5)).pollInterval(Duration.ofMillis(10)).until(() -> {
                try {
                    pool.execute(blocker);
                    return true;
                } catch (RejectedExecutionException exception) {
                    return false;
                }
            });
        }
        assertThat(entered.await(5, TimeUnit.SECONDS)).as("all executor slots are held by the test").isTrue();
    }

    private User createUser(UserStatus status) {
        User user = users.saveAndFlush(User.builder().email("recovery-http-" + UUID.randomUUID() + "@example.com")
                .passwordHash(encoder.encode(OLD_PASSWORD)).fullName("Recovery Test").status(status).build());
        userIds.add(user.getUserId());
        return user;
    }

    private HttpRequest request(String path, String body) {
        return HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).timeout(Duration.ofSeconds(15))
                .header("Content-Type", "application/json").header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build();
    }

    private HttpResponse<String> post(String path, String body) throws Exception {
        return client.send(request(path, body), HttpResponse.BodyHandlers.ofString());
    }

    private String resetBody(String token, String password) {
        return "{\"token\":\"%s\",\"new_password\":\"%s\"}".formatted(token, password);
    }

    private String loginBody(User user, String password) {
        return "{\"email\":\"%s\",\"password\":\"%s\"}".formatted(user.getEmail(), password);
    }

    private void assertInvalid(HttpResponse<String> response) {
        assertThat(response.statusCode()).as(response.body()).isEqualTo(401);
        assertThat(response.headers().allValues("WWW-Authenticate"))
                .containsExactly("Bearer realm=\"central-identity\"");
        var error = mapper.readTree(response.body());
        assertErrorEnvelope(error);

        assertThat(error.get("code").asText()).isEqualTo("INVALID_OR_EXPIRED_RESET_TOKEN");
        assertThat(error.get("message").asText()).isEqualTo("Invalid or expired password reset token");
    }

    private String hash(String token) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
    }
}
