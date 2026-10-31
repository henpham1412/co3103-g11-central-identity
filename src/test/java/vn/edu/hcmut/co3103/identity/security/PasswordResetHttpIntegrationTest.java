package vn.edu.hcmut.co3103.identity.security;

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
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import tools.jackson.databind.ObjectMapper;
import vn.edu.hcmut.co3103.identity.entity.PasswordReset;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.entity.UserStatus;
import vn.edu.hcmut.co3103.identity.service.PasswordResetNotificationService;
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
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Real HTTP and PostgreSQL transactions, including asynchronous issuance and single-use races. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class PasswordResetHttpIntegrationTest {
    private static final String OLD_PASSWORD = "OriginalPassword123!";
    private static final String NEW_PASSWORD = "NewPassword456!";
    private static final String FORGOT_MESSAGE =
            "If the email is eligible for recovery, password reset instructions have been sent.";
    @Value("${local.server.port}") private int port;
    @MockitoSpyBean private UserRepository users;
    @MockitoSpyBean private PasswordResetRepository resets;
    @MockitoSpyBean private PasswordResetNotificationService notifications;
    @Autowired private PasswordEncoder encoder;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private ObjectMapper mapper;
    @Autowired @Qualifier("applicationTaskExecutor") private ThreadPoolTaskExecutor executor;

    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private final List<UUID> userIds = new ArrayList<>();

    @AfterEach
    void cleanUp() {
        awaitIdle();
        for (UUID id : userIds) {
            resets.deleteByUserId(id);
            users.deleteById(id);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"/auth", "/api/v1/auth"})
    void recoveryChangesLoginPasswordAndRejectsReplay(String prefix, CapturedOutput output) throws Exception {
        User user = createUser(UserStatus.ACTIVE);
        String token = requestToken(prefix, user);
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
        assertThat(output.getAll()).contains("Simulated password reset email delivery")
                .doesNotContain(token, OLD_PASSWORD, NEW_PASSWORD);
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
        verify(users, timeout(10000)).findByEmail(unknownEmail);
        verify(users, timeout(10000)).findByEmail(user.getEmail());
        awaitIdle();
        var issued = resets.findByUserIdOrderByCreatedAtDesc(user.getUserId());
        assertThat(issued).hasSize(status == UserStatus.ACTIVE ? 1 : 0);
        if (status != UserStatus.ACTIVE) verifyNoInteractions(notifications);
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
            assertThat(responses).extracting(HttpResponse::statusCode).containsExactlyInAnyOrder(200, 400);
            assertInvalid(responses.stream().filter(response -> response.statusCode() == 400).findFirst().orElseThrow());
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
        }).when(users).findByEmail(email);
        try {
            var response = client.sendAsync(request("/auth/forgot-password", "{\"email\":\"" + email + "\"}"),
                    HttpResponse.BodyHandlers.ofString());
            assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
            assertThat(response.get(2, TimeUnit.SECONDS).statusCode()).isEqualTo(200);
        } finally {
            release.countDown();
        }
    }

    @Test
    void deliveryFailureDoesNotRevealAccountExistence() throws Exception {
        User user = createUser(UserStatus.ACTIVE);
        doThrow(new IllegalStateException("simulated delivery failure")).when(notifications).send(anyString(), anyString());
        var response = post("/auth/forgot-password", "{\"email\":\"" + user.getEmail() + "\"}");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(mapper.readTree(response.body()).get("message").asText()).isEqualTo(FORGOT_MESSAGE);
        verify(notifications, timeout(10000)).send(eq(user.getEmail()), anyString());
        awaitIdle();
        assertThat(resets.findByUserIdOrderByCreatedAtDesc(user.getUserId())).isEmpty();
    }

    private String requestToken(String prefix, User user) throws Exception {
        var response = post(prefix + "/forgot-password", "{\"email\":\"" + user.getEmail() + "\"}");
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        assertThat(mapper.readTree(response.body()).get("message").asText()).isEqualTo(FORGOT_MESSAGE);
        var token = ArgumentCaptor.forClass(String.class);
        verify(notifications, timeout(10000)).send(eq(user.getEmail()), token.capture());
        awaitIdle();
        assertThat(resets.findByTokenHash(hash(token.getValue()))).isPresent();
        return token.getValue();
    }

    private void awaitIdle() {
        await().atMost(Duration.ofSeconds(10)).until(() -> executor.getActiveCount() == 0
                && executor.getThreadPoolExecutor().getQueue().isEmpty());
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
        assertThat(response.statusCode()).as(response.body()).isEqualTo(400);
        var error = mapper.readTree(response.body());
        assertThat(error.get("code").asText()).isEqualTo("INVALID_OR_EXPIRED_RESET_TOKEN");
        assertThat(error.get("message").asText()).isEqualTo("Invalid or expired password reset token");
    }

    private String hash(String token) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
    }
}
