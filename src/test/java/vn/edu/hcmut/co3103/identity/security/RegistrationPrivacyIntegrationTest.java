package vn.edu.hcmut.co3103.identity.security;

import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import tools.jackson.databind.ObjectMapper;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.mockito.Mockito.doAnswer;
import static org.awaitility.Awaitility.await;
import static vn.edu.hcmut.co3103.identity.support.ErrorResponseAssertions.assertErrorEnvelope;

/** Real PostgreSQL and HTTP with production logging levels; only the file sink is added. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "logging.file.name=target/registration-privacy.log")
@ExtendWith(OutputCaptureExtension.class)
class RegistrationPrivacyIntegrationTest {

    @Value("${local.server.port}") private int port;
    @Autowired private UserRepository users;
    @MockitoSpyBean private PasswordEncoder passwordEncoder;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private ObjectMapper mapper;

    @ParameterizedTest
    @ValueSource(strings = {"/auth/register", "/api/v1/auth/register"})
    void concurrentAndSequentialDuplicatesDoNotDisclosePrivateData(String path, CapturedOutput output)
            throws Exception {
        String marker = UUID.randomUUID().toString();
        String email = "privacy-" + marker + "@example.com";
        String fullName = "Privacy " + marker;
        String password = "Private-" + marker + "!";
        var privateValues = new ConcurrentLinkedQueue<>(List.of(marker, email, fullName, password));
        Path logFile = Path.of("target/registration-privacy.log");
        long logOffset = Files.size(logFile);
        int outputOffset = output.getAll().length();
        assertThat(jdbc.queryForObject("show server_version_num", String.class)).isEqualTo("180006");
        for (var setting : Map.of("log_error_verbosity", "terse", "log_statement", "none",
                "log_min_error_statement", "panic", "log_parameter_max_length", "0",
                "log_parameter_max_length_on_error", "0").entrySet()) {
            assertThat(jdbc.queryForObject("select current_setting(?)", String.class, setting.getKey()))
                    .as(setting.getKey()).isEqualTo(setting.getValue());
        }
        // CI/local test PostgreSQL must enable logging_collector and permit reading its stderr log.
        // Missing log access fails this test; privacy is never certified from application logs alone.
        String serverLog = jdbc.queryForObject("select pg_current_logfile('stderr')", String.class);
        assertThat(serverLog).as("Enable PostgreSQL logging_collector for the privacy regression").isNotBlank();
        Long serverOffset = jdbc.queryForObject("select (pg_stat_file(?)).size", Long.class, serverLog);
        int requests = 6;
        var prechecks = new CountDownLatch(requests);
        var executor = Executors.newFixedThreadPool(requests);

        // Encoding follows the real existence query. Gate here so all requests pass the pre-check
        // before any can insert, while retaining the production BCrypt and repository operations.
        doAnswer(invocation -> {
            prechecks.countDown();
            assertThat(prechecks.await(15, TimeUnit.SECONDS)).isTrue();
            String hash = (String) invocation.callRealMethod();
            privateValues.add(hash);
            return hash;
        }).when(passwordEncoder).encode(password);

        try (HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()) {
            String body = mapper.writeValueAsString(Map.of(
                    "email", email, "full_name", fullName, "password", password));
            HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                    .timeout(Duration.ofSeconds(30)).header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body)).build();
            List<Future<HttpResponse<String>>> pending = new ArrayList<>();
            for (int i = 0; i < requests; i++) {
                pending.add(executor.submit(() -> client.send(request, HttpResponse.BodyHandlers.ofString())));
            }
            List<HttpResponse<String>> responses = new ArrayList<>();
            for (var result : pending) {
                responses.add(result.get(40, TimeUnit.SECONDS));
            }
            assertThat(prechecks.getCount()).isZero();
            assertThat(responses.stream().filter(response -> response.statusCode() == 201).count()).isEqualTo(1);
            assertThat(responses.stream().filter(response -> response.statusCode() == 409).count())
                    .isEqualTo(requests - 1);
            assertThat(jdbc.queryForObject("select count(*) from users where email = ?", Long.class, email))
                    .isEqualTo(1);
            User stored = users.findByEmail(email).orElseThrow();
            privateValues.add(stored.getPasswordHash());
            privateValues.add(stored.getUserId().toString());

            // Exercise the pre-check path too, after the winner has committed.
            HttpResponse<String> sequential = client.send(request, HttpResponse.BodyHandlers.ofString());
            assertThat(sequential.statusCode()).isEqualTo(409);
            responses.add(sequential);
            // The collector is asynchronous. A positive count proves all five real collisions arrived.
            await().atMost(Duration.ofSeconds(10)).untilAsserted(() -> {
                String logs = jdbc.queryForObject("select pg_read_file(?, ?, 10000000)",
                        String.class, serverLog, serverOffset);
                assertThat(logs.split("duplicate key value violates unique constraint \"users_email_key\"", -1).length - 1)
                        .isEqualTo(requests - 1);
                assertThat(logs).doesNotContain("DETAIL:", "STATEMENT:");
                assertNoPrivateData(logs, privateValues);
            });
            String stdout = output.getAll().substring(outputOffset);
            String fileLog;
            try (var input = Files.newInputStream(logFile)) {
                input.skipNBytes(logOffset);
                fileLog = new String(input.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            }
            assertAll(
                    () -> assertSafeDiagnostics(stdout, privateValues),
                    () -> assertSafeDiagnostics(fileLog, privateValues),
                    () -> {
                        for (var response : responses) {
                            if (response.statusCode() == 409) {
                                var error = mapper.readTree(response.body());
                                assertErrorEnvelope(error);
                                assertThat(error.get("code").asText()).isEqualTo("EMAIL_ALREADY_REGISTERED");
                                assertThat(error.get("message").asText()).isEqualTo("Email already registered");
                                assertNoPrivateData(response.body(), privateValues);
                            }
                        }
                    });
        } finally {
            executor.shutdownNow();
            assertThat(executor.awaitTermination(40, TimeUnit.SECONDS)).isTrue();
            jdbc.update("delete from users where email = ?", email);
        }
    }

    private static void assertSafeDiagnostics(String logs, ConcurrentLinkedQueue<String> privateValues) {
        assertThat(LoggerFactory.getLogger("org.hibernate.orm.jdbc.error").isWarnEnabled()).isTrue();
        // Prove the actual ORM collision diagnostic was captured, not silenced or missed.
        assertThat(logs).contains("org.hibernate.orm.jdbc.error", "23505", "users_email_key");
        assertNoPrivateData(logs, privateValues);
    }

    private static void assertNoPrivateData(String text, ConcurrentLinkedQueue<String> privateValues) {
        assertThat(text).doesNotContain(privateValues.toArray(String[]::new));
        assertThat(text).doesNotContainPattern("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");
    }
}
