package vn.edu.hcmut.co3103.identity.security;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtService;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** Real HTTP, production security, and committed PostgreSQL transactions (no test rollback). */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "jwt.secret=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
class AuthHttpIntegrationTest {

    private static final String REGISTER_PATH = "/api/v1/auth/register";
    private static final String LOGIN_PATH = "/api/v1/auth/login";
    private static final String MISSING_PATH = "/api/v1/does-not-exist";
    private static final String PASSWORD = "Password123!";

    @Value("${local.server.port}")
    private int port;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private JdbcTemplate jdbcTemplate;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private ObjectMapper objectMapper;

    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private final Set<String> testEmails = new HashSet<>();

    @AfterEach
    void removeOnlyTestUsers() {
        for (String email : testEmails) {
            userRepository.findByEmail(email).ifPresent(userRepository::delete);
        }
        client.close();
    }

    @Test
    void unacceptableRegistrationDoesNotCommitUserAndJsonRetrySucceeds() throws Exception {
        String email = newEmail();
        String body = registerBody(email, PASSWORD);

        assertError(send("POST", REGISTER_PATH, body, "application/xml", null), 406, REGISTER_PATH);
        assertThat(countUsers(email)).isZero();

        HttpResponse<String> retry = send("POST", REGISTER_PATH, body, "application/json", null);
        assertThat(retry.statusCode()).isEqualTo(201);
        assertThat(countUsers(email)).isEqualTo(1);
        assertThat(objectMapper.readTree(retry.body()).get("userId").asText())
                .isEqualTo(userRepository.findByEmail(email).orElseThrow().getUserId().toString());
    }

    @Test
    void unacceptableLoginDoesNotCommitFailedAttemptOrLoginTime() throws Exception {
        User user = createUser();
        String body = "{\"email\":\"%s\",\"password\":\"wrong-password\"}".formatted(user.getEmail());

        assertError(send("POST", LOGIN_PATH, body, "application/xml", null), 406, LOGIN_PATH);

        User persisted = userRepository.findById(user.getUserId()).orElseThrow();
        assertThat(persisted.getFailedLoginAttempts()).isZero();
        assertThat(persisted.getLockedUntil()).isNull();
        assertThat(persisted.getLastLoginAt()).isNull();
    }

    @Test
    void authenticatedMissingEndpointReturnsJson404() throws Exception {
        String token = jwtService.generateToken(createUser());
        JsonNode error = assertError(send("GET", MISSING_PATH, null, "application/json", token), 404, MISSING_PATH);
        assertThat(error.get("code").asText()).isEqualTo("RESOURCE_NOT_FOUND");
        assertThat(error.get("message").asText()).isEqualTo("Requested resource was not found");
    }

    @Test
    void publicMissingResourceReturnsJson404WithoutAuthentication() throws Exception {
        String path = "/swagger-ui/does-not-exist.css";
        JsonNode error = assertError(send("GET", path, null, "application/xml", null), 404, path);
        assertThat(error.get("code").asText()).isEqualTo("RESOURCE_NOT_FOUND");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void firewallRejectionPreserves400AndOriginalPathThroughServletContainer(boolean authenticated) throws Exception {
        String token = authenticated ? jwtService.generateToken(createUser()) : null;
        String path = LOGIN_PATH + ";invalid";
        JsonNode error = assertError(send("POST", path, "{}", "application/xml", token), 400, path);
        assertThat(error.get("code").asText()).isEqualTo("INVALID_REQUEST");
        assertThat(error.get("message").asText()).contains(";");
    }

    @Test
    void deletedAccountsTokenCannotAuthenticateReplacementWithSameEmail() throws Exception {
        User original = createUser();
        String oldToken = jwtService.generateToken(original);
        userRepository.deleteById(original.getUserId());
        User replacement = userRepository.saveAndFlush(User.builder().email(original.getEmail())
                .passwordHash(original.getPasswordHash()).fullName("Replacement User").build());
        assertThat(replacement.getUserId()).isNotEqualTo(original.getUserId());

        assertError(send("GET", MISSING_PATH, null, "application/json", oldToken), 401, MISSING_PATH);
        // A token belonging to the replacement reaches MVC and receives the expected 404.
        assertError(send("GET", MISSING_PATH, null, "application/json", jwtService.generateToken(replacement)),
                404, MISSING_PATH);
    }

    @ParameterizedTest
    @ValueSource(strings = {"a", "\u00e9", "\u20ac", "\uD83D\uDE00"})
    void bcryptByteBoundaryIsValidatedBeforeWritingAndAcceptsExactly72Bytes(String character) throws Exception {
        String email = newEmail();
        int bytesPerCharacter = character.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        String atLimit = character.repeat(72 / bytesPerCharacter);
        JsonNode error = assertError(send("POST", REGISTER_PATH, registerBody(email, atLimit + "a"),
                "application/json", null), 400, REGISTER_PATH);
        assertThat(error.get("validationErrors").get("password").asText())
                .isEqualTo("Password must not exceed 72 UTF-8 bytes");
        assertThat(countUsers(email)).isZero();

        assertThat(send("POST", REGISTER_PATH, registerBody(email, atLimit), "application/json", null).statusCode())
                .isEqualTo(201);
        User user = userRepository.findByEmail(email).orElseThrow();
        assertThat(passwordEncoder.matches(atLimit, user.getPasswordHash())).isTrue();
        HttpResponse<String> login = send("POST", LOGIN_PATH,
                "{\"email\":\"%s\",\"password\":\"%s\"}".formatted(email, atLimit), "application/json", null);
        assertThat(login.statusCode()).isEqualTo(200);
        String token = objectMapper.readTree(login.body()).get("accessToken").asText();
        assertThat(jwtService.isTokenValid(token, new IdentityUserDetails(user))).isTrue();
    }

    private HttpResponse<String> send(String method, String path, String body, String accept, String token)
            throws Exception {
        var builder = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .timeout(Duration.ofSeconds(15)).header("Accept", accept);
        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        builder.method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(body));
        if (body != null) {
            builder.header("Content-Type", "application/json");
        }
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private JsonNode assertError(HttpResponse<String> response, int status, String path) {
        assertThat(response.statusCode()).as(response.body()).isEqualTo(status);
        assertThat(response.headers().firstValue("Content-Type").orElse("")).startsWith("application/json");
        JsonNode error = objectMapper.readTree(response.body());
        assertThat(error.get("status").asInt()).isEqualTo(status);
        assertThat(error.get("error").asText()).isEqualTo(HttpStatus.valueOf(status).getReasonPhrase());
        assertThat(error.get("message").asText()).isNotBlank();
        assertThat(error.get("path").asText()).isEqualTo(path);
        assertThat(Instant.parse(error.get("timestamp").asText())).isNotNull();
        return error;
    }

    private long countUsers(String email) {
        return jdbcTemplate.queryForObject("SELECT COUNT(*) FROM users WHERE email = ?", Long.class, email);
    }

    private String newEmail() {
        String email = "security-regression-" + UUID.randomUUID() + "@example.com";
        testEmails.add(email);
        return email;
    }

    private User createUser() {
        return userRepository.saveAndFlush(User.builder().email(newEmail())
                .passwordHash(passwordEncoder.encode(PASSWORD)).fullName("Security Test").build());
    }

    private String registerBody(String email, String password) {
        return "{\"email\":\"%s\",\"password\":\"%s\",\"fullName\":\"Security Test\"}".formatted(email, password);
    }
}
