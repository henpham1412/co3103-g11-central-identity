package vn.edu.hcmut.co3103.identity.security;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.entity.UserStatus;
import vn.edu.hcmut.co3103.identity.entity.LmsClient;
import vn.edu.hcmut.co3103.identity.repository.LmsClientRepository;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtService;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** Real HTTP, production security, and committed PostgreSQL transactions (no test rollback). */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
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
    @Autowired
    private LmsClientRepository lmsClientRepository;

    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private final Set<String> testEmails = new HashSet<>();
    private final Set<String> testClientIds = new HashSet<>();

    @ParameterizedTest
    @ValueSource(strings = {"unknown", "numericPassword", "booleanName", "duplicate", "trailing", "array",
            "camelCase", "duplicateName"})
    void rejectsUnexpectedJsonWithoutCommittingRegistration(String scenario) throws Exception {
        String email = newEmail();
        String body = registerBody(email, PASSWORD);
        body = switch (scenario) {
            case "unknown" -> body.replace("}", ",\"role\":\"ADMIN\"}");
            case "numericPassword" -> body.replace("\"" + PASSWORD + "\"", "12345678");
            case "booleanName" -> body.replace("\"Security Test\"", "true");
            case "duplicate" -> body.replace("}", ",\"password\":\"AnotherPassword\"}");
            case "trailing" -> body + " {}";
            case "array" -> "[" + body + "]";
            case "camelCase" -> body.replace("full_name", "fullName");
            case "duplicateName" -> body.replace("}", ",\"full_name\":\"Another name\"}");
            default -> throw new IllegalArgumentException(scenario);
        };
        assertError(send("POST", REGISTER_PATH, body, "application/json", null), 400, REGISTER_PATH);
        assertThat(countUsers(email)).isZero();
    }

    @Test
    void documentedUnprefixedEndpointsSupportCompleteAuthenticationFlow() throws Exception {
        String email = newEmail();
        HttpResponse<String> registration = send("POST", "/auth/register", registerBody(email, PASSWORD),
                "application/json", null);
        assertThat(registration.statusCode()).isEqualTo(201);
        JsonNode registered = objectMapper.readTree(registration.body());
        assertThat(registered.size()).isEqualTo(5);
        assertThat(registered.get("message").asText()).isEqualTo("User registered successfully");
        assertThat(registered.get("full_name").asText()).isEqualTo("Security Test");
        assertThat(registered.get("email").asText()).isEqualTo(email);
        assertThat(registered.get("status").asText()).isEqualTo("ACTIVE");
        HttpResponse<String> login = send("POST", "/auth/login", loginBody(email, PASSWORD), "application/json", null);
        assertThat(login.statusCode()).isEqualTo(200);
        JsonNode response = objectMapper.readTree(login.body());
        assertThat(response.size()).isEqualTo(5);
        assertThat(response.get("token_type").asText()).isEqualTo("Bearer");
        assertThat(response.get("expires_in").asLong()).isEqualTo(86400);
        assertThat(response.get("client_id").asText()).isEqualTo("central-identity");
        assertThat(response.get("user").size()).isEqualTo(4);
        assertThat(response.get("user").get("user_id")).isEqualTo(registered.get("user_id"));
        assertThat(response.get("user").get("email").asText()).isEqualTo(email);
        assertThat(response.get("user").get("full_name").asText()).isEqualTo("Security Test");
        assertThat(response.get("user").get("status").asText()).isEqualTo("ACTIVE");
        String token = response.get("access_token").asText();
        assertThat(jwtService.extractUserId(token)).isEqualTo(registered.get("user_id").asText());
        String clientId = jwtService.extractClaim(token, claims -> claims.get("clientId", String.class));
        assertThat(clientId).isEqualTo("central-identity");
        assertThat(send("GET", "/users/me", null, "application/json", token).statusCode()).isEqualTo(200);
        JsonNode duplicate = assertError(send("POST", "/auth/register", registerBody(email, PASSWORD),
                "application/json", null), 409, "/auth/register");
        assertThat(duplicate.get("code").asText()).isEqualTo("EMAIL_ALREADY_REGISTERED");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void activeClientIssuesTokenWithValidatedContext(boolean includeRedirect) throws Exception {
        User user = createUser();
        String clientId = createClient(true);
        String fields = ",\"client_id\":\"" + clientId + "\"";
        if (includeRedirect) {
            fields += ",\"redirect_uri\":\"https://lms.example.com/auth/callback\"";
        }
        HttpResponse<String> login = send("POST", LOGIN_PATH,
                loginBody(user.getEmail(), PASSWORD).replace("}", fields + "}"), "application/json", null);
        assertThat(login.statusCode()).as(login.body()).isEqualTo(200);
        JsonNode body = objectMapper.readTree(login.body());
        assertThat(body.get("client_id").asText()).isEqualTo(clientId);
        String claim = jwtService.extractClaim(body.get("access_token").asText(),
                claims -> claims.get("clientId", String.class));
        assertThat(claim).isEqualTo(clientId);
        assertThat(userRepository.findById(user.getUserId()).orElseThrow().getLastLoginAt()).isNotNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "inactive", "redirect", "redirectOnly", "emptyRedirect", "prefixRedirect"})
    void invalidLmsContextCannotIssueTokenOrChangeLoginState(String scenario) throws Exception {
        User user = createUser();
        user.setFailedLoginAttempts(2);
        userRepository.saveAndFlush(user);
        String clientId = scenario.equals("missing") ? "unregistered-" + UUID.randomUUID()
                : createClient(!scenario.equals("inactive"));
        String fields = ",\"client_id\":\"" + clientId + "\"";
        switch (scenario) {
            case "redirect" -> fields += ",\"redirect_uri\":\"https://evil.example/callback\"";
            case "prefixRedirect" -> fields += ",\"redirect_uri\":\"https://lms.example.com/auth/callback/evil\"";
            case "redirectOnly" -> fields = ",\"redirect_uri\":\"https://lms.example.com/auth/callback\"";
            case "emptyRedirect" -> fields += ",\"redirect_uri\":\"\"";
            default -> { }
        }
        JsonNode error = assertError(send("POST", LOGIN_PATH,
                loginBody(user.getEmail(), PASSWORD).replace("}", fields + "}"), "application/json", null),
                400, LOGIN_PATH);
        assertThat(error.get("code").asText()).isEqualTo(
                scenario.equals("missing") || scenario.equals("inactive") ? "INVALID_CLIENT" : "INVALID_REDIRECT_URI");
        User persisted = userRepository.findById(user.getUserId()).orElseThrow();
        assertThat(persisted.getLastLoginAt()).isNull();
        assertThat(persisted.getFailedLoginAttempts()).isEqualTo(2);
        assertThat(persisted.getLockedUntil()).isNull();
    }

    private String createClient(boolean active) {
        String clientId = "pr9-client-" + UUID.randomUUID();
        testClientIds.add(clientId);
        lmsClientRepository.saveAndFlush(LmsClient.builder().clientId(clientId).clientName("PR9 Test")
                .isActive(active).redirectUris(List.of("https://lms.example.com/auth/callback")).build());
        return clientId;
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "client name", "tooLong"})
    void invalidClientContextDoesNotCommitRegistrationOrLogin(String clientId) throws Exception {
        String value = clientId.equals("tooLong") ? "x".repeat(101) : clientId;
        String email = newEmail();
        String registration = registerBody(email, PASSWORD).replace("}", ",\"client_id\":\"" + value + "\"}");
        assertError(send("POST", REGISTER_PATH, registration, "application/json", null), 400, REGISTER_PATH);
        assertThat(countUsers(email)).isZero();
        User user = createUser();
        String login = loginBody(user.getEmail(), PASSWORD).replace("}", ",\"client_id\":\"" + value + "\"}");
        assertError(send("POST", LOGIN_PATH, login, "application/json", null), 400, LOGIN_PATH);
        assertThat(userRepository.findById(user.getUserId()).orElseThrow().getLastLoginAt()).isNull();
    }

    @Test
    void loginTokenCanBeVerifiedWithPublicJwksOverHttp() throws Exception {
        String email = newEmail();
        assertThat(send("POST", REGISTER_PATH, registerBody(email, PASSWORD), "application/json", null).statusCode())
                .isEqualTo(201);
        HttpResponse<String> login = send("POST", LOGIN_PATH, loginBody(email, PASSWORD), "application/json", null);
        assertThat(login.statusCode()).isEqualTo(200);
        String accessToken = objectMapper.readTree(login.body()).get("access_token").asText();
        HttpResponse<String> keys = send("GET", "/.well-known/jwks.json", null, "application/json", null);
        assertThat(keys.statusCode()).isEqualTo(200);
        var token = com.nimbusds.jwt.SignedJWT.parse(accessToken);
        var publicKey = com.nimbusds.jose.jwk.JWKSet.parse(keys.body())
                .getKeyByKeyId(token.getHeader().getKeyID()).toRSAKey();
        assertThat(publicKey.isPrivate()).isFalse();
        assertThat(token.getHeader().getAlgorithm().getName()).isEqualTo("RS256");
        assertThat(token.getJWTClaimsSet().getIssuer()).isEqualTo("http://localhost:8080");
        assertThat(token.verify(new com.nimbusds.jose.crypto.RSASSAVerifier(publicKey))).isTrue();
    }

    @AfterEach
    void removeOnlyTestUsers() {
        for (String email : testEmails) {
            userRepository.findByEmail(email).ifPresent(userRepository::delete);
        }
        testClientIds.forEach(lmsClientRepository::deleteById);
        client.close();
    }

    @ParameterizedTest
    @ValueSource(strings = {"application/xml", "application/json;q=0", "application/xml;q=1, */*;q=0",
            "application/json;q=0, */*;q=1", "*/*;q=1, application/json;q=0",
            "application/*;q=0, */*;q=1", "application/json;q=0, application/*;q=1"})
    void unacceptableRegistrationDoesNotCommitUserAndJsonRetrySucceeds(String accept) throws Exception {
        String email = newEmail();
        String body = registerBody(email, PASSWORD);

        JsonNode error = assertError(send("POST", REGISTER_PATH, body, accept, null), 406, REGISTER_PATH);
        assertThat(error.get("code").asText()).isEqualTo("NOT_ACCEPTABLE");
        assertThat(countUsers(email)).isZero();

        HttpResponse<String> retry = send("POST", REGISTER_PATH, body, "application/json", null);
        assertThat(retry.statusCode()).isEqualTo(201);
        assertThat(countUsers(email)).isEqualTo(1);
        assertThat(objectMapper.readTree(retry.body()).get("user_id").asText())
                .isEqualTo(userRepository.findByEmail(email).orElseThrow().getUserId().toString());
    }

    @ParameterizedTest
    @ValueSource(strings = {"application/xml", "application/json;q=0", "application/xml;q=1, */*;q=0",
            "application/json;q=0, */*;q=1", "*/*;q=1, application/json;q=0",
            "application/*;q=0, */*;q=1"})
    void unacceptableLoginDoesNotCommitFailedAttemptOrLoginTime(String accept) throws Exception {
        User user = createUser();
        for (String password : new String[]{"wrong-password", PASSWORD}) {
            JsonNode error = assertError(send("POST", LOGIN_PATH, loginBody(user.getEmail(), password),
                    accept, null), 406, LOGIN_PATH);
            assertThat(error.get("code").asText()).isEqualTo("NOT_ACCEPTABLE");
        }

        User persisted = userRepository.findById(user.getUserId()).orElseThrow();
        assertThat(persisted.getFailedLoginAttempts()).isZero();
        assertThat(persisted.getLockedUntil()).isNull();
        assertThat(persisted.getLastLoginAt()).isNull();
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"*/*", "application/json", "application/json, text/plain, */*",
            "application/json;q=0.1, */*;q=0", "*/*;q=0, application/json;q=0.1",
            "application/*;q=0.5", "application/xml;q=1, */*;q=0.1",
            "application/json;q=0.1, application/*;q=0"})
    void acceptableJsonRegistrationAndLoginSucceed(String accept) throws Exception {
        String email = newEmail();
        assertThat(send("POST", REGISTER_PATH, registerBody(email, PASSWORD), accept, null).statusCode())
                .isEqualTo(201);
        assertThat(countUsers(email)).isEqualTo(1);
        HttpResponse<String> login = send("POST", LOGIN_PATH, loginBody(email, PASSWORD), accept, null);
        assertThat(login.statusCode()).as(login.body()).isEqualTo(200);
        String token = objectMapper.readTree(login.body()).get("access_token").asText();
        assertThat(jwtService.isTokenValid(token,
                new IdentityUserDetails(userRepository.findByEmail(email).orElseThrow()))).isTrue();
    }

    @ParameterizedTest
    @EnumSource(value = UserStatus.class, names = {"SUSPENDED", "DEACTIVATED"})
    void nonActiveAccountDisclosesStatusOnlyAfterCorrectPassword(UserStatus status) throws Exception {
        User user = createUser();
        user.setStatus(status);
        userRepository.saveAndFlush(user);

        JsonNode unknown = assertError(send("POST", LOGIN_PATH, loginBody(newEmail(), "wrong-password"),
                "application/json", null), 401, LOGIN_PATH);
        JsonNode wrong = assertError(send("POST", LOGIN_PATH, loginBody(user.getEmail(), "wrong-password"),
                "application/json", null), 401, LOGIN_PATH);
        assertThat(wrong.get("message").asText()).isEqualTo("Invalid email or password");
        // Only the timestamp varies between an unknown email and an existing account's wrong password.
        ((tools.jackson.databind.node.ObjectNode) unknown).remove("timestamp");
        ((tools.jackson.databind.node.ObjectNode) wrong).remove("timestamp");
        assertThat(wrong).isEqualTo(unknown);

        User persisted = userRepository.findById(user.getUserId()).orElseThrow();
        assertThat(persisted.getFailedLoginAttempts()).isEqualTo(1);
        assertThat(persisted.getLastLoginAt()).isNull();
        JsonNode correct = assertError(send("POST", LOGIN_PATH, loginBody(user.getEmail(), PASSWORD),
                "application/json", null), 403, LOGIN_PATH);
        assertThat(correct.get("message").asText()).isEqualTo("Account is inactive");
        assertThat(userRepository.findById(user.getUserId()).orElseThrow().getFailedLoginAttempts()).isEqualTo(1);
    }

    @ParameterizedTest
    @EnumSource(UserStatus.class)
    void lockedAccountDisclosesLockOnlyAfterCorrectPassword(UserStatus status) throws Exception {
        User user = createUser();
        user.setStatus(status);
        user.setFailedLoginAttempts(4);
        userRepository.saveAndFlush(user);

        for (int attempts = 5; attempts <= 6; attempts++) {
            JsonNode wrong = assertError(send("POST", LOGIN_PATH, loginBody(user.getEmail(), "wrong-password"),
                    "application/json", null), 401, LOGIN_PATH);
            assertThat(wrong.get("message").asText()).isEqualTo("Invalid email or password");
            assertThat(wrong.has("lockedUntil")).isFalse();
            User persisted = userRepository.findById(user.getUserId()).orElseThrow();
            assertThat(persisted.getFailedLoginAttempts()).isEqualTo(attempts);
            assertThat(persisted.getLockedUntil()).isAfter(Instant.now());
            assertThat(persisted.getLastLoginAt()).isNull();
        }
        JsonNode correct = assertError(send("POST", LOGIN_PATH, loginBody(user.getEmail(), PASSWORD),
                "application/json", null), 423, LOGIN_PATH);
        assertThat(correct.get("lockedUntil").asText()).isNotBlank();
        assertThat(userRepository.findById(user.getUserId()).orElseThrow().getFailedLoginAttempts()).isEqualTo(6);
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
        assertThat(error.get("message").asText()).isEqualTo("Request was rejected because its format is invalid");
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
        assertThat(atLimit.getBytes(java.nio.charset.StandardCharsets.UTF_8)).hasSize(72);
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
        String token = objectMapper.readTree(login.body()).get("access_token").asText();
        assertThat(jwtService.isTokenValid(token, new IdentityUserDetails(user))).isTrue();

        Instant lastLoginAt = userRepository.findByEmail(email).orElseThrow().getLastLoginAt();
        String overLimit = atLimit + "b";
        assertThat(overLimit.getBytes(java.nio.charset.StandardCharsets.UTF_8)).hasSize(73);
        JsonNode loginError = assertError(send("POST", LOGIN_PATH, loginBody(email, overLimit),
                "application/json", null), 400, LOGIN_PATH);
        assertThat(loginError.get("validationErrors").get("password").asText())
                .isEqualTo("Password must not exceed 72 bytes");
        User persisted = userRepository.findByEmail(email).orElseThrow();
        assertThat(persisted.getFailedLoginAttempts()).isZero();
        assertThat(persisted.getLockedUntil()).isNull();
        assertThat(persisted.getLastLoginAt()).isEqualTo(lastLoginAt);
    }

    private HttpResponse<String> send(String method, String path, String body, String accept, String token)
            throws Exception {
        var builder = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .timeout(Duration.ofSeconds(15));
        if (accept != null) {
            builder.header("Accept", accept);
        }
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
        assertThat(error.get("code").asText()).isNotBlank();
        if (status == 401) {
            assertThat(error.get("code").asText()).isEqualTo(path.equals(LOGIN_PATH)
                    ? "INVALID_CREDENTIALS" : "UNAUTHORIZED");
        } else if (status == 403 && path.equals(LOGIN_PATH)) {
            assertThat(error.get("code").asText()).isEqualTo("ACCOUNT_NOT_ACTIVE");
        } else if (status == 423) {
            assertThat(error.get("code").asText()).isEqualTo("LOGIN_TEMPORARILY_LOCKED");
        }
        assertThat(error.get("path").asText()).isEqualTo(path);
        assertThat(Instant.parse(error.get("timestamp").asText())).isNotNull();
        assertThat(error.has("access_token")).isFalse();
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
        return "{\"email\":\"%s\",\"password\":\"%s\",\"full_name\":\"Security Test\"}".formatted(email, password);
    }

    private String loginBody(String email, String password) {
        return "{\"email\":\"%s\",\"password\":\"%s\"}".formatted(email, password);
    }
}
