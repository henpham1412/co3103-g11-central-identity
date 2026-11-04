package vn.edu.hcmut.co3103.identity.security;

import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.entity.UserStatus;
import vn.edu.hcmut.co3103.identity.repository.UserProfileRepository;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtService;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtTestKeys;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Date;
import java.util.HashMap;
import java.util.UUID;
import java.util.stream.Stream;

import static vn.edu.hcmut.co3103.identity.support.ErrorResponseAssertions.assertErrorEnvelope;
import static vn.edu.hcmut.co3103.identity.support.ErrorResponseAssertions.validationMessage;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class CurrentUserHttpIntegrationTest {

    private static final String PATH = "/api/v1/users/me";

    @Value("${local.server.port}")
    private int port;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UserProfileRepository userProfileRepository;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private JdbcTemplate jdbc;

    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private final String email = "current-user-" + UUID.randomUUID() + "@example.com";

    @DynamicPropertySource
    static void rsaKeys(DynamicPropertyRegistry registry) {
        JwtTestKeys.registerProperties(registry);
    }

    @AfterEach
    void cleanUp() {
        userRepository.findByEmail(email).ifPresent(userRepository::delete);
        client.close();
    }

    @Test
    void registeredUserCanLoginAndReadCurrentProfileUntilAccountIsDisabledOrDeleted() throws Exception {
        String credentials = "{\"email\":\"%s\",\"password\":\"Password123!\"}".formatted(email);
        String registration = credentials.substring(0, credentials.length() - 1)
                + ",\"full_name\":\"Profile Student\"}";
        assertThat(send("/api/v1/auth/register", registration, null).statusCode()).isEqualTo(201);
        HttpResponse<String> login = send("/api/v1/auth/login", credentials, null);
        assertThat(login.statusCode()).isEqualTo(200);
        String token = objectMapper.readTree(login.body()).get("access_token").asText();
        User user = userRepository.findByEmail(email).orElseThrow();

        HttpResponse<String> response = send(PATH, null, token);
        assertThat(response.statusCode()).isEqualTo(200);
        JsonNode profile = objectMapper.readTree(response.body());
        assertThat(profile.propertyNames()).containsExactlyInAnyOrder("user_id", "email", "full_name", "status", "profile");
        assertThat(profile.has("id")).isFalse();
        assertThat(profile.get("email").asText()).isEqualTo(email);
        assertThat(profile.has("fullName")).isFalse();
        assertThat(profile.get("status").asText()).isEqualTo("ACTIVE");
        assertThat(profile.has("role")).isFalse();
        assertThat(profile.get("user_id").asText()).isEqualTo(user.getUserId().toString());
        assertThat(profile.get("full_name").asText()).isEqualTo("Profile Student");
        assertThat(profile.get("profile").isNull()).isTrue();
        assertThat(response.headers().firstValue("Set-Cookie")).isEmpty();

        assertProfileRoutesMatch(token, profile);
        assertThat(userProfileRepository.findById(user.getUserId())).isEmpty();

        // Verify PATCH /users/me updates profile information
        String updateBody = """
                {
                    "full_name": "Updated Profile Student",
                    "avatar_url": "https://example.com/avatar.png",
                    "bio": "Software Engineering Student",
                    "phone_number": "+84912345678",
                    "date_of_birth": "2000-01-02",
                    "locale": "vi",
                    "timezone": "Asia/Ho_Chi_Minh"
                }
                """;
        HttpResponse<String> patchResponse = patch("/users/me", updateBody, token);
        assertThat(patchResponse.statusCode()).as(patchResponse.body()).isEqualTo(200);
        JsonNode patchResult = objectMapper.readTree(patchResponse.body());
        assertThat(patchResult.get("message").asText()).isEqualTo("Profile updated successfully");
        assertThat(patchResult.get("updated_at")).isNotNull();

        var savedProfile = userProfileRepository.findById(user.getUserId()).orElseThrow();
        assertThat(savedProfile.getUserId()).isEqualTo(user.getUserId());
        assertThat(savedProfile.getAvatarUrl()).isEqualTo("https://example.com/avatar.png");
        assertThat(savedProfile.getBio()).isEqualTo("Software Engineering Student");
        assertThat(savedProfile.getPhoneNumber()).isEqualTo("+84912345678");
        assertThat(savedProfile.getDateOfBirth()).isEqualTo(java.time.LocalDate.of(2000, 1, 2));
        assertThat(savedProfile.getLocale()).isEqualTo("vi");
        assertThat(savedProfile.getTimezone()).isEqualTo("Asia/Ho_Chi_Minh");
        HttpResponse<String> updated = send(PATH, null, token);
        assertThat(updated.statusCode()).isEqualTo(200);
        JsonNode updatedProfile = objectMapper.readTree(updated.body());
        assertThat(updatedProfile.get("full_name").asText()).isEqualTo("Updated Profile Student");
        assertThat(updatedProfile.has("fullName")).isFalse();
        assertThat(updatedProfile.get("profile").get("bio").asText()).isEqualTo("Software Engineering Student");
        assertProfileRoutesMatch(token, updatedProfile);

        // Omitted fields retain their values while the supplied bio changes.
        assertThat(patch(PATH, "{\"bio\":\"Only bio changed\"}", token).statusCode()).isEqualTo(200);
        JsonNode partial = objectMapper.readTree(send(PATH, null, token).body());
        assertThat(partial.get("full_name")).isEqualTo(updatedProfile.get("full_name"));
        for (String field : new String[]{"avatar_url", "phone_number", "date_of_birth", "locale", "timezone"}) {
            assertThat(partial.get("profile").get(field)).isEqualTo(updatedProfile.get("profile").get(field));
        }
        assertThat(partial.get("profile").get("bio").asText()).isEqualTo("Only bio changed");

        assertThat(patch("/users/me", """
                {"avatar_url":null,"bio":null,"phone_number":null,"date_of_birth":null,"locale":null,"timezone":null}
                """, token).statusCode()).isEqualTo(200);
        JsonNode cleared = objectMapper.readTree(send(PATH, null, token).body());
        assertThat(cleared.get("full_name")).isEqualTo(updatedProfile.get("full_name"));
        assertThat(cleared.get("profile").size()).isEqualTo(6);
        cleared.get("profile").forEach(value -> assertThat(value.isNull()).isTrue());
        savedProfile = userProfileRepository.findById(user.getUserId()).orElseThrow();
        assertThat(savedProfile.getAvatarUrl()).isNull();
        assertThat(savedProfile.getBio()).isNull();
        assertThat(savedProfile.getPhoneNumber()).isNull();
        assertThat(savedProfile.getDateOfBirth()).isNull();
        assertThat(savedProfile.getLocale()).isNull();
        assertThat(savedProfile.getTimezone()).isNull();
        assertProfileRoutesMatch(token, cleared);
        assertThat(userProfileRepository.findAll().stream()
                .map(row -> row.getUserId()).filter(user.getUserId()::equals).count()).isEqualTo(1);

        user = userRepository.findById(user.getUserId()).orElseThrow();
        user.setStatus(UserStatus.SUSPENDED);
        userRepository.saveAndFlush(user);
        assertUnauthorized(send(PATH, null, token));
        userRepository.deleteById(user.getUserId());
        assertUnauthorized(send(PATH, null, token));
    }

    @ParameterizedTest
    @CsvSource({"/users/me,http://localhost:3000", "/api/v1/users/me,http://localhost:5173"})
    void allowedFrontendCanPreflightAndPatchProfile(String path, String origin) throws Exception {
        User user = userRepository.saveAndFlush(User.builder().email(email).fullName("Original Name")
                .passwordHash("unused-test-hash").build());
        var preflight = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .header("Origin", origin).header("Access-Control-Request-Method", "PATCH")
                .header("Access-Control-Request-Headers", "authorization,content-type")
                .method("OPTIONS", HttpRequest.BodyPublishers.noBody()).build();
        var allowed = client.send(preflight, HttpResponse.BodyHandlers.ofString());
        assertThat(allowed.statusCode()).as(allowed.body()).isEqualTo(200);
        assertThat(allowed.headers().firstValue("Access-Control-Allow-Origin")).contains(origin);
        assertThat(allowed.headers().firstValue("Access-Control-Allow-Methods").orElse("")).contains("PATCH");
        assertThat(allowed.headers().firstValue("Access-Control-Allow-Headers").orElse("").toLowerCase(java.util.Locale.ROOT))
                .contains("authorization", "content-type");
        var update = HttpRequest.newBuilder(preflight.uri()).header("Origin", origin)
                .header("Authorization", "Bearer " + jwtService.generateToken(user))
                .header("Content-Type", "application/json")
                .method("PATCH", HttpRequest.BodyPublishers.ofString("{\"full_name\":\"Nguyễn Văn An\"}")).build();
        var response = client.send(update, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        assertThat(response.headers().firstValue("Access-Control-Allow-Origin")).contains(origin);
        assertThat(userRepository.findById(user.getUserId()).orElseThrow().getFullName()).isEqualTo("Nguyễn Văn An");
    }

    @ParameterizedTest
    @ValueSource(strings = {"/users/me", "/api/v1/users/me"})
    void blankNamesCannotMutateUserOrProfile(String path) throws Exception {
        User user = userRepository.saveAndFlush(User.builder().email(email).fullName("Original Name")
                .passwordHash("unused-test-hash").build());
        String token = jwtService.generateToken(user);
        assertThat(patch(path, "{\"bio\":\"Original bio\"}", token).statusCode()).isEqualTo(200);
        JsonNode before = objectMapper.readTree(send(path, null, token).body());
        for (String blank : new String[]{"", " \t\n", "\u2003"}) {
            var response = patch(path, objectMapper.writeValueAsString(
                    java.util.Map.of("full_name", blank, "bio", "Must not persist")), token);
            assertThat(response.statusCode()).as(response.body()).isEqualTo(400);
            JsonNode error = objectMapper.readTree(response.body());
            assertErrorEnvelope(error);
            assertThat(error.get("code").asText()).isEqualTo("VALIDATION_ERROR");
            assertThat(validationMessage(error, "full_name")).isNotBlank();
            assertThat(objectMapper.readTree(send(path, null, token).body())).isEqualTo(before);
        }
    }

    static Stream<Arguments> storageBoundaryCases() {
        return Stream.concat(
                Stream.of("bio", "full_name", "phone_number", "locale", "timezone")
                        .map(field -> Arguments.of(field, "bad\0value")),
                Stream.of(LocalDate.now().plusDays(1).toString())
                        .map(date -> Arguments.of("date_of_birth", date)));
    }

    @ParameterizedTest
    @MethodSource("storageBoundaryCases")
    void storageBoundariesReturnValidationErrorsWithoutMutatingRows(String field, String value) throws Exception {
        String path = PATH;
        User user = userRepository.saveAndFlush(User.builder().email(email).fullName("Original Name")
                .passwordHash("unused-test-hash").build());
        String token = jwtService.generateToken(user);
        assertThat(patch(path, """
                {"bio":"Original bio","phone_number":"123","locale":"vi","timezone":"Asia/Ho_Chi_Minh",
                 "date_of_birth":"2000-01-02"}
                """, token).statusCode()).isEqualTo(200);
        var userBefore = jdbc.queryForMap("SELECT * FROM users WHERE user_id = ?", user.getUserId());
        var profileBefore = jdbc.queryForMap("SELECT * FROM user_profiles WHERE user_id = ?", user.getUserId());
        var body = new HashMap<String, String>();
        body.put("full_name", "Must not persist");
        body.put("bio", "Must not persist");
        body.put(field, value);
        var response = patch(path, objectMapper.writeValueAsString(body), token);
        assertThat(response.statusCode()).as(response.body()).isEqualTo(400);
        JsonNode error = objectMapper.readTree(response.body());
        assertErrorEnvelope(error);

        assertThat(error.get("code").asText()).isEqualTo("VALIDATION_ERROR");
        assertThat(validationMessage(error, field)).isNotBlank();
        assertThat(jdbc.queryForMap("SELECT * FROM users WHERE user_id = ?", user.getUserId())).isEqualTo(userBefore);
        assertThat(jdbc.queryForMap("SELECT * FROM user_profiles WHERE user_id = ?", user.getUserId())).isEqualTo(profileBefore);
    }

    @ParameterizedTest
    @MethodSource("validPastBirthDates")
    void acceptsPastBirthDatesAndPreservesOmittedAndNullSemantics(
            String path, boolean profileExists, String date) throws Exception {
        User user = userRepository.saveAndFlush(User.builder().email(email).fullName("Original Name")
                .passwordHash("unused-test-hash").build());
        String token = jwtService.generateToken(user);
        if (profileExists) {
            assertThat(patch(path, "{\"bio\":\"Original bio\",\"date_of_birth\":\"1999-01-01\"}", token)
                    .statusCode()).isEqualTo(200);
        }
        var response = patch(path, "{\"date_of_birth\":\"" + date + "\"}", token);
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        assertThat(userProfileRepository.findById(user.getUserId()).orElseThrow().getDateOfBirth())
                .isEqualTo(LocalDate.parse(date));
        LocalDate storedDate = jdbc.queryForObject("SELECT date_of_birth FROM user_profiles WHERE user_id = ?",
                (row, index) -> row.getObject(1, LocalDate.class), user.getUserId());
        assertThat(storedDate)
                .as("the actual PostgreSQL value must retain the requested year").isEqualTo(LocalDate.parse(date));
        assertThat(objectMapper.readTree(send(path, null, token).body()).get("profile").get("date_of_birth").asText())
                .isEqualTo(date);

        assertThat(patch(path, "{\"bio\":\"Updated bio\"}", token).statusCode()).isEqualTo(200);
        assertThat(userProfileRepository.findById(user.getUserId()).orElseThrow().getDateOfBirth())
                .as("omitted date_of_birth retains its value").isEqualTo(LocalDate.parse(date));
        assertThat(patch(path, "{\"date_of_birth\":null}", token).statusCode()).isEqualTo(200);
        var cleared = userProfileRepository.findById(user.getUserId()).orElseThrow();
        assertThat(cleared.getDateOfBirth()).isNull();
        assertThat(cleared.getBio()).isEqualTo("Updated bio");
        assertThat(userRepository.findById(user.getUserId()).orElseThrow().getFullName()).isEqualTo("Original Name");
    }

    static Stream<Arguments> validPastBirthDates() {
        return Stream.of("/users/me", "/api/v1/users/me").flatMap(path ->
                Stream.of(false, true).flatMap(existing ->
                        Stream.of("0000-01-01", "1899-12-31", "1900-01-01", "2000-02-29", LocalDate.now().toString())
                                .map(date -> Arguments.of(path, existing, date))));
    }

    @ParameterizedTest
    @CsvSource({"/users/me,false", "/users/me,true", "/api/v1/users/me,false", "/api/v1/users/me,true"})
    void invalidAndFutureBirthDatesNeverCreateOrModifyProfile(String path, boolean profileExists) throws Exception {
        User user = userRepository.saveAndFlush(User.builder().email(email).fullName("Original Name")
                .passwordHash("unused-test-hash").build());
        String token = jwtService.generateToken(user);
        if (profileExists) {
            assertThat(patch(path, "{\"bio\":\"Original bio\",\"date_of_birth\":\"1899-12-31\"}", token)
                    .statusCode()).isEqualTo(200);
        }
        var userBefore = jdbc.queryForMap("SELECT * FROM users WHERE user_id = ?", user.getUserId());
        var profilesBefore = jdbc.queryForList("SELECT * FROM user_profiles WHERE user_id = ?", user.getUserId());
        for (String date : new String[]{"1900-02-29", LocalDate.now().plusDays(1).toString()}) {
            var response = patch(path, "{\"full_name\":\"Must not persist\",\"bio\":\"Must not persist\","
                    + "\"date_of_birth\":\"" + date + "\"}", token);
            assertThat(response.statusCode()).as(response.body()).isEqualTo(400);
            var error = objectMapper.readTree(response.body());
            assertErrorEnvelope(error);
            assertThat(error.get("code").asText())
                    .isEqualTo(date.equals("1900-02-29") ? "BAD_REQUEST" : "VALIDATION_ERROR");
            assertThat(jdbc.queryForMap("SELECT * FROM users WHERE user_id = ?", user.getUserId())).isEqualTo(userBefore);
            assertThat(jdbc.queryForList("SELECT * FROM user_profiles WHERE user_id = ?", user.getUserId()))
                    .as("profile existence, values and updated_at must be unchanged").isEqualTo(profilesBefore);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"/users/me", "/api/v1/users/me"})
    void patchTimestampExactlyMatchesPersistedValue(String path) throws Exception {
        User user = userRepository.saveAndFlush(User.builder().email(email).fullName("Original Name")
                .passwordHash("unused-test-hash").build());
        String token = jwtService.generateToken(user);
        for (String body : new String[]{"{\"bio\":\"New profile\"}", "{\"bio\":\"Updated profile\"}",
                "{\"full_name\":\"Updated Name\"}", "{\"bio\":null}"}) {
            var response = patch(path, body, token);
            assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
            Instant returned = Instant.parse(objectMapper.readTree(response.body()).get("updated_at").asText());
            Instant persisted = jdbc.queryForObject("SELECT updated_at FROM user_profiles WHERE user_id = ?",
                    (row, index) -> row.getTimestamp(1).toInstant(), user.getUserId());
            assertThat(returned).as("timestamp for PATCH %s", body).isEqualTo(persisted);
        }
    }

    @ParameterizedTest
    @CsvSource({"/users/me,false", "/users/me,true", "/api/v1/users/me,false", "/api/v1/users/me,true"})
    void rejectedPatchesPreserveAccountAndProfileIncludingTimestamps(String path, boolean profileExists) throws Exception {
        User user = userRepository.saveAndFlush(User.builder().email(email).fullName("Original Name")
                .passwordHash("unused-test-hash").build());
        String token = jwtService.generateToken(user);
        if (profileExists) {
            assertThat(patch(path, "{\"bio\":\"Original bio\",\"locale\":\"vi-VN\"}", token).statusCode())
                    .isEqualTo(200);
        }
        var userBefore = jdbc.queryForMap("SELECT * FROM users WHERE user_id = ?", user.getUserId());
        var profilesBefore = jdbc.queryForList("SELECT * FROM user_profiles WHERE user_id = ?", user.getUserId());

        for (String body : new String[]{"{}", "{\"full_name\":null}",
                "{\"full_name\":null,\"bio\":\"Must not persist\",\"locale\":null}"}) {
            var response = patch(path, body, token);
            assertThat(response.statusCode()).as("PATCH %s: %s", body, response.body()).isEqualTo(400);
            var error = objectMapper.readTree(response.body());
            assertErrorEnvelope(error);
            assertThat(error.get("code").asText()).isEqualTo("VALIDATION_ERROR");
            if (!body.equals("{}")) {
                assertThat(validationMessage(error, "full_name")).isEqualTo("Full name must not be null");
            }
            assertThat(jdbc.queryForMap("SELECT * FROM users WHERE user_id = ?", user.getUserId()))
                    .as("account values and updated_at after PATCH %s", body).isEqualTo(userBefore);
            assertThat(jdbc.queryForList("SELECT * FROM user_profiles WHERE user_id = ?", user.getUserId()))
                    .as("profile existence, values and updated_at after PATCH %s", body).isEqualTo(profilesBefore);
        }
    }

    static Stream<Arguments> malformedProfileUnicode() {
        return Stream.of("full_name", "bio", "avatar_url", "phone_number", "locale", "timezone")
                .flatMap(field -> vn.edu.hcmut.co3103.identity.support.UnicodeInputs.malformedUnicode()
                        .map(value -> Arguments.of(field, value)));
    }

    @ParameterizedTest
    @MethodSource("malformedProfileUnicode")
    void malformedUnicodeNeverMutatesProfileOrTimestamps(String field, String value) throws Exception {
        String text = field.equals("avatar_url") ? "https://example.com/" + value : value;
        assertRejectedPatchPreservesRows("{\"" + field + "\":"
                + vn.edu.hcmut.co3103.identity.support.UnicodeInputs.jsonString(text) + "}",
                "VALIDATION_ERROR", field);
    }

    @ParameterizedTest
    @ValueSource(strings = {"\"\"", "\"\\t\\n\"", "[2000,1,2]", "{\"year\":2000}", "946771200000", "1.5", "true",
            "\"2000-01-02T00:00:00Z\"", "\" 2000-01-02\"", "\"2000-01-02 \"", "\"2000-1-2\"",
            "\"2001-02-29\"", "\"2000-02-30\"", "\"2000-13-01\"", "\"-5000-01-01\""})
    void invalidBirthDateShapesNeverMutateProfileOrTimestamps(String value) throws Exception {
        assertRejectedPatchPreservesRows("{\"full_name\":\"Must not persist\",\"bio\":\"Must not persist\","
                + "\"date_of_birth\":" + value + "}", "BAD_REQUEST", null);
    }

    private void assertRejectedPatchPreservesRows(String body, String code, String field) throws Exception {
        User user = userRepository.saveAndFlush(User.builder().email(email).fullName("Original Name")
                .passwordHash("unused-test-hash").build());
        String token = jwtService.generateToken(user);
        assertThat(patch(PATH, """
                {"bio":"Original bio","date_of_birth":"2000-01-02","phone_number":"123",
                 "avatar_url":"https://example.com/avatar.png","locale":"vi","timezone":"UTC"}
                """, token).statusCode()).isEqualTo(200);
        var userBefore = jdbc.queryForMap("SELECT * FROM users WHERE user_id = ?", user.getUserId());
        var profileBefore = jdbc.queryForMap("SELECT * FROM user_profiles WHERE user_id = ?", user.getUserId());
        for (String path : new String[]{"/users/me", PATH}) {
            var response = patch(path, body, token);
            assertThat(response.statusCode()).as(response.body()).isEqualTo(400);
            var error = objectMapper.readTree(response.body());
            assertErrorEnvelope(error);
            assertThat(error.get("code").asText()).isEqualTo(code);

            if (field != null) assertThat(validationMessage(error, field)).isNotBlank();
            assertThat(jdbc.queryForMap("SELECT * FROM users WHERE user_id = ?", user.getUserId())).isEqualTo(userBefore);
            assertThat(jdbc.queryForMap("SELECT * FROM user_profiles WHERE user_id = ?", user.getUserId())).isEqualTo(profileBefore);
        }
    }

    @Test
    void supplementaryUnicodeRoundTripsAllProfileText() throws Exception {
        User user = userRepository.saveAndFlush(User.builder().email(email).fullName("Original Name")
                .passwordHash("unused-test-hash").build());
        String token = jwtService.generateToken(user);
        var fields = new HashMap<String, String>();
        for (String field : new String[]{"full_name", "bio", "avatar_url", "phone_number", "locale", "timezone"}) {
            fields.put(field, field.equals("avatar_url") ? "https://example.com/😀" : "Nguyễn 😀");
        }
        assertThat(patch(PATH, objectMapper.writeValueAsString(fields), token).statusCode()).isEqualTo(200);
        var actual = objectMapper.readTree(send(PATH, null, token).body());
        fields.forEach((field, value) -> assertThat((field.equals("full_name") ? actual : actual.get("profile"))
                .get(field).asText()).isEqualTo(value));
    }

    private void assertProfileRoutesMatch(String token, JsonNode expected) throws Exception {
        for (String path : new String[]{"/users/me", "/api/v1/users/me", "/users/me/profile", "/api/v1/users/me/profile"}) {
            HttpResponse<String> response = send(path, null, token);
            assertThat(response.statusCode()).as(path + ": " + response.body()).isEqualTo(200);
            var actual = (tools.jackson.databind.node.ObjectNode) objectMapper.readTree(response.body());
            if (path.startsWith("/users/")) {
                assertThat(actual.size()).isEqualTo(8);
                assertThat(actual.remove("id")).isEqualTo(expected.get("user_id"));
                assertThat(actual.remove("fullName")).isEqualTo(expected.get("full_name"));
                assertThat(actual.remove("role").asText()).isEqualTo("USER");
            }
            assertThat(actual).isEqualTo(expected);
        }
    }

    private HttpResponse<String> patch(String path, String body, String token) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .timeout(Duration.ofSeconds(15))
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + token)
                .method("PATCH", HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }

    @ParameterizedTest
    @ValueSource(strings = {"/api/v1/users/me", "/api/users/me", "/users/me"})
    void missingExpiredAndTamperedTokensReturnBearerChallengeWithJsonUnauthorized(String path) throws Exception {
        User user = User.builder().userId(UUID.randomUUID()).email(email).fullName("Profile Student").build();
        String token = jwtService.generateToken(user);
        var claims = jwtService.extractClaim(token, value -> value);
        String kid = (String) jwtService.getJwks().get("keys").getFirst().get("kid");
        String expired = Jwts.builder().header().keyId(kid).and().claims(claims)
                .expiration(Date.from(Instant.now().minusSeconds(60)))
                .signWith(JwtTestKeys.KEY_PAIR.getPrivate(), Jwts.SIG.RS256).compact();
        for (String invalid : new String[]{null, "invalid-token", expired, token + "tampered"}) {
            assertUnauthorized(send(path, null, invalid));
        }
    }

    private HttpResponse<String> send(String path, String body, String token) throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .timeout(Duration.ofSeconds(15)).header("Accept", "application/json");
        if (token != null) {
            request.header("Authorization", "Bearer " + token);
        }
        if (body != null) {
            request.header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body));
        }
        return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    @ParameterizedTest
    @CsvSource({"\"central-identity\", true", "'[\"lms-client\",\"central-identity\"]', true",
            "\"other-service\", false", "'[\"other-service\",\"lms-client\"]', false",
            "null, false", "\"\", false", "[], false", "'[\"central-identity\",123]', false"})
    void signedAudienceRestrictionIsEnforcedOnProfileReadsAndWrites(String audienceJson, boolean accepted)
            throws Exception {
        User user = userRepository.saveAndFlush(User.builder().email(email).fullName("Profile Student")
                .passwordHash("unused-test-hash").build());
        var claims = new HashMap<>(jwtService.extractClaim(jwtService.generateToken(user, "lms-client"), value -> value));
        claims.put("aud", objectMapper.readValue(audienceJson, Object.class));
        String kid = (String) jwtService.getJwks().get("keys").getFirst().get("kid");
        String token = Jwts.builder().header().keyId(kid).and().content(objectMapper.writeValueAsBytes(claims))
                .signWith(JwtTestKeys.KEY_PAIR.getPrivate(), Jwts.SIG.RS256).compact();

        for (String path : new String[]{"/users/me", PATH}) {
            var read = send(path, null, token);
            var write = patch(path, "{\"full_name\":\"Updated Name\"}", token);
            if (accepted) {
                assertThat(read.statusCode()).as(read.body()).isEqualTo(200);
                assertThat(write.statusCode()).as(write.body()).isEqualTo(200);
            } else {
                assertUnauthorized(read);
                assertUnauthorized(write);
                assertThat(userRepository.findById(user.getUserId()).orElseThrow().getFullName())
                        .isEqualTo("Profile Student");
                assertThat(userProfileRepository.findById(user.getUserId())).isEmpty();
            }
        }
    }

    private void assertUnauthorized(HttpResponse<String> response) {
        assertThat(response.statusCode()).as(response.body()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(response.headers().allValues("WWW-Authenticate")).containsExactly("Bearer realm=\"central-identity\"");
        assertThat(response.headers().firstValue("Content-Type")).contains("application/json");
        assertThat(response.body()).isEqualTo("{\"code\":\"UNAUTHORIZED\","
                + "\"message\":\"Full authentication is required to access this resource\",\"details\":[]}");
        JsonNode error = objectMapper.readTree(response.body());
        assertErrorEnvelope(error);
    }

    @ParameterizedTest
    @ValueSource(strings = {"exp", "iat", "nbf"})
    void malformedNumericDatesReturnTheStandard401OnBothRoutePrefixes(String claim) throws Exception {
        User user = userRepository.saveAndFlush(User.builder().email(email).fullName("Profile Student")
                .passwordHash("unused-test-hash").build());
        var claims = new HashMap<>(jwtService.extractClaim(jwtService.generateToken(user), value -> value));
        claims.remove(claim);
        String json = objectMapper.writeValueAsString(claims);
        String kid = (String) jwtService.getJwks().get("keys").getFirst().get("kid");
        for (String value : new String[]{"\"1741234567\"", "null", "{}", "[]", "[1741234567]",
                "true", "false", "1e309", "-1e309", "NaN", "Infinity"}) {
            String payload = json.substring(0, json.length() - 1) + ",\"" + claim + "\":" + value + "}";
            String token = Jwts.builder().header().keyId(kid).and()
                    .content(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8))
                    .signWith(JwtTestKeys.KEY_PAIR.getPrivate(), Jwts.SIG.RS256).compact();
            for (String path : new String[]{"/users/me", PATH}) {
                assertUnauthorized(send(path, null, token));
                assertUnauthorized(patch(path, "{\"full_name\":\"Must not change\"}", token));
            }
        }
        assertThat(userRepository.findById(user.getUserId()).orElseThrow().getFullName()).isEqualTo("Profile Student");
    }
}
