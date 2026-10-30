package vn.edu.hcmut.co3103.identity.security;

import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.entity.UserStatus;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtService;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtTestKeys;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class CurrentUserHttpIntegrationTest {

    private static final String PATH = "/api/v1/users/me";

    @Value("${local.server.port}")
    private int port;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private ObjectMapper objectMapper;

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
                + ",\"fullName\":\"Profile Student\"}";
        assertThat(send("/api/v1/auth/register", registration, null).statusCode()).isEqualTo(201);
        HttpResponse<String> login = send("/api/v1/auth/login", credentials, null);
        assertThat(login.statusCode()).isEqualTo(200);
        String token = objectMapper.readTree(login.body()).get("accessToken").asText();
        User user = userRepository.findByEmail(email).orElseThrow();

        HttpResponse<String> response = send(PATH, null, token);
        assertThat(response.statusCode()).isEqualTo(200);
        JsonNode profile = objectMapper.readTree(response.body());
        assertThat(profile.size()).isEqualTo(5);
        assertThat(profile.get("id").asText()).isEqualTo(user.getUserId().toString());
        assertThat(profile.get("email").asText()).isEqualTo(email);
        assertThat(profile.get("fullName").asText()).isEqualTo("Profile Student");
        assertThat(profile.get("status").asText()).isEqualTo("ACTIVE");
        assertThat(profile.get("role").asText()).isEqualTo("USER");
        assertThat(response.headers().firstValue("Set-Cookie")).isEmpty();

        user.setFullName("Updated Profile Student");
        userRepository.saveAndFlush(user);
        HttpResponse<String> updated = send(PATH, null, token);
        assertThat(updated.statusCode()).isEqualTo(200);
        assertThat(objectMapper.readTree(updated.body()).get("fullName").asText())
                .isEqualTo("Updated Profile Student");

        user.setStatus(UserStatus.SUSPENDED);
        userRepository.saveAndFlush(user);
        assertUnauthorized(send(PATH, null, token));
        userRepository.deleteById(user.getUserId());
        assertUnauthorized(send(PATH, null, token));
    }

    @Test
    void missingExpiredAndTamperedTokensReturnJsonUnauthorized() throws Exception {
        User user = User.builder().userId(UUID.randomUUID()).email(email).fullName("Profile Student").build();
        String token = jwtService.generateToken(user);
        var claims = jwtService.extractClaim(token, value -> value);
        String kid = (String) jwtService.getJwks().get("keys").getFirst().get("kid");
        String expired = Jwts.builder().header().keyId(kid).and().claims(claims)
                .expiration(Date.from(Instant.now().minusSeconds(60)))
                .signWith(JwtTestKeys.KEY_PAIR.getPrivate(), Jwts.SIG.RS256).compact();
        for (String invalid : new String[]{null, "invalid-token", expired, token + "tampered"}) {
            assertUnauthorized(send(PATH, null, invalid));
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

    private void assertUnauthorized(HttpResponse<String> response) {
        assertThat(response.statusCode()).as(response.body()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(response.headers().firstValue("Content-Type").orElse("")).startsWith("application/json");
        JsonNode error = objectMapper.readTree(response.body());
        assertThat(error.get("status").asInt()).isEqualTo(401);
        assertThat(error.get("path").asText()).isEqualTo(PATH);
    }
}
