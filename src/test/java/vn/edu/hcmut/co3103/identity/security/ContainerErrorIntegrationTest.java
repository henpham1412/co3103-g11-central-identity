package vn.edu.hcmut.co3103.identity.security;

import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.json.JsonMapper;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtService;

import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static vn.edu.hcmut.co3103.identity.support.ErrorResponseAssertions.assertErrorEnvelope;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(ContainerErrorIntegrationTest.Fixture.class)
class ContainerErrorIntegrationTest {
    @Value("${local.server.port}") private int port;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private UserRepository users;
    @Autowired private JwtService jwt;
    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    static Stream<Arguments> malformedPaths() {
        return Stream.of("/api/v1/users/me", "/users/me", "/api/v1/auth/register", "/auth/register")
                .flatMap(path -> Stream.of("%GG", "%00", "%", "%0", "%G0", "%2")
                        .map(suffix -> Arguments.of(path + "/" + suffix)));
    }

    @ParameterizedTest
    @MethodSource("malformedPaths")
    void rejectsMalformedPathsBeforeDispatchWithJson(String path) throws Exception {
        List<Long> before = rowCounts();
        for (String accept : List.of("application/json", "text/html")) {
            String response = exchange("POST", path, accept, null);
            assertError(response, 400, "BAD_REQUEST");
            assertThat(response).doesNotContain(path, "Tomcat", "Exception", "<html", "Invalid URI");
        }
        assertThat(rowCounts()).isEqualTo(before);
    }

    @Test
    void normalPathsStillReachApplication() throws Exception {
        String jwks = exchange("GET", "/.well-known/jwks.json", "application/json", null);
        assertThat(jwks).startsWith("HTTP/1.1 200");
        assertThat(MAPPER.readTree(body(jwks)).get("keys").isArray()).isTrue();
        assertError(exchange("GET", "/api/v1/users/me", "application/json", null), 401, "UNAUTHORIZED");
    }

    @Test
    void servletSendErrorUsesSameEnvelopeWithoutContainerReason() throws Exception {
        User user = users.saveAndFlush(User.builder().email("error-dispatch-" + UUID.randomUUID() + "@example.test")
                .passwordHash("unused-test-hash").fullName("Error dispatch fixture").build());
        try {
            String response = exchange("GET", "/test/servlet-error", "text/html", jwt.generateToken(user));
            assertError(response, 503, "SERVICE_UNAVAILABLE");
            assertThat(response).doesNotContain("private-container-reason", "<html");
        } finally {
            users.deleteById(user.getUserId());
        }
    }

    private List<Long> rowCounts() {
        return List.of("users", "user_profiles", "password_resets", "recovery_jobs").stream()
                .map(table -> jdbc.queryForObject("select count(*) from " + table, Long.class)).toList();
    }

    private String exchange(String method, String path, String accept, String token) throws IOException {
        try (Socket socket = new Socket("127.0.0.1", port)) {
            socket.setSoTimeout(10000);
            // HTTP/1.0 avoids chunk framing while exercising Tomcat's real request parser.
            String request = method + " " + path + " HTTP/1.0\r\nHost: localhost\r\nAccept: " + accept
                    + (token == null ? "" : "\r\nAuthorization: Bearer " + token)
                    + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            socket.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
            return new String(socket.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static void assertError(String response, int status, String code) {
        assertThat(response).startsWith("HTTP/1.1 " + status);
        assertThat(response.substring(0, response.indexOf("\r\n\r\n")).toLowerCase())
                .contains("content-type: application/json");
        var error = MAPPER.readTree(body(response));
        assertErrorEnvelope(error);
        assertThat(error.path("code").asText()).isEqualTo(code);
        assertThat(error.path("details").isEmpty()).isTrue();
    }

    private static String body(String response) {
        return response.substring(response.indexOf("\r\n\r\n") + 4);
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class Fixture {
        @Bean SendErrorController sendErrorController() { return new SendErrorController(); }
    }

    @RestController
    static class SendErrorController {
        @GetMapping("/test/servlet-error")
        void fail(HttpServletResponse response) throws IOException {
            response.sendError(503, "private-container-reason");
        }
    }
}
