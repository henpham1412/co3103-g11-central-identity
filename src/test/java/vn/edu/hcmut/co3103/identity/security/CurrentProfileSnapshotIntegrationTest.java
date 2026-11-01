package vn.edu.hcmut.co3103.identity.security;

import org.aopalliance.intercept.MethodInterceptor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.aop.framework.Advised;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import tools.jackson.databind.ObjectMapper;
import vn.edu.hcmut.co3103.identity.dto.user.request.UpdateProfileRequest;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtService;
import vn.edu.hcmut.co3103.identity.service.UserService;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import static org.assertj.core.api.Assertions.*;

/** Actual HTTP/JPA/PostgreSQL; an AOP latch pauses only after the real projection query. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class CurrentProfileSnapshotIntegrationTest {
    @Autowired UserRepository users;
    @Autowired UserService profiles;
    @Autowired JwtService jwt;
    @Autowired ObjectMapper mapper;
    @Value("${local.server.port}") int port;
    private User user;
    private final HttpClient client = HttpClient.newHttpClient();

    @AfterEach
    void cleanup() {
        client.close();
        users.deleteById(user.getUserId());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void currentProfileIsOneCommittedSnapshotDuringAtomicPatch(boolean existingProfile) throws Exception {
        user = users.saveAndFlush(User.builder().email("snapshot-" + UUID.randomUUID() + "@example.com")
                .passwordHash("unused").fullName("Before name").build());
        if (existingProfile) profiles.updateProfile(user.getUserId(), UpdateProfileRequest.builder().bio("Before bio").build());
        String token = jwt.generateToken(user);
        var snapshotRead = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        MethodInterceptor pauseAfterQuery = invocation -> {
            Object snapshot = invocation.proceed();
            if (!invocation.getMethod().getName().equals("findCurrentProfile")) return snapshot;
            snapshotRead.countDown();
            assertThat(release.await(10, TimeUnit.SECONDS)).isTrue();
            return snapshot;
        };
        var advised = (Advised) users;
        advised.addAdvice(0, pauseAfterQuery);
        try {
            var get = client.sendAsync(request(token).GET().build(), HttpResponse.BodyHandlers.ofString());
            assertThat(snapshotRead.await(5, TimeUnit.SECONDS)).isTrue();
            var patch = client.send(request(token).header("Content-Type", "application/json")
                    .method("PATCH", HttpRequest.BodyPublishers.ofString("{\"full_name\":\"After name\",\"bio\":\"After bio\"}"))
                    .build(), HttpResponse.BodyHandlers.ofString());
            assertThat(patch.statusCode()).isEqualTo(200);
            release.countDown();
            var response = get.get(5, TimeUnit.SECONDS);
            assertThat(response.statusCode()).isEqualTo(200);
            var before = mapper.readTree(response.body());
            assertThat(before.get("full_name").asText()).isEqualTo("Before name");
            if (existingProfile) assertThat(before.get("profile").get("bio").asText()).isEqualTo("Before bio");
            else assertThat(before.get("profile").isNull()).isTrue();
            var after = mapper.readTree(client.send(request(token).GET().build(), HttpResponse.BodyHandlers.ofString()).body());
            assertThat(after.get("full_name").asText()).isEqualTo("After name");
            assertThat(after.get("profile").get("bio").asText()).isEqualTo("After bio");
        } finally {
            release.countDown();
            advised.removeAdvice(pauseAfterQuery);
        }
    }

    private HttpRequest.Builder request(String token) {
        return HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/api/v1/users/me"))
                .timeout(Duration.ofSeconds(10)).header("Authorization", "Bearer " + token);
    }
}
