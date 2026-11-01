package vn.edu.hcmut.co3103.identity.security;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.jdbc.core.JdbcTemplate;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.repository.*;
import vn.edu.hcmut.co3103.identity.service.PasswordResetService;
import java.net.InetAddress;
import java.util.UUID;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "app.recovery.trusted-proxies=10.0.0.0/8,2001:db8:ffff::/48")
@AutoConfigureMockMvc
class RecoveryIpIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired UserRepository users;
    @Autowired PasswordResetRepository resets;
    @Autowired RecoveryQueue queue;
    @Autowired PasswordResetService service;
    @Autowired JdbcTemplate jdbc;
    private User user;

    @AfterEach
    void cleanup() {
        jdbc.update("DELETE FROM recovery_jobs");
        jdbc.update("DELETE FROM recovery_admissions");
        resets.deleteByUserId(user.getUserId());
        users.deleteById(user.getUserId());
    }

    @ParameterizedTest
    @CsvSource({
            "192.0.2.8, 1.1.1.1, 192.0.2.8",
            "2001:db8::8, 1.1.1.1, 2001:db8::8",
            "10.0.0.1, 192.0.2.8, 192.0.2.8",
            "10.0.0.1, 2001:db8::8, 2001:db8::8",
            "2001:db8:ffff::1, 192.0.2.8, 192.0.2.8",
            "10.0.0.1, attacker.example, 10.0.0.1"
    })
    void forgotPasswordPersistsRequestIpAcrossAsyncBoundaryAndCooldown(String peer, String header, String expected) throws Exception {
        user = users.saveAndFlush(User.builder().email("ip-" + UUID.randomUUID() + "@example.com")
                .passwordHash("unused").fullName("IP test").build());
        request(peer, header);
        service.issuePasswordReset(queue.claim(false));
        var reset = resets.findByUserIdOrderByCreatedAtDesc(user.getUserId()).getFirst();
        assertThat(reset.getIpRequested()).isEqualTo(InetAddress.ofLiteral(expected));
        request("192.0.2.99", "9.9.9.9");
        service.issuePasswordReset(queue.claim(false));
        assertThat(resets.findByUserIdOrderByCreatedAtDesc(user.getUserId())).hasSize(1);
        assertThat(resets.findById(reset.getResetId()).orElseThrow().getIpRequested()).isEqualTo(reset.getIpRequested());
    }

    private void request(String peer, String header) throws Exception {
        mvc.perform(post("/api/v1/auth/forgot-password").with(request -> { request.setRemoteAddr(peer); return request; })
                .header("X-Forwarded-For", header).contentType("application/json")
                .content("{\"email\":\"" + user.getEmail() + "\"}")).andExpect(status().isOk());
    }
}
