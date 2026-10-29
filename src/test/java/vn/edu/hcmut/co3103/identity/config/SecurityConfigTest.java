package vn.edu.hcmut.co3103.identity.config;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.web.SpringJUnitWebConfig;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.entity.UserStatus;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtAuthenticationFilter;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtService;

import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringJUnitWebConfig(SecurityConfigTest.TestConfig.class)
@TestPropertySource(properties = {
        "jwt.secret=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        "jwt.expiration-ms=120000",
        "jwt.refresh-expiration-ms=600000"
})
class SecurityConfigTest {

    private static final String EMAIL = "student@example.com";
    private static final String PASSWORD = "TestPassword123!";

    @Autowired
    private WebApplicationContext context;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private JwtProperties jwtProperties;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private FilterRegistrationBean<JwtAuthenticationFilter> jwtFilterRegistration;
    @MockitoBean
    private UserRepository userRepository;

    private MockMvc mockMvc;
    private User user;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        user = User.builder()
                .userId(UUID.fromString("00000000-0000-0000-0000-000000000000"))
                .email(EMAIL)
                .fullName("Test Student")
                .passwordHash(passwordEncoder.encode(PASSWORD))
                .build();
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
    }

    @ParameterizedTest
    @CsvSource({
            "POST, /api/v1/auth/login",
            "POST, /api/v1/auth/register",
            "GET, /actuator/health",
            "GET, /v3/api-docs",
            "POST, /v3/api-docs",
            "GET, /v3/api-docs/swagger-config",
            "POST, /v3/api-docs/swagger-config",
            "GET, /swagger-ui/index.html",
            "POST, /swagger-ui/index.html",
            "GET, /swagger-ui.html",
            "POST, /swagger-ui.html"
    })
    void permitsPublicEndpointsWithoutAuthenticationOrCsrf(String method, String path) throws Exception {
        mockMvc.perform(request(HttpMethod.valueOf(method), path))
                .andExpect(status().isOk())
                .andExpect(content().string("public"));
    }

    @Test
    void disablesServletContainerRegistrationForJwtFilter() {
        assertFalse(jwtFilterRegistration.isEnabled());
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"})
    void requiresAuthenticationForNonPostAuthRequests(String method) throws Exception {
        for (String path : new String[]{"/api/v1/auth/register", "/api/v1/auth/login"}) {
            mockMvc.perform(request(HttpMethod.valueOf(method), path))
                    .andExpect(status().isUnauthorized());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
    void requiresAuthenticationForNonGetHealthRequests(String method) throws Exception {
        mockMvc.perform(request(HttpMethod.valueOf(method), "/actuator/health"))
                .andExpect(status().isUnauthorized());
    }

    @ParameterizedTest
    @ValueSource(strings = {"/api/v1/auth", "/api/v1/auth/secret", "/api/v1/auth/logout",
            "/api/v1/auth/login/extra", "/api/v1/auth/register/extra", "/actuator", "/actuator/info",
            "/actuator/metrics", "/actuator/env", "/actuator/health/readiness", "/api/v1/users/me"})
    void requiresAuthenticationForOtherRoutes(String path) throws Exception {
        for (String method : new String[]{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}) {
            mockMvc.perform(request(HttpMethod.valueOf(method), path))
                    .andExpect(status().isUnauthorized());
        }
    }

    @ParameterizedTest
    @CsvSource({
            "GET, /api/v1/auth/login",
            "GET, /api/v1/auth/register",
            "POST, /actuator/health",
            "GET, /api/v1/auth/secret",
            "GET, /actuator/info"
    })
    void permitsAuthenticatedRequestsOutsidePublicAllowlist(String method, String path) throws Exception {
        mockMvc.perform(request(HttpMethod.valueOf(method), path)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtService.generateToken(user, "lms-client")))
                .andExpect(status().isOk())
                .andExpect(content().string(EMAIL));
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://localhost:3000", "http://localhost:5173"})
    void permitsCorsPreflightWithoutAuthentication(String origin) throws Exception {
        for (String method : new String[]{"GET", "POST", "PUT", "DELETE", "OPTIONS"}) {
            mockMvc.perform(options("/api/v1/users/me")
                            .header(HttpHeaders.ORIGIN, origin)
                            .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, method)
                            .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS,
                                    "Authorization, Content-Type, X-Request-Id"))
                    .andExpect(status().isOk())
                    .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin))
                    .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS,
                            "GET,POST,PUT,DELETE,OPTIONS"))
                    .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS,
                            "Authorization, Content-Type, X-Request-Id"))
                    .andExpect(content().string(""));
        }
    }

    @ParameterizedTest
    @CsvSource({
            "http://untrusted.example, POST",
            "http://localhost:3000, PATCH"
    })
    void rejectsCorsPreflightForDisallowedOriginsOrMethods(String origin, String method) throws Exception {
        mockMvc.perform(options("/api/v1/users/me")
                        .header(HttpHeaders.ORIGIN, origin)
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, method))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    @Test
    void appliesCorsHeadersWithoutBypassingAuthentication() throws Exception {
        String origin = "http://localhost:5173";
        mockMvc.perform(post("/api/v1/auth/login").header(HttpHeaders.ORIGIN, origin))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin));

        mockMvc.perform(get("/api/v1/auth/secret").header(HttpHeaders.ORIGIN, origin))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin));

        mockMvc.perform(get("/api/v1/users/me")
                        .header(HttpHeaders.ORIGIN, origin)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtService.generateToken(user, "lms-client")))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin))
                .andExpect(content().string(EMAIL));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"Basic dXNlcjpwYXNz", "Bearer", "Bearer ", "Bearer invalid-token"})
    void rejectsProtectedRequestWithoutValidBearerToken(String authorization) throws Exception {
        var request = get("/api/v1/users/me");
        if (authorization != null) {
            request.header(HttpHeaders.AUTHORIZATION, authorization);
        }
        mockMvc.perform(request).andExpect(status().isUnauthorized());
    }

    @Test
    void authenticatesBearerTokenAndKeepsRequestsStateless() throws Exception {
        mockMvc.perform(post("/api/v1/users/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtService.generateToken(user, "lms-client")))
                .andExpect(status().isOk())
                .andExpect(content().string(EMAIL))
                .andExpect(result -> assertNull(result.getRequest().getSession(false)));
        verify(userRepository).findByEmail(EMAIL);

        mockMvc.perform(get("/api/v1/users/me")).andExpect(status().isUnauthorized());
    }

    @Test
    void acceptsCaseInsensitiveBearerScheme() throws Exception {
        mockMvc.perform(get("/api/v1/users/me")
                        .header(HttpHeaders.AUTHORIZATION, "bearer " + jwtService.generateToken(user, "lms-client")))
                .andExpect(status().isOk())
                .andExpect(content().string(EMAIL));
    }

    @Test
    void invalidTokenDoesNotBlockPublicEndpoint() throws Exception {
        mockMvc.perform(post("/api/v1/auth/login").header(HttpHeaders.AUTHORIZATION, "Bearer invalid-token"))
                .andExpect(status().isOk());
    }

    @Test
    void rejectsExpiredAndTamperedTokensWithoutServerError() throws Exception {
        String expiredToken = Jwts.builder().subject(EMAIL)
                .expiration(Date.from(Instant.now().minusSeconds(60)))
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtProperties.getSecret())))
                .compact();
        String tamperedToken = jwtService.generateToken(user, "lms-client") + "tampered";

        for (String token : new String[]{expiredToken, tamperedToken}) {
            mockMvc.perform(get("/api/v1/users/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Test
    void rejectsTokenForDeletedUser() throws Exception {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/v1/users/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtService.generateToken(user, "lms-client")))
                .andExpect(status().isUnauthorized());
    }

    @ParameterizedTest
    @EnumSource(value = UserStatus.class, names = {"INACTIVE", "SUSPENDED", "DEACTIVATED"})
    void rejectsInactiveUsersForBothJwtAndPasswordAuthentication(UserStatus status) throws Exception {
        user.setStatus(status);

        mockMvc.perform(get("/api/v1/users/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtService.generateToken(user, "lms-client")))
                .andExpect(status().isUnauthorized());
        assertThrows(DisabledException.class, () -> authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(EMAIL, PASSWORD)));
    }

    @Test
    void rejectsLockedUserAndAcceptsUserAfterLockHasExpired() throws Exception {
        String token = jwtService.generateToken(user, "lms-client");
        user.setLockedUntil(Instant.now().plusSeconds(60));

        mockMvc.perform(get("/api/v1/users/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized());
        assertThrows(LockedException.class, () -> authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(EMAIL, PASSWORD)));

        user.setLockedUntil(Instant.now().minusSeconds(60));
        mockMvc.perform(get("/api/v1/users/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    void authenticatesRepositoryUserWithBcryptAndRejectsWrongPassword() {
        Authentication authentication = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(EMAIL, PASSWORD));

        assertTrue(authentication.isAuthenticated());
        assertEquals(EMAIL, authentication.getName());
        assertTrue(((UserDetails) authentication.getPrincipal()).getAuthorities().isEmpty());
        assertTrue(user.getPasswordHash().startsWith("$2a$"));
        assertThrows(BadCredentialsException.class, () -> authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(EMAIL, "wrong-password")));
    }

    @Test
    void bindsJwtConfigurationProperties() {
        assertEquals(120000L, jwtProperties.getExpirationMs());
        assertEquals(600000L, jwtProperties.getRefreshExpirationMs());
    }

    @Configuration
    @EnableWebMvc
    @Import({SecurityConfig.class, JwtService.class, JwtAuthenticationFilter.class, ProbeController.class})
    static class TestConfig {
    }

    @RestController
    static class ProbeController {
        @RequestMapping("/**")
        String probe(Authentication authentication) {
            return authentication == null ? "public" : authentication.getName();
        }
    }
}
