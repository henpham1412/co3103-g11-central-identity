package vn.edu.hcmut.co3103.identity.config;

import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
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
import org.springframework.transaction.CannotCreateTransactionException;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.entity.UserStatus;
import vn.edu.hcmut.co3103.identity.exception.GlobalExceptionHandler;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtAuthenticationFilter;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtService;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtTestKeys;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import vn.edu.hcmut.co3103.identity.security.IdentityUserDetails;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

import static vn.edu.hcmut.co3103.identity.support.ErrorResponseAssertions.errorEnvelope;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringJUnitWebConfig(SecurityConfigTest.TestConfig.class)
@TestPropertySource(properties = {
        "jwt.issuer=https://identity.example.com",
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

    @DynamicPropertySource
    static void rsaKeys(DynamicPropertyRegistry registry) {
        JwtTestKeys.registerProperties(registry);
    }

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).alwaysExpect(errorEnvelope()).build();
        user = User.builder()
                .userId(UUID.fromString("00000000-0000-0000-0000-000000000000"))
                .email(EMAIL)
                .fullName("Test Student")
                .passwordHash(passwordEncoder.encode(PASSWORD))
                .build();
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        when(userRepository.findById(user.getUserId())).thenReturn(Optional.of(user));
    }

    @Test
    void permitsPublicEndpointsWithoutAuthenticationOrCsrf() throws Exception {
        for (String prefix : new String[]{"/auth", "/api/v1/auth"}) {
            for (String endpoint : new String[]{"/login", "/register", "/forgot-password", "/reset-password"}) {
                mockMvc.perform(post(prefix + endpoint))
                        .andExpect(status().isOk()).andExpect(content().string("public"));
            }
        }
        for (String path : new String[]{"/actuator/health", "/.well-known/jwks.json", "/v3/api-docs",
                "/v3/api-docs/swagger-config", "/swagger-ui/index.html", "/swagger-ui.html"}) {
            mockMvc.perform(get(path)).andExpect(status().isOk()).andExpect(content().string("public"));
        }
    }

    @Test
    void disablesServletContainerRegistrationForJwtFilter() {
        assertFalse(jwtFilterRegistration.isEnabled());
    }

    @Test
    void requiresBearerTokenOutsidePublicRouteAndMethodAllowlist() throws Exception {
        for (String path : new String[]{"/auth/login", "/api/v1/auth/register", "/auth/forgot-password",
                "/api/v1/auth/reset-password", "/api/v1/auth", "/api/v1/auth/secret", "/api/v1/auth/logout",
                "/api/v1/auth/refresh", "/api/v1/auth/login/extra", "/api/v1/auth/register/extra",
                "/actuator/info", "/actuator/health/readiness", "/users/me", "/api/v1/users/me"}) {
            mockMvc.perform(get(path)).andExpect(status().isUnauthorized());
        }
        for (String path : new String[]{"/actuator/health", "/.well-known/jwks.json"}) {
            mockMvc.perform(post(path)).andExpect(status().isUnauthorized());
        }
    }

    @Test
    void permitsAuthenticatedRequestsOutsidePublicAllowlist() throws Exception {
        String token = jwtService.generateToken(user, "lms-client");
        for (String path : new String[]{"/api/v1/auth/login", "/api/v1/auth/secret", "/actuator/info", "/users/me"}) {
            mockMvc.perform(get(path).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                    .andExpect(status().isOk()).andExpect(content().string(EMAIL));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://localhost:3000", "http://localhost:5173"})
    void permitsCorsPreflightWithoutAuthentication(String origin) throws Exception {
        mockMvc.perform(options("/api/v1/users/me")
                        .header(HttpHeaders.ORIGIN, origin)
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "PATCH")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS,
                                "Authorization, Content-Type, X-Request-Id"))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin))
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS,
                        "GET,POST,PUT,PATCH,DELETE,OPTIONS"))
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS,
                        "Authorization, Content-Type, X-Request-Id"))
                .andExpect(content().string(""));
    }

    @ParameterizedTest
    @CsvSource({
            "https://untrusted.example, POST",
            "http://localhost:3000, TRACE"
    })
    void rejectsCorsPreflightForDisallowedOriginsOrMethods(String origin, String method) throws Exception {
        mockMvc.perform(options("/api/v1/users/me")
                        .accept(MediaType.APPLICATION_XML)
                        .header(HttpHeaders.ORIGIN, origin)
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, method))
                .andExpect(status().isForbidden())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.message").value("Invalid CORS request"))
                .andExpect(jsonPath("$.code").value("CORS_REJECTED"))
                .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    @Test
    void rejectsUntrustedOriginOnPublicPostWithJson() throws Exception {
        mockMvc.perform(post("/api/v1/auth/login").header(HttpHeaders.ORIGIN, "https://untrusted.example"))
                .andExpect(status().isForbidden())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.message").value("Invalid CORS request"))
                .andExpect(jsonPath("$.code").value("CORS_REJECTED"))
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
        for (String path : new String[]{"/api/v1/users/me", "/api/users/me", "/users/me"}) {
            var request = get(path);
            if (authorization != null) {
                request.header(HttpHeaders.AUTHORIZATION, authorization);
            }
            mockMvc.perform(request.accept(MediaType.APPLICATION_XML))
                    .andExpect(status().isUnauthorized())
                    .andExpect(header().stringValues(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"central-identity\""))
                    .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                    .andExpect(content().string("{\"code\":\"UNAUTHORIZED\","
                            + "\"message\":\"Full authentication is required to access this resource\",\"details\":[]}"));
        }
    }

    @Test
    void accessDeniedReturnsJsonForbiddenEvenWhenClientAcceptsXml() throws Exception {
        mockMvc.perform(get("/api/v1/admin").accept(MediaType.APPLICATION_XML)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtService.generateToken(user)))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist(HttpHeaders.WWW_AUTHENTICATE))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.message").value("Access is denied"))
                .andExpect(jsonPath("$.code").value("ACCESS_DENIED"));
    }

    @ParameterizedTest
    @MethodSource("lookupFailures")
    void lookupFailureReturnsJsonServerErrorInsteadOfUnauthorized(RuntimeException failure) throws Exception {
        when(userRepository.findById(user.getUserId())).thenThrow(failure);

        mockMvc.perform(get("/api/v1/users/me").accept(MediaType.APPLICATION_XML)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtService.generateToken(user)))
                .andExpect(status().isInternalServerError())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.message").value("An unexpected internal error occurred"))
                .andExpect(jsonPath("$.code").value("INTERNAL_SERVER_ERROR"))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("Sensitive database"))));
    }

    static Stream<RuntimeException> lookupFailures() {
        return Stream.of(
                new DataAccessResourceFailureException("Sensitive database connection details"),
                new CannotCreateTransactionException("Sensitive database transaction details"),
                new IllegalArgumentException("Sensitive database lookup details"));
    }

    @Test
    void authenticatesBearerTokenAndKeepsRequestsStateless() throws Exception {
        mockMvc.perform(post("/api/v1/users/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtService.generateToken(user, "lms-client")))
                .andExpect(status().isOk())
                .andExpect(content().string(EMAIL))
                .andExpect(result -> assertNull(result.getRequest().getSession(false)));
        verify(userRepository).findById(user.getUserId());
        verify(userRepository, never()).findByEmail(EMAIL);

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
        String expiredToken = Jwts.builder().header().keyId((String) jwtService.getJwks().get("keys").getFirst().get("kid"))
                .and().issuer(jwtProperties.getIssuer()).subject(EMAIL)
                .expiration(Date.from(Instant.now().minusSeconds(60)))
                .signWith(JwtTestKeys.KEY_PAIR.getPrivate(), Jwts.SIG.RS256)
                .compact();
        String tamperedToken = jwtService.generateToken(user, "lms-client") + "tampered";

        for (String token : new String[]{expiredToken, tamperedToken}) {
            mockMvc.perform(get("/api/v1/users/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Test
    void rejectsTokenForDeletedUser() throws Exception {
        when(userRepository.findById(user.getUserId())).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/v1/users/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtService.generateToken(user, "lms-client")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void retainsDatabaseUuidInAuthenticatedPrincipal() throws Exception {
        mockMvc.perform(get("/api/v1/identity")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtService.generateToken(user)))
                .andExpect(status().isOk())
                .andExpect(content().string(user.getUserId().toString()));
        verify(userRepository).findById(user.getUserId());
        verify(userRepository, never()).findByEmail(EMAIL);
    }

    @Test
    void rejectsOldTokenAfterEmailIsReusedByAnotherAccount() throws Exception {
        String oldToken = jwtService.generateToken(user);
        UUID oldId = user.getUserId();
        user.setUserId(UUID.randomUUID());
        when(userRepository.findById(oldId)).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/v1/users/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + oldToken))
                .andExpect(status().isUnauthorized());
        verify(userRepository).findById(oldId);
        verify(userRepository, never()).findByEmail(EMAIL);
    }

    @Test
    void rejectsEmailChangeButAllowsEmailCaseDifferences() throws Exception {
        String token = jwtService.generateToken(user);
        user.setEmail("STUDENT@EXAMPLE.COM");
        mockMvc.perform(get("/api/v1/users/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk());
        user.setEmail("new@example.com");
        mockMvc.perform(get("/api/v1/users/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @ParameterizedTest
    @ValueSource(strings = {"student@example.com", "not-a-uuid", "1-1-1-1-1",
            "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"})
    void rejectsInvalidUuidBeforeDatabaseLookup(String subject) throws Exception {
        String token = Jwts.builder().header().keyId((String) jwtService.getJwks().get("keys").getFirst().get("kid"))
                .and().issuer(jwtProperties.getIssuer()).subject(subject).claim("userId", subject)
                .claim("email", EMAIL).claim("role", "USER").claim("fullName", user.getFullName())
                .claim("clientId", "lms-client")
                .expiration(Date.from(Instant.now().plusSeconds(60)))
                .signWith(JwtTestKeys.KEY_PAIR.getPrivate(), Jwts.SIG.RS256)
                .compact();

        mockMvc.perform(get("/api/v1/users/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized());
        verifyNoInteractions(userRepository);
    }

    @Test
    void firewallRejectionReturnsJson400WithOriginalPathWithoutForwarding() throws Exception {
        String path = "/api/v1/auth/login;invalid";
        mockMvc.perform(post(path).accept(MediaType.APPLICATION_XML))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code").value("BAD_REQUEST"))
                .andExpect(jsonPath("$.message").isNotEmpty())
                .andExpect(result -> assertNull(result.getResponse().getForwardedUrl()))
                .andExpect(result -> assertNull(result.getResponse().getErrorMessage()));
        verifyNoInteractions(userRepository);
    }

    @ParameterizedTest
    @ValueSource(strings = {"sub", "userId", "email", "role", "fullName", "clientId"})
    void rejectsMissingIdentityClaimBeforeDatabaseLookup(String claim) throws Exception {
        var claims = new java.util.HashMap<>(jwtService.extractClaim(jwtService.generateToken(user), value -> value));
        claims.remove(claim);
        String token = Jwts.builder().header().keyId((String) jwtService.getJwks().get("keys").getFirst().get("kid"))
                .and().issuer(jwtProperties.getIssuer()).claims(claims)
                .signWith(JwtTestKeys.KEY_PAIR.getPrivate(), Jwts.SIG.RS256)
                .compact();

        mockMvc.perform(get("/api/v1/users/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized());
        verifyNoInteractions(userRepository);
    }

    @Test
    void rejectsConflictingUuidClaimsBeforeDatabaseLookup() throws Exception {
        var claims = jwtService.extractClaim(jwtService.generateToken(user), value -> value);
        String token = Jwts.builder().header().keyId((String) jwtService.getJwks().get("keys").getFirst().get("kid"))
                .and().issuer(jwtProperties.getIssuer()).claims(claims).claim("userId", UUID.randomUUID().toString())
                .signWith(JwtTestKeys.KEY_PAIR.getPrivate(), Jwts.SIG.RS256)
                .compact();

        mockMvc.perform(get("/api/v1/users/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized());
        verifyNoInteractions(userRepository);
    }

    @ParameterizedTest
    @EnumSource(value = UserStatus.class, names = {"SUSPENDED", "DEACTIVATED"})
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
        assertEquals("https://identity.example.com", jwtProperties.getIssuer());
        assertEquals(120000L, jwtProperties.getExpirationMs());
        assertEquals(600000L, jwtProperties.getRefreshExpirationMs());
    }

    @Configuration
    @EnableWebMvc
    @Import({SecurityConfig.class, JwtService.class, JwtAuthenticationFilter.class,
            GlobalExceptionHandler.class, ProbeController.class})
    static class TestConfig {
        @Bean
        ObjectMapper objectMapper() {
            return JsonMapper.builder().build();
        }
    }

    @RestController
    static class ProbeController {
        @GetMapping("/api/v1/identity")
        public String identity(Authentication authentication) {
            return ((IdentityUserDetails) authentication.getPrincipal()).getUserId().toString();
        }

        @GetMapping("/api/v1/admin")
        @PreAuthorize("hasRole('ADMIN')")
        public String admin() {
            return "admin";
        }

        @RequestMapping("/**")
        String probe(Authentication authentication) {
            return authentication == null ? "public" : authentication.getName();
        }
    }
}
