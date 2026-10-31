package vn.edu.hcmut.co3103.identity.controller;

import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import vn.edu.hcmut.co3103.identity.config.SecurityConfig;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.entity.UserStatus;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtAuthenticationFilter;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtService;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtTestKeys;

import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import static org.hamcrest.Matchers.aMapWithSize;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(CurrentUserController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, JwtService.class})
class CurrentUserControllerTest {

    private static final String PATH = "/api/v1/users/me";

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private JwtService jwtService;
    @MockitoBean
    private UserRepository userRepository;

    private User user;

    @DynamicPropertySource
    static void rsaKeys(DynamicPropertyRegistry registry) {
        JwtTestKeys.registerProperties(registry);
    }

    @BeforeEach
    void setUp() {
        user = User.builder().userId(UUID.randomUUID()).email("student@example.com")
                .passwordHash("must-not-be-exposed").fullName("Test Student").build();
    }

    @Test
    void returnsCurrentDatabaseProfileWithoutCredentialsOrSession() throws Exception {
        String token = jwtService.generateToken(user);
        user.setFullName("Updated Student");
        when(userRepository.findById(user.getUserId())).thenReturn(Optional.of(user));

        mockMvc.perform(get(PATH).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", aMapWithSize(5)))
                .andExpect(jsonPath("$.id").value(user.getUserId().toString()))
                .andExpect(jsonPath("$.email").value(user.getEmail()))
                .andExpect(jsonPath("$.fullName").value("Updated Student"))
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE))
                .andExpect(result -> assertNull(result.getRequest().getSession(false)));
        verify(userRepository).findById(user.getUserId());
        mockMvc.perform(get(PATH)).andExpect(status().isUnauthorized());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"Basic dXNlcjpwYXNz", "Bearer", "Bearer ", "Bearer invalid-token"})
    void rejectsMissingOrMalformedBearerToken(String authorization) throws Exception {
        var request = get(PATH);
        if (authorization != null) {
            request.header(HttpHeaders.AUTHORIZATION, authorization);
        }
        mockMvc.perform(request)
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.path").value(PATH));
        verifyNoInteractions(userRepository);
    }

    @ParameterizedTest
    @ValueSource(strings = {"expired", "issuer", "signature", "algorithm", "kid", "no-expiration"})
    void rejectsInvalidSignedTokensBeforeDatabaseLookup(String failure) throws Exception {
        var claims = jwtService.extractClaim(jwtService.generateToken(user), value -> value);
        String kid = (String) jwtService.getJwks().get("keys").getFirst().get("kid");
        var builder = Jwts.builder().header().keyId(kid).and().claims(claims);
        switch (failure) {
            case "expired" -> builder.expiration(Date.from(Instant.now().minusSeconds(60)));
            case "issuer" -> builder.issuer("https://untrusted.example");
            case "kid" -> builder.header().keyId("unknown-key");
            case "no-expiration" -> builder.expiration(null);
            default -> { }
        }
        String token = failure.equals("algorithm")
                ? builder.signWith(Jwts.SIG.HS256.key().build(), Jwts.SIG.HS256).compact()
                : builder.signWith(failure.equals("signature") ? Jwts.SIG.RS256.keyPair().build().getPrivate()
                        : JwtTestKeys.KEY_PAIR.getPrivate(), Jwts.SIG.RS256).compact();
        mockMvc.perform(get(PATH).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized());
        verifyNoInteractions(userRepository);
    }

    @Test
    void rejectsDeletedAccount() throws Exception {
        when(userRepository.findById(user.getUserId())).thenReturn(Optional.empty());
        mockMvc.perform(get(PATH).header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtService.generateToken(user)))
                .andExpect(status().isUnauthorized());
    }

    @ParameterizedTest
    @EnumSource(value = UserStatus.class, names = {"SUSPENDED", "DEACTIVATED"})
    void rejectsDisabledAccountEvenWhenTokenWasIssuedWhileActive(UserStatus status) throws Exception {
        String token = jwtService.generateToken(user);
        user.setStatus(status);
        when(userRepository.findById(user.getUserId())).thenReturn(Optional.of(user));
        mockMvc.perform(get(PATH).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void rejectsLockedAccount() throws Exception {
        String token = jwtService.generateToken(user);
        user.setLockedUntil(Instant.now().plusSeconds(60));
        when(userRepository.findById(user.getUserId())).thenReturn(Optional.of(user));
        mockMvc.perform(get(PATH).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void rejectsUnsupportedResponseFormat() throws Exception {
        when(userRepository.findById(user.getUserId())).thenReturn(Optional.of(user));
        mockMvc.perform(get(PATH).accept(MediaType.APPLICATION_XML)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtService.generateToken(user)))
                .andExpect(status().isNotAcceptable());
    }
}
