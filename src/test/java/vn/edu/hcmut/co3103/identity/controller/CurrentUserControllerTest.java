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
    @MockitoBean
    private vn.edu.hcmut.co3103.identity.service.UserService userService;

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

    @Test
    void currentUserProfileReturnsCompleteUserProfile() throws Exception {
        String token = jwtService.generateToken(user);
        when(userRepository.findById(user.getUserId())).thenReturn(Optional.of(user));

        vn.edu.hcmut.co3103.identity.dto.user.response.UserProfileResponse profileResponse =
                new vn.edu.hcmut.co3103.identity.dto.user.response.UserProfileResponse(
                        "https://example.com/avatar.png",
                        "Computer Science student",
                        "+84901234567",
                        java.time.LocalDate.of(2000, 1, 1),
                        "vi-VN",
                        "Asia/Ho_Chi_Minh"
                );
        vn.edu.hcmut.co3103.identity.dto.user.response.CurrentUserProfileResponse fullResponse =
                new vn.edu.hcmut.co3103.identity.dto.user.response.CurrentUserProfileResponse(
                        user.getUserId(),
                        user.getEmail(),
                        user.getFullName(),
                        user.getStatus(),
                        profileResponse
                );

        when(userService.getCurrentUserProfile(user.getUserId())).thenReturn(fullResponse);

        mockMvc.perform(get("/api/v1/users/me/profile").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.user_id").value(user.getUserId().toString()))
                .andExpect(jsonPath("$.email").value(user.getEmail()))
                .andExpect(jsonPath("$.full_name").value(user.getFullName()))
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andExpect(jsonPath("$.profile.avatar_url").value("https://example.com/avatar.png"))
                .andExpect(jsonPath("$.profile.bio").value("Computer Science student"))
                .andExpect(jsonPath("$.profile.phone_number").value("+84901234567"))
                .andExpect(jsonPath("$.profile.date_of_birth").value("2000-01-01"))
                .andExpect(jsonPath("$.profile.locale").value("vi-VN"))
                .andExpect(jsonPath("$.profile.timezone").value("Asia/Ho_Chi_Minh"));

        verify(userService).getCurrentUserProfile(user.getUserId());
    }

    @Test
    void updateProfileUpdatesFieldsSuccessfully() throws Exception {
        String token = jwtService.generateToken(user);
        when(userRepository.findById(user.getUserId())).thenReturn(Optional.of(user));

        Instant now = Instant.parse("2026-10-14T08:30:00Z");
        vn.edu.hcmut.co3103.identity.dto.user.response.UpdateProfileResponse updateResponse =
                new vn.edu.hcmut.co3103.identity.dto.user.response.UpdateProfileResponse("Profile updated successfully", now);
        when(userService.updateProfile(org.mockito.ArgumentMatchers.eq(user.getUserId()), org.mockito.ArgumentMatchers.any(vn.edu.hcmut.co3103.identity.dto.user.request.UpdateProfileRequest.class)))
                .thenReturn(updateResponse);

        String payload = """
                {
                  "full_name": "Nguyen Van A Updated",
                  "avatar_url": "https://example.com/new.png",
                  "bio": "New bio",
                  "phone_number": "+84912345678",
                  "date_of_birth": "1995-05-20",
                  "locale": "vi",
                  "timezone": "Asia/Ho_Chi_Minh"
                }
                """;

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch("/api/v1/users/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.message").value("Profile updated successfully"))
                .andExpect(jsonPath("$.updated_at").value("2026-10-14T08:30:00Z"));

        verify(userService).updateProfile(org.mockito.ArgumentMatchers.eq(user.getUserId()), org.mockito.ArgumentMatchers.any(vn.edu.hcmut.co3103.identity.dto.user.request.UpdateProfileRequest.class));
    }

    @Test
    void updateProfileRejectsInvalidFieldsWithValidationError() throws Exception {
        String token = jwtService.generateToken(user);
        when(userRepository.findById(user.getUserId())).thenReturn(Optional.of(user));

        String payload = """
                {
                  "avatar_url": "invalid-url",
                  "date_of_birth": "2099-01-01"
                }
                """;

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch("/api/v1/users/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));

        verifyNoInteractions(userService);
    }
}
