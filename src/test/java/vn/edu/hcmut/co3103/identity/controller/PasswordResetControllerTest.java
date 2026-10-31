package vn.edu.hcmut.co3103.identity.controller;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import vn.edu.hcmut.co3103.identity.config.SecurityConfig;
import vn.edu.hcmut.co3103.identity.exception.InvalidPasswordResetTokenException;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtAuthenticationFilter;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtService;
import vn.edu.hcmut.co3103.identity.service.PasswordResetService;

import static org.hamcrest.Matchers.aMapWithSize;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(PasswordResetController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, JwtService.class})
class PasswordResetControllerTest {
    @Autowired private MockMvc mvc;
    @MockitoBean private PasswordResetService service;
    @MockitoBean private UserRepository users;

    @ParameterizedTest
    @ValueSource(strings = {"/auth", "/api/v1/auth"})
    void forgotIsPublicAndAlwaysReturnsOnlyGenericMessage(String prefix) throws Exception {
        for (String email : new String[]{"active@example.com", "unknown@example.com", "disabled@example.com"}) {
            mvc.perform(post(prefix + "/forgot-password").contentType(MediaType.APPLICATION_JSON)
                            .content("{\"email\":\"  " + email.toUpperCase(java.util.Locale.ROOT) + "  \"}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$", aMapWithSize(1)))
                    .andExpect(jsonPath("$.message").value(
                            "If the email is eligible for recovery, password reset instructions have been sent."));
            verify(service).forgotPassword(argThat(request -> request.getEmail().equals(email)));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"/auth", "/api/v1/auth"})
    void resetIsPublicAndUsesSnakeCasePassword(String prefix) throws Exception {
        mvc.perform(post(prefix + "/reset-password").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"raw-token\",\"new_password\":\"NewPassword123!\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", aMapWithSize(1)))
                .andExpect(jsonPath("$.message").value(
                        "Password has been reset successfully. Please log in with your new password."));
        verify(service).resetPassword(argThat(request -> request.getToken().equals("raw-token")
                && request.getNewPassword().equals("NewPassword123!")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "expired", "used"})
    void invalidResetTokenReturnsSameSafeError(String token) throws Exception {
        doThrow(new InvalidPasswordResetTokenException()).when(service).resetPassword(any());
        mvc.perform(post("/auth/reset-password").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + token + "\",\"new_password\":\"NewPassword123!\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_OR_EXPIRED_RESET_TOKEN"))
                .andExpect(jsonPath("$.message").value("Invalid or expired password reset token"))
                .andExpect(jsonPath("$.path").value("/auth/reset-password"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"{}", "{\"email\":null}", "{\"email\":\" \"}", "{\"email\":\"invalid\"}",
            "{\"email\":true}", "{\"email\":\"a@example.com\",\"unknown\":1}",
            "{\"email\":\"a@example.com\",\"email\":\"b@example.com\"}", "[]", "null"})
    void invalidForgotBodyNeverInvokesService(String body) throws Exception {
        mvc.perform(post("/auth/forgot-password").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest());
        verifyNoInteractions(service);
    }

    @ParameterizedTest
    @ValueSource(strings = {"{}", "{\"token\":\"t\",\"new_password\":\"short\"}",
            "{\"token\":\" \",\"new_password\":\"NewPassword123!\"}",
            "{\"token\":\"t\",\"newPassword\":\"NewPassword123!\"}",
            "{\"token\":123,\"new_password\":\"NewPassword123!\"}",
            "{\"token\":\"t\",\"new_password\":false}",
            "{\"token\":\"t\",\"new_password\":\"NewPassword123!\"} {}"})
    void invalidResetBodyNeverInvokesService(String body) throws Exception {
        mvc.perform(post("/auth/reset-password").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest());
        verifyNoInteractions(service);
    }

    @ParameterizedTest
    @ValueSource(strings = {"a", "é", "€", "😀"})
    void validatesBcryptByteBoundaryWithSnakeCaseField(String character) throws Exception {
        int bytes = character.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        String password = character.repeat(72 / bytes);
        mvc.perform(post("/auth/reset-password").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"t\",\"new_password\":\"" + password + "a\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.validation_errors.new_password").exists());
        verifyNoInteractions(service);
        mvc.perform(post("/auth/reset-password").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"t\",\"new_password\":\"" + password + "\"}"))
                .andExpect(status().isOk());
    }

    @ParameterizedTest
    @CsvSource({"/auth/forgot-password,application/json,application/xml,406",
            "/auth/reset-password,application/json,application/xml,406",
            "/auth/forgot-password,text/plain,application/json,415",
            "/auth/reset-password,text/plain,application/json,415"})
    void rejectsUnsupportedMediaBeforeBusinessLogic(String path, String type, String accept, int status)
            throws Exception {
        mvc.perform(post(path).contentType(type).accept(accept).content("{}"))
                .andExpect(status().is(status));
        verifyNoInteractions(service);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/auth/forgot-password", "/auth/reset-password", "/auth/other"})
    void publicAccessIsLimitedToDocumentedPostRoutes(String path) throws Exception {
        mvc.perform(get(path)).andExpect(status().isUnauthorized());
        verifyNoInteractions(service);
    }
}
