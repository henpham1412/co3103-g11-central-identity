package vn.edu.hcmut.co3103.identity.exception;

import jakarta.validation.Valid;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import vn.edu.hcmut.co3103.identity.dto.auth.request.LoginRequest;
import vn.edu.hcmut.co3103.identity.dto.auth.request.RegisterRequest;
import vn.edu.hcmut.co3103.identity.dto.auth.response.AuthResponse;
import vn.edu.hcmut.co3103.identity.dto.auth.response.RegisterResponse;
import vn.edu.hcmut.co3103.identity.service.AuthService;

import java.time.Instant;

import static org.hamcrest.Matchers.aMapWithSize;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class GlobalExceptionHandlerTest {

    private static final String REGISTER_PATH = "/api/v1/auth/register";
    private static final String LOGIN_PATH = "/api/v1/auth/login";
    private static final String REGISTER_JSON = """
            {"email":"student@example.com","password":"Password123!","fullName":"Test Student"}
            """;
    private static final String LOGIN_JSON = """
            {"email":"student@example.com","password":"Password123!"}
            """;

    @Mock
    private AuthService authService;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(new TestAuthController(authService))
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void duplicateEmailReturnsConflict() throws Exception {
        String message = "Email already exists: student@example.com";
        when(authService.register(any(RegisterRequest.class))).thenThrow(new DuplicateEmailException(message));

        expectError(REGISTER_PATH, REGISTER_JSON, 409, "Conflict", message)
                .andExpect(jsonPath("$.lockedUntil").doesNotExist())
                .andExpect(jsonPath("$.validationErrors").doesNotExist());
    }

    @Test
    void dataIntegrityViolationReturnsConflictWithoutDatabaseDetails() throws Exception {
        when(authService.register(any(RegisterRequest.class))).thenThrow(
                new DataIntegrityViolationException("duplicate key violates users_email_key; SQL: insert into users"));

        expectError(REGISTER_PATH, REGISTER_JSON, 409, "Conflict", "Data conflicts with an existing record")
                .andExpect(jsonPath("$.lockedUntil").doesNotExist())
                .andExpect(jsonPath("$.validationErrors").doesNotExist());
    }

    @Test
    void invalidCredentialsReturnsUnauthorized() throws Exception {
        String message = "Invalid email or password";
        when(authService.login(any(LoginRequest.class))).thenThrow(new InvalidCredentialsException(message));

        expectError(LOGIN_PATH, LOGIN_JSON, 401, "Unauthorized", message);
    }

    @Test
    void lockedAccountReturnsLockedWithExpiryTimestamp() throws Exception {
        String message = "Account is locked due to 5 consecutive failed login attempts";
        Instant lockedUntil = Instant.parse("2026-10-29T12:15:00Z");
        when(authService.login(any(LoginRequest.class)))
                .thenThrow(new AccountLockedException(message, lockedUntil));

        expectError(LOGIN_PATH, LOGIN_JSON, 423, "Locked", message)
                .andExpect(jsonPath("$.lockedUntil").value(lockedUntil.toString()));
    }

    @Test
    void inactiveAccountReturnsForbidden() throws Exception {
        String message = "Account is inactive";
        when(authService.login(any(LoginRequest.class))).thenThrow(new AccountInactiveException(message));

        expectError(LOGIN_PATH, LOGIN_JSON, 403, "Forbidden", message);
    }

    @Test
    void invalidRegistrationReturnsBadRequestWithFieldErrors() throws Exception {
        String invalidRequest = """
                {"email":"invalid","password":"short","fullName":" "}
                """;

        expectError(REGISTER_PATH, invalidRequest, 400, "Bad Request", "Validation failed")
                .andExpect(jsonPath("$.validationErrors", aMapWithSize(3)))
                .andExpect(jsonPath("$.validationErrors.email").value("Invalid email format"))
                .andExpect(jsonPath("$.validationErrors.password")
                        .value("Password must be between 8 and 128 characters"))
                .andExpect(jsonPath("$.validationErrors.fullName").value("Full name is required"));
        verifyNoInteractions(authService);
    }

    @Test
    void multipleViolationsOnSameFieldReturnOneValidationMessage() throws Exception {
        String invalidRequest = """
                {"email":"student@example.com","password":"","fullName":"Test Student"}
                """;

        expectError(REGISTER_PATH, invalidRequest, 400, "Bad Request", "Validation failed")
                .andExpect(jsonPath("$.validationErrors", aMapWithSize(1)))
                .andExpect(jsonPath("$.validationErrors.password").isNotEmpty());
        verifyNoInteractions(authService);
    }

    @Test
    void invalidLoginReturnsBadRequestBeforeCallingService() throws Exception {
        expectError(LOGIN_PATH, "{}", 400, "Bad Request", "Validation failed")
                .andExpect(jsonPath("$.validationErrors", aMapWithSize(2)))
                .andExpect(jsonPath("$.validationErrors.email").value("Email is required"))
                .andExpect(jsonPath("$.validationErrors.password").value("Password is required"));
        verifyNoInteractions(authService);
    }

    private ResultActions expectError(String path, String requestBody, int statusCode,
                                      String error, String message) throws Exception {
        return mockMvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(requestBody))
                .andExpect(status().is(statusCode))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value(statusCode))
                .andExpect(jsonPath("$.error").value(error))
                .andExpect(jsonPath("$.message").value(message))
                .andExpect(jsonPath("$.path").value(path))
                .andExpect(jsonPath("$.timestamp").isNotEmpty());
    }

    @RestController
    static class TestAuthController {

        private final AuthService authService;

        TestAuthController(AuthService authService) {
            this.authService = authService;
        }

        @PostMapping(REGISTER_PATH)
        RegisterResponse register(@Valid @RequestBody RegisterRequest request) {
            return authService.register(request);
        }

        @PostMapping(LOGIN_PATH)
        AuthResponse login(@Valid @RequestBody LoginRequest request) {
            return authService.login(request);
        }
    }
}
