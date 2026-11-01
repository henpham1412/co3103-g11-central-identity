package vn.edu.hcmut.co3103.identity.exception;

import jakarta.validation.Valid;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.password.PasswordEncoder;
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
import vn.edu.hcmut.co3103.identity.config.JwtProperties;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtService;

import java.time.Instant;
import java.sql.SQLException;
import java.util.stream.Stream;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasSize;
import static vn.edu.hcmut.co3103.identity.support.ErrorResponseAssertions.errorEnvelope;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class GlobalExceptionHandlerTest {

    private static final String REGISTER_PATH = "/api/v1/auth/register";
    private static final String LOGIN_PATH = "/api/v1/auth/login";
    private static final String REGISTER_JSON = """
            {"email":"student@example.com","password":"Password123!","full_name":"Test Student"}
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
                .alwaysExpect(errorEnvelope()).build();
    }

    @Test
    void duplicateEmailReturnsConflict() throws Exception {
        String message = "Email already registered";
        when(authService.register(any(RegisterRequest.class))).thenThrow(new DuplicateEmailException());

        expectError(REGISTER_PATH, REGISTER_JSON, 409, "Conflict", message)
                .andExpect(jsonPath("$.locked_until").doesNotExist())
                .andExpect(jsonPath("$.validation_errors").doesNotExist());
    }

    @Test
    void dataIntegrityViolationReturnsConflictWithoutDatabaseDetails() throws Exception {
        when(authService.register(any(RegisterRequest.class))).thenThrow(
                new DataIntegrityViolationException("duplicate key violates users_email_key; SQL: insert into users"));

        expectError(REGISTER_PATH, REGISTER_JSON, 409, "Conflict", "Email already registered")
                .andExpect(jsonPath("$.locked_until").doesNotExist())
                .andExpect(jsonPath("$.validation_errors").doesNotExist());
    }

    @ParameterizedTest
    @CsvSource({"23505, 500, Internal Server Error", "23514, 400, Bad Request", "23502, 400, Bad Request",
            "23503, 400, Bad Request", "22001, 400, Bad Request", "22021, 400, Bad Request",
            "XX000, 500, Internal Server Error"})
    void classifiesSqlIntegrityFailuresWithoutExposingDatabaseDetails(String sqlState, int status, String error)
            throws Exception {
        when(authService.register(any(RegisterRequest.class))).thenThrow(new DataIntegrityViolationException(
                "Sensitive SQL parameters", new SQLException("Sensitive database details", sqlState)));

        expectError(REGISTER_PATH, REGISTER_JSON, status, error, status == 500
                ? "An unexpected internal error occurred" : "Request violates a data constraint")
                .andExpect(content().string(not(containsString("Sensitive"))));
    }

    @ParameterizedTest
    @CsvSource({"users_email_key, 23505, 409, Conflict",
            "users_pkey, 23505, 500, Internal Server Error",
            "users_external_id_key, 23505, 500, Internal Server Error",
            "users_status_check, 23514, 400, Bad Request",
            "users_full_name_not_null, 23502, 400, Bad Request",
            "users_full_name, 22001, 400, Bad Request",
            "users_full_name, 22021, 400, Bad Request",
            "unknown, XX000, 500, Internal Server Error"})
    void classifiesRepositoryFailuresThroughRealServiceAndAdvice(
            String constraint, String sqlState, int status, String error) throws Exception {
        UserRepository repository = mock(UserRepository.class);
        AuthService service = new AuthService(repository, mock(PasswordEncoder.class),
                mock(JwtService.class), new JwtProperties(),
                mock(vn.edu.hcmut.co3103.identity.repository.LmsClientRepository.class),
                new vn.edu.hcmut.co3103.identity.config.LoginPolicyProperties(),
                mock(vn.edu.hcmut.co3103.identity.service.AccountNotificationService.class));
        when(repository.saveAndFlush(any(User.class))).thenThrow(new DataIntegrityViolationException(
                "Sensitive SQL parameters", new org.hibernate.exception.ConstraintViolationException(
                "Sensitive database details", new SQLException("Sensitive database details", sqlState), constraint)));
        mockMvc = MockMvcBuilders.standaloneSetup(new TestAuthController(service))
                .setControllerAdvice(new GlobalExceptionHandler()).alwaysExpect(errorEnvelope()).build();

        String message = switch (status) {
            case 409 -> "Email already registered";
            case 400 -> "Request violates a data constraint";
            default -> "An unexpected internal error occurred";
        };
        expectError(REGISTER_PATH, REGISTER_JSON, status, error, message)
                .andExpect(content().string(not(containsString("Sensitive"))));
    }

    @ParameterizedTest
    @ValueSource(strings = {REGISTER_PATH, LOGIN_PATH})
    void unsupportedMethodReturnsJson405AndAllowHeader(String path) throws Exception {
        mockMvc.perform(get(path).accept(MediaType.APPLICATION_XML))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(header().string("Allow", containsString("POST")))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code").value("METHOD_NOT_ALLOWED"))
                .andExpect(jsonPath("$.message").value("Request method is not supported"));
        verifyNoInteractions(authService);
    }

    @ParameterizedTest
    @ValueSource(strings = {REGISTER_PATH, LOGIN_PATH})
    void unsupportedRequestMediaTypeReturnsJson415(String path) throws Exception {
        mockMvc.perform(post(path).contentType(MediaType.APPLICATION_XML)
                        .accept(MediaType.APPLICATION_XML).content("<request/>"))
                .andExpect(status().isUnsupportedMediaType())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code").value("UNSUPPORTED_MEDIA_TYPE"))
                .andExpect(jsonPath("$.message").value("Request media type is not supported"));
        verifyNoInteractions(authService);
    }

    @ParameterizedTest
    @ValueSource(strings = {"application/xml", "text/plain", "image/png"})
    void unsupportedResponseMediaTypeReturnsJson406(String accept) throws Exception {
        when(authService.register(any(RegisterRequest.class)))
                .thenReturn(RegisterResponse.builder().email("student@example.com").build());

        expectError(REGISTER_PATH, REGISTER_JSON, 406, "Not Acceptable",
                "Requested response media type is not supported", accept);
    }

    @ParameterizedTest
    @MethodSource("handledFailures")
    void handledExceptionsRemainJsonForUnsupportedAcceptHeaders(RuntimeException failure,
                                                               int status, String error, String message)
            throws Exception {
        when(authService.register(any(RegisterRequest.class))).thenThrow(failure);

        for (String accept : new String[]{"application/xml", "text/plain", "image/png"}) {
            expectError(REGISTER_PATH, REGISTER_JSON, status, error, message, accept)
                    .andExpect(content().string(not(containsString("Sensitive"))));
        }
    }

    static Stream<Arguments> handledFailures() {
        return Stream.of(
                Arguments.of(new ResourceNotFoundException("Sensitive missing database record"),
                        404, "Not Found", "Requested resource was not found"),
                Arguments.of(new org.springframework.web.server.ResponseStatusException(
                                org.springframework.http.HttpStatus.UNPROCESSABLE_CONTENT, "Sensitive business details"),
                        422, "Unprocessable Content", "Unprocessable Content"),
                Arguments.of(new DuplicateEmailException(), 409, "Conflict", "Email already registered"),
                Arguments.of(new InvalidCredentialsException("Invalid email or password"),
                        401, "Unauthorized", "Invalid email or password"),
                Arguments.of(new AccountInactiveException("Account is inactive"), 403, "Forbidden", "Account is inactive"),
                Arguments.of(new AccessDeniedException("Sensitive authorization details"),
                        403, "Forbidden", "Access is denied"),
                Arguments.of(new AccountLockedException("Account is locked", Instant.now()), 423, "Locked", "Account is locked"),
                Arguments.of(new DataIntegrityViolationException("Sensitive constraint details"),
                        500, "Internal Server Error", "An unexpected internal error occurred"),
                Arguments.of(new IllegalArgumentException("Sensitive arguments"),
                        400, "Bad Request", "Invalid request argument"),
                Arguments.of(new IllegalStateException("Sensitive connection details"),
                        500, "Internal Server Error", "An unexpected internal error occurred"));
    }

    @Test
    void validationAndMalformedJsonErrorsIgnoreUnsupportedAcceptHeader() throws Exception {
        expectError(REGISTER_PATH, "{}", 400, "Bad Request", "Validation failed", "application/xml")
                .andExpect(jsonPath("$.details", hasSize(3)));
        expectError(REGISTER_PATH, "{", 400, "Bad Request",
                "Required request body is missing or malformed", "application/xml");
        verifyNoInteractions(authService);
    }

    @Test
    void invalidCredentialsReturnsUnauthorized() throws Exception {
        String message = "Invalid email or password";
        when(authService.login(any(LoginRequest.class))).thenThrow(new InvalidCredentialsException(message));

        expectError(LOGIN_PATH, LOGIN_JSON, 401, "Unauthorized", message)
                .andExpect(header().stringValues("WWW-Authenticate", "Bearer realm=\"central-identity\""));
    }

    @Test
    void frameworkUnauthorizedErrorUsesBearerRealmWithoutLeakingReason() throws Exception {
        when(authService.login(any(LoginRequest.class))).thenThrow(
                new org.springframework.web.server.ResponseStatusException(
                        org.springframework.http.HttpStatus.UNAUTHORIZED, "Sensitive authentication details"));

        mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON).content(LOGIN_JSON))
                .andExpect(status().isUnauthorized())
                .andExpect(header().stringValues("WWW-Authenticate", "Bearer realm=\"central-identity\""))
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"))
                .andExpect(jsonPath("$.message").value("Unauthorized"));
    }

    @Test
    void lockedAccountReturnsLockedWithExpiryTimestamp() throws Exception {
        String message = "Account is locked due to 5 consecutive failed login attempts";
        Instant lockedUntil = Instant.parse("2026-10-29T12:15:00Z");
        when(authService.login(any(LoginRequest.class)))
                .thenThrow(new AccountLockedException(message, lockedUntil));

        expectError(LOGIN_PATH, LOGIN_JSON, 423, "Locked", message)
                .andExpect(jsonPath("$.details[0].locked_until").value(lockedUntil.toString()));
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
                {"email":"invalid","password":"short","full_name":" "}
                """;

        expectError(REGISTER_PATH, invalidRequest, 400, "Bad Request", "Validation failed")
                .andExpect(jsonPath("$.details", hasSize(3)))
                .andExpect(jsonPath("$.details[?(@.field == 'email')].message").value(contains("Invalid email format")))
                .andExpect(jsonPath("$.details[?(@.field == 'password')].message").value(contains("Password must be between 8 and 128 characters")))
                .andExpect(jsonPath("$.details[?(@.field == 'full_name')].message").value(contains("Full name is required")))
                .andExpect(jsonPath("$.details[?(@.field == 'fullName')].message").doesNotExist());
        verifyNoInteractions(authService);
    }

    @ParameterizedTest
    @ValueSource(strings = {REGISTER_PATH, LOGIN_PATH})
    void invalidClientIdUsesSnakeCaseValidationKey(String path) throws Exception {
        String requestBody = (REGISTER_PATH.equals(path) ? REGISTER_JSON : LOGIN_JSON)
                .replace("}", ",\"client_id\":\"invalid client\"}");

        expectError(path, requestBody, 400, "Bad Request", "Validation failed")
                .andExpect(jsonPath("$.details", hasSize(1)))
                .andExpect(jsonPath("$.details[?(@.field == 'client_id')].message").value(contains("Client ID must not contain whitespace")))
                .andExpect(jsonPath("$.details[?(@.field == 'clientId')].message").doesNotExist());
        verifyNoInteractions(authService);
    }

    @Test
    void multipleViolationsOnSameFieldReturnOneValidationMessage() throws Exception {
        String invalidRequest = """
                {"email":"student@example.com","password":"","full_name":"Test Student"}
                """;

        expectError(REGISTER_PATH, invalidRequest, 400, "Bad Request", "Validation failed")
                .andExpect(jsonPath("$.details", hasSize(1)))
                .andExpect(jsonPath("$.details[?(@.field == 'password')].message").isNotEmpty());
        verifyNoInteractions(authService);
    }

    @Test
    void invalidLoginReturnsBadRequestBeforeCallingService() throws Exception {
        expectError(LOGIN_PATH, "{}", 400, "Bad Request", "Validation failed")
                .andExpect(jsonPath("$.details", hasSize(2)))
                .andExpect(jsonPath("$.details[?(@.field == 'email')].message").value(contains("Email is required")))
                .andExpect(jsonPath("$.details[?(@.field == 'password')].message").value(contains("Password is required")));
        verifyNoInteractions(authService);
    }

    private ResultActions expectError(String path, String requestBody, int statusCode,
                                      String error, String message) throws Exception {
        return expectError(path, requestBody, statusCode, error, message, MediaType.APPLICATION_JSON_VALUE);
    }

    private ResultActions expectError(String path, String requestBody, int statusCode,
                                      String error, String message, String accept) throws Exception {
        return mockMvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).accept(accept).content(requestBody))
                .andExpect(status().is(statusCode))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code").value(switch (statusCode) {
                    case 400 -> "BAD_REQUEST";
                    case 401 -> "INVALID_CREDENTIALS";
                    case 403 -> message.equals("Access is denied") ? "ACCESS_DENIED" : "ACCOUNT_NOT_ACTIVE";
                    case 404 -> "RESOURCE_NOT_FOUND";
                    case 406 -> "NOT_ACCEPTABLE";
                    case 409 -> "EMAIL_ALREADY_REGISTERED";
                    case 422 -> "UNPROCESSABLE_CONTENT";
                    case 423 -> "LOGIN_TEMPORARILY_LOCKED";
                    default -> "INTERNAL_SERVER_ERROR";
                }))
                .andExpect(jsonPath("$.message").value(message))
                .andExpect(jsonPath("$.lockedUntil").doesNotExist())
                .andExpect(jsonPath("$.validationErrors").doesNotExist());
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
