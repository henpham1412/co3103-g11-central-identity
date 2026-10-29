package vn.edu.hcmut.co3103.identity.controller;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import vn.edu.hcmut.co3103.identity.config.JwtProperties;
import vn.edu.hcmut.co3103.identity.config.SecurityConfig;
import vn.edu.hcmut.co3103.identity.dto.auth.request.LoginRequest;
import vn.edu.hcmut.co3103.identity.dto.auth.request.RegisterRequest;
import vn.edu.hcmut.co3103.identity.dto.auth.response.AuthResponse;
import vn.edu.hcmut.co3103.identity.dto.auth.response.RegisterResponse;
import vn.edu.hcmut.co3103.identity.entity.UserStatus;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.exception.AccountInactiveException;
import vn.edu.hcmut.co3103.identity.exception.AccountLockedException;
import vn.edu.hcmut.co3103.identity.exception.DuplicateEmailException;
import vn.edu.hcmut.co3103.identity.exception.InvalidCredentialsException;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtAuthenticationFilter;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtService;
import vn.edu.hcmut.co3103.identity.service.AuthService;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.UUID;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.isOneOf;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(value = AuthController.class,
        properties = "jwt.secret=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, JwtService.class})
class AuthControllerTest {

    private static final String REGISTER_PATH = "/api/v1/auth/register";
    private static final String LOGIN_PATH = "/api/v1/auth/login";
    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000007");
    private static final String EMAIL = "student@example.com";
    private static final String PASSWORD = "Password123!";
    private static final String FULL_NAME = "Test Student";
    private static final String REGISTER_JSON = """
            {"email":"student@example.com","password":"Password123!","fullName":"Test Student","clientId":"lms-client"}
            """;
    private static final String LOGIN_JSON = """
            {"email":"student@example.com","password":"Password123!","clientId":"lms-client"}
            """;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private JwtProperties jwtProperties;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private UserRepository userRepository;

    @Test
    void registerReturnsCreatedWithUserPayload() throws Exception {
        Instant createdAt = Instant.parse("2026-10-30T10:00:00Z");
        when(authService.register(any(RegisterRequest.class))).thenReturn(RegisterResponse.builder()
                .userId(USER_ID)
                .email(EMAIL)
                .fullName(FULL_NAME)
                .status(UserStatus.ACTIVE)
                .createdAt(createdAt)
                .build());

        mockMvc.perform(post(REGISTER_PATH).contentType(MediaType.APPLICATION_JSON).content(REGISTER_JSON))
                .andExpect(status().isCreated())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", aMapWithSize(5)))
                .andExpect(jsonPath("$.userId").value(USER_ID.toString()))
                .andExpect(jsonPath("$.email").value(EMAIL))
                .andExpect(jsonPath("$.fullName").value(FULL_NAME))
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andExpect(jsonPath("$.createdAt").value(createdAt.toString()));

        verify(authService).register(argThat(request -> EMAIL.equals(request.getEmail())
                && PASSWORD.equals(request.getPassword()) && FULL_NAME.equals(request.getFullName())
                && "lms-client".equals(request.getClientId())));
    }

    @Test
    void registerAndLoginNormalizeWhitespaceAndUppercaseBeforeValidation() throws Exception {
        String rawEmail = "   STUDENT.WHITESPACE@EXAMPLE.COM   ";
        String normalizedEmail = "student.whitespace@example.com";
        AuthService realService = new AuthService(userRepository, passwordEncoder, jwtService, jwtProperties);
        AtomicReference<User> savedUser = new AtomicReference<>();
        when(userRepository.saveAndFlush(any(User.class))).thenAnswer(invocation -> {
            User saved = invocation.getArgument(0);
            saved.setUserId(USER_ID);
            saved.setCreatedAt(Instant.now());
            savedUser.set(saved);
            return saved;
        });
        when(userRepository.findByEmailForUpdate(normalizedEmail))
                .thenAnswer(invocation -> Optional.ofNullable(savedUser.get()));
        when(authService.register(any(RegisterRequest.class)))
                .thenAnswer(invocation -> realService.register(invocation.getArgument(0)));
        when(authService.login(any(LoginRequest.class)))
                .thenAnswer(invocation -> realService.login(invocation.getArgument(0)));

        mockMvc.perform(post(REGISTER_PATH).contentType(MediaType.APPLICATION_JSON)
                        .content(REGISTER_JSON.replace(EMAIL, rawEmail)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value(normalizedEmail));
        mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                        .content(LOGIN_JSON.replace(EMAIL, rawEmail)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(normalizedEmail))
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(result -> {
                    String token = com.jayway.jsonpath.JsonPath.read(
                            result.getResponse().getContentAsString(), "$.accessToken");
                    assertThat(jwtService.extractUserId(token)).isEqualTo(USER_ID.toString());
                    String clientId = jwtService.extractClaim(token, claims -> claims.get("clientId", String.class));
                    assertThat(clientId).isEqualTo("lms-client");
                });
        verify(authService).register(argThat(request -> normalizedEmail.equals(request.getEmail())));
        verify(authService).login(argThat(request -> normalizedEmail.equals(request.getEmail())));
        verify(userRepository).existsByEmail(normalizedEmail);
        verify(userRepository).findByEmailForUpdate(normalizedEmail);
    }

    @ParameterizedTest
    @MethodSource("controlCharacters")
    void registerRejectsNullAndControlCharactersInFullName(int codePoint) throws Exception {
        String escapedControl = String.format("\\u%04x", codePoint);
        String requestBody = REGISTER_JSON.replace(FULL_NAME, "Test" + escapedControl + " Student");

        expectError(REGISTER_PATH, requestBody, 400, "Bad Request", "Validation failed")
                .andExpect(jsonPath("$.validationErrors.fullName").value("Full name contains invalid characters"));
        verifyNoInteractions(authService, userRepository);
    }

    static IntStream controlCharacters() {
        return IntStream.concat(IntStream.rangeClosed(0, 31), IntStream.rangeClosed(127, 159));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Nguyễn Thị Ánh", "李明", "Jose\u0301 Silva"})
    void registerAcceptsUnicodeNamesWithoutControlCharacters(String fullName) throws Exception {
        when(authService.register(any(RegisterRequest.class))).thenReturn(RegisterResponse.builder()
                .userId(USER_ID).email(EMAIL).fullName(fullName).status(UserStatus.ACTIVE).build());

        mockMvc.perform(post(REGISTER_PATH).contentType(MediaType.APPLICATION_JSON)
                        .content(REGISTER_JSON.replace(FULL_NAME, fullName)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.fullName").value(fullName));
        verify(authService).register(argThat(request -> fullName.equals(request.getFullName())));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', textBlock = """
            {"password":"Password123!","fullName":"Test Student"} | email | Email is required
            {"email":null,"password":"Password123!","fullName":"Test Student"} | email | Email is required
            {"email":"","password":"Password123!","fullName":"Test Student"} | email | Email is required
            {"email":"invalid-email","password":"Password123!","fullName":"Test Student"} | email | Invalid email format
            {"email":"student@example.com","password":"1234567","fullName":"Test Student"} | password | Password must be between 8 and 128 characters
            {"email":"student@example.com","fullName":"Test Student"} | password | Password is required
            {"email":"student@example.com","password":"Password123!"} | fullName | Full name is required
            {"email":"student@example.com","password":"Password123!","fullName":null} | fullName | Full name is required
            {"email":"student@example.com","password":"Password123!","fullName":""} | fullName | Full name is required
            {"email":"student@example.com","password":"Password123!","fullName":"   "} | fullName | Full name is required
            """)
    void registerRejectsInvalidInputBeforeCallingService(String requestBody, String field, String message)
            throws Exception {
        expectError(REGISTER_PATH, requestBody, 400, "Bad Request", "Validation failed")
                .andExpect(jsonPath("$.validationErrors", aMapWithSize(1)))
                .andExpect(jsonPath("$.validationErrors." + field).value(message));
        verifyNoInteractions(authService);
    }

    @ParameterizedTest
    @ValueSource(strings = {REGISTER_PATH, LOGIN_PATH})
    void rejectsUnsupportedAcceptBeforeCallingService(String path) throws Exception {
        for (String accept : new String[]{"application/xml", "text/plain", "image/png"}) {
            mockMvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).accept(accept)
                            .content(REGISTER_PATH.equals(path) ? REGISTER_JSON : LOGIN_JSON))
                    .andExpect(status().isNotAcceptable())
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.status").value(406))
                    .andExpect(jsonPath("$.path").value(path))
                    .andExpect(jsonPath("$.timestamp").isNotEmpty());
        }
        verifyNoInteractions(authService, userRepository);
    }

    @ParameterizedTest
    @ValueSource(strings = {REGISTER_PATH, LOGIN_PATH})
    void rejectsUnsupportedContentTypeBeforeCallingService(String path) throws Exception {
        mockMvc.perform(post(path).contentType(MediaType.APPLICATION_XML).content("<request/>"))
                .andExpect(status().isUnsupportedMediaType())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value(415));
        verifyNoInteractions(authService, userRepository);
    }

    @Test
    void registerReturnsConflictForDuplicateEmail() throws Exception {
        String message = "Email already exists: " + EMAIL;
        when(authService.register(any(RegisterRequest.class))).thenThrow(new DuplicateEmailException(message));

        expectError(REGISTER_PATH, REGISTER_JSON, 409, "Conflict", message);
        verify(authService).register(any(RegisterRequest.class));
    }

    @Test
    void registerReturnsConflictForDatabaseConstraintViolation() throws Exception {
        when(authService.register(any(RegisterRequest.class))).thenThrow(
                new DataIntegrityViolationException("duplicate key violates users_email_key"));

        expectError(REGISTER_PATH, REGISTER_JSON, 409, "Conflict", "Data conflicts with an existing record");
        verify(authService).register(any(RegisterRequest.class));
    }

    @ParameterizedTest
    @CsvSource({"a, 73", "\u20ac, 25"})
    void registerRejectsPasswordsExceedingBcryptByteLimit(String character, int repetitions) throws Exception {
        String password = character.repeat(repetitions);
        String requestBody = REGISTER_JSON.replace(PASSWORD, password);
        expectError(REGISTER_PATH, requestBody, 400, "Bad Request", "Validation failed")
                .andExpect(jsonPath("$.validationErrors.password").value("Password must not exceed 72 UTF-8 bytes"))
                .andExpect(content().string(not(containsString(password))));
        verifyNoInteractions(authService, userRepository);
    }

    @Test
    void loginReturnsOkWithTokenAndUserPayload() throws Exception {
        String accessToken = "test-access-token";
        when(authService.login(any(LoginRequest.class))).thenReturn(AuthResponse.builder()
                .accessToken(accessToken)
                .tokenType("Bearer")
                .expiresIn(86400)
                .userId(USER_ID)
                .email(EMAIL)
                .fullName(FULL_NAME)
                .status(UserStatus.ACTIVE)
                .build());

        mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON).content(LOGIN_JSON))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", aMapWithSize(7)))
                .andExpect(jsonPath("$.accessToken").value(accessToken))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(86400))
                .andExpect(jsonPath("$.userId").value(USER_ID.toString()))
                .andExpect(jsonPath("$.email").value(EMAIL))
                .andExpect(jsonPath("$.fullName").value(FULL_NAME))
                .andExpect(jsonPath("$.status").value("ACTIVE"));

        verify(authService).login(argThat(request -> EMAIL.equals(request.getEmail())
                && PASSWORD.equals(request.getPassword()) && "lms-client".equals(request.getClientId())));
    }

    @ParameterizedTest(name = "login rejects {0}")
    @CsvSource({"wrong password, student@example.com, WrongPassword123!",
            "unknown email, unknown@example.com, Password123!"})
    void loginReturnsUnauthorizedForInvalidCredentials(String scenario, String email, String password)
            throws Exception {
        String message = "Invalid email or password";
        when(authService.login(any(LoginRequest.class))).thenThrow(new InvalidCredentialsException(message));
        String requestBody = """
                {"email":"%s","password":"%s"}
                """.formatted(email, password);

        expectError(LOGIN_PATH, requestBody, 401, "Unauthorized", message);
        verify(authService).login(argThat(request -> email.equals(request.getEmail())
                && password.equals(request.getPassword())));
    }

    @Test
    void loginReturnsLockedWithLockExpiryAfterFiveFailedAttempts() throws Exception {
        String message = "Account is locked due to 5 consecutive failed login attempts";
        Instant lockedUntil = Instant.parse("2026-10-30T10:15:00Z");
        when(authService.login(any(LoginRequest.class)))
                .thenThrow(new AccountLockedException(message, lockedUntil));

        expectError(LOGIN_PATH, LOGIN_JSON, 423, "Locked", message)
                .andExpect(jsonPath("$.lockedUntil").value(lockedUntil.toString()));
        verify(authService).login(any(LoginRequest.class));
    }

    @Test
    void loginReturnsForbiddenForInactiveAccount() throws Exception {
        String message = "Account is inactive";
        when(authService.login(any(LoginRequest.class))).thenThrow(new AccountInactiveException(message));

        expectError(LOGIN_PATH, LOGIN_JSON, 403, "Forbidden", message);
        verify(authService).login(any(LoginRequest.class));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', textBlock = """
            {"password":"Password123!"} | email | Email is required
            {"email":null,"password":"Password123!"} | email | Email is required
            {"email":"","password":"Password123!"} | email | Email is required
            {"email":"invalid-email","password":"Password123!"} | email | Invalid email format
            {"email":"student@example.com"} | password | Password is required
            {"email":"student@example.com","password":null} | password | Password is required
            {"email":"student@example.com","password":""} | password | Password is required
            {"email":"student@example.com","password":"   "} | password | Password is required
            """)
    void loginRejectsInvalidInputBeforeCallingService(String requestBody, String field, String message)
            throws Exception {
        expectError(LOGIN_PATH, requestBody, 400, "Bad Request", "Validation failed")
                .andExpect(jsonPath("$.validationErrors", aMapWithSize(1)))
                .andExpect(jsonPath("$.validationErrors." + field).value(message));
        verifyNoInteractions(authService);
    }

    @Test
    void loginRejectsMissingEmailAndPassword() throws Exception {
        expectError(LOGIN_PATH, "{}", 400, "Bad Request", "Validation failed")
                .andExpect(jsonPath("$.validationErrors", aMapWithSize(2)))
                .andExpect(jsonPath("$.validationErrors.email").value("Email is required"))
                .andExpect(jsonPath("$.validationErrors.password").value("Password is required"));
        verifyNoInteractions(authService);
    }

    @ParameterizedTest
    @ValueSource(strings = {REGISTER_PATH, LOGIN_PATH})
    void rejectsWhitespaceEmailBeforeCallingService(String path) throws Exception {
        String requestBody = (REGISTER_PATH.equals(path) ? REGISTER_JSON : LOGIN_JSON).replace(EMAIL, "   ");

        // Whitespace can violate both constraints; their evaluation order is unspecified.
        expectError(path, requestBody, 400, "Bad Request", "Validation failed")
                .andExpect(jsonPath("$.validationErrors", aMapWithSize(1)))
                .andExpect(jsonPath("$.validationErrors.email",
                        isOneOf("Email is required", "Invalid email format")));
        verifyNoInteractions(authService);
    }

    @ParameterizedTest
    @ValueSource(strings = {REGISTER_PATH, LOGIN_PATH})
    void rejectsEmptyRequestBodyBeforeCallingService(String path) throws Exception {
        expectError(path, "", 400, "Bad Request", "Required request body is missing or malformed")
                .andExpect(jsonPath("$", aMapWithSize(5)));
        verifyNoInteractions(authService);
    }

    @ParameterizedTest
    @ValueSource(strings = {REGISTER_PATH, LOGIN_PATH})
    void rejectsMalformedJsonWithoutExposingPassword(String path) throws Exception {
        String password = "SensitivePasswordToken";
        String requestBody = """
                {"email":"student@example.com","password":%s,"fullName":"Test Student"}
                """.formatted(password);

        expectError(path, requestBody, 400, "Bad Request", "Required request body is missing or malformed")
                .andExpect(jsonPath("$", aMapWithSize(5)))
                .andExpect(content().string(not(containsString(password))));
        verifyNoInteractions(authService);
    }

    @ParameterizedTest
    @ValueSource(strings = {REGISTER_PATH, LOGIN_PATH})
    void rejectsTruncatedJsonBeforeCallingService(String path) throws Exception {
        expectError(path, "{", 400, "Bad Request", "Required request body is missing or malformed")
                .andExpect(jsonPath("$", aMapWithSize(5)));
        verifyNoInteractions(authService);
    }

    @ParameterizedTest
    @ValueSource(strings = {REGISTER_PATH, LOGIN_PATH})
    @ExtendWith(OutputCaptureExtension.class)
    void unexpectedExceptionReturnsInternalServerErrorWithoutForwarding(String path, CapturedOutput output)
            throws Exception {
        String internalDetails = "Sensitive internal database connection details";
        IllegalStateException exception = new IllegalStateException(internalDetails);
        String requestBody;
        if (REGISTER_PATH.equals(path)) {
            when(authService.register(any(RegisterRequest.class))).thenThrow(exception);
            requestBody = REGISTER_JSON;
        } else {
            when(authService.login(any(LoginRequest.class))).thenThrow(exception);
            requestBody = LOGIN_JSON;
        }

        expectError(path, requestBody, 500, "Internal Server Error", "An unexpected internal error occurred")
                .andExpect(jsonPath("$", aMapWithSize(5)))
                .andExpect(content().string(not(containsString(internalDetails))))
                .andExpect(content().string(not(containsString("IllegalStateException"))))
                .andExpect(result -> assertThat(result.getResponse().getForwardedUrl()).isNull())
                .andExpect(result -> assertThat(result.getResponse().getErrorMessage()).isNull());
        assertThat(output.getOut()).contains("ERROR", "Unhandled exception for request " + path, internalDetails);
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
}
