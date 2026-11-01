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
import vn.edu.hcmut.co3103.identity.support.ErrorContractTestConfiguration;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import vn.edu.hcmut.co3103.identity.config.JwtProperties;
import vn.edu.hcmut.co3103.identity.config.LoginPolicyProperties;
import vn.edu.hcmut.co3103.identity.entity.LmsClient;
import vn.edu.hcmut.co3103.identity.repository.LmsClientRepository;
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

import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasSize;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(value = {AuthController.class, JwksController.class})
@Import({ErrorContractTestConfiguration.class, SecurityConfig.class, JwtAuthenticationFilter.class, JwtService.class})
class AuthControllerTest {

    private static final String REGISTER_PATH = "/api/v1/auth/register";
    private static final String LOGIN_PATH = "/api/v1/auth/login";
    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000007");
    private static final String EMAIL = "student@example.com";
    private static final String PASSWORD = "Password123!";
    private static final String FULL_NAME = "Test Student";
    private static final String REGISTER_JSON = """
            {"email":"student@example.com","password":"Password123!","full_name":"Test Student","client_id":"lms-client"}
            """;
    private static final String LOGIN_JSON = """
            {"email":"student@example.com","password":"Password123!","client_id":"lms-client","redirect_uri":"https://lms.example.com/auth/callback"}
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

    @MockitoBean
    private LmsClientRepository lmsClientRepository;

    @Test
    void registerReturnsCreatedWithUserPayload() throws Exception {
        when(authService.register(any(RegisterRequest.class))).thenReturn(RegisterResponse.builder()
                .userId(USER_ID)
                .email(EMAIL)
                .fullName(FULL_NAME)
                .status(UserStatus.ACTIVE)
                .build());

        mockMvc.perform(post(REGISTER_PATH).contentType(MediaType.APPLICATION_JSON).content(REGISTER_JSON))
                .andExpect(status().isCreated())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", aMapWithSize(5)))
                .andExpect(jsonPath("$.user_id").value(USER_ID.toString()))
                .andExpect(jsonPath("$.email").value(EMAIL))
                .andExpect(jsonPath("$.full_name").value(FULL_NAME))
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andExpect(jsonPath("$.message").value("User registered successfully"));

        verify(authService).register(argThat(request -> EMAIL.equals(request.getEmail())
                && PASSWORD.equals(request.getPassword()) && FULL_NAME.equals(request.getFullName())
                && "lms-client".equals(request.getClientId())));
    }

    @Test
    void registerAndLoginNormalizeWhitespaceAndUppercaseBeforeValidation() throws Exception {
        String rawEmail = "   STUDENT.WHITESPACE@EXAMPLE.COM   ";
        String normalizedEmail = "student.whitespace@example.com";
        AuthService realService = new AuthService(userRepository, passwordEncoder, jwtService, jwtProperties,
                lmsClientRepository, new LoginPolicyProperties());
        when(lmsClientRepository.findByClientIdAndIsActiveTrue("lms-client"))
                .thenReturn(Optional.of(LmsClient.builder().clientId("lms-client")
                        .redirectUris(java.util.List.of("https://lms.example.com/auth/callback")).build()));
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
                .andExpect(jsonPath("$.user.email").value(normalizedEmail))
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(result -> {
                    String token = com.jayway.jsonpath.JsonPath.read(
                            result.getResponse().getContentAsString(), "$.access_token");
                    assertThat(jwtService.extractUserId(token)).isEqualTo(USER_ID.toString());
                    String jwks = mockMvc.perform(get("/.well-known/jwks.json"))
                            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
                    var signed = com.nimbusds.jwt.SignedJWT.parse(token);
                    var publicKey = com.nimbusds.jose.jwk.JWKSet.parse(jwks)
                            .getKeyByKeyId(signed.getHeader().getKeyID()).toRSAKey();
                    assertThat(signed.getHeader().getAlgorithm().getName()).isEqualTo("RS256");
                    assertThat(signed.getJWTClaimsSet().getIssuer()).isEqualTo(jwtProperties.getIssuer());
                    assertThat(signed.verify(new com.nimbusds.jose.crypto.RSASSAVerifier(publicKey))).isTrue();
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
                .andExpect(jsonPath("$.details[?(@.field == 'full_name')].message").value(contains("Full name contains invalid characters")));
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
                .andExpect(jsonPath("$.full_name").value(fullName));
        verify(authService).register(argThat(request -> fullName.equals(request.getFullName())));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', textBlock = """
            {"password":"Password123!","full_name":"Test Student"} | email | Email is required
            {"email":null,"password":"Password123!","full_name":"Test Student"} | email | Email is required
            {"email":"","password":"Password123!","full_name":"Test Student"} | email | Email is required
            {"email":"invalid-email","password":"Password123!","full_name":"Test Student"} | email | Invalid email format
            {"email":"student@example.com","password":"1234567","full_name":"Test Student"} | password | Password must be between 8 and 128 characters
            {"email":"student@example.com","full_name":"Test Student"} | password | Password is required
            {"email":"student@example.com","password":"Password123!"} | full_name | Full name is required
            {"email":"student@example.com","password":"Password123!","full_name":null} | full_name | Full name is required
            {"email":"student@example.com","password":"Password123!","full_name":""} | full_name | Full name is required
            {"email":"student@example.com","password":"Password123!","full_name":"   "} | full_name | Full name is required
            """)
    void registerRejectsInvalidInputBeforeCallingService(String requestBody, String field, String message)
            throws Exception {
        expectError(REGISTER_PATH, requestBody, 400, "Bad Request", "Validation failed")
                .andExpect(jsonPath("$.details", hasSize(1)))
                .andExpect(jsonPath("$.details[?(@.field == '" + field + "')].message").value(contains(message)));
        verifyNoInteractions(authService);
    }

    @ParameterizedTest
    @ValueSource(strings = {REGISTER_PATH, LOGIN_PATH})
    void rejectsUnsupportedAcceptBeforeCallingService(String path) throws Exception {
        for (String accept : new String[]{"application/xml", "text/plain", "image/png",
                "application/json;q=0", "application/xml;q=1, */*;q=0",
                "application/json;q=0, */*;q=1", "*/*;q=1, application/json;q=0",
                "application/*;q=0, */*;q=1"}) {
            mockMvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).accept(accept)
                            .content(REGISTER_PATH.equals(path) ? REGISTER_JSON : LOGIN_JSON))
                    .andExpect(status().isNotAcceptable())
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.code").value("NOT_ACCEPTABLE"));
        }
        verifyNoInteractions(authService, userRepository);
    }

    @ParameterizedTest
    @ValueSource(strings = {REGISTER_PATH, LOGIN_PATH})
    void explicitJsonExclusionAcrossAcceptHeaderLinesRejectsBeforeService(String path) throws Exception {
        mockMvc.perform(post(path).contentType(MediaType.APPLICATION_JSON)
                        .header("Accept", "*/*;q=1", "application/json;q=0")
                        .content(REGISTER_PATH.equals(path) ? REGISTER_JSON : LOGIN_JSON))
                .andExpect(status().isNotAcceptable())
                .andExpect(jsonPath("$.code").value("NOT_ACCEPTABLE"));
        verifyNoInteractions(authService, userRepository);
    }

    @ParameterizedTest
    @ValueSource(strings = {"a", "\u00e9", "\u20ac", "\uD83D\uDE00"})
    void loginRejects73Utf8BytesBeforeService(String character) throws Exception {
        int bytesPerCharacter = character.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        String password = character.repeat(72 / bytesPerCharacter) + "b";
        expectError(LOGIN_PATH, LOGIN_JSON.replace(PASSWORD, password), 400, "Bad Request", "Validation failed")
                .andExpect(jsonPath("$.details[?(@.field == 'password')].message").value(contains("Password must be valid Unicode and not exceed 72 UTF-8 bytes")))
                .andExpect(jsonPath("$.access_token").doesNotExist())
                .andExpect(content().string(not(containsString(password))));
        verifyNoInteractions(authService, userRepository);
    }

    @ParameterizedTest
    @ValueSource(strings = {REGISTER_PATH, LOGIN_PATH})
    void rejectsUnsupportedContentTypeBeforeCallingService(String path) throws Exception {
        mockMvc.perform(post(path).contentType(MediaType.APPLICATION_XML).content("<request/>"))
                .andExpect(status().isUnsupportedMediaType())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
        verifyNoInteractions(authService, userRepository);
    }

    @Test
    void registerReturnsConflictForDuplicateEmail() throws Exception {
        String message = "Email already registered";
        when(authService.register(any(RegisterRequest.class))).thenThrow(new DuplicateEmailException());

        expectError(REGISTER_PATH, REGISTER_JSON, 409, "Conflict", message);
        verify(authService).register(any(RegisterRequest.class));
    }

    @Test
    void registerReturnsConflictForDatabaseConstraintViolation() throws Exception {
        when(authService.register(any(RegisterRequest.class))).thenThrow(
                new DataIntegrityViolationException("duplicate key violates users_email_key"));

        expectError(REGISTER_PATH, REGISTER_JSON, 409, "Conflict", "Email already registered");
        verify(authService).register(any(RegisterRequest.class));
    }

    @ParameterizedTest
    @CsvSource({"a, 73", "\u20ac, 25"})
    void registerRejectsPasswordsExceedingBcryptByteLimit(String character, int repetitions) throws Exception {
        String password = character.repeat(repetitions);
        String requestBody = REGISTER_JSON.replace(PASSWORD, password);
        expectError(REGISTER_PATH, requestBody, 400, "Bad Request", "Validation failed")
                .andExpect(jsonPath("$.details[?(@.field == 'password')].message").value(contains("Password must be valid Unicode and not exceed 72 UTF-8 bytes")))
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
                .clientId("lms-client")
                .user(new AuthResponse.AuthUser(USER_ID, EMAIL, FULL_NAME, UserStatus.ACTIVE))
                .build());

        mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON).content(LOGIN_JSON))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", aMapWithSize(5)))
                .andExpect(jsonPath("$.access_token").value(accessToken))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(86400))
                .andExpect(jsonPath("$.client_id").value("lms-client"))
                .andExpect(jsonPath("$.user", aMapWithSize(4)))
                .andExpect(jsonPath("$.user.user_id").value(USER_ID.toString()))
                .andExpect(jsonPath("$.user.email").value(EMAIL))
                .andExpect(jsonPath("$.user.full_name").value(FULL_NAME))
                .andExpect(jsonPath("$.user.status").value("ACTIVE"));

        verify(authService).login(argThat(request -> EMAIL.equals(request.getEmail())
                && PASSWORD.equals(request.getPassword()) && "lms-client".equals(request.getClientId())
                && "https://lms.example.com/auth/callback".equals(request.getRedirectUri())));
    }

    @ParameterizedTest
    @CsvSource({"full_name, fullName", "client_id, clientId"})
    void registerRejectsCamelCaseAliases(String canonical, String alias) throws Exception {
        expectError(REGISTER_PATH, REGISTER_JSON.replace(canonical, alias), 400, "Bad Request",
                "Required request body is missing or malformed")
                .andExpect(jsonPath("$.code").value("BAD_REQUEST"));
        verifyNoInteractions(authService, userRepository);
    }

    @ParameterizedTest
    @CsvSource({"client_id, clientId", "redirect_uri, redirectUri"})
    void loginRejectsCamelCaseAliases(String canonical, String alias) throws Exception {
        expectError(LOGIN_PATH, LOGIN_JSON.replace(canonical, alias), 400, "Bad Request",
                "Required request body is missing or malformed")
                .andExpect(jsonPath("$.code").value("BAD_REQUEST"));
        verifyNoInteractions(authService, userRepository);
    }

    @ParameterizedTest
    @ValueSource(strings = {"client_id", "redirect_uri"})
    void loginRejectsDuplicateContextFields(String field) throws Exception {
        expectError(LOGIN_PATH, LOGIN_JSON.replace("}", ",\"" + field + "\":\"duplicate\"}"),
                400, "Bad Request", "Required request body is missing or malformed")
                .andExpect(jsonPath("$.code").value("BAD_REQUEST"));
        verifyNoInteractions(authService, userRepository);
    }

    @Test
    void invalidClientAndRedirectHaveDistinctCodes() throws Exception {
        when(authService.login(any(LoginRequest.class)))
                .thenThrow(new vn.edu.hcmut.co3103.identity.exception.InvalidClientException())
                .thenThrow(new vn.edu.hcmut.co3103.identity.exception.InvalidRedirectUriException());
        expectError(LOGIN_PATH, LOGIN_JSON, 400, "Bad Request", "Client is invalid or inactive")
                .andExpect(jsonPath("$.code").value("BAD_REQUEST"));
        expectError(LOGIN_PATH, LOGIN_JSON, 400, "Bad Request", "Redirect URI is not registered for this client")
                .andExpect(jsonPath("$.code").value("BAD_REQUEST"));
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
                .andExpect(jsonPath("$.details[0].locked_until").value(lockedUntil.toString()));
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
                .andExpect(jsonPath("$.details", hasSize(1)))
                .andExpect(jsonPath("$.details[?(@.field == '" + field + "')].message").value(contains(message)));
        verifyNoInteractions(authService);
    }

    @Test
    void loginRejectsMissingEmailAndPassword() throws Exception {
        expectError(LOGIN_PATH, "{}", 400, "Bad Request", "Validation failed")
                .andExpect(jsonPath("$.details", hasSize(2)))
                .andExpect(jsonPath("$.details[?(@.field == 'email')].message").value(contains("Email is required")))
                .andExpect(jsonPath("$.details[?(@.field == 'password')].message").value(contains("Password is required")));
        verifyNoInteractions(authService);
    }

    @ParameterizedTest
    @ValueSource(strings = {REGISTER_PATH, LOGIN_PATH})
    void rejectsWhitespaceEmailBeforeCallingService(String path) throws Exception {
        String requestBody = (REGISTER_PATH.equals(path) ? REGISTER_JSON : LOGIN_JSON).replace(EMAIL, "   ");

        // Whitespace can violate both constraints; their evaluation order is unspecified.
        expectError(path, requestBody, 400, "Bad Request", "Validation failed")
                .andExpect(jsonPath("$.details", hasSize(1)))
                .andExpect(jsonPath("$.details[?(@.field == 'email')].message",
                        hasItem(isOneOf("Email is required", "Invalid email format"))));
        verifyNoInteractions(authService);
    }

    @ParameterizedTest
    @ValueSource(strings = {REGISTER_PATH, LOGIN_PATH})
    void rejectsEmptyRequestBodyBeforeCallingService(String path) throws Exception {
        expectError(path, "", 400, "Bad Request", "Required request body is missing or malformed")
                .andExpect(jsonPath("$", aMapWithSize(3)));
        verifyNoInteractions(authService);
    }

    @ParameterizedTest
    @ValueSource(strings = {REGISTER_PATH, LOGIN_PATH})
    void rejectsMalformedJsonWithoutExposingPassword(String path) throws Exception {
        String password = "SensitivePasswordToken";
        String requestBody = """
                {"email":"student@example.com","password":%s,"full_name":"Test Student"}
                """.formatted(password);

        expectError(path, requestBody, 400, "Bad Request", "Required request body is missing or malformed")
                .andExpect(jsonPath("$", aMapWithSize(3)))
                .andExpect(content().string(not(containsString(password))));
        verifyNoInteractions(authService);
    }

    @ParameterizedTest
    @ValueSource(strings = {REGISTER_PATH, LOGIN_PATH})
    void rejectsTruncatedJsonBeforeCallingService(String path) throws Exception {
        expectError(path, "{", 400, "Bad Request", "Required request body is missing or malformed")
                .andExpect(jsonPath("$", aMapWithSize(3)));
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
                .andExpect(jsonPath("$", aMapWithSize(3)))
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
                .andExpect(jsonPath("$.code").value(switch (statusCode) {
                    case 400 -> "BAD_REQUEST";
                    case 401 -> "INVALID_CREDENTIALS";
                    case 403 -> "ACCOUNT_NOT_ACTIVE";
                    case 409 -> "EMAIL_ALREADY_REGISTERED";
                    case 423 -> "LOGIN_TEMPORARILY_LOCKED";
                    default -> "INTERNAL_SERVER_ERROR";
                }))
                .andExpect(jsonPath("$.message").value(message))
                .andExpect(jsonPath("$.lockedUntil").doesNotExist())
                .andExpect(jsonPath("$.validationErrors").doesNotExist());
    }
}
