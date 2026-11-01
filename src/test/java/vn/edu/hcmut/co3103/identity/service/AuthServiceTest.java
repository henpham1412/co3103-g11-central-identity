package vn.edu.hcmut.co3103.identity.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.hibernate.exception.ConstraintViolationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;
import org.springframework.transaction.support.SimpleTransactionStatus;
import vn.edu.hcmut.co3103.identity.config.JwtProperties;
import vn.edu.hcmut.co3103.identity.config.LoginPolicyProperties;
import vn.edu.hcmut.co3103.identity.entity.LmsClient;
import vn.edu.hcmut.co3103.identity.exception.InvalidClientException;
import vn.edu.hcmut.co3103.identity.exception.InvalidRedirectUriException;
import vn.edu.hcmut.co3103.identity.repository.LmsClientRepository;
import vn.edu.hcmut.co3103.identity.dto.auth.request.LoginRequest;
import vn.edu.hcmut.co3103.identity.dto.auth.request.RegisterRequest;
import vn.edu.hcmut.co3103.identity.dto.auth.response.AuthResponse;
import vn.edu.hcmut.co3103.identity.dto.auth.response.RegisterResponse;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.entity.UserStatus;
import vn.edu.hcmut.co3103.identity.exception.AccountInactiveException;
import vn.edu.hcmut.co3103.identity.exception.AccountLockedException;
import vn.edu.hcmut.co3103.identity.exception.DuplicateEmailException;
import vn.edu.hcmut.co3103.identity.exception.InvalidCredentialsException;
import vn.edu.hcmut.co3103.identity.exception.InvalidEmailException;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtService;

import java.time.Duration;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Optional;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final String EMAIL = "student@example.com";
    private static final String PASSWORD = "Password123!";
    private static final String PASSWORD_HASH = "encoded-password";
    private static final String FULL_NAME = "Test Student";
    private static final String TOKEN = "signed-access-token";
    private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtService jwtService;
    @Mock
    private JwtProperties jwtProperties;
    @Mock
    private LmsClientRepository lmsClientRepository;
    @Spy
    private LoginPolicyProperties loginPolicyProperties = new LoginPolicyProperties();
    @InjectMocks
    private AuthService authService;

    private User user;
    private RegisterRequest registerRequest;
    private LoginRequest loginRequest;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .userId(USER_ID)
                .email(EMAIL)
                .passwordHash(PASSWORD_HASH)
                .fullName(FULL_NAME)
                .status(UserStatus.ACTIVE)
                .failedLoginAttempts(0)
                .createdAt(CREATED_AT)
                .build();
        registerRequest = RegisterRequest.builder()
                .email(EMAIL)
                .password(PASSWORD)
                .fullName(FULL_NAME)
                .build();
        loginRequest = LoginRequest.builder().email(EMAIL).password(PASSWORD).build();
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.MethodSource("vn.edu.hcmut.co3103.identity.support.UnicodeInputs#malformedUnicode")
    void directCredentialCallsRejectMalformedUnicodeBeforeEncodingOrLookup(String password) {
        registerRequest.setPassword(password);
        loginRequest.setPassword(password);
        assertThrows(IllegalArgumentException.class, () -> authService.register(registerRequest));
        assertThrows(InvalidCredentialsException.class, () -> authService.login(loginRequest));
        registerRequest.setPassword(PASSWORD);
        registerRequest.setFullName(password);
        assertThrows(IllegalArgumentException.class, () -> authService.register(registerRequest));
        verifyNoInteractions(userRepository, passwordEncoder, jwtService, lmsClientRepository);
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.MethodSource("vn.edu.hcmut.co3103.identity.support.UnicodeInputs#malformedEmails")
    void directEmailCallsRejectMalformedUnicodeBeforeAnyLookupOrEncoding(String email) {
        registerRequest.setEmail(email);
        loginRequest.setEmail(email);
        assertThrows(InvalidEmailException.class, () -> authService.register(registerRequest));
        assertThrows(InvalidEmailException.class, () -> authService.login(loginRequest));
        verifyNoInteractions(userRepository, passwordEncoder, jwtService, jwtProperties, lmsClientRepository);
    }

    @Test
    void registerSuccess() {
        stubRegistration();

        RegisterResponse response = authService.register(registerRequest);

        assertAll(
                () -> assertEquals(USER_ID, response.getUserId()),
                () -> assertEquals(EMAIL, response.getEmail()),
                () -> assertEquals(FULL_NAME, response.getFullName()),
                () -> assertEquals(UserStatus.ACTIVE, response.getStatus()),
                () -> assertEquals("User registered successfully", response.getMessage())
        );
        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).existsByEmail(EMAIL);
        verify(userRepository).saveAndFlush(captor.capture());
        User savedUser = captor.getValue();
        assertAll(
                () -> assertEquals(EMAIL, savedUser.getEmail()),
                () -> assertEquals(FULL_NAME, savedUser.getFullName()),
                () -> assertEquals(UserStatus.ACTIVE, savedUser.getStatus()),
                () -> assertEquals(0, savedUser.getFailedLoginAttempts()),
                () -> assertNull(savedUser.getLockedUntil()),
                () -> assertNull(savedUser.getLastLoginAt())
        );
        verifyNoInteractions(jwtService, jwtProperties);
    }

    @Test
    void registerDuplicateEmailThrowsException() {
        when(userRepository.existsByEmail(EMAIL)).thenReturn(true);

        DuplicateEmailException exception = assertThrows(DuplicateEmailException.class,
                () -> authService.register(registerRequest));

        assertEquals("Email already registered", exception.getMessage());
        verify(userRepository, never()).saveAndFlush(any(User.class));
        verifyNoInteractions(passwordEncoder, jwtService, jwtProperties);
    }

    @Test
    void registerConcurrentDuplicateEmailThrowsDuplicateEmailAndRollsBack() {
        when(userRepository.existsByEmail(EMAIL)).thenReturn(false);
        when(passwordEncoder.encode(PASSWORD)).thenReturn(PASSWORD_HASH);
        when(userRepository.saveAndFlush(any(User.class)))
                .thenThrow(new DataIntegrityViolationException("duplicate key violates users_email_key"));
        PlatformTransactionManager transactionManager = mock(PlatformTransactionManager.class);
        SimpleTransactionStatus transactionStatus = new SimpleTransactionStatus();
        when(transactionManager.getTransaction(any(TransactionDefinition.class))).thenReturn(transactionStatus);

        DuplicateEmailException exception = assertThrows(DuplicateEmailException.class,
                () -> transactionalService(transactionManager).register(registerRequest));

        assertEquals("Email already registered", exception.getMessage());
        var order = inOrder(userRepository, transactionManager);
        order.verify(userRepository).existsByEmail(EMAIL);
        order.verify(userRepository).saveAndFlush(any(User.class));
        order.verify(transactionManager).rollback(transactionStatus);
        verify(transactionManager, never()).commit(any());
        verifyNoInteractions(jwtService, jwtProperties);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = "23505")
    void registerRecognizesEmailConstraintFromHibernateMetadata(String sqlState) {
        when(passwordEncoder.encode(PASSWORD)).thenReturn(PASSWORD_HASH);
        var sql = new SQLException("constraint violation", sqlState);
        var violation = new ConstraintViolationException("insert failed", sql, "users_email_key");
        when(userRepository.saveAndFlush(any(User.class)))
                .thenThrow(new DataIntegrityViolationException("could not execute statement", violation));

        var exception = assertThrows(DuplicateEmailException.class, () -> authService.register(registerRequest));

        assertEquals("Email already registered", exception.getMessage());
    }

    @Test
    void registerRecognizesEmailConstraintInNestedSqlUniqueViolation() {
        when(passwordEncoder.encode(PASSWORD)).thenReturn(PASSWORD_HASH);
        var sql = new SQLException("ERROR: duplicate key value violates unique constraint \"users_email_key\"\n"
                + "Detail: Key (email)=(student@example.com) already exists", "23505");
        var batch = new SQLException("batch failed");
        batch.setNextException(sql);
        when(userRepository.saveAndFlush(any(User.class)))
                .thenThrow(new DataIntegrityViolationException("could not execute batch", batch));

        assertThrows(DuplicateEmailException.class, () -> authService.register(registerRequest));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', textBlock = """
            23514 | new row violates check constraint chk_users_status
            23502 | null value in column email violates not-null constraint
            22001 | value too long for type character varying(150)
            22021 | invalid byte sequence for encoding UTF8: 0x00
            23505 | duplicate key violates unique constraint users_pkey; insert into users (email)
            23514 | check constraint rejected full_name value: duplicate key violates users_email_key
            """)
    void registerRethrowsNonEmailIntegrityViolations(String sqlState, String detail) {
        when(passwordEncoder.encode(PASSWORD)).thenReturn(PASSWORD_HASH);
        var failure = new DataIntegrityViolationException("insert failed", new SQLException(detail, sqlState));
        when(userRepository.saveAndFlush(any(User.class))).thenThrow(failure);

        assertSame(failure, assertThrows(DataIntegrityViolationException.class,
                () -> authService.register(registerRequest)));
        verifyNoInteractions(jwtService, jwtProperties);
    }

    @Test
    void registerRethrowsUnclassifiedIntegrityViolationAndRollsBack() {
        when(passwordEncoder.encode(PASSWORD)).thenReturn(PASSWORD_HASH);
        var failure = new DataIntegrityViolationException("unknown integrity failure");
        when(userRepository.saveAndFlush(any(User.class))).thenThrow(failure);
        PlatformTransactionManager transactionManager = mock(PlatformTransactionManager.class);
        SimpleTransactionStatus transactionStatus = new SimpleTransactionStatus();
        when(transactionManager.getTransaction(any(TransactionDefinition.class))).thenReturn(transactionStatus);

        assertSame(failure, assertThrows(DataIntegrityViolationException.class,
                () -> transactionalService(transactionManager).register(registerRequest)));

        verify(transactionManager).rollback(transactionStatus);
        verify(transactionManager, never()).commit(any());
    }

    @Test
    void registerNormalizesEmailAndTrimsFullName() {
        // Bypass the DTO's own normalization to exercise the service boundary.
        RegisterRequest request = mock(RegisterRequest.class);
        when(request.getEmail()).thenReturn("  STUDENT@Example.COM  ");
        when(request.getPassword()).thenReturn(PASSWORD);
        when(request.getFullName()).thenReturn("  Test Student  ");
        stubRegistration();

        RegisterResponse response = authService.register(request);

        verify(userRepository).existsByEmail(EMAIL);
        verify(userRepository).saveAndFlush(argThat(saved -> EMAIL.equals(saved.getEmail())
                && FULL_NAME.equals(saved.getFullName())));
        assertEquals(EMAIL, response.getEmail());
        assertEquals(FULL_NAME, response.getFullName());
    }

    @Test
    void registerHashesPassword() {
        stubRegistration();

        authService.register(registerRequest);

        verify(passwordEncoder).encode(PASSWORD);
        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).saveAndFlush(captor.capture());
        assertEquals(PASSWORD_HASH, captor.getValue().getPasswordHash());
        assertNotEquals(PASSWORD, captor.getValue().getPasswordHash());
    }

    @Test
    void loginSuccessReturnsAuthResponseAndResetsCounters() {
        user.setFailedLoginAttempts(4);
        user.setLastLoginAt(CREATED_AT);
        stubSuccessfulLogin();
        Instant before = Instant.now();

        AuthResponse response = authService.login(loginRequest);

        assertAll(
                () -> assertEquals(TOKEN, response.getAccessToken()),
                () -> assertEquals("Bearer", response.getTokenType()),
                () -> assertEquals(3600L, response.getExpiresIn()),
                () -> assertEquals("central-identity", response.getClientId()),
                () -> assertEquals(USER_ID, response.getUser().userId()),
                () -> assertEquals(EMAIL, response.getUser().email()),
                () -> assertEquals(FULL_NAME, response.getUser().fullName()),
                () -> assertEquals(UserStatus.ACTIVE, response.getUser().status()),
                () -> assertEquals(0, user.getFailedLoginAttempts()),
                () -> assertNull(user.getLockedUntil()),
                () -> assertFalse(user.getLastLoginAt().isBefore(before)),
                () -> assertFalse(user.getLastLoginAt().isAfter(Instant.now()))
        );
        var order = inOrder(userRepository, passwordEncoder, jwtService);
        order.verify(userRepository).findByEmailForUpdate(EMAIL);
        order.verify(passwordEncoder).matches(PASSWORD, PASSWORD_HASH);
        order.verify(userRepository).save(user);
        order.verify(jwtService).generateToken(user, "central-identity");
        verifyNoInteractions(lmsClientRepository);
        verify(userRepository, never()).findByEmail(anyString());
    }

    @ParameterizedTest
    @ValueSource(strings = {"a", "\u00e9", "\u20ac", "\uD83D\uDE00"})
    void loginRejectsMoreThan72Utf8BytesBeforeRepositoryOrBcrypt(String character) {
        int bytesPerCharacter = character.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        loginRequest.setPassword(character.repeat(72 / bytesPerCharacter) + "b");

        InvalidCredentialsException exception = assertThrows(InvalidCredentialsException.class,
                () -> authService.login(loginRequest));

        assertEquals("Invalid email or password", exception.getMessage());
        verifyNoInteractions(userRepository, passwordEncoder, jwtService, jwtProperties);
    }

    @Test
    void loginNormalizesEmail() {
        LoginRequest request = mock(LoginRequest.class);
        when(request.getEmail()).thenReturn("  STUDENT@Example.COM  ");
        when(request.getPassword()).thenReturn(PASSWORD);
        stubSuccessfulLogin();

        assertEquals(TOKEN, authService.login(request).getAccessToken());

        verify(userRepository).findByEmailForUpdate(EMAIL);
    }

    @Test
    void loginPassesPersistedClientIdToTokenGenerationAndResponse() {
        loginRequest.setClientId("lms-client");
        loginRequest.setRedirectUri("https://lms.example.com/auth/callback");
        when(lmsClientRepository.findByClientIdAndIsActiveTrue("lms-client"))
                .thenReturn(Optional.of(LmsClient.builder().clientId("persisted-client")
                        .redirectUris(List.of("https://lms.example.com/auth/callback")).build()));
        when(userRepository.findByEmailForUpdate(EMAIL)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(PASSWORD, PASSWORD_HASH)).thenReturn(true);
        when(jwtService.generateToken(user, "persisted-client")).thenReturn(TOKEN);
        when(jwtProperties.getExpirationMs()).thenReturn(3_600_000L);

        AuthResponse response = authService.login(loginRequest);
        assertEquals(TOKEN, response.getAccessToken());
        assertEquals("persisted-client", response.getClientId());

        verify(jwtService).generateToken(user, "persisted-client");
    }

    @ParameterizedTest
    @ValueSource(strings = {"client\ud800", "client\udfff", "client\0"})
    void loginRejectsMalformedClientBeforeAnyRepositoryLookup(String clientId) {
        loginRequest.setClientId(clientId);
        loginRequest.setRedirectUri("https://lms.example.com/auth/callback");

        assertThrows(InvalidClientException.class, () -> authService.login(loginRequest));

        verifyNoInteractions(lmsClientRepository, userRepository, passwordEncoder, jwtService, jwtProperties);
    }

    @Test
    void loginRejectsUnregisteredOrInactiveClientBeforeAuthentication() {
        loginRequest.setClientId("invalid-client");
        when(lmsClientRepository.findByClientIdAndIsActiveTrue("invalid-client"))
                .thenReturn(Optional.empty());
        assertThrows(InvalidClientException.class, () -> authService.login(loginRequest));
        verifyNoInteractions(userRepository, passwordEncoder, jwtService, jwtProperties);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", " ", "https://evil.example/callback", "https://lms.example.com/auth/callback/",
            "https://lms.example.com/auth/callback?next=evil", "https://lms.example.com/auth/callback#fragment",
            "https://LMS.example.com/auth/callback", "https://lms.example.com/auth/%63allback"})
    void loginRejectsMissingOrUnregisteredRedirectBeforeAuthentication(String redirectUri) {
        loginRequest.setClientId("lms-client");
        loginRequest.setRedirectUri(redirectUri);
        when(lmsClientRepository.findByClientIdAndIsActiveTrue("lms-client"))
                .thenReturn(Optional.of(LmsClient.builder()
                        .redirectUris(List.of("https://lms.example.com/auth/callback")).build()));
        assertThrows(InvalidRedirectUriException.class, () -> authService.login(loginRequest));
        verifyNoInteractions(userRepository, passwordEncoder, jwtService, jwtProperties);
    }

    @Test
    void loginRejectsRedirectWithoutClient() {
        loginRequest.setRedirectUri("https://lms.example.com/auth/callback");
        assertThrows(InvalidRedirectUriException.class, () -> authService.login(loginRequest));
        verifyNoInteractions(lmsClientRepository, userRepository, passwordEncoder, jwtService, jwtProperties);
    }

    @Test
    void loginRejectsRedirectIfClientHasNoRegisteredUris() {
        loginRequest.setClientId("lms-client");
        loginRequest.setRedirectUri("https://lms.example.com/auth/callback");
        when(lmsClientRepository.findByClientIdAndIsActiveTrue("lms-client"))
                .thenReturn(Optional.of(LmsClient.builder().build()));
        assertThrows(InvalidRedirectUriException.class, () -> authService.login(loginRequest));
        verifyNoInteractions(userRepository, passwordEncoder, jwtService, jwtProperties);
    }

    @Test
    void loginUsesConfiguredThresholdAndDurationWithoutExtendingExistingLock() {
        loginPolicyProperties.setMaxFailedAttempts(2);
        loginPolicyProperties.setLockoutDuration(Duration.ofSeconds(90));
        stubFailedLogin();
        assertThrows(InvalidCredentialsException.class, () -> authService.login(loginRequest));
        assertNull(user.getLockedUntil());
        Instant before = Instant.now();
        assertThrows(InvalidCredentialsException.class, () -> authService.login(loginRequest));
        Instant lockedUntil = user.getLockedUntil();
        assertFalse(lockedUntil.isBefore(before.plusSeconds(90)));
        assertFalse(lockedUntil.isAfter(Instant.now().plusSeconds(90)));
        assertThrows(AccountLockedException.class, () -> authService.login(loginRequest));
        assertEquals(lockedUntil, user.getLockedUntil());
        assertEquals(2, user.getFailedLoginAttempts());
        verify(passwordEncoder, times(2)).matches(PASSWORD, PASSWORD_HASH);
        verifyNoInteractions(jwtService, jwtProperties);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(ints = {0, 1, 2, 3})
    void loginInvalidPasswordIncrementsAttempts(Integer previousAttempts) {
        user.setFailedLoginAttempts(previousAttempts);
        user.setLastLoginAt(CREATED_AT);
        stubFailedLogin();

        InvalidCredentialsException exception = assertThrows(InvalidCredentialsException.class,
                () -> authService.login(loginRequest));

        assertEquals("Invalid email or password", exception.getMessage());
        assertEquals((previousAttempts == null ? 0 : previousAttempts) + 1, user.getFailedLoginAttempts());
        assertNull(user.getLockedUntil());
        assertEquals(CREATED_AT, user.getLastLoginAt());
        verify(userRepository).save(user);
        verifyNoInteractions(jwtService, jwtProperties);
    }

    @Test
    void loginFifthFailedAttemptLocksAccountFor15Minutes() {
        user.setFailedLoginAttempts(4);
        stubFailedLogin();
        Instant before = Instant.now();

        InvalidCredentialsException exception = assertThrows(InvalidCredentialsException.class,
                () -> authService.login(loginRequest));
        Instant after = Instant.now();

        assertAll(
                () -> assertEquals(5, user.getFailedLoginAttempts()),
                () -> assertEquals("Invalid email or password", exception.getMessage()),
                () -> assertFalse(user.getLockedUntil().isBefore(before.plus(Duration.ofMinutes(15)))),
                () -> assertFalse(user.getLockedUntil().isAfter(after.plus(Duration.ofMinutes(15)))),
                () -> assertNull(user.getLastLoginAt())
        );
        verify(userRepository).save(user);
        verifyNoInteractions(jwtService, jwtProperties);
    }

    @ParameterizedTest
    @EnumSource(UserStatus.class)
    void loginWhileLockedRejectsEveryPasswordWithoutHashComparisonOrStateChanges(UserStatus status) {
        Instant lockedUntil = Instant.now().plus(Duration.ofMinutes(10));
        user.setStatus(status);
        user.setFailedLoginAttempts(5);
        user.setLockedUntil(lockedUntil);
        when(userRepository.findByEmailForUpdate(EMAIL)).thenReturn(Optional.of(user));
        for (String password : List.of(PASSWORD, "WrongPassword123!")) {
            loginRequest.setPassword(password);
            AccountLockedException exception = assertThrows(AccountLockedException.class,
                    () -> authService.login(loginRequest));
            assertEquals("Account is temporarily locked until " + lockedUntil, exception.getMessage());
            assertEquals(lockedUntil, exception.getLockedUntil());
        }
        assertEquals(lockedUntil, user.getLockedUntil());
        assertEquals(5, user.getFailedLoginAttempts());
        assertNull(user.getLastLoginAt());
        verify(userRepository, never()).save(any(User.class));
        verifyNoInteractions(passwordEncoder, jwtService, jwtProperties);
    }

    @Test
    void loginAfterLockoutExpiredAutoUnlocksAndSucceeds() {
        user.setFailedLoginAttempts(5);
        user.setLockedUntil(Instant.now().minusSeconds(60));
        stubSuccessfulLogin();

        AuthResponse response = authService.login(loginRequest);

        assertEquals(TOKEN, response.getAccessToken());
        assertEquals(0, user.getFailedLoginAttempts());
        assertNull(user.getLockedUntil());
        verify(userRepository).save(user);
    }

    @Test
    void loginAtLockoutExpiryAutoUnlocksAndSucceeds() {
        Instant now = Instant.parse("2026-10-29T12:00:00Z");
        user.setFailedLoginAttempts(5);
        user.setLockedUntil(now);
        stubSuccessfulLogin();

        try (MockedStatic<Instant> clock = mockStatic(Instant.class)) {
            clock.when(Instant::now).thenReturn(now);

            assertEquals(TOKEN, authService.login(loginRequest).getAccessToken());

            assertEquals(0, user.getFailedLoginAttempts());
            assertNull(user.getLockedUntil());
            assertEquals(now, user.getLastLoginAt());
        }
        verify(userRepository).save(user);
    }

    @Test
    void loginAfterLockoutExpiredWithInvalidPasswordStartsNewCounter() {
        user.setFailedLoginAttempts(5);
        user.setLockedUntil(Instant.now().minusSeconds(60));
        stubFailedLogin();

        assertThrows(InvalidCredentialsException.class, () -> authService.login(loginRequest));

        assertEquals(1, user.getFailedLoginAttempts());
        assertNull(user.getLockedUntil());
        verify(userRepository).save(user);
        verifyNoInteractions(jwtService, jwtProperties);
    }

    @ParameterizedTest
    @NullSource
    @EnumSource(value = UserStatus.class, names = {"SUSPENDED", "DEACTIVATED"})
    void loginNonActiveAccountWithCorrectPasswordReturnsForbidden(UserStatus status) {
        user = spy(user);
        user.setStatus(status);
        user.setFailedLoginAttempts(3);
        when(userRepository.findByEmailForUpdate(EMAIL)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(PASSWORD, PASSWORD_HASH)).thenReturn(true);

        AccountInactiveException exception = assertThrows(AccountInactiveException.class,
                () -> authService.login(loginRequest));

        assertEquals("Account is inactive", exception.getMessage());
        var order = inOrder(passwordEncoder, user);
        order.verify(passwordEncoder).matches(PASSWORD, PASSWORD_HASH);
        order.verify(user).getStatus();
        assertEquals(3, user.getFailedLoginAttempts());
        verify(userRepository, never()).save(any(User.class));
        verifyNoInteractions(jwtService, jwtProperties);
    }

    @ParameterizedTest
    @NullSource
    @EnumSource(UserStatus.class)
    void loginWrongPasswordNeverDisclosesAccountStatus(UserStatus status) {
        user = spy(user);
        user.setStatus(status);
        stubFailedLogin();

        InvalidCredentialsException exception = assertThrows(InvalidCredentialsException.class,
                () -> authService.login(loginRequest));

        assertEquals("Invalid email or password", exception.getMessage());
        verify(passwordEncoder).matches(PASSWORD, PASSWORD_HASH);
        verify(user, never()).getStatus();
        assertEquals(1, user.getFailedLoginAttempts());
        verify(userRepository).save(user);
        verifyNoInteractions(jwtService, jwtProperties);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void loginNonexistentUserChecksDummyPasswordAndAlwaysRejects(boolean dummyMatches) {
        when(userRepository.findByEmailForUpdate(EMAIL)).thenReturn(Optional.empty());
        when(passwordEncoder.matches(eq(PASSWORD), anyString())).thenReturn(dummyMatches);

        InvalidCredentialsException exception = assertThrows(InvalidCredentialsException.class,
                () -> authService.login(loginRequest));

        assertEquals("Invalid email or password", exception.getMessage());
        ArgumentCaptor<String> hashCaptor = ArgumentCaptor.forClass(String.class);
        var order = inOrder(userRepository, passwordEncoder);
        order.verify(userRepository).findByEmailForUpdate(EMAIL);
        order.verify(passwordEncoder).matches(eq(PASSWORD), hashCaptor.capture());
        // A malformed hash can return immediately; verify that real BCrypt accepts this hash.
        BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder();
        assertTrue(bcrypt.matches("dummy-password-for-nonexistent-user", hashCaptor.getValue()));
        assertFalse(bcrypt.upgradeEncoding(hashCaptor.getValue()));
        verify(userRepository, never()).save(any(User.class));
        verify(passwordEncoder, never()).encode(anyString());
        verifyNoInteractions(jwtService, jwtProperties);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 4})
    void loginAuthenticationFailureCommitsAttemptsAndLockout(int previousAttempts) {
        user.setFailedLoginAttempts(previousAttempts);
        stubFailedLogin();
        PlatformTransactionManager transactionManager = mock(PlatformTransactionManager.class);
        SimpleTransactionStatus transactionStatus = new SimpleTransactionStatus();
        when(transactionManager.getTransaction(any(TransactionDefinition.class))).thenReturn(transactionStatus);
        AuthService transactionalService = transactionalService(transactionManager);

        assertThrows(InvalidCredentialsException.class, () -> transactionalService.login(loginRequest));

        verify(transactionManager).getTransaction(argThat(definition -> !definition.isReadOnly()));
        var order = inOrder(userRepository, transactionManager);
        order.verify(userRepository).save(user);
        order.verify(transactionManager).commit(transactionStatus);
        verify(transactionManager, never()).rollback(any());
        assertEquals(previousAttempts + 1, user.getFailedLoginAttempts());
    }

    @Test
    void loginTokenGenerationFailureRollsBackTransaction() {
        when(userRepository.findByEmailForUpdate(EMAIL)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(PASSWORD, PASSWORD_HASH)).thenReturn(true);
        IllegalStateException failure = new IllegalStateException("Token signing failed");
        when(jwtService.generateToken(user, "central-identity")).thenThrow(failure);
        PlatformTransactionManager transactionManager = mock(PlatformTransactionManager.class);
        SimpleTransactionStatus transactionStatus = new SimpleTransactionStatus();
        when(transactionManager.getTransaction(any(TransactionDefinition.class))).thenReturn(transactionStatus);
        AuthService transactionalService = transactionalService(transactionManager);

        assertSame(failure, assertThrows(IllegalStateException.class,
                () -> transactionalService.login(loginRequest)));

        verify(transactionManager).rollback(transactionStatus);
        verify(transactionManager, never()).commit(any());
    }

    private void stubRegistration() {
        when(passwordEncoder.encode(PASSWORD)).thenReturn(PASSWORD_HASH);
        when(userRepository.saveAndFlush(any(User.class))).thenReturn(user);
    }

    @ParameterizedTest
    @ValueSource(strings = {"a", "\u00e9", "\u20ac", "\uD83D\uDE00"})
    void registerRejectsOversizedPasswordBeforeEncodingOrRepository(String character) {
        int bytes = character.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        registerRequest.setPassword(character.repeat(72 / bytes) + "x");
        assertThrows(IllegalArgumentException.class, () -> authService.register(registerRequest));
        verifyNoInteractions(userRepository, passwordEncoder, jwtService, jwtProperties);
    }

    @Test
    void registerDoesNotMistakeUniqueViolationDetailForEmailConstraint() {
        var sql = new SQLException("ERROR: duplicate key value violates unique constraint \"users_external_id_key\"\n"
                + "Detail: Key (external_id)=(Key (email)=attacker@example.com) already exists", "23505");
        var failure = new DataIntegrityViolationException("insert failed", sql);
        when(passwordEncoder.encode(PASSWORD)).thenReturn(PASSWORD_HASH);
        when(userRepository.saveAndFlush(any(User.class))).thenThrow(failure);
        assertSame(failure, assertThrows(DataIntegrityViolationException.class,
                () -> authService.register(registerRequest)));
    }

    private void stubSuccessfulLogin() {
        when(userRepository.findByEmailForUpdate(EMAIL)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(PASSWORD, PASSWORD_HASH)).thenReturn(true);
        when(jwtService.generateToken(user, "central-identity")).thenReturn(TOKEN);
        when(jwtProperties.getExpirationMs()).thenReturn(3_600_999L);
    }

    private void stubFailedLogin() {
        when(userRepository.findByEmailForUpdate(EMAIL)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(PASSWORD, PASSWORD_HASH)).thenReturn(false);
    }

    private AuthService transactionalService(PlatformTransactionManager transactionManager) {
        TransactionInterceptor interceptor = new TransactionInterceptor();
        interceptor.setTransactionManager(transactionManager);
        interceptor.setTransactionAttributeSource(new AnnotationTransactionAttributeSource());
        ProxyFactory factory = new ProxyFactory(authService);
        factory.addAdvice(interceptor);
        return (AuthService) factory.getProxy();
    }
}
