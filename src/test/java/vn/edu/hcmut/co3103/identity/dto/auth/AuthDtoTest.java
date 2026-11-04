package vn.edu.hcmut.co3103.identity.dto.auth;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import vn.edu.hcmut.co3103.identity.dto.auth.request.ForgotPasswordRequest;
import vn.edu.hcmut.co3103.identity.dto.auth.request.LoginRequest;
import vn.edu.hcmut.co3103.identity.dto.auth.request.RegisterRequest;
import vn.edu.hcmut.co3103.identity.dto.auth.request.ResetPasswordRequest;
import vn.edu.hcmut.co3103.identity.dto.auth.response.AuthResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthDtoTest {

    private static Validator validator;
    private static ValidatorFactory factory;

    @BeforeAll
    static void setUp() {
        factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @AfterAll
    static void closeValidatorFactory() {
        factory.close();
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.MethodSource("vn.edu.hcmut.co3103.identity.support.UnicodeInputs#malformedEmails")
    void allEmailFieldsRejectMalformedUnicode(String email) {
        for (Object request : new Object[]{new ForgotPasswordRequest(email),
                new RegisterRequest(email, "Password123!", "Test User", null),
                new LoginRequest(email, "Password123!", null, null)}) {
            var violations = validator.validate(request);
            assertFalse(violations.isEmpty());
            assertTrue(violations.stream().allMatch(violation -> violation.getPropertyPath().toString().equals("email")));
        }
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.MethodSource("vn.edu.hcmut.co3103.identity.support.UnicodeInputs#validEmails")
    void allEmailFieldsPreserveWellFormedUnicode(String email) {
        var forgot = new ForgotPasswordRequest(email);
        var register = new RegisterRequest(email, "Password123!", "Test User", null);
        var login = new LoginRequest(email, "Password123!", null, null);
        assertEquals(email, forgot.getEmail());
        assertEquals(email, register.getEmail());
        assertEquals(email, login.getEmail());
        for (Object request : new Object[]{forgot, register, login}) {
            assertTrue(validator.validate(request).isEmpty());
        }
    }

    @Test
    void normalizesEmailsAndDefaultsTokenType() {
        RegisterRequest registerRequest = RegisterRequest.builder()
                .email("  USER@Example.COM  ")
                .password("Password123!")
                .fullName("Test User")
                .build();
        LoginRequest loginRequest = LoginRequest.builder()
                .email("  USER@Example.COM  ")
                .password("Password123!")
                .build();

        assertEquals("user@example.com", registerRequest.getEmail());
        assertEquals("user@example.com", loginRequest.getEmail());
        assertNull(new LoginRequest().getEmail());
        assertEquals("Bearer", AuthResponse.builder().build().getTokenType());
        assertEquals("Bearer", new AuthResponse().getTokenType());

        assertTrue(validator.validate(registerRequest).isEmpty());
        assertTrue(validator.validate(loginRequest).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"client\ud800", "client\udfff", "client\0"})
    void loginRejectsMalformedClientIdentifiers(String clientId) {
        var request = new LoginRequest("student@example.com", "Password123!", clientId,
                "https://lms.example.com/auth/callback");
        var violations = validator.validate(request);
        assertEquals(1, violations.size());
        assertEquals("clientId", violations.iterator().next().getPropertyPath().toString());
    }

    @ParameterizedTest
    @ValueSource(strings = {"a", "\u00e9", "\u20ac", "\uD83D\uDE00"})
    void validatesBcryptLimitInUtf8BytesIncludingMultibyteBoundary(String character) {
        int bytesPerCharacter = character.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        String atLimit = character.repeat(72 / bytesPerCharacter);
        RegisterRequest request = RegisterRequest.builder().email("student@example.com")
                .fullName("Test Student").password(atLimit).build();

        assertTrue(validator.validate(request).isEmpty());
        request.setPassword(atLimit + "a");
        var violations = validator.validate(request);
        assertEquals(1, violations.size());
        var violation = violations.iterator().next();
        assertEquals("password", violation.getPropertyPath().toString());
        assertEquals("Password must be valid Unicode and not exceed 72 UTF-8 bytes", violation.getMessage());
    }

    @Test
    void registrationRejectsEveryControlCharacterInFullName() {
        // Exhaustive character validation belongs here; MVC only checks representative binding failures.
        java.util.stream.IntStream.concat(java.util.stream.IntStream.rangeClosed(0, 31),
                java.util.stream.IntStream.rangeClosed(127, 159)).forEach(codePoint -> {
            var request = new RegisterRequest("student@example.com", "Password123!",
                    "Test" + (char) codePoint + " Student", null);
            var violations = validator.validate(request);
            assertEquals(1, violations.size(), "control character " + codePoint);
            assertEquals("fullName", violations.iterator().next().getPropertyPath().toString());
        });
    }

    @Test
    void rejectsInvalidInputs() {
        // Keep the field-value matrix at the DTO boundary instead of repeating HTTP requests.
        for (String email : new String[]{null, "", "   ", "invalid-email"}) {
            assertFalse(validator.validateProperty(new RegisterRequest(email, "Password123!", "Student", null),
                    "email").isEmpty());
            assertFalse(validator.validateProperty(new LoginRequest(email, "Password123!", null, null),
                    "email").isEmpty());
        }
        for (String password : new String[]{null, "", "   "}) {
            assertFalse(validator.validateProperty(new RegisterRequest("student@example.com", password, "Student", null),
                    "password").isEmpty());
            assertFalse(validator.validateProperty(new LoginRequest("student@example.com", password, null, null),
                    "password").isEmpty());
        }
        assertFalse(validator.validateProperty(new RegisterRequest("student@example.com", "short", "Student", null),
                "password").isEmpty());
        for (String fullName : new String[]{null, "", "   "}) {
            assertFalse(validator.validateProperty(new RegisterRequest("student@example.com", "Password123!", fullName, null),
                    "fullName").isEmpty());
        }

        ForgotPasswordRequest badForgot = ForgotPasswordRequest.builder()
                .email("")
                .build();
        assertFalse(validator.validate(badForgot).isEmpty());

        ResetPasswordRequest badReset = ResetPasswordRequest.builder()
                .token("")
                .newPassword("short")
                .build();
        assertFalse(validator.validate(badReset).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"a", "\u00e9", "\u20ac", "\uD83D\uDE00"})
    void loginAndResetEnforce72Utf8Bytes(String character) {
        int bytesPerCharacter = character.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        String atLimit = character.repeat(72 / bytesPerCharacter);
        LoginRequest login = LoginRequest.builder().email("student@example.com").password(atLimit).build();
        ResetPasswordRequest reset = ResetPasswordRequest.builder().token("reset-token")
                .newPassword(atLimit).build();

        assertTrue(validator.validate(login).isEmpty());
        assertTrue(validator.validate(reset).isEmpty());
        login.setPassword(atLimit + "b");
        reset.setNewPassword(atLimit + "b");

        var loginViolations = validator.validate(login);
        var resetViolations = validator.validate(reset);
        assertEquals(1, loginViolations.size());
        assertEquals(1, resetViolations.size());
        var loginViolation = loginViolations.iterator().next();
        var resetViolation = resetViolations.iterator().next();
        assertEquals("password", loginViolation.getPropertyPath().toString());
        assertEquals("newPassword", resetViolation.getPropertyPath().toString());
        assertEquals("Password must be valid Unicode and not exceed 72 UTF-8 bytes", loginViolation.getMessage());
        assertEquals("Password must be valid Unicode and not exceed 72 UTF-8 bytes", resetViolation.getMessage());
    }
}
