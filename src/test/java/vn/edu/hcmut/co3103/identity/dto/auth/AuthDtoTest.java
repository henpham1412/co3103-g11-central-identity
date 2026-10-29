package vn.edu.hcmut.co3103.identity.dto.auth;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
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

    @BeforeAll
    static void setUp() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
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

    @Test
    void rejectsInvalidInputs() {
        RegisterRequest badRegister = RegisterRequest.builder()
                .email("not-an-email")
                .password("short")
                .fullName("")
                .build();
        assertFalse(validator.validate(badRegister).isEmpty());

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
}
