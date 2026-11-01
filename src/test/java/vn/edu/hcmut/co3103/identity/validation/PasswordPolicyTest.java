package vn.edu.hcmut.co3103.identity.validation;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import vn.edu.hcmut.co3103.identity.exception.PasswordPolicyViolationException;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PasswordPolicyTest {
    @ParameterizedTest
    @ValueSource(strings = {"password", "PASSWORD", "Password", "12345678", "123456789", "qwertyuiop",
            "admin123", "iloveyou", "letmein", "welcome1", "1qaz2wsx", "football", "princess", "abcdefgh"})
    void rejectsCommonPasswordsWithoutEchoingThem(String password) {
        assertThatThrownBy(() -> PasswordPolicy.validate(password))
                .isInstanceOf(PasswordPolicyViolationException.class)
                .hasMessage("Password does not meet the password policy");
    }

    @ParameterizedTest
    @ValueSource(strings = {"Password123!", "correct horse battery staple", "A unique passphrase 2026!"})
    void acceptsExistingUnlistedPasswordsAndPassphrases(String password) {
        assertThatCode(() -> PasswordPolicy.validate(password)).doesNotThrowAnyException();
    }
}
