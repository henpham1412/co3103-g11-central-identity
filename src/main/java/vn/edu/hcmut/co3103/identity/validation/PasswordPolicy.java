package vn.edu.hcmut.co3103.identity.validation;

import vn.edu.hcmut.co3103.identity.exception.PasswordPolicyViolationException;

import java.util.Locale;
import java.util.Set;

/** Local, case-insensitive blocklist; never transmit or log submitted passwords. */
public final class PasswordPolicy {
    private static final Set<String> COMMON_PASSWORDS = Set.of(
            "password", "password1", "password12", "password123", "password1234", "password!",
            "123456", "1234567", "12345678", "123456789", "1234567890", "123123", "123123123",
            "111111", "11111111", "111111111", "000000", "00000000", "000000000", "12121212",
            "12341234", "12344321", "87654321", "987654321", "11223344", "112233", "123456abc",
            "abc123", "abc12345", "abc123456", "abcd1234", "abcdef", "abcdefgh", "abcdefg",
            "qwerty", "qwertyuiop", "qwerty123", "qwerty12", "qwerty1", "qwe123", "qweasdzxc",
            "qazwsx", "qazwsxedc", "1qaz2wsx", "1q2w3e4r", "1q2w3e4r5t", "asdfghjk",
            "asdfghjkl", "zxcvbnm", "zxcvbnm123", "admin", "admin123", "admin1234", "administrator",
            "iloveyou", "iloveyou1", "letmein", "letmein1", "welcome", "welcome1", "welcome123",
            "monkey", "monkey123", "dragon", "dragon123", "football", "baseball", "basketball",
            "superman", "batman", "spiderman", "trustno1", "sunshine", "princess", "princess1",
            "master", "master123", "hello", "hello123", "hello1234", "whatever", "freedom",
            "secret", "secret123", "passw0rd", "passw0rd1", "changeme", "changeme1", "default",
            "test", "test123", "test1234", "testtest", "guest", "guest123", "login", "login123",
            "michael", "michael1", "jennifer", "jessica", "charlie", "charlie1", "thomas",
            "daniel", "robert", "jordan", "jordan23", "joshua", "ashley", "michelle", "andrew",
            "andrew123", "william", "alexander", "benjamin", "elizabeth", "samantha", "anthony",
            "computer", "internet", "pokemon", "pokemon1", "starwars", "starwars1", "matrix",
            "matrix123", "mercedes", "ferrari", "mustang", "mustang1", "chevrolet", "corvette",
            "liverpool", "arsenal", "chelsea", "chelsea1", "manchester", "barcelona", "juventus",
            "tigger", "snoopy", "buster", "hunter", "ranger", "killer", "shadow", "shadow123",
            "hannah", "amanda", "nicole", "peanut", "cookie", "chocolate", "diamond", "purple",
            "summer", "summer2020", "winter2020", "lovely", "loveme", "loveyou", "ninja",
            "zaq12wsx", "zaq1xsw2", "asdf1234", "pass1234", "password01", "welcome01");

    private PasswordPolicy() {}

    public static void validate(String password) {
        if (password == null || password.isBlank() || password.length() < 8
                || !Utf8ByteLengthValidator.isValid(password, 72)
                || COMMON_PASSWORDS.contains(password.toLowerCase(Locale.ROOT))) {
            throw new PasswordPolicyViolationException();
        }
    }
}
