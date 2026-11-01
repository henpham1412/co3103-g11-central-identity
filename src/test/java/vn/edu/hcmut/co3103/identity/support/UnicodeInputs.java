package vn.edu.hcmut.co3103.identity.support;

import tools.jackson.core.json.JsonWriteFeature;
import tools.jackson.databind.json.JsonMapper;

import java.util.stream.Stream;

public final class UnicodeInputs {
    private UnicodeInputs() {}

    public static Stream<String> malformedUnicode() {
        // One lone high and one lone low surrogate cover the two malformed UTF-16 classes.
        return Stream.of("Password123!\ud800", "Password123!\udfff");
    }

    public static Stream<String> malformedEmails() {
        return Stream.of("member\ud800", "member\udfff")
                .map(localPart -> localPart + "@example.com");
    }

    public static Stream<String> validEmails() {
        return Stream.of("member@example.com", "member?@example.com", "m\u00e9mber@example.com",
                "me\u0301mber@example.com");
    }

    // Send literal JSON escapes: the HTTP client's UTF-8 encoder must not replace test input first.
    public static String jsonString(String value) {
        return JsonMapper.builder().enable(JsonWriteFeature.ESCAPE_NON_ASCII).build().writeValueAsString(value);
    }
}
