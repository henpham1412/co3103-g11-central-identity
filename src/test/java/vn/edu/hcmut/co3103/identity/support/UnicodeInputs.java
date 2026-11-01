package vn.edu.hcmut.co3103.identity.support;

import tools.jackson.core.json.JsonWriteFeature;
import tools.jackson.databind.json.JsonMapper;

import java.util.stream.Stream;

public final class UnicodeInputs {
    private UnicodeInputs() {}

    public static Stream<String> malformedUnicode() {
        return Stream.of("\ud800Password123!", "\udfffPassword123!",
                "Pass\ud800word123!", "Pass\udfffword123!", "Password123!\ud800", "Password123!\udfff",
                "\ud800\ud800Password123!", "\udfff\udfffPassword123!", "\udfff\ud800Password123!",
                "\ud83d\ude00\ud800Password123!", "\ud800".repeat(8), "\udfff".repeat(8));
    }

    public static Stream<String> malformedEmails() {
        return Stream.of("\ud800member", "\udfffmember", "mem\ud800ber", "mem\udfffber",
                "member\ud800", "member\udfff", "\ud800\ud800member", "\udfff\udfffmember",
                "\udfff\ud800member", "\ud83d\ude00\ud800member", "\ud800".repeat(8), "\udfff".repeat(8))
                .map(localPart -> localPart + "@example.com");
    }

    public static Stream<String> validEmails() {
        return Stream.of("member@example.com", "member?@example.com", "m\u00e9mber@example.com",
                "th\u00e0nh@example.com", "me\u0301mber@example.com");
    }

    // Send literal JSON escapes: the HTTP client's UTF-8 encoder must not replace test input first.
    public static String jsonString(String value) {
        return JsonMapper.builder().enable(JsonWriteFeature.ESCAPE_NON_ASCII).build().writeValueAsString(value);
    }
}
