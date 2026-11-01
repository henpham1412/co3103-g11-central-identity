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

    // Send literal JSON escapes: the HTTP client's UTF-8 encoder must not replace test input first.
    public static String jsonString(String value) {
        return JsonMapper.builder().enable(JsonWriteFeature.ESCAPE_NON_ASCII).build().writeValueAsString(value);
    }
}
