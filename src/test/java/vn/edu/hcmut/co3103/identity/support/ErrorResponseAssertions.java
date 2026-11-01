package vn.edu.hcmut.co3103.identity.support;

import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultMatcher;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

/** Shared strict DOC-05 contract check for MVC, security, and real HTTP errors. */
public final class ErrorResponseAssertions {
    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    private ErrorResponseAssertions() {}

    public static void assertErrorEnvelope(JsonNode error) {
        assertThat(error.isObject()).isTrue();
        assertThat(error.propertyNames()).containsExactlyInAnyOrder("code", "message", "details");
        assertThat(error.path("code").isString()).isTrue();
        assertThat(error.path("code").asText()).isNotBlank();
        assertThat(error.path("message").isString()).isTrue();
        assertThat(error.path("message").asText()).isNotBlank();
        assertThat(error.path("details").isArray()).isTrue();
        for (JsonNode detail : error.path("details")) {
            assertThat(detail.isObject() || detail.isString()).isTrue();
        }
    }

    public static ResultMatcher errorEnvelope() {
        return result -> {
            if (result.getResponse().getStatus() >= 400) {
                assertThat(MediaType.parseMediaType(result.getResponse().getContentType())
                        .isCompatibleWith(MediaType.APPLICATION_JSON)).isTrue();
                assertErrorEnvelope(MAPPER.readTree(result.getResponse().getContentAsString()));
            }
        };
    }

    public static String validationMessage(JsonNode error, String field) {
        assertErrorEnvelope(error);
        for (JsonNode detail : error.path("details")) {
            if (field.equals(detail.path("field").asText())) {
                assertThat(detail.propertyNames()).containsExactlyInAnyOrder("field", "message");
                return detail.path("message").asText();
            }
        }
        throw new AssertionError("Missing validation detail for " + field);
    }
}
