package vn.edu.hcmut.co3103.identity.exception;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApiErrorResponse {

    private int status;
    private String error;
    private String code;
    private String message;

    @Builder.Default
    private Instant timestamp = Instant.now();

    private String path;

    @JsonProperty("locked_until")
    private Instant lockedUntil;

    @JsonProperty("validation_errors")
    private Map<String, String> validationErrors;
}
