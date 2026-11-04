package vn.edu.hcmut.co3103.identity.exception;

import lombok.Builder;
import org.springframework.http.HttpStatus;

import java.util.List;

/** DOC-05 section 1.8: every error has exactly these three JSON members. */
@Builder
public record ApiErrorResponse(String code, String message, List<?> details) {

    public ApiErrorResponse {
        details = details == null ? List.of() : List.copyOf(details);
    }

    /** Sanitized fallback for errors raised before a controller or security handler runs. */
    public static ApiErrorResponse forStatus(int statusCode) {
        HttpStatus status = HttpStatus.resolve(statusCode);
        if (status == null || !status.isError()) {
            status = HttpStatus.INTERNAL_SERVER_ERROR;
        }
        String code = switch (status) {
            case FORBIDDEN -> "ACCESS_DENIED";
            case NOT_FOUND -> "RESOURCE_NOT_FOUND";
            default -> status.name();
        };
        return new ApiErrorResponse(code, status.getReasonPhrase(), List.of());
    }
}
