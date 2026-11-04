package vn.edu.hcmut.co3103.identity.dto.user.response;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

public record UpdateProfileResponse(
        @JsonProperty("message") String message,
        @JsonProperty("updated_at") Instant updatedAt) {
}
