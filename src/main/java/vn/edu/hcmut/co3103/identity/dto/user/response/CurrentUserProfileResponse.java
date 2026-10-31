package vn.edu.hcmut.co3103.identity.dto.user.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import vn.edu.hcmut.co3103.identity.entity.UserStatus;

import java.util.UUID;

public record CurrentUserProfileResponse(
        @JsonProperty("user_id") UUID userId,
        @JsonProperty("email") String email,
        @JsonProperty("full_name") String fullName,
        @JsonProperty("status") UserStatus status,
        @JsonProperty("profile") UserProfileResponse profile) {

    // Preserve the identity fields consumed by clients of the original /users/me response.
    @JsonProperty("id")
    public UUID legacyId() {
        return userId;
    }

    @JsonProperty("fullName")
    public String legacyFullName() {
        return fullName;
    }

    @JsonProperty("role")
    public String legacyRole() {
        return "USER";
    }
}
