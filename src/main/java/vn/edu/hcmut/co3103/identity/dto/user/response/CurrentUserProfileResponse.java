package vn.edu.hcmut.co3103.identity.dto.user.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import vn.edu.hcmut.co3103.identity.entity.UserStatus;

import java.util.UUID;
import java.time.LocalDate;

public record CurrentUserProfileResponse(
        @JsonProperty("user_id") UUID userId,
        @JsonProperty("email") String email,
        @JsonProperty("full_name") String fullName,
        @JsonProperty("status") UserStatus status,
        @JsonProperty("profile") UserProfileResponse profile) {

    // Scalar projection: all fields come from one SQL statement, including an absent profile.
    public CurrentUserProfileResponse(UUID userId, String email, String fullName, UserStatus status,
            UUID profileId, String avatarUrl, String bio, String phoneNumber, LocalDate dateOfBirth,
            String locale, String timezone) {
        this(userId, email, fullName, status, profileId == null ? null :
                new UserProfileResponse(avatarUrl, bio, phoneNumber, dateOfBirth, locale, timezone));
    }
}
