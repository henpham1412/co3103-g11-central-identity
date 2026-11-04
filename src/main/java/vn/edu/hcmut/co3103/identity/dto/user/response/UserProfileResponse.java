package vn.edu.hcmut.co3103.identity.dto.user.response;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.LocalDate;

public record UserProfileResponse(
        @JsonProperty("avatar_url") String avatarUrl,
        @JsonProperty("bio") String bio,
        @JsonProperty("phone_number") String phoneNumber,
        @JsonProperty("date_of_birth") LocalDate dateOfBirth,
        @JsonProperty("locale") String locale,
        @JsonProperty("timezone") String timezone) {
}
