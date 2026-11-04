package vn.edu.hcmut.co3103.identity.dto.user.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import java.util.UUID;

/** Compatibility fields belong only to unversioned routes. */
public record LegacyCurrentUserProfileResponse(@JsonUnwrapped CurrentUserProfileResponse account) {
    @JsonProperty("id") public UUID legacyId() { return account.userId(); }
    @JsonProperty("fullName") public String legacyFullName() { return account.fullName(); }
    @JsonProperty("role") public String legacyRole() { return "USER"; }
}
