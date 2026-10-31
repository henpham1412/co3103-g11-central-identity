package vn.edu.hcmut.co3103.identity.dto.auth.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import vn.edu.hcmut.co3103.identity.entity.UserStatus;

import java.util.UUID;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {

    @JsonProperty("access_token")
    private String accessToken;

    @Builder.Default
    @JsonProperty("token_type")
    private String tokenType = "Bearer";

    /** Configured token lifetime in seconds. */
    @JsonProperty("expires_in")
    private long expiresIn;

    @JsonProperty("client_id")
    private String clientId;

    private AuthUser user;

    public record AuthUser(@JsonProperty("user_id") UUID userId, String email,
                           @JsonProperty("full_name") String fullName, UserStatus status) {
    }
}
