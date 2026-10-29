package vn.edu.hcmut.co3103.identity.dto.auth.response;

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

    private String accessToken;

    @Builder.Default
    private String tokenType = "Bearer";

    private long expiresIn;
    private UUID userId;
    private String email;
    private String fullName;
    private UserStatus status;
}
