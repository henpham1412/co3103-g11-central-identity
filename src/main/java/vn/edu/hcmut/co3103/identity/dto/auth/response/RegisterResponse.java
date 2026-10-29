package vn.edu.hcmut.co3103.identity.dto.auth.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import vn.edu.hcmut.co3103.identity.entity.UserStatus;

import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterResponse {

    private UUID userId;
    private String email;
    private String fullName;
    private UserStatus status;
    private Instant createdAt;
}
