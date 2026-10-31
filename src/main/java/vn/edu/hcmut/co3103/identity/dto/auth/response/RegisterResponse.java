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
public class RegisterResponse {

    @Builder.Default
    private String message = "User registered successfully";

    @JsonProperty("user_id")
    private UUID userId;
    private String email;
    @JsonProperty("full_name")
    private String fullName;
    private UserStatus status;
}
