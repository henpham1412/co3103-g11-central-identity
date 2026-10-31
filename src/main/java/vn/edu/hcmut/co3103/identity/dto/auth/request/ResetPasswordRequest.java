package vn.edu.hcmut.co3103.identity.dto.auth.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import vn.edu.hcmut.co3103.identity.validation.Utf8ByteLength;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ResetPasswordRequest {

    @JsonProperty("token")
    @NotBlank(message = "Token is required")
    private String token;

    @JsonProperty("new_password")
    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
    @Utf8ByteLength(max = 72, message = "Password must not exceed 72 bytes")
    private String newPassword;
}
